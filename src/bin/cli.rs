//! ipswatch-cli - headless use: services, scripting, offline analysis.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};

use ipswatch::config::{self, Severity};
use ipswatch::monitor::{Monitor, Shared, Status};
use ipswatch::opnsense::OPNsense;
use ipswatch::store::Store;
use ipswatch::{collect, engine, logbuf, report};

#[derive(Parser)]
#[command(name = "ipswatch-cli", version, about = "OPNsense IPS monitor (command line)")]
struct Cli {
    /// Config file (default: %APPDATA%\ipswatch\config.toml, shared with the desktop app)
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify API access and IDS status
    Check,
    /// Explain the firewall's HTTPS certificate (Let's Encrypt? need a CA file?)
    CheckCert {
        /// URL to check (default: the configured firewall URL)
        url: Option<String>,
    },
    /// Monitor continuously (Ctrl+C to stop)
    Run,
    /// One poll + detection pass (for Task Scheduler / cron)
    Poll,
    /// Import an eve.json or syslog capture and analyze it
    Import {
        file: PathBuf,
        /// Don't send notifications during replay
        #[arg(long)]
        quiet: bool,
    },
    /// List findings
    Findings {
        /// Include acknowledged / false positive
        #[arg(long)]
        all: bool,
        #[arg(long, default_value = "low")]
        min: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Acknowledge a finding
    Ack { key: String },
    /// Mark a finding as a false positive (stays silent)
    Fp { key: String },
    /// Reopen a finding
    Reopen { key: String },
    /// Write a static HTML report
    Report { out: PathBuf },
    /// Drop policy for high-risk rulesets on the firewall. Without flags: dry run (changes nothing).
    IpsPolicy {
        /// Create/update the policy and reload Suricata (requires --yes)
        #[arg(long)]
        apply: bool,
        /// Remove the policy and reload Suricata (requires --yes)
        #[arg(long, conflicts_with = "apply")]
        remove: bool,
        /// Confirm --apply / --remove
        #[arg(long)]
        yes: bool,
    },
    /// Run the firewall health, exposure, device and config checks once and print the result
    Health,
    /// Check the Technitium DNS servers once and print the result
    Dns {
        /// Skip the firewall exposure audit (port forwards to the DNS servers)
        #[arg(long)]
        no_exposure: bool,
    },
    /// GET a Technitium API path from one DNS server and print the JSON (secrets hidden), e.g. dashboard/stats/get type=LastHour
    DumpDns {
        /// Server name or address as configured
        server: String,
        path: String,
        /// Query parameters as key=value
        params: Vec<String>,
    },
    /// Add or remove blocklist URLs on the Technitium DNS servers (keeps other lists) and download them.
    /// Without --yes: dry run. Needs a token allowed to modify Settings.
    DnsBlocklists {
        /// Only this server (name or address); default: all configured
        #[arg(long)]
        server: Option<String>,
        /// Blocklist URL to add (repeatable)
        #[arg(long = "add", required_unless_present_any = ["remove", "verify"])]
        add: Vec<String>,
        /// Blocklist URL to remove (repeatable)
        #[arg(long = "remove")]
        remove: Vec<String>,
        /// Check the configured lists: loaded, and listed domains that resolve publicly are blocked here
        #[arg(long, conflicts_with_all = ["add", "remove"])]
        verify: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Disable the Suricata rulesets listed in a file (one filename per line, # comments ok) with
    /// a single reload. Without --yes: dry run. Logs to rulesets-change.log next to the config.
    IpsRulesets {
        #[arg(long)]
        disable_from: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    /// Recompute all findings from stored events with the current rules (keeps your ack/false-positive marks)
    Rescore,
    /// Print raw alert rows from the firewall API (diagnostics)
    DumpAlerts {
        #[arg(default_value_t = 3)]
        rows: u32,
    },
    /// GET any API path and print the JSON, e.g. diagnostics/interface/get_interface_config
    DumpApi {
        path: String,
        /// Send this JSON as a POST body (only use with search_* endpoints)
        #[arg(long)]
        post: Option<String>,
    },
    /// Print raw firewall log rows from the API (diagnostics)
    DumpFirewallLog {
        #[arg(default_value_t = 3)]
        rows: u32,
    },
}

fn print_findings(store: &Store, all: bool, min: Severity, limit: usize) -> Result<()> {
    let rows = store.list_findings(if all { None } else { Some("open") }, min, limit)?;
    if rows.is_empty() {
        println!("no findings");
    }
    for f in rows {
        println!(
            "{:<9} {:>4}  {}  {:<14} {}",
            f.severity.as_str().to_uppercase(),
            f.score,
            ipswatch::local_time(&f.last_seen),
            f.status_label(),
            f.key
        );
        println!("          {}", f.title);
        for r in f.reasons.iter().take(6) {
            println!("            - {r}");
        }
    }
    Ok(())
}

/// For each server: lists configured and loaded, then up to 3 domains per list that resolve via
/// 1.1.1.1 must be blocked by the server (port 53), and a normal name must still resolve.
fn verify_blocklists(cfg: &config::Config, servers: &[&config::DnsServerCfg]) -> Result<()> {
    use ipswatch::dns::{fetch_blocklist, mask_url, query, Technitium};
    use std::collections::HashMap;
    let to = std::time::Duration::from_secs(3);
    let mut samples: HashMap<String, Result<(usize, Vec<String>), String>> = HashMap::new();
    let mut failures = 0;
    for srv in servers {
        let t = Technitium::new(srv, cfg.dns.timeout_seconds)?;
        let set = t.get("settings/get", &[])?;
        let stats = t.get("dashboard/stats/get", &[("type", "LastHour")])?;
        let urls: Vec<String> = set.get("blockListUrls").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let s = |k: &str| set.get(k).map(|v| v.to_string()).unwrap_or_default();
        println!("{} ({}): blocking {} · type {} · {} list(s) · {} blocklist domains loaded · next update {}",
            srv.label(), srv.host(), s("enableBlocking"), s("blockingType"), urls.len(),
            stats.pointer("/stats/blockListZones").map(|v| v.to_string()).unwrap_or("?".into()), s("blockListNextUpdatedOn"));
        if urls.is_empty() {
            failures += 1;
            println!("  FAIL: no blocklist URLs saved");
        }
        for url in &urls {
            let entry = samples.entry(url.clone()).or_insert_with(|| {
                fetch_blocklist(url).map_err(|e| format!("{e:#}")).map(|names| {
                    // Listed names that really resolve publicly, so NXDOMAIN here can only mean "blocked".
                    let live: Vec<String> = names.iter().take(400).filter(|d| query("1.1.1.1", d, to).ok).take(3).cloned().collect();
                    (names.len(), live)
                })
            });
            match entry {
                Err(e) => {
                    failures += 1;
                    println!("  FAIL {e}");
                }
                Ok((n, live)) => {
                    println!("  list {} - {n} domains, {} sampled that resolve publicly", mask_url(url), live.len());
                    for d in live.iter() {
                        let l = query(&srv.host(), d, to);
                        let blocked = l.result == "NXDOMAIN" || (l.result == "NOERROR" && l.answers == 0);
                        failures += usize::from(!blocked);
                        println!("    {} {d}: {} here (1.1.1.1 answers it)", if blocked { "BLOCKED" } else { "NOT BLOCKED" }, l.result);
                    }
                }
            }
        }
        for d in cfg.dns.test_domains.iter().filter(|d| !d.trim().is_empty()) {
            let l = query(&srv.host(), d.trim(), to);
            failures += usize::from(!l.ok);
            println!("  normal lookup {}: {} ({} answers)", d.trim(), l.result, l.answers);
        }
    }
    println!("
{}", if failures == 0 { "VERIFIED: blocklists loaded and blocking on every server".to_string() } else { format!("{failures} check(s) failed") });
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_file = match &cli.cmd {
        Cmd::IpsRulesets { .. } => Some(cli.config.clone().unwrap_or_else(config::default_config_path).with_file_name("rulesets-change.log")),
        _ => None,
    };
    logbuf::init(log_file, true);
    let cfg_path = cli.config.unwrap_or_else(config::default_config_path);
    let cfg = config::load(&cfg_path)?;
    let store = Arc::new(Store::open(&cfg.db_path_for(&cfg_path))?);
    let api = || -> Result<OPNsense> { OPNsense::new(&cfg.opnsense) };

    match cli.cmd {
        Cmd::Check => println!("{}", api()?.check(cfg.firewall.correlate, cfg.block.enabled.then_some(cfg.block.alias.as_str()))?),
        Cmd::CheckCert { url } => {
            let url = url.unwrap_or_else(|| cfg.opnsense.url.clone());
            let r = ipswatch::tlscheck::check(&url, &cfg.opnsense.ca_file)?;
            println!("[{:?}] {url}\n{}", r.verdict, r.summary);
            if let Some(s) = r.suggested_url {
                println!("\nSuggested Firewall URL: {s}");
            }
        }
        Cmd::Poll => {
            let a = if cfg.opnsense.url.is_empty() { None } else { Some(api()?) };
            let added = match &a {
                Some(a) => collect::poll_api(a, &store, cfg.opnsense.page_size, cfg.opnsense.max_pages)?,
                None => 0,
            };
            let alerted = engine::run_detection(&cfg, &store, a.as_ref(), None, true)?;
            println!("{added} new events, {} notifications", alerted.len());
        }
        Cmd::Run => {
            let shared = Arc::new(Shared {
                cfg: RwLock::new(cfg),
                store,
                status: Mutex::new(Status::default()),
                data_version: AtomicU64::new(0),
                health: Mutex::new(None),
                dns: Mutex::new(None),
                on_alert: Box::new(|_, _| {}),
                on_cycle: Box::new(|| {}),
            });
            let m = Monitor::start(shared);
            while !m.is_finished() {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        Cmd::Import { file, quiet } => {
            let n = collect::import_file(&file, &store).with_context(|| format!("importing {}", file.display()))?;
            println!("imported {n} new alert events from {}", file.display());
            engine::replay(&cfg, &store, !quiet)?;
            print_findings(&store, false, Severity::Low, 50)?;
        }
        Cmd::Findings { all, min, limit } => print_findings(&store, all, Severity::parse(&min), limit)?,
        Cmd::Ack { key } => store.set_status(&key, "ack")?,
        Cmd::Fp { key } => store.set_status(&key, "false_positive")?,
        Cmd::Reopen { key } => store.set_status(&key, "open")?,
        Cmd::Report { out } => println!("wrote {} ({} findings)", out.display(), report::write_html(&store, &out)?),
        Cmd::IpsRulesets { disable_from, yes } => {
            let text = std::fs::read_to_string(&disable_from).with_context(|| format!("reading {}", disable_from.display()))?;
            let files: Vec<String> = text
                .lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            log::info!("Ruleset change from {} ({} rulesets, {})", disable_from.display(), files.len(), if yes { "APPLY" } else { "dry run" });
            let a = api()?;
            let plan = ipswatch::ipspolicy::plan_disable(&a, &files)?;
            println!("{}", plan.render());
            if yes {
                match ipswatch::ipspolicy::apply_disable(&a, &plan) {
                    Ok(msg) => println!("\n{msg}"),
                    Err(e) => {
                        log::error!("Ruleset change failed: {e:#}");
                        return Err(e);
                    }
                }
            } else {
                println!("\nDRY RUN - nothing was changed. Apply with --yes.");
            }
        }
        Cmd::IpsPolicy { apply, remove, yes } => {
            let a = api()?;
            if remove {
                anyhow::ensure!(yes, "Removing changes the firewall: add --yes to confirm.");
                println!("{}", ipswatch::ipspolicy::remove(&a)?);
            } else {
                let plan = ipswatch::ipspolicy::plan(&a, &cfg.ips_policy.rulesets)?;
                println!("{}", plan.render());
                if apply {
                    anyhow::ensure!(yes, "\nThis was a dry run. Add --yes to apply it.");
                    println!("\n{}", ipswatch::ipspolicy::apply(&a, &plan)?);
                } else {
                    println!("\nDRY RUN - nothing was changed. Apply with: ipswatch-cli ips-policy --apply --yes");
                }
            }
        }
        Cmd::Health => {
            let (snap, _) = ipswatch::health::run(&cfg, &store, &api()?)?;
            println!("{} - {}  up {}  load {}", snap.hostname, snap.version, snap.uptime, snap.loadavg);
            println!("\nGateways:");
            for g in &snap.gateways {
                println!("  {:<22} {:<10} delay {:>7}  loss {:>5}", g.name, g.status, g.delay_ms.map(|d| format!("{d:.1} ms")).unwrap_or_default(), g.loss_pct.map(|l| format!("{l:.0}%")).unwrap_or_default());
            }
            let stopped: Vec<_> = snap.services.iter().filter(|s| !s.running).map(|s| s.name.as_str()).collect();
            println!("\nServices: {} running, stopped: {}", snap.services.len() - stopped.len(), if stopped.is_empty() { "none".into() } else { stopped.join(", ") });
            println!("Memory {}%  States {}  Disks {}", snap.memory_pct.map(|m| m.to_string()).unwrap_or("?".into()),
                snap.states.map(|(c, l)| format!("{c}/{l}")).unwrap_or("?".into()),
                snap.disks.iter().map(|(m, p)| format!("{m} {p}%")).collect::<Vec<_>>().join(", "));
            for w in &snap.system_warnings {
                println!("Warning: {} [{}] {}", w.0, w.1, w.2);
            }
            println!("Firmware: {}", snap.firmware);
            println!("\nExposure ({}):", snap.exposure.len());
            for e in &snap.exposure {
                println!("  {:<22} {:<6} {:<9} {:<22} {}{}", format!("{}:{}", e.target, e.port), e.protocol, e.source.split(' ').next().unwrap_or(""), e.status_label(), e.note, if e.hits > 0 { format!(" ({} hits)", e.hits) } else { String::new() });
            }
            match &snap.crowdsec {
                Some(cs) => {
                    println!("\nCrowdSec: {} · bouncer last seen {} · {} IPs blocked in the firewall ({} local, {} community/lists) · {} alerts",
                        if cs.running { "running" } else { "STOPPED" },
                        if cs.bouncer_last_seen.is_empty() { "never".into() } else { ipswatch::local_time(&cs.bouncer_last_seen) },
                        cs.firewall_blocked.map(|b| b.to_string()).unwrap_or_else(|| "?".into()), cs.local_bans, cs.community_bans, cs.alerts_total);
                    for (sc, n) in &cs.top_scenarios {
                        println!("  {n:>4}  {sc}");
                    }
                }
                None => println!("\nCrowdSec: not installed"),
            }
            println!("\nDevices known: {} (new this run: {})", snap.devices.len(), snap.new_devices);
            println!("Recent config changes:");
            for c in snap.config_changes.iter().take(5) {
                println!("  {}  {}  {}", ipswatch::local_time(&c.time), c.user, c.description);
            }
            for e in &snap.errors {
                println!("Check failed: {e}");
            }
            println!();
            let open = store.list_findings(Some("open"), Severity::Low, 100)?;
            let mine: Vec<_> = open.iter().filter(|f| matches!(f.kind.as_str(), "health" | "exposure" | "device" | "config" | "crowdsec")).collect();
            println!("Open health/exposure/device/config findings: {}", mine.len());
            for f in mine {
                println!("  {:<8} {}", f.severity.as_str().to_uppercase(), f.title);
            }
        }
        Cmd::Dns { no_exposure } => {
            let exposure = if no_exposure || cfg.opnsense.url.is_empty() {
                vec![]
            } else {
                ipswatch::health::run(&cfg, &store, &api()?)?.0.exposure
            };
            let (snap, _) = ipswatch::dns::run(&cfg, &store, &exposure, &ipswatch::monitor::recent_ids_restarts(&cfg))?;
            for r in &snap.ids_restarts {
                println!("{r}");
            }
            for s in &snap.servers {
                println!("{} ({}) - DNS {} - API {}", s.name, s.host, if s.dns_ok { "UP" } else { "DOWN" }, if s.api_ok { format!("OK, Technitium {}", s.version) } else { s.api_error.clone() });
                for l in &s.lookups {
                    println!("  lookup {:<20} {:<9} {} answers {:>4} ms", l.domain, l.result, l.answers, l.ms);
                }
                if let Some(st) = &s.stats {
                    println!("  last hour: {} queries, {:.1}% blocked, {:.1}% SERVFAIL, {:.1}% NXDOMAIN, {} clients, {} blocklist domains",
                        st.total, st.pct(st.blocked), st.pct(st.servfail), st.pct(st.nxdomain), st.clients, st.block_list_zones);
                }
                println!("  recursion {} · forwarders {} · blocking {} ({} lists, refreshed {} h ago, next {})",
                    s.recursion, if s.forwarders.is_empty() { "none".into() } else { s.forwarders.join(", ") }, s.blocking, s.blocklist_urls,
                    s.blocklist_age_hours.map(|a| format!("{a:.1}")).unwrap_or("?".into()), ipswatch::local_time(&s.blocklist_next_update));
                println!("  server log, last hour: {} failed resolutions; failing most: {}; name servers timing out: {}",
                    s.upstream_failures, ipswatch::dns::pairs_text(&s.failing_names, 6), ipswatch::dns::pairs_text(&s.silent_nameservers, 5));
                for c in s.top_clients.iter().take(5) {
                    println!("  client {:<16} {:<30} {:>6} queries (usual {})", c.ip, c.name, c.hits, c.usual.map(|u| format!("{u:.0}")).unwrap_or("learning".into()));
                }
                for (d, n) in s.top_blocked.iter().take(5) {
                    println!("  blocked {d} x{n}");
                }
                println!("  query log app: {}", if s.query_logger.is_empty() { "none" } else { &s.query_logger });
                for c in &s.nx_clients {
                    println!("  nxdomain {:<16} {:>5} ({} distinct) e.g. {}", c.ip, c.count, c.unique, c.sample.join(", "));
                }
                println!("  zones: {}", s.zones.iter().map(|z| format!("{} [{}{}]", z.name, z.kind, if z.problem.is_empty() { String::new() } else { format!(", {}", z.problem) })).collect::<Vec<_>>().join(", "));
                for e in &s.exposure {
                    println!("  WAN {} {}/{} {} - used for: {} - listening: {:?} - {}", e.interface, e.port, e.protocol, if e.blocked { "blocked" } else { "OPEN" }, if e.purpose.is_empty() { "-" } else { &e.purpose }, e.listening, e.note);
                }
                for e in &s.errors {
                    println!("  check failed: {e}");
                }
                println!();
            }
            let open = store.list_findings(Some("open"), Severity::Low, 200)?;
            let mine: Vec<_> = open.iter().filter(|f| f.kind == "dns").collect();
            println!("Open DNS findings: {}", mine.len());
            for f in mine {
                println!("  {:<8} {}", f.severity.as_str().to_uppercase(), f.title);
                for r in &f.reasons {
                    println!("             - {r}");
                }
            }
        }
        Cmd::DnsBlocklists { server, add, remove, verify, yes } => {
            let servers: Vec<_> = cfg.dns.servers.iter().filter(|s| server.as_ref().is_none_or(|n| s.label() == *n || s.host() == *n)).collect();
            anyhow::ensure!(!servers.is_empty(), "no matching DNS server in the config");
            if verify {
                return verify_blocklists(&cfg, &servers);
            }
            for srv in servers {
                let t = ipswatch::dns::Technitium::new(srv, cfg.dns.timeout_seconds)?;
                let set = t.get("settings/get", &[])?;
                let mut urls: Vec<String> = set.get("blockListUrls").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                let old = urls.clone();
                let before = urls.len();
                urls.retain(|u| !remove.contains(u));
                for u in &add {
                    if !urls.iter().any(|x| x == u) {
                        urls.push(u.clone());
                    }
                }
                let shown = |v: &[String]| v.iter().map(|u| ipswatch::dns::mask_url(u)).collect::<Vec<_>>().join(", ");
                println!("{}: {} list(s) now, {} after: {}", srv.label(), before, urls.len(), shown(&urls));
                if urls == old {
                    println!("  nothing to add");
                } else if yes {
                    // Technitium clears the list when given "false".
                    let value = if urls.is_empty() { "false".to_string() } else { urls.join(",") };
                    t.get("settings/set", &[("blockListUrls", &value)])?;
                    println!("  saved");
                } else {
                    println!("  DRY RUN - add --yes to save");
                    continue;
                }
                if yes && !urls.is_empty() {
                    t.get("settings/forceUpdateBlockLists", &[])?;
                    println!("  blocklist download started");
                }
            }
        }
        Cmd::DumpDns { server, path, params } => {
            let srv = cfg.dns.servers.iter().find(|s| s.label() == server || s.host() == server).context("no such DNS server in the config")?;
            let q: Vec<(&str, &str)> = params.iter().filter_map(|p| p.split_once('=')).collect();
            let t = ipswatch::dns::Technitium::new(srv, cfg.dns.timeout_seconds)?;
            if path.starts_with("logs/download") {
                print!("{}", t.get_text(&path, &q)?);
                return Ok(());
            }
            let v = t.get(&path, &q)?;
            println!("{}", serde_json::to_string_pretty(&ipswatch::dns::sanitize(&v))?)
        }
        Cmd::Rescore => {
            if !cfg.opnsense.url.is_empty() {
                engine::refresh_own_addresses(&store, &api()?, true);
            }
            let r = engine::rescore(&cfg, &store)?;
            println!("re-scored {} events: {} findings before, {} after", r.events, r.before, r.after);
            print_findings(&store, true, Severity::Low, 50)?;
        }
        Cmd::DumpAlerts { rows } => {
            for r in api()?.ids_alerts(1, rows)? {
                println!("{}", serde_json::to_string_pretty(&r)?);
            }
        }
        Cmd::DumpApi { path, post } => {
            let v = match post {
                Some(body) => api()?.post_raw(&path, serde_json::from_str(&body)?)?,
                None => api()?.get_raw(&path)?,
            };
            println!("{}", serde_json::to_string_pretty(&v)?)
        }
        Cmd::DumpFirewallLog { rows } => {
            for r in api()?.firewall_log(rows)? {
                println!("{}", serde_json::to_string_pretty(&r)?);
            }
        }
    }
    Ok(())
}
