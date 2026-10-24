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
    /// Recompute all findings from stored events with the current rules (keeps your ack/false-positive marks)
    Rescore,
    /// Print raw alert rows from the firewall API (diagnostics)
    DumpAlerts {
        #[arg(default_value_t = 3)]
        rows: u32,
    },
    /// GET any API path and print the JSON, e.g. diagnostics/interface/get_interface_config
    DumpApi { path: String },
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    logbuf::init(None, true);
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
        Cmd::DumpApi { path } => println!("{}", serde_json::to_string_pretty(&api()?.get_raw(&path)?)?),
        Cmd::DumpFirewallLog { rows } => {
            for r in api()?.firewall_log(rows)? {
                println!("{}", serde_json::to_string_pretty(&r)?);
            }
        }
    }
    Ok(())
}
