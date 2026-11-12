//! Troubleshooting: find out why the internet (or one site) isn't working and offer fixes.
//!
//! One [`run`] collects:
//! - **Clock**: the firewall's time against this PC (a wrong clock breaks TLS, DNSSEC, CrowdSec
//!   and log times; it happens after restoring a VM snapshot) and competing time services.
//! - **Sites that must work**: each one is resolved, connected to and fetched over HTTPS from
//!   this PC; a failure is matched against the firewall log and IPS alerts to name the cause.
//! - **Gateway history**: outages and packet loss from the gateway monitor (dpinger) log.
//! - **Blocked LAN traffic**: firewall-log blocks of your own devices, split into rule blocks
//!   and dropped packets of existing connections (lost state).
//! - **Inline inspection**: Suricata IPS and Zenarmor both inspecting the same traffic, and
//!   hardware offloading left on with inline IPS.
//! - **What changed**: a baseline of key firewall settings, kept from before the last firmware
//!   update (or set by hand), compared with now. Snapshot rollbacks and updates show up here.
//!
//! Fixes are only ever applied by [`Fix::apply`], which the app and CLI call after showing
//! [`Fix::preview`] and getting confirmation.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::config::{Config, Severity};
use crate::opnsense::OPNsense;
use crate::store::Store;

const BASELINE_KV: &str = "fw_baseline";
const LAST_STATE_KV: &str = "fw_state_last";

/// A change IPS Watch can make for you (always previewed and confirmed first).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Fix {
    /// Restart a firewall service (start it if stopped).
    RestartService { name: String, description: String },
    /// Restart the time service so it steps the clock to the right time.
    ResyncClock { service: String },
}

impl Fix {
    pub fn label(&self) -> String {
        match self {
            Fix::RestartService { description, .. } => format!("Restart {description}"),
            Fix::ResyncClock { .. } => "Resync the firewall clock".into(),
        }
    }

    /// What will happen, for the confirmation dialog. Changes nothing.
    pub fn preview(&self) -> String {
        match self {
            Fix::RestartService { name, description } => format!(
                "IPS Watch will ask the firewall to restart the service \"{description}\" ({name}).\n\n\
                 Nothing else changes. Connections that depend on it may pause for a few seconds."
            ),
            Fix::ResyncClock { service } => format!(
                "IPS Watch will restart the firewall's time service ({service}). On start it sets the clock \
                 straight to the time from its time servers, even if it is hours off.\n\n\
                 Nothing else changes. If the clock is still wrong afterwards, check \
                 Services > Network Time has working servers (e.g. pool.ntp.org)."
            ),
        }
    }

    /// Apply the fix. Only call this after the user confirmed [`Fix::preview`].
    pub fn apply(&self, api: &OPNsense) -> Result<String> {
        let name = match self {
            Fix::RestartService { name, .. } => name,
            Fix::ResyncClock { service } => service,
        };
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) {
            return Err(anyhow!("refusing an unexpected service name {name:?}"));
        }
        let v = api.post_raw(&format!("core/service/restart/{name}"), json!({}))?;
        let res = v.get("result").and_then(Value::as_str).unwrap_or("").to_lowercase();
        if !res.is_empty() && !res.contains("ok") && !res.contains("restart") {
            return Err(anyhow!("the firewall answered {v}"));
        }
        let msg = format!("{}: done.", self.label());
        log::warn!("Troubleshoot fix applied: {msg}");
        Ok(msg)
    }
}

/// One problem found, in plain language.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issue {
    pub area: String,
    pub severity: Severity,
    pub title: String,
    /// What it means and why it matters.
    pub explain: String,
    /// The facts it is based on.
    pub evidence: Vec<String>,
    /// Steps to fix it by hand (when IPS Watch can't, or as an alternative).
    pub manual: Vec<String>,
    pub fix: Option<Fix>,
}

impl Issue {
    fn new(area: &str, severity: Severity, title: impl Into<String>, explain: impl Into<String>) -> Self {
        Issue { area: area.into(), severity, title: title.into(), explain: explain.into(), evidence: vec![], manual: vec![], fix: None }
    }
    fn evidence(mut self, e: impl IntoIterator<Item = String>) -> Self {
        self.evidence.extend(e);
        self
    }
    fn manual(mut self, m: &[&str]) -> Self {
        self.manual.extend(m.iter().map(|x| x.to_string()));
        self
    }
    fn fix(mut self, f: Option<Fix>) -> Self {
        self.fix = f;
        self
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SiteResult {
    pub site: String,
    pub addresses: Vec<String>,
    pub dns_ms: Option<u128>,
    pub connect_ms: Option<u128>,
    pub https_ms: Option<u128>,
    /// HTTP status (any status means the site is reachable).
    pub status: Option<u16>,
    /// Empty when the site works.
    pub error: String,
    /// What blocked it, when the firewall log or IPS alerts show it.
    pub cause: String,
}

impl SiteResult {
    pub fn ok(&self) -> bool {
        self.error.is_empty()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewayHistory {
    pub name: String,
    pub monitor_ip: String,
    pub down_24h: usize,
    pub loss_24h: usize,
    pub delay_24h: usize,
    pub down_7d: usize,
    pub loss_7d: usize,
    /// Newest first: (time, "none -> loss", details).
    pub events: Vec<(String, String, String)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Change {
    pub key: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub at: String,
    pub version: String,
    pub items: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub at: String,
    pub firmware: String,
    pub issues: Vec<Issue>,
    pub sites: Vec<SiteResult>,
    pub gateways: Vec<GatewayHistory>,
    /// Clock difference, firewall minus this PC, in seconds.
    pub clock_offset_s: Option<i64>,
    pub baseline_at: String,
    pub baseline_version: String,
    pub changes: Vec<Change>,
    /// Checks that couldn't run.
    pub errors: Vec<String>,
}

impl Report {
    pub fn render(&self) -> String {
        let mut s = format!("Troubleshoot {}  ·  firmware {}\n", self.at, self.firmware);
        if self.issues.is_empty() {
            s += "\nNo problems found.\n";
        }
        for i in &self.issues {
            s += &format!("\n[{}] {}: {}\n  {}\n", i.severity.as_str().to_uppercase(), i.area, i.title, i.explain);
            for e in &i.evidence {
                s += &format!("    - {e}\n");
            }
            if !i.manual.is_empty() {
                s += "  To fix it:\n";
                for (n, m) in i.manual.iter().enumerate() {
                    s += &format!("    {}. {m}\n", n + 1);
                }
            }
            if let Some(f) = &i.fix {
                s += &format!("  IPS Watch can fix this: {}\n", f.label());
            }
        }
        s += "\nSites:\n";
        for r in &self.sites {
            if r.ok() {
                s += &format!("  OK    {:28} {} ({} ms)\n", r.site, r.status.map(|c| format!("HTTP {c}")).unwrap_or_default(), r.https_ms.unwrap_or(0));
            } else {
                s += &format!("  FAIL  {:28} {}{}\n", r.site, r.error, if r.cause.is_empty() { String::new() } else { format!(" - {}", r.cause) });
            }
        }
        if !self.gateways.is_empty() {
            s += "\nGateways (last 24 h / 7 days):\n";
            for g in &self.gateways {
                s += &format!(
                    "  {:22} monitor {:15} down {}/{}  loss {}/{}  delay {}\n",
                    g.name, g.monitor_ip, g.down_24h, g.down_7d, g.loss_24h, g.loss_7d, g.delay_24h
                );
            }
        }
        if !self.changes.is_empty() {
            s += &format!("\nChanged since the baseline ({}, firmware {}):\n", self.baseline_at, self.baseline_version);
            for c in self.changes.iter().take(60) {
                s += &format!("  {}: {} -> {}\n", c.key, show(&c.before), show(&c.after));
            }
        }
        for e in &self.errors {
            s += &format!("\n(could not check: {e})");
        }
        s
    }
}

fn show(v: &str) -> &str {
    if v.is_empty() {
        "(none)"
    } else {
        v
    }
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

// ------------------------------------------------------------------ clock

fn check_clock(cfg: &Config, api: &OPNsense, services: &[(String, String, bool)], rep: &mut Report) {
    let before = Utc::now();
    let fw = match api.server_time() {
        Ok(t) => t,
        Err(e) => {
            rep.errors.push(format!("firewall clock: {e:#}"));
            return;
        }
    };
    // The Date header has 1 s resolution; compare with the middle of the request.
    let mid = before + (Utc::now() - before) / 2;
    let offset = (fw - mid).num_seconds();
    rep.clock_offset_s = Some(offset);
    let running = |n: &str| services.iter().any(|(name, _, r)| name == n && *r);
    let time_services: Vec<&str> = ["ntpd", "chronyd"].into_iter().filter(|n| running(n)).collect();
    if offset.abs() > cfg.troubleshoot.clock_tolerance_seconds {
        let fix = time_services.first().map(|s| Fix::ResyncClock { service: s.to_string() });
        rep.issues.push(
            Issue::new(
                "Clock",
                if offset.abs() > 3600 { Severity::High } else { Severity::Medium },
                format!("The firewall's clock is {} {}", human_secs(offset.abs()), if offset < 0 { "behind" } else { "ahead" }),
                "A wrong clock breaks HTTPS certificate checks, DNSSEC, CrowdSec check-ins and makes every log time \
                 misleading. It usually happens after restoring a VM snapshot (the clock goes back to when the snapshot \
                 was taken) or a long pause of the VM, and time services won't jump that far by themselves.",
            )
            .evidence([
                format!("firewall: {} UTC", fw.format("%Y-%m-%d %H:%M:%S")),
                format!("this PC:  {} UTC", mid.format("%Y-%m-%d %H:%M:%S")),
                format!("time services running: {}", if time_services.is_empty() { "none".to_string() } else { time_services.join(", ") }),
            ])
            .manual(&[
                "Click the fix button, or in a firewall shell run: service ntpd onestop; ntpd -gq; service ntpd onestart",
                "Check Services > Network Time > General has reachable servers (e.g. 0.opnsense.pool.ntp.org).",
                "If the firewall runs in a VM: install the os-qemu-guest-agent plugin (Proxmox) so the clock is corrected after a restore.",
            ])
            .fix(fix),
        );
    }
    if time_services.len() > 1 {
        rep.issues.push(
            Issue::new(
                "Clock",
                Severity::Low,
                "Two time services are running (ntpd and chronyd)",
                "Both try to set the clock and fight over the time-server port, so neither may keep it right.",
            )
            .manual(&[
                "Keep one: if you installed the os-chrony plugin, clear the time servers in Services > Network Time > General so ntpd stops; otherwise remove os-chrony.",
            ]),
        );
    }
}

fn human_secs(s: i64) -> String {
    match s {
        s if s >= 86_400 => format!("{:.1} days", s as f64 / 86_400.0),
        s if s >= 3600 => format!("{:.1} hours", s as f64 / 3600.0),
        s if s >= 60 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

// ------------------------------------------------------------------ services & inline inspection

fn services(api: &OPNsense) -> Result<Vec<(String, String, bool)>> {
    let v = api.get_raw("core/service/search")?;
    Ok(v.get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|r| (s(r, "name"), s(r, "description"), s(r, "running") == "1" || r.get("running").and_then(Value::as_bool) == Some(true)))
        .collect())
}

fn check_services(cfg: &Config, svcs: &[(String, String, bool)], rep: &mut Report) {
    let ignore: BTreeSet<String> = cfg.health.ignore_services.iter().map(|x| x.trim().to_lowercase()).collect();
    for (name, desc, running) in svcs {
        if *running || ignore.contains(&name.to_lowercase()) {
            continue;
        }
        let important = ["unbound", "dpinger", "suricata", "ntpd", "chronyd", "dhcpd", "kea", "crowdsec", "openvpn", "wireguard", "haproxy"]
            .iter()
            .any(|k| name.to_lowercase().contains(k));
        rep.issues.push(
            Issue::new(
                "Services",
                if important { Severity::High } else { Severity::Medium },
                format!("{desc} ({name}) is not running"),
                "A stopped service means the feature it provides (DNS, DHCP, IPS, VPN...) is off.",
            )
            .manual(&["Start it in System > Diagnostics > Services and check System > Log Files > General for why it stopped."])
            .fix(Some(Fix::RestartService { name: name.clone(), description: desc.clone() })),
        );
    }
}

fn check_inline(api: &OPNsense, svcs: &[(String, String, bool)], rep: &mut Report) {
    let ids = api.get_raw("ids/settings/get").ok();
    let general = ids.as_ref().and_then(|v| v.pointer("/ids/general"));
    let on = |k: &str| general.map(|g| s(g, k) == "1").unwrap_or(false);
    let ips_inline = on("enabled") && on("ips");
    let zen = svcs.iter().any(|(n, d, r)| *r && (n.to_lowercase().contains("sensei") || d.to_lowercase().contains("zenarmor")));
    if ips_inline && zen {
        rep.issues.push(
            Issue::new(
                "Inspection",
                Severity::Medium,
                "Suricata IPS and Zenarmor are both inspecting traffic inline",
                "Both use netmap to sit in the traffic path. On the same interfaces they can break or stall connections \
                 (especially long-lived HTTPS like AI chat apps and video calls), and Zenarmor's own app/web policies can \
                 block sites by category.",
            )
            .manual(&[
                "Test: stop Zenarmor (Zenarmor > Dashboard > stop engine) and retry the failing site. If it works, check Zenarmor's policies (app controls / web categories, e.g. AI) or keep only one inline engine per interface.",
                "Otherwise put Suricata on WAN only and Zenarmor on LAN only.",
            ]),
        );
    }
    if ips_inline {
        if let Ok(v) = api.get_raw("interfaces/settings/get") {
            let st = v.get("settings").cloned().unwrap_or_default();
            let off: Vec<&str> = [("disablechecksumoffloading", "checksum"), ("disablesegmentationoffloading", "TSO"), ("disablelargereceiveoffloading", "LRO")]
                .into_iter()
                .filter(|(k, _)| s(&st, k) != "1")
                .map(|(_, l)| l)
                .collect();
            if !off.is_empty() {
                rep.issues.push(
                    Issue::new(
                        "Inspection",
                        Severity::High,
                        format!("Hardware offloading is on ({}) while the IPS runs inline", off.join(", ")),
                        "Inline IPS (netmap) needs hardware offloading off; with it on, large packets get dropped and \
                         HTTPS connections hang or fail. Firmware updates and config restores can switch it back on.",
                    )
                    .manual(&["Interfaces > Settings: tick Disable hardware checksum offload, TSO and LRO, save, then reboot the firewall."]),
                );
            }
        }
    }
}

// ------------------------------------------------------------------ sites

fn is_sinkhole(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified() || v.is_loopback(),
        IpAddr::V6(v) => v.is_unspecified() || v.is_loopback(),
    }
}

fn check_site(site: &str, timeout: Duration) -> SiteResult {
    let host = site.trim().trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("").to_string();
    let mut r = SiteResult { site: host.clone(), ..Default::default() };
    let t = Instant::now();
    let addrs: Vec<std::net::SocketAddr> = match (host.as_str(), 443).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            r.error = format!("DNS lookup failed ({e})");
            return r;
        }
    };
    r.dns_ms = Some(t.elapsed().as_millis());
    r.addresses = addrs.iter().map(|a| a.ip().to_string()).collect::<BTreeSet<_>>().into_iter().collect();
    if addrs.is_empty() {
        r.error = "DNS returned no address".into();
        return r;
    }
    if addrs.iter().all(|a| is_sinkhole(&a.ip())) {
        r.error = format!("DNS answers {} - the name is blocked by a DNS blocklist", addrs[0].ip());
        return r;
    }
    let target = addrs.iter().find(|a| a.is_ipv4()).unwrap_or(&addrs[0]);
    let t = Instant::now();
    match TcpStream::connect_timeout(target, timeout) {
        Ok(_) => r.connect_ms = Some(t.elapsed().as_millis()),
        Err(e) => {
            r.error = format!("can't connect to {}:443 ({e})", target.ip());
            return r;
        }
    }
    let tls = match native_tls::TlsConnector::new() {
        Ok(t) => t,
        Err(e) => {
            r.error = format!("TLS setup failed on this PC ({e})");
            return r;
        }
    };
    let agent = ureq::AgentBuilder::new().tls_connector(std::sync::Arc::new(tls)).timeout(timeout * 2).redirects(0).build();
    let t = Instant::now();
    match agent.get(&format!("https://{host}/")).set("User-Agent", "IPSWatch-troubleshoot").call() {
        Ok(resp) => r.status = Some(resp.status()),
        Err(ureq::Error::Status(code, _)) => r.status = Some(code),
        Err(ureq::Error::Transport(e)) => {
            r.error = format!("HTTPS failed after connecting ({e})");
            return r;
        }
    }
    r.https_ms = Some(t.elapsed().as_millis());
    r
}

// ------------------------------------------------------------------ firewall log

#[derive(Clone, Debug, Default)]
struct LogRow {
    action: String,
    label: String,
    iface: String,
    src: String,
    dst: String,
    dport: String,
    proto: String,
    flags: String,
}

fn log_rows(raw: &[Value]) -> Vec<LogRow> {
    raw.iter()
        .map(|r| LogRow {
            action: s(r, "action"),
            label: s(r, "label"),
            iface: s(r, "interface"),
            src: s(r, "src"),
            dst: s(r, "dst"),
            dport: s(r, "dstport"),
            proto: s(r, "protoname"),
            flags: s(r, "tcpflags"),
        })
        .collect()
}

/// A TCP packet that opens a connection (SYN without ACK); anything else blocked by the default
/// rule belongs to a connection the firewall no longer tracks.
fn is_new_conn(r: &LogRow) -> bool {
    r.proto != "tcp" || (r.flags.contains('S') && !r.flags.contains('A'))
}

fn is_default_deny(label: &str) -> bool {
    let l = label.to_lowercase();
    l.contains("default deny") || l.contains("state violation")
}

fn noise(r: &LogRow) -> bool {
    // Multicast / broadcast discovery chatter.
    r.dst.starts_with("224.") || r.dst.starts_with("239.") || r.dst.starts_with("ff0") || r.dst.ends_with(".255")
}

fn top<K: Ord + Clone>(m: &HashMap<K, usize>, n: usize) -> Vec<(K, usize)> {
    let mut v: Vec<(K, usize)> = m.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn check_blocks(cfg: &Config, rows: &[LogRow], rep: &mut Report) {
    let Ok(nets) = cfg.detect.nets() else { return };
    let lan: Vec<&LogRow> = rows.iter().filter(|r| r.action == "block" && nets.is_internal(&r.src) && !noise(r)).collect();
    // Rule blocks of new connections, per rule.
    let mut by_rule: BTreeMap<String, Vec<&LogRow>> = BTreeMap::new();
    for r in lan.iter().filter(|r| is_new_conn(r)) {
        by_rule.entry(if r.label.is_empty() { "(unnamed rule)".into() } else { r.label.clone() }).or_default().push(r);
    }
    for (rule, hits) in &by_rule {
        if hits.len() < 5 {
            continue;
        }
        let mut hosts = HashMap::new();
        let mut dests = HashMap::new();
        for h in hits {
            *hosts.entry(h.src.clone()).or_insert(0) += 1;
            *dests.entry(format!("{}:{} {}", h.dst, h.dport, h.proto)).or_insert(0) += 1;
        }
        let default = is_default_deny(rule);
        rep.issues.push(
            Issue::new(
                "Blocked traffic",
                if hits.len() >= 50 { Severity::Medium } else { Severity::Low },
                if default {
                    format!("{} new connections from your network matched no allow rule", hits.len())
                } else {
                    format!("Rule \"{rule}\" blocked {} new connections from your network", hits.len())
                },
                if default {
                    "Nothing allows this traffic, so the firewall's default rule drops it. If these devices should reach \
                     those destinations, an allow rule is missing (or was lost in a restore)."
                } else {
                    "A block rule is stopping your own devices. Fine if intended; if something isn't working, this rule is \
                     the first suspect."
                },
            )
            .evidence(
                top(&hosts, 5)
                    .into_iter()
                    .map(|(h, n)| format!("from {h}: {n}"))
                    .chain(top(&dests, 6).into_iter().map(|(d, n)| format!("to {d}: {n}"))),
            )
            .manual(&["Firewall > Log Files > Live View, filter on the device's address, to see each block; adjust the rule in Firewall > Rules."]),
        );
    }
    // Dropped packets of existing connections.
    let lost: Vec<&&LogRow> = lan.iter().filter(|r| !is_new_conn(r) && is_default_deny(&r.label)).collect();
    let total_lan_tcp = rows.iter().filter(|r| nets.is_internal(&r.src) && r.proto == "tcp").count().max(1);
    if lost.len() >= 50 {
        let mut dests = HashMap::new();
        let mut ifaces = HashMap::new();
        for r in &lost {
            *dests.entry(format!("{}:{}", r.dst, r.dport)).or_insert(0) += 1;
            *ifaces.entry(r.iface.clone()).or_insert(0) += 1;
        }
        let pct = lost.len() * 100 / total_lan_tcp;
        rep.issues.push(
            Issue::new(
                "Blocked traffic",
                if pct >= 10 { Severity::Medium } else { Severity::Low },
                format!("{} packets of already-open connections were dropped ({pct}% of your devices' TCP in the log)", lost.len()),
                "These belong to connections the firewall had stopped tracking (lost state). A few are normal when \
                 connections close. Many means connections are being cut: a WAN failover or gateway restart, a reboot, \
                 a state-table flush, or traffic leaving by one WAN and returning by the other. Long-lived HTTPS (chat \
                 apps, AI apps, video calls) is hit first.",
            )
            .evidence(top(&dests, 6).into_iter().map(|(d, n)| format!("to {d}: {n}")).chain(top(&ifaces, 3).into_iter().map(|(i, n)| format!("on {i}: {n}"))))
            .manual(&[
                "With two WANs: System > Settings > General - untick 'Allow default gateway switching' if you don't need it, and in System > Gateways > Configuration avoid frequent failovers (see Gateway history).",
                "Firewall > Settings > Advanced: keep 'Sticky connections' on for multi-WAN load balancing.",
            ]),
        );
    }
}

// ------------------------------------------------------------------ gateways

fn parse_monitor(line: &str) -> Option<(String, String, String, String)> {
    // " MONITOR: NAME (Addr: 8.8.8.8 Alarm: none -> loss RTT: 90.6 ms RTTd: 26.7 ms Loss: 11.0 %)"
    let rest = line.trim().strip_prefix("MONITOR:")?.trim();
    let (name, rest) = rest.split_once(" (")?;
    let addr = rest.split("Addr: ").nth(1)?.split_whitespace().next()?.to_string();
    let alarm = rest.split("Alarm: ").nth(1)?;
    let (from, rest) = alarm.split_once(" -> ")?;
    let to = rest.split_whitespace().next()?.to_string();
    let detail = rest.split_once(' ').map(|x| x.1.trim_end_matches(')').to_string()).unwrap_or_default();
    Some((name.trim().to_string(), addr, format!("{from} -> {to}"), detail))
}

fn check_gateways(api: &OPNsense, rep: &mut Report) {
    let v = match api.post_raw("diagnostics/log/core/gateways", json!({"current": 1, "rowCount": 2000, "searchPhrase": "MONITOR"})) {
        Ok(v) => v,
        Err(e) => {
            rep.errors.push(format!("gateway log: {e:#}"));
            return;
        }
    };
    let now = Utc::now();
    let mut gws: BTreeMap<String, GatewayHistory> = BTreeMap::new();
    for r in v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default() {
        let Some((name, addr, change, detail)) = parse_monitor(&s(&r, "line")) else { continue };
        let ts = s(&r, "timestamp");
        let age = DateTime::parse_from_rfc3339(&ts).map(|t| now - t.with_timezone(&Utc)).unwrap_or(chrono::Duration::days(999));
        let g = gws.entry(name.clone()).or_insert_with(|| GatewayHistory { name, monitor_ip: addr.clone(), ..Default::default() });
        let to = change.rsplit(' ').next().unwrap_or("");
        let d24 = age <= chrono::Duration::hours(24);
        let d7 = age <= chrono::Duration::days(7);
        match to {
            "down" => {
                g.down_24h += d24 as usize;
                g.down_7d += d7 as usize;
            }
            "loss" => {
                g.loss_24h += d24 as usize;
                g.loss_7d += d7 as usize;
            }
            "delay" => g.delay_24h += d24 as usize,
            _ => {}
        }
        if g.events.len() < 30 {
            g.events.push((crate::local_time(&ts), change, detail));
        }
    }
    let monitors: HashMap<String, Vec<String>> = gws.values().fold(HashMap::new(), |mut m, g| {
        m.entry(g.monitor_ip.clone()).or_default().push(g.name.clone());
        m
    });
    for g in gws.values() {
        let bad = g.down_24h + g.loss_24h;
        if g.down_24h == 0 && g.loss_24h < 3 && (g.down_7d >= 3 || g.loss_7d >= 10) {
            rep.issues.push(
                Issue::new(
                    "Internet",
                    Severity::Low,
                    format!("{} was unstable this week ({} down, {} packet-loss alarms in 7 days)", g.name, g.down_7d, g.loss_7d),
                    "Each alarm can switch traffic to the other WAN and cut open connections. Quiet in the last 24 h.",
                )
                .evidence(g.events.iter().take(5).map(|(t, c, d)| format!("{t}  {c}  {d}")))
                .manual(&[
                    "System > Gateways > Configuration > edit the gateway: for a satellite / wireless WAN raise the packet-loss thresholds and the 'Time period' so short blips don't count.",
                    "Make sure each gateway has its own dependable Monitor IP.",
                ]),
            );
        }
        if g.down_24h > 0 || g.loss_24h >= 3 {
            rep.issues.push(
                Issue::new(
                    "Internet",
                    if g.down_24h >= 3 { Severity::High } else { Severity::Medium },
                    format!("{} dropped out {} time(s) in the last 24 h ({} down, {} packet-loss alarms)", g.name, bad, g.down_24h, g.loss_24h),
                    "The gateway monitor pings a target through this WAN; when replies stop or get lost it marks the WAN \
                     bad, moves traffic to the other WAN and existing connections break. Either the line really drops, or \
                     the monitor target is unreliable.",
                )
                .evidence(g.events.iter().take(6).map(|(t, c, d)| format!("{t}  {c}  {d}")))
                .manual(&[
                    "System > Gateways > Configuration > edit the gateway: use a dependable Monitor IP (e.g. 1.1.1.1 for one WAN, 9.9.9.9 for the other) - never the same one on both.",
                    "For a satellite / wireless WAN, raise the loss and latency thresholds and the 'Time period' so short blips don't trigger failover.",
                    "If the line itself drops: check the modem / dish and the ISP.",
                ]),
            );
        }
    }
    for (ip, names) in monitors.iter().filter(|(_, n)| n.len() > 1) {
        rep.issues.push(
            Issue::new(
                "Internet",
                Severity::Low,
                format!("{} use the same monitor IP {ip}", names.join(" and ")),
                "If that one address has a problem, every WAN looks down at once.",
            )
            .manual(&["System > Gateways > Configuration: give each gateway its own Monitor IP."]),
        );
    }
    rep.gateways = gws.into_values().collect();
}

// ------------------------------------------------------------------ baseline / changes

/// Flatten an API answer into "path = value" pairs. OPNsense option lists
/// (`{"x": {"value": .., "selected": 1}}`) become the selected keys.
pub fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(m) if !m.is_empty() && m.values().all(|x| x.get("selected").is_some()) => {
            let sel: Vec<&str> = m.iter().filter(|(_, x)| matches!(x.get("selected"), Some(Value::Number(n)) if n.as_i64() == Some(1)) || x.get("selected") == Some(&Value::Bool(true)) || x.get("selected") == Some(&json!("1"))).map(|(k, _)| k.as_str()).filter(|k| !k.is_empty()).collect();
            out.insert(prefix.to_string(), sel.join(","));
        }
        Value::Object(m) => {
            for (k, x) in m {
                flatten(&if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") }, x, out);
            }
        }
        Value::Array(a) => {
            out.insert(prefix.to_string(), a.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(","));
        }
        Value::String(x) => {
            out.insert(prefix.to_string(), x.clone());
        }
        Value::Null => {}
        other => {
            out.insert(prefix.to_string(), other.to_string());
        }
    }
}

fn capture(api: &OPNsense, svcs: &[(String, String, bool)], version: &str) -> Baseline {
    let mut items = BTreeMap::new();
    items.insert("firmware.version".into(), version.to_string());
    for (name, desc, running) in svcs {
        items.insert(format!("service.{name}"), if *running { "running".into() } else { format!("stopped ({desc})") });
    }
    // Settings pages whose changes most often break connectivity.
    for (label, path, pointer) in [
        ("ids", "ids/settings/get", "/ids/general"),
        ("offload", "interfaces/settings/get", "/settings"),
        ("unbound.general", "unbound/settings/get", "/unbound/general"),
        ("unbound.forwarding", "unbound/settings/get", "/unbound/forwarding"),
        ("unbound.dnsbl", "unbound/settings/get", "/unbound/dnsbl"),
    ] {
        if let Ok(v) = api.get_raw(path) {
            if let Some(x) = v.pointer(pointer) {
                flatten(label, x, &mut items);
            }
        }
    }
    if let Ok(v) = api.get_raw("routes/gateway/status") {
        for g in v.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
            items.insert(format!("gateway.{}", s(&g, "name")), format!("monitor {}", s(&g, "monitor")));
        }
    }
    if let Ok(v) = api.post_raw("firewall/filter/search_rule", json!({"current": 1, "rowCount": -1, "searchPhrase": ""})) {
        for r in v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default() {
            let id = s(&r, "uuid");
            let key = format!("rule.{}", if s(&r, "description").is_empty() { id.clone() } else { s(&r, "description") });
            items.insert(key, format!("{} {} {} -> {} {} {}", if s(&r, "enabled") == "1" { "on" } else { "OFF" }, s(&r, "action"), s(&r, "source_net"), s(&r, "destination_net"), s(&r, "destination_port"), s(&r, "interface")));
        }
    }
    // Volatile values that change on their own.
    items.retain(|k, _| {
        if k.ends_with("UpdateCron") {
            return false;
        }
        !k.contains("dnsbl.blocklist") || k.ends_with(".enabled") || k.ends_with(".type")
    });
    Baseline { at: crate::iso(Utc::now()), version: version.to_string(), items }
}

pub fn diff(before: &Baseline, after: &Baseline) -> Vec<Change> {
    let keys: BTreeSet<&String> = before.items.keys().chain(after.items.keys()).collect();
    keys.into_iter()
        .filter_map(|k| {
            let (b, a) = (before.items.get(k).cloned().unwrap_or_default(), after.items.get(k).cloned().unwrap_or_default());
            (b != a).then(|| Change { key: k.clone(), before: b, after: a })
        })
        .collect()
}

fn load<T: for<'de> Deserialize<'de>>(store: &Store, k: &str) -> Option<T> {
    store.get_kv(k).ok().flatten().and_then(|v| serde_json::from_str(&v).ok())
}

/// Make the current firewall state the baseline future runs compare against.
pub fn set_baseline(store: &Store) -> Result<()> {
    let last: Baseline = load(store, LAST_STATE_KV).ok_or_else(|| anyhow!("run Troubleshoot once first"))?;
    store.set_kv(BASELINE_KV, &serde_json::to_string(&last)?)
}

fn check_changes(store: &Store, api: &OPNsense, svcs: &[(String, String, bool)], rep: &mut Report) -> Result<()> {
    let now = capture(api, svcs, &rep.firmware);
    let last: Option<Baseline> = load(store, LAST_STATE_KV);
    let mut base: Option<Baseline> = load(store, BASELINE_KV);
    // A firmware change since the last run: what we saw just before it is the baseline.
    if let Some(l) = &last {
        if !l.version.is_empty() && l.version != now.version {
            store.set_kv(BASELINE_KV, &serde_json::to_string(l)?)?;
            base = Some(l.clone());
        }
    }
    if base.is_none() {
        store.set_kv(BASELINE_KV, &serde_json::to_string(&now)?)?;
        base = Some(now.clone());
    }
    store.set_kv(LAST_STATE_KV, &serde_json::to_string(&now)?)?;
    let base = base.unwrap_or_default();
    rep.baseline_at = crate::local_time(&base.at);
    rep.baseline_version = base.version.clone();
    rep.changes = diff(&base, &now);
    if !rep.changes.is_empty() {
        let updated = base.version != now.version;
        let interesting: Vec<&Change> = rep.changes.iter().filter(|c| !c.key.starts_with("firmware.")).collect();
        rep.issues.push(
            Issue::new(
                "Changes",
                if updated { Severity::Medium } else { Severity::Low },
                if updated {
                    format!("Firmware {} -> {}: {} setting(s) changed", base.version, now.version, interesting.len())
                } else {
                    format!("{} setting(s) differ from the baseline of {}", interesting.len(), crate::local_time(&base.at))
                },
                "If something broke since then, look here first: settings switched by an update, removed by a snapshot \
                 rollback, or changed by hand. When everything works, click 'Mark as baseline' so later problems \
                 show only new changes.",
            )
            .evidence(interesting.iter().take(12).map(|c| format!("{}: {} -> {}", c.key, show(&c.before), show(&c.after)))),
        );
    }
    Ok(())
}

// ------------------------------------------------------------------ run

/// Run every check. Read-only: nothing on the firewall changes.
pub fn run(cfg: &Config, store: &Store, api: &OPNsense) -> Result<Report> {
    let mut rep = Report { at: crate::local_time(&crate::iso(Utc::now())), ..Default::default() };
    // Site checks from this PC run while the firewall is queried.
    let sites = cfg.troubleshoot.sites.clone();
    let site_thread = std::thread::spawn(move || {
        sites.iter().filter(|x| !x.trim().is_empty()).map(|x| check_site(x, Duration::from_secs(6))).collect::<Vec<_>>()
    });
    rep.firmware = api
        .get_raw("core/firmware/info")
        .ok()
        .and_then(|v| v.pointer("/product/product_version").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    let svcs = services(api).unwrap_or_else(|e| {
        rep.errors.push(format!("services: {e:#}"));
        vec![]
    });
    check_clock(cfg, api, &svcs, &mut rep);
    check_services(cfg, &svcs, &mut rep);
    check_inline(api, &svcs, &mut rep);
    check_gateways(api, &mut rep);
    let rows = match api.firewall_log(cfg.troubleshoot.log_rows.max(200)) {
        Ok(r) => log_rows(&r),
        Err(e) => {
            rep.errors.push(format!("firewall log: {e:#}"));
            vec![]
        }
    };
    check_blocks(cfg, &rows, &mut rep);
    if let Err(e) = check_changes(store, api, &svcs, &mut rep) {
        rep.errors.push(format!("baseline: {e:#}"));
    }
    rep.sites = site_thread.join().unwrap_or_default();
    explain_sites(store, &rows, &mut rep);
    rep.issues.sort_by_key(|i| std::cmp::Reverse(i.severity));
    Ok(rep)
}

/// Name the cause of each failing site from the firewall log and IPS alerts.
fn explain_sites(store: &Store, rows: &[LogRow], rep: &mut Report) {
    let events = store.recent_events(5000, "").unwrap_or_default();
    let mut failed = vec![];
    for site in rep.sites.iter_mut().filter(|x| !x.ok()) {
        let ips: BTreeSet<&str> = site.addresses.iter().map(String::as_str).collect();
        let dropped: Vec<_> = events.iter().filter(|e| e.was_dropped() && (ips.contains(e.dest_ip.as_str()) || ips.contains(e.src_ip.as_str()))).collect();
        let blocks: Vec<&LogRow> = rows.iter().filter(|r| r.action == "block" && ips.contains(r.dst.as_str())).collect();
        site.cause = if let Some(e) = dropped.first() {
            format!("the IPS dropped it: [{}] {}", e.sid.unwrap_or(0), e.signature)
        } else if let Some(b) = blocks.iter().find(|b| is_new_conn(b)) {
            format!("firewall rule \"{}\" blocked it", b.label)
        } else if !blocks.is_empty() {
            "the firewall dropped packets of the connection (lost state)".into()
        } else if site.error.contains("DNS") {
            "DNS".into()
        } else {
            String::new()
        };
        failed.push(site.clone());
    }
    let working = rep.sites.iter().filter(|x| x.ok()).count();
    for site in failed {
        let all_down = working == 0;
        let mut issue = Issue::new(
            "Sites",
            if all_down { Severity::Critical } else { Severity::High },
            format!("{} doesn't work: {}", site.site, site.error),
            if all_down {
                "None of the test sites work from this PC, so the internet connection itself is down (see Internet / Clock / Services above)."
            } else if site.error.contains("blocklist") {
                "Your DNS server answers with a blocked address, so a DNS blocklist (Technitium, Unbound DNSBL or AdGuard) contains this name or one it depends on."
            } else if site.error.contains("DNS") {
                "The name can't be resolved: the DNS server is down, can't reach upstream, or DNSSEC fails (a wrong firewall clock causes that)."
            } else if site.error.contains("HTTPS") {
                "The connection opens but the secure (TLS) handshake or the reply is cut. Typical causes: the inline IPS or Zenarmor dropping it, hardware offloading with inline IPS, or an MTU problem on the WAN."
            } else {
                "The site can't be reached on port 443: something in the path is blocking or dropping it."
            },
        )
        .evidence(std::iter::once(format!("addresses: {}", site.addresses.join(", "))).chain((!site.cause.is_empty()).then(|| format!("cause: {}", site.cause))));
        if site.cause.starts_with("the IPS") {
            issue = issue.manual(&[
                "Services > Intrusion Detection > Administration > Rules: search the SID and set its action to Alert (or add it to IPS Watch's ignore list if it's a false positive).",
            ]);
        } else if site.error.contains("blocklist") {
            issue = issue.manual(&["Add the name to the allow list of your DNS blocklist (Technitium: Settings > Blocking > Allowed; Unbound: Services > Unbound DNS > Blocklist > Allowlist)."]);
        }
        rep.issues.push(issue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dpinger_lines() {
        let (n, a, c, d) = parse_monitor(" MONITOR: WAN2_DHCP (Addr: 8.8.8.8 Alarm: none -> loss RTT: 90.6 ms RTTd: 26.7 ms Loss: 11.0 %)").unwrap();
        assert_eq!((n.as_str(), a.as_str(), c.as_str()), ("WAN2_DHCP", "8.8.8.8", "none -> loss"));
        assert!(d.contains("Loss: 11.0 %"));
        assert!(parse_monitor(" Reloaded gateway watcher configuration on SIGHUP").is_none());
    }

    #[test]
    fn flatten_collapses_option_lists_and_diffs() {
        let v = json!({"mode": {"netmap": {"value": "Netmap", "selected": 1}, "pcap": {"value": "PCAP", "selected": 0}}, "ips": "1", "homenet": ["10.0.0.0/8"]});
        let mut a = BTreeMap::new();
        flatten("ids", &v, &mut a);
        assert_eq!(a["ids.mode"], "netmap");
        assert_eq!(a["ids.ips"], "1");
        assert_eq!(a["ids.homenet"], "10.0.0.0/8");
        let mut b = a.clone();
        b.insert("ids.ips".into(), "0".into());
        b.remove("ids.homenet");
        let d = diff(&Baseline { items: a, ..Default::default() }, &Baseline { items: b, ..Default::default() });
        assert_eq!(d.len(), 2);
        assert!(d.iter().any(|c| c.key == "ids.ips" && c.before == "1" && c.after == "0"));
    }

    #[test]
    fn new_connection_vs_lost_state() {
        let syn = LogRow { proto: "tcp".into(), flags: "S".into(), ..Default::default() };
        let ack = LogRow { proto: "tcp".into(), flags: "PA".into(), ..Default::default() };
        let udp = LogRow { proto: "udp".into(), ..Default::default() };
        assert!(is_new_conn(&syn) && !is_new_conn(&ack) && is_new_conn(&udp));
        assert!(is_default_deny("Default deny / state violation rule"));
    }

    #[test]
    fn sinkhole_answers() {
        assert!(is_sinkhole(&"0.0.0.0".parse().unwrap()));
        assert!(is_sinkhole(&"::".parse().unwrap()));
        assert!(!is_sinkhole(&"160.79.104.10".parse().unwrap()));
    }
}
