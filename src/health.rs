//! Firewall health, exposure audit, new devices and config changes.
//!
//! One `run` per interval collects a [`Snapshot`] for the Health page and turns problems into
//! findings (kinds `health`, `exposure`, `device`, `config`) so they share the Findings list,
//! notifications, toasts and the tray icon with IPS findings.

use anyhow::Result;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::config::{Config, Nets, Severity};
use crate::opnsense::OPNsense;
use crate::store::{Finding, Store};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Gateway {
    pub name: String,
    pub status: String,
    pub delay_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub ok: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub description: String,
    pub running: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Exposed {
    /// "port forward", "WAN pass rule" or "seen in firewall log"
    pub source: String,
    pub interface: String,
    pub target: String,
    pub port: String,
    pub protocol: String,
    /// Port forward without an enabled pass rule for the same target/port (probably blocked).
    pub blocked: bool,
    pub hits: usize,
    pub note: String,
}

impl Exposed {
    /// Short status for tables.
    pub fn status_label(&self) -> String {
        match (self.blocked, self.source.as_str()) {
            (true, "port forward") => "forwarded, no pass rule".into(),
            (true, _) => "not reachable".into(),
            (false, _) if self.hits > 0 => format!("OPEN · {} hits", self.hits),
            (false, _) => "OPEN".into(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Device {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub vendor: String,
    pub interface: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigChange {
    pub time: String,
    pub user: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub at: String,
    pub hostname: String,
    pub version: String,
    pub uptime: String,
    pub boottime: String,
    pub loadavg: String,
    pub gateways: Vec<Gateway>,
    pub services: Vec<Service>,
    pub memory_pct: Option<f64>,
    pub states: Option<(u64, u64)>,
    pub disks: Vec<(String, u64)>,
    pub system_warnings: Vec<(String, String, String)>, // (title, status, message)
    pub firmware: String,
    pub exposure: Vec<Exposed>,
    pub devices: Vec<Device>,
    pub new_devices: usize,
    pub config_changes: Vec<ConfigChange>,
    /// None when CrowdSec isn't installed (or the check is off).
    pub crowdsec: Option<crate::crowdsec::Status>,
    /// Checks that couldn't run (missing privilege, endpoint not present...).
    pub errors: Vec<String>,
}

/// A problem found by a check; becomes (or updates) a finding.
#[derive(Clone, Debug)]
pub struct Problem {
    pub key: String,
    pub kind: &'static str,
    pub severity: Severity,
    pub title: String,
    pub reasons: Vec<String>,
    pub targets: Vec<String>,
}

impl Problem {
    pub fn health(key: &str, severity: Severity, title: &str, reasons: Vec<String>) -> Self {
        Problem { key: key.into(), kind: "health", severity, title: title.into(), reasons, targets: vec![] }
    }
}

fn score_for(s: Severity) -> i64 {
    match s {
        Severity::Critical => 130,
        Severity::High => 90,
        Severity::Medium => 60,
        Severity::Low => 30,
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

fn num_prefix(text: &str) -> Option<f64> {
    let t: String = text.trim().chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
    t.parse().ok()
}

fn rows(v: &Value) -> Vec<Value> {
    v.get("rows").or_else(|| v.get("items")).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn all_rows(api: &OPNsense, path: &str) -> Result<Vec<Value>> {
    Ok(rows(&api.post_raw(path, json!({"current": 1, "rowCount": -1, "searchPhrase": ""}))?))
}

// ---------------------------------------------------------------- individual checks

fn check_gateways(cfg: &Config, api: &OPNsense, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let h = &cfg.health;
    let v = api.get_raw("routes/gateway/status")?;
    for g in v.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
        let status = { let t = s(&g, "status_translated"); if t.is_empty() { s(&g, "status") } else { t } };
        let delay = num_prefix(&s(&g, "delay"));
        let loss = num_prefix(&s(&g, "loss"));
        let down = { let l = status.to_lowercase(); l.contains("down") || l.contains("offline") };
        let name = s(&g, "name");
        let mut ok = !down;
        if down {
            out.push(Problem {
                key: format!("health:gateway:{name}"),
                kind: "health",
                severity: Severity::High,
                title: format!("Gateway {name} is down"),
                reasons: vec![format!("status: {status}"), "traffic fails over to the other WAN if one is configured".into()],
                targets: vec![name.clone()],
            });
        } else if loss.is_some_and(|l| l >= h.gateway_loss_pct) || delay.is_some_and(|d| d >= h.gateway_delay_ms) {
            ok = false;
            out.push(Problem {
                key: format!("health:gateway:{name}"),
                kind: "health",
                severity: Severity::Medium,
                title: format!("Gateway {name} is degraded"),
                reasons: vec![format!(
                    "loss {} (limit {}%), latency {} (limit {} ms)",
                    s(&g, "loss"),
                    h.gateway_loss_pct,
                    s(&g, "delay"),
                    h.gateway_delay_ms
                )],
                targets: vec![name.clone()],
            });
        }
        snap.gateways.push(Gateway { name, status, delay_ms: delay, loss_pct: loss, ok });
    }
    if !snap.gateways.is_empty() && snap.gateways.iter().all(|g| !g.ok && g.status.to_lowercase().contains("down")) {
        out.push(Problem {
            key: "health:gateway:all".into(),
            kind: "health",
            severity: Severity::Critical,
            title: "All gateways are down - no internet".into(),
            reasons: snap.gateways.iter().map(|g| format!("{}: {}", g.name, g.status)).collect(),
            targets: vec![],
        });
    }
    Ok(())
}

fn check_services(cfg: &Config, api: &OPNsense, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let ignore: BTreeSet<String> = cfg.health.ignore_services.iter().map(|x| x.trim().to_lowercase()).collect();
    for r in rows(&api.get_raw("core/service/search")?) {
        let svc = Service {
            name: s(&r, "name"),
            description: s(&r, "description"),
            running: s(&r, "running") == "1" || r.get("running").and_then(Value::as_bool) == Some(true),
        };
        if !svc.running && !ignore.contains(&svc.name.to_lowercase()) {
            out.push(Problem {
                key: format!("health:service:{}", svc.name),
                kind: "health",
                severity: Severity::High,
                title: format!("Service stopped: {} ({})", svc.description, svc.name),
                reasons: vec!["the service is not running".into(), "start it from System > Diagnostics > Services, or ignore it in Settings > Health checks".into()],
                targets: vec![svc.name.clone()],
            });
        }
        snap.services.push(svc);
    }
    snap.services.sort_by_key(|x| (x.running, x.description.to_lowercase()));
    Ok(())
}

fn check_system(cfg: &Config, store: &Store, api: &OPNsense, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let h = &cfg.health;
    if let Ok(info) = api.get_raw("diagnostics/system/system_information") {
        snap.hostname = s(&info, "name");
        snap.version = info.get("versions").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("").into();
    }
    let t = api.get_raw("diagnostics/system/system_time")?;
    snap.uptime = s(&t, "uptime");
    snap.boottime = s(&t, "boottime");
    snap.loadavg = s(&t, "loadavg");
    // Reboot detection: boot time changed since last check.
    if !snap.boottime.is_empty() {
        let prev = store.get_kv("health_boottime")?;
        if prev.as_deref().is_some_and(|p| p != snap.boottime) {
            out.push(Problem {
                key: format!("event:reboot:{}", snap.boottime),
                kind: "health",
                severity: Severity::Medium,
                title: format!("Firewall rebooted ({})", snap.boottime),
                reasons: vec![
                    format!("boot time changed from {} to {}", prev.unwrap_or_default(), snap.boottime),
                    "if nobody rebooted it, check System > Firmware > Reporter for a crash report".into(),
                ],
                targets: vec![],
            });
        }
        store.set_kv("health_boottime", &snap.boottime)?;
    }

    if let Ok(r) = api.get_raw("diagnostics/system/system_resources") {
        let m = r.get("memory").cloned().unwrap_or_default();
        let total = num_prefix(&s(&m, "total")).unwrap_or(0.0);
        let used = num_prefix(&s(&m, "used")).unwrap_or(0.0);
        let arc = num_prefix(&s(&m, "arc")).unwrap_or(0.0); // ZFS cache, freed on demand
        if total > 0.0 {
            let pct = ((used - arc).max(0.0) / total * 100.0).round();
            snap.memory_pct = Some(pct);
            if pct >= h.memory_pct {
                out.push(Problem {
                    key: "health:memory".into(),
                    kind: "health",
                    severity: Severity::Medium,
                    title: format!("Memory use is high ({pct:.0}%)"),
                    reasons: vec![format!("limit {}% (ZFS cache excluded)", h.memory_pct)],
                    targets: vec![],
                });
            }
        }
    }
    if let Ok(st) = api.get_raw("diagnostics/firewall/pf_states") {
        let (cur, lim) = (num_prefix(&s(&st, "current")).unwrap_or(0.0) as u64, num_prefix(&s(&st, "limit")).unwrap_or(0.0) as u64);
        if lim > 0 {
            snap.states = Some((cur, lim));
            let pct = cur as f64 / lim as f64 * 100.0;
            if pct >= h.states_pct {
                out.push(Problem {
                    key: "health:states".into(),
                    kind: "health",
                    severity: Severity::Medium,
                    title: format!("Firewall state table {pct:.0}% full"),
                    reasons: vec![format!("{cur} of {lim} states (limit {}%) - possible flood or state exhaustion attack", h.states_pct)],
                    targets: vec![],
                });
            }
        }
    }
    if let Ok(d) = api.get_raw("diagnostics/system/system_disk") {
        for dev in d.get("devices").and_then(Value::as_array).cloned().unwrap_or_default() {
            let total = dev.get("total_bytes").and_then(Value::as_u64).unwrap_or(0);
            let pct = dev.get("used_pct").and_then(Value::as_u64).unwrap_or(0);
            let mount = s(&dev, "mountpoint");
            if total < (1u64 << 30) || mount.starts_with("/dev") {
                continue;
            }
            if pct >= h.disk_pct as u64 {
                out.push(Problem {
                    key: format!("health:disk:{mount}"),
                    kind: "health",
                    severity: Severity::Medium,
                    title: format!("Disk {mount} is {pct}% full"),
                    reasons: vec![format!("{} used of {} (limit {}%)", s(&dev, "used"), s(&dev, "total"), h.disk_pct)],
                    targets: vec![],
                });
            }
            if mount == "/" || pct >= 5 {
                snap.disks.push((mount, pct));
            }
        }
    }
    if let Ok(st) = api.get_raw("core/system/status") {
        if let Some(subs) = st.get("subsystems").and_then(Value::as_object) {
            for (name, v) in subs {
                let status = s(v, "status");
                if status.eq_ignore_ascii_case("OK") || status.is_empty() {
                    continue;
                }
                let title = { let t = s(v, "title"); if t.is_empty() { name.clone() } else { t } };
                let msg = s(v, "message");
                snap.system_warnings.push((title.clone(), status.clone(), msg.clone()));
                out.push(Problem {
                    key: format!("health:system:{name}"),
                    kind: "health",
                    severity: if status.eq_ignore_ascii_case("ERROR") { Severity::High } else { Severity::Medium },
                    title: format!("Firewall reports: {title}"),
                    reasons: vec![msg, format!("status {status}; see the OPNsense dashboard")],
                    targets: vec![],
                });
            }
        }
    }
    if let Ok(f) = api.get_raw("core/firmware/status") {
        let status = s(&f, "status");
        snap.firmware = match status.as_str() {
            "update" | "upgrade" => s(&f, "status_msg"),
            "none" | "" => "No update check yet (System > Firmware > Check for updates)".into(),
            _ => s(&f, "status_msg"),
        };
        if matches!(status.as_str(), "update" | "upgrade") {
            out.push(Problem {
                key: "health:firmware".into(),
                kind: "health",
                severity: Severity::Low,
                title: "Firmware update available".into(),
                reasons: vec![s(&f, "status_msg")],
                targets: vec![],
            });
        }
    }
    Ok(())
}

/// What's reachable from the internet: port forwards, any-source WAN pass rules, and inbound
/// passes actually seen in the firewall log.
fn check_exposure(cfg: &Config, api: &OPNsense, nets: &Nets, wan_ifaces: &BTreeSet<String>, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let sensitive: BTreeSet<String> = cfg.detect.sensitive_ports.iter().map(|p| p.to_string()).collect();
    let is_wan = |i: &str| wan_ifaces.contains(&i.to_lowercase());

    let rules = all_rows(api, "firewall/filter/search_rule").unwrap_or_default();
    let pass_rules: Vec<&Value> = rules
        .iter()
        .filter(|r| s(r, "action") == "pass" && s(r, "enabled") == "1" && s(r, "direction") != "out")
        .filter(|r| s(r, "interface").split(',').any(is_wan))
        .collect();
    let any_src = |r: &Value| { let x = s(r, "source_net"); x.is_empty() || x == "any" };

    for f in all_rows(api, "firewall/d_nat/search_rule").unwrap_or_default() {
        if f.get("is_automatic").and_then(Value::as_bool) == Some(true) || s(&f, "disabled") == "1" || !s(&f, "interface").split(',').any(is_wan) {
            continue;
        }
        let (target, port) = (s(&f, "target"), { let lp = s(&f, "local-port"); if lp.is_empty() { s(&f, "destination.port") } else { lp } });
        // A forward with its own "pass" association (or a linked rule) is open by itself.
        let allowed = s(&f, "pass") == "1"
            || !s(&f, "associated-rule-id").is_empty()
            || pass_rules.iter().any(|r| s(r, "destination_net") == target && (s(r, "destination_port") == port || s(r, "destination_port").is_empty()));
        let src = s(&f, "source.network");
        snap.exposure.push(Exposed {
            source: "port forward".into(),
            interface: s(&f, "%interface"),
            target: target.clone(),
            port: port.clone(),
            protocol: s(&f, "protocol").to_uppercase(),
            blocked: !allowed,
            hits: 0,
            note: [s(&f, "descr"), if src.is_empty() || src == "any" { String::new() } else { format!("only from {src}") }]
                .into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · "),
        });
    }
    for r in &pass_rules {
        if !any_src(r) {
            continue;
        }
        let already = snap.exposure.iter().any(|e| e.target == s(r, "destination_net") && e.port == s(r, "destination_port"));
        if !already {
            // A pass rule to a LAN address does nothing from the internet without a port forward
            // (no NAT translation reaches it) - typically a leftover rule.
            let dst = s(r, "destination_net");
            let lan_target = dst.parse::<std::net::IpAddr>().is_ok_and(|ip| nets.is_internal(&dst) && !nets.is_own(&dst) && match ip {
                std::net::IpAddr::V4(a) => a.is_private(),
                std::net::IpAddr::V6(_) => false,
            });
            snap.exposure.push(Exposed {
                source: "WAN pass rule".into(),
                interface: s(r, "%interface"),
                target: if dst.is_empty() { "any".into() } else { dst.clone() },
                port: { let p = s(r, "destination_port"); if p.is_empty() { "any".into() } else { p } },
                protocol: s(r, "protocol"),
                blocked: lan_target,
                hits: 0,
                note: if lan_target {
                    [s(r, "description"), "no port forward to it, so not reachable from the internet (leftover rule?)".into()]
                        .into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · ")
                } else {
                    s(r, "description")
                },
            });
        }
    }
    // Observed in the firewall log: external source passed inbound.
    let mut seen: BTreeMap<(String, String, String), (usize, BTreeSet<String>)> = BTreeMap::new();
    for row in api.firewall_log(cfg.firewall.log_limit).unwrap_or_default() {
        let get = |k: &str| s(&row, k);
        if get("action") != "pass" || get("dir") != "in" || get("dstport").is_empty() {
            continue;
        }
        let (src, dst, port) = (get("src"), get("dst"), get("dstport"));
        if nets.is_internal(&src) || port.parse::<u16>().is_ok_and(|p| cfg.firewall.correlate_ignore_ports.contains(&p)) {
            continue;
        }
        let e = seen.entry((dst, port, get("protoname").to_uppercase())).or_default();
        e.0 += 1;
        e.1.insert(src);
    }
    for ((dst, port, proto), (hits, srcs)) in seen {
        if let Some(x) = snap.exposure.iter_mut().find(|e| e.port == port && (e.target == dst || nets.is_own(&dst))) {
            x.hits += hits;
            x.blocked = false;
        } else {
            snap.exposure.push(Exposed {
                source: "seen in firewall log".into(),
                interface: String::new(),
                target: dst,
                port,
                protocol: proto,
                blocked: false,
                hits,
                note: format!("{} external source(s) recently", srcs.len()),
            });
        }
    }

    for e in &snap.exposure {
        if e.blocked {
            continue;
        }
        let ports: Vec<&str> = e.port.split([',', '-', ':']).collect();
        let (sev, why) = if ports.contains(&"53") {
            (Severity::High, "DNS open to the internet: can be abused for DNS amplification attacks and leaks your resolver".to_string())
        } else if ports.iter().any(|p| sensitive.contains(*p)) || e.port == "any" {
            (Severity::High, format!("sensitive service port {} reachable from the internet", e.port))
        } else {
            (Severity::Low, format!("port {} reachable from the internet - fine if intended (acknowledge it)", e.port))
        };
        out.push(Problem {
            key: format!("exposure:{}:{}", e.target, e.port),
            kind: "exposure",
            severity: sev,
            title: format!("Exposed to the internet: {}:{} ({})", e.target, e.port, e.protocol),
            reasons: vec![why, format!("via {}{}", e.source, if e.interface.is_empty() { String::new() } else { format!(" on {}", e.interface) })]
                .into_iter()
                .chain((e.hits > 0).then(|| format!("{} inbound connection(s) passed recently", e.hits)))
                .chain((!e.note.is_empty()).then(|| e.note.clone()))
                .collect(),
            targets: vec![format!("{}:{}", e.target, e.port)],
        });
    }
    snap.exposure.sort_by_key(|e| (e.blocked, e.target.clone(), e.port.clone()));
    Ok(())
}

/// Locally administered (randomised / private Wi-Fi) MAC address.
pub fn is_random_mac(mac: &str) -> bool {
    mac.get(1..2).and_then(|c| u8::from_str_radix(c, 16).ok()).is_some_and(|n| n & 0x2 != 0)
}

fn check_devices(cfg: &Config, store: &Store, api: &OPNsense, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let names: HashMap<String, String> = all_rows(api, "dnsmasq/leases/search")
        .unwrap_or_default()
        .iter()
        .filter(|l| !s(l, "hwaddr").is_empty() && !s(l, "hostname").is_empty())
        .map(|l| (s(l, "hwaddr").to_lowercase(), s(l, "hostname")))
        .collect();
    let baselined_at = store.get_kv("devices_baselined")?.and_then(|t| crate::parse_iso(&t));
    let baselined = baselined_at.is_some();
    // ARP only lists recently active devices, so keep learning quietly for a while after the baseline.
    let learning = baselined_at.is_some_and(|t| chrono::Utc::now() - t < chrono::Duration::hours(cfg.health.device_learning_hours as i64));
    let now = crate::now_iso();
    let mut new = Vec::new();
    for a in all_rows(api, "diagnostics/interface/search_arp")? {
        let mac = s(&a, "mac").to_lowercase();
        if mac.len() != 17 || a.get("permanent").and_then(Value::as_bool) == Some(true) || mac == "ff:ff:ff:ff:ff:ff" {
            continue;
        }
        let hostname = { let h = s(&a, "hostname"); if h.is_empty() { names.get(&mac).cloned().unwrap_or_default() } else { h } };
        let dev = Device {
            mac: mac.clone(),
            ip: s(&a, "ip"),
            hostname,
            vendor: s(&a, "manufacturer"),
            interface: s(&a, "intf_description"),
            first_seen: now.clone(),
            last_seen: now.clone(),
        };
        if store.upsert_device(&dev)? && baselined && !learning && cfg.health.device_alerts {
            new.push(dev);
        }
    }
    if !baselined {
        store.set_kv("devices_baselined", &now)?;
        info!("Recorded the current devices as the baseline; new ones will be reported from now on");
    }
    for d in &new {
        let label = [d.hostname.as_str(), d.vendor.as_str()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
        out.push(Problem {
            key: format!("device:{}", d.mac),
            kind: "device",
            severity: Severity::Medium,
            title: format!("New device on {}: {} ({})", if d.interface.is_empty() { "the network" } else { &d.interface }, d.ip, if label.is_empty() { "unknown" } else { &label }),
            reasons: [
                Some(format!("MAC {} first seen now", d.mac)),
                is_random_mac(&d.mac).then(|| "randomised (private) MAC - phones and laptops use these per network".to_string()),
                Some("acknowledge it if you know the device".into()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            targets: vec![d.ip.clone()],
        });
    }
    snap.new_devices = new.len();
    snap.devices = store.list_devices(500)?;
    Ok(())
}

fn check_config(cfg: &Config, store: &Store, api: &OPNsense, snap: &mut Snapshot, out: &mut Vec<Problem>) -> Result<()> {
    let items = api.get_raw("core/backup/backups/this")?.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    let changes: Vec<(f64, ConfigChange, String)> = items
        .iter()
        .map(|i| {
            (
                num_prefix(&s(i, "time")).unwrap_or(0.0),
                ConfigChange { time: s(i, "time_iso"), user: s(i, "username"), description: s(i, "description") },
                s(i, "id"),
            )
        })
        .collect();
    snap.config_changes = changes.iter().take(30).map(|c| c.1.clone()).collect();
    let newest = changes.iter().map(|c| c.0).fold(0.0, f64::max);
    let last = store.get_kv("config_last_seen")?.and_then(|x| x.parse::<f64>().ok());
    if let Some(last) = last {
        let fresh: Vec<&(f64, ConfigChange, String)> = changes.iter().filter(|c| c.0 > last).collect();
        if !fresh.is_empty() && cfg.health.config_alerts {
            let api_user = format!("{}@", "ipswatch");
            let by_others = fresh.iter().any(|c| !c.1.user.starts_with(&api_user));
            out.push(Problem {
                key: format!("config:{}", fresh[0].2),
                kind: "config",
                severity: if by_others { Severity::Medium } else { Severity::Low },
                title: format!(
                    "Firewall configuration changed {} time(s){}",
                    fresh.len(),
                    if by_others { String::new() } else { " (by IPS Watch)".into() }
                ),
                reasons: fresh.iter().take(10).map(|c| format!("{} {}: {}", crate::local_time(&c.1.time).get(11..16).unwrap_or(""), c.1.user, c.1.description)).collect(),
                targets: fresh.iter().map(|c| c.1.user.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
            });
        }
    }
    if newest > 0.0 {
        store.set_kv("config_last_seen", &newest.to_string())?;
    }
    Ok(())
}

/// Interfaces that face the internet: the IDS-inspected ones plus anything named like a WAN.
fn wan_interfaces(api: &OPNsense) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::from(["wan".to_string()]);
    if let Ok(v) = api.get_raw("ids/settings/get") {
        if let Some(m) = v.pointer("/ids/general/interfaces").and_then(Value::as_object) {
            out.extend(m.iter().filter(|(_, o)| o.get("selected").and_then(Value::as_i64) == Some(1)).map(|(k, _)| k.to_lowercase()));
        }
    }
    out
}

// ---------------------------------------------------------------- orchestration

/// Run every check, sync findings, and return the snapshot plus findings to alert on.
pub fn run(cfg: &Config, store: &Store, api: &OPNsense) -> Result<(Snapshot, Vec<Finding>)> {
    let mut snap = Snapshot { at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(), ..Default::default() };
    let mut problems = Vec::new();
    crate::engine::refresh_own_addresses(store, api, false);
    let nets = cfg.detect.nets()?.with_own(crate::engine::own_addresses(store));
    let wan = wan_interfaces(api);

    macro_rules! check {
        ($name:expr, $e:expr) => {
            if let Err(e) = $e {
                warn!("health check '{}' failed: {e:#}", $name);
                snap.errors.push(format!("{}: {e:#}", $name));
            }
        };
    }
    check!("gateways", check_gateways(cfg, api, &mut snap, &mut problems));
    check!("services", check_services(cfg, api, &mut snap, &mut problems));
    check!("system", check_system(cfg, store, api, &mut snap, &mut problems));
    let mut resolvable: Vec<&str> = vec!["health:"];
    if cfg.health.exposure_audit {
        match check_exposure(cfg, api, &nets, &wan, &mut snap, &mut problems) {
            Ok(()) => resolvable.push("exposure:"),
            Err(e) => {
                warn!("health check 'exposure' failed: {e:#}");
                snap.errors.push(format!("exposure: {e:#}"));
            }
        }
    }
    check!("devices", check_devices(cfg, store, api, &mut snap, &mut problems));
    check!("config", check_config(cfg, store, api, &mut snap, &mut problems));
    if cfg.crowdsec.enabled {
        match crate::crowdsec::check(cfg, store, api, &mut problems) {
            Ok(st) => snap.crowdsec = st,
            Err(e) => {
                warn!("health check 'crowdsec' failed: {e:#}");
                snap.errors.push(format!("crowdsec: {e:#}"));
            }
        }
    }

    let alerted = sync(cfg, store, &problems, &resolvable)?;
    Ok((snap, alerted))
}

/// Upsert findings for current problems; resolve stateful health findings that cleared.
/// `resolve_prefixes`: finding keys with these prefixes that no longer appear get resolved.
fn sync(cfg: &Config, store: &Store, problems: &[Problem], resolve_prefixes: &[&str]) -> Result<Vec<Finding>> {
    let now = crate::now_iso();
    let mut alerted = Vec::new();
    for p in problems {
        let f = Finding {
            key: p.key.clone(),
            kind: p.kind.to_string(),
            subject_ip: p.targets.first().cloned().unwrap_or_default(),
            first_seen: now.clone(),
            last_seen: now.clone(),
            score: score_for(p.severity),
            severity: p.severity,
            title: p.title.clone(),
            reasons: p.reasons.clone(),
            targets: p.targets.clone(),
            signatures: vec![],
            event_count: 1,
            status: "open".into(),
            notified_at: None,
            notified_severity: None,
            blocked_at: None,
        };
        let merged = store.upsert_finding(&f)?;
        if let Some(f) = crate::engine::notify_if_due(cfg, store, merged)? {
            alerted.push(f);
        }
    }
    if !resolve_prefixes.is_empty() {
        let active: BTreeSet<&str> = problems.iter().map(|p| p.key.as_str()).collect();
        for f in store.list_findings(None, Severity::Low, usize::MAX)? {
            let resolvable = resolve_prefixes.iter().any(|p| f.key.starts_with(p));
            if resolvable && f.key != "health:unreachable" && !active.contains(f.key.as_str()) && matches!(f.status.as_str(), "open" | "ack") {
                store.set_status(&f.key, "resolved")?;
                info!("Resolved: {}", f.title);
            }
        }
    }
    Ok(alerted)
}

/// Heartbeat: raise / resolve "can't reach the firewall". `down_since` = first failed poll time.
pub fn heartbeat(cfg: &Config, store: &Store, down_since: Option<chrono::DateTime<chrono::Utc>>, last_error: &str) -> Result<Vec<Finding>> {
    let key = "health:unreachable";
    match down_since {
        Some(t) if chrono::Utc::now() - t >= chrono::Duration::minutes(cfg.health.offline_minutes as i64) => sync(
            cfg,
            store,
            &[Problem {
                key: key.into(),
                kind: "health",
                severity: Severity::High,
                title: "IPS Watch can't reach the firewall".into(),
                reasons: vec![
                    format!("no successful API call since {}", crate::local_time(&crate::iso(t))),
                    format!("last error: {last_error}"),
                    "the firewall may be down, rebooting, or the network path / API key changed".into(),
                ],
                targets: vec![],
            }],
            &[],
        ),
        None => {
            if store.get_finding(key)?.is_some_and(|f| f.status == "open" || f.status == "ack") {
                store.set_status(key, "resolved")?;
                info!("Firewall reachable again");
            }
            Ok(vec![])
        }
        _ => Ok(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_helpers() {
        assert_eq!(num_prefix("14.5 ms"), Some(14.5));
        assert_eq!(num_prefix("0.0 %"), Some(0.0));
        assert_eq!(num_prefix("~"), None);
        assert!(is_random_mac("da:a1:19:00:00:01"));
        assert!(!is_random_mac("1c:3b:f3:a6:c7:4c"));
    }
}
