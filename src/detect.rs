//! Detection engine: score IPS events and roll them up into findings.
//!
//! * `inbound` - keyed on an external source attacking internal hosts. Titled
//!   "Potential unwanted access" when traffic got through (not dropped by the
//!   IPS, or the firewall log shows the source was passed to internal hosts).
//! * `compromise` - keyed on an internal host that is the source of malware / C2 / exploit /
//!   lateral-movement alerts (something is already inside).
//!
//! The firewall's own addresses count as internal, and informational rules (app detection,
//! `ET INFO`, ...) are kept for display but never scored.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use chrono::Duration;
use serde_json::Value;

use crate::config::{DetectCfg, Nets, Severity};
use crate::normalize::Event;
use crate::store::Finding;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
    Lateral,
    External,
}

pub fn direction(ev: &Event, nets: &Nets) -> Direction {
    match (nets.is_internal(&ev.src_ip), nets.is_internal(&ev.dest_ip)) {
        (false, true) => Direction::Inbound,
        (true, false) => Direction::Outbound,
        (true, true) => Direction::Lateral,
        (false, false) => Direction::External,
    }
}

/// Signature text normalised for matching: upper case, "ETPRO " treated like "ET ".
fn norm_sig(sig: &str) -> String {
    let up = sig.trim().to_uppercase();
    match up.strip_prefix("ETPRO ") {
        Some(rest) => format!("ET {rest}"),
        None => up,
    }
}

/// Rule families from the signature prefix (ET/ETPRO/GPL). OPNsense's alert API doesn't
/// return severity or category, so this is how we tell an exploit from an ad-tracker.
const HIGH_FAMILIES: &[&str] = &[
    "EXPLOIT", "MALWARE", "TROJAN", "CNC", "ATTACK_RESPONSE", "WEB_SERVER", "WEB_SPECIFIC_APPS", "SHELLCODE",
    "CURRENT_EVENTS", "PHISHING", "MOBILE_MALWARE", "WORM", "BOTCC", "COMPROMISED", "EXPLOIT_KIT", "COINMINER",
    "RANSOMWARE", "DOS",
];
const MEDIUM_FAMILIES: &[&str] = &["SCAN", "DROP", "DSHIELD", "TOR", "CIARMY", "SQL", "NETBIOS", "WEB_CLIENT", "HUNTING", "USER_AGENTS"];

/// Severity implied by the rule family (1 = high, 3 = low).
pub fn implied_severity(sig: &str) -> i64 {
    let s = norm_sig(sig);
    let family = s.strip_prefix("ET ").or_else(|| s.strip_prefix("GPL ")).and_then(|r| r.split_whitespace().next());
    match family {
        Some(f) if HIGH_FAMILIES.contains(&f) => 1,
        Some(f) if MEDIUM_FAMILIES.contains(&f) => 2,
        _ => 3,
    }
}

/// The event's own severity, or - when the source didn't say (OPNsense's alert API never
/// does; stored as 0) - the severity implied by the rule family.
pub fn effective_severity(ev: &Event) -> i64 {
    if (1..=4).contains(&ev.severity) {
        ev.severity
    } else {
        implied_severity(&ev.signature)
    }
}

pub fn is_informational(sig: &str, cfg: &DetectCfg) -> bool {
    let s = sig.trim().to_uppercase();
    cfg.informational_prefixes.iter().any(|p| !p.trim().is_empty() && s.starts_with(&p.trim().to_uppercase()))
}

fn is_compromise_indicator(ev: &Event, cfg: &DetectCfg) -> bool {
    let cat = ev.category.to_lowercase();
    let sig = norm_sig(&ev.signature);
    (!cat.is_empty() && cfg.compromise_categories.iter().any(|c| c.to_lowercase() == cat))
        || cfg.compromise_keywords.iter().any(|k| !k.trim().is_empty() && sig.contains(&norm_sig(k)))
        || implied_severity(&ev.signature) == 1
}

fn sev_points(sev: i64) -> i64 {
    match sev {
        1 => 40,
        2 => 20,
        3 => 5,
        _ => 2,
    }
}

/// A firewall log row reduced to what correlation needs.
#[derive(Clone, Debug)]
pub struct FwPass {
    pub dst: String,
    pub dstport: String,
}

struct Acc {
    kind: &'static str,
    ip: String,
    reasons: BTreeMap<String, i64>, // reason -> points (dedupe, keep max)
    targets: BTreeSet<String>,
    hosts: HashSet<String>,
    ports: HashSet<i64>,
    sigs: HashMap<String, i64>,
    count: i64,
    first: String,
    last: String,
    passed_through: bool,
    /// Hit the firewall's own addresses / internal hosts behind it.
    hit_firewall: bool,
    hit_internal: bool,
    top_sev: i64,
    sens_ports: BTreeSet<i64>,
    indicators: BTreeSet<String>,
}

impl Acc {
    fn new(kind: &'static str, ip: &str) -> Self {
        Acc {
            kind,
            ip: ip.to_string(),
            reasons: BTreeMap::new(),
            targets: BTreeSet::new(),
            hosts: HashSet::new(),
            ports: HashSet::new(),
            sigs: HashMap::new(),
            count: 0,
            first: String::new(),
            last: String::new(),
            passed_through: false,
            hit_firewall: false,
            hit_internal: false,
            top_sev: 4,
            sens_ports: BTreeSet::new(),
            indicators: BTreeSet::new(),
        }
    }

    fn reason(&mut self, text: String, pts: i64) {
        let e = self.reasons.entry(text).or_insert(0);
        *e = (*e).max(pts);
    }

    fn add(&mut self, ev: &Event, peer_ip: &str, peer_port: Option<i64>) {
        self.count += 1;
        if self.first.is_empty() || ev.ts < self.first {
            self.first = ev.ts.clone();
        }
        if ev.ts > self.last {
            self.last = ev.ts.clone();
        }
        self.targets.insert(match peer_port {
            Some(p) => format!("{peer_ip}:{p}"),
            None => peer_ip.to_string(),
        });
        self.hosts.insert(peer_ip.to_string());
        if let Some(p) = peer_port {
            self.ports.insert(p);
        }
        let sid = ev.sid.map(|s| s.to_string()).unwrap_or_else(|| "?".into());
        *self.sigs.entry(format!("[{sid}] {}", ev.signature)).or_insert(0) += 1;
        self.top_sev = self.top_sev.min(effective_severity(ev));
    }
}

/// Compute findings for a window of events (not yet merged with the store).
pub fn analyze(
    events: &[Event],
    cfg: &DetectCfg,
    nets: &Nets,
    fw_passes: Option<&HashMap<String, Vec<FwPass>>>,
) -> Vec<Finding> {
    let mut accs: BTreeMap<String, Acc> = BTreeMap::new();
    let sensitive: HashSet<i64> = cfg.sensitive_ports.iter().map(|&p| p as i64).collect();
    let ignore: HashSet<i64> = cfg.ignore_sids.iter().copied().collect();

    for ev in events {
        if ev.sid.is_some_and(|s| ignore.contains(&s)) || nets.is_ignored(&ev.src_ip) || is_informational(&ev.signature, cfg) {
            continue;
        }
        let dirn = direction(ev, nets);
        let compromise = is_compromise_indicator(ev, cfg);
        let not_blocked = !ev.was_dropped();
        let label = if ev.signature.is_empty() { ev.category.clone() } else { ev.signature.clone() };

        if matches!(dirn, Direction::Inbound | Direction::External) {
            let acc = accs.entry(format!("inbound:{}", ev.src_ip)).or_insert_with(|| Acc::new("inbound", &ev.src_ip));
            acc.add(ev, &ev.dest_ip, ev.dest_port);
            let at_firewall = nets.is_own(&ev.dest_ip);
            if at_firewall {
                acc.hit_firewall = true;
            } else if dirn == Direction::Inbound {
                acc.hit_internal = true;
            }
            if dirn == Direction::Inbound && not_blocked && !at_firewall {
                acc.passed_through = true;
                acc.reason("alert was NOT dropped by IPS - traffic reached internal host".into(), 30);
            }
            if dirn == Direction::Inbound {
                if let Some(p) = ev.dest_port.filter(|p| sensitive.contains(p)) {
                    acc.sens_ports.insert(p);
                }
            }
            if compromise {
                acc.indicators.insert(label);
            }
        } else {
            let acc = accs
                .entry(format!("compromise:{}", ev.src_ip))
                .or_insert_with(|| Acc::new("compromise", &ev.src_ip));
            acc.add(ev, &ev.dest_ip, ev.dest_port);
            if compromise {
                acc.indicators.insert(label);
            }
            if dirn == Direction::Lateral && effective_severity(ev) <= 2 {
                acc.reason("possible lateral movement (internal -> internal)".into(), 30);
            }
            if dirn == Direction::Outbound && not_blocked && compromise {
                acc.reason("outbound malicious traffic was NOT dropped".into(), 20);
            }
        }
    }

    let mut out = Vec::new();
    for (key, mut acc) in accs {
        // Each signal type counts once; details go in the reason text.
        let who = if acc.kind == "inbound" { "" } else { " from internal host" };
        acc.reason(format!("highest IPS severity {}{who}", acc.top_sev), sev_points(acc.top_sev));
        if !acc.sens_ports.is_empty() {
            let ports: Vec<String> = acc.sens_ports.iter().map(|p| p.to_string()).collect();
            acc.reason(format!("targeted sensitive service port(s) {}", ports.join(", ")), 20);
        }
        if !acc.indicators.is_empty() {
            let mut label = acc.indicators.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
            if acc.indicators.len() > 3 {
                label.push_str(" ...");
            }
            if acc.kind == "inbound" {
                acc.reason(format!("exploit/malware signature: {label}"), 30);
            } else {
                acc.reason(format!("internal host triggered compromise indicator: {label}"), 60);
            }
        }
        if acc.count >= cfg.repeat_threshold as i64 {
            acc.reason(format!("{} alerts in {} min (brute force / flood)", acc.count, cfg.window_minutes), 25);
        }
        if acc.hosts.len() >= cfg.scan_hosts_threshold as usize {
            acc.reason(format!("touched {} distinct hosts (sweep)", acc.hosts.len()), 25);
        }
        if acc.ports.len() >= cfg.scan_ports_threshold as usize {
            acc.reason(format!("touched {} distinct ports (port scan)", acc.ports.len()), 25);
        }
        if acc.hit_firewall && !acc.hit_internal {
            acc.reason("aimed at the firewall's own address, not a host behind it".into(), 0);
        }
        if acc.kind == "inbound" {
            if let Some(passes) = fw_passes.and_then(|m| m.get(&acc.ip)).filter(|p| !p.is_empty()) {
                let dsts: BTreeSet<String> = passes.iter().map(|p| format!("{}:{}", p.dst, p.dstport)).collect();
                let dsts: Vec<String> = dsts.into_iter().take(10).collect();
                acc.reason(
                    format!("firewall PASSED {} inbound connection(s) from this source to: {}", passes.len(), dsts.join(", ")),
                    40,
                );
                acc.passed_through = true;
            }
        }

        let score: i64 = acc.reasons.values().sum();
        if score < cfg.flag_score {
            continue;
        }
        let title = match (acc.kind, acc.passed_through) {
            ("inbound", true) => format!("Potential unwanted access from {}", acc.ip),
            ("inbound", false) if acc.hit_firewall && !acc.hit_internal => format!("Attack attempts against the firewall from {}", acc.ip),
            ("inbound", false) => format!("Blocked attack activity from {}", acc.ip),
            _ => format!("Internal host {} shows signs of compromise", acc.ip),
        };
        let mut reasons: Vec<(String, i64)> = acc.reasons.into_iter().collect();
        reasons.sort_by_key(|r| std::cmp::Reverse(r.1));
        let mut sigs: Vec<(String, i64)> = acc.sigs.into_iter().collect();
        sigs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out.push(Finding {
            key,
            kind: acc.kind.to_string(),
            subject_ip: acc.ip,
            first_seen: acc.first,
            last_seen: acc.last,
            score,
            severity: Severity::from_score(score),
            title,
            reasons: reasons.into_iter().map(|r| r.0).collect(),
            targets: acc.targets.into_iter().take(50).collect(),
            signatures: sigs.into_iter().take(10).map(|(s, n)| format!("{s} (x{n})")).collect(),
            event_count: acc.count,
            status: "open".into(),
            notified_at: None,
            notified_severity: None,
            blocked_at: None,
        });
    }
    out
}

/// Window [anchor - minutes, anchor] as stored-timestamp strings.
pub fn window(anchor: &str, minutes: u32) -> (String, String) {
    let end = crate::parse_iso(anchor).unwrap_or_else(chrono::Utc::now);
    (crate::iso(end - Duration::minutes(minutes as i64)), crate::iso(end))
}

fn is_broadcast_or_multicast(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_multicast() || a.is_broadcast() || a.octets()[3] == 255,
        Ok(IpAddr::V6(a)) => a.is_multicast(),
        Err(_) => false,
    }
}

/// Index OPNsense firewall log rows: external src -> passed *inbound* packets to internal hosts,
/// limited to the detection window and ignoring broadcast/multicast and routine service ports.
pub fn firewall_passes_by_src(
    rows: &[Value],
    nets: &Nets,
    window: Option<(&str, &str)>,
    ignore_ports: &[u16],
) -> HashMap<String, Vec<FwPass>> {
    let mut out: HashMap<String, Vec<FwPass>> = HashMap::new();
    let start_end = window.and_then(|(s, e)| Some((crate::parse_iso(s)?, crate::parse_iso(e)?)));
    for r in rows {
        let get = |k: &str| r.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
        if !get("action").eq_ignore_ascii_case("pass") {
            continue;
        }
        let dir = get("dir");
        if !dir.is_empty() && !dir.eq_ignore_ascii_case("in") {
            continue;
        }
        if let (Some((start, end)), Some(ts)) = (start_end, crate::parse_iso(&get("__timestamp__"))) {
            // A minute of slack either side for clock skew / log batching.
            if ts < start - Duration::minutes(1) || ts > end + Duration::minutes(1) {
                continue;
            }
        }
        let (src, dst, port) = (get("src"), get("dst"), get("dstport"));
        if port.parse::<u16>().is_ok_and(|p| ignore_ports.contains(&p)) || is_broadcast_or_multicast(&dst) {
            continue;
        }
        if !src.is_empty() && !nets.is_internal(&src) && nets.is_internal(&dst) {
            out.entry(src).or_default().push(FwPass { dst, dstport: port });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families() {
        assert_eq!(implied_severity("ETPRO EXPLOIT Possible Asus WRT LAN Backdoor Command Execution"), 1);
        assert_eq!(implied_severity("ET MALWARE Cobalt Strike Beacon"), 1);
        assert_eq!(implied_severity("ET SCAN Potential SSH Scan"), 2);
        assert_eq!(implied_severity("GPL ICMP_INFO PING speedera"), 3);
        assert_eq!(implied_severity("OPN_Social_Media - Facebook"), 3);
    }

    #[test]
    fn informational() {
        let cfg = DetectCfg::default();
        assert!(is_informational("OPN_Media_Streaming - Netflix - DNS request for netflix.com", &cfg));
        assert!(is_informational("ET INFO Session Traversal Utilities for NAT (STUN Binding Request)", &cfg));
        assert!(is_informational("GPL P2P BitTorrent transfer", &cfg));
        assert!(!is_informational("ET SCAN Potential SSH Scan", &cfg));
        assert!(!is_informational("ETPRO EXPLOIT Possible Asus WRT LAN Backdoor Command Execution", &cfg));
    }
}
