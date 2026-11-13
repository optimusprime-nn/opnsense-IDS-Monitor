//! CrowdSec (os-crowdsec plugin) on the firewall: status, alerts and active bans.
//!
//! * Health: the service and the firewall bouncer must be checking in (otherwise bans
//!   aren't enforced).
//! * Findings: alerts for serious scenarios (brute force, CVE/exploit attempts) become
//!   findings; routine ones (port scans) are only counted on the Health page.
//! * IPS scoring: active bans are cached so IPS findings from a banned IP say so.
//! * Blocking watch: alerts when CrowdSec blocks your own devices, addresses your devices
//!   connect to (from the firewall log), or the troubleshoot "sites that must work".
//! * Overrides: [`unblock`] lifts a ban / blocklist entry; addresses on the always-allow list
//!   (`crowdsec.allow`) are lifted automatically on every check.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use crate::config::{in_nets, parse_nets, Config, Severity};
use crate::health::Problem;
use crate::opnsense::OPNsense;
use crate::store::Store;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CsAlert {
    pub id: i64,
    pub created: String,
    pub ip: String,
    pub scenario: String,
    pub country: String,
    pub network: String,
    pub decisions: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub running: bool,
    pub agent: bool,
    pub lapi: bool,
    pub bouncer_enabled: bool,
    pub bouncer_last_seen: String,
    pub agent_last_seen: String,
    pub active_bans: usize,
    pub local_bans: usize,
    pub community_bans: usize,
    /// IPs actually loaded into the firewall's CrowdSec tables (local + community + subscribed lists).
    pub firewall_blocked: Option<usize>,
    pub alerts_total: usize,
    pub top_scenarios: Vec<(String, usize)>,
    pub recent: Vec<CsAlert>,
}

/// A ban, as cached for IPS scoring.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Ban {
    pub reason: String,
    pub country: String,
    pub network: String,
    pub expires: String,
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// "Ip:1.2.3.4" -> "1.2.3.4" (ranges and other scopes are returned as-is).
fn ip_of(scope_value: &str) -> String {
    scope_value.strip_prefix("Ip:").unwrap_or(scope_value).to_string()
}

fn search(api: &OPNsense, what: &str) -> Result<Vec<Value>> {
    let v = api.post_raw(&format!("crowdsec/{what}/search"), json!({"current": 1, "rowCount": -1, "searchPhrase": ""}))?;
    Ok(v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default())
}

/// Is CrowdSec installed? (the plugin's API answers)
pub fn installed(api: &OPNsense) -> bool {
    api.get_raw("crowdsec/service/status").is_ok()
}

fn minutes_since(ts: &str) -> Option<i64> {
    crate::parse_iso(ts).map(|t| (chrono::Utc::now() - t).num_minutes())
}

pub fn is_serious(cfg: &Config, scenario: &str) -> bool {
    let sc = scenario.to_lowercase();
    cfg.crowdsec.finding_scenarios.iter().any(|p| !p.trim().is_empty() && sc.contains(&p.trim().to_lowercase()))
}

/// Collect status, raise problems, cache bans. Returns None when CrowdSec isn't installed.
pub fn check(cfg: &Config, store: &Store, api: &OPNsense, out: &mut Vec<Problem>) -> Result<Option<Status>> {
    let Ok(svc) = api.get_raw("crowdsec/service/status") else { return Ok(None) };
    let mut st = Status { running: s(&svc, "status") == "running", ..Default::default() };
    if let Ok(g) = api.get_raw("crowdsec/general/get") {
        let g = g.get("general").cloned().unwrap_or_default();
        st.agent = s(&g, "agent_enabled") == "1";
        st.lapi = s(&g, "lapi_enabled") == "1";
        st.bouncer_enabled = s(&g, "firewall_bouncer_enabled") == "1";
    }
    st.bouncer_last_seen = search(api, "bouncers").ok().and_then(|r| r.first().map(|b| s(b, "last_seen"))).unwrap_or_default();
    st.agent_last_seen = search(api, "machines").ok().and_then(|r| r.first().map(|m| s(m, "last_seen"))).unwrap_or_default();

    if !st.running {
        out.push(Problem::health("health:crowdsec:service", Severity::High, "CrowdSec is not running", vec![
            "community blocklists and brute-force bans are not being applied".into(),
        ]));
    } else if st.bouncer_enabled {
        let stale = minutes_since(&st.bouncer_last_seen).is_none_or(|m| m > cfg.crowdsec.bouncer_stale_minutes as i64);
        if stale {
            out.push(Problem::health("health:crowdsec:bouncer", Severity::High, "CrowdSec firewall bouncer isn't checking in", vec![
                format!("last seen: {}", if st.bouncer_last_seen.is_empty() { "never".into() } else { crate::local_time(&st.bouncer_last_seen) }),
                "new bans are not being pushed into the firewall".into(),
            ]));
        }
    } else {
        out.push(Problem::health("health:crowdsec:bouncer", Severity::Medium, "CrowdSec firewall bouncer is disabled", vec![
            "CrowdSec detects attacks but nothing blocks them - enable it in Services > CrowdSec > Settings".into(),
        ]));
    }

    // Active bans -> cache for IPS scoring.
    let decisions = search(api, "decisions").unwrap_or_default();
    let mut bans: HashMap<String, Ban> = HashMap::new();
    for d in &decisions {
        if s(d, "action") != "ban" {
            continue;
        }
        st.active_bans += 1;
        if s(d, "source") == "crowdsec" { st.local_bans += 1 } else { st.community_bans += 1 }
        bans.insert(
            ip_of(&s(d, "scope_value")),
            Ban { reason: s(d, "reason"), country: s(d, "country"), network: s(d, "as"), expires: s(d, "expiration") },
        );
    }
    store.set_kv("crowdsec_bans", &serde_json::to_string(&bans)?)?;
    if st.running {
        enforce_allow(cfg, api, &decisions, out);
        if cfg.crowdsec.watch_blocking {
            watch_blocking(cfg, api, &decisions, out);
        }
    }

    // The bouncer's firewall tables hold everything that is really blocked, including the
    // community blocklist, which the plugin's decision list doesn't show.
    let mut blocked = None;
    for alias in ["crowdsec_blocklists", "crowdsec6_blocklists"] {
        if let Ok(v) = api.get_raw(&format!("firewall/alias_util/list/{alias}")) {
            let n = v.get("total").and_then(Value::as_u64).map(|n| n as usize)
                .unwrap_or_else(|| v.get("rows").and_then(Value::as_array).map_or(0, |r| r.len()));
            blocked = Some(blocked.unwrap_or(0) + n);
        }
    }
    st.firewall_blocked = blocked;
    if let Some(b) = blocked {
        st.community_bans = st.community_bans.max(b.saturating_sub(st.local_bans));
    }

    // Alerts: counts for the page, findings for serious scenarios not seen before.
    let alerts: Vec<CsAlert> = search(api, "alerts")
        .unwrap_or_default()
        .iter()
        .map(|a| CsAlert {
            id: a.get("id").and_then(Value::as_i64).unwrap_or(0),
            created: s(a, "created"),
            ip: ip_of(&s(a, "value")),
            scenario: { let r = s(a, "reason"); if r.is_empty() { s(a, "scenario") } else { r } },
            country: s(a, "country"),
            network: s(a, "as"),
            decisions: s(a, "decisions"),
        })
        .collect();
    st.alerts_total = alerts.len();
    let mut by_scenario: BTreeMap<String, usize> = BTreeMap::new();
    for a in &alerts {
        *by_scenario.entry(a.scenario.clone()).or_default() += 1;
    }
    let mut top: Vec<(String, usize)> = by_scenario.into_iter().collect();
    top.sort_by_key(|t| std::cmp::Reverse(t.1));
    st.top_scenarios = top.into_iter().take(8).collect();
    let mut recent = alerts.clone();
    recent.sort_by(|a, b| b.created.cmp(&a.created));
    st.recent = recent.into_iter().take(50).collect();

    let last_seen_id: i64 = store.get_kv("crowdsec_last_alert_id")?.and_then(|x| x.parse().ok()).unwrap_or(-1);
    let max_id = alerts.iter().map(|a| a.id).max().unwrap_or(last_seen_id.max(0));
    if last_seen_id >= 0 {
        for a in alerts.iter().filter(|a| a.id > last_seen_id && is_serious(cfg, &a.scenario)) {
            let banned = a.decisions.contains("ban");
            let short = a.scenario.rsplit('/').next().unwrap_or(&a.scenario);
            out.push(Problem {
                key: format!("crowdsec:{}:{}", a.ip, short),
                kind: "crowdsec",
                severity: Severity::High,
                title: format!("CrowdSec: {short} from {}{}", a.ip, if banned { " (banned)" } else { "" }),
                reasons: [
                    Some(format!("scenario {}", a.scenario)),
                    (!a.country.is_empty() || !a.network.is_empty()).then(|| format!("{} {}", a.country, a.network).trim().to_string()),
                    Some(if banned { "the firewall bouncer is blocking this IP".to_string() } else { "no ban decision was taken".to_string() }),
                ]
                .into_iter()
                .flatten()
                .collect(),
                targets: vec![a.ip.clone()],
            });
        }
    }
    // First run only records where we are, so existing alerts don't all fire at once.
    store.set_kv("crowdsec_last_alert_id", &max_id.max(last_seen_id).to_string())?;
    Ok(Some(st))
}

fn is_crowdsec_list(alias: &str) -> bool {
    alias.to_lowercase().starts_with("crowdsec")
}

/// CrowdSec blocklist tables holding `ip` on the firewall.
fn crowdsec_lists(api: &OPNsense, ip: &str) -> Vec<String> {
    api.aliases_containing(ip).unwrap_or_default().into_iter().filter(|a| is_crowdsec_list(a)).collect()
}

/// Local CrowdSec decisions (bans) covering `ip`: (decision id, reason).
fn decisions_for(decisions: &[Value], ip: &str) -> Vec<(i64, String)> {
    decisions
        .iter()
        .filter(|d| {
            let v = ip_of(&s(d, "scope_value"));
            v == ip || v.strip_prefix("Range:").and_then(|r| parse_nets(&[r.to_string()]).ok()).is_some_and(|n| in_nets(ip, &n))
        })
        .filter_map(|d| d.get("id").and_then(Value::as_i64).map(|id| (id, s(d, "reason"))))
        .collect()
}

fn how_blocked(bans: &[(i64, String)], lists: &[String]) -> Vec<String> {
    bans.iter().map(|(_, r)| format!("ban ({r})")).chain(lists.iter().map(|a| format!("blocklist {a}"))).collect()
}

/// Is `ip` blocked by CrowdSec right now? Returns how (empty = not blocked).
pub fn blocked_by(api: &OPNsense, ip: &str) -> Vec<String> {
    let bans = search(api, "decisions").map(|d| decisions_for(&d, ip)).unwrap_or_default();
    how_blocked(&bans, &crowdsec_lists(api, ip))
}

/// What [`unblock`] will do, for the confirmation dialog. Changes nothing.
pub fn unblock_preview(api: &OPNsense, ip: &str, always: bool) -> String {
    let how = blocked_by(api, ip);
    let mut t = if how.is_empty() {
        format!("CrowdSec isn't blocking {ip} right now.")
    } else {
        format!("CrowdSec is blocking {ip}: {}.\n\nIPS Watch will remove the ban / blocklist entry so traffic flows again.", how.join(", "))
    };
    if always {
        t += &format!(
            "\n\n{ip} will also go on IPS Watch's CrowdSec always-allow list: if CrowdSec blocks it again (a new ban or the next \
             blocklist download), IPS Watch lifts it on its next health check and tells you."
        );
    } else if !how.is_empty() {
        t += "\n\nA blocklist entry can come back with the next blocklist download. Use 'Always allow' to keep it unblocked.";
    }
    t
}

/// Lift every CrowdSec block on `ip`: delete its local decisions and remove it from the
/// CrowdSec blocklist tables. Only call after the user confirmed [`unblock_preview`].
pub fn unblock(api: &OPNsense, ip: &str) -> Result<String> {
    ip.parse::<std::net::IpAddr>().map_err(|_| anyhow::anyhow!("'{ip}' is not an IP address"))?;
    let mut done = vec![];
    for (id, reason) in decisions_for(&search(api, "decisions")?, ip) {
        // The plugin's delAction only acts on POST (it advertises DELETE, but anything other than
        // POST makes it return nothing, which PHP turns into a 500). Older versions took DELETE.
        let path = format!("crowdsec/decisions/del/{id}");
        let v = match api.post_raw(&path, json!({})) {
            Ok(v) => v,
            Err(e) if e.to_string().contains("405") => api.delete_raw(&path)?,
            Err(e) => return Err(e),
        };
        let r = s(&v, "result");
        // "not found": already gone (expired or removed); the check at the end confirms it.
        if !r.is_empty() && r != "deleted" && r != "ok" && r != "not found" {
            anyhow::bail!("removing CrowdSec decision {id}: the firewall answered {v}");
        }
        done.push(format!("ban removed ({reason})"));
    }
    for alias in crowdsec_lists(api, ip) {
        // Checked below with find_references (the alias listing is paged).
        let v = api.post_raw(&format!("firewall/alias_util/delete/{alias}"), json!({"address": ip}))?;
        let st = s(&v, "status");
        if !st.is_empty() && st != "done" && st != "ok" {
            anyhow::bail!("removing {ip} from {alias}: the firewall answered {v}");
        }
        done.push(format!("removed from {alias}"));
    }
    let left = blocked_by(api, ip);
    if !left.is_empty() {
        anyhow::bail!("{ip} is still blocked after the change: {}", left.join(", "));
    }
    let msg = if done.is_empty() { format!("CrowdSec wasn't blocking {ip}.") } else { format!("Unblocked {ip}: {}.", done.join(", ")) };
    log::warn!("CrowdSec override: {msg}");
    Ok(msg)
}

/// Lift blocks on always-allowed addresses, and say so.
fn enforce_allow(cfg: &Config, api: &OPNsense, decisions: &[Value], out: &mut Vec<Problem>) {
    let Ok(allow) = parse_nets(&cfg.crowdsec.allow) else { return };
    if allow.is_empty() {
        return;
    }
    let mut ips: Vec<String> = decisions.iter().map(|d| ip_of(&s(d, "scope_value"))).filter(|ip| in_nets(ip, &allow)).collect();
    // Single addresses on the list are also checked against the blocklist tables.
    ips.extend(allow.iter().filter(|n| n.prefix_len() == n.max_prefix_len()).map(|n| n.addr().to_string()));
    ips.sort();
    ips.dedup();
    for ip in ips {
        if blocked_by(api, &ip).is_empty() {
            continue;
        }
        let (sev, reasons) = match unblock(api, &ip) {
            Ok(m) => (Severity::Low, vec![m, "it's on your CrowdSec always-allow list (Settings > Health checks)".into()]),
            Err(e) => (Severity::High, vec![format!("IPS Watch could not lift the block: {e:#}"), "it's on your CrowdSec always-allow list".into()]),
        };
        out.push(Problem {
            key: format!("crowdsec:allowed:{ip}"),
            kind: "crowdsec",
            severity: sev,
            title: format!("CrowdSec blocked {ip} (always allowed) - {}", if sev == Severity::Low { "lifted" } else { "COULD NOT lift" }),
            reasons,
            targets: vec![ip],
        });
    }
}

/// Raise findings when CrowdSec blocks something you need.
fn watch_blocking(cfg: &Config, api: &OPNsense, decisions: &[Value], out: &mut Vec<Problem>) {
    use std::collections::BTreeSet;
    let Ok(nets) = cfg.detect.nets() else { return };
    let allow = parse_nets(&cfg.crowdsec.allow).unwrap_or_default();
    let mut flagged = BTreeSet::new();
    let mut raise = |out: &mut Vec<Problem>, ip: &str, sev: Severity, title: String, mut reasons: Vec<String>| {
        if in_nets(ip, &allow) || !flagged.insert(ip.to_string()) {
            return;
        }
        reasons.push("if you need it: open this finding and click 'Unblock in CrowdSec' or 'Always allow'".into());
        out.push(Problem { key: format!("crowdsec:blocking:{ip}"), kind: "crowdsec", severity: sev, title, reasons, targets: vec![ip.to_string()] });
    };
    // 1. Bans on your own devices / the firewall.
    for d in decisions.iter().filter(|d| s(d, "action") == "ban") {
        let ip = ip_of(&s(d, "scope_value"));
        if nets.is_internal(&ip) {
            raise(
                out,
                &ip,
                Severity::High,
                format!("CrowdSec is blocking your own device {ip}"),
                vec![
                    format!("scenario {}", s(d, "reason")),
                    format!("expires in {}", s(d, "expiration")),
                    "this device is cut off from the firewall until the ban expires".into(),
                ],
            );
        }
    }
    // 2. Sites that must work.
    for site in &cfg.troubleshoot.sites {
        let host = site.trim();
        if host.is_empty() {
            continue;
        }
        let ips: BTreeSet<String> = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443)).map(|a| a.map(|x| x.ip().to_string()).collect()).unwrap_or_default();
        for ip in ips {
            let how = how_blocked(&decisions_for(decisions, &ip), &crowdsec_lists(api, &ip));
            if !how.is_empty() {
                raise(
                    out,
                    &ip,
                    Severity::High,
                    format!("CrowdSec is blocking {host} ({ip})"),
                    vec![format!("blocked by {}", how.join(", ")), format!("{host} is on your 'sites that must work' list")],
                );
            }
        }
    }
    // 3. Addresses your devices tried to reach and were blocked.
    let Ok(rows) = api.firewall_log(2000) else { return };
    let mut by_dst: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    for r in &rows {
        let (src, dst) = (s(r, "src"), s(r, "dst"));
        let public = dst.parse::<std::net::IpAddr>().is_ok_and(|a| !a.is_multicast() && !a.is_unspecified());
        if s(r, "action") == "block" && nets.is_internal(&src) && !nets.is_internal(&dst) && public {
            let e = by_dst.entry(dst).or_default();
            e.0 += 1;
            e.1.insert(src);
        }
    }
    let mut busiest: Vec<(String, (usize, BTreeSet<String>))> = by_dst.into_iter().collect();
    busiest.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
    for (dst, (n, srcs)) in busiest.into_iter().take(40) {
        let how = how_blocked(&decisions_for(decisions, &dst), &crowdsec_lists(api, &dst));
        if how.is_empty() {
            continue;
        }
        raise(
            out,
            &dst,
            Severity::Medium,
            format!("CrowdSec blocked your devices from reaching {dst} ({n} times)"),
            vec![
                format!("blocked by {}", how.join(", ")),
                format!("from {}", srcs.into_iter().take(6).collect::<Vec<_>>().join(", ")),
                "if something stopped working, this is the likely cause; if you don't recognise the address, leave it blocked".into(),
            ],
        );
    }
}

/// Active CrowdSec bans as last cached (for IPS scoring).
pub fn cached_bans(store: &Store) -> HashMap<String, Ban> {
    store
        .get_kv("crowdsec_bans")
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(ip_of("Ip:45.56.82.11"), "45.56.82.11");
        assert_eq!(ip_of("Range:1.2.3.0/24"), "Range:1.2.3.0/24");
        let cfg = Config::default();
        assert!(is_serious(&cfg, "crowdsecurity/opnsense-gui-bf"));
        assert!(is_serious(&cfg, "crowdsecurity/ssh-slow-bf"));
        assert!(is_serious(&cfg, "crowdsecurity/CVE-2017-9841"));
        assert!(!is_serious(&cfg, "firewallservices/pf-scan-multi_ports"));
    }

    #[test]
    fn decisions_match_ips_and_ranges() {
        let d = vec![
            json!({"id": 7, "scope_value": "Ip:203.0.113.9", "reason": "ssh-bf", "action": "ban"}),
            json!({"id": 8, "scope_value": "Range:198.51.100.0/24", "reason": "list", "action": "ban"}),
        ];
        assert_eq!(decisions_for(&d, "203.0.113.9"), vec![(7, "ssh-bf".to_string())]);
        assert_eq!(decisions_for(&d, "198.51.100.77"), vec![(8, "list".to_string())]);
        assert!(decisions_for(&d, "192.0.2.1").is_empty());
        assert!(is_crowdsec_list("crowdsec_blocklists") && is_crowdsec_list("crowdsec6_blocklists") && !is_crowdsec_list("__qfeeds_malware_ip"));
        assert_eq!(how_blocked(&[(7, "ssh-bf".into())], &["crowdsec_blocklists".into()]), vec!["ban (ssh-bf)", "blocklist crowdsec_blocklists"]);
    }
}
