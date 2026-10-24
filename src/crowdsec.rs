//! CrowdSec (os-crowdsec plugin) on the firewall: status, alerts and active bans.
//!
//! * Health: the service and the firewall bouncer must be checking in (otherwise bans
//!   aren't enforced).
//! * Findings: alerts for serious scenarios (brute force, CVE/exploit attempts) become
//!   findings; routine ones (port scans) are only counted on the Health page.
//! * IPS scoring: active bans are cached so IPS findings from a banned IP say so.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use crate::config::{Config, Severity};
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
}
