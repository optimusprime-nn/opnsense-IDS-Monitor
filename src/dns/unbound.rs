//! OPNsense's built-in Unbound resolver, read through the firewall API (GET only).
//!
//! Endpoints (checked against opnsense/core 25.1, 25.7 and 26.7,
//! `controllers/OPNsense/Unbound/Api/` and `scripts/unbound/{stats,wrapper}.py`):
//!
//! * `unbound/settings/get` - the whole Unbound model as `{"unbound": {...}}`: on/off, port,
//!   forwarding, DNS-over-TLS / forward servers, access lists and blocklist (DNSBL) policies.
//!   Used for settings-change alerts, forwarders, blocking state and the open-resolver check.
//! * `unbound/overview/is_enabled` - `{"enabled": "0"|"1"}`: whether local statistics are
//!   collected (Reporting > Unbound DNS). Everything below except `diagnostics/stats` needs them.
//! * `unbound/overview/rolling/1` - per-minute counts for the last hour, keyed by start time:
//!   `{"<epoch>": {"total", "passed", "blocked", "dropped", "resolved", "local", "cached"}}`.
//! * `unbound/overview/rolling/1/1` - top 10 clients per minute for the last hour:
//!   `{"<epoch>": {"<client ip>": {"count", "hostname"}}}`.
//! * `unbound/overview/totals/<n>` - counts since statistics started, top `n` passed and blocked
//!   domains and `blocklist_size` (domains loaded by Unbound's blocklist module).
//! * `unbound/overview/search_queries` - the newest 1000 queries as `{"rows": [...]}`, each with
//!   `time` (epoch), `client` (resolved host name or address), `domain`, `rcode`, `action`...
//! * `unbound/diagnostics/stats` - `unbound-control stats_noreset` as nested JSON under `data`
//!   (`{"status": "failed"}` while Unbound isn't running). Per-rcode counters only appear with
//!   Services > Unbound DNS > Advanced > Extended statistics.
//!
//! Not available for Unbound, so quietly skipped: blocklist age (OPNsense doesn't expose when the
//! lists were last downloaded), the update check, zones and the upstream-failure server log.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{arr, check_exposure, report_nx, sanitize, score_clients, servfail_problem, settings_change, ExposureCtx, NxCounts, Purpose, ServerStatus, Stats};
use crate::config::{Config, Severity};
use crate::health::{Exposed, Problem};
use crate::opnsense::OPNsense;
use crate::store::Store;

pub const STATS_OFF: &str = "Unbound statistics are off - turn them on under Reporting > Unbound DNS (Enabled) \
                             to get query counts, top clients and domains, blocklist hits and NXDOMAIN bursts";

pub const TURNED_OFF: &str = "Unbound is turned off on the firewall (Services > Unbound DNS > General)";

/// The query log endpoint returns at most this many (the newest) queries.
pub const QUERY_LOG_ROWS: usize = 1000;

// ---------------------------------------------------------------- parsing

/// Numbers arrive as JSON numbers or as strings ("12"); unbound-control counters may be "12.5".
fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        // wrapper.py keeps a value that later became a branch as {"__value__": ...}.
        Value::Object(m) => num(m.get("__value__")),
        _ => None,
    }
}

fn n(v: &Value, k: &str) -> u64 {
    num(v.get(k)).map(|x| x.max(0.0) as u64).unwrap_or(0)
}

/// OPNsense booleans are "0" / "1" strings.
fn flag(v: &Value, k: &str) -> bool {
    num(v.get(k)).is_some_and(|x| x != 0.0)
}

fn text(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(x)) => x.to_string(),
        _ => String::new(),
    }
}

/// The Unbound model inside a `settings/get` answer.
pub fn settings_root(v: &Value) -> &Value {
    v.get("unbound").unwrap_or(v)
}

fn is_option(m: &Map<String, Value>) -> bool {
    !m.is_empty() && m.values().all(|x| x.get("selected").is_some() && x.get("value").is_some())
}

/// Selected entries of an option / list field. OPNsense sends these as
/// `{"key": {"value": "Label", "selected": 0|1}}`, as a list `[{"value", "selected"}]` when the
/// keys are numeric, or as a plain "a,b" string. Empty keys (an empty list field) are skipped.
pub fn selected(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Object(m)) if is_option(m) => m.iter().filter(|(k, x)| !k.is_empty() && flag(x, "selected")).map(|(k, _)| k.clone()).collect(),
        Some(Value::Array(a)) => a.iter().filter(|x| flag(x, "selected")).map(|x| text(x, "value")).filter(|x| !x.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect(),
        _ => vec![],
    }
}

/// Records of an ArrayField (`{"<uuid>": {...}}`, or `[]` when empty).
fn records(v: Option<&Value>) -> Vec<(&str, &Value)> {
    match v {
        Some(Value::Object(m)) if !is_option(m) => m.iter().map(|(k, x)| (k.as_str(), x)).collect(),
        _ => vec![],
    }
}

/// Flatten the settings to one level ("general.port": "53", "dnsbl.blocklist.<uuid>.type": "ag,el")
/// with option fields reduced to what is selected, so a change diffs to one readable line.
pub fn compact_settings(v: &Value) -> Value {
    fn walk(v: &Value, path: &str, out: &mut Map<String, Value>) {
        match v {
            Value::Object(m) if is_option(m) => {
                out.insert(path.to_string(), Value::String(selected(Some(v)).join(",")));
            }
            Value::Array(a) if a.iter().all(|x| x.get("selected").is_some()) && !a.is_empty() => {
                out.insert(path.to_string(), Value::String(selected(Some(v)).join(",")));
            }
            Value::Object(m) => {
                for (k, x) in m {
                    walk(x, &if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out);
                }
            }
            Value::Array(a) if a.is_empty() => {
                out.insert(path.to_string(), Value::String(String::new()));
            }
            x => {
                out.insert(path.to_string(), x.clone());
            }
        }
    }
    let mut out = Map::new();
    walk(settings_root(v), "", &mut out);
    Value::Object(out)
}

/// What the monitor needs from `unbound/settings/get`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    /// Local statistics (same switch as `overview/is_enabled`).
    pub stats: bool,
    pub port: u16,
    /// "recursive", "forwarding to the system DNS servers" or "forwarding (DNS over TLS)"...
    pub recursion: String,
    /// Enabled DNS-over-TLS / forward servers, "1.1.1.1:853 (DoT)".
    pub forwarders: Vec<String>,
    pub blocking: bool,
    /// Predefined lists selected plus custom list URLs, over all enabled blocklist policies.
    pub blocklists: usize,
    /// Access lists default to "allow" for everyone.
    pub open_resolver: bool,
}

pub fn parse_settings(v: &Value) -> Settings {
    let root = settings_root(v);
    let general = root.get("general").cloned().unwrap_or_default();
    let mut st = Settings {
        enabled: flag(&general, "enabled"),
        stats: flag(&general, "stats"),
        port: num(general.get("port")).map(|p| p as u16).filter(|p| *p > 0).unwrap_or(53),
        ..Default::default()
    };
    let dots = root.get("dots").cloned().unwrap_or_default();
    for (_, d) in records(dots.get("dot")).into_iter().filter(|(_, d)| flag(d, "enabled")) {
        let kind = selected(d.get("type")).first().cloned().unwrap_or_else(|| "dot".into());
        let server = text(d, "server");
        if server.is_empty() {
            continue;
        }
        let port = text(d, "port");
        let domain = text(d, "domain");
        let addr = match (server.contains(':'), port.is_empty()) {
            (_, true) => server,
            (true, false) => format!("[{server}]:{port}"),
            (false, false) => format!("{server}:{port}"),
        };
        st.forwarders.push(format!(
            "{addr}{}{}",
            if kind == "dot" { " (DoT)" } else { "" },
            if domain.is_empty() { String::new() } else { format!(" for {domain}") }
        ));
    }
    let forwarding = root.get("forwarding").is_some_and(|f| flag(f, "enabled"));
    st.recursion = match (forwarding, st.forwarders.is_empty()) {
        (true, _) => "forwarding to the system DNS servers".into(),
        (false, false) => "forwarding to the servers below".into(),
        (false, true) => "recursive".into(),
    };
    let dnsbl = root.get("dnsbl").cloned().unwrap_or_default();
    let policies = records(dnsbl.get("blocklist"));
    let count = |p: &Value| -> usize {
        selected(p.get("type")).len() + selected(p.get("lists")).len() + selected(p.get("blocklists")).len()
    };
    if !policies.is_empty() {
        // 25.7 and later: one or more blocklist policies.
        for (_, p) in policies.into_iter().filter(|(_, p)| flag(p, "enabled")) {
            st.blocklists += count(p);
        }
        st.blocking = st.blocklists > 0;
    } else if dnsbl.get("enabled").is_some() {
        // 25.1: a single dnsbl section.
        st.blocking = flag(&dnsbl, "enabled");
        st.blocklists = if st.blocking { count(&dnsbl) } else { 0 };
    }
    let acls = root.get("acls").cloned().unwrap_or_default();
    // The template writes "access-control: 0.0.0.0/0 <default_action>" (default allow).
    st.open_resolver = selected(acls.get("default_action")).first().is_none_or(|a| a == "allow");
    st
}

/// `overview/is_enabled`: `{"enabled": "1"}`.
pub fn parse_enabled(v: &Value) -> bool {
    flag(v, "enabled")
}

/// Sum of `overview/rolling/1` (per-minute counts for the last hour).
pub fn parse_rolling(v: &Value) -> Stats {
    let mut st = Stats::default();
    if let Value::Object(m) = v {
        for x in m.values() {
            st.total += n(x, "total");
            st.blocked += n(x, "blocked") + n(x, "dropped");
            st.cached += n(x, "cached");
            st.recursive += n(x, "resolved");
            st.authoritative += n(x, "local");
        }
    }
    st
}

/// Sum of `overview/rolling/1/1`: (client, host name, queries), busiest first. Each minute only
/// lists its 10 busiest clients, so quiet clients are missing and counts are lower bounds.
pub fn parse_rolling_clients(v: &Value) -> Vec<(String, String, u64)> {
    let mut per: BTreeMap<String, (String, u64)> = BTreeMap::new();
    if let Value::Object(m) = v {
        for minute in m.values() {
            if let Value::Object(c) = minute {
                for (ip, x) in c {
                    let e = per.entry(ip.clone()).or_default();
                    e.1 += n(x, "count");
                    let h = text(x, "hostname");
                    if !h.is_empty() {
                        e.0 = h;
                    }
                }
            }
        }
    }
    let mut v: Vec<(String, String, u64)> = per.into_iter().map(|(ip, (h, c))| (ip, h, c)).collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    v
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Totals {
    pub total: u64,
    /// Domains loaded by Unbound's blocklist module (None when the answer has no such field).
    pub blocklist_size: Option<u64>,
    pub top: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    /// When the statistics start (epoch seconds).
    pub start_time: Option<i64>,
}

/// `overview/totals/<n>`. An empty or failed answer is `[]`.
pub fn parse_totals(v: &Value) -> Option<Totals> {
    let m = v.as_object()?;
    let pairs = |k: &str| -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = m.get(k).and_then(Value::as_object).map(|o| o.iter().map(|(d, x)| (d.clone(), n(x, "total"))).collect()).unwrap_or_default();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    };
    Some(Totals {
        total: n(v, "total"),
        blocklist_size: num(m.get("blocklist_size")).map(|x| x as u64),
        top: pairs("top"),
        top_blocked: pairs("top_blocked"),
        start_time: num(m.get("start_time")).map(|x| x as i64),
    })
}

/// Rows of `overview/search_queries`.
pub fn query_rows(v: &Value) -> Vec<Value> {
    arr(v, "rows")
}

fn row_time(r: &Value) -> i64 {
    num(r.get("time")).unwrap_or(0.0) as i64
}

/// NXDOMAIN answers per client in rows newer than `since` (epoch seconds).
pub fn nx_by_client(rows: &[Value], since: i64) -> NxCounts {
    let mut per = NxCounts::new();
    for r in rows.iter().filter(|r| row_time(r) >= since && text(r, "rcode") == "NXDOMAIN") {
        let c = per.entry(text(r, "client")).or_default();
        c.0 += 1;
        if c.1.len() < 2000 {
            c.1.insert(text(r, "domain").trim_end_matches('.').to_lowercase());
        }
    }
    per
}

/// (queries, SERVFAIL, NXDOMAIN) among rows newer than `since`.
pub fn rcode_sample(rows: &[Value], since: i64) -> (u64, u64, u64) {
    rows.iter().filter(|r| row_time(r) >= since).fold((0, 0, 0), |(t, sf, nx), r| {
        let rc = text(r, "rcode");
        (t + 1, sf + u64::from(rc == "SERVFAIL"), nx + u64::from(rc == "NXDOMAIN"))
    })
}

/// Cumulative unbound-control counters from `diagnostics/stats`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub queries: u64,
    pub cachehits: u64,
    pub cachemiss: u64,
    /// Only with extended statistics.
    pub servfail: Option<u64>,
    pub nxdomain: Option<u64>,
    /// Seconds since Unbound started.
    pub uptime: Option<f64>,
}

/// `diagnostics/stats`; None while Unbound isn't running (`{"status": "failed"}`).
pub fn parse_diag(v: &Value) -> Option<Counters> {
    if v.get("status").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let d = v.get("data")?;
    let at = |p: &str| num(d.pointer(p));
    Some(Counters {
        queries: at("/total/num/queries")? as u64,
        cachehits: at("/total/num/cachehits").unwrap_or(0.0) as u64,
        cachemiss: at("/total/num/cachemiss").unwrap_or(0.0) as u64,
        servfail: at("/num/answer/rcode/SERVFAIL").map(|x| x as u64),
        nxdomain: at("/num/answer/rcode/NXDOMAIN").map(|x| x as u64),
        uptime: at("/time/up"),
    })
}

/// Traffic between two counter samples; None after a restart (counters went down) or with no traffic.
pub fn counter_delta(prev: &Counters, now: &Counters) -> Option<Stats> {
    if now.queries < prev.queries || now.cachehits < prev.cachehits || now.cachemiss < prev.cachemiss {
        return None;
    }
    let d = |a: Option<u64>, b: Option<u64>| match (a, b) {
        (Some(a), Some(b)) if b >= a => b - a,
        _ => 0,
    };
    Some(Stats {
        total: now.queries - prev.queries,
        cached: now.cachehits - prev.cachehits,
        recursive: now.cachemiss - prev.cachemiss,
        servfail: d(prev.servfail, now.servfail),
        nxdomain: d(prev.nxdomain, now.nxdomain),
        ..Default::default()
    })
}

// ---------------------------------------------------------------- checks

#[derive(Serialize, Deserialize)]
struct Sample {
    at: String,
    counters: Counters,
}

/// Check Unbound on the firewall; `st.lookups` were already done.
pub(super) fn check(cfg: &Config, store: &Store, exposure: &[Exposed], st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let api = match OPNsense::new(&cfg.opnsense) {
        Ok(a) => a,
        Err(e) => {
            st.api_error = format!("{e:#}");
            return;
        }
    };
    check_with(cfg, store, &api, exposure, st, out);
}

fn check_with(cfg: &Config, store: &Store, api: &OPNsense, exposure: &[Exposed], st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let host = st.host.clone();
    let label = st.name.clone();
    let raw = match api.get_raw("unbound/settings/get") {
        Ok(v) if v.get("unbound").is_some() => v,
        Ok(_) => {
            st.api_error = "unbound/settings/get: unexpected answer (is this OPNsense with Unbound?)".into();
            return;
        }
        Err(e) => {
            st.api_error = format!("{e:#}");
            out.push(Problem {
                key: format!("dns:health:{host}:api"),
                kind: "dns",
                severity: Severity::Medium,
                title: format!("DNS {label}: can't read Unbound through the firewall API"),
                reasons: vec![st.api_error.clone(), "the API user needs read access to the Unbound DNS pages (settings, overview / reporting, diagnostics)".into()],
                targets: vec![host.clone()],
            });
            return;
        }
    };
    st.api_ok = true;
    let set = parse_settings(&raw);
    st.recursion = set.recursion.clone();
    st.forwarders = set.forwarders.clone();
    st.blocking = set.blocking;
    st.blocklist_urls = set.blocklists;

    settings_change(cfg, store, st, sanitize(&compact_settings(&raw)), out);
    let ctx = ExposureCtx {
        purposes: BTreeMap::from([(set.port, Purpose { name: "DNS".into(), udp_only: false })]),
        open_resolver: set.open_resolver,
        product: "Unbound",
    };
    let timeout = std::time::Duration::from_secs(cfg.dns.timeout_seconds.clamp(2, 5));
    check_exposure(&ctx, &host, &label, exposure, timeout, st, out);

    if !set.enabled {
        st.notes.push(TURNED_OFF.into());
        return;
    }

    // unbound-control counters: uptime, and traffic since the last check.
    let counters = api.get_raw("unbound/diagnostics/stats").ok().as_ref().and_then(parse_diag);
    let mut delta = None;
    if let Some(c) = &counters {
        let now = chrono::Utc::now();
        if let Some(up) = c.uptime {
            st.up_since = crate::iso(now - chrono::Duration::seconds(up as i64));
        }
        let key = format!("dns_unbound_counters:{host}");
        if let Some(prev) = store.get_kv(&key).ok().flatten().and_then(|x| serde_json::from_str::<Sample>(&x).ok()) {
            let mins = crate::parse_iso(&prev.at).map(|t| (now - t).num_minutes()).unwrap_or(0);
            if mins <= 120 {
                delta = counter_delta(&prev.counters, c).map(|s| (s, mins, c.servfail.is_some()));
            }
        }
        if let Ok(j) = serde_json::to_string(&Sample { at: crate::iso(now), counters: c.clone() }) {
            let _ = store.set_kv(&key, &j);
        }
    } else {
        st.notes.push("unbound-control statistics are unavailable (Unbound may be starting or stopped)".into());
    }

    let stats_on = match api.get_raw("unbound/overview/is_enabled") {
        Ok(v) => parse_enabled(&v),
        Err(e) => {
            st.errors.push(format!("statistics state: {e:#}"));
            set.stats
        }
    };

    let totals = api.get_raw("unbound/overview/totals/10").ok().as_ref().and_then(parse_totals);
    // blocklist_size is what Unbound's blocklist module loaded; only meaningful while it runs.
    if let (true, true, Some(0)) = (set.blocking, counters.is_some(), totals.as_ref().and_then(|t| t.blocklist_size)) {
        out.push(Problem {
            key: format!("dns:health:{host}:blocklist"),
            kind: "dns",
            severity: Severity::Medium,
            title: format!("DNS {label}: blocklists are empty"),
            reasons: vec![
                format!("{} blocklist(s) selected but Unbound loaded no domains - downloads are failing", set.blocklists),
                "see Services > Unbound DNS > Blocklists and the Unbound log".into(),
            ],
            targets: vec![host.clone()],
        });
    }

    if !stats_on {
        st.notes.push(STATS_OFF.into());
        out.push(Problem {
            key: format!("dns:health:{host}:stats_off"),
            kind: "dns",
            severity: Severity::Low,
            title: format!("DNS {label}: Unbound statistics are off"),
            reasons: vec![
                STATS_OFF.into(),
                "without them IPS Watch can only check that Unbound answers, its settings and blocklists".into(),
            ],
            targets: vec![host.clone()],
        });
        // Fall back to unbound-control counters for traffic and SERVFAIL.
        if let Some((stats, mins, rcodes)) = delta.filter(|d| d.0.total > 0) {
            st.stats_window = format!("in the last {} min", mins.max(1));
            if !rcodes {
                st.notes.push("SERVFAIL / NXDOMAIN counts need Services > Unbound DNS > Advanced > Extended statistics".into());
            }
            servfail_problem(cfg, &stats, st, out);
            st.stats = Some(stats);
        }
        return;
    }

    let mut stats = match api.get_raw("unbound/overview/rolling/1") {
        Ok(v) => parse_rolling(&v),
        Err(e) => {
            st.errors.push(format!("traffic: {e:#}"));
            Stats::default()
        }
    };

    // Query log: SERVFAIL / NXDOMAIN share and NXDOMAIN bursts per client.
    let now = chrono::Utc::now();
    match api.get_raw("unbound/overview/search_queries") {
        Ok(v) => {
            let rows = query_rows(&v);
            let hour_ago = (now - chrono::Duration::hours(1)).timestamp();
            let (sample, servfail, nxdomain) = rcode_sample(&rows, hour_ago);
            if sample > 0 && stats.total > 0 {
                // The log holds the newest queries only; scale its shares to the hour's total.
                let scale = stats.total as f64 / sample.max(1) as f64;
                stats.servfail = (servfail as f64 * scale.max(1.0)).round() as u64;
                stats.nxdomain = (nxdomain as f64 * scale.max(1.0)).round() as u64;
            }
            let key = format!("dns_nx_since:{host}");
            let since = store
                .get_kv(&key)
                .ok()
                .flatten()
                .and_then(|x| crate::parse_iso(&x))
                .filter(|t| now - *t < chrono::Duration::hours(2))
                .unwrap_or(now - chrono::Duration::minutes(cfg.dns.interval_minutes.max(1) as i64));
            let _ = store.set_kv(&key, &crate::iso(now));
            let oldest = rows.iter().map(row_time).filter(|t| *t > 0).min();
            if rows.len() >= QUERY_LOG_ROWS && oldest.is_some_and(|t| t > since.timestamp()) {
                st.notes.push(format!("the query log only returns the newest {QUERY_LOG_ROWS} queries, so NXDOMAIN bursts are counted over a shorter span than the check interval"));
            }
            st.query_logger = "Unbound query log".into();
            report_nx(cfg, st, nx_by_client(&rows, since.timestamp()), since, out);
        }
        Err(e) => st.errors.push(format!("query log: {e:#}")),
    }

    match api.get_raw("unbound/overview/rolling/1/1") {
        Ok(v) => {
            let rows = parse_rolling_clients(&v);
            stats.clients = rows.len() as u64;
            score_clients(cfg, store, st, rows, "see Reporting > Unbound DNS > Details for this client", out);
        }
        Err(e) => st.errors.push(format!("top clients: {e:#}")),
    }

    if let Some(t) = &totals {
        st.top_domains = t.top.clone();
        st.top_blocked = t.top_blocked.clone();
        stats.block_list_zones = t.blocklist_size.unwrap_or(0);
        if let Some(start) = t.start_time.and_then(|s| chrono::DateTime::from_timestamp(s, 0)) {
            st.top_window = format!("since {}", crate::local_time(&crate::iso(start)));
        }
    }
    servfail_problem(cfg, &stats, st, out);
    st.stats = Some(stats);
}

/// Connection test for Settings: one line describing what was read.
pub fn test(cfg: &Config) -> Result<String> {
    let api = OPNsense::new(&cfg.opnsense)?;
    let raw = api.get_raw("unbound/settings/get")?;
    if raw.get("unbound").is_none() {
        bail!("unbound/settings/get: unexpected answer (is this OPNsense with Unbound?)");
    }
    let set = parse_settings(&raw);
    let stats = api.get_raw("unbound/overview/is_enabled").map(|v| parse_enabled(&v));
    let running = api.get_raw("unbound/diagnostics/stats").ok().as_ref().and_then(parse_diag).is_some();
    Ok(format!(
        "OPNsense Unbound {}, {}, statistics {}, {}",
        if set.enabled { "enabled" } else { "DISABLED" },
        if running { "running" } else { "not running" },
        match stats {
            Ok(true) => "on".to_string(),
            Ok(false) => "OFF (enable under Reporting > Unbound DNS)".to_string(),
            Err(e) => format!("unreadable ({e:#})"),
        },
        if set.blocking { format!("blocking on ({} list(s))", set.blocklists) } else { "blocking off".into() }
    ))
}
