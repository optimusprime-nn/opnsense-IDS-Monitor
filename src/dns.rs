//! Technitium DNS servers: reachability, resolution, traffic, blocklists, unusual clients,
//! zone / settings changes and WAN exposure.
//!
//! * Health (`dns:health:*`, resolved automatically): API reachable, test lookups answered on
//!   port 53 (with failover state when one server is down), SERVFAIL rate, blocklist age,
//!   available updates and WAN port forwards to the servers.
//! * Events (`dns:client:*`, `dns:change:*`): clients querying far above their usual rate or
//!   getting bursts of NXDOMAIN answers (possible malware / DGA), and zone or settings changes.

use anyhow::{anyhow, bail, Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::config::{Config, DnsServerCfg, Severity};
use crate::health::{Exposed, Problem};
use crate::store::{Finding, Store};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Lookup {
    pub domain: String,
    pub ok: bool,
    /// NOERROR, NXDOMAIN, SERVFAIL... or "timeout" / an error.
    pub result: String,
    pub answers: u16,
    pub ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub total: u64,
    pub no_error: u64,
    pub servfail: u64,
    pub nxdomain: u64,
    pub refused: u64,
    pub blocked: u64,
    pub cached: u64,
    pub recursive: u64,
    pub authoritative: u64,
    pub clients: u64,
    pub zones: u64,
    pub block_list_zones: u64,
}

impl Stats {
    pub fn pct(&self, n: u64) -> f64 {
        if self.total == 0 { 0.0 } else { n as f64 * 100.0 / self.total as f64 }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Client {
    pub ip: String,
    pub name: String,
    pub hits: u64,
    /// Usual queries per hour (None while still learning).
    pub usual: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NxClient {
    pub ip: String,
    pub count: u64,
    pub unique: usize,
    pub sample: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Zone {
    pub name: String,
    pub kind: String,
    pub disabled: bool,
    pub serial: String,
    pub modified: String,
    pub problem: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsExposure {
    pub port: String,
    pub protocol: String,
    pub interface: String,
    /// Forward exists but no pass rule lets it through.
    pub blocked: bool,
    /// What Technitium uses this port for ("" = nothing it is configured for).
    pub purpose: String,
    /// TCP connect from this PC succeeded (None = not tested, e.g. UDP only / port range).
    pub listening: Option<bool>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub url: String,
    pub host: String,
    pub server_domain: String,
    pub api_ok: bool,
    pub api_error: String,
    pub version: String,
    pub up_since: String,
    pub update: String,
    pub dns_ok: bool,
    pub lookups: Vec<Lookup>,
    pub stats: Option<Stats>,
    pub top_clients: Vec<Client>,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub recursion: String,
    pub forwarders: Vec<String>,
    pub blocking: bool,
    pub blocklist_urls: usize,
    pub blocklist_interval_hours: u64,
    pub blocklist_next_update: String,
    pub blocklist_age_hours: Option<f64>,
    pub zones: Vec<Zone>,
    pub query_logger: String,
    pub nx_clients: Vec<NxClient>,
    pub exposure: Vec<DnsExposure>,
    /// From the server log, last hour: failed recursive resolutions, by name and by silent name server.
    pub upstream_failures: u64,
    pub failing_names: Vec<(String, u64)>,
    pub silent_nameservers: Vec<(String, u64)>,
    pub errors: Vec<String>,
}

/// "a (3), b (2)"
pub fn pairs_text(v: &[(String, u64)], n: usize) -> String {
    v.iter().take(n).map(|(k, c)| format!("{k} ({c})")).collect::<Vec<_>>().join(", ")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub at: String,
    pub servers: Vec<ServerStatus>,
    /// Suricata restarts in the last hour (inline IPS stalls the WAN meanwhile).
    pub ids_restarts: Vec<String>,
}

// ---------------------------------------------------------------- Technitium API

pub struct Technitium {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl Technitium {
    pub fn new(cfg: &DnsServerCfg, timeout_seconds: u64) -> Result<Self> {
        if cfg.url.trim().is_empty() {
            bail!("no console URL");
        }
        let tls = native_tls::TlsConnector::new()?;
        let agent = ureq::AgentBuilder::new()
            .tls_connector(std::sync::Arc::new(tls))
            .timeout(Duration::from_secs(timeout_seconds.max(2)))
            .build();
        Ok(Self { base: cfg.url.trim().trim_end_matches('/').to_string(), token: cfg.token.trim().to_string(), agent })
    }

    /// GET /api/<path>; returns the `response` object. The token is never part of an error.
    pub fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}/api/{}", self.base, path.trim_start_matches('/'));
        let mut r = self.agent.get(&url).query("token", &self.token);
        for (k, v) in query {
            r = r.query(k, v);
        }
        let v: Value = match r.call() {
            Ok(resp) => resp.into_json().with_context(|| format!("{path}: response is not JSON"))?,
            Err(ureq::Error::Status(code, _)) => bail!("{path}: HTTP {code}"),
            Err(ureq::Error::Transport(t)) => bail!("{path}: {}", t.to_string().replace(&self.token, "***")),
        };
        match v.get("status").and_then(Value::as_str) {
            Some("ok") => Ok(v.get("response").cloned().unwrap_or(Value::Null)),
            Some("invalid-token") => bail!("the API token was rejected (invalid or expired)"),
            Some(other) => bail!("{path}: {other}: {}", s(&v, "errorMessage")),
            None => bail!("{path}: unexpected response"),
        }
    }
}

impl Technitium {
    /// GET /api/<path> returning plain text (e.g. logs/download).
    pub fn get_text(&self, path: &str, query: &[(&str, &str)]) -> Result<String> {
        let url = format!("{}/api/{}", self.base, path.trim_start_matches('/'));
        let mut r = self.agent.get(&url).query("token", &self.token);
        for (k, v) in query {
            r = r.query(k, v);
        }
        match r.call() {
            Ok(resp) => Ok(resp.into_string()?),
            Err(ureq::Error::Status(code, _)) => bail!("{path}: HTTP {code}"),
            Err(ureq::Error::Transport(t)) => bail!("{path}: {}", t.to_string().replace(&self.token, "***")),
        }
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

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|t| t.parse().ok()))).unwrap_or(0)
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn arr(v: &Value, k: &str) -> Vec<Value> {
    v.get(k).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn hours_since(ts: &str) -> Option<f64> {
    crate::parse_iso(ts).map(|t| (chrono::Utc::now() - t).num_seconds() as f64 / 3600.0)
}

// ---------------------------------------------------------------- DNS over UDP

fn qname(domain: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for label in domain.trim().trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("'{domain}' is not a valid name");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        n => format!("RCODE {n}"),
    }
}

/// Ask `server` (port 53, UDP) for the A record of `domain`.
pub fn query(server: &str, domain: &str, timeout: Duration) -> Lookup {
    let started = Instant::now();
    let mut l = Lookup { domain: domain.to_string(), ..Default::default() };
    let r = (|| -> Result<(u8, u16)> {
        let addr: SocketAddr = (server, 53).to_socket_addrs()?.next().ok_or_else(|| anyhow!("can't resolve {server}"))?;
        let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        sock.set_read_timeout(Some(timeout))?;
        let id: u16 = (started.elapsed().as_nanos() as u16) ^ (std::process::id() as u16) ^ 0x5a5a;
        let mut pkt = id.to_be_bytes().to_vec();
        pkt.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
        pkt.extend(qname(domain)?);
        pkt.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        sock.send_to(&pkt, addr)?;
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = sock.recv_from(&mut buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => anyhow!("timeout"),
                _ => anyhow!(e),
            })?;
            if from.ip() == addr.ip() && n >= 12 && buf[..2] == id.to_be_bytes() {
                return Ok((buf[3] & 0x0f, u16::from_be_bytes([buf[6], buf[7]])));
            }
        }
    })();
    l.ms = started.elapsed().as_millis() as u64;
    match r {
        Ok((rcode, an)) => {
            l.result = rcode_name(rcode);
            l.answers = an;
            l.ok = rcode == 0 && an > 0;
        }
        Err(e) => l.result = format!("{e:#}"),
    }
    l
}

fn tcp_open(host: &str, port: u16, timeout: Duration) -> bool {
    (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| TcpStream::connect_timeout(&a, timeout).is_ok())
}

// ---------------------------------------------------------------- per-server checks

/// Strip volatile values and hide secrets so settings can be stored and compared.
/// Hide keys embedded in URLs (e.g. abuse.ch ".../exports/<auth-key>/hostfile.txt" or "?key=..."):
/// any path or query part of 24+ letters/digits that mixes both.
pub fn mask_url(url: &str) -> String {
    let mut out = String::new();
    let mut part = String::new();
    let flush = |part: &mut String, out: &mut String| {
        let keyish = part.len() >= 24
            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && part.chars().any(|c| c.is_ascii_digit())
            && part.chars().any(|c| c.is_ascii_alphabetic());
        out.push_str(if keyish { "***" } else { part });
        part.clear();
    };
    for c in url.chars() {
        if matches!(c, '/' | '?' | '&' | '=' | '#') {
            flush(&mut part, &mut out);
            out.push(c);
        } else {
            part.push(c);
        }
    }
    flush(&mut part, &mut out);
    out
}

pub fn sanitize(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m {
                let kl = k.to_lowercase();
                if matches!(k.as_str(), "uptimestamp" | "blockListNextUpdatedOn") {
                    continue;
                }
                if kl.contains("password") || kl.contains("secret") || kl.contains("token") {
                    let h = sha1_smol::Sha1::from(x.to_string()).digest().to_string();
                    out.insert(k.clone(), Value::String(format!("(hidden, changes tracked: {})", &h[..8])));
                } else {
                    out.insert(k.clone(), sanitize(x));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sanitize).collect()),
        Value::String(x) if x.starts_with("http://") || x.starts_with("https://") => Value::String(mask_url(x)),
        x => x.clone(),
    }
}

fn short(v: Option<&Value>) -> String {
    let t = match v {
        None | Some(Value::Null) => "(none)".to_string(),
        Some(Value::String(x)) => x.clone(),
        Some(x) => x.to_string(),
    };
    if t.chars().count() > 90 { format!("{}...", t.chars().take(87).collect::<String>()) } else { t }
}

/// Top-level settings that differ, as "name: old -> new".
pub fn settings_diff(old: &Value, new: &Value) -> Vec<String> {
    let empty = Map::new();
    let (o, n) = (old.as_object().unwrap_or(&empty), new.as_object().unwrap_or(&empty));
    let keys: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
    keys.into_iter()
        .filter(|k| o.get(*k) != n.get(*k))
        .map(|k| format!("{k}: {} -> {}", short(o.get(k)), short(n.get(k))))
        .collect()
}

/// What Technitium uses a port for, from its settings.
#[derive(Clone, Debug, Default, PartialEq)]
struct Purpose {
    /// e.g. "DNS-over-UDP-PROXY + DNS-over-TCP-PROXY"
    name: String,
    /// Every service on the port is UDP (QUIC, UDP proxy), so a TCP connect test says nothing.
    udp_only: bool,
}

/// Port -> purpose. Several services can share a port (UDP and TCP proxy on 538, DoT and DoQ on 853).
fn port_purposes(set: &Value) -> BTreeMap<u16, Purpose> {
    let port = |k: &str, def: u64| -> u16 { set.get(k).and_then(Value::as_u64).unwrap_or(def) as u16 };
    let mut list: Vec<(u16, &str, bool)> = vec![(53, "DNS", false), (port("webServiceHttpPort", 5380), "web console (HTTP)", false)];
    for (on, k, def, name, udp) in [
        ("webServiceEnableTls", "webServiceTlsPort", 53443, "web console (HTTPS)", false),
        ("enableDnsOverTls", "dnsOverTlsPort", 853, "DNS-over-TLS", false),
        ("enableDnsOverHttps", "dnsOverHttpsPort", 443, "DNS-over-HTTPS", false),
        ("enableDnsOverHttp", "dnsOverHttpPort", 80, "DNS-over-HTTP", false),
        ("enableDnsOverUdpProxy", "dnsOverUdpProxyPort", 538, "DNS-over-UDP-PROXY", true),
        ("enableDnsOverTcpProxy", "dnsOverTcpProxyPort", 538, "DNS-over-TCP-PROXY", false),
        ("enableDnsOverQuic", "dnsOverQuicPort", 853, "DNS-over-QUIC", true),
    ] {
        if b(set, on) {
            list.push((port(k, def), name, udp));
        }
    }
    let mut m: BTreeMap<u16, Purpose> = BTreeMap::new();
    for (p, name, udp) in list {
        match m.get_mut(&p) {
            Some(x) => {
                x.name = format!("{} + {name}", x.name);
                x.udp_only &= udp;
            }
            None => {
                m.insert(p, Purpose { name: name.into(), udp_only: udp });
            }
        }
    }
    m
}

/// Recursion allowed from anywhere (an open resolver if reachable from the internet).
fn recursion_open(set: &Value) -> bool {
    match s(set, "recursion").as_str() {
        "Allow" => true,
        "UseSpecifiedNetworkACL" => arr(set, "recursionNetworkACL")
            .iter()
            .filter_map(Value::as_str)
            .any(|a| matches!(a.trim(), "0.0.0.0/0" | "::/0" | "0.0.0.0" | "::")),
        _ => false,
    }
}

/// Failed resolutions in the last hour, from today's server log.
fn check_upstream_log(api: &Technitium, st: &mut ServerStatus) {
    let r = (|| -> Result<String> {
        let files = api.get("logs/list", &[])?;
        let Some(name) = arr(&files, "logFiles").first().map(|f| s(f, "fileName")) else { return Ok(String::new()) };
        api.get_text("logs/download", &[("fileName", &name)])
    })();
    match r {
        Ok(text) => {
            let (n, names, ns) = parse_failures(&text, chrono::Utc::now() - chrono::Duration::hours(1));
            st.upstream_failures = n;
            st.failing_names = names;
            st.silent_nameservers = ns;
        }
        Err(e) => st.errors.push(format!("server log: {e:#}")),
    }
}

fn top(m: HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Log entries start "[2026-10-24 19:32:46 UTC] DNS Server failed to resolve the request 'x.com. A IN'."
/// and are followed by exception lines naming the name servers that timed out.
pub fn parse_failures(text: &str, since: chrono::DateTime<chrono::Utc>) -> (u64, Vec<(String, u64)>, Vec<(String, u64)>) {
    let mut recent = false;
    let (mut total, mut names, mut servers) = (0u64, HashMap::new(), HashMap::new());
    for line in text.lines() {
        if let Some((ts, msg)) = line.strip_prefix('[').and_then(|r| r.split_once("] ")) {
            if let Ok(t) = chrono::NaiveDateTime::parse_from_str(ts.trim_end_matches(" UTC"), "%Y-%m-%d %H:%M:%S") {
                recent = t.and_utc() >= since;
                if let Some(q) = msg.strip_prefix("DNS Server failed to resolve the request '").filter(|_| recent) {
                    total += 1;
                    let name = q.split_whitespace().next().unwrap_or("").trim_end_matches('.').to_lowercase();
                    *names.entry(name).or_insert(0) += 1;
                }
                continue;
            }
        }
        if let Some((_, rest)) = line.split_once("request timed out for name server [").filter(|_| recent) {
            let ns = rest.split(" (").next().unwrap_or("").trim_end_matches(']').to_string();
            *servers.entry(ns).or_insert(0) += 1;
        }
    }
    (total, top(names, 10), top(servers, 10))
}

fn first_port(p: &str) -> Option<u16> {
    let p = p.trim();
    if p.contains([':', '-', ',']) { None } else { p.parse().ok() }
}

#[derive(Serialize, Deserialize, Default)]
struct Baseline {
    /// client -> (usual hourly queries, samples)
    clients: HashMap<String, (f64, u32)>,
}

const LEARN_SAMPLES: u32 = 12;

#[allow(clippy::too_many_arguments)]
fn check_server(cfg: &Config, store: &Store, srv: &DnsServerCfg, exposure: &[Exposed], st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let d = &cfg.dns;
    let label = srv.label();
    let host = st.host.clone();
    let timeout = Duration::from_secs(d.timeout_seconds.clamp(2, 5));

    // Resolution on port 53 (works without a token).
    for dom in d.test_domains.iter().filter(|x| !x.trim().is_empty()) {
        st.lookups.push(query(&host, dom.trim(), timeout));
    }
    st.dns_ok = st.lookups.iter().any(|l| l.ok) || st.lookups.is_empty();
    let failed: Vec<&Lookup> = st.lookups.iter().filter(|l| !l.ok).collect();
    if st.dns_ok && !failed.is_empty() {
        out.push(Problem {
            key: format!("dns:health:{host}:lookup"),
            kind: "dns",
            severity: Severity::Medium,
            title: format!("DNS {label} can't resolve {}", failed.iter().map(|l| l.domain.as_str()).collect::<Vec<_>>().join(", ")),
            reasons: failed.iter().map(|l| format!("{}: {}", l.domain, l.result)).chain(["other test names resolve, so the server is up - check its forwarders / upstream".to_string()]).collect(),
            targets: vec![host.clone()],
        });
    }

    let api = match Technitium::new(srv, d.timeout_seconds) {
        Ok(a) if !srv.token.trim().is_empty() => a,
        Ok(_) => {
            st.api_error = "no API token configured".into();
            return;
        }
        Err(e) => {
            st.api_error = format!("{e:#}");
            return;
        }
    };
    let set = match api.get("settings/get", &[]) {
        Ok(v) => v,
        Err(e) => {
            st.api_error = format!("{e:#}");
            out.push(Problem {
                key: format!("dns:health:{host}:api"),
                kind: "dns",
                severity: Severity::Medium,
                title: format!("DNS {label}: can't read the Technitium API"),
                reasons: vec![st.api_error.clone(), format!("console {}", srv.url)],
                targets: vec![host.clone()],
            });
            return;
        }
    };
    st.api_ok = true;
    st.version = s(&set, "version");
    st.up_since = s(&set, "uptimestamp");
    st.server_domain = s(&set, "dnsServerDomain");
    st.recursion = s(&set, "recursion");
    st.forwarders = arr(&set, "forwarders").iter().filter_map(|f| f.as_str().map(String::from)).collect();
    if !st.forwarders.is_empty() {
        let proto = s(&set, "forwarderProtocol");
        if !proto.is_empty() {
            st.forwarders.iter_mut().for_each(|f| *f = format!("{f} ({proto})"));
        }
    }
    st.blocking = b(&set, "enableBlocking");
    st.blocklist_urls = arr(&set, "blockListUrls").len();
    st.blocklist_interval_hours = u(&set, "blockListUpdateIntervalHours").max(u(&set, "blockListUrlUpdateIntervalHours"));
    st.blocklist_next_update = s(&set, "blockListNextUpdatedOn");
    if st.blocklist_interval_hours > 0 && !st.blocklist_next_update.is_empty() {
        // Last refresh = next scheduled refresh minus the interval.
        st.blocklist_age_hours = hours_since(&st.blocklist_next_update).map(|h| h + st.blocklist_interval_hours as f64);
    }

    check_upstream_log(&api, st);

    // Traffic (last hour).
    match api.get("dashboard/stats/get", &[("type", "LastHour"), ("utc", "true")]) {
        Ok(v) => {
            let x = v.get("stats").cloned().unwrap_or_default();
            let stats = Stats {
                total: u(&x, "totalQueries"),
                no_error: u(&x, "totalNoError"),
                servfail: u(&x, "totalServerFailure"),
                nxdomain: u(&x, "totalNxDomain"),
                refused: u(&x, "totalRefused"),
                blocked: u(&x, "totalBlocked"),
                cached: u(&x, "totalCached"),
                recursive: u(&x, "totalRecursive"),
                authoritative: u(&x, "totalAuthoritative"),
                clients: u(&x, "totalClients"),
                zones: u(&x, "zones"),
                block_list_zones: u(&x, "blockListZones"),
            };
            let pairs = |k: &str| -> Vec<(String, u64)> { arr(&v, k).iter().map(|e| (s(e, "name"), u(e, "hits"))).take(10).collect() };
            st.top_domains = pairs("topDomains");
            st.top_blocked = pairs("topBlockedDomains");
            if stats.total >= 100 && stats.pct(stats.servfail) >= d.servfail_pct {
                out.push(Problem {
                    key: format!("dns:health:{host}:servfail"),
                    kind: "dns",
                    severity: Severity::Medium,
                    title: format!("DNS {label}: {:.1}% of queries failing upstream", stats.pct(stats.servfail)),
                    reasons: [
                        Some(format!("{} of {} queries in the last hour answered SERVFAIL (limit {}%)", stats.servfail, stats.total, d.servfail_pct)),
                        Some(if st.forwarders.is_empty() { "recursive resolution (no forwarders)".into() } else { format!("forwarders: {}", st.forwarders.join(", ")) }),
                        (st.upstream_failures > 0).then(|| format!("server log: {} failed resolutions in the last hour", st.upstream_failures)),
                        (!st.failing_names.is_empty()).then(|| format!("failing most: {}", pairs_text(&st.failing_names, 6))),
                        (!st.silent_nameservers.is_empty()).then(|| format!("name servers timing out: {}", pairs_text(&st.silent_nameservers, 5))),
                        Some("timeouts to many unrelated name servers point at the internet link (WAN, firewall states); a few names failing over and over is usually those domains' own problem".into()),
                    ]
                    .into_iter()
                    .flatten()
                    .collect(),
                    targets: vec![host.clone()],
                });
            }
            if st.blocking && st.blocklist_urls > 0 && stats.block_list_zones == 0 {
                out.push(Problem {
                    key: format!("dns:health:{host}:blocklist"),
                    kind: "dns",
                    severity: Severity::Medium,
                    title: format!("DNS {label}: blocklists are empty"),
                    reasons: vec![format!("{} blocklist URL(s) configured but no domains loaded - downloads are failing", st.blocklist_urls)],
                    targets: vec![host.clone()],
                });
            }
            st.stats = Some(stats);
        }
        Err(e) => st.errors.push(format!("dashboard: {e:#}")),
    }
    if st.blocking && st.blocklist_urls > 0 {
        if let Some(age) = st.blocklist_age_hours.filter(|a| *a > d.blocklist_max_age_hours as f64) {
            out.push(Problem {
                key: format!("dns:health:{host}:blocklist"),
                kind: "dns",
                severity: Severity::Medium,
                title: format!("DNS {label}: blocklists not refreshed for {age:.0} hours"),
                reasons: vec![format!("next update was due {}", crate::local_time(&st.blocklist_next_update)), format!("limit {} hours", d.blocklist_max_age_hours)],
                targets: vec![host.clone()],
            });
        }
    }

    check_clients(cfg, store, &api, st, out);
    check_nxdomain(cfg, store, &api, st, out);
    check_changes(cfg, store, &api, &set, st, out);

    if let Ok(v) = api.get("user/checkForUpdate", &[]) {
        if b(&v, "updateAvailable") {
            st.update = s(&v, "updateVersion");
            out.push(Problem {
                key: format!("dns:health:{host}:update"),
                kind: "dns",
                severity: Severity::Low,
                title: format!("DNS {label}: Technitium {} is available", st.update),
                reasons: vec![format!("running {}", st.version), format!("update from the console: {}", srv.url)],
                targets: vec![host.clone()],
            });
        }
    }

    check_exposure(&set, &host, &label, exposure, timeout, st, out);
}

fn check_clients(cfg: &Config, store: &Store, api: &Technitium, st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let d = &cfg.dns;
    let v = match api.get("dashboard/stats/getTop", &[("type", "LastHour"), ("statsType", "TopClients"), ("limit", "1000")]) {
        Ok(v) => v,
        Err(e) => {
            st.errors.push(format!("top clients: {e:#}"));
            return;
        }
    };
    let key = format!("dns_baseline:{}", st.host);
    let mut base: Baseline = store.get_kv(&key).ok().flatten().and_then(|x| serde_json::from_str(&x).ok()).unwrap_or_default();
    let mut clients = Vec::new();
    for c in arr(&v, "topClients") {
        let ip = s(&c, "name");
        let hits = u(&c, "hits");
        let entry = base.clients.get(&ip).copied();
        let usual = entry.filter(|e| e.1 >= LEARN_SAMPLES).map(|e| e.0);
        let busy = hits >= d.client_queries_per_hour
            && match usual {
                Some(u) => hits as f64 >= d.client_spike_factor * u.max(1.0),
                // Unknown client: only when far over the threshold.
                None => entry.is_none() && hits as f64 >= d.client_spike_factor * d.client_queries_per_hour as f64,
            };
        if busy {
            out.push(Problem {
                key: format!("dns:client:{ip}:busy"),
                kind: "dns",
                severity: Severity::Medium,
                title: format!("{ip} is making unusually many DNS queries"),
                reasons: vec![
                    format!("{hits} queries in the last hour to {}", st.name),
                    match usual {
                        Some(u) => format!("usually about {u:.0} per hour ({:.0}x normal)", hits as f64 / u.max(1.0)),
                        None => "new client, no usual rate yet".into(),
                    },
                    format!("name: {}", if s(&c, "domain").is_empty() { "(no reverse name)".into() } else { s(&c, "domain") }),
                    "could be malware, a misbehaving app or a DNS loop - see the top domains for this client in Technitium".into(),
                ],
                targets: vec![ip.clone()],
            });
        }
        // Learn slowly, and not from a spike.
        let (avg, n) = entry.unwrap_or((hits as f64, 0));
        let sample = if busy { avg } else { hits as f64 };
        base.clients.insert(ip.clone(), (if n == 0 { sample } else { avg * 0.95 + sample * 0.05 }, n.saturating_add(1)));
        clients.push(Client { ip, name: s(&c, "domain"), hits, usual });
    }
    clients.sort_by_key(|c| std::cmp::Reverse(c.hits));
    st.top_clients = clients.into_iter().take(15).collect();
    if let Ok(j) = serde_json::to_string(&base) {
        let _ = store.set_kv(&key, &j);
    }
}

/// NXDOMAIN bursts per client, from a query-log app (e.g. "Query Logs (Sqlite)") if installed.
fn check_nxdomain(cfg: &Config, store: &Store, api: &Technitium, st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let Ok(apps) = api.get("apps/list", &[]) else { return };
    let Some((name, class)) = arr(&apps, "apps").iter().find_map(|a| {
        arr(a, "dnsApps").iter().find(|x| b(x, "isQueryLogger")).map(|x| (s(a, "name"), s(x, "classPath")))
    }) else {
        return;
    };
    st.query_logger = name.clone();
    let key = format!("dns_nx_since:{}", st.host);
    let now = chrono::Utc::now();
    let since = store
        .get_kv(&key)
        .ok()
        .flatten()
        .and_then(|x| crate::parse_iso(&x))
        .filter(|t| now - *t < chrono::Duration::hours(2))
        .unwrap_or(now - chrono::Duration::minutes(cfg.dns.interval_minutes.max(1) as i64));
    let start = since.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let mut per: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
    for page in 1..=10 {
        let p = page.to_string();
        let v = match api.get(
            "logs/query",
            &[("name", &name), ("classPath", &class), ("pageNumber", &p), ("entriesPerPage", "1000"), ("descendingOrder", "false"), ("start", &start), ("rcode", "NxDomain")],
        ) {
            Ok(v) => v,
            Err(e) => {
                st.errors.push(format!("query log: {e:#}"));
                return;
            }
        };
        for e in arr(&v, "entries") {
            let c = per.entry(s(&e, "clientIpAddress")).or_default();
            c.0 += 1;
            if c.1.len() < 2000 {
                c.1.insert(s(&e, "qname").to_lowercase());
            }
        }
        if u(&v, "totalPages") <= page {
            break;
        }
    }
    let _ = store.set_kv(&key, &crate::iso(now));
    let mut nx: Vec<NxClient> = per
        .into_iter()
        .map(|(ip, (count, names))| NxClient { ip, count, unique: names.len(), sample: names.into_iter().take(8).collect() })
        .collect();
    nx.sort_by_key(|c| std::cmp::Reverse(c.count));
    for c in nx.iter().filter(|c| c.count >= cfg.dns.nxdomain_burst) {
        // Many distinct non-existent names looks like a DGA; repeats of a few are usually a broken config.
        let dga = c.unique as u64 * 2 >= c.count;
        out.push(Problem {
            key: format!("dns:client:{}:nxdomain", c.ip),
            kind: "dns",
            severity: if dga { Severity::High } else { Severity::Medium },
            title: format!("{}: burst of {} failed lookups (NXDOMAIN){}", c.ip, c.count, if dga { " - possible malware" } else { "" }),
            reasons: vec![
                format!("{} names that don't exist, {} distinct, since {} on {}", c.count, c.unique, crate::local_time(&crate::iso(since)), st.name),
                if dga { "many different random-looking names is typical of malware using a domain generation algorithm (DGA)".into() } else { "few distinct names - usually a misconfigured device or app".into() },
                format!("examples: {}", c.sample.join(", ")),
            ],
            targets: vec![c.ip.clone()],
        });
    }
    st.nx_clients = nx.into_iter().take(10).collect();
}

fn check_changes(cfg: &Config, store: &Store, api: &Technitium, set: &Value, st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let host = st.host.clone();
    let label = st.name.clone();
    // Settings.
    let now_set = sanitize(set);
    let key = format!("dns_settings:{host}");
    if let Some(old) = store.get_kv(&key).ok().flatten().and_then(|x| serde_json::from_str::<Value>(&x).ok()) {
        let diff = settings_diff(&old, &now_set);
        if !diff.is_empty() && cfg.dns.change_alerts {
            let h = sha1_smol::Sha1::from(now_set.to_string()).digest().to_string();
            out.push(Problem {
                key: format!("dns:change:{host}:settings:{}", &h[..10]),
                kind: "dns",
                severity: Severity::Medium,
                title: format!("DNS {label}: settings changed ({})", diff.len()),
                reasons: diff.into_iter().take(15).collect(),
                targets: vec![host.clone()],
            });
        }
    }
    let _ = store.set_kv(&key, &now_set.to_string());

    // Zones.
    let v = match api.get("zones/list", &[]) {
        Ok(v) => v,
        Err(e) => {
            st.errors.push(format!("zones: {e:#}"));
            return;
        }
    };
    let zones: Vec<Zone> = arr(&v, "zones")
        .iter()
        .filter(|z| !b(z, "internal"))
        .map(|z| Zone {
            name: s(z, "name"),
            kind: s(z, "type"),
            disabled: b(z, "disabled"),
            serial: s(z, "soaSerial"),
            modified: s(z, "lastModified"),
            problem: [(b(z, "isExpired"), "expired"), (b(z, "syncFailed"), "sync failed"), (b(z, "notifyFailed"), "notify failed")]
                .iter()
                .filter(|x| x.0)
                .map(|x| x.1)
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect();
    for z in zones.iter().filter(|z| !z.problem.is_empty() && !z.disabled) {
        out.push(Problem {
            key: format!("dns:health:{host}:zone:{}", z.name),
            kind: "dns",
            severity: if z.problem.contains("expired") { Severity::High } else { Severity::Medium },
            title: format!("DNS {label}: zone {} {}", if z.name.is_empty() { "(root)" } else { &z.name }, z.problem),
            reasons: vec![format!("{} zone, serial {}", z.kind, z.serial), "secondary zones stop answering once expired".into()],
            targets: vec![host.clone()],
        });
    }
    let zkey = format!("dns_zones:{host}");
    let state: BTreeMap<String, (String, bool, String)> = zones.iter().map(|z| (z.name.clone(), (z.kind.clone(), z.disabled, z.serial.clone()))).collect();
    if let Some(old) = store.get_kv(&zkey).ok().flatten().and_then(|x| serde_json::from_str::<BTreeMap<String, (String, bool, String)>>(&x).ok()) {
        let mut lines = Vec::new();
        let mut structural = false;
        for (name, (kind, dis, serial)) in &state {
            match old.get(name) {
                None => {
                    structural = true;
                    lines.push(format!("added {kind} zone {name}"));
                }
                Some((_, odis, _)) if odis != dis => {
                    structural = true;
                    lines.push(format!("zone {name} {}", if *dis { "disabled" } else { "enabled" }));
                }
                Some((_, _, oserial)) if oserial != serial => lines.push(format!("zone {name} records changed (serial {oserial} -> {serial})")),
                _ => {}
            }
        }
        for name in old.keys().filter(|n| !state.contains_key(*n)) {
            structural = true;
            lines.push(format!("deleted zone {name}"));
        }
        if !lines.is_empty() && cfg.dns.change_alerts {
            // Record edits (incl. dynamic updates) share one finding per day; added/removed zones get their own.
            let day = chrono::Local::now().format("%Y-%m-%d");
            let id = if structural { sha1_smol::Sha1::from(lines.join("|")).digest().to_string()[..10].to_string() } else { format!("records:{day}") };
            out.push(Problem {
                key: format!("dns:change:{host}:zones:{id}"),
                kind: "dns",
                severity: if structural { Severity::Medium } else { Severity::Low },
                title: format!("DNS {label}: {}", if structural { "zones added / removed / disabled" } else { "zone records changed" }),
                reasons: lines.into_iter().take(15).collect(),
                targets: vec![host.clone()],
            });
        }
    }
    if let Ok(j) = serde_json::to_string(&state) {
        let _ = store.set_kv(&zkey, &j);
    }
    st.zones = zones;
}

fn check_exposure(set: &Value, host: &str, label: &str, exposure: &[Exposed], timeout: Duration, st: &mut ServerStatus, out: &mut Vec<Problem>) {
    let purposes = port_purposes(set);
    let open_resolver = recursion_open(set);
    for e in exposure.iter().filter(|e| e.target == host && e.source == "port forward") {
        let port = first_port(&e.port);
        let pp = port.and_then(|p| purposes.get(&p).cloned()).unwrap_or_default();
        let purpose = pp.name.clone();
        let tcp = !pp.udp_only && e.protocol.to_lowercase().contains("tcp") || e.protocol.is_empty() || e.protocol.eq_ignore_ascii_case("any");
        let listening = port.filter(|_| tcp).map(|p| tcp_open(host, p, timeout));
        let mut x = DnsExposure {
            port: e.port.clone(),
            protocol: e.protocol.clone(),
            interface: e.interface.clone(),
            blocked: e.blocked,
            purpose: purpose.clone(),
            listening,
            note: String::new(),
        };
        let pkey = format!("dns:health:exposure:{host}:{}", e.port);
        let target = vec![host.to_string()];
        if purpose.starts_with("web console") {
            x.note = "admin console".into();
            if !e.blocked {
                out.push(Problem {
                    key: pkey,
                    kind: "dns",
                    severity: Severity::Critical,
                    title: format!("DNS {label}: web console is open to the internet"),
                    reasons: vec![format!("{} forwards port {} to the Technitium {purpose}", e.interface, e.port), "anyone can try to log in as admin - remove the port forward".into()],
                    targets: target,
                });
            }
        } else if purpose.is_empty() {
            x.note = match listening {
                Some(true) => "something listens here, but Technitium isn't configured for this port".into(),
                Some(false) => "nothing listens on this port - the forward does nothing".into(),
                None => "not tested".into(),
            };
            if !e.blocked {
                match listening {
                    Some(true) => out.push(Problem {
                        key: pkey,
                        kind: "dns",
                        severity: Severity::Medium,
                        title: format!("DNS {label}: unknown service on port {} is open to the internet", e.port),
                        reasons: vec![
                            format!("{} forwards {} {} to {host}, and the server accepts connections there", e.interface, e.protocol, e.port),
                            "Technitium's settings don't use this port - check what it is, or whether 5380 / 53 was meant".into(),
                        ],
                        targets: target,
                    }),
                    Some(false) => out.push(Problem {
                        key: pkey,
                        kind: "dns",
                        severity: Severity::Low,
                        title: format!("DNS {label}: port forward to {} goes nowhere", e.port),
                        reasons: vec![format!("{} forwards {} {} to {host} but nothing listens there", e.interface, e.protocol, e.port), "remove the forward to keep the rules tidy".into()],
                        targets: target,
                    }),
                    None => {}
                }
            }
        } else {
            x.note = if open_resolver { "recursion allowed for everyone".into() } else { format!("recursion: {}", st.recursion) };
            if !e.blocked && open_resolver {
                out.push(Problem {
                    key: pkey,
                    kind: "dns",
                    severity: Severity::High,
                    title: format!("DNS {label} is an open resolver on the internet ({purpose})"),
                    reasons: vec![
                        format!("{} forwards {} {} to {host} and recursion is allowed for everyone", e.interface, e.protocol, e.port),
                        "it can be abused for DNS amplification attacks - set Recursion to private networks only, or remove the forward".into(),
                    ],
                    targets: target,
                });
            } else if !e.blocked && listening == Some(false) {
                x.note = format!("{purpose} not listening - the forward does nothing");
            }
        }
        st.exposure.push(x);
    }
}

// ---------------------------------------------------------------- orchestration

/// Connection test for Settings: lookups and token check only (stores nothing). Returns (text, any error).
pub fn test(cfg: &Config) -> (String, bool) {
    if cfg.dns.servers.is_empty() {
        return ("No DNS servers are configured.".into(), true);
    }
    let timeout = Duration::from_secs(cfg.dns.timeout_seconds.clamp(2, 5));
    let mut err = false;
    let mut out = Vec::new();
    for srv in &cfg.dns.servers {
        let mut lines = vec![format!("{} ({})", srv.label(), srv.url)];
        for dom in cfg.dns.test_domains.iter().filter(|x| !x.trim().is_empty()) {
            let l = query(&srv.host(), dom.trim(), timeout);
            err |= !l.ok;
            lines.push(format!("  lookup {}: {} ({} answers, {} ms)", l.domain, l.result, l.answers, l.ms));
        }
        let api = if srv.token.trim().is_empty() {
            Err(anyhow!("no API token entered"))
        } else {
            Technitium::new(srv, cfg.dns.timeout_seconds).and_then(|a| a.get("settings/get", &[]))
        };
        match api {
            Ok(v) => lines.push(format!("  API: OK - Technitium {} ({})", s(&v, "version"), s(&v, "dnsServerDomain"))),
            Err(e) => {
                err = true;
                lines.push(format!("  API: FAILED - {e:#}"));
            }
        }
        out.push(lines.join("
"));
    }
    (out.join("

"), err)
}

/// Suricata stop / start pairs in the firewall log within the last `hours`, e.g.
/// "Suricata restarted 10:10:08 - 10:14:36 (4.5 min)". In inline (Netmap) mode the WAN stalls meanwhile.
pub fn ids_restarts(api: &crate::opnsense::OPNsense, hours: i64) -> Result<Vec<String>> {
    let since = chrono::Utc::now() - chrono::Duration::hours(hours);
    let times = |phrase: &str| -> Result<Vec<chrono::DateTime<chrono::Utc>>> {
        let v = api.post_raw("diagnostics/log/core/suricata", serde_json::json!({"current": 1, "rowCount": 50, "searchPhrase": phrase}))?;
        let mut t: Vec<_> = arr(&v, "rows").iter().filter_map(|r| crate::parse_iso(&s(r, "timestamp"))).filter(|t| *t >= since).collect();
        t.sort();
        Ok(t)
    };
    let stops = times("Stopping engine")?;
    let starts = times("Engine started")?;
    let local = |t: &chrono::DateTime<chrono::Utc>| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string();
    Ok(stops
        .iter()
        .map(|stop| match starts.iter().find(|st| *st >= stop) {
            Some(st) => format!("Suricata restarted {} - {} ({:.1} min)", local(stop), local(st), (*st - *stop).num_seconds() as f64 / 60.0),
            None => format!("Suricata stopped at {} and hasn't logged a restart", local(stop)),
        })
        .collect())
}

/// Check every configured server. `exposure` is the firewall's latest exposure audit and `ids_restarts`
/// Suricata's recent restarts (both may be empty).
pub fn run(cfg: &Config, store: &Store, exposure: &[Exposed], ids_restarts: &[String]) -> Result<(Snapshot, Vec<Finding>)> {
    let mut snap = Snapshot { at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(), servers: vec![], ids_restarts: ids_restarts.to_vec() };
    let mut problems = Vec::new();
    let servers: Vec<&DnsServerCfg> = cfg.dns.servers.iter().filter(|s| !s.url.trim().is_empty()).collect();
    std::thread::scope(|sc| {
        let handles: Vec<_> = servers
            .iter()
            .map(|srv| {
                sc.spawn(move || {
                    let mut st = ServerStatus { name: srv.label(), url: srv.url.clone(), host: srv.host(), ..Default::default() };
                    let mut out = Vec::new();
                    check_server(cfg, store, srv, exposure, &mut st, &mut out);
                    for e in &st.errors {
                        warn!("DNS {}: {e}", st.name);
                    }
                    (st, out)
                })
            })
            .collect();
        for h in handles {
            if let Ok((st, out)) = h.join() {
                snap.servers.push(st);
                problems.extend(out);
            }
        }
    });

    // Up / down with failover state.
    let down: Vec<&ServerStatus> = snap.servers.iter().filter(|s| !s.dns_ok).collect();
    let up: Vec<&ServerStatus> = snap.servers.iter().filter(|s| s.dns_ok).collect();
    for s in &down {
        let why = s.lookups.iter().map(|l| format!("{}: {}", l.domain, l.result)).collect::<Vec<_>>().join("; ");
        if up.is_empty() {
            continue;
        }
        problems.push(Problem {
            key: format!("dns:health:{}:down", s.host),
            kind: "dns",
            severity: Severity::High,
            title: format!("DNS server {} ({}) is not answering", s.name, s.host),
            reasons: vec![
                why,
                format!("clients fail over to {} - lookups are slower and there is no redundancy", up.iter().map(|u| u.name.as_str()).collect::<Vec<_>>().join(", ")),
                if s.api_ok { "the web console still answers, so the DNS service itself is stuck".into() } else { format!("web console: {}", if s.api_error.is_empty() { "unreachable" } else { &s.api_error }) },
            ],
            targets: vec![s.host.clone()],
        });
    }
    if !down.is_empty() && up.is_empty() {
        problems.push(Problem {
            key: "dns:health:all:down".into(),
            kind: "dns",
            severity: Severity::Critical,
            title: "No DNS server is answering - name resolution is down on the LAN".into(),
            reasons: down.iter().map(|s| format!("{} ({}): {}", s.name, s.host, s.lookups.first().map(|l| l.result.as_str()).unwrap_or("?"))).collect(),
            targets: down.iter().map(|s| s.host.clone()).collect(),
        });
    }

    // Upstream trouble during an inline-IPS restart has a known cause; say so.
    if !ids_restarts.is_empty() {
        for p in problems.iter_mut().filter(|p| p.key.ends_with(":servfail") || p.key.ends_with(":lookup") || p.key == "dns:health:all:down") {
            p.reasons.insert(1, format!("{} - with inline IPS the WAN stalls while Suricata reloads, so this is expected and clears within the hour", ids_restarts.join("; ")));
        }
    }

    let alerted = crate::health::sync(cfg, store, &problems, &["dns:health:"])?;
    Ok((snap, alerted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn qname_encoding() {
        assert_eq!(qname("a.bc").unwrap(), vec![1, b'a', 2, b'b', b'c', 0]);
        assert!(qname("a..b").is_err());
    }

    #[test]
    fn settings_are_sanitized_and_diffed() {
        let a = sanitize(&json!({"version": "13.6", "uptimestamp": "x", "proxy": {"password": "hunter2"}, "forwarders": ["1.1.1.1"]}));
        assert!(!a.to_string().contains("hunter2"));
        assert!(a.get("uptimestamp").is_none());
        let b = sanitize(&json!({"version": "13.6", "uptimestamp": "y", "proxy": {"password": "other"}, "forwarders": ["9.9.9.9"]}));
        let d = settings_diff(&a, &b);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d.iter().any(|l| l.starts_with("forwarders:") && l.contains("9.9.9.9")));
        let u = sanitize(&json!({"blockListUrls": ["https://threatfox-api.abuse.ch/v2/files/exports/3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c/hostfile.txt"]}));
        assert_eq!(u["blockListUrls"][0], "https://threatfox-api.abuse.ch/v2/files/exports/***/hostfile.txt");
        assert_eq!(mask_url("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"), "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt");
    }

    #[test]
    fn log_failures() {
        let log = [
            "[2026-10-24 19:32:46 UTC] DNS Server failed to resolve the request 'edge.nc0.co. A IN'.",
            " ---> y: request timed out for name server [ns-1781.awsdns-30.co.uk (205.251.198.245)].",
            "[2026-10-24 19:33:00 UTC] DNS Server successfully refreshed 'a' Secondary zone",
            "[2026-10-24 10:00:00 UTC] DNS Server failed to resolve the request 'old.com. A IN'.",
            " ---> y: request timed out for name server [old (1.1.1.1)].",
        ]
        .join("\n");
        let since = chrono::DateTime::parse_from_rfc3339("2026-10-24T19:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let (n, names, ns) = parse_failures(&log, since);
        assert_eq!(n, 1);
        assert_eq!(names, vec![("edge.nc0.co".to_string(), 1)]);
        assert_eq!(ns, vec![("ns-1781.awsdns-30.co.uk".to_string(), 1)]);
    }

    #[test]
    fn ports() {
        let p = port_purposes(&json!({"webServiceHttpPort": 5380, "enableDnsOverTls": true, "dnsOverTlsPort": 853, "enableDnsOverQuic": true,
            "enableDnsOverUdpProxy": true, "enableDnsOverTcpProxy": true}));
        assert_eq!(p[&5380].name, "web console (HTTP)");
        assert_eq!(p[&853].name, "DNS-over-TLS + DNS-over-QUIC");
        assert!(!p[&853].udp_only);
        assert_eq!(p[&538].name, "DNS-over-UDP-PROXY + DNS-over-TCP-PROXY");
        assert!(port_purposes(&json!({"enableDnsOverQuic": true}))[&853].udp_only);
        assert!(recursion_open(&json!({"recursion": "UseSpecifiedNetworkACL", "recursionNetworkACL": ["0.0.0.0/0"]})));
        assert!(!recursion_open(&json!({"recursion": "UseSpecifiedNetworkACL", "recursionNetworkACL": ["192.168.1.0/24"]})));
        assert_eq!(first_port("538"), Some(538));
        assert_eq!(first_port("53:54"), None);
    }
}
