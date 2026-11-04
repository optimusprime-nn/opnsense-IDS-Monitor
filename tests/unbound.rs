//! OPNsense Unbound DNS backend: response parsing from fixture JSON (shapes taken from opnsense/core
//! 25.1-26.7 and a live 26.x firewall) and full checks against a loopback fake of the firewall API.
//! Nothing here contacts a real firewall or DNS server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ipswatch::config::{Config, DnsKind, DnsServerCfg, Severity};
use ipswatch::dns::unbound::*;
use ipswatch::dns::{self, settings_diff, Stats};
use ipswatch::store::Store;
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unbound").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

// ---- parsing ---------------------------------------------------------------------------

#[test]
fn settings_26x_policies_forwarders_and_acl() {
    let s = parse_settings(&fixture("settings_26.json"));
    assert!(s.enabled && s.stats);
    assert_eq!(s.port, 53);
    // Enabled DoT and plain forward entries; the disabled one is left out.
    assert_eq!(s.forwarders, vec!["9.9.9.9:853 (DoT)".to_string(), "192.168.50.2 for lab.example".to_string()]);
    assert_eq!(s.recursion, "forwarding to the servers below");
    // Enabled policy: two predefined lists + one custom URL; the disabled policy doesn't count.
    assert!(s.blocking);
    assert_eq!(s.blocklists, 3);
    assert!(s.open_resolver, "default_action allow -> 0.0.0.0/0 allow");
}

#[test]
fn settings_25_1_single_dnsbl_section() {
    let s = parse_settings(&fixture("settings_25_1.json"));
    assert!(s.enabled && !s.stats);
    assert_eq!(s.port, 5353);
    assert!(s.forwarders.is_empty());
    assert_eq!(s.recursion, "forwarding to the system DNS servers");
    assert!(s.blocking);
    assert_eq!(s.blocklists, 3, "one predefined list + two custom URLs");
    assert!(!s.open_resolver, "default_action refuse");
}

#[test]
fn settings_disabled_unbound_and_empty_blocklist() {
    let v = json!({"unbound": {"general": {"enabled": "0", "stats": "0", "port": "53"},
        "dnsbl": {"blocklist": {"u1": {"enabled": "1", "type": {"ag": {"selected": 0, "value": "AdGuard"}}, "lists": {"": {"selected": 1, "value": ""}}}}},
        "acls": {"acl": [], "default_action": {"allow": {"selected": 1, "value": "Allow"}}}}});
    let s = parse_settings(&v);
    assert!(!s.enabled);
    assert!(!s.blocking, "an enabled policy with nothing selected blocks nothing");
    assert_eq!(s.blocklists, 0);
    assert_eq!(s.recursion, "recursive");
}

#[test]
fn option_fields_in_every_shape() {
    assert_eq!(selected(Some(&json!({"a": {"value": "A", "selected": 1}, "b": {"value": "B", "selected": 0}}))), vec!["a"]);
    assert_eq!(selected(Some(&json!([{"value": "Level 0", "selected": 0}, {"value": "Level 1", "selected": 1}]))), vec!["Level 1"]);
    assert_eq!(selected(Some(&json!("x, y,,z"))), vec!["x", "y", "z"]);
    assert!(selected(Some(&json!({"": {"value": "", "selected": 1}}))).is_empty());
    assert!(selected(None).is_empty());
}

#[test]
fn settings_changes_diff_to_readable_lines() {
    let before = fixture("settings_26.json");
    let mut after = before.clone();
    after["unbound"]["general"]["port"] = json!("5353");
    after["unbound"]["dots"]["dot"]["13045c61-2060-475b-b463-e156cb0e25a9"]["server"] = json!("149.112.112.112");
    after["unbound"]["dnsbl"]["blocklist"]["4eaac1bd-d2cd-4c74-995f-3f9cd6b01fd2"]["type"]["el"]["selected"] = json!(1);
    let a = dns::sanitize(&compact_settings(&before));
    let b = dns::sanitize(&compact_settings(&after));
    assert_eq!(a["general.local_zone_type"], "transparent");
    assert_eq!(a["advanced.logverbosity"], "Level 1 (Default)");
    let d = settings_diff(&a, &b);
    assert_eq!(d.len(), 3, "{d:?}");
    assert!(d.contains(&"general.port: 53 -> 5353".to_string()), "{d:?}");
    assert!(d.iter().any(|l| l.starts_with("dots.dot.13045c61-2060-475b-b463-e156cb0e25a9.server: 9.9.9.9 -> 149.112.112.112")), "{d:?}");
    assert!(d.iter().any(|l| l.contains(".type: ag,hgz011 -> ag,el,hgz011")), "{d:?}");
    // Nothing changed -> nothing to report.
    assert!(settings_diff(&a, &dns::sanitize(&compact_settings(&before))).is_empty());
}

#[test]
fn stats_switch() {
    assert!(parse_enabled(&json!({"enabled": "1"})));
    assert!(!parse_enabled(&json!({"enabled": "0"})));
    assert!(!parse_enabled(&json!({})));
}

#[test]
fn rolling_counts_sum_to_the_hour() {
    let s = parse_rolling(&fixture("rolling.json"));
    assert_eq!((s.total, s.blocked, s.cached, s.recursive, s.authoritative), (200, 12, 133, 50, 5));
    // No statistics database yet: OPNsense answers [].
    assert_eq!(parse_rolling(&json!([])).total, 0);
}

#[test]
fn rolling_clients_sum_per_client() {
    let c = parse_rolling_clients(&fixture("rolling_clients.json"));
    assert_eq!(
        c,
        vec![
            ("192.168.1.20".to_string(), "nas.home.example".to_string(), 75),
            ("192.168.1.44".to_string(), "laptop.home.example".to_string(), 50),
            ("192.168.1.31".to_string(), String::new(), 12),
        ]
    );
    assert!(parse_rolling_clients(&json!([])).is_empty());
}

#[test]
fn totals_top_lists_sorted() {
    let t = parse_totals(&fixture("totals.json")).unwrap();
    assert_eq!(t.total, 48210);
    assert_eq!(t.blocklist_size, Some(152344));
    assert_eq!(t.start_time, Some(1793600000));
    assert_eq!(t.top[0], ("time.example.org".to_string(), 9001));
    // Ties sort by name.
    assert_eq!(t.top[1].0, "cdn.example.net");
    assert_eq!(t.top_blocked, vec![("ads.example.com".to_string(), 1201), ("telemetry.example.com".to_string(), 640)]);
    assert!(parse_totals(&json!([])).is_none(), "a failed totals call is []");
}

fn row(t: i64, client: &str, domain: &str, rcode: &str) -> Value {
    json!({"time": t, "client": client, "family": "IPv4", "type": "A", "domain": domain, "action": "Pass",
           "source": "Recursion", "blocklist": null, "rcode": rcode, "resolve_time_ms": 12, "dnssec_status": "Insecure",
           "ttl": 300, "uuid": null, "policy": "", "status": 2})
}

#[test]
fn query_log_nxdomain_and_rcodes() {
    let v = json!({"total": 5, "rowCount": 5, "current": 1, "rows": [
        row(1000, "192.168.1.44", "qxzvbk.example", "NXDOMAIN"),
        row(1001, "192.168.1.44", "Plmnbv.example.", "NXDOMAIN"),
        row(1002, "192.168.1.44", "qxzvbk.example", "NXDOMAIN"),
        row(1003, "nas.home.example", "time.example.org", "SERVFAIL"),
        row(10, "192.168.1.44", "old.example", "NXDOMAIN"),
    ]});
    let rows = query_rows(&v);
    assert_eq!(rows.len(), 5);
    let nx = nx_by_client(&rows, 1000);
    assert_eq!(nx.len(), 1);
    let (count, names) = &nx["192.168.1.44"];
    assert_eq!(*count, 3);
    assert_eq!(names.iter().cloned().collect::<Vec<_>>(), vec!["plmnbv.example", "qxzvbk.example"]);
    assert_eq!(rcode_sample(&rows, 1000), (4, 1, 3));
    assert!(query_rows(&json!({"current": 1, "rowCount": 0, "rows": [], "total": 0})).is_empty());
}

#[test]
fn unbound_control_counters() {
    let c = parse_diag(&fixture("diag_stats.json")).unwrap();
    assert_eq!((c.queries, c.cachehits, c.cachemiss), (52000, 41000, 11000));
    assert_eq!((c.servfail, c.nxdomain), (Some(700), Some(3300)));
    assert_eq!(c.uptime, Some(86400.5));
    // Unbound not running.
    assert!(parse_diag(&json!({"status": "failed"})).is_none());
    // Without extended statistics there are no rcode counters.
    let plain = parse_diag(&json!({"status": "ok", "data": {"total": {"num": {"queries": "10", "cachehits": "4", "cachemiss": "6"}}}})).unwrap();
    assert_eq!(plain.servfail, None);

    let later = Counters { queries: 53000, cachehits: 41700, cachemiss: 11300, servfail: Some(900), nxdomain: Some(3400), uptime: Some(86700.0) };
    let d = counter_delta(&c, &later).unwrap();
    assert_eq!((d.total, d.cached, d.recursive, d.servfail, d.nxdomain), (1000, 700, 300, 200, 100));
    assert!((d.pct(d.servfail) - 20.0).abs() < 1e-9);
    // Restarted: counters went down.
    assert!(counter_delta(&later, &c).is_none());
}

// ---- end to end against a fake firewall API ------------------------------------------

/// Minimal HTTP fake of the OPNsense API: `answer("GET /api/...")` gives the JSON body.
fn fake_api(answer: impl Fn(&str) -> String + Send + Sync + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            let mut r = BufReader::new(sock.try_clone().unwrap());
            let mut first = String::new();
            if r.read_line(&mut first).is_err() {
                continue;
            }
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            let _ = r.read_exact(&mut body);
            let req = first.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            let out = answer(&req);
            log.lock().unwrap().push(req);
            let mut w = sock;
            let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
        }
    });
    (url, seen)
}

fn unbound_cfg(url: &str) -> Config {
    let mut cfg = Config::default();
    cfg.opnsense.url = url.into();
    cfg.opnsense.allow_http = true; // the fake speaks plain HTTP
    cfg.opnsense.api_key = "k".into();
    cfg.opnsense.api_secret = "s".into();
    cfg.dns.test_domains = vec![]; // no port-53 traffic in tests
    cfg.dns.nxdomain_burst = 20;
    cfg.dns.servers = vec![DnsServerCfg { name: "fw".into(), kind: DnsKind::Unbound, ..Default::default() }];
    cfg
}

/// A host that bursts NXDOMAIN for random names, and some SERVFAIL, all within the last minutes.
fn live_query_log() -> String {
    let now = chrono::Utc::now().timestamp();
    let mut rows: Vec<Value> = (0..30).map(|i| row(now - 30 + i, "192.168.1.66", &format!("k{i}x{}q.example", i * 7919 % 1000), "NXDOMAIN")).collect();
    rows.extend((0..50).map(|i| row(now - 120 + i, "192.168.1.20", "time.example.org", if i % 2 == 0 { "SERVFAIL" } else { "NOERROR" })));
    rows.extend((0..20).map(|i| row(now - 200 + i, "192.168.1.20", "cdn.example.net", "NOERROR")));
    json!({"total": rows.len(), "rowCount": rows.len(), "current": 1, "rows": rows}).to_string()
}

fn stats_on_api(req: &str) -> String {
    let path = req.split_whitespace().nth(1).unwrap_or("");
    match path {
        "/api/unbound/settings/get" => fixture("settings_26.json").to_string(),
        "/api/unbound/overview/is_enabled" => r#"{"enabled":"1"}"#.into(),
        "/api/unbound/diagnostics/stats" => fixture("diag_stats.json").to_string(),
        "/api/unbound/overview/totals/10" => fixture("totals.json").to_string(),
        "/api/unbound/overview/rolling/1" => fixture("rolling.json").to_string(),
        "/api/unbound/overview/rolling/1/1" => fixture("rolling_clients.json").to_string(),
        "/api/unbound/overview/search_queries" => live_query_log(),
        _ => "{}".into(),
    }
}

#[test]
fn unbound_with_statistics_full_check() {
    let (url, seen) = fake_api(stats_on_api);
    let cfg = unbound_cfg(&url);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("u.db")).unwrap();
    let (snap, _) = dns::run(&cfg, &store, &[], &[]).unwrap();
    let st = &snap.servers[0];

    assert_eq!(st.backend, "unbound");
    assert_eq!(st.host, "127.0.0.1", "Unbound defaults to the firewall's address");
    assert!(st.api_ok && st.dns_ok, "{st:?}");
    assert!(st.errors.is_empty(), "{:?}", st.errors);
    assert!(!st.notes.iter().any(|n| n.contains("statistics are off")), "{:?}", st.notes);
    assert!(!st.up_since.is_empty());
    assert_eq!(st.forwarders.len(), 2);
    assert!(st.blocking);

    let stats: &Stats = st.stats.as_ref().expect("stats");
    assert_eq!(stats.total, 200);
    assert_eq!(stats.clients, 3);
    assert_eq!(stats.block_list_zones, 152344);
    // Query log sample: 25 SERVFAIL and 30 NXDOMAIN of 100, scaled to the hour's 200 queries.
    assert_eq!((stats.servfail, stats.nxdomain), (50, 60));
    assert_eq!(st.top_blocked[0].0, "ads.example.com");
    assert!(st.top_window.starts_with("since "));
    assert_eq!(st.top_clients[0].ip, "192.168.1.20");

    let nx = store.get_finding("dns:client:192.168.1.66:nxdomain").unwrap().expect("NXDOMAIN burst finding");
    assert_eq!(nx.severity, Severity::High, "30 distinct random names looks like a DGA");
    let sf = store.get_finding("dns:health:127.0.0.1:servfail").unwrap().expect("SERVFAIL finding");
    assert!(sf.reasons[0].contains("50 of 200"), "{:?}", sf.reasons);
    assert!(store.get_finding("dns:health:127.0.0.1:stats_off").unwrap().is_none());
    assert!(store.get_finding("dns:health:127.0.0.1:blocklist").unwrap().is_none());

    // GET only, and only Unbound paths on the firewall.
    let reqs = seen.lock().unwrap().clone();
    assert!(!reqs.is_empty());
    assert!(reqs.iter().all(|r| r.starts_with("GET /api/unbound/")), "{reqs:?}");

    // Second run: a settings change is reported as a readable diff.
    let (url2, _) = fake_api(|req| {
        if req.ends_with("/settings/get") {
            let mut v = fixture("settings_26.json");
            v["unbound"]["general"]["port"] = json!("5353");
            v.to_string()
        } else {
            stats_on_api(req)
        }
    });
    let mut cfg2 = unbound_cfg(&url2);
    cfg2.opnsense.url = cfg2.opnsense.url.replace("127.0.0.1", "localhost");
    // Same host key as before so the stored settings are compared.
    cfg2.dns.servers[0].url = "127.0.0.1".into();
    dns::run(&cfg2, &store, &[], &[]).unwrap();
    let changed = store.list_findings(Some("open"), Severity::Low, 100).unwrap();
    let ch = changed.iter().find(|f| f.key.starts_with("dns:change:127.0.0.1:settings:")).expect("settings change finding");
    assert_eq!(ch.reasons, vec!["general.port: 53 -> 5353".to_string()]);
}

#[test]
fn unbound_statistics_off_is_reported_not_an_error() {
    // The user's own firewall today: Unbound off, statistics off, stats call failed, totals [].
    let (url, seen) = fake_api(|req| {
        let path = req.split_whitespace().nth(1).unwrap_or("");
        match path {
            "/api/unbound/settings/get" => {
                let mut v = fixture("settings_26.json");
                v["unbound"]["general"]["stats"] = json!("0");
                v.to_string()
            }
            "/api/unbound/overview/is_enabled" => r#"{"enabled":"0"}"#.into(),
            "/api/unbound/diagnostics/stats" => r#"{"status":"failed"}"#.into(),
            "/api/unbound/overview/totals/10" => "[]".into(),
            "/api/unbound/overview/rolling/1" | "/api/unbound/overview/rolling/1/1" => "[]".into(),
            _ => r#"{"current":1,"rowCount":0,"rows":[],"total":0}"#.into(),
        }
    });
    let cfg = unbound_cfg(&url);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("off.db")).unwrap();
    let (snap, _) = dns::run(&cfg, &store, &[], &[]).unwrap();
    let st = &snap.servers[0];
    assert!(st.api_ok);
    assert!(st.errors.is_empty(), "missing statistics are not errors: {:?}", st.errors);
    assert!(st.stats.is_none());
    assert!(st.notes.iter().any(|n| n == STATS_OFF), "{:?}", st.notes);
    let f = store.get_finding("dns:health:127.0.0.1:stats_off").unwrap().expect("statistics-off finding");
    assert_eq!(f.severity, Severity::Low);
    assert!(f.reasons[0].contains("Reporting > Unbound DNS"));
    // No blocklist alarm without a running Unbound to report what it loaded.
    assert!(store.get_finding("dns:health:127.0.0.1:blocklist").unwrap().is_none());
    // Statistics endpoints that need them are not called.
    let reqs = seen.lock().unwrap().clone();
    assert!(!reqs.iter().any(|r| r.contains("search_queries") || r.contains("rolling")), "{reqs:?}");
    assert!(reqs.iter().all(|r| r.starts_with("GET ")));

    // Turning statistics on resolves the finding.
    let (url2, _) = fake_api(stats_on_api);
    dns::run(&unbound_cfg(&url2), &store, &[], &[]).unwrap();
    assert_eq!(store.get_finding("dns:health:127.0.0.1:stats_off").unwrap().unwrap().status, "resolved");
}

#[test]
fn unbound_disabled_skips_traffic_checks_quietly() {
    let (url, seen) = fake_api(|req| {
        if req.ends_with("/settings/get") {
            let mut v = fixture("settings_26.json");
            v["unbound"]["general"]["enabled"] = json!("0");
            v.to_string()
        } else {
            "{}".into()
        }
    });
    let cfg = unbound_cfg(&url);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("dis.db")).unwrap();
    let (snap, _) = dns::run(&cfg, &store, &[], &[]).unwrap();
    let st = &snap.servers[0];
    assert!(st.api_ok && st.errors.is_empty());
    assert!(st.notes.iter().any(|n| n.contains("turned off")), "{:?}", st.notes);
    assert_eq!(seen.lock().unwrap().len(), 1, "only the settings are read");
}

#[test]
fn unbound_api_failure_is_one_finding_without_secrets() {
    // Nothing listens here: the API call fails.
    let mut cfg = unbound_cfg("http://127.0.0.1:9");
    cfg.opnsense.api_secret = "sup3r-s3cret".into();
    cfg.opnsense.timeout_seconds = 5;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("f.db")).unwrap();
    let (snap, _) = dns::run(&cfg, &store, &[], &[]).unwrap();
    let st = &snap.servers[0];
    assert!(!st.api_ok);
    assert!(!st.api_error.contains("sup3r"));
    let f = store.get_finding("dns:health:127.0.0.1:api").unwrap().expect("API finding");
    assert!(f.title.contains("Unbound"));
    assert!(!f.reasons.join(" ").contains("sup3r"));
}

#[test]
fn unbound_config_validation_and_defaults() {
    // Old configs without `kind` stay Technitium.
    let old: DnsServerCfg = toml::from_str("name = \"ns1\"\nurl = \"https://192.168.1.53:53443\"\ntoken = \"t\"").unwrap();
    assert_eq!(old.kind, DnsKind::Technitium);
    let new: DnsServerCfg = toml::from_str("name = \"fw\"\nkind = \"unbound\"").unwrap();
    assert_eq!(new.kind, DnsKind::Unbound);
    assert_eq!(new.query_host("https://192.168.1.1:8443"), "192.168.1.1");
    assert_eq!(DnsServerCfg { kind: DnsKind::Unbound, url: "10.0.0.1".into(), ..Default::default() }.query_host("https://192.168.1.1"), "10.0.0.1");
    assert_eq!(DnsServerCfg { kind: DnsKind::Unbound, ..Default::default() }.label(), "Unbound (firewall)");

    let mut cfg = Config::default();
    cfg.dns.servers.push(new);
    assert!(cfg.validate().is_err(), "Unbound needs the firewall URL");
    cfg.opnsense.url = "https://192.168.1.1".into();
    assert!(cfg.validate().is_ok(), "no token or console URL needed for Unbound");
}

#[test]
fn ipv6_forwarders_are_bracketed() {
    let v = json!({"unbound": {"general": {"enabled": "1"}, "dots": {"dot": {"u": {"enabled": "1", "server": "2620:fe::9", "port": "853",
        "type": {"dot": {"selected": 1, "value": "DNS over TLS"}}}}}}});
    assert_eq!(parse_settings(&v).forwarders, vec!["[2620:fe::9]:853 (DoT)".to_string()]);
}
