//! Regression tests for the 2026-11-03 security review. They use loopback fakes and temporary
//! databases only; nothing here contacts a real firewall or DNS server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use chrono::{Duration, TimeZone, Utc};
use ipswatch::collect;
use ipswatch::config::{Config, DnsServerCfg};
use ipswatch::engine;
use ipswatch::normalize::{normalize, Event};
use ipswatch::opnsense::OPNsense;
use ipswatch::store::Store;
use serde_json::{json, Value};

#[allow(clippy::too_many_arguments)]
fn eve(src: &str, dst: &str, dport: i64, sig: &str, sid: i64, sev: i64, cat: &str, action: &str, t: i64) -> Value {
    let ts = Utc.with_ymd_and_hms(2026, 10, 19, 12, 0, 0).unwrap() + Duration::seconds(t);
    json!({
        "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.6f+0000").to_string(),
        "flow_id": 1000 + t, "in_iface": "igb0", "event_type": "alert",
        "src_ip": src, "src_port": 40000 + t % 1000, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
        "alert": {"action": action, "gid": 1, "signature_id": sid, "rev": 1, "signature": sig, "category": cat, "severity": sev}
    })
}

/// The audit's forged event: severity 1 exploit, not dropped, against internal SSH (scores 120).
fn forged(i: i64) -> Event {
    normalize(&eve("198.51.100.50", "192.168.1.10", 22, "ET EXPLOIT OpenSSH", 2, 1, "Attempted Administrator Privilege Gain", "allowed", i)).unwrap()
}

/// Minimal HTTP fake of the OPNsense API. `answer(method_and_path)` gives the JSON body;
/// every request line is recorded.
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

fn api_cfg(url: &str) -> Config {
    let mut cfg = Config::default();
    cfg.opnsense.url = url.into();
    cfg.opnsense.allow_http = true; // the fake speaks plain HTTP
    cfg.opnsense.api_key = "k".into();
    cfg.opnsense.api_secret = "s".into();
    cfg.firewall.correlate = false;
    cfg.crowdsec.enabled = false;
    cfg.block.enabled = true;
    cfg.block.dry_run = false;
    cfg
}

/// Fake whose alias accepts additions and then lists them.
fn working_alias() -> impl Fn(&str) -> String + Send + Sync + 'static {
    let members = Arc::new(Mutex::new(Vec::<String>::new()));
    move |req: &str| {
        if req.contains("alias_util/add") {
            members.lock().unwrap().push("198.51.100.50".into());
            r#"{"status":"done"}"#.into()
        } else if req.contains("alias_util/list") {
            let rows: Vec<Value> = members.lock().unwrap().iter().map(|ip| json!({"ip": ip})).collect();
            json!({"rows": rows}).to_string()
        } else {
            "{}".into()
        }
    }
}

// ---- Finding 1: syslog-only alerts never cause a firewall write --------------------------

#[test]
fn syslog_only_critical_finding_is_not_auto_blocked() {
    let (url, seen) = fake_api(working_alias());
    let cfg = api_cfg(&url);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("s.db")).unwrap();
    store.add_events(&[forged(0), forged(1)], "syslog").unwrap();
    let api = OPNsense::new(&cfg.opnsense).unwrap();
    engine::run_detection(&cfg, &store, Some(&api), None, false).unwrap();
    let f = store.get_finding("inbound:198.51.100.50").unwrap().expect("finding still raised");
    assert_eq!(f.severity, ipswatch::config::Severity::Critical);
    assert!(f.blocked_at.is_none());
    assert!(!seen.lock().unwrap().iter().any(|r| r.contains("alias_util/add")), "{:?}", seen.lock().unwrap());
}

#[test]
fn api_confirmed_critical_finding_is_blocked_and_verified() {
    let (url, seen) = fake_api(working_alias());
    let cfg = api_cfg(&url);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("a.db")).unwrap();
    store.add_events(&[forged(0), forged(1)], "api").unwrap();
    let api = OPNsense::new(&cfg.opnsense).unwrap();
    engine::run_detection(&cfg, &store, Some(&api), None, false).unwrap();
    assert!(store.get_finding("inbound:198.51.100.50").unwrap().unwrap().blocked_at.is_some());
    let reqs = seen.lock().unwrap();
    assert!(reqs.iter().any(|r| r.contains("alias_util/add")));
    assert!(reqs.iter().any(|r| r.contains("alias_util/list")), "the write was verified");
}

// ---- Finding 2: syslog intake limits ----------------------------------------------------

#[test]
fn syslog_from_unlisted_sender_is_refused() {
    let rx = collect::SyslogReceiver::start("127.0.0.1", 55151, "udp", vec!["10.9.9.9/32".parse().unwrap()]).unwrap();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let line = format!("<14>1 2026-10-19T12:00:00Z fw suricata 1 - - {}", eve("203.0.113.1", "192.168.1.2", 22, "ET SCAN", 9, 2, "Misc", "allowed", 0));
    sock.send_to(line.as_bytes(), "127.0.0.1:55151").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("u.db")).unwrap();
    assert_eq!(rx.flush(&store).unwrap(), 0);
}

#[test]
fn syslog_receiver_needs_an_allowed_sender() {
    assert!(collect::SyslogReceiver::start("127.0.0.1", 55152, "udp", vec![]).is_err());
}

#[test]
fn tcp_syslog_drops_oversized_lines_but_keeps_normal_ones() {
    let rx = collect::SyslogReceiver::start("127.0.0.1", 55153, "tcp", vec!["127.0.0.1/32".parse().unwrap()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // A line longer than the limit, never terminated: the connection is closed.
    let mut big = std::net::TcpStream::connect("127.0.0.1:55153").unwrap();
    let junk = vec![b'x'; collect::MAX_LINE + 10];
    let _ = big.write_all(&junk);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let mut buf = [0u8; 1];
    big.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    assert!(matches!(big.read(&mut buf), Ok(0) | Err(_)), "oversized connection should be closed");
    // A normal connection still works.
    let mut ok = std::net::TcpStream::connect("127.0.0.1:55153").unwrap();
    let line = format!("<14>1 2026-10-19T12:00:00Z fw suricata 1 - - {}\n", eve("203.0.113.1", "192.168.1.2", 22, "ET SCAN", 9, 2, "Misc", "allowed", 1));
    ok.write_all(line.as_bytes()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("t.db")).unwrap();
    assert_eq!(rx.flush(&store).unwrap(), 1);
}

#[test]
fn event_storage_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("c.db")).unwrap();
    let evs: Vec<Event> = (0..50).map(forged).collect();
    store.add_events(&evs, "api").unwrap();
    assert_eq!(store.cap_events(20).unwrap(), 30);
    assert_eq!(store.event_count_since("").unwrap(), 20);
    // The newest are the ones kept.
    assert!(store.latest_event_ts().unwrap().unwrap() >= evs[49].ts);
}

// ---- Finding 3: a flood bigger than one poll's budget is caught up, not skipped ---------

#[test]
fn polling_catches_up_instead_of_skipping_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("p.db")).unwrap();
    let ev = |i: i64| eve("203.0.113.9", "192.168.1.2", 80, "ET SCAN probe", 1, 3, "Misc", "blocked", i);
    // Already collected up to t=0; 25 newer alerts are waiting (log is newest-first).
    let log: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new((0..=25).rev().map(ev).collect()));
    store.set_kv("api_cursor", &normalize(&ev(0)).unwrap().ts).unwrap();
    store.add_events(&[normalize(&ev(0)).unwrap()], "api").unwrap();
    let fetch = |log: Arc<Mutex<Vec<Value>>>| {
        move |page: u32, size: u32| -> anyhow::Result<Vec<Value>> {
            let l = log.lock().unwrap();
            let from = ((page - 1) * size) as usize;
            Ok(l.iter().skip(from).take(size as usize).cloned().collect())
        }
    };
    // Budget: 2 pages of 5 per poll.
    collect::poll_pages(fetch(log.clone()), &store, 5, 2).unwrap();
    assert!(collect::collection_gap(&store).is_some(), "gap must be visible");
    assert_eq!(store.get_kv("api_cursor").unwrap().unwrap(), normalize(&ev(0)).unwrap().ts, "cursor must not jump");
    // More alerts arrive on top while catching up.
    {
        let mut l = log.lock().unwrap();
        for i in 26..=28 {
            l.insert(0, ev(i));
        }
    }
    for _ in 0..10 {
        collect::poll_pages(fetch(log.clone()), &store, 5, 2).unwrap();
        if collect::collection_gap(&store).is_none() {
            break;
        }
    }
    assert!(collect::collection_gap(&store).is_none(), "should have caught up");
    assert_eq!(store.event_count_since("").unwrap(), 29, "every alert t=0..28 collected");
    assert_eq!(store.get_kv("api_cursor").unwrap().unwrap(), normalize(&ev(28)).unwrap().ts);
}

// ---- Finding 4: failed alias writes are errors -----------------------------------------

#[test]
fn failed_or_unverified_alias_writes_are_errors() {
    let failing = |req: &str| -> String {
        if req.contains("alias_util/add") { r#"{"status":"failed","message":"alias does not exist"}"#.into() } else { r#"{"rows":[]}"#.into() }
    };
    let (url, _) = fake_api(failing);
    let api = OPNsense::new(&api_cfg(&url).opnsense).unwrap();
    let e = api.alias_add("ipswatch_block", "198.51.100.50").unwrap_err();
    assert!(format!("{e:#}").contains("alias does not exist"), "{e:#}");

    // "done" but the address never shows up in the alias.
    let silent = |req: &str| -> String { if req.contains("alias_util/add") { r#"{"status":"done"}"#.into() } else { r#"{"rows":[]}"#.into() } };
    let (url, _) = fake_api(silent);
    let api = OPNsense::new(&api_cfg(&url).opnsense).unwrap();
    assert!(api.alias_add("ipswatch_block", "198.51.100.50").is_err());

    let (url, _) = fake_api(working_alias());
    let api = OPNsense::new(&api_cfg(&url).opnsense).unwrap();
    assert!(api.alias_add("ipswatch_block", "198.51.100.50").is_ok());
}

// ---- Finding 5: no credentials over plain HTTP unless explicitly allowed ----------------

#[test]
fn http_urls_are_refused_unless_allowed() {
    let mut cfg = Config::default();
    cfg.opnsense.url = "http://192.0.2.1".into();
    assert!(cfg.validate().is_err());
    assert!(OPNsense::new(&cfg.opnsense).is_err());
    cfg.opnsense.allow_http = true;
    assert!(cfg.validate().is_ok());

    let srv = DnsServerCfg { name: "ns1".into(), url: "http://192.0.2.53:5380".into(), token: "t".into() };
    cfg.dns.servers.push(srv.clone());
    assert!(cfg.validate().is_err());
    assert!(ipswatch::dns::Technitium::new(&srv, 5, false).is_err());
    cfg.dns.allow_http = true;
    assert!(cfg.validate().is_ok());
    assert!(ipswatch::dns::Technitium::new(&srv, 5, true).is_ok());
}

// ---- Other: reserved addresses are never blockable -------------------------------------

#[test]
fn reserved_addresses_are_never_blockable() {
    let cfg = Config::default();
    for ip in ["224.0.0.5", "239.1.2.3", "100.64.1.1", "0.1.2.3", "240.0.0.1", "198.18.0.1", "fe80::1", "ff02::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"] {
        assert!(engine::blockable(&cfg, ip).is_err(), "{ip} should not be blockable");
    }
    for ip in ["8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8"] {
        assert!(engine::blockable(&cfg, ip).is_ok(), "{ip} should be blockable");
    }
}
