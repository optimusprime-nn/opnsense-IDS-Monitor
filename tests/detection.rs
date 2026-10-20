//! Detection and pipeline tests (ported from the Python suite).

use std::collections::HashMap;

use chrono::{Duration, TimeZone, Utc};
use ipswatch::config::{Config, Severity};
use ipswatch::detect::{self, FwPass};
use ipswatch::normalize::{normalize, Event};
use ipswatch::store::Store;
use ipswatch::{collect, engine};
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

fn run(raws: &[Value], fw: Option<&HashMap<String, Vec<FwPass>>>) -> HashMap<String, ipswatch::store::Finding> {
    let cfg = Config::default();
    let evs: Vec<Event> = raws.iter().filter_map(normalize).collect();
    detect::analyze(&evs, &cfg.detect, &cfg.detect.nets().unwrap(), fw).into_iter().map(|f| (f.key.clone(), f)).collect()
}

#[test]
fn single_blocked_low_alert_not_flagged() {
    let out = run(&[eve("198.51.100.1", "192.168.1.10", 80, "ET SCAN probe", 1, 3, "Misc", "blocked", 0)], None);
    assert!(out.is_empty());
}

#[test]
fn unblocked_high_sev_to_ssh_is_unwanted_access() {
    let out = run(
        &[eve("203.0.113.7", "192.168.1.10", 22, "ET EXPLOIT OpenSSH", 2, 1, "Attempted Administrator Privilege Gain", "allowed", 0)],
        None,
    );
    let f = &out["inbound:203.0.113.7"];
    assert!(f.title.starts_with("Potential unwanted access"), "{}", f.title);
    assert!(f.severity >= Severity::High);
}

#[test]
fn port_scan_counts_sensitive_ports_once() {
    let raws: Vec<Value> = (1..30).map(|p| eve("203.0.113.9", "192.168.1.10", p, "ET SCAN", 3, 3, "Misc", "blocked", p)).collect();
    let f = &run(&raws, None)["inbound:203.0.113.9"];
    assert!(f.reasons.iter().any(|r| r.contains("port scan")));
    assert_eq!(f.reasons.iter().filter(|r| r.contains("sensitive")).count(), 1);
    assert!(f.title.starts_with("Blocked attack"));
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn internal_c2_is_compromise() {
    let out = run(
        &[eve("192.168.1.50", "185.100.87.1", 443, "ET MALWARE Cobalt Strike Beacon", 4, 1, "A Network Trojan was detected", "allowed", 0)],
        None,
    );
    assert!(out["compromise:192.168.1.50"].score >= 80);
}

#[test]
fn firewall_pass_correlation_escalates() {
    let cfg = Config::default();
    let nets = cfg.detect.nets().unwrap();
    let fw = detect::firewall_passes_by_src(
        &[
            json!({"action": "pass", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "443"}),
            json!({"action": "block", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "22"}),
        ],
        &nets,
    );
    let out = run(&[eve("203.0.113.20", "192.168.1.10", 443, "ET SCAN Nmap", 5, 2, "Misc", "blocked", 0)], Some(&fw));
    let f = &out["inbound:203.0.113.20"];
    assert!(f.title.starts_with("Potential unwanted access"));
    assert!(f.reasons.iter().any(|r| r.contains("firewall PASSED 1")));
}

#[test]
fn ignored_sid_and_trusted_source() {
    let mut cfg = Config::default();
    cfg.detect.ignore_sids = vec![2];
    cfg.detect.ignore_sources = vec!["198.51.100.0/24".into()];
    let nets = cfg.detect.nets().unwrap();
    let evs: Vec<Event> = [
        eve("203.0.113.7", "192.168.1.10", 22, "x", 2, 1, "Misc", "allowed", 0),
        eve("198.51.100.5", "192.168.1.10", 22, "y", 9, 1, "Misc", "allowed", 1),
    ]
    .iter()
    .filter_map(normalize)
    .collect();
    assert!(detect::analyze(&evs, &cfg.detect, &nets, None).is_empty());
}

#[test]
fn blockable_rules() {
    let mut cfg = Config::default();
    cfg.block.never_block = vec!["8.8.8.0/24".into()];
    assert!(engine::blockable(&cfg, "203.0.113.5").is_ok());
    assert!(engine::blockable(&cfg, "192.168.1.5").is_err());
    assert!(engine::blockable(&cfg, "127.0.0.1").is_err());
    assert!(engine::blockable(&cfg, "8.8.8.8").is_err());
}

#[test]
fn import_store_dedupe_and_notification_suppression() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("eve.json");
    let mut body = String::new();
    for i in 0..25 {
        body += &eve("203.0.113.66", "192.168.1.20", 3389, "ET SCAN RDP brute", 7, 2, "Misc", "allowed", i).to_string();
        body.push('\n');
    }
    body += "{\"event_type\": \"stats\"}\nnot json at all\n";
    std::fs::write(&path, body).unwrap();

    let mut cfg = Config::default();
    cfg.notify.min_severity = Severity::Low;
    cfg.gui.alert_min_severity = Severity::Low;
    let store = Store::open(&dir.path().join("t.db")).unwrap();
    assert_eq!(collect::import_file(&path, &store).unwrap(), 25);
    assert_eq!(collect::import_file(&path, &store).unwrap(), 0, "dedupe");
    assert_eq!(engine::run_detection(&cfg, &store, None, None, true).unwrap().len(), 1);
    assert!(engine::run_detection(&cfg, &store, None, None, true).unwrap().is_empty(), "no re-notify");
    store.set_status("inbound:203.0.113.66", "false_positive").unwrap();
    assert!(engine::run_detection(&cfg, &store, None, None, true).unwrap().is_empty());
    let f = store.get_finding("inbound:203.0.113.66").unwrap().unwrap();
    assert_eq!(f.status, "false_positive", "false positives stay silenced");
}

#[test]
fn sample_file_matches_python_results() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("s.db")).unwrap();
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/eve-sample.json");
    assert_eq!(collect::import_file(&sample, &store).unwrap(), 73);
    engine::replay(&Config::default(), &store, false).unwrap();
    let got: Vec<(String, i64)> = store
        .list_findings(Some("open"), Severity::Low, 10)
        .unwrap()
        .into_iter()
        .map(|f| (f.key, f.score))
        .collect();
    assert_eq!(
        got,
        vec![
            ("compromise:192.168.1.50".to_string(), 150),
            ("inbound:198.51.100.44".to_string(), 125),
            ("inbound:203.0.113.9".to_string(), 75)
        ]
    );
}

#[test]
fn syslog_receiver_udp() {
    let rx = collect::SyslogReceiver::start("127.0.0.1", 55141, "udp").unwrap();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..5 {
        let line = format!("<14>1 2026-10-19T12:00:00Z fw suricata 1 - - {}", eve("203.0.113.1", "192.168.1.2", 22, "ET SCAN", 9, 2, "Misc", "allowed", i));
        sock.send_to(line.as_bytes(), "127.0.0.1:55141").unwrap();
    }
    sock.send_to(b"<14>fw suricata: not json", "127.0.0.1:55141").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("u.db")).unwrap();
    assert_eq!(rx.flush(&store).unwrap(), 5);
}

#[test]
fn icon_png_is_valid() {
    let png = ipswatch::icon::png(32);
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    let ico = ipswatch::icon::ico(&[16, 32]);
    assert_eq!(&ico[..4], &[0, 0, 1, 0]);
}
