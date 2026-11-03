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
            json!({"action": "pass", "dir": "in", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "443", "__timestamp__": "2026-10-19T12:00:30+00:00"}),
            json!({"action": "block", "dir": "in", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "22"}),
        ],
        &nets,
        None,
        &cfg.firewall.correlate_ignore_ports,
    );
    let out = run(&[eve("203.0.113.20", "192.168.1.10", 443, "ET SCAN Nmap", 5, 2, "Misc", "blocked", 0)], Some(&fw));
    let f = &out["inbound:203.0.113.20"];
    assert!(f.title.starts_with("Potential unwanted access"));
    assert!(f.reasons.iter().any(|r| r.contains("firewall PASSED 1 inbound")));
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

#[test]
fn firewall_correlation_ignores_routine_and_out_of_window_traffic() {
    let cfg = Config::default();
    let nets = cfg.detect.nets().unwrap();
    let rows = [
        json!({"action": "pass", "dir": "in", "src": "203.0.113.9", "dst": "192.168.1.5", "dstport": "123", "__timestamp__": "2026-10-19T12:00:00+00:00"}),
        json!({"action": "pass", "dir": "in", "src": "203.0.113.9", "dst": "192.168.1.255", "dstport": "445", "__timestamp__": "2026-10-19T12:00:00+00:00"}),
        json!({"action": "pass", "dir": "out", "src": "203.0.113.9", "dst": "192.168.1.5", "dstport": "445", "__timestamp__": "2026-10-19T12:00:00+00:00"}),
        json!({"action": "pass", "dir": "in", "src": "203.0.113.9", "dst": "192.168.1.5", "dstport": "445", "__timestamp__": "2026-10-19T09:00:00+00:00"}),
        json!({"action": "pass", "dir": "in", "src": "203.0.113.9", "dst": "192.168.1.5", "dstport": "3389", "__timestamp__": "2026-10-19T11:58:00+00:00"}),
    ];
    let w = detect::window("2026-10-19T12:05:00.000000+00:00", 15);
    let fw = detect::firewall_passes_by_src(&rows, &nets, Some((&w.0, &w.1)), &cfg.firewall.correlate_ignore_ports);
    let passes = &fw["203.0.113.9"];
    assert_eq!(passes.len(), 1, "only the in-window inbound RDP pass counts");
    assert_eq!(passes[0].dstport, "3389");
}

#[test]
fn firewall_own_address_is_not_an_attacker() {
    let cfg = Config::default();
    let own: std::net::IpAddr = "203.0.113.158".parse().unwrap();
    let nets = cfg.detect.nets().unwrap().with_own(vec![own]);
    let evs: Vec<Event> = (0..25)
        .map(|i| eve("203.0.113.158", "192.168.1.77", 22, "ET SCAN Potential SSH Scan", 2001219, 3, "", "allowed", i))
        .filter_map(|v| normalize(&v))
        .collect();
    let out = detect::analyze(&evs, &cfg.detect, &nets, None);
    assert!(out.is_empty(), "traffic from the firewall's own address is never scored: {out:?}");
    // ...but attacks aimed at the WAN address still are.
    let at_wan: Vec<Event> = (0..3)
        .map(|i| eve("198.51.100.9", "203.0.113.158", 443, "ET EXPLOIT Something", 1, 0, "", "allowed", i))
        .filter_map(|v| normalize(&v))
        .collect();
    assert!(detect::analyze(&at_wan, &cfg.detect, &nets, None).iter().any(|f| f.key == "inbound:198.51.100.9"));
}

#[test]
fn etpro_exploit_without_category_is_flagged() {
    let raws: Vec<Value> = (0..3)
        // severity 0 = not provided, as with OPNsense's alert API
        .map(|i| eve("198.51.100.77", "192.168.1.1", 80, "ETPRO EXPLOIT Possible Asus WRT LAN Backdoor Command Execution", 2809444, 0, "", "allowed", i))
        .collect();
    let f = &run(&raws, None)["inbound:198.51.100.77"];
    assert!(f.reasons.iter().any(|r| r.contains("exploit/malware signature")), "{:?}", f.reasons);
    assert!(f.severity >= Severity::High, "{:?} {}", f.severity, f.score);
}

#[test]
fn informational_rules_are_not_scored() {
    let raws: Vec<Value> = (0..40)
        .map(|i| eve("192.168.1.50", "45.57.8.1", 53, "OPN_Media_Streaming - Netflix - DNS request for netflix.com", 55000021, 3, "", "allowed", i))
        .collect();
    assert!(run(&raws, None).is_empty());
}

#[test]
fn reasons_do_not_pile_up_across_passes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("r.db")).unwrap();
    let mut f = detect::analyze(
        &(0..25).filter_map(|i| normalize(&eve("203.0.113.66", "192.168.1.20", 3389, "ET SCAN RDP", 7, 2, "", "allowed", i))).collect::<Vec<_>>(),
        &Config::default().detect,
        &Config::default().detect.nets().unwrap(),
        None,
    )
    .remove(0);
    store.upsert_finding(&f).unwrap();
    f.reasons[0] = "firewall PASSED 12 inbound connection(s) from this source to: x".into();
    store.upsert_finding(&f).unwrap();
    f.reasons[0] = "firewall PASSED 13 inbound connection(s) from this source to: x".into();
    let m = store.upsert_finding(&f).unwrap();
    assert_eq!(m.reasons.iter().filter(|r| r.contains("firewall PASSED")).count(), 1, "{:?}", m.reasons);
}

#[test]
fn attacks_on_the_firewall_itself_are_not_access_to_internal_hosts() {
    let cfg = Config::default();
    let nets = cfg.detect.nets().unwrap().with_own(vec!["203.0.113.158".parse().unwrap()]);
    let evs = |sig: &str, port: i64, n: i64| -> Vec<Event> {
        (0..n).filter_map(|i| normalize(&eve("16.5.0.240", "203.0.113.158", port, sig, 2809444, 0, "", "allowed", i))).collect()
    };
    let out = detect::analyze(&evs("ETPRO EXPLOIT Possible Asus WRT LAN Backdoor Command Execution", 9999, 4), &cfg.detect, &nets, None);
    let f = &out[0];
    assert!(f.title.starts_with("Attack attempts against the firewall"), "{}", f.title);
    assert_eq!(f.severity, Severity::Medium);
    assert!(!f.reasons.iter().any(|r| r.contains("reached internal host")));
    // A single background scan of the WAN isn't a finding at all.
    assert!(detect::analyze(&evs("ET SCAN Zmap User-Agent (Inbound)", 443, 1), &cfg.detect, &nets, None).is_empty());
}

fn health_finding(key: &str, kind: &str) -> ipswatch::store::Finding {
    let mut f = ipswatch::notify::sample_finding();
    f.key = key.into();
    f.kind = kind.into();
    f
}

#[test]
fn acknowledged_exposure_stays_acknowledged_but_resolved_health_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("h.db")).unwrap();
    // Exposure: ack sticks even when seen again later.
    let mut e = health_finding("exposure:192.168.1.60:443", "exposure");
    store.upsert_finding(&e).unwrap();
    store.set_status(&e.key, "ack").unwrap();
    e.last_seen = "2099-01-01T00:00:00.000000+00:00".into();
    assert_eq!(store.upsert_finding(&e).unwrap().status, "ack");
    // Health: resolved -> comes back -> open again, and re-notifies.
    let h = health_finding("health:gateway:WAN_GW", "health");
    store.upsert_finding(&h).unwrap();
    store.set_notified(&h.key, &ipswatch::now_iso(), Severity::Low).unwrap();
    store.set_status(&h.key, "resolved").unwrap();
    let again = store.upsert_finding(&h).unwrap();
    assert_eq!(again.status, "open");
    assert!(again.notified_at.is_none());
    // IPS findings still reopen from ack on new activity.
    let mut i = health_finding("inbound:203.0.113.1", "inbound");
    store.upsert_finding(&i).unwrap();
    store.set_status(&i.key, "ack").unwrap();
    i.last_seen = "2099-01-01T00:00:00.000000+00:00".into();
    assert_eq!(store.upsert_finding(&i).unwrap().status, "open");
    // Re-scoring IPS data never wipes health/exposure findings.
    store.delete_findings().unwrap();
    assert!(store.get_finding("exposure:192.168.1.60:443").unwrap().is_some());
    assert!(store.get_finding("inbound:203.0.113.1").unwrap().is_none());
}

#[test]
fn device_tracking_reports_only_new_macs() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("d.db")).unwrap();
    let d = ipswatch::health::Device {
        mac: "1c:3b:f3:a6:c7:4c".into(),
        ip: "192.168.1.42".into(),
        hostname: "".into(),
        vendor: "TP-LINK".into(),
        interface: "LAN".into(),
        first_seen: ipswatch::now_iso(),
        last_seen: ipswatch::now_iso(),
    };
    assert!(store.upsert_device(&d).unwrap(), "first sighting is new");
    let mut d2 = d.clone();
    d2.ip = "192.168.1.43".into();
    assert!(!store.upsert_device(&d2).unwrap(), "same MAC again is not new");
    let list = store.list_devices(10).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].ip, "192.168.1.43");
}

#[test]
fn ips_findings_from_crowdsec_banned_ips_are_boosted() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("cs.db")).unwrap();
    let evs: Vec<Event> = (0..25)
        .filter_map(|i| normalize(&eve("194.195.208.213", "192.168.1.20", 3389, "ET SCAN RDP", 7, 2, "", "allowed", i)))
        .collect();
    store.add_events(&evs, "api").unwrap();
    let cfg = Config::default();
    engine::run_detection(&cfg, &store, None, None, false).unwrap();
    let plain = store.get_finding("inbound:194.195.208.213").unwrap().unwrap().score;

    store.delete_findings().unwrap();
    store
        .set_kv(
            "crowdsec_bans",
            r#"{"194.195.208.213":{"reason":"firewallservices/pf-scan-multi_ports","country":"US","network":"Akamai Connected Cloud","expires":"3h"}}"#,
        )
        .unwrap();
    engine::run_detection(&cfg, &store, None, None, false).unwrap();
    let f = store.get_finding("inbound:194.195.208.213").unwrap().unwrap();
    assert_eq!(f.score, plain + 20);
    assert!(f.reasons.iter().any(|r| r.contains("CrowdSec has banned this IP") && r.contains("Akamai")), "{:?}", f.reasons);
}

#[test]
fn damaged_database_is_rebuilt_from_backup_and_salvage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipswatch.db");
    {
        let store = Store::open(&path).unwrap();
        let evs: Vec<Event> =
            (0..3000).filter_map(|i| normalize(&eve("198.51.100.9", "192.168.1.10", 443, "ET SCAN padding padding padding", 1, 2, "Misc", "allowed", i))).collect();
        store.add_events(&evs, "api").unwrap();
        store.upsert_finding(&health_finding("exposure:192.168.1.60:443", "exposure")).unwrap();
        store.set_kv("api_cursor", "2026-10-19T12:00:00").unwrap();
        // Daily backup: written once, not again the same day.
        let b = store.backup_if_due().unwrap().expect("first backup of the day");
        assert!(b.exists());
        assert!(store.backup_if_due().unwrap().is_none());
        store.set_kv("after_backup", "1").unwrap();
    } // closing checkpoints the WAL into the main file

    // A healthy database opens without repair.
    assert!(Store::open_or_repair(&path).unwrap().1.is_none());

    // Damage a run of pages in the middle of the file.
    let mut bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() > 40 * 4096, "test database too small to damage");
    for b in &mut bytes[20 * 4096..30 * 4096] {
        *b = 0xA5;
    }
    std::fs::write(&path, &bytes).unwrap();

    let (store, msg) = Store::open_or_repair(&path).unwrap();
    let msg = msg.expect("repair should have happened");
    assert!(msg.contains("backup ipswatch-"), "{msg}");
    assert!(dir.path().read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("damaged-")));
    // Everything from the backup is back; the cursor is cleared so alerts are downloaded again.
    assert_eq!(store.event_count_since("2000-01-01").unwrap(), 3000);
    assert!(store.get_finding("exposure:192.168.1.60:443").unwrap().is_some());
    assert!(store.get_kv("api_cursor").unwrap().is_none());
}
