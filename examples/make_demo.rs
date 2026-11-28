//! Builds the demo data in `samples/demo` (config.toml + demo.db) that the documentation's
//! screenshots are made from (`scripts/screenshots.ps1`). Everything is made up: internet
//! addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
//! LAN addresses are 192.168.1.x and names end in `.example`.
//!
//!   cargo run --example make_demo            # writes samples/demo
//!   cargo run --example make_demo -- <dir>   # somewhere else

use std::path::PathBuf;

use chrono::{Duration, Utc};
use ipswatch::config::{Config, Severity};
use ipswatch::crowdsec::{Ban, CsAlert, Status};
use ipswatch::dns::{self, Client, DnsExposure, Lookup, NxClient, ServerStatus, Stats, Zone};
use ipswatch::health::{ConfigChange, Device, Exposed, Gateway, Service, Snapshot};
use ipswatch::normalize::{normalize, Event};
use ipswatch::store::{Finding, Store};
use serde_json::json;

const CONFIG: &str = r#"# Demo settings for the documentation's screenshots (made-up addresses; no secrets).
db_path = "demo.db"

[opnsense]
url = "https://192.0.2.1"

[gui]
autostart_monitor = false
start_with_windows = false

[[dns.servers]]
name = "ns1"
kind = "technitium"
url = "https://192.168.1.99:53443"
token = ""

[[dns.servers]]
name = "ns2"
kind = "technitium"
url = "https://192.168.1.98:53443"
token = ""
"#;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("samples/demo"));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("config.toml"), CONFIG)?;
    let db = dir.join("demo.db");
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", db.display()));
    }
    let store = Store::open(&db)?;
    let cfg = Config::default();
    let now = Utc::now();
    let at = |mins: i64| ipswatch::iso(now - Duration::minutes(mins));
    // How the checks stamp their snapshots: local time.
    let local = |mins: i64| (chrono::Local::now() - Duration::minutes(mins)).format("%Y-%m-%d %H:%M:%S").to_string();

    // ---- IPS events -> findings, scored by the real engine
    let mut raws = vec![];
    let mut eve = |src: &str, dst: &str, dport: i64, sig: &str, sid: i64, sev: i64, cat: &str, action: &str, mins_ago: f64| {
        let ts = now - Duration::milliseconds((mins_ago * 60_000.0) as i64);
        raws.push(json!({
            "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.6f+0000").to_string(),
            "flow_id": raws.len() as i64 + 1000, "in_iface": "igb0", "event_type": "alert",
            "src_ip": src, "src_port": 40000 + (raws.len() as i64 % 20000), "dest_ip": dst, "dest_port": dport, "proto": "TCP",
            "alert": {"action": action, "gid": 1, "signature_id": sid, "rev": 1, "signature": sig, "category": cat, "severity": sev}
        }));
    };
    for i in 0..30 {
        eve("198.51.100.44", "192.168.1.20", 3389, "ET SCAN Possible RDP brute force", 2023753, 2, "Attempted Administrator Privilege Gain", "allowed", 95.0 - i as f64 * 0.05);
    }
    for p in 1..41 {
        eve("203.0.113.9", "192.168.1.60", p * 37 % 1024, "ET SCAN Suspicious inbound to multiple ports", 2010937, 2, "Potentially Bad Traffic", "blocked", 140.0 - p as f64 * 0.02);
    }
    eve("192.168.1.50", "203.0.113.200", 443, "ET MALWARE Cobalt Strike Beacon Observed", 2027082, 1, "A Network Trojan was detected", "allowed", 40.0);
    eve("192.168.1.50", "192.168.1.5", 445, "ET EXPLOIT Possible ETERNALBLUE SMB exploit", 2024218, 1, "Attempted Administrator Privilege Gain", "allowed", 39.8);
    for i in 0..6 {
        eve("203.0.113.50", "192.168.1.60", 443, "ET WEB_SERVER Possible SQL injection attempt", 2006445, 1, "Web Application Attack", "blocked", 300.0 - i as f64);
    }
    for i in 0..12 {
        eve("198.51.100.77", "192.168.1.1", 22, "ET SCAN Potential SSH Scan", 2001219, 2, "Attempted Information Leak", "blocked", 600.0 - i as f64 * 3.0);
    }
    for i in 0..40 {
        let src = format!("198.51.100.{}", 120 + i % 30);
        eve(&src, "192.168.1.1", 23 + (i % 3) * 1000, "ET DROP Dshield Block Listed Source", 2402000, 2, "Misc Attack", "blocked", 1400.0 - i as f64 * 30.0);
    }
    let events: Vec<Event> = raws.iter().filter_map(normalize).collect();
    store.add_events(&events, "api")?;
    for f in ipswatch::detect::analyze(&events, &cfg.detect, &cfg.detect.nets()?, None) {
        store.upsert_finding(&f)?;
    }
    store.set_blocked("inbound:203.0.113.50", Some(&at(290)))?;
    store.set_status("inbound:198.51.100.77", "ack")?;

    // ---- findings from the other checks
    let finding = |key: &str, kind: &str, ip: &str, sev: Severity, score: i64, title: &str, reasons: &[&str], mins: i64| Finding {
        key: key.into(),
        kind: kind.into(),
        subject_ip: ip.into(),
        first_seen: at(mins),
        last_seen: at(mins),
        score,
        severity: sev,
        title: title.into(),
        reasons: reasons.iter().map(|r| r.to_string()).collect(),
        targets: vec![ip.into()],
        signatures: vec![],
        event_count: 1,
        status: "open".into(),
        notified_at: None,
        notified_severity: None,
        blocked_at: None,
    };
    for f in [
        finding("device:6c:0c:9a:12:34:56", "device", "192.168.1.197", Severity::Medium, 60, "New device on LAN: 192.168.1.197 (Amazon Technologies Inc.)", &["MAC 6c:0c:9a:12:34:56 first seen now", "no DHCP name"], 25),
        finding("dns:client:192.168.1.96", "dns", "192.168.1.96", Severity::Medium, 60, "192.168.1.96 is making unusually many DNS queries", &["3607 queries in the last hour to ns1", "usually about 240 an hour"], 12),
        finding("dns:settings:192.168.1.98", "dns", "192.168.1.98", Severity::Medium, 60, "DNS ns2: settings changed (2)", &["forwarders: (none) -> 9.9.9.9", "blockListUrls: 1 -> 2"], 300),
        finding("config:demo-1", "config", "(root)", Severity::Medium, 60, "Firewall configuration changed 2 time(s)", &["10:14 (admin): Firewall/NAT/Port Forward edited", "10:15 (admin): Firewall/Rules edited"], 180),
        finding("dns:health:192.168.1.99:update", "dns", "192.168.1.99", Severity::Low, 30, "DNS ns1: Technitium 15.6.2.17 is available", &["running 15.6.2.15", "update from the console: https://192.168.1.99:53443"], 60),
        finding("crowdsec:alert:203.0.113.40", "crowdsec", "203.0.113.40", Severity::High, 90, "CrowdSec: SSH brute force from 203.0.113.40", &["crowdsecurity/ssh-bf", "banned for 4h"], 75),
        finding("exposure:192.168.1.70:25565", "exposure", "192.168.1.70", Severity::Low, 30, "Exposed to the internet: 192.168.1.70:25565 (TCP)", &["port forward on WAN", "acknowledge it if this is intended"], 1440),
    ] {
        store.upsert_finding(&f)?;
    }

    // ---- devices (ARP + DHCP)
    let devices: Vec<Device> = [
        ("6c:0c:9a:12:34:56", "192.168.1.197", "", "Amazon Technologies Inc.", 25),
        ("3c:22:fb:10:20:30", "192.168.1.104", "phone-02.home.example", "Apple, Inc.", 4000),
        ("a4:83:e7:44:55:66", "192.168.1.78", "tablet-01.home.example", "Apple, Inc.", 9000),
        ("f0:2f:74:01:02:03", "192.168.1.50", "desktop-03.home.example", "ASUSTek COMPUTER INC.", 20000),
        ("00:11:32:aa:bb:cc", "192.168.1.5", "nas.home.example", "Synology Incorporated", 40000),
        ("b8:27:eb:12:12:12", "192.168.1.60", "web.home.example", "Raspberry Pi Foundation", 30000),
        ("dc:a6:32:34:34:34", "192.168.1.70", "game.home.example", "Raspberry Pi Trading Ltd", 25000),
        ("f4:f5:d8:56:56:56", "192.168.1.199", "tv-living.home.example", "Google, Inc.", 15000),
        ("30:05:5c:78:78:78", "192.168.1.20", "office-pc.home.example", "Brother Industries, LTD.", 50000),
        ("de:ad:be:ef:00:01", "192.168.1.96", "", "", 7000),
    ]
    .iter()
    .map(|(mac, ip, name, vendor, mins)| Device { mac: mac.to_string(), ip: ip.to_string(), hostname: name.to_string(), vendor: vendor.to_string(), interface: "LAN".into(), first_seen: at(*mins), last_seen: at(2) })
    .collect();
    for d in &devices {
        store.upsert_device(d)?;
    }

    // ---- last health check
    let alert = |mins: i64, ip: &str, scenario: &str| CsAlert { id: mins, created: at(mins), ip: ip.into(), scenario: scenario.into(), country: "US".into(), network: "EXAMPLE-ASN".into(), decisions: "ban:1".into() };
    let services = ["configd", "cron", "crowdsec", "crowdsec-firewall", "dhcpd", "dpinger", "kea-dhcp4", "lighttpd", "login", "ntpd", "openssh", "pf", "suricata", "syslog-ng", "unbound", "wireguard"];
    let health = Snapshot {
        at: local(1),
        hostname: "fw.home.example".into(),
        version: "OPNsense 26.7.8-amd64".into(),
        uptime: "12 days, 04:18:22".into(),
        boottime: at(17_538),
        loadavg: "0.41, 0.38, 0.35".into(),
        gateways: vec![
            Gateway { name: "WAN_DHCP".into(), status: "online".into(), delay_ms: Some(12.6), loss_pct: Some(0.0), ok: true },
            Gateway { name: "WAN2_DHCP".into(), status: "online".into(), delay_ms: Some(41.2), loss_pct: Some(0.0), ok: true },
        ],
        services: services.iter().map(|s| Service { name: s.to_string(), description: String::new(), running: true }).collect(),
        memory_pct: Some(18.0),
        states: Some((6214, 3_264_800)),
        disks: vec![("/".into(), 11)],
        system_warnings: vec![],
        firmware: String::new(),
        exposure: vec![
            Exposed { source: "port forward".into(), interface: "WAN".into(), target: "192.168.1.60".into(), port: "443".into(), protocol: "TCP".into(), blocked: false, hits: 128, note: String::new() },
            Exposed { source: "port forward".into(), interface: "WAN".into(), target: "192.168.1.70".into(), port: "25565".into(), protocol: "TCP".into(), blocked: false, hits: 9, note: String::new() },
            Exposed { source: "port forward".into(), interface: "WAN".into(), target: "192.168.1.5".into(), port: "5001".into(), protocol: "TCP".into(), blocked: true, hits: 0, note: String::new() },
            Exposed { source: "WAN pass rule".into(), interface: "WAN".into(), target: "192.168.1.2".into(), port: "51820".into(), protocol: "UDP".into(), blocked: true, hits: 0, note: "no port forward to it, so not reachable from the internet (leftover rule?)".into() },
        ],
        devices: devices.clone(),
        new_devices: 1,
        config_changes: vec![
            ConfigChange { time: at(180), user: "admin".into(), description: "Firewall/NAT/Port Forward edited".into() },
            ConfigChange { time: at(179), user: "admin".into(), description: "Firewall/Rules edited".into() },
        ],
        crowdsec: Some(Status {
            running: true,
            agent: true,
            lapi: true,
            bouncer_enabled: true,
            bouncer_last_seen: at(1),
            agent_last_seen: at(1),
            active_bans: 3,
            local_bans: 3,
            community_bans: 15_240,
            firewall_blocked: Some(15_243),
            alerts_total: 9,
            top_scenarios: vec![("crowdsecurity/ssh-bf".into(), 4), ("firewallservices/pf-scan-multi_ports".into(), 5)],
            recent: vec![
                alert(75, "203.0.113.40", "crowdsecurity/ssh-bf"),
                alert(130, "203.0.113.41", "firewallservices/pf-scan-multi_ports"),
                alert(400, "198.51.100.60", "firewallservices/pf-scan-multi_ports"),
            ],
        }),
        errors: vec![],
    };
    store.set_kv("snapshot_health", &serde_json::to_string(&health)?)?;
    let ban = |reason: &str| Ban { reason: reason.into(), country: "US".into(), network: "EXAMPLE-ASN".into(), expires: "3h41m".into() };
    let bans = std::collections::HashMap::from([("203.0.113.40".to_string(), ban("crowdsecurity/ssh-bf")), ("203.0.113.41".to_string(), ban("firewallservices/pf-scan-multi_ports"))]);
    store.set_kv("crowdsec_bans", &serde_json::to_string(&bans)?)?;

    // ---- last DNS check
    let lookups = |ms: u64| vec![
        Lookup { domain: "cloudflare.com".into(), ok: true, result: "NOERROR".into(), answers: 2, ms },
        Lookup { domain: "opnsense.org".into(), ok: true, result: "NOERROR".into(), answers: 1, ms: ms + 30 },
    ];
    let client = |ip: &str, name: &str, hits: u64, usual: Option<f64>| Client { ip: ip.into(), name: name.into(), hits, usual };
    let server = |name: &str, host: &str, engine: &str, version: &str, update: &str, total: u64, clients: Vec<Client>, nx: Vec<NxClient>| ServerStatus {
        name: name.into(),
        backend: "technitium".into(),
        engine: engine.into(),
        url: format!("https://{host}:53443"),
        host: host.into(),
        server_domain: format!("{name}.home.example"),
        api_ok: true,
        version: version.into(),
        up_since: at(14_000),
        update: update.into(),
        dns_ok: true,
        lookups: lookups(if name == "ns1" { 18 } else { 24 }),
        stats: Some(Stats { total, no_error: total * 90 / 100, servfail: total / 400, nxdomain: total * 5 / 100, blocked: total * 7 / 100, cached: total * 60 / 100, recursive: total * 30 / 100, clients: clients.len() as u64 + 20, zones: 6, block_list_zones: 312_000, ..Default::default() }),
        top_clients: clients,
        top_domains: vec![("api.weather.example".into(), 812), ("cdn.video.example".into(), 640), ("time.example".into(), 402), ("updates.vendor.example".into(), 251)],
        top_blocked: vec![("ads.tracker.example".into(), 330), ("telemetry.vendor.example".into(), 214), ("metrics.app.example".into(), 97)],
        recursion: "AllowOnlyForPrivateNetworks".into(),
        forwarders: vec![],
        blocking: true,
        blocklist_urls: 2,
        blocklist_interval_hours: 24,
        blocklist_age_hours: Some(if name == "ns1" { 7.0 } else { 15.0 }),
        zones: vec![Zone { name: "home.example".into(), kind: "Primary".into(), serial: "2026112701".into(), modified: at(900), ..Default::default() }],
        query_logger: "Query Logs (Sqlite)".into(),
        nx_clients: nx,
        exposure: if name == "ns1" {
            vec![DnsExposure { port: "853".into(), protocol: "TCP".into(), interface: "WAN".into(), blocked: false, purpose: "DNS-over-TLS".into(), listening: Some(true), note: "recursion: AllowOnlyForPrivateNetworks".into() }]
        } else {
            vec![]
        },
        ..Default::default()
    };
    let dns = dns::Snapshot {
        at: local(1),
        servers: vec![
            server(
                "ns1",
                "192.168.1.99",
                "Technitium",
                "15.6.2.15",
                "15.6.2.17",
                16_527,
                vec![client("192.168.1.104", "phone-02.home.example", 5016, Some(5020.0)), client("192.168.1.96", "", 3607, Some(240.0)), client("192.168.1.78", "tablet-01.home.example", 867, Some(874.0)), client("192.168.1.199", "tv-living.home.example", 739, Some(235.0))],
                vec![NxClient { ip: "192.168.1.96".into(), count: 412, unique: 380, sample: vec!["qx7fkq2m.example".into(), "zt0pl9ab.example".into(), "m3kd81vv.example".into()] }],
            ),
            server("ns2", "192.168.1.98", "RUSTy-DNS", "1.2.0", "", 3502, vec![client("192.168.1.50", "desktop-03.home.example", 1210, Some(1150.0)), client("192.168.1.5", "nas.home.example", 402, Some(390.0))], vec![]),
        ],
        ids_restarts: vec![],
    };
    store.set_kv("snapshot_dns", &serde_json::to_string(&dns)?)?;

    // A sample activity log (copied in as ipswatch.log by scripts/screenshots.ps1; *.log is not committed).
    let log = [
        (300, "INFO ", "IPS Watch 1.4.0 starting"),
        (300, "INFO ", "Monitoring started (poll every 30s)"),
        (299, "INFO ", "Health check: 2 gateways online, 16/16 services running"),
        (299, "INFO ", "DNS check: ns1 UP (18 ms), ns2 UP (24 ms)"),
        (290, "INFO ", "6 new IPS events"),
        (290, "WARN ", "FINDING inbound:203.0.113.50: [MEDIUM] Blocked attack activity from 203.0.113.50 (score 70)"),
        (289, "INFO ", "Blocked 203.0.113.50 in alias ipswatch_block (confirmed by the firewall)"),
        (180, "WARN ", "FINDING config:demo-1: [MEDIUM] Firewall configuration changed 2 time(s) (score 60)"),
        (140, "INFO ", "40 new IPS events"),
        (139, "WARN ", "FINDING inbound:203.0.113.9: [MEDIUM] Blocked attack activity from 203.0.113.9 (score 70)"),
        (95, "INFO ", "30 new IPS events"),
        (94, "WARN ", "FINDING inbound:198.51.100.44: [CRITICAL] Potential unwanted access from 198.51.100.44 (score 125)"),
        (75, "WARN ", "FINDING crowdsec:alert:203.0.113.40: [HIGH] CrowdSec: SSH brute force from 203.0.113.40 (score 90)"),
        (40, "INFO ", "2 new IPS events"),
        (40, "WARN ", "FINDING compromise:192.168.1.50: [CRITICAL] Internal host 192.168.1.50 shows signs of compromise (score 150)"),
        (25, "WARN ", "FINDING device:6c:0c:9a:12:34:56: [MEDIUM] New device on LAN: 192.168.1.197 (Amazon Technologies Inc.) (score 60)"),
        (12, "WARN ", "FINDING dns:client:192.168.1.96: [MEDIUM] 192.168.1.96 is making unusually many DNS queries (score 60)"),
        (5, "WARN ", "Gateway WAN2_DHCP: latency 312 ms (threshold 300 ms)"),
        (1, "INFO ", "Gateway WAN2_DHCP back to normal (41 ms)"),
    ]
    .iter()
    .map(|(m, lvl, msg)| format!("{}  {lvl} {msg}", local(*m)))
    .collect::<Vec<_>>()
    .join("\n");
    std::fs::write(dir.join("demo-log.txt"), log + "\n")?;

    drop(store);
    // Fold the WAL into the file so demo.db is complete on its own.
    let conn = rusqlite::Connection::open(&db)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE; VACUUM;")?;
    println!("demo data written to {}", dir.display());
    Ok(())
}
