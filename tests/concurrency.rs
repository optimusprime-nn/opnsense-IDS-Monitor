//! The desktop app and the CLI open the same database at the same time. Several connections
//! writing at once (events, findings, kv, pruning, the daily VACUUM INTO backup) must never
//! damage the file.

use ipswatch::normalize::{normalize, Event};
use ipswatch::store::Store;
use serde_json::json;
use std::sync::Arc;
use std::thread;

fn ev(i: u64, w: u64) -> Event {
    normalize(&json!({
        "timestamp": format!("2026-11-12T10:{:02}:{:02}.{:06}+0000", (i / 60) % 60, i % 60, w * 1000 + i % 1000),
        "flow_id": w * 1_000_000 + i, "in_iface": "igb0", "event_type": "alert",
        "src_ip": format!("203.0.113.{}", i % 250), "src_port": 40000, "dest_ip": "192.168.1.10", "dest_port": 443, "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1000 + i % 50, "rev": 1, "signature": "ET TEST", "category": "Misc", "severity": 2}
    }))
    .unwrap()
}

#[test]
fn concurrent_writers_keep_the_database_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("c.db"));
    Store::open(&path).unwrap();
    let workers: Vec<_> = (0..4u64)
        .map(|w| {
            let path = path.clone();
            thread::spawn(move || {
                // Each worker is its own connection, like the app and the CLI.
                let store = Store::open(&path).unwrap();
                for round in 0..60u64 {
                    let batch: Vec<Event> = (0..20).map(|k| ev(round * 20 + k, w)).collect();
                    store.add_events(&batch, "api").unwrap();
                    store.set_kv(&format!("k{w}"), &round.to_string()).unwrap();
                    store.set_kv("shared", &format!("{w}-{round}")).unwrap();
                    if round % 15 == 0 {
                        store.prune_events("2026-11-12T10:00:30").unwrap();
                    }
                    if w == 0 && round % 20 == 0 {
                        store.delete_kv("last_db_backup").unwrap();
                        store.backup_if_due().unwrap();
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let check = rusqlite::Connection::open(path.as_path()).unwrap();
    let r: String = check.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(r, "ok");
}
