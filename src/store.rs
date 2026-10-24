//! SQLite persistence for events and findings (schema compatible with the Python version).

use anyhow::Result;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

use crate::config::Severity;
use crate::normalize::Event;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    uid TEXT PRIMARY KEY, ts TEXT NOT NULL,
    src_ip TEXT, src_port INTEGER, dest_ip TEXT, dest_port INTEGER,
    proto TEXT, iface TEXT, sid INTEGER, signature TEXT, category TEXT, severity INTEGER,
    action TEXT, flow_id TEXT, app_proto TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip, ts);
CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY, kind TEXT NOT NULL, subject_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, score INTEGER NOT NULL,
    severity TEXT NOT NULL, title TEXT NOT NULL,
    reasons TEXT NOT NULL, targets TEXT NOT NULL, signatures TEXT NOT NULL,
    event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    notified_at TEXT, notified_severity TEXT, blocked_at TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, interface TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
"#;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub key: String,
    pub kind: String, // inbound | compromise
    pub subject_ip: String,
    pub first_seen: String,
    pub last_seen: String,
    pub score: i64,
    pub severity: Severity,
    pub title: String,
    pub reasons: Vec<String>,
    pub targets: Vec<String>,
    pub signatures: Vec<String>,
    pub event_count: i64,
    pub status: String, // open | ack | false_positive
    pub notified_at: Option<String>,
    pub notified_severity: Option<Severity>,
    pub blocked_at: Option<String>,
}

impl Finding {
    pub fn status_label(&self) -> &'static str {
        match self.status.as_str() {
            "ack" => "Acknowledged",
            "resolved" => "Resolved",
            "false_positive" => "False positive",
            _ => "Open",
        }
    }
}

pub struct Store {
    db: Mutex<Connection>,
}

fn finding_from_row(r: &Row) -> rusqlite::Result<Finding> {
    let json = |i: usize| -> rusqlite::Result<Vec<String>> {
        Ok(serde_json::from_str(&r.get::<_, String>(i)?).unwrap_or_default())
    };
    Ok(Finding {
        key: r.get(0)?,
        kind: r.get(1)?,
        subject_ip: r.get(2)?,
        first_seen: r.get(3)?,
        last_seen: r.get(4)?,
        score: r.get(5)?,
        severity: Severity::parse(&r.get::<_, String>(6)?),
        title: r.get(7)?,
        reasons: json(8)?,
        targets: json(9)?,
        signatures: json(10)?,
        event_count: r.get(11)?,
        status: r.get(12)?,
        notified_at: r.get(13)?,
        notified_severity: r.get::<_, Option<String>>(14)?.map(|s| Severity::parse(&s)),
        blocked_at: r.get(15)?,
    })
}

fn event_from_row(r: &Row) -> rusqlite::Result<Event> {
    Ok(Event {
        uid: r.get(0)?,
        ts: r.get(1)?,
        src_ip: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        src_port: r.get(3)?,
        dest_ip: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        dest_port: r.get(5)?,
        proto: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
        iface: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
        sid: r.get(8)?,
        signature: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
        category: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
        severity: r.get::<_, Option<i64>>(11)?.unwrap_or(0),
        action: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
        flow_id: r.get::<_, Option<String>>(13)?.unwrap_or_default(),
        app_proto: r.get::<_, Option<String>>(14)?.unwrap_or_default(),
    })
}

const EVENT_COLS: &str =
    "uid, ts, src_ip, src_port, dest_ip, dest_port, proto, iface, sid, signature, category, severity, action, flow_id, app_proto";
const FINDING_COLS: &str = "key, kind, subject_ip, first_seen, last_seen, score, severity, title, reasons, targets, \
     signatures, event_count, status, notified_at, notified_severity, blocked_at";

fn merge(a: &[String], b: &[String], cap: usize) -> Vec<String> {
    let mut out = a.to_vec();
    for x in b {
        if !out.contains(x) {
            out.push(x.clone());
        }
    }
    let skip = out.len().saturating_sub(cap);
    out.split_off(skip)
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        // v0.2 stored API events (which never carry a severity) as severity 3; mark them unknown.
        if db.query_row("SELECT v FROM kv WHERE k = 'migr_api_sev'", [], |r| r.get::<_, String>(0)).optional()?.is_none() {
            db.execute("UPDATE events SET severity = 0 WHERE source = 'api' AND severity = 3", [])?;
            db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('migr_api_sev', '1')", [])?;
        }
        Ok(Store { db: Mutex::new(db) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- events ---------------------------------------------------------
    pub fn add_events(&self, events: &[Event], source: &str) -> Result<usize> {
        let mut db = self.conn();
        let tx = db.transaction()?;
        let mut n = 0;
        {
            let mut st = tx.prepare_cached(&format!(
                "INSERT OR IGNORE INTO events ({EVENT_COLS}, source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"
            ))?;
            for e in events {
                n += st.execute(params![
                    e.uid, e.ts, e.src_ip, e.src_port, e.dest_ip, e.dest_port, e.proto, e.iface, e.sid,
                    e.signature, e.category, e.severity, e.action, e.flow_id, e.app_proto, source
                ])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn events_between(&self, start: &str, end: &str) -> Result<Vec<Event>> {
        let db = self.conn();
        let mut st = db.prepare_cached(&format!("SELECT {EVENT_COLS} FROM events WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts"))?;
        let rows = st.query_map(params![start, end], event_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn recent_events(&self, limit: usize, search: &str) -> Result<Vec<Event>> {
        let db = self.conn();
        let search = search.trim();
        let (sql, args): (String, Vec<String>) = if search.is_empty() {
            (format!("SELECT {EVENT_COLS} FROM events ORDER BY ts DESC LIMIT {limit}"), vec![])
        } else {
            let like = format!("%{search}%");
            (
                format!(
                    "SELECT {EVENT_COLS} FROM events WHERE src_ip LIKE ?1 OR dest_ip LIKE ?1 OR signature LIKE ?1 \
                     OR category LIKE ?1 OR CAST(sid AS TEXT) = ?2 ORDER BY ts DESC LIMIT {limit}"
                ),
                vec![like, search.to_string()],
            )
        };
        let mut st = db.prepare(&sql)?;
        let rows = st.query_map(params_from_iter(args.iter()), event_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn event_count_since(&self, since: &str) -> Result<i64> {
        Ok(self.conn().query_row("SELECT COUNT(*) FROM events WHERE ts >= ?1", [since], |r| r.get(0))?)
    }

    pub fn first_last_ts(&self) -> Result<(Option<String>, Option<String>)> {
        Ok(self.conn().query_row("SELECT MIN(ts), MAX(ts) FROM events", [], |r| Ok((r.get(0)?, r.get(1)?)))?)
    }

    pub fn latest_event_ts(&self) -> Result<Option<String>> {
        Ok(self.first_last_ts()?.1)
    }

    pub fn prune_events(&self, before: &str) -> Result<usize> {
        Ok(self.conn().execute("DELETE FROM events WHERE ts < ?1", [before])?)
    }

    // ---- findings -------------------------------------------------------
    pub fn get_finding(&self, key: &str) -> Result<Option<Finding>> {
        let db = self.conn();
        let mut st = db.prepare_cached(&format!("SELECT {FINDING_COLS} FROM findings WHERE key = ?1"))?;
        Ok(st.query_row([key], finding_from_row).optional()?)
    }

    fn write_finding(&self, f: &Finding) -> Result<()> {
        let j = |v: &Vec<String>| serde_json::to_string(v).unwrap_or_else(|_| "[]".into());
        self.conn().execute(
            &format!("INSERT OR REPLACE INTO findings ({FINDING_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"),
            params![
                f.key, f.kind, f.subject_ip, f.first_seen, f.last_seen, f.score, f.severity.as_str(), f.title,
                j(&f.reasons), j(&f.targets), j(&f.signatures), f.event_count, f.status, f.notified_at,
                f.notified_severity.map(|s| s.as_str()), f.blocked_at
            ],
        )?;
        Ok(())
    }

    /// Merge a freshly computed finding into the DB and return the merged record.
    pub fn upsert_finding(&self, f: &Finding) -> Result<Finding> {
        let merged = match self.get_finding(&f.key)? {
            Some(prev) => {
                let mut m = prev.clone();
                m.last_seen = prev.last_seen.clone().max(f.last_seen.clone());
                m.first_seen = prev.first_seen.clone().min(f.first_seen.clone());
                if f.score >= prev.score {
                    // The strongest assessment wins: its score, severity, title and reasons.
                    m.score = f.score;
                    m.severity = f.severity;
                    m.title = f.title.clone();
                    m.reasons = f.reasons.clone();
                }
                m.targets = merge(&prev.targets, &f.targets, 50);
                m.signatures = merge(&prev.signatures, &f.signatures, 30);
                m.event_count = prev.event_count.max(f.event_count);
                // Resolved health problems reopen when they come back. Acknowledged IPS findings
                // reopen on new activity; acknowledged exposure/device/config/health findings stay
                // acknowledged. False positives stay silenced.
                let ips_kind = matches!(prev.kind.as_str(), "inbound" | "compromise");
                if prev.status == "resolved" || (prev.status == "ack" && ips_kind && f.last_seen > prev.last_seen) {
                    m.status = "open".into();
                    if prev.status == "resolved" {
                        m.notified_at = None; // a recurrence is news
                    }
                }
                m
            }
            None => Finding {
                status: "open".into(),
                notified_at: None,
                notified_severity: None,
                blocked_at: None,
                ..f.clone()
            },
        };
        self.write_finding(&merged)?;
        Ok(merged)
    }

    pub fn set_status(&self, key: &str, status: &str) -> Result<()> {
        self.conn().execute("UPDATE findings SET status = ?1 WHERE key = ?2", params![status, key])?;
        Ok(())
    }

    pub fn set_notified(&self, key: &str, at: &str, sev: Severity) -> Result<()> {
        self.conn().execute(
            "UPDATE findings SET notified_at = ?1, notified_severity = ?2 WHERE key = ?3",
            params![at, sev.as_str(), key],
        )?;
        Ok(())
    }

    pub fn set_blocked(&self, key: &str, at: Option<&str>) -> Result<()> {
        self.conn().execute("UPDATE findings SET blocked_at = ?1 WHERE key = ?2", params![at, key])?;
        Ok(())
    }

    /// Findings filtered by status (None = all) and minimum severity, most severe / recent first.
    pub fn list_findings(&self, status: Option<&str>, min: Severity, limit: usize) -> Result<Vec<Finding>> {
        let db = self.conn();
        let mut rows: Vec<Finding> = match status {
            Some(s) => {
                let mut st = db.prepare(&format!("SELECT {FINDING_COLS} FROM findings WHERE status = ?1"))?;
                let r = st.query_map([s], finding_from_row)?.collect::<rusqlite::Result<_>>()?;
                r
            }
            None => {
                let mut st = db.prepare(&format!("SELECT {FINDING_COLS} FROM findings"))?;
                let r = st.query_map([], finding_from_row)?.collect::<rusqlite::Result<_>>()?;
                r
            }
        };
        rows.retain(|f| f.severity >= min);
        rows.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.last_seen.cmp(&a.last_seen)));
        rows.truncate(limit);
        Ok(rows)
    }

    /// Record a device sighting; returns true if this MAC was never seen before.
    pub fn upsert_device(&self, d: &crate::health::Device) -> Result<bool> {
        let db = self.conn();
        let known: bool = db.query_row("SELECT COUNT(*) FROM devices WHERE mac = ?1", [&d.mac], |r| r.get::<_, i64>(0))? > 0;
        if known {
            db.execute(
                "UPDATE devices SET ip = ?2, hostname = CASE WHEN ?3 = '' THEN hostname ELSE ?3 END, vendor = ?4, interface = ?5, last_seen = ?6 WHERE mac = ?1",
                params![d.mac, d.ip, d.hostname, d.vendor, d.interface, d.last_seen],
            )?;
        } else {
            db.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, interface, first_seen, last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![d.mac, d.ip, d.hostname, d.vendor, d.interface, d.first_seen, d.last_seen],
            )?;
        }
        Ok(!known)
    }

    pub fn list_devices(&self, limit: usize) -> Result<Vec<crate::health::Device>> {
        let db = self.conn();
        let mut st = db.prepare(&format!(
            "SELECT mac, ip, hostname, vendor, interface, first_seen, last_seen FROM devices ORDER BY first_seen DESC, last_seen DESC LIMIT {limit}"
        ))?;
        let rows = st.query_map([], |r| {
            Ok(crate::health::Device {
                mac: r.get(0)?,
                ip: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                hostname: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                vendor: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                interface: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_findings(&self) -> Result<()> {
        self.conn().execute("DELETE FROM findings WHERE kind IN ('inbound', 'compromise')", [])?;
        Ok(())
    }

    /// (total, dropped) alert counts since `since`.
    pub fn action_counts_since(&self, since: &str) -> Result<(i64, i64)> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*), COALESCE(SUM(action IN ('blocked','drop','dropped','rejected')), 0) FROM events WHERE ts >= ?1",
            [since],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn delete_all(&self) -> Result<()> {
        self.conn().execute_batch("DELETE FROM events; DELETE FROM findings; DELETE FROM kv;")?;
        Ok(())
    }

    // ---- kv -------------------------------------------------------------
    pub fn get_kv(&self, k: &str) -> Result<Option<String>> {
        Ok(self.conn().query_row("SELECT v FROM kv WHERE k = ?1", [k], |r| r.get(0)).optional()?)
    }

    pub fn set_kv(&self, k: &str, v: &str) -> Result<()> {
        self.conn().execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)", params![k, v])?;
        Ok(())
    }
}
