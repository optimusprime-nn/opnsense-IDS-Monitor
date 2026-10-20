"""SQLite persistence for events and findings."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    uid TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    src_ip TEXT, src_port INTEGER,
    dest_ip TEXT, dest_port INTEGER,
    proto TEXT, iface TEXT,
    sid INTEGER, signature TEXT, category TEXT, severity INTEGER,
    action TEXT, flow_id TEXT, app_proto TEXT,
    source TEXT                       -- api | syslog | file
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip, ts);

CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY,             -- e.g. "inbound:203.0.113.7" or "compromise:10.0.0.5"
    kind TEXT NOT NULL,
    subject_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    reasons TEXT NOT NULL,            -- JSON list
    targets TEXT NOT NULL,            -- JSON list of "ip:port"
    signatures TEXT NOT NULL,         -- JSON list
    event_count INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',  -- open | ack | false_positive
    notified_at TEXT,
    notified_severity TEXT,
    blocked_at TEXT
);

CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    # --- events ----------------------------------------------------------
    def add_events(self, events: list[dict], source: str) -> int:
        cols = ["uid", "ts", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "iface", "sid",
                "signature", "category", "severity", "action", "flow_id", "app_proto"]
        sql = (f"INSERT OR IGNORE INTO events ({','.join(cols)},source) "
               f"VALUES ({','.join('?' * len(cols))},?)")
        with self.lock:
            before = self.db.total_changes
            self.db.execute("BEGIN")
            self.db.executemany(sql, [tuple(e.get(c) for c in cols) + (source,) for e in events])
            self.db.execute("COMMIT")
            return self.db.total_changes - before

    def events_between(self, start: str, end: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts", (start, end))
            return [dict(r) for r in rows]

    def recent_events(self, limit: int = 1000, search: str = "") -> list[dict]:
        sql, args = "SELECT * FROM events", []
        if search:
            like = f"%{search}%"
            sql += " WHERE src_ip LIKE ? OR dest_ip LIKE ? OR signature LIKE ? OR category LIKE ? OR CAST(sid AS TEXT) = ?"
            args = [like, like, like, like, search]
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args)]

    def event_count(self, since: str = "") -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (since,)).fetchone()[0]

    def events_for_ip(self, ip: str, limit: int = 500) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE src_ip = ? OR dest_ip = ? ORDER BY ts DESC LIMIT ?",
                                   (ip, ip, limit))
            return [dict(r) for r in rows]

    def first_last_ts(self) -> tuple[str | None, str | None]:
        with self.lock:
            r = self.db.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return r[0], r[1]

    def latest_event_ts(self) -> str | None:
        with self.lock:
            r = self.db.execute("SELECT MAX(ts) FROM events").fetchone()
            return r[0]

    def prune(self, before: str) -> int:
        with self.lock:
            return self.db.execute("DELETE FROM events WHERE ts < ?", (before,)).rowcount

    # --- findings --------------------------------------------------------
    def get_finding(self, key: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM findings WHERE key = ?", (key,)).fetchone()
        return _decode(r) if r else None

    def upsert_finding(self, f: dict) -> tuple[dict, dict | None]:
        """Merge a freshly computed finding into the DB. Returns (merged, previous)."""
        prev = self.get_finding(f["key"])
        if prev:
            merged = dict(prev)
            merged["last_seen"] = max(prev["last_seen"], f["last_seen"])
            merged["first_seen"] = min(prev["first_seen"], f["first_seen"])
            merged["score"] = max(prev["score"], f["score"])
            if SEV_ORDER[f["severity"]] > SEV_ORDER[prev["severity"]]:
                merged["severity"] = f["severity"]
                merged["title"] = f["title"]
            merged["reasons"] = _merge(prev["reasons"], f["reasons"], 30)
            merged["targets"] = _merge(prev["targets"], f["targets"], 50)
            merged["signatures"] = _merge(prev["signatures"], f["signatures"], 30)
            merged["event_count"] = max(prev["event_count"], f["event_count"])
            # An acknowledged finding that becomes active again is reopened;
            # false positives stay silenced.
            if prev["status"] == "ack" and f["last_seen"] > prev["last_seen"]:
                merged["status"] = "open"
        else:
            merged = {**f, "status": "open", "notified_at": None, "notified_severity": None, "blocked_at": None}
        with self.lock:
            self.db.execute(
                """INSERT OR REPLACE INTO findings
                   (key, kind, subject_ip, first_seen, last_seen, score, severity, title, reasons, targets,
                    signatures, event_count, status, notified_at, notified_severity, blocked_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (merged["key"], merged["kind"], merged["subject_ip"], merged["first_seen"], merged["last_seen"],
                 merged["score"], merged["severity"], merged["title"], json.dumps(merged["reasons"]),
                 json.dumps(merged["targets"]), json.dumps(merged["signatures"]), merged["event_count"],
                 merged["status"], merged["notified_at"], merged["notified_severity"], merged["blocked_at"]))
        return merged, prev

    def mark(self, key: str, **fields) -> None:
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self.lock:
            self.db.execute(f"UPDATE findings SET {sets} WHERE key = ?", (*fields.values(), key))

    def list_findings(self, status: str | None = "open", min_severity: str = "low", limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM findings"
        args: list = []
        if status:
            sql += " WHERE status = ?"
            args.append(status)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit * 4)
        with self.lock:
            rows = [_decode(r) for r in self.db.execute(sql, args)]
        rows = [r for r in rows if SEV_ORDER[r["severity"]] >= SEV_ORDER[min_severity]]
        rows.sort(key=lambda r: (SEV_ORDER[r["severity"]], r["last_seen"]), reverse=True)
        return rows[:limit]

    # --- kv --------------------------------------------------------------
    def get(self, k: str, default: str | None = None) -> str | None:
        with self.lock:
            r = self.db.execute("SELECT v FROM kv WHERE k = ?", (k,)).fetchone()
        return r[0] if r else default

    def set(self, k: str, v: str) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (k, v))


def _decode(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("reasons", "targets", "signatures"):
        d[k] = json.loads(d[k])
    return d


def _merge(a: list, b: list, cap: int) -> list:
    out = list(a)
    for x in b:
        if x not in out:
            out.append(x)
    return out[-cap:]
