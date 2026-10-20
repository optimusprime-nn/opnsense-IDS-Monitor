"""Normalize Suricata EVE records from OPNsense into a flat event dict.

Handles both raw EVE JSON (nested ``alert`` object, as sent by syslog/eve.json)
and the flattened rows returned by OPNsense's ``ids/service/query_alerts`` API
(``alert`` = signature string, ``alert_sid``, ``alert_action``...).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

_JSON_RE = re.compile(r"\{.*\}\s*$", re.S)


def parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    v = value.strip().replace("Z", "+00:00")
    # Suricata: 2026-10-19T18:22:01.123456+0000 -> make offset ISO compatible
    v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def from_syslog_line(line: str) -> dict | None:
    """Extract the EVE JSON payload from a syslog line (RFC3164/5424)."""
    m = _JSON_RE.search(line)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def normalize(rec: dict) -> dict | None:
    """Return a normalized alert event, or None if the record isn't an alert."""
    if rec.get("event_type", "alert") != "alert":
        return None

    alert = rec.get("alert")
    if isinstance(alert, dict):
        signature = alert.get("signature", "")
        sid = alert.get("signature_id")
        action = alert.get("action", "")
        category = alert.get("category", "")
        severity = alert.get("severity")
    else:  # OPNsense API flattened form
        signature = alert or rec.get("alert_signature", "")
        sid = rec.get("alert_sid")
        action = rec.get("alert_action", "")
        category = rec.get("alert_category", rec.get("category", ""))
        severity = rec.get("alert_severity", rec.get("severity"))

    if not signature and sid is None:
        return None

    ts = parse_ts(rec.get("timestamp"))
    ev = {
        "ts": ts.isoformat(timespec="microseconds"),
        "src_ip": rec.get("src_ip", ""),
        "src_port": _int(rec.get("src_port")),
        "dest_ip": rec.get("dest_ip", ""),
        "dest_port": _int(rec.get("dest_port")),
        "proto": str(rec.get("proto", "")).upper(),
        "iface": rec.get("in_iface", ""),
        "sid": _int(sid),
        "signature": signature,
        "category": category or "",
        "severity": _int(severity) or 3,
        # Suricata: "allowed" (IDS / not dropped) vs "blocked" (IPS dropped it)
        "action": (action or "").lower(),
        "flow_id": str(rec.get("flow_id", "")),
        "app_proto": rec.get("app_proto", ""),
    }
    ev["uid"] = hashlib.sha1(
        f'{ev["ts"]}|{ev["flow_id"]}|{ev["sid"]}|{ev["src_ip"]}|{ev["dest_ip"]}|{ev["dest_port"]}'.encode()
    ).hexdigest()
    return ev


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
