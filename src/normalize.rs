//! Normalize Suricata EVE records from OPNsense into a flat [`Event`].
//!
//! Handles raw EVE JSON (nested `alert` object - syslog / eve.json) and the flattened rows
//! returned by OPNsense's `ids/service/query_alerts` API (`alert` = signature string,
//! `alert_sid`, `alert_action` ...).

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub uid: String,
    pub ts: String,
    pub src_ip: String,
    pub src_port: Option<i64>,
    pub dest_ip: String,
    pub dest_port: Option<i64>,
    pub proto: String,
    pub iface: String,
    pub sid: Option<i64>,
    pub signature: String,
    pub category: String,
    pub severity: i64,
    /// Suricata: "allowed" (not dropped) vs "blocked" (dropped by IPS).
    pub action: String,
    pub flow_id: String,
    pub app_proto: String,
}

impl Event {
    pub fn was_dropped(&self) -> bool {
        matches!(self.action.as_str(), "blocked" | "drop" | "dropped" | "rejected")
    }
}

pub fn parse_ts(v: Option<&str>) -> DateTime<Utc> {
    let Some(s) = v.map(str::trim) else { return Utc::now() };
    DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z")
        .or_else(|_| DateTime::parse_from_rfc3339(s))
        .map(|d| d.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").map(|n| n.and_utc())
        })
        .unwrap_or_else(|_| Utc::now())
}

/// Extract the EVE JSON payload from a syslog line (RFC3164/5424).
pub fn from_syslog_line(line: &str) -> Option<Value> {
    let start = line.find('{')?;
    let end = line.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&line[start..=end]).ok()
}

fn as_i64(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn as_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Returns a normalized alert event, or None if the record isn't an alert.
pub fn normalize(rec: &Value) -> Option<Event> {
    let obj = rec.as_object()?;
    if obj.get("event_type").and_then(Value::as_str).unwrap_or("alert") != "alert" {
        return None;
    }
    let (signature, sid, action, category, severity) = match obj.get("alert") {
        Some(Value::Object(a)) => (
            as_str(a.get("signature")),
            as_i64(a.get("signature_id")),
            as_str(a.get("action")),
            as_str(a.get("category")),
            as_i64(a.get("severity")),
        ),
        other => (
            match other {
                Some(Value::String(s)) => s.clone(),
                _ => as_str(obj.get("alert_signature")),
            },
            as_i64(obj.get("alert_sid")),
            as_str(obj.get("alert_action")),
            as_str(obj.get("alert_category").or(obj.get("category"))),
            as_i64(obj.get("alert_severity").or(obj.get("severity"))),
        ),
    };
    if signature.is_empty() && sid.is_none() {
        return None;
    }
    let ts = crate::iso(parse_ts(obj.get("timestamp").and_then(Value::as_str)));
    let mut ev = Event {
        uid: String::new(),
        ts,
        src_ip: as_str(obj.get("src_ip")),
        src_port: as_i64(obj.get("src_port")),
        dest_ip: as_str(obj.get("dest_ip")),
        dest_port: as_i64(obj.get("dest_port")),
        proto: as_str(obj.get("proto")).to_uppercase(),
        iface: as_str(obj.get("in_iface")),
        sid,
        signature,
        category,
        // 0 = unknown (OPNsense's alert API omits it); detection infers it from the rule family.
        severity: severity.unwrap_or(0),
        action: action.to_lowercase(),
        flow_id: as_str(obj.get("flow_id")),
        app_proto: as_str(obj.get("app_proto")),
    };
    // Same uid recipe as the Python version (keeps dedupe working on old databases).
    let key = format!(
        "{}|{}|{}|{}|{}|{}",
        ev.ts,
        ev.flow_id,
        ev.sid.map(|s| s.to_string()).unwrap_or_else(|| "None".into()),
        ev.src_ip,
        ev.dest_ip,
        ev.dest_port.map(|s| s.to_string()).unwrap_or_else(|| "None".into())
    );
    ev.uid = sha1_smol::Sha1::from(key).digest().to_string();
    Some(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_eve() {
        let ev = normalize(&json!({"timestamp": "2026-10-19T12:00:00.000000+0000", "event_type": "alert",
            "src_ip": "203.0.113.7", "dest_ip": "192.168.1.10", "dest_port": 22, "proto": "TCP",
            "alert": {"action": "allowed", "signature_id": 2001219, "signature": "ET SCAN SSH", "severity": 2}}))
        .unwrap();
        assert_eq!(ev.sid, Some(2001219));
        assert_eq!(ev.ts, "2026-10-19T12:00:00.000000+00:00");
        assert!(!ev.was_dropped());
    }

    #[test]
    fn opnsense_api_flattened() {
        let ev = normalize(&json!({"timestamp": "2026-10-19T12:00:00.000000+0000", "src_ip": "1.2.3.4",
            "dest_ip": "10.0.0.5", "dest_port": 3389, "alert": "ET SCAN RDP", "alert_sid": 2023753,
            "alert_action": "blocked"}))
        .unwrap();
        assert_eq!(ev.signature, "ET SCAN RDP");
        assert!(ev.was_dropped());
    }

    #[test]
    fn syslog_line_and_non_alerts() {
        let line = r#"<14>Oct 19 12:00:00 fw suricata[1]: {"event_type":"alert","src_ip":"1.1.1.1","dest_ip":"10.0.0.1","alert":{"signature":"x","signature_id":1}}"#;
        assert!(normalize(&from_syslog_line(line).unwrap()).is_some());
        assert!(normalize(&json!({"event_type": "flow"})).is_none());
        assert!(from_syslog_line("no json here").is_none());
    }
}
