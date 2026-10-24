//! ipswatch - capture OPNsense IPS (Suricata) alerts and flag potential unwanted access.

pub mod autostart;
pub mod collect;
pub mod config;
pub mod crowdsec;
pub mod detect;
pub mod engine;
pub mod health;
pub mod icon;
pub mod ipspolicy;
pub mod logbuf;
pub mod monitor;
pub mod normalize;
pub mod notify;
pub mod opnsense;
pub mod report;
pub mod store;
pub mod tlscheck;
pub mod toast;
pub mod winsecret;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use chrono::{DateTime, Local, Utc};

/// Fixed-width UTC timestamp so string comparison == time comparison.
/// Same format as the earlier Python version, so existing databases stay compatible.
pub fn iso(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
}

pub fn now_iso() -> String {
    iso(Utc::now())
}

pub fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

/// Render a stored UTC timestamp in local time for display.
pub fn local_time(s: &str) -> String {
    parse_iso(s)
        .map(|d| d.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| s.to_string())
}
