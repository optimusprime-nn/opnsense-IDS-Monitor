//! ipswatch - capture OPNsense IPS (Suricata) alerts and flag potential unwanted access.

pub mod autostart;
pub mod collect;
pub mod config;
pub mod crowdsec;
pub mod detect;
pub mod dns;
pub mod engine;
pub mod health;
pub mod icon;
pub mod ipspolicy;
pub mod logbuf;
pub mod monitor;
pub mod normalize;
pub mod notify;
pub mod host;
pub mod opnsense;
pub mod rdap;
pub mod report;
pub mod store;
pub mod tlscheck;
pub mod troubleshoot;
pub mod toast;
pub mod winsecret;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use chrono::{DateTime, Local, Utc};

/// Fixed-width UTC timestamp so string comparison == time comparison.
/// Same format as the earlier Python version, so existing databases stay compatible.
/// Stack for IPS Watch's own threads. The default (2 MiB, 1 MiB for the main thread on
/// Windows) has proven too small; a stack overflow kills the whole app without a trace.
pub const THREAD_STACK: usize = 16 * 1024 * 1024;

/// Start a named thread with a generous stack. The name shows in crash reports and dumps.
pub fn spawn_thread<F, T>(name: &str, f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new().name(name.to_string()).stack_size(THREAD_STACK).spawn(f).expect("starting a thread")
}

/// Longest text kept from the network (characters).
pub const MAX_TEXT: usize = 8192;

/// Text that comes from the network (DHCP host names, DNS client names, signatures, CrowdSec
/// reasons...) is chosen by whoever sends it. Before it is stored or shown: control characters
/// become spaces (a line break could fake a row), invisible direction and formatting marks are
/// removed (they can make one name read as another), and it is cut to [`MAX_TEXT`] characters.
pub fn clean_text(s: &str) -> String {
    fn invisible(c: char) -> bool {
        matches!(
            c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
        )
    }
    if s.len() <= MAX_TEXT && !s.chars().any(|c| c.is_control() || invisible(c)) {
        return s.to_string();
    }
    s.chars().filter(|&c| !invisible(c)).map(|c| if c.is_control() { ' ' } else { c }).take(MAX_TEXT).collect()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_text_cannot_fake_rows_or_hide_characters() {
        assert_eq!(clean_text("printer-01"), "printer-01");
        assert_eq!(clean_text("evil\nCRITICAL fake row"), "evil CRITICAL fake row");
        assert_eq!(clean_text("pay\u{202E}fdp.exe"), "payfdp.exe");
        assert_eq!(clean_text("a\u{200B}b\u{FEFF}c\u{2066}d"), "abcd");
        assert_eq!(clean_text(&"x".repeat(MAX_TEXT + 10)).chars().count(), MAX_TEXT);
        assert_eq!(clean_text("Zoë's iPhone"), "Zoë's iPhone");
    }
}
