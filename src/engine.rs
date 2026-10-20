//! Glue: run detection over the store, merge findings, notify, optionally block.

use anyhow::Result;
use chrono::{Duration, Utc};
use log::{error, warn};
use std::net::IpAddr;

use crate::config::{parse_nets, Config};
use crate::opnsense::OPNsense;
use crate::store::{Finding, Store};
use crate::{detect, notify};

/// Analyze the `window_minutes` before `anchor` (default: latest event).
/// Returns findings that are new or escalated enough to alert on (already sent to remote channels
/// when `do_notify` is set; the caller decides about desktop alerts).
pub fn run_detection(
    cfg: &Config,
    store: &Store,
    api: Option<&OPNsense>,
    anchor: Option<&str>,
    do_notify: bool,
) -> Result<Vec<Finding>> {
    let anchor = match anchor {
        Some(a) => a.to_string(),
        None => match store.latest_event_ts()? {
            Some(a) => a,
            None => return Ok(vec![]),
        },
    };
    let (start, end) = detect::window(&anchor, cfg.detect.window_minutes);
    let events = store.events_between(&start, &end)?;
    if events.is_empty() {
        return Ok(vec![]);
    }
    let nets = cfg.detect.nets()?;

    let fw = match api {
        Some(api) if cfg.firewall.correlate => match api.firewall_log(cfg.firewall.log_limit) {
            Ok(rows) => Some(detect::firewall_passes_by_src(&rows, &nets)),
            Err(e) => {
                warn!("firewall log correlation skipped: {e:#}");
                None
            }
        },
        _ => None,
    };

    let mut alerted = Vec::new();
    for f in detect::analyze(&events, &cfg.detect, &nets, fw.as_ref()) {
        let mut merged = store.upsert_finding(&f)?;
        if merged.status == "false_positive" {
            continue;
        }
        if cfg.block.enabled && merged.blocked_at.is_none() {
            if let Some(api) = api {
                maybe_block(cfg, store, api, &mut merged);
            }
        }
        if do_notify && should_notify(cfg, &merged) {
            // Remote channels have their own threshold; desktop alerts use gui.alert_min_severity.
            let delivered = if merged.severity >= cfg.notify.min_severity {
                notify::send(&merged, &cfg.notify)
            } else {
                warn!("FINDING {}: {}", merged.key, merged.title);
                true
            };
            if delivered {
                store.set_notified(&merged.key, &crate::now_iso(), merged.severity)?;
            }
            alerted.push(merged);
        }
    }
    Ok(alerted)
}

fn should_notify(cfg: &Config, f: &Finding) -> bool {
    if f.severity < cfg.notify.min_severity.min(cfg.gui.alert_min_severity) || f.status != "open" {
        return false;
    }
    let Some(at) = &f.notified_at else { return true };
    if f.notified_severity.is_none_or(|s| f.severity > s) {
        return true; // escalated since last notification
    }
    let last = crate::parse_iso(at).unwrap_or_else(Utc::now);
    Utc::now() - last > Duration::minutes(cfg.detect.renotify_minutes as i64) && f.last_seen.as_str() > at.as_str()
}

/// Whether `ip` may be blocked at all (public, external, not on the never-block list).
pub fn blockable(cfg: &Config, ip: &str) -> Result<(), String> {
    let addr: IpAddr = ip.parse().map_err(|_| format!("{ip} is not an IP address"))?;
    let nets = cfg.detect.nets().map_err(|e| e.to_string())?;
    if nets.is_internal(ip) {
        return Err(format!("{ip} is inside your internal networks"));
    }
    let private = match addr {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || (a.segments()[0] & 0xfe00) == 0xfc00,
    };
    if private {
        return Err(format!("{ip} is a private/reserved address"));
    }
    let never = parse_nets(&cfg.block.never_block).map_err(|e| e.to_string())?;
    if crate::config::in_nets(ip, &never) {
        return Err(format!("{ip} is on the never-block list"));
    }
    Ok(())
}

fn maybe_block(cfg: &Config, store: &Store, api: &OPNsense, f: &mut Finding) {
    if f.kind != "inbound" || f.severity < cfg.block.min_severity || blockable(cfg, &f.subject_ip).is_err() {
        return;
    }
    if cfg.block.dry_run {
        warn!("[dry-run] would add {} to alias {}", f.subject_ip, cfg.block.alias);
        return;
    }
    match api.alias_add(&cfg.block.alias, &f.subject_ip) {
        Ok(()) => {
            let now = crate::now_iso();
            let _ = store.set_blocked(&f.key, Some(&now));
            f.blocked_at = Some(now);
            warn!("blocked {} via alias {}", f.subject_ip, cfg.block.alias);
        }
        Err(e) => error!("auto-block of {} failed: {e:#}", f.subject_ip),
    }
}

/// Slide the detection window across all stored events (offline / imported data).
pub fn replay(cfg: &Config, store: &Store, do_notify: bool) -> Result<usize> {
    let (Some(first), Some(last)) = store.first_last_ts()? else { return Ok(0) };
    let step = Duration::minutes((cfg.detect.window_minutes / 2).max(1) as i64);
    let mut t = crate::parse_iso(&first).unwrap_or_else(Utc::now);
    let end = crate::parse_iso(&last).unwrap_or_else(Utc::now) + step;
    let mut n = 0;
    while t <= end {
        n += run_detection(cfg, store, None, Some(&crate::iso(t)), do_notify)?.len();
        t += step;
    }
    Ok(n)
}

/// Delete events older than the retention period.
pub fn prune(cfg: &Config, store: &Store) -> Result<usize> {
    let cutoff = crate::iso(Utc::now() - Duration::days(cfg.retention_days.max(1) as i64));
    store.prune_events(&cutoff)
}
