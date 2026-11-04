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
    if let Some(api) = api {
        refresh_own_addresses(store, api, false);
    }
    let nets = cfg.detect.nets()?.with_own(own_addresses(store));

    let fw = match api {
        Some(api) if cfg.firewall.correlate => match api.firewall_log(cfg.firewall.log_limit) {
            Ok(rows) => Some(detect::firewall_passes_by_src(
                &rows,
                &nets,
                Some((&start, &end)),
                &cfg.firewall.correlate_ignore_ports,
            )),
            Err(e) => {
                warn!("firewall log correlation skipped: {e:#}");
                None
            }
        },
        _ => None,
    };

    let mut alerted = Vec::new();
    let bans = if cfg.crowdsec.enabled && cfg.crowdsec.boost_ips { crate::crowdsec::cached_bans(store) } else { Default::default() };
    for mut f in detect::analyze(&events, &cfg.detect, &nets, fw.as_ref()) {
        // Known attacker: CrowdSec (local detection or community blocklist) has banned this source.
        if f.kind == "inbound" {
            if let Some(b) = bans.get(&f.subject_ip) {
                let place = [b.country.as_str(), b.network.as_str()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
                f.reasons.push(format!("CrowdSec has banned this IP: {}{}", b.reason, if place.is_empty() { String::new() } else { format!(" ({place})") }));
                f.score += 20;
                f.severity = crate::config::Severity::from_score(f.score);
            }
        }
        let mut merged = store.upsert_finding(&f)?;
        if merged.status == "false_positive" {
            continue;
        }
        if cfg.block.enabled && merged.blocked_at.is_none() {
            if let Some(api) = api {
                maybe_block(cfg, store, api, &mut merged);
            }
        }
        if do_notify {
            if let Some(f) = notify_if_due(cfg, store, merged)? {
                alerted.push(f);
            }
        }
    }
    Ok(alerted)
}

/// The firewall's own interface addresses, as last detected.
pub fn own_addresses(store: &Store) -> Vec<IpAddr> {
    store
        .get_kv("own_ips")
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Re-read the firewall's interface addresses (at most hourly unless `force`).
pub fn refresh_own_addresses(store: &Store, api: &OPNsense, force: bool) {
    let fresh = store
        .get_kv("own_ips_at")
        .ok()
        .flatten()
        .and_then(|t| crate::parse_iso(&t))
        .is_some_and(|t| Utc::now() - t < Duration::hours(1));
    if fresh && !force {
        return;
    }
    match api.interface_addresses() {
        Ok(ips) => {
            let list: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
            if store.get_kv("own_ips").ok().flatten().as_deref() != Some(&serde_json::to_string(&list).unwrap_or_default()) {
                log::info!("Firewall addresses (treated as internal): {}", list.join(", "));
            }
            let _ = store.set_kv("own_ips", &serde_json::to_string(&list).unwrap_or_default());
            let _ = store.set_kv("own_ips_at", &crate::now_iso());
        }
        Err(e) => warn!("could not read the firewall's interface addresses: {e:#}"),
    }
}

/// Send a finding to the remote channels if it's due; returns it when it should alert
/// (the caller decides about desktop toasts).
pub fn notify_if_due(cfg: &Config, store: &Store, f: Finding) -> Result<Option<Finding>> {
    if f.status == "false_positive" || !should_notify(cfg, &f) {
        return Ok(None);
    }
    // Remote channels have their own threshold; desktop alerts use gui.alert_min_severity.
    let delivered = if f.severity >= cfg.notify.min_severity {
        notify::send(&f, &cfg.notify)
    } else {
        warn!("FINDING {}: {}", f.key, f.title);
        true
    };
    if delivered {
        store.set_notified(&f.key, &crate::now_iso(), f.severity)?;
    }
    Ok(Some(f))
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
    if is_reserved(addr) {
        return Err(format!("{ip} is a private/reserved address"));
    }
    let never = parse_nets(&cfg.block.never_block).map_err(|e| e.to_string())?;
    if crate::config::in_nets(ip, &never) {
        return Err(format!("{ip} is on the never-block list"));
    }
    Ok(())
}

/// Addresses that are never a real outside attacker: private, loopback, link-local, multicast,
/// shared/CGNAT, "this network", benchmarking and future-use ranges, IPv6 unique-local,
/// link-local and multicast, and IPv4-mapped IPv6 forms of any of those.
pub fn is_reserved(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let [o1, o2, ..] = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || o1 == 0 // "this network"
                || (o1 == 100 && (64..128).contains(&o2)) // shared address space (CGNAT)
                || (o1 == 192 && o2 == 0 && a.octets()[2] == 0) // IETF protocol assignments
                || (o1 == 198 && (o2 == 18 || o2 == 19)) // benchmarking
                || o1 >= 240 // reserved for future use
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_reserved(IpAddr::V4(v4));
            }
            let s0 = a.segments()[0];
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s0 & 0xfe00) == 0xfc00 // unique local
                || (s0 & 0xffc0) == 0xfe80 // link local
        }
    }
}

fn maybe_block(cfg: &Config, store: &Store, api: &OPNsense, f: &mut Finding) {
    if f.kind != "inbound" || f.severity < cfg.block.min_severity || blockable(cfg, &f.subject_ip).is_err() {
        return;
    }
    // Syslog is unauthenticated and can be forged: only block when the firewall's own API
    // reported this source too.
    match store.has_api_event_from(&f.subject_ip, &f.first_seen) {
        Ok(true) => {}
        Ok(false) => {
            warn!("not auto-blocking {}: only seen via syslog/import, not confirmed by the firewall API", f.subject_ip);
            return;
        }
        Err(e) => {
            error!("not auto-blocking {}: {e:#}", f.subject_ip);
            return;
        }
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

pub struct RescoreResult {
    pub events: usize,
    pub before: usize,
    pub after: usize,
}

/// Recompute every finding from the stored events with the current rules.
///
/// Your marks (acknowledged / false positive), block times and notification state are carried
/// over by key; findings that no longer qualify disappear. Re-scored findings are marked as
/// already notified so this never triggers a burst of alerts.
pub fn rescore(cfg: &Config, store: &Store) -> Result<RescoreResult> {
    let old = store.list_findings(None, crate::config::Severity::Low, usize::MAX)?;
    let events = store.first_last_ts().map(|_| store.event_count_since("")).unwrap_or(Ok(0))? as usize;
    store.delete_findings()?;
    replay(cfg, store, false)?;
    let now = crate::now_iso();
    let after = store.list_findings(None, crate::config::Severity::Low, usize::MAX)?;
    for f in &after {
        match old.iter().find(|o| o.key == f.key) {
            Some(o) => {
                store.set_status(&f.key, &o.status)?;
                store.set_blocked(&f.key, o.blocked_at.as_deref())?;
                store.set_notified(&f.key, o.notified_at.as_deref().unwrap_or(&now), o.notified_severity.unwrap_or(f.severity))?;
            }
            None => store.set_notified(&f.key, &now, f.severity)?,
        }
    }
    Ok(RescoreResult { events, before: old.len(), after: after.len() })
}

/// Delete events older than the retention period.
pub fn prune(cfg: &Config, store: &Store) -> Result<usize> {
    let cutoff = crate::iso(Utc::now() - Duration::days(cfg.retention_days.max(1) as i64));
    Ok(store.prune_events(&cutoff)? + store.cap_events(cfg.max_events)?)
}
