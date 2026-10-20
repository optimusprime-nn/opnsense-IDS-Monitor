"""Glue: run detection over the store, merge findings, notify, optionally block."""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from . import detect, notify
from .config import Config
from .opnsense import OPNsense, OPNsenseError
from .store import SEV_ORDER, Store, utcnow

log = logging.getLogger("ipswatch.engine")


def run_detection(cfg: Config, store: Store, api: OPNsense | None, anchor: str | None = None,
                  do_notify: bool = True) -> list[dict]:
    """Analyze the last `window_minutes` of events. Returns findings that triggered a notification."""
    anchor = anchor or store.latest_event_ts()
    if not anchor:
        return []
    start, end = detect.window(anchor, cfg.detect.window_minutes)
    events = store.events_between(start, end)
    if not events:
        return []

    fw = None
    if api and cfg.firewall.correlate:
        try:
            fw = detect.firewall_passes_by_src(api.firewall_log(cfg.firewall.log_limit), cfg.detect)
        except OPNsenseError as e:
            log.warning("firewall log correlation skipped: %s", e)

    alerted = []
    for f in detect.analyze(events, cfg.detect, fw):
        merged, prev = store.upsert_finding(f)
        if merged["status"] == "false_positive":
            continue
        if cfg.block.enabled and api and not merged.get("blocked_at"):
            _maybe_block(cfg, store, api, merged)
        if do_notify and _should_notify(cfg, merged):
            if notify.send(merged, cfg.notify):
                store.mark(merged["key"], notified_at=utcnow(), notified_severity=merged["severity"])
            alerted.append(merged)
    return alerted


def _should_notify(cfg: Config, f: dict) -> bool:
    if SEV_ORDER[f["severity"]] < SEV_ORDER[cfg.notify.min_severity] or f["status"] != "open":
        return False
    if not f.get("notified_at"):
        return True
    if SEV_ORDER[f["severity"]] > SEV_ORDER.get(f.get("notified_severity") or "low", 0):
        return True  # escalated since last notification
    last = datetime.fromisoformat(f["notified_at"])
    return (datetime.now(timezone.utc) - last > timedelta(minutes=cfg.detect.renotify_minutes)
            and f["last_seen"] > f["notified_at"])


def _maybe_block(cfg: Config, store: Store, api: OPNsense, f: dict) -> None:
    b = cfg.block
    ip = f["subject_ip"]
    if f["kind"] != "inbound" or SEV_ORDER[f["severity"]] < SEV_ORDER[b.min_severity]:
        return
    if cfg.detect.is_internal(ip):
        return
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            return
        if any(addr in ipaddress.ip_network(n, strict=False) for n in b.never_block
               if ipaddress.ip_network(n, strict=False).version == addr.version):
            return
    except ValueError:
        return
    if b.dry_run:
        log.warning("[dry-run] would add %s to alias %s", ip, b.alias)
        return
    try:
        api.alias_add(b.alias, ip)
        now = utcnow()
        store.mark(f["key"], blocked_at=now)
        f["blocked_at"] = now
        log.warning("blocked %s via alias %s", ip, b.alias)
    except OPNsenseError as e:
        log.error("auto-block of %s failed: %s", ip, e)


def replay(cfg: Config, store: Store, do_notify: bool = False) -> int:
    """Slide the detection window across all stored events (offline / imported data).

    Returns the number of findings that would have notified.
    """
    first, last = store.first_last_ts()
    if not first:
        return 0
    step = timedelta(minutes=max(1, cfg.detect.window_minutes // 2))
    t, end = datetime.fromisoformat(first), datetime.fromisoformat(last) + step
    n = 0
    while t <= end:
        n += len(run_detection(cfg, store, None, anchor=t.isoformat(), do_notify=do_notify))
        t += step
    return n
