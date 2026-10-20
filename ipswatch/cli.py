"""Command-line interface.

    ipswatch -c config.toml check          # verify API access + IDS status
    ipswatch -c config.toml run            # continuous: poll API / receive syslog, detect, alert
    ipswatch -c config.toml poll           # one poll + detection pass (for cron / Task Scheduler)
    ipswatch -c config.toml import eve.json
    ipswatch -c config.toml findings [--all] [--min high]
    ipswatch -c config.toml ack <key> | fp <key> | reopen <key>
    ipswatch -c config.toml report report.html
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import collect, config, engine, report
from .opnsense import OPNsense, OPNsenseError
from .store import Store

log = logging.getLogger("ipswatch")


def _api(cfg) -> OPNsense | None:
    if not cfg.opnsense.url:
        return None
    return OPNsense(cfg.opnsense)


def cmd_check(cfg, store, args) -> int:
    api = _api(cfg)
    if not api:
        print("opnsense.url not set")
        return 1
    try:
        print("IDS status:", api.ids_status())
        rows = api.ids_alerts(rows=5)
        print(f"Alert query OK ({len(rows)} sample rows)")
        if cfg.firewall.correlate:
            print(f"Firewall log OK ({len(api.firewall_log(10))} sample rows)")
        if cfg.block.enabled:
            print(f"Block alias '{cfg.block.alias}' has {len(api.alias_list(cfg.block.alias))} entries")
    except OPNsenseError as e:
        print("FAILED:", e)
        return 1
    return 0


def _poll_once(cfg, store, api) -> int:
    added = 0
    if api:
        try:
            added = collect.poll_api(api, store, cfg.opnsense.page_size, cfg.opnsense.max_pages)
        except OPNsenseError as e:
            log.error("API poll failed: %s", e)
    return added


def cmd_poll(cfg, store, args) -> int:
    api = _api(cfg)
    added = _poll_once(cfg, store, api)
    alerted = engine.run_detection(cfg, store, api)
    log.info("poll: %d new events, %d notifications", added, len(alerted))
    return 0


def cmd_run(cfg, store, args) -> int:
    api = _api(cfg)
    buf = None
    if cfg.syslog.enabled:
        buf, _ = collect.start_syslog(cfg.syslog.bind, cfg.syslog.port, cfg.syslog.protocol, store)
    if not api and not buf:
        log.error("nothing to collect from: configure [opnsense] url and/or enable [syslog]")
        return 1

    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    log.info("ipswatch running (poll every %ds)", cfg.poll_seconds)
    last_prune = 0.0
    while not stop:
        added = _poll_once(cfg, store, api)
        if buf:
            added += buf.flush()
        if added:
            log.info("%d new IPS events", added)
        # Anchor on wall-clock time in live mode so stale windows age out.
        engine.run_detection(cfg, store, api, anchor=datetime.now(timezone.utc).isoformat())
        if time.time() - last_prune > 3600:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=args.retention_days)).isoformat()
            store.prune(cutoff)
            last_prune = time.time()
        for _ in range(cfg.poll_seconds):
            if stop:
                break
            time.sleep(1)
    log.info("stopped")
    return 0


def cmd_import(cfg, store, args) -> int:
    n = collect.import_file(args.file, store)
    print(f"imported {n} new alert events from {args.file}")
    if not args.no_detect:
        engine.replay(cfg, store, do_notify=not args.quiet)
        return cmd_findings(cfg, store, argparse.Namespace(all=False, min="low", limit=50))
    return 0


def cmd_findings(cfg, store, args) -> int:
    rows = store.list_findings(None if args.all else "open", args.min, args.limit)
    if not rows:
        print("no findings")
        return 0
    for f in rows:
        print(f"{f['severity'].upper():9} {f['score']:4}  {f['last_seen'][:19]}  {f['status']:14} {f['key']}")
        print(f"          {f['title']}")
        for r in f["reasons"][:6]:
            print(f"            - {r}")
    return 0


def _set_status(status):
    def _cmd(cfg, store, args) -> int:
        if not store.get_finding(args.key):
            print("no such finding:", args.key)
            return 1
        store.mark(args.key, status=status)
        print(f"{args.key} -> {status}")
        return 0
    return _cmd


def cmd_report(cfg, store, args) -> int:
    n = report.write_html(store, args.out)
    print(f"wrote {args.out} ({n} findings)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ipswatch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", help="TOML config file")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    r = sub.add_parser("run")
    r.add_argument("--retention-days", type=int, default=30)
    sub.add_parser("poll")
    i = sub.add_parser("import")
    i.add_argument("file")
    i.add_argument("--no-detect", action="store_true")
    i.add_argument("--quiet", action="store_true", help="don't send notifications during replay")
    fl = sub.add_parser("findings")
    fl.add_argument("--all", action="store_true", help="include acked / false-positive")
    fl.add_argument("--min", default="low", choices=["low", "medium", "high", "critical"])
    fl.add_argument("--limit", type=int, default=50)
    for name in ("ack", "fp", "reopen"):
        s = sub.add_parser(name)
        s.add_argument("key")
    rp = sub.add_parser("report")
    rp.add_argument("out")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load(args.config)
    db = Path(cfg.db_path)
    if args.config and not db.is_absolute():  # relative to the config file, same as the GUI
        db = Path(args.config).resolve().parent / db
    store = Store(str(db))
    handlers = {
        "check": cmd_check, "run": cmd_run, "poll": cmd_poll, "import": cmd_import,
        "findings": cmd_findings, "report": cmd_report,
        "ack": _set_status("ack"), "fp": _set_status("false_positive"), "reopen": _set_status("open"),
    }
    return handlers[args.cmd](cfg, store, args)


if __name__ == "__main__":
    sys.exit(main())
