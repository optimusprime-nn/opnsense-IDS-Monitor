"""Event collectors: OPNsense API poller, syslog receiver, and EVE file import."""
from __future__ import annotations

import json
import logging
import socketserver
import threading

from .normalize import from_syslog_line, normalize
from .opnsense import OPNsense
from .store import Store

log = logging.getLogger("ipswatch.collect")


def poll_api(api: OPNsense, store: Store, page_size: int, max_pages: int) -> int:
    """Pull alerts newer than the stored cursor (pages are newest-first)."""
    cursor = store.get("api_cursor", "")
    batch: list[dict] = []
    newest = cursor
    for page in range(1, max_pages + 1):
        rows = api.ids_alerts(page=page, rows=page_size)
        if not rows:
            break
        reached_cursor = False
        for row in rows:
            ev = normalize(row)
            if not ev:
                continue
            if cursor and ev["ts"] < cursor:
                reached_cursor = True
                continue
            batch.append(ev)
            newest = max(newest, ev["ts"])
        if reached_cursor or len(rows) < page_size:
            break
    else:
        log.warning("hit max_pages=%d; some older alerts may have been skipped", max_pages)
    added = store.add_events(batch, "api") if batch else 0
    if newest and newest != cursor:
        store.set("api_cursor", newest)
    return added


def import_file(path: str, store: Store) -> int:
    """Import an eve.json (one JSON object per line) or a syslog capture."""
    batch = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = from_syslog_line(line)
            ev = normalize(rec) if rec else None
            if ev:
                batch.append(ev)
    return store.add_events(batch, "file") if batch else 0


class _Buffer:
    """Thread-safe batch writer so the syslog handler doesn't hit SQLite per packet."""

    def __init__(self, store: Store):
        self.store = store
        self.items: list[dict] = []
        self.lock = threading.Lock()

    def add(self, ev: dict) -> None:
        with self.lock:
            self.items.append(ev)

    def flush(self) -> int:
        with self.lock:
            items, self.items = self.items, []
        return self.store.add_events(items, "syslog") if items else 0


def _handle_line(buf: _Buffer, line: str) -> None:
    rec = from_syslog_line(line)
    ev = normalize(rec) if rec else None
    if ev:
        buf.add(ev)


def start_syslog(bind: str, port: int, protocol: str, store: Store) -> tuple[_Buffer, socketserver.BaseServer]:
    """Start a background syslog receiver for OPNsense remote logging (Suricata EVE)."""
    buf = _Buffer(store)

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            _handle_line(buf, self.request[0].decode("utf-8", "replace"))

    class TCPHandler(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:  # newline-framed (OPNsense/syslog-ng default)
                _handle_line(buf, raw.decode("utf-8", "replace"))

    if protocol == "tcp":
        server = socketserver.ThreadingTCPServer((bind, port), TCPHandler)
    else:
        server = socketserver.ThreadingUDPServer((bind, port), UDPHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="syslog", daemon=True).start()
    log.info("syslog receiver listening on %s/%s:%d", protocol, bind, port)
    return buf, server
