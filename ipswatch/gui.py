"""Windows desktop GUI for ipswatch (Tkinter, stdlib only).

    python -m ipswatch.gui [--config PATH]

Settings and the database live in %APPDATA%\\ipswatch by default. API secrets are
encrypted with Windows DPAPI when saved.
"""
from __future__ import annotations

import argparse
import logging
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__, collect, config, engine, notify, report
from .opnsense import OPNsense, OPNsenseError
from .store import SEV_ORDER, Store

log = logging.getLogger("ipswatch")

APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / "ipswatch"
SEVERITIES = ["low", "medium", "high", "critical"]
SEV_FG = {"critical": "#b42318", "high": "#c4320a", "medium": "#a15c07", "low": "#475467"}
SEV_BG = {"critical": "#fde4e2", "high": "#ffeedd", "medium": "#fff7d6", "low": "#ffffff"}
STATUS_LABEL = {"open": "Open", "ack": "Acknowledged", "false_positive": "False positive"}


def local_time(ts: str | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


# --------------------------------------------------------------------------- background work
class QueueLogHandler(logging.Handler):
    def __init__(self, q: queue.Queue):
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        self.q.put(("log", self.format(record)))


class Monitor(threading.Thread):
    """Poll OPNsense / receive syslog, run detection, report back through a queue."""

    def __init__(self, cfg: config.Config, store: Store, q: queue.Queue):
        super().__init__(name="monitor", daemon=True)
        self.cfg, self.store, self.q = cfg, store, q
        self.stopping = False
        self.wake = threading.Event()

    def stop(self):
        self.stopping = True
        self.wake.set()

    def poll_now(self):
        self.wake.set()

    def run(self):
        cfg = self.cfg
        api = None
        if cfg.opnsense.url:
            try:
                api = OPNsense(cfg.opnsense)
            except OPNsenseError as e:
                log.error("%s", e)
        buf = server = None
        if cfg.syslog.enabled:
            try:
                buf, server = collect.start_syslog(cfg.syslog.bind, cfg.syslog.port, cfg.syslog.protocol, self.store)
            except OSError as e:
                log.error("could not open syslog port %s/%d: %s", cfg.syslog.protocol, cfg.syslog.port, e)
        if not api and not buf:
            log.error("Nothing to collect from - set the OPNsense URL or enable syslog in Settings.")
            self.q.put(("stopped", self))
            return

        log.info("Monitoring started (poll every %ds)", cfg.poll_seconds)
        while not self.stopping:
            error, added = None, 0
            if api:
                try:
                    added = collect.poll_api(api, self.store, cfg.opnsense.page_size, cfg.opnsense.max_pages)
                except OPNsenseError as e:
                    error = str(e)
                    log.error("API poll failed: %s", e)
            if buf:
                added += buf.flush()
            if added:
                log.info("%d new IPS events", added)
            try:
                alerted = engine.run_detection(cfg, self.store, api, anchor=datetime.now(timezone.utc).isoformat())
            except Exception as e:  # never let the loop die silently
                log.exception("detection failed: %s", e)
                alerted = []
            self.q.put(("cycle", {"added": added, "alerted": alerted, "error": error,
                                  "at": datetime.now().strftime("%H:%M:%S")}))
            self.wake.wait(cfg.poll_seconds)
            self.wake.clear()
        if server:
            server.shutdown()
            server.server_close()
        log.info("Monitoring stopped")
        self.q.put(("stopped", self))


def run_bg(q: queue.Queue, kind: str, fn, *args):
    """Run fn(*args) on a worker thread; post (kind, (ok, result)) back to the UI queue."""
    def work():
        try:
            q.put((kind, (True, fn(*args))))
        except Exception as e:
            q.put((kind, (False, e)))
    threading.Thread(target=work, daemon=True).start()


# --------------------------------------------------------------------------- settings form spec
# (section, field, label, kind, help)
FORM = [
    ("OPNsense firewall", [
        ("opnsense", "url", "Firewall URL", "str", "e.g. https://192.168.1.1"),
        ("opnsense", "api_key", "API key", "secret", "System > Access > Users > API keys"),
        ("opnsense", "api_secret", "API secret", "secret", ""),
        ("opnsense", "verify_tls", "Verify TLS certificate", "bool", "Turn off only for a self-signed cert"),
        ("opnsense", "ca_file", "CA certificate file", "file", "Optional: firewall CA (.crt/.pem)"),
        ("", "poll_seconds", "Poll interval (seconds)", "int", ""),
        ("firewall", "correlate", "Correlate with firewall log", "bool", "Flag sources the firewall let through"),
    ]),
    ("Realtime syslog feed (optional)", [
        ("syslog", "enabled", "Enable syslog receiver", "bool", "OPNsense remote logging of Suricata EVE"),
        ("syslog", "port", "Port", "int", "Allow it in Windows Firewall"),
        ("syslog", "protocol", "Protocol", "choice:udp,tcp", ""),
    ]),
    ("Detection", [
        ("detect", "internal_networks", "Internal networks", "list_str", "Comma-separated CIDRs"),
        ("detect", "window_minutes", "Window (minutes)", "int", ""),
        ("detect", "flag_score", "Minimum score to flag", "int", "Medium >= 50, high >= 80, critical >= 120"),
        ("detect", "repeat_threshold", "Brute-force threshold (alerts)", "int", ""),
        ("detect", "scan_hosts_threshold", "Sweep threshold (hosts)", "int", ""),
        ("detect", "scan_ports_threshold", "Port-scan threshold (ports)", "int", ""),
        ("detect", "sensitive_ports", "Sensitive ports", "list_int", ""),
        ("detect", "ignore_sids", "Ignore signature IDs", "list_int", "Reviewed noisy SIDs"),
        ("detect", "ignore_sources", "Trusted sources", "list_str", "CIDRs never flagged (your scanners)"),
        ("detect", "renotify_minutes", "Re-notify after (minutes)", "int", ""),
    ]),
    ("Desktop alerts", [
        ("gui", "desktop_alerts", "Pop-up + sound for new findings", "bool", ""),
        ("gui", "alert_min_severity", "Pop-up minimum severity", "choice:low,medium,high,critical", ""),
        ("gui", "autostart_monitor", "Start monitoring when the app opens", "bool", ""),
        ("gui", "minimize_to_background", "Closing the window minimizes it", "bool", "Keeps monitoring running"),
    ]),
    ("Remote notifications", [
        ("notify", "min_severity", "Minimum severity", "choice:low,medium,high,critical", ""),
        ("notify", "webhook_url", "Webhook URL", "str", "Slack / Discord / generic"),
        ("notify", "webhook_format", "Webhook format", "choice:slack,discord,generic", ""),
        ("notify", "ntfy_url", "ntfy topic URL", "str", "e.g. https://ntfy.sh/my-private-topic"),
        ("notify", "smtp_host", "SMTP server", "str", ""),
        ("notify", "smtp_port", "SMTP port", "int", ""),
        ("notify", "smtp_starttls", "Use STARTTLS", "bool", ""),
        ("notify", "smtp_user", "SMTP user", "str", ""),
        ("notify", "smtp_password", "SMTP password", "secret", ""),
        ("notify", "smtp_from", "From address", "str", ""),
        ("notify", "smtp_to", "To addresses", "list_str", "Comma-separated"),
    ]),
    ("Auto-block (needs alias + WAN block rule on OPNsense)", [
        ("block", "enabled", "Enable auto-block", "bool", ""),
        ("block", "dry_run", "Dry run (log only)", "bool", "Keep on until you trust the findings"),
        ("block", "alias", "Alias name", "str", "Host(s) alias used by a WAN block rule"),
        ("block", "min_severity", "Minimum severity", "choice:low,medium,high,critical", ""),
        ("block", "never_block", "Never block", "list_str", "Your own public IPs / VPN egress"),
    ]),
]


# --------------------------------------------------------------------------- main window
class App(tk.Tk):
    def __init__(self, cfg_path: Path):
        super().__init__()
        self.cfg_path = cfg_path
        self.q: queue.Queue = queue.Queue()
        self.monitor: Monitor | None = None
        self.toasts: list[tk.Toplevel] = []
        self.findings_by_iid: dict[str, dict] = {}

        handler = QueueLogHandler(self.q)
        logging.getLogger("ipswatch").addHandler(handler)
        logging.getLogger("ipswatch").setLevel(logging.INFO)

        self.cfg = self._load_cfg()
        self.store = Store(self._db_path())

        self.title(f"IPS Watch {__version__} - OPNsense intrusion monitor")
        self.k = k = self.winfo_fpixels("1i") / 96  # Windows display scaling (1.0 = 100%)
        w, h = int(1240 * k), int(800 * k)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(w, sw - 40), min(h, sh - 80)
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(0, (sh - h) // 2 - 20)}")
        self.minsize(int(900 * k), int(560 * k))
        self._icon()
        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh_all()
        self.after(150, self._pump)
        self.after(30_000, self._periodic_refresh)
        if self.cfg.gui.autostart_monitor:
            self.after(500, self.start_monitor)
        elif not self.cfg.opnsense.url and not self.cfg.syslog.enabled:
            self.nb.select(self.tab_settings)
            self.status_var.set("Welcome - enter your OPNsense details in Settings to get started.")

    # ---- config / paths
    def _load_cfg(self) -> config.Config:
        if self.cfg_path.exists():
            try:
                return config.load(self.cfg_path)
            except Exception as e:
                messagebox.showerror("IPS Watch", f"Could not read {self.cfg_path}:\n{e}\n\nUsing defaults.")
        cfg = config.load(None)
        cfg.db_path = "ipswatch.db"
        return cfg

    def _db_path(self) -> str:
        p = Path(self.cfg.db_path)
        return str(p if p.is_absolute() else self.cfg_path.parent / p)

    def _icon(self):
        # Draw a small shield so we don't need an .ico file.
        img = tk.PhotoImage(width=32, height=32)
        for y in range(2, 31):
            half = 13 if y < 17 else 13 - (y - 17) * 13 // 14
            if half > 0:
                img.put("#1f6feb", to=(16 - half, y, 16 + half, y + 1))
        img.put("#ffffff", to=(14, 7, 18, 23))
        img.put("#ffffff", to=(9, 12, 23, 16))
        self._icon_img = img
        self.iconphoto(True, img)

    def _style(self):
        s = ttk.Style(self)
        if "vista" in s.theme_names():
            s.theme_use("vista")
        s.configure("Treeview", rowheight=int(24 * self.k))
        s.configure("Card.TFrame", relief="solid", borderwidth=1)
        s.configure("Big.TLabel", font=("Segoe UI", 20, "bold"))
        s.configure("Small.TLabel", foreground="#667085")
        s.configure("Hdr.TLabel", font=("Segoe UI", 10, "bold"))

    # ---- layout
    def _build(self):
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")
        self.btn_start = ttk.Button(bar, text="Start monitoring", command=self.toggle_monitor)
        self.btn_start.pack(side="left")
        ttk.Button(bar, text="Poll now", command=self.poll_now).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(bar, text="Import eve.json...", command=self.import_file).pack(side="left")
        ttk.Button(bar, text="Export report...", command=self.export_report).pack(side="left", padx=4)
        self.state_lbl = ttk.Label(bar, text="  Stopped", foreground="#667085", font=("Segoe UI", 10, "bold"))
        self.state_lbl.pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8)
        self.tab_findings = ttk.Frame(self.nb, padding=6)
        self.tab_events = ttk.Frame(self.nb, padding=6)
        self.tab_log = ttk.Frame(self.nb, padding=6)
        self.tab_settings = ttk.Frame(self.nb)
        self.nb.add(self.tab_findings, text="  Findings  ")
        self.nb.add(self.tab_events, text="  IPS events  ")
        self.nb.add(self.tab_log, text="  Activity log  ")
        self.nb.add(self.tab_settings, text="  Settings  ")
        self._build_findings()
        self._build_events()
        self._build_log()
        self._build_settings()

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(10, 4), style="Small.TLabel").pack(fill="x")

    def _build_findings(self):
        t = self.tab_findings
        cards = ttk.Frame(t)
        cards.pack(fill="x", pady=(0, 6))
        self.count_lbls = {}
        for sev in reversed(SEVERITIES):
            c = ttk.Frame(cards, style="Card.TFrame", padding=(14, 6))
            c.pack(side="left", padx=(0, 8))
            lbl = ttk.Label(c, text="0", style="Big.TLabel", foreground=SEV_FG[sev])
            lbl.pack(anchor="w")
            ttk.Label(c, text=f"open {sev}", style="Small.TLabel").pack(anchor="w")
            self.count_lbls[sev] = lbl
        c = ttk.Frame(cards, style="Card.TFrame", padding=(14, 6))
        c.pack(side="left")
        self.events24_lbl = ttk.Label(c, text="0", style="Big.TLabel")
        self.events24_lbl.pack(anchor="w")
        ttk.Label(c, text="IPS events, last 24h", style="Small.TLabel").pack(anchor="w")

        flt = ttk.Frame(t)
        flt.pack(fill="x", pady=(0, 4))
        ttk.Label(flt, text="Show").pack(side="left")
        self.f_status = ttk.Combobox(flt, state="readonly", width=16,
                                     values=["Open", "All", "Acknowledged", "False positive"])
        self.f_status.set("Open")
        self.f_status.pack(side="left", padx=4)
        ttk.Label(flt, text="Min severity").pack(side="left", padx=(8, 0))
        self.f_sev = ttk.Combobox(flt, state="readonly", width=10, values=SEVERITIES)
        self.f_sev.set("low")
        self.f_sev.pack(side="left", padx=4)
        ttk.Label(flt, text="Search").pack(side="left", padx=(8, 0))
        self.f_search = tk.StringVar()
        ttk.Entry(flt, textvariable=self.f_search, width=24).pack(side="left", padx=4)
        for w in (self.f_status, self.f_sev):
            w.bind("<<ComboboxSelected>>", lambda e: self.refresh_findings())
        self.f_search.trace_add("write", lambda *a: self.refresh_findings())

        acts = ttk.Frame(flt)
        acts.pack(side="right")
        self.btn_ack = ttk.Button(acts, text="Acknowledge", command=lambda: self.set_status("ack"))
        self.btn_fp = ttk.Button(acts, text="False positive", command=lambda: self.set_status("false_positive"))
        self.btn_reopen = ttk.Button(acts, text="Reopen", command=lambda: self.set_status("open"))
        self.btn_block = ttk.Button(acts, text="Block IP...", command=self.block_selected)
        self.btn_unblock = ttk.Button(acts, text="Unblock IP...", command=self.unblock_selected)
        self.btn_events = ttk.Button(acts, text="Show events", command=self.show_events_for_selected)
        for b in (self.btn_ack, self.btn_fp, self.btn_reopen, self.btn_block, self.btn_unblock, self.btn_events):
            b.pack(side="left", padx=2)

        pane = ttk.PanedWindow(t, orient="vertical")
        pane.pack(fill="both", expand=True)
        top = ttk.Frame(pane)
        cols = ("severity", "score", "title", "ip", "events", "last", "status")
        self.ftree = ttk.Treeview(top, columns=cols, show="headings", selectmode="browse")
        for col, text, w, anchor in [("severity", "Severity", 80, "w"), ("score", "Score", 55, "e"),
                                     ("title", "Finding", 420, "w"), ("ip", "IP", 130, "w"),
                                     ("events", "Events", 60, "e"), ("last", "Last seen", 145, "w"),
                                     ("status", "Status", 110, "w")]:
            self.ftree.heading(col, text=text)
            self.ftree.column(col, width=int(w * self.k), anchor=anchor, stretch=(col == "title"))
        for sev in SEVERITIES:
            self.ftree.tag_configure(sev, background=SEV_BG[sev])
        self.ftree.tag_configure("muted", foreground="#98a2b3")
        sb = ttk.Scrollbar(top, orient="vertical", command=self.ftree.yview)
        self.ftree.configure(yscrollcommand=sb.set)
        self.ftree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.ftree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        self.ftree.bind("<Double-1>", lambda e: self.show_events_for_selected())
        self._tree_menu(self.ftree, lambda: self._selected() and self._selected()["subject_ip"])
        pane.add(top, weight=3)

        self.detail = ScrolledText(pane, height=12, wrap="word", font=("Segoe UI", 10), padx=10, pady=8,
                              relief="flat", background="#f8f9fb", state="disabled")
        self.detail.tag_configure("h", font=("Segoe UI", 12, "bold"))
        self.detail.tag_configure("b", font=("Segoe UI", 10, "bold"))
        self.detail.tag_configure("m", foreground="#667085")
        for sev in SEVERITIES:
            self.detail.tag_configure(sev, foreground=SEV_FG[sev], font=("Segoe UI", 10, "bold"))
        pane.add(self.detail.frame, weight=2)
        self._update_action_buttons()

    def _build_events(self):
        t = self.tab_events
        top = ttk.Frame(t)
        top.pack(fill="x", pady=(0, 4))
        ttk.Label(top, text="Search (IP, signature, SID)").pack(side="left")
        self.e_search = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.e_search, width=36)
        ent.pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: self.refresh_events())
        ttk.Button(top, text="Search", command=self.refresh_events).pack(side="left")
        ttk.Button(top, text="Clear", command=lambda: (self.e_search.set(""), self.refresh_events())).pack(side="left", padx=4)
        self.e_count = ttk.Label(top, style="Small.TLabel")
        self.e_count.pack(side="right")

        frm = ttk.Frame(t)
        frm.pack(fill="both", expand=True)
        cols = ("time", "src", "dst", "proto", "sid", "sig", "cat", "sev", "action")
        self.etree = ttk.Treeview(frm, columns=cols, show="headings")
        for col, text, w in [("time", "Time", 145), ("src", "Source", 150), ("dst", "Destination", 160),
                             ("proto", "Proto", 55), ("sid", "SID", 80), ("sig", "Signature", 380),
                             ("cat", "Category", 220), ("sev", "Sev", 40), ("action", "Action", 70)]:
            self.etree.heading(col, text=text)
            self.etree.column(col, width=int(w * self.k), stretch=(col in ("sig", "cat")))
        self.etree.tag_configure("passed", foreground="#b42318")
        sb = ttk.Scrollbar(frm, orient="vertical", command=self.etree.yview)
        self.etree.configure(yscrollcommand=sb.set)
        self.etree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.events_by_iid: dict[str, dict] = {}
        self._tree_menu(self.etree, lambda: (self.events_by_iid.get(self.etree.focus()) or {}).get("src_ip"))
        ttk.Label(t, text="Red rows: the IPS did not drop the traffic.", style="Small.TLabel").pack(anchor="w", pady=(4, 0))

    def _build_log(self):
        self.logbox = ScrolledText(self.tab_log, font=("Consolas", 9), state="disabled", wrap="none")
        self.logbox.pack(fill="both", expand=True)
        self.logbox.tag_configure("ERROR", foreground="#b42318")
        self.logbox.tag_configure("WARNING", foreground="#a15c07")

    def _build_settings(self):
        outer = self.tab_settings
        canvas = tk.Canvas(outer, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=14)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>",
                    lambda ev: canvas.yview_scroll(int(-ev.delta / 120), "units")))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        self.form_vars: dict[tuple[str, str], tuple[str, tk.Variable]] = {}
        row = 0
        for title, fields in FORM:
            ttk.Label(inner, text=title, style="Hdr.TLabel").grid(row=row, column=0, columnspan=3, sticky="w", pady=(14, 4))
            row += 1
            for sec, name, label, kind, help_ in fields:
                ttk.Label(inner, text=label).grid(row=row, column=0, sticky="w", padx=(10, 12), pady=2)
                if kind == "bool":
                    var = tk.BooleanVar()
                    ttk.Checkbutton(inner, variable=var).grid(row=row, column=1, sticky="w")
                elif kind.startswith("choice:"):
                    var = tk.StringVar()
                    ttk.Combobox(inner, textvariable=var, state="readonly", width=14,
                                 values=kind.split(":", 1)[1].split(",")).grid(row=row, column=1, sticky="w")
                else:
                    var = tk.StringVar()
                    cell = ttk.Frame(inner)
                    cell.grid(row=row, column=1, sticky="we")
                    e = ttk.Entry(cell, textvariable=var, width=12 if kind == "int" else 46,
                                  show="•" if kind == "secret" else "")
                    e.pack(side="left", fill="x", expand=(kind != "int"))
                    if kind == "file":
                        ttk.Button(cell, text="...", width=3, command=lambda v=var: v.set(
                            filedialog.askopenfilename(filetypes=[("Certificates", "*.crt *.pem *.cer"), ("All", "*.*")])
                            or v.get())).pack(side="left", padx=2)
                ttk.Label(inner, text=help_, style="Small.TLabel").grid(row=row, column=2, sticky="w", padx=8)
                self.form_vars[(sec, name)] = (kind, var)
                row += 1
        inner.columnconfigure(1, weight=1)

        btns = ttk.Frame(inner)
        btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=(18, 4))
        ttk.Button(btns, text="Save settings", command=self.save_settings).pack(side="left")
        ttk.Button(btns, text="Test firewall connection", command=self.test_connection).pack(side="left", padx=6)
        ttk.Button(btns, text="Send test notification", command=self.test_notification).pack(side="left")
        ttk.Button(btns, text="Revert", command=self.load_form).pack(side="left", padx=6)
        row += 1
        info = ttk.Frame(inner)
        info.grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(info, text=f"Settings: {self.cfg_path}    Database: {self._db_path()}",
                  style="Small.TLabel").pack(side="left")
        ttk.Button(info, text="Open folder", command=lambda: os.startfile(self.cfg_path.parent)
                   if hasattr(os, "startfile") else None).pack(side="left", padx=8)
        ttk.Label(inner, text="API key/secret and SMTP password are encrypted with Windows DPAPI "
                  "(readable only by your Windows account).", style="Small.TLabel"
                  ).grid(row=row + 1, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self.load_form()

    def _tree_menu(self, tree: ttk.Treeview, get_ip):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy IP", command=lambda: self._copy(get_ip()))
        menu.add_command(label="Look up IP (AbuseIPDB)", command=lambda: get_ip() and webbrowser.open(
            f"https://www.abuseipdb.com/check/{get_ip()}"))

        def popup(e):
            iid = tree.identify_row(e.y)
            if iid:
                tree.selection_set(iid)
                tree.focus(iid)
                menu.tk_popup(e.x_root, e.y_root)
        tree.bind("<Button-3>", popup)

    def _copy(self, text):
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_var.set(f"Copied {text}")

    # ---- settings
    def load_form(self):
        data = config.to_dict(self.cfg)
        for (sec, name), (kind, var) in self.form_vars.items():
            v = data[sec][name] if sec else data[name]
            if kind in ("list_str", "list_int"):
                var.set(", ".join(map(str, v)))
            else:
                var.set(v)

    def form_config(self) -> config.Config:
        data = config.to_dict(self.cfg)
        for (sec, name), (kind, var) in self.form_vars.items():
            v = var.get()
            try:
                if kind == "int":
                    v = int(str(v).strip())
                elif kind == "list_str":
                    v = [x.strip() for x in str(v).replace("\n", ",").split(",") if x.strip()]
                elif kind == "list_int":
                    v = [int(x) for x in str(v).replace(" ", "").split(",") if x]
                elif kind in ("str", "secret", "file"):
                    v = str(v).strip()
            except ValueError:
                label = next(lbl for _, fs in FORM for s, n, lbl, *_ in fs if (s, n) == (sec, name))
                raise ValueError(f"'{label}' must be a number (or comma-separated numbers)")
            if sec:
                data[sec][name] = v
            else:
                data[name] = v
        if data["poll_seconds"] < 10:
            raise ValueError("Poll interval must be at least 10 seconds")
        return config.from_dict(data)  # validates CIDRs

    def save_settings(self):
        try:
            cfg = self.form_config()
            config.save(cfg, self.cfg_path)
        except Exception as e:
            messagebox.showerror("Settings", f"Not saved:\n{e}")
            return
        self.cfg = cfg
        self.status_var.set(f"Settings saved to {self.cfg_path}")
        log.info("Settings saved")
        if self.monitor:
            self.stop_monitor()
            self.after(800, self.start_monitor)
            log.info("Restarting monitoring with new settings")

    def test_connection(self):
        try:
            cfg = self.form_config()
        except Exception as e:
            messagebox.showerror("Test connection", str(e))
            return

        def check():
            api = OPNsense(cfg.opnsense)
            lines = [f"IDS service: {api.ids_status()}"]
            lines.append(f"Alert log: OK ({len(api.ids_alerts(rows=5))} sample rows)")
            if cfg.firewall.correlate:
                lines.append(f"Firewall log: OK ({len(api.firewall_log(10))} rows)")
            if cfg.block.enabled:
                lines.append(f"Alias '{cfg.block.alias}': {len(api.alias_list(cfg.block.alias))} entries")
            return "\n".join(lines)
        self.status_var.set("Testing connection...")
        run_bg(self.q, "test_conn", check)

    def test_notification(self):
        try:
            cfg = self.form_config()
        except Exception as e:
            messagebox.showerror("Test notification", str(e))
            return
        sample = {"key": "test:0.0.0.0", "kind": "inbound", "subject_ip": "203.0.113.1", "event_count": 1,
                  "first_seen": datetime.now(timezone.utc).isoformat(), "last_seen": datetime.now(timezone.utc).isoformat(),
                  "score": 0, "severity": "low", "title": "IPS Watch test notification",
                  "reasons": ["This is a test - your notification channel works."], "targets": [], "signatures": []}
        run_bg(self.q, "test_notify", notify.send, sample, cfg.notify)
        self.show_toast(sample)

    # ---- monitoring
    def toggle_monitor(self):
        self.stop_monitor() if self.monitor else self.start_monitor()

    def start_monitor(self):
        if self.monitor:
            return
        self.monitor = Monitor(self.cfg, self.store, self.q)
        self.monitor.start()
        self.btn_start.configure(text="Stop monitoring")
        self.state_lbl.configure(text="● Monitoring", foreground="#067647")

    def stop_monitor(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        self.btn_start.configure(text="Start monitoring")
        self.state_lbl.configure(text="  Stopped", foreground="#667085")

    def poll_now(self):
        if self.monitor:
            self.monitor.poll_now()
            self.status_var.set("Polling...")
        else:
            self.start_monitor()

    # ---- actions
    def import_file(self):
        path = filedialog.askopenfilename(title="Import Suricata eve.json",
                                          filetypes=[("EVE JSON / logs", "*.json *.log *.txt"), ("All files", "*.*")])
        if not path:
            return
        self.status_var.set(f"Importing {path}...")

        def work():
            n = collect.import_file(path, self.store)
            engine.replay(self.cfg, self.store, do_notify=False)
            return n, path
        run_bg(self.q, "imported", work)

    def export_report(self):
        path = filedialog.asksaveasfilename(title="Export HTML report", defaultextension=".html",
                                            initialfile=f"ipswatch-report-{datetime.now():%Y%m%d}.html",
                                            filetypes=[("HTML", "*.html")])
        if path:
            n = report.write_html(self.store, path)
            self.status_var.set(f"Report with {n} findings written to {path}")
            webbrowser.open(Path(path).as_uri())

    def _selected(self) -> dict | None:
        sel = self.ftree.selection()
        return self.findings_by_iid.get(sel[0]) if sel else None

    def set_status(self, status: str):
        f = self._selected()
        if f:
            self.store.mark(f["key"], status=status)
            self.refresh_findings(keep=f["key"])

    def _block_target(self) -> tuple[dict, OPNsense] | None:
        f = self._selected()
        if not f:
            return None
        if not self.cfg.opnsense.url:
            messagebox.showinfo("Block", "Configure the OPNsense connection in Settings first.")
            return None
        if self.cfg.detect.is_internal(f["subject_ip"]):
            messagebox.showwarning("Block", f"{f['subject_ip']} is an internal address - isolate the host "
                                   "instead of blocking it at the WAN.")
            return None
        return f, OPNsense(self.cfg.opnsense)

    def block_selected(self):
        t = self._block_target()
        if not t:
            return
        f, api = t
        if messagebox.askyesno("Block IP", f"Add {f['subject_ip']} to firewall alias '{self.cfg.block.alias}'?\n\n"
                               "This only blocks traffic if a WAN rule uses that alias."):
            run_bg(self.q, "blocked", lambda: (api.alias_add(self.cfg.block.alias, f["subject_ip"]), f["key"],
                                               f["subject_ip"]))

    def unblock_selected(self):
        t = self._block_target()
        if not t:
            return
        f, api = t
        if messagebox.askyesno("Unblock IP", f"Remove {f['subject_ip']} from alias '{self.cfg.block.alias}'?"):
            run_bg(self.q, "unblocked", lambda: (api.alias_delete(self.cfg.block.alias, f["subject_ip"]), f["key"],
                                                 f["subject_ip"]))

    def show_events_for_selected(self):
        f = self._selected()
        if f:
            self.e_search.set(f["subject_ip"])
            self.refresh_events()
            self.nb.select(self.tab_events)

    # ---- refresh
    def refresh_all(self):
        self.refresh_findings()
        self.refresh_events()

    def _periodic_refresh(self):
        self.refresh_counts()
        self.after(30_000, self._periodic_refresh)

    def refresh_counts(self):
        open_rows = self.store.list_findings("open", "low", 1000)
        for sev, lbl in self.count_lbls.items():
            lbl.configure(text=str(sum(1 for f in open_rows if f["severity"] == sev)))
        since = datetime.fromtimestamp(datetime.now().timestamp() - 86400, timezone.utc).isoformat()
        self.events24_lbl.configure(text=str(self.store.event_count(since)))

    def refresh_findings(self, keep: str | None = None):
        keep = keep or (self._selected() or {}).get("key")
        status = {"Open": "open", "All": None, "Acknowledged": "ack", "False positive": "false_positive"}[self.f_status.get()]
        rows = self.store.list_findings(status, self.f_sev.get(), 500)
        needle = self.f_search.get().strip().lower()
        if needle:
            rows = [f for f in rows if needle in f["subject_ip"].lower() or needle in f["title"].lower()
                    or any(needle in s.lower() for s in f["signatures"])]
        self.ftree.delete(*self.ftree.get_children())
        self.findings_by_iid.clear()
        for i, f in enumerate(rows):
            iid = f"f{i}"
            tags = (f["severity"],) if f["status"] == "open" else ("muted",)
            title = f["title"] + ("   [blocked]" if f.get("blocked_at") else "")
            self.ftree.insert("", "end", iid=iid, tags=tags, values=(
                f["severity"].upper(), f["score"], title, f["subject_ip"], f["event_count"],
                local_time(f["last_seen"]), STATUS_LABEL.get(f["status"], f["status"])))
            self.findings_by_iid[iid] = f
            if f["key"] == keep:
                self.ftree.selection_set(iid)
                self.ftree.see(iid)
        if not self.ftree.selection():
            self.show_detail()
        self.refresh_counts()

    def show_detail(self):
        f = self._selected()
        d = self.detail
        d.configure(state="normal")
        d.delete("1.0", "end")
        if not f:
            d.insert("end", "Select a finding to see why it was flagged.", "m")
        else:
            d.insert("end", f["severity"].upper() + "  ", f["severity"])
            d.insert("end", f["title"] + "\n", "h")
            d.insert("end", f"score {f['score']}  ·  {f['event_count']} events  ·  first "
                     f"{local_time(f['first_seen'])}  ·  last {local_time(f['last_seen'])}  ·  "
                     f"{STATUS_LABEL.get(f['status'])}" + (f"  ·  blocked {local_time(f['blocked_at'])}"
                                                           if f.get("blocked_at") else "") + "\n\n", "m")
            d.insert("end", "Why it was flagged\n", "b")
            for r in f["reasons"]:
                d.insert("end", f"  • {r}\n")
            d.insert("end", "\nTargets\n", "b")
            d.insert("end", "  " + ", ".join(f["targets"][:40]) + "\n")
            d.insert("end", "\nSignatures\n", "b")
            for s in f["signatures"]:
                d.insert("end", f"  • {s}\n")
            if f["kind"] == "compromise":
                d.insert("end", "\nSuggested action: ", "b")
                d.insert("end", "isolate this internal host and check it for malware.\n")
            elif "unwanted access" in f["title"]:
                d.insert("end", "\nSuggested action: ", "b")
                d.insert("end", "check logs on the targeted hosts for successful logins, close the exposed port "
                                "or set the IPS rule to Drop, and consider blocking the source.\n")
        d.configure(state="disabled")
        self._update_action_buttons()

    def _update_action_buttons(self):
        f = self._selected()
        state = "normal" if f else "disabled"
        for b in (self.btn_ack, self.btn_fp, self.btn_reopen, self.btn_events):
            b.configure(state=state)
        ext = f is not None and f["kind"] == "inbound"
        for b in (self.btn_block, self.btn_unblock):
            b.configure(state="normal" if ext else "disabled")

    def refresh_events(self):
        rows = self.store.recent_events(2000, self.e_search.get().strip())
        self.etree.delete(*self.etree.get_children())
        self.events_by_iid.clear()
        for i, e in enumerate(rows):
            passed = e["action"] not in ("blocked", "drop", "dropped", "rejected")
            self.events_by_iid[f"e{i}"] = e
            self.etree.insert("", "end", iid=f"e{i}", tags=("passed",) if passed else (), values=(
                local_time(e["ts"]), f"{e['src_ip']}:{e['src_port'] or ''}".rstrip(":"),
                f"{e['dest_ip']}:{e['dest_port'] or ''}".rstrip(":"), e["proto"], e["sid"], e["signature"],
                e["category"], e["severity"], e["action"]))
        self.e_count.configure(text=f"{len(rows)} events shown" + (" (max 2000)" if len(rows) == 2000 else ""))

    # ---- queue pump (UI thread)
    def _pump(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                self._handle(kind, data)
        except queue.Empty:
            pass
        self.after(150, self._pump)

    def _handle(self, kind, data):
        if kind == "log":
            self.logbox.configure(state="normal")
            level = "ERROR" if " ERROR " in data else "WARNING" if " WARNING " in data else ""
            self.logbox.insert("end", data + "\n", level)
            lines = int(self.logbox.index("end-1c").split(".")[0])
            if lines > 5000:
                self.logbox.delete("1.0", f"{lines - 5000}.0")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        elif kind == "cycle":
            msg = f"Last poll {data['at']}: {data['added']} new events"
            if data["error"]:
                msg += f"  —  ERROR: {data['error']}"
                self.state_lbl.configure(text="● Monitoring (errors)", foreground="#b42318")
            elif self.monitor:
                self.state_lbl.configure(text="● Monitoring", foreground="#067647")
            self.status_var.set(msg)
            if data["added"] or data["alerted"]:
                self.refresh_all()
            for f in data["alerted"]:
                if self.cfg.gui.desktop_alerts and SEV_ORDER[f["severity"]] >= SEV_ORDER[self.cfg.gui.alert_min_severity]:
                    self.show_toast(f)
        elif kind == "stopped":
            if self.monitor is data:  # monitor ended on its own (e.g. nothing configured)
                self.stop_monitor()
        elif kind == "imported":
            ok, res = data
            if ok:
                self.status_var.set(f"Imported {res[0]} new events from {res[1]}")
                self.refresh_all()
            else:
                messagebox.showerror("Import", f"Import failed:\n{res}")
        elif kind == "test_conn":
            ok, res = data
            self.status_var.set("Connection OK" if ok else "Connection failed")
            (messagebox.showinfo if ok else messagebox.showerror)("Test connection", str(res))
        elif kind == "test_notify":
            ok, res = data
            if not ok or not res:
                messagebox.showerror("Test notification", "A remote channel failed - see the Activity log.")
            else:
                self.status_var.set("Test notification sent")
        elif kind in ("blocked", "unblocked"):
            ok, res = data
            if not ok:
                messagebox.showerror("Firewall", f"Failed:\n{res}")
                return
            _, key, ip = res
            if kind == "blocked":
                self.store.mark(key, blocked_at=datetime.now(timezone.utc).isoformat())
            else:
                self.store.mark(key, blocked_at=None)
            log.warning("%s %s via alias %s", kind.capitalize(), ip, self.cfg.block.alias)
            self.refresh_findings(keep=key)

    # ---- desktop pop-up
    def show_toast(self, f: dict):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass
        w = tk.Toplevel(self)
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.configure(background=SEV_FG[f["severity"]])
        body = tk.Frame(w, background="#ffffff", padx=12, pady=10)
        body.pack(fill="both", expand=True, padx=(6, 1), pady=1)
        tk.Label(body, text=f"{f['severity'].upper()}  ·  IPS Watch", fg=SEV_FG[f["severity"]], bg="#ffffff",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(body, text=f["title"], bg="#ffffff", font=("Segoe UI", 11, "bold"), wraplength=int(330 * self.k),
                 justify="left").pack(anchor="w")
        tk.Label(body, text=(f["reasons"] or [""])[0], bg="#ffffff", fg="#475467", wraplength=int(330 * self.k),
                 justify="left").pack(anchor="w", pady=(2, 0))
        width, height = int(380 * self.k), int(120 * self.k)
        idx = len(self.toasts)
        x = self.winfo_screenwidth() - width - 16
        y = self.winfo_screenheight() - (height + 12) * (idx + 1) - 48
        w.geometry(f"{width}x{height}+{x}+{y}")
        self.toasts.append(w)

        def close(_=None):
            if w in self.toasts:
                self.toasts.remove(w)
            w.destroy()

        def open_(_=None):
            close()
            self.deiconify()
            self.lift()
            self.focus_force()
            self.nb.select(self.tab_findings)
            self.f_status.set("All")
            self.refresh_findings(keep=f["key"])
        for widget in [w, body, *body.winfo_children()]:
            widget.bind("<Button-1>", open_)
            widget.bind("<Button-3>", close)
        w.after(15_000, close)

    def on_close(self):
        if self.monitor:
            if self.cfg.gui.minimize_to_background:
                self.iconify()
                return
            if not messagebox.askyesno("IPS Watch", "Monitoring is running. Stop monitoring and exit?"):
                return
            self.stop_monitor()
        self.destroy()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ipswatch-gui")
    p.add_argument("-c", "--config", help=f"config file (default {APP_DIR / 'config.toml'})")
    args = p.parse_args(argv)
    if sys.platform == "win32":
        try:  # crisp text on high-DPI displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ipswatch.gui")
        except Exception:
            pass
    cfg_path = Path(args.config) if args.config else APP_DIR / "config.toml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    App(cfg_path.resolve()).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
