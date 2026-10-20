"""Configuration loading (TOML) with defaults."""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import winsecret

DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]

# Ports that should almost never be reached from the internet.
DEFAULT_SENSITIVE_PORTS = [22, 23, 445, 135, 139, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8443, 9200, 27017]

# Suricata/ET classtypes that indicate an attack succeeded or a host is compromised.
DEFAULT_COMPROMISE_CATEGORIES = [
    "A Network Trojan was detected",
    "Successful Administrator Privilege Gain",
    "Successful User Privilege Gain",
    "Attempted Administrator Privilege Gain",
    "Executable code was detected",
    "Malware Command and Control Activity Detected",
    "Information Leak",
    "Large Scale Information Leak",
    "Exploit Kit Activity Detected",
    "Domain Observed Used for C2 Detected",
]

DEFAULT_COMPROMISE_KEYWORDS = [
    "ET TROJAN", "ET MALWARE", "ET CNC", "ET EXPLOIT", "ET WEB_SERVER WebShell",
    "C2", "Cobalt Strike", "Metasploit", "Meterpreter", "Reverse Shell", "Mimikatz",
    "ET POLICY PE EXE", "ET ATTACK_RESPONSE",
]


@dataclass
class OPNsenseCfg:
    url: str = ""
    api_key: str = ""
    api_secret: str = ""
    verify_tls: bool = True
    ca_file: str = ""
    page_size: int = 500
    max_pages: int = 20


@dataclass
class SyslogCfg:
    enabled: bool = False
    bind: str = "0.0.0.0"
    port: int = 5514
    protocol: str = "udp"  # udp | tcp


@dataclass
class DetectCfg:
    internal_networks: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL))
    sensitive_ports: list[int] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_PORTS))
    compromise_categories: list[str] = field(default_factory=lambda: list(DEFAULT_COMPROMISE_CATEGORIES))
    compromise_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_COMPROMISE_KEYWORDS))
    window_minutes: int = 15
    repeat_threshold: int = 20          # alerts from one source in window
    scan_hosts_threshold: int = 10      # distinct internal hosts touched by one source in window
    scan_ports_threshold: int = 15      # distinct internal ports touched by one source in window
    flag_score: int = 50                # score at or above this becomes a finding
    ignore_sids: list[int] = field(default_factory=list)
    ignore_sources: list[str] = field(default_factory=list)  # CIDRs (scanners you trust, etc.)
    renotify_minutes: int = 360         # suppress repeat notifications for the same finding key

    def __post_init__(self) -> None:
        self._internal = [ipaddress.ip_network(n, strict=False) for n in self.internal_networks]
        self._ignore_src = [ipaddress.ip_network(n, strict=False) for n in self.ignore_sources]

    def is_internal(self, ip: str) -> bool:
        return _in_nets(ip, self._internal)

    def is_ignored_source(self, ip: str) -> bool:
        return _in_nets(ip, self._ignore_src)


@dataclass
class FirewallCfg:
    correlate: bool = True       # look up passed firewall traffic from flagged sources
    log_limit: int = 2000


@dataclass
class NotifyCfg:
    min_severity: str = "medium"  # low | medium | high | critical
    webhook_url: str = ""         # Slack/Discord/Mattermost/generic JSON
    webhook_format: str = "slack"  # slack | discord | generic
    ntfy_url: str = ""            # e.g. https://ntfy.sh/my-topic
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)


@dataclass
class BlockCfg:
    enabled: bool = False
    dry_run: bool = True
    alias: str = "ipswatch_block"   # host alias referenced by a WAN block rule
    min_severity: str = "critical"
    never_block: list[str] = field(default_factory=list)


@dataclass
class GuiCfg:
    autostart_monitor: bool = False   # start monitoring when the window opens
    desktop_alerts: bool = True       # pop-up + sound for new findings
    alert_min_severity: str = "high"
    minimize_to_background: bool = False  # closing the window keeps monitoring (restore via taskbar)


@dataclass
class Config:
    db_path: str = "ipswatch.db"
    poll_seconds: int = 60
    opnsense: OPNsenseCfg = field(default_factory=OPNsenseCfg)
    syslog: SyslogCfg = field(default_factory=SyslogCfg)
    detect: DetectCfg = field(default_factory=DetectCfg)
    firewall: FirewallCfg = field(default_factory=FirewallCfg)
    notify: NotifyCfg = field(default_factory=NotifyCfg)
    block: BlockCfg = field(default_factory=BlockCfg)
    gui: GuiCfg = field(default_factory=GuiCfg)


SECTIONS = {
    "opnsense": OPNsenseCfg, "syslog": SyslogCfg, "detect": DetectCfg,
    "firewall": FirewallCfg, "notify": NotifyCfg, "block": BlockCfg, "gui": GuiCfg,
}
# Fields encrypted with DPAPI when saved from the GUI on Windows.
SECRET_FIELDS = {("opnsense", "api_key"), ("opnsense", "api_secret"), ("notify", "smtp_password")}


def _in_nets(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def from_dict(raw: dict) -> Config:
    kwargs = {k: v for k, v in raw.items() if k not in SECTIONS}
    for name, cls in SECTIONS.items():
        sec = dict(raw.get(name, {}))
        for s, f in SECRET_FIELDS:
            if s == name and isinstance(sec.get(f), str):
                sec[f] = winsecret.unprotect(sec[f])
        kwargs[name] = cls(**sec)
    return Config(**kwargs)


def to_dict(cfg: Config) -> dict:
    return {f.name: (dataclasses.asdict(getattr(cfg, f.name)) if f.name in SECTIONS else getattr(cfg, f.name))
            for f in dataclasses.fields(cfg)}


def load(path: str | Path | None) -> Config:
    raw: dict = {}
    if path:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    return from_dict(raw)


def save(cfg: Config, path: str | Path, protect_secrets: bool = True) -> None:
    """Write the config as TOML. Secrets are DPAPI-encrypted on Windows."""
    data = to_dict(cfg)
    if protect_secrets:
        for s, f in SECRET_FIELDS:
            data[s][f] = winsecret.protect(data[s][f])
    lines = ["# ipswatch configuration (written by ipswatch)"]
    lines += [f"{k} = {_toml(v)}" for k, v in data.items() if k not in SECTIONS]
    for name in SECTIONS:
        lines.append(f"\n[{name}]")
        lines += [f"{k} = {_toml(v)}" for k, v in data[name].items()]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _toml(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml(x) for x in v) + "]"
    return json.dumps(str(v))  # JSON string escaping is valid TOML basic-string escaping
