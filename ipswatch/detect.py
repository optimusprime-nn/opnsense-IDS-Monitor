"""Detection engine: score IPS events and roll them up into findings.

Two kinds of finding are produced:

* ``inbound``    - keyed on an *external* source attacking internal hosts.
                   "Potential unwanted access" is raised when the traffic was not
                   dropped by the IPS, hit a sensitive service, or the firewall log
                   shows the same source was passed through to internal hosts.
* ``compromise`` - keyed on an *internal* host that is the source of malware / C2 /
                   exploit / lateral-movement alerts (i.e. something already got in).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .config import DetectCfg

# Score -> severity
def severity_for(score: int) -> str:
    if score >= 120:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def direction(ev: dict, cfg: DetectCfg) -> str:
    s, d = cfg.is_internal(ev["src_ip"]), cfg.is_internal(ev["dest_ip"])
    if not s and d:
        return "inbound"
    if s and not d:
        return "outbound"
    if s and d:
        return "lateral"
    return "external"


def _is_compromise_indicator(ev: dict, cfg: DetectCfg) -> bool:
    cat = (ev.get("category") or "").lower()
    sig = (ev.get("signature") or "").lower()
    return (any(c.lower() == cat for c in cfg.compromise_categories)
            or any(k.lower() in sig for k in cfg.compromise_keywords))


def _sev_points(sev: int | None) -> int:
    return {1: 40, 2: 20, 3: 5}.get(sev or 3, 2)


class _Acc:
    def __init__(self, kind: str, ip: str):
        self.kind, self.ip = kind, ip
        self.top_sev = 4                    # most severe Suricata severity seen (1 = highest)
        self.sens_ports: set[int] = set()
        self.indicators: set[str] = set()   # compromise / exploit signatures or categories
        self.reasons: dict[str, int] = {}   # reason -> points (dedupe, keep max)
        self.targets: set[str] = set()
        self.hosts: set[str] = set()
        self.ports: set[int] = set()
        self.sigs: dict[str, int] = defaultdict(int)
        self.count = 0
        self.first = self.last = ""
        self.passed_through = False   # at least one alert not dropped by IPS

    def reason(self, text: str, pts: int) -> None:
        self.reasons[text] = max(pts, self.reasons.get(text, 0))

    def add_event(self, ev: dict, peer_ip: str, peer_port) -> None:
        self.count += 1
        self.first = min(self.first or ev["ts"], ev["ts"])
        self.last = max(self.last, ev["ts"])
        self.targets.add(f"{peer_ip}:{peer_port}" if peer_port else peer_ip)
        self.hosts.add(peer_ip)
        if peer_port:
            self.ports.add(peer_port)
        self.sigs[f'[{ev.get("sid")}] {ev.get("signature")}'] += 1
        self.top_sev = min(self.top_sev, ev.get("severity") or 3)


def analyze(events: list[dict], cfg: DetectCfg, firewall_passes: dict[str, list[dict]] | None = None) -> list[dict]:
    """Return computed findings (not yet merged with the store)."""
    accs: dict[str, _Acc] = {}
    sensitive = set(cfg.sensitive_ports)
    ignore_sids = set(cfg.ignore_sids)

    for ev in events:
        if ev.get("sid") in ignore_sids or cfg.is_ignored_source(ev["src_ip"]):
            continue
        dirn = direction(ev, cfg)
        compromise = _is_compromise_indicator(ev, cfg)
        not_blocked = ev.get("action") not in ("blocked", "drop", "dropped", "rejected")

        if dirn in ("inbound", "external"):
            key = f"inbound:{ev['src_ip']}"
            acc = accs.setdefault(key, _Acc("inbound", ev["src_ip"]))
            acc.add_event(ev, ev["dest_ip"], ev.get("dest_port"))
            if dirn == "inbound" and not_blocked:
                acc.passed_through = True
                acc.reason("alert was NOT dropped by IPS - traffic reached internal host", 30)
            if dirn == "inbound" and ev.get("dest_port") in sensitive:
                acc.sens_ports.add(ev["dest_port"])
            if compromise:
                acc.indicators.add(ev.get("signature") or ev.get("category"))

        else:  # outbound / lateral: an internal host is the *source*
            key = f"compromise:{ev['src_ip']}"
            acc = accs.setdefault(key, _Acc("compromise", ev["src_ip"]))
            acc.add_event(ev, ev["dest_ip"], ev.get("dest_port"))
            if compromise:
                acc.indicators.add(ev.get("signature") or ev.get("category"))
            if dirn == "lateral" and (ev.get("severity") or 3) <= 2:
                acc.reason("possible lateral movement (internal -> internal)", 30)
            if dirn == "outbound" and not_blocked and compromise:
                acc.reason("outbound malicious traffic was NOT dropped", 20)

    findings = []
    for key, acc in accs.items():
        # Each signal type counts once; the details are listed in the reason text.
        who = "" if acc.kind == "inbound" else " from internal host"
        acc.reason(f"highest IPS severity {acc.top_sev}{who}", _sev_points(acc.top_sev))
        if acc.sens_ports:
            acc.reason(f"targeted sensitive service port(s) {', '.join(map(str, sorted(acc.sens_ports)))}", 20)
        if acc.indicators:
            label = "; ".join(sorted(acc.indicators)[:3]) + (" ..." if len(acc.indicators) > 3 else "")
            if acc.kind == "inbound":
                acc.reason(f"exploit/malware signature: {label}", 30)
            else:
                acc.reason(f"internal host triggered compromise indicator: {label}", 60)
        if acc.count >= cfg.repeat_threshold:
            acc.reason(f"{acc.count} alerts in {cfg.window_minutes} min (brute force / flood)", 25)
        if len(acc.hosts) >= cfg.scan_hosts_threshold:
            acc.reason(f"touched {len(acc.hosts)} distinct hosts (sweep)", 25)
        if len(acc.ports) >= cfg.scan_ports_threshold:
            acc.reason(f"touched {len(acc.ports)} distinct ports (port scan)", 25)

        if acc.kind == "inbound" and firewall_passes:
            passes = firewall_passes.get(acc.ip, [])
            if passes:
                dsts = sorted({f'{p.get("dst")}:{p.get("dstport")}' for p in passes})[:10]
                acc.reason(f"firewall PASSED {len(passes)} connection(s) from this source to: {', '.join(dsts)}", 40)
                acc.passed_through = True

        score = sum(acc.reasons.values())
        if score < cfg.flag_score:
            continue
        sev = severity_for(score)
        if acc.kind == "inbound":
            title = (f"Potential unwanted access from {acc.ip}" if acc.passed_through
                     else f"Blocked attack activity from {acc.ip}")
        else:
            title = f"Internal host {acc.ip} shows signs of compromise"
        top_sigs = sorted(acc.sigs.items(), key=lambda kv: kv[1], reverse=True)[:10]
        findings.append({
            "key": key, "kind": acc.kind, "subject_ip": acc.ip,
            "first_seen": acc.first, "last_seen": acc.last,
            "score": score, "severity": sev, "title": title,
            "reasons": [r for r, _ in sorted(acc.reasons.items(), key=lambda kv: kv[1], reverse=True)],
            "targets": sorted(acc.targets)[:50],
            "signatures": [f"{s} (x{n})" for s, n in top_sigs],
            "event_count": acc.count,
        })
    return findings


def window(anchor_iso: str, minutes: int) -> tuple[str, str]:
    end = datetime.fromisoformat(anchor_iso)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    end = end.astimezone(timezone.utc)
    return ((end - timedelta(minutes=minutes)).isoformat(timespec="microseconds"),
            end.isoformat(timespec="microseconds"))


def firewall_passes_by_src(rows: list[dict], cfg: DetectCfg) -> dict[str, list[dict]]:
    """Index OPNsense firewall log rows: external src -> passed packets to internal dst."""
    out: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if str(r.get("action", "")).lower() != "pass":
            continue
        src, dst = r.get("src", ""), r.get("dst", "")
        if src and not cfg.is_internal(src) and cfg.is_internal(dst):
            out[src].append(r)
    return out
