"""Notification channels: console log, webhook (Slack/Discord/generic), ntfy, SMTP email."""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from .config import NotifyCfg

log = logging.getLogger("ipswatch.notify")

ICON = {"low": "[low]", "medium": "[MEDIUM]", "high": "[HIGH]", "critical": "[CRITICAL]"}


def render(f: dict) -> tuple[str, str]:
    subject = f"{ICON[f['severity']]} {f['title']} (score {f['score']})"
    lines = [
        subject,
        f"Kind: {f['kind']}   Subject IP: {f['subject_ip']}   Events: {f['event_count']}",
        f"Seen: {f['first_seen']} -> {f['last_seen']}",
        "",
        "Why it was flagged:",
        *[f"  - {r}" for r in f["reasons"]],
        "",
        "Targets: " + ", ".join(f["targets"][:15]) + (" ..." if len(f["targets"]) > 15 else ""),
        "Top signatures:",
        *[f"  - {s}" for s in f["signatures"][:8]],
    ]
    if f.get("blocked_at"):
        lines.append(f"\nAuto-blocked at {f['blocked_at']}")
    return subject, "\n".join(lines)


def send(f: dict, cfg: NotifyCfg) -> bool:
    """Send a finding to every configured channel.

    Returns True if at least one channel delivered it (or only console logging is configured),
    so a single broken channel doesn't cause the finding to be re-sent every cycle.
    """
    subject, body = render(f)
    log.warning("FINDING %s\n%s", f["key"], body)
    channels = [(name, fn) for name, fn, on in (
        ("webhook", _webhook, cfg.webhook_url),
        ("ntfy", _ntfy, cfg.ntfy_url),
        ("email", _email, cfg.smtp_host and cfg.smtp_to)) if on]
    ok = 0
    for name, fn in channels:
        try:
            fn(f, subject, body, cfg)
            ok += 1
        except Exception as e:  # keep going on other channels
            log.error("notify via %s failed: %s", name, e)
    return ok > 0 or not channels


def _post(url: str, data: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def _webhook(f, subject, body, cfg: NotifyCfg) -> None:
    if not cfg.webhook_url:
        return
    if cfg.webhook_format == "discord":
        payload = {"content": f"**{subject}**\n```\n{body[:1800]}\n```"}
    elif cfg.webhook_format == "slack":
        payload = {"text": f"*{subject}*\n```{body}```"}
    else:
        payload = {"subject": subject, "body": body, "finding": f}
    _post(cfg.webhook_url, json.dumps(payload).encode(), {"Content-Type": "application/json"})


def _ntfy(f, subject, body, cfg: NotifyCfg) -> None:
    if not cfg.ntfy_url:
        return
    prio = {"low": "2", "medium": "3", "high": "4", "critical": "5"}[f["severity"]]
    _post(cfg.ntfy_url, body.encode(), {"Title": subject.encode("ascii", "replace").decode(),
                                       "Priority": prio, "Tags": "rotating_light,shield"})


def _email(f, subject, body, cfg: NotifyCfg) -> None:
    if not (cfg.smtp_host and cfg.smtp_to):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from or cfg.smtp_user
    msg["To"] = ", ".join(cfg.smtp_to)
    msg.set_content(body)
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
        if cfg.smtp_starttls:
            s.starttls(context=ssl.create_default_context())
        if cfg.smtp_user:
            s.login(cfg.smtp_user, cfg.smtp_password)
        s.send_message(msg)
