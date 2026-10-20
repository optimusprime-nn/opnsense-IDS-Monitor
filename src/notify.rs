//! Remote notification channels: webhook (Slack/Discord/generic), ntfy, SMTP email.

use anyhow::Result;
use log::{error, warn};
use serde_json::json;
use std::time::Duration;

use crate::config::{NotifyCfg, Severity};
use crate::store::Finding;

pub fn render(f: &Finding) -> (String, String) {
    let tag = match f.severity {
        Severity::Low => "[low]",
        Severity::Medium => "[MEDIUM]",
        Severity::High => "[HIGH]",
        Severity::Critical => "[CRITICAL]",
    };
    let subject = format!("{tag} {} (score {})", f.title, f.score);
    let mut lines = vec![
        subject.clone(),
        format!("Kind: {}   Subject IP: {}   Events: {}", f.kind, f.subject_ip, f.event_count),
        format!("Seen: {} -> {}", crate::local_time(&f.first_seen), crate::local_time(&f.last_seen)),
        String::new(),
        "Why it was flagged:".into(),
    ];
    lines.extend(f.reasons.iter().map(|r| format!("  - {r}")));
    lines.push(String::new());
    let more = if f.targets.len() > 15 { " ..." } else { "" };
    lines.push(format!("Targets: {}{more}", f.targets.iter().take(15).cloned().collect::<Vec<_>>().join(", ")));
    lines.push("Top signatures:".into());
    lines.extend(f.signatures.iter().take(8).map(|s| format!("  - {s}")));
    if let Some(b) = &f.blocked_at {
        lines.push(format!("\nAuto-blocked at {}", crate::local_time(b)));
    }
    (subject, lines.join("\n"))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build()
}

fn webhook(cfg: &NotifyCfg, f: &Finding, subject: &str, body: &str) -> Result<()> {
    let payload = match cfg.webhook_format.as_str() {
        "discord" => json!({"content": format!("**{subject}**\n```\n{}\n```", body.chars().take(1800).collect::<String>())}),
        "slack" => json!({"text": format!("*{subject}*\n```{body}```")}),
        _ => json!({"subject": subject, "body": body, "finding": f}),
    };
    agent().post(&cfg.webhook_url).send_json(payload)?;
    Ok(())
}

fn ntfy(cfg: &NotifyCfg, f: &Finding, subject: &str, body: &str) -> Result<()> {
    let prio = match f.severity {
        Severity::Low => "2",
        Severity::Medium => "3",
        Severity::High => "4",
        Severity::Critical => "5",
    };
    let title: String = subject.chars().map(|c| if c.is_ascii() { c } else { '?' }).collect();
    agent()
        .post(&cfg.ntfy_url)
        .set("Title", &title)
        .set("Priority", prio)
        .set("Tags", "rotating_light,shield")
        .send_string(body)?;
    Ok(())
}

fn email(cfg: &NotifyCfg, subject: &str, body: &str) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    let from = if cfg.smtp_from.is_empty() { &cfg.smtp_user } else { &cfg.smtp_from };
    let mut msg = Message::builder().from(from.parse()?).subject(subject);
    for to in &cfg.smtp_to {
        msg = msg.to(to.parse()?);
    }
    let msg = msg.body(body.to_string())?;
    let mut t = if cfg.smtp_port == 465 {
        SmtpTransport::relay(&cfg.smtp_host)?
    } else if cfg.smtp_starttls {
        SmtpTransport::starttls_relay(&cfg.smtp_host)?
    } else {
        SmtpTransport::builder_dangerous(&cfg.smtp_host)
    }
    .port(cfg.smtp_port)
    .timeout(Some(Duration::from_secs(20)));
    if !cfg.smtp_user.is_empty() {
        t = t.credentials(Credentials::new(cfg.smtp_user.clone(), cfg.smtp_password.clone()));
    }
    t.build().send(&msg)?;
    Ok(())
}

/// Send to every configured channel. Returns true if at least one delivered it (or none
/// is configured), so one broken channel doesn't cause re-sending every cycle.
pub fn send(f: &Finding, cfg: &NotifyCfg) -> bool {
    let (subject, body) = render(f);
    warn!("FINDING {}: {}", f.key, subject);
    let mut configured = 0;
    let mut ok = 0;
    let mut attempt = |name: &str, on: bool, r: &dyn Fn() -> Result<()>| {
        if !on {
            return;
        }
        configured += 1;
        match r() {
            Ok(()) => ok += 1,
            Err(e) => error!("notify via {name} failed: {e:#}"),
        }
    };
    attempt("webhook", !cfg.webhook_url.is_empty(), &|| webhook(cfg, f, &subject, &body));
    attempt("ntfy", !cfg.ntfy_url.is_empty(), &|| ntfy(cfg, f, &subject, &body));
    attempt("email", !cfg.smtp_host.is_empty() && !cfg.smtp_to.is_empty(), &|| email(cfg, &subject, &body));
    ok > 0 || configured == 0
}

/// Send a test message; returns per-channel results for the settings screen.
pub fn send_test(cfg: &NotifyCfg) -> Vec<(String, Result<()>)> {
    let f = sample_finding();
    let (subject, body) = render(&f);
    let mut out = Vec::new();
    if !cfg.webhook_url.is_empty() {
        out.push(("Webhook".into(), webhook(cfg, &f, &subject, &body)));
    }
    if !cfg.ntfy_url.is_empty() {
        out.push(("ntfy".into(), ntfy(cfg, &f, &subject, &body)));
    }
    if !cfg.smtp_host.is_empty() && !cfg.smtp_to.is_empty() {
        out.push(("Email".into(), email(cfg, &subject, &body)));
    }
    out
}

pub fn sample_finding() -> Finding {
    let now = crate::now_iso();
    Finding {
        key: "test:203.0.113.1".into(),
        kind: "inbound".into(),
        subject_ip: "203.0.113.1".into(),
        first_seen: now.clone(),
        last_seen: now,
        score: 0,
        severity: Severity::Low,
        title: "IPS Watch test notification".into(),
        reasons: vec!["This is a test - your notification channel works.".into()],
        targets: vec![],
        signatures: vec![],
        event_count: 1,
        status: "open".into(),
        notified_at: None,
        notified_severity: None,
        blocked_at: None,
    }
}
