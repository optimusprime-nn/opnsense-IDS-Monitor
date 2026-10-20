//! Static HTML report of findings.

use anyhow::Result;
use std::path::Path;

use crate::config::Severity;
use crate::store::Store;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#b42318",
        Severity::High => "#c4320a",
        Severity::Medium => "#a15c07",
        Severity::Low => "#475467",
    }
}

/// Write a report of all findings; returns how many were included.
pub fn write_html(store: &Store, out: &Path) -> Result<usize> {
    let rows = store.list_findings(None, Severity::Low, 500)?;
    let mut cards = String::new();
    for f in &rows {
        let open = if f.severity >= Severity::High && f.status == "open" { " open" } else { "" };
        let li = |v: &[String]| v.iter().map(|x| format!("<li>{}</li>", esc(x))).collect::<String>();
        let blocked = f.blocked_at.as_deref().map(|b| format!(" · <b>blocked</b> {}", esc(&crate::local_time(b)))).unwrap_or_default();
        cards += &format!(
            r#"<details class="f"{open}><summary><span class="sev" style="background:{c}">{sev}</span> <b>{title}</b>
<span class="m">score {score} · {n} events · {status} · last {last}</span></summary><div class="body">
<p class="m">key <code>{key}</code> · first seen {first}{blocked}</p>
<h4>Why</h4><ul>{reasons}</ul><h4>Targets</h4><p><code>{targets}</code></p><h4>Signatures</h4><ul>{sigs}</ul></div></details>
"#,
            c = sev_color(f.severity),
            sev = f.severity.as_str(),
            title = esc(&f.title),
            score = f.score,
            n = f.event_count,
            status = f.status_label(),
            last = esc(&crate::local_time(&f.last_seen)),
            key = esc(&f.key),
            first = esc(&crate::local_time(&f.first_seen)),
            reasons = li(&f.reasons),
            targets = esc(&f.targets.join(", ")),
            sigs = li(&f.signatures),
        );
    }
    let tiles: String = Severity::ALL
        .iter()
        .rev()
        .map(|&s| {
            let n = rows.iter().filter(|f| f.severity == s && f.status == "open").count();
            format!(r#"<div class="t"><div class="n" style="color:{}">{n}</div>{}</div>"#, sev_color(s), s.as_str())
        })
        .collect();
    let doc = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPS Watch Report</title><style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:16px;background:#f8f9fb;color:#1d2939}}
h1{{font-size:20px}} .m{{color:#667085;font-size:12px}} code{{font-size:12px;word-break:break-all}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 20px}} .t{{background:#fff;border:1px solid #e4e7ec;border-radius:8px;padding:10px 16px;min-width:90px}}
.n{{font-size:24px;font-weight:700}} .f{{background:#fff;border:1px solid #e4e7ec;border-radius:8px;margin:8px 0;padding:10px 14px}}
summary{{cursor:pointer}} .sev{{color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;text-transform:uppercase;margin-right:6px}}
h4{{margin:10px 0 2px;font-size:13px}} ul{{margin:0;padding-left:20px}}
</style></head><body><h1>OPNsense IPS Watch</h1><div class="m">Generated {gen} · open findings by severity</div>
<div class="tiles">{tiles}</div>{cards}</body></html>"#,
        gen = chrono::Local::now().format("%Y-%m-%d %H:%M"),
        cards = if cards.is_empty() { "<p>No findings.</p>".to_string() } else { cards },
    );
    std::fs::write(out, doc)?;
    Ok(rows.len())
}
