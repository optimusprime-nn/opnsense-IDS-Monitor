"""Static HTML report of findings."""
from __future__ import annotations

import html
from datetime import datetime, timezone


SEV_COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}


def write_html(store, out: str) -> int:
    """Write a static HTML report of all findings. Returns the number of findings."""
    rows = store.list_findings(None, "low", 500)
    e = html.escape
    cards = []
    for f in rows:
        cards.append(f"""
<details class="f" {'open' if f['severity'] in ('critical', 'high') and f['status'] == 'open' else ''}>
  <summary><span class="sev" style="background:{SEV_COLOR[f['severity']]}">{e(f['severity'])}</span>
    <b>{e(f['title'])}</b> <span class="m">score {f['score']} · {f['event_count']} events · {e(f['status'])}
    · last {e(f['last_seen'][:19].replace('T', ' '))} UTC</span></summary>
  <div class="body">
    <p class="m">key <code>{e(f['key'])}</code> · first seen {e(f['first_seen'][:19].replace('T', ' '))} UTC
    {('· <b>blocked</b> ' + e(f['blocked_at'][:19])) if f.get('blocked_at') else ''}</p>
    <h4>Why</h4><ul>{''.join(f'<li>{e(r)}</li>' for r in f['reasons'])}</ul>
    <h4>Targets</h4><p><code>{e(', '.join(f['targets']))}</code></p>
    <h4>Signatures</h4><ul>{''.join(f'<li>{e(s)}</li>' for s in f['signatures'])}</ul>
  </div>
</details>""")
    counts = {s: sum(1 for f in rows if f["severity"] == s and f["status"] == "open")
              for s in ("critical", "high", "medium", "low")}
    tiles = "".join(f'<div class="t"><div class="n" style="color:{SEV_COLOR[s]}">{n}</div>{s}</div>'
                    for s, n in counts.items())
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>IPS Watch Report</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:16px;background:#f8f9fb;color:#1d2939}}
h1{{font-size:20px}} .m{{color:#667085;font-size:12px}} code{{font-size:12px;word-break:break-all}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 20px}} .t{{background:#fff;border:1px solid #e4e7ec;border-radius:8px;padding:10px 16px;min-width:90px}}
.n{{font-size:24px;font-weight:700}} .f{{background:#fff;border:1px solid #e4e7ec;border-radius:8px;margin:8px 0;padding:10px 14px}}
summary{{cursor:pointer}} .sev{{color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;text-transform:uppercase;margin-right:6px}}
h4{{margin:10px 0 2px;font-size:13px}} ul{{margin:0;padding-left:20px}}
</style></head><body>
<h1>OPNsense IPS Watch</h1><div class="m">Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC · open findings by severity</div>
<div class="tiles">{tiles}</div>
{''.join(cards) or '<p>No findings.</p>'}
</body></html>"""
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return len(rows)
