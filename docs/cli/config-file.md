---
title: Config file
parent: Command line (CLI)
nav_order: 2
---

# Config file reference
{: .no_toc }

Settings live in one TOML file, `%APPDATA%\ipswatch\config.toml` on Windows (or the file given with `-c`). The desktop
app writes it from its Settings page; from the command line, edit it in any text editor. Every key is optional:
anything left out takes the default shown here. `config.example.toml` in the repository is a complete example.

The **GUI** column names the matching field in the [desktop app's settings](../gui/settings.html).

{: .note }
On Windows, secrets (`api_key`, `api_secret`, `smtp_password`, DNS `token`, `webhook_url`, `ntfy_url`) are stored
encrypted with DPAPI (`dpapi:…`) once the app saves the file. You can type a plain value; it's encrypted on the next
save from the app. On Linux they're stored as written, so keep the file private (mode `0600`).

1. TOC
{:toc}

---

## Top level

| Key | Default | GUI | Description |
|---|---|---|---|
| `db_path` | `"ipswatch.db"` | Data & storage → Database file | SQLite database, relative to the config file's folder. |
| `poll_seconds` | `60` | Firewall connection → Poll interval | How often to fetch new alerts. |
| `retention_days` | `30` | Data & storage → Keep events for | Events older than this are deleted. Findings are kept. |
| `max_events` | `1000000` | — | Most events kept, whatever their age (the oldest go first). |

## [opnsense]

| Key | Default | GUI | Description |
|---|---|---|---|
| `url` | `""` | Firewall URL | e.g. `"https://fw.example.com"`. |
| `api_key` | `""` | API key | Secret. |
| `api_secret` | `""` | API secret | Secret. |
| `verify_tls` | `true` | Verify TLS certificate | |
| `ca_file` | `""` | CA certificate file | PEM / CRT file for a self-signed certificate. |
| `page_size` | `500` | Alerts per page | |
| `max_pages` | `20` | Max pages per poll | Catch-up limit per poll. |
| `timeout_seconds` | `30` | Request timeout | |
| `allow_http` | `false` | Allow unencrypted HTTP | Required for an `http://` URL. |

## [syslog]

| Key | Default | GUI | Description |
|---|---|---|---|
| `enabled` | `false` | Collection → Enable syslog receiver | |
| `bind` | `"0.0.0.0"` | Listen address | |
| `port` | `5514` | Port | |
| `protocol` | `"udp"` | Protocol | `"udp"` or `"tcp"`. |
| `allowed_senders` | `[]` | Allowed senders | IPs / CIDRs. Empty = the firewall's own addresses only. |

## [detect]

| Key | Default | GUI | Description |
|---|---|---|---|
| `internal_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]` | Internal networks | Decides inbound vs internal. |
| `window_minutes` | `15` | Window | Grouping window per source. |
| `flag_score` | `50` | Minimum score to flag | |
| `repeat_threshold` | `20` | Brute-force threshold | |
| `scan_hosts_threshold` | `10` | Sweep threshold | |
| `scan_ports_threshold` | `15` | Port-scan threshold | |
| `sensitive_ports` | `[22, 23, 445, 135, 139, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8443, 9200, 27017]` | Sensitive ports | |
| `ignore_sids` | `[]` | Ignored signature IDs | Integers. |
| `ignore_sources` | `[]` | Trusted sources | CIDRs never flagged. |
| `renotify_minutes` | `360` | Re-notify after | |
| `informational_prefixes` | `["OPN_", "ET INFO", "GPL ICMP_INFO", "ET GAMES", "ET CHAT", "GPL CHAT", "ET P2P", "GPL P2P"]` | Signature rules → Informational rules | Shown, never scored. |
| `compromise_categories` | 10 Suricata classtypes (trojan, privilege gain, C2…) | Signature rules → Compromise categories | Exact classtype text. |
| `compromise_keywords` | `["ET TROJAN", "ET MALWARE", "ET CNC", "ET EXPLOIT", …]` | Signature rules → Signature keywords | Case-insensitive substrings. |

## [firewall]

| Key | Default | GUI | Description |
|---|---|---|---|
| `correlate` | `true` | Firewall connection → Correlate with firewall log | |
| `log_limit` | `2000` | Firewall log rows | Rows fetched per detection pass. |
| `correlate_ignore_ports` | `[53, 67, 68, 123, 137, 138, 1900, 5353, 5355]` | Ignore ports when correlating | |

## [notify]

| Key | Default | GUI | Description |
|---|---|---|---|
| `min_severity` | `"medium"` | Notifications → Minimum severity | `low`, `medium`, `high`, `critical`. |
| `webhook_url` | `""` | Webhook URL | Secret. |
| `webhook_format` | `"slack"` | Webhook format | `slack`, `discord`, `generic`. |
| `ntfy_url` | `""` | ntfy topic URL | Secret. |
| `smtp_host` | `""` | SMTP server | |
| `smtp_port` | `587` | SMTP port | |
| `smtp_starttls` | `true` | Use STARTTLS | |
| `smtp_user` | `""` | SMTP user | |
| `smtp_password` | `""` | SMTP password | Secret. |
| `smtp_from` | `""` | From address | Defaults to `smtp_user`. |
| `smtp_to` | `[]` | To addresses | |

## [block]

| Key | Default | GUI | Description |
|---|---|---|---|
| `enabled` | `false` | Auto-block → Enable auto-block | |
| `dry_run` | `true` | Dry run (log only) | |
| `alias` | `"ipswatch_block"` | Alias name | Host(s) alias on the firewall. |
| `min_severity` | `"critical"` | Minimum severity | |
| `never_block` | `[]` | Never block | IPs / CIDRs. |

## [ips_policy]

| Key | Default | GUI | Description |
|---|---|---|---|
| `rulesets` | 25 high-risk rulesets (abuse.ch, botcc, compromised, drop, dshield, ciarmy, emerging-exploit / malware / trojan…, Snort malware-cnc…) | Signature rules → Drop policy rulesets | Used by `ips-policy`. |

## [health]

| Key | Default | GUI | Description |
|---|---|---|---|
| `enabled` | `true` | Health checks → Enable health checks | |
| `interval_minutes` | `5` | Check every | |
| `gateway_loss_pct` | `10.0` | Gateway packet loss alert | |
| `gateway_delay_ms` | `500.0` | Gateway latency alert | |
| `offline_minutes` | `5` | Unreachable alert after | |
| `memory_pct` | `90.0` | Memory alert | |
| `states_pct` | `80.0` | State table alert | |
| `disk_pct` | `85` | Disk alert | |
| `ignore_services` | `[]` | Services allowed to be stopped | |
| `exposure_audit` | `true` | Exposure audit | |
| `device_alerts` | `true` | New device alerts | |
| `device_learning_hours` | `24` | Device learning period | |
| `config_alerts` | `true` | Config change alerts | |

## [crowdsec]

| Key | Default | GUI | Description |
|---|---|---|---|
| `enabled` | `true` | Health checks → Read CrowdSec | |
| `finding_scenarios` | `["-bf", "bruteforce", "cve-", "exploit", "backdoor"]` | Scenarios that raise findings | |
| `bouncer_stale_minutes` | `10` | Bouncer check-in alert | |
| `boost_ips` | `true` | Boost IPS findings from banned IPs | |

## [dns]

| Key | Default | GUI | Description |
|---|---|---|---|
| `enabled` | `true` | DNS servers → Monitor DNS servers | |
| `interval_minutes` | `5` | Check every | |
| `timeout_seconds` | `10` | Request timeout | |
| `test_domains` | `["cloudflare.com", "opnsense.org"]` | Test lookups | |
| `servfail_pct` | `10.0` | Upstream failure alert | |
| `blocklist_max_age_hours` | `48` | Blocklist age alert | Technitium only. |
| `client_queries_per_hour` | `3000` | Busy client threshold | |
| `client_spike_factor` | `5.0` | Busy client factor | |
| `nxdomain_burst` | `200` | NXDOMAIN burst | |
| `change_alerts` | `true` | Zone / settings change alerts | |
| `allow_http` | `false` | Allow unencrypted HTTP | Required for `http://` Technitium consoles. |

### [[dns.servers]]

One table per server:

| Key | Default | GUI | Description |
|---|---|---|---|
| `name` | `""` | Name | Shown in alerts. |
| `kind` | `"technitium"` | Server type | `"technitium"` or `"unbound"`. |
| `url` | `""` | Web console URL / DNS address | Technitium: console URL. Unbound: optional address for test queries (empty = the firewall). |
| `token` | `""` | API token | Technitium only. Secret. |

```toml
[[dns.servers]]
name = "ns1"
kind = "technitium"
url = "https://192.168.1.53:53443"
token = "..."

[[dns.servers]]
name = "firewall"
kind = "unbound"
url = ""
```

## [troubleshoot]

Used by the [Troubleshoot](../gui/troubleshoot.html) page and `ipswatch-cli troubleshoot`.

| Key | Default | GUI | Description |
|---|---|---|---|
| `sites` | `["claude.ai", "api.anthropic.com", "cloudflare.com", "google.com"]` | Troubleshoot → Sites to test | Checked from this PC (DNS, connect, HTTPS) on every run |
| `log_rows` | `3000` | | Firewall log rows read to find blocked traffic |
| `clock_tolerance_seconds` | `120` | | Clock difference between the firewall and this PC that counts as wrong |

## [gui]

Used by the desktop app only.

| Key | Default | GUI | Description |
|---|---|---|---|
| `theme` | `"dark"` | Application → Theme | `"dark"`, `"light"`, `"system"`. |
| `start_with_windows` | `false` | Start with Windows | |
| `start_minimized` | `false` | Start minimized to tray | |
| `close_to_tray` | `true` | Close button hides to tray | |
| `autostart_monitor` | `true` | Start monitoring on launch | |
| `desktop_alerts` | `true` | Desktop notifications | |
| `alert_min_severity` | `"high"` | Desktop alert minimum severity | |

## A minimal file

```toml
[opnsense]
url = "https://fw.example.com"
api_key = "..."
api_secret = "..."

[detect]
internal_networks = ["192.168.1.0/24"]

[notify]
ntfy_url = "https://ntfy.sh/your-private-topic"
```
