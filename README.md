# IPS Watch â€” OPNsense IPS capture & unwanted-access flagging

A Windows desktop app (plus a command-line build) written in Rust. It collects Suricata IPS
alerts from OPNsense, stores them in SQLite, correlates them with the firewall log, and raises
**findings** when something looks like real unwanted access rather than background noise.

- **System tray**: runs in the background, the tray icon turns red while high/critical findings are open,
  and the right-click menu has Open, Start/Stop monitoring, Poll now, Start with Windows and Quit.
- **Start with Windows**: per-user Run entry (no admin rights), launches hidden in the tray.
- **Settings editor**: every option is editable in the app (Settings tab or the **Settings** menu), with
  validation, Revert, per-section Restore defaults, and test buttons.
- **Alerts**: Windows toast notifications, and optionally Slack/Discord/webhook, ntfy and email.
- **Response**: acknowledge / false positive, block or unblock an IP through a firewall alias, and optional auto-block.
- **Dark mode**: dark by default, with Light and Follow Windows options (View → Theme, the Settings menu, or Settings → Application). The title bar changes too, and exported HTML reports follow the viewer's dark/light preference.
- **Secrets**: the API key, API secret and SMTP password are encrypted with Windows DPAPI.

![Findings](docs/findings.png)

```
 OPNsense â”€â”€(REST API poll: ids/service/query_alerts, firewall log)â”€â”€â”
          â”€â”€(remote syslog: Suricata EVE JSON, optional realtime)â”€â”€â”€â”€â”¤
                                                                     â–¼
                           normalize â†’ SQLite â†’ detection rules â†’ findings
                                                       â”‚              â”‚
                                        firewall-log correlation      â”œâ”€ toast / webhook / ntfy / email
                                                                      â””â”€ block via alias (manual or auto)
```

## Install / build

Download or build `IPSWatch.exe` and run it. It is a single portable file with no installer and no runtime.

```powershell
.\build.ps1          # runs the tests, builds dist\IPSWatch.exe and dist\ipswatch-cli.exe
```

Building needs the Rust toolchain (`rustup`, MSVC target). Settings, the database and the log live in
`%APPDATA%\ipswatch\`.

## First run

1. The app opens on **Settings â†’ Firewall connection**. Enter the firewall URL and API key/secret, then click
   **Test firewall connection** and **Save settings**. Monitoring starts automatically.
2. **Settings â†’ Application**: tick **Start with Windows** (or use the tray menu or the **Settings** menu).
   Closing the window hides it to the tray; use **Quit** in the tray menu or the File menu to exit.
3. To try it without a firewall, use **File â†’ Import eve.json...** with `samples/eve-sample.json`.

| Settings page | What's there |
|---|---|
| Firewall connection | URL, API key/secret, TLS verify / CA file, timeout, poll interval, paging, firewall-log correlation |
| Collection | Realtime syslog receiver: on/off, address, port, UDP/TCP |
| Detection | Internal networks, window, score threshold, brute-force/sweep/port-scan thresholds, sensitive ports, ignored SIDs, trusted sources, re-notify interval |
| Signature rules | Compromise categories and signature keywords |
| Notifications | Webhook (Slack/Discord/generic), ntfy, SMTP; minimum severity; test button |
| Auto-block | Enable, dry run, alias, minimum severity, never-block list |
| Application | Theme (dark / light / follow Windows), start with Windows, start minimized, close to tray, auto-start monitoring, desktop alerts and their minimum severity |
| Data & storage | Database file, event retention, delete old events, delete all data, open data folder |

![Settings](docs/settings.png)

## What gets flagged

Events are grouped per actor inside a sliding window (default 15 min) and scored. A finding is raised
at score â‰¥ 50; severity is medium â‰¥ 50, high â‰¥ 80, critical â‰¥ 120.

**Inbound findings (external source â†’ your network)**

| Signal | Points |
|---|---|
| Highest Suricata severity 1 / 2 / 3 | 40 / 20 / 5 |
| An alert was **not dropped** by the IPS (traffic reached the host) | 30 |
| Targeted a sensitive port (SSH, RDP, SMB, DBs, WinRM, VNCâ€¦) | 20 |
| Exploit / malware / privilege-gain signature | 30 |
| â‰¥ 20 alerts in the window (brute force) | 25 |
| â‰¥ 10 distinct hosts (sweep) / â‰¥ 15 distinct ports (port scan) | 25 each |
| **Firewall log shows PASSED connections from the source to internal hosts** | 40 |

Titled *"Potential unwanted access from X"* if traffic got through, otherwise *"Blocked attack activity from X"*.

**Compromise findings (an internal host is the source)**: a trojan/C2/exploit indicator (60),
internalâ†’internal severity â‰¤ 2 (lateral movement, 30), outbound malicious traffic not dropped (20),
plus the severity/repeat/scan points. These usually matter most: something is already inside.

## OPNsense setup

**Intrusion detection** (*Services â†’ Intrusion Detection â†’ Administration*)
1. Enable it, turn on **IPS mode**, and choose the interfaces: WAN, plus LAN if you want internal, lateral and outbound visibility.
2. Download rule sets (e.g. ET open / abuse.ch). Under *Policy*, set the categories you want blocked to **Drop**.
   In IPS mode only *drop* rules block traffic; IPS Watch treats any alert that wasn't dropped as "reached the host".
3. Optional realtime feed: enable **eve syslog output** (advanced mode), then *System â†’ Settings â†’ Logging â†’ Remote*
   with application `suricata` â†’ this PC, port 5514. Allow that port in Windows Firewall.

**API user** (*System â†’ Access â†’ Users*): create a dedicated user and give it only the Intrusion Detection
and firewall-log privileges, plus *Firewall: Alias* if you'll block IPs. Then create an API key for it.

**Blocking**: create a *Host(s)* alias `ipswatch_block` and a WAN **Block** rule at the top with that alias
as the source. Leave auto-block in dry run until you trust the findings. Internal, private and reserved
addresses, and anything on the never-block list, are never blocked.

## Command line

`ipswatch-cli` uses the same engine and, by default, the same settings file as the desktop app.

```powershell
ipswatch-cli check                          # verify API access
ipswatch-cli run                            # monitor in the foreground
ipswatch-cli poll                           # one pass (Task Scheduler / cron)
ipswatch-cli import samples\eve-sample.json --quiet
ipswatch-cli findings --min high
ipswatch-cli ack inbound:203.0.113.7        # also: fp, reopen
ipswatch-cli report report.html
ipswatch-cli -c path\to\config.toml ...     # use another settings file
```

`deploy/ipswatch.service` runs the CLI as a Linux service.

## Development

```powershell
cargo test                                               # unit + detection/pipeline tests
cargo test --test windows_integration -- --ignored       # toggles the real Run key, shows a toast
cargo run --bin IPSWatch -- --config samples\demo\config.toml --tab settings:application
```

The `--tab findings|events|log|settings[:section]` option opens a specific page. `--minimized` starts in the tray.

History: the first commit is the original Python/Tkinter version. The SQLite schema, the settings file
(including DPAPI-encrypted secrets) and the scoring are compatible with it.
