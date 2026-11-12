---
title: Desktop app (GUI)
nav_order: 4
has_children: true
permalink: /gui/
---

# Desktop app (GUI)

`IPSWatch.exe` is a Windows tray app. It monitors in the background and shows a window with six pages:

| Page | What's on it |
|---|---|
| [Findings](findings.html) | Everything that needs a look: IPS findings plus health, DNS, exposure, device and config findings |
| [Health](health.html) | The firewall: gateways, resources, services, exposure audit, CrowdSec, devices, config changes |
| [DNS](dns.html) | Each DNS server: up / down, traffic, failures, blocklists, top clients, WAN exposure |
| [Troubleshoot](troubleshoot.html) | One button that finds why the internet or a site isn't working, explains it and offers fixes |
| [IPS events and log](events-and-log.html) | Raw IPS alerts, and the app's own activity log |
| [Settings](settings.html) | Every option, in ten sections |

## Toolbar and status

- **Start monitoring / Stop monitoring** starts or stops the background poller and the health and DNS checks.
- **Poll now** fetches new alerts immediately.
- The top-right corner shows *Monitoring* or *Stopped*; the status bar at the bottom shows the last poll result and
  the version.

## Menus

| Menu | Items |
|---|---|
| File | Import eve.json..., Export HTML report..., Open data folder, Hide to tray, Quit |
| Monitor | Start / Stop monitoring, Poll now |
| View | Theme (Dark, Light, Follow Windows), Toggle dark / light, the pages |
| Settings | The ten settings sections, Firewall Drop policy..., Start with Windows |
| Help | About IPS Watch, Open log file |

## System tray

The tray icon turns **red** while high or critical findings are open. Right-click it for **Open IPS Watch**,
**Start monitoring** / Stop, **Poll now**, **Start with Windows** and **Quit**. With *Close button hides to tray* on
(the default), closing the window keeps monitoring running.

## Desktop notifications

New findings at or above the *Desktop alert minimum severity* (default: high) show a Windows toast. Webhook, ntfy
and email alerts are configured separately under
[Settings → Notifications](settings.html#notifications).

## Start-up options

| Option | Effect |
|---|---|
| `--minimized` | Start hidden in the tray (used by *Start with Windows*) |
| `--config <file>` | Use another settings file (the database path inside it is relative to that file) |
| `--tab <page>[:section]` | Open on a given page: `findings`, `health`, `dns`, `events`, `log` or `settings`. For settings, add a section: `firewall`, `collection`, `detection`, `rules`, `notifications`, `autoblock`, `health`, `dns`, `application` or `data`, e.g. `--tab settings:application` |

Only one copy runs at a time; starting it again brings the running window to the front.
