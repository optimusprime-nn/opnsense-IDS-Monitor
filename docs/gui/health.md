---
title: Health
parent: Desktop app (GUI)
nav_order: 2
---

# Health

![The Health page](../assets/img/health.png)

While monitoring runs, IPS Watch checks the firewall itself every 5 minutes (*Settings → Health checks*). The
Health page shows the latest result, which is kept across restarts; **Check now** runs it immediately. Problems
become findings like IPS ones, with alerts, toasts and the red tray icon, and they clear themselves when fixed.

## Summary line and tiles

The line under **Check now** shows the firewall's host name, OPNsense version, uptime, load and when it was
checked. The tiles show each gateway (status, latency, loss), memory (ZFS cache excluded), firewall states, disk
use and how many services are running.

## Checks

| Check | Raises |
|---|---|
| Gateways (latency / loss per WAN) | gateway down (HIGH), degraded (MEDIUM), all down (CRITICAL) |
| Services | any stopped service (HIGH), unless it's listed as allowed to be stopped |
| System status, reboots, firmware | crash reporter and system warnings, "firewall rebooted", update available |
| Memory, state table, disk | above the configured percentage |
| Reachability | IPS Watch can't reach the firewall API for N minutes (HIGH) |
| **Exposure audit** | each port forward, any-source WAN pass rule or inbound pass in the log that's actually open: DNS or sensitive ports HIGH, others LOW |
| **New devices** | a MAC address not seen before in the ARP table (names from DHCP leases); quiet for the first 24 hours while it learns |
| **Config changes** | each change in the firewall's configuration history, with who and what (MEDIUM unless IPS Watch made it) |

## Exposed to the internet

The table lists every way in from the internet: the target, protocol, how (port forward or WAN pass rule), the
interface and whether it's actually open. Rows like *forwarded, no pass rule* or *not reachable* point at leftover
rules worth cleaning up. Acknowledge the exposures you intend; the acknowledgement sticks.

## CrowdSec

If the os-crowdsec plugin is installed, this section shows whether CrowdSec and its firewall bouncer are running and
checking in, how many IPs are blocked, the top scenarios and recent alerts. Alerts for serious scenarios (brute
force on the web GUI or SSH, CVE / exploit attempts) become findings; routine ones like port scans are only counted.
IPS findings from an IP CrowdSec has banned get "CrowdSec has banned this IP" and +20 points.

## Devices and config changes

Further down the page: the devices seen on each interface (IP, MAC, vendor, name, first and last seen) and the
firewall's recent configuration changes.

Thresholds for all of this are under [Settings → Health checks](settings.html#health-checks).
CLI equivalent: `ipswatch-cli health`.
