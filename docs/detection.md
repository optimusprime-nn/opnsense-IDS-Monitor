---
title: How findings are scored
nav_order: 6
---

# How findings are scored
{: .no_toc }

1. TOC
{:toc}

Events are grouped per source inside a sliding window (default 15 minutes) and scored. A finding is raised at a
score of **50 or more**. Severity follows the score:

| Severity | Score |
|---|---|
| medium | ≥ 50 |
| high | ≥ 80 |
| critical | ≥ 120 |

The window, the threshold and every count below are configurable
([GUI: Detection](gui/settings.html#detection), [config: `[detect]`](cli/config-file.html#detect)).

## Inbound findings (external source → your network)

| Signal | Points |
|---|---|
| Highest Suricata severity 1 / 2 / 3 | 40 / 20 / 5 |
| An alert was **not dropped** by the IPS (traffic reached the host) | 30 |
| Targeted a sensitive port (SSH, RDP, SMB, databases, WinRM, VNC…) | 20 |
| Exploit / malware / privilege-gain signature | 30 |
| ≥ 20 alerts in the window (brute force) | 25 |
| ≥ 10 distinct hosts (sweep) / ≥ 15 distinct ports (port scan) | 25 each |
| **Firewall log shows PASSED connections from the source to internal hosts** | 40 |

The title says what happened:

- *"Potential unwanted access from X"*: traffic got through to a host behind the firewall.
- *"Attack attempts against the firewall from X"*: it only hit the firewall's own addresses.
- *"Blocked attack activity from X"*: everything else.

## Compromise findings (an internal host is the source)

| Signal | Points |
|---|---|
| Trojan / C2 / exploit indicator (compromise categories and keywords) | 60 |
| Internal → internal at severity ≤ 2 (lateral movement) | 30 |
| Outbound malicious traffic not dropped | 20 |
| plus the severity, repeat and scan points above | |

These usually matter most: something is already inside.

## Health, DNS, exposure, device and config findings

These come from the firewall and DNS checks rather than from IPS alerts. They use fixed severities (for example a
gateway down is HIGH, all gateways down is CRITICAL, a new device is MEDIUM) and **clear themselves** when the
problem goes away. See [Health](gui/health.html) and [DNS](gui/dns.html).

## How noise is kept out

- **Informational rules are shown but never scored**: signatures starting with `OPN_` (app detection), `ET INFO`,
  `GPL ICMP_INFO`, P2P, chat and games. Edit the list under *Settings → Signature rules*.
- **Ignore a signature in one click**: right-click an event, or use **Ignore** next to a signature on a finding. It's
  added to the ignored SIDs and your data is re-scored.
- **The firewall's own addresses are recognised automatically.** IPS Watch reads them from the API every hour.
  Traffic *from* them is never scored: it's the firewall itself, or NAT'd / hairpinned client traffic.
- **Severity comes from the rule family when the API doesn't send it.** OPNsense's alert API leaves out severity and
  category, so ET/ETPRO EXPLOIT, MALWARE, TROJAN and CNC count as high, and SCAN, DROP and TOR as medium.
- **Firewall-log correlation is strict.** It only counts *inbound* passes inside the alert window, and skips
  broadcast / multicast and routine ports (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS; editable).
- **A banner warns when the IPS hasn't dropped anything for a week**: IPS mode is off, or no policy is set to Drop. Applying the Drop policy clears it; it only comes back if the next 20 alerts are all let through too.
- **Re-score after changing rules**: *Settings → Data & storage → Re-score all findings*, or `ipswatch-cli rescore`.
  Your acknowledged and false-positive marks are kept.

## Catching up

If more alerts arrive than one poll can download (alerts per page × max pages per poll), IPS Watch catches up over
the following polls instead of skipping the rest, and shows "Alert history is behind" until it has.
