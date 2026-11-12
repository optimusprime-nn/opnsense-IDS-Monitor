---
title: Troubleshoot
parent: Desktop app (GUI)
nav_order: 4
---

# Troubleshoot
{: .no_toc }

1. TOC
{:toc}

When the internet, or one site, stops working, open **Troubleshoot** and click **Find problems**.
IPS Watch checks the firewall and your connection, then lists what's wrong in plain language, worst
first. Each problem says what it means, what IPS Watch saw, and how to fix it. Some can be fixed with
one click.

Running the checks is **read-only**. Nothing on the firewall changes unless you click a **Fix it** button
and then confirm.

## What it checks

| Check | What it finds |
|---|---|
| **Clock** | The firewall's time compared with your PC's. A wrong clock breaks HTTPS, DNSSEC and CrowdSec, and makes every log time misleading. Restoring a VM snapshot puts the clock back to when the snapshot was taken. Also flags two time services (ntpd and chrony) running at once. |
| **Services** | Stopped firewall services (DNS, DHCP, IPS, VPN...). |
| **Inspection** | Suricata IPS and Zenarmor both inspecting traffic inline, and hardware offloading left on while the IPS runs inline. Both are common causes of HTTPS connections that hang or fail. |
| **Internet** | WAN drop-outs and packet loss from the gateway monitor's log (last 24 hours and 7 days), plus gateways sharing one monitor IP. |
| **Blocked traffic** | Your own devices' traffic in the firewall log, split into connections a rule blocked and packets of open connections that were dropped because the firewall stopped tracking them (lost state, typical after a WAN failover or reboot). |
| **Sites** | Each site in *Sites that must work* is looked up, connected to and fetched over HTTPS from your PC. A failure names its cause where the firewall log or IPS alerts show it: a DNS blocklist, a firewall rule, an IPS signature or lost state. |
| **Changes** | Key firewall settings compared with a baseline (see below). |

## Fixes

A **Fix it** button first shows exactly what will change and asks you to confirm. After a fix, the checks
run again on their own. The fixes IPS Watch can apply are:

- **Restart a stopped service.**
- **Resync the firewall clock.** This restarts the time service, which sets the clock straight from the
  time servers even when it's hours off.

Everything else comes with step-by-step instructions under **How to fix it**.

These fixes need the API user to have the *Status: Services* privilege (see [OPNsense setup](../opnsense-setup.html#api-user)).

## Sites that must work

The list defaults to `claude.ai`, `api.anthropic.com`, `cloudflare.com` and `google.com`. Edit it on the
page (one site per line), then click **Save list**. In the config file it's `troubleshoot.sites`.

If every site fails, the problem is the connection itself. If only some fail, the page says which part
of the path is blocking them.

## What changed (the baseline)

IPS Watch keeps a baseline of the settings that most often break connectivity: the firmware version,
running services, IPS settings, hardware offloading, Unbound DNS and blocklist settings, gateways and
firewall rules. Each run compares the firewall with that baseline.

- The **first run** saves the baseline.
- **After a firmware update,** the baseline becomes the state from just before the update, so you see
  exactly what the update changed.
- **Mark the current settings as the baseline** once everything works, so later runs show only new changes.

Rolled back a VM snapshot? Settings saved after the snapshot was taken show up here as changes too.

## Command line

```powershell
ipswatch-cli troubleshoot                    # run every check and print the report
ipswatch-cli troubleshoot --fix 1            # preview fix number 1 (changes nothing)
ipswatch-cli troubleshoot --fix 1 --yes      # apply it
ipswatch-cli troubleshoot --mark-baseline    # make the current settings the baseline
```
