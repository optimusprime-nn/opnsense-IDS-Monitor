---
title: OPNsense setup
nav_order: 3
---

# OPNsense setup
{: .no_toc }

1. TOC
{:toc}

## Intrusion detection

In *Services → Intrusion Detection → Administration*:

1. Enable it, turn on **IPS mode**, and choose the interfaces: WAN, plus LAN if you want to see internal,
   lateral and outbound traffic.
2. Download rule sets (for example ET open and abuse.ch). Under *Policy*, set the categories you want blocked to
   **Drop**. In IPS mode only *drop* rules block traffic, and IPS Watch treats any alert that wasn't dropped as
   "reached the host". IPS Watch can set up a policy for you; see [Drop policy](#drop-policy) below.
3. Optional realtime feed: enable **eve syslog output** (advanced mode), then add *System → Settings → Logging →
   Remote* with application `suricata`, pointing to the PC running IPS Watch on port 5514. Allow that port in
   Windows Firewall, only from the firewall. The API poller keeps running and fills any gaps.

{: .note }
Syslog can't prove who sent a message. IPS Watch only accepts it from the firewall's own addresses (or the
*Allowed senders* you list), and alerts seen only through syslog are shown and alerted on but never trigger
auto-block on their own.

## API user

In *System → Access → Users*, create a dedicated user and give it only what IPS Watch reads:

| Feature | Privileges |
|---|---|
| IPS alerts (required) | Intrusion Detection, firewall log (*Diagnostics: Firewall Log*) |
| Health checks | Gateways, Services, Diagnostics (system, ARP), Firewall rules / NAT, DHCP leases, Configuration history |
| CrowdSec | the os-crowdsec plugin pages |
| Troubleshoot | the Health checks pages, plus *Diagnostics: Logs* (gateway log), *System: Firmware*, Interfaces settings; for its fixes *Status: Services* |
| Unbound DNS checks | Unbound DNS settings, reporting overview and diagnostics |
| Blocking IPs | *Firewall: Alias* |
| Drop policy | Intrusion Detection (write) |

Then create an API key for that user and enter the key and secret in IPS Watch.

## HTTPS certificate: do I need a CA certificate file?

Not sure? Click **Check certificate** next to the field (or run `ipswatch-cli check-cert`). It connects to the
firewall and tells you which case you're in.

- **Let's Encrypt or another public CA** (see *Services → ACME Client → Certificates*). Windows already trusts it:
  leave the CA file **empty** and keep *Verify TLS certificate* ticked. Use the host name the certificate was issued
  for as the Firewall URL (for example `https://fw.example.com`), not the IP: Let's Encrypt can't issue certificates
  for private IPs. The name must resolve to the firewall from your PC; if it doesn't, add an override in
  *Services → Unbound DNS → Overrides*.
- **Self-signed / OPNsense's default certificate**. *System → Settings → Administration → SSL Certificate* shows which
  certificate the web interface uses. Download its CA from *System → Trust → Authorities*. The default self-signed
  "Web GUI TLS certificate" has no CA, so download the certificate itself from *System → Trust → Certificates*.
  Download the certificate only, never the private key. Alternatively, install it into Windows (*Trusted Root
  Certification Authorities*, Current User) and leave the field empty.
- Unticking *Verify TLS certificate* also works, but then the connection, including your API key, can be
  intercepted. Use it only to test.

## Drop policy

In IPS mode, rules only block when a policy sets them to *Drop*. IPS Watch can create one policy,
"IPS Watch - drop high-risk". It switches the Alert rules in the high-risk rulesets you have enabled (abuse.ch,
botcc, compromised, drop / dshield / ciarmy, exploit, exploit_kit, attack_response, malware, mobile_malware,
phishing, coinminer, worm, Snort malware-cnc / backdoor) to Drop. Everything else stays on Alert.

You always get a dry run first that lists every ruleset and rule count, and nothing changes until you confirm.

- Desktop app: **Settings → Firewall Drop policy...**, or the banner that appears when nothing has been dropped for a week.
- CLI: `ipswatch-cli ips-policy` (dry run), then `ipswatch-cli ips-policy --apply --yes`, or `--remove --yes` to undo.

The list of rulesets is editable under *Settings → Signature rules* (`ips_policy.rulesets`).

## Blocking

Create a *Host(s)* alias named `ipswatch_block` and a WAN **Block** rule at the top with that alias as the source.
IPS Watch then adds and removes addresses in the alias: by hand from the Findings page, or automatically
(*Settings → Auto-block*). Leave auto-block in **dry run** until you trust the findings.

Internal, private and reserved addresses (including multicast, CGNAT and IPv6 link-local) and anything on the
never-block list are never blocked. Auto-block only acts on sources the firewall API itself reported, and a block
only counts once the firewall confirms it and the address shows up in the alias.

## Unbound statistics (for DNS checks)

If you monitor OPNsense's own Unbound resolver, open *Reporting → Unbound DNS* and enable **local statistics** in
its settings. Without them, IPS Watch can only do test lookups and a few counters, and a LOW finding
("Unbound statistics are off") stays open. For SERVFAIL counters without statistics, enable
*Services → Unbound DNS → Advanced → Extended statistics*.
