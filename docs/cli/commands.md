---
title: Commands
parent: Command line (CLI)
nav_order: 1
---

# Commands
{: .no_toc }

All commands accept the global `-c, --config <file>` option. `ipswatch-cli help <command>` prints the same
information.

1. TOC
{:toc}

---

## Monitoring

### check

Verify API access and IDS status. It reports the IDS service status, reads a few alert rows, and (when enabled)
checks access to the firewall log and the block alias. Any failure, such as a certificate or credential problem,
is printed and gives a non-zero exit status.

```text
ipswatch-cli check
```

### check-cert

Explain the firewall's HTTPS certificate: is it Let's Encrypt or another public CA, self-signed, or the wrong host
name, and do you need a CA file?

```text
ipswatch-cli check-cert [URL]

Arguments:
  [URL]  URL to check (default: the configured firewall URL)
```

### run

Monitor continuously: polls alerts, runs the health and DNS checks on their intervals, sends notifications and
auto-blocks, like the desktop app does in the background. Ctrl+C to stop.

```text
ipswatch-cli run
```

### poll

One poll plus a detection pass, then exit. Meant for Task Scheduler or cron.

```text
ipswatch-cli poll
```

### import

Import an `eve.json` or syslog capture and analyse it: useful to try IPS Watch without a firewall, or to replay an
incident.

```text
ipswatch-cli import [OPTIONS] <FILE>

Options:
      --quiet  Don't send notifications during replay
```

## Findings

### findings

List findings (open ones by default).

```text
ipswatch-cli findings [OPTIONS]

Options:
      --all            Include acknowledged / false positive
      --min <MIN>      [default: low]    low | medium | high | critical
      --limit <LIMIT>  [default: 50]
```

Each finding prints its **key** (for example `inbound:203.0.113.9` or `compromise:192.168.1.50`), which the next
three commands take.

### ack, fp, reopen

```text
ipswatch-cli ack <KEY>       # acknowledge: seen, comes back if it escalates
ipswatch-cli fp <KEY>        # false positive: stays silent
ipswatch-cli reopen <KEY>    # undo either
```

### rescore

Recompute all findings from stored events with the current rules. Keeps your acknowledged / false-positive marks.
Run it after changing detection settings or ignored SIDs.

```text
ipswatch-cli rescore
```

### report

Write a static HTML report of the findings. It follows the viewer's dark / light preference.

```text
ipswatch-cli report <OUT>
```

## Firewall and DNS checks

### health

Run the firewall health, exposure, device and config checks once and print the result. Findings are created and
resolved as in the app.

```text
ipswatch-cli health
```

### dns

Check the configured DNS servers (Technitium and Unbound) once and print the result.

```text
ipswatch-cli dns [OPTIONS]

Options:
      --no-exposure  Skip the firewall exposure audit (port forwards to the DNS servers)
```

## Firewall changes

These change the firewall or DNS servers. Each one does a **dry run** by default and changes nothing until you add
`--yes`.

### ips-policy

Create, update or remove the "IPS Watch - drop high-risk" policy, which sets the Alert rules of the high-risk
rulesets (`ips_policy.rulesets`) to Drop. See [Drop policy](../opnsense-setup.html#drop-policy).

```text
ipswatch-cli ips-policy [OPTIONS]

Options:
      --apply   Create/update the policy and reload Suricata (requires --yes)
      --remove  Remove the policy and reload Suricata (requires --yes)
      --yes     Confirm --apply / --remove
```

### ips-rulesets

Disable the Suricata rulesets listed in a file (one ruleset filename per line, `#` comments allowed) with a single
reload. Logs to `rulesets-change.log` next to the config.

```text
ipswatch-cli ips-rulesets [OPTIONS] --disable-from <DISABLE_FROM>

Options:
      --disable-from <FILE>       File listing the rulesets to disable
      --yes                       Apply (without it: dry run)
      --retries <RETRIES>         Retry a failed run this many more times (safe: already-disabled
                                  rulesets are skipped) [default: 0]
      --retry-wait <RETRY_WAIT>   Seconds to wait between retries [default: 300]
```

Useful from Task Scheduler for an off-hours change, since a ruleset reload briefly stalls traffic in IPS mode:

```powershell
ipswatch-cli ips-rulesets --disable-from rulesets.txt --yes --retries 3 --retry-wait 300
```

### dns-blocklists

Add or remove blocklist URLs on the Technitium DNS servers (other lists are kept) and download them. Needs a token
allowed to modify Settings. Technitium only.

```text
ipswatch-cli dns-blocklists [OPTIONS]

Options:
      --server <SERVER>  Only this server (name or address); default: all configured
      --add <ADD>        Blocklist URL to add (repeatable)
      --remove <REMOVE>  Blocklist URL to remove (repeatable)
      --verify           Check the configured lists: loaded, and listed domains that resolve
                         publicly are blocked here
      --yes              Apply (without it: dry run)
```

## Diagnostics

Read-only helpers for troubleshooting. Secrets are never printed.

| Command | What it prints |
|---|---|
| `dump-alerts [ROWS]` | Raw alert rows from the firewall API (default 3) |
| `dump-firewall-log [ROWS]` | Raw firewall log rows from the API (default 3) |
| `dump-api <PATH> [--post <JSON>]` | Any firewall API path as JSON, e.g. `diagnostics/interface/get_interface_config` or `unbound/overview/totals/10`. `--post` sends a JSON body (only for `search_*` endpoints). |
| `dump-dns <SERVER> <PATH> [key=value]...` | A Technitium API path from one server, e.g. `dump-dns ns1 dashboard/stats/get type=LastHour` |
