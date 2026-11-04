---
title: Command line (CLI)
nav_order: 5
has_children: true
permalink: /cli/
---

# Command line (CLI)

`ipswatch-cli` uses the same engine as the desktop app. On Windows it reads the same settings file and database
by default, so you can script it alongside the app. It also builds and runs on Linux.

```text
ipswatch-cli [OPTIONS] <COMMAND>

Options:
  -c, --config <CONFIG>  Config file (default: %APPDATA%\ipswatch\config.toml, shared with the desktop app)
  -h, --help             Print help
  -V, --version          Print version
```

| Group | Commands |
|---|---|
| Monitoring | `check`, `check-cert`, `run`, `poll`, `import` |
| Findings | `findings`, `ack`, `fp`, `reopen`, `rescore`, `report` |
| Firewall and DNS checks | `health`, `dns` |
| Firewall changes (dry run first) | `ips-policy`, `ips-rulesets`, `dns-blocklists` |
| Diagnostics | `dump-alerts`, `dump-api`, `dump-firewall-log`, `dump-dns` |

Every command is described on the [Commands](commands.html) page. Settings are edited in `config.toml`;
every key is listed in the [config file reference](config-file.html).

## Quick examples

```powershell
ipswatch-cli check                          # verify API access and IDS status
ipswatch-cli run                            # monitor in the foreground (Ctrl+C to stop)
ipswatch-cli poll                           # one pass, for Task Scheduler / cron
ipswatch-cli import samples\eve-sample.json --quiet
ipswatch-cli findings --min high
ipswatch-cli ack inbound:203.0.113.7        # also: fp, reopen
ipswatch-cli report report.html
ipswatch-cli -c D:\other\config.toml check  # use another settings file
```

## Running unattended

**Windows, Task Scheduler**: create a task that runs `ipswatch-cli.exe poll` every few minutes as your user (so it
can decrypt the DPAPI-protected secrets). Don't run `poll` while the desktop app is monitoring the same database;
use one or the other.

**Linux, systemd**: the repository has `deploy/ipswatch.service`, which runs `ipswatch-cli run` as a service.
Outside Windows there is no DPAPI, so secrets are stored as written: the config is created with mode `0600` in a
`0700` folder, and the service sets `UMask=0077`.

```bash
sudo cp deploy/ipswatch.service /etc/systemd/system/
sudo systemctl enable --now ipswatch
journalctl -u ipswatch -f
```

## Exit status

Commands exit with `0` on success and non-zero on errors (unreachable firewall, invalid config, a refused change),
so they can be used in scripts and scheduled tasks.
