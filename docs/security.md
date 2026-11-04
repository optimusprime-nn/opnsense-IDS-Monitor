---
title: Security and privacy
nav_order: 7
---

# Security and privacy

- **Secrets are encrypted.** On Windows, the firewall API key and secret, SMTP password, DNS tokens and webhook /
  ntfy URLs are stored encrypted with DPAPI, readable only by your Windows account. On Linux the config file is
  created with mode `0600` in a `0700` folder.
- **HTTPS by default.** Firewall and DNS connections must use HTTPS unless you explicitly allow plain HTTP for that
  connection (`opnsense.allow_http`, `dns.allow_http`). Certificates are verified unless you turn that off.
- **Secrets stay out of logs.** Tokens, keys and notification URLs are masked in errors, the activity log and the
  diagnostic `dump-*` commands.
- **Read-only unless you say otherwise.** IPS Watch only reads from the firewall and DNS servers. The exceptions are
  explicit: blocking IPs in the block alias, the Drop policy, and the `ips-rulesets` and `dns-blocklists` commands.
  Each change command does a dry run first and needs confirmation (`--yes` on the CLI).
- **Least privilege.** Give the API user only the pages listed in [OPNsense setup](opnsense-setup.html#api-user).
- **Syslog is treated as untrusted.** Only the firewall's addresses (or the senders you list) are accepted, intake is
  bounded, and syslog-only alerts never trigger auto-block.
- **Blocking has guard rails.** Internal, private and reserved addresses and the never-block list are never blocked;
  auto-block only acts on sources the firewall API reported, and a block counts only once the firewall confirms it.
- **No telemetry.** IPS Watch talks only to your firewall, your DNS servers and the notification services you configure.

Found a security problem? Please open a private
[security advisory](https://github.com/optimusprime-nn/opnsense-IDS-Monitor/security/advisories/new) on GitHub
rather than a public issue.
