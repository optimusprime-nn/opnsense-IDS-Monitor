//! Everything IPS Watch knows about one address, from data it already has: the findings about
//! it, its IPS events, the device the firewall sees at it (ARP / DHCP), what the DNS servers
//! know about it, port forwards to it, and CrowdSec. Nothing here asks the network; the owner
//! lookup ([`crate::rdap`]) is a separate click.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::config::Config;
use crate::crowdsec::{Ban, CsAlert};
use crate::health::{Device, Exposed};
use crate::normalize::Event;
use crate::store::{Finding, Store};

/// Events read for the counts; the newest [`SHOWN_EVENTS`] of them are listed.
const READ_EVENTS: usize = 5000;
pub const SHOWN_EVENTS: usize = 200;

/// What one DNS server knows about the address as a client.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsSeen {
    pub server: String,
    /// The name the server gives the client (its own records or DHCP), if any.
    pub name: String,
    /// Queries in the last hour, and the client's usual number per hour once learned.
    pub queries: u64,
    pub usual: Option<f64>,
    /// NXDOMAIN answers in the window the server reported (possible malware / DGA).
    pub nxdomain: u64,
    pub nx_sample: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HostReport {
    pub ip: String,
    /// Inside the networks set under Detection, or one of the firewall's own addresses.
    pub internal: bool,
    /// Can be registered to anyone (so "Who owns it?" can be asked).
    pub public: bool,
    /// Devices the firewall has seen at this address (newest first): MAC, DHCP name, vendor.
    pub devices: Vec<Device>,
    pub dns: Vec<DnsSeen>,
    pub findings: Vec<Finding>,
    /// Newest first, at most [`SHOWN_EVENTS`].
    pub events: Vec<Event>,
    pub event_total: usize,
    /// True when there were more events than were read for the counts.
    pub events_capped: bool,
    pub as_source: usize,
    pub as_destination: usize,
    pub not_dropped: usize,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
    /// (SID, signature, times), most frequent first.
    pub top_signatures: Vec<(Option<i64>, String, usize)>,
    /// Port forwards and WAN pass rules that reach this address.
    pub exposure: Vec<Exposed>,
    /// When IPS Watch put it in the block alias (the newest such finding), if it did.
    pub blocked_at: Option<String>,
    pub crowdsec_ban: Option<Ban>,
    pub crowdsec_alerts: Vec<CsAlert>,
    pub always_allowed: bool,
}

/// Builds the report for `ip` from the database and the last health and DNS snapshots.
pub fn build(store: &Store, cfg: &Config, health: Option<&crate::health::Snapshot>, dns: Option<&crate::dns::Snapshot>, ip: &str) -> HostReport {
    let ip = ip.trim().to_string();
    let addr = ip.parse::<IpAddr>().ok();
    let internal = cfg.detect.nets().is_ok_and(|n| n.is_internal(&ip));
    let public = addr.is_some_and(crate::rdap::is_public);

    let mut devices: Vec<Device> = store.list_devices(100_000).unwrap_or_default().into_iter().filter(|d| d.ip == ip).collect();
    if let Some(h) = health {
        for d in h.devices.iter().filter(|d| d.ip == ip) {
            if !devices.iter().any(|x| x.mac == d.mac) {
                devices.push(d.clone());
            }
        }
    }
    devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let mut dns_seen = vec![];
    if let Some(snap) = dns {
        for srv in &snap.servers {
            let client = srv.top_clients.iter().find(|c| c.ip == ip);
            let nx = srv.nx_clients.iter().find(|c| c.ip == ip);
            if client.is_none() && nx.is_none() {
                continue;
            }
            dns_seen.push(DnsSeen {
                server: if srv.name.is_empty() { srv.host.clone() } else { srv.name.clone() },
                name: client.map(|c| c.name.clone()).unwrap_or_default(),
                queries: client.map(|c| c.hits).unwrap_or(0),
                usual: client.and_then(|c| c.usual),
                nxdomain: nx.map(|n| n.count).unwrap_or(0),
                nx_sample: nx.map(|n| n.sample.iter().take(5).cloned().collect()).unwrap_or_default(),
            });
        }
    }

    let findings = store.findings_for_ip(&ip).unwrap_or_default();
    let blocked_at = findings.iter().filter(|f| f.subject_ip == ip).filter_map(|f| f.blocked_at.clone()).max();

    let all = store.events_for_ip(&ip, READ_EVENTS).unwrap_or_default();
    let mut sigs: BTreeMap<(Option<i64>, String), usize> = BTreeMap::new();
    for e in &all {
        *sigs.entry((e.sid, e.signature.clone())).or_default() += 1;
    }
    let mut top_signatures: Vec<_> = sigs.into_iter().map(|((sid, sig), n)| (sid, sig, n)).collect();
    top_signatures.sort_by(|a, b| b.2.cmp(&a.2).then(a.1.cmp(&b.1)));
    top_signatures.truncate(10);

    let exposure = health.map(|h| h.exposure.iter().filter(|e| e.target == ip).cloned().collect()).unwrap_or_default();
    let crowdsec_alerts = health.and_then(|h| h.crowdsec.as_ref()).map(|c| c.recent.iter().filter(|a| a.ip == ip).cloned().collect()).unwrap_or_default();

    HostReport {
        internal,
        public,
        devices,
        dns: dns_seen,
        findings,
        event_total: all.len(),
        events_capped: all.len() >= READ_EVENTS,
        as_source: all.iter().filter(|e| e.src_ip == ip).count(),
        as_destination: all.iter().filter(|e| e.dest_ip == ip).count(),
        not_dropped: all.iter().filter(|e| !e.was_dropped()).count(),
        first_event: all.last().map(|e| e.ts.clone()),
        last_event: all.first().map(|e| e.ts.clone()),
        top_signatures,
        events: all.into_iter().take(SHOWN_EVENTS).collect(),
        exposure,
        blocked_at,
        crowdsec_ban: crate::crowdsec::cached_bans(store).remove(&ip),
        crowdsec_alerts,
        always_allowed: cfg.crowdsec.allow.iter().any(|a| a.trim() == ip),
        ip,
    }
}

impl HostReport {
    /// One line on what the address is, e.g. "Internal · printer-01 (HP Inc.)".
    pub fn summary(&self) -> String {
        let mut parts = vec![if self.internal { "Internal".to_string() } else if self.public { "Internet".to_string() } else { "Private / reserved".to_string() }];
        if let Some(d) = self.devices.first() {
            let name = if d.hostname.is_empty() { "unnamed device".to_string() } else { d.hostname.clone() };
            parts.push(if d.vendor.is_empty() { name } else { format!("{name} ({})", d.vendor) });
        } else if let Some(n) = self.dns.iter().find(|d| !d.name.is_empty()) {
            parts.push(n.name.clone());
        }
        parts.join(" · ")
    }

    /// The report as text, for Copy.
    pub fn text(&self) -> String {
        let t = crate::local_time;
        let mut out = vec![format!("Host {}  ({})", self.ip, self.summary())];
        if !self.devices.is_empty() {
            out.push("\nDevice".into());
            for d in &self.devices {
                out.push(format!("  {}  {}  {}  {}  seen {} – {}", d.mac, d.hostname, d.vendor, d.interface, t(&d.first_seen), t(&d.last_seen)));
            }
        }
        if !self.dns.is_empty() {
            out.push("\nDNS".into());
            for d in &self.dns {
                out.push(format!("  {}: {} queries last hour{}{}", d.server, d.queries, if d.name.is_empty() { String::new() } else { format!(" as {}", d.name) }, if d.nxdomain > 0 { format!(", {} NXDOMAIN", d.nxdomain) } else { String::new() }));
            }
        }
        out.push(format!("\nFirewall: {}{}{}",
            self.blocked_at.as_ref().map(|b| format!("blocked by IPS Watch {}", t(b))).unwrap_or_else(|| "not blocked by IPS Watch".into()),
            self.crowdsec_ban.as_ref().map(|b| format!(" · banned by CrowdSec ({}) until {}", b.reason, b.expires)).unwrap_or_default(),
            if self.always_allowed { " · always allowed in CrowdSec" } else { "" }));
        for e in &self.exposure {
            out.push(format!("  {} {} {} via {} ({})", e.target, e.port, e.protocol, e.source, e.interface));
        }
        out.push(format!("\nFindings ({})", self.findings.len()));
        for f in &self.findings {
            out.push(format!("  [{}] {}  ({}, last {})", f.severity.as_str().to_uppercase(), f.title, f.status_label(), t(&f.last_seen)));
        }
        out.push(format!("\nIPS events: {}{} ({} as source, {} as destination, {} not dropped)", self.event_total, if self.events_capped { "+" } else { "" }, self.as_source, self.as_destination, self.not_dropped));
        for (sid, sig, n) in &self.top_signatures {
            out.push(format!("  {n:>5}  [{}] {sig}", sid.map(|s| s.to_string()).unwrap_or_default()));
        }
        out.join("\n")
    }
}
