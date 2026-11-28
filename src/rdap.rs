//! Who an internet address is registered to, asked of the internet registries over RDAP
//! (the free, keyless successor of whois). The question goes from this computer to `rdap.org`,
//! which passes it to the registry that holds the address. Only on a click ("Who owns it?").
//!
//! Only the one address asked about is sent, and only public addresses are asked about.

use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::clean_text;

/// Seconds before a lookup gives up.
pub const TIMEOUT_SECS: u64 = 15;

/// The service that knows which registry holds an address and redirects there.
pub const DEFAULT_BASE: &str = "https://rdap.org";
/// The largest answer read.
const MAX_ANSWER: u64 = 512 * 1024;

/// What a registry says about the network an address is in. Every text is the registry's
/// (in the end the network owner's) own and is cleaned before it is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owner {
    /// The network's name and the registry's handle for it.
    pub name: Option<String>,
    pub handle: Option<String>,
    /// The network's first and last address, or its prefixes.
    pub range: Option<String>,
    pub organisation: Option<String>,
    pub country: Option<String>,
    /// The registry's word for the kind of assignment.
    pub kind: Option<String>,
    /// The AS numbers the network is announced from, where the registry lists them.
    pub origin_as: Option<String>,
    /// Where to report abuse.
    pub abuse: Option<String>,
    /// Dates as the registry writes them, cut to the day.
    pub registered: Option<String>,
    pub changed: Option<String>,
    /// The server that answered.
    pub source: Option<String>,
}

/// Whether an address can be registered to anyone: not private, local, shared or reserved.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (18..20).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            // Global unicast is 2000::/3; 2001:db8::/32 is for documentation.
            (first & 0xe000) == 0x2000 && !(first == 0x2001 && a.segments()[1] == 0x0db8)
        }
    }
}

/// Asks who `ip` is registered to. `base` is [`DEFAULT_BASE`] outside tests.
pub fn lookup(base: &str, ip: IpAddr, timeout: Duration) -> Result<Owner, String> {
    if !is_public(ip) {
        return Err(format!("{ip} is a private or reserved address: it is registered to no one."));
    }
    let tls = native_tls::TlsConnector::builder().min_protocol_version(Some(native_tls::Protocol::Tlsv12)).build().map_err(|e| e.to_string())?;
    let base = base.trim_end_matches('/');
    // The registries are reached by redirect; from an https start none may lead to plain http.
    let agent = ureq::AgentBuilder::new().timeout(timeout).redirects(5).https_only(base.starts_with("https://")).user_agent(concat!("ipswatch/", env!("CARGO_PKG_VERSION"))).tls_connector(Arc::new(tls)).build();
    let resp = match agent.get(&format!("{base}/ip/{ip}")).set("Accept", "application/rdap+json, application/json").call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(404, _)) => return Err(format!("No registry has a record for {ip}.")),
        Err(ureq::Error::Status(429, _)) => return Err("The registry asks for fewer questions; try again in a minute.".to_string()),
        Err(ureq::Error::Status(status, _)) => return Err(format!("The registry answered with an error ({status}).")),
        Err(ureq::Error::Transport(t)) => return Err(format!("The registry could not be reached: {t}")),
    };
    let source = resp.get_url().split("://").nth(1).and_then(|rest| rest.split('/').next()).map(clean_text);
    let mut body = Vec::new();
    resp.into_reader().take(MAX_ANSWER + 1).read_to_end(&mut body).map_err(|e| format!("The answer could not be read: {e}"))?;
    if body.len() as u64 > MAX_ANSWER {
        return Err("The registry's answer is too large to read.".to_string());
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| "The registry's answer could not be read.".to_string())?;
    let mut owner = parse(&v);
    owner.source = source;
    Ok(owner)
}

/// The name the address's own DNS record gives it, asked of this computer's resolver. The
/// registry names who the address block belongs to (often a hosting company); this name is
/// set by whoever runs the machine and often says more (a VPN or CDN provider). It is their
/// claim, not a checked fact.
pub fn reverse_name(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    let name = clean_text(name.trim().trim_end_matches('.'));
    // Without a record the resolver hands the address itself back.
    (!name.is_empty() && name.parse::<IpAddr>().is_err()).then(|| name.chars().take(253).collect())
}

fn text(v: Option<&Value>) -> Option<String> {
    let s = clean_text(v?.as_str()?);
    let s = s.trim();
    (!s.is_empty()).then(|| s.chars().take(200).collect())
}

/// One property of an entity's contact card (`vcardArray`): `fn`, `email`, `org`, ...
fn card(entity: &Value, property: &str) -> Option<String> {
    let rows = entity.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    rows.iter().find_map(|row| {
        let row = row.as_array()?;
        (row.first()?.as_str()? == property).then_some(())?;
        match row.get(3)? {
            // A structured value (an organisation with units): its first part.
            Value::Array(parts) => text(parts.first()),
            value => text(Some(value)),
        }
    })
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity.get("roles").and_then(Value::as_array).is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some(role)))
}

/// The entities of an object with the entities inside them, outer ones first.
fn entities(v: &Value, depth: u8, out: &mut Vec<Value>) {
    let Some(list) = v.get("entities").and_then(Value::as_array) else {
        return;
    };
    for e in list.iter().take(32) {
        out.push(e.clone());
    }
    if depth < 3 {
        for e in list.iter().take(32) {
            entities(e, depth + 1, out);
        }
    }
}

fn day(v: &Value, action: &str) -> Option<String> {
    let event = v.get("events")?.as_array()?.iter().find(|e| e.get("eventAction").and_then(Value::as_str) == Some(action))?;
    text(event.get("eventDate")).map(|date| date.chars().take(10).collect())
}

/// Reads an RDAP "ip network" answer.
pub fn parse(v: &Value) -> Owner {
    let mut all = Vec::new();
    entities(v, 0, &mut all);
    let named = |role: &str| all.iter().filter(|e| has_role(e, role)).find_map(|e| card(e, "org").or_else(|| card(e, "fn")));
    let organisation = named("registrant").or_else(|| named("administrative")).or_else(|| all.iter().filter(|e| !has_role(e, "abuse")).find_map(|e| card(e, "org").or_else(|| card(e, "fn"))));
    let abuse = all.iter().filter(|e| has_role(e, "abuse")).find_map(|e| card(e, "email"));
    let prefixes = v.get("cidr0_cidrs").and_then(Value::as_array).map(|list| {
        list.iter()
            .take(8)
            .filter_map(|c| {
                let prefix = text(c.get("v4prefix")).or_else(|| text(c.get("v6prefix")))?;
                Some(format!("{prefix}/{}", c.get("length")?.as_u64()?))
            })
            .collect::<Vec<_>>()
            .join(", ")
    });
    let range = prefixes.filter(|p| !p.is_empty()).or_else(|| match (text(v.get("startAddress")), text(v.get("endAddress"))) {
        (Some(first), Some(last)) => Some(format!("{first} – {last}")),
        _ => None,
    });
    let origin_as = v.get("arin_originas0_originautnums").and_then(Value::as_array).map(|list| list.iter().take(8).filter_map(Value::as_u64).map(|n| format!("AS{n}")).collect::<Vec<_>>().join(", ")).filter(|a| !a.is_empty());
    Owner {
        name: text(v.get("name")),
        handle: text(v.get("handle")),
        range,
        organisation,
        country: text(v.get("country")),
        kind: text(v.get("type")),
        origin_as,
        abuse,
        registered: day(v, "registration"),
        changed: day(v, "last changed"),
        source: None,
    }
}

impl Owner {
    /// The record as lines to show, the parts the registry did not give left out.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut add = |label: &str, value: &Option<String>| {
            if let Some(v) = value {
                lines.push(format!("{label:<14}{v}"));
            }
        };
        add("Organisation", &self.organisation);
        let network = match (&self.name, &self.handle) {
            (Some(name), Some(handle)) if name != handle => Some(format!("{name} ({handle})")),
            (Some(name), _) => Some(name.clone()),
            (None, handle) => handle.clone(),
        };
        add("Network", &network);
        add("Range", &self.range);
        add("Country", &self.country);
        add("Type", &self.kind);
        add("Announced by", &self.origin_as);
        add("Abuse contact", &self.abuse);
        add("Registered", &self.registered);
        add("Last changed", &self.changed);
        add("Answered by", &self.source);
        if lines.is_empty() {
            lines.push("The registry's record names nothing.".to_string());
        }
        lines
    }
}
