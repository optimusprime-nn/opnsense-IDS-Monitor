//! Minimal OPNsense REST API client.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::config::OpnsenseCfg;

pub struct OPNsense {
    base: String,
    auth: String,
    agent: ureq::Agent,
}

fn quote(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// alias_util add/delete answer {"status": "done"}; anything else (e.g. "failed") is an error.
fn alias_write_ok(v: &Value) -> Result<()> {
    match v.get("status").and_then(Value::as_str) {
        Some("done") => Ok(()),
        Some(other) => bail!("the firewall answered '{other}'{}", v.get("message").and_then(Value::as_str).map(|m| format!(": {m}")).unwrap_or_default()),
        None => bail!("unexpected answer from the firewall: {v}"),
    }
}

/// Alias entries may be listed as "1.2.3.4" or "1.2.3.4/32".
fn same_address(entry: &str, address: &str) -> bool {
    let e = entry.trim();
    e == address || e.strip_suffix("/32").or_else(|| e.strip_suffix("/128")) == Some(address)
}

impl OPNsense {
    pub fn new(cfg: &OpnsenseCfg) -> Result<Self> {
        if cfg.url.trim().is_empty() {
            bail!("The firewall URL is not configured");
        }
        if !cfg.url.trim().starts_with("https://") && !cfg.allow_http {
            bail!("The firewall URL must use https:// (http:// would send the API key and secret unencrypted)");
        }
        let mut tls = native_tls::TlsConnector::builder();
        if !cfg.verify_tls {
            tls.danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true);
        }
        if !cfg.ca_file.trim().is_empty() {
            let pem = std::fs::read(cfg.ca_file.trim()).with_context(|| format!("reading CA file {}", cfg.ca_file))?;
            let cert = native_tls::Certificate::from_pem(&pem)
                .or_else(|_| native_tls::Certificate::from_der(&pem))
                .context("CA file is not a PEM or DER certificate")?;
            tls.add_root_certificate(cert);
        }
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls.build()?))
            .timeout(Duration::from_secs(cfg.timeout_seconds.max(5)))
            .max_idle_connections(0)
            .build();
        Ok(Self {
            base: cfg.url.trim().trim_end_matches('/').to_string(),
            auth: format!("Basic {}", B64.encode(format!("{}:{}", cfg.api_key, cfg.api_secret))),
            agent,
        })
    }

    #[allow(clippy::result_large_err)] // ureq::Error is large by design
    fn req(&self, method: &str, path: &str, body: Option<Value>, query: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}/api/{}", self.base, path.trim_start_matches('/'));
        let mut r = self.agent.request(method, &url).set("Authorization", &self.auth).set("Accept", "application/json");
        for (k, v) in query {
            r = r.query(k, v);
        }
        // Reloading Suricata with a large rule set can take minutes.
        if path.starts_with("ids/service/reconfigure") {
            r = r.timeout(Duration::from_secs(900));
        }
        // Only reads are safe to retry; never repeat a write.
        let read_only = method == "GET" || path.contains("search") || path.contains("query_alerts");
        let send = |r: ureq::Request| match &body {
            Some(b) => r.send_json(b.clone()),
            None => r.call(),
        };
        let resp = match send(r.clone()) {
            // A dropped connection ("Unexpected EOF", reset) is retried once on a fresh one.
            Err(ureq::Error::Transport(t)) if read_only => {
                log::debug!("{method} {path}: {t}; retrying once");
                std::thread::sleep(Duration::from_millis(500));
                send(r)
            }
            other => other,
        };
        let resp = resp.map_err(|e| match e {
            ureq::Error::Status(401, _) => anyhow!("{method} {path}: HTTP 401 - check the API key and secret"),
            ureq::Error::Status(403, _) => anyhow!("{method} {path}: HTTP 403 - the API user lacks the privilege for this page"),
            ureq::Error::Status(code, r) => anyhow!("{method} {path}: HTTP {code} {}", r.status_text()),
            ureq::Error::Transport(t) => anyhow!("{method} {path}: {t}"),
        })?;
        let text = resp.into_string()?;
        if text.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&text).with_context(|| format!("{method} {path}: response is not JSON"))
    }

    /// Raw GET of any API path (diagnostics).
    pub fn get_raw(&self, path: &str) -> Result<Value> {
        self.req("GET", path, None, &[])
    }

    /// Raw POST of a JSON body (searches and, for policy changes, writes).
    pub fn post_raw(&self, path: &str, body: Value) -> Result<Value> {
        self.req("POST", path, Some(body), &[])
    }

    // ---- IDS ------------------------------------------------------------
    /// Newest-first page of Suricata alerts from the current eve log.
    pub fn ids_alerts(&self, page: u32, rows: u32) -> Result<Vec<Value>> {
        let res = self.req(
            "POST",
            "ids/service/query_alerts",
            Some(json!({"current": page, "rowCount": rows, "searchPhrase": "", "fileid": ""})),
            &[],
        )?;
        Ok(res.get("rows").and_then(Value::as_array).cloned().unwrap_or_default())
    }

    pub fn ids_status(&self) -> Result<String> {
        let v = self.req("GET", "ids/service/status", None, &[])?;
        Ok(v.get("status").and_then(Value::as_str).map(String::from).unwrap_or_else(|| v.to_string()))
    }

    /// All addresses configured on the firewall's interfaces (WAN, LAN, VLANs, VPNs...).
    pub fn interface_addresses(&self) -> Result<Vec<std::net::IpAddr>> {
        fn walk(v: &Value, key: &str, out: &mut Vec<std::net::IpAddr>) {
            match v {
                Value::Object(m) => m.iter().for_each(|(k, x)| walk(x, k, out)),
                Value::Array(a) => a.iter().for_each(|x| walk(x, key, out)),
                Value::String(s) if key.starts_with("ipaddr") => {
                    if let Ok(ip) = s.split('%').next().unwrap_or("").parse::<std::net::IpAddr>() {
                        if !ip.is_loopback() && !out.contains(&ip) {
                            out.push(ip);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        walk(&self.req("GET", "diagnostics/interface/get_interface_config", None, &[])?, "", &mut out);
        Ok(out)
    }

    // ---- Firewall log ---------------------------------------------------
    pub fn firewall_log(&self, limit: u32) -> Result<Vec<Value>> {
        let v = self.req("GET", "diagnostics/firewall/log", None, &[("limit", limit.to_string())])?;
        Ok(match v {
            Value::Array(a) => a,
            other => other.get("rows").and_then(Value::as_array).cloned().unwrap_or_default(),
        })
    }

    // ---- Alias management (blocking) ------------------------------------
    /// Add an address to an alias. Succeeds only when the firewall reports success AND the
    /// address is then actually listed in the alias.
    pub fn alias_add(&self, alias: &str, address: &str) -> Result<()> {
        let v = self.req("POST", &format!("firewall/alias_util/add/{}", quote(alias)), Some(json!({"address": address})), &[])?;
        alias_write_ok(&v).with_context(|| format!("adding {address} to alias {alias}"))?;
        if !self.alias_list(alias)?.iter().any(|a| same_address(a, address)) {
            bail!("adding {address} to alias {alias}: the firewall accepted it, but the address is not in the alias");
        }
        Ok(())
    }

    /// Remove an address from an alias, verified the same way.
    pub fn alias_delete(&self, alias: &str, address: &str) -> Result<()> {
        let v = self.req("POST", &format!("firewall/alias_util/delete/{}", quote(alias)), Some(json!({"address": address})), &[])?;
        alias_write_ok(&v).with_context(|| format!("removing {address} from alias {alias}"))?;
        if self.alias_list(alias)?.iter().any(|a| same_address(a, address)) {
            bail!("removing {address} from alias {alias}: the firewall accepted it, but the address is still in the alias");
        }
        Ok(())
    }

    pub fn alias_list(&self, alias: &str) -> Result<Vec<String>> {
        let v = self.req("GET", &format!("firewall/alias_util/list/{}", quote(alias)), None, &[])?;
        Ok(v.get("rows")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().filter_map(|r| r.get("ip").and_then(Value::as_str).map(String::from)).collect())
            .unwrap_or_default())
    }

    /// Human-readable connection check used by the "Test connection" buttons.
    pub fn check(&self, correlate: bool, block_alias: Option<&str>) -> Result<String> {
        let mut lines = vec![format!("IDS service: {}", self.ids_status()?)];
        lines.push(format!("Alert log: OK ({} sample rows)", self.ids_alerts(1, 5)?.len()));
        if correlate {
            lines.push(format!("Firewall log: OK ({} rows)", self.firewall_log(10)?.len()));
        }
        if let Some(a) = block_alias {
            lines.push(format!("Alias '{a}': {} entries", self.alias_list(a)?.len()));
        }
        Ok(lines.join("\n"))
    }
}
