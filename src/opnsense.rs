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

impl OPNsense {
    pub fn new(cfg: &OpnsenseCfg) -> Result<Self> {
        if cfg.url.trim().is_empty() {
            bail!("The firewall URL is not configured");
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
            .build();
        Ok(Self {
            base: cfg.url.trim().trim_end_matches('/').to_string(),
            auth: format!("Basic {}", B64.encode(format!("{}:{}", cfg.api_key, cfg.api_secret))),
            agent,
        })
    }

    fn req(&self, method: &str, path: &str, body: Option<Value>, query: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}/api/{}", self.base, path.trim_start_matches('/'));
        let mut r = self.agent.request(method, &url).set("Authorization", &self.auth).set("Accept", "application/json");
        for (k, v) in query {
            r = r.query(k, v);
        }
        let resp = match body {
            Some(b) => r.send_json(b),
            None => r.call(),
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

    // ---- Firewall log ---------------------------------------------------
    pub fn firewall_log(&self, limit: u32) -> Result<Vec<Value>> {
        let v = self.req("GET", "diagnostics/firewall/log", None, &[("limit", limit.to_string())])?;
        Ok(match v {
            Value::Array(a) => a,
            other => other.get("rows").and_then(Value::as_array).cloned().unwrap_or_default(),
        })
    }

    // ---- Alias management (blocking) ------------------------------------
    pub fn alias_add(&self, alias: &str, address: &str) -> Result<()> {
        self.req("POST", &format!("firewall/alias_util/add/{}", quote(alias)), Some(json!({"address": address})), &[])?;
        Ok(())
    }

    pub fn alias_delete(&self, alias: &str, address: &str) -> Result<()> {
        self.req("POST", &format!("firewall/alias_util/delete/{}", quote(alias)), Some(json!({"address": address})), &[])?;
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
