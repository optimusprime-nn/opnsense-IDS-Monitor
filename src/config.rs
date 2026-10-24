//! Configuration (TOML) with defaults, validation and DPAPI-protected secrets.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::winsecret;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 4] = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn from_score(score: i64) -> Severity {
        match score {
            s if s >= 120 => Severity::Critical,
            s if s >= 80 => Severity::High,
            s if s >= 50 => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct OpnsenseCfg {
    pub url: String,
    pub api_key: String,
    pub api_secret: String,
    pub verify_tls: bool,
    pub ca_file: String,
    pub page_size: u32,
    pub max_pages: u32,
    pub timeout_seconds: u64,
}

impl Default for OpnsenseCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            api_key: String::new(),
            api_secret: String::new(),
            verify_tls: true,
            ca_file: String::new(),
            page_size: 500,
            max_pages: 20,
            timeout_seconds: 30,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct SyslogCfg {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    pub protocol: String, // udp | tcp
}

impl Default for SyslogCfg {
    fn default() -> Self {
        Self { enabled: false, bind: "0.0.0.0".into(), port: 5514, protocol: "udp".into() }
    }
}

pub const DEFAULT_SENSITIVE_PORTS: &[u16] =
    &[22, 23, 445, 135, 139, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8443, 9200, 27017];

pub const DEFAULT_COMPROMISE_CATEGORIES: &[&str] = &[
    "A Network Trojan was detected",
    "Successful Administrator Privilege Gain",
    "Successful User Privilege Gain",
    "Attempted Administrator Privilege Gain",
    "Executable code was detected",
    "Malware Command and Control Activity Detected",
    "Information Leak",
    "Large Scale Information Leak",
    "Exploit Kit Activity Detected",
    "Domain Observed Used for C2 Detected",
];

pub const DEFAULT_COMPROMISE_KEYWORDS: &[&str] = &[
    "ET TROJAN", "ET MALWARE", "ET CNC", "ET EXPLOIT", "ET WEB_SERVER WebShell", "C2", "Cobalt Strike",
    "Metasploit", "Meterpreter", "Reverse Shell", "Mimikatz", "ET POLICY PE EXE", "ET ATTACK_RESPONSE",
];

pub const DEFAULT_INFORMATIONAL_PREFIXES: &[&str] = &[
    "OPN_", "ET INFO", "GPL ICMP_INFO", "ET GAMES", "ET CHAT", "GPL CHAT", "ET P2P", "GPL P2P",
];

/// Ports whose "passed" firewall entries are routine and not evidence of access.
pub const DEFAULT_CORRELATE_IGNORE_PORTS: &[u16] = &[53, 67, 68, 123, 137, 138, 1900, 5353, 5355];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct DetectCfg {
    pub internal_networks: Vec<String>,
    pub sensitive_ports: Vec<u16>,
    pub compromise_categories: Vec<String>,
    pub compromise_keywords: Vec<String>,
    pub window_minutes: u32,
    pub repeat_threshold: u32,
    pub scan_hosts_threshold: u32,
    pub scan_ports_threshold: u32,
    pub flag_score: i64,
    pub ignore_sids: Vec<i64>,
    pub ignore_sources: Vec<String>,
    pub renotify_minutes: u32,
    /// Signatures starting with these are shown but never scored (app detection, info rules).
    pub informational_prefixes: Vec<String>,
}

impl Default for DetectCfg {
    fn default() -> Self {
        Self {
            internal_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]
                .map(String::from)
                .to_vec(),
            sensitive_ports: DEFAULT_SENSITIVE_PORTS.to_vec(),
            compromise_categories: DEFAULT_COMPROMISE_CATEGORIES.iter().map(|s| s.to_string()).collect(),
            compromise_keywords: DEFAULT_COMPROMISE_KEYWORDS.iter().map(|s| s.to_string()).collect(),
            window_minutes: 15,
            repeat_threshold: 20,
            scan_hosts_threshold: 10,
            scan_ports_threshold: 15,
            flag_score: 50,
            ignore_sids: vec![],
            ignore_sources: vec![],
            renotify_minutes: 360,
            informational_prefixes: DEFAULT_INFORMATIONAL_PREFIXES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Parsed network lists used by detection.
#[derive(Clone, Debug, Default)]
pub struct Nets {
    internal: Vec<IpNet>,
    ignore: Vec<IpNet>,
    /// The firewall's own interface addresses (auto-detected); treated as internal.
    own: Vec<IpAddr>,
}

impl Nets {
    pub fn with_own(mut self, own: Vec<IpAddr>) -> Self {
        self.own = own;
        self
    }

    pub fn is_internal(&self, ip: &str) -> bool {
        in_nets(ip, &self.internal) || self.is_own(ip)
    }
    /// Trusted sources, plus the firewall's own addresses: traffic *from* them is the firewall
    /// itself or NAT'd / hairpinned client traffic, so it can't be attributed to an attacker or
    /// to one compromised host.
    pub fn is_ignored(&self, ip: &str) -> bool {
        in_nets(ip, &self.ignore) || self.is_own(ip)
    }
    pub fn is_own(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>().is_ok_and(|a| self.own.contains(&a))
    }
}

pub fn parse_nets(list: &[String]) -> Result<Vec<IpNet>> {
    list.iter()
        .map(|s| {
            let s = s.trim();
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .with_context(|| format!("'{s}' is not a valid IP network (CIDR)"))
        })
        .collect()
}

pub fn in_nets(ip: &str, nets: &[IpNet]) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(a) => nets.iter().any(|n| n.contains(&a)),
        Err(_) => false,
    }
}

impl DetectCfg {
    pub fn nets(&self) -> Result<Nets> {
        Ok(Nets { internal: parse_nets(&self.internal_networks)?, ignore: parse_nets(&self.ignore_sources)?, own: vec![] })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct FirewallCfg {
    pub correlate: bool,
    pub log_limit: u32,
    /// Passed connections to these ports don't count as access (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS...).
    pub correlate_ignore_ports: Vec<u16>,
}

impl Default for FirewallCfg {
    fn default() -> Self {
        Self { correlate: true, log_limit: 2000, correlate_ignore_ports: DEFAULT_CORRELATE_IGNORE_PORTS.to_vec() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct NotifyCfg {
    pub min_severity: Severity,
    pub webhook_url: String,
    pub webhook_format: String, // slack | discord | generic
    pub ntfy_url: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_from: String,
    pub smtp_to: Vec<String>,
}

impl Default for NotifyCfg {
    fn default() -> Self {
        Self {
            min_severity: Severity::Medium,
            webhook_url: String::new(),
            webhook_format: "slack".into(),
            ntfy_url: String::new(),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_starttls: true,
            smtp_user: String::new(),
            smtp_password: String::new(),
            smtp_from: String::new(),
            smtp_to: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct BlockCfg {
    pub enabled: bool,
    pub dry_run: bool,
    pub alias: String,
    pub min_severity: Severity,
    pub never_block: Vec<String>,
}

impl Default for BlockCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            alias: "ipswatch_block".into(),
            min_severity: Severity::Critical,
            never_block: vec![],
        }
    }
}

/// Window colour scheme.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the Windows app colour setting.
    System,
    #[default]
    Dark,
    Light,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::Dark, Theme::Light, Theme::System];
    pub fn label(self) -> &'static str {
        match self {
            Theme::System => "Follow Windows",
            Theme::Dark => "Dark",
            Theme::Light => "Light",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct GuiCfg {
    pub theme: Theme,
    pub autostart_monitor: bool,
    pub desktop_alerts: bool,
    pub alert_min_severity: Severity,
    /// Closing the window hides it to the system tray (monitoring keeps running).
    #[serde(alias = "minimize_to_background")]
    pub close_to_tray: bool,
    /// Launch hidden in the tray (used for start-with-Windows).
    pub start_minimized: bool,
    /// Mirrors the HKCU Run registry entry; applied when settings are saved.
    pub start_with_windows: bool,
}

impl Default for GuiCfg {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            autostart_monitor: true,
            desktop_alerts: true,
            alert_min_severity: Severity::High,
            close_to_tray: true,
            start_minimized: false,
            start_with_windows: false,
        }
    }
}

/// Firewall health checks, exposure audit, new devices and config changes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct HealthCfg {
    pub enabled: bool,
    pub interval_minutes: u32,
    pub gateway_loss_pct: f64,
    pub gateway_delay_ms: f64,
    /// Service names (e.g. "eastpect") that may be stopped without an alert.
    pub ignore_services: Vec<String>,
    pub memory_pct: f64,
    pub states_pct: f64,
    pub disk_pct: u32,
    /// Alert when the firewall API has been unreachable this long.
    pub offline_minutes: u32,
    pub exposure_audit: bool,
    pub device_alerts: bool,
    /// After the first device scan, record devices quietly for this long (ARP only shows recently active ones).
    pub device_learning_hours: u32,
    pub config_alerts: bool,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 5,
            gateway_loss_pct: 10.0,
            gateway_delay_ms: 500.0,
            ignore_services: vec![],
            memory_pct: 90.0,
            states_pct: 80.0,
            disk_pct: 85,
            offline_minutes: 5,
            exposure_audit: true,
            device_alerts: true,
            device_learning_hours: 24,
            config_alerts: true,
        }
    }
}

/// CrowdSec (os-crowdsec plugin) integration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct CrowdsecCfg {
    pub enabled: bool,
    /// Alerts whose scenario contains one of these become findings (others are only counted).
    pub finding_scenarios: Vec<String>,
    /// Alert when the firewall bouncer hasn't checked in for this long.
    pub bouncer_stale_minutes: u32,
    /// Add points to IPS findings whose source CrowdSec has banned.
    pub boost_ips: bool,
}

impl Default for CrowdsecCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            finding_scenarios: ["-bf", "bruteforce", "cve-", "exploit", "backdoor"].map(String::from).to_vec(),
            bouncer_stale_minutes: 10,
            boost_ips: true,
        }
    }
}

/// The Drop policy IPS Watch can create on the firewall.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct IpsPolicyCfg {
    /// Ruleset base names (filename without .rules / et_open. prefix) whose Alert rules become Drop.
    pub rulesets: Vec<String>,
}

impl Default for IpsPolicyCfg {
    fn default() -> Self {
        Self { rulesets: crate::ipspolicy::DEFAULT_RULESETS.iter().map(|s| s.to_string()).collect() }
    }
}

/// One Technitium DNS server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct DnsServerCfg {
    pub name: String,
    /// Web console, e.g. http://192.168.1.99:5380
    pub url: String,
    /// API token (Administration > Sessions > Create Token); DPAPI-encrypted on disk.
    pub token: String,
}

impl DnsServerCfg {
    /// Address test queries go to: the console URL's host.
    pub fn host(&self) -> String {
        let u = self.url.trim();
        let rest = u.split_once("://").map(|x| x.1).unwrap_or(u);
        let hostport = rest.split('/').next().unwrap_or("");
        if let Some(v6) = hostport.strip_prefix('[') {
            return v6.split(']').next().unwrap_or("").to_string();
        }
        hostport.rsplit_once(':').map(|x| x.0).unwrap_or(hostport).to_string()
    }
    pub fn label(&self) -> String {
        if self.name.trim().is_empty() { self.host() } else { self.name.trim().to_string() }
    }
}

/// Technitium DNS server monitoring.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct DnsCfg {
    pub enabled: bool,
    pub servers: Vec<DnsServerCfg>,
    pub interval_minutes: u32,
    pub timeout_seconds: u64,
    /// Names looked up on every check (should resolve; tests recursion / forwarders).
    pub test_domains: Vec<String>,
    /// Alert when this share of the last hour's queries failed upstream (SERVFAIL).
    pub servfail_pct: f64,
    /// Alert when blocklists haven't been refreshed for this long.
    pub blocklist_max_age_hours: u32,
    /// A client is unusual above this many queries per hour AND this many times its usual rate.
    pub client_queries_per_hour: u64,
    pub client_spike_factor: f64,
    /// NXDOMAIN answers to one client in one check interval (needs a query-log app).
    pub nxdomain_burst: u64,
    pub change_alerts: bool,
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            servers: vec![],
            interval_minutes: 5,
            timeout_seconds: 10,
            test_domains: ["cloudflare.com", "opnsense.org"].map(String::from).to_vec(),
            servfail_pct: 10.0,
            blocklist_max_age_hours: 48,
            client_queries_per_hour: 3000,
            client_spike_factor: 5.0,
            nxdomain_burst: 200,
            change_alerts: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    pub db_path: String,
    pub poll_seconds: u64,
    pub retention_days: u32,
    pub opnsense: OpnsenseCfg,
    pub syslog: SyslogCfg,
    pub detect: DetectCfg,
    pub firewall: FirewallCfg,
    pub notify: NotifyCfg,
    pub block: BlockCfg,
    pub ips_policy: IpsPolicyCfg,
    pub health: HealthCfg,
    pub crowdsec: CrowdsecCfg,
    pub dns: DnsCfg,
    pub gui: GuiCfg,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "ipswatch.db".into(),
            poll_seconds: 60,
            retention_days: 30,
            opnsense: Default::default(),
            syslog: Default::default(),
            detect: Default::default(),
            firewall: Default::default(),
            notify: Default::default(),
            block: Default::default(),
            ips_policy: Default::default(),
            health: Default::default(),
            crowdsec: Default::default(),
            dns: Default::default(),
            gui: Default::default(),
        }
    }
}

impl Config {
    /// Check everything the user can type; returns a human-readable error.
    pub fn validate(&self) -> Result<()> {
        self.detect.nets()?;
        parse_nets(&self.block.never_block).context("Never block")?;
        if self.poll_seconds < 10 {
            bail!("Poll interval must be at least 10 seconds");
        }
        if !self.opnsense.url.is_empty()
            && !(self.opnsense.url.starts_with("https://") || self.opnsense.url.starts_with("http://"))
        {
            bail!("Firewall URL must start with https:// (or http://)");
        }
        if !matches!(self.syslog.protocol.as_str(), "udp" | "tcp") {
            bail!("Syslog protocol must be udp or tcp");
        }
        if self.block.enabled && self.block.alias.trim().is_empty() {
            bail!("Auto-block needs an alias name");
        }
        if self.opnsense.page_size == 0 || self.opnsense.max_pages == 0 {
            bail!("Page size and max pages must be at least 1");
        }
        for d in &self.dns.servers {
            if !(d.url.starts_with("http://") || d.url.starts_with("https://")) || d.host().is_empty() {
                bail!("DNS server '{}': console URL must look like http://192.168.1.99:5380", d.label());
            }
        }
        Ok(())
    }

    /// Database path; relative paths are resolved against the config file's folder.
    pub fn db_path_for(&self, cfg_path: &Path) -> PathBuf {
        let p = PathBuf::from(&self.db_path);
        if p.is_absolute() {
            p
        } else {
            cfg_path.parent().unwrap_or(Path::new(".")).join(p)
        }
    }
}

/// Default config location: %APPDATA%\ipswatch\config.toml
pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    base.join("ipswatch").join("config.toml")
}

pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    for s in secrets_mut(&mut cfg) {
        *s = winsecret::unprotect(s).context("decrypting a saved secret (was the config made by another Windows user?)")?;
    }
    Ok(cfg)
}

pub fn save(cfg: &Config, path: &Path) -> Result<()> {
    let mut out = cfg.clone();
    for s in secrets_mut(&mut out) {
        *s = winsecret::protect(s)?;
    }
    let body = toml::to_string_pretty(&out)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, format!("# ipswatch configuration (written by IPS Watch {})\n{body}", crate::VERSION))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn secrets_mut(cfg: &mut Config) -> Vec<&mut String> {
    let mut v = vec![&mut cfg.opnsense.api_key, &mut cfg.opnsense.api_secret, &mut cfg.notify.smtp_password];
    v.extend(cfg.dns.servers.iter_mut().map(|d| &mut d.token));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        let mut c = Config::default();
        c.opnsense.api_secret = "s3cr\"et".into();
        c.detect.ignore_sids = vec![1, 2];
        c.dns.servers.push(DnsServerCfg { name: "ns1".into(), url: "http://192.168.1.99:5380".into(), token: "t0kenvalue".into() });
        save(&c, &p).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        #[cfg(windows)]
        assert!(text.contains("dpapi:"), "secret should be encrypted on disk");
        assert!(!text.contains("s3cr"));
        #[cfg(windows)]
        assert!(!text.contains("t0ken"));
        assert_eq!(load(&p).unwrap(), c);
    }

    #[test]
    fn reads_python_era_config() {
        let c: Config = toml::from_str(
            "db_path = \"x.db\"\n[gui]\nminimize_to_background = true\n[notify]\nmin_severity = \"high\"\n",
        )
        .unwrap();
        assert!(c.gui.close_to_tray);
        assert_eq!(c.notify.min_severity, Severity::High);
        assert_eq!(c.poll_seconds, 60);
    }

    #[test]
    fn validation() {
        let mut c = Config::default();
        assert!(c.validate().is_ok());
        c.detect.internal_networks.push("bogus".into());
        assert!(c.validate().unwrap_err().to_string().contains("bogus"));
    }

    #[test]
    fn dns_host() {
        let d = |u: &str| DnsServerCfg { url: u.into(), ..Default::default() }.host();
        assert_eq!(d("http://192.168.1.99:5380"), "192.168.1.99");
        assert_eq!(d("https://ns1.example.com/"), "ns1.example.com");
        assert_eq!(d("http://[fd00::1]:5380"), "fd00::1");
    }
}
