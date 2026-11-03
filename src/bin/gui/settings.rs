//! Settings editor: every config option, grouped into sections, edited as a draft.

use eframe::egui::{self, ComboBox, DragValue, RichText, TextEdit, Ui};
use ipswatch::config::{Config, Severity, Theme};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Firewall,
    Collection,
    Detection,
    Rules,
    Notifications,
    AutoBlock,
    Health,
    Dns,
    Application,
    Data,
}

impl Section {
    pub const ALL: [Section; 10] = [
        Section::Firewall,
        Section::Collection,
        Section::Detection,
        Section::Rules,
        Section::Notifications,
        Section::AutoBlock,
        Section::Health,
        Section::Dns,
        Section::Application,
        Section::Data,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Section::Firewall => "Firewall connection",
            Section::Collection => "Collection",
            Section::Detection => "Detection",
            Section::Rules => "Signature rules",
            Section::Notifications => "Notifications",
            Section::AutoBlock => "Auto-block",
            Section::Health => "Health checks",
            Section::Dns => "DNS servers",
            Section::Application => "Application",
            Section::Data => "Data & storage",
        }
    }
}

/// Things the settings page asks the app to do.
pub enum Action {
    Save,
    Revert,
    Defaults(Section),
    TestConnection,
    CheckCertificate,
    TestNotify,
    TestDns,
    TestToast,
    PruneNow,
    Rescore,
    DeleteAll,
    OpenDataFolder,
}

/// List-valued fields are edited as text, one item per line (commas also accepted).
#[derive(Clone, PartialEq, Default)]
struct Lists {
    internal: String,
    sensitive_ports: String,
    categories: String,
    keywords: String,
    ignore_sids: String,
    ignore_sources: String,
    informational: String,
    fw_ignore_ports: String,
    policy_rulesets: String,
    ignore_services: String,
    cs_scenarios: String,
    dns_domains: String,
    smtp_to: String,
    never_block: String,
}

pub struct SettingsForm {
    pub draft: Config,
    lists: Lists,
    pub section: Section,
    pub error: Option<String>,
    show_secrets: bool,
    /// The firewall's own addresses as last detected (display only).
    pub own_ips: String,
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")
}

fn split(s: &str, by_comma: bool) -> Vec<String> {
    s.split(|c| c == '\n' || (by_comma && c == ','))
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn nums<T: std::str::FromStr>(s: &str, what: &str) -> Result<Vec<T>, String> {
    split(s, true)
        .iter()
        .map(|x| x.parse::<T>().map_err(|_| format!("{what}: '{x}' is not a valid number")))
        .collect()
}

impl SettingsForm {
    pub fn new(cfg: &Config) -> Self {
        let mut f = SettingsForm { draft: cfg.clone(), lists: Lists::default(), section: Section::Firewall, error: None, show_secrets: false, own_ips: String::new() };
        f.load(cfg);
        f
    }

    pub fn load(&mut self, cfg: &Config) {
        self.draft = cfg.clone();
        let d = &cfg.detect;
        self.lists = Lists {
            internal: join(&d.internal_networks),
            sensitive_ports: join(&d.sensitive_ports),
            categories: join(&d.compromise_categories),
            keywords: join(&d.compromise_keywords),
            ignore_sids: join(&d.ignore_sids),
            ignore_sources: join(&d.ignore_sources),
            smtp_to: join(&cfg.notify.smtp_to),
            never_block: join(&cfg.block.never_block),
            informational: join(&d.informational_prefixes),
            fw_ignore_ports: join(&cfg.firewall.correlate_ignore_ports),
            policy_rulesets: join(&cfg.ips_policy.rulesets),
            ignore_services: join(&cfg.health.ignore_services),
            cs_scenarios: join(&cfg.crowdsec.finding_scenarios),
            dns_domains: join(&cfg.dns.test_domains),
        };
        self.error = None;
    }

    pub fn load_section_defaults(&mut self, s: Section) {
        let def = Config::default();
        let mut c = self.to_config_unchecked();
        match s {
            Section::Firewall => {
                // Keep the address and credentials; reset the knobs.
                let keep = c.opnsense.clone();
                c.opnsense = def.opnsense;
                c.opnsense.url = keep.url;
                c.opnsense.api_key = keep.api_key;
                c.opnsense.api_secret = keep.api_secret;
                c.firewall = def.firewall;
                c.poll_seconds = def.poll_seconds;
            }
            Section::Collection => c.syslog = def.syslog,
            Section::Detection => {
                let rules = (
                    c.detect.compromise_categories.clone(),
                    c.detect.compromise_keywords.clone(),
                    c.detect.informational_prefixes.clone(),
                );
                c.detect = def.detect;
                (c.detect.compromise_categories, c.detect.compromise_keywords, c.detect.informational_prefixes) = rules;
            }
            Section::Rules => {
                c.detect.compromise_categories = def.detect.compromise_categories;
                c.detect.compromise_keywords = def.detect.compromise_keywords;
                c.detect.informational_prefixes = def.detect.informational_prefixes;
                c.ips_policy = def.ips_policy;
            }
            Section::Notifications => c.notify = def.notify,
            Section::AutoBlock => c.block = def.block,
            Section::Health => {
                c.health = def.health;
                c.crowdsec = def.crowdsec;
            }
            Section::Dns => {
                // Keep the servers and their tokens; reset the knobs.
                let servers = std::mem::take(&mut c.dns.servers);
                c.dns = def.dns;
                c.dns.servers = servers;
            }
            Section::Application => c.gui = def.gui,
            Section::Data => {
                c.db_path = def.db_path;
                c.retention_days = def.retention_days;
            }
        }
        let section = self.section;
        self.load(&c);
        self.section = section;
    }

    fn to_config_unchecked(&self) -> Config {
        let mut c = self.draft.clone();
        let l = &self.lists;
        c.detect.internal_networks = split(&l.internal, true);
        c.detect.compromise_categories = split(&l.categories, false);
        c.detect.compromise_keywords = split(&l.keywords, false);
        c.detect.ignore_sources = split(&l.ignore_sources, true);
        c.notify.smtp_to = split(&l.smtp_to, true);
        c.block.never_block = split(&l.never_block, true);
        c.detect.sensitive_ports = nums(&l.sensitive_ports, "").unwrap_or(c.detect.sensitive_ports);
        c.detect.ignore_sids = nums(&l.ignore_sids, "").unwrap_or(c.detect.ignore_sids);
        c.detect.informational_prefixes = split(&l.informational, false);
        c.ips_policy.rulesets = split(&l.policy_rulesets, true);
        c.health.ignore_services = split(&l.ignore_services, true);
        c.crowdsec.finding_scenarios = split(&l.cs_scenarios, true);
        c.dns.test_domains = split(&l.dns_domains, true);
        c.firewall.correlate_ignore_ports = nums(&l.fw_ignore_ports, "").unwrap_or(c.firewall.correlate_ignore_ports);
        c
    }

    /// Parse + validate the draft.
    pub fn to_config(&self) -> Result<Config, String> {
        let mut c = self.to_config_unchecked();
        c.detect.sensitive_ports = nums(&self.lists.sensitive_ports, "Sensitive ports")?;
        c.detect.ignore_sids = nums(&self.lists.ignore_sids, "Ignored signature IDs")?;
        c.firewall.correlate_ignore_ports = nums(&self.lists.fw_ignore_ports, "Ports ignored when correlating")?;
        c.opnsense.url = c.opnsense.url.trim().to_string();
        for d in &mut c.dns.servers {
            d.url = d.url.trim().trim_end_matches('/').to_string();
            d.token = d.token.trim().to_string();
        }
        c.validate().map_err(|e| format!("{e:#}"))?;
        Ok(c)
    }

    pub fn is_dirty(&self, saved: &Config) -> bool {
        self.to_config_unchecked() != *saved || self.to_config().is_err()
    }

    pub fn ui(&mut self, ui: &mut Ui, saved: &Config, db_path: &str, actions: &mut Vec<Action>) {
        let dirty = self.is_dirty(saved);
        egui::TopBottomPanel::bottom("settings_bar").show_inside(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let save = if dirty { RichText::new("Save settings").strong() } else { RichText::new("Save settings") };
                if ui.add_enabled(dirty, egui::Button::new(save)).clicked() {
                    actions.push(Action::Save);
                }
                if ui.add_enabled(dirty, egui::Button::new("Revert")).clicked() {
                    actions.push(Action::Revert);
                }
                if ui.button(format!("Restore defaults for \"{}\"", self.section.title())).clicked() {
                    actions.push(Action::Defaults(self.section));
                }
                if dirty {
                    ui.label(RichText::new("Unsaved changes").color(ui.visuals().warn_fg_color));
                }
                if let Some(e) = &self.error {
                    ui.label(RichText::new(e).color(ui.visuals().error_fg_color));
                }
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("settings_nav").resizable(false).exact_width(190.0).show_inside(ui, |ui| {
            ui.add_space(6.0);
            for s in Section::ALL {
                if ui.selectable_label(self.section == s, s.title()).clicked() {
                    self.section = s;
                }
            }
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                ui.heading(self.section.title());
                ui.add_space(8.0);
                match self.section {
                    Section::Firewall => self.firewall(ui, actions),
                    Section::Collection => self.collection(ui),
                    Section::Detection => self.detection(ui),
                    Section::Rules => self.rules(ui),
                    Section::Notifications => self.notifications(ui, actions),
                    Section::AutoBlock => self.autoblock(ui),
                    Section::Health => self.health(ui),
                    Section::Dns => self.dns(ui, actions),
                    Section::Application => self.application(ui, actions),
                    Section::Data => self.data(ui, db_path, actions),
                }
            });
        });
    }

    fn firewall(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let d = &mut self.draft;
        let show = self.show_secrets;
        grid(ui, "fw", |ui| {
            row(ui, "Firewall URL", "e.g. https://192.168.1.1", |ui| text(ui, &mut d.opnsense.url, 360.0));
            row(ui, "API key", "System > Access > Users > API keys", |ui| {
                ui.add(TextEdit::singleline(&mut d.opnsense.api_key).password(!show).desired_width(360.0));
            });
            row(ui, "API secret", "", |ui| {
                ui.add(TextEdit::singleline(&mut d.opnsense.api_secret).password(!show).desired_width(360.0));
            });
            row(ui, "", "", |ui| {
                ui.checkbox(&mut self.show_secrets, "Show key and secret");
            });
            row(ui, "Verify TLS certificate", "Turn off only for a self-signed cert you can't add a CA for", |ui| {
                ui.checkbox(&mut d.opnsense.verify_tls, "");
            });
            row(ui, "CA certificate file", "Leave empty for Let's Encrypt. Not sure? Click Check certificate (help below)", |ui| {
                text(ui, &mut d.opnsense.ca_file, 260.0);
                if ui.button("Browse...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().add_filter("Certificates", &["crt", "pem", "cer"]).pick_file() {
                        d.opnsense.ca_file = p.display().to_string();
                    }
                }
                if ui.button("Check certificate").clicked() {
                    actions.push(Action::CheckCertificate);
                }
            });
            row(ui, "Request timeout (s)", "", |ui| num(ui, &mut d.opnsense.timeout_seconds, 5..=300));
            row(ui, "Poll interval (s)", "How often to fetch new alerts", |ui| num(ui, &mut d.poll_seconds, 10..=3600));
            row(ui, "Alerts per page", "", |ui| num(ui, &mut d.opnsense.page_size, 10..=5000));
            row(ui, "Max pages per poll", "Upper bound when catching up after downtime", |ui| num(ui, &mut d.opnsense.max_pages, 1..=500));
            row(ui, "Correlate with firewall log", "Flag sources the firewall let through", |ui| {
                ui.checkbox(&mut d.firewall.correlate, "");
            });
            row(ui, "Firewall log rows", "Rows fetched per detection pass", |ui| num(ui, &mut d.firewall.log_limit, 100..=50000));
            row(ui, "Ignore ports when correlating", "Routine services (DNS, DHCP, NTP, NetBIOS...) - passed traffic to these isn't counted", |ui| {
                multi(ui, &mut self.lists.fw_ignore_ports, 2)
            });
        });
        ui.add_space(8.0);
        egui::CollapsingHeader::new("Do I need a CA certificate file? Where do I find it?")
            .default_open(self.draft.opnsense.ca_file.trim().is_empty() && !self.draft.opnsense.url.trim().is_empty())
            .show(ui, |ui| {
                ui.set_max_width(760.0);
                ui.label(RichText::new("Not sure? Click \"Check certificate\" - it looks at the firewall and tells you which case you're in.").strong());
                ui.add_space(6.0);
                ui.label(RichText::new("Let's Encrypt (or another public CA)").strong());
                ui.label("Windows already trusts these. Leave the CA certificate file EMPTY and keep \"Verify TLS certificate\" ticked. \
                          Use the host name the certificate was issued for (e.g. https://fw.example.com) as the Firewall URL, not the IP: \
                          Let's Encrypt can't issue certificates for private IP addresses. That name must resolve to the firewall from this PC; \
                          if it doesn't, add an override in OPNsense under Services > Unbound DNS > Overrides. \
                          You can see if you use Let's Encrypt in OPNsense under Services > ACME Client > Certificates.");
                ui.add_space(6.0);
                ui.label(RichText::new("Self-signed / OPNsense's default certificate").strong());
                ui.label("System > Settings > Administration > SSL Certificate shows which certificate the web GUI uses. \
                          Download its CA from System > Trust > Authorities (download icon). For the default self-signed \
                          \"Web GUI TLS certificate\" there is no CA: download the certificate itself from System > Trust > Certificates. \
                          Download the certificate only - never the private key. Save it somewhere permanent and pick it with Browse.");
                ui.add_space(6.0);
                ui.label(RichText::new("Other options").strong());
                ui.label("Install the certificate into Windows (double-click > Install Certificate > Current User > Trusted Root \
                          Certification Authorities) and leave this field empty. Unticking \"Verify TLS certificate\" also works, \
                          but then the connection (and your API key) isn't protected from interception - use it only to test.");
            });
        ui.add_space(10.0);
        if ui.button("Test firewall connection").clicked() {
            actions.push(Action::TestConnection);
        }
        ui.add_space(6.0);
        if !self.own_ips.is_empty() {
            ui.weak(format!("Firewall's own addresses (auto-detected hourly, treated as internal): {}", self.own_ips));
            ui.add_space(4.0);
        }
        ui.weak("The API key, API secret and SMTP password are encrypted with Windows DPAPI when saved, so only your Windows account can read them.");
    }

    fn collection(&mut self, ui: &mut Ui) {
        let s = &mut self.draft.syslog;
        ui.label("Optional realtime feed: OPNsense System > Settings > Logging > Remote, application \"suricata\". \
                  Requires \"Enable eve syslog output\" in Intrusion Detection. The API poller still runs and fills gaps.");
        ui.add_space(8.0);
        grid(ui, "col", |ui| {
            row(ui, "Enable syslog receiver", "", |ui| {
                ui.checkbox(&mut s.enabled, "");
            });
            row(ui, "Listen address", "0.0.0.0 = all interfaces", |ui| text(ui, &mut s.bind, 160.0));
            row(ui, "Port", "Allow it in Windows Firewall", |ui| num(ui, &mut s.port, 1..=65535));
            row(ui, "Protocol", "", |ui| {
                ComboBox::from_id_salt("proto").selected_text(s.protocol.to_uppercase()).show_ui(ui, |ui| {
                    ui.selectable_value(&mut s.protocol, "udp".to_string(), "UDP");
                    ui.selectable_value(&mut s.protocol, "tcp".to_string(), "TCP");
                });
            });
        });
    }

    fn detection(&mut self, ui: &mut Ui) {
        let d = &mut self.draft.detect;
        let l = &mut self.lists;
        grid(ui, "det", |ui| {
            row(ui, "Internal networks", "One CIDR per line - direction detection depends on it", |ui| multi(ui, &mut l.internal, 4));
            row(ui, "Window (minutes)", "Events are grouped per source within this window", |ui| num(ui, &mut d.window_minutes, 1..=1440));
            row(ui, "Minimum score to flag", "Medium >= 50, high >= 80, critical >= 120", |ui| num(ui, &mut d.flag_score, 1..=500));
            row(ui, "Brute-force threshold", "Alerts from one source in the window", |ui| num(ui, &mut d.repeat_threshold, 2..=10000));
            row(ui, "Sweep threshold", "Distinct internal hosts touched", |ui| num(ui, &mut d.scan_hosts_threshold, 2..=10000));
            row(ui, "Port-scan threshold", "Distinct ports touched", |ui| num(ui, &mut d.scan_ports_threshold, 2..=65535));
            row(ui, "Sensitive ports", "Inbound hits on these add points", |ui| multi(ui, &mut l.sensitive_ports, 3));
            row(ui, "Ignored signature IDs", "Reviewed noisy SIDs", |ui| multi(ui, &mut l.ignore_sids, 3));
            row(ui, "Trusted sources", "CIDRs never flagged (your own scanners)", |ui| multi(ui, &mut l.ignore_sources, 3));
            row(ui, "Re-notify after (minutes)", "Repeat alerts for ongoing activity", |ui| num(ui, &mut d.renotify_minutes, 5..=100000));
        });
    }

    fn rules(&mut self, ui: &mut Ui) {
        ui.label("Alerts matching these mark an attack as an exploit, or an internal host as compromised. \
                  ET / ETPRO EXPLOIT, MALWARE, TROJAN, CNC and similar rule families always count.");
        ui.add_space(8.0);
        grid(ui, "rules", |ui| {
            row(ui, "Informational rules (not scored)", "Signature prefixes shown in IPS events but never flagged - app detection, ET INFO, P2P...", |ui| {
                multi(ui, &mut self.lists.informational, 6)
            });
            row(ui, "Compromise categories", "Exact Suricata classtype text, one per line", |ui| multi(ui, &mut self.lists.categories, 10));
            row(ui, "Drop policy rulesets", "Used by \"Set up Drop policy\": these rulesets' Alert rules become Drop on the firewall", |ui| {
                multi(ui, &mut self.lists.policy_rulesets, 8)
            });
            row(ui, "Signature keywords", "Matched case-insensitively inside the signature", |ui| multi(ui, &mut self.lists.keywords, 10));
        });
    }

    fn notifications(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let n = &mut self.draft.notify;
        let show = self.show_secrets;
        grid(ui, "notif", |ui| {
            row(ui, "Minimum severity", "For webhook / ntfy / email", |ui| severity(ui, "nsev", &mut n.min_severity));
            row(ui, "Webhook URL", "Slack / Discord / Mattermost / generic JSON", |ui| text(ui, &mut n.webhook_url, 380.0));
            row(ui, "Webhook format", "", |ui| {
                ComboBox::from_id_salt("whf").selected_text(n.webhook_format.clone()).show_ui(ui, |ui| {
                    for f in ["slack", "discord", "generic"] {
                        ui.selectable_value(&mut n.webhook_format, f.to_string(), f);
                    }
                });
            });
            row(ui, "ntfy topic URL", "e.g. https://ntfy.sh/your-private-topic", |ui| text(ui, &mut n.ntfy_url, 380.0));
            row(ui, "SMTP server", "", |ui| text(ui, &mut n.smtp_host, 260.0));
            row(ui, "SMTP port", "587 = STARTTLS, 465 = TLS", |ui| num(ui, &mut n.smtp_port, 1..=65535));
            row(ui, "Use STARTTLS", "", |ui| {
                ui.checkbox(&mut n.smtp_starttls, "");
            });
            row(ui, "SMTP user", "", |ui| text(ui, &mut n.smtp_user, 260.0));
            row(ui, "SMTP password", "", |ui| {
                ui.add(TextEdit::singleline(&mut n.smtp_password).password(!show).desired_width(260.0));
            });
            row(ui, "From address", "Defaults to the SMTP user", |ui| text(ui, &mut n.smtp_from, 260.0));
            row(ui, "To addresses", "One per line", |ui| multi(ui, &mut self.lists.smtp_to, 3));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Send test notification").clicked() {
                actions.push(Action::TestNotify);
            }
            ui.weak("Uses the values on this page (saved or not).");
        });
    }

    fn autoblock(&mut self, ui: &mut Ui) {
        let b = &mut self.draft.block;
        ui.label("Adds attacker IPs to a firewall alias. On OPNsense, create a Host(s) alias with this name and a \
                  WAN block rule that uses it. Keep dry run on until you trust the findings.");
        ui.add_space(8.0);
        grid(ui, "blk", |ui| {
            row(ui, "Enable auto-block", "", |ui| {
                ui.checkbox(&mut b.enabled, "");
            });
            row(ui, "Dry run (log only)", "", |ui| {
                ui.checkbox(&mut b.dry_run, "");
            });
            row(ui, "Alias name", "", |ui| text(ui, &mut b.alias, 200.0));
            row(ui, "Minimum severity", "", |ui| severity(ui, "bsev", &mut b.min_severity));
            row(ui, "Never block", "Your own public IPs / VPN egress, one per line", |ui| multi(ui, &mut self.lists.never_block, 3));
        });
        ui.add_space(6.0);
        ui.weak("Internal, private and reserved addresses are never blocked. Manual Block/Unblock on the Findings page uses the same alias.");
    }

    fn health(&mut self, ui: &mut Ui) {
        let h = &mut self.draft.health;
        ui.label("Checks the firewall itself every few minutes while monitoring runs. Problems appear as findings \
                  (and alerts) and clear themselves when they're fixed.");
        ui.add_space(8.0);
        grid(ui, "health", |ui| {
            row(ui, "Enable health checks", "", |ui| {
                ui.checkbox(&mut h.enabled, "");
            });
            row(ui, "Check every (minutes)", "", |ui| num(ui, &mut h.interval_minutes, 1..=120));
            row(ui, "Gateway packet loss alert (%)", "", |ui| {
                ui.add(DragValue::new(&mut h.gateway_loss_pct).range(1.0..=100.0).speed(1.0));
            });
            row(ui, "Gateway latency alert (ms)", "Satellite links are typically 30-80 ms", |ui| {
                ui.add(DragValue::new(&mut h.gateway_delay_ms).range(20.0..=5000.0).speed(5.0));
            });
            row(ui, "Unreachable alert after (minutes)", "When IPS Watch can't reach the firewall API", |ui| num(ui, &mut h.offline_minutes, 1..=1440));
            row(ui, "Memory alert (%)", "ZFS cache is excluded", |ui| {
                ui.add(DragValue::new(&mut h.memory_pct).range(50.0..=100.0).speed(1.0));
            });
            row(ui, "State table alert (%)", "", |ui| {
                ui.add(DragValue::new(&mut h.states_pct).range(10.0..=100.0).speed(1.0));
            });
            row(ui, "Disk alert (%)", "", |ui| num(ui, &mut h.disk_pct, 50..=100));
            row(ui, "Services allowed to be stopped", "Service names, one per line (e.g. eastpect)", |ui| multi(ui, &mut self.lists.ignore_services, 3));
            row(ui, "Exposure audit", "Port forwards, WAN pass rules and inbound passes", |ui| {
                ui.checkbox(&mut h.exposure_audit, "");
            });
            row(ui, "New device alerts", "From the ARP table", |ui| {
                ui.checkbox(&mut h.device_alerts, "");
            });
            row(ui, "Device learning period (hours)", "After the first scan, devices are recorded quietly for this long", |ui| num(ui, &mut h.device_learning_hours, 0..=720));
            row(ui, "Config change alerts", "From the firewall's configuration history", |ui| {
                ui.checkbox(&mut h.config_alerts, "");
            });
        });
        ui.add_space(12.0);
        ui.label(RichText::new("CrowdSec").strong());
        let cs = &mut self.draft.crowdsec;
        grid(ui, "crowdsec", |ui| {
            row(ui, "Read CrowdSec", "Needs the os-crowdsec plugin and the API user allowed to read it", |ui| {
                ui.checkbox(&mut cs.enabled, "");
            });
            row(ui, "Scenarios that raise findings", "Matched inside the scenario name; others are only counted (e.g. port scans)", |ui| {
                multi(ui, &mut self.lists.cs_scenarios, 4)
            });
            row(ui, "Bouncer check-in alert (minutes)", "Bans aren't enforced while the bouncer is away", |ui| num(ui, &mut cs.bouncer_stale_minutes, 2..=1440));
            row(ui, "Boost IPS findings from banned IPs", "+20 points and a \"CrowdSec has banned this IP\" reason", |ui| {
                ui.checkbox(&mut cs.boost_ips, "");
            });
        });
    }

    fn dns(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        ui.label("Watches your Technitium DNS servers: each one answering, upstream failures, blocklists, unusual clients,                   zone and settings changes, and WAN port forwards to them. Results are on the DNS page.");
        ui.add_space(8.0);
        let show = self.show_secrets;
        let d = &mut self.draft.dns;
        let mut remove = None;
        for (i, srv) in d.servers.iter_mut().enumerate() {
            egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
                grid(ui, &format!("dns_srv{i}"), |ui| {
                    row(ui, "Name", "Shown in alerts, e.g. ns1", |ui| {
                        text(ui, &mut srv.name, 160.0);
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                    });
                    row(ui, "Web console URL", "e.g. http://192.168.1.53:5380 - test queries go to this host on port 53", |ui| text(ui, &mut srv.url, 300.0));
                    row(ui, "API token", "Technitium: Administration > Sessions > Create Token (a read-only user is enough)", |ui| {
                        ui.add(TextEdit::singleline(&mut srv.token).password(!show).desired_width(360.0));
                    });
                });
            });
            ui.add_space(4.0);
        }
        if let Some(i) = remove {
            d.servers.remove(i);
        }
        ui.horizontal(|ui| {
            if ui.button("Add DNS server").clicked() {
                d.servers.push(Default::default());
            }
            ui.checkbox(&mut self.show_secrets, "Show tokens");
        });
        ui.add_space(10.0);
        grid(ui, "dns", |ui| {
            row(ui, "Monitor DNS servers", "", |ui| {
                ui.checkbox(&mut d.enabled, "");
            });
            row(ui, "Check every (minutes)", "", |ui| num(ui, &mut d.interval_minutes, 1..=120));
            row(ui, "Request timeout (s)", "", |ui| num(ui, &mut d.timeout_seconds, 2..=120));
            row(ui, "Test lookups", "Names asked of every server on each check; they must resolve", |ui| multi(ui, &mut self.lists.dns_domains, 2));
            row(ui, "Upstream failure alert (%)", "SERVFAIL share of the last hour's queries", |ui| {
                ui.add(DragValue::new(&mut d.servfail_pct).range(0.5..=100.0).speed(0.5));
            });
            row(ui, "Blocklist age alert (hours)", "", |ui| num(ui, &mut d.blocklist_max_age_hours, 1..=2160));
            row(ui, "Busy client threshold (queries/hour)", "Below this a client is never unusual", |ui| num(ui, &mut d.client_queries_per_hour, 100..=1_000_000));
            row(ui, "Busy client factor", "... and it must be this many times its usual hourly rate", |ui| {
                ui.add(DragValue::new(&mut d.client_spike_factor).range(1.5..=100.0).speed(0.5));
            });
            row(ui, "NXDOMAIN burst (per client per check)", "Many lookups of names that don't exist = possible malware (DGA). Needs a query-log app in Technitium", |ui| {
                num(ui, &mut d.nxdomain_burst, 10..=100_000)
            });
            row(ui, "Zone / settings change alerts", "", |ui| {
                ui.checkbox(&mut d.change_alerts, "");
            });
        });
        ui.add_space(10.0);
        if ui.button("Test DNS servers").on_hover_text("Uses the values above, saved or not").clicked() {
            actions.push(Action::TestDns);
        }
        ui.add_space(6.0);
        ui.weak("Tokens are encrypted with Windows DPAPI when saved, like the firewall API key. IPS Watch only reads from the DNS servers.");
    }

    fn application(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let g = &mut self.draft.gui;
        grid(ui, "app", |ui| {
            row(ui, "Theme", "Previews immediately; Save to keep it", |ui| {
                ComboBox::from_id_salt("theme").selected_text(g.theme.label()).show_ui(ui, |ui| {
                    for t in Theme::ALL {
                        ui.selectable_value(&mut g.theme, t, t.label());
                    }
                });
            });
            row(ui, "Start with Windows", "Launches hidden in the tray when you sign in", |ui| {
                ui.checkbox(&mut g.start_with_windows, "");
            });
            row(ui, "Start minimized to tray", "Also applies when launched manually", |ui| {
                ui.checkbox(&mut g.start_minimized, "");
            });
            row(ui, "Close button hides to tray", "Monitoring keeps running; use Quit to exit", |ui| {
                ui.checkbox(&mut g.close_to_tray, "");
            });
            row(ui, "Start monitoring on launch", "", |ui| {
                ui.checkbox(&mut g.autostart_monitor, "");
            });
            row(ui, "Desktop notifications", "Windows toast for new findings", |ui| {
                ui.checkbox(&mut g.desktop_alerts, "");
            });
            row(ui, "Desktop alert minimum severity", "", |ui| severity(ui, "gsev", &mut g.alert_min_severity));
        });
        ui.add_space(10.0);
        if ui.button("Show a test desktop notification").clicked() {
            actions.push(Action::TestToast);
        }
        ui.add_space(6.0);
        let reg = if ipswatch::autostart::is_enabled() { "enabled" } else { "not enabled" };
        ui.weak(format!("Start with Windows is currently {reg} (HKCU\\...\\CurrentVersion\\Run). Changes apply when you save."));
    }

    fn data(&mut self, ui: &mut Ui, db_path: &str, actions: &mut Vec<Action>) {
        let d = &mut self.draft;
        grid(ui, "data", |ui| {
            row(ui, "Database file", "Relative to the settings folder; takes effect after restart", |ui| text(ui, &mut d.db_path, 320.0));
            row(ui, "Keep events for (days)", "Findings are kept until you delete them", |ui| num(ui, &mut d.retention_days, 1..=3650));
        });
        ui.add_space(8.0);
        ui.label(format!("Database in use: {db_path}"));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Open data folder").clicked() {
                actions.push(Action::OpenDataFolder);
            }
            if ui.button("Re-score all findings").on_hover_text("Recompute findings from stored events with the current rules. Keeps your acknowledged / false-positive marks.").clicked() {
                actions.push(Action::Rescore);
            }
            if ui.button("Delete old events now").clicked() {
                actions.push(Action::PruneNow);
            }
            if ui.button(RichText::new("Delete all events and findings...").color(ui.visuals().error_fg_color)).clicked() {
                actions.push(Action::DeleteAll);
            }
        });
    }
}

// ---- small form helpers ----------------------------------------------------
fn grid(ui: &mut Ui, id: &str, add: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id).num_columns(2).spacing([18.0, 10.0]).min_col_width(200.0).show(ui, add);
}

fn row(ui: &mut Ui, label: &str, hint: &str, add: impl FnOnce(&mut Ui)) {
    ui.label(label);
    ui.vertical(|ui| {
        ui.horizontal(add);
        if !hint.is_empty() {
            ui.weak(hint);
        }
    });
    ui.end_row();
}

fn text(ui: &mut Ui, s: &mut String, w: f32) {
    ui.add(TextEdit::singleline(s).desired_width(w));
}

fn multi(ui: &mut Ui, s: &mut String, rows: usize) {
    ui.add(TextEdit::multiline(s).desired_rows(rows).desired_width(380.0).font(egui::TextStyle::Monospace));
}

fn num<N: egui::emath::Numeric>(ui: &mut Ui, v: &mut N, range: std::ops::RangeInclusive<N>) {
    ui.add(DragValue::new(v).range(range).speed(1.0));
}

fn severity(ui: &mut Ui, id: &str, v: &mut Severity) {
    ComboBox::from_id_salt(id).selected_text(v.as_str()).show_ui(ui, |ui| {
        for s in Severity::ALL {
            ui.selectable_value(v, s, s.as_str());
        }
    });
}
