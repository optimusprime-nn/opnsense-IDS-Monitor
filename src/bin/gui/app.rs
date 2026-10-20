//! Main window.

use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use ipswatch::config::{self, Severity};
use ipswatch::normalize::Event;
use ipswatch::opnsense::OPNsense;
use ipswatch::store::Finding;
use ipswatch::{autostart, collect, engine, logbuf, notify, report, toast};

use crate::settings::{self, SettingsForm};
use crate::tray::Tray;
use crate::Controller;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Findings,
    Events,
    Log,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusFilter {
    Open,
    All,
    Ack,
    FalsePositive,
}

impl StatusFilter {
    fn label(self) -> &'static str {
        match self {
            StatusFilter::Open => "Open",
            StatusFilter::All => "All",
            StatusFilter::Ack => "Acknowledged",
            StatusFilter::FalsePositive => "False positive",
        }
    }
    fn db(self) -> Option<&'static str> {
        match self {
            StatusFilter::Open => Some("open"),
            StatusFilter::All => None,
            StatusFilter::Ack => Some("ack"),
            StatusFilter::FalsePositive => Some("false_positive"),
        }
    }
}

/// Results of background jobs, delivered to the UI thread.
enum Bg {
    Message { title: String, text: String, error: bool },
    Reload,
}

pub fn sev_color(s: Severity, dark: bool) -> Color32 {
    match (s, dark) {
        (Severity::Critical, false) => Color32::from_rgb(0xb4, 0x23, 0x18),
        (Severity::Critical, true) => Color32::from_rgb(0xff, 0x6b, 0x5e),
        (Severity::High, false) => Color32::from_rgb(0xc4, 0x32, 0x0a),
        (Severity::High, true) => Color32::from_rgb(0xff, 0x9a, 0x5c),
        (Severity::Medium, false) => Color32::from_rgb(0xa1, 0x5c, 0x07),
        (Severity::Medium, true) => Color32::from_rgb(0xf5, 0xc0, 0x4a),
        (Severity::Low, false) => Color32::from_rgb(0x47, 0x54, 0x67),
        (Severity::Low, true) => Color32::from_rgb(0xa0, 0xaa, 0xba),
    }
}

pub struct App {
    ctl: Arc<Controller>,
    tray: Option<Tray>,
    tab: Tab,
    // findings
    f_status: StatusFilter,
    f_min: Severity,
    f_search: String,
    findings: Vec<Finding>,
    selected: Option<String>,
    counts: [usize; 4],
    events_24h: i64,
    // events
    e_search: String,
    events: Vec<Event>,
    // bookkeeping
    loaded_version: u64,
    last_reload: Instant,
    settings: SettingsForm,
    db_path: String,
    bg_tx: Sender<Bg>,
    bg_rx: Receiver<Bg>,
    message: Option<(String, String, bool)>,
    about: bool,
    log_follow: bool,
    tray_hint_shown: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, ctl: Arc<Controller>, cfg_error: Option<String>) -> Self {
        let cfg = ctl.cfg();
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        cc.egui_ctx.set_style(style);

        let tray = match Tray::new(ctl.clone()) {
            Ok(t) => Some(t),
            Err(e) => {
                log::error!("system tray unavailable: {e:#}");
                ctl.show_window(); // never leave the app hidden without a tray icon
                None
            }
        };
        let (bg_tx, bg_rx) = channel();
        let db_path = cfg.db_path_for(&ctl.cfg_path).display().to_string();
        let first_run = cfg.opnsense.url.is_empty() && !cfg.syslog.enabled;
        let mut app = App {
            settings: SettingsForm::new(&cfg),
            tray,
            tab: if first_run { Tab::Settings } else { Tab::Findings },
            f_status: StatusFilter::Open,
            f_min: Severity::Low,
            f_search: String::new(),
            findings: vec![],
            selected: None,
            counts: [0; 4],
            events_24h: 0,
            e_search: String::new(),
            events: vec![],
            loaded_version: 0,
            last_reload: Instant::now(),
            db_path,
            bg_tx,
            bg_rx,
            message: cfg_error.map(|e| ("Settings could not be read".to_string(), format!("{e}\n\nDefaults are in use until you save."), true)),
            about: false,
            log_follow: true,
            tray_hint_shown: ctl.shared.store.get_kv("tray_hint_shown").ok().flatten().is_some(),
            ctl,
        };
        if first_run && app.message.is_none() {
            app.message = Some((
                "Welcome to IPS Watch".into(),
                "Enter your OPNsense firewall URL and API key/secret here, click \"Test firewall connection\", then Save.\n\n\
                 You can also try it offline with File > Import eve.json."
                    .into(),
                false,
            ));
        }
        // --tab findings|events|log|settings[:section] opens a specific page.
        if let Some(t) = std::env::args().skip_while(|a| a != "--tab").nth(1) {
            let (page, section) = t.split_once(':').unwrap_or((&t, ""));
            app.tab = match page {
                "events" => Tab::Events,
                "log" => Tab::Log,
                "settings" => Tab::Settings,
                _ => Tab::Findings,
            };
            if let Some(s) = settings::Section::ALL.into_iter().find(|s| format!("{s:?}").eq_ignore_ascii_case(section)) {
                app.settings.section = s;
            }
        }
        if cfg.gui.autostart_monitor && !first_run {
            app.ctl.start();
        }
        app.reload();
        app
    }

    // ---- data -----------------------------------------------------------
    fn reload(&mut self) {
        let store = &self.ctl.shared.store;
        let mut rows = store.list_findings(self.f_status.db(), self.f_min, 1000).unwrap_or_default();
        let needle = self.f_search.trim().to_lowercase();
        if !needle.is_empty() {
            rows.retain(|f| {
                f.subject_ip.contains(&needle)
                    || f.title.to_lowercase().contains(&needle)
                    || f.signatures.iter().any(|s| s.to_lowercase().contains(&needle))
            });
        }
        self.findings = rows;
        if self.selected.is_none() {
            self.selected = self.findings.first().map(|f| f.key.clone());
        }
        let open = store.list_findings(Some("open"), Severity::Low, 100_000).unwrap_or_default();
        self.counts = [0; 4];
        for f in &open {
            self.counts[f.severity as usize] += 1;
        }
        let since = ipswatch::iso(chrono::Utc::now() - chrono::Duration::hours(24));
        self.events_24h = store.event_count_since(&since).unwrap_or(0);
        self.events = store.recent_events(2000, &self.e_search).unwrap_or_default();
        self.loaded_version = self.ctl.shared.data_version.load(Ordering::Relaxed);
        self.last_reload = Instant::now();
        let running = self.ctl.is_running();
        let high = self.counts[Severity::High as usize] + self.counts[Severity::Critical as usize];
        if let Some(t) = &mut self.tray {
            t.update(running, high, open.len());
        }
    }

    fn selected_finding(&self) -> Option<&Finding> {
        let key = self.selected.as_ref()?;
        self.findings.iter().find(|f| &f.key == key)
    }

    fn set_status(&mut self, status: &str) {
        if let Some(k) = self.selected.clone() {
            let _ = self.ctl.shared.store.set_status(&k, status);
            self.reload();
            self.selected = Some(k);
        }
    }

    fn message(&mut self, title: &str, text: impl Into<String>, error: bool) {
        self.message = Some((title.to_string(), text.into(), error));
    }

    fn spawn(&self, f: impl FnOnce() -> Bg + Send + 'static) {
        let tx = self.bg_tx.clone();
        let ctx = self.ctl.ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    // ---- actions --------------------------------------------------------
    fn import(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import Suricata eve.json")
            .add_filter("EVE JSON / logs", &["json", "log", "txt"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        let shared = self.ctl.shared.clone();
        self.spawn(move || {
            let cfg = shared.cfg.read().unwrap_or_else(|e| e.into_inner()).clone();
            match collect::import_file(&path, &shared.store).and_then(|n| engine::replay(&cfg, &shared.store, false).map(|_| n)) {
                Ok(n) => {
                    shared.bump();
                    log::info!("Imported {n} new events from {}", path.display());
                    Bg::Message { title: "Import".into(), text: format!("Imported {n} new events from\n{}", path.display()), error: false }
                }
                Err(e) => Bg::Message { title: "Import failed".into(), text: format!("{e:#}"), error: true },
            }
        });
    }

    fn export(&mut self) {
        let name = format!("ipswatch-report-{}.html", chrono::Local::now().format("%Y%m%d"));
        if let Some(path) = rfd::FileDialog::new().add_filter("HTML", &["html"]).set_file_name(name).save_file() {
            match report::write_html(&self.ctl.shared.store, &path) {
                Ok(n) => {
                    log::info!("Report with {n} findings written to {}", path.display());
                    let _ = open::that(&path);
                }
                Err(e) => self.message("Export failed", format!("{e:#}"), true),
            }
        }
    }

    fn block(&mut self, unblock: bool) {
        let Some(f) = self.selected_finding().cloned() else { return };
        let cfg = self.ctl.cfg();
        if cfg.opnsense.url.is_empty() {
            self.message("Block", "Configure the firewall connection in Settings first.", true);
            return;
        }
        if !unblock {
            if let Err(why) = engine::blockable(&cfg, &f.subject_ip) {
                self.message("Block", format!("Not blocking: {why}.\nFor an internal host, isolate it instead."), true);
                return;
            }
        }
        let verb = if unblock { "Remove" } else { "Add" };
        let prep = if unblock { "from" } else { "to" };
        let yes = rfd::MessageDialog::new()
            .set_title(if unblock { "Unblock IP" } else { "Block IP" })
            .set_description(format!(
                "{verb} {} {prep} firewall alias '{}'?\n\nThis only blocks traffic if a WAN rule uses that alias.",
                f.subject_ip, cfg.block.alias
            ))
            .set_buttons(rfd::MessageButtons::YesNo)
            .show();
        if yes != rfd::MessageDialogResult::Yes {
            return;
        }
        let shared = self.ctl.shared.clone();
        self.spawn(move || {
            let r = OPNsense::new(&cfg.opnsense).and_then(|api| {
                if unblock {
                    api.alias_delete(&cfg.block.alias, &f.subject_ip)
                } else {
                    api.alias_add(&cfg.block.alias, &f.subject_ip)
                }
            });
            match r {
                Ok(()) => {
                    let now = ipswatch::now_iso();
                    let _ = shared.store.set_blocked(&f.key, if unblock { None } else { Some(&now) });
                    log::warn!("{} {} via alias {}", if unblock { "Unblocked" } else { "Blocked" }, f.subject_ip, cfg.block.alias);
                    shared.bump();
                    Bg::Reload
                }
                Err(e) => Bg::Message { title: "Firewall".into(), text: format!("{e:#}"), error: true },
            }
        });
    }

    fn handle_settings(&mut self, actions: Vec<settings::Action>) {
        for a in actions {
            match a {
                settings::Action::Save => self.save_settings(),
                settings::Action::Revert => {
                    let c = self.ctl.cfg();
                    let section = self.settings.section;
                    self.settings.load(&c);
                    self.settings.section = section;
                }
                settings::Action::Defaults(s) => self.settings.load_section_defaults(s),
                settings::Action::TestConnection => match self.settings.to_config() {
                    Err(e) => self.message("Test connection", e, true),
                    Ok(cfg) => self.spawn(move || {
                        let alias = cfg.block.enabled.then_some(cfg.block.alias.as_str());
                        match OPNsense::new(&cfg.opnsense).and_then(|a| a.check(cfg.firewall.correlate, alias)) {
                            Ok(t) => Bg::Message { title: "Connection OK".into(), text: t, error: false },
                            Err(e) => Bg::Message { title: "Connection failed".into(), text: format!("{e:#}"), error: true },
                        }
                    }),
                },
                settings::Action::TestNotify => match self.settings.to_config() {
                    Err(e) => self.message("Test notification", e, true),
                    Ok(cfg) => self.spawn(move || {
                        let res = notify::send_test(&cfg.notify);
                        if res.is_empty() {
                            return Bg::Message {
                                title: "Test notification".into(),
                                text: "No webhook, ntfy or email channel is configured.".into(),
                                error: true,
                            };
                        }
                        let error = res.iter().any(|r| r.1.is_err());
                        let text = res
                            .into_iter()
                            .map(|(n, r)| match r {
                                Ok(()) => format!("{n}: sent"),
                                Err(e) => format!("{n}: FAILED - {e:#}"),
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        Bg::Message { title: "Test notification".into(), text, error }
                    }),
                },
                settings::Action::TestToast => toast::show(&notify::sample_finding()),
                settings::Action::PruneNow => {
                    let cfg = self.ctl.cfg();
                    match engine::prune(&cfg, &self.ctl.shared.store) {
                        Ok(n) => self.message("Data", format!("Deleted {n} events older than {} days.", cfg.retention_days), false),
                        Err(e) => self.message("Data", format!("{e:#}"), true),
                    }
                    self.reload();
                }
                settings::Action::DeleteAll => {
                    let yes = rfd::MessageDialog::new()
                        .set_title("Delete all data")
                        .set_description("Delete ALL stored IPS events and findings? This cannot be undone.")
                        .set_level(rfd::MessageLevel::Warning)
                        .set_buttons(rfd::MessageButtons::YesNo)
                        .show();
                    if yes == rfd::MessageDialogResult::Yes {
                        match self.ctl.shared.store.delete_all() {
                            Ok(()) => log::warn!("All events and findings deleted"),
                            Err(e) => self.message("Data", format!("{e:#}"), true),
                        }
                        self.selected = None;
                        self.reload();
                    }
                }
                settings::Action::OpenDataFolder => {
                    if let Some(dir) = self.ctl.cfg_path.parent() {
                        let _ = open::that(dir);
                    }
                }
            }
        }
    }

    fn save_settings(&mut self) {
        let new = match self.settings.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.settings.error = Some(e);
                return;
            }
        };
        let old = self.ctl.cfg();
        if let Err(e) = config::save(&new, &self.ctl.cfg_path) {
            self.settings.error = Some(format!("Could not save: {e:#}"));
            return;
        }
        if new.gui.start_with_windows != autostart::is_enabled() {
            if let Err(e) = autostart::set_enabled(new.gui.start_with_windows) {
                self.message("Start with Windows", format!("Settings saved, but the startup entry could not be changed:\n{e:#}"), true);
            }
        }
        *self.ctl.shared.cfg.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
        self.settings.load(&new);
        self.settings.error = None;
        log::info!("Settings saved");
        let collection_changed = new.opnsense != old.opnsense
            || new.syslog != old.syslog
            || new.poll_seconds != old.poll_seconds
            || new.detect != old.detect
            || new.firewall != old.firewall
            || new.notify != old.notify
            || new.block != old.block
            || new.retention_days != old.retention_days;
        if collection_changed && self.ctl.is_running() {
            log::info!("Restarting monitoring with the new settings");
            self.ctl.restart_if_running();
        }
        if new.db_path != old.db_path {
            self.message("Database location changed", "Restart IPS Watch to use the new database file.", false);
        }
        if (old.opnsense.url.is_empty() && !old.syslog.enabled) && (!new.opnsense.url.is_empty() || new.syslog.enabled)
            && new.gui.autostart_monitor
        {
            self.ctl.start();
        }
        self.reload();
    }

    // ---- views ----------------------------------------------------------
    fn menu_bar(&mut self, ui: &mut Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Import eve.json...").clicked() {
                    ui.close_menu();
                    self.import();
                }
                if ui.button("Export HTML report...").clicked() {
                    ui.close_menu();
                    self.export();
                }
                if ui.button("Open data folder").clicked() {
                    ui.close_menu();
                    if let Some(d) = self.ctl.cfg_path.parent() {
                        let _ = open::that(d);
                    }
                }
                ui.separator();
                if self.tray.is_some() && ui.button("Hide to tray").clicked() {
                    ui.close_menu();
                    self.ctl.hide_window();
                }
                if ui.button("Quit").clicked() {
                    self.ctl.quit();
                }
            });
            ui.menu_button("Monitor", |ui| {
                let running = self.ctl.is_running();
                if ui.button(if running { "Stop monitoring" } else { "Start monitoring" }).clicked() {
                    ui.close_menu();
                    self.ctl.toggle();
                }
                if ui.button("Poll now").clicked() {
                    ui.close_menu();
                    self.ctl.poll_now();
                }
            });
            ui.menu_button("View", |ui| {
                for (t, l) in [(Tab::Findings, "Findings"), (Tab::Events, "IPS events"), (Tab::Log, "Activity log")] {
                    if ui.selectable_label(self.tab == t, l).clicked() {
                        ui.close_menu();
                        self.tab = t;
                    }
                }
            });
            ui.menu_button("Settings", |ui| {
                for s in settings::Section::ALL {
                    if ui.button(format!("{}...", s.title())).clicked() {
                        ui.close_menu();
                        self.tab = Tab::Settings;
                        self.settings.section = s;
                    }
                }
                ui.separator();
                // Quick toggles that save immediately.
                let mut cfg = self.ctl.cfg();
                let mut changed = false;
                let mut sw = autostart::is_enabled();
                if ui.checkbox(&mut sw, "Start with Windows").changed() {
                    match autostart::set_enabled(sw) {
                        Ok(()) => {
                            cfg.gui.start_with_windows = sw;
                            changed = true;
                        }
                        Err(e) => self.message("Start with Windows", format!("{e:#}"), true),
                    }
                }
                changed |= ui.checkbox(&mut cfg.gui.start_minimized, "Start minimized to tray").changed();
                changed |= ui.checkbox(&mut cfg.gui.close_to_tray, "Close button hides to tray").changed();
                changed |= ui.checkbox(&mut cfg.gui.desktop_alerts, "Desktop notifications").changed();
                changed |= ui.checkbox(&mut cfg.gui.autostart_monitor, "Start monitoring on launch").changed();
                if changed {
                    match config::save(&cfg, &self.ctl.cfg_path) {
                        Ok(()) => {
                            // Keep any unsaved edits on the settings page, but sync these toggles.
                            self.settings.draft.gui = cfg.gui.clone();
                            *self.ctl.shared.cfg.write().unwrap_or_else(|e| e.into_inner()) = cfg;
                        }
                        Err(e) => self.message("Settings", format!("{e:#}"), true),
                    }
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("About IPS Watch").clicked() {
                    ui.close_menu();
                    self.about = true;
                }
                if ui.button("Open log file").clicked() {
                    ui.close_menu();
                    let _ = open::that(self.ctl.cfg_path.with_file_name("ipswatch.log"));
                }
            });
        });
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        let st = self.ctl.shared.status();
        let running = self.ctl.is_running();
        ui.horizontal(|ui| {
            let label = if running { "Stop monitoring" } else { "Start monitoring" };
            if ui.button(RichText::new(label).strong()).clicked() {
                self.ctl.toggle();
            }
            if ui.button("Poll now").clicked() {
                self.ctl.poll_now();
            }
            ui.separator();
            for (t, l) in [(Tab::Findings, "Findings"), (Tab::Events, "IPS events"), (Tab::Log, "Activity log"), (Tab::Settings, "Settings")] {
                if ui.selectable_label(self.tab == t, RichText::new(l).size(15.0)).clicked() {
                    self.tab = t;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let dark = ui.visuals().dark_mode;
                let (txt, col) = match (running, &st.last_error) {
                    (true, Some(_)) => ("Monitoring (errors)", sev_color(Severity::Critical, dark)),
                    (true, None) => ("Monitoring", Color32::from_rgb(0x12, 0x9a, 0x50)),
                    (false, _) => ("Stopped", ui.visuals().weak_text_color()),
                };
                ui.label(RichText::new(txt).strong().color(col));
            });
        });
    }

    fn findings_view(&mut self, ui: &mut Ui) {
        let dark = ui.visuals().dark_mode;
        // Summary cards
        ui.horizontal(|ui| {
            for s in Severity::ALL.iter().rev() {
                card(ui, &self.counts[*s as usize].to_string(), &format!("open {}", s.as_str()), sev_color(*s, dark));
            }
            card(ui, &self.events_24h.to_string(), "IPS events, last 24h", ui.visuals().strong_text_color());
        });
        ui.add_space(4.0);
        // Filters + actions
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label("Show");
            egui::ComboBox::from_id_salt("fstatus").selected_text(self.f_status.label()).show_ui(ui, |ui| {
                for s in [StatusFilter::Open, StatusFilter::All, StatusFilter::Ack, StatusFilter::FalsePositive] {
                    changed |= ui.selectable_value(&mut self.f_status, s, s.label()).changed();
                }
            });
            ui.label("Min severity");
            egui::ComboBox::from_id_salt("fmin").selected_text(self.f_min.as_str()).show_ui(ui, |ui| {
                for s in Severity::ALL {
                    changed |= ui.selectable_value(&mut self.f_min, s, s.as_str()).changed();
                }
            });
            ui.label("Search");
            changed |= ui.add(egui::TextEdit::singleline(&mut self.f_search).desired_width(180.0).hint_text("IP, title, signature")).changed();
        });
        if changed {
            self.reload();
        }
        ui.add_space(2.0);

        let sel = self.selected.clone();
        let mut clicked: Option<String> = None;
        let mut double: Option<String> = None;
        let row_h = 24.0;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(80.0))
            .column(Column::initial(50.0))
            .column(Column::remainder().at_least(260.0).clip(true))
            .column(Column::initial(120.0))
            .column(Column::initial(55.0))
            .column(Column::initial(145.0))
            .column(Column::initial(100.0))
            .header(row_h, |mut h| {
                for t in ["Severity", "Score", "Finding", "IP", "Events", "Last seen", "Status"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, self.findings.len(), |mut row| {
                    let f = &self.findings[row.index()];
                    let open = f.status == "open";
                    let muted = |t: String| if open { RichText::new(t) } else { RichText::new(t).weak() };
                    row.set_selected(sel.as_deref() == Some(f.key.as_str()));
                    row.col(|ui| {
                        ui.label(RichText::new(f.severity.as_str().to_uppercase()).strong().color(sev_color(f.severity, dark)));
                    });
                    row.col(|ui| {
                        ui.label(muted(f.score.to_string()));
                    });
                    row.col(|ui| {
                        let t = if f.blocked_at.is_some() { format!("{}   [blocked]", f.title) } else { f.title.clone() };
                        ui.label(muted(t));
                    });
                    row.col(|ui| {
                        ui.label(muted(f.subject_ip.clone()));
                    });
                    row.col(|ui| {
                        ui.label(muted(f.event_count.to_string()));
                    });
                    row.col(|ui| {
                        ui.label(muted(ipswatch::local_time(&f.last_seen)));
                    });
                    row.col(|ui| {
                        ui.label(muted(f.status_label().to_string()));
                    });
                    let r = row.response();
                    if r.clicked() {
                        clicked = Some(f.key.clone());
                    }
                    if r.double_clicked() {
                        double = Some(f.subject_ip.clone());
                    }
                });
            });
        if let Some(k) = clicked {
            self.selected = Some(k);
        }
        if let Some(ip) = double {
            self.e_search = ip;
            self.events = self.ctl.shared.store.recent_events(2000, &self.e_search).unwrap_or_default();
            self.tab = Tab::Events;
        }
        if self.findings.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| ui.weak("No findings match. New ones appear here as IPS alerts are analyzed."));
        }
    }

    fn detail_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("detail").resizable(true).default_width(430.0).min_width(320.0).show(ctx, |ui| {
            let dark = ui.visuals().dark_mode;
            let Some(f) = self.selected_finding().cloned() else {
                ui.add_space(20.0);
                ui.weak("Select a finding to see why it was flagged.");
                return;
            };
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let enabled = true;
                if ui.add_enabled(f.status != "ack", egui::Button::new("Acknowledge")).clicked() {
                    self.set_status("ack");
                }
                if ui.add_enabled(f.status != "false_positive", egui::Button::new("False positive")).clicked() {
                    self.set_status("false_positive");
                }
                if ui.add_enabled(f.status != "open" && enabled, egui::Button::new("Reopen")).clicked() {
                    self.set_status("open");
                }
            });
            ui.horizontal(|ui| {
                let inbound = f.kind == "inbound";
                if ui.add_enabled(inbound, egui::Button::new("Block IP...")).clicked() {
                    self.block(false);
                }
                if ui.add_enabled(inbound, egui::Button::new("Unblock IP...")).clicked() {
                    self.block(true);
                }
                if ui.button("Show events").clicked() {
                    self.e_search = f.subject_ip.clone();
                    self.events = self.ctl.shared.store.recent_events(2000, &self.e_search).unwrap_or_default();
                    self.tab = Tab::Events;
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Copy IP").clicked() {
                    ui.ctx().copy_text(f.subject_ip.clone());
                }
                if ui.button("Look up on AbuseIPDB").clicked() {
                    let _ = open::that(format!("https://www.abuseipdb.com/check/{}", f.subject_ip));
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                ui.label(RichText::new(f.severity.as_str().to_uppercase()).strong().color(sev_color(f.severity, dark)));
                ui.label(RichText::new(&f.title).size(17.0).strong());
                let mut meta = format!(
                    "score {} · {} events · {}\nfirst {}\nlast {}",
                    f.score,
                    f.event_count,
                    f.status_label(),
                    ipswatch::local_time(&f.first_seen),
                    ipswatch::local_time(&f.last_seen)
                );
                if let Some(b) = &f.blocked_at {
                    meta += &format!("\nblocked {}", ipswatch::local_time(b));
                }
                ui.weak(meta);
                ui.add_space(8.0);
                ui.strong("Why it was flagged");
                for r in &f.reasons {
                    ui.label(format!("•  {r}"));
                }
                ui.add_space(8.0);
                ui.strong("Targets");
                ui.label(f.targets.iter().take(40).cloned().collect::<Vec<_>>().join(", "));
                ui.add_space(8.0);
                ui.strong("Signatures");
                for s in &f.signatures {
                    ui.label(format!("•  {s}"));
                }
                ui.add_space(8.0);
                if f.kind == "compromise" {
                    ui.strong("Suggested action");
                    ui.label("Isolate this internal host and check it for malware.");
                } else if f.title.contains("unwanted access") {
                    ui.strong("Suggested action");
                    ui.label("Check the targeted hosts' logs for successful logins, close the exposed port or set the IPS rule to Drop, and consider blocking the source.");
                }
                ui.add_space(4.0);
                ui.weak(format!("key: {}", f.key));
            });
        });
    }

    fn events_view(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Search (IP, signature, SID)");
            let r = ui.add(egui::TextEdit::singleline(&mut self.e_search).desired_width(260.0));
            let go = ui.button("Search").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            let clear = ui.button("Clear").clicked();
            if clear {
                self.e_search.clear();
            }
            if go || clear {
                self.events = self.ctl.shared.store.recent_events(2000, &self.e_search).unwrap_or_default();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(format!("{} events shown{}  ·  red = not dropped by the IPS", self.events.len(), if self.events.len() == 2000 { " (max)" } else { "" }));
            });
        });
        let dark = ui.visuals().dark_mode;
        let red = sev_color(Severity::Critical, dark);
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(145.0))
            .column(Column::initial(150.0))
            .column(Column::initial(160.0))
            .column(Column::initial(50.0))
            .column(Column::initial(80.0))
            .column(Column::initial(300.0).clip(true))
            .column(Column::initial(190.0).clip(true))
            .column(Column::initial(35.0))
            .column(Column::remainder().at_least(60.0))
            .header(22.0, |mut h| {
                for t in ["Time", "Source", "Destination", "Proto", "SID", "Signature", "Category", "Sev", "Action"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, self.events.len(), |mut row| {
                    let e = &self.events[row.index()];
                    let c = |t: String| if e.was_dropped() { RichText::new(t) } else { RichText::new(t).color(red) };
                    let hp = |ip: &str, p: Option<i64>| p.map(|p| format!("{ip}:{p}")).unwrap_or_else(|| ip.to_string());
                    let cells = [
                        ipswatch::local_time(&e.ts),
                        hp(&e.src_ip, e.src_port),
                        hp(&e.dest_ip, e.dest_port),
                        e.proto.clone(),
                        e.sid.map(|s| s.to_string()).unwrap_or_default(),
                        e.signature.clone(),
                        e.category.clone(),
                        e.severity.to_string(),
                        e.action.clone(),
                    ];
                    for t in cells {
                        row.col(|ui| {
                            ui.label(c(t));
                        });
                    }
                });
            });
    }

    fn log_view(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.log_follow, "Follow");
            if ui.button("Clear").clicked() {
                logbuf::clear();
            }
            if ui.button("Open log file").clicked() {
                let _ = open::that(self.ctl.cfg_path.with_file_name("ipswatch.log"));
            }
        });
        let lines = logbuf::lines();
        let dark = ui.visuals().dark_mode;
        egui::ScrollArea::vertical().auto_shrink(false).stick_to_bottom(self.log_follow).show_rows(
            ui,
            16.0,
            lines.len(),
            |ui, range| {
                for l in &lines[range] {
                    let t = RichText::new(&l.text).monospace();
                    ui.label(match l.level {
                        log::Level::Error => t.color(sev_color(Severity::Critical, dark)),
                        log::Level::Warn => t.color(sev_color(Severity::Medium, dark)),
                        _ => t,
                    });
                }
            },
        );
    }
}

fn card(ui: &mut Ui, big: &str, small: &str, color: Color32) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(14, 6)).show(ui, |ui| {
        ui.set_min_width(96.0);
        ui.vertical(|ui| {
            ui.label(RichText::new(big).size(24.0).strong().color(color));
            ui.weak(small);
        });
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Close button -> hide to tray (unless disabled or no tray).
        if ctx.input(|i| i.viewport().close_requested()) {
            let cfg = self.ctl.cfg();
            if cfg.gui.close_to_tray && self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.ctl.hide_window();
                if !self.tray_hint_shown {
                    self.tray_hint_shown = true;
                    let _ = self.ctl.shared.store.set_kv("tray_hint_shown", "1");
                    let mut hint = notify::sample_finding();
                    hint.title = "IPS Watch is still running".into();
                    hint.reasons = vec!["It keeps monitoring in the system tray. Right-click the tray icon to quit.".into()];
                    toast::show(&hint);
                }
            } else {
                self.ctl.stop();
            }
        }

        while let Ok(m) = self.bg_rx.try_recv() {
            match m {
                Bg::Message { title, text, error } => self.message = Some((title, text, error)),
                Bg::Reload => {}
            }
            self.reload();
        }
        if self.ctl.shared.data_version.load(Ordering::Relaxed) != self.loaded_version
            || self.last_reload.elapsed() > Duration::from_secs(30)
        {
            self.reload();
        }

        egui::TopBottomPanel::top("menu").show(ctx, |ui| self.menu_bar(ui));
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui);
            ui.add_space(2.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            let st = self.ctl.shared.status();
            let text = match (&st.last_poll, &st.last_error) {
                (Some(t), Some(e)) => format!("Last poll {t}: ERROR - {e}"),
                (Some(t), None) => format!("Last poll {t}: {} new events", st.last_added),
                (None, _) if self.ctl.is_running() => "Starting...".to_string(),
                _ => "Not monitoring".to_string(),
            };
            ui.horizontal(|ui| {
                ui.weak(text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("v{}", ipswatch::VERSION));
                });
            });
        });

        if self.tab == Tab::Findings {
            self.detail_panel(ctx);
        }
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Findings => self.findings_view(ui),
            Tab::Events => self.events_view(ui),
            Tab::Log => self.log_view(ui),
            Tab::Settings => {
                let saved = self.ctl.cfg();
                let mut actions = Vec::new();
                let db = self.db_path.clone();
                self.settings.ui(ui, &saved, &db, &mut actions);
                self.handle_settings(actions);
            }
        });

        if let Some((title, text, error)) = self.message.clone() {
            let mut open = true;
            let mut close = false;
            egui::Window::new(RichText::new(&title).strong())
                .id(egui::Id::new("message"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_max_width(460.0);
                    let t = RichText::new(&text);
                    ui.label(if error { t.color(ui.visuals().error_fg_color) } else { t });
                    ui.add_space(8.0);
                    if ui.button("  OK  ").clicked() {
                        close = true;
                    }
                });
            if !open || close {
                self.message = None;
            }
        }
        if self.about {
            egui::Window::new("About IPS Watch")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut self.about)
                .show(ctx, |ui| {
                    ui.label(format!("IPS Watch {}", ipswatch::VERSION));
                    ui.label("Captures OPNsense Suricata IPS alerts and flags potential unwanted access.");
                    ui.weak(format!("Settings: {}", self.ctl.cfg_path.display()));
                    ui.weak(format!("Database: {}", self.db_path));
                });
        }

        // Keep the status line fresh while visible.
        ctx.request_repaint_after(Duration::from_secs(5));
    }
}
