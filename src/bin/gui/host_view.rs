//! Host page: everything IPS Watch knows about one address, in one window.

use eframe::egui::{self, RichText, Ui};
use ipswatch::host::HostReport;

use crate::app::sev_color;

/// The open host window.
pub struct HostWin {
    pub report: HostReport,
    /// "Who owns it?": None = not asked; Some(None) = asking; Some(Some(..)) = the answer.
    pub owner: Option<Option<Result<Owner, String>>>,
}

#[derive(Clone)]
pub struct Owner {
    pub lines: Vec<String>,
    /// The address's own DNS name (PTR), if it has one.
    pub reverse: Option<String>,
}

pub enum Action {
    None,
    Close,
    OpenFinding(String),
    ShowEvents(String),
    LookUpOwner(String),
    Refresh(String),
}

/// Recent events listed in the window (the report holds more).
const LISTED: usize = 50;

pub fn show(ctx: &egui::Context, win: &HostWin) -> Action {
    let mut action = Action::None;
    let mut open = true;
    let r = &win.report;
    egui::Window::new(format!("Host {}", r.ip))
        .id(egui::Id::new("host_window"))
        .open(&mut open)
        .default_size([700.0, 620.0])
        .collapsible(false)
        .resizable(true)
        .show(ctx, |ui| {
            let dark = ui.visuals().dark_mode;
            ui.label(RichText::new(r.summary()).strong());
            ui.horizontal_wrapped(|ui| {
                if ui.button("Show events").clicked() {
                    action = Action::ShowEvents(r.ip.clone());
                }
                if ui.button("Copy report").on_hover_text("Copy everything on this page as text").clicked() {
                    ui.ctx().copy_text(r.text());
                }
                if ui.button("Copy IP").clicked() {
                    ui.ctx().copy_text(r.ip.clone());
                }
                let asking = matches!(win.owner, Some(None));
                if ui
                    .add_enabled(r.public && !asking, egui::Button::new(if asking { "Asking..." } else { "Who owns it?" }))
                    .on_hover_text("Ask the internet registries (RDAP, through rdap.org) who this address is registered to, and its DNS name. Only this address is sent, only now.")
                    .on_disabled_hover_text("Private and reserved addresses are registered to no one.")
                    .clicked()
                {
                    action = Action::LookUpOwner(r.ip.clone());
                }
                if r.public && ui.button("AbuseIPDB").on_hover_text("Open the address on abuseipdb.com in your browser").clicked() {
                    let _ = open::that(format!("https://www.abuseipdb.com/check/{}", r.ip));
                }
                if ui.button("Refresh").clicked() {
                    action = Action::Refresh(r.ip.clone());
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                owner_section(ui, win);
                device_section(ui, r);
                firewall_section(ui, r);
                ui.add_space(8.0);
                ui.strong(format!("Findings ({})", r.findings.len()));
                if r.findings.is_empty() {
                    ui.weak("None about this address.");
                }
                for f in &r.findings {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(f.severity.as_str().to_uppercase()).strong().color(sev_color(f.severity, dark)));
                        let t = if f.status == "open" { RichText::new(&f.title) } else { RichText::new(&f.title).weak() };
                        if ui.link(t).on_hover_text("Open this finding").clicked() {
                            action = Action::OpenFinding(f.key.clone());
                        }
                        ui.weak(format!("{} · {}", f.status_label(), ipswatch::local_time(&f.last_seen)));
                    });
                }
                events_section(ui, r);
            });
        });
    if !open {
        action = Action::Close;
    }
    action
}

fn owner_section(ui: &mut Ui, win: &HostWin) {
    match &win.owner {
        Some(Some(Ok(o))) => {
            ui.strong("Who owns it");
            if let Some(name) = &o.reverse {
                ui.label(format!("DNS name      {name}"));
            }
            for l in &o.lines {
                ui.label(RichText::new(l).monospace());
            }
            ui.weak("The registry's record names who holds the address block (often a hosting company); the DNS name is set by whoever runs the machine.");
            ui.add_space(8.0);
        }
        Some(Some(Err(e))) => {
            ui.strong("Who owns it");
            ui.label(e);
            ui.add_space(8.0);
        }
        _ => {}
    }
}

fn device_section(ui: &mut Ui, r: &HostReport) {
    if !r.devices.is_empty() {
        ui.strong("Device");
        for d in &r.devices {
            let name = if d.hostname.is_empty() { "(no DHCP name)" } else { d.hostname.as_str() };
            ui.label(format!("{name}  ·  {}  ·  {}  ·  {}", d.mac, if d.vendor.is_empty() { "unknown vendor" } else { &d.vendor }, d.interface));
            ui.weak(format!("first seen {} · last seen {}", ipswatch::local_time(&d.first_seen), ipswatch::local_time(&d.last_seen)));
        }
        ui.add_space(8.0);
    }
    if !r.dns.is_empty() {
        ui.strong("DNS");
        for d in &r.dns {
            let mut line = format!("{}: {} queries in the last hour", d.server, d.queries);
            if let Some(u) = d.usual {
                line += &format!(" (usually {u:.0})");
            }
            if !d.name.is_empty() {
                line += &format!(", known as {}", d.name);
            }
            ui.label(line);
            if d.nxdomain > 0 {
                ui.label(format!("    {} NXDOMAIN answers, e.g. {}", d.nxdomain, d.nx_sample.join(", ")));
            }
        }
        ui.add_space(8.0);
    }
}

fn firewall_section(ui: &mut Ui, r: &HostReport) {
    ui.strong("Firewall");
    match &r.blocked_at {
        Some(b) => ui.label(format!("Blocked by IPS Watch (block alias) {}", ipswatch::local_time(b))),
        None => ui.weak("Not blocked by IPS Watch."),
    };
    if let Some(b) = &r.crowdsec_ban {
        ui.label(format!("Banned by CrowdSec: {} · {} {} · until {}", b.reason, b.country, b.network, b.expires));
    }
    if r.always_allowed {
        ui.label("Always allowed in CrowdSec (IPS Watch lifts any block on it).");
    }
    for a in &r.crowdsec_alerts {
        ui.label(format!("CrowdSec alert {}: {} ({})", ipswatch::local_time(&a.created), a.scenario, a.decisions));
    }
    for e in &r.exposure {
        let state = if e.blocked { "no pass rule" } else { "open to the internet" };
        ui.label(format!("{} {} {} via {} on {}: {state}", e.target, e.port, e.protocol, e.source, e.interface));
    }
}

fn events_section(ui: &mut Ui, r: &HostReport) {
    ui.add_space(8.0);
    ui.strong(format!("IPS events ({}{})", r.event_total, if r.events_capped { "+" } else { "" }));
    if r.event_total == 0 {
        ui.weak("None stored for this address.");
        return;
    }
    ui.label(format!(
        "{} as source, {} as destination, {} not dropped by the IPS · {} – {}",
        r.as_source,
        r.as_destination,
        r.not_dropped,
        r.first_event.as_deref().map(ipswatch::local_time).unwrap_or_default(),
        r.last_event.as_deref().map(ipswatch::local_time).unwrap_or_default()
    ));
    ui.add_space(4.0);
    ui.label("Most frequent signatures");
    for (sid, sig, n) in &r.top_signatures {
        ui.add(egui::Label::new(RichText::new(format!("{n:>6}  [{}] {sig}", sid.map(|s| s.to_string()).unwrap_or_default())).monospace()).truncate());
    }
    ui.add_space(4.0);
    ui.label(format!("Newest {}", r.events.len().min(LISTED)));
    for e in r.events.iter().take(LISTED) {
        let text = format!(
            "{}  {} -> {}{}  {}  {}",
            ipswatch::local_time(&e.ts),
            e.src_ip,
            e.dest_ip,
            e.dest_port.map(|p| format!(":{p}")).unwrap_or_default(),
            e.action,
            e.signature
        );
        let t = RichText::new(text).monospace();
        let t = if e.was_dropped() { t } else { t.color(sev_color(ipswatch::config::Severity::Critical, ui.visuals().dark_mode)) };
        // One line per event: cut at the window's edge rather than wrap.
        ui.add(egui::Label::new(t).truncate());
    }
}
