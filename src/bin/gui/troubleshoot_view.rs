//! The Troubleshoot page: one button that finds what's wrong, in plain language, with fixes.

use eframe::egui::{self, Color32, RichText, Ui};
use ipswatch::config::Severity;
use ipswatch::troubleshoot::{Fix, Issue, Report};

use crate::app::sev_color;

pub enum Action {
    None,
    Run,
    Fix(Fix),
    MarkBaseline,
    SaveSites(Vec<String>),
}

fn card(ui: &mut Ui, accent: Color32, add: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(accent.gamma_multiply(0.08))
        .stroke(egui::Stroke::new(1.0_f32, accent.gamma_multiply(0.6)))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
    ui.add_space(6.0);
}

fn issue_card(ui: &mut Ui, n: usize, i: &Issue, dark: bool, busy: bool, action: &mut Action) {
    let col = sev_color(i.severity, dark);
    card(ui, col, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(i.severity.as_str().to_uppercase()).strong().color(col));
            ui.label(RichText::new(&i.area).weak());
            ui.label(RichText::new(&i.title).strong().size(15.0));
        });
        ui.label(&i.explain);
        if let Some(f) = &i.fix {
            ui.add_space(4.0);
            if ui
                .add_enabled(!busy, egui::Button::new(RichText::new(format!("Fix it: {}", f.label())).strong()))
                .on_hover_text("Shows exactly what will change and asks before doing anything")
                .clicked()
            {
                *action = Action::Fix(f.clone());
            }
        }
        if !i.manual.is_empty() {
            egui::CollapsingHeader::new(if i.fix.is_some() { "Or fix it by hand" } else { "How to fix it" })
                .id_salt(("ts-manual", n))
                .default_open(i.fix.is_none())
                .show(ui, |ui| {
                    for (k, m) in i.manual.iter().enumerate() {
                        ui.label(format!("{}. {m}", k + 1));
                    }
                });
        }
        if !i.evidence.is_empty() {
            egui::CollapsingHeader::new("What IPS Watch saw").id_salt(("ts-evidence", n)).show(ui, |ui| {
                for e in &i.evidence {
                    ui.label(RichText::new(e).monospace());
                }
            });
        }
    });
}

pub fn show(ui: &mut Ui, report: Option<&Report>, busy: bool, sites: &mut String) -> Action {
    let dark = ui.visuals().dark_mode;
    let mut action = Action::None;
    ui.horizontal(|ui| {
        if ui.add_enabled(!busy, egui::Button::new(RichText::new("Find problems").strong().size(15.0))).clicked() {
            action = Action::Run;
        }
        if busy {
            ui.spinner();
            ui.label("Checking the clock, services, gateways, firewall log, sites and settings (read-only)...");
        } else if let Some(r) = report {
            ui.weak(format!("checked {}  ·  firmware {}", r.at, r.firmware));
        } else {
            ui.weak("Checks the firewall and your connection for problems and explains them. Nothing changes unless you click a fix.");
        }
    });
    ui.add_space(6.0);
    let Some(r) = report else { return action };

    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        // Overall verdict.
        let worst = r.issues.iter().map(|i| i.severity).max();
        let (text, col) = match worst {
            None => ("Everything looks fine.".to_string(), Color32::from_rgb(0x12, 0x9a, 0x50)),
            Some(s) if s >= Severity::High => (format!("{} problem(s) found - the top ones are probably what you're noticing.", r.issues.len()), sev_color(s, dark)),
            Some(s) => (format!("{} minor thing(s) worth a look.", r.issues.len()), sev_color(s, dark)),
        };
        card(ui, col, |ui| {
            ui.label(RichText::new(text).strong().size(16.0).color(col));
            let failing: Vec<&str> = r.sites.iter().filter(|s| !s.ok()).map(|s| s.site.as_str()).collect();
            let mut line = format!(
                "Sites: {} of {} work",
                r.sites.len() - failing.len(),
                r.sites.len()
            );
            if let Some(o) = r.clock_offset_s {
                line += &format!("  ·  firewall clock {}", if o.abs() <= 2 { "correct".to_string() } else { format!("off by {o} s") });
            }
            if !r.gateways.is_empty() {
                let d: usize = r.gateways.iter().map(|g| g.down_24h + g.loss_24h).sum();
                line += &format!("  ·  WAN alarms in 24 h: {d}");
            }
            ui.label(line);
            if !failing.is_empty() {
                ui.label(RichText::new(format!("Not working: {}", failing.join(", "))).strong());
            }
        });

        for (n, i) in r.issues.iter().enumerate() {
            issue_card(ui, n, i, dark, busy, &mut action);
        }

        ui.add_space(8.0);
        egui::CollapsingHeader::new(RichText::new("Sites that must work").strong()).id_salt("ts-sites").default_open(true).show(ui, |ui| {
            egui::Grid::new("ts-sites-grid").striped(true).num_columns(4).show(ui, |ui| {
                for s in &r.sites {
                    let (st, c) = if s.ok() { ("OK", Color32::from_rgb(0x12, 0x9a, 0x50)) } else { ("FAIL", sev_color(Severity::High, dark)) };
                    ui.label(RichText::new(st).strong().color(c));
                    ui.label(&s.site);
                    ui.label(if s.ok() {
                        format!("DNS {} ms · connect {} ms · HTTPS {} ms", s.dns_ms.unwrap_or(0), s.connect_ms.unwrap_or(0), s.https_ms.unwrap_or(0))
                    } else {
                        s.error.clone()
                    });
                    ui.label(RichText::new(&s.cause).weak());
                    ui.end_row();
                }
            });
            ui.add_space(4.0);
            ui.label("Sites to test (one per line):");
            ui.add(egui::TextEdit::multiline(sites).desired_rows(3).desired_width(360.0).font(egui::TextStyle::Monospace));
            if ui.button("Save list").clicked() {
                action = Action::SaveSites(sites.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect());
            }
        });

        if !r.gateways.is_empty() {
            egui::CollapsingHeader::new(RichText::new("Gateway history").strong()).id_salt("ts-gw").show(ui, |ui| {
                egui::Grid::new("ts-gw-grid").striped(true).num_columns(5).show(ui, |ui| {
                    for h in ["Gateway", "Monitor IP", "Down 24h / 7d", "Packet loss 24h / 7d", "Latency 24h"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for g in &r.gateways {
                        ui.label(&g.name);
                        ui.label(&g.monitor_ip);
                        ui.label(format!("{} / {}", g.down_24h, g.down_7d));
                        ui.label(format!("{} / {}", g.loss_24h, g.loss_7d));
                        ui.label(g.delay_24h.to_string());
                        ui.end_row();
                    }
                });
                for g in &r.gateways {
                    if g.events.is_empty() {
                        continue;
                    }
                    egui::CollapsingHeader::new(format!("{}: recent alarms", g.name)).id_salt(("ts-gw-ev", &g.name)).show(ui, |ui| {
                        for (t, c, d) in &g.events {
                            ui.label(RichText::new(format!("{t}  {c:14}  {d}")).monospace());
                        }
                    });
                }
            });
        }

        egui::CollapsingHeader::new(RichText::new(format!("What changed ({})", r.changes.len())).strong()).id_salt("ts-changes").show(ui, |ui| {
            ui.label(format!(
                "Compared with the baseline from {} (firmware {}). The baseline is kept automatically from just before a firmware update.",
                r.baseline_at, r.baseline_version
            ));
            if r.changes.is_empty() {
                ui.weak("No differences.");
            } else {
                egui::Grid::new("ts-changes-grid").striped(true).num_columns(3).show(ui, |ui| {
                    ui.strong("Setting");
                    ui.strong("Before");
                    ui.strong("Now");
                    ui.end_row();
                    for c in &r.changes {
                        ui.label(&c.key);
                        ui.label(if c.before.is_empty() { "(none)" } else { &c.before });
                        ui.label(if c.after.is_empty() { "(none)" } else { &c.after });
                        ui.end_row();
                    }
                });
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Mark the current settings as the baseline"))
                .on_hover_text("Do this when everything works, so later runs only show new changes")
                .clicked()
            {
                action = Action::MarkBaseline;
            }
        });

        for e in &r.errors {
            ui.weak(format!("Couldn't check: {e}"));
        }
    });
    action
}
