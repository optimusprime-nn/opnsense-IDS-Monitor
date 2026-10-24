//! Health page: gateways, system, services, exposure, devices, config changes.

use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use ipswatch::config::Severity;
use ipswatch::health::Snapshot;
use ipswatch::store::Finding;

use crate::app::sev_color;

pub enum Action {
    None,
    CheckNow,
    OpenFinding(String),
}

fn good(dark: bool) -> Color32 {
    if dark { Color32::from_rgb(0x4a, 0xd6, 0x8a) } else { Color32::from_rgb(0x12, 0x9a, 0x50) }
}

fn tile(ui: &mut Ui, big: RichText, small: &str) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(14, 6)).show(ui, |ui| {
        ui.set_min_width(120.0);
        ui.vertical(|ui| {
            ui.label(big.size(20.0).strong());
            ui.weak(small);
        });
    });
}

pub fn show(ui: &mut Ui, snap: Option<&Snapshot>, problems: &[Finding], busy: bool) -> Action {
    let dark = ui.visuals().dark_mode;
    let mut action = Action::None;
    ui.horizontal(|ui| {
        if ui.add_enabled(!busy, egui::Button::new(RichText::new("Check now").strong())).clicked() {
            action = Action::CheckNow;
        }
        if busy {
            ui.spinner();
        }
        match snap {
            Some(s) => ui.weak(format!("{} · {} · up {} · load {} · checked {}", s.hostname, s.version, s.uptime, s.loadavg, s.at)),
            None => ui.weak("No health data yet - it's collected every few minutes while monitoring runs, or click Check now."),
        };
    });
    let Some(s) = snap else { return action };
    ui.add_space(6.0);

    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        // Tiles
        ui.horizontal_wrapped(|ui| {
            for g in &s.gateways {
                let col = if g.ok { good(dark) } else { sev_color(Severity::Critical, dark) };
                let detail = format!(
                    "{} · {} · loss {}",
                    g.name,
                    g.delay_ms.map(|d| format!("{d:.0} ms")).unwrap_or_else(|| "-".into()),
                    g.loss_pct.map(|l| format!("{l:.0}%")).unwrap_or_else(|| "-".into())
                );
                tile(ui, RichText::new(&g.status).color(col), &detail);
            }
            if let Some(m) = s.memory_pct {
                tile(ui, RichText::new(format!("{m:.0}%")), "memory used (excl. ZFS cache)");
            }
            if let Some((c, l)) = s.states {
                tile(ui, RichText::new(format!("{c}")), &format!("firewall states of {l}"));
            }
            if let Some((_, p)) = s.disks.iter().find(|d| d.0 == "/") {
                tile(ui, RichText::new(format!("{p}%")), "disk / used");
            }
            let stopped = s.services.iter().filter(|x| !x.running).count();
            let col = if stopped == 0 { good(dark) } else { sev_color(Severity::High, dark) };
            tile(ui, RichText::new(format!("{}/{}", s.services.len() - stopped, s.services.len())).color(col), "services running");
        });
        ui.add_space(4.0);
        if !s.firmware.is_empty() {
            ui.weak(format!("Firmware: {}", s.firmware));
        }
        for e in &s.errors {
            ui.label(RichText::new(format!("Check failed - {e}")).color(ui.visuals().warn_fg_color));
        }

        // Open problems from these checks
        ui.add_space(8.0);
        ui.heading(format!("Open problems ({})", problems.len()));
        if problems.is_empty() {
            ui.label(RichText::new("Nothing needs attention.").color(good(dark)));
        }
        for f in problems {
            ui.horizontal(|ui| {
                ui.label(RichText::new(f.severity.as_str().to_uppercase()).strong().color(sev_color(f.severity, dark)));
                if ui.link(&f.title).clicked() {
                    action = Action::OpenFinding(f.key.clone());
                }
                if let Some(r) = f.reasons.first() {
                    ui.weak(r);
                }
            });
        }

        // Exposure
        ui.add_space(10.0);
        egui::CollapsingHeader::new(RichText::new(format!("Exposed to the internet ({})", s.exposure.iter().filter(|e| !e.blocked).count())).heading())
            .id_salt("h_exp")
            .default_open(true)
            .show(ui, |ui| {
                ui.weak("Port forwards and WAN pass rules that let the internet in, plus inbound connections the firewall log shows passing.");
                let red = sev_color(Severity::High, dark);
                TableBuilder::new(ui)
                    .id_salt("exp_t")
                    .striped(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(190.0))
                    .column(Column::initial(80.0))
                    .column(Column::initial(150.0))
                    .column(Column::initial(120.0))
                    .column(Column::initial(200.0))
                    .column(Column::remainder())
                    .header(22.0, |mut h| {
                        for t in ["Target", "Protocol", "Via", "Interface", "Status", "Notes"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|mut b| {
                        for e in &s.exposure {
                            b.row(22.0, |mut r| {
                                r.col(|ui| {
                                    ui.label(format!("{}:{}", e.target, e.port));
                                });
                                r.col(|ui| {
                                    ui.label(&e.protocol);
                                });
                                r.col(|ui| {
                                    ui.label(&e.source);
                                });
                                r.col(|ui| {
                                    ui.label(&e.interface);
                                });
                                r.col(|ui| {
                                    if e.blocked {
                                        ui.weak(e.status_label());
                                    } else {
                                        ui.label(RichText::new(e.status_label()).color(red));
                                    }
                                });
                                r.col(|ui| {
                                    ui.weak(&e.note);
                                });
                            });
                        }
                    });
            });

        // CrowdSec
        egui::CollapsingHeader::new(RichText::new("CrowdSec").heading()).id_salt("h_cs").default_open(true).show(ui, |ui| match &s.crowdsec {
            None => {
                ui.weak("Not installed. Add the os-crowdsec plugin (System > Firmware > Plugins) for community blocklists and brute-force bans.");
            }
            Some(cs) => {
                ui.horizontal_wrapped(|ui| {
                    let (txt, col) = if cs.running { ("running", good(dark)) } else { ("STOPPED", sev_color(Severity::Critical, dark)) };
                    ui.label(RichText::new(txt).strong().color(col));
                    ui.weak(format!(
                        "· bouncer {} (last seen {}) · {} IPs blocked in the firewall ({} detected here, {} from community / subscribed lists) · {} alerts",
                        if cs.bouncer_enabled { "on" } else { "OFF" },
                        if cs.bouncer_last_seen.is_empty() { "never".into() } else { ipswatch::local_time(&cs.bouncer_last_seen) },
                        cs.firewall_blocked.map(|b| b.to_string()).unwrap_or_else(|| "?".into()),
                        cs.local_bans,
                        cs.community_bans,
                        cs.alerts_total
                    ));
                });
                ui.horizontal_wrapped(|ui| {
                    if cs.firewall_blocked.is_some_and(|b| b <= cs.local_bans + 5) {
                        ui.label(RichText::new("Community blocklist not loaded yet").color(ui.visuals().warn_fg_color));
                        ui.weak("- accept the engine at app.crowdsec.net (Security Engines); the first download can take ~2 h.                                  See it on the firewall: Firewall > Diagnostics > Aliases > crowdsec_blocklists.");
                    }
                });
                if !cs.top_scenarios.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.weak("Top scenarios:");
                        for (sc, n) in &cs.top_scenarios {
                            ui.label(format!("{} ×{n}", sc.rsplit('/').next().unwrap_or(sc)));
                        }
                    });
                }
                TableBuilder::new(ui)
                    .id_salt("cs_t")
                    .striped(true)
                    .max_scroll_height(260.0)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(150.0))
                    .column(Column::initial(140.0))
                    .column(Column::initial(60.0))
                    .column(Column::initial(220.0))
                    .column(Column::initial(260.0))
                    .column(Column::remainder())
                    .header(22.0, |mut h| {
                        for t in ["Time", "IP", "Country", "Network", "Scenario", "Decision"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|b| {
                        b.rows(22.0, cs.recent.len(), |mut r| {
                            let a = &cs.recent[r.index()];
                            for t in [ipswatch::local_time(&a.created), a.ip.clone(), a.country.clone(), a.network.clone(), a.scenario.clone(), a.decisions.clone()] {
                                r.col(|ui| {
                                    ui.label(t);
                                });
                            }
                        });
                    });
            }
        });

        // Services
        egui::CollapsingHeader::new(RichText::new("Services").heading()).id_salt("h_svc").default_open(false).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                for svc in &s.services {
                    let t = RichText::new(if svc.running { svc.description.clone() } else { format!("{} (STOPPED)", svc.description) });
                    ui.label(if svc.running { t.color(good(dark)) } else { t.color(sev_color(Severity::Critical, dark)).strong() })
                        .on_hover_text(&svc.name);
                }
            });
        });

        // Devices
        egui::CollapsingHeader::new(RichText::new(format!("Devices ({})", s.devices.len())).heading()).id_salt("h_dev").default_open(false).show(ui, |ui| {
            ui.weak("From the firewall's ARP table, newest first. The first check records what's already there; later devices raise a finding.");
            TableBuilder::new(ui)
                .id_salt("dev_t")
                .striped(true)
                .max_scroll_height(320.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(150.0))
                .column(Column::initial(120.0))
                .column(Column::initial(160.0))
                .column(Column::initial(220.0))
                .column(Column::initial(150.0))
                .column(Column::remainder())
                .header(22.0, |mut h| {
                    for t in ["First seen", "IP", "Hostname", "Vendor", "MAC", "Interface"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(22.0, s.devices.len(), |mut r| {
                        let d = &s.devices[r.index()];
                        let random = ipswatch::health::is_random_mac(&d.mac);
                        for t in [
                            ipswatch::local_time(&d.first_seen),
                            d.ip.clone(),
                            d.hostname.clone(),
                            if d.vendor.is_empty() && random { "(randomised MAC)".into() } else { d.vendor.clone() },
                            d.mac.clone(),
                            d.interface.clone(),
                        ] {
                            r.col(|ui| {
                                ui.label(t);
                            });
                        }
                    });
                });
        });

        // Config changes
        egui::CollapsingHeader::new(RichText::new("Configuration changes").heading()).id_salt("h_cfg").default_open(false).show(ui, |ui| {
            for c in &s.config_changes {
                ui.horizontal(|ui| {
                    ui.monospace(ipswatch::local_time(&c.time));
                    ui.label(RichText::new(&c.user).strong());
                    ui.weak(&c.description);
                });
            }
        });
    });
    action
}
