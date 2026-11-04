//! DNS page: Technitium / Unbound servers - up/down, traffic, blocking, clients, zones, exposure.

use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use ipswatch::config::Severity;
use ipswatch::dns::{ServerStatus, Snapshot};
use ipswatch::store::Finding;

use crate::app::sev_color;
use crate::health_view::Action;

fn good(dark: bool) -> Color32 {
    if dark { Color32::from_rgb(0x4a, 0xd6, 0x8a) } else { Color32::from_rgb(0x12, 0x9a, 0x50) }
}

fn tile(ui: &mut Ui, big: RichText, small: &str) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(14, 6)).show(ui, |ui| {
        ui.set_min_width(110.0);
        ui.vertical(|ui| {
            ui.label(big.size(20.0).strong());
            ui.weak(small);
        });
    });
}

fn table(ui: &mut Ui, id: &str, headers: &[&str], widths: &[f32], rows: Vec<Vec<String>>) {
    let mut t = TableBuilder::new(ui).id_salt(id).striped(true).max_scroll_height(260.0).cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    for w in widths {
        t = t.column(Column::initial(*w));
    }
    t.column(Column::remainder())
        .header(22.0, |mut h| {
            for x in headers {
                h.col(|ui| {
                    ui.strong(*x);
                });
            }
        })
        .body(|b| {
            b.rows(22.0, rows.len(), |mut r| {
                for c in &rows[r.index()] {
                    r.col(|ui| {
                        ui.label(c);
                    });
                }
            });
        });
}

pub fn show(ui: &mut Ui, snap: Option<&Snapshot>, problems: &[Finding], busy: bool, configured: bool) -> Action {
    let dark = ui.visuals().dark_mode;
    let mut action = Action::None;
    ui.horizontal(|ui| {
        if ui.add_enabled(!busy && configured, egui::Button::new(RichText::new("Check now").strong())).clicked() {
            action = Action::CheckNow;
        }
        if busy {
            ui.spinner();
        }
        match (snap, configured) {
            (_, false) => ui.weak("No DNS servers configured - add them in Settings > DNS servers."),
            (Some(s), _) => ui.weak(format!("checked {}", s.at)),
            (None, _) => ui.weak("No DNS data yet - it's collected every few minutes while monitoring runs, or click Check now."),
        };
    });
    let Some(s) = snap else { return action };
    for r in &s.ids_restarts {
        ui.label(RichText::new(format!("{r} - the WAN stalls while inline IPS reloads, so upstream lookups fail meanwhile")).color(ui.visuals().warn_fg_color));
    }
    ui.add_space(6.0);

    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        // One tile row per server.
        for srv in &s.servers {
            ui.horizontal_wrapped(|ui| {
                let (txt, col) = match (srv.dns_ok, srv.api_ok) {
                    (true, true) => ("UP", good(dark)),
                    (true, false) => ("UP (no API)", sev_color(Severity::Medium, dark)),
                    (false, _) => ("DOWN", sev_color(Severity::Critical, dark)),
                };
                let ms = srv.lookups.iter().filter(|l| l.ok).map(|l| l.ms).max();
                tile(ui, RichText::new(txt).color(col), &format!("{} · {}{}", srv.name, srv.host, ms.map(|m| format!(" · {m} ms")).unwrap_or_default()));
                if let Some(st) = &srv.stats {
                    let window = if srv.stats_window.is_empty() { "last hour" } else { srv.stats_window.as_str() };
                    tile(ui, RichText::new(st.total.to_string()), &format!("queries, {window}"));
                    tile(ui, RichText::new(format!("{:.1}%", st.pct(st.blocked))), "blocked");
                    let sf = st.pct(st.servfail);
                    tile(ui, RichText::new(format!("{sf:.1}%")).color(if sf >= 5.0 { sev_color(Severity::Medium, dark) } else { ui.visuals().text_color() }), "upstream failures");
                    tile(ui, RichText::new(format!("{:.1}%", st.pct(st.nxdomain))), "NXDOMAIN");
                    if st.clients > 0 || srv.backend != "unbound" {
                        tile(ui, RichText::new(st.clients.to_string()), "clients");
                    }
                }
                if let Some(age) = srv.blocklist_age_hours {
                    tile(ui, RichText::new(format!("{age:.0} h")), "blocklists updated");
                }
            });
            let mut info = vec![];
            if !srv.version.is_empty() {
                info.push(format!("Technitium {}", srv.version));
            } else if srv.backend == "unbound" {
                info.push("OPNsense Unbound".into());
            }
            if !srv.update.is_empty() {
                info.push(format!("update {} available", srv.update));
            }
            if !srv.up_since.is_empty() {
                info.push(format!("up since {}", ipswatch::local_time(&srv.up_since)));
            }
            if !srv.recursion.is_empty() {
                info.push(format!("recursion: {}", srv.recursion));
            }
            info.push(if srv.forwarders.is_empty() { "no forwarders (recursive)".into() } else { format!("forwarders: {}", srv.forwarders.join(", ")) });
            if srv.api_ok {
                info.push(match (srv.blocking, srv.blocklist_urls) {
                    (false, _) => "blocking OFF".into(),
                    (true, 0) => "blocking on, no blocklists".into(),
                    (true, n) => format!("blocking on, {n} list(s)"),
                });
            }
            ui.weak(info.join(" · "));
            if !srv.api_error.is_empty() {
                ui.label(RichText::new(format!("API: {}", srv.api_error)).color(ui.visuals().warn_fg_color));
            }
            for n in &srv.notes {
                ui.label(RichText::new(n).color(ui.visuals().warn_fg_color));
            }
            for e in &srv.errors {
                ui.label(RichText::new(format!("Check failed - {e}")).color(ui.visuals().warn_fg_color));
            }
            ui.add_space(6.0);
        }

        // Open problems
        ui.add_space(4.0);
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
        ui.add_space(8.0);

        for srv in &s.servers {
            server_details(ui, srv, dark);
        }
    });
    action
}

fn server_details(ui: &mut Ui, srv: &ServerStatus, dark: bool) {
    let id = |x: &str| format!("dns_{}_{x}", srv.host);
    egui::CollapsingHeader::new(RichText::new(format!("{} ({})", srv.name, srv.host)).heading()).id_salt(id("h")).default_open(true).show(ui, |ui| {
        // Test lookups
        ui.horizontal_wrapped(|ui| {
            ui.weak("Test lookups:");
            for l in &srv.lookups {
                let t = format!("{} {} ({} ms)", l.domain, l.result, l.ms);
                ui.label(if l.ok { RichText::new(t).color(good(dark)) } else { RichText::new(t).color(sev_color(Severity::High, dark)).strong() });
            }
        });

        if srv.api_ok && srv.backend != "unbound" {
            ui.horizontal_wrapped(|ui| {
                ui.weak("Failed resolutions in the server log, last hour:");
                ui.label(RichText::new(srv.upstream_failures.to_string()).strong());
                if !srv.failing_names.is_empty() {
                    ui.weak(format!("· failing most: {}", ipswatch::dns::pairs_text(&srv.failing_names, 6)));
                }
                if !srv.silent_nameservers.is_empty() {
                    ui.weak(format!("· name servers timing out: {}", ipswatch::dns::pairs_text(&srv.silent_nameservers, 5)));
                }
            });
        }

        // Exposure
        if !srv.exposure.is_empty() {
            ui.add_space(4.0);
            ui.strong("WAN port forwards to this server");
            let rows = srv
                .exposure
                .iter()
                .map(|e| {
                    vec![
                        e.port.clone(),
                        e.protocol.clone(),
                        e.interface.clone(),
                        if e.blocked { "forwarded, no pass rule".into() } else { "OPEN".into() },
                        if e.purpose.is_empty() { format!("(not a {} port)", srv.product()) } else { e.purpose.clone() },
                        match e.listening {
                            Some(true) => "yes".into(),
                            Some(false) => "no".into(),
                            None => "-".into(),
                        },
                        e.note.clone(),
                    ]
                })
                .collect();
            table(ui, &id("exp"), &["Port", "Protocol", "Interface", "Firewall", "Used for", "Listening", "Notes"], &[70.0, 80.0, 110.0, 170.0, 170.0, 70.0], rows);
        }

        ui.columns(2, |cols| {
            cols[0].strong("Top clients (last hour)");
            let rows = srv
                .top_clients
                .iter()
                .map(|c| vec![c.ip.clone(), c.name.clone(), c.hits.to_string(), c.usual.map(|u| format!("{u:.0}")).unwrap_or_else(|| "learning".into())])
                .collect();
            table(&mut cols[0], &id("cl"), &["Client", "Name", "Queries", "Usual/h"], &[120.0, 170.0, 70.0], rows);
            cols[1].strong(format!("Top blocked domains ({})", if srv.top_window.is_empty() { "last hour" } else { &srv.top_window }));
            let rows = srv.top_blocked.iter().map(|(d, n)| vec![d.clone(), n.to_string()]).collect();
            table(&mut cols[1], &id("bl"), &["Domain", "Hits"], &[300.0], rows);
        });

        if !srv.query_logger.is_empty() || !srv.nx_clients.is_empty() {
            ui.add_space(4.0);
            ui.strong(format!("NXDOMAIN by client since the last check (from {})", srv.query_logger));
            let rows = srv.nx_clients.iter().map(|c| vec![c.ip.clone(), c.count.to_string(), c.unique.to_string(), c.sample.join(", ")]).collect();
            table(ui, &id("nx"), &["Client", "Failed", "Distinct", "Examples"], &[120.0, 70.0, 70.0], rows);
        } else if srv.api_ok && srv.backend == "unbound" {
            ui.weak("NXDOMAIN bursts per client need Unbound statistics (Reporting > Unbound DNS).");
        } else if srv.api_ok {
            ui.weak("NXDOMAIN bursts per client need a query-log app (e.g. \"Query Logs (Sqlite)\" from Technitium's App Store).");
        }

        if srv.backend != "unbound" {
            egui::CollapsingHeader::new(format!("Zones ({})", srv.zones.len())).id_salt(id("z")).default_open(false).show(ui, |ui| {
                let rows = srv
                    .zones
                    .iter()
                    .map(|z| {
                        vec![
                            if z.name.is_empty() { "(root)".into() } else { z.name.clone() },
                            z.kind.clone(),
                            z.serial.clone(),
                            ipswatch::local_time(&z.modified),
                            if z.disabled { "disabled".into() } else if z.problem.is_empty() { "ok".into() } else { z.problem.clone() },
                        ]
                    })
                    .collect();
                table(ui, &id("zt"), &["Zone", "Type", "Serial", "Last modified", "Status"], &[220.0, 90.0, 110.0, 150.0], rows);
            });
        }
        egui::CollapsingHeader::new(format!("Top domains ({})", if srv.top_window.is_empty() { "last hour" } else { &srv.top_window })).id_salt(id("td")).default_open(false).show(ui, |ui| {
            let rows = srv.top_domains.iter().map(|(d, n)| vec![d.clone(), n.to_string()]).collect();
            table(ui, &id("tdt"), &["Domain", "Hits"], &[320.0], rows);
        });
    });
    ui.add_space(6.0);
}
