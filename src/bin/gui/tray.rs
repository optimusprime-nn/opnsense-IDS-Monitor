//! System tray icon and menu.

use std::sync::Arc;

use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::Controller;

pub struct Tray {
    icon: TrayIcon,
    toggle: MenuItem,
    autostart: CheckMenuItem,
    alert_state: Option<bool>,
}

struct Ids {
    open: MenuId,
    toggle: MenuId,
    poll: MenuId,
    autostart: MenuId,
    quit: MenuId,
}

fn icon(alert: bool) -> Icon {
    Icon::from_rgba(ipswatch::icon::rgba(32, alert), 32, 32).expect("valid icon")
}

impl Tray {
    /// Must be called on the main (event loop) thread.
    pub fn new(ctl: Arc<Controller>) -> anyhow::Result<Tray> {
        let open = MenuItem::new("Open IPS Watch", true, None);
        let toggle = MenuItem::new("Start monitoring", true, None);
        let poll = MenuItem::new("Poll now", true, None);
        let autostart = CheckMenuItem::new("Start with Windows", true, ipswatch::autostart::is_enabled(), None);
        let quit = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        menu.append_items(&[
            &open,
            &PredefinedMenuItem::separator(),
            &toggle,
            &poll,
            &PredefinedMenuItem::separator(),
            &autostart,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;
        let ids = Ids {
            open: open.id().clone(),
            toggle: toggle.id().clone(),
            poll: poll.id().clone(),
            autostart: autostart.id().clone(),
            quit: quit.id().clone(),
        };

        let icon = TrayIconBuilder::new()
            .with_tooltip("IPS Watch")
            .with_icon(icon(false))
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .build()?;

        // Handlers run on the main thread, even while the window is hidden.
        let c = ctl.clone();
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| match e {
            TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
            | TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } => c.show_window(),
            _ => {}
        }));
        let c = ctl;
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            if e.id == ids.open {
                c.show_window();
            } else if e.id == ids.toggle {
                c.toggle();
            } else if e.id == ids.poll {
                c.poll_now();
            } else if e.id == ids.autostart {
                let want = !ipswatch::autostart::is_enabled();
                match ipswatch::autostart::set_enabled(want) {
                    Ok(()) => {
                        let mut cfg = c.cfg();
                        cfg.gui.start_with_windows = want;
                        if ipswatch::config::save(&cfg, &c.cfg_path).is_ok() {
                            *c.shared.cfg.write().unwrap_or_else(|e| e.into_inner()) = cfg;
                        }
                        log::info!("Start with Windows {}", if want { "enabled" } else { "disabled" });
                    }
                    Err(e) => log::error!("could not change Start with Windows: {e:#}"),
                }
                c.ctx.request_repaint();
            } else if e.id == ids.quit {
                c.quit();
            }
        }));

        Ok(Tray { icon, toggle, autostart, alert_state: None })
    }

    /// Refresh labels, tooltip and icon colour (call from the UI thread).
    pub fn update(&mut self, running: bool, open_high: usize, open_total: usize) {
        self.toggle.set_text(if running { "Stop monitoring" } else { "Start monitoring" });
        self.autostart.set_checked(ipswatch::autostart::is_enabled());
        let state = if running { "monitoring" } else { "stopped" };
        let tip = match open_total {
            0 => format!("IPS Watch - {state}, no open findings"),
            n => format!("IPS Watch - {state}, {n} open finding(s), {open_high} high/critical"),
        };
        let _ = self.icon.set_tooltip(Some(tip));
        let alert = open_high > 0;
        if self.alert_state != Some(alert) {
            let _ = self.icon.set_icon(Some(icon(alert)));
            self.alert_state = Some(alert);
        }
    }
}
