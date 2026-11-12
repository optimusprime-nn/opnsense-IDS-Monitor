//! IPS Watch desktop app (Windows): egui window + system tray + toast alerts.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod dns_view;
mod health_view;
mod settings;
mod tray;
mod troubleshoot_view;
mod win;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use eframe::egui;
use ipswatch::config::{self, Config};
use ipswatch::monitor::{Monitor, Shared, Status};
use ipswatch::store::Store;
use ipswatch::{logbuf, toast};

pub const WINDOW_TITLE: &str = "IPS Watch";

/// Everything the window and the tray menu both need to drive.
pub struct Controller {
    pub shared: Arc<Shared>,
    pub cfg_path: PathBuf,
    monitor: Mutex<Option<Monitor>>,
    pub hwnd: AtomicIsize,
    pub ctx: egui::Context,
    pub visible: AtomicBool,
}

impl Controller {
    pub fn cfg(&self) -> Config {
        self.shared.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn is_running(&self) -> bool {
        self.monitor.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|m| !m.is_finished())
    }

    pub fn start(&self) {
        let mut m = self.monitor.lock().unwrap_or_else(|e| e.into_inner());
        if m.as_ref().is_some_and(|m| !m.is_finished()) {
            return;
        }
        *m = Some(Monitor::start(self.shared.clone()));
        self.ctx.request_repaint();
    }

    pub fn stop(&self) {
        if let Some(m) = self.monitor.lock().unwrap_or_else(|e| e.into_inner()).take() {
            m.stop();
        }
        self.ctx.request_repaint();
    }

    pub fn toggle(&self) {
        if self.is_running() {
            self.stop()
        } else {
            self.start()
        }
    }

    pub fn poll_now(&self) {
        let m = self.monitor.lock().unwrap_or_else(|e| e.into_inner());
        match m.as_ref().filter(|m| !m.is_finished()) {
            Some(m) => m.poll_now(),
            None => {
                drop(m);
                self.start();
            }
        }
    }

    /// Restart monitoring so new settings take effect.
    pub fn restart_if_running(&self) {
        if self.is_running() {
            self.stop();
            // The old thread exits after its current request; a new one starts right away.
            self.start();
        }
    }

    pub fn show_window(&self) {
        win::show(self.hwnd.load(Ordering::Relaxed));
        self.visible.store(true, Ordering::Relaxed);
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        self.ctx.request_repaint();
    }

    pub fn hide_window(&self) {
        self.visible.store(false, Ordering::Relaxed);
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    pub fn quit(&self) -> ! {
        self.stop();
        log::info!("IPS Watch exiting");
        // The monitor thread may be mid-request; SQLite (WAL) is safe to leave.
        std::process::exit(0)
    }
}

/// Record every panic (message, thread, source location) in ipswatch.log and crash.log.
/// A panic on the UI thread ends the app, so also tell the user instead of vanishing silently.
fn install_panic_hook(crash_file: PathBuf) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let line = format!("{} PANIC in thread '{thread}' at {at}: {msg}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        log::error!("PANIC in thread '{thread}' at {at}: {msg}");
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&crash_file) {
            use std::io::Write;
            let _ = writeln!(f, "{line}\n{}", std::backtrace::Backtrace::force_capture());
        }
        if thread == "monitor" {
            ipswatch::monitor::MONITOR_PANICS.fetch_add(1, Ordering::Relaxed);
        } else if thread == "main" {
            win::error_box("IPS Watch stopped unexpectedly", &format!("{msg}\n\nat {at}\n\nDetails were saved to {}.", crash_file.display()));
        }
        default(info);
    }));
}

fn main() -> eframe::Result<()> {
    let minimized_arg = std::env::args().any(|a| a == "--minimized");
    let cfg_path = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(config::default_config_path);

    // One instance only: a second launch brings the running one to the front.
    if !win::claim_single_instance() {
        win::show(win::find_window(WINDOW_TITLE));
        return Ok(());
    }

    let _ = std::fs::create_dir_all(cfg_path.parent().unwrap_or(std::path::Path::new(".")));
    logbuf::init(Some(cfg_path.with_file_name("ipswatch.log")), cfg!(debug_assertions));
    install_panic_hook(cfg_path.with_file_name("crash.log"));
    toast::register_app_id();

    let (cfg, cfg_error) = match config::load(&cfg_path) {
        Ok(c) => (c, None),
        Err(e) => (Config::default(), Some(format!("{e:#}"))),
    };
    let db_path = cfg.db_path_for(&cfg_path);
    let store = match Store::open_or_repair(&db_path) {
        Ok((s, repaired)) => {
            if let Some(msg) = repaired {
                toast::show_message("IPS Watch repaired its database", &msg);
            }
            Arc::new(s)
        }
        Err(e) => {
            win::error_box("IPS Watch", &format!("Could not open the database {}:\n{e:#}", db_path.display()));
            std::process::exit(1);
        }
    };
    let saved = ipswatch::monitor::saved_snapshots(&store);
    // Keep the Run entry pointing at this exe if the app was moved/updated.
    if cfg.gui.start_with_windows && ipswatch::autostart::is_stale() {
        let _ = ipswatch::autostart::set_enabled(true);
    }
    let start_hidden = minimized_arg || cfg.gui.start_minimized;
    log::info!("IPS Watch {} starting (config {})", ipswatch::VERSION, cfg_path.display());

    let icon = egui::IconData { rgba: ipswatch::icon::rgba(64, false), width: 64, height: 64 };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_app_id("IPSWatch.Monitor")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 560.0])
            .with_icon(Arc::new(icon))
            .with_visible(!start_hidden),
        ..Default::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let repaint_ctx = ctx.clone();
            let shared = Arc::new(Shared {
                cfg: RwLock::new(cfg.clone()),
                store,
                status: Mutex::new(Status::default()),
                data_version: AtomicU64::new(1),
                health: Mutex::new(saved.0),
                dns: Mutex::new(saved.1),
                on_alert: Box::new(|sh: &Shared, f| {
                    let c = sh.cfg.read().unwrap_or_else(|e| e.into_inner());
                    if c.gui.desktop_alerts && f.severity >= c.gui.alert_min_severity {
                        toast::show(f);
                    }
                }),
                on_cycle: Box::new(move || repaint_ctx.request_repaint()),
            });
            let ctl = Arc::new(Controller {
                shared,
                cfg_path,
                monitor: Mutex::new(None),
                hwnd: AtomicIsize::new(win::hwnd_from(cc)),
                ctx,
                visible: AtomicBool::new(!start_hidden),
            });
            Ok(Box::new(app::App::new(cc, ctl, cfg_error)))
        }),
    )
}
