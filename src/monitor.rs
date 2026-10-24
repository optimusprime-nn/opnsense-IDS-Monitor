//! Background monitoring loop: poll the API / receive syslog, detect, alert.

use log::{error, info};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::collect::{self, SyslogReceiver};
use crate::config::Config;
use crate::engine;
use crate::opnsense::OPNsense;
use crate::store::{Finding, Store};

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub running: bool,
    pub last_poll: Option<String>, // local time
    pub last_added: usize,
    pub last_error: Option<String>,
}

enum Cmd {
    PollNow,
    Stop,
}

/// Called on the monitor thread for each finding that should alert.
pub type AlertHook = Box<dyn Fn(&Shared, &Finding) + Send + Sync>;

pub struct Monitor {
    tx: Sender<Cmd>,
    join: Option<JoinHandle<()>>,
}

/// State shared between the monitor thread and its owner (GUI / CLI).
pub struct Shared {
    pub cfg: RwLock<Config>,
    pub store: Arc<Store>,
    pub status: Mutex<Status>,
    /// Bumped whenever new data lands, so views know to reload.
    pub data_version: AtomicU64,
    /// Latest firewall health snapshot (None until the first check).
    pub health: Mutex<Option<crate::health::Snapshot>>,
    /// Called on the monitor thread for each finding that should alert (desktop toast, repaint...).
    pub on_alert: AlertHook,
    /// Called after every cycle (e.g. to request a GUI repaint).
    pub on_cycle: Box<dyn Fn() + Send + Sync>,
}

impl Shared {
    pub fn bump(&self) {
        self.data_version.fetch_add(1, Ordering::Relaxed);
    }
    pub fn status(&self) -> Status {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn set_status(&self, f: impl FnOnce(&mut Status)) {
        f(&mut self.status.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

impl Monitor {
    pub fn start(shared: Arc<Shared>) -> Monitor {
        let (tx, rx) = channel();
        let join = std::thread::Builder::new()
            .name("monitor".into())
            .spawn(move || {
                let cfg = shared.cfg.read().unwrap_or_else(|e| e.into_inner()).clone();
                let api = if cfg.opnsense.url.trim().is_empty() {
                    None
                } else {
                    match OPNsense::new(&cfg.opnsense) {
                        Ok(a) => Some(a),
                        Err(e) => {
                            error!("{e:#}");
                            None
                        }
                    }
                };
                let syslog = if cfg.syslog.enabled {
                    match SyslogReceiver::start(&cfg.syslog.bind, cfg.syslog.port, &cfg.syslog.protocol) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            error!("could not open syslog port {}/{}: {e}", cfg.syslog.protocol, cfg.syslog.port);
                            None
                        }
                    }
                } else {
                    None
                };
                if api.is_none() && syslog.is_none() {
                    error!("Nothing to collect from - set the firewall URL or enable the syslog receiver in Settings.");
                    shared.set_status(|s| s.running = false);
                    (shared.on_cycle)();
                    return;
                }
                shared.set_status(|s| {
                    s.running = true;
                    s.last_error = None;
                });
                info!("Monitoring started (poll every {}s)", cfg.poll_seconds);
                let mut last_prune = Instant::now() - Duration::from_secs(7200);
                let mut last_health: Option<Instant> = None;
                let mut down_since: Option<chrono::DateTime<chrono::Utc>> = None;
                loop {
                    let mut added = 0;
                    let mut err = None;
                    if let Some(api) = &api {
                        match collect::poll_api(api, &shared.store, cfg.opnsense.page_size, cfg.opnsense.max_pages) {
                            Ok(n) => added += n,
                            Err(e) => {
                                error!("API poll failed: {e:#}");
                                err = Some(format!("{e:#}"));
                            }
                        }
                    }
                    if let Some(s) = &syslog {
                        added += s.flush(&shared.store).unwrap_or(0);
                    }
                    // Heartbeat: is the firewall API reachable?
                    if api.is_some() {
                        match &err {
                            Some(_) => down_since = down_since.or(Some(chrono::Utc::now())),
                            None => down_since = None,
                        }
                        if let Ok(alerts) = crate::health::heartbeat(&cfg, &shared.store, down_since, err.as_deref().unwrap_or("")) {
                            for f in &alerts {
                                (shared.on_alert)(&shared, f);
                            }
                            if !alerts.is_empty() {
                                shared.bump();
                            }
                        }
                    }
                    // Health checks every interval (and right away on start).
                    if let Some(api) = api.as_ref().filter(|_| cfg.health.enabled && err.is_none()) {
                        let due = last_health.is_none_or(|t| t.elapsed() >= Duration::from_secs(cfg.health.interval_minutes.max(1) as u64 * 60));
                        if due {
                            last_health = Some(Instant::now());
                            match crate::health::run(&cfg, &shared.store, api) {
                                Ok((snap, alerts)) => {
                                    *shared.health.lock().unwrap_or_else(|e| e.into_inner()) = Some(snap);
                                    for f in &alerts {
                                        (shared.on_alert)(&shared, f);
                                    }
                                    shared.bump();
                                }
                                Err(e) => error!("health check failed: {e:#}"),
                            }
                        }
                    }
                    if added > 0 {
                        info!("{added} new IPS events");
                    }
                    match engine::run_detection(&cfg, &shared.store, api.as_ref(), Some(&crate::now_iso()), true) {
                        Ok(alerted) => {
                            for f in &alerted {
                                (shared.on_alert)(&shared, f);
                            }
                            if added > 0 || !alerted.is_empty() {
                                shared.bump();
                            }
                        }
                        Err(e) => error!("detection failed: {e:#}"),
                    }
                    if last_prune.elapsed() > Duration::from_secs(3600) {
                        if let Ok(n) = engine::prune(&cfg, &shared.store) {
                            if n > 0 {
                                info!("pruned {n} events older than {} days", cfg.retention_days);
                            }
                        }
                        last_prune = Instant::now();
                    }
                    shared.set_status(|s| {
                        s.last_poll = Some(chrono::Local::now().format("%H:%M:%S").to_string());
                        s.last_added = added;
                        s.last_error = err;
                    });
                    (shared.on_cycle)();
                    match rx.recv_timeout(Duration::from_secs(cfg.poll_seconds.max(10))) {
                        Ok(Cmd::PollNow) | Err(RecvTimeoutError::Timeout) => {}
                        Ok(Cmd::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                drop(syslog);
                shared.set_status(|s| s.running = false);
                info!("Monitoring stopped");
                (shared.on_cycle)();
            })
            .expect("spawn monitor thread");
        Monitor { tx, join: Some(join) }
    }

    pub fn poll_now(&self) {
        let _ = self.tx.send(Cmd::PollNow);
    }

    pub fn is_finished(&self) -> bool {
        self.join.as_ref().is_none_or(|j| j.is_finished())
    }

    /// Ask the thread to stop without waiting (it finishes its current HTTP call first).
    pub fn stop(&self) {
        let _ = self.tx.send(Cmd::Stop);
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
    }
}
