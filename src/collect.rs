//! Event collectors: OPNsense API poller, syslog receiver, and EVE file import.

use anyhow::Result;
use log::{error, info, warn};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::normalize::{from_syslog_line, normalize, Event};
use crate::opnsense::OPNsense;
use crate::store::Store;

/// Pull alerts newer than the stored cursor (pages are newest-first).
pub fn poll_api(api: &OPNsense, store: &Store, page_size: u32, max_pages: u32) -> Result<usize> {
    let cursor = store.get_kv("api_cursor")?.unwrap_or_default();
    let mut newest = cursor.clone();
    let mut batch = Vec::new();
    let mut complete = false;
    for page in 1..=max_pages {
        let rows = api.ids_alerts(page, page_size)?;
        if rows.is_empty() {
            complete = true;
            break;
        }
        let mut reached = false;
        for row in &rows {
            let Some(ev) = normalize(row) else { continue };
            if !cursor.is_empty() && ev.ts < cursor {
                reached = true;
                continue;
            }
            if ev.ts > newest {
                newest = ev.ts.clone();
            }
            batch.push(ev);
        }
        if reached || (rows.len() as u32) < page_size {
            complete = true;
            break;
        }
    }
    if !complete {
        warn!("hit max_pages={max_pages}; some older alerts may have been skipped");
    }
    let added = if batch.is_empty() { 0 } else { store.add_events(&batch, "api")? };
    if !newest.is_empty() && newest != cursor {
        store.set_kv("api_cursor", &newest)?;
    }
    Ok(added)
}

/// Import an eve.json (one JSON object per line) or a syslog capture.
pub fn import_file(path: &Path, store: &Store) -> Result<usize> {
    let f = std::fs::File::open(path)?;
    let mut batch = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line.unwrap_or_default();
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec = serde_json::from_str(line).ok().or_else(|| from_syslog_line(line));
        if let Some(ev) = rec.as_ref().and_then(normalize) {
            batch.push(ev);
        }
    }
    Ok(if batch.is_empty() { 0 } else { store.add_events(&batch, "file")? })
}

/// Background syslog receiver for OPNsense remote logging of Suricata EVE JSON.
pub struct SyslogReceiver {
    buf: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
}

impl SyslogReceiver {
    pub fn start(bind: &str, port: u16, protocol: &str) -> Result<Self> {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let addr = format!("{bind}:{port}");
        let push = {
            let buf = buf.clone();
            move |line: &str| {
                if let Some(ev) = from_syslog_line(line).as_ref().and_then(normalize) {
                    buf.lock().unwrap_or_else(|e| e.into_inner()).push(ev);
                }
            }
        };
        if protocol == "tcp" {
            let listener = TcpListener::bind(&addr)?;
            listener.set_nonblocking(true)?;
            let stop2 = stop.clone();
            std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((sock, _)) => {
                            let push = push.clone();
                            let stop3 = stop2.clone();
                            std::thread::spawn(move || {
                                let _ = sock.set_nonblocking(false);
                                let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
                                let mut r = BufReader::new(sock);
                                let mut line = String::new();
                                while !stop3.load(Ordering::Relaxed) {
                                    line.clear();
                                    match r.read_line(&mut line) {
                                        Ok(0) => break,
                                        Ok(_) => push(&line),
                                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(200)),
                        Err(e) => {
                            error!("syslog accept failed: {e}");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            });
        } else {
            let sock = UdpSocket::bind(&addr)?;
            sock.set_read_timeout(Some(Duration::from_millis(500)))?;
            let stop2 = stop.clone();
            std::thread::spawn(move || {
                let mut b = vec![0u8; 65536];
                while !stop2.load(Ordering::Relaxed) {
                    if let Ok((n, _)) = sock.recv_from(&mut b) {
                        push(&String::from_utf8_lossy(&b[..n]));
                    }
                }
            });
        }
        info!("syslog receiver listening on {protocol}/{addr}");
        Ok(Self { buf, stop })
    }

    /// Write buffered events to the store.
    pub fn flush(&self, store: &Store) -> Result<usize> {
        let items = std::mem::take(&mut *self.buf.lock().unwrap_or_else(|e| e.into_inner()));
        Ok(if items.is_empty() { 0 } else { store.add_events(&items, "syslog")? })
    }
}

impl Drop for SyslogReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
