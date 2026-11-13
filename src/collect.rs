//! Event collectors: OPNsense API poller, syslog receiver, and EVE file import.

use anyhow::Result;
use ipnet::IpNet;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::normalize::{from_syslog_line, normalize, Event};
use crate::opnsense::OPNsense;
use crate::store::Store;

/// Alert history that one poll could not reach within its page budget. Until it is caught up,
/// `api_cursor` stays at `low`, so nothing between `low` and the pages already read is skipped.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Backlog {
    /// Oldest timestamp still to collect (the last complete cursor).
    low: String,
    /// Newest timestamp collected so far.
    high: String,
    /// Rows from the top of the (newest-first) log already read when `high` was newest.
    rows_done: u64,
}

const BACKLOG_KEY: &str = "api_backlog";

/// Pull alerts newer than the stored cursor (pages are newest-first).
pub fn poll_api(api: &OPNsense, store: &Store, page_size: u32, max_pages: u32) -> Result<usize> {
    poll_pages(|page, rows| api.ids_alerts(page, rows), store, page_size, max_pages)
}

/// The poller itself, with the page fetch passed in (tests use a fake alert log).
///
/// Each poll first reads the newest pages down to what is already stored. If an earlier poll ran
/// out of pages before reaching the cursor, it then continues where that one stopped (accounting
/// for rows that arrived on top since) until it reaches the cursor. The cursor only moves once
/// everything down to it has been read, so a flood never makes alerts silently disappear.
pub fn poll_pages(
    mut fetch: impl FnMut(u32, u32) -> Result<Vec<Value>>,
    store: &Store,
    page_size: u32,
    max_pages: u32,
) -> Result<usize> {
    let cursor = store.get_kv("api_cursor")?.unwrap_or_default();
    let backlog: Option<Backlog> = store.get_kv(BACKLOG_KEY)?.and_then(|s| serde_json::from_str(&s).ok());
    let high = backlog.as_ref().map_or(cursor.clone(), |b| b.high.clone());
    let low = backlog.as_ref().map_or(cursor.clone(), |b| b.low.clone());
    let size = page_size.max(1);
    let mut budget = max_pages.max(1);
    let mut batch = Vec::new();
    let mut newest = high.clone();

    // Reads pages from `page` on, keeping events at or after `floor`, until a row older than
    // `stop` (or the end of the log). Returns (reached stop / end, rows newer than stop, next page).
    let mut read = |mut page: u32, stop: &str, floor: &str, budget: &mut u32, batch: &mut Vec<Event>| -> Result<(bool, u64, u32)> {
        let mut above = 0u64;
        while *budget > 0 {
            let rows = fetch(page, size)?;
            *budget -= 1;
            page += 1;
            let mut reached = rows.is_empty() || (rows.len() as u32) < size;
            let mut below = false;
            for row in &rows {
                let Some(ev) = normalize(row) else {
                    above += u64::from(!below);
                    continue;
                };
                if !stop.is_empty() && ev.ts.as_str() < stop {
                    below = true;
                    reached = true;
                } else if !below && (stop.is_empty() || ev.ts.as_str() > stop) {
                    above += 1; // strictly newer: rows equal to `stop` were already read
                }
                if floor.is_empty() || ev.ts.as_str() >= floor {
                    if ev.ts > newest {
                        newest = ev.ts.clone();
                    }
                    batch.push(ev);
                }
            }
            if reached {
                return Ok((true, above, page));
            }
        }
        Ok((false, above, page))
    };

    // 1) Newest alerts down to what is already stored.
    let (head_done, head_rows, head_next) = read(1, &high, &low, &mut budget, &mut batch)?;
    let state = if !head_done {
        // Out of pages before reaching stored data: everything below is still owed.
        Some(Backlog { low: low.clone(), high: String::new(), rows_done: (head_next as u64 - 1) * size as u64 })
    } else if let Some(b) = &backlog {
        // 2) Continue the earlier catch-up below the new rows. Rows that arrived since push the
        // unread ones down; re-reading part of a page is harmless (events are de-duplicated).
        let offset = head_rows + b.rows_done;
        let start = (offset / size as u64) as u32 + 1;
        if budget == 0 {
            Some(Backlog { low: low.clone(), high: String::new(), rows_done: offset })
        } else {
            let (done, _, next) = read(start, &low, &low, &mut budget, &mut batch)?;
            (!done).then(|| Backlog { low: low.clone(), high: String::new(), rows_done: (next as u64 - 1) * size as u64 })
        }
    } else {
        None
    };

    let added = if batch.is_empty() { 0 } else { store.add_events(&batch, "api")? };
    match state {
        Some(mut b) => {
            b.high = newest;
            warn!("alert history is behind: alerts since {} are still being downloaded (more than {max_pages} pages)", if b.low.is_empty() { "the start" } else { b.low.as_str() });
            store.set_kv(BACKLOG_KEY, &serde_json::to_string(&b)?)?;
        }
        None => {
            if backlog.is_some() {
                info!("alert history caught up");
                store.delete_kv(BACKLOG_KEY)?;
            }
            if !newest.is_empty() && newest != cursor {
                store.set_kv("api_cursor", &newest)?;
            }
        }
    }
    Ok(added)
}

/// When the API poller is still catching up: a sentence saying since when.
pub fn collection_gap(store: &Store) -> Option<String> {
    let b: Backlog = serde_json::from_str(&store.get_kv(BACKLOG_KEY).ok()??).ok()?;
    Some(format!(
        "Alert history is behind: alerts since {} are still being downloaded from the firewall",
        if b.low.is_empty() { "the start of the log".to_string() } else { b.low }
    ))
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

/// Longest syslog line accepted (EVE alerts are a few KB).
pub const MAX_LINE: usize = 64 * 1024;
/// Simultaneous TCP syslog connections.
pub const MAX_CONNECTIONS: usize = 8;
/// Events held between flushes; more are dropped (and counted) until the next flush.
pub const MAX_QUEUED: usize = 50_000;
/// A TCP connection that sends nothing for this long is closed.
const IDLE_LIMIT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct Counters {
    dropped: AtomicU64,
    rejected: AtomicU64,
    oversized: AtomicU64,
}

/// Background syslog receiver for OPNsense remote logging of Suricata EVE JSON.
///
/// Only senders in `allowed` are accepted. Syslog is not authenticated (UDP senders can be
/// spoofed), so its events are stored as source "syslog" and never trigger blocking on their own.
pub struct SyslogReceiver {
    buf: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

impl SyslogReceiver {
    pub fn start(bind: &str, port: u16, protocol: &str, allowed: Vec<IpNet>) -> Result<Self> {
        anyhow::ensure!(!allowed.is_empty(), "no allowed syslog senders (set the firewall's address under Syslog > Allowed senders)");
        let buf = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let addr = format!("{bind}:{port}");
        let allowed = Arc::new(allowed);
        let permitted = {
            let (allowed, counters) = (allowed.clone(), counters.clone());
            move |ip: IpAddr| {
                let ip = match ip {
                    IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                    v4 => v4,
                };
                let ok = allowed.iter().any(|n| n.contains(&ip));
                if !ok {
                    counters.rejected.fetch_add(1, Ordering::Relaxed);
                }
                ok
            }
        };
        let push = {
            let (buf, counters) = (buf.clone(), counters.clone());
            move |line: &str| {
                if let Some(ev) = from_syslog_line(line).as_ref().and_then(normalize) {
                    let mut q = buf.lock().unwrap_or_else(|e| e.into_inner());
                    if q.len() < MAX_QUEUED {
                        q.push(ev);
                    } else {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        };
        if protocol == "tcp" {
            let listener = TcpListener::bind(&addr)?;
            listener.set_nonblocking(true)?;
            let stop2 = stop.clone();
            let open = Arc::new(AtomicUsize::new(0));
            let counters2 = counters.clone();
            crate::spawn_thread("syslog-tcp", move || {
                while !stop2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((sock, peer)) => {
                            if !permitted(peer.ip()) {
                                continue; // dropping `sock` closes it
                            }
                            if open.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                                counters2.rejected.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            open.fetch_add(1, Ordering::Relaxed);
                            let (push, stop3, open2, counters3) = (push.clone(), stop2.clone(), open.clone(), counters2.clone());
                            crate::spawn_thread("syslog-conn", move || {
                                read_tcp(sock, &stop3, &counters3, &push);
                                open2.fetch_sub(1, Ordering::Relaxed);
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
            crate::spawn_thread("syslog-udp", move || {
                let mut b = vec![0u8; 65536];
                while !stop2.load(Ordering::Relaxed) {
                    if let Ok((n, peer)) = sock.recv_from(&mut b) {
                        if permitted(peer.ip()) {
                            push(&String::from_utf8_lossy(&b[..n]));
                        }
                    }
                }
            });
        }
        let list: Vec<String> = allowed.iter().map(|n| n.to_string()).collect();
        info!("syslog receiver listening on {protocol}/{addr} (accepting {})", list.join(", "));
        Ok(Self { buf, stop, counters })
    }

    /// Write buffered events to the store (and report anything dropped since the last flush).
    pub fn flush(&self, store: &Store) -> Result<usize> {
        let items = std::mem::take(&mut *self.buf.lock().unwrap_or_else(|e| e.into_inner()));
        let take = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        let (dropped, rejected, oversized) = (take(&self.counters.dropped), take(&self.counters.rejected), take(&self.counters.oversized));
        if dropped + rejected + oversized > 0 {
            warn!("syslog: dropped {dropped} events (queue full), refused {rejected} packets/connections (unknown sender or too many connections), {oversized} oversized lines");
        }
        Ok(if items.is_empty() { 0 } else { store.add_events(&items, "syslog")? })
    }
}

/// Read newline-separated messages from one TCP connection, with a line-length and idle limit.
fn read_tcp(sock: std::net::TcpStream, stop: &AtomicBool, counters: &Counters, push: &impl Fn(&str)) {
    let _ = sock.set_nonblocking(false);
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let mut r = BufReader::new(sock);
    let mut line = Vec::new();
    let mut idle = Duration::ZERO;
    while !stop.load(Ordering::Relaxed) && idle < IDLE_LIMIT {
        let before = line.len();
        let room = (MAX_LINE + 1 - line.len()) as u64;
        match r.by_ref().take(room).read_until(b'\n', &mut line) {
            Ok(0) if line.len() == before => break, // closed
            Ok(_) | Err(_) if line.len() > MAX_LINE => {
                counters.oversized.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Ok(_) => {
                idle = Duration::ZERO;
                if line.ends_with(b"\n") {
                    push(&String::from_utf8_lossy(&line));
                    line.clear();
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                if line.len() == before {
                    idle += Duration::from_secs(1);
                } else {
                    idle = Duration::ZERO;
                }
            }
            Err(_) => break,
        }
    }
}

impl Drop for SyslogReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
