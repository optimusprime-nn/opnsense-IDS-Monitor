//! Logger that keeps recent lines in memory (for the Activity log view) and appends to a file.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const KEEP: usize = 5000;
const MAX_FILE: u64 = 5 * 1024 * 1024;

#[derive(Clone)]
pub struct Line {
    pub level: Level,
    pub text: String,
}

struct Buf {
    lines: Mutex<VecDeque<Line>>,
    file: Option<PathBuf>,
    stderr: bool,
}

static BUF: OnceLock<Buf> = OnceLock::new();

impl Log for Buf {
    fn enabled(&self, m: &Metadata) -> bool {
        // Our own crate/binaries at info level; dependencies only when they warn.
        let ours = m.target().to_ascii_lowercase().starts_with("ipswatch");
        (ours && m.level() <= Level::Info) || m.level() <= Level::Warn
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let text = format!("{}  {:<5} {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), r.level(), r.args());
        if self.stderr {
            eprintln!("{text}");
        }
        if let Some(p) = &self.file {
            if std::fs::metadata(p).map(|m| m.len() > MAX_FILE).unwrap_or(false) {
                let _ = std::fs::rename(p, p.with_extension("log.1"));
            }
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{text}");
            }
        }
        let mut q = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(Line { level: r.level(), text });
        while q.len() > KEEP {
            q.pop_front();
        }
    }

    fn flush(&self) {}
}

/// Install the logger. `file`: optional log file; `stderr`: also print (CLI).
pub fn init(file: Option<PathBuf>, stderr: bool) {
    let buf = BUF.get_or_init(|| Buf { lines: Mutex::new(VecDeque::new()), file, stderr });
    let _ = log::set_logger(buf);
    log::set_max_level(LevelFilter::Info);
}

/// Snapshot of recent lines (oldest first).
pub fn lines() -> Vec<Line> {
    BUF.get()
        .map(|b| b.lines.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect())
        .unwrap_or_default()
}

pub fn len() -> usize {
    BUF.get().map(|b| b.lines.lock().map(|q| q.len()).unwrap_or(0)).unwrap_or(0)
}

pub fn clear() {
    if let Some(b) = BUF.get() {
        b.lines.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}
