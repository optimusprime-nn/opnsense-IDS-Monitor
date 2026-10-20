//! Native Windows toast notifications for new findings.

use crate::config::Severity;
use crate::store::Finding;

pub const APP_ID: &str = "IPSWatch.Monitor";

/// Register our AppUserModelID so toasts show "IPS Watch" as the sender (per-user, no admin).
#[cfg(windows)]
pub fn register_app_id() {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    let path = format!(r"Software\Classes\AppUserModelId\{APP_ID}");
    if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(path) {
        let _ = key.set_value("DisplayName", &"IPS Watch");
        if let Some(icon) = icon_png_path() {
            let _ = key.set_value("IconUri", &icon.display().to_string());
        }
    }
}

/// The toast icon is written next to the config as a small PNG.
#[cfg(windows)]
fn icon_png_path() -> Option<std::path::PathBuf> {
    let p = crate::config::default_config_path().with_file_name("ipswatch.png");
    if !p.exists() {
        std::fs::create_dir_all(p.parent()?).ok()?;
        std::fs::write(&p, crate::icon::png(64)).ok()?;
    }
    Some(p)
}

#[cfg(windows)]
pub fn show(f: &Finding) {
    use tauri_winrt_notification::{Duration, Sound, Toast};
    let sev = match f.severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "low",
    };
    let first_reason = f.reasons.first().cloned().unwrap_or_default();
    let r = Toast::new(APP_ID)
        .title(&format!("{sev}: {}", f.title))
        .text1(&first_reason)
        .text2(&format!("Score {} · {} events · open IPS Watch from the tray for details", f.score, f.event_count))
        .sound(Some(if f.severity >= Severity::High { Sound::Default } else { Sound::IM }))
        .duration(if f.severity == Severity::Critical { Duration::Long } else { Duration::Short })
        .show();
    if let Err(e) = r {
        log::error!("desktop notification failed: {e:?}");
    }
}

#[cfg(not(windows))]
pub fn register_app_id() {}
#[cfg(not(windows))]
pub fn show(f: &Finding) {
    log::warn!("ALERT {}", f.title);
}
