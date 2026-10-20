//! Start with Windows via the per-user Run key (no admin rights needed).

use anyhow::Result;

const VALUE: &str = "IPSWatch";

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Command line registered for autostart: the current exe, launched hidden in the tray.
pub fn command() -> Result<String> {
    let exe = std::env::current_exe()?;
    Ok(format!("\"{}\" --minimized", exe.display()))
}

#[cfg(windows)]
pub fn is_enabled() -> bool {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(VALUE))
        .is_ok()
}

/// True when the registered command points at a different exe (e.g. the app was moved).
#[cfg(windows)]
pub fn is_stale() -> bool {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    match RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY).and_then(|k| k.get_value::<String, _>(VALUE)) {
        Ok(v) => command().map(|c| !c.eq_ignore_ascii_case(&v)).unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn set_enabled(on: bool) -> Result<()> {
    use winreg::{enums::*, RegKey};
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)?;
    if on {
        key.set_value(VALUE, &command()?)?;
    } else {
        match key.delete_value(VALUE) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn is_enabled() -> bool {
    false
}
#[cfg(not(windows))]
pub fn is_stale() -> bool {
    false
}
#[cfg(not(windows))]
pub fn set_enabled(_on: bool) -> Result<()> {
    anyhow::bail!("start with Windows is only available on Windows")
}
