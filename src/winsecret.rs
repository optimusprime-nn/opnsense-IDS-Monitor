//! Protect secrets in the config file with Windows DPAPI (current-user scope).
//!
//! Values are stored as `dpapi:<base64>`, readable only by the same Windows user.
//! The format matches the earlier Python version.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};

const PREFIX: &str = "dpapi:";

#[cfg(windows)]
mod imp {
    use anyhow::{bail, Result};
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn call(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: input points to a live buffer; output is allocated by the OS and freed below.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(),
                                 std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(),
                                   std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if ok == 0 {
            bail!("DPAPI call failed (error {})", unsafe { GetLastError() });
        }
        let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(out)
    }
}

pub fn protect(value: &str) -> Result<String> {
    if value.is_empty() || value.starts_with(PREFIX) {
        return Ok(value.to_string());
    }
    #[cfg(windows)]
    {
        Ok(format!("{PREFIX}{}", B64.encode(imp::call(value.as_bytes(), true)?)))
    }
    #[cfg(not(windows))]
    {
        Ok(value.to_string())
    }
}

pub fn unprotect(value: &str) -> Result<String> {
    let Some(b64) = value.strip_prefix(PREFIX) else {
        return Ok(value.to_string());
    };
    let blob = B64.decode(b64)?;
    #[cfg(windows)]
    {
        Ok(String::from_utf8(imp::call(&blob, false)?)?)
    }
    #[cfg(not(windows))]
    {
        let _ = blob;
        anyhow::bail!("DPAPI-protected value can only be read on Windows")
    }
}
