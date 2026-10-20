//! Small Win32 helpers: window show/find, single instance, message box.

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsIconic, MessageBoxW, SetForegroundWindow, ShowWindow, MB_ICONERROR, MB_OK, SW_RESTORE, SW_SHOW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn show(hwnd: isize) {
        if hwnd == 0 {
            return;
        }
        let h = hwnd as _;
        // SAFETY: plain Win32 calls on a window handle owned by this process.
        unsafe {
            ShowWindow(h, SW_SHOW);
            if IsIconic(h) != 0 {
                ShowWindow(h, SW_RESTORE);
            }
            SetForegroundWindow(h);
        }
    }

    pub fn find_window(title: &str) -> isize {
        let t = wide(title);
        unsafe { FindWindowW(std::ptr::null(), t.as_ptr()) as isize }
    }

    /// Returns false if another instance already holds the mutex.
    pub fn claim_single_instance() -> bool {
        let name = wide("Local\\IPSWatch.SingleInstance");
        unsafe {
            let h = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            // Leak the handle on purpose: it must live as long as the process.
            !h.is_null() && GetLastError() != ERROR_ALREADY_EXISTS
        }
    }

    pub fn error_box(title: &str, text: &str) {
        let (t, x) = (wide(title), wide(text));
        unsafe { MessageBoxW(std::ptr::null_mut(), x.as_ptr(), t.as_ptr(), MB_OK | MB_ICONERROR) };
    }
}

#[cfg(windows)]
pub use imp::*;

/// The native window handle of the main viewport, as an integer (0 if unavailable).
pub fn hwnd_from(cc: &eframe::CreationContext<'_>) -> isize {
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        if let Ok(h) = cc.window_handle() {
            if let RawWindowHandle::Win32(w) = h.as_raw() {
                return w.hwnd.get();
            }
        }
        find_window(crate::WINDOW_TITLE)
    }
    #[cfg(not(windows))]
    {
        let _ = cc;
        0
    }
}

#[cfg(not(windows))]
pub fn show(_: isize) {}
#[cfg(not(windows))]
pub fn find_window(_: &str) -> isize {
    0
}
#[cfg(not(windows))]
pub fn claim_single_instance() -> bool {
    true
}
#[cfg(not(windows))]
pub fn error_box(_: &str, text: &str) {
    eprintln!("{text}");
}
