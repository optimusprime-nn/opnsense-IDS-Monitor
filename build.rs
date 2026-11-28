fn main() {
    // The UI thread runs on the main thread, which MSVC gives only 1 MiB of stack by default.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
        // The DLLs the program is linked against are loaded from System32 only, never from the
        // folder it runs in or the current one (DLL planting, e.g. a DLL in Downloads).
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    // Embed the application icon and version info into the Windows executables.
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/ipswatch.ico");
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/ipswatch.ico")
            .set("ProductName", "IPS Watch")
            .set("FileDescription", "IPS Watch - OPNsense intrusion monitor");
        if let Err(e) = res.compile() {
            // Missing rc.exe should not break the build; the exe just has no icon.
            println!("cargo:warning=could not embed icon: {e}");
        }
    }
}
