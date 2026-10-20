fn main() {
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
