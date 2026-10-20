//! Touches the real per-user registry and shows a real toast, so it is opt-in:
//!     cargo test --test windows_integration -- --ignored
#![cfg(windows)]

#[test]
#[ignore]
fn autostart_toggle_and_toast() {
    use ipswatch::autostart;
    let was = autostart::is_enabled();
    autostart::set_enabled(true).unwrap();
    assert!(autostart::is_enabled());
    assert!(!autostart::is_stale(), "Run entry should point at this exe");
    autostart::set_enabled(false).unwrap();
    assert!(!autostart::is_enabled());
    autostart::set_enabled(was).unwrap(); // leave it as we found it

    ipswatch::logbuf::init(None, true);
    ipswatch::toast::register_app_id();
    let before = ipswatch::logbuf::len();
    let mut f = ipswatch::notify::sample_finding();
    f.title = "IPS Watch test notification (from cargo test)".into();
    ipswatch::toast::show(&f);
    let errors: Vec<_> = ipswatch::logbuf::lines().into_iter().skip(before).filter(|l| l.level == log::Level::Error).map(|l| l.text).collect();
    assert!(errors.is_empty(), "{errors:?}");
}
