use ipswatch::config::{self, Config};
fn main() { let p = std::path::Path::new("config.example.toml"); config::save(&Config::default(), p).unwrap(); }
