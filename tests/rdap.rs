//! The owner lookup against a loopback stand-in for a registry; made-up records only.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ipswatch::rdap::{is_public, lookup, parse, Owner};

/// Answers each request in turn; reports the request lines it saw.
fn serve(answers: Vec<(u16, String)>) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for (status, body) in answers {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&seen).to_string();
            let _ = tx.send(head.lines().next().unwrap_or("").to_string());
            let reply = format!("HTTP/1.1 {status} X\r\nContent-Type: application/rdap+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (base, rx)
}

const RIPE_STYLE: &str = r#"{
  "handle": "192.0.2.0 - 192.0.2.255", "name": "EXAMPLE-NET", "type": "ASSIGNED PA", "country": "NL",
  "startAddress": "192.0.2.0", "endAddress": "192.0.2.255", "ipVersion": "v4",
  "events": [{"eventAction": "registration", "eventDate": "2011-03-04T10:11:12Z"}, {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"}],
  "entities": [
    {"handle": "ORG-EX1", "roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Hosting B.V."], ["kind", {}, "text", "org"]]]},
    {"handle": "AB1", "roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"], ["email", {}, "text", "abuse@example.net"]]]}
  ]
}"#;

const ARIN_STYLE: &str = r#"{
  "handle": "NET-198-51-100-0-1", "name": "EXAMPLE-BLK", "type": "DIRECT ALLOCATION",
  "startAddress": "198.51.100.0", "endAddress": "198.51.100.255",
  "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}], "arin_originas0_originautnums": [64500, 64501],
  "entities": [
    {"handle": "EXAMPLE", "roles": ["registrant"],
     "vcardArray": ["vcard", [["fn", {}, "text", "Example\u202e Cloud\tLLC"], ["org", {}, "text", ["Example Cloud LLC", "Network Operations"]]]],
     "entities": [{"handle": "ABUSE1", "roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.com"]]]}]}
  ]
}"#;

#[test]
fn a_record_is_read_whichever_registry_wrote_it() {
    let ripe = parse(&serde_json::from_str(RIPE_STYLE).unwrap());
    assert_eq!(
        ripe,
        Owner {
            name: Some("EXAMPLE-NET".into()),
            handle: Some("192.0.2.0 - 192.0.2.255".into()),
            range: Some("192.0.2.0 – 192.0.2.255".into()),
            organisation: Some("Example Hosting B.V.".into()),
            country: Some("NL".into()),
            kind: Some("ASSIGNED PA".into()),
            origin_as: None,
            abuse: Some("abuse@example.net".into()),
            registered: Some("2011-03-04".into()),
            changed: Some("2024-06-01".into()),
            source: None,
        }
    );

    // The abuse contact sits inside the registrant; the organisation is a structured value.
    let arin = parse(&serde_json::from_str(ARIN_STYLE).unwrap());
    assert_eq!((arin.organisation.as_deref(), arin.abuse.as_deref(), arin.range.as_deref(), arin.country.as_deref()), (Some("Example Cloud LLC"), Some("abuse@example.com"), Some("198.51.100.0/24"), None));
    let lines = arin.lines();
    assert_eq!(lines[0], "Organisation  Example Cloud LLC");
    assert_eq!(lines[1], "Network       EXAMPLE-BLK (NET-198-51-100-0-1)");
    assert!(lines.iter().all(|l| !l.starts_with("Country")));
    assert!(lines.contains(&"Announced by  AS64500, AS64501".to_string()));

    // A record that names nothing still says so.
    assert_eq!(parse(&serde_json::json!({"entities": "not a list", "name": 7})).lines(), ["The registry's record names nothing."]);
}

#[test]
fn text_from_a_record_is_cleaned() {
    let v = serde_json::json!({"name": "NET\u{202e}EVIL\n second line", "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "x".repeat(900)]]]}]});
    let owner = parse(&v);
    assert_eq!(owner.name.as_deref(), Some("NETEVIL  second line"));
    assert_eq!(owner.organisation.unwrap().chars().count(), 200);
}

#[test]
fn only_public_addresses_are_asked_about() {
    for private in ["10.1.2.3", "192.168.7.7", "172.16.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.2.1", "224.0.0.1", "255.255.255.255", "0.0.0.0", "::1", "fe80::1", "fd00::1", "2001:db8::1", "ff02::1"] {
        assert!(!is_public(private.parse().unwrap()), "{private}");
    }
    for public in ["9.9.9.9", "1.1.1.1", "100.128.0.1", "2620:fe::fe"] {
        assert!(is_public(public.parse().unwrap()), "{public}");
    }
    // A private address is never sent anywhere: this base would refuse the connection.
    let said = lookup("http://127.0.0.1:1", "192.168.7.7".parse().unwrap(), Duration::from_secs(2)).unwrap_err();
    assert!(said.contains("private or reserved"), "{said}");
}

#[test]
fn the_registry_is_asked_for_the_one_address() {
    let (base, seen) = serve(vec![(200, RIPE_STYLE.to_string()), (404, "{}".to_string()), (429, "{}".to_string()), (200, "<html>".to_string())]);
    let ip: IpAddr = "9.9.9.9".parse().unwrap();
    let wait = Duration::from_secs(5);

    let owner = lookup(&base, ip, wait).unwrap();
    assert_eq!(seen.recv().unwrap(), "GET /ip/9.9.9.9 HTTP/1.1");
    assert_eq!(owner.organisation.as_deref(), Some("Example Hosting B.V."));
    assert!(owner.source.as_deref().unwrap().starts_with("127.0.0.1:"));
    assert!(owner.lines().last().unwrap().starts_with("Answered by   127.0.0.1:"));

    assert_eq!(lookup(&base, ip, wait).unwrap_err(), "No registry has a record for 9.9.9.9.");
    assert!(lookup(&base, ip, wait).unwrap_err().contains("fewer questions"));
    assert_eq!(lookup(&base, ip, wait).unwrap_err(), "The registry's answer could not be read.");
    assert!(lookup("http://127.0.0.1:1", ip, Duration::from_secs(2)).unwrap_err().starts_with("The registry could not be reached"));
}
