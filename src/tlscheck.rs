//! "Check certificate": look at the firewall's HTTPS certificate and explain, in plain words,
//! whether Windows already trusts it (e.g. Let's Encrypt) and what to put in the settings.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Windows trusts it and the name matches: leave the CA file empty.
    Trusted,
    /// Trusted issuer, but the URL uses a name/IP the certificate doesn't cover.
    NameMismatch,
    /// Self-signed or private CA: a CA file (or Windows trust) is needed.
    Untrusted,
    /// Past its expiry date.
    Expired,
    /// The configured CA file makes it verify.
    TrustedViaCaFile,
}

#[derive(Debug, Clone)]
pub struct CertReport {
    pub verdict: Verdict,
    pub summary: String,
    /// A better Firewall URL to offer (e.g. the Let's Encrypt hostname).
    pub suggested_url: Option<String>,
}

struct CertInfo {
    subject_cn: String,
    issuer_cn: String,
    issuer_org: String,
    names: Vec<String>,
    not_after: String,
    expired: bool,
    self_signed: bool,
}

/// Split "https://host:port/path" into (host, port).
pub fn host_port(url: &str) -> Result<(String, u16)> {
    let rest = url.trim().strip_prefix("https://").or_else(|| url.trim().strip_prefix("http://"));
    let Some(rest) = rest else { bail!("The firewall URL must start with https://") };
    let authority = rest.split('/').next().unwrap_or("");
    if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').context("bad IPv6 address in URL")?;
        let port = tail.strip_prefix(':').map(str::parse).transpose()?.unwrap_or(443);
        return Ok((h.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse().context("bad port in URL")?)),
        None if !authority.is_empty() => Ok((authority.to_string(), 443)),
        None => bail!("The firewall URL has no host name"),
    }
}

fn parse(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("unreadable certificate: {e}"))?;
    let cn = |n: &X509Name| n.iter_common_name().next().and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for g in &san.value.general_names {
            match g {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => names.push(IpAddr::from(<[u8; 4]>::try_from(*b).unwrap()).to_string()),
                    16 => names.push(IpAddr::from(<[u8; 16]>::try_from(*b).unwrap()).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let mut subject_cn = cn(cert.subject());
    if names.is_empty() && !subject_cn.is_empty() {
        names.push(subject_cn.clone());
    }
    if subject_cn.is_empty() {
        subject_cn = names.first().cloned().unwrap_or_default();
    }
    let not_after = cert.validity().not_after;
    let ts = chrono::DateTime::from_timestamp(not_after.timestamp(), 0).unwrap_or_default();
    let issuer_org = cert.issuer().iter_organization().next().and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    Ok(CertInfo {
        issuer_cn: cn(cert.issuer()),
        issuer_org,
        self_signed: cert.subject() == cert.issuer(),
        expired: ts < chrono::Utc::now(),
        not_after: ts.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string(),
        subject_cn,
        names,
    })
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match p.strip_prefix("*.") {
        Some(suffix) => h.split_once('.').is_some_and(|(_, rest)| rest == suffix),
        None => p == h,
    }
}

/// TLS handshake; returns the server's leaf certificate (DER) or the handshake error.
fn handshake(host: &str, port: u16, connector: &native_tls::TlsConnector) -> Result<Result<Vec<u8>, String>> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("can't resolve {host}"))?
        .next()
        .with_context(|| format!("no address for {host}"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .with_context(|| format!("can't connect to {host}:{port} - is the address right and the web GUI reachable?"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(8)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(8)))?;
    match connector.connect(host, tcp) {
        Ok(mut s) => {
            let der = s.peer_certificate()?.map(|c| c.to_der()).transpose()?.unwrap_or_default();
            let _ = s.shutdown();
            let _ = s.flush();
            Ok(Ok(der))
        }
        Err(e) => Ok(Err(e.to_string())),
    }
}

pub fn check(url: &str, ca_file: &str) -> Result<CertReport> {
    let (host, port) = host_port(url)?;
    let strict = native_tls::TlsConnector::new()?;
    let lenient = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    let strict_result = handshake(&host, port, &strict)?;
    let der = match &strict_result {
        Ok(d) => d.clone(),
        Err(_) => handshake(&host, port, &lenient)?.map_err(|e| {
            if host.parse::<IpAddr>().is_ok() {
                anyhow::anyhow!(
                    "TLS handshake with {host} failed: {e}

The server may only answer when it's addressed by name.                      Try the firewall's host name instead of its IP address."
                )
            } else {
                anyhow::anyhow!("TLS handshake with {host} failed: {e}")
            }
        })?,
    };
    let info = parse(&der)?;
    let host_is_ip = host.parse::<IpAddr>().is_ok();
    let covered = info.names.iter().any(|n| name_matches(n, &host));
    let lets_encrypt = info.issuer_org.contains("Let's Encrypt");

    let issuer = match (lets_encrypt, info.issuer_org.is_empty()) {
        (true, _) => format!("Let's Encrypt (intermediate {})", info.issuer_cn),
        (false, false) => format!("{} ({})", info.issuer_org, info.issuer_cn),
        _ => info.issuer_cn.clone(),
    };
    let mut details = format!(
        "Issued to: {}\nIssued by: {}{}\nValid for: {}\nExpires: {}",
        info.subject_cn,
        issuer,
        if info.self_signed { " - self-signed" } else { "" },
        info.names.join(", "),
        info.not_after
    );

    let pick_name = || {
        info.names
            .iter()
            .find(|n| !n.starts_with("*.") && n.parse::<IpAddr>().is_err())
            .map(|n| if port == 443 { format!("https://{n}") } else { format!("https://{n}:{port}") })
    };

    if info.expired {
        details.insert_str(0, "The certificate has EXPIRED. Renew it on the firewall (for Let's Encrypt: Services > ACME Client > Certificates > Issue/Renew).\n\n");
        return Ok(CertReport { verdict: Verdict::Expired, summary: details, suggested_url: None });
    }

    if strict_result.is_ok() {
        let what = if lets_encrypt { "a Let's Encrypt certificate" } else { "a certificate from a CA" };
        let summary = format!(
            "Good news: the firewall uses {what} that Windows already trusts.\n\n\
             Leave \"CA certificate file\" EMPTY and keep \"Verify TLS certificate\" ticked.\n\n{details}"
        );
        return Ok(CertReport { verdict: Verdict::Trusted, summary, suggested_url: None });
    }

    // Trusted chain but wrong name? Typical for Let's Encrypt when the URL is an IP address.
    if !covered && !info.self_signed {
        let mut using_name = native_tls::TlsConnector::builder();
        using_name.danger_accept_invalid_hostnames(true);
        if let Ok(Ok(_)) = handshake(&host, port, &using_name.build()?) {
            let suggested = pick_name();
            let why = if host_is_ip {
                "Let's Encrypt (and other public CAs) can't issue certificates for private IP addresses, so connect by name instead."
            } else {
                "Use one of the names the certificate was issued for."
            };
            let summary = format!(
                "The certificate is trusted by Windows, but it isn't valid for \"{host}\", the address in Firewall URL.\n\
                 {why}\n\n\
                 Change Firewall URL to {} and leave \"CA certificate file\" EMPTY.\n\
                 The name must resolve to the firewall from this PC. If it doesn't, add a host override in OPNsense \
                 (Services > Unbound DNS > Overrides) pointing the name to the firewall's LAN IP.\n\n{details}",
                suggested.clone().unwrap_or_else(|| "the certificate's host name".into())
            );
            return Ok(CertReport { verdict: Verdict::NameMismatch, summary, suggested_url: suggested });
        }
    }

    // Not trusted by Windows: does the configured CA file fix it?
    if !ca_file.trim().is_empty() {
        let pem = std::fs::read(ca_file.trim()).with_context(|| format!("reading CA file {ca_file}"))?;
        let ca = native_tls::Certificate::from_pem(&pem).or_else(|_| native_tls::Certificate::from_der(&pem))?;
        let with_ca = native_tls::TlsConnector::builder().add_root_certificate(ca).build()?;
        if let Ok(Ok(_)) = handshake(&host, port, &with_ca) {
            let summary = format!("The certificate verifies using your CA certificate file. Nothing else to do.\n\n{details}");
            return Ok(CertReport { verdict: Verdict::TrustedViaCaFile, summary, suggested_url: None });
        }
    }

    let mut summary = String::from(
        "Windows does not trust this certificate (self-signed or from a private CA), so a CA certificate file is needed.\n\n\
         Download it from the firewall: System > Trust > Authorities (download icon on the CA). If it's the default \
         self-signed certificate, use System > Trust > Certificates and download the web GUI certificate. \
         Download the certificate only, never the private key.",
    );
    if !covered {
        summary += &format!(
            "\n\nAlso: the certificate is not valid for \"{host}\". Use {} as the Firewall URL, or create a new \
             certificate that includes this address.",
            pick_name().unwrap_or_else(|| "one of the names below".into())
        );
    }
    summary += &format!("\n\n{details}");
    Ok(CertReport { verdict: Verdict::Untrusted, summary, suggested_url: if covered { None } else { pick_name() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(host_port("https://192.168.1.1").unwrap(), ("192.168.1.1".into(), 443));
        assert_eq!(host_port("https://fw.example.com:8443/ui").unwrap(), ("fw.example.com".into(), 8443));
        assert_eq!(host_port("https://[fd00::1]:444").unwrap(), ("fd00::1".into(), 444));
        assert!(host_port("192.168.1.1").is_err());
    }

    #[test]
    fn wildcard_names() {
        assert!(name_matches("*.example.com", "fw.example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(name_matches("FW.example.com", "fw.EXAMPLE.com"));
        assert!(!name_matches("fw.example.com", "192.168.1.1"));
    }
}
