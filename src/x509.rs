//! Read the public parts of an X.509 certificate for display: subject,
//! issuer, validity, serial and SANs. Uses `x509-cert` (RustCrypto).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub sans: Vec<String>,
    pub self_signed: bool,
}

/// Summarise a DER certificate. `None` if it isn't one.
pub fn summarise(der: &[u8]) -> Option<Summary> {
    let cert = Certificate::from_der(der).ok()?;
    let tbs = cert.tbs_certificate();
    let v = tbs.validity();
    let mut sans = Vec::new();
    if let Some(exts) = tbs.extensions() {
        for ext in exts {
            if ext.extn_id == x509_cert::der::oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME
                && let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes())
            {
                for name in san.0 {
                    match name {
                        GeneralName::DnsName(n) => sans.push(n.to_string()),
                        GeneralName::Rfc822Name(n) => sans.push(n.to_string()),
                        GeneralName::UniformResourceIdentifier(n) => sans.push(n.to_string()),
                        GeneralName::IpAddress(ip) => sans.push(format_ip(ip.as_bytes())),
                        _ => {}
                    }
                }
            }
        }
    }
    let subject = tbs.subject().to_string();
    let issuer = tbs.issuer().to_string();
    Some(Summary {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: tbs
            .serial_number()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect(),
        not_before: v.not_before.to_unix_duration().as_secs() as i64,
        not_after: v.not_after.to_unix_duration().as_secs() as i64,
        sans,
    })
}

fn format_ip(b: &[u8]) -> String {
    match b.len() {
        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap_or([0; 16])).to_string(),
        _ => String::new(),
    }
}

/// DER to PEM with 64-character lines.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Every `-----BEGIN <label>-----` block in `pem`, decoded.
pub fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        let body: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Ok(der) = STANDARD.decode(body) {
            out.push(der);
        }
        rest = &after[stop + end.len()..];
    }
    out
}

/// Re-encode a parsed certificate, to check DER round-trips.
pub fn is_certificate(der: &[u8]) -> bool {
    Certificate::from_der(der)
        .and_then(|c| c.to_der())
        .is_ok_and(|again| again == der)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small self-signed test certificate: CN=keyring.test, SAN
    /// DNS:keyring.test and DNS:www.keyring.test, valid 2026-01-01 to
    /// 2036-01-01. Made with openssl for these tests only; no key is kept.
    pub(crate) const TEST_CERT_PEM: &str = include_str!("../tests/fixtures/test-cert.pem");

    #[test]
    fn summarises_a_certificate() {
        let der = &pem_blocks(TEST_CERT_PEM, "CERTIFICATE")[0];
        let s = summarise(der).unwrap();
        assert_eq!(s.subject, "CN=keyring.test");
        assert!(s.self_signed);
        assert_eq!(s.sans, vec!["keyring.test", "www.keyring.test"]);
        assert_eq!(crate::dates::iso_date(s.not_before), "2026-01-01");
        assert_eq!(crate::dates::iso_date(s.not_after), "2036-01-01");
        assert!(!s.serial.is_empty());
        assert!(is_certificate(der));
    }

    #[test]
    fn pem_round_trip() {
        let der = &pem_blocks(TEST_CERT_PEM, "CERTIFICATE")[0];
        let pem = to_pem("CERTIFICATE", der);
        assert_eq!(&pem_blocks(&pem, "CERTIFICATE")[0], der);
        assert!(pem.lines().all(|l| l.len() <= 64));
    }

    #[test]
    fn rejects_garbage() {
        assert!(summarise(b"not a cert").is_none());
        assert!(pem_blocks("nothing here", "CERTIFICATE").is_empty());
        assert!(!is_certificate(b"\x30\x03\x02\x01\x00"));
    }
}
