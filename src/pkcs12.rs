//! Just enough PKCS #12 (`.pfx`) reading to check a file before upload:
//! is it a PFX at all, does it hold a private key, and which certificates
//! are stored without encryption.
//!
//! Nothing is decrypted. Most tools encrypt the certificate part of a PFX
//! with the password, so for those Key Vault does the full check on import.
//! A full PKCS #12 crate would add about 44 crates, some pre-release, for a
//! preview, so we read the outer structure by hand instead.

/// DER tag and value, borrowed from the input.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one TLV from the front of `input`, returning it and the rest.
fn read_tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((
        Tlv {
            tag,
            value: &rest[..len],
        },
        &rest[len..],
    ))
}

/// Every TLV inside a constructed value.
fn children(mut input: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (tlv, rest) = read_tlv(input)?;
        out.push(tlv);
        input = rest;
    }
    Some(out)
}

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const INTEGER: u8 = 0x02;
const CONTEXT_0: u8 = 0xa0;

// DER-encoded OID bodies.
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
const OID_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01,
];
const OID_SHROUDED_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
];
const OID_CERT_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
];

/// What we could tell about a PFX without the password.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PfxInfo {
    pub has_key: bool,
    /// Key or certificates are in a password-encrypted part we can't read.
    pub has_encrypted_part: bool,
    /// DER certificates stored without encryption.
    pub certs: Vec<Vec<u8>>,
}

/// Inspect a PFX. `None` if it isn't one.
pub fn inspect(der: &[u8]) -> Option<PfxInfo> {
    let (pfx, rest) = read_tlv(der)?;
    if pfx.tag != SEQUENCE || !rest.is_empty() {
        return None;
    }
    let parts = children(pfx.value)?;
    // version INTEGER 3
    let version = parts.first().filter(|t| t.tag == INTEGER)?;
    if version.value != [3] {
        return None;
    }
    // authSafe ContentInfo { data, [0] OCTET STRING }
    let auth_safe = parts.get(1).filter(|t| t.tag == SEQUENCE)?;
    let ci = children(auth_safe.value)?;
    if ci.first()?.tag != OID || ci[0].value != OID_DATA {
        return None;
    }
    let inner = content_octets(ci.get(1)?)?;
    let (seq, _) = read_tlv(inner)?;
    if seq.tag != SEQUENCE {
        return None;
    }
    let mut info = PfxInfo::default();
    for content_info in children(seq.value)? {
        let fields = children(content_info.value)?;
        let kind = fields.first().filter(|t| t.tag == OID)?;
        if kind.value == OID_ENCRYPTED_DATA {
            info.has_encrypted_part = true;
            continue;
        }
        if kind.value != OID_DATA {
            continue;
        }
        let Some(safe_contents) = fields.get(1).and_then(content_octets) else {
            continue;
        };
        let Some((bags, _)) = read_tlv(safe_contents) else {
            continue;
        };
        for bag in children(bags.value).unwrap_or_default() {
            let Some(bag_fields) = children(bag.value) else {
                continue;
            };
            let Some(bag_id) = bag_fields.first().filter(|t| t.tag == OID) else {
                continue;
            };
            if bag_id.value == OID_KEY_BAG || bag_id.value == OID_SHROUDED_KEY_BAG {
                info.has_key = true;
            } else if bag_id.value == OID_CERT_BAG
                && let Some(der) = bag_fields.get(1).and_then(cert_from_bag)
            {
                info.certs.push(der);
            }
        }
    }
    Some(info)
}

/// `[0] EXPLICIT OCTET STRING` content.
fn content_octets<'a>(t: &Tlv<'a>) -> Option<&'a [u8]> {
    if t.tag != CONTEXT_0 {
        return None;
    }
    let (octets, _) = read_tlv(t.value)?;
    (octets.tag == OCTET_STRING).then_some(octets.value)
}

/// CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
fn cert_from_bag(value: &Tlv<'_>) -> Option<Vec<u8>> {
    if value.tag != CONTEXT_0 {
        return None;
    }
    let (cert_bag, _) = read_tlv(value.value)?;
    let fields = children(cert_bag.value)?;
    content_octets(fields.get(1)?).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PFX_PLAIN: &[u8] = include_bytes!("../tests/fixtures/test-plain.pfx");
    const PFX_ENCRYPTED: &[u8] = include_bytes!("../tests/fixtures/test-encrypted.pfx");

    #[test]
    fn reads_unencrypted_certs() {
        let info = inspect(PFX_PLAIN).unwrap();
        assert!(info.has_key);
        assert_eq!(info.certs.len(), 1);
        let s = crate::x509::summarise(&info.certs[0]).unwrap();
        assert_eq!(s.subject, "CN=keyring.test");
    }

    #[test]
    fn spots_encrypted_parts() {
        let info = inspect(PFX_ENCRYPTED).unwrap();
        assert!(info.has_encrypted_part);
        assert!(info.certs.is_empty());
    }

    #[test]
    fn rejects_other_files() {
        assert!(inspect(b"").is_none());
        assert!(inspect(b"-----BEGIN CERTIFICATE-----").is_none());
        assert!(inspect(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_none());
        let pem_cert = crate::x509::pem_blocks(crate::x509::tests::TEST_CERT_PEM, "CERTIFICATE");
        assert!(
            inspect(&pem_cert[0]).is_none(),
            "a bare certificate isn't a PFX"
        );
        // Truncated input never panics.
        for n in 0..PFX_PLAIN.len().min(200) {
            let _ = inspect(&PFX_PLAIN[..n]);
        }
    }
}
