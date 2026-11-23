//! The JSON Web Token pieces sign-in and the Event Grid webhook need: the
//! tenant's published RSA signing keys, RS256 signature checks with `ring`,
//! and the OpenID Connect ID token checks.
//!
//! Only RS256 is accepted. `none`, HS*, ES*, PS* and anything else are
//! refused before a key is looked at, as are a header with `crit` or `cty`,
//! a `typ` other than JWT, and one without a `kid`. The signature is checked
//! before any claim is trusted.
//!
//! Errors are fixed [`JwtError`] codes. Tokens and claim values are never
//! put in an error, so they can't reach the logs.

use std::fmt;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::{Map, Value};

use crate::auth::crypto::constant_time_eq;

/// Clock skew allowed on `exp`, `nbf` and `iat`, in seconds. Five minutes,
/// as Microsoft's own token libraries allow by default.
pub const CLOCK_SKEW_SECS: i64 = 5 * 60;

/// Longest ID token read, in bytes.
pub const MAX_ID_TOKEN_BYTES: usize = 64 * 1024;

/// Longest `kid` accepted, in a token header or a published key.
const MAX_KID_LEN: usize = 128;

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    /// Not three base64url parts of JSON, or too long.
    Malformed,
    /// `alg` isn't RS256, or the header asks for something Keyring doesn't
    /// do (`crit`, `cty`, a `typ` other than JWT, no `kid`).
    Algorithm,
    /// No published key with this `kid`.
    UnknownKey,
    /// The signature doesn't match the key.
    Signature,
    Issuer,
    /// `aud` doesn't hold the client ID, or `azp` isn't the client ID.
    Audience,
    /// Past `exp`, or no `exp`.
    Expired,
    /// Before `nbf`, or `iat` in the future.
    NotYetValid,
    /// No `sub`.
    Subject,
    /// `nonce` missing or not the one this sign-in sent.
    Nonce,
}

impl JwtError {
    /// True when the signing keys may be out of date: no key had this
    /// `kid`, or the key with it didn't match. Fetching the keys again may
    /// help.
    pub fn is_key_miss(self) -> bool {
        matches!(self, Self::UnknownKey | Self::Signature)
    }
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "token is malformed",
            Self::Algorithm => "token header is not RS256 with a key ID",
            Self::UnknownKey => "no published signing key matches the token",
            Self::Signature => "token signature does not match",
            Self::Issuer => "token issuer is wrong",
            Self::Audience => "token audience is wrong",
            Self::Expired => "token has expired",
            Self::NotYetValid => "token is not valid yet",
            Self::Subject => "token has no subject",
            Self::Nonce => "token nonce does not match",
        })
    }
}

impl std::error::Error for JwtError {}

/// Unix seconds now.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A NumericDate claim (`exp`, `auth_time`), whole seconds. Fractions are
/// dropped.
pub fn timestamp(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| {
        v.as_f64()
            .filter(|f| f.is_finite() && f.abs() < 1e15)
            .map(|f| f as i64)
    })
}

fn b64(part: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(part).ok()
}

/// A big-endian integer with its leading zero bytes removed, as `ring`
/// wants it.
fn without_leading_zeros(mut v: Vec<u8>) -> Vec<u8> {
    let zeros = v.iter().take_while(|b| **b == 0).count();
    v.drain(..zeros);
    v
}

/// One RSA public key from the tenant's key set.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwk {
    kid: String,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwk")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl Jwk {
    /// A key from its JWK JSON. `None` for anything but an RSA signing key
    /// for RS256 with a `kid`: `use`, when present, must be `sig`, and
    /// `alg`, when present, `RS256`.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        if o.get("kty")?.as_str()? != "RSA" {
            return None;
        }
        if o.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
            return None;
        }
        if o.get("alg").is_some_and(|a| a.as_str() != Some("RS256")) {
            return None;
        }
        let kid = o
            .get("kid")?
            .as_str()
            .filter(|k| (1..=MAX_KID_LEN).contains(&k.len()))?
            .to_owned();
        let n = without_leading_zeros(b64(o.get("n")?.as_str()?)?);
        let e = without_leading_zeros(b64(o.get("e")?.as_str()?)?);
        if n.is_empty() || e.is_empty() {
            return None;
        }
        Some(Self { kid, n, e })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// True when `signature` is this key's RSASSA-PKCS1-v1_5 SHA-256
    /// signature of `signing_input`. Keys under 2048 bits never verify.
    pub fn verify_rs256(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        RsaPublicKeyComponents {
            n: self.n.as_slice(),
            e: self.e.as_slice(),
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input, signature)
        .is_ok()
    }
}

/// The tenant's published signing keys (`jwks_uri`).
#[derive(Debug, Clone, Default)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    /// Read a JWK set. Keys Keyring can't use are skipped; `None` only when
    /// the document isn't a JWK set at all.
    pub fn from_json(body: &[u8]) -> Option<Self> {
        let doc: Value = serde_json::from_slice(body).ok()?;
        let keys = doc.get("keys")?.as_array()?;
        Some(Self {
            keys: keys.iter().filter_map(Jwk::from_json).collect(),
        })
    }

    /// The key with this `kid`, if exactly one has it.
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        let mut it = self.keys.iter().filter(|k| k.kid == kid);
        match (it.next(), it.next()) {
            (Some(k), None) => Some(k),
            _ => None,
        }
    }
}

/// A token split and decoded, its header checked, its signature not yet.
pub struct Unverified<'a> {
    pub kid: String,
    /// `<header>.<payload>`, the bytes the signature covers.
    pub signing_input: &'a str,
    pub signature: Vec<u8>,
    pub claims: Map<String, Value>,
}

/// Split a compact JWS and check its header: RS256 with a `kid`, nothing
/// Keyring doesn't understand.
pub fn split(token: &str) -> Result<Unverified<'_>, JwtError> {
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(JwtError::Malformed);
    };
    let header: Map<String, Value> = b64(h)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    let claims: Map<String, Value> = b64(p)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    let signature = b64(s).ok_or(JwtError::Malformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(JwtError::Algorithm);
    }
    if header.contains_key("crit") || header.contains_key("cty") {
        return Err(JwtError::Algorithm);
    }
    if let Some(typ) = header.get("typ")
        && !typ.as_str().is_some_and(|t| t.eq_ignore_ascii_case("JWT"))
    {
        return Err(JwtError::Algorithm);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| (1..=MAX_KID_LEN).contains(&k.len()))
        .ok_or(JwtError::Algorithm)?
        .to_owned();
    Ok(Unverified {
        kid,
        signing_input: &token[..h.len() + 1 + p.len()],
        signature,
        claims,
    })
}

/// What an ID token must say.
#[derive(Debug, Clone, Copy)]
pub struct IdTokenCheck<'a> {
    /// The issuer from discovery, matched exactly.
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// The nonce this sign-in sent.
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
}

/// Check an ID token from the token endpoint: header, signature against
/// `keys`, then issuer, audience, authorised party, expiry, not-before,
/// issued-at, subject and nonce. The claims, once every check passed.
pub fn verify_id_token(
    token: &str,
    keys: &Jwks,
    check: &IdTokenCheck<'_>,
) -> Result<Map<String, Value>, JwtError> {
    if token.len() > MAX_ID_TOKEN_BYTES {
        return Err(JwtError::Malformed);
    }
    let t = split(token)?;
    let key = keys.find(&t.kid).ok_or(JwtError::UnknownKey)?;
    if !key.verify_rs256(t.signing_input.as_bytes(), &t.signature) {
        return Err(JwtError::Signature);
    }
    check_id_claims(&t.claims, check)?;
    Ok(t.claims)
}

fn check_id_claims(c: &Map<String, Value>, check: &IdTokenCheck<'_>) -> Result<(), JwtError> {
    if c.get("iss").and_then(Value::as_str) != Some(check.issuer) {
        return Err(JwtError::Issuer);
    }
    let audiences: Vec<&str> = match c.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(a)) => a
            .iter()
            .map(Value::as_str)
            .collect::<Option<_>>()
            .ok_or(JwtError::Audience)?,
        _ => return Err(JwtError::Audience),
    };
    if !audiences.contains(&check.client_id) {
        return Err(JwtError::Audience);
    }
    // With more than one audience, `azp` must say the token is for us. When
    // it is there at all, it must be us.
    match c.get("azp") {
        None if audiences.len() > 1 => return Err(JwtError::Audience),
        None => {}
        Some(azp) if azp.as_str() == Some(check.client_id) => {}
        Some(_) => return Err(JwtError::Audience),
    }
    let exp = c.get("exp").and_then(timestamp).ok_or(JwtError::Expired)?;
    if check.now >= exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err(JwtError::Expired);
    }
    let latest = check.now.saturating_add(CLOCK_SKEW_SECS);
    if let Some(v) = c.get("nbf")
        && timestamp(v).is_none_or(|nbf| nbf > latest)
    {
        return Err(JwtError::NotYetValid);
    }
    let iat = c
        .get("iat")
        .and_then(timestamp)
        .ok_or(JwtError::NotYetValid)?;
    if iat > latest {
        return Err(JwtError::NotYetValid);
    }
    if !c
        .get("sub")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return Err(JwtError::Subject);
    }
    // Compared as digests, so neither the time taken nor the lengths say
    // anything about the expected nonce.
    let nonce = c
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(JwtError::Nonce)?;
    let got = digest(&SHA256, nonce.as_bytes());
    let want = digest(&SHA256, check.nonce.as_bytes());
    if !constant_time_eq(got.as_ref(), want.as_ref()) {
        return Err(JwtError::Nonce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
    use serde_json::json;

    use super::*;

    const K1: &[u8] = include_bytes!("../../tests/fixtures/test-idp-k1.pk8");
    const K2: &[u8] = include_bytes!("../../tests/fixtures/test-idp-k2.pk8");
    const ISS: &str = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0";
    const CLIENT: &str = "11111111-1111-1111-1111-111111111111";
    const NOW: i64 = 1_800_000_000;

    fn pair(der: &[u8]) -> RsaKeyPair {
        RsaKeyPair::from_pkcs8(der).unwrap()
    }

    fn jwk(der: &[u8], kid: &str) -> Value {
        let c = RsaPublicKeyComponents::<Vec<u8>>::from(pair(der).public());
        json!({
            "kty": "RSA", "use": "sig", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(&c.n), "e": URL_SAFE_NO_PAD.encode(&c.e),
        })
    }

    fn keys() -> Jwks {
        Jwks::from_json(json!({ "keys": [jwk(K1, "k1")] }).to_string().as_bytes()).unwrap()
    }

    fn sign(der: &[u8], header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let key = pair(der);
        let mut sig = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn header() -> Value {
        json!({"alg": "RS256", "typ": "JWT", "kid": "k1"})
    }

    fn claims() -> Value {
        json!({
            "iss": ISS, "aud": CLIENT, "sub": "subject",
            "exp": NOW + 3600, "iat": NOW, "nbf": NOW, "nonce": "the-nonce",
        })
    }

    fn check(token: &str) -> Result<Map<String, Value>, JwtError> {
        verify_id_token(
            token,
            &keys(),
            &IdTokenCheck {
                issuer: ISS,
                client_id: CLIENT,
                nonce: "the-nonce",
                now: NOW,
            },
        )
    }

    fn with(f: impl FnOnce(&mut Map<String, Value>)) -> Result<Map<String, Value>, JwtError> {
        let mut c = claims();
        f(c.as_object_mut().unwrap());
        check(&sign(K1, &header(), &c))
    }

    #[test]
    fn a_good_token_passes() {
        let c = check(&sign(K1, &header(), &claims())).unwrap();
        assert_eq!(c["sub"], "subject");
        // An array audience with us in it, and no typ header.
        assert!(
            with(|c| {
                c.insert("aud".into(), json!([CLIENT]));
            })
            .is_ok()
        );
        assert!(check(&sign(K1, &json!({"alg": "RS256", "kid": "k1"}), &claims())).is_ok());
        // Several audiences are fine when azp says it's ours.
        assert!(
            with(|c| {
                c.insert("aud".into(), json!([CLIENT, "other"]));
                c.insert("azp".into(), json!(CLIENT));
            })
            .is_ok()
        );
        // Clock skew either side.
        assert!(
            with(|c| {
                c.insert("exp".into(), json!(NOW - 60));
            })
            .is_ok()
        );
        assert!(
            with(|c| {
                c.insert("nbf".into(), json!(NOW + 60));
            })
            .is_ok()
        );
        assert!(
            with(|c| {
                c.insert("iat".into(), json!(NOW + 60));
            })
            .is_ok()
        );
    }

    #[test]
    fn only_rs256_with_a_key_id() {
        for bad in [
            json!({"alg": "none", "kid": "k1"}),
            json!({"alg": "HS256", "kid": "k1"}),
            json!({"alg": "RS384", "kid": "k1"}),
            json!({"alg": "PS256", "kid": "k1"}),
            json!({"alg": "ES256", "kid": "k1"}),
            json!({"alg": "rs256", "kid": "k1"}),
            json!({"kid": "k1"}),
            json!({"alg": "RS256"}),
            json!({"alg": "RS256", "kid": ""}),
            json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}),
            json!({"alg": "RS256", "kid": "k1", "crit": ["exp"]}),
            json!({"alg": "RS256", "kid": "k1", "cty": "JWT"}),
        ] {
            assert_eq!(
                check(&sign(K1, &bad, &claims())).err(),
                Some(JwtError::Algorithm),
                "{bad}"
            );
        }
        // alg none with no signature at all.
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        assert_eq!(check(&unsigned).err(), Some(JwtError::Algorithm));
        for bad in ["", "a.b", "a.b.c.d", "!!.e30.c2ln", "e30.e30.!!"] {
            assert_eq!(check(bad).err(), Some(JwtError::Malformed), "{bad}");
        }
    }

    #[test]
    fn wrong_key_or_tampering_fails() {
        let unknown = sign(K1, &json!({"alg": "RS256", "kid": "k9"}), &claims());
        assert_eq!(check(&unknown).err(), Some(JwtError::UnknownKey));
        // Signed by a key that was never published, under a published kid.
        assert_eq!(
            check(&sign(K2, &header(), &claims())).err(),
            Some(JwtError::Signature)
        );
        let good = sign(K1, &header(), &claims());
        let parts: Vec<&str> = good.split('.').collect();
        let mut c = claims();
        c["sub"] = json!("someone-else");
        let forged = URL_SAFE_NO_PAD.encode(c.to_string());
        assert_eq!(
            check(&format!("{}.{forged}.{}", parts[0], parts[2])).err(),
            Some(JwtError::Signature),
            "tampered payload"
        );
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig[10] ^= 1;
        let sig = URL_SAFE_NO_PAD.encode(sig);
        assert_eq!(
            check(&format!("{}.{}.{sig}", parts[0], parts[1])).err(),
            Some(JwtError::Signature),
            "tampered signature"
        );
        assert!(JwtError::UnknownKey.is_key_miss());
        assert!(JwtError::Signature.is_key_miss());
        assert!(!JwtError::Nonce.is_key_miss());
        assert!(!JwtError::Audience.is_key_miss());
    }

    #[test]
    fn claims_are_checked() {
        type Edit = Box<dyn FnOnce(&mut Map<String, Value>)>;
        let cases: Vec<(JwtError, Edit)> = vec![
            (
                JwtError::Issuer,
                Box::new(|c| {
                    c.remove("iss");
                }),
            ),
            (
                JwtError::Issuer,
                Box::new(|c| {
                    c.insert("iss".into(), json!(format!("{ISS}/")));
                }),
            ),
            (
                JwtError::Audience,
                Box::new(|c| {
                    c.insert("aud".into(), json!("other"));
                }),
            ),
            (
                JwtError::Audience,
                Box::new(|c| {
                    c.remove("aud");
                }),
            ),
            (
                JwtError::Audience,
                Box::new(|c| {
                    c.insert("aud".into(), json!([CLIENT, 5]));
                }),
            ),
            (
                JwtError::Audience,
                Box::new(|c| {
                    c.insert("aud".into(), json!([CLIENT, "other"]));
                }),
            ),
            (
                JwtError::Audience,
                Box::new(|c| {
                    c.insert("azp".into(), json!("other"));
                }),
            ),
            (
                JwtError::Expired,
                Box::new(|c| {
                    c.insert("exp".into(), json!(NOW - CLOCK_SKEW_SECS));
                }),
            ),
            (
                JwtError::Expired,
                Box::new(|c| {
                    c.remove("exp");
                }),
            ),
            (
                JwtError::Expired,
                Box::new(|c| {
                    c.insert("exp".into(), json!("never"));
                }),
            ),
            (
                JwtError::NotYetValid,
                Box::new(|c| {
                    c.insert("nbf".into(), json!(NOW + CLOCK_SKEW_SECS + 1));
                }),
            ),
            (
                JwtError::NotYetValid,
                Box::new(|c| {
                    c.insert("nbf".into(), json!("soon"));
                }),
            ),
            (
                JwtError::NotYetValid,
                Box::new(|c| {
                    c.insert("iat".into(), json!(NOW + CLOCK_SKEW_SECS + 1));
                }),
            ),
            (
                JwtError::NotYetValid,
                Box::new(|c| {
                    c.remove("iat");
                }),
            ),
            (
                JwtError::Subject,
                Box::new(|c| {
                    c.remove("sub");
                }),
            ),
            (
                JwtError::Subject,
                Box::new(|c| {
                    c.insert("sub".into(), json!(""));
                }),
            ),
            (
                JwtError::Nonce,
                Box::new(|c| {
                    c.insert("nonce".into(), json!("not-the-nonce"));
                }),
            ),
            (
                JwtError::Nonce,
                Box::new(|c| {
                    c.remove("nonce");
                }),
            ),
        ];
        for (want, f) in cases {
            assert_eq!(with(f).err(), Some(want));
        }
    }

    #[test]
    fn key_sets_keep_only_usable_keys() {
        let mut enc = jwk(K2, "enc");
        enc["use"] = json!("enc");
        let mut hs = jwk(K2, "hs");
        hs["alg"] = json!("HS256");
        let mut no_kid = jwk(K2, "x");
        no_kid.as_object_mut().unwrap().remove("kid");
        let ec = json!({"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"});
        let mut padded = jwk(K2, "padded");
        let n = URL_SAFE_NO_PAD
            .decode(padded["n"].as_str().unwrap())
            .unwrap();
        padded["n"] = json!(URL_SAFE_NO_PAD.encode([&[0u8][..], &n].concat()));
        let set = json!({ "keys": [jwk(K1, "k1"), enc, hs, no_kid, ec, padded, jwk(K1, "dup"), jwk(K2, "dup")] });
        let set = Jwks::from_json(set.to_string().as_bytes()).unwrap();
        assert!(set.find("k1").is_some());
        for gone in ["enc", "hs", "x", "ec", "missing"] {
            assert!(set.find(gone).is_none(), "{gone}");
        }
        assert!(
            set.find("dup").is_none(),
            "an ambiguous kid matches nothing"
        );
        // A leading zero byte on n is fine.
        let padded = set.find("padded").unwrap();
        let t = sign(K2, &json!({"alg": "RS256", "kid": "padded"}), &claims());
        let u = split(&t).unwrap();
        assert!(padded.verify_rs256(u.signing_input.as_bytes(), &u.signature));
        assert_eq!(format!("{padded:?}"), r#"Jwk { kid: "padded", .. }"#);
        assert!(Jwks::from_json(b"[]").is_none());
        assert!(Jwks::from_json(b"not json").is_none());
    }

    #[test]
    fn timestamps_take_whole_and_fractional_seconds() {
        assert_eq!(timestamp(&json!(5)), Some(5));
        assert_eq!(timestamp(&json!(5.9)), Some(5));
        assert_eq!(timestamp(&json!("5")), None);
        assert_eq!(timestamp(&json!(1e300)), None);
    }
}
