//! Key Vault keys REST API, called as the signed-in user.
//!
//! Only public key parts are ever requested or returned. There is no
//! export, backup or release call anywhere in Keyring.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::secrets::{Attributes, Timestamp};
use crate::azure::{AzureClient, AzureError, Resource};

pub const API_VERSION: &str = "7.5";
const MAX_RESULTS: u32 = 25;

/// Public key in JWK form. Private fields (`d`, `p`, `q`, `dp`, `dq`,
/// `qi`, `k`) are deliberately not here, so even if Key Vault sent them
/// they'd be dropped while parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicJwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default)]
    pub kty: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl PublicJwk {
    fn decode(v: &Option<String>) -> Option<Vec<u8>> {
        v.as_deref()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
    }

    /// RSA modulus size in bits.
    pub fn rsa_bits(&self) -> Option<usize> {
        let n = Self::decode(&self.n)?;
        let n = &n[n.iter().position(|b| *b != 0)?..];
        Some(n.len() * 8 - n[0].leading_zeros() as usize)
    }

    /// "RSA 3072", "EC P-256", "RSA-HSM 2048" and so on.
    pub fn describe(&self) -> String {
        match (self.kty.as_str(), &self.crv) {
            (k, Some(crv)) if k.starts_with("EC") => format!("{k} {crv}"),
            (k, _) if k.starts_with("RSA") => match self.rsa_bits() {
                Some(b) => format!("{k} {b}"),
                None => k.to_owned(),
            },
            (k, _) => k.to_owned(),
        }
    }

    /// Public key as PEM (`PUBLIC KEY`, SubjectPublicKeyInfo). `None` for
    /// key types that have no public half, such as AES keys.
    pub fn to_pem(&self) -> Option<String> {
        let der = if self.kty.starts_with("RSA") {
            spki_rsa(&Self::decode(&self.n)?, &Self::decode(&self.e)?)
        } else if self.kty.starts_with("EC") {
            let curve = match self.crv.as_deref()? {
                "P-256" => OID_P256,
                "P-384" => OID_P384,
                "P-521" => OID_P521,
                "P-256K" => OID_SECP256K1,
                _ => return None,
            };
            let x = Self::decode(&self.x)?;
            let y = Self::decode(&self.y)?;
            let mut point = vec![0x04];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            spki_ec(curve, &point)
        } else {
            return None;
        };
        Some(crate::x509::to_pem("PUBLIC KEY", &der))
    }

    /// Pretty JWK JSON, public fields only.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// --- Minimal DER writer for SubjectPublicKeyInfo ---

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// Positive INTEGER from unsigned big-endian bytes.
fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = match bytes.iter().position(|b| *b != 0) {
        Some(i) => &bytes[i..],
        None => &[0],
    };
    let mut v = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(trimmed);
    tlv(0x02, &v)
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0];
    v.extend_from_slice(bytes);
    tlv(0x03, &v)
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

fn spki_rsa(n: &[u8], e: &[u8]) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, OID_RSA), vec![0x05, 0x00]].concat());
    let key = tlv(0x30, &[der_uint(n), der_uint(e)].concat());
    tlv(0x30, &[alg, bit_string(&key)].concat())
}

fn spki_ec(curve: &[u8], point: &[u8]) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, OID_EC), tlv(0x06, curve)].concat());
    tlv(0x30, &[alg, bit_string(point)].concat())
}

/// Key properties from the list and versions calls.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KeyItem {
    pub kid: String,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub managed: Option<bool>,
}

fn id_part(id: &str, idx: usize) -> &str {
    id.split_once("/keys/")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split('/').nth(idx))
        .unwrap_or_default()
}

impl KeyItem {
    pub fn name(&self) -> &str {
        id_part(&self.kid, 0)
    }
    pub fn version(&self) -> &str {
        id_part(&self.kid, 1)
    }
    pub fn tags(&self) -> &BTreeMap<String, String> {
        static EMPTY: BTreeMap<String, String> = BTreeMap::new();
        self.tags.as_ref().unwrap_or(&EMPTY)
    }
}

/// A key version with its public JWK.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyBundle {
    pub key: PublicJwk,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub managed: Option<bool>,
}

impl KeyBundle {
    pub fn kid(&self) -> &str {
        self.key.kid.as_deref().unwrap_or_default()
    }
    pub fn name(&self) -> &str {
        id_part(self.kid(), 0)
    }
    pub fn version(&self) -> &str {
        id_part(self.kid(), 1)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedKeyItem {
    pub kid: String,
    #[serde(default)]
    pub deleted_date: Option<Timestamp>,
    #[serde(default)]
    pub scheduled_purge_date: Option<Timestamp>,
}

impl DeletedKeyItem {
    pub fn name(&self) -> &str {
        id_part(&self.kid, 0)
    }
}

/// Rotation policy. Durations are ISO 8601, for example `P90D`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationPolicy {
    #[serde(default)]
    pub lifetime_actions: Vec<RotationAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<RotationAttributes>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationAttributes {
    /// How long each new version lasts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RotationAction {
    pub trigger: RotationTrigger,
    pub action: RotationActionType,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationTrigger {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_after_create: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_before_expiry: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RotationActionType {
    /// `Rotate` or `Notify`.
    #[serde(rename = "type")]
    pub kind: String,
}

impl RotationPolicy {
    fn find(&self, kind: &str) -> Option<&RotationTrigger> {
        self.lifetime_actions
            .iter()
            .find(|a| a.action.kind.eq_ignore_ascii_case(kind))
            .map(|a| &a.trigger)
    }

    /// Days after creation that Key Vault rotates the key, if set.
    pub fn rotate_after_days(&self) -> Option<u32> {
        self.find("Rotate")
            .and_then(|t| t.time_after_create.as_deref())
            .and_then(iso_days)
    }

    /// Days before expiry that Key Vault rotates the key, if set that way.
    pub fn rotate_before_expiry_days(&self) -> Option<u32> {
        self.find("Rotate")
            .and_then(|t| t.time_before_expiry.as_deref())
            .and_then(iso_days)
    }

    /// Days before expiry that Key Vault sends a near-expiry event.
    pub fn notify_before_days(&self) -> Option<u32> {
        self.find("Notify")
            .and_then(|t| t.time_before_expiry.as_deref())
            .and_then(iso_days)
    }

    /// Lifetime of each new version, in days.
    pub fn expiry_days(&self) -> Option<u32> {
        self.attributes
            .as_ref()
            .and_then(|a| a.expiry_time.as_deref())
            .and_then(iso_days)
    }

    /// Build a policy from days. `None` leaves that part out.
    pub fn from_days(
        rotate_after: Option<u32>,
        notify_before: Option<u32>,
        expiry: Option<u32>,
    ) -> Self {
        let mut actions = Vec::new();
        if let Some(d) = rotate_after {
            actions.push(RotationAction {
                trigger: RotationTrigger {
                    time_after_create: Some(format!("P{d}D")),
                    time_before_expiry: None,
                },
                action: RotationActionType {
                    kind: "Rotate".into(),
                },
            });
        }
        if let Some(d) = notify_before {
            actions.push(RotationAction {
                trigger: RotationTrigger {
                    time_after_create: None,
                    time_before_expiry: Some(format!("P{d}D")),
                },
                action: RotationActionType {
                    kind: "Notify".into(),
                },
            });
        }
        Self {
            lifetime_actions: actions,
            attributes: expiry.map(|d| RotationAttributes {
                expiry_time: Some(format!("P{d}D")),
            }),
        }
    }
}

/// Parse simple ISO 8601 durations Key Vault uses: `P90D`, `P3M`, `P1Y`,
/// `P1Y6M`. Months count as 30 days and years as 365.
pub fn iso_days(s: &str) -> Option<u32> {
    let rest = s.trim().strip_prefix('P')?;
    if rest.is_empty() || rest.contains('T') {
        return None;
    }
    let mut total: u32 = 0;
    let mut num = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u32 = num.parse().ok()?;
        num.clear();
        total = total.checked_add(match c {
            'D' => n,
            'W' => n.checked_mul(7)?,
            'M' => n.checked_mul(30)?,
            'Y' => n.checked_mul(365)?,
            _ => return None,
        })?;
    }
    num.is_empty().then_some(total)
}

/// Body for creating a key.
#[derive(Debug, Serialize)]
pub struct CreateKey {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    pub key_ops: Vec<String>,
    pub attributes: Attributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

pub struct KeysApi<'a> {
    pub azure: &'a AzureClient,
    pub session: &'a Session,
    pub vault_url: String,
}

impl KeysApi<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}?api-version={API_VERSION}", self.vault_url)
    }

    async fn collect<T: serde::de::DeserializeOwned>(
        &self,
        first: String,
    ) -> Result<Vec<T>, AzureError> {
        crate::azure::paging::collect(self.azure, self.session, &self.vault_url, first).await
    }

    pub async fn list(&self) -> Result<Vec<KeyItem>, AzureError> {
        let first = format!("{}&maxresults={MAX_RESULTS}", self.url("/keys"));
        let mut items: Vec<KeyItem> = self.collect(first).await?;
        items.sort_by_key(|k| k.name().to_ascii_lowercase());
        Ok(items)
    }

    pub async fn versions(&self, name: &str) -> Result<Vec<KeyItem>, AzureError> {
        let first = format!(
            "{}&maxresults={MAX_RESULTS}",
            self.url(&format!("/keys/{name}/versions"))
        );
        let mut items: Vec<KeyItem> = self.collect(first).await?;
        items.sort_by_key(|k| std::cmp::Reverse(k.attributes.created));
        Ok(items)
    }

    /// Public key and properties. `GET /keys/{name}` never returns private
    /// material.
    pub async fn get(&self, name: &str, version: Option<&str>) -> Result<KeyBundle, AzureError> {
        let path = match version {
            Some(v) => format!("/keys/{name}/{v}"),
            None => format!("/keys/{name}"),
        };
        self.azure
            .get_json(self.session, Resource::KeyVault, &self.url(&path))
            .await
    }

    pub async fn create(&self, name: &str, body: &CreateKey) -> Result<KeyBundle, AzureError> {
        self.azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::POST,
                &self.url(&format!("/keys/{name}/create")),
                body,
            )
            .await
    }

    /// Make a new version now.
    pub async fn rotate(&self, name: &str) -> Result<KeyBundle, AzureError> {
        self.azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::POST,
                &self.url(&format!("/keys/{name}/rotate")),
                &serde_json::json!({}),
            )
            .await
    }

    pub async fn rotation_policy(&self, name: &str) -> Result<RotationPolicy, AzureError> {
        self.azure
            .get_json(
                self.session,
                Resource::KeyVault,
                &self.url(&format!("/keys/{name}/rotationpolicy")),
            )
            .await
    }

    pub async fn set_rotation_policy(
        &self,
        name: &str,
        policy: &RotationPolicy,
    ) -> Result<RotationPolicy, AzureError> {
        self.azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::PUT,
                &self.url(&format!("/keys/{name}/rotationpolicy")),
                policy,
            )
            .await
    }

    async fn call(&self, method: Method, path: &str) -> Result<(), AzureError> {
        self.azure
            .send(
                self.session,
                Resource::KeyVault,
                method,
                &self.url(path),
                None,
            )
            .await
            .map(|_| ())
    }

    pub async fn delete(&self, name: &str) -> Result<(), AzureError> {
        self.call(Method::DELETE, &format!("/keys/{name}")).await
    }

    pub async fn list_deleted(&self) -> Result<Vec<DeletedKeyItem>, AzureError> {
        let first = format!("{}&maxresults={MAX_RESULTS}", self.url("/deletedkeys"));
        let mut items: Vec<DeletedKeyItem> = self.collect(first).await?;
        items.sort_by_key(|k| k.name().to_ascii_lowercase());
        Ok(items)
    }

    pub async fn get_deleted(&self, name: &str) -> Result<DeletedKeyItem, AzureError> {
        self.azure
            .get_json(
                self.session,
                Resource::KeyVault,
                &self.url(&format!("/deletedkeys/{name}")),
            )
            .await
    }

    pub async fn recover(&self, name: &str) -> Result<(), AzureError> {
        self.call(Method::POST, &format!("/deletedkeys/{name}/recover"))
            .await
    }

    pub async fn purge(&self, name: &str) -> Result<(), AzureError> {
        self.call(Method::DELETE, &format!("/deletedkeys/{name}"))
            .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Public parts of a 2048-bit RSA test key and its openssl PEM.
    pub(crate) const RSA_N: &str = include_str!("../../tests/fixtures/test-rsa-n.txt");
    pub(crate) const RSA_PEM: &str = include_str!("../../tests/fixtures/test-rsa-pub.pem");
    const EC_X: &str = include_str!("../../tests/fixtures/test-ec-x.txt");
    const EC_Y: &str = include_str!("../../tests/fixtures/test-ec-y.txt");
    const EC_PEM: &str = include_str!("../../tests/fixtures/test-ec-pub.pem");

    #[test]
    fn rsa_pem_matches_openssl() {
        let jwk = PublicJwk {
            kty: "RSA".into(),
            n: Some(RSA_N.trim().into()),
            e: Some("AQAB".into()),
            ..PublicJwk::default()
        };
        assert_eq!(jwk.to_pem().unwrap(), RSA_PEM);
        assert_eq!(jwk.rsa_bits(), Some(2048));
        assert_eq!(jwk.describe(), "RSA 2048");
    }

    #[test]
    fn ec_pem_matches_openssl() {
        let jwk = PublicJwk {
            kty: "EC".into(),
            crv: Some("P-256".into()),
            x: Some(EC_X.trim().into()),
            y: Some(EC_Y.trim().into()),
            ..PublicJwk::default()
        };
        assert_eq!(jwk.to_pem().unwrap(), EC_PEM);
        assert_eq!(jwk.describe(), "EC P-256");
    }

    #[test]
    fn private_fields_are_dropped() {
        let jwk: PublicJwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "PRIVATE", "p": "PRIVATE", "q": "PRIVATE",
            "dp": "PRIVATE", "dq": "PRIVATE", "qi": "PRIVATE", "k": "PRIVATE"
        }))
        .unwrap();
        assert!(!jwk.to_json().contains("PRIVATE"));
        assert!(!format!("{jwk:?}").contains("PRIVATE"));
    }

    #[test]
    fn symmetric_keys_have_no_pem() {
        let jwk = PublicJwk {
            kty: "oct-HSM".into(),
            ..PublicJwk::default()
        };
        assert_eq!(jwk.to_pem(), None);
    }

    #[test]
    fn durations() {
        assert_eq!(iso_days("P90D"), Some(90));
        assert_eq!(iso_days("P3M"), Some(90));
        assert_eq!(iso_days("P1Y"), Some(365));
        assert_eq!(iso_days("P1Y6M"), Some(545));
        assert_eq!(iso_days("P2W"), Some(14));
        for bad in ["", "P", "90D", "PT1H", "P1X", "P99999999999D"] {
            assert_eq!(iso_days(bad), None, "{bad}");
        }
    }

    #[test]
    fn rotation_policy_round_trip() {
        let p = RotationPolicy::from_days(Some(90), Some(30), Some(365));
        assert_eq!(p.rotate_after_days(), Some(90));
        assert_eq!(p.notify_before_days(), Some(30));
        assert_eq!(p.expiry_days(), Some(365));
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(
            j["lifetimeActions"][0]["trigger"]["timeAfterCreate"],
            "P90D"
        );
        assert_eq!(j["lifetimeActions"][0]["action"]["type"], "Rotate");
        assert_eq!(
            j["lifetimeActions"][1]["trigger"]["timeBeforeExpiry"],
            "P30D"
        );
        assert_eq!(j["attributes"]["expiryTime"], "P365D");
        let empty = RotationPolicy::from_days(None, None, None);
        assert!(empty.lifetime_actions.is_empty());
    }

    #[test]
    fn create_body_shape() {
        let b = CreateKey {
            kty: "RSA".into(),
            key_size: Some(3072),
            crv: None,
            key_ops: vec!["encrypt".into()],
            attributes: Attributes::default(),
            tags: None,
        };
        let j = serde_json::to_value(&b).unwrap();
        assert_eq!(j["key_size"], 3072);
        assert!(j.get("crv").is_none());
    }
}
