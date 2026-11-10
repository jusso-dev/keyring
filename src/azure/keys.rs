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

/// When the rotate trigger fires, with Key Vault's own duration string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateAt {
    /// `timeAfterCreate`.
    AfterCreate(String),
    /// `timeBeforeExpiry`.
    BeforeExpiry(String),
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
        self.notify_before().and_then(iso_days)
    }

    /// Lifetime of each new version, in days.
    pub fn expiry_days(&self) -> Option<u32> {
        self.expiry().and_then(iso_days)
    }

    /// The rotate trigger as Key Vault wrote it.
    pub fn rotate_at(&self) -> Option<RotateAt> {
        let t = self.find("Rotate")?;
        match (&t.time_after_create, &t.time_before_expiry) {
            (Some(d), _) => Some(RotateAt::AfterCreate(d.clone())),
            (_, Some(d)) => Some(RotateAt::BeforeExpiry(d.clone())),
            _ => None,
        }
    }

    /// The notify trigger as Key Vault wrote it.
    pub fn notify_before(&self) -> Option<&str> {
        self.find("Notify")
            .and_then(|t| t.time_before_expiry.as_deref())
    }

    /// The expiry as Key Vault wrote it.
    pub fn expiry(&self) -> Option<&str> {
        self.attributes
            .as_ref()
            .and_then(|a| a.expiry_time.as_deref())
    }

    /// Key Vault answers a key with no policy set with a default: one
    /// Notify action 30 days before expiry, and no expiry, so it never
    /// fires. Keyring treats that as "no policy".
    pub fn is_key_vault_default(&self) -> bool {
        matches!(self.lifetime_actions.as_slice(), [a]
            if a.action.kind.eq_ignore_ascii_case("Notify")
                && a.trigger.time_after_create.is_none()
                && a.trigger.time_before_expiry.as_deref() == Some("P30D"))
            && self.expiry().is_none()
    }

    /// Parts of the policy that Keyring's form can't show, in words. Empty
    /// when the form can show all of it.
    pub fn unsupported(&self) -> Vec<String> {
        let mut out = Vec::new();
        let (mut rotates, mut notifies) = (0, 0);
        for a in &self.lifetime_actions {
            let t = &a.trigger;
            match a.action.kind.to_ascii_lowercase().as_str() {
                "rotate" => {
                    rotates += 1;
                    if t.time_after_create.is_some() == t.time_before_expiry.is_some() {
                        out.push("a rotate action that doesn't have exactly one trigger".into());
                    }
                }
                "notify" => {
                    notifies += 1;
                    if t.time_after_create.is_some() || t.time_before_expiry.is_none() {
                        out.push("a notify action that doesn't count back from expiry".into());
                    }
                }
                _ => out.push(format!("an action of type {}", a.action.kind)),
            }
            for d in [&t.time_after_create, &t.time_before_expiry]
                .into_iter()
                .flatten()
            {
                if iso_days(d).is_none() {
                    out.push(format!("the time {d}, which isn't a whole number of days"));
                }
            }
        }
        if rotates > 1 {
            out.push(format!("{rotates} rotate actions"));
        }
        if notifies > 1 {
            out.push(format!("{notifies} notify actions"));
        }
        if let Some(e) = self.expiry()
            && iso_days(e).is_none()
        {
            out.push(format!(
                "the expiry {e}, which isn't a whole number of days"
            ));
        }
        out
    }

    /// Build a policy. Durations are ISO 8601 strings. `None` leaves that
    /// part out.
    pub fn from_parts(
        rotate: Option<RotateAt>,
        notify_before: Option<String>,
        expiry: Option<String>,
    ) -> Self {
        let mut actions = Vec::new();
        if let Some(r) = rotate {
            let trigger = match r {
                RotateAt::AfterCreate(d) => RotationTrigger {
                    time_after_create: Some(d),
                    time_before_expiry: None,
                },
                RotateAt::BeforeExpiry(d) => RotationTrigger {
                    time_after_create: None,
                    time_before_expiry: Some(d),
                },
            };
            actions.push(RotationAction {
                trigger,
                action: RotationActionType {
                    kind: "Rotate".into(),
                },
            });
        }
        if let Some(d) = notify_before {
            actions.push(RotationAction {
                trigger: RotationTrigger {
                    time_after_create: None,
                    time_before_expiry: Some(d),
                },
                action: RotationActionType {
                    kind: "Notify".into(),
                },
            });
        }
        Self {
            lifetime_actions: actions,
            attributes: expiry.map(|d| RotationAttributes {
                expiry_time: Some(d),
            }),
        }
    }
}

/// Parse simple ISO 8601 durations Key Vault uses: `P90D`, `P3M`, `P1Y`,
/// `P1Y6M`. Months count as 30 days and years as 365, so the result is for
/// showing a number in the form. Keyring keeps the original string when
/// saving an unchanged field, so `P18M` stays `P18M`. `None` for a time
/// part (`PT48H`).
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

/// True for a plain `P<n>D` duration.
pub fn is_plain_days(s: &str) -> bool {
    s.strip_prefix('P')
        .and_then(|r| r.strip_suffix('D'))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
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

    /// Turn a key version on or off. Only `enabled` is sent.
    pub async fn set_enabled(
        &self,
        name: &str,
        version: &str,
        enabled: bool,
    ) -> Result<KeyBundle, AzureError> {
        self.azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::PATCH,
                &self.url(&format!("/keys/{name}/{version}")),
                &serde_json::json!({ "attributes": { "enabled": enabled } }),
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
        let p = RotationPolicy::from_parts(
            Some(RotateAt::AfterCreate("P90D".into())),
            Some("P30D".into()),
            Some("P365D".into()),
        );
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
        let empty = RotationPolicy::from_parts(None, None, None);
        assert!(empty.lifetime_actions.is_empty());
        let before =
            RotationPolicy::from_parts(Some(RotateAt::BeforeExpiry("P30D".into())), None, None);
        assert_eq!(before.rotate_before_expiry_days(), Some(30));
        assert_eq!(
            before.rotate_at(),
            Some(RotateAt::BeforeExpiry("P30D".into()))
        );
    }

    fn policy(v: serde_json::Value) -> RotationPolicy {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn key_vault_default_policy_is_spotted() {
        let default = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}],
            "attributes": {"created": 1, "updated": 1}
        }));
        assert!(default.is_key_vault_default());
        assert!(default.unsupported().is_empty());
        let with_expiry = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}],
            "attributes": {"expiryTime": "P1Y"}
        }));
        assert!(!with_expiry.is_key_vault_default());
    }

    #[test]
    fn unsupported_parts_are_named() {
        let p = policy(serde_json::json!({
            "lifetimeActions": [
                {"trigger": {"timeAfterCreate": "PT48H"}, "action": {"type": "Rotate"}},
                {"trigger": {"timeAfterCreate": "P10D"}, "action": {"type": "Rotate"}},
                {"trigger": {"timeBeforeExpiry": "P1DT12H"}, "action": {"type": "Notify"}}
            ],
            "attributes": {"expiryTime": "P90D"}
        }));
        let u = p.unsupported();
        assert!(u.iter().any(|x| x.contains("PT48H")), "{u:?}");
        assert!(u.iter().any(|x| x.contains("P1DT12H")), "{u:?}");
        assert!(u.iter().any(|x| x == "2 rotate actions"), "{u:?}");
        let simple = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "rotate"}}],
            "attributes": {"expiryTime": "P18M"}
        }));
        assert!(simple.unsupported().is_empty());
        assert_eq!(simple.rotate_before_expiry_days(), Some(30));
    }

    #[test]
    fn plain_days() {
        assert!(is_plain_days("P90D"));
        for no in ["P", "PD", "P18M", "P1Y", "P1DT1H", "90D"] {
            assert!(!is_plain_days(no), "{no}");
        }
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
