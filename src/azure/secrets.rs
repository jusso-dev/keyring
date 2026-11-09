//! Key Vault secrets REST API, called as the signed-in user.
//!
//! Secret values are only fetched by [`get_value`], and only when the
//! person asks. Nothing here logs or caches a value.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::{AzureClient, AzureError, Resource};
use crate::secret::Secret;

pub const API_VERSION: &str = "7.5";
/// Page size for list calls. 25 is Key Vault's maximum.
pub const MAX_RESULTS: u32 = 25;

/// Unix seconds, as Key Vault sends them.
pub type Timestamp = i64;

pub fn now_ts() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as Timestamp)
        .unwrap_or_default()
}

/// How soon counts as "expiring soon".
pub const EXPIRING_SOON: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    #[serde(default, rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    #[serde(default, skip_serializing)]
    pub created: Option<Timestamp>,
    #[serde(default, skip_serializing)]
    pub updated: Option<Timestamp>,
    #[serde(default, skip_serializing)]
    pub recovery_level: Option<String>,
    #[serde(default, skip_serializing)]
    pub recoverable_days: Option<u32>,
}

/// Where a secret stands on its dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryState {
    None,
    Ok,
    Soon,
    Expired,
}

impl Attributes {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn expiry_state(&self, now: Timestamp) -> ExpiryState {
        match self.expires {
            None => ExpiryState::None,
            Some(exp) if exp <= now => ExpiryState::Expired,
            Some(exp) if exp - now <= EXPIRING_SOON.as_secs() as Timestamp => ExpiryState::Soon,
            Some(_) => ExpiryState::Ok,
        }
    }

    pub fn not_yet_valid(&self, now: Timestamp) -> bool {
        self.not_before.is_some_and(|nbf| nbf > now)
    }
}

/// Secret properties without the value, from list and version calls.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub managed: Option<bool>,
}

impl SecretItem {
    /// Secret name from its ID, `https://<vault>/secrets/<name>[/<version>]`.
    pub fn name(&self) -> &str {
        id_part(&self.id, 0)
    }

    pub fn version(&self) -> &str {
        id_part(&self.id, 1)
    }

    pub fn tags(&self) -> &BTreeMap<String, String> {
        static EMPTY: BTreeMap<String, String> = BTreeMap::new();
        self.tags.as_ref().unwrap_or(&EMPTY)
    }
}

fn id_part(id: &str, idx: usize) -> &str {
    id.split_once("/secrets/")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split('/').nth(idx))
        .unwrap_or_default()
}

/// A secret with its value. Only built when the value was asked for.
pub struct SecretBundle {
    pub item: SecretItem,
    pub value: Secret,
}

impl std::fmt::Debug for SecretBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBundle")
            .field("item", &self.item)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleWire {
    id: String,
    value: String,
    #[serde(default)]
    attributes: Attributes,
    #[serde(default)]
    tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    managed: Option<bool>,
}

impl From<BundleWire> for SecretBundle {
    fn from(w: BundleWire) -> Self {
        Self {
            value: Secret::new(w.value),
            item: SecretItem {
                id: w.id,
                attributes: w.attributes,
                tags: w.tags,
                content_type: w.content_type,
                managed: w.managed,
            },
        }
    }
}

/// A soft-deleted secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedSecretItem {
    pub id: String,
    #[serde(default)]
    pub recovery_id: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<Timestamp>,
    #[serde(default)]
    pub scheduled_purge_date: Option<Timestamp>,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub content_type: Option<String>,
}

impl DeletedSecretItem {
    pub fn name(&self) -> &str {
        id_part(&self.id, 0)
    }
}

/// Key Vault secret names: 1 to 127 letters, digits and hyphens.
pub fn is_valid_secret_name(name: &str) -> bool {
    crate::routes::vault_ctx::is_valid_object_name(name)
}

/// Versions are 32 hex characters.
pub fn is_valid_version(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Talks to one vault's secrets endpoints.
pub struct SecretsApi<'a> {
    pub azure: &'a AzureClient,
    pub session: &'a Session,
    /// `https://<vault>.vault.azure.net`, no trailing slash.
    pub vault_url: String,
}

impl SecretsApi<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}?api-version={API_VERSION}", self.vault_url)
    }

    async fn collect<T: serde::de::DeserializeOwned>(
        &self,
        first: String,
    ) -> Result<Vec<T>, AzureError> {
        crate::azure::paging::collect(self.azure, self.session, &self.vault_url, first).await
    }

    /// Properties of every secret, never values.
    pub async fn list(&self) -> Result<Vec<SecretItem>, AzureError> {
        let first = format!("{}&maxresults={MAX_RESULTS}", self.url("/secrets"));
        let mut items: Vec<SecretItem> = self.collect(first).await?;
        items.sort_by_key(|s| s.name().to_ascii_lowercase());
        Ok(items)
    }

    /// Properties of every version of one secret, newest first.
    pub async fn versions(&self, name: &str) -> Result<Vec<SecretItem>, AzureError> {
        let first = format!(
            "{}&maxresults={MAX_RESULTS}",
            self.url(&format!("/secrets/{name}/versions"))
        );
        let mut items: Vec<SecretItem> = self.collect(first).await?;
        items.sort_by_key(|s| std::cmp::Reverse(s.attributes.created));
        Ok(items)
    }

    /// Properties of the current version, without the value. Uses the
    /// versions list, which never carries values, so opening a secret's
    /// page doesn't read its value.
    pub async fn properties(&self, name: &str) -> Result<SecretItem, AzureError> {
        let versions = self.versions(name).await?;
        // Key Vault's current version is the most recently created one.
        versions.into_iter().next().ok_or(AzureError::Status {
            status: 404,
            code: Some("SecretNotFound".into()),
            message: None,
        })
    }

    /// Read a secret's value. `version` of `None` means the current one.
    pub async fn get_value(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretBundle, AzureError> {
        let path = match version {
            Some(v) => format!("/secrets/{name}/{v}"),
            None => format!("/secrets/{name}"),
        };
        let wire: BundleWire = self
            .azure
            .get_json(self.session, Resource::KeyVault, &self.url(&path))
            .await?;
        Ok(wire.into())
    }

    /// Set a value, which creates a new version.
    pub async fn set(&self, name: &str, body: &SetSecret) -> Result<SecretItem, AzureError> {
        let wire: BundleWire = self
            .azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::PUT,
                &self.url(&format!("/secrets/{name}")),
                body,
            )
            .await?;
        Ok(SecretBundle::from(wire).item)
    }

    /// Change properties of one version without touching its value.
    pub async fn update(
        &self,
        name: &str,
        version: &str,
        body: &UpdateSecret,
    ) -> Result<SecretItem, AzureError> {
        let wire: SecretItem = self
            .azure
            .send_json(
                self.session,
                Resource::KeyVault,
                Method::PATCH,
                &self.url(&format!("/secrets/{name}/{version}")),
                body,
            )
            .await?;
        Ok(wire)
    }

    pub async fn delete(&self, name: &str) -> Result<(), AzureError> {
        self.azure
            .send(
                self.session,
                Resource::KeyVault,
                Method::DELETE,
                &self.url(&format!("/secrets/{name}")),
                None,
            )
            .await
            .map(|_| ())
    }

    pub async fn list_deleted(&self) -> Result<Vec<DeletedSecretItem>, AzureError> {
        let first = format!("{}&maxresults={MAX_RESULTS}", self.url("/deletedsecrets"));
        let mut items: Vec<DeletedSecretItem> = self.collect(first).await?;
        items.sort_by_key(|s| s.name().to_ascii_lowercase());
        Ok(items)
    }

    pub async fn get_deleted(&self, name: &str) -> Result<DeletedSecretItem, AzureError> {
        self.azure
            .get_json(
                self.session,
                Resource::KeyVault,
                &self.url(&format!("/deletedsecrets/{name}")),
            )
            .await
    }

    pub async fn recover(&self, name: &str) -> Result<(), AzureError> {
        self.azure
            .send(
                self.session,
                Resource::KeyVault,
                Method::POST,
                &self.url(&format!("/deletedsecrets/{name}/recover")),
                None,
            )
            .await
            .map(|_| ())
    }

    pub async fn purge(&self, name: &str) -> Result<(), AzureError> {
        self.azure
            .send(
                self.session,
                Resource::KeyVault,
                Method::DELETE,
                &self.url(&format!("/deletedsecrets/{name}")),
                None,
            )
            .await
            .map(|_| ())
    }
}

/// Body for setting a value.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSecret {
    /// Serialised from `Secret` without printing it anywhere else.
    #[serde(serialize_with = "expose_secret")]
    pub value: Secret,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub attributes: Attributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

impl std::fmt::Debug for SetSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetSecret")
            .field("value", &"[redacted]")
            .field("content_type", &self.content_type)
            .field("attributes", &self.attributes)
            .field("tags", &self.tags)
            .finish()
    }
}

fn expose_secret<S: serde::Serializer>(v: &Secret, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.expose())
}

/// One date in a PATCH. Key Vault merges attributes, so leaving a field
/// out keeps it, and only an explicit `null` clears it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DateChange {
    #[default]
    Keep,
    Set(Timestamp),
    Clear,
}

impl DateChange {
    fn is_keep(&self) -> bool {
        *self == Self::Keep
    }

    /// Compare what the form says with what's there now. An unchanged
    /// calendar day is kept as it is, so editing tags doesn't move an
    /// expiry from 10:00 to the end of the day.
    pub fn between(current: Option<Timestamp>, wanted: Option<Timestamp>) -> Self {
        match (current, wanted) {
            (None, None) => Self::Keep,
            (Some(_), None) => Self::Clear,
            (Some(c), Some(w)) if c.div_euclid(86_400) == w.div_euclid(86_400) => Self::Keep,
            (_, Some(w)) => Self::Set(w),
        }
    }
}

impl Serialize for DateChange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Set(t) => s.serialize_i64(*t),
            Self::Clear | Self::Keep => s.serialize_none(),
        }
    }
}

/// Attributes for a PATCH. Only what changes is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "nbf", skip_serializing_if = "DateChange::is_keep")]
    pub not_before: DateChange,
    #[serde(rename = "exp", skip_serializing_if = "DateChange::is_keep")]
    pub expires: DateChange,
}

/// Body for changing properties only. No value field, so it can't create
/// a new version.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSecret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub attributes: UpdateAttributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_versions_from_ids() {
        let item: SecretItem = serde_json::from_value(serde_json::json!({
            "id": "https://kv.vault.azure.net/secrets/db-password/0123456789abcdef0123456789abcdef",
            "attributes": {"enabled": true, "created": 1, "updated": 2}
        }))
        .unwrap();
        assert_eq!(item.name(), "db-password");
        assert_eq!(item.version(), "0123456789abcdef0123456789abcdef");
        let bare: SecretItem = serde_json::from_value(
            serde_json::json!({"id": "https://kv.vault.azure.net/secrets/x"}),
        )
        .unwrap();
        assert_eq!(bare.name(), "x");
        assert_eq!(bare.version(), "");
        assert!(bare.attributes.is_enabled());
        assert!(bare.tags().is_empty());
    }

    #[test]
    fn expiry_states() {
        let now = 1_000_000_000;
        let a = |exp: Option<i64>| Attributes {
            expires: exp,
            ..Attributes::default()
        };
        assert_eq!(a(None).expiry_state(now), ExpiryState::None);
        assert_eq!(a(Some(now - 1)).expiry_state(now), ExpiryState::Expired);
        assert_eq!(a(Some(now + 86_400)).expiry_state(now), ExpiryState::Soon);
        assert_eq!(
            a(Some(now + 90 * 86_400)).expiry_state(now),
            ExpiryState::Ok
        );
    }

    #[test]
    fn name_and_version_rules() {
        assert!(is_valid_secret_name("db-Password-1"));
        assert!(is_valid_secret_name(&"a".repeat(127)));
        for bad in ["", "a_b", "a.b", "a/b", "a b", "../x", &"a".repeat(128)] {
            assert!(!is_valid_secret_name(bad), "{bad}");
        }
        assert!(is_valid_version("0123456789abcdef0123456789ABCDEF"));
        assert!(!is_valid_version("../../secrets"));
        assert!(!is_valid_version("0123"));
    }

    #[test]
    fn set_body_has_value_and_debug_hides_it() {
        let body = SetSecret {
            value: Secret::new("hunter2"),
            content_type: Some("text/plain".into()),
            attributes: Attributes {
                enabled: Some(true),
                expires: Some(5),
                created: Some(9),
                ..Attributes::default()
            },
            tags: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["value"], "hunter2");
        assert_eq!(json["attributes"]["exp"], 5);
        assert!(
            json["attributes"].get("created").is_none(),
            "read-only fields aren't sent"
        );
        assert!(!format!("{body:?}").contains("hunter2"));
    }

    #[test]
    fn date_changes() {
        let day = 86_400;
        let midnight = 20_833 * day;
        let t = midnight + 10 * 3600; // 10:00
        assert_eq!(
            DateChange::between(Some(t), Some(midnight + day - 1)),
            DateChange::Keep,
            "same day kept"
        );
        assert_eq!(DateChange::between(Some(t), None), DateChange::Clear);
        assert_eq!(DateChange::between(None, None), DateChange::Keep);
        assert_eq!(
            DateChange::between(Some(t), Some(t + 2 * day)),
            DateChange::Set(t + 2 * day)
        );
        let a = UpdateAttributes {
            enabled: Some(true),
            not_before: DateChange::Keep,
            expires: DateChange::Clear,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("nbf").is_none(), "kept fields are left out");
        assert!(
            j.get("exp").unwrap().is_null(),
            "cleared fields are sent as null"
        );
    }

    #[test]
    fn update_body_never_carries_a_value() {
        let body = UpdateSecret {
            content_type: None,
            attributes: UpdateAttributes {
                enabled: Some(false),
                ..UpdateAttributes::default()
            },
            tags: Some(BTreeMap::from([("env".into(), "prod".into())])),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("value").is_none());
        assert_eq!(json["attributes"]["enabled"], false);
    }

    #[test]
    fn bundle_debug_hides_value() {
        let b = SecretBundle::from(BundleWire {
            id: "https://kv/secrets/a/1".into(),
            value: "hunter2".into(),
            attributes: Attributes::default(),
            tags: None,
            content_type: None,
            managed: None,
        });
        assert!(!format!("{b:?}").contains("hunter2"));
    }
}
