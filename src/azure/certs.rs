//! Key Vault certificates REST API, called as the signed-in user.
//!
//! Listing and viewing only ever returns the public certificate. The
//! private key is only read through the backing secret, for the `.pfx`
//! download, and only after the person confirms.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::secrets::{Attributes, Timestamp};
use crate::azure::{AzureClient, AzureError, Resource};

pub const API_VERSION: &str = "7.5";
const MAX_RESULTS: u32 = 25;

/// Certificate properties from the list call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CertItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub tags: Option<BTreeMap<String, String>>,
    /// SHA-1 thumbprint, base64url.
    #[serde(default)]
    pub x5t: Option<String>,
}

fn id_part(id: &str, idx: usize) -> &str {
    id.split_once("/certificates/")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split('/').nth(idx))
        .unwrap_or_default()
}

impl CertItem {
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

    /// Thumbprint as upper-case hex, the way Windows and the portal show it.
    pub fn thumbprint(&self) -> String {
        thumbprint_hex(self.x5t.as_deref())
    }
}

pub fn thumbprint_hex(x5t: Option<&str>) -> String {
    x5t.and_then(|t| URL_SAFE_NO_PAD.decode(t.trim_end_matches('=')).ok())
        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyProps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_key: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretProps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubjectAltNames {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upns: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct X509Props {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<SubjectAltNames>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_months: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ekus: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerProps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct LifetimeTrigger {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_percentage: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_before_expiry: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct LifetimeActionType {
    /// `AutoRenew` or `EmailContacts`.
    pub action_type: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct LifetimeAction {
    pub trigger: LifetimeTrigger,
    pub action: LifetimeActionType,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
/// Key Vault's certificate policy. Its JSON uses snake_case field names
/// (`key_props`, `key_size`, `x509_props`), except `secret_props.contentType`.
pub struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_props: Option<KeyProps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_props: Option<SecretProps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_props: Option<X509Props>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifetime_actions: Vec<LifetimeAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerProps>,
}

impl Policy {
    pub fn exportable(&self) -> bool {
        self.key_props
            .as_ref()
            .and_then(|k| k.exportable)
            .unwrap_or(false)
    }

    pub fn content_type(&self) -> &str {
        self.secret_props
            .as_ref()
            .and_then(|s| s.content_type.as_deref())
            .unwrap_or("application/x-pkcs12")
    }

    pub fn issuer_name(&self) -> &str {
        self.issuer
            .as_ref()
            .and_then(|i| i.name.as_deref())
            .unwrap_or("Unknown")
    }

    /// Plain description of what happens near expiry.
    pub fn renewal(&self) -> String {
        let Some(a) = self.lifetime_actions.first() else {
            return "Nothing happens automatically".into();
        };
        let when = match (a.trigger.days_before_expiry, a.trigger.lifetime_percentage) {
            (Some(d), _) => format!("{d} days before it expires"),
            (_, Some(p)) => format!("at {p}% of its lifetime"),
            _ => "near expiry".into(),
        };
        match a.action.action_type.as_str() {
            "AutoRenew" => format!("Renews automatically {when}"),
            "EmailContacts" => format!("Emails the vault's contacts {when}"),
            other => format!("{other} {when}"),
        }
    }
}

/// A full certificate version: properties, the public certificate and the
/// IDs of its backing key and secret. Never holds the private key.
#[derive(Debug, Clone, Deserialize)]
pub struct CertBundle {
    pub id: String,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub x5t: Option<String>,
    /// DER certificate, base64 (standard alphabet).
    #[serde(default)]
    pub cer: Option<String>,
    /// URL of the backing secret (holds the private key when exportable).
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub policy: Option<Policy>,
}

impl CertBundle {
    pub fn der(&self) -> Option<Vec<u8>> {
        self.cer.as_deref().and_then(|c| STANDARD.decode(c).ok())
    }

    pub fn version(&self) -> &str {
        id_part(&self.id, 1)
    }
}

/// A pending create or renewal.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Operation {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_details: Option<String>,
    #[serde(default)]
    pub cancellation_requested: Option<bool>,
    #[serde(default)]
    pub error: Option<OperationError>,
    #[serde(default)]
    pub issuer: Option<IssuerProps>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OperationError {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedCertItem {
    pub id: String,
    #[serde(default)]
    pub deleted_date: Option<Timestamp>,
    #[serde(default)]
    pub scheduled_purge_date: Option<Timestamp>,
    #[serde(default)]
    pub attributes: Attributes,
    #[serde(default)]
    pub x5t: Option<String>,
}

impl DeletedCertItem {
    pub fn name(&self) -> &str {
        id_part(&self.id, 0)
    }
}

pub struct CertsApi<'a> {
    pub azure: &'a AzureClient,
    pub session: &'a Session,
    pub vault_url: String,
}

impl CertsApi<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}?api-version={API_VERSION}", self.vault_url)
    }

    async fn collect<T: serde::de::DeserializeOwned>(
        &self,
        first: String,
    ) -> Result<Vec<T>, AzureError> {
        crate::azure::paging::collect(self.azure, self.session, &self.vault_url, first).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, AzureError> {
        self.azure
            .get_json(self.session, Resource::KeyVault, &self.url(path))
            .await
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, AzureError> {
        self.azure
            .send_json(
                self.session,
                Resource::KeyVault,
                method,
                &self.url(path),
                body,
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

    pub async fn list(&self) -> Result<Vec<CertItem>, AzureError> {
        let first = format!("{}&maxresults={MAX_RESULTS}", self.url("/certificates"));
        let mut items: Vec<CertItem> = self.collect(first).await?;
        items.sort_by_key(|c| c.name().to_ascii_lowercase());
        Ok(items)
    }

    pub async fn versions(&self, name: &str) -> Result<Vec<CertItem>, AzureError> {
        let first = format!(
            "{}&maxresults={MAX_RESULTS}",
            self.url(&format!("/certificates/{name}/versions"))
        );
        let mut items: Vec<CertItem> = self.collect(first).await?;
        items.sort_by_key(|c| std::cmp::Reverse(c.attributes.created));
        Ok(items)
    }

    /// The current version (with its policy) or a given one.
    pub async fn get_cert(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<CertBundle, AzureError> {
        match version {
            Some(v) => self.get(&format!("/certificates/{name}/{v}")).await,
            None => self.get(&format!("/certificates/{name}")).await,
        }
    }

    pub async fn policy(&self, name: &str) -> Result<Policy, AzureError> {
        self.get(&format!("/certificates/{name}/policy")).await
    }

    /// The pending operation, or `None` if there isn't one.
    pub async fn pending(&self, name: &str) -> Result<Option<Operation>, AzureError> {
        match self.get(&format!("/certificates/{name}/pending")).await {
            Ok(op) => Ok(Some(op)),
            Err(AzureError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn import(&self, name: &str, body: &ImportCert) -> Result<CertBundle, AzureError> {
        self.send(Method::POST, &format!("/certificates/{name}/import"), body)
            .await
    }

    pub async fn create(&self, name: &str, body: &CreateCert) -> Result<Operation, AzureError> {
        self.send(Method::POST, &format!("/certificates/{name}/create"), body)
            .await
    }

    pub async fn delete(&self, name: &str) -> Result<(), AzureError> {
        self.call(Method::DELETE, &format!("/certificates/{name}"))
            .await
    }

    pub async fn list_deleted(&self) -> Result<Vec<DeletedCertItem>, AzureError> {
        let first = format!(
            "{}&maxresults={MAX_RESULTS}",
            self.url("/deletedcertificates")
        );
        let mut items: Vec<DeletedCertItem> = self.collect(first).await?;
        items.sort_by_key(|c| c.name().to_ascii_lowercase());
        Ok(items)
    }

    pub async fn get_deleted(&self, name: &str) -> Result<DeletedCertItem, AzureError> {
        self.get(&format!("/deletedcertificates/{name}")).await
    }

    pub async fn recover(&self, name: &str) -> Result<(), AzureError> {
        self.call(
            Method::POST,
            &format!("/deletedcertificates/{name}/recover"),
        )
        .await
    }

    pub async fn purge(&self, name: &str) -> Result<(), AzureError> {
        self.call(Method::DELETE, &format!("/deletedcertificates/{name}"))
            .await
    }
}

/// Body for importing a `.pfx` or `.pem`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCert {
    /// Base64 PFX, or the PEM text.
    #[serde(serialize_with = "expose")]
    pub value: crate::secret::Secret,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "expose_opt")]
    pub pwd: Option<crate::secret::Secret>,
    pub policy: Policy,
    pub attributes: Attributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

impl std::fmt::Debug for ImportCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportCert { .. }")
    }
}

fn expose<S: serde::Serializer>(v: &crate::secret::Secret, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.expose())
}

fn expose_opt<S: serde::Serializer>(
    v: &Option<crate::secret::Secret>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_str(v.expose()),
        None => s.serialize_none(),
    }
}

/// Body for creating a certificate from a policy.
#[derive(Debug, Serialize)]
pub struct CreateCert {
    pub policy: Policy,
    pub attributes: Attributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_thumbprint() {
        let c: CertItem = serde_json::from_value(serde_json::json!({
            "id": "https://kv.vault.azure.net/certificates/web-tls/abc123",
            "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo",
        }))
        .unwrap();
        assert_eq!(c.name(), "web-tls");
        assert_eq!(c.version(), "abc123");
        assert_eq!(c.thumbprint(), "7CB8B7539D87BA7215357B9B9049DFF2D3FA59BA");
        assert_eq!(thumbprint_hex(None), "");
    }

    #[test]
    fn policy_summaries() {
        let p: Policy = serde_json::from_value(serde_json::json!({
            "key_props": {"exportable": true, "kty": "RSA", "key_size": 2048},
            "lifetime_actions": [{"trigger": {"days_before_expiry": 30}, "action": {"action_type": "AutoRenew"}}],
            "issuer": {"name": "Self"}
        }))
        .unwrap();
        assert!(p.exportable());
        assert_eq!(
            p.renewal(),
            "Renews automatically 30 days before it expires"
        );
        assert_eq!(p.issuer_name(), "Self");
        assert_eq!(p.content_type(), "application/x-pkcs12");
        assert_eq!(Policy::default().renewal(), "Nothing happens automatically");
        assert!(!Policy::default().exportable());
    }

    #[test]
    fn policy_uses_key_vault_field_names() {
        let p = Policy {
            key_props: Some(KeyProps {
                key_size: Some(2048),
                reuse_key: Some(false),
                ..KeyProps::default()
            }),
            secret_props: Some(SecretProps {
                content_type: Some("application/x-pkcs12".into()),
            }),
            x509_props: Some(X509Props {
                validity_months: Some(12),
                sans: Some(SubjectAltNames {
                    dns_names: vec!["a.com".into()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            lifetime_actions: vec![LifetimeAction {
                trigger: LifetimeTrigger {
                    days_before_expiry: Some(30),
                    lifetime_percentage: None,
                },
                action: LifetimeActionType {
                    action_type: "AutoRenew".into(),
                },
            }],
            issuer: None,
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["key_props"]["key_size"], 2048);
        assert_eq!(j["key_props"]["reuse_key"], false);
        assert_eq!(j["secret_props"]["contentType"], "application/x-pkcs12");
        assert_eq!(j["x509_props"]["validity_months"], 12);
        assert_eq!(j["x509_props"]["sans"]["dns_names"][0], "a.com");
        assert_eq!(
            j["lifetime_actions"][0]["trigger"]["days_before_expiry"],
            30
        );
        assert_eq!(
            j["lifetime_actions"][0]["action"]["action_type"],
            "AutoRenew"
        );
        let op: Operation = serde_json::from_value(serde_json::json!({
            "status": "inProgress", "status_details": "Pending", "cancellation_requested": false
        }))
        .unwrap();
        assert_eq!(op.status_details.as_deref(), Some("Pending"));
    }

    #[test]
    fn import_debug_hides_everything() {
        let body = ImportCert {
            value: crate::secret::Secret::new("MIIprivate"),
            pwd: Some(crate::secret::Secret::new("hunter2")),
            policy: Policy::default(),
            attributes: Attributes::default(),
            tags: None,
        };
        let dbg = format!("{body:?}");
        assert!(!dbg.contains("MIIprivate") && !dbg.contains("hunter2"));
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["pwd"], "hunter2");
    }
}
