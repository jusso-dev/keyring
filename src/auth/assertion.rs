//! The managed identity token source, and how Keyring proves to Entra
//! that it is the app registration.
//!
//! Keyring has at most one managed identity of its own
//! (`KEYRING_MANAGED_IDENTITY_CLIENT_ID`). [`ManagedIdentityTokens`] gets its
//! tokens from the platform's local token service, one cache per resource.
//! Two resources are ever asked for: [`ASSERTION_AUDIENCE`], sent to Entra
//! as `client_assertion` in place of a client secret, and
//! [`crate::audit::sink::MONITOR_RESOURCE`], for writing audit rows. No
//! token from here ever reads or changes a person's vault, ARM or Log
//! Analytics data: that is always the person's own on-behalf-of token.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openidconnect::url::{Host, Url};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::azure::token::{EXPIRY_SKEW, FAILURE_MEMORY, MAX_LIFETIME, TokenError};
use crate::config::{ClientCredential, Config, ManagedIdentity};
use crate::http::{HttpError, local_client};
use crate::secret::Secret;

/// `client_assertion_type` for a JWT assertion.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Audience of the managed identity's token. Entra's global cloud value.
pub const ASSERTION_AUDIENCE: &str = "api://AzureADTokenExchange";

/// Version of the local token service's API, as App Service and Container
/// Apps document it.
const IDENTITY_API_VERSION: &str = "2019-08-01";

/// Check `IDENTITY_ENDPOINT` is a plain HTTP address on this machine or a
/// link-local address, and return it in normal form. The client that calls
/// it allows plain HTTP, so it must never be pointed at the network.
pub fn checked_endpoint(raw: &str) -> Result<String, String> {
    let rule = "must be an http:// address on localhost, 127.0.0.1 or 169.254.0.0/16";
    let url = Url::parse(raw.trim()).map_err(|_| rule.to_owned())?;
    let local = match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST || ip.octets()[..2] == [169, 254],
        _ => false,
    };
    if url.scheme() != "http" || !local {
        return Err(rule.to_owned());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("must not include a user name, query or fragment".to_owned());
    }
    Ok(url.to_string())
}

/// `expires_on` is Unix seconds, sent as a string. A number is accepted too.
#[derive(Deserialize)]
#[serde(untagged)]
enum ExpiresOn {
    Text(String),
    Number(u64),
}

impl ExpiresOn {
    fn at(&self) -> Option<SystemTime> {
        let secs = match self {
            Self::Text(s) => s.trim().parse().ok()?,
            Self::Number(n) => *n,
        };
        UNIX_EPOCH.checked_add(Duration::from_secs(secs))
    }
}

#[derive(Deserialize)]
struct IdentityToken {
    access_token: String,
    expires_on: ExpiresOn,
}

/// Gets tokens from the managed identity's local token service, for any
/// resource Keyring names. Each resource's token is held until shortly
/// before it expires.
pub struct ManagedIdentityTokens {
    endpoint: String,
    header: Secret,
    identity_client_id: String,
    http: reqwest::Client,
    /// One slot per resource. The slot's lock is held while fetching, so
    /// concurrent callers for one resource make one request.
    cached: std::sync::Mutex<HashMap<&'static str, Arc<Mutex<Cached>>>>,
}

/// The last token, and the last failure so callers queued behind a failed
/// fetch get its answer instead of each waiting out their own timeout.
#[derive(Default)]
struct Cached {
    token: Option<(Secret, SystemTime)>,
    failed: Option<(Instant, TokenError)>,
}

impl ManagedIdentityTokens {
    pub fn new(
        endpoint: String,
        header: Secret,
        identity_client_id: String,
        http: reqwest::Client,
    ) -> Self {
        Self {
            endpoint,
            header,
            identity_client_id,
            http,
            cached: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// From the configured identity, with the local-only client.
    pub fn for_identity(identity: &ManagedIdentity) -> Result<Self, HttpError> {
        Ok(Self::new(
            identity.endpoint.clone(),
            identity.header.clone(),
            identity.client_id.clone(),
            local_client()?,
        ))
    }

    /// The identity's client ID, for the audit sink's writer column.
    pub fn client_id(&self) -> &str {
        &self.identity_client_id
    }

    /// A token for `api://AzureADTokenExchange`, sent to Entra as
    /// `client_assertion`.
    pub async fn assertion(&self) -> Result<Secret, TokenError> {
        self.token(ASSERTION_AUDIENCE).await
    }

    /// A token for `resource` from the managed identity. Cached until 5
    /// minutes before it expires. One fetch at a time per resource. A
    /// caller that was waiting while a fetch failed gets that failure, the
    /// same way [`crate::azure::TokenBroker`] shares a failed exchange, so
    /// an outage costs one timeout and not one per queued request.
    pub async fn token(&self, resource: &'static str) -> Result<Secret, TokenError> {
        let started = Instant::now();
        let slot = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(resource)
            .or_default()
            .clone();
        let mut cached = slot.lock().await;
        if let Some((token, expires_at)) = cached.token.as_ref()
            && expires_at
                .duration_since(SystemTime::now())
                .is_ok_and(|left| left > EXPIRY_SKEW)
        {
            return Ok(token.clone());
        }
        if let Some((at, err)) = cached.failed.as_ref()
            && *at >= started
            && at.elapsed() < FAILURE_MEMORY
        {
            return Err(err.clone());
        }
        match self.fetch(resource).await {
            Ok((token, expires_at)) => {
                cached.token = Some((token.clone(), expires_at));
                cached.failed = None;
                Ok(token)
            }
            Err(e) => {
                cached.failed = Some((Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    /// Forget the cached token for `resource`, so the next call fetches a
    /// new one. For a token the resource has just refused.
    pub async fn forget(&self, resource: &'static str) {
        let slot = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(resource)
            .cloned();
        if let Some(slot) = slot {
            slot.lock().await.token = None;
        }
    }

    async fn fetch(&self, resource: &str) -> Result<(Secret, SystemTime), TokenError> {
        let mut url = Url::parse(&self.endpoint)
            .map_err(|_| TokenError::Unreachable("identity endpoint is not a URL".into()))?;
        url.query_pairs_mut()
            .append_pair("resource", resource)
            .append_pair("api-version", IDENTITY_API_VERSION)
            .append_pair("client_id", &self.identity_client_id);
        let unreachable = |e: reqwest::Error| {
            let e = HttpError::from(e);
            tracing::warn!(error = %e, "managed identity token service unreachable");
            TokenError::from(e)
        };
        let res = self
            .http
            .get(url)
            .header("X-IDENTITY-HEADER", self.header.expose())
            .send()
            .await
            .map_err(unreachable)?;
        let status = res.status();
        if !status.is_success() {
            // The body is not read or logged: it may describe the request.
            tracing::warn!(
                status = status.as_u16(),
                "managed identity token service refused"
            );
            return Err(TokenError::Unreachable(format!(
                "identity endpoint returned {status}"
            )));
        }
        let body = res.bytes().await.map_err(unreachable)?;
        let parsed: IdentityToken = serde_json::from_slice(&body).map_err(|_| {
            tracing::warn!(
                status = status.as_u16(),
                "unreadable managed identity token response"
            );
            TokenError::Unreachable("unreadable identity token response".into())
        })?;
        let now = SystemTime::now();
        let Some(expires_at) = parsed.expires_on.at() else {
            tracing::warn!("managed identity token response has no usable expires_on");
            return Err(TokenError::Unreachable(
                "unreadable identity token response".into(),
            ));
        };
        // Believe no lifetime past what Entra issues.
        let expires_at = expires_at.min(now + MAX_LIFETIME);
        Ok((Secret::new(parsed.access_token), expires_at))
    }
}

/// What Keyring sends Entra to prove it is the app registration.
#[derive(Clone)]
pub enum Credential {
    Secret(Secret),
    Assertion(Arc<ManagedIdentityTokens>),
}

impl Credential {
    /// Build from the configuration, with a token source of its own. For
    /// tests; [`crate::AppState`] uses [`Credential::with_identity`] so the
    /// audit sink shares the one source.
    pub fn new(config: &Config) -> Result<Self, HttpError> {
        let identity = config
            .managed_identity
            .as_ref()
            .map(ManagedIdentityTokens::for_identity)
            .transpose()?
            .map(Arc::new);
        Ok(Self::with_identity(config, identity))
    }

    /// Build from the configuration and the shared token source. With a
    /// client secret configured, the secret is the credential and the
    /// identity (if any) is only for the audit sink.
    pub fn with_identity(config: &Config, identity: Option<Arc<ManagedIdentityTokens>>) -> Self {
        match (&config.credential, identity) {
            (ClientCredential::Secret(secret), _) => Self::Secret(secret.clone()),
            (ClientCredential::ManagedIdentity, Some(tokens)) => Self::Assertion(tokens),
            (ClientCredential::ManagedIdentity, None) => {
                unreachable!("Config only picks the managed identity credential when one is set")
            }
        }
    }

    /// The client secret, when that is the credential.
    pub fn secret(&self) -> Option<&Secret> {
        match self {
            Self::Secret(s) => Some(s),
            Self::Assertion(_) => None,
        }
    }

    /// A fresh assertion, when that is the credential.
    pub async fn assertion(&self) -> Result<Option<Secret>, TokenError> {
        match self {
            Self::Secret(_) => Ok(None),
            Self::Assertion(source) => source.assertion().await.map(Some),
        }
    }

    /// Form fields that authenticate a token request: the client secret, or
    /// the assertion and its type. Never both.
    pub async fn form_fields(&self) -> Result<Vec<(&'static str, Secret)>, TokenError> {
        match self {
            Self::Secret(secret) => Ok(vec![("client_secret", secret.clone())]),
            Self::Assertion(source) => Ok(vec![
                ("client_assertion_type", Secret::new(ASSERTION_TYPE)),
                ("client_assertion", source.assertion().await?),
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_on_is_read_from_a_string_or_a_number() {
        let t: IdentityToken =
            serde_json::from_str(r#"{"access_token":"a","expires_on":"1586984735"}"#).unwrap();
        assert_eq!(
            t.expires_on.at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_586_984_735))
        );
        let t: IdentityToken =
            serde_json::from_str(r#"{"access_token":"a","expires_on":1586984735}"#).unwrap();
        assert_eq!(
            t.expires_on.at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_586_984_735))
        );
        let t: IdentityToken = serde_json::from_str(
            r#"{"access_token":"a","expires_on":"07/01/2026 10:00:00 +00:00"}"#,
        )
        .unwrap();
        assert_eq!(t.expires_on.at(), None);
    }

    #[test]
    fn only_local_and_link_local_endpoints_are_accepted() {
        for ok in [
            "http://localhost:42356/msi/token",
            "http://LOCALHOST:42356/msi/token",
            "http://127.0.0.1:8081/msi/token",
            "http://169.254.129.1:8081/msi/token",
            "http://169.254.255.254/msi/token",
        ] {
            assert!(checked_endpoint(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [
            "https://localhost:42356/msi/token",
            "http://example.com/msi/token",
            "http://localhost.evil.com/msi/token",
            "http://169.253.1.1/msi/token",
            "http://169.255.1.1/msi/token",
            "http://10.0.0.4/msi/token",
            "http://127.0.0.2/msi/token",
            "http://[::1]:8081/msi/token",
            "http://user@localhost/msi/token",
            "http://localhost/msi/token?x=1",
            "localhost:8081/msi/token",
            "",
        ] {
            assert!(checked_endpoint(bad).is_err(), "{bad} should be refused");
        }
    }

    #[tokio::test]
    async fn the_secret_credential_sends_only_the_secret() {
        let c = Credential::Secret(Secret::new("s"));
        let fields = c.form_fields().await.unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "client_secret");
        assert_eq!(fields[0].1.expose(), "s");
        assert!(c.assertion().await.unwrap().is_none());
    }
}
