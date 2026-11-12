//! How Keyring proves to Entra that it is the app registration.
//!
//! Either with a client secret, or with a short-lived token from a
//! user-assigned managed identity that the app registration trusts as a
//! federated credential. The token goes to Entra as `client_assertion`, so
//! there is no secret to store or rotate.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openidconnect::url::{Host, Url};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::azure::token::{EXPIRY_SKEW, FAILURE_MEMORY, MAX_LIFETIME, TokenError};
use crate::config::{ClientCredential, Config};
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

/// Gets tokens for [`ASSERTION_AUDIENCE`] from the managed identity's local
/// token service. Holds the token until shortly before it expires.
pub struct AssertionSource {
    endpoint: String,
    header: Secret,
    identity_client_id: String,
    http: reqwest::Client,
    /// Held while fetching, so concurrent callers make one request.
    cached: Mutex<Cached>,
}

/// The last token, and the last failure so callers queued behind a failed
/// fetch get its answer instead of each waiting out their own timeout.
#[derive(Default)]
struct Cached {
    token: Option<(Secret, SystemTime)>,
    failed: Option<(Instant, TokenError)>,
}

impl AssertionSource {
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
            cached: Mutex::new(Cached::default()),
        }
    }

    /// A token for `api://AzureADTokenExchange` from the managed identity.
    /// Cached until 5 minutes before it expires. One fetch at a time. A
    /// caller that was waiting while a fetch failed gets that failure, the
    /// same way [`crate::azure::TokenBroker`] shares a failed exchange, so an
    /// outage costs one timeout and not one per queued request.
    pub async fn assertion(&self) -> Result<Secret, TokenError> {
        let started = Instant::now();
        let mut cached = self.cached.lock().await;
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
        match self.fetch().await {
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

    async fn fetch(&self) -> Result<(Secret, SystemTime), TokenError> {
        let mut url = Url::parse(&self.endpoint)
            .map_err(|_| TokenError::Unreachable("identity endpoint is not a URL".into()))?;
        url.query_pairs_mut()
            .append_pair("resource", ASSERTION_AUDIENCE)
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
    Assertion(Arc<AssertionSource>),
}

impl Credential {
    /// Build from the configuration. Make this once and share it, so the
    /// assertion is cached once.
    pub fn new(config: &Config) -> Result<Self, HttpError> {
        Ok(match &config.credential {
            ClientCredential::Secret(secret) => Self::Secret(secret.clone()),
            ClientCredential::ManagedIdentity {
                identity_client_id,
                endpoint,
                header,
            } => Self::Assertion(Arc::new(AssertionSource::new(
                endpoint.clone(),
                header.clone(),
                identity_client_id.clone(),
                local_client()?,
            ))),
        })
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
