//! A small REST client that calls Azure as the signed-in user.
//!
//! Plain REST over `reqwest`, not the `azure_*` SDK crates. See
//! docs/architecture.md for why.

use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::auth::session::Session;
use crate::azure::token::{Resource, TokenBroker, TokenError};
use crate::http::HttpError;

/// What went wrong calling Azure. Mapped to plain English by the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureError {
    /// Couldn't get a token for the user.
    Token(TokenError),
    /// Azure answered with an error status.
    Status {
        status: u16,
        /// Azure's error code, for example `Forbidden` or `SecretNotFound`.
        code: Option<String>,
        /// Azure's own message. Shown under a form after a 400 on a write,
        /// and matched to spot purge protection. Never logged.
        message: Option<String>,
    },
    /// Couldn't reach Azure.
    Network(String),
    /// Azure's answer wasn't what we expected.
    Unreadable,
}

impl std::fmt::Display for AzureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(e) => write!(f, "{e}"),
            Self::Status { status, code, .. } => {
                write!(
                    f,
                    "Azure returned {status} {}",
                    code.as_deref().unwrap_or("")
                )
            }
            Self::Network(m) => write!(f, "network error: {m}"),
            Self::Unreadable => f.write_str("unreadable response from Azure"),
        }
    }
}

impl std::error::Error for AzureError {}

impl From<TokenError> for AzureError {
    fn from(e: TokenError) -> Self {
        Self::Token(e)
    }
}

impl From<HttpError> for AzureError {
    fn from(e: HttpError) -> Self {
        Self::Network(e.to_string())
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: Option<String>,
    message: Option<String>,
    #[serde(default, rename = "innererror")]
    inner: Option<Box<InnerError>>,
}

/// Key Vault puts the useful reason inside: the outer code is just
/// `Forbidden`, the inner one `ForbiddenByFirewall`, `ForbiddenByRbac`,
/// `SecretDisabled` and so on. Inner errors can nest.
#[derive(Deserialize)]
struct InnerError {
    code: Option<String>,
    #[serde(default, rename = "innererror")]
    inner: Option<Box<InnerError>>,
}

impl ErrorBody {
    /// The most specific code: the deepest inner one, else the outer.
    fn best_code(&self) -> Option<String> {
        let mut best = self.code.clone();
        let mut cur = self.inner.as_deref();
        let mut depth = 0;
        while let Some(i) = cur {
            if i.code.is_some() {
                best = i.code.clone();
            }
            cur = i.inner.as_deref();
            depth += 1;
            if depth > 8 {
                break;
            }
        }
        best
    }
}

/// The error code and message from an Azure error body, if it has one.
pub fn error_code(body: &[u8]) -> (Option<String>, Option<String>) {
    serde_json::from_slice::<ErrorEnvelope>(body)
        .map(|e| (e.error.best_code(), e.error.message))
        .unwrap_or((None, None))
}

#[derive(Clone)]
pub struct AzureClient {
    http: reqwest::Client,
    broker: Arc<TokenBroker>,
}

impl AzureClient {
    pub fn new(http: reqwest::Client, broker: Arc<TokenBroker>) -> Self {
        Self { http, broker }
    }

    pub fn broker(&self) -> &TokenBroker {
        &self.broker
    }

    /// GET and parse JSON.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        session: &Session,
        resource: Resource,
        url: &str,
    ) -> Result<T, AzureError> {
        let body = self.send(session, resource, Method::GET, url, None).await?;
        serde_json::from_slice(&body)
            .map_err(|_| unreadable(resource, &method_path(&Method::GET, url)))
    }

    /// Send a JSON body (POST, PUT, PATCH) and parse the JSON reply.
    pub async fn send_json<T: DeserializeOwned>(
        &self,
        session: &Session,
        resource: Resource,
        method: Method,
        url: &str,
        body: &impl serde::Serialize,
    ) -> Result<T, AzureError> {
        let body = serde_json::to_vec(body).map_err(|_| AzureError::Unreadable)?;
        let what = method_path(&method, url);
        let reply = self
            .send(session, resource, method, url, Some(body))
            .await?;
        serde_json::from_slice(&reply).map_err(|_| unreadable(resource, &what))
    }

    /// Make a call as the user and return the raw body of a 2xx reply. If
    /// Azure says the token is no good (401), get a fresh one and try once
    /// more. If Azure is throttling (429), wait as asked (up to
    /// [`MAX_RETRY_WAIT`]) and try again, at most [`MAX_THROTTLE_RETRIES`]
    /// times.
    pub async fn send(
        &self,
        session: &Session,
        resource: Resource,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, AzureError> {
        let mut retried = false;
        let mut throttled = 0;
        loop {
            let token = self.broker.token_for(session, resource).await?;
            let mut req = self
                .http
                .request(method.clone(), url)
                .header(AUTHORIZATION, format!("Bearer {}", token.expose()))
                .header(ACCEPT, "application/json");
            if let Some(b) = &body {
                req = req.header(CONTENT_TYPE, "application/json").body(b.clone());
            } else if method == Method::POST {
                // Key Vault answers 411 Length Required to a POST with no
                // Content-Length, such as recover. hyper leaves the header
                // off an empty body, so set it.
                req = req.header(CONTENT_LENGTH, "0");
            }
            let res = req
                .send()
                .await
                .map_err(|e| network(resource, &method, url, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !retried {
                session.azure_tokens.forget(resource);
                retried = true;
                continue;
            }
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS && throttled < MAX_THROTTLE_RETRIES
            {
                throttled += 1;
                let wait = retry_after(res.headers().get(reqwest::header::RETRY_AFTER), throttled)
                    .max(quota_resets_after(
                        res.headers().get("x-ms-user-quota-resets-after"),
                    ))
                    .min(MAX_RETRY_WAIT);
                tracing::info!(resource = ?resource, wait_ms = wait.as_millis() as u64, "Azure throttled, waiting");
                tokio::time::sleep(wait).await;
                continue;
            }
            let bytes = res
                .bytes()
                .await
                .map_err(|e| network(resource, &method, url, e))?
                .to_vec();
            if status.is_success() {
                return Ok(bytes);
            }
            let (code, message) = error_code(&bytes);
            // Log the status and code only. Messages can name items.
            tracing::info!(status = status.as_u16(), code = ?code, resource = ?resource, "Azure call failed");
            return Err(AzureError::Status {
                status: status.as_u16(),
                code,
                message,
            });
        }
    }
}

/// `GET /secrets/x`: the method and the URL's path, never its query string.
fn method_path(method: &Method, url: &str) -> String {
    let path = reqwest::Url::parse(url)
        .map(|u| format!("{}{}", u.host_str().unwrap_or_default(), u.path()))
        .unwrap_or_default();
    format!("{method} {path}")
}

/// Log a failed connection with its cause, and turn it into an error.
fn network(resource: Resource, method: &Method, url: &str, err: reqwest::Error) -> AzureError {
    let err = HttpError::from(err);
    tracing::warn!(resource = ?resource, request = %method_path(method, url), error = %err, "could not reach Azure");
    AzureError::from(err)
}

/// Log an answer Keyring couldn't read, and turn it into an error.
fn unreadable(resource: Resource, what: &str) -> AzureError {
    tracing::warn!(resource = ?resource, request = %what, "unreadable answer from Azure");
    AzureError::Unreadable
}

/// Throttled calls are tried again at most this many times.
pub const MAX_THROTTLE_RETRIES: u32 = 2;
/// Longest Keyring will wait before trying a throttled call again.
pub const MAX_RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait after a 429: Azure's `Retry-After` seconds if given,
/// otherwise a short backoff, capped at [`MAX_RETRY_WAIT`].
pub fn retry_after(
    header: Option<&reqwest::header::HeaderValue>,
    attempt: u32,
) -> std::time::Duration {
    let asked = header
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_secs);
    let fallback = std::time::Duration::from_millis(500 * u64::from(attempt));
    asked.unwrap_or(fallback).min(MAX_RETRY_WAIT)
}

/// Resource Graph says when its quota resets as `hh:mm:ss`, instead of
/// `Retry-After`. Zero if missing or unreadable.
pub fn quota_resets_after(header: Option<&reqwest::header::HeaderValue>) -> std::time::Duration {
    let secs = header
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let mut parts = v.trim().split(':').map(|p| p.parse::<u64>().ok());
            let (h, m, s) = (parts.next()??, parts.next()??, parts.next()??);
            let secs = h
                .checked_mul(3600)?
                .checked_add(m.checked_mul(60)?)?
                .checked_add(s)?;
            parts.next().is_none().then_some(secs)
        })
        .unwrap_or(0);
    std::time::Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_graph_quota_header() {
        let h = reqwest::header::HeaderValue::from_static("00:00:03");
        assert_eq!(
            quota_resets_after(Some(&h)),
            std::time::Duration::from_secs(3)
        );
        let h = reqwest::header::HeaderValue::from_static("01:02:03");
        assert_eq!(
            quota_resets_after(Some(&h)),
            std::time::Duration::from_secs(3723)
        );
        // Too big to add up: treated as unreadable, not a panic.
        let huge = reqwest::header::HeaderValue::from_static("18446744073709551615:00:00");
        assert_eq!(quota_resets_after(Some(&huge)), std::time::Duration::ZERO);
        let bad = reqwest::header::HeaderValue::from_static("soon");
        assert_eq!(quota_resets_after(Some(&bad)), std::time::Duration::ZERO);
        assert_eq!(quota_resets_after(None), std::time::Duration::ZERO);
    }

    #[test]
    fn logged_requests_have_no_query_string() {
        assert_eq!(
            method_path(
                &Method::GET,
                "https://kv-prod.vault.azure.net/secrets/db?api-version=7.4&x=y"
            ),
            "GET kv-prod.vault.azure.net/secrets/db"
        );
    }

    #[test]
    fn inner_error_codes_win() {
        let firewall = br#"{"error":{"code":"Forbidden","message":"m","innererror":{"code":"ForbiddenByFirewall"}}}"#;
        assert_eq!(
            error_code(firewall).0.as_deref(),
            Some("ForbiddenByFirewall")
        );
        let nested = br#"{"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByPolicy","innererror":{"code":"SecretDisabled"}}}}"#;
        assert_eq!(error_code(nested).0.as_deref(), Some("SecretDisabled"));
        let plain = br#"{"error":{"code":"SecretNotFound","message":"m"}}"#;
        assert_eq!(error_code(plain).0.as_deref(), Some("SecretNotFound"));
        assert_eq!(error_code(b"not json"), (None, None));
    }

    #[test]
    fn retry_after_rules() {
        let h = reqwest::header::HeaderValue::from_static("2");
        assert_eq!(retry_after(Some(&h), 1), std::time::Duration::from_secs(2));
        let big = reqwest::header::HeaderValue::from_static("120");
        assert_eq!(retry_after(Some(&big), 1), MAX_RETRY_WAIT);
        assert_eq!(retry_after(None, 2), std::time::Duration::from_millis(1000));
        let date = reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(
            retry_after(Some(&date), 1),
            std::time::Duration::from_millis(500)
        );
    }
}
