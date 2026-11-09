//! A small REST client that calls Azure as the signed-in user.
//!
//! Plain REST over `reqwest`, not the `azure_*` SDK crates. See
//! docs/architecture.md for why.

use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
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
        /// Azure's own message. Shown to the user, never logged.
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
        serde_json::from_slice(&body).map_err(|_| AzureError::Unreadable)
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
        let reply = self
            .send(session, resource, method, url, Some(body))
            .await?;
        serde_json::from_slice(&reply).map_err(|_| AzureError::Unreadable)
    }

    /// Make a call as the user and return the raw body of a 2xx reply. If
    /// Azure says the token is no good (401), get a fresh one and try once more.
    pub async fn send(
        &self,
        session: &Session,
        resource: Resource,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, AzureError> {
        let mut retried = false;
        loop {
            let token = self.broker.token_for(session, resource).await?;
            let mut req = self
                .http
                .request(method.clone(), url)
                .header(AUTHORIZATION, format!("Bearer {}", token.expose()))
                .header(ACCEPT, "application/json");
            if let Some(b) = &body {
                req = req.header(CONTENT_TYPE, "application/json").body(b.clone());
            }
            let res = req.send().await.map_err(HttpError::from)?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !retried {
                session.azure_tokens.forget(resource);
                retried = true;
                continue;
            }
            let bytes = res.bytes().await.map_err(HttpError::from)?.to_vec();
            if status.is_success() {
                return Ok(bytes);
            }
            let (code, message) = serde_json::from_slice::<ErrorEnvelope>(&bytes)
                .map(|e| (e.error.code, e.error.message))
                .unwrap_or((None, None));
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
