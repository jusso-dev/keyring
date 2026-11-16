//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub(crate) mod age;
pub mod audit;
pub mod auth;
pub mod azure;
pub mod config;
pub mod dates;
pub(crate) mod expiry;
pub(crate) mod generator;
pub(crate) mod health;
pub mod http;
pub(crate) mod pkcs12;
pub(crate) mod rotation;
pub mod routes;
pub mod secret;
pub mod serve;
pub mod telemetry;
pub mod x509;

use std::sync::Arc;

use axum::Router;

use crate::audit::sink::AuditSink;
use crate::auth::assertion::{Credential, ManagedIdentityTokens};
use crate::auth::cookies::CookieOptions;
use crate::auth::crypto::Sealer;
use crate::auth::oidc::Oidc;
use crate::auth::session::SessionStore;
use crate::azure::{AzureClient, TokenBroker};
use crate::config::Config;

/// Shared state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sessions: Arc<SessionStore>,
    pub oidc: Arc<Oidc>,
    /// Seals the short-lived login cookie (state, nonce and PKCE verifier).
    pub sealer: Arc<Sealer>,
    /// Seals flash cookies. A separate key from login cookies, so neither
    /// can be passed off as the other.
    pub flash_sealer: Arc<Sealer>,
    pub cookies: CookieOptions,
    pub azure: AzureClient,
    /// Limits for reading every vault. Always [`Limits::STANDARD`] outside
    /// tests.
    ///
    /// [`Limits::STANDARD`]: crate::azure::fanout::Limits::STANDARD
    pub fanout: azure::fanout::Limits,
    /// Sends Keyring's own audit events to Log Analytics, when set.
    pub audit_sink: Option<Arc<AuditSink>>,
}

impl AppState {
    /// Build the state, panicking if the HTTP client can't be built. For
    /// tests; `main` uses [`AppState::try_new`] so start-up can report it.
    pub fn new(config: Config) -> Self {
        Self::try_new(config).expect("HTTP client settings are valid")
    }

    /// Build the state. Fails if the outbound HTTP client can't be built,
    /// for example because the TLS trust store can't be read. With the
    /// audit sink set, starts its sender task, so needs a Tokio runtime.
    pub fn try_new(config: Config) -> Result<Self, http::HttpError> {
        let http = http::client(config.outbound_https_only())?;
        // One managed identity token source, shared by the credential and
        // the audit sink, so each resource's token is cached once.
        let identity = config
            .managed_identity
            .as_ref()
            .map(ManagedIdentityTokens::for_identity)
            .transpose()?
            .map(Arc::new);
        let credential = Credential::with_identity(&config, identity.clone());
        let oidc = Oidc::new(&config, http.clone(), credential.clone());
        let broker = Arc::new(TokenBroker::new(&config, http.clone(), credential));
        // The sink writes with the managed identity only. Config refuses the
        // sink settings without one.
        let audit_sink = match (config.audit_ingestion_url(), &config.audit_sink, identity) {
            (Some(url), Some(settings), Some(identity)) => Some(AuditSink::start(
                url,
                settings.tuning,
                identity,
                http.clone(),
            )),
            _ => None,
        };
        let sessions = Arc::new(SessionStore::new(&config.session_secret));
        if let Some(sink) = &audit_sink {
            sessions.set_audit_sink(sink.clone());
        }
        Ok(Self {
            audit_sink,
            sessions,
            oidc: Arc::new(oidc),
            azure: AzureClient::new(http, broker),
            fanout: azure::fanout::Limits::STANDARD,
            sealer: Arc::new(Sealer::new(&config.session_secret, "login")),
            flash_sealer: Arc::new(Sealer::new(&config.session_secret, "flash")),
            cookies: CookieOptions {
                secure: config.is_https(),
            },
            config: Arc::new(config),
        })
    }
}

impl AppState {
    /// The on-behalf-of token broker.
    pub fn azure_broker(&self) -> &TokenBroker {
        self.azure.broker()
    }
}

/// Build the full application router.
pub fn app(state: AppState) -> Router {
    routes::router(state.clone()).with_state(state)
}
