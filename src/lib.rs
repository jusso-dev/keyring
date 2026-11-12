//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub mod auth;
pub mod azure;
pub mod config;
pub mod dates;
pub(crate) mod expiry;
pub(crate) mod generator;
pub mod http;
pub(crate) mod pkcs12;
pub mod routes;
pub mod secret;
pub mod serve;
pub mod telemetry;
pub mod x509;

use std::sync::Arc;

use axum::Router;

use crate::auth::assertion::Credential;
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
}

impl AppState {
    /// Build the state, panicking if the HTTP client can't be built. For
    /// tests; `main` uses [`AppState::try_new`] so start-up can report it.
    pub fn new(config: Config) -> Self {
        Self::try_new(config).expect("HTTP client settings are valid")
    }

    /// Build the state. Fails if the outbound HTTP client can't be built,
    /// for example because the TLS trust store can't be read.
    pub fn try_new(config: Config) -> Result<Self, http::HttpError> {
        let http = http::client(config.outbound_https_only())?;
        // One credential, so the managed identity's assertion is cached once.
        let credential = Credential::new(&config)?;
        let oidc = Oidc::new(&config, http.clone(), credential.clone());
        let broker = Arc::new(TokenBroker::new(&config, http.clone(), credential));
        Ok(Self {
            sessions: Arc::new(SessionStore::default()),
            oidc: Arc::new(oidc),
            azure: AzureClient::new(http, broker),
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
