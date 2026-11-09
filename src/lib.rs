//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub mod auth;
pub mod azure;
pub mod config;
pub mod dates;
pub mod expiry;
pub mod generator;
pub mod http;
pub mod pkcs12;
pub mod routes;
pub mod secret;
pub mod serve;
pub mod telemetry;
pub mod x509;

use std::sync::Arc;

use axum::Router;

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
    pub sealer: Arc<Sealer>,
    pub cookies: CookieOptions,
    pub azure: AzureClient,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let http = http::client(config.outbound_https_only());
        let oidc = Oidc::new(&config, http.clone());
        let broker = Arc::new(TokenBroker::new(&config, http.clone()));
        Self {
            sessions: Arc::new(SessionStore::default()),
            oidc: Arc::new(oidc),
            azure: AzureClient::new(http, broker),
            sealer: Arc::new(Sealer::new(&config.session_secret, "login")),
            cookies: CookieOptions {
                secure: config.is_https(),
            },
            config: Arc::new(config),
        }
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
