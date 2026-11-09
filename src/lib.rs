//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub mod auth;
pub mod azure;
pub mod config;
pub mod http;
pub mod routes;
pub mod secret;
pub mod telemetry;

use std::sync::Arc;

use axum::Router;

use crate::auth::cookies::CookieOptions;
use crate::auth::crypto::Sealer;
use crate::auth::oidc::Oidc;
use crate::auth::session::SessionStore;
use crate::config::Config;

/// Shared state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sessions: Arc<SessionStore>,
    pub oidc: Arc<Oidc>,
    pub sealer: Arc<Sealer>,
    pub cookies: CookieOptions,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            sessions: Arc::new(SessionStore::default()),
            oidc: Arc::new(Oidc::new(&config)),
            sealer: Arc::new(Sealer::new(&config.session_secret, "login")),
            cookies: CookieOptions {
                secure: config.is_https(),
            },
            config: Arc::new(config),
        }
    }
}

/// Build the full application router.
pub fn app(state: AppState) -> Router {
    routes::router(state.clone()).with_state(state)
}
