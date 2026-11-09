//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub mod auth;
pub mod azure;
pub mod config;
pub mod routes;
pub mod secret;
pub mod telemetry;

use std::sync::Arc;

use axum::Router;

use crate::config::Config;

/// Shared state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

/// Build the full application router.
pub fn app(state: AppState) -> Router {
    routes::router().with_state(state)
}
