//! HTTP routes.

pub mod assets;
mod auth;
mod health;
mod home;
pub mod shell;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};

use crate::AppState;

pub fn router(state: AppState) -> Router<AppState> {
    // Everything here needs a signed-in session. New pages go in this list.
    let protected =
        Router::new()
            .route("/", get(home::index))
            .route_layer(middleware::from_fn_with_state(
                state,
                crate::auth::require_session,
            ));

    let public = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/static/{file}", get(assets::serve))
        .route("/auth/sign-in", get(auth::sign_in))
        .route("/auth/start", get(auth::start))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/sign-out", post(auth::sign_out))
        .route("/auth/signed-out", get(auth::signed_out));

    protected.merge(public)
}
