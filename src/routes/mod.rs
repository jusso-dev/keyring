//! HTTP routes.

pub mod assets;
mod auth;
pub mod confirm;
pub mod error;
pub mod flash;
mod headers;
mod health;
mod home;
mod secrets;
mod sections;
pub mod shell;
mod vaults;

use axum::Router;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::AppState;
use crate::routes::error::{PageError, Problem};
use crate::routes::shell::Shell;

pub fn router(state: AppState) -> Router<AppState> {
    // Everything here needs a signed-in session. New pages go in this list.
    let protected = Router::new()
        .route("/", get(home::index))
        .route("/vaults", get(vaults::list))
        .route("/vaults/select", post(vaults::select))
        .route("/secrets", get(secrets::list))
        .route(
            "/secrets/new",
            get(secrets::edit::new_form).post(secrets::edit::create),
        )
        .route("/secrets/{name}", get(secrets::detail))
        .route(
            "/secrets/{name}/value",
            get(secrets::edit::value_form).post(secrets::edit::set_value),
        )
        .route(
            "/secrets/{name}/edit",
            get(secrets::edit::edit_form).post(secrets::edit::update),
        )
        .route("/secrets/{name}/enabled", post(secrets::edit::toggle))
        .route("/secrets/{name}/versions", get(secrets::versions::list))
        .route(
            "/secrets/{name}/rollback",
            get(secrets::versions::confirm).post(secrets::versions::rollback),
        )
        .route("/secrets/{name}/reveal", post(secrets::reveal::reveal))
        .route("/certificates", get(sections::certificates))
        .route("/keys", get(sections::keys))
        .route("/expiry", get(sections::expiry))
        .route("/generator", get(sections::generator))
        .route("/audit", get(sections::audit))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
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

    protected
        .merge(public)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), flash::layer))
        .layer(middleware::from_fn_with_state(state, headers::layer))
}

async fn not_found(shell: Shell) -> Response {
    PageError::new(shell, Problem::not_found()).into_response()
}
