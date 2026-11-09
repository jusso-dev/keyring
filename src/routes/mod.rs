//! HTTP routes.

pub mod assets;
mod auth;
mod certs;
pub mod confirm;
pub mod error;
pub mod flash;
mod headers;
mod health;
mod home;
pub mod lifecycle;
mod secrets;
mod sections;
pub mod shell;
pub mod vault_ctx;
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
        .route("/secrets/deleted", get(secrets::delete::list_deleted))
        .route(
            "/secrets/deleted/{name}",
            get(secrets::delete::deleted_detail),
        )
        .route(
            "/secrets/deleted/{name}/recover",
            post(secrets::delete::recover),
        )
        .route(
            "/secrets/deleted/{name}/purge",
            get(secrets::delete::purge_form).post(secrets::delete::purge),
        )
        .route(
            "/secrets/{name}/delete",
            get(secrets::delete::delete_form).post(secrets::delete::delete),
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
        .route("/certificates", get(certs::list))
        .route(
            "/certificates/upload",
            get(certs::upload::form).post(certs::upload::preview).layer(
                axum::extract::DefaultBodyLimit::max(certs::upload::MAX_BODY_BYTES),
            ),
        )
        .route("/certificates/upload/confirm", post(certs::upload::confirm))
        .route(
            "/certificates/new",
            get(certs::create::form).post(certs::create::create),
        )
        .route("/certificates/deleted", get(certs::delete::list_deleted))
        .route(
            "/certificates/deleted/{name}",
            get(certs::delete::deleted_detail),
        )
        .route(
            "/certificates/deleted/{name}/recover",
            post(certs::delete::recover),
        )
        .route(
            "/certificates/deleted/{name}/purge",
            get(certs::delete::purge_form).post(certs::delete::purge),
        )
        .route(
            "/certificates/{name}/delete",
            get(certs::delete::delete_form).post(certs::delete::delete),
        )
        .route("/certificates/{name}", get(certs::detail))
        .route("/certificates/{name}/cer", get(certs::download::cer))
        .route(
            "/certificates/{name}/download-key",
            get(certs::download::pfx_form).post(certs::download::pfx),
        )
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
