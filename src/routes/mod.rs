//! HTTP routes.

pub mod assets;
mod audit;
mod auth;
mod certs;
pub mod confirm;
pub mod error;
mod expiry;
pub mod flash;
mod generator;
mod headers;
mod health;
mod home;
mod keys;
pub mod lifecycle;
mod origin;
mod secrets;
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

/// Largest request body for ordinary forms. Secret values are capped at
/// 25 KB, so this leaves room for the rest of the form.
pub const MAX_FORM_BYTES: usize = 64 * 1024;

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
        .route("/keys", get(keys::list))
        .route(
            "/keys/new",
            get(keys::edit::create_form).post(keys::edit::create),
        )
        .route("/keys/deleted", get(keys::delete::list_deleted))
        .route("/keys/deleted/{name}", get(keys::delete::deleted_detail))
        .route("/keys/deleted/{name}/recover", post(keys::delete::recover))
        .route(
            "/keys/deleted/{name}/purge",
            get(keys::delete::purge_form).post(keys::delete::purge),
        )
        .route("/keys/{name}", get(keys::detail))
        .route("/keys/{name}/enabled", post(keys::toggle))
        .route(
            "/keys/{name}/rotate",
            get(keys::edit::rotate_form).post(keys::edit::rotate),
        )
        .route(
            "/keys/{name}/rotation",
            get(keys::edit::rotation_form).post(keys::edit::save_rotation),
        )
        .route(
            "/keys/{name}/delete",
            get(keys::delete::delete_form).post(keys::delete::delete),
        )
        .route("/expiry", get(expiry::page))
        .route("/expiry.csv", get(expiry::csv))
        .route("/generator", get(generator::page).post(generator::generate))
        .route("/audit", get(audit::page))
        .route("/audit.csv", get(audit::csv))
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
        .layer(middleware::from_fn_with_state(state.clone(), origin::layer))
        // Small forms only by default. The certificate upload route sets
        // its own larger limit.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_FORM_BYTES))
        .layer(middleware::from_fn_with_state(state, headers::layer))
}

async fn not_found(shell: Shell) -> Response {
    PageError::new(shell, Problem::not_found()).into_response()
}
