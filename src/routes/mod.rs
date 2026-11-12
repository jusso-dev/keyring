//! HTTP routes.

pub mod assets;
mod audit;
mod auth;
mod certs;
pub(crate) mod confirm;
pub mod error;
mod expiry;
pub mod flash;
pub(crate) mod forms;
mod generator;
mod headers;
mod health;
mod home;
mod keys;
pub(crate) mod lifecycle;
mod moved;
mod origin;
pub(crate) mod paging;
mod rejection;
mod secrets;
pub(crate) mod shell;
pub(crate) mod vault_ctx;
mod vaults;

use axum::Router;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};

use crate::AppState;
use crate::routes::error::{PageError, Problem};
use crate::routes::shell::Shell;

/// Largest request body for ordinary forms.
pub const MAX_FORM_BYTES: usize = 64 * 1024;

/// Largest body for the two forms that carry a secret value. Values are
/// capped at 25 KB once line breaks are LF. The worst case on the wire is a
/// value of line breaks: the browser sends each as CRLF, encoded `%0D%0A`,
/// so six bytes for every byte stored (150 KB). Other bytes take at most
/// three. 256 KB leaves room for that and the other fields, so a valid
/// value always gets the form's own message, not a 413.
pub const MAX_VALUE_FORM_BYTES: usize = 256 * 1024;

/// Every page that works on one vault. Nested under `/v/{vault}`, so the
/// vault in the address is the one the request acts on. New vault pages go
/// here and start with `vault_ctx::path_vault`.
fn vault_routes() -> Router<AppState> {
    Router::new()
        .route("/secrets", get(secrets::list))
        .route(
            "/secrets/-/new",
            get(secrets::edit::new_form)
                .post(secrets::edit::create)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_VALUE_FORM_BYTES)),
        )
        .route(
            "/secrets/-/deleted",
            get(lifecycle::handlers::list_deleted::<secrets::delete::Secrets>),
        )
        .route(
            "/secrets/-/deleted/{name}",
            get(lifecycle::handlers::deleted_detail::<secrets::delete::Secrets>),
        )
        .route(
            "/secrets/-/deleted/{name}/recover",
            post(lifecycle::handlers::recover::<secrets::delete::Secrets>),
        )
        .route(
            "/secrets/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<secrets::delete::Secrets>)
                .post(lifecycle::handlers::purge::<secrets::delete::Secrets>),
        )
        .route(
            "/secrets/{name}/delete",
            get(lifecycle::handlers::delete_form::<secrets::delete::Secrets>)
                .post(lifecycle::handlers::delete::<secrets::delete::Secrets>),
        )
        .route(
            "/secrets/{name}",
            get(secrets::detail).post(moved::post_item),
        )
        .route(
            "/secrets/{name}/value",
            get(secrets::edit::value_form)
                .post(secrets::edit::set_value)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_VALUE_FORM_BYTES)),
        )
        .route(
            "/secrets/{name}/edit",
            get(secrets::edit::edit_form).post(secrets::edit::update),
        )
        .route("/secrets/{name}/enabled", post(secrets::edit::toggle))
        .route("/secrets/{name}/disable", get(secrets::edit::disable_form))
        .route("/secrets/{name}/versions", get(secrets::versions::list))
        .route(
            "/secrets/{name}/rollback",
            get(secrets::versions::confirm).post(secrets::versions::rollback),
        )
        .route("/secrets/{name}/reveal", post(secrets::reveal::reveal))
        .route("/certificates", get(certs::list))
        .route(
            "/certificates/-/upload",
            get(certs::upload::form).post(certs::upload::preview).layer(
                axum::extract::DefaultBodyLimit::max(certs::upload::MAX_BODY_BYTES),
            ),
        )
        .route(
            "/certificates/-/upload/confirm",
            post(certs::upload::confirm),
        )
        .route("/certificates/-/upload/cancel", post(certs::upload::cancel))
        .route(
            "/certificates/-/new",
            get(certs::create::form).post(certs::create::create),
        )
        .route(
            "/certificates/-/deleted",
            get(lifecycle::handlers::list_deleted::<certs::delete::Certificates>),
        )
        .route(
            "/certificates/-/deleted/{name}",
            get(lifecycle::handlers::deleted_detail::<certs::delete::Certificates>),
        )
        .route(
            "/certificates/-/deleted/{name}/recover",
            post(lifecycle::handlers::recover::<certs::delete::Certificates>),
        )
        .route(
            "/certificates/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<certs::delete::Certificates>)
                .post(lifecycle::handlers::purge::<certs::delete::Certificates>),
        )
        .route(
            "/certificates/{name}/delete",
            get(lifecycle::handlers::delete_form::<certs::delete::Certificates>)
                .post(lifecycle::handlers::delete::<certs::delete::Certificates>),
        )
        .route(
            "/certificates/{name}",
            get(certs::detail).post(moved::post_item),
        )
        .route("/certificates/{name}/enabled", post(certs::toggle))
        .route("/certificates/{name}/disable", get(certs::disable_form))
        .route(
            "/certificates/{name}/pending/cancel",
            post(certs::create::cancel_pending),
        )
        .route("/certificates/{name}/cer", get(certs::download::cer))
        .route(
            "/certificates/{name}/download-key",
            get(certs::download::pfx_form).post(certs::download::pfx),
        )
        .route("/keys", get(keys::list))
        .route(
            "/keys/-/new",
            get(keys::edit::create_form).post(keys::edit::create),
        )
        .route(
            "/keys/-/deleted",
            get(lifecycle::handlers::list_deleted::<keys::delete::Keys>),
        )
        .route(
            "/keys/-/deleted/{name}",
            get(lifecycle::handlers::deleted_detail::<keys::delete::Keys>),
        )
        .route(
            "/keys/-/deleted/{name}/recover",
            post(lifecycle::handlers::recover::<keys::delete::Keys>),
        )
        .route(
            "/keys/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<keys::delete::Keys>)
                .post(lifecycle::handlers::purge::<keys::delete::Keys>),
        )
        .route("/keys/{name}", get(keys::detail).post(moved::post_item))
        .route("/keys/{name}/enabled", post(keys::toggle))
        .route("/keys/{name}/disable", get(keys::disable_form))
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
            get(lifecycle::handlers::delete_form::<keys::delete::Keys>)
                .post(lifecycle::handlers::delete::<keys::delete::Keys>),
        )
        .route("/audit", get(audit::page))
        .route("/audit.csv", get(audit::csv))
}

pub fn router(state: AppState) -> Router<AppState> {
    // Everything here needs a signed-in session. New pages go in this list.
    let protected = Router::new()
        .route("/", get(home::index))
        .route("/vaults", get(vaults::list))
        .route("/vaults/select", post(vaults::select))
        .nest("/v/{vault}", vault_routes())
        // The old addresses, before the vault was in the path.
        .route("/secrets", any(moved::legacy))
        .route("/secrets/{*rest}", any(moved::legacy))
        .route("/certificates", any(moved::legacy))
        .route("/certificates/{*rest}", any(moved::legacy))
        .route("/keys", any(moved::legacy))
        .route("/keys/{*rest}", any(moved::legacy))
        .route("/audit", any(moved::legacy))
        .route("/audit.csv", any(moved::legacy))
        .route("/expiry", get(expiry::page))
        .route("/expiry.csv", get(expiry::csv))
        .route("/generator", get(generator::page).post(generator::generate))
        .route("/auth/keepalive", get(auth::keepalive))
        // Inside the session check, so the error page has the signed-in shell.
        .route_layer(middleware::from_fn(rejection::layer))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_session,
        ));

    let public = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/static/{file}", get(assets::serve))
        .route("/favicon.ico", get(assets::favicon))
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
        // A panic in any handler becomes a 500 page for that request
        // instead of ending the process. Inside the headers layer, so the
        // page still gets the security headers.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(panicked))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            headers::layer,
        ))
        // Outermost, so the logged status includes timeouts and panics.
        .layer(middleware::from_fn(crate::telemetry::request_log))
}

/// The page for a request whose handler panicked. The panic message is not
/// logged: it could hold a value from the request.
fn panicked(_: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!("request handler panicked");
    PageError::new(
        Shell::anonymous(),
        Problem::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Keyring hit a problem showing this page. Nothing else was affected. Try again, and if it keeps happening, let whoever runs Keyring know.",
        ),
    )
    .into_response()
}

async fn not_found(shell: Shell, req: axum::extract::Request) -> Response {
    // An old fixed-page address under a vault, such as `/v/kv/secrets/new/x`.
    if let Some(res) = moved::from_vault_fallback(req.uri()) {
        return res;
    }
    PageError::new(shell, Problem::not_found()).into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn a_panicking_handler_gets_a_500_page() {
        let app: Router = Router::new()
            .route(
                "/boom",
                get(|| async {
                    panic!("test panic");
                    #[allow(unreachable_code)]
                    ""
                }),
            )
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(panicked));
        let res = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
