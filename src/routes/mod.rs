//! HTTP routes.

mod access;
pub(crate) mod access_request;
mod access_review;
mod age;
pub mod assets;
mod audit;
mod audit_across;
pub(crate) mod audit_gate;
mod audit_keyring;
mod auth;
pub(crate) mod batch;
mod bulk;
mod certs;
pub(crate) mod confirm;
mod defender;
mod details;
pub(crate) mod environments;
pub mod error;
mod every_vault;
mod expiry;
pub mod flash;
pub(crate) mod forms;
mod generator;
mod headers;
mod health;
pub(crate) mod hints;
mod home;
mod hooks;
mod keys;
pub(crate) mod lifecycle;
mod moved;
mod origin;
pub(crate) mod paging;
pub(crate) mod pim;
pub(crate) mod reason;
mod rejection;
pub(crate) mod reports;
pub(crate) mod reveal_limit;
pub mod search;
mod secrets;
pub(crate) mod share;
pub(crate) mod shell;
pub(crate) mod step_up;
pub(crate) mod tag_rows;
pub(crate) mod used_by;
pub(crate) mod vault_ctx;
mod vault_health;
mod vaults;

use axum::Router;
use axum::extract::Request;
use axum::handler::Handler;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, any, get, post};

use crate::AppState;
use crate::audit::Action;
use crate::routes::error::{PageError, Problem};
use crate::routes::shell::Shell;

/// Largest request body for ordinary forms.
pub const MAX_FORM_BYTES: usize = 64 * 1024;

/// Largest body for the two forms that carry a secret value. Values are
/// capped at 25,600 UTF-16 code units once line breaks are LF, as Key Vault
/// counts them. The worst case on the wire is 25,600 three-byte characters,
/// each sent as `%XX%XX%XX`: nine bytes a character (225 KB). A line break
/// is sent as `%0D%0A`, six bytes, and a four-byte character counts as two
/// units, so twelve bytes for two. 256 KB leaves room for that and the other
/// fields, so a valid value always gets the form's own message, not a 413.
pub const MAX_VALUE_FORM_BYTES: usize = 256 * 1024;

/// A POST route whose every request writes one audit event for `action`,
/// whatever the outcome. Every POST that can change something in Key
/// Vault, or reads a value, goes through here. `tests/audit_events.rs`
/// fails on a POST route that is neither this nor on its exempt list.
///
/// It also runs the reason gate (`KEYRING_REQUIRE_REASON`), so every
/// audited action asks for a reason the same way.
fn audited<H, T>(action: Action, handler: H) -> MethodRouter<AppState>
where
    H: Handler<T, AppState>,
    T: 'static,
{
    post(handler).layer(middleware::from_fn(
        move |req: Request, next: Next| async move {
            crate::audit::set_action(action);
            reason::gate(action, req, next).await
        },
    ))
}

/// Every page that works on one vault. Nested under `/v/{vault}`, so the
/// vault in the address is the one the request acts on. New vault pages go
/// here and start with `vault_ctx::path_vault`.
fn vault_routes() -> Router<AppState> {
    Router::new()
        .route("/secrets", get(secrets::list))
        .route(
            "/secrets/-/new",
            get(secrets::edit::new_form)
                .merge(audited(Action::SecretCreate, secrets::edit::create))
                .layer(axum::extract::DefaultBodyLimit::max(MAX_VALUE_FORM_BYTES)),
        )
        .route(
            "/secrets/-/import",
            get(secrets::import::form)
                .post(secrets::import::preview)
                .layer(axum::extract::DefaultBodyLimit::max(
                    secrets::import_file::MAX_BODY_BYTES,
                )),
        )
        .route(
            "/secrets/-/import/confirm",
            audited(Action::SecretImport, secrets::import::confirm),
        )
        .route("/secrets/-/import/cancel", post(secrets::import::cancel))
        .route("/secrets/-/bulk", post(bulk::review::<bulk::Secrets>))
        .route(
            "/secrets/-/bulk/apply",
            audited(Action::SecretBulkUpdate, bulk::apply::<bulk::Secrets>),
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
            audited(
                Action::SecretRecover,
                lifecycle::handlers::recover::<secrets::delete::Secrets>,
            ),
        )
        .route(
            "/secrets/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<secrets::delete::Secrets>).merge(audited(
                Action::SecretPurge,
                lifecycle::handlers::purge::<secrets::delete::Secrets>,
            )),
        )
        .route(
            "/secrets/{name}/delete",
            get(lifecycle::handlers::delete_form::<secrets::delete::Secrets>).merge(audited(
                Action::SecretDelete,
                lifecycle::handlers::delete::<secrets::delete::Secrets>,
            )),
        )
        .route(
            "/secrets/{name}",
            get(secrets::detail).post(moved::post_item),
        )
        .route(
            "/secrets/{name}/value",
            get(secrets::edit::value_form)
                .merge(audited(Action::SecretSet, secrets::edit::set_value))
                .layer(axum::extract::DefaultBodyLimit::max(MAX_VALUE_FORM_BYTES)),
        )
        .route(
            "/secrets/{name}/edit",
            get(secrets::edit::edit_form)
                .merge(audited(Action::SecretUpdate, secrets::edit::update)),
        )
        .route(
            "/secrets/{name}/enabled",
            audited(Action::SecretEnabledSet, secrets::edit::toggle),
        )
        .route("/secrets/{name}/disable", get(secrets::edit::disable_form))
        .route("/secrets/{name}/versions", get(secrets::versions::list))
        .route(
            "/secrets/{name}/rollback",
            get(secrets::versions::confirm)
                .merge(audited(Action::SecretRollback, secrets::versions::rollback)),
        )
        .route(
            "/secrets/{name}/copy",
            get(secrets::copy::page).merge(audited(Action::SecretCopyRead, secrets::copy::apply)),
        )
        .route("/secrets/{name}/copy/review", get(secrets::copy::review))
        // Sharing (#286). Every sharing route answers "not found" unless
        // KEYRING_SHARING=true, before the reason gate or the handler.
        .route(
            "/secrets/{name}/share",
            get(share::form)
                .merge(audited(Action::ShareGrant, share::grant))
                .route_layer(middleware::from_fn(share::require_on)),
        )
        .route(
            "/secrets/{name}/share/revoke",
            get(share::revoke_form)
                .merge(audited(Action::ShareRevoke, share::revoke))
                .route_layer(middleware::from_fn(share::require_on)),
        )
        .route(
            "/share/people",
            get(share::people).route_layer(middleware::from_fn(share::require_on)),
        )
        .route(
            "/secrets/{name}/reveal",
            audited(Action::SecretReveal, secrets::reveal::reveal),
        )
        .route("/certificates", get(certs::list))
        .route(
            "/certificates/-/upload",
            get(certs::upload::form).post(certs::upload::preview).layer(
                axum::extract::DefaultBodyLimit::max(certs::upload::MAX_BODY_BYTES),
            ),
        )
        .route(
            "/certificates/-/upload/confirm",
            audited(Action::CertificateUpload, certs::upload::confirm),
        )
        .route("/certificates/-/upload/cancel", post(certs::upload::cancel))
        .route(
            "/certificates/-/bulk",
            post(bulk::review::<bulk::Certificates>),
        )
        .route(
            "/certificates/-/bulk/apply",
            audited(
                Action::CertificateBulkUpdate,
                bulk::apply::<bulk::Certificates>,
            ),
        )
        .route(
            "/certificates/-/new",
            get(certs::create::form)
                .merge(audited(Action::CertificateCreate, certs::create::create)),
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
            audited(
                Action::CertificateRecover,
                lifecycle::handlers::recover::<certs::delete::Certificates>,
            ),
        )
        .route(
            "/certificates/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<certs::delete::Certificates>).merge(audited(
                Action::CertificatePurge,
                lifecycle::handlers::purge::<certs::delete::Certificates>,
            )),
        )
        .route(
            "/certificates/{name}/delete",
            get(lifecycle::handlers::delete_form::<certs::delete::Certificates>).merge(audited(
                Action::CertificateDelete,
                lifecycle::handlers::delete::<certs::delete::Certificates>,
            )),
        )
        .route(
            "/certificates/{name}",
            get(certs::detail).post(moved::post_item),
        )
        .route(
            "/certificates/{name}/details",
            get(details::form::<details::Certificates>).merge(audited(
                Action::CertificateUpdate,
                details::save::<details::Certificates>,
            )),
        )
        .route(
            "/certificates/{name}/enabled",
            audited(Action::CertificateEnabledSet, certs::toggle),
        )
        .route("/certificates/{name}/disable", get(certs::disable_form))
        .route(
            "/certificates/{name}/renewal",
            get(certs::renewal::form)
                .merge(audited(Action::CertificateRenewalSet, certs::renewal::save)),
        )
        .route(
            "/certificates/{name}/pending/cancel",
            audited(
                Action::CertificatePendingCancel,
                certs::create::cancel_pending,
            ),
        )
        .route("/certificates/{name}/cer", get(certs::download::cer))
        .route(
            "/certificates/{name}/download-key",
            get(certs::download::pfx_form).merge(audited(
                Action::CertificateDownloadPrivateKey,
                certs::download::pfx,
            )),
        )
        .route("/keys", get(keys::list))
        .route(
            "/keys/-/new",
            get(keys::edit::create_form).merge(audited(Action::KeyCreate, keys::edit::create)),
        )
        .route("/keys/-/bulk", post(bulk::review::<bulk::Keys>))
        .route(
            "/keys/-/bulk/apply",
            audited(Action::KeyBulkUpdate, bulk::apply::<bulk::Keys>),
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
            audited(
                Action::KeyRecover,
                lifecycle::handlers::recover::<keys::delete::Keys>,
            ),
        )
        .route(
            "/keys/-/deleted/{name}/purge",
            get(lifecycle::handlers::purge_form::<keys::delete::Keys>).merge(audited(
                Action::KeyPurge,
                lifecycle::handlers::purge::<keys::delete::Keys>,
            )),
        )
        .route("/keys/{name}", get(keys::detail).post(moved::post_item))
        .route(
            "/keys/{name}/details",
            get(details::form::<details::Keys>)
                .merge(audited(Action::KeyUpdate, details::save::<details::Keys>)),
        )
        .route(
            "/keys/{name}/enabled",
            audited(Action::KeyEnabledSet, keys::toggle),
        )
        .route("/keys/{name}/disable", get(keys::disable_form))
        .route(
            "/keys/{name}/rotate",
            get(keys::edit::rotate_form).merge(audited(Action::KeyRotate, keys::edit::rotate)),
        )
        .route(
            "/keys/{name}/rotation",
            get(keys::edit::rotation_form).merge(audited(
                Action::KeyRotationPolicySet,
                keys::edit::save_rotation,
            )),
        )
        .route(
            "/keys/{name}/delete",
            get(lifecycle::handlers::delete_form::<keys::delete::Keys>).merge(audited(
                Action::KeyDelete,
                lifecycle::handlers::delete::<keys::delete::Keys>,
            )),
        )
        .route("/audit", get(audit::page))
        .route("/audit.csv", get(audit::csv))
        .route("/audit/keyring", get(audit_keyring::page))
        .route("/access", get(access::page))
        .route("/access.csv", get(access::csv))
        .route("/access/review", get(access_review::page))
        .route("/access/review.csv", get(access_review::csv))
        .route("/my-access", get(pim::my_access))
        .route(
            "/my-access/shares",
            get(share::my_shares).route_layer(middleware::from_fn(share::require_on)),
        )
        .route(
            "/my-access/activate",
            get(pim::activate_form).merge(audited(Action::RoleActivate, pim::activate)),
        )
        .route(
            "/my-access/deactivate",
            audited(Action::RoleDeactivate, pim::deactivate),
        )
        .route(
            "/my-access/request",
            get(access_request::form).merge(audited(Action::AccessRequest, access_request::send)),
        )
        // A change to a vault drops the list search keeps for it.
        .route_layer(middleware::from_fn(every_vault::forget_on_change))
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
        .route("/access", get(moved::legacy))
        .route("/my-access", get(moved::legacy))
        // Across every vault. An old per-vault address is still sent on.
        .route("/audit", get(audit_across::page))
        .route("/audit.csv", get(audit_across::csv))
        .route("/expiry", get(expiry::page))
        .route("/expiry.csv", get(expiry::csv))
        .route("/expiry/age", get(age::page))
        .route("/expiry/age.csv", get(age::csv))
        .route("/vault-health", get(vault_health::page))
        .route("/vault-health.csv", get(vault_health::csv))
        .route("/defender", get(defender::page))
        .route("/defender.csv", get(defender::csv))
        .route("/reports/executive", get(reports::page))
        .route("/reports/executive/export", get(reports::export))
        .route("/environments", get(environments::page))
        .route("/environments.csv", get(environments::csv))
        .route(
            "/environments/set",
            get(environments::set_form)
                .merge(audited(Action::SecretMultiEnvSet, environments::apply))
                .layer(axum::extract::DefaultBodyLimit::max(MAX_VALUE_FORM_BYTES)),
        )
        .route("/search", get(search::page))
        .route("/generator", get(generator::page).post(generator::generate))
        .route("/auth/keepalive", get(auth::keepalive))
        // Adds "Activate" to a Key Vault RBAC 403 page when the person has
        // an eligible PIM role for it. Inside the session check.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            pim::offer_layer,
        ))
        // Inside the session check, so the error page has the signed-in shell.
        .route_layer(middleware::from_fn(rejection::layer))
        // For the reason gate and the reason fields on forms.
        .route_layer(axum::Extension(state.config.clone()))
        // For the reason gate's reveal limit check.
        .route_layer(axum::Extension(state.clone()))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_session,
        ));

    let public = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/healthz/audit", get(health::audit))
        .route("/healthz/notify", get(health::notify))
        .route("/static/{file}", get(assets::serve))
        .route("/favicon.ico", get(assets::favicon))
        .route("/auth/sign-in", get(auth::sign_in))
        .route("/auth/start", get(auth::start))
        .route("/auth/callback", get(auth::callback))
        .route(
            "/auth/sign-out",
            audited(Action::SessionSignOut, auth::sign_out),
        )
        .route("/auth/signed-out", get(auth::signed_out))
        // Event Grid's expiry events. No session: Entra token checks, its
        // own body limit and rate limit, and 404 unless `expiry` is on.
        // `tests/audit_events.rs` reads this path; keep it a literal equal
        // to `notify::expiry::HOOK_PATH` (a test checks).
        .route(
            "/hooks/eventgrid",
            any(hooks::eventgrid).layer(axum::extract::DefaultBodyLimit::max(
                crate::notify::expiry::MAX_BODY_BYTES,
            )),
        );

    protected
        .merge(public)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), flash::layer))
        .layer(middleware::from_fn_with_state(state.clone(), origin::layer))
        // Small forms only by default. The certificate upload and secrets
        // import routes set their own larger limits.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_FORM_BYTES))
        // A panic in any handler becomes a 500 page for that request
        // instead of ending the process. Inside the headers layer, so the
        // page still gets the security headers.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(panicked))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            headers::layer,
        ))
        // Outside the time limit and the origin and session checks, so a
        // request that times out or is refused still gets its audit event.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::audit::layer,
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
    #[test]
    fn the_hook_route_is_the_hook_path() {
        assert!(include_str!("mod.rs").contains(&format!(
            "\"{}\",\n            any(hooks::eventgrid)",
            crate::notify::expiry::HOOK_PATH
        )));
    }

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
