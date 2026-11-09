//! Sign-in with Entra ID and session handling.

pub mod cookies;
pub mod crypto;
pub mod oidc;
pub mod return_to;
pub mod session;

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::auth::session::Session;

/// Base name of the session cookie. Gets the `__Host-` prefix over HTTPS.
pub const SESSION_COOKIE: &str = "keyring_session";
/// Base name of the short-lived cookie that carries sign-in state.
pub const LOGIN_COOKIE: &str = "keyring_login";

/// The signed-in session for this request. Only available on routes behind
/// [`require_session`].
#[derive(Clone)]
pub struct CurrentSession(pub Arc<Session>);

impl<S: Send + Sync> FromRequestParts<S> for CurrentSession {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CurrentSession>()
            .cloned()
            // Reaching here means a route was registered outside the guard.
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Middleware for every route except sign-in, health and static files.
/// Sends anyone without a live session to sign in, remembering where they
/// were going.
pub async fn require_session(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let cookie_name = state.cookies.name(SESSION_COOKIE);
    let id = cookies::get(req.headers(), &cookie_name).map(str::to_owned);
    if let Some(session) = id.as_deref().and_then(|id| state.sessions.get(id)) {
        req.extensions_mut().insert(CurrentSession(session));
        return next.run(req).await;
    }

    // Only remember GET destinations; replaying a form post after sign-in
    // would be surprising.
    let return_to = if req.method() == Method::GET {
        req.uri().path_and_query().map(|pq| pq.as_str().to_owned())
    } else {
        None
    };
    let return_to = return_to::sanitise(return_to.as_deref());
    let mut target = format!("/auth/sign-in?return_to={}", return_to::encode(&return_to));
    if id.is_some() {
        target.push_str("&reason=expired");
    }
    let mut res = Redirect::to(&target).into_response();
    if id.is_some()
        && let Ok(v) = state.cookies.clear(&cookie_name).parse()
    {
        res.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    res
}
