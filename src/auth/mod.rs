//! Sign-in with Entra ID and session handling.

pub mod assertion;
pub mod cookies;
pub mod crypto;
pub mod entra;
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

    // A GET goes back where it was going. A form post is never replayed:
    // it goes back to the form's own page (from a same-origin `Referer`),
    // and the sign-in page says nothing was saved.
    let is_get = req.method() == Method::GET;
    let return_to = if is_get {
        req.uri().path_and_query().map(|pq| pq.as_str().to_owned())
    } else {
        referer_path(req.headers(), &state.config.base_url)
    };
    let return_to = return_to::sanitise(return_to.as_deref());
    let mut target = format!("/auth/sign-in?return_to={}", return_to::encode(&return_to));
    match (is_get, id.is_some()) {
        (false, true) => target.push_str("&reason=unsaved"),
        (true, true) => target.push_str("&reason=expired"),
        // No session cookie at all: nobody was signed out.
        (_, false) => {}
    }
    let mut res = Redirect::to(&target).into_response();
    if id.is_some()
        && let Ok(v) = state.cookies.clear(&cookie_name).parse()
    {
        res.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    res
}

/// The local path and query of a same-origin `Referer`, if there is one.
fn referer_path(headers: &axum::http::HeaderMap, base_url: &str) -> Option<String> {
    let referer = headers.get(axum::http::header::REFERER)?.to_str().ok()?;
    let rest = referer.strip_prefix(base_url)?;
    // `https://keyring.example.com.evil` must not count as this site.
    rest.starts_with('/')
        .then(|| rest.split('#').next().unwrap_or(rest).to_owned())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header::REFERER};

    use super::*;

    fn with(referer: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(REFERER, HeaderValue::from_static(referer));
        h
    }

    #[test]
    fn referer_must_be_this_site() {
        let base = "https://keyring.example.com";
        assert_eq!(
            referer_path(&with("https://keyring.example.com/secrets/new?x=1#f"), base).as_deref(),
            Some("/secrets/new?x=1")
        );
        assert_eq!(
            referer_path(&with("https://keyring.example.com.evil/secrets"), base),
            None
        );
        assert_eq!(referer_path(&with("https://evil.example/"), base), None);
        assert_eq!(referer_path(&HeaderMap::new(), base), None);
    }
}
