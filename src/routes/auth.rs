//! Sign-in, callback and sign-out pages.

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::entra::EntraAdvice;
use crate::auth::oidc::{PendingLogin, SignInError};
use crate::auth::session::{ABSOLUTE_TIMEOUT, IDLE_TIMEOUT};
use crate::auth::{CurrentSession, LOGIN_COOKIE, SESSION_COOKIE, cookies, crypto, return_to};
use crate::routes::assets::render;
use crate::routes::error::{PageError, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::shell::Shell;

/// How long someone has to finish signing in at Entra.
const LOGIN_COOKIE_SECS: u64 = 10 * 60;

#[derive(Template)]
#[template(path = "auth/sign_in.html")]
struct SignInPage {
    shell: Shell,
    start_url: String,
    expired: bool,
    /// Signed out before a form was saved.
    unsaved: bool,
    /// Minutes without a request before Keyring signs someone out.
    idle_minutes: u64,
    /// Hours after sign-in before Keyring signs someone out regardless.
    absolute_hours: u64,
}

#[derive(Template)]
#[template(path = "auth/problem.html")]
struct ProblemPage {
    shell: Shell,
    heading: &'static str,
    message: &'static str,
    /// For an admin, such as the Entra error code. Never Entra's own text.
    detail: Option<String>,
    retry_url: String,
}

#[derive(Template)]
#[template(path = "auth/signed_out.html")]
struct SignedOutPage {
    shell: Shell,
}

#[derive(Deserialize)]
pub struct SignInQuery {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// `reason` values the session guard sends to the sign-in page.
pub const REASON_EXPIRED: &str = "expired";
/// Signed out, and the form being posted was not saved.
pub const REASON_UNSAVED: &str = "unsaved";

pub async fn sign_in(Query(q): Query<SignInQuery>) -> Response {
    let return_to = return_to::sanitise(q.return_to.as_deref());
    let unsaved = q.reason.as_deref() == Some(REASON_UNSAVED);
    let mut start_url = format!("/auth/start?return_to={}", return_to::encode(&return_to));
    if unsaved {
        start_url.push_str("&reason=");
        start_url.push_str(REASON_UNSAVED);
    }
    let page = SignInPage {
        shell: Shell::anonymous(),
        start_url,
        expired: unsaved || q.reason.as_deref() == Some(REASON_EXPIRED),
        unsaved,
        idle_minutes: IDLE_TIMEOUT.as_secs() / 60,
        absolute_hours: ABSOLUTE_TIMEOUT.as_secs() / 3600,
    };
    no_store(render(&page).into_response())
}

#[derive(Deserialize)]
pub struct StartQuery {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Send the browser to Entra ID, keeping state, nonce and the PKCE verifier
/// in a short-lived encrypted cookie.
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> Response {
    let return_to = return_to::sanitise(q.return_to.as_deref());
    // A claims challenge from this browser's current session, if any. It
    // comes from Entra, never from the request.
    let claims = cookies::get(&headers, &state.cookies.name(SESSION_COOKIE))
        .and_then(|id| state.sessions.get(id))
        .and_then(|s| s.claims_challenge());
    let unsaved = q.reason.as_deref() == Some(REASON_UNSAVED);
    match state.oidc.begin(return_to.clone(), unsaved, claims).await {
        Ok((url, pending)) => {
            let name = state.cookies.name(LOGIN_COOKIE);
            let json = serde_json::to_vec(&pending).expect("pending login serialises");
            let sealed = state.sealer.seal(&name, &json);
            let mut res = Redirect::to(&url).into_response();
            append_cookie(
                &mut res,
                &state.cookies.set(&name, &sealed, Some(LOGIN_COOKIE_SECS)),
            );
            no_store(res)
        }
        Err(err) => {
            tracing::warn!(error = ?err.to_string(), "could not start sign-in");
            problem(
                StatusCode::BAD_GATEWAY,
                "Can't reach Microsoft sign-in",
                "Keyring couldn't reach Entra ID to sign you in. Wait a minute and try again. If it keeps happening, ask your admin to check Keyring's settings.",
                None,
                &return_to,
            )
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let login_name = state.cookies.name(LOGIN_COOKIE);
    let pending: Option<PendingLogin> = cookies::get(&headers, &login_name)
        .and_then(|v| state.sealer.open(&login_name, v))
        .and_then(|raw| serde_json::from_slice(&raw).ok());

    // The returned `state` must match before anything else is believed,
    // errors included: Entra sends `state` back with errors too, and a
    // cross-site link to `?error=...` must not cancel a sign-in under way.
    let pending = match pending {
        None => Err(SignInError::Stale(
            "missing, old or unreadable login cookie".into(),
        )),
        Some(p)
            if q.state.as_deref().is_some_and(|returned| {
                crypto::constant_time_eq(p.state.as_bytes(), returned.as_bytes())
            }) =>
        {
            Ok(p)
        }
        Some(_) => Err(SignInError::Stale("state missing or mismatched".into())),
    };
    let result = match (pending, q.error, q.code) {
        (Err(e), ..) => Err(e),
        (Ok(_), Some(code), _) => Err(SignInError::Provider {
            code: crate::auth::oidc::safe_code(&code),
            codes: Vec::new(),
        }),
        (Ok(p), None, Some(code)) => {
            let (return_to, unsaved) = (p.return_to.clone(), p.unsaved);
            state
                .oidc
                .finish(p, code)
                .await
                .map(|ok| (ok, return_to, unsaved))
        }
        (Ok(_), None, None) => Err(SignInError::Stale("no code returned".into())),
    };
    // A forged callback must not cancel the sign-in in progress, so keep
    // the login cookie unless this callback really was the reply to it.
    let consumed = !matches!(result, Err(SignInError::Stale(_)));

    let mut res = match result {
        Ok(((user, tokens), return_to, unsaved)) => {
            let session_name = state.cookies.name(SESSION_COOKIE);
            // Fresh ID every sign-in, and drop any old session.
            if let Some(old) = cookies::get(&headers, &session_name) {
                state.sessions.remove(old);
            }
            tracing::info!(subject = %user.subject, "signed in");
            let id = state.sessions.create(user, tokens);
            let mut res = Redirect::to(&return_to).into_response();
            append_cookie(&mut res, &state.cookies.set(&session_name, &id, None));
            if unsaved {
                flash::set(
                    &state,
                    &mut res,
                    &Flash::error(
                        "You were signed out before that was saved. Nothing changed. Enter it again.",
                    ),
                );
            }
            res
        }
        Err(err) => {
            tracing::warn!(error = ?err.to_string(), "sign-in failed");
            let (heading, message, detail) = describe(&err);
            problem(StatusCode::BAD_REQUEST, heading, message, detail, "/")
        }
    };
    if consumed {
        append_cookie(&mut res, &state.cookies.clear(&login_name));
    }
    no_store(res)
}

#[derive(Deserialize)]
pub struct SignOutForm {
    #[serde(default)]
    csrf: String,
}

/// Sign out: forget the session here, then sign out of Entra ID too.
pub async fn sign_out(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignOutForm>,
) -> Response {
    let session_name = state.cookies.name(SESSION_COOKIE);
    let Some(id) = cookies::get(&headers, &session_name) else {
        return Redirect::to("/auth/signed-out").into_response();
    };
    match state.sessions.get(id) {
        // Sign-out doesn't act on a vault, so a form from any vault will do.
        Some(s) if !s.csrf_matches_any(&form.csrf) => {
            return PageError::new(Shell::anonymous(), Problem::stale_form()).into_response();
        }
        _ => {}
    }
    state.sessions.remove(id);
    let target = state
        .oidc
        .end_session_url()
        .await
        .unwrap_or_else(|| "/auth/signed-out".to_owned());
    let mut res = Redirect::to(&target).into_response();
    append_cookie(&mut res, &state.cookies.clear(&session_name));
    no_store(res)
}

/// Keep the session alive. The idle-warning script calls this when the
/// person chooses to stay signed in. Behind the session guard, which marks
/// the session as used.
pub async fn keepalive(_session: CurrentSession) -> Response {
    no_store(StatusCode::NO_CONTENT.into_response())
}

pub async fn signed_out() -> Response {
    no_store(
        render(&SignedOutPage {
            shell: Shell::anonymous(),
        })
        .into_response(),
    )
}

fn describe(err: &SignInError) -> (&'static str, &'static str, Option<String>) {
    match (err, err.advice()) {
        (_, Some(EntraAdvice::Cancelled)) => (
            "Sign-in was cancelled",
            "You didn't finish signing in. Try again when you're ready.",
            None,
        ),
        (_, Some(EntraAdvice::ConsentNeeded)) => (
            "Your organisation needs to approve Keyring",
            "Keyring needs permission to act on your behalf. Ask your admin to grant consent for the Keyring app in Entra ID, then try again.",
            None,
        ),
        (_, Some(EntraAdvice::SignInAgain)) => (
            "Microsoft sign-in needs another try",
            "Entra ID asked for a fresh sign-in, for example to check a second factor. Start again from the sign-in page.",
            None,
        ),
        (_, Some(EntraAdvice::Configuration { code })) => (
            "Microsoft sign-in didn't finish",
            "Entra ID stopped the sign-in. Try again. If it keeps happening, ask your admin to check the Keyring app registration.",
            Some(format!("Entra ID gave the code {code}.")),
        ),
        (SignInError::Unreachable(_), None) => (
            "Can't reach Microsoft sign-in",
            "Keyring couldn't finish signing you in because Entra ID didn't answer. Wait a minute and try again.",
            None,
        ),
        (SignInError::Rejected(_), None) => (
            "Keyring couldn't check your sign-in",
            "Entra ID's answer didn't pass Keyring's checks, so you aren't signed in. Try again. If it keeps happening, ask your admin to check Keyring's Entra ID settings (tenant ID and client ID).",
            None,
        ),
        (SignInError::Stale(_) | SignInError::Provider { .. }, None) => (
            "Sign-in expired",
            "Your sign-in took too long or was started in another tab. Start again from the sign-in page.",
            None,
        ),
    }
}

fn problem(
    status: StatusCode,
    heading: &'static str,
    message: &'static str,
    detail: Option<String>,
    return_to: &str,
) -> Response {
    let page = ProblemPage {
        shell: Shell::anonymous(),
        heading,
        message,
        detail,
        retry_url: format!("/auth/sign-in?return_to={}", return_to::encode(return_to)),
    };
    no_store((status, render(&page)).into_response())
}

fn append_cookie(res: &mut Response, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        res.headers_mut().append(SET_COOKIE, v);
    }
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}
