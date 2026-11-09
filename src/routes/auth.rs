//! Sign-in, callback and sign-out pages.

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::oidc::{PendingLogin, SignInError};
use crate::auth::{LOGIN_COOKIE, SESSION_COOKIE, cookies, crypto, return_to};
use crate::routes::assets::render;
use crate::routes::shell::Shell;

/// How long someone has to finish signing in at Entra.
const LOGIN_COOKIE_SECS: u64 = 10 * 60;

#[derive(Template)]
#[template(path = "auth/sign_in.html")]
struct SignInPage {
    shell: Shell,
    start_url: String,
    expired: bool,
}

#[derive(Template)]
#[template(path = "auth/problem.html")]
struct ProblemPage {
    shell: Shell,
    heading: &'static str,
    message: &'static str,
    retry_url: String,
}

#[derive(Template)]
#[template(path = "auth/signed_out.html")]
struct SignedOutPage {
    shell: Shell,
}

#[derive(Deserialize)]
pub struct SignInQuery {
    return_to: Option<String>,
    reason: Option<String>,
}

pub async fn sign_in(Query(q): Query<SignInQuery>) -> Response {
    let return_to = return_to::sanitise(q.return_to.as_deref());
    let page = SignInPage {
        shell: Shell::anonymous(),
        start_url: format!("/auth/start?return_to={}", return_to::encode(&return_to)),
        expired: q.reason.as_deref() == Some("expired"),
    };
    no_store(render(&page).into_response())
}

#[derive(Deserialize)]
pub struct StartQuery {
    return_to: Option<String>,
}

/// Send the browser to Entra ID, keeping state, nonce and the PKCE verifier
/// in a short-lived encrypted cookie.
pub async fn start(State(state): State<AppState>, Query(q): Query<StartQuery>) -> Response {
    let return_to = return_to::sanitise(q.return_to.as_deref());
    match state.oidc.begin(return_to.clone()).await {
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
            tracing::warn!(error = %err, "could not start sign-in");
            problem(
                StatusCode::BAD_GATEWAY,
                "Can't reach Microsoft sign-in",
                "Keyring couldn't reach Entra ID to sign you in. Wait a minute and try again. If it keeps happening, ask your admin to check Keyring's settings.",
                &return_to,
            )
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
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

    let result = match (pending, q.error, q.code, q.state) {
        (None, ..) => Err(SignInError::Invalid(
            "missing or unreadable login cookie".into(),
        )),
        (Some(_), Some(code), ..) => Err(SignInError::Provider { code }),
        (Some(p), None, Some(code), Some(returned_state))
            if crypto::constant_time_eq(p.state.as_bytes(), returned_state.as_bytes()) =>
        {
            let return_to = p.return_to.clone();
            state.oidc.finish(p, code).await.map(|ok| (ok, return_to))
        }
        (Some(_), None, _, _) => Err(SignInError::Invalid("state missing or mismatched".into())),
    };

    let mut res = match result {
        Ok(((user, tokens), return_to)) => {
            let session_name = state.cookies.name(SESSION_COOKIE);
            // Fresh ID every sign-in, and drop any old session.
            if let Some(old) = cookies::get(&headers, &session_name) {
                state.sessions.remove(old);
            }
            tracing::info!(subject = %user.subject, "signed in");
            let id = state.sessions.create(user, tokens);
            let mut res = Redirect::to(&return_to).into_response();
            append_cookie(&mut res, &state.cookies.set(&session_name, &id, None));
            res
        }
        Err(err) => {
            tracing::warn!(error = %err, "sign-in failed");
            let (heading, message) = describe(&err);
            problem(StatusCode::BAD_REQUEST, heading, message, "/")
        }
    };
    append_cookie(&mut res, &state.cookies.clear(&login_name));
    no_store(res)
}

#[derive(Deserialize)]
pub struct SignOutForm {
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
        Some(s) if !s.csrf_matches(&form.csrf) => {
            return problem(
                StatusCode::FORBIDDEN,
                "That didn't work",
                "The page was out of date. Go back, refresh and try again.",
                "/",
            );
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

pub async fn signed_out() -> Response {
    no_store(
        render(&SignedOutPage {
            shell: Shell::anonymous(),
        })
        .into_response(),
    )
}

fn describe(err: &SignInError) -> (&'static str, &'static str) {
    match err {
        SignInError::Provider { code } if code == "access_denied" => (
            "Sign-in was cancelled",
            "You didn't finish signing in. Try again when you're ready.",
        ),
        SignInError::Provider { code }
            if code == "consent_required" || code == "interaction_required" =>
        {
            (
                "Your organisation needs to approve Keyring",
                "Keyring needs permission to act on your behalf. Ask your admin to grant consent for the Keyring app in Entra ID, then try again.",
            )
        }
        SignInError::Provider { .. } => (
            "Microsoft sign-in didn't finish",
            "Entra ID stopped the sign-in. Try again. If it keeps happening, ask your admin to check the Keyring app registration.",
        ),
        SignInError::Unreachable(_) => (
            "Can't reach Microsoft sign-in",
            "Keyring couldn't finish signing you in because Entra ID didn't answer. Wait a minute and try again.",
        ),
        SignInError::Invalid(_) => (
            "Sign-in expired",
            "Your sign-in took too long or was started in another tab. Start again from the sign-in page.",
        ),
    }
}

fn problem(
    status: StatusCode,
    heading: &'static str,
    message: &'static str,
    return_to: &str,
) -> Response {
    let page = ProblemPage {
        shell: Shell::anonymous(),
        heading,
        message,
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
