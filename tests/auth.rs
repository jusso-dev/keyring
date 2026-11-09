//! Sign-in flow against a mock Entra ID.

mod support;

use axum::Router;
use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use support::{MockIdp, TokenBehaviour};
use tower::ServiceExt;

struct Harness {
    app: Router,
    idp: MockIdp,
}

impl Harness {
    async fn new() -> Self {
        let idp = support::start_idp().await;
        let config = support::config_with(&idp.authority(), "http://localhost:3000");
        let app = keyring::app(keyring::AppState::new(config));
        Self { app, idp }
    }

    async fn get(&self, path: &str, cookies: &[String]) -> Response<Body> {
        let mut req = Request::get(path);
        if !cookies.is_empty() {
            req = req.header(COOKIE, cookies.join("; "));
        }
        self.app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn post(&self, path: &str, cookies: &[String], form: &str) -> Response<Body> {
        let req = Request::post(path)
            .header(COOKIE, cookies.join("; "))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// Run `/auth/start`, returning the Entra URL and the login cookie.
    async fn start(&self, return_to: &str) -> (url::Url, String) {
        let res = self
            .get(&format!("/auth/start?return_to={return_to}"), &[])
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = url::Url::parse(location(&res)).unwrap();
        let cookie = set_cookies(&res)
            .into_iter()
            .find(|c| c.starts_with("keyring_login="))
            .expect("login cookie");
        (location, cookie_pair(&cookie))
    }

    /// Full sign-in. Returns the session cookie pair and the final redirect.
    async fn sign_in(&self, return_to: &str) -> (String, String) {
        let (url, login) = self.start(return_to).await;
        let nonce = query(&url, "nonce").unwrap();
        *self.idp.state.nonce.lock().unwrap() = Some(nonce);
        let state = query(&url, "state").unwrap();
        let res = self
            .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", body(res).await);
        let session = set_cookies(&res)
            .into_iter()
            .find(|c| c.starts_with("keyring_session="))
            .expect("session cookie");
        (cookie_pair(&session), location(&res).to_owned())
    }
}

fn location(res: &Response<Body>) -> &str {
    res.headers().get(LOCATION).unwrap().to_str().unwrap()
}

fn set_cookies(res: &Response<Body>) -> Vec<String> {
    res.headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

async fn body(res: Response<Body>) -> String {
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn unauthenticated_requests_redirect_to_sign_in() {
    let h = Harness::new().await;
    let res = h.get("/?tab=secrets", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&res),
        "/auth/sign-in?return_to=%2F%3Ftab%3Dsecrets"
    );
}

#[tokio::test]
async fn start_uses_pkce_state_nonce_and_requests_api_scope() {
    let h = Harness::new().await;
    let (url, cookie) = h.start("%2F").await;
    assert_eq!(url.path(), "/authorize");
    assert_eq!(
        query(&url, "client_id").as_deref(),
        Some(support::CLIENT_ID)
    );
    assert_eq!(
        query(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(query(&url, "code_challenge").is_some());
    assert!(query(&url, "state").is_some());
    assert!(query(&url, "nonce").is_some());
    assert_eq!(
        query(&url, "redirect_uri").as_deref(),
        Some("http://localhost:3000/auth/callback")
    );
    let scope = query(&url, "scope").unwrap();
    assert!(scope.contains("openid"));
    assert!(scope.contains(&format!("api://{}/access_as_user", support::CLIENT_ID)));
    // The login cookie is encrypted: no state or verifier in the clear.
    assert!(!cookie.contains(&query(&url, "state").unwrap()));
}

#[tokio::test]
async fn full_sign_in_lands_on_requested_page_and_shows_name() {
    let h = Harness::new().await;
    let (session, landed) = h.sign_in("%2F%3Ftab%3Dsecrets").await;
    assert_eq!(landed, "/?tab=secrets");

    // The token request carried the PKCE verifier and the client secret.
    let form = h.idp.state.last_token_form.lock().unwrap().clone().unwrap();
    assert!(form.iter().any(|(k, _)| k == "code_verifier"));
    assert!(
        form.iter()
            .any(|(k, v)| k == "client_secret" && v == support::CLIENT_SECRET)
    );

    let res = h.get("/", &[session]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("Alex Example"));
    assert!(html.contains("Sign out"));
    // Tokens never reach the browser.
    assert!(!html.contains("user-access-token-for-keyring-api"));
    assert!(!html.contains("user-refresh-token"));
}

#[tokio::test]
async fn session_cookie_holds_only_a_random_id() {
    let h = Harness::new().await;
    let (url, login) = h.start("%2F").await;
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
        .await;
    for c in set_cookies(&res) {
        assert!(!c.contains("user-access-token"), "{c}");
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Lax"), "{c}");
    }
}

#[tokio::test]
async fn open_redirects_are_blocked() {
    let h = Harness::new().await;
    let (_, landed) = h.sign_in("https%3A%2F%2Fevil.example").await;
    assert_eq!(landed, "/");
    let (_, landed) = h.sign_in("%2F%2Fevil.example").await;
    assert_eq!(landed, "/");
}

#[tokio::test]
async fn callback_rejects_wrong_state() {
    let h = Harness::new().await;
    let (url, login) = h.start("%2F").await;
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let res = h
        .get("/auth/callback?code=abc&state=forged", &[login])
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        set_cookies(&res)
            .iter()
            .all(|c| !c.starts_with("keyring_session="))
    );
    // The token endpoint was never called.
    assert!(h.idp.state.last_token_form.lock().unwrap().is_none());
}

#[tokio::test]
async fn callback_rejects_missing_login_cookie() {
    let h = Harness::new().await;
    let (url, _) = h.start("%2F").await;
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[])
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("Sign-in expired"));
}

#[tokio::test]
async fn callback_rejects_tampered_login_cookie() {
    let h = Harness::new().await;
    let (url, login) = h.start("%2F").await;
    let state = query(&url, "state").unwrap();
    let tampered = format!("{}x", login);
    let res = h
        .get(
            &format!("/auth/callback?code=abc&state={state}"),
            &[tampered],
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

async fn callback_with(behaviour: TokenBehaviour) -> (StatusCode, String) {
    let h = Harness::new().await;
    *h.idp.state.behaviour.lock().unwrap() = behaviour;
    let (url, login) = h.start("%2F").await;
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
        .await;
    assert!(
        set_cookies(&res)
            .iter()
            .all(|c| !c.starts_with("keyring_session="))
    );
    (res.status(), body(res).await)
}

#[tokio::test]
async fn callback_rejects_wrong_nonce() {
    let (status, _) = callback_with(TokenBehaviour::WrongNonce).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_rejects_bad_signature() {
    let (status, _) = callback_with(TokenBehaviour::WrongKey).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_rejects_wrong_audience() {
    let (status, _) = callback_with(TokenBehaviour::WrongAudience).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_errors_explain_what_to_ask_for() {
    let (status, html) = callback_with(TokenBehaviour::Error("consent_required")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(html.contains("Ask your admin to grant consent"));
}

#[tokio::test]
async fn cancelled_sign_in_is_explained() {
    let h = Harness::new().await;
    let (_, login) = h.start("%2F").await;
    let res = h
        .get("/auth/callback?error=access_denied&state=x", &[login])
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("Sign-in was cancelled"));
}

#[tokio::test]
async fn unknown_session_sends_back_with_expired_message() {
    let h = Harness::new().await;
    let res = h.get("/", &["keyring_session=gone".to_owned()]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(location(&res).ends_with("&reason=expired"));
    assert!(set_cookies(&res).iter().any(|c| c.contains("Max-Age=0")));
    let res = h.get(location(&res), &[]).await;
    assert!(body(res).await.contains("You were signed out"));
}

#[tokio::test]
async fn sign_out_needs_csrf_clears_session_and_calls_entra() {
    let h = Harness::new().await;
    let (session, _) = h.sign_in("%2F").await;

    // Without the form token, sign-out is refused and the session survives.
    let res = h
        .post(
            "/auth/sign-out",
            std::slice::from_ref(&session),
            "csrf=wrong",
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        h.get("/", std::slice::from_ref(&session)).await.status(),
        StatusCode::OK
    );

    let html = body(h.get("/", std::slice::from_ref(&session)).await).await;
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_owned();
    let res = h
        .post(
            "/auth/sign-out",
            std::slice::from_ref(&session),
            &format!("csrf={csrf}"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let target = url::Url::parse(location(&res)).unwrap();
    assert_eq!(target.path(), "/logout");
    assert_eq!(
        query(&target, "post_logout_redirect_uri").as_deref(),
        Some("http://localhost:3000/auth/signed-out")
    );
    assert!(
        set_cookies(&res)
            .iter()
            .any(|c| c.starts_with("keyring_session=;"))
    );

    // The old cookie no longer works.
    let res = h.get("/", &[session]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}
