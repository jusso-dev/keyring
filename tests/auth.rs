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
            .header("origin", "http://localhost:3000")
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
    let (url, login) = h.start("%2F").await;
    let state = query(&url, "state").unwrap();
    let res = h
        .get(
            &format!("/auth/callback?error=access_denied&state={state}"),
            &[login],
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // The real reply to this sign-in, so the login cookie is cleared.
    assert!(
        set_cookies(&res)
            .iter()
            .any(|c| c.starts_with("keyring_login=;"))
    );
    assert!(body(res).await.contains("Sign-in was cancelled"));
}

#[tokio::test]
async fn forged_error_callback_does_not_cancel_the_sign_in() {
    let h = Harness::new().await;
    let (url, login) = h.start("%2F").await;
    for forged in [
        "/auth/callback?error=consent_required&state=forged",
        "/auth/callback?error=consent_required",
    ] {
        let res = h.get(forged, std::slice::from_ref(&login)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // The login cookie is left alone, so the real reply still works.
        assert!(
            set_cookies(&res)
                .iter()
                .all(|c| !c.starts_with("keyring_login=")),
            "{forged}"
        );
        let html = body(res).await;
        assert!(!html.contains("approve Keyring"), "{forged}: {html}");
        assert!(html.contains("Sign-in expired"), "{forged}");
    }
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn interaction_required_at_sign_in_means_sign_in_again() {
    // The token broker and the callback agree on what this code means.
    let (_, html) = callback_with(TokenBehaviour::Error("interaction_required")).await;
    assert!(html.contains("fresh sign-in"), "{html}");
    assert!(!html.contains("grant consent"), "{html}");
}

#[tokio::test]
async fn unknown_entra_errors_show_the_code_for_the_admin() {
    let (_, html) = callback_with(TokenBehaviour::Error("invalid_client")).await;
    assert!(
        html.contains("Entra ID gave the code invalid_client."),
        "{html}"
    );
}

#[tokio::test]
async fn rejected_id_tokens_are_not_called_slow_sign_ins() {
    for b in [TokenBehaviour::WrongAudience, TokenBehaviour::WrongNonce] {
        let (_, html) = callback_with(b.clone()).await;
        assert!(html.contains("check your sign-in"), "{b:?}: {html}");
        assert!(!html.contains("took too long"), "{b:?}");
    }
}

#[tokio::test]
async fn signing_key_rollover_is_retried_in_the_same_sign_in() {
    let h = Harness::new().await;
    // Cache discovery and keys with the first key.
    let (url, login) = h.start("%2F").await;
    let discovery_before = *h.idp.state.discovery_hits.lock().unwrap();
    // Entra rolls its keys: tokens are now signed with the second key,
    // and the published set has it.
    *h.idp.state.rolled_over.lock().unwrap() = true;
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", body(res).await);
    assert_eq!(
        *h.idp.state.discovery_hits.lock().unwrap(),
        discovery_before + 1,
        "keys were fetched again once"
    );
}

#[tokio::test]
async fn old_login_cookies_are_refused_on_the_server() {
    // A login cookie sealed eleven minutes ago, as if the browser kept it
    // past its Max-Age.
    let h = Harness::new().await;
    let (url, _) = h.start("%2F").await;
    let state = query(&url, "state").unwrap();
    let sealer = keyring::auth::crypto::Sealer::new(
        &keyring::secret::Secret::new("0123456789abcdef0123456789abcdef0123456789abcdef"),
        "login",
    );
    let pending = serde_json::json!({
        "state": state, "nonce": "n", "pkce_verifier": "v", "return_to": "/"
    });
    let eleven_minutes_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 11 * 60;
    let old = sealer.seal_at(
        "keyring_login",
        pending.to_string().as_bytes(),
        eleven_minutes_ago,
    );
    let res = h
        .get(
            &format!("/auth/callback?code=abc&state={state}"),
            &[format!("keyring_login={old}")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("Sign-in expired"));
    assert!(h.idp.state.last_token_form.lock().unwrap().is_none());
}

#[tokio::test]
async fn sign_in_page_states_the_time_limit() {
    let h = Harness::new().await;
    let html = body(h.get("/auth/sign-in", &[]).await).await;
    assert!(html.contains("signs you out after 60 minutes without activity"));
    // Signed out, so the idle script has nothing to count.
    assert!(html.contains("<body data-idle-seconds=\"\">"));
}

#[tokio::test]
async fn timed_out_post_returns_to_the_form_and_says_nothing_was_saved() {
    let h = Harness::new().await;
    let req = Request::post("/secrets/new")
        .header("origin", "http://localhost:3000")
        .header("referer", "http://localhost:3000/secrets/new?for=x")
        .header(COOKIE, "keyring_session=gone")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("csrf=x&name=db&value=hunter2"))
        .unwrap();
    let res = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let to = location(&res).to_owned();
    assert_eq!(
        to,
        "/auth/sign-in?return_to=%2Fsecrets%2Fnew%3Ffor%3Dx&reason=unsaved"
    );
    // The value is never carried across sign-in.
    assert!(!to.contains("hunter2"));
    let html = body(h.get(&to, &[]).await).await;
    assert!(html.contains("signed out before that was saved"), "{html}");

    // Signing in from there lands on the form with a flash saying so.
    let start = html
        .split("href=\"/auth/start?")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .replace("&#38;", "&")
        .replace("&amp;", "&");
    let res = h.get(&format!("/auth/start?{start}"), &[]).await;
    let url = url::Url::parse(location(&res)).unwrap();
    let login = cookie_pair(
        &set_cookies(&res)
            .into_iter()
            .find(|c| c.starts_with("keyring_login="))
            .unwrap(),
    );
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(&format!("/auth/callback?code=abc&state={state}"), &[login])
        .await;
    assert_eq!(location(&res), "/secrets/new?for=x");
    let cookies = set_cookies(&res);
    let session = cookie_pair(
        cookies
            .iter()
            .find(|c| c.starts_with("keyring_session="))
            .unwrap(),
    );
    let flash = cookie_pair(
        cookies
            .iter()
            .find(|c| c.starts_with("keyring_flash="))
            .unwrap(),
    );
    let html = body(h.get("/", &[session, flash]).await).await;
    assert!(html.contains("Nothing changed. Enter it again."), "{html}");

    // A cross-site referer is not followed.
    let req = Request::post("/secrets/new")
        .header("origin", "http://localhost:3000")
        .header("referer", "https://evil.example/phish")
        .header(COOKIE, "keyring_session=gone")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("csrf=x"))
        .unwrap();
    let res = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(location(&res), "/auth/sign-in?return_to=%2F&reason=unsaved");
}

#[tokio::test]
async fn keepalive_needs_a_session_and_is_not_cached() {
    let h = Harness::new().await;
    let res = h.get("/auth/keepalive", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (session, _) = h.sign_in("%2F").await;
    let res = h
        .get("/auth/keepalive", std::slice::from_ref(&session))
        .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    let html = body(h.get("/", &[session]).await).await;
    assert!(html.contains("<body data-idle-seconds=\"3600\">"));
}

#[tokio::test]
async fn sign_in_over_https_uses_host_prefixed_secure_cookies() {
    let idp = support::start_idp().await;
    let config = support::config_with(&idp.authority(), "https://keyring.example.com");
    let h = Harness {
        app: keyring::app(keyring::AppState::new(config)),
        idp,
    };
    let res = h.get("/auth/start?return_to=%2F", &[]).await;
    let url = url::Url::parse(location(&res)).unwrap();
    assert_eq!(
        query(&url, "redirect_uri").as_deref(),
        Some("https://keyring.example.com/auth/callback")
    );
    let login = set_cookies(&res)
        .into_iter()
        .find(|c| c.starts_with("__Host-keyring_login="))
        .expect("host-prefixed login cookie");
    assert!(
        login.contains("; Secure") && login.contains("Path=/"),
        "{login}"
    );
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();
    let res = h
        .get(
            &format!("/auth/callback?code=abc&state={state}"),
            &[cookie_pair(&login)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", body(res).await);
    let session = set_cookies(&res)
        .into_iter()
        .find(|c| c.starts_with("__Host-keyring_session="))
        .expect("host-prefixed session cookie");
    assert!(session.contains("; Secure"), "{session}");
    let res = h.get("/", &[cookie_pair(&session)]).await;
    assert_eq!(res.status(), StatusCode::OK);
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

    // Sign-out accepts the form token whichever vault the page was for.
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

#[tokio::test]
async fn crafted_error_codes_cannot_forge_log_lines() {
    let h = Harness::new().await;
    let (url, login) = h.start("%2F").await;
    let state = query(&url, "state").unwrap();
    let res = h
        .get(
            &format!(
                "/auth/callback?error=x%0A2026-11-09T00:00:00Z%20WARN%20secret%20purged&state={state}"
            ),
            &[login],
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        keyring::auth::oidc::safe_code("access_denied"),
        "access_denied"
    );
    assert_eq!(
        keyring::auth::oidc::safe_code("x\nWARN fake"),
        "unrecognised"
    );
    assert_eq!(keyring::auth::oidc::safe_code(""), "unrecognised");
}

/// An `Oidc` against the mock with short cache timings.
fn oidc(idp: &MockIdp, ttl_ms: u64, retry_ms: u64) -> keyring::auth::oidc::Oidc {
    let config = support::config_with(&idp.authority(), "http://localhost:3000");
    keyring::auth::oidc::Oidc::new(&config, keyring::http::client(false).unwrap())
        .with_metadata_timings(
            std::time::Duration::from_millis(ttl_ms),
            std::time::Duration::from_millis(retry_ms),
        )
}

fn hits(idp: &MockIdp) -> usize {
    *idp.state.discovery_hits.lock().unwrap()
}

#[tokio::test]
async fn discovery_is_cached_then_refetched_after_its_ttl() {
    let idp = support::start_idp().await;
    let o = oidc(&idp, 300, 50);
    o.begin("/".into(), false, None).await.unwrap();
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 1);
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 2);
    o.forget_metadata().await;
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 3);
}

#[tokio::test]
async fn concurrent_sign_ins_share_one_discovery_fetch() {
    let idp = support::start_idp().await;
    let o = std::sync::Arc::new(oidc(&idp, 60_000, 50));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let o = o.clone();
            tokio::spawn(async move { o.begin("/".into(), false, None).await.map(|_| ()) })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(hits(&idp), 1);
}

#[tokio::test]
async fn a_failed_refresh_keeps_the_old_document_and_backs_off() {
    let idp = support::start_idp().await;
    let o = oidc(&idp, 100, 60_000);
    o.begin("/".into(), false, None).await.unwrap();
    *idp.state.discovery_down.lock().unwrap() = true;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    // Past the TTL with discovery down: the old document still works.
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 2);
    // And for a while no more fetches are tried.
    o.begin("/".into(), false, None).await.unwrap();
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 2);
}

#[tokio::test]
async fn with_no_document_a_failed_fetch_backs_off() {
    let idp = support::start_idp().await;
    *idp.state.discovery_down.lock().unwrap() = true;
    let o = oidc(&idp, 60_000, 200);
    assert!(o.begin("/".into(), false, None).await.is_err());
    assert!(o.begin("/".into(), false, None).await.is_err());
    assert_eq!(hits(&idp), 1, "no second fetch during the back-off");
    *idp.state.discovery_down.lock().unwrap() = false;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    o.begin("/".into(), false, None).await.unwrap();
    assert_eq!(hits(&idp), 2);
}

#[tokio::test]
async fn a_form_rendered_for_one_vault_is_refused_after_switching() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    // The delete form is rendered while kv-test is chosen.
    let (_, html) = w.page("/secrets/db-password/delete").await;
    let form_token = support::hidden_value(&html, "csrf").unwrap();
    assert!(form_token.starts_with("kv-test."));

    // Another tab switches to kv-other. The switch form accepts a token
    // from any vault.
    let res = w.post("/vaults/select", &[("name", "kv-other")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    // The first tab's form is posted with the right name typed.
    let mut w = w;
    w.csrf = form_token;
    let res = w
        .post(
            "/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(support::body_text(res).await.contains("switched vaults"));
    assert!(
        w.kv.state.current("db-password").is_some(),
        "nothing deleted"
    );

    // A form rendered for kv-other works.
    let (_, html) = w.page("/secrets/db-password/delete").await;
    w.csrf = support::hidden_value(&html, "csrf").unwrap();
    assert!(w.csrf.starts_with("kv-other."));
    let res = w
        .post(
            "/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn forms_using_the_shared_check_name_the_vault_they_were_for() {
    let mut w = support::world().await;
    let (_, html) = w.page("/keys/new").await;
    let form_token = support::hidden_value(&html, "csrf").unwrap();
    w.post("/vaults/select", &[("name", "kv-other")]).await;
    w.csrf = form_token;
    let res = w.post("/keys/new", &[("name", "k1"), ("kty", "RSA")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = support::body_text(res).await;
    assert!(html.contains("This page was for kv-test"), "{html}");
    assert!(w.kv.state.keys.lock().unwrap().is_empty());
}

#[tokio::test]
async fn signed_in_person_is_known_by_object_and_tenant_id() {
    let idp = support::start_idp().await;
    let config = support::config_with(&idp.authority(), "http://localhost:3000");
    let state = keyring::AppState::new(config);
    let h = Harness {
        app: keyring::app(state.clone()),
        idp,
    };
    let (session, _) = h.sign_in("%2F").await;
    let id = session.split('=').nth(1).unwrap();
    let user = state.sessions.get(id).unwrap().user.subject.clone();
    assert_eq!(user.sub, "user-subject");
    assert_eq!(user.oid.as_deref(), Some(support::USER_OID));
    assert_eq!(user.tid.as_deref(), Some(support::TENANT));
    assert_eq!(
        user.to_string(),
        format!("oid:{},tid:{}", support::USER_OID, support::TENANT)
    );
}
