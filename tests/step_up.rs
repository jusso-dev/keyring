//! Step-up before a sensitive action (`KEYRING_STEP_UP_AUTH_CONTEXT`,
//! `KEYRING_STEP_UP_MAX_AGE`), against a mock Entra that issues ID tokens
//! with or without `acrs` and `auth_time`.

mod support;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use keyring::auth::step_up::{SignInFacts, unix};
use support::{World, body_text, location};
use tower::ServiceExt;

const CONTEXT: (&str, &str) = ("KEYRING_STEP_UP_AUTH_CONTEXT", "c1");
const MAX_AGE: (&str, &str) = ("KEYRING_STEP_UP_MAX_AGE", "15");

fn session(w: &World) -> std::sync::Arc<keyring::auth::session::Session> {
    let id = w.cookie.split('=').nth(1).unwrap();
    w.state.sessions.get(id).unwrap()
}

fn met(w: &World, acrs: &[&str], auth_time: Option<i64>) {
    session(w).set_sign_in_facts(SignInFacts {
        acrs: acrs.iter().map(|s| (*s).to_owned()).collect(),
        auth_time,
    });
}

fn now() -> i64 {
    unix(SystemTime::now())
}

async fn seeded(extra: &[(&'static str, &'static str)]) -> (World, String, String) {
    let mut env = vec![("KEYRING_ALLOW_PURGE", "true")];
    env.extend_from_slice(extra);
    let w = support::world_with(&env).await;
    let old = w.kv.state.put("db-password", "first-value");
    let current = w.kv.state.put("db-password", "second-value");
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.put("gone", "x");
    w.kv.state.soft_delete("gone");
    (w, old, current)
}

/// Undo Askama's HTML escaping.
fn unescape(html: &str) -> String {
    html.replace("&#39;", "'")
        .replace("&#38;", "&")
        .replace("&#x2f;", "/")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// The step-up page: its link to `/auth/start`, decoded.
fn start_link(html: &str) -> String {
    let html = unescape(html);
    let at = html.find("/auth/start?").expect("link to /auth/start");
    let end = at + html[at..].find('"').unwrap();
    html[at..end].to_owned()
}

fn query(url: &str, key: &str) -> Option<String> {
    url::Url::parse(&format!("http://x{url}"))
        .or_else(|_| url::Url::parse(url))
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
async fn with_the_settings_off_nothing_changes() {
    let (w, _, _) = seeded(&[]).await;
    // No acrs, no auth_time: the default session from before.
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("second-value"));
    let (status, _) = w.page("/v/kv-test/certificates/web-tls/download-key").await;
    assert_eq!(status, StatusCode::OK);
    // /auth/start with reason=step_up and nothing configured asks for no
    // claims.
    let res = w
        .get("/auth/start?return_to=%2Fv%2Fkv-test%2Fsecrets&reason=step_up")
        .await;
    let entra = location(&res);
    assert_eq!(query(&entra, "claims"), None);
    assert_eq!(query(&entra, "prompt"), None);
    assert_eq!(query(&entra, "max_age"), None);
}

#[tokio::test]
async fn a_session_that_meets_the_settings_goes_ahead() {
    let (w, _, _) = seeded(&[CONTEXT, MAX_AGE]).await;
    met(&w, &["c1"], Some(now() - 60));
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("second-value"));
}

#[tokio::test]
async fn without_the_context_every_sensitive_action_asks_first() {
    let (w, old, _) = seeded(&[CONTEXT]).await;
    met(&w, &[], Some(now()));
    let reads = w.kv.state.value_reads().len();
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], String);
    let cases: [Case; 4] = [
        (
            "/v/kv-test/secrets/db-password/reveal",
            &[],
            "/v/kv-test/secrets/db-password".into(),
        ),
        (
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
            "/v/kv-test/certificates/web-tls/download-key".into(),
        ),
        (
            "/v/kv-test/secrets/db-password/rollback",
            &[("version", old.as_str())],
            format!("/v/kv-test/secrets/db-password/rollback?version={old}"),
        ),
        (
            "/v/kv-test/secrets/-/deleted/gone/purge",
            &[("confirm_name", "gone")],
            "/v/kv-test/secrets/-/deleted/gone/purge".into(),
        ),
    ];
    for (path, fields, back) in cases {
        let res = w.post(path, fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        let html = body_text(res).await;
        assert!(
            unescape(&html)
                .contains("Your organisation asks you to confirm it's you before showing values."),
            "{path}: {html}"
        );
        assert!(!html.contains("second-value") && !html.contains("first-value"));
        let link = start_link(&html);
        assert_eq!(query(&link, "reason").as_deref(), Some("step_up"), "{path}");
        // Back to the confirmation step, never into the action.
        assert_eq!(
            query(&link, "return_to").as_deref(),
            Some(back.as_str()),
            "{path}"
        );
    }
    // Nothing was read or changed in Key Vault.
    assert_eq!(w.kv.state.value_reads().len(), reads);
    assert_eq!(w.kv.state.version_count("db-password"), 2);
    // The GET confirmation pages ask too, before a name is typed.
    for page in [
        "/v/kv-test/certificates/web-tls/download-key".to_owned(),
        format!("/v/kv-test/secrets/db-password/rollback?version={old}"),
        "/v/kv-test/secrets/-/deleted/gone/purge".to_owned(),
    ] {
        let (status, html) = w.page(&page).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(html.contains("Confirm it"), "{page}");
    }

    // The link goes to Entra with the claims parameter.
    let res = w
        .get("/auth/start?return_to=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password&reason=step_up")
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let entra = location(&res);
    assert_eq!(
        query(&entra, "claims").as_deref(),
        Some(r#"{"id_token":{"acrs":{"essential":true,"value":"c1"}}}"#)
    );
    assert_eq!(
        query(&entra, "prompt"),
        None,
        "context only: no forced login"
    );
    // An ordinary sign-in doesn't ask for it.
    let res = w.get("/auth/start?return_to=%2F").await;
    assert_eq!(query(&location(&res), "claims"), None);
}

#[tokio::test]
async fn max_age_passed_asks_for_a_fresh_sign_in() {
    let (w, _, _) = seeded(&[MAX_AGE]).await;
    met(&w, &[], Some(now() - 16 * 60));
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let link = start_link(&body_text(res).await);
    let res = w.get(&link).await;
    let entra = location(&res);
    assert_eq!(query(&entra, "prompt").as_deref(), Some("login"));
    assert_eq!(query(&entra, "max_age").as_deref(), Some("900"));
    assert_eq!(query(&entra, "claims"), None, "age only: no context asked");
    // No auth_time at all counts as too old.
    met(&w, &[], None);
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // Within the limit, it goes ahead.
    met(&w, &[], Some(now() - 14 * 60));
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// Run `/auth/start?reason=step_up` and the callback, with the mock IdP
/// set to answer with `acrs` and `auth_time`.
async fn step_up_round_trip(
    w: &World,
    acrs: Option<Vec<String>>,
    auth_time: Option<i64>,
) -> axum::http::Response<Body> {
    let res = w
        .get("/auth/start?return_to=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password&reason=step_up")
        .await;
    let entra = location(&res);
    let login = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_login="))
        .unwrap();
    *w.idp.state.nonce.lock().unwrap() = query(&entra, "nonce");
    *w.idp.state.acrs.lock().unwrap() = acrs;
    *w.idp.state.auth_time.lock().unwrap() = auth_time;
    let state = query(&entra, "state").unwrap();
    let req = Request::get(format!("/auth/callback?code=abc&state={state}"))
        .header("cookie", format!("{}; {login}", w.cookie))
        .body(Body::empty())
        .unwrap();
    w.app.clone().oneshot(req).await.unwrap()
}

#[tokio::test]
async fn a_callback_with_the_context_stores_acrs_and_auth_time() {
    let (w, _, _) = seeded(&[CONTEXT, MAX_AGE]).await;
    met(&w, &[], None);
    let t = now() - 5;
    let res = step_up_round_trip(
        &w,
        Some(vec!["c1".into(), "C9".into(), "bad\n".into()]),
        Some(t),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/secrets/db-password");
    let cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_session="))
        .unwrap();
    let id = cookie.split('=').nth(1).unwrap();
    let s = w.state.sessions.get(id).unwrap();
    assert_eq!(
        s.sign_in_facts(),
        SignInFacts {
            acrs: vec!["c1".into(), "c9".into()],
            auth_time: Some(t),
        },
        "only well-formed context IDs are kept"
    );
    // The new session can reveal.
    s.select_vault("kv-test".into());
    let csrf = s.csrf_token();
    let body = format!(
        "csrf={}",
        url::form_urlencoded::byte_serialize(csrf.as_bytes()).collect::<String>()
    );
    let req = Request::post("/v/kv-test/secrets/db-password/reveal")
        .header("origin", "http://localhost:3000")
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_callback_without_the_context_is_refused_and_does_not_loop() {
    let (w, _, _) = seeded(&[CONTEXT]).await;
    met(&w, &[], None);
    let sessions = w.state.sessions.len();
    for acrs in [None, Some(vec!["c2".into()])] {
        let res = step_up_round_trip(&w, acrs, Some(now())).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(
            res.headers()
                .get_all("set-cookie")
                .iter()
                .all(|v| !v.to_str().unwrap().starts_with("keyring_session=")),
            "no new session"
        );
        let html = body_text(res).await;
        assert!(html.contains("Couldn"), "{html}");
        // The only way on is back to the confirmation step, not another
        // sign-in, so it can't loop.
        assert!(!html.contains("/auth/start"), "{html}");
        assert!(!html.contains("/auth/sign-in"), "{html}");
        assert!(
            html.contains("href=\"/v/kv-test/secrets/db-password\""),
            "{html}"
        );
    }
    // The old session is still there and unchanged.
    assert_eq!(w.state.sessions.len(), sessions);
    assert_eq!(session(&w).sign_in_facts().acrs, Vec::<String>::new());
}

#[tokio::test]
async fn a_step_up_without_a_fresh_sign_in_is_refused() {
    let (w, _, _) = seeded(&[MAX_AGE]).await;
    met(&w, &[], None);
    let res = step_up_round_trip(&w, None, Some(now() - 3600)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_ordinary_sign_in_is_not_held_to_the_step_up_rules() {
    let (w, _, _) = seeded(&[CONTEXT]).await;
    let res = w.get("/auth/start?return_to=%2F").await;
    let entra = location(&res);
    let login = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_login="))
        .unwrap();
    *w.idp.state.nonce.lock().unwrap() = query(&entra, "nonce");
    let state = query(&entra, "state").unwrap();
    let req = Request::get(format!("/auth/callback?code=abc&state={state}"))
        .header("cookie", login)
        .body(Body::empty())
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn entra_refusing_the_policy_is_explained() {
    let (w, _, _) = seeded(&[CONTEXT]).await;
    let res = w.get("/auth/start?return_to=%2F&reason=step_up").await;
    let entra = location(&res);
    let login = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_login="))
        .unwrap();
    let state = query(&entra, "state").unwrap();
    *w.idp.state.behaviour.lock().unwrap() =
        support::TokenBehaviour::ErrorWithCode("invalid_grant", 53003);
    let req = Request::get(format!("/auth/callback?code=abc&state={state}"))
        .header("cookie", login)
        .body(Body::empty())
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let html = body_text(res).await;
    assert!(html.contains("sign-in rules weren"), "{html}");
    assert!(html.contains("AADSTS53003"), "{html}");
}
