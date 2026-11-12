//! The managed identity's token never reaches the logs.
//!
//! Kept in its own test binary with a single test, for the reason given in
//! `no_secrets_in_logs.rs`: `tracing` caches whether a log line is wanted,
//! and other tests running alongside without a subscriber can switch lines
//! off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Request, StatusCode};
use keyring::azure::Resource;
use keyring::secret::Secret;
use tower::ServiceExt;

/// Collects everything `tracing` writes, at every level.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn the_managed_identity_token_never_reaches_the_logs() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let idp = support::start_idp().await;
    let identity = support::start_identity().await;
    let config = support::config_with_identity(
        &idp.authority(),
        "http://localhost:3000",
        &identity.endpoint(),
    );
    let state = keyring::AppState::new(config);
    let app = keyring::app(state.clone());

    // Sign-in, through to the code exchange.
    let res = app
        .clone()
        .oneshot(
            Request::get("/auth/start?return_to=%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(res.headers().get(LOCATION).unwrap().to_str().unwrap()).unwrap();
    let query = |key: &str| {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    let login = res
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|c| c.starts_with("keyring_login="))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .expect("login cookie");
    *idp.state.nonce.lock().unwrap() = query("nonce");
    let callback = format!("/auth/callback?code=abc&state={}", query("state").unwrap());
    let res = app
        .oneshot(
            Request::get(callback)
                .header(COOKIE, login)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    // Exchanges and a refresh, which also carry the assertion.
    let id = state.sessions.create(
        keyring::auth::session::User {
            name: "Alex".into(),
            username: None,
            subject: keyring::auth::session::UserId {
                sub: "sub".into(),
                oid: None,
                tid: None,
            },
        },
        keyring::auth::session::UserTokens {
            access_token: Secret::new("user-api-token"),
            expires_at: SystemTime::now() + Duration::from_secs(30),
            refresh_token: Some(Secret::new("user-refresh")),
        },
    );
    let session = state.sessions.get(&id).unwrap();
    state
        .azure_broker()
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    assert_eq!(*identity.state.calls.lock().unwrap(), 1);

    // A failure in Entra's answer, with the assertion in the request.
    *idp.state.grant_error.lock().unwrap() = Some(("invalid_grant", 50013));
    let _ = state
        .azure_broker()
        .token_for(&session, Resource::Management)
        .await
        .unwrap_err();

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("token request refused"),
        "the failure path was logged: {logs}"
    );
    assert!(
        !logs.contains(support::MI_ASSERTION),
        "the assertion leaked into the logs:\n{logs}"
    );
    assert!(
        !logs.contains(support::IDENTITY_HEADER),
        "the identity header leaked into the logs:\n{logs}"
    );
    assert!(
        !logs.contains("user-api-token") && !logs.contains("obo:"),
        "a token leaked into the logs:\n{logs}"
    );
}
