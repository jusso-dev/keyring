//! Proving Keyring's identity to Entra with the managed identity's token
//! (`client_assertion`) instead of a client secret. That the token never
//! reaches the logs is checked in `federated_logs.rs`.

mod support;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use keyring::AppState;
use keyring::auth::session::{Session, User, UserId, UserTokens};
use keyring::azure::{Resource, TokenError};
use keyring::secret::Secret;
use support::{ASSERTION_TYPE, MI_ASSERTION, OBO_GRANT, field};
use tower::ServiceExt;

struct Harness {
    state: AppState,
    idp: support::MockIdp,
    identity: support::MockIdentity,
}

async fn harness() -> Harness {
    let idp = support::start_idp().await;
    let identity = support::start_identity().await;
    let config = support::config_with_identity(
        &idp.authority(),
        "http://localhost:3000",
        &identity.endpoint(),
    );
    Harness {
        state: AppState::new(config),
        idp,
        identity,
    }
}

impl Harness {
    fn session(&self, expires_in: Duration, refresh: Option<&str>) -> Arc<Session> {
        let id = self.state.sessions.create(
            User {
                name: "Alex".into(),
                username: None,
                subject: UserId {
                    sub: "sub".into(),
                    oid: None,
                    tid: None,
                },
            },
            UserTokens {
                access_token: Secret::new("user-api-token"),
                expires_at: SystemTime::now() + expires_in,
                refresh_token: refresh.map(Secret::new),
            },
        );
        self.state.sessions.get(&id).unwrap()
    }
}

/// The request carried the assertion and its type, and no client secret.
fn assert_asserts(form: &[(String, String)]) {
    assert_eq!(field(form, "client_assertion"), Some(MI_ASSERTION));
    assert_eq!(field(form, "client_assertion_type"), Some(ASSERTION_TYPE));
    assert_eq!(field(form, "client_id"), Some(support::CLIENT_ID));
    assert!(
        !form.iter().any(|(k, _)| k == "client_secret"),
        "a client secret was sent along with the assertion"
    );
}

fn location(res: &axum::http::Response<Body>) -> String {
    res.headers()
        .get(LOCATION)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn cookie_pair(res: &axum::http::Response<Body>, name: &str) -> String {
    res.headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|c| c.starts_with(name))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no {name} cookie"))
}

#[tokio::test]
async fn sign_in_sends_the_assertion_and_no_secret() {
    let h = harness().await;
    let app = keyring::app(h.state.clone());
    let res = app
        .clone()
        .oneshot(
            Request::get("/auth/start?return_to=%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let url = url::Url::parse(&location(&res)).unwrap();
    let login = cookie_pair(&res, "keyring_login");
    *h.idp.state.nonce.lock().unwrap() = query(&url, "nonce");
    let state = query(&url, "state").unwrap();

    let res = app
        .oneshot(
            Request::get(format!("/auth/callback?code=abc&state={state}"))
                .header(COOKIE, login)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "sign-in should finish");
    cookie_pair(&res, "keyring_session");

    let form = h.idp.state.last_token_form.lock().unwrap().clone().unwrap();
    assert_eq!(field(&form, "grant_type"), Some("authorization_code"));
    assert!(form.iter().any(|(k, _)| k == "code_verifier"));
    assert_asserts(&form);
    assert_eq!(*h.identity.state.calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn on_behalf_of_sends_the_assertion_and_no_secret() {
    let h = harness().await;
    let session = h.session(Duration::from_secs(3600), Some("user-refresh"));
    let token = h
        .state
        .azure_broker()
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    assert!(
        token
            .expose()
            .starts_with("obo:https://vault.azure.net/.default:for:user-api-token")
    );
    let reqs = h.idp.state.requests_of(OBO_GRANT);
    assert_eq!(reqs.len(), 1);
    assert_asserts(&reqs[0]);
    assert_eq!(field(&reqs[0], "requested_token_use"), Some("on_behalf_of"));
}

#[tokio::test]
async fn refresh_sends_the_assertion_and_no_secret() {
    let h = harness().await;
    // The user's own token is inside the expiry margin, so it is refreshed.
    let session = h.session(Duration::from_secs(30), Some("user-refresh"));
    h.state
        .azure_broker()
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    let refreshes = h.idp.state.requests_of("refresh_token");
    assert_eq!(refreshes.len(), 1);
    assert_asserts(&refreshes[0]);
    // The exchange that followed carried it too.
    let exchanges = h.idp.state.requests_of(OBO_GRANT);
    assert_eq!(exchanges.len(), 1);
    assert_asserts(&exchanges[0]);
}

#[tokio::test]
async fn ten_concurrent_exchanges_fetch_the_assertion_once() {
    let h = harness().await;
    *h.identity.state.delay.lock().unwrap() = Duration::from_millis(200);
    // Ten sessions, so each needs its own exchange and none shares a cache.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let state = h.state.clone();
        let session = h.session(Duration::from_secs(3600), None);
        tasks.push(tokio::spawn(async move {
            state
                .azure_broker()
                .token_for(&session, Resource::KeyVault)
                .await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(h.idp.state.requests_of(OBO_GRANT).len(), 10);
    assert_eq!(
        *h.identity.state.calls.lock().unwrap(),
        1,
        "the assertion is fetched once and shared"
    );
}

#[tokio::test]
async fn the_assertion_is_fetched_again_when_it_is_about_to_expire() {
    let h = harness().await;
    // Inside the 5 minute margin, so it is stale on arrival.
    *h.identity.state.expires_in.lock().unwrap() = 120;
    let session = h.session(Duration::from_secs(3600), None);
    let broker = h.state.azure_broker();
    broker
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    broker
        .token_for(&session, Resource::Management)
        .await
        .unwrap();
    assert_eq!(*h.identity.state.calls.lock().unwrap(), 2);

    // A longer-lived one is kept.
    let h = harness().await;
    let session = h.session(Duration::from_secs(3600), None);
    let broker = h.state.azure_broker();
    broker
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    broker
        .token_for(&session, Resource::Management)
        .await
        .unwrap();
    assert_eq!(*h.identity.state.calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn identity_endpoint_down_is_reported_as_unreachable() {
    let idp = support::start_idp().await;
    // Nothing listens on port 9, so the identity's token service is down.
    let config = support::config_with_identity(
        &idp.authority(),
        "http://localhost:3000",
        "http://127.0.0.1:9/msi/token",
    );
    let (state, app, cookie) = support::signed_in_app(config);

    let id = cookie.split('=').nth(1).unwrap();
    let session = state.sessions.get(id).unwrap();
    let err = state
        .azure_broker()
        .token_for(&session, Resource::Management)
        .await
        .unwrap_err();
    assert!(matches!(err, TokenError::Unreachable(_)), "{err:?}");
    // Entra was never asked, since there was nothing to ask with.
    assert!(idp.state.token_requests.lock().unwrap().is_empty());

    // The page tells the person Keyring couldn't reach Microsoft sign-in,
    // without a token in it.
    let res = app
        .oneshot(
            Request::get("/vaults")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let html =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains("Can&#39;t reach Microsoft sign-in"), "{html}");
    assert!(
        html.contains("Keyring couldn&#39;t reach Entra ID"),
        "{html}"
    );
    assert!(!html.contains(MI_ASSERTION));
}

#[tokio::test]
async fn a_wrong_identity_header_is_a_failure_not_a_token() {
    // A service that refuses the header answers 401 with no token.
    let idp = support::start_idp().await;
    let identity = support::start_identity().await;
    let endpoint = identity.endpoint();
    let config = {
        let authority = idp.authority();
        keyring::config::Config::from_lookup(move |k| {
            Some(match k {
                "ENTRA_TENANT_ID" => support::TENANT.to_owned(),
                "ENTRA_CLIENT_ID" => support::CLIENT_ID.to_owned(),
                "KEYRING_FEDERATED_IDENTITY_CLIENT_ID" => support::IDENTITY_CLIENT_ID.to_owned(),
                "IDENTITY_ENDPOINT" => endpoint.clone(),
                "IDENTITY_HEADER" => "not-the-header".to_owned(),
                "ENTRA_AUTHORITY_HOST" => authority.clone(),
                "APP_BASE_URL" => "http://localhost:3000".to_owned(),
                "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
                _ => return None,
            })
        })
        .unwrap()
    };
    let state = AppState::new(config);
    let id = state.sessions.create(
        User {
            name: "Alex".into(),
            username: None,
            subject: UserId {
                sub: "sub".into(),
                oid: None,
                tid: None,
            },
        },
        UserTokens {
            access_token: Secret::new("t"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let session = state.sessions.get(&id).unwrap();
    let err = state
        .azure_broker()
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap_err();
    assert!(matches!(err, TokenError::Unreachable(_)), "{err:?}");
    assert!(idp.state.token_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn secret_mode_still_sends_the_secret_and_never_asks_the_identity() {
    let idp = support::start_idp().await;
    let config = support::config_with(&idp.authority(), "http://localhost:3000");
    let state = AppState::new(config);
    let id = state.sessions.create(
        User {
            name: "Alex".into(),
            username: None,
            subject: UserId {
                sub: "sub".into(),
                oid: None,
                tid: None,
            },
        },
        UserTokens {
            access_token: Secret::new("user-api-token"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let session = state.sessions.get(&id).unwrap();
    state
        .azure_broker()
        .token_for(&session, Resource::KeyVault)
        .await
        .unwrap();
    let reqs = idp.state.requests_of(OBO_GRANT);
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        field(&reqs[0], "client_secret"),
        Some(support::CLIENT_SECRET)
    );
    assert!(field(&reqs[0], "client_assertion").is_none());
    assert!(field(&reqs[0], "client_assertion_type").is_none());
}
