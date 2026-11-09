//! On-behalf-of exchange, caching, refresh and error mapping against a mock
//! Entra token endpoint and a mock Azure API.

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use keyring::AppState;
use keyring::auth::session::{Session, User, UserTokens};
use keyring::azure::{AzureError, Resource, TokenError};
use keyring::secret::Secret;
use support::{OBO_GRANT, field};

struct Harness {
    state: AppState,
    idp: support::MockIdp,
    session: Arc<Session>,
}

fn user() -> User {
    User {
        name: "Alex".into(),
        username: None,
        subject: "sub".into(),
    }
}

async fn harness_with(expires_in: Duration, refresh: Option<&str>) -> Harness {
    let idp = support::start_idp().await;
    let config = support::config_with(&idp.authority(), "http://localhost:3000");
    let state = AppState::new(config);
    let id = state.sessions.create(
        user(),
        UserTokens {
            access_token: Secret::new("user-api-token"),
            expires_at: SystemTime::now() + expires_in,
            refresh_token: refresh.map(Secret::new),
        },
    );
    let session = state.sessions.get(&id).unwrap();
    Harness {
        state,
        idp,
        session,
    }
}

async fn harness() -> Harness {
    harness_with(Duration::from_secs(3600), Some("user-refresh")).await
}

#[tokio::test]
async fn exchanges_user_token_on_behalf_of_user() {
    let h = harness().await;
    let token = h
        .state
        .azure_broker()
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    assert!(
        token
            .expose()
            .starts_with("obo:https://vault.azure.net/.default:for:user-api-token")
    );

    let reqs = h.idp.state.requests_of(OBO_GRANT);
    assert_eq!(reqs.len(), 1);
    let f = &reqs[0];
    assert_eq!(field(f, "requested_token_use"), Some("on_behalf_of"));
    assert_eq!(field(f, "assertion"), Some("user-api-token"));
    assert_eq!(field(f, "client_id"), Some(support::CLIENT_ID));
    assert_eq!(field(f, "scope"), Some("https://vault.azure.net/.default"));
    // No app-only grants anywhere.
    assert!(h.idp.state.requests_of("client_credentials").is_empty());
}

#[tokio::test]
async fn caches_per_resource() {
    let h = harness().await;
    let broker = h.state.azure_broker();
    let a = broker
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    let b = broker
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    assert_eq!(a.expose(), b.expose());
    let m = broker
        .token_for(&h.session, Resource::Management)
        .await
        .unwrap();
    assert!(m.expose().contains("management.azure.com"));
    let l = broker
        .token_for(&h.session, Resource::LogAnalytics)
        .await
        .unwrap();
    assert!(l.expose().contains("api.loganalytics.io"));
    assert_eq!(h.idp.state.requests_of(OBO_GRANT).len(), 3);
}

#[tokio::test]
async fn sessions_do_not_share_tokens() {
    let h = harness().await;
    let other_id = h.state.sessions.create(
        user(),
        UserTokens {
            access_token: Secret::new("someone-else"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let other = h.state.sessions.get(&other_id).unwrap();
    let broker = h.state.azure_broker();
    let a = broker
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    let b = broker.token_for(&other, Resource::KeyVault).await.unwrap();
    assert!(a.expose().contains("user-api-token"));
    assert!(b.expose().contains("someone-else"));
}

#[tokio::test]
async fn refreshes_obo_token_before_expiry() {
    let h = harness().await;
    // Tokens that are already inside the expiry margin.
    *h.idp.state.grant_expires_in.lock().unwrap() = 60;
    let broker = h.state.azure_broker();
    let a = broker
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    let b = broker
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    assert_ne!(a.expose(), b.expose());
    assert_eq!(h.idp.state.requests_of(OBO_GRANT).len(), 2);
}

#[tokio::test]
async fn refreshes_user_token_when_it_is_about_to_expire() {
    let h = harness_with(Duration::from_secs(30), Some("user-refresh")).await;
    let token = h
        .state
        .azure_broker()
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap();
    let refreshes = h.idp.state.requests_of("refresh_token");
    assert_eq!(refreshes.len(), 1);
    assert_eq!(field(&refreshes[0], "refresh_token"), Some("user-refresh"));
    // The OBO exchange used the refreshed token, and the session kept the rotated refresh token.
    assert!(token.expose().contains(":for:refreshed-user-token-"));
    let tokens = h.session.tokens();
    assert!(
        tokens
            .refresh_token
            .unwrap()
            .expose()
            .starts_with("rotated-refresh-")
    );
}

#[tokio::test]
async fn expired_user_token_without_refresh_means_sign_in_again() {
    let h = harness_with(Duration::from_secs(10), None).await;
    let err = h
        .state
        .azure_broker()
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap_err();
    assert_eq!(err, TokenError::SignInAgain);
}

#[tokio::test]
async fn maps_entra_errors() {
    for (error, code, expected) in [
        ("interaction_required", 50076, TokenError::SignInAgain),
        ("invalid_grant", 65001, TokenError::ConsentNeeded),
        ("invalid_grant", 70043, TokenError::SignInAgain),
        (
            "unauthorized_client",
            700016,
            TokenError::Refused {
                code: "unauthorized_client".into(),
            },
        ),
    ] {
        let h = harness().await;
        *h.idp.state.grant_error.lock().unwrap() = Some((error, code));
        let err = h
            .state
            .azure_broker()
            .token_for(&h.session, Resource::KeyVault)
            .await
            .unwrap_err();
        assert_eq!(err, expected, "{error} {code}");
    }
}

#[tokio::test]
async fn unreachable_token_endpoint_is_reported() {
    let config = support::config_with("http://127.0.0.1:9", "http://localhost:3000");
    let state = AppState::new(config);
    let id = state.sessions.create(
        user(),
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
    assert!(matches!(err, TokenError::Unreachable(_)));
}

/// A stand-in Azure API that records the bearer token it was sent.
struct MockAzure {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn start_azure() -> MockAzure {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let calls = seen.clone();
    let reject_first = Arc::new(Mutex::new(true));
    let app = Router::new()
        .route(
            "/ok",
            get({
                let calls = calls.clone();
                move |headers: HeaderMap| {
                    let calls = calls.clone();
                    async move {
                        calls.lock().unwrap().push(bearer(&headers));
                        ([("content-type", "application/json")], r#"{"value":42}"#)
                    }
                }
            }),
        )
        .route(
            "/forbidden",
            get(|| async {
                (
                    StatusCode::FORBIDDEN,
                    [("content-type", "application/json")],
                    r#"{"error":{"code":"Forbidden","message":"Caller is not authorized"}}"#,
                )
            }),
        )
        .route(
            "/stale-once",
            get({
                let calls = calls.clone();
                move |headers: HeaderMap| {
                    let calls = calls.clone();
                    let reject_first = reject_first.clone();
                    async move {
                        calls.lock().unwrap().push(bearer(&headers));
                        let mut first = reject_first.lock().unwrap();
                        if *first {
                            *first = false;
                            StatusCode::UNAUTHORIZED.into_response()
                        } else {
                            ([("content-type", "application/json")], r#"{"value":7}"#)
                                .into_response()
                        }
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockAzure { addr, seen }
}

fn bearer(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[derive(Debug, serde::Deserialize)]
struct Value {
    value: u32,
}

#[tokio::test]
async fn azure_calls_carry_the_users_obo_token() {
    let h = harness().await;
    let azure = start_azure().await;
    let v: Value = h
        .state
        .azure
        .get_json(
            &h.session,
            Resource::KeyVault,
            &format!("http://{}/ok", azure.addr),
        )
        .await
        .unwrap();
    assert_eq!(v.value, 42);
    let seen = azure.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("Bearer obo:https://vault.azure.net/.default:for:user-api-token"));
}

#[tokio::test]
async fn azure_errors_keep_status_and_code() {
    let h = harness().await;
    let azure = start_azure().await;
    let err = h
        .state
        .azure
        .get_json::<Value>(
            &h.session,
            Resource::KeyVault,
            &format!("http://{}/forbidden", azure.addr),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err,
        AzureError::Status {
            status: 403,
            code: Some("Forbidden".into()),
            message: Some("Caller is not authorized".into()),
        }
    );
}

#[tokio::test]
async fn a_401_gets_a_fresh_token_and_retries_once() {
    let h = harness().await;
    let azure = start_azure().await;
    let v: Value = h
        .state
        .azure
        .get_json(
            &h.session,
            Resource::KeyVault,
            &format!("http://{}/stale-once", azure.addr),
        )
        .await
        .unwrap();
    assert_eq!(v.value, 7);
    let seen = azure.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0], seen[1], "second try should use a new token");
}

#[tokio::test]
async fn conditional_access_challenge_is_passed_to_the_next_sign_in() {
    let h = harness().await;
    *h.idp.state.grant_error.lock().unwrap() = Some(("interaction_required", 50076));
    let err = h
        .state
        .azure_broker()
        .token_for(&h.session, Resource::KeyVault)
        .await
        .unwrap_err();
    assert_eq!(err, TokenError::SignInAgain);
    let claims = h.session.claims_challenge().expect("challenge kept");
    assert!(claims.contains("capolids"));

    // The next sign-in from this browser carries it to Entra.
    let id = h.state.sessions.create(
        user(),
        UserTokens {
            access_token: Secret::new("t"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let s = h.state.sessions.get(&id).unwrap();
    s.set_claims_challenge(&claims);
    let app = keyring::app(h.state.clone());
    let res = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::get("/auth/start?return_to=%2F")
            .header("cookie", format!("keyring_session={id}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    let location = res.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(location).unwrap();
    let sent = url
        .query_pairs()
        .find(|(k, _)| k == "claims")
        .map(|(_, v)| v.into_owned());
    assert_eq!(sent.as_deref(), Some(claims.as_str()));

    // Anything that isn't a JSON object is ignored.
    s.set_claims_challenge("not json");
    assert_eq!(s.claims_challenge().as_deref(), Some(claims.as_str()));
}
