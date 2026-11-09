//! Shared test helpers: a config and a mock Entra ID.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use keyring::config::Config;
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserName, EndUserUsername, IssuerUrl, JsonWebKeyId,
    LocalizedClaim, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;

/// JSON response without needing axum's `json` feature in the app.
fn json_response(status: StatusCode, v: serde_json::Value) -> Response {
    (status, [(CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

pub const TENANT: &str = "00000000-0000-0000-0000-000000000000";
pub const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
pub const CLIENT_SECRET: &str = "test-client-secret";

pub fn config_with(authority: &str, base_url: &str) -> Config {
    let authority = authority.to_owned();
    let base_url = base_url.to_owned();
    Config::from_lookup(move |k| {
        Some(match k {
            "ENTRA_TENANT_ID" => TENANT.to_owned(),
            "ENTRA_CLIENT_ID" => CLIENT_ID.to_owned(),
            "ENTRA_CLIENT_SECRET" => CLIENT_SECRET.to_owned(),
            "ENTRA_AUTHORITY_HOST" => authority.clone(),
            "APP_BASE_URL" => base_url.clone(),
            "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            _ => return None,
        })
    })
    .expect("test config")
}

pub fn config() -> Config {
    config_with("http://127.0.0.1:9", "http://localhost:3000")
}

/// What the mock should do on the next token request.
#[derive(Clone, Debug)]
pub enum TokenBehaviour {
    /// Return a valid ID token carrying this nonce.
    Ok,
    /// Return an ID token with the wrong nonce.
    WrongNonce,
    /// Return an ID token signed by a key that isn't in the JWKS.
    WrongKey,
    /// Return an ID token for another app.
    WrongAudience,
    /// Return an OAuth error.
    Error(&'static str),
}

pub struct MockIdp {
    pub addr: SocketAddr,
    pub state: Arc<IdpState>,
}

pub struct IdpState {
    issuer: String,
    key: CoreRsaPrivateSigningKey,
    other_key: CoreRsaPrivateSigningKey,
    pub behaviour: Mutex<TokenBehaviour>,
    /// Nonce the next ID token should carry (taken from the authorise URL by the test).
    pub nonce: Mutex<Option<String>>,
    /// Form fields of the last token request.
    pub last_token_form: Mutex<Option<Vec<(String, String)>>>,
}

impl MockIdp {
    pub fn authority(&self) -> String {
        format!("http://{}", self.addr)
    }
}

static KEYS: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

fn keys() -> (CoreRsaPrivateSigningKey, CoreRsaPrivateSigningKey) {
    // RSA key generation is slow; make the PEMs once per test binary.
    let (a, b) = KEYS.get_or_init(|| {
        let gen_pem = || {
            let mut rng = rsa::rand_core::OsRng;
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
            key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .expect("pem")
                .to_string()
        };
        (gen_pem(), gen_pem())
    });
    (
        CoreRsaPrivateSigningKey::from_pem(a, Some(JsonWebKeyId::new("k1".into()))).unwrap(),
        CoreRsaPrivateSigningKey::from_pem(b, Some(JsonWebKeyId::new("k2".into()))).unwrap(),
    )
}

pub async fn start_idp() -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (key, other_key) = keys();
    let state = Arc::new(IdpState {
        issuer: format!("http://{addr}/{TENANT}/v2.0"),
        key,
        other_key,
        behaviour: Mutex::new(TokenBehaviour::Ok),
        nonce: Mutex::new(None),
        last_token_form: Mutex::new(None),
    });
    let app = Router::new()
        .route(
            &format!("/{TENANT}/v2.0/.well-known/openid-configuration"),
            get(discovery),
        )
        .route("/keys", get(jwks))
        .route("/token", post(token))
        .with_state(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockIdp { addr, state }
}

async fn discovery(State(s): State<Arc<IdpState>>) -> Response {
    let base = s
        .issuer
        .trim_end_matches(&format!("/{TENANT}/v2.0"))
        .to_owned();
    json_response(
        StatusCode::OK,
        json!({
            "issuer": s.issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/keys"),
            "end_session_endpoint": format!("{base}/logout"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }),
    )
}

async fn jwks(State(s): State<Arc<IdpState>>) -> Response {
    let jwk: CoreJsonWebKey = s.key.as_verification_key();
    json_response(StatusCode::OK, json!({ "keys": [jwk] }))
}

fn now_plus(secs: u64) -> DateTime<Utc> {
    let t = SystemTime::now() + Duration::from_secs(secs);
    let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    DateTime::from_timestamp(secs, 0).unwrap()
}

async fn token(
    State(s): State<Arc<IdpState>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    *s.last_token_form.lock().unwrap() = Some(form);
    let behaviour = s.behaviour.lock().unwrap().clone();
    if let TokenBehaviour::Error(code) = behaviour {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": code, "error_description": "test" }),
        );
    }
    let nonce = match behaviour {
        TokenBehaviour::WrongNonce => "not-the-nonce".to_owned(),
        _ => s.nonce.lock().unwrap().clone().unwrap_or_default(),
    };
    let audience = match behaviour {
        TokenBehaviour::WrongAudience => "22222222-2222-2222-2222-222222222222",
        _ => CLIENT_ID,
    };
    let mut name = LocalizedClaim::new();
    name.insert(None, EndUserName::new("Alex Example".into()));
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        vec![Audience::new(audience.into())],
        now_plus(3600),
        now_plus(0),
        StandardClaims::new(SubjectIdentifier::new("user-subject".into()))
            .set_name(Some(name))
            .set_preferred_username(Some(EndUserUsername::new("alex@example.com".into()))),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce)));
    let key = match behaviour {
        TokenBehaviour::WrongKey => &s.other_key,
        _ => &s.key,
    };
    let id_token = CoreIdToken::new(
        claims,
        key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    json_response(
        StatusCode::OK,
        json!({
            "access_token": "user-access-token-for-keyring-api",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "user-refresh-token",
            "id_token": id_token.to_string(),
        }),
    )
}
