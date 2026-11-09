//! Shared test helpers: a config and a mock Entra ID.

#![allow(dead_code)]

pub mod certs;
pub mod keyvault;

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
pub fn json_response(status: StatusCode, v: serde_json::Value) -> Response {
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
    /// Every token request's form, in order.
    pub token_requests: Mutex<Vec<Vec<(String, String)>>>,
    /// If set, on-behalf-of and refresh requests fail with this OAuth error
    /// and Entra error code.
    pub grant_error: Mutex<Option<(&'static str, u64)>>,
    /// Lifetime in seconds of tokens handed out by OBO and refresh.
    pub grant_expires_in: Mutex<u64>,
}

impl IdpState {
    /// Token requests with this `grant_type`.
    pub fn requests_of(&self, grant_type: &str) -> Vec<Vec<(String, String)>> {
        self.token_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|f| field(f, "grant_type") == Some(grant_type))
            .cloned()
            .collect()
    }
}

pub fn field<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub const OBO_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

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
        token_requests: Mutex::new(Vec::new()),
        grant_error: Mutex::new(None),
        grant_expires_in: Mutex::new(3600),
    });
    let app = Router::new()
        .route(
            &format!("/{TENANT}/v2.0/.well-known/openid-configuration"),
            get(discovery),
        )
        .route("/keys", get(jwks))
        .route("/token", post(token))
        .route(&format!("/{TENANT}/oauth2/v2.0/token"), post(token))
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
    *s.last_token_form.lock().unwrap() = Some(form.clone());
    s.token_requests.lock().unwrap().push(form.clone());
    let grant = field(&form, "grant_type").unwrap_or_default().to_owned();
    if grant == OBO_GRANT || grant == "refresh_token" {
        return other_grant(&s, &form, &grant);
    }
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

/// On-behalf-of and refresh grants. Tokens encode what they were issued for,
/// so tests can see which token reached the mock Azure API.
fn other_grant(s: &IdpState, form: &[(String, String)], grant: &str) -> Response {
    if field(form, "client_secret") != Some(CLIENT_SECRET) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "invalid_client" }),
        );
    }
    if let Some((error, code)) = *s.grant_error.lock().unwrap() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": error, "error_codes": [code], "error_description": "test" }),
        );
    }
    let expires_in = *s.grant_expires_in.lock().unwrap();
    let n = s.token_requests.lock().unwrap().len();
    if grant == OBO_GRANT {
        let scope = field(form, "scope").unwrap_or_default();
        let assertion = field(form, "assertion").unwrap_or_default();
        json_response(
            StatusCode::OK,
            json!({
                "access_token": format!("obo:{scope}:for:{assertion}:{n}"),
                "token_type": "Bearer",
                "expires_in": expires_in,
            }),
        )
    } else {
        json_response(
            StatusCode::OK,
            json!({
                "access_token": format!("refreshed-user-token-{n}"),
                "refresh_token": format!("rotated-refresh-{n}"),
                "token_type": "Bearer",
                "expires_in": expires_in,
            }),
        )
    }
}

/// An app plus a cookie for a session that's already signed in.
pub fn signed_in_app(config: Config) -> (keyring::AppState, axum::Router, String) {
    use keyring::auth::session::{User, UserTokens};
    use keyring::secret::Secret;
    let state = keyring::AppState::new(config);
    let id = state.sessions.create(
        User {
            name: "Alex Example".into(),
            username: Some("alex@example.com".into()),
            subject: "sub".into(),
        },
        UserTokens {
            access_token: Secret::new("user-api-token"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let app = keyring::app(state.clone());
    (state, app, format!("keyring_session={id}"))
}

/// A mock Azure Resource Manager that answers Resource Graph queries.
pub struct MockArm {
    pub addr: SocketAddr,
    pub state: Arc<ArmState>,
}

pub struct ArmState {
    /// Vault rows returned, split into pages of `page_size`.
    pub vaults: Mutex<Vec<serde_json::Value>>,
    pub subscriptions: Mutex<Vec<serde_json::Value>>,
    pub page_size: Mutex<usize>,
    /// If set, every query fails with this status and Azure error code.
    pub fail: Mutex<Option<(u16, &'static str)>>,
    /// Request bodies received, in order.
    pub requests: Mutex<Vec<serde_json::Value>>,
    /// Bearer tokens received.
    pub bearers: Mutex<Vec<String>>,
}

impl MockArm {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

pub fn vault_row(name: &str, sub: &str, rbac: bool) -> serde_json::Value {
    json!({
        "id": format!("/subscriptions/{sub}/resourceGroups/rg-{name}/providers/Microsoft.KeyVault/vaults/{name}"),
        "name": name,
        "resourceGroup": format!("rg-{name}"),
        "subscriptionId": sub,
        "location": "australiaeast",
        "tags": {"env": "prod"},
        "enableRbacAuthorization": rbac,
        "enableSoftDelete": true,
        "enablePurgeProtection": false,
    })
}

pub async fn start_arm() -> MockArm {
    let state = Arc::new(ArmState {
        vaults: Mutex::new(Vec::new()),
        subscriptions: Mutex::new(Vec::new()),
        page_size: Mutex::new(1000),
        fail: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        bearers: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route(
            "/providers/Microsoft.ResourceGraph/resources",
            post(resource_graph),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockArm { addr, state }
}

async fn resource_graph(
    State(s): State<Arc<ArmState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    s.requests.lock().unwrap().push(body.clone());
    s.bearers.lock().unwrap().push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    );
    if let Some((status, code)) = *s.fail.lock().unwrap() {
        return json_response(
            StatusCode::from_u16(status).unwrap(),
            json!({"error": {"code": code, "message": "mock failure"}}),
        );
    }
    let query = body["query"].as_str().unwrap_or_default();
    let rows = if query.contains("resourcecontainers") {
        s.subscriptions.lock().unwrap().clone()
    } else {
        s.vaults.lock().unwrap().clone()
    };
    let size = *s.page_size.lock().unwrap();
    let start: usize = body["options"]["$skipToken"]
        .as_str()
        .and_then(|t| t.strip_prefix("skip-"))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let end = (start + size).min(rows.len());
    let mut out = json!({
        "totalRecords": rows.len(),
        "count": end - start,
        "data": rows[start..end].to_vec(),
    });
    if end < rows.len() {
        out["$skipToken"] = json!(format!("skip-{end}"));
    }
    json_response(StatusCode::OK, out)
}

/// Config pointing sign-in at `idp` and ARM at `arm`.
pub fn config_with_arm(idp: &MockIdp, arm: &MockArm) -> Config {
    let authority = idp.authority();
    let arm_url = arm.url();
    Config::from_lookup(move |k| {
        Some(match k {
            "ENTRA_TENANT_ID" => TENANT.to_owned(),
            "ENTRA_CLIENT_ID" => CLIENT_ID.to_owned(),
            "ENTRA_CLIENT_SECRET" => CLIENT_SECRET.to_owned(),
            "ENTRA_AUTHORITY_HOST" => authority.clone(),
            "KEYRING_TEST_MANAGEMENT_URL" => arm_url.clone(),
            "APP_BASE_URL" => "http://localhost:3000".to_owned(),
            "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            _ => return None,
        })
    })
    .expect("test config")
}

/// Everything a page test needs: mock IdP, ARM and Key Vault, and a
/// signed-in session.
pub struct World {
    pub app: axum::Router,
    pub state: keyring::AppState,
    pub cookie: String,
    pub csrf: String,
    pub kv: keyvault::MockKeyVault,
    pub arm: MockArm,
    pub idp: MockIdp,
}

pub async fn world_with(extra: &[(&'static str, &'static str)]) -> World {
    let idp = start_idp().await;
    let arm = start_arm().await;
    let kv = keyvault::start().await;
    let mut env: std::collections::HashMap<&'static str, String> =
        std::collections::HashMap::from([
            ("ENTRA_TENANT_ID", TENANT.to_owned()),
            ("ENTRA_CLIENT_ID", CLIENT_ID.to_owned()),
            ("ENTRA_CLIENT_SECRET", CLIENT_SECRET.to_owned()),
            ("ENTRA_AUTHORITY_HOST", idp.authority()),
            ("KEYRING_TEST_MANAGEMENT_URL", arm.url()),
            ("KEYRING_TEST_KEYVAULT_URL", kv.url()),
            ("APP_BASE_URL", "http://localhost:3000".to_owned()),
            (
                "SESSION_SECRET",
                "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        ]);
    for (k, v) in extra {
        env.insert(k, (*v).to_owned());
    }
    let config = Config::from_lookup(|k| env.get(k).cloned()).expect("test config");
    let (state, app, cookie) = signed_in_app(config);
    let id = cookie.split('=').nth(1).unwrap().to_owned();
    let session = state.sessions.get(&id).unwrap();
    session.select_vault("kv-test".into());
    let csrf = session.csrf.clone();
    World {
        app,
        state,
        cookie,
        csrf,
        kv,
        arm,
        idp,
    }
}

pub async fn world() -> World {
    world_with(&[]).await
}

impl World {
    pub async fn get(&self, path: &str) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let req = axum::http::Request::get(path)
            .header("cookie", &self.cookie)
            .body(axum::body::Body::empty())
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// POST a form. `csrf` is added automatically.
    pub async fn post(
        &self,
        path: &str,
        fields: &[(&str, &str)],
    ) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let mut all = vec![("csrf", self.csrf.as_str())];
        all.extend_from_slice(fields);
        let body: String = openidconnect::url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(all)
            .finish();
        let req = axum::http::Request::post(path)
            .header("cookie", &self.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// GET and return status and body text.
    pub async fn page(&self, path: &str) -> (StatusCode, String) {
        let res = self.get(path).await;
        let status = res.status();
        (status, body_text(res).await)
    }
}

pub async fn body_text(res: axum::http::Response<axum::body::Body>) -> String {
    use http_body_util::BodyExt;
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

pub fn location(res: &axum::http::Response<axum::body::Body>) -> String {
    res.headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

/// The test certificate (public part only), shared with the unit tests.
pub const TEST_CERT_PEM: &str = include_str!("../fixtures/test-cert.pem");

/// First CERTIFICATE block in a PEM string, decoded.
pub fn pem_first_cert(pem: &str) -> Option<Vec<u8>> {
    keyring::x509::pem_blocks(pem, "CERTIFICATE")
        .into_iter()
        .next()
}
