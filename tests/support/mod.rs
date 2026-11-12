//! Shared test helpers: a config and a mock Entra ID.

#![allow(dead_code)]

pub(crate) mod certs;
pub(crate) mod keys;
pub(crate) mod keyvault;

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
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EndUserName, EndUserUsername, IssuerUrl, JsonWebKeyId, LocalizedClaim, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;

/// JSON response without needing axum's `json` feature in the app.
pub(crate) fn json_response(status: StatusCode, v: serde_json::Value) -> Response {
    (status, [(CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

pub(crate) const TENANT: &str = "00000000-0000-0000-0000-000000000000";
pub(crate) const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
pub(crate) const CLIENT_SECRET: &str = "test-client-secret";

/// The managed identity's client ID, and what its mock token service hands out.
pub(crate) const IDENTITY_CLIENT_ID: &str = "33333333-3333-3333-3333-333333333333";
pub(crate) const IDENTITY_HEADER: &str = "mock-identity-header";
pub(crate) const MI_ASSERTION: &str = "mi-assertion";
pub(crate) const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub(crate) fn config_with(authority: &str, base_url: &str) -> Config {
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

pub(crate) fn config() -> Config {
    config_with("http://127.0.0.1:9", "http://localhost:3000")
}

/// Like [`config_with`], but Keyring proves itself with the managed
/// identity whose token service is at `identity_endpoint`.
pub(crate) fn config_with_identity(
    authority: &str,
    base_url: &str,
    identity_endpoint: &str,
) -> Config {
    let authority = authority.to_owned();
    let base_url = base_url.to_owned();
    let identity_endpoint = identity_endpoint.to_owned();
    Config::from_lookup(move |k| {
        Some(match k {
            "ENTRA_TENANT_ID" => TENANT.to_owned(),
            "ENTRA_CLIENT_ID" => CLIENT_ID.to_owned(),
            "KEYRING_FEDERATED_IDENTITY_CLIENT_ID" => IDENTITY_CLIENT_ID.to_owned(),
            "IDENTITY_ENDPOINT" => identity_endpoint.clone(),
            "IDENTITY_HEADER" => IDENTITY_HEADER.to_owned(),
            "ENTRA_AUTHORITY_HOST" => authority.clone(),
            "APP_BASE_URL" => base_url.clone(),
            "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            _ => return None,
        })
    })
    .expect("test config")
}

/// A mock of the managed identity's local token service, as App Service and
/// Container Apps provide it.
pub(crate) struct MockIdentity {
    pub addr: SocketAddr,
    pub state: Arc<IdentityState>,
}

pub(crate) struct IdentityState {
    /// Requests that passed the header and query checks.
    pub calls: Mutex<usize>,
    /// Delay before answering, so tests can overlap requests.
    pub delay: Mutex<Duration>,
    /// Lifetime in seconds of the token handed out.
    pub expires_in: Mutex<u64>,
}

impl MockIdentity {
    pub(crate) fn endpoint(&self) -> String {
        format!("http://{}/msi/token", self.addr)
    }
}

pub(crate) async fn start_identity() -> MockIdentity {
    let state = Arc::new(IdentityState {
        calls: Mutex::new(0),
        delay: Mutex::new(Duration::ZERO),
        expires_in: Mutex::new(3600),
    });
    let app = Router::new()
        .route("/msi/token", get(identity_token))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockIdentity { addr, state }
}

async fn identity_token(
    State(s): State<Arc<IdentityState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let header_ok = headers
        .get("x-identity-header")
        .and_then(|v| v.to_str().ok())
        == Some(IDENTITY_HEADER);
    if !header_ok {
        return json_response(StatusCode::UNAUTHORIZED, json!({}));
    }
    let query_ok = q.get("resource").map(String::as_str) == Some("api://AzureADTokenExchange")
        && q.get("api-version").map(String::as_str) == Some("2019-08-01")
        && q.get("client_id").map(String::as_str) == Some(IDENTITY_CLIENT_ID);
    if !query_ok {
        return json_response(StatusCode::BAD_REQUEST, json!({}));
    }
    *s.calls.lock().unwrap() += 1;
    let delay = *s.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let expires_on = (SystemTime::now() + Duration::from_secs(*s.expires_in.lock().unwrap()))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json_response(
        StatusCode::OK,
        json!({
            "access_token": MI_ASSERTION,
            "expires_on": expires_on.to_string(),
            "resource": "api://AzureADTokenExchange",
            "token_type": "Bearer",
            "client_id": IDENTITY_CLIENT_ID,
        }),
    )
}

/// What the mock should do on the next token request.
#[derive(Clone, Debug)]
pub(crate) enum TokenBehaviour {
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

pub(crate) struct MockIdp {
    pub addr: SocketAddr,
    pub state: Arc<IdpState>,
}

pub(crate) struct IdpState {
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
    /// Discovery document requests served.
    pub discovery_hits: Mutex<usize>,
    /// Make discovery answer 503.
    pub discovery_down: Mutex<bool>,
    /// Entra rolled its signing keys: publish and sign with the second key.
    pub rolled_over: Mutex<bool>,
    /// Delay before answering token requests, so tests can overlap them.
    pub token_delay: Mutex<Duration>,
}

impl IdpState {
    /// Token requests with this `grant_type`.
    pub(crate) fn requests_of(&self, grant_type: &str) -> Vec<Vec<(String, String)>> {
        self.token_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|f| field(f, "grant_type") == Some(grant_type))
            .cloned()
            .collect()
    }
}

pub(crate) fn field<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub(crate) const OBO_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The object ID the mock puts in every ID token, as Entra does with `oid`.
pub(crate) const USER_OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";

/// An ID token with Entra's `oid` and `tid` claims.
type EntraIdToken = openidconnect::IdToken<
    keyring::auth::oidc::EntraClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

impl MockIdp {
    pub(crate) fn authority(&self) -> String {
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

pub(crate) async fn start_idp() -> MockIdp {
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
        discovery_hits: Mutex::new(0),
        discovery_down: Mutex::new(false),
        rolled_over: Mutex::new(false),
        token_delay: Mutex::new(Duration::ZERO),
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
    *s.discovery_hits.lock().unwrap() += 1;
    if *s.discovery_down.lock().unwrap() {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, json!({}));
    }
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
    let key = if *s.rolled_over.lock().unwrap() {
        &s.other_key
    } else {
        &s.key
    };
    let jwk: CoreJsonWebKey = key.as_verification_key();
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
    let delay = *s.token_delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let grant = field(&form, "grant_type").unwrap_or_default().to_owned();
    if !client_authenticated(&form) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "invalid_client" }),
        );
    }
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
    let claims = openidconnect::IdTokenClaims::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        vec![Audience::new(audience.into())],
        now_plus(3600),
        now_plus(0),
        StandardClaims::new(SubjectIdentifier::new("user-subject".into()))
            .set_name(Some(name))
            .set_preferred_username(Some(EndUserUsername::new("alex@example.com".into()))),
        keyring::auth::oidc::EntraClaims {
            oid: Some(USER_OID.into()),
            tid: Some(TENANT.into()),
        },
    )
    .set_nonce(Some(Nonce::new(nonce)));
    let rolled = *s.rolled_over.lock().unwrap();
    let key = match behaviour {
        TokenBehaviour::WrongKey if rolled => &s.key,
        TokenBehaviour::WrongKey => &s.other_key,
        _ if rolled => &s.other_key,
        _ => &s.key,
    };
    let id_token = EntraIdToken::new(
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

/// How the app proves who it is: the client secret, or the managed
/// identity's assertion with its type. A request that carries both, or a
/// half of the assertion, is refused, as Entra does.
fn client_authenticated(form: &[(String, String)]) -> bool {
    let secret = field(form, "client_secret");
    let assertion = field(form, "client_assertion");
    let assertion_type = field(form, "client_assertion_type");
    match (secret, assertion) {
        (Some(s), None) => s == CLIENT_SECRET && assertion_type.is_none(),
        (None, Some(a)) => a == MI_ASSERTION && assertion_type == Some(ASSERTION_TYPE),
        _ => false,
    }
}

/// On-behalf-of and refresh grants. Tokens encode what they were issued for,
/// so tests can see which token reached the mock Azure API.
fn other_grant(s: &IdpState, form: &[(String, String)], grant: &str) -> Response {
    if let Some((error, code)) = *s.grant_error.lock().unwrap() {
        let mut body =
            json!({ "error": error, "error_codes": [code], "error_description": "test" });
        if error == "interaction_required" {
            body["claims"] =
                json!(r#"{"access_token":{"capolids":{"essential":true,"values":["policy-1"]}}}"#);
        }
        return json_response(StatusCode::BAD_REQUEST, body);
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
pub(crate) fn signed_in_app(config: Config) -> (keyring::AppState, axum::Router, String) {
    use keyring::auth::session::{User, UserTokens};
    use keyring::secret::Secret;
    let state = keyring::AppState::new(config);
    let id = state.sessions.create(
        User {
            name: "Alex Example".into(),
            username: Some("alex@example.com".into()),
            subject: keyring::auth::session::UserId {
                sub: "sub".into(),
                oid: Some(USER_OID.into()),
                tid: Some(TENANT.into()),
            },
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
pub(crate) struct MockArm {
    pub addr: SocketAddr,
    pub state: Arc<ArmState>,
}

pub(crate) struct ArmState {
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
    /// Diagnostic settings returned for any vault. `None` means 403.
    pub diagnostics: Mutex<Option<serde_json::Value>>,
    /// The path of each diagnostic settings request, which names the vault.
    pub diagnostics_paths: Mutex<Vec<String>>,
    /// Log Analytics rows returned: (time, who, operation, item, result, ip).
    pub audit_rows: Mutex<Vec<[String; 6]>>,
    /// Make Log Analytics answer 403.
    pub audit_forbidden: Mutex<bool>,
    /// Status to answer for one workspace, keyed by the end of its
    /// resource ID (for example `/workspaces/logs-b`).
    pub audit_fail_workspace: Mutex<Vec<(String, u16)>>,
    /// KQL queries received.
    pub audit_queries: Mutex<Vec<String>>,
    pub audit_bearers: Mutex<Vec<String>>,
}

impl MockArm {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

pub(crate) fn vault_row(name: &str, sub: &str, rbac: bool) -> serde_json::Value {
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

pub(crate) async fn start_arm() -> MockArm {
    let state = Arc::new(ArmState {
        vaults: Mutex::new(Vec::new()),
        subscriptions: Mutex::new(Vec::new()),
        page_size: Mutex::new(1000),
        fail: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        bearers: Mutex::new(Vec::new()),
        diagnostics: Mutex::new(Some(json!({"value": []}))),
        diagnostics_paths: Mutex::new(Vec::new()),
        audit_rows: Mutex::new(Vec::new()),
        audit_forbidden: Mutex::new(false),
        audit_fail_workspace: Mutex::new(Vec::new()),
        audit_queries: Mutex::new(Vec::new()),
        audit_bearers: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route(
            "/providers/Microsoft.ResourceGraph/resources",
            post(resource_graph),
        )
        .fallback(arm_fallback)
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

/// Diagnostic settings (GET .../providers/Microsoft.Insights/diagnosticSettings)
/// and the Log Analytics query API (POST /v1/<workspace id>/query) share this
/// mock server.
async fn arm_fallback(
    State(s): State<Arc<ArmState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let path = uri.path().to_owned();
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if method == axum::http::Method::GET
        && path.ends_with("/providers/Microsoft.Insights/diagnosticSettings")
    {
        s.bearers.lock().unwrap().push(bearer);
        s.diagnostics_paths.lock().unwrap().push(path.clone());
        return match s.diagnostics.lock().unwrap().clone() {
            Some(v) => json_response(StatusCode::OK, v),
            None => json_response(
                StatusCode::FORBIDDEN,
                json!({"error": {"code": "AuthorizationFailed", "message": "x"}}),
            ),
        };
    }
    if method == axum::http::Method::POST && path.starts_with("/v1/") && path.ends_with("/query") {
        s.audit_bearers.lock().unwrap().push(bearer);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        s.audit_queries
            .lock()
            .unwrap()
            .push(body["query"].as_str().unwrap_or_default().to_owned());
        let one_fails = s
            .audit_fail_workspace
            .lock()
            .unwrap()
            .iter()
            .find(|(ws, _)| path.ends_with(&format!("{ws}/query")))
            .map(|(_, status)| *status);
        if let Some(status) = one_fails {
            let code = if status == 403 {
                "InsufficientAccessError"
            } else {
                "ServiceError"
            };
            return json_response(
                StatusCode::from_u16(status).unwrap(),
                json!({"error": {"code": code, "message": "x"}}),
            );
        }
        if *s.audit_forbidden.lock().unwrap() {
            return json_response(
                StatusCode::FORBIDDEN,
                json!({"error": {"code": "InsufficientAccessError", "message": "x"}}),
            );
        }
        let rows: Vec<serde_json::Value> = s
            .audit_rows
            .lock()
            .unwrap()
            .iter()
            .map(|r| json!(r))
            .collect();
        return json_response(
            StatusCode::OK,
            json!({"tables": [{"name": "PrimaryResult", "columns": [
                {"name": "TimeGenerated", "type": "datetime"}, {"name": "Who", "type": "string"},
                {"name": "OperationName", "type": "string"}, {"name": "Item", "type": "string"},
                {"name": "ResultSignature", "type": "string"}, {"name": "CallerIpAddress", "type": "string"}
            ], "rows": rows}]}),
        );
    }
    json_response(
        StatusCode::NOT_FOUND,
        json!({"error": {"code": "NotFound", "message": "x"}}),
    )
}

pub(crate) fn audit_settings(dedicated: bool) -> serde_json::Value {
    json!({"value": [{"properties": {
        "workspaceId": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs",
        "logAnalyticsDestinationType": if dedicated { json!("Dedicated") } else { json!(null) },
        "logs": [{"categoryGroup": "audit", "enabled": true}]
    }}]})
}

/// Config pointing sign-in at `idp` and ARM at `arm`.
pub(crate) fn config_with_arm(idp: &MockIdp, arm: &MockArm) -> Config {
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
pub(crate) struct World {
    pub app: axum::Router,
    pub state: keyring::AppState,
    pub cookie: String,
    pub csrf: String,
    pub kv: keyvault::MockKeyVault,
    pub arm: MockArm,
    pub idp: MockIdp,
}

pub(crate) async fn world_with(extra: &[(&'static str, &'static str)]) -> World {
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
            ("KEYRING_TEST_LOGANALYTICS_URL", arm.url()),
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
    let csrf = session.csrf_token();
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

pub(crate) async fn world() -> World {
    world_with(&[]).await
}

impl World {
    pub(crate) async fn get(&self, path: &str) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let req = axum::http::Request::get(path)
            .header("cookie", &self.cookie)
            .body(axum::body::Body::empty())
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// POST a form. `csrf` is added automatically.
    pub(crate) async fn post(
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
            .header("origin", "http://localhost:3000")
            .header("cookie", &self.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// GET and return status and body text.
    pub(crate) async fn page(&self, path: &str) -> (StatusCode, String) {
        let res = self.get(path).await;
        let status = res.status();
        (status, body_text(res).await)
    }
}

pub(crate) async fn body_text(res: axum::http::Response<axum::body::Body>) -> String {
    use http_body_util::BodyExt;
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

pub(crate) fn location(res: &axum::http::Response<axum::body::Body>) -> String {
    res.headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

/// The test certificate (public part only), shared with the unit tests.
pub(crate) const TEST_CERT_PEM: &str = include_str!("../fixtures/test-cert.pem");

/// First CERTIFICATE block in a PEM string, decoded.
pub(crate) fn pem_first_cert(pem: &str) -> Option<Vec<u8>> {
    keyring::x509::pem_blocks(pem, "CERTIFICATE")
        .into_iter()
        .next()
}

/// One part of a multipart form.
pub(crate) enum Part<'a> {
    Text(&'a str, &'a str),
    File(&'a str, &'a str, &'a [u8]),
}

impl World {
    /// POST a multipart form. `csrf` is added automatically.
    pub(crate) async fn post_multipart(
        &self,
        path: &str,
        parts: &[Part<'_>],
    ) -> axum::http::Response<axum::body::Body> {
        self.post_multipart_with_csrf(&self.csrf, path, parts).await
    }

    /// POST a multipart form with a given form token.
    pub(crate) async fn post_multipart_with_csrf(
        &self,
        csrf: &str,
        path: &str,
        parts: &[Part<'_>],
    ) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let boundary = "keyringtestboundary7d1f";
        let mut body: Vec<u8> = Vec::new();
        let push_text = |name: &str, value: &str, body: &mut Vec<u8>| {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
        };
        push_text("csrf", csrf, &mut body);
        for p in parts {
            match p {
                Part::Text(n, v) => push_text(n, v, &mut body),
                Part::File(n, file_name, bytes) => {
                    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{n}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
                    body.extend_from_slice(bytes);
                    body.extend_from_slice(b"\r\n");
                }
            }
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = axum::http::Request::post(path)
            .header("origin", "http://localhost:3000")
            .header("cookie", &self.cookie)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(axum::body::Body::from(body))
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }
}

/// Pull `name="field" value="..."` out of a page.
pub(crate) fn hidden_value(html: &str, field: &str) -> Option<String> {
    let marker = format!("name=\"{field}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_owned())
}
