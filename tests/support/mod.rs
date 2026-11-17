//! Shared test helpers: a config and a mock Entra ID.

#![allow(dead_code)]

pub(crate) mod certs;
pub(crate) mod ingestion;
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
/// What the mock token service hands out for `https://monitor.azure.com`.
/// The mock ingestion endpoint accepts nothing else.
pub(crate) const MI_MONITOR_TOKEN: &str = "mi-monitor-token";
pub(crate) const MONITOR_RESOURCE: &str = "https://monitor.azure.com";
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
    /// The `resource` of each request that passed the checks, in order.
    pub resources: Mutex<Vec<String>>,
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
        resources: Mutex::new(Vec::new()),
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
    // Only the two resources Keyring's identity is ever used for.
    let resource = q.get("resource").cloned().unwrap_or_default();
    let token = match resource.as_str() {
        "api://AzureADTokenExchange" => MI_ASSERTION,
        MONITOR_RESOURCE => MI_MONITOR_TOKEN,
        _ => return json_response(StatusCode::BAD_REQUEST, json!({})),
    };
    let query_ok = q.get("api-version").map(String::as_str) == Some("2019-08-01")
        && q.get("client_id").map(String::as_str) == Some(IDENTITY_CLIENT_ID);
    if !query_ok {
        return json_response(StatusCode::BAD_REQUEST, json!({}));
    }
    *s.calls.lock().unwrap() += 1;
    s.resources.lock().unwrap().push(resource.clone());
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
            "access_token": token,
            "expires_on": expires_on.to_string(),
            "resource": resource,
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
    /// Return an OAuth error with an `AADSTS` number in its description,
    /// as Entra does.
    ErrorWithCode(&'static str, u64),
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
    /// Sign the next person in as this object ID and user name, instead of
    /// [`USER_OID`] and alex@example.com.
    pub user: Mutex<Option<(&'static str, &'static str)>>,
    /// `acrs` in the next ID tokens: authentication contexts met. `None`
    /// leaves the claim out, as Entra does when none was asked for.
    pub acrs: Mutex<Option<Vec<String>>>,
    /// `auth_time` in the next ID tokens, Unix seconds. `None` leaves it out.
    pub auth_time: Mutex<Option<i64>>,
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
        user: Mutex::new(None),
        acrs: Mutex::new(None),
        auth_time: Mutex::new(None),
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
    if let TokenBehaviour::ErrorWithCode(code, n) = behaviour {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": code, "error_codes": [n], "error_description": format!("AADSTS{n}: test") }),
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
    let (oid, upn) = s
        .user
        .lock()
        .unwrap()
        .unwrap_or((USER_OID, "alex@example.com"));
    let mut name = LocalizedClaim::new();
    name.insert(None, EndUserName::new("Alex Example".into()));
    let claims = openidconnect::IdTokenClaims::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        vec![Audience::new(audience.into())],
        now_plus(3600),
        now_plus(0),
        StandardClaims::new(SubjectIdentifier::new("user-subject".into()))
            .set_name(Some(name))
            .set_preferred_username(Some(EndUserUsername::new(upn.into()))),
        keyring::auth::oidc::EntraClaims {
            oid: Some(oid.into()),
            tid: Some(TENANT.into()),
            acrs: s.acrs.lock().unwrap().clone(),
        },
    )
    .set_nonce(Some(Nonce::new(nonce)))
    .set_auth_time(
        s.auth_time
            .lock()
            .unwrap()
            .and_then(|t| DateTime::from_timestamp(t, 0)),
    );
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
    signed_in_app_with(config, None)
}

fn signed_in_app_with(
    config: Config,
    limits: Option<keyring::azure::fanout::Limits>,
) -> (keyring::AppState, axum::Router, String) {
    use keyring::auth::session::{User, UserTokens};
    use keyring::secret::Secret;
    let mut state = keyring::AppState::new(config);
    if let Some(limits) = limits {
        state.fanout = limits;
    }
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
    /// Diagnostic settings for one vault by name, in place of
    /// `diagnostics`. `None` means 403 for that vault.
    pub diagnostics_by_vault: Mutex<std::collections::HashMap<String, Option<serde_json::Value>>>,
    /// Log Analytics rows returned: (time, who, operation, item, result, ip).
    pub audit_rows: Mutex<Vec<[String; 6]>>,
    /// Make Log Analytics answer 403.
    pub audit_forbidden: Mutex<bool>,
    /// Status to answer for one workspace, keyed by the end of its
    /// resource ID (for example `/workspaces/logs-b`). 400 answers the way
    /// Log Analytics does when the queried table doesn't exist yet.
    pub audit_fail_workspace: Mutex<Vec<(String, u16)>>,
    /// Answer "used by" queries with Log Analytics' `PartialError`.
    pub used_by_partial: Mutex<bool>,
    /// With `used_by_partial`, also leave out the vault's count row, as a
    /// cut-short answer can.
    pub used_by_no_summary: Mutex<bool>,
    /// KQL queries received.
    pub audit_queries: Mutex<Vec<String>>,
    /// The path of each Log Analytics query, which names the workspace.
    pub audit_paths: Mutex<Vec<String>>,
    /// Diagnostic settings for one vault, keyed by its name. Takes the
    /// place of `diagnostics` for that vault. `None` means 403.
    pub diagnostics_for: Mutex<Vec<(String, Option<serde_json::Value>)>>,
    /// Raw audit events in each workspace, keyed by the end of its
    /// resource ID (`/workspaces/logs`), for the reports across vaults.
    /// See [`answer_report`].
    pub workspace_events: Mutex<Vec<(String, Vec<RawEvent>)>>,
    /// Workspaces that answer only after this long, keyed like
    /// `workspace_events`.
    pub workspace_delay: Mutex<Vec<(String, Duration)>>,
    pub audit_bearers: Mutex<Vec<String>>,
    /// Rows of `KeyringAudit_CL` the Log Analytics mock answers with, as
    /// column name and value pairs.
    pub keyring_rows: Mutex<Vec<Vec<(&'static str, serde_json::Value)>>>,
    /// Answer `KeyringAudit_CL` queries with a `PartialError` beside the rows.
    pub keyring_partial: Mutex<bool>,
    /// Access (role assignments, eligibility, role definitions and the
    /// vault resource). See [`AuthzMock`].
    pub authz: Mutex<AuthzMock>,
}

/// What the mock ARM answers for the Access reads. Like ARM, the
/// assignment lists come back whatever their scope (at, above and below
/// the one asked for), so Keyring has to keep the ones that reach it.
#[derive(Default)]
pub(crate) struct AuthzMock {
    /// Active role assignments: (scope, role GUID, principal ID, type).
    pub assignments: Vec<(String, String, String, String)>,
    /// PIM eligible assignments, the same shape.
    pub eligible: Vec<(String, String, String, String)>,
    /// Role definitions by GUID: (role name, data actions).
    pub roles: std::collections::HashMap<String, (String, Vec<String>)>,
    /// Access policies by vault name, for `GET {vault ID}`. A vault's RBAC
    /// flag comes from its Resource Graph row.
    pub policies: std::collections::HashMap<String, serde_json::Value>,
    /// Answer 403 to role assignments.
    pub assignments_forbidden: bool,
    /// Answer this status to eligibility, as a tenant without PIM might.
    pub eligible_status: Option<u16>,
    /// Answer this status to every role definition read.
    pub definitions_status: Option<u16>,
    /// Answer 403 to the vault resource.
    pub vault_forbidden: bool,
    /// The signed-in person's own permissions, for
    /// `{scope}/providers/Microsoft.Authorization/permissions` at any
    /// scope: one (dataActions, notDataActions) pair per role. `None`
    /// answers 403, so tests that don't set it see every button enabled.
    pub permissions: Option<Vec<RolePerms>>,
    /// Permissions at one scope (compared without regard to case), in
    /// place of `permissions` there.
    pub permissions_at: Vec<(String, Vec<RolePerms>)>,
    /// Answer this status to every `permissions` read.
    pub permissions_status: Option<u16>,
    /// Answer `permissions` with a body Keyring can't read.
    pub permissions_garbled: bool,
    /// Wait this long before answering a `permissions` read.
    pub permissions_delay: Duration,
    /// Wait this long before answering any Access read.
    pub delay: Duration,
    /// Path of every Access read, in order.
    pub paths: Vec<String>,
    /// Bearer token of every Access read.
    pub bearers: Vec<String>,
    /// PIM for the signed-in person. See [`PimMock`].
    pub pim: PimMock,
}

/// What mock ARM answers for PIM, for the signed-in person (`asTarget()`).
/// Every list answers 400 `InvalidResourceType`-style errors when
/// `status` is set, as a tenant without PIM might.
#[derive(Default)]
pub(crate) struct PimMock {
    /// Eligible: (scope, role GUID, schedule ID).
    pub eligible: Vec<(String, String, String)>,
    /// Active: (scope, role GUID, `Activated` or `Assigned`, end time).
    pub active: Vec<(String, String, String, Option<String>)>,
    /// Requests waiting: (scope, role GUID, status).
    pub pending: Vec<(String, String, String)>,
    /// Policy rules by role GUID: `effectiveRules`.
    pub policies: std::collections::HashMap<String, serde_json::Value>,
    /// `startDateTime` of each active one, by position. Left out when
    /// there is no entry.
    pub active_starts: Vec<Option<String>>,
    /// `startDateTime` of every eligibility. Left out when `None`.
    pub eligible_start: Option<String>,
    /// Answer this status to the eligibility list.
    pub eligible_status: Option<u16>,
    /// Answer this status to the request list (`asRequestor()`).
    pub pending_status: Option<u16>,
    /// Return this as every eligibility's `roleDefinitionId`, in place of
    /// a well-formed one.
    pub eligible_role_id: Option<String>,
    /// Answer this status to the policy list.
    pub policy_status: Option<u16>,
    /// Wait this long before answering the eligibility list.
    pub eligible_delay: Duration,
    /// What a PUT of a schedule request answers: a status, and a body.
    /// `None` answers 201 with `status` `Provisioned`.
    pub reply: Option<(u16, serde_json::Value)>,
    /// Every PUT body received, with its path.
    pub requests: Vec<(String, serde_json::Value)>,
    /// Paths of every PIM read.
    pub reads: Vec<String>,
}

/// One PIM end-user rule set: maximum, and which of justification,
/// ticket, MFA and approval PIM asks for.
pub(crate) fn pim_rules(
    max: &str,
    justification: bool,
    ticket: bool,
    approval: bool,
) -> serde_json::Value {
    let mut enabled = vec![];
    if justification {
        enabled.push("Justification");
    }
    if ticket {
        enabled.push("Ticketing");
    }
    let target = json!({"caller": "EndUser", "operations": ["All"], "level": "Assignment"});
    json!([
        {"isExpirationRequired": true, "maximumDuration": "P90D", "id": "Expiration_Admin_Assignment",
         "ruleType": "RoleManagementPolicyExpirationRule", "target": {"caller": "Admin", "operations": ["All"], "level": "Assignment"}},
        {"isExpirationRequired": true, "maximumDuration": max, "id": "Expiration_EndUser_Assignment",
         "ruleType": "RoleManagementPolicyExpirationRule", "target": target},
        {"enabledRules": enabled, "id": "Enablement_EndUser_Assignment",
         "ruleType": "RoleManagementPolicyEnablementRule", "target": target},
        {"setting": {"isApprovalRequired": approval, "approvalStages": [{"primaryApprovers": [
            {"id": "2385b0f3-5fa9-43cf-8ca4-b01dc97298cd", "description": "kv-approvers", "isBackup": false, "userType": "Group"}]}]},
         "id": "Approval_EndUser_Assignment", "ruleType": "RoleManagementPolicyApprovalRule", "target": target},
        {"isEnabled": false, "claimValue": "", "id": "AuthenticationContext_EndUser_Assignment",
         "ruleType": "RoleManagementPolicyAuthenticationContextRule", "target": target}
    ])
}

/// PIM's reads and requests, or `None` if `path` isn't one.
async fn pim_answer(
    s: &ArmState,
    method: &axum::http::Method,
    path: &str,
    query: &str,
    body: &str,
) -> Option<Response> {
    const ELIGIBLE: &str = "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances";
    const ACTIVE: &str = "/providers/Microsoft.Authorization/roleAssignmentScheduleInstances";
    const REQUESTS: &str = "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests";
    const POLICIES: &str = "/providers/Microsoft.Authorization/roleManagementPolicyAssignments";
    let pim_read = (path.ends_with(ELIGIBLE) && query.contains("asTarget()"))
        || path.ends_with(ACTIVE)
        || path.ends_with(REQUESTS)
        || path.ends_with(POLICIES);
    let pim_put = *method == axum::http::Method::PUT && path.contains(&format!("{REQUESTS}/"));
    if !(pim_read || pim_put) {
        return None;
    }
    assert!(query.contains("api-version=2020-10-01"), "{query}");
    let err = |status: u16, code: &str| {
        json_response(
            StatusCode::from_u16(status).unwrap(),
            json!({"error": {"code": code, "message": "private Azure detail"}}),
        )
    };
    if pim_put {
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        let mut m = s.authz.lock().unwrap();
        m.pim.requests.push((path.to_owned(), body.clone()));
        return Some(match m.pim.reply.clone() {
            Some((status, reply)) => json_response(StatusCode::from_u16(status).unwrap(), reply),
            None => json_response(
                StatusCode::CREATED,
                json!({"properties": {"status": "Provisioned", "requestType": body["properties"]["requestType"]}}),
            ),
        });
    }
    let delay = {
        let mut m = s.authz.lock().unwrap();
        m.pim.reads.push(path.to_owned());
        if path.ends_with(ELIGIBLE) {
            m.pim.eligible_delay
        } else {
            Duration::ZERO
        }
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let m = s.authz.lock().unwrap();
    let role_id = |g: &str| {
        format!("/subscriptions/sub-a/providers/Microsoft.Authorization/roleDefinitions/{g}")
    };
    if path.ends_with(ELIGIBLE) {
        if let Some(status) = m.pim.eligible_status {
            return Some(err(status, "InvalidResourceType"));
        }
        let value: Vec<_> = m.pim.eligible.iter().map(|(scope, g, sched)| {
            let mut v = json!({"properties": {
            "scope": scope, "roleDefinitionId": m.pim.eligible_role_id.clone().unwrap_or_else(|| role_id(g)), "principalId": USER_OID, "principalType": "User",
            "status": "Provisioned", "roleEligibilityScheduleId": sched, "memberType": "Direct",
            "endDateTime": "2027-09-10T00:31:41.477Z"}});
            if let Some(start) = &m.pim.eligible_start {
                v["properties"]["startDateTime"] = json!(start);
            }
            v
        }).collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if path.ends_with(ACTIVE) {
        assert!(query.contains("asTarget()"), "{query}");
        let value: Vec<_> = m.pim.active.iter().enumerate().map(|(i, (scope, g, kind, end))| {
            let mut v = json!({"properties": {
            "scope": scope, "roleDefinitionId": role_id(g), "principalId": USER_OID, "assignmentType": kind,
            "status": "Provisioned", "endDateTime": end}});
            if let Some(Some(start)) = m.pim.active_starts.get(i) {
                v["properties"]["startDateTime"] = json!(start);
            }
            v
        }).collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if path.ends_with(REQUESTS) {
        assert!(query.contains("asRequestor()"), "{query}");
        if let Some(status) = m.pim.pending_status {
            return Some(err(status, "AuthorizationFailed"));
        }
        let value: Vec<_> = m.pim.pending.iter().map(|(scope, g, status)| json!({"properties": {
            "scope": scope, "roleDefinitionId": role_id(g), "requestType": "SelfActivate", "status": status}})).collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if let Some(status) = m.pim.policy_status {
        return Some(err(status, "AuthorizationFailed"));
    }
    let value: Vec<_> = m.pim.policies.iter().map(|(g, rules)| json!({"properties": {
        "scope": path.trim_end_matches(POLICIES), "roleDefinitionId": role_id(g), "effectiveRules": rules}})).collect();
    Some(json_response(StatusCode::OK, json!({"value": value})))
}

pub(crate) const SECRETS_USER: &str = "4633458b-17de-408a-b874-0445c86b69e6";
pub(crate) const OWNER_ROLE: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
pub(crate) const READER_ROLE: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
pub(crate) const CERT_OFFICER: &str = "a4417e6f-fecd-4de8-b567-7b0420556985";

/// One role's (dataActions, notDataActions).
pub(crate) type RolePerms = (Vec<String>, Vec<String>);

/// Data actions of built-in roles, as Microsoft defines them, for
/// [`AuthzMock::permissions`].
pub(crate) fn role_data_actions(role: &str) -> RolePerms {
    let actions: &[&str] = match role {
        "Key Vault Reader" => &[
            "Microsoft.KeyVault/vaults/*/read",
            "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        ],
        "Key Vault Secrets User" => &[
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        ],
        "Key Vault Secrets Officer" => &["Microsoft.KeyVault/vaults/secrets/*"],
        "Key Vault Certificates Officer" => &[
            "Microsoft.KeyVault/vaults/certificatecas/*",
            "Microsoft.KeyVault/vaults/certificates/*",
            "Microsoft.KeyVault/vaults/certificatecontacts/write",
        ],
        "Key Vault Crypto Officer" => &[
            "Microsoft.KeyVault/vaults/keys/*",
            "Microsoft.KeyVault/vaults/keyrotationpolicies/*",
        ],
        "Key Vault Administrator" => &["Microsoft.KeyVault/vaults/*"],
        other => panic!("no data actions for {other}"),
    };
    (
        actions.iter().map(|a| (*a).to_owned()).collect(),
        Vec::new(),
    )
}

impl AuthzMock {
    /// The built-in roles the tests use.
    pub(crate) fn with_builtin_roles() -> Self {
        let mut m = Self::default();
        for (g, name, actions) in [
            (
                SECRETS_USER,
                "Key Vault Secrets User",
                vec![
                    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
                    "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
                ],
            ),
            (OWNER_ROLE, "Owner", vec![]),
            (READER_ROLE, "Reader", vec![]),
            (
                CERT_OFFICER,
                "Key Vault Certificates Officer",
                vec!["Microsoft.KeyVault/vaults/certificates/*"],
            ),
        ] {
            m.roles.insert(
                g.into(),
                (name.into(), actions.into_iter().map(String::from).collect()),
            );
        }
        m
    }
}

fn assignment_json(kind: &str, a: &(String, String, String, String)) -> serde_json::Value {
    json!({
        "id": format!("{}/providers/Microsoft.Authorization/{kind}/{}", a.0, a.2),
        "properties": {
            "scope": a.0,
            "roleDefinitionId": format!("/subscriptions/sub-a/providers/Microsoft.Authorization/roleDefinitions/{}", a.1),
            "principalId": a.2,
            "principalType": a.3,
        }
    })
}

/// The Access reads, or `None` if `path` isn't one.
async fn authz_answer(s: &ArmState, path: &str, query: &str, bearer: String) -> Option<Response> {
    const ASSIGN: &str = "/providers/Microsoft.Authorization/roleAssignments";
    const ELIGIBLE: &str = "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances";
    const DEFS: &str = "/providers/Microsoft.Authorization/roleDefinitions/";
    const PERMS: &str = "/providers/Microsoft.Authorization/permissions";
    let is_vault = path.contains("/providers/Microsoft.KeyVault/vaults/")
        && path
            .rsplit("/vaults/")
            .next()
            .is_some_and(|n| !n.contains('/'));
    if !(path.ends_with(ASSIGN)
        || path.ends_with(ELIGIBLE)
        || path.contains(DEFS)
        || path.ends_with(PERMS)
        || is_vault)
    {
        return None;
    }
    let delay = {
        let mut m = s.authz.lock().unwrap();
        m.paths.push(path.to_owned());
        m.bearers.push(bearer);
        if path.ends_with(PERMS) {
            m.delay + m.permissions_delay
        } else {
            m.delay
        }
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let forbidden = || {
        json_response(
            StatusCode::FORBIDDEN,
            json!({"error": {"code": "AuthorizationFailed", "message": "x"}}),
        )
    };
    let m = s.authz.lock().unwrap();
    if let Some(scope) = path.strip_suffix(PERMS) {
        assert!(query.contains("api-version=2022-04-01"), "{query}");
        if let Some(status) = m.permissions_status {
            return Some(json_response(
                StatusCode::from_u16(status).unwrap(),
                json!({"error": {"code": "AuthorizationFailed", "message": "x"}}),
            ));
        }
        if m.permissions_garbled {
            return Some(json_response(
                StatusCode::OK,
                json!({"value": "not a list"}),
            ));
        }
        let sets = m
            .permissions_at
            .iter()
            .find(|(at, _)| at.eq_ignore_ascii_case(scope))
            .map(|(_, sets)| sets)
            .or(m.permissions.as_ref());
        let Some(sets) = sets else {
            return Some(forbidden());
        };
        let value: Vec<_> = sets
            .iter()
            .map(|(data, not)| {
                json!({"actions": ["Microsoft.KeyVault/vaults/*/read"], "notActions": [],
                       "dataActions": data, "notDataActions": not})
            })
            .collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if path.ends_with(ASSIGN) {
        assert!(query.contains("api-version=2022-04-01"), "{query}");
        if m.assignments_forbidden {
            return Some(forbidden());
        }
        let value: Vec<_> = m
            .assignments
            .iter()
            .map(|a| assignment_json("roleAssignments", a))
            .collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if path.ends_with(ELIGIBLE) {
        assert!(query.contains("atScope()"), "{query}");
        if let Some(status) = m.eligible_status {
            return Some(json_response(
                StatusCode::from_u16(status).unwrap(),
                json!({"error": {"code": "AuthorizationFailed", "message": "x"}}),
            ));
        }
        let value: Vec<_> = m
            .eligible
            .iter()
            .map(|a| assignment_json("roleEligibilityScheduleInstances", a))
            .collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    if let Some((_, guid)) = path.split_once(DEFS) {
        if let Some(status) = m.definitions_status {
            return Some(json_response(
                StatusCode::from_u16(status).unwrap(),
                json!({"error": {"code": "AuthorizationFailed", "message": "x"}}),
            ));
        }
        return Some(match m.roles.get(guid) {
            Some((name, actions)) => json_response(
                StatusCode::OK,
                json!({"name": guid, "properties": {"roleName": name, "permissions": [{"actions": [], "dataActions": actions}]}}),
            ),
            None => json_response(
                StatusCode::NOT_FOUND,
                json!({"error": {"code": "RoleDefinitionDoesNotExist", "message": "x"}}),
            ),
        });
    }
    assert!(query.contains("api-version=2023-07-01"), "{query}");
    if m.vault_forbidden {
        return Some(forbidden());
    }
    let name = path.rsplit("/vaults/").next().unwrap_or_default();
    let row = s
        .vaults
        .lock()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .cloned()?;
    Some(json_response(
        StatusCode::OK,
        json!({"id": row["id"], "name": name, "properties": {
            "enableRbacAuthorization": row["enableRbacAuthorization"],
            "accessPolicies": m.policies.get(name).cloned().unwrap_or(json!([])),
        }}),
    ))
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
        diagnostics_by_vault: Mutex::new(std::collections::HashMap::new()),
        audit_rows: Mutex::new(Vec::new()),
        audit_forbidden: Mutex::new(false),
        audit_fail_workspace: Mutex::new(Vec::new()),
        used_by_partial: Mutex::new(false),
        used_by_no_summary: Mutex::new(false),
        audit_queries: Mutex::new(Vec::new()),
        audit_paths: Mutex::new(Vec::new()),
        diagnostics_for: Mutex::new(Vec::new()),
        workspace_events: Mutex::new(Vec::new()),
        workspace_delay: Mutex::new(Vec::new()),
        audit_bearers: Mutex::new(Vec::new()),
        keyring_rows: Mutex::new(Vec::new()),
        keyring_partial: Mutex::new(false),
        authz: Mutex::new(AuthzMock::with_builtin_roles()),
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
    if let Some(res) = pim_answer(&s, &method, &path, uri.query().unwrap_or_default(), &body).await
    {
        return res;
    }
    if method == axum::http::Method::GET
        && let Some(res) =
            authz_answer(&s, &path, uri.query().unwrap_or_default(), bearer.clone()).await
    {
        return res;
    }
    if method == axum::http::Method::GET
        && path.ends_with("/providers/Microsoft.Insights/diagnosticSettings")
    {
        s.bearers.lock().unwrap().push(bearer);
        s.diagnostics_paths.lock().unwrap().push(path.clone());
        // Per-vault settings win over the shared ones: `diagnostics_for`
        // (audit across vaults) first, then `diagnostics_by_vault` (vault
        // health).
        let vault = path
            .split("/vaults/")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or_default()
            .to_owned();
        let own = s
            .diagnostics_for
            .lock()
            .unwrap()
            .iter()
            .find(|(v, _)| *v == vault)
            .map(|(_, d)| d.clone())
            .or_else(|| s.diagnostics_by_vault.lock().unwrap().get(&vault).cloned());
        return match own.unwrap_or_else(|| s.diagnostics.lock().unwrap().clone()) {
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
        let query = body["query"].as_str().unwrap_or_default().to_owned();
        s.audit_queries.lock().unwrap().push(query.clone());
        s.audit_paths.lock().unwrap().push(path.clone());
        let wait = s
            .workspace_delay
            .lock()
            .unwrap()
            .iter()
            .find(|(ws, _)| path.ends_with(&format!("{ws}/query")))
            .map(|(_, d)| *d);
        if let Some(wait) = wait {
            tokio::time::sleep(wait).await;
        }
        let one_fails = s
            .audit_fail_workspace
            .lock()
            .unwrap()
            .iter()
            .find(|(ws, _)| path.ends_with(&format!("{ws}/query")))
            .map(|(_, status)| *status);
        if one_fails == Some(400) {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"code": "BadArgumentError", "message": "x",
                    "innererror": {"code": "SemanticError",
                        "message": "'where' operator: Failed to resolve table or column expression named 'AZKVAuditLogs'",
                        "innererror": {"code": "SEM0100", "message": "x"}}}}),
            );
        }
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
        if query.contains("| summarize Reads = count(), LastRead = max(TimeGenerated)") {
            let events = s
                .workspace_events
                .lock()
                .unwrap()
                .iter()
                .find(|(ws, _)| path.ends_with(&format!("{ws}/query")))
                .map(|(_, e)| e.clone())
                .unwrap_or_default();
            let mut answer = answer_used_by(&query, &events);
            if *s.used_by_partial.lock().unwrap() {
                answer["error"] = json!({"code": "PartialError", "message": "x"});
                if *s.used_by_no_summary.lock().unwrap() {
                    answer["tables"][0]["rows"].as_array_mut().unwrap().pop();
                }
            }
            return json_response(StatusCode::OK, answer);
        }
        if query.contains("\nKeyringAudit_CL\n") {
            let mut answer = answer_keyring(&query, &s.keyring_rows.lock().unwrap());
            if *s.keyring_partial.lock().unwrap() {
                answer["error"] = json!({"code": "PartialError", "message": "x"});
            }
            return json_response(StatusCode::OK, answer);
        }
        if query.starts_with("let vault0 = ") {
            let events = s
                .workspace_events
                .lock()
                .unwrap()
                .iter()
                .find(|(ws, _)| path.ends_with(&format!("{ws}/query")))
                .map(|(_, e)| e.clone())
                .unwrap_or_default();
            return json_response(StatusCode::OK, answer_report(&query, &events));
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

/// Answer a query over `KeyringAudit_CL`: the rows whose `Vault` matches
/// the query's `let vaultName`, with the columns it projects.
fn answer_keyring(
    query: &str,
    rows: &[Vec<(&'static str, serde_json::Value)>],
) -> serde_json::Value {
    let vault = query
        .lines()
        .find_map(|l| l.strip_prefix("let vaultName = \""))
        .and_then(|l| l.strip_suffix("\";"))
        .unwrap_or_default()
        .to_owned();
    let columns: Vec<String> = query
        .lines()
        .find_map(|l| l.strip_prefix("| project "))
        .unwrap_or_default()
        .split(", ")
        .map(str::to_owned)
        .collect();
    let out: Vec<serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r.iter().any(|(k, v)| {
                *k == "Vault" && v.as_str().is_some_and(|v| v.eq_ignore_ascii_case(&vault))
            })
        })
        .map(|r| {
            json!(
                columns
                    .iter()
                    .map(|c| r
                        .iter()
                        .find(|(k, _)| k == c)
                        .map(|(_, v)| v.clone())
                        .unwrap_or(serde_json::Value::Null))
                    .collect::<Vec<_>>()
            )
        })
        .collect();
    json!({"tables": [{"name": "PrimaryResult",
        "columns": columns.iter().map(|c| json!({"name": c, "type": "string"})).collect::<Vec<_>>(),
        "rows": out}]})
}

/// One Key Vault audit event as it sits in a workspace, for the mock.
#[derive(Clone, Debug)]
pub(crate) struct RawEvent {
    pub vault_id: String,
    pub time: String,
    pub who: String,
    pub operation: String,
    pub item: String,
    pub status: u16,
    /// The caller's app and object IDs. A person (`who` with an `@`) has
    /// their sign-in name as well.
    pub app_id: String,
    pub object_id: String,
    /// The token was a managed identity's.
    pub managed: bool,
    pub client_info: String,
    pub ip: String,
}

impl RawEvent {
    pub(crate) fn new(
        vault: &str,
        time: &str,
        who: &str,
        op: &str,
        item: &str,
        status: u16,
    ) -> Self {
        Self {
            vault_id: format!(
                "/subscriptions/sub-a/resourceGroups/rg-{vault}/providers/Microsoft.KeyVault/vaults/{vault}"
            ),
            time: time.into(),
            who: who.into(),
            operation: op.into(),
            item: item.into(),
            status,
            app_id: "04b07795-8ddb-461a-bbee-02f9e1bf7b46".into(),
            object_id: format!("oid-{who}"),
            managed: false,
            client_info: "Mozilla/5.0".into(),
            ip: "203.0.113.5".into(),
        }
    }

    /// The same event made by an app, not a person: `who` is empty and
    /// the app ID is `app_id`.
    pub(crate) fn by_app(mut self, app_id: &str, object_id: &str, managed: bool) -> Self {
        self.who = String::new();
        self.app_id = app_id.into();
        self.object_id = object_id.into();
        self.managed = managed;
        self.client_info = "azsdk-net-Security.KeyVault.Secrets/4.6.0".into();
        self.ip = "10.0.0.4".into();
        self
    }

    fn signature(&self) -> &'static str {
        match self.status {
            200..=299 => "OK",
            403 => "Forbidden",
            _ => "Error",
        }
    }
}

/// The string in `let <name> = "...";`, unescaped.
fn let_literal(query: &str, name: &str) -> Option<String> {
    let start = format!("let {name} = \"");
    let line = query.lines().find(|l| l.starts_with(&start))?;
    let lit = line.strip_prefix(&start)?.strip_suffix("\";")?;
    Some(lit.replace("\\\"", "\"").replace("\\\\", "\\"))
}

/// Answer a report query across vaults the way Log Analytics would, for
/// the handful of fixed reports in `src/azure/audit_across.rs`: only the
/// vaults named in the `let vaultN` lines, then each report's own filter,
/// picked out by its fixed text.
pub(crate) fn answer_report(query: &str, events: &[RawEvent]) -> serde_json::Value {
    let vaults: Vec<String> = (0..)
        .map_while(|i| let_literal(query, &format!("vault{i}")))
        .map(|v| v.to_ascii_lowercase())
        .collect();
    let who = let_literal(query, "who").unwrap_or_default();
    let mine: Vec<&RawEvent> = events
        .iter()
        .filter(|e| vaults.contains(&e.vault_id.to_ascii_lowercase()))
        .collect();
    let allowed = |e: &&RawEvent| (200..300).contains(&e.status);
    let picked: Vec<&RawEvent> = if query.contains("summarize Refused = count()") {
        let mut groups: Vec<(String, String, u64, String, Vec<String>)> = Vec::new();
        for e in mine.iter().filter(|e| e.status == 403) {
            match groups
                .iter_mut()
                .find(|g| g.0 == e.vault_id && g.1 == e.who)
            {
                Some(g) => {
                    g.2 += 1;
                    if e.time > g.3 {
                        g.3 = e.time.clone();
                    }
                    if !g.4.contains(&e.operation) {
                        g.4.push(e.operation.clone());
                    }
                }
                None => groups.push((
                    e.vault_id.clone(),
                    e.who.clone(),
                    1,
                    e.time.clone(),
                    vec![e.operation.clone()],
                )),
            }
        }
        groups.sort_by_key(|g| std::cmp::Reverse(g.2));
        let rows: Vec<serde_json::Value> = groups
            .into_iter()
            .map(|(v, w, n, t, ops)| json!([v, w, n, t, ops.join(", ")]))
            .collect();
        return json!({"tables": [{"name": "PrimaryResult", "columns": [
            {"name": "VaultId"}, {"name": "Who"}, {"name": "Refused"}, {"name": "LastSeen"}, {"name": "Operations"}
        ], "rows": rows}]});
    } else if query.contains("join kind=leftsemi certificates") {
        mine.iter()
            .filter(|e| e.operation == "SecretGet" && allowed(e))
            .filter(|e| {
                mine.iter().any(|c| {
                    c.operation.starts_with("Certificate")
                        && c.vault_id == e.vault_id
                        && c.item.eq_ignore_ascii_case(&e.item)
                })
            })
            .copied()
            .collect()
    } else if query.contains("| where OperationName == 'SecretGet'") {
        mine.iter()
            .filter(|e| e.operation == "SecretGet" && allowed(e))
            .copied()
            .collect()
    } else if query.contains("| where OperationName in ('SecretDelete'") {
        mine.iter()
            .filter(|e| {
                ["Delete", "Purge", "Recover"]
                    .iter()
                    .any(|s| e.operation.ends_with(s))
            })
            .copied()
            .collect()
    } else if query.contains("| where Who contains who") {
        mine.iter()
            .filter(|e| e.who.to_lowercase().contains(&who.to_lowercase()))
            .copied()
            .collect()
    } else {
        panic!("the mock doesn't know this report: {query}");
    };
    let mut picked = picked;
    picked.sort_by(|a, b| b.time.cmp(&a.time));
    let rows: Vec<serde_json::Value> = picked
        .iter()
        .map(|e| {
            json!([
                e.time,
                e.vault_id,
                e.who,
                e.operation,
                e.item,
                e.signature(),
                "203.0.113.5",
                e.status
            ])
        })
        .collect();
    json!({"tables": [{"name": "PrimaryResult", "columns": [
        {"name": "TimeGenerated"}, {"name": "VaultId"}, {"name": "Who"}, {"name": "OperationName"},
        {"name": "Item"}, {"name": "ResultSignature"}, {"name": "CallerIpAddress"}, {"name": "Status"}
    ], "rows": rows}]})
}

/// Answer a "used by" query from `src/azure/used_by.rs` the way Log
/// Analytics would: allowed uses of the named item in the named vault,
/// summarised by caller, then the row counting all the vault's events.
pub(crate) fn answer_used_by(query: &str, events: &[RawEvent]) -> serde_json::Value {
    let vault = let_literal(query, "vaultName")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let item = let_literal(query, "itemName").unwrap_or_default();
    let ops: &[&str] = if query.contains("'KeySign'") {
        &[
            "KeySign",
            "KeyVerify",
            "KeyWrap",
            "KeyUnwrap",
            "KeyEncrypt",
            "KeyDecrypt",
        ]
    } else {
        &["SecretGet"]
    };
    struct Group {
        key: (String, String, String),
        reads: u64,
        last: String,
        managed: u64,
        clients: Vec<String>,
        ips: Vec<String>,
    }
    let mut groups: Vec<Group> = Vec::new();
    for e in events.iter().filter(|e| {
        e.vault_id
            .to_ascii_lowercase()
            .ends_with(&format!("/vaults/{vault}"))
            && e.item.eq_ignore_ascii_case(&item)
            && ops.contains(&e.operation.as_str())
            && (200..300).contains(&e.status)
    }) {
        let upn = if e.who.contains('@') {
            e.who.clone()
        } else {
            String::new()
        };
        let key = (e.object_id.clone(), e.app_id.clone(), upn);
        let i = match groups.iter().position(|g| g.key == key) {
            Some(i) => i,
            None => {
                groups.push(Group {
                    key,
                    reads: 0,
                    last: String::new(),
                    managed: 0,
                    clients: Vec::new(),
                    ips: Vec::new(),
                });
                groups.len() - 1
            }
        };
        let g = &mut groups[i];
        g.reads += 1;
        if e.time > g.last {
            g.last = e.time.clone();
        }
        g.managed += u64::from(e.managed);
        if !g.clients.contains(&e.client_info) && g.clients.len() < 3 {
            g.clients.push(e.client_info.clone());
        }
        if !g.ips.contains(&e.ip) && g.ips.len() < 3 {
            g.ips.push(e.ip.clone());
        }
    }
    groups.sort_by(|a, b| b.last.cmp(&a.last));
    let from_vault: Vec<&RawEvent> = events
        .iter()
        .filter(|e| {
            e.vault_id
                .to_ascii_lowercase()
                .ends_with(&format!("/vaults/{vault}"))
        })
        .collect();
    let newest = from_vault.iter().map(|e| e.time.clone()).max();
    let mut rows: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|g| {
            json!([
                g.key.0,
                g.key.1,
                g.key.2,
                g.reads,
                g.last,
                g.managed,
                g.clients.join(", "),
                g.ips.join(", "),
                null,
                null
            ])
        })
        .collect();
    rows.push(json!([
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        from_vault.len(),
        newest
    ]));
    json!({"tables": [{"name": "PrimaryResult", "columns": [
        {"name": "ObjectId"}, {"name": "AppId"}, {"name": "Upn"}, {"name": "Reads"},
        {"name": "LastRead"}, {"name": "Managed"}, {"name": "ClientInfo"}, {"name": "CallerIp"},
        {"name": "VaultEvents"}, {"name": "Newest"}
    ], "rows": rows}]})
}

/// Diagnostic settings sending audit logs to the workspace `name`.
pub(crate) fn settings_to(name: &str, dedicated: bool) -> serde_json::Value {
    json!({"value": [{"properties": {
        "workspaceId": format!("/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/{name}"),
        "logAnalyticsDestinationType": if dedicated { json!("Dedicated") } else { json!(null) },
        "logs": [{"categoryGroup": "audit", "enabled": true}]
    }}]})
}

pub(crate) fn audit_settings(dedicated: bool) -> serde_json::Value {
    json!({"value": [{"properties": {
        "workspaceId": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs",
        "logAnalyticsDestinationType": if dedicated { json!("Dedicated") } else { json!(null) },
        "logs": [{"categoryGroup": "audit", "enabled": true}]
    }}]})
}

/// A diagnostic setting that sends audit logs to a storage account only,
/// which the audit view can't read but still counts as kept.
pub(crate) fn storage_audit_settings() -> serde_json::Value {
    json!({"value": [{"properties": {
        "storageAccountId": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs",
        "logs": [{"category": "AuditEvent", "enabled": true}]
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

/// The usual world, with the cross-vault reads held to `limits`.
pub(crate) async fn world_within(limits: keyring::azure::fanout::Limits) -> World {
    world_over(keyvault::start().await, &[], Some(limits)).await
}

pub(crate) async fn world_with(extra: &[(&'static str, &'static str)]) -> World {
    world_over(keyvault::start().await, extra, None).await
}

/// A world whose Key Vault mock serves each named vault from its own
/// state, with the cross-vault reads held to `limits`. `kv` in the result
/// is the first vault.
pub(crate) async fn world_of_vaults(
    vaults: Vec<(&'static str, Arc<keyvault::KvState>)>,
    limits: keyring::azure::fanout::Limits,
) -> World {
    let names: Vec<&str> = vaults.iter().map(|(n, _)| *n).collect();
    let rows = names.iter().map(|n| vault_row(n, "sub-a", true)).collect();
    let w = world_over(keyvault::start_several(vaults).await, &[], Some(limits)).await;
    *w.arm.state.vaults.lock().unwrap() = rows;
    w
}

/// A world over several vaults, as [`world_of_vaults`], with `extra`
/// settings and the standard cross-vault limits.
pub(crate) async fn world_of_vaults_with(
    vaults: Vec<(&'static str, Arc<keyvault::KvState>)>,
    extra: &[(&'static str, &'static str)],
) -> World {
    let rows = vaults
        .iter()
        .map(|(n, _)| vault_row(n, "sub-a", true))
        .collect();
    let w = world_over(keyvault::start_several(vaults).await, extra, None).await;
    *w.arm.state.vaults.lock().unwrap() = rows;
    w
}

async fn world_over(
    kv: keyvault::MockKeyVault,
    extra: &[(&'static str, &'static str)],
    limits: Option<keyring::azure::fanout::Limits>,
) -> World {
    world_over_with(kv, extra, limits, |_| {}).await
}

/// A world whose config gets `extra` settings (owned values) and then
/// `tweak`, before the app state is built.
pub(crate) async fn world_configured(
    extra: Vec<(&'static str, String)>,
    tweak: impl FnOnce(&mut Config),
) -> World {
    let leaked: Vec<(&'static str, &'static str)> = extra
        .into_iter()
        .map(|(k, v)| (k, &*Box::leak(v.into_boxed_str())))
        .collect();
    world_over_with(keyvault::start().await, &leaked, None, tweak).await
}

async fn world_over_with(
    kv: keyvault::MockKeyVault,
    extra: &[(&'static str, &'static str)],
    limits: Option<keyring::azure::fanout::Limits>,
    tweak: impl FnOnce(&mut Config),
) -> World {
    let idp = start_idp().await;
    let arm = start_arm().await;
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
    let mut config = Config::from_lookup(|k| env.get(k).cloned()).expect("test config");
    tweak(&mut config);
    let (state, app, cookie) = signed_in_app_with(config, limits);
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
