//! An in-memory stand-in for the Key Vault secrets API. Records every
//! request so tests can check, for example, that listing never reads values.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::{Value, json};

use super::json_response;

#[derive(Clone, Debug)]
pub struct Version {
    pub version: String,
    pub value: String,
    pub enabled: bool,
    pub created: i64,
    pub updated: i64,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub content_type: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct StoredSecret {
    /// Oldest first.
    pub versions: Vec<Version>,
    pub managed: bool,
}

#[derive(Clone, Debug)]
pub struct Deleted {
    pub secret: StoredSecret,
    pub deleted: i64,
    pub purge: i64,
}

#[derive(Default)]
pub struct KvState {
    pub secrets: Mutex<BTreeMap<String, StoredSecret>>,
    pub deleted: Mutex<BTreeMap<String, Deleted>>,
    /// Every request as "METHOD /path".
    pub log: Mutex<Vec<String>>,
    /// Bearer tokens seen.
    pub bearers: Mutex<Vec<String>>,
    /// If set, every request fails with this status and code.
    pub fail: Mutex<Option<(u16, &'static str)>>,
    /// If set, only requests whose path contains this fail.
    pub fail_path: Mutex<Option<String>>,
    /// If set, only requests with this method fail.
    pub fail_method: Mutex<Option<Method>>,
    pub certs: Mutex<BTreeMap<String, super::certs::StoredCert>>,
    pub deleted_certs: Mutex<BTreeMap<String, super::certs::DeletedCert>>,
    pub imports: Mutex<Vec<super::certs::ImportRecord>>,
    pub creates: Mutex<Vec<super::certs::ImportRecord>>,
    pub keys: Mutex<BTreeMap<String, super::keys::StoredKey>>,
    pub deleted_keys: Mutex<BTreeMap<String, super::keys::DeletedKey>>,
    pub key_creates: Mutex<Vec<serde_json::Value>>,
    /// Answer this many requests with 429 before serving normally.
    pub throttle_next: Mutex<u32>,
    /// Whether the vault allows HSM keys.
    pub premium: Mutex<bool>,
    seq: Mutex<i64>,
}

pub const BASE_TIME: i64 = 1_790_000_000;

impl KvState {
    fn tick(&self) -> i64 {
        let mut s = self.seq.lock().unwrap();
        *s += 1;
        BASE_TIME + *s * 60
    }

    /// Key Vault versions look random. Spread the counter's bits so the
    /// first characters differ between versions, as they do for real.
    fn new_version(&self) -> String {
        let n = (*self.seq.lock().unwrap() + 1) as u128;
        let mixed = n.wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835);
        format!("{mixed:032x}")
    }

    /// Add a secret version directly.
    pub fn put(&self, name: &str, value: &str) -> String {
        self.put_with(name, value, |_| {})
    }

    pub fn put_with(&self, name: &str, value: &str, edit: impl FnOnce(&mut Version)) -> String {
        let version = self.new_version();
        let t = self.tick();
        let mut v = Version {
            version: version.clone(),
            value: value.into(),
            enabled: true,
            created: t,
            updated: t,
            exp: None,
            nbf: None,
            content_type: None,
            tags: BTreeMap::new(),
        };
        edit(&mut v);
        self.secrets
            .lock()
            .unwrap()
            .entry(name.into())
            .or_default()
            .versions
            .push(v);
        version
    }

    pub fn current(&self, name: &str) -> Option<Version> {
        self.secrets
            .lock()
            .unwrap()
            .get(name)
            .and_then(|s| s.versions.last().cloned())
    }

    pub fn version_count(&self, name: &str) -> usize {
        self.secrets
            .lock()
            .unwrap()
            .get(name)
            .map(|s| s.versions.len())
            .unwrap_or(0)
    }

    /// Add a key version. Returns the version ID.
    pub fn add_key_with(
        &self,
        name: &str,
        kty: &str,
        edit: impl FnOnce(&mut super::keys::KeyVersion),
    ) -> String {
        let version = self.new_version();
        let t = self.tick();
        let mut v = super::keys::KeyVersion {
            version: version.clone(),
            kty: kty.into(),
            crv: None,
            ops: vec![
                "encrypt".into(),
                "decrypt".into(),
                "sign".into(),
                "verify".into(),
            ],
            enabled: true,
            created: t,
            exp: None,
            tags: BTreeMap::new(),
        };
        edit(&mut v);
        self.keys
            .lock()
            .unwrap()
            .entry(name.into())
            .or_insert_with(|| super::keys::StoredKey {
                versions: Vec::new(),
                rotation: serde_json::json!({"lifetimeActions": []}),
            })
            .versions
            .push(v);
        version
    }

    pub fn key_versions(&self, name: &str) -> usize {
        self.keys
            .lock()
            .unwrap()
            .get(name)
            .map(|k| k.versions.len())
            .unwrap_or(0)
    }

    /// Add a certificate version. Returns the version ID.
    pub fn add_cert_version(
        &self,
        name: &str,
        der: Option<Vec<u8>>,
        policy: serde_json::Value,
        edit: impl FnOnce(&mut super::certs::CertVersion),
    ) -> String {
        let version = self.new_version();
        let t = self.tick();
        let mut v = super::certs::CertVersion {
            version: version.clone(),
            der,
            enabled: true,
            created: t,
            exp: Some(t + 365 * 86_400),
            nbf: Some(t),
            tags: BTreeMap::new(),
        };
        edit(&mut v);
        let mut certs = self.certs.lock().unwrap();
        let c = certs
            .entry(name.into())
            .or_insert_with(|| super::certs::StoredCert {
                versions: Vec::new(),
                policy: policy.clone(),
                pending: None,
            });
        c.policy = policy;
        c.pending = None;
        c.versions.push(v);
        version
    }

    /// Add a certificate with the test cert and a backing secret holding
    /// `secret_value` (what a .pfx download returns).
    pub fn add_cert(&self, name: &str, exportable: bool, secret_value: &str) -> String {
        let der = super::pem_first_cert(super::TEST_CERT_PEM);
        let v = self.add_cert_version(
            name,
            der,
            super::certs::default_policy(exportable, false),
            |_| {},
        );
        self.put_with(name, secret_value, |sv| {
            sv.content_type = Some("application/x-pkcs12".into());
            sv.version = v.clone();
        });
        v
    }

    /// Move a secret to the deleted list, as `DELETE` would.
    pub fn soft_delete(&self, name: &str) {
        let sec = self.secrets.lock().unwrap().remove(name).unwrap();
        let t = self.tick();
        self.deleted.lock().unwrap().insert(
            name.into(),
            Deleted {
                secret: sec,
                deleted: t,
                purge: t + 90 * 86_400,
            },
        );
    }

    /// Requests that would return a secret value.
    pub fn value_reads(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| {
                l.starts_with("GET ")
                    && l.contains("/secrets/")
                    && !l.ends_with("/versions")
                    && !l.contains("/deletedsecrets")
            })
            .cloned()
            .collect()
    }
}

pub struct MockKeyVault {
    pub addr: SocketAddr,
    pub state: Arc<KvState>,
}

impl MockKeyVault {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

pub async fn start() -> MockKeyVault {
    let state = Arc::new(KvState::default());
    let app = Router::new()
        .route("/{vault}/secrets", get(list))
        .route(
            "/{vault}/secrets/{name}",
            get(get_current).put(set).delete(delete),
        )
        .route("/{vault}/secrets/{name}/versions", get(versions))
        .route(
            "/{vault}/secrets/{name}/{version}",
            get(get_version).patch(update),
        )
        .route("/{vault}/deletedsecrets", get(list_deleted))
        .route(
            "/{vault}/deletedsecrets/{name}",
            get(get_deleted).delete(purge),
        )
        .route("/{vault}/deletedsecrets/{name}/recover", post(recover))
        .merge(super::certs::router(state.clone()))
        .merge(super::keys::router())
        .layer(axum::middleware::from_fn_with_state(state.clone(), record))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockKeyVault { addr, state }
}

async fn record(
    State(s): State<Arc<KvState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    s.log
        .lock()
        .unwrap()
        .push(format!("{} {}", req.method(), req.uri().path()));
    s.bearers.lock().unwrap().push(
        req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    );
    let fail = *s.fail.lock().unwrap();
    let method_ok = s
        .fail_method
        .lock()
        .unwrap()
        .as_ref()
        .is_none_or(|m| m == req.method())
        && s.fail_path
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|p| req.uri().path().contains(p.as_str()));
    if let Some((status, code)) = fail
        && method_ok
    {
        return err(status, code);
    }
    {
        let mut t = s.throttle_next.lock().unwrap();
        if *t > 0 {
            *t -= 1;
            let mut res = err(429, "Throttled");
            res.headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from_static("0"));
            return res;
        }
    }
    next.run(req).await
}

fn err(status: u16, code: &str) -> Response {
    json_response(
        StatusCode::from_u16(status).unwrap(),
        // Real Key Vault's shape: a broad outer code, the reason inside.
        if code.starts_with("ForbiddenBy") || code.ends_with("Disabled") {
            json!({"error": {"code": "Forbidden", "message": "mock Key Vault error with private detail", "innererror": {"code": code}}})
        } else {
            json!({"error": {"code": code, "message": "mock Key Vault error with private detail"}})
        },
    )
}

fn base(headers: &HeaderMap, vault: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("x");
    format!("http://{host}/{vault}")
}

fn attrs(v: &Version) -> Value {
    let mut a = json!({
        "enabled": v.enabled,
        "created": v.created,
        "updated": v.updated,
        "recoveryLevel": "Recoverable+Purgeable",
        "recoverableDays": 90,
    });
    if let Some(e) = v.exp {
        a["exp"] = json!(e);
    }
    if let Some(n) = v.nbf {
        a["nbf"] = json!(n);
    }
    a
}

fn item(base: &str, name: &str, v: &Version, managed: bool, with_version: bool) -> Value {
    let id = if with_version {
        format!("{base}/secrets/{name}/{}", v.version)
    } else {
        format!("{base}/secrets/{name}")
    };
    let mut out = json!({"id": id, "attributes": attrs(v), "tags": v.tags});
    if let Some(ct) = &v.content_type {
        out["contentType"] = json!(ct);
    }
    if managed {
        out["managed"] = json!(true);
    }
    out
}

fn bundle(base: &str, name: &str, v: &Version, managed: bool) -> Value {
    let mut out = item(base, name, v, managed, true);
    out["value"] = json!(v.value);
    out
}

#[derive(serde::Deserialize)]
struct PageQuery {
    #[serde(rename = "$skiptoken")]
    skip: Option<usize>,
    maxresults: Option<usize>,
}

fn page(items: Vec<Value>, q: &PageQuery, uri: &Uri, base: &str) -> Response {
    let size = q.maxresults.unwrap_or(25).min(25);
    let start = q.skip.unwrap_or(0);
    let end = (start + size).min(items.len());
    let mut out = json!({"value": items[start.min(end)..end].to_vec()});
    if end < items.len() {
        let path = uri.path().split_once('/').map(|x| x.1).unwrap_or_default();
        let path = path.split_once('/').map(|x| x.1).unwrap_or_default();
        out["nextLink"] = json!(format!(
            "{base}/{path}?api-version=7.5&$skiptoken={end}&maxresults={size}"
        ));
    } else {
        out["nextLink"] = Value::Null;
    }
    json_response(StatusCode::OK, out)
}

async fn list(
    State(s): State<Arc<KvState>>,
    Path(vault): Path<String>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let b = base(&headers, &vault);
    let items: Vec<Value> = s
        .secrets
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(n, sec)| {
            sec.versions
                .last()
                .map(|v| item(&b, n, v, sec.managed, false))
        })
        .collect();
    page(items, &q, &uri, &b)
}

async fn versions(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let b = base(&headers, &vault);
    let Some(sec) = s.secrets.lock().unwrap().get(&name).cloned() else {
        return err(404, "SecretNotFound");
    };
    let items: Vec<Value> = sec
        .versions
        .iter()
        .map(|v| item(&b, &name, v, sec.managed, true))
        .collect();
    page(items, &q, &uri, &b)
}

async fn get_current(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    match s.secrets.lock().unwrap().get(&name) {
        Some(sec) => match sec.versions.last() {
            Some(v) if !v.enabled => err(403, "SecretDisabled"),
            Some(v) => json_response(StatusCode::OK, bundle(&b, &name, v, sec.managed)),
            None => err(404, "SecretNotFound"),
        },
        None => err(404, "SecretNotFound"),
    }
}

async fn get_version(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    let secrets = s.secrets.lock().unwrap();
    let Some(sec) = secrets.get(&name) else {
        return err(404, "SecretNotFound");
    };
    match sec.versions.iter().find(|v| v.version == version) {
        Some(v) if !v.enabled => err(403, "Forbidden"),
        Some(v) => json_response(StatusCode::OK, bundle(&b, &name, v, sec.managed)),
        None => err(404, "SecretNotFound"),
    }
}

fn tags_from(body: &Value) -> BTreeMap<String, String> {
    body["tags"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

async fn set(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if s.deleted.lock().unwrap().contains_key(&name) {
        return err(409, "Conflict");
    }
    let body: Value = serde_json::from_str(&body).unwrap();
    let Some(value) = body["value"].as_str() else {
        return err(400, "BadParameter");
    };
    let a = &body["attributes"];
    s.put_with(&name, value, |v| {
        v.enabled = a["enabled"].as_bool().unwrap_or(true);
        v.exp = a["exp"].as_i64();
        v.nbf = a["nbf"].as_i64();
        v.content_type = body["contentType"].as_str().map(str::to_owned);
        v.tags = tags_from(&body);
    });
    let b = base(&headers, &vault);
    let current = s.current(&name).unwrap();
    json_response(StatusCode::OK, bundle(&b, &name, &current, false))
}

async fn update(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    if body.get("value").is_some() {
        return err(400, "BadParameter");
    }
    let t = s.tick();
    let mut secrets = s.secrets.lock().unwrap();
    let Some(sec) = secrets.get_mut(&name) else {
        return err(404, "SecretNotFound");
    };
    let managed = sec.managed;
    let Some(v) = sec.versions.iter_mut().find(|v| v.version == version) else {
        return err(404, "SecretNotFound");
    };
    // Like real Key Vault: fields left out are kept, `null` clears.
    let a = &body["attributes"];
    if let Some(e) = a["enabled"].as_bool() {
        v.enabled = e;
    }
    if let Some(exp) = a.get("exp") {
        v.exp = exp.as_i64();
    }
    if let Some(nbf) = a.get("nbf") {
        v.nbf = nbf.as_i64();
    }
    if body.get("contentType").is_some() {
        v.content_type = body["contentType"]
            .as_str()
            .filter(|c| !c.is_empty())
            .map(str::to_owned);
    }
    if body.get("tags").is_some() {
        v.tags = tags_from(&body);
    }
    v.updated = t;
    let b = base(&headers, &vault);
    json_response(StatusCode::OK, item(&b, &name, v, managed, true))
}

async fn delete(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(sec) = s.secrets.lock().unwrap().remove(&name) else {
        return err(404, "SecretNotFound");
    };
    let t = s.tick();
    s.deleted.lock().unwrap().insert(
        name,
        Deleted {
            secret: sec,
            deleted: t,
            purge: t + 90 * 86_400,
        },
    );
    json_response(StatusCode::OK, json!({}))
}

fn deleted_item(b: &str, name: &str, d: &Deleted) -> Value {
    let v = d.secret.versions.last().unwrap();
    let mut out = item(b, name, v, d.secret.managed, false);
    out["recoveryId"] = json!(format!("{b}/deletedsecrets/{name}"));
    out["deletedDate"] = json!(d.deleted);
    out["scheduledPurgeDate"] = json!(d.purge);
    out
}

async fn list_deleted(
    State(s): State<Arc<KvState>>,
    Path(vault): Path<String>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let b = base(&headers, &vault);
    let items: Vec<Value> = s
        .deleted
        .lock()
        .unwrap()
        .iter()
        .map(|(n, d)| deleted_item(&b, n, d))
        .collect();
    page(items, &q, &uri, &b)
}

async fn get_deleted(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    match s.deleted.lock().unwrap().get(&name) {
        Some(d) => json_response(StatusCode::OK, deleted_item(&b, &name, d)),
        None => err(404, "SecretNotFound"),
    }
}

async fn recover(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(d) = s.deleted.lock().unwrap().remove(&name) else {
        return err(404, "SecretNotFound");
    };
    s.secrets.lock().unwrap().insert(name, d.secret);
    json_response(StatusCode::OK, json!({}))
}

async fn purge(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    match s.deleted.lock().unwrap().remove(&name) {
        Some(_) => axum::response::IntoResponse::into_response(StatusCode::NO_CONTENT),
        None => err(404, "SecretNotFound"),
    }
}
