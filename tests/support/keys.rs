//! Keys for the mock Key Vault. Records every request path so tests can
//! check nothing asks for private material.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::{Value, json};

use super::json_response;
use super::keyvault::KvState;

#[derive(Clone, Debug)]
pub struct KeyVersion {
    pub version: String,
    pub kty: String,
    pub crv: Option<String>,
    pub ops: Vec<String>,
    pub enabled: bool,
    pub created: i64,
    pub exp: Option<i64>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct StoredKey {
    pub versions: Vec<KeyVersion>,
    pub rotation: Value,
    /// A key Key Vault made behind a certificate.
    pub managed: bool,
}

impl StoredKey {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
            rotation: default_rotation_policy(),
            managed: false,
        }
    }
}

impl Default for StoredKey {
    fn default() -> Self {
        Self::new()
    }
}

/// What "Get Key Rotation Policy" returns for a key nobody set a policy
/// on: one Notify action 30 days before expiry and no expiry time (REST
/// reference, Keys, Get Key Rotation Policy; the portal shows the same
/// default).
pub fn default_rotation_policy() -> Value {
    json!({
        "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}],
        "attributes": {"created": 1_790_000_000, "updated": 1_790_000_000}
    })
}

#[derive(Clone, Debug)]
pub struct DeletedKey {
    pub key: StoredKey,
    pub deleted: i64,
    pub purge: i64,
}

pub const RSA_N: &str = include_str!("../fixtures/test-rsa-n.txt");
pub const EC_X: &str = include_str!("../fixtures/test-ec-x.txt");
pub const EC_Y: &str = include_str!("../fixtures/test-ec-y.txt");

pub fn router() -> Router<Arc<KvState>> {
    Router::new()
        .route("/{vault}/keys", get(list))
        .route("/{vault}/keys/{name}", get(get_current).delete(delete))
        .route("/{vault}/keys/{name}/versions", get(versions))
        .route("/{vault}/keys/{name}/create", post(create))
        .route("/{vault}/keys/{name}/rotate", post(rotate))
        .route(
            "/{vault}/keys/{name}/rotationpolicy",
            get(get_policy).put(put_policy),
        )
        .route(
            "/{vault}/keys/{name}/{version}",
            get(get_version).patch(update_version),
        )
        .route("/{vault}/deletedkeys", get(list_deleted))
        .route(
            "/{vault}/deletedkeys/{name}",
            get(get_deleted).delete(purge),
        )
        .route("/{vault}/deletedkeys/{name}/recover", post(recover))
}

fn err(status: u16, code: &str) -> Response {
    json_response(
        StatusCode::from_u16(status).unwrap(),
        json!({"error": {"code": code, "message": "mock Key Vault error with private detail"}}),
    )
}

fn base(headers: &HeaderMap, vault: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("x");
    format!("http://{host}/{vault}")
}

fn attrs(v: &KeyVersion) -> Value {
    let mut a = json!({"enabled": v.enabled, "created": v.created, "updated": v.created, "recoveryLevel": "Recoverable+Purgeable"});
    if let Some(e) = v.exp {
        a["exp"] = json!(e);
    }
    a
}

fn item(b: &str, name: &str, v: &KeyVersion, with_version: bool, managed: bool) -> Value {
    let kid = if with_version {
        format!("{b}/keys/{name}/{}", v.version)
    } else {
        format!("{b}/keys/{name}")
    };
    let mut out = json!({"kid": kid, "attributes": attrs(v), "tags": v.tags});
    if managed {
        out["managed"] = json!(true);
    }
    out
}

fn bundle(b: &str, name: &str, v: &KeyVersion, managed: bool) -> Value {
    let mut key =
        json!({"kid": format!("{b}/keys/{name}/{}", v.version), "kty": v.kty, "key_ops": v.ops});
    if v.kty.starts_with("RSA") {
        key["n"] = json!(RSA_N.trim());
        key["e"] = json!("AQAB");
    } else if v.kty.starts_with("EC") {
        key["crv"] = json!(v.crv.clone().unwrap_or_else(|| "P-256".into()));
        key["x"] = json!(EC_X.trim());
        key["y"] = json!(EC_Y.trim());
    }
    let mut out = json!({"key": key, "attributes": attrs(v), "tags": v.tags});
    if managed {
        out["managed"] = json!(true);
    }
    out
}

fn page(items: Vec<Value>) -> Response {
    json_response(StatusCode::OK, json!({"value": items, "nextLink": null}))
}

async fn list(
    State(s): State<Arc<KvState>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    page(
        s.keys
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(n, k)| k.versions.last().map(|v| item(&b, n, v, false, k.managed)))
            .collect(),
    )
}

async fn versions(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    // "Get Key Versions" answers 200 with an empty list for a name it
    // doesn't have (REST reference, Keys, Get Key Versions).
    match s.keys.lock().unwrap().get(&name) {
        Some(k) => page(
            k.versions
                .iter()
                .map(|v| item(&b, &name, v, true, k.managed))
                .collect(),
        ),
        None => page(Vec::new()),
    }
}

async fn get_current(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    match s.keys.lock().unwrap().get(&name) {
        Some(k) => json_response(
            StatusCode::OK,
            bundle(&b, &name, k.versions.last().unwrap(), k.managed),
        ),
        None => err(404, "KeyNotFound"),
    }
}

async fn get_version(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    let keys = s.keys.lock().unwrap();
    let Some(k) = keys.get(&name) else {
        return err(404, "KeyNotFound");
    };
    match k.versions.iter().find(|v| v.version == version) {
        Some(v) => json_response(StatusCode::OK, bundle(&b, &name, v, k.managed)),
        None => err(404, "KeyNotFound"),
    }
}

/// "Update Key": only `attributes.enabled` is used here.
async fn update_version(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    let b = base(&headers, &vault);
    let mut keys = s.keys.lock().unwrap();
    let Some(k) = keys.get_mut(&name) else {
        return err(404, "KeyNotFound");
    };
    let managed = k.managed;
    let Some(v) = k.versions.iter_mut().find(|v| v.version == version) else {
        return err(404, "KeyNotFound");
    };
    if let Some(e) = body["attributes"]["enabled"].as_bool() {
        v.enabled = e;
    }
    json_response(StatusCode::OK, bundle(&b, &name, v, managed))
}

async fn create(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    if s.deleted_keys.lock().unwrap().contains_key(&name) {
        return err(409, "Conflict");
    }
    let kty = body["kty"].as_str().unwrap_or("RSA").to_owned();
    // A Standard vault refuses HSM keys with `400 BadParameter` and a
    // message about the vault's SKU (REST reference, Keys, Create Key, as
    // read by the review; to confirm on a real vault).
    if kty.ends_with("-HSM") && !*s.premium.lock().unwrap() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": {"code": "BadParameter", "message": "Key type RSA-HSM is not supported by this vault's SKU. Premium SKU is required."}}),
        );
    }
    s.key_creates.lock().unwrap().push(body.clone());
    let ops = body["key_ops"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let tags = body["tags"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let crv = body["crv"].as_str().map(str::to_owned);
    let exp = body["attributes"]["exp"].as_i64();
    s.add_key_with(&name, &kty, |v| {
        v.ops = ops;
        v.tags = tags;
        v.crv = crv;
        v.exp = exp;
    });
    let b = base(&headers, &vault);
    let keys = s.keys.lock().unwrap();
    json_response(
        StatusCode::OK,
        bundle(&b, &name, keys[&name].versions.last().unwrap(), false),
    )
}

async fn rotate(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let current = match s.keys.lock().unwrap().get(&name) {
        Some(k) => k.versions.last().unwrap().clone(),
        None => return err(404, "KeyNotFound"),
    };
    s.add_key_with(&name, &current.kty, |v| {
        v.ops = current.ops.clone();
        v.tags = current.tags.clone();
        v.crv = current.crv.clone();
    });
    let b = base(&headers, &vault);
    let keys = s.keys.lock().unwrap();
    json_response(
        StatusCode::OK,
        bundle(&b, &name, keys[&name].versions.last().unwrap(), false),
    )
}

async fn get_policy(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    match s.keys.lock().unwrap().get(&name) {
        Some(k) => json_response(StatusCode::OK, k.rotation.clone()),
        None => err(404, "KeyNotFound"),
    }
}

async fn put_policy(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    if let Some(m) = rotation_policy_problem(&body) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": {"code": "BadParameter", "message": m}}),
        );
    }
    match s.keys.lock().unwrap().get_mut(&name) {
        Some(k) => {
            k.rotation = body.clone();
            json_response(StatusCode::OK, body)
        }
        None => err(404, "KeyNotFound"),
    }
}

fn days(v: &Value) -> Option<u32> {
    let s = v.as_str()?;
    s.strip_prefix('P')?.strip_suffix('D')?.parse().ok()
}

/// "Update Key Rotation Policy" refuses out-of-range values with 400
/// (REST reference and "Configure key auto-rotation"): expiry at least 28
/// days, and a rotate trigger at least 7 days before expiry. The mock only
/// checks day durations.
fn rotation_policy_problem(p: &Value) -> Option<String> {
    let expiry = days(&p["attributes"]["expiryTime"]);
    if expiry.is_some_and(|e| e < 28) {
        return Some("Expiry time should be at least 28 days.".into());
    }
    for a in p["lifetimeActions"].as_array().into_iter().flatten() {
        if a["action"]["type"] == "Rotate"
            && let (Some(r), Some(e)) = (days(&a["trigger"]["timeAfterCreate"]), expiry)
            && r + 7 > e
        {
            return Some(
                "The time after create must be at least 7 days less than the expiry time.".into(),
            );
        }
    }
    None
}

async fn delete(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(k) = s.keys.lock().unwrap().remove(&name) else {
        return err(404, "KeyNotFound");
    };
    s.deleted_keys.lock().unwrap().insert(
        name,
        DeletedKey {
            key: k,
            deleted: 1_790_000_000,
            purge: 1_790_000_000 + 90 * 86_400,
        },
    );
    json_response(StatusCode::OK, json!({}))
}

fn deleted_item(b: &str, name: &str, d: &DeletedKey) -> Value {
    // Key Vault sends the deleted key's attributes, with its recovery level
    // and retention: https://learn.microsoft.com/rest/api/keyvault/keys/get-deleted-key/get-deleted-key
    let mut attributes = d
        .key
        .versions
        .last()
        .map_or_else(|| json!({"recoveryLevel": "Recoverable+Purgeable"}), attrs);
    attributes["recoverableDays"] = json!(90);
    json!({"kid": format!("{b}/keys/{name}"), "recoveryId": format!("{b}/deletedkeys/{name}"), "deletedDate": d.deleted, "scheduledPurgeDate": d.purge, "attributes": attributes})
}

async fn list_deleted(
    State(s): State<Arc<KvState>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    page(
        s.deleted_keys
            .lock()
            .unwrap()
            .iter()
            .map(|(n, d)| deleted_item(&b, n, d))
            .collect(),
    )
}

async fn get_deleted(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    match s.deleted_keys.lock().unwrap().get(&name) {
        Some(d) => json_response(StatusCode::OK, deleted_item(&b, &name, d)),
        None => err(404, "KeyNotFound"),
    }
}

async fn recover(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(d) = s.deleted_keys.lock().unwrap().remove(&name) else {
        return err(404, "KeyNotFound");
    };
    s.keys.lock().unwrap().insert(name, d.key);
    json_response(StatusCode::OK, json!({}))
}

async fn purge(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    match s.deleted_keys.lock().unwrap().remove(&name) {
        Some(_) => axum::response::IntoResponse::into_response(StatusCode::NO_CONTENT),
        None => err(404, "KeyNotFound"),
    }
}

impl KvState {
    /// The key Key Vault makes behind each certificate version, with the
    /// same name and version, marked `managed: true` (REST reference, Keys,
    /// Get Key: "managed: True if the key's lifetime is managed by key
    /// vault. If this is a key backing a certificate, then managed will be
    /// true.").
    pub fn add_managed_key(&self, name: &str, version: &str) {
        let mut keys = self.keys.lock().unwrap();
        let k = keys.entry(name.into()).or_default();
        k.managed = true;
        k.versions.push(KeyVersion {
            version: version.into(),
            kty: "RSA".into(),
            crv: None,
            ops: vec!["sign".into(), "verify".into()],
            enabled: true,
            created: super::keyvault::BASE_TIME,
            exp: None,
            tags: BTreeMap::new(),
        });
    }
}
