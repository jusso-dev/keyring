//! Certificates for the mock Key Vault. Shares state with the secrets mock,
//! because Key Vault backs every certificate with a secret of the same name.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::json_response;
use super::keyvault::KvState;

#[derive(Clone, Debug)]
pub(crate) struct CertVersion {
    pub version: String,
    pub der: Option<Vec<u8>>,
    pub enabled: bool,
    pub created: i64,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredCert {
    pub versions: Vec<CertVersion>,
    pub policy: Value,
    pub pending: Option<Value>,
}

/// Certificate state the mock keeps beside the shared stores.
#[derive(Default)]
pub(crate) struct Extra {
    /// Issuer names `GET /certificates/issuers` lists.
    pub issuers: Mutex<Vec<String>>,
    /// Keep a self-signed create `inProgress` until a test clears this.
    pub hold_self_signed: Mutex<bool>,
    /// Answer "list versions" for an unknown name with 404 instead of an
    /// empty list, to test both replies.
    pub versions_404: Mutex<bool>,
    /// When set, a PFX import with any other password gets Key Vault's 400.
    pub pfx_password: Mutex<Option<String>>,
    /// The body of every "Update Certificate Policy" call, in order.
    pub policy_patches: Mutex<Vec<Value>>,
    /// Answer a policy update with 200 but keep the old lifetime actions, as
    /// Key Vault might for a change it ignores.
    pub keep_lifetime_actions: Mutex<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct DeletedCert {
    pub cert: StoredCert,
    pub deleted: i64,
    pub purge: i64,
}

pub(crate) fn thumb(der: &[u8]) -> String {
    // Not SHA-1, just a stable stand-in for tests.
    let mut h = [0u8; 20];
    for (i, b) in der.iter().enumerate() {
        h[i % 20] = h[i % 20].wrapping_add(*b).rotate_left(3);
    }
    URL_SAFE_NO_PAD.encode(h)
}

pub(crate) fn default_policy(exportable: bool, pem: bool) -> Value {
    json!({
        "key_props": {"exportable": exportable, "kty": "RSA", "key_size": 2048, "reuse_key": false},
        "secret_props": {"contentType": if pem { "application/x-pem-file" } else { "application/x-pkcs12" }},
        "x509_props": {"subject": "CN=keyring.test", "validity_months": 12},
        "lifetime_actions": [{"trigger": {"lifetime_percentage": 80}, "action": {"action_type": "AutoRenew"}}],
        "issuer": {"name": "Self"}
    })
}

pub(crate) fn router(state: Arc<KvState>) -> Router<Arc<KvState>> {
    let _ = state;
    Router::new()
        .route("/{vault}/certificates", axum::routing::get(list))
        .route(
            "/{vault}/certificates/{name}",
            axum::routing::get(get_current).delete(delete),
        )
        .route(
            "/{vault}/certificates/{name}/versions",
            axum::routing::get(versions),
        )
        .route(
            "/{vault}/certificates/{name}/policy",
            axum::routing::get(policy).patch(update_policy),
        )
        .route("/{vault}/certificates/issuers", axum::routing::get(issuers))
        .route(
            "/{vault}/certificates/{name}/pending",
            axum::routing::get(pending)
                .patch(cancel_pending)
                .delete(delete_pending),
        )
        .route(
            "/{vault}/certificates/{name}/import",
            axum::routing::post(import),
        )
        .route(
            "/{vault}/certificates/{name}/create",
            axum::routing::post(create),
        )
        .route(
            "/{vault}/certificates/{name}/{version}",
            axum::routing::get(get_version).patch(update_version),
        )
        .route(
            "/{vault}/deletedcertificates",
            axum::routing::get(list_deleted),
        )
        .route(
            "/{vault}/deletedcertificates/{name}",
            axum::routing::get(get_deleted).delete(purge),
        )
        .route(
            "/{vault}/deletedcertificates/{name}/recover",
            axum::routing::post(recover),
        )
}

fn err(status: u16, code: &str) -> Response {
    json_response(
        StatusCode::from_u16(status).unwrap(),
        json!({"error": {"code": code, "message": "mock Key Vault error with private detail"}}),
    )
}

/// Key Vault's 409 for an import or create onto a soft-deleted name: the
/// same shape as for secrets (see `keyvault::conflict`).
fn deleted_name_conflict() -> Response {
    super::keyvault::conflict(
        "Certificate",
        "ObjectIsDeletedButRecoverable",
        "is currently in a deleted but recoverable state",
    )
}

/// A 400 with Key Vault's own message, which Keyring now shows.
fn bad_request(message: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({"error": {"code": "BadParameter", "message": message}}),
    )
}

/// A self-signed create finishes a few seconds after Key Vault answers.
/// The mock finishes it on the next read of that certificate, unless the
/// test holds it.
fn settle(s: &KvState, name: &str) {
    if *s.cert_extra.hold_self_signed.lock().unwrap() {
        return;
    }
    let policy = {
        let mut certs = s.certs.lock().unwrap();
        let Some(c) = certs.get_mut(name) else { return };
        let waiting = c
            .pending
            .as_ref()
            .is_some_and(|p| p["status"] == "inProgress" && p["issuer"]["name"] == "Self");
        if !waiting {
            return;
        }
        c.versions.clear();
        c.policy.clone()
    };
    let der = super::pem_first_cert(super::TEST_CERT_PEM);
    s.add_cert_version(name, der, policy, |_| {});
    if let Some(c) = s.certs.lock().unwrap().get_mut(name) {
        c.pending = Some(json!({"status": "completed", "issuer": {"name": "Self"}}));
    }
}

fn settle_all(s: &KvState) {
    let names: Vec<String> = s.certs.lock().unwrap().keys().cloned().collect();
    for n in names {
        settle(s, &n);
    }
}

fn base(headers: &HeaderMap, vault: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("x");
    format!("http://{host}/{vault}")
}

fn attrs(v: &CertVersion) -> Value {
    let mut a = json!({"enabled": v.enabled, "created": v.created, "updated": v.created, "recoveryLevel": "Recoverable+Purgeable"});
    if let Some(e) = v.exp {
        a["exp"] = json!(e);
    }
    if let Some(n) = v.nbf {
        a["nbf"] = json!(n);
    }
    a
}

fn item(b: &str, name: &str, v: &CertVersion, with_version: bool) -> Value {
    let id = if with_version {
        format!("{b}/certificates/{name}/{}", v.version)
    } else {
        format!("{b}/certificates/{name}")
    };
    let mut out = json!({"id": id, "attributes": attrs(v), "tags": v.tags});
    if let Some(d) = &v.der {
        out["x5t"] = json!(thumb(d));
    }
    out
}

fn bundle(b: &str, name: &str, c: &StoredCert, v: &CertVersion) -> Value {
    let mut out = item(b, name, v, true);
    if let Some(d) = &v.der {
        out["cer"] = json!(STANDARD.encode(d));
    }
    out["sid"] = json!(format!("{b}/secrets/{name}/{}", v.version));
    out["kid"] = json!(format!("{b}/keys/{name}/{}", v.version));
    out["policy"] = c.policy.clone();
    out
}

#[derive(serde::Deserialize)]
struct PageQuery {
    #[serde(rename = "$skiptoken")]
    skip: Option<usize>,
}

fn page(items: Vec<Value>, q: &PageQuery, uri: &Uri, b: &str) -> Response {
    let start = q.skip.unwrap_or(0);
    let end = (start + 25).min(items.len());
    let mut out = json!({"value": items[start.min(end)..end].to_vec(), "nextLink": null});
    if end < items.len() {
        let path = uri.path().splitn(3, '/').nth(2).unwrap_or_default();
        out["nextLink"] = json!(format!("{b}/{path}?api-version=7.5&$skiptoken={end}"));
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
    settle_all(&s);
    let items = s
        .certs
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(n, c)| c.versions.last().map(|v| item(&b, n, v, false)))
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
    settle(&s, &name);
    // Key Vault's "Get Certificate Versions" answers 200 with an empty
    // list for a name it doesn't have (REST reference, Certificates, Get
    // Certificate Versions). Keyring has to treat that as "free".
    let Some(c) = s.certs.lock().unwrap().get(&name).cloned() else {
        if *s.cert_extra.versions_404.lock().unwrap() {
            return err(404, "CertificateNotFound");
        }
        return page(Vec::new(), &q, &uri, &b);
    };
    page(
        c.versions
            .iter()
            .map(|v| item(&b, &name, v, true))
            .collect(),
        &q,
        &uri,
        &b,
    )
}

async fn get_current(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    settle(&s, &name);
    match s.certs.lock().unwrap().get(&name) {
        Some(c) => json_response(
            StatusCode::OK,
            bundle(&b, &name, c, c.versions.last().unwrap()),
        ),
        None => err(404, "CertificateNotFound"),
    }
}

async fn get_version(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    settle(&s, &name);
    let certs = s.certs.lock().unwrap();
    let Some(c) = certs.get(&name) else {
        return err(404, "CertificateNotFound");
    };
    match c.versions.iter().find(|v| v.version == version) {
        Some(v) => json_response(StatusCode::OK, bundle(&b, &name, c, v)),
        None => err(404, "CertificateNotFound"),
    }
}

/// "Update Certificate": only `attributes.enabled` is used here.
async fn update_version(
    State(s): State<Arc<KvState>>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    let b = base(&headers, &vault);
    let mut certs = s.certs.lock().unwrap();
    let Some(c) = certs.get_mut(&name) else {
        return err(404, "CertificateNotFound");
    };
    let Some(v) = c.versions.iter_mut().find(|v| v.version == version) else {
        return err(404, "CertificateNotFound");
    };
    if let Some(e) = body["attributes"]["enabled"].as_bool() {
        v.enabled = e;
    }
    let v = v.clone();
    json_response(StatusCode::OK, bundle(&b, &name, c, &v))
}

/// "Get Certificate Issuers".
async fn issuers(
    State(s): State<Arc<KvState>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
) -> Response {
    let b = base(&headers, &vault);
    let items: Vec<Value> = s
        .cert_extra
        .issuers
        .lock()
        .unwrap()
        .iter()
        .map(|n| json!({"id": format!("{b}/certificates/issuers/{n}"), "provider": "Test"}))
        .collect();
    json_response(StatusCode::OK, json!({"value": items, "nextLink": null}))
}

/// "Update Certificate Operation": records `cancellation_requested`.
async fn cancel_pending(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    let mut certs = s.certs.lock().unwrap();
    match certs.get_mut(&name).and_then(|c| c.pending.as_mut()) {
        Some(p) => {
            p["cancellation_requested"] = body["cancellation_requested"].clone();
            json_response(StatusCode::OK, p.clone())
        }
        None => err(404, "PendingCertificateNotFound"),
    }
}

/// "Delete Certificate Operation".
async fn delete_pending(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let mut certs = s.certs.lock().unwrap();
    match certs.get_mut(&name).and_then(|c| c.pending.take()) {
        Some(p) => json_response(StatusCode::OK, p),
        None => err(404, "PendingCertificateNotFound"),
    }
}

async fn policy(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    settle(&s, &name);
    match s.certs.lock().unwrap().get(&name) {
        Some(c) => json_response(StatusCode::OK, c.policy.clone()),
        None => err(404, "CertificateNotFound"),
    }
}

/// "Update Certificate Policy": the members sent replace the stored ones,
/// the rest are left alone. Only `lifetime_actions` is used here. As in the
/// real run of 13-11-2026, an empty list is answered 200 and changes
/// nothing: Key Vault won't remove a certificate's actions. Refuses
/// what Key Vault documents: `days_before_expiry` above 27 times the
/// validity in months, and `AutoRenew` for an issuer of `Unknown`.
async fn update_policy(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    s.cert_extra
        .policy_patches
        .lock()
        .unwrap()
        .push(body.clone());
    let mut certs = s.certs.lock().unwrap();
    let Some(c) = certs.get_mut(&name) else {
        return err(404, "CertificateNotFound");
    };
    if let Some(actions) = body.get("lifetime_actions") {
        let months = c.policy["x509_props"]["validity_months"]
            .as_u64()
            .unwrap_or(12);
        let unknown_issuer = c.policy["issuer"]["name"] == "Unknown";
        for a in actions.as_array().cloned().unwrap_or_default() {
            if let Some(d) = a["trigger"]["days_before_expiry"].as_u64()
                && (d < 1 || d > months * 27)
            {
                return bad_request(&format!(
                    "days_before_expiry must be between 1 and {}",
                    months * 27
                ));
            }
            if unknown_issuer && a["action"]["action_type"] == "AutoRenew" {
                return bad_request(
                    "AutoRenew isn't allowed for a certificate with issuer Unknown",
                );
            }
        }
        let empty = actions.as_array().is_none_or(Vec::is_empty);
        if !empty && !*s.cert_extra.keep_lifetime_actions.lock().unwrap() {
            c.policy["lifetime_actions"] = actions.clone();
        }
    }
    json_response(StatusCode::OK, c.policy.clone())
}

async fn pending(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    settle(&s, &name);
    match s
        .certs
        .lock()
        .unwrap()
        .get(&name)
        .and_then(|c| c.pending.clone())
    {
        Some(p) => json_response(StatusCode::OK, p),
        None => err(404, "PendingCertificateNotFound"),
    }
}

/// What an import looked like, so tests can check it.
#[derive(Clone, Debug)]
pub(crate) struct ImportRecord {
    pub name: String,
    pub body: Value,
}

async fn import(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    if s.deleted_certs.lock().unwrap().contains_key(&name) {
        return deleted_name_conflict();
    }
    let value = body["value"].as_str().unwrap_or_default();
    let is_pem = body["policy"]["secret_props"]["contentType"] == "application/x-pem-file";
    // "Import Certificate" answers 400 when it can't read the file: a PEM
    // key that isn't unencrypted PKCS #8, or a PFX password that doesn't
    // open it (REST reference, Certificates, Import Certificate). The mock
    // only checks the password when a test sets `pfx_password`.
    if is_pem && (value.contains("BEGIN RSA PRIVATE KEY") || value.contains("BEGIN EC PRIVATE KEY"))
    {
        return bad_request(
            "The specified PEM X.509 certificate content is in an unexpected format. Please check if certificate is in valid PEM format.",
        );
    }
    let want = s.cert_extra.pfx_password.lock().unwrap().clone();
    if !is_pem && want.is_some_and(|w| body["pwd"].as_str() != Some(w.as_str())) {
        return bad_request(
            "Specified PKCS#12 X.509 certificate content can not be read. Please check if certificate is in valid PKCS#12 format.",
        );
    }
    s.imports.lock().unwrap().push(ImportRecord {
        name: name.clone(),
        body: body.clone(),
    });
    let value = body["value"].as_str().unwrap_or_default().to_owned();
    let ct = body["policy"]["secret_props"]["contentType"]
        .as_str()
        .unwrap_or("application/x-pkcs12")
        .to_owned();
    // Pull the first certificate out of PEM; for PFX tests pass the cert DER in tags.
    let der = if ct == "application/x-pem-file" {
        super::pem_first_cert(&value)
    } else {
        body["tags"]["test-der"]
            .as_str()
            .and_then(|d| STANDARD.decode(d).ok())
    };
    let exportable = body["policy"]["key_props"]["exportable"]
        .as_bool()
        .unwrap_or(true);
    let mut policy = default_policy(exportable, ct == "application/x-pem-file");
    policy["issuer"] = json!({"name": "Unknown"});
    let mut tags: BTreeMap<String, String> = body["tags"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    tags.remove("test-der");
    let enabled = body["attributes"]["enabled"].as_bool().unwrap_or(true);
    let v = s.add_cert_version(&name, der, policy, |v| {
        v.tags = tags;
        v.enabled = enabled;
    });
    // The backing secret holds what was imported.
    s.put_with(&name, &value, |sv| {
        sv.content_type = Some(ct);
        sv.version = v.clone();
    });
    let b = base(&headers, &vault);
    let certs = s.certs.lock().unwrap();
    let c = certs.get(&name).unwrap();
    json_response(
        StatusCode::OK,
        bundle(&b, &name, c, c.versions.last().unwrap()),
    )
}

async fn create(
    State(s): State<Arc<KvState>>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body: Value = serde_json::from_str(&body).unwrap();
    if s.deleted_certs.lock().unwrap().contains_key(&name) {
        return deleted_name_conflict();
    }
    s.creates.lock().unwrap().push(ImportRecord {
        name: name.clone(),
        body: body.clone(),
    });
    let issuer = body["policy"]["issuer"]["name"]
        .as_str()
        .unwrap_or("Self")
        .to_owned();
    let b = base(&headers, &vault);
    let op_id = format!("{b}/certificates/{name}/pending");
    // "Create Certificate" answers 202 with `status: inProgress` for every
    // issuer, Self included (REST reference, Certificates, Create
    // Certificate). A self-signed one completes a few seconds later; the
    // mock completes it on the next read (see `settle`).
    let details = if issuer == "Self" {
        "Pending certificate created. Certificate request is in progress. This may take some time based on the issuer provider."
    } else {
        "Waiting for the CA to approve the request."
    };
    let op = json!({"id": op_id, "status": "inProgress", "status_details": details, "cancellation_requested": false, "issuer": {"name": issuer}});
    let mut certs = s.certs.lock().unwrap();
    certs.insert(
        name.clone(),
        StoredCert {
            versions: vec![CertVersion {
                version: "f".repeat(32),
                der: None,
                enabled: false,
                created: 1,
                exp: None,
                nbf: None,
                tags: BTreeMap::new(),
            }],
            policy: body["policy"].clone(),
            pending: Some(op.clone()),
        },
    );
    json_response(StatusCode::ACCEPTED, op)
}

async fn delete(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(c) = s.certs.lock().unwrap().remove(&name) else {
        return err(404, "CertificateNotFound");
    };
    s.deleted_certs.lock().unwrap().insert(
        name,
        DeletedCert {
            cert: c,
            deleted: 1_790_000_000,
            purge: 1_790_000_000 + 90 * 86_400,
        },
    );
    json_response(StatusCode::OK, json!({}))
}

fn deleted_item(b: &str, name: &str, d: &DeletedCert) -> Value {
    let v = d.cert.versions.last().unwrap();
    let mut out = item(b, name, v, false);
    out["attributes"]["recoverableDays"] = json!(90);
    out["recoveryId"] = json!(format!("{b}/deletedcertificates/{name}"));
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
    let items = s
        .deleted_certs
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
    match s.deleted_certs.lock().unwrap().get(&name) {
        Some(d) => json_response(StatusCode::OK, deleted_item(&b, &name, d)),
        None => err(404, "CertificateNotFound"),
    }
}

async fn recover(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    let Some(d) = s.deleted_certs.lock().unwrap().remove(&name) else {
        return err(404, "CertificateNotFound");
    };
    s.certs.lock().unwrap().insert(name, d.cert);
    json_response(StatusCode::OK, json!({}))
}

async fn purge(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    match s.deleted_certs.lock().unwrap().remove(&name) {
        Some(_) => axum::response::IntoResponse::into_response(StatusCode::NO_CONTENT),
        None => err(404, "CertificateNotFound"),
    }
}
