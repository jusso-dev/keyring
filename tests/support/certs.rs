//! Certificates for the mock Key Vault. Shares state with the secrets mock,
//! because Key Vault backs every certificate with a secret of the same name.

use std::collections::BTreeMap;
use std::sync::Arc;

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
pub struct CertVersion {
    pub version: String,
    pub der: Option<Vec<u8>>,
    pub enabled: bool,
    pub created: i64,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct StoredCert {
    pub versions: Vec<CertVersion>,
    pub policy: Value,
    pub pending: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct DeletedCert {
    pub cert: StoredCert,
    pub deleted: i64,
    pub purge: i64,
}

pub fn thumb(der: &[u8]) -> String {
    // Not SHA-1, just a stable stand-in for tests.
    let mut h = [0u8; 20];
    for (i, b) in der.iter().enumerate() {
        h[i % 20] = h[i % 20].wrapping_add(*b).rotate_left(3);
    }
    URL_SAFE_NO_PAD.encode(h)
}

pub fn default_policy(exportable: bool, pem: bool) -> Value {
    json!({
        "keyProps": {"exportable": exportable, "kty": "RSA", "key_size": 2048, "reuse_key": false},
        "secretProps": {"contentType": if pem { "application/x-pem-file" } else { "application/x-pkcs12" }},
        "x509Props": {"subject": "CN=keyring.test", "validity_months": 12},
        "lifetimeActions": [{"trigger": {"lifetimePercentage": 80}, "action": {"actionType": "AutoRenew"}}],
        "issuer": {"name": "Self"}
    })
}

pub fn router(state: Arc<KvState>) -> Router<Arc<KvState>> {
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
            axum::routing::get(policy),
        )
        .route(
            "/{vault}/certificates/{name}/pending",
            axum::routing::get(pending),
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
            axum::routing::get(get_version),
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
    let Some(c) = s.certs.lock().unwrap().get(&name).cloned() else {
        return err(404, "CertificateNotFound");
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
    let certs = s.certs.lock().unwrap();
    let Some(c) = certs.get(&name) else {
        return err(404, "CertificateNotFound");
    };
    match c.versions.iter().find(|v| v.version == version) {
        Some(v) => json_response(StatusCode::OK, bundle(&b, &name, c, v)),
        None => err(404, "CertificateNotFound"),
    }
}

async fn policy(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
    match s.certs.lock().unwrap().get(&name) {
        Some(c) => json_response(StatusCode::OK, c.policy.clone()),
        None => err(404, "CertificateNotFound"),
    }
}

async fn pending(
    State(s): State<Arc<KvState>>,
    Path((_vault, name)): Path<(String, String)>,
) -> Response {
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
pub struct ImportRecord {
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
        return err(409, "Conflict");
    }
    s.imports.lock().unwrap().push(ImportRecord {
        name: name.clone(),
        body: body.clone(),
    });
    let value = body["value"].as_str().unwrap_or_default().to_owned();
    let ct = body["policy"]["secretProps"]["contentType"]
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
    let exportable = body["policy"]["keyProps"]["exportable"]
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
        return err(409, "Conflict");
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
    if issuer == "Self" {
        // Self-signed completes straight away with the test certificate.
        let der = super::pem_first_cert(super::TEST_CERT_PEM);
        s.add_cert_version(&name, der, body["policy"].clone(), |_| {});
        json_response(
            StatusCode::ACCEPTED,
            json!({"id": op_id, "status": "completed", "issuer": {"name": "Self"}}),
        )
    } else {
        let op = json!({"id": op_id, "status": "inProgress", "status_details": "Pending approval", "statusDetails": "Waiting for the CA to approve the request.", "issuer": {"name": issuer}});
        let mut certs = s.certs.lock().unwrap();
        let t = 1;
        certs.insert(
            name.clone(),
            StoredCert {
                versions: vec![CertVersion {
                    version: "f".repeat(32),
                    der: None,
                    enabled: false,
                    created: t,
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
