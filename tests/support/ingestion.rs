//! A mock Azure Monitor Logs Ingestion endpoint, for the audit sink.
//!
//! Follows Microsoft's REST reference: `POST /dataCollectionRules/{id}/
//! streams/{stream}?api-version=2023-01-01`, a JSON array body (gzipped
//! with `Content-Encoding: gzip`), a bearer token for
//! `https://monitor.azure.com`, 204 on success and nothing over 1 MB.
//!
//! Any request whose bearer token isn't the mock managed identity's for
//! that resource is recorded as a violation, which tests check is empty:
//! no path may write audit rows with a person's token.

use std::collections::VecDeque;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::Value;

use super::MI_MONITOR_TOKEN;

/// The API's limit on one call's body, uncompressed.
pub(crate) const MAX_BODY: usize = 1024 * 1024;

pub(crate) const DCR_ID: &str = "dcr-00112233445566778899aabbccddeeff";
pub(crate) const STREAM: &str = "Custom-KeyringAudit_CL";

/// One accepted call.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub rows: Vec<Value>,
    /// The body's size before gzip.
    pub raw_len: usize,
    pub gzipped: bool,
}

#[derive(Default)]
pub(crate) struct IngestionState {
    /// Calls that were accepted, in order.
    pub accepted: Mutex<Vec<Call>>,
    /// Every request, whatever the answer.
    pub attempts: Mutex<usize>,
    /// Answers to give before accepting: a status and optional
    /// `Retry-After` seconds, taken from the front.
    pub script: Mutex<VecDeque<(u16, Option<u64>)>>,
    /// Answer every request with this, until cleared.
    pub always: Mutex<Option<u16>>,
    /// Anything that broke the rules: a wrong token, path, header or body.
    pub violations: Mutex<Vec<String>>,
}

impl IngestionState {
    /// Every accepted row, in order.
    pub(crate) fn rows(&self) -> Vec<Value> {
        self.accepted
            .lock()
            .unwrap()
            .iter()
            .flat_map(|c| c.rows.clone())
            .collect()
    }

    pub(crate) fn violations(&self) -> Vec<String> {
        self.violations.lock().unwrap().clone()
    }
}

pub(crate) struct MockIngestion {
    pub addr: SocketAddr,
    pub state: Arc<IngestionState>,
}

impl MockIngestion {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

pub(crate) async fn start() -> MockIngestion {
    let state = Arc::new(IngestionState::default());
    let app = Router::new()
        .route("/dataCollectionRules/{dcr}/streams/{stream}", post(ingest))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockIngestion { addr, state }
}

async fn ingest(
    State(s): State<Arc<IngestionState>>,
    Path((dcr, stream)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    *s.attempts.lock().unwrap() += 1;
    let violation = |why: String| {
        s.violations.lock().unwrap().push(why);
        StatusCode::UNAUTHORIZED.into_response()
    };
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bearer != MI_MONITOR_TOKEN {
        // Never the person's token, never anything but the identity's.
        return violation(format!("bearer token was {bearer:?}"));
    }
    if dcr != DCR_ID || stream != STREAM {
        return violation(format!("wrong rule or stream: {dcr} {stream}"));
    }
    if q.get("api-version").map(String::as_str) != Some("2023-01-01") {
        return violation("wrong api-version".into());
    }
    if headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json") {
        return violation("content-type isn't application/json".into());
    }
    let gzipped = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        == Some("gzip");
    let raw = if gzipped {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .is_err()
        {
            return violation("body isn't gzip".into());
        }
        out
    } else {
        body.to_vec()
    };
    if raw.len() > MAX_BODY {
        s.violations
            .lock()
            .unwrap()
            .push(format!("body over 1 MB: {}", raw.len()));
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let always = *s.always.lock().unwrap();
    let scripted = s.script.lock().unwrap().pop_front();
    if let Some(code) = always {
        return StatusCode::from_u16(code).unwrap().into_response();
    }
    if let Some((code, retry)) = scripted {
        let mut res = StatusCode::from_u16(code).unwrap().into_response();
        if let Some(secs) = retry {
            res.headers_mut()
                .insert("retry-after", secs.to_string().parse().unwrap());
        }
        return res;
    }
    let Ok(Value::Array(rows)) = serde_json::from_slice::<Value>(&raw) else {
        return violation("body isn't a JSON array".into());
    };
    s.accepted.lock().unwrap().push(Call {
        rows,
        raw_len: raw.len(),
        gzipped,
    });
    StatusCode::NO_CONTENT.into_response()
}
