//! A mock Azure Communication Services Email endpoint, for the notifier.
//!
//! Follows Microsoft's REST reference for api-version 2025-09-01:
//! `POST /emails:send` with a bearer token for
//! `https://communication.azure.com`, `Repeatability-Request-Id` (a GUID)
//! and `Repeatability-First-Sent` (an IMF-fixdate); 202 with
//! `Operation-Location` and `retry-after`; and `GET /emails/operations/{id}`
//! answering `NotStarted`, `Running`, `Succeeded`, `Failed` or `Canceled`.
//! A request ID sent again with a different body gets 400, as ACS does.
//!
//! Any request with a bearer token that isn't the mock managed identity's
//! for ACS is recorded as a violation, which tests check is empty.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use serde_json::{Value, json};

use super::MI_ACS_TOKEN;

/// Azure's message on a failed result. Must never reach a log, an email or
/// an audit event.
pub(crate) const AZURE_MESSAGE: &str = "ACSLEAK mailbox unavailable for alex@example.com";

/// One send request, whatever the answer.
#[derive(Debug, Clone)]
pub(crate) struct Attempt {
    pub request_id: String,
    pub first_sent: String,
    pub body: Value,
    pub raw: String,
}

/// A scripted answer to a send.
#[derive(Debug, Clone)]
pub(crate) enum Answer {
    /// This status, with an optional `Retry-After` in seconds.
    Status(u16, Option<u64>),
    /// 202 with this `Operation-Location` instead of the mock's own.
    AcceptAt(String),
    /// 202 with no `Operation-Location`.
    AcceptWithout,
}

#[derive(Default)]
pub(crate) struct AcsState {
    /// Every send request, in order.
    pub attempts: Mutex<Vec<Attempt>>,
    /// Answers to give before accepting, from the front.
    pub script: Mutex<VecDeque<Answer>>,
    /// Statuses to give for result polls, from the front. `Succeeded` once
    /// empty.
    pub statuses: Mutex<VecDeque<&'static str>>,
    /// `retry-after` seconds sent with a 202 and each poll answer.
    pub poll_after: Mutex<u64>,
    /// Every result poll, by operation ID.
    pub polls: Mutex<Vec<String>>,
    /// Bodies seen for each request ID, to answer 400 to a changed body.
    pub seen: Mutex<HashMap<String, String>>,
    /// Anything that broke the rules.
    pub violations: Mutex<Vec<String>>,
}

impl AcsState {
    pub(crate) fn violations(&self) -> Vec<String> {
        self.violations.lock().unwrap().clone()
    }

    pub(crate) fn attempts(&self) -> Vec<Attempt> {
        self.attempts.lock().unwrap().clone()
    }

    /// Every raw body ACS was sent, joined.
    pub(crate) fn all_bodies(&self) -> String {
        self.attempts()
            .iter()
            .map(|a| a.raw.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub(crate) struct MockAcs {
    pub addr: SocketAddr,
    pub state: Arc<AcsState>,
}

impl MockAcs {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn send_url(&self) -> String {
        format!("{}/emails:send?api-version=2025-09-01", self.url())
    }
}

pub(crate) async fn start() -> MockAcs {
    let state = Arc::new(AcsState::default());
    let app = Router::new()
        .route("/emails:send", post(send))
        .route("/emails/operations/{id}", get(result))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockAcs { addr, state }
}

/// A server that records every request it gets, for checking a token is
/// never sent to a host other than the endpoint.
pub(crate) struct Trap {
    pub addr: SocketAddr,
    pub hits: Arc<Mutex<Vec<String>>>,
}

pub(crate) async fn trap() -> Trap {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let h = hits.clone();
    let app = Router::new().fallback(any(move |headers: HeaderMap| {
        let h = h.clone();
        async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            h.lock().unwrap().push(auth);
            StatusCode::OK
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Trap { addr, hits }
}

fn bearer_ok(s: &AcsState, headers: &HeaderMap) -> bool {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bearer != MI_ACS_TOKEN {
        s.violations
            .lock()
            .unwrap()
            .push(format!("bearer token was {bearer:?}"));
        return false;
    }
    true
}

fn is_guid(v: &str) -> bool {
    let parts: Vec<&str> = v.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `Tue, 17 Nov 2026 09:30:05 GMT`.
fn is_imf_fixdate(v: &str) -> bool {
    let b = v.as_bytes();
    v.len() == 29
        && v.ends_with(" GMT")
        && b[3] == b','
        && b[4] == b' '
        && b[7] == b' '
        && b[11] == b' '
        && b[16] == b' '
        && b[19] == b':'
        && b[22] == b':'
}

async fn send(
    State(s): State<Arc<AcsState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !bearer_ok(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let violation = |why: String| {
        s.violations.lock().unwrap().push(why);
        StatusCode::BAD_REQUEST.into_response()
    };
    if q.get("api-version").map(String::as_str) != Some("2025-09-01") {
        return violation("wrong api-version".into());
    }
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let request_id = h("repeatability-request-id");
    let first_sent = h("repeatability-first-sent");
    if !is_guid(&request_id) || !is_imf_fixdate(&first_sent) {
        return violation(format!(
            "bad repeatability headers: {request_id:?} {first_sent:?}"
        ));
    }
    if h("content-type") != "application/json" {
        return violation("content-type isn't application/json".into());
    }
    let raw = String::from_utf8_lossy(&body).into_owned();
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        return violation("body isn't JSON".into());
    };
    // Only `to`: never cc or bcc.
    let r = &parsed["recipients"];
    if r.get("cc").is_some() || r.get("bcc").is_some() || !r["to"].is_array() {
        return violation("recipients other than to".into());
    }
    s.attempts.lock().unwrap().push(Attempt {
        request_id: request_id.clone(),
        first_sent: first_sent.clone(),
        body: parsed,
        raw: raw.clone(),
    });
    {
        let mut seen = s.seen.lock().unwrap();
        match seen.get(&request_id) {
            Some(prev) if *prev != raw => {
                return violation("a request ID was sent again with a different body".into());
            }
            _ => {
                seen.insert(request_id.clone(), raw);
            }
        }
    }
    let after = *s.poll_after.lock().unwrap();
    let accept = |loc: Option<String>| {
        let mut res = StatusCode::ACCEPTED.into_response();
        if let Some(loc) = loc {
            res.headers_mut()
                .insert("operation-location", loc.parse().unwrap());
        }
        res.headers_mut()
            .insert("retry-after", after.to_string().parse().unwrap());
        res
    };
    let host = h("host");
    match s.script.lock().unwrap().pop_front() {
        Some(Answer::Status(code, retry)) => {
            let mut res = (
                StatusCode::from_u16(code).unwrap(),
                [("content-type", "application/json")],
                json!({"error": {"code": "Err", "message": AZURE_MESSAGE}}).to_string(),
            )
                .into_response();
            if let Some(secs) = retry {
                res.headers_mut()
                    .insert("retry-after", secs.to_string().parse().unwrap());
            }
            res
        }
        Some(Answer::AcceptAt(loc)) => accept(Some(loc)),
        Some(Answer::AcceptWithout) => accept(None),
        None => accept(Some(format!(
            "http://{host}/emails/operations/{request_id}?api-version=2025-09-01"
        ))),
    }
}

async fn result(
    State(s): State<Arc<AcsState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !bearer_ok(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    s.polls.lock().unwrap().push(id.clone());
    let status = s
        .statuses
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or("Succeeded");
    let mut v = json!({ "id": id, "status": status });
    if status == "Failed" {
        v["error"] =
            json!({ "code": "EmailDroppedAllRecipientsSuppressed", "message": AZURE_MESSAGE });
    }
    let after = *s.poll_after.lock().unwrap();
    let mut res = (
        StatusCode::OK,
        [("content-type", "application/json")],
        v.to_string(),
    )
        .into_response();
    res.headers_mut()
        .insert("retry-after", after.to_string().parse().unwrap());
    res
}
