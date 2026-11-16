//! The audit sink: Keyring's own audit events, also sent to a custom table
//! in Log Analytics through the Azure Monitor Logs Ingestion API.
//!
//! Not to be confused with Key Vault's audit log, which the audit pages
//! read as the signed-in person. The sink only writes Keyring's own events.
//!
//! - **Who writes.** Every request carries a token for
//!   [`MONITOR_RESOURCE`] from Keyring's one configured managed identity,
//!   and nothing else. Never a person's token, never a client secret.
//! - **Who acted.** Each row's actor columns come from the event, which
//!   [`super::record`] got from the verified session at the moment of the
//!   action. The sender never looks up or guesses an actor.
//! - **Batching.** One sender task flushes every few seconds, or sooner
//!   once a batch is full, and keeps each call under the API's 1 MB limit.
//!   Bodies are gzipped.
//! - **Failure.** 429 and 5xx are retried with backoff, honouring
//!   `Retry-After`. A 401 or 403 drops the cached token and is retried. A
//!   batch any other 4xx refuses (or a redirect) is dropped and counted.
//!   The sink is degraded once retries have gone on for
//!   [`Tuning::degraded_after`] with no success. The queue is
//!   bounded and drops the oldest event when full. Every event has already
//!   gone to standard output, so the platform's console log still has it.
//! - **Shutdown.** [`AuditSink::shutdown`] sends what is queued, for up to
//!   [`Tuning::shutdown_grace`].
//!
//! Never logs a row, a body or a token: only status codes and counts.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, RETRY_AFTER};
use serde_json::{Map, Value};
use tokio::sync::{Notify, watch};

use super::{AuditEvent, KEYRING_VERSION, SCHEMA_VERSION, instance};
use crate::auth::assertion::ManagedIdentityTokens;

/// The resource the managed identity's token is asked for. The bearer
/// token's scope is `https://monitor.azure.com/.default`.
pub const MONITOR_RESOURCE: &str = "https://monitor.azure.com";

/// Logs Ingestion API version.
pub const API_VERSION: &str = "2023-01-01";

/// Batching, retry and failure timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// Most events waiting to be sent. Past this the oldest is dropped.
    pub queue_capacity: usize,
    /// Most events in one call.
    pub batch_max: usize,
    /// How often the queue is flushed when it isn't full.
    pub flush_every: Duration,
    /// Largest JSON body in one call, before gzip. The API takes 1 MB.
    pub max_body_bytes: usize,
    /// How long the sink must have been failing to count as degraded.
    pub degraded_after: Duration,
    /// How long shutdown waits to send what is queued.
    pub shutdown_grace: Duration,
    /// First wait before a retry. Doubles each time, up to `backoff_max`.
    pub backoff_first: Duration,
    pub backoff_max: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            queue_capacity: 10_000,
            batch_max: 500,
            flush_every: Duration::from_secs(5),
            // Under 1 MB (1,048,576 bytes) with room for the brackets.
            max_body_bytes: 1_000_000,
            degraded_after: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(10),
            backoff_first: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// Longest `Retry-After` believed.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// One column of the `KeyringAudit_CL` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// The table's column, as in `infra/modules/audit-sink.bicep`.
    pub name: &'static str,
    /// The same column in the stream Keyring sends. Only `time` differs:
    /// the rule's transform makes it `TimeGenerated`.
    pub stream: &'static str,
    /// Its Log Analytics type.
    pub kind: &'static str,
    /// The schema version 1 field it holds, or [`WRITER`].
    pub field: &'static str,
}

/// The `field` of the writer column, which isn't an event field.
pub const WRITER: &str = "writer";

const fn col(name: &'static str, kind: &'static str, field: &'static str) -> Column {
    Column {
        name,
        stream: name,
        kind,
        field,
    }
}

/// Every column, in order. The one source of truth for the table: the
/// Bicep module's stream and table columns and the event's field names are
/// all checked against this (`tests/audit_events.rs`). `TimeGenerated` is
/// the event's `time`, sent as `time` and renamed by the rule's transform. The actor columns name the person who acted and are empty only
/// for events with nobody signed in. The writer columns name Keyring.
pub const COLUMNS: &[Column] = &[
    Column {
        name: "TimeGenerated",
        stream: "time",
        kind: "datetime",
        field: "time",
    },
    col("EventId", "string", "event_id"),
    col("SchemaVersion", "int", "schema_version"),
    col("Action", "string", "action"),
    col("Outcome", "string", "outcome"),
    col("ReasonCode", "string", "reason_code"),
    col("ActorObjectId", "string", "actor_oid"),
    col("ActorTenantId", "string", "actor_tid"),
    col("ActorUpn", "string", "actor_upn"),
    col("SessionRef", "string", "session_ref"),
    col("ClientIp", "string", "client_ip"),
    col("UserAgent", "string", "user_agent"),
    col("Vault", "string", "vault"),
    col("ItemKind", "string", "item_kind"),
    col("ItemName", "string", "item_name"),
    col("ItemVersion", "string", "item_version"),
    col("KvRequestId", "string", "kv_request_id"),
    col("Reason", "string", "reason"),
    col("Ticket", "string", "ticket"),
    col("WriterIdentityClientId", "string", WRITER),
    col("KeyringInstance", "string", "instance"),
    col("KeyringVersion", "string", "keyring_version"),
];

/// The value of one column for an event. `None` leaves it out of the row.
fn value(ev: &AuditEvent, field: &str, writer: &str) -> Option<Value> {
    let s = |v: &Option<String>| v.clone().map(Value::String);
    match field {
        "time" => Some(ev.time.clone().into()),
        "event_id" => Some(ev.event_id.clone().into()),
        "schema_version" => Some(SCHEMA_VERSION.into()),
        "action" => Some(ev.action.as_str().into()),
        "outcome" => Some(ev.outcome.as_str().into()),
        "reason_code" => s(&ev.reason_code),
        "actor_oid" => s(&ev.actor_oid),
        "actor_tid" => s(&ev.actor_tid),
        "actor_upn" => s(&ev.actor_upn),
        "session_ref" => s(&ev.session_ref),
        "client_ip" => s(&ev.client_ip),
        "user_agent" => s(&ev.user_agent),
        "vault" => s(&ev.vault),
        "item_kind" => ev.item_kind.map(Value::from),
        "item_name" => s(&ev.item_name),
        "item_version" => s(&ev.item_version),
        "kv_request_id" => s(&ev.kv_request_id),
        "reason" => s(&ev.reason),
        "ticket" => s(&ev.ticket),
        "instance" => Some(instance().into()),
        "keyring_version" => Some(KEYRING_VERSION.into()),
        WRITER => Some(writer.into()),
        other => unreachable!("column for unknown field {other}"),
    }
}

/// One event as a row of the stream, JSON.
pub fn row(ev: &AuditEvent, writer: &str) -> Vec<u8> {
    let mut m = Map::new();
    for c in COLUMNS {
        if let Some(v) = value(ev, c.field, writer) {
            m.insert(c.stream.to_owned(), v);
        }
    }
    serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
}

/// Counts since start, for `/healthz/audit`.
#[derive(Debug, Default)]
struct Counts {
    sent: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_rejected: AtomicU64,
    dropped_at_shutdown: AtomicU64,
    failed_attempts: AtomicU64,
}

/// What `/healthz/audit` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    pub degraded: bool,
    pub queued: usize,
    pub sent: u64,
    pub dropped_queue_full: u64,
    pub dropped_rejected: u64,
    pub dropped_at_shutdown: u64,
    pub failed_attempts: u64,
}

/// The running sink. Shared by the app state and the session store.
pub struct AuditSink {
    url: String,
    tuning: Tuning,
    identity: Arc<ManagedIdentityTokens>,
    http: reqwest::Client,
    queue: Mutex<VecDeque<Vec<u8>>>,
    /// Wakes the sender when a batch is full.
    wake: Notify,
    counts: Counts,
    /// When sending started failing, cleared by the next success.
    failing_since: Mutex<Option<Instant>>,
    /// Rows in the batch being sent: off the queue, not yet counted.
    in_flight: AtomicU64,
    stop: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink")
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How one call ended.
enum Sent {
    Ok,
    /// Try again after this long.
    Retry(Duration),
    /// The batch was refused for good.
    Rejected,
}

impl AuditSink {
    /// Start the sender task. Needs a Tokio runtime. `http` must be the
    /// main client: HTTPS only, no redirects.
    pub fn start(
        url: String,
        tuning: Tuning,
        identity: Arc<ManagedIdentityTokens>,
        http: reqwest::Client,
    ) -> Arc<Self> {
        let (stop, stop_rx) = watch::channel(false);
        let sink = Arc::new(Self {
            url,
            tuning,
            identity,
            http,
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            counts: Counts::default(),
            failing_since: Mutex::new(None),
            in_flight: AtomicU64::new(0),
            stop,
            task: Mutex::new(None),
        });
        let task = tokio::spawn(sink.clone().run(stop_rx));
        *lock(&sink.task) = Some(task);
        sink
    }

    /// Queue an event. Never blocks on the network. When the queue is full
    /// the oldest event is dropped and counted.
    pub fn enqueue(&self, ev: &AuditEvent) {
        let row = row(ev, self.identity.client_id());
        let len = {
            let mut q = lock(&self.queue);
            if q.len() >= self.tuning.queue_capacity {
                q.pop_front();
                self.counts
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(row);
            q.len()
        };
        if len >= self.tuning.batch_max {
            self.wake.notify_one();
        }
    }

    /// True once sending has failed for longer than
    /// [`Tuning::degraded_after`] with no success since.
    pub fn degraded(&self) -> bool {
        lock(&self.failing_since).is_some_and(|t| t.elapsed() >= self.tuning.degraded_after)
    }

    pub fn health(&self) -> Health {
        let c = &self.counts;
        Health {
            degraded: self.degraded(),
            queued: lock(&self.queue).len(),
            sent: c.sent.load(Ordering::Relaxed),
            dropped_queue_full: c.dropped_queue_full.load(Ordering::Relaxed),
            dropped_rejected: c.dropped_rejected.load(Ordering::Relaxed),
            dropped_at_shutdown: c.dropped_at_shutdown.load(Ordering::Relaxed),
            failed_attempts: c.failed_attempts.load(Ordering::Relaxed),
        }
    }

    /// Send what is queued, for up to [`Tuning::shutdown_grace`], then stop
    /// the sender. Whatever is left is counted as dropped.
    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let task = lock(&self.task).take();
        let Some(mut task) = task else { return };
        if tokio::time::timeout(self.tuning.shutdown_grace, &mut task)
            .await
            .is_err()
        {
            task.abort();
            // The batch being sent when the task was stopped is lost too.
            let left = std::mem::take(&mut *lock(&self.queue)).len()
                + self.in_flight.swap(0, Ordering::Relaxed) as usize;
            self.count_shutdown_drop(left);
            tracing::warn!(
                dropped = left,
                "audit sink: shutdown grace ran out; events still queued were only written to standard output"
            );
        }
    }

    async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        'outer: loop {
            // On the timer, send everything. When woken by a full batch,
            // send only full batches and leave the rest for the timer.
            let timed = tokio::select! {
                () = tokio::time::sleep(self.tuning.flush_every) => true,
                () = self.wake.notified() => false,
                _ = stop.wait_for(|s| *s) => break,
            };
            loop {
                if !timed && lock(&self.queue).len() < self.tuning.batch_max {
                    break;
                }
                let Some(batch) = self.next_batch() else {
                    break;
                };
                if !self.deliver(batch, None, &mut stop).await {
                    break 'outer;
                }
            }
            if *stop.borrow() {
                break;
            }
        }
        // Shutdown: send what is left, within the grace period.
        let deadline = Instant::now() + self.tuning.shutdown_grace;
        while let Some(batch) = self.next_batch() {
            if Instant::now() >= deadline {
                self.count_shutdown_drop(batch.len());
                continue;
            }
            self.deliver(batch, Some(deadline), &mut stop).await;
        }
    }

    fn count_shutdown_drop(&self, n: usize) {
        self.counts
            .dropped_at_shutdown
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Take the next batch off the queue: at most `batch_max` rows and
    /// `max_body_bytes` of JSON. A row too big to ever send is dropped.
    fn next_batch(&self) -> Option<Vec<Vec<u8>>> {
        let mut q = lock(&self.queue);
        let mut batch = Vec::new();
        // `[` and `]`.
        let mut size = 2;
        while let Some(row) = q.front() {
            if row.len() + 2 > self.tuning.max_body_bytes {
                q.pop_front();
                self.counts.dropped_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("audit sink: an event too large to send was dropped");
                continue;
            }
            let add = row.len() + usize::from(!batch.is_empty());
            if batch.len() >= self.tuning.batch_max || size + add > self.tuning.max_body_bytes {
                break;
            }
            size += add;
            batch.push(q.pop_front().unwrap_or_default());
        }
        (!batch.is_empty()).then_some(batch)
    }

    /// [`Self::send_batch`], with the batch's rows held in `in_flight`
    /// until it has been counted one way or another, so a batch cut off by
    /// the end of the shutdown grace is counted as dropped.
    async fn deliver(
        &self,
        batch: Vec<Vec<u8>>,
        deadline: Option<Instant>,
        stop: &mut watch::Receiver<bool>,
    ) -> bool {
        self.in_flight.store(batch.len() as u64, Ordering::Relaxed);
        let more = self.send_batch(batch, deadline, stop).await;
        self.in_flight.store(0, Ordering::Relaxed);
        more
    }

    /// Send one batch until it is accepted or refused for good. Before
    /// shutdown, retries until it works; after, only until `deadline`.
    /// False if shutdown began while waiting to retry.
    async fn send_batch(
        &self,
        batch: Vec<Vec<u8>>,
        deadline: Option<Instant>,
        stop: &mut watch::Receiver<bool>,
    ) -> bool {
        let body = match gzip_array(&batch) {
            Ok(b) => b,
            Err(_) => {
                tracing::warn!("audit sink: could not compress a batch");
                self.counts
                    .dropped_rejected
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                return true;
            }
        };
        let mut backoff = self.tuning.backoff_first;
        loop {
            let sent = match deadline {
                None => self.send(&body).await,
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(left, self.send(&body)).await {
                        Ok(sent) => sent,
                        Err(_) => {
                            self.count_shutdown_drop(batch.len());
                            return false;
                        }
                    }
                }
            };
            match sent {
                Sent::Ok => {
                    *lock(&self.failing_since) = None;
                    self.counts
                        .sent
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    return true;
                }
                Sent::Rejected => {
                    // Starts the degraded clock as a retry does: if every
                    // batch is refused (a changed table, say), events are
                    // being lost. The next accepted batch clears it, so one
                    // bad batch doesn't hold up reveals for good.
                    self.note_failure();
                    self.counts
                        .dropped_rejected
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    return true;
                }
                Sent::Retry(after) => {
                    self.note_failure();
                    let wait = if after.is_zero() { backoff } else { after };
                    backoff = (backoff * 2).min(self.tuning.backoff_max);
                    match deadline {
                        Some(d) => {
                            if Instant::now() + wait >= d {
                                self.count_shutdown_drop(batch.len());
                                return false;
                            }
                            tokio::time::sleep(wait).await;
                        }
                        None => {
                            tokio::select! {
                                () = tokio::time::sleep(wait) => {}
                                _ = stop.wait_for(|s| *s) => {
                                    // Put it back at the front for the
                                    // shutdown flush.
                                    let mut q = lock(&self.queue);
                                    for row in batch.into_iter().rev() {
                                        q.push_front(row);
                                    }
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn note_failure(&self) {
        self.counts.failed_attempts.fetch_add(1, Ordering::Relaxed);
        lock(&self.failing_since).get_or_insert_with(Instant::now);
    }

    async fn send(&self, body: &[u8]) -> Sent {
        let token = match self.identity.token(MONITOR_RESOURCE).await {
            Ok(t) => t,
            // Already logged by the token source, without the token.
            Err(_) => return Sent::Retry(Duration::ZERO),
        };
        let res = self
            .http
            .post(&self.url)
            .header(AUTHORIZATION, format!("Bearer {}", token.expose()))
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_ENCODING, "gzip")
            .body(body.to_vec())
            .send()
            .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                let e = crate::http::HttpError::from(e);
                tracing::warn!(error = %e, "audit sink: ingestion endpoint unreachable");
                return Sent::Retry(Duration::ZERO);
            }
        };
        let status = res.status().as_u16();
        // The body is never read or logged.
        match status {
            200..=299 => Sent::Ok,
            401 | 403 => {
                tracing::warn!(
                    status,
                    "audit sink: ingestion refused Keyring's managed identity. Check it has Monitoring Metrics Publisher on the audit data collection rule"
                );
                self.identity.forget(MONITOR_RESOURCE).await;
                Sent::Retry(Duration::ZERO)
            }
            408 | 429 | 500..=599 => {
                tracing::warn!(status, "audit sink: ingestion busy or failing; will retry");
                Sent::Retry(retry_after(res.headers()))
            }
            _ => {
                tracing::warn!(status, "audit sink: ingestion refused a batch; dropped");
                Sent::Rejected
            }
        }
    }
}

/// `Retry-After` in seconds, capped. Zero when absent or unreadable.
fn retry_after(h: &reqwest::header::HeaderMap) -> Duration {
    h.get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_default()
        .min(MAX_RETRY_AFTER)
}

/// The rows as one gzipped JSON array.
fn gzip_array(rows: &[Vec<u8>]) -> std::io::Result<Vec<u8>> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"[")?;
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            gz.write_all(b",")?;
        }
        gz.write_all(r)?;
    }
    gz.write_all(b"]")?;
    gz.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Action, Outcome};

    fn full_event() -> AuditEvent {
        let mut ev = AuditEvent::new(Action::SecretReveal, Outcome::Success);
        for f in [
            &mut ev.reason_code,
            &mut ev.actor_oid,
            &mut ev.actor_tid,
            &mut ev.actor_upn,
            &mut ev.session_ref,
            &mut ev.client_ip,
            &mut ev.user_agent,
            &mut ev.vault,
            &mut ev.item_name,
            &mut ev.item_version,
            &mut ev.kv_request_id,
            &mut ev.reason,
            &mut ev.ticket,
        ] {
            *f = Some("x".into());
        }
        ev
    }

    #[test]
    fn every_column_has_a_value_and_names_are_unique() {
        let ev = full_event();
        let row: Value = serde_json::from_slice(&row(&ev, "w")).unwrap();
        let obj = row.as_object().unwrap();
        assert_eq!(obj.len(), COLUMNS.len());
        assert_eq!(obj["time"], ev.time.as_str());
        assert_eq!(obj["SchemaVersion"], SCHEMA_VERSION);
        assert_eq!(obj["WriterIdentityClientId"], "w");
        assert_eq!(obj["Action"], "secret.reveal");
        for c in COLUMNS {
            assert!(matches!(c.kind, "string" | "int" | "datetime"), "{c:?}");
        }
    }

    #[test]
    fn absent_fields_are_left_out() {
        let ev = AuditEvent::new(Action::SessionSignInFailed, Outcome::Refused);
        let row: Value = serde_json::from_slice(&row(&ev, "w")).unwrap();
        assert!(row.get("ActorObjectId").is_none());
        assert!(row.get("ActorUpn").is_none());
        assert_eq!(row["WriterIdentityClientId"], "w");
    }

    #[test]
    fn retry_after_is_read_and_capped() {
        let mut h = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after(&h), Duration::ZERO);
        h.insert(RETRY_AFTER, "7".parse().unwrap());
        assert_eq!(retry_after(&h), Duration::from_secs(7));
        h.insert(RETRY_AFTER, "99999".parse().unwrap());
        assert_eq!(retry_after(&h), MAX_RETRY_AFTER);
        h.insert(
            RETRY_AFTER,
            "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&h), Duration::ZERO);
    }

    #[test]
    fn gzip_round_trips() {
        use std::io::Read;
        let gz = gzip_array(&[b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]).unwrap();
        let mut out = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, r#"[{"a":1},{"b":2}]"#);
    }
}
