//! The email sender: a bounded queue and one task that sends each email
//! through Azure Communication Services' Email REST API as Keyring's
//! managed identity, then polls for its result.
//!
//! - **Who sends.** Every request carries a token for [`ACS_RESOURCE`]
//!   from Keyring's one configured managed identity. Never a person's
//!   token, an access key or a connection string.
//! - **Sending.** `POST {endpoint}/emails:send?api-version=`[`API_VERSION`]
//!   with `Repeatability-Request-Id` (a new UUID) and
//!   `Repeatability-First-Sent` (when it was first tried). A retry sends
//!   the same ID, the same first-sent time and the same body, so ACS can
//!   tell it from a new email. ACS remembers a request for five minutes,
//!   so once an email is [`Tuning::give_up_after`] old the sender stops
//!   trying it. It is never tried again under a new ID, which could send
//!   it twice.
//! - **Answers.** 202 is accepted. 429, 408 and 5xx are retried, honouring
//!   `Retry-After`. 409 means the first try is still being processed, and
//!   is retried the same way. 412 means the first try is too old to match,
//!   so the sender gives up. 401 and 403 drop the cached token and retry.
//!   Any other answer (including a redirect) is refused for good.
//! - **Result.** The 202's `Operation-Location` is checked to be on the
//!   same scheme, host and port as the endpoint, under
//!   `/emails/operations/`, before it is fetched with the token, so a
//!   wrong or hostile answer can't send the token anywhere else. It is
//!   polled at most [`MAX_POLLS`] times. Each email is then counted as
//!   delivered, failed or unknown, and gets one audit event, `notify.sent`
//!   or `notify.failed`.
//! - **Never logged.** Recipient addresses, bodies, tokens and Azure's
//!   error messages. A failed result's message is never read into a
//!   string: only its status is parsed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use openidconnect::url::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Notify, watch};

use super::rate::RateLimit;
use super::{
    Address, EmailBody, EmailContext, Enqueued, ItemRef, MAX_BODY_BYTES, MAX_RECIPIENTS,
    Notification, NotifyType, subject,
};
use crate::audit::sink::AuditSink;
use crate::audit::{Action, AuditEvent, Outcome};
use crate::auth::assertion::ManagedIdentityTokens;

/// The resource the managed identity's token is asked for. The bearer
/// token's scope is `https://communication.azure.com/.default`.
pub const ACS_RESOURCE: &str = "https://communication.azure.com";

/// Email REST API version, for both Send and Get Send Result. The current
/// non-preview version.
pub const API_VERSION: &str = "2025-09-01";

/// Most times a result is polled before it is counted as unknown.
pub const MAX_POLLS: u32 = 3;

/// Timings and sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// Most emails waiting. Past this, new ones are refused.
    pub queue_capacity: usize,
    /// How long after its first try an email is given up. ACS remembers a
    /// repeatable request for five minutes.
    pub give_up_after: Duration,
    /// First wait before a retry. Doubles each time, up to `backoff_max`.
    pub backoff_first: Duration,
    pub backoff_max: Duration,
    /// Longest wait between polls, whatever `Retry-After` says.
    pub poll_wait_max: Duration,
    /// Wait between polls when ACS doesn't say.
    pub poll_wait_default: Duration,
    /// Longest `Retry-After` believed on a send.
    pub retry_after_max: Duration,
    /// How long sending must have been failing to count as degraded.
    pub degraded_after: Duration,
    /// How long shutdown waits to send what is queued.
    pub shutdown_grace: Duration,
    /// The per-recipient rate limit's window. One hour outside tests.
    pub rate_window: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            queue_capacity: 1_000,
            give_up_after: Duration::from_secs(300),
            backoff_first: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            poll_wait_max: Duration::from_secs(30),
            poll_wait_default: Duration::from_secs(5),
            retry_after_max: Duration::from_secs(60),
            degraded_after: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(10),
            rate_window: Duration::from_secs(3600),
        }
    }
}

/// What the notifier needs to run. Built from the configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `{endpoint}/emails:send?api-version=...`.
    pub send_url: String,
    pub sender: Address,
    pub admins: Vec<Address>,
    /// `None` lets any domain through.
    pub allowed_domains: Option<Vec<String>>,
    pub types: Vec<NotifyType>,
    pub audit_recipients: bool,
    pub per_hour: u32,
    /// `APP_BASE_URL`, for links to items.
    pub base_url: String,
    pub tuning: Tuning,
}

/// What an email's audit event needs: its type, item and recipients.
type JobRef = (NotifyType, Option<ItemRef>, Vec<Address>);

/// One email waiting to be sent.
struct Job {
    kind: NotifyType,
    item: Option<ItemRef>,
    to: Vec<Address>,
    body: Vec<u8>,
}

/// Counts since start, for `/healthz/notify`.
#[derive(Debug, Default)]
struct Counts {
    delivered: AtomicU64,
    failed: AtomicU64,
    unknown: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_at_shutdown: AtomicU64,
    rate_limited: AtomicU64,
    not_allowed: AtomicU64,
    invalid: AtomicU64,
    failed_attempts: AtomicU64,
}

/// What `/healthz/notify` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    pub degraded: bool,
    pub queued: usize,
    pub delivered: u64,
    pub failed: u64,
    pub unknown: u64,
    pub dropped_queue_full: u64,
    pub dropped_at_shutdown: u64,
    pub rate_limited: u64,
    pub not_allowed: u64,
    pub invalid: u64,
    pub failed_attempts: u64,
}

/// How one email ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// ACS said `Succeeded`.
    Delivered,
    /// ACS accepted it, but its result wasn't known after the polls.
    AcceptedUnknown,
    /// ACS said `Failed`.
    DeliveryFailed,
    /// ACS said `Canceled`.
    Canceled,
    /// ACS refused the request for good: nothing was sent.
    Rejected,
    /// Given up before ACS accepted it, after a try that may have reached
    /// it (a network error, 5xx, 409 or 412): it may have been sent.
    GaveUpMaybeSent,
    /// Given up before ACS accepted it, and no try reached it.
    GaveUp,
    /// Still queued or being tried when Keyring shut down.
    Shutdown,
}

impl Ending {
    fn action(self) -> Action {
        match self {
            Self::Delivered | Self::AcceptedUnknown => Action::NotifySent,
            _ => Action::NotifyFailed,
        }
    }

    fn outcome(self) -> Outcome {
        match self {
            Self::Delivered | Self::AcceptedUnknown => Outcome::Success,
            _ => Outcome::Failed,
        }
    }

    /// `reason_code` on the event. `None` for a delivered email.
    fn code(self) -> Option<&'static str> {
        match self {
            Self::Delivered => None,
            Self::AcceptedUnknown => Some("status_unknown"),
            Self::DeliveryFailed => Some("delivery_failed"),
            Self::Canceled => Some("delivery_canceled"),
            Self::Rejected => Some("rejected"),
            Self::GaveUpMaybeSent => Some("gave_up_maybe_sent"),
            Self::GaveUp => Some("gave_up"),
            Self::Shutdown => Some("shutdown"),
        }
    }
}

/// The running notifier. Shared by the app state.
pub struct Notifier {
    settings: Settings,
    identity: Arc<ManagedIdentityTokens>,
    http: reqwest::Client,
    audit: Option<Arc<AuditSink>>,
    rate: RateLimit,
    /// Scheme, host and port of the send URL. Poll URLs must match it.
    origin: (String, String, Option<u16>),
    queue: Mutex<VecDeque<Job>>,
    wake: Notify,
    counts: Counts,
    failing_since: Mutex<Option<Instant>>,
    /// The job being sent, so shutdown can count it.
    in_flight: Mutex<Option<JobRef>>,
    stop: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Queue a notification on `notifier`, or [`Enqueued::Off`] when email is
/// off. For callers holding `state.notifier.as_deref()`.
pub fn enqueue<B: EmailBody>(notifier: Option<&Notifier>, n: Notification<B>) -> Enqueued {
    match notifier {
        Some(x) => x.enqueue(n),
        None => Enqueued::Off,
    }
}

impl Notifier {
    /// Start the sender task. Needs a Tokio runtime. `http` must be the
    /// main client: HTTPS only outside tests, no redirects.
    pub fn start(
        settings: Settings,
        identity: Arc<ManagedIdentityTokens>,
        http: reqwest::Client,
        audit: Option<Arc<AuditSink>>,
    ) -> Arc<Self> {
        let url =
            Url::parse(&settings.send_url).expect("the send URL was built from checked parts");
        let origin = (
            url.scheme().to_owned(),
            url.host_str().unwrap_or_default().to_ascii_lowercase(),
            url.port(),
        );
        let (stop, stop_rx) = watch::channel(false);
        let n = Arc::new(Self {
            rate: RateLimit::new(
                settings.per_hour,
                settings.tuning.rate_window,
                crate::notify::rate::DEFAULT_MAX_ENTRIES,
            ),
            settings,
            identity,
            http,
            audit,
            origin,
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            counts: Counts::default(),
            failing_since: Mutex::new(None),
            in_flight: Mutex::new(None),
            stop,
            task: Mutex::new(None),
        });
        let task = tokio::spawn(n.clone().run(stop_rx));
        *lock(&n.task) = Some(task);
        n
    }

    /// True when this type is in `KEYRING_NOTIFY_TYPES`.
    pub fn is_on(&self, kind: NotifyType) -> bool {
        self.settings.types.contains(&kind)
    }

    /// `KEYRING_NOTIFY_ADMINS`, for health and fallback notices.
    pub fn admins(&self) -> &[Address] {
        &self.settings.admins
    }

    /// Queue a notification. Returns at once, never blocks on the network
    /// and never fails the caller. See [`Enqueued`] for what happened.
    /// Recipients outside `KEYRING_NOTIFY_ALLOWED_DOMAINS` or over their
    /// rate limit are left out; the rest get one email together, and that
    /// counts as queued. With nobody left, [`Enqueued::RateLimited`] when
    /// the rate limit alone left everyone out, otherwise
    /// [`Enqueued::NoRecipients`].
    pub fn enqueue<B: EmailBody>(&self, n: Notification<B>) -> Enqueued {
        if !self.is_on(n.kind) {
            return Enqueued::Off;
        }
        if lock(&self.queue).len() >= self.settings.tuning.queue_capacity {
            self.counts
                .dropped_queue_full
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                kind = n.kind.as_str(),
                "notify: queue full; email not queued"
            );
            self.audit_event(
                n.kind,
                n.item.as_ref(),
                &n.to,
                Ending::GaveUp,
                Some("queue_full"),
            );
            return Enqueued::QueueFull;
        }
        // Rendered before any rate limit is used, so a body that can't be
        // sent costs nobody their count.
        let link = n.item.as_ref().map(|i| i.link(&self.settings.base_url));
        let ctx = EmailContext {
            kind: n.kind,
            item: n.item.as_ref(),
            link: link.as_deref(),
        };
        let rendered = match n.data.render(&ctx) {
            Ok(r) if r.text.len() + r.html.len() <= MAX_BODY_BYTES => r,
            _ => {
                self.counts.invalid.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    kind = n.kind.as_str(),
                    "notify: email body couldn't be rendered or was too large; not queued"
                );
                return Enqueued::Invalid;
            }
        };
        let mut to: Vec<Address> = Vec::new();
        let mut refused = false;
        for a in n.to {
            // One mailbox once, however its address is written.
            let key = a.mailbox_key();
            if to.iter().any(|t| t.mailbox_key() == key) {
                continue;
            }
            if !self.allowed(&a) || to.len() >= MAX_RECIPIENTS {
                self.counts.not_allowed.fetch_add(1, Ordering::Relaxed);
                refused = true;
                continue;
            }
            if !self.rate.allow(n.kind, &a) {
                self.counts.rate_limited.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            to.push(a);
        }
        if to.is_empty() {
            tracing::info!(
                kind = n.kind.as_str(),
                "notify: no recipient left after the allow-list and rate limit"
            );
            // Only the rate limit stood in the way: a later try can send.
            return if refused {
                Enqueued::NoRecipients
            } else {
                Enqueued::RateLimited
            };
        }
        let body = json!({
            "senderAddress": self.settings.sender.as_str(),
            "recipients": {
                "to": to.iter().map(|a| json!({ "address": a.as_str() })).collect::<Vec<_>>(),
            },
            "content": {
                "subject": subject(n.kind, n.item.as_ref()),
                "plainText": rendered.text,
                "html": rendered.html,
            },
            "userEngagementTrackingDisabled": true,
        });
        let body = serde_json::to_vec(&body).unwrap_or_default();
        let recipients = to.len();
        {
            let mut q = lock(&self.queue);
            if q.len() >= self.settings.tuning.queue_capacity {
                drop(q);
                self.counts
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                self.audit_event(
                    n.kind,
                    n.item.as_ref(),
                    &to,
                    Ending::GaveUp,
                    Some("queue_full"),
                );
                return Enqueued::QueueFull;
            }
            q.push_back(Job {
                kind: n.kind,
                item: n.item,
                to,
                body,
            });
        }
        self.wake.notify_one();
        Enqueued::Queued { recipients }
    }

    fn allowed(&self, a: &Address) -> bool {
        match &self.settings.allowed_domains {
            None => true,
            Some(list) => list.iter().any(|d| d == a.domain()),
        }
    }

    /// True once sending has failed for longer than
    /// [`Tuning::degraded_after`] with no success since.
    pub fn degraded(&self) -> bool {
        lock(&self.failing_since)
            .is_some_and(|t| t.elapsed() >= self.settings.tuning.degraded_after)
    }

    pub fn health(&self) -> Health {
        let c = &self.counts;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Health {
            degraded: self.degraded(),
            queued: lock(&self.queue).len(),
            delivered: l(&c.delivered),
            failed: l(&c.failed),
            unknown: l(&c.unknown),
            dropped_queue_full: l(&c.dropped_queue_full),
            dropped_at_shutdown: l(&c.dropped_at_shutdown),
            rate_limited: l(&c.rate_limited),
            not_allowed: l(&c.not_allowed),
            invalid: l(&c.invalid),
            failed_attempts: l(&c.failed_attempts),
        }
    }

    /// Send what is queued, for up to [`Tuning::shutdown_grace`], then stop.
    /// Whatever is left is counted and gets a `notify.failed` event.
    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let task = lock(&self.task).take();
        let Some(mut task) = task else { return };
        if tokio::time::timeout(self.settings.tuning.shutdown_grace, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let mut left: Vec<JobRef> = std::mem::take(&mut *lock(&self.queue))
                .into_iter()
                .map(|j| (j.kind, j.item, j.to))
                .collect();
            if let Some(j) = lock(&self.in_flight).take() {
                left.push(j);
            }
            for (kind, item, to) in &left {
                self.finish(*kind, item.as_ref(), to, Ending::Shutdown);
            }
            tracing::warn!(
                dropped = left.len(),
                "notify: shutdown grace ran out; emails still queued were not sent"
            );
        }
    }

    async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        loop {
            let job = lock(&self.queue).pop_front();
            let Some(job) = job else {
                if *stop.borrow() {
                    return;
                }
                tokio::select! {
                    () = self.wake.notified() => {}
                    _ = stop.wait_for(|s| *s) => {}
                }
                continue;
            };
            *lock(&self.in_flight) = Some((job.kind, job.item.clone(), job.to.clone()));
            let ending = self.deliver(&job).await;
            lock(&self.in_flight).take();
            self.finish(job.kind, job.item.as_ref(), &job.to, ending);
        }
    }

    /// Count an ending, log it without any address, and write its event.
    fn finish(&self, kind: NotifyType, item: Option<&ItemRef>, to: &[Address], e: Ending) {
        let c = &self.counts;
        let counter = match e {
            Ending::Delivered => &c.delivered,
            Ending::AcceptedUnknown | Ending::GaveUpMaybeSent => &c.unknown,
            Ending::Shutdown => &c.dropped_at_shutdown,
            _ => &c.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            kind = kind.as_str(),
            recipients = to.len(),
            result = e.code().unwrap_or("delivered"),
            "notify: email finished"
        );
        self.audit_event(kind, item, to, e, None);
    }

    fn audit_event(
        &self,
        kind: NotifyType,
        item: Option<&ItemRef>,
        to: &[Address],
        e: Ending,
        code: Option<&'static str>,
    ) {
        let mut ev = AuditEvent::new(e.action(), e.outcome());
        ev.reason_code = code.or(e.code()).map(str::to_owned);
        ev.notify_type = Some(kind.as_str());
        ev.notify_recipient_count = Some(to.len() as u64);
        if self.settings.audit_recipients {
            ev.notify_recipients =
                Some(to.iter().map(Address::as_str).collect::<Vec<_>>().join(","));
        }
        if let Some(i) = item {
            ev.vault = Some(i.vault().to_owned());
            ev.item_kind = Some(i.kind().as_str());
            ev.item_name = Some(i.name().to_owned());
        }
        crate::audit::record(ev, self.audit.as_deref());
    }

    fn note_failure(&self) {
        self.counts.failed_attempts.fetch_add(1, Ordering::Relaxed);
        lock(&self.failing_since).get_or_insert_with(Instant::now);
    }

    /// Send one email and poll for its result.
    async fn deliver(&self, job: &Job) -> Ending {
        let t = self.settings.tuning;
        let started = Instant::now();
        let request_id = crate::audit::new_uuid();
        let first_sent = imf_fixdate(SystemTime::now());
        let mut backoff = t.backoff_first;
        // Did a try possibly reach ACS and get processed?
        let mut maybe_sent = false;
        let op = loop {
            let left = t.give_up_after.saturating_sub(started.elapsed());
            if left.is_zero() {
                return self.gave_up(maybe_sent);
            }
            let wait = match self.send(job, &request_id, &first_sent).await {
                Send::Accepted(op) => {
                    *lock(&self.failing_since) = None;
                    break op;
                }
                Send::Rejected => {
                    self.note_failure();
                    return Ending::Rejected;
                }
                Send::TooOld => {
                    self.note_failure();
                    return Ending::GaveUpMaybeSent;
                }
                Send::Retry { after, reached } => {
                    self.note_failure();
                    maybe_sent |= reached;
                    let w = if after.is_zero() {
                        backoff
                    } else {
                        after.min(t.retry_after_max)
                    };
                    backoff = (backoff * 2).min(t.backoff_max);
                    w
                }
            };
            // Never wait past the window: the next try would only get 412.
            let left = t.give_up_after.saturating_sub(started.elapsed());
            if wait >= left {
                tokio::time::sleep(left).await;
                return self.gave_up(maybe_sent);
            }
            tokio::time::sleep(wait).await;
        };
        let Some((poll_url, mut wait)) = op else {
            return Ending::AcceptedUnknown;
        };
        for _ in 0..MAX_POLLS {
            tokio::time::sleep(wait.min(t.poll_wait_max)).await;
            match self.poll(&poll_url).await {
                Poll::Final(e) => return e,
                Poll::Pending(after) => {
                    wait = if after.is_zero() {
                        t.poll_wait_default
                    } else {
                        after
                    };
                }
            }
        }
        Ending::AcceptedUnknown
    }

    fn gave_up(&self, maybe_sent: bool) -> Ending {
        tracing::warn!(
            "notify: an email was still not accepted after ACS's five-minute repeat window; given up, not retried under a new ID"
        );
        if maybe_sent {
            Ending::GaveUpMaybeSent
        } else {
            Ending::GaveUp
        }
    }

    async fn send(&self, job: &Job, request_id: &str, first_sent: &str) -> Send {
        let token = match self.identity.token(ACS_RESOURCE).await {
            Ok(t) => t,
            // Already logged by the token source, without the token.
            Err(_) => {
                return Send::Retry {
                    after: Duration::ZERO,
                    reached: false,
                };
            }
        };
        let res = self
            .http
            .post(&self.settings.send_url)
            .header(AUTHORIZATION, format!("Bearer {}", token.expose()))
            .header(CONTENT_TYPE, "application/json")
            .header("Repeatability-Request-Id", request_id)
            .header("Repeatability-First-Sent", first_sent)
            .body(job.body.clone())
            .send()
            .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                let e = crate::http::HttpError::from(e);
                tracing::warn!(error = %e, "notify: ACS endpoint unreachable; will retry");
                // The request may have got there before the connection
                // broke.
                return Send::Retry {
                    after: Duration::ZERO,
                    reached: true,
                };
            }
        };
        let status = res.status().as_u16();
        // The body is never read or logged: it may hold Azure's message.
        match status {
            202 => {
                let op = self.operation(res.headers());
                if op.is_none() {
                    tracing::warn!(
                        "notify: ACS accepted an email without a usable Operation-Location; its result won't be known"
                    );
                }
                Send::Accepted(op)
            }
            401 | 403 => {
                tracing::warn!(
                    status,
                    "notify: ACS refused Keyring's managed identity. Check its role on the Communication Services resource"
                );
                self.identity.forget(ACS_RESOURCE).await;
                Send::Retry {
                    after: Duration::ZERO,
                    reached: false,
                }
            }
            409 => {
                tracing::info!("notify: ACS is still processing the first try; will check again");
                Send::Retry {
                    after: retry_after(res.headers()),
                    reached: true,
                }
            }
            412 => {
                tracing::warn!(
                    "notify: ACS no longer remembers the first try (412); given up, not retried under a new ID"
                );
                Send::TooOld
            }
            408 | 429 | 500..=599 => {
                tracing::warn!(status, "notify: ACS busy or failing; will retry");
                Send::Retry {
                    after: retry_after(res.headers()),
                    reached: status != 429,
                }
            }
            _ => {
                tracing::warn!(status, "notify: ACS refused an email; dropped");
                Send::Rejected
            }
        }
    }

    /// The poll URL and first wait from a 202, if the URL is safe to send
    /// the token to.
    fn operation(&self, h: &reqwest::header::HeaderMap) -> Option<(String, Duration)> {
        let raw = h.get("operation-location")?.to_str().ok()?;
        let url = checked_poll_url(raw, &self.origin)?;
        Some((url, retry_after(h)))
    }

    async fn poll(&self, url: &str) -> Poll {
        let pending = Poll::Pending(Duration::ZERO);
        let Ok(token) = self.identity.token(ACS_RESOURCE).await else {
            return pending;
        };
        let res = self
            .http
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {}", token.expose()))
            .send()
            .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                let e = crate::http::HttpError::from(e);
                tracing::warn!(error = %e, "notify: ACS result check unreachable");
                return pending;
            }
        };
        let status = res.status().as_u16();
        if status != 200 {
            tracing::warn!(status, "notify: ACS result check refused");
            if matches!(status, 401 | 403) {
                self.identity.forget(ACS_RESOURCE).await;
            }
            return Poll::Pending(retry_after(res.headers()));
        }
        let after = retry_after(res.headers());
        let Ok(body) = res.bytes().await else {
            return Poll::Pending(after);
        };
        // Only `status` is read. `error`, which holds Azure's message, is
        // never parsed into a string.
        #[derive(Deserialize)]
        struct OpStatus {
            status: String,
        }
        match serde_json::from_slice::<OpStatus>(&body).map(|s| s.status) {
            Ok(s) if s == "Succeeded" => Poll::Final(Ending::Delivered),
            Ok(s) if s == "Failed" => Poll::Final(Ending::DeliveryFailed),
            Ok(s) if s == "Canceled" => Poll::Final(Ending::Canceled),
            _ => Poll::Pending(after),
        }
    }
}

enum Send {
    /// 202, with the poll URL and first wait when usable.
    Accepted(Option<(String, Duration)>),
    /// Try again after this long (zero: use the backoff). `reached` when
    /// the try may have been processed by ACS.
    Retry { after: Duration, reached: bool },
    /// 412: ACS no longer matches this request.
    TooOld,
    /// Refused for good.
    Rejected,
}

enum Poll {
    Final(Ending),
    Pending(Duration),
}

/// Check an `Operation-Location` is on the same scheme, host and port as
/// the endpoint, with no user name or fragment, and a path of
/// `/emails/operations/<id>`. Only then is the token sent to it.
pub fn checked_poll_url(raw: &str, origin: &(String, String, Option<u16>)) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let same = url.scheme() == origin.0
        && url.host_str().map(str::to_ascii_lowercase).as_deref() == Some(origin.1.as_str())
        && url.port() == origin.2;
    let id = url.path().strip_prefix("/emails/operations/")?;
    let id_ok = (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (same
        && id_ok
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then(|| url.to_string())
}

/// `Retry-After` in seconds. Zero when absent or unreadable.
fn retry_after(h: &reqwest::header::HeaderMap) -> Duration {
    h.get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| Duration::from_secs(s.min(3600)))
        .unwrap_or_default()
}

/// RFC 7231 IMF-fixdate, `Tue, 17 Nov 2026 09:30:05 GMT`.
pub fn imf_fixdate(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let (y, m, d) = crate::dates::civil_from_days(days);
    let s = secs.rem_euclid(86_400);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m as usize).saturating_sub(1).min(11)],
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imf_fixdate_is_right() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_907_805);
        assert_eq!(imf_fixdate(t), "Tue, 17 Nov 2026 09:30:05 GMT");
        assert_eq!(
            imf_fixdate(SystemTime::UNIX_EPOCH),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    fn poll_urls_must_stay_on_the_endpoint() {
        let o = (
            "https".to_owned(),
            "kr.australia.communication.azure.com".to_owned(),
            None,
        );
        let ok = "https://kr.australia.communication.azure.com/emails/operations/abc-123?api-version=2025-09-01";
        assert!(checked_poll_url(ok, &o).is_some());
        assert!(
            checked_poll_url(
                "https://KR.australia.communication.azure.com/emails/operations/abc",
                &o
            )
            .is_some()
        );
        for bad in [
            "http://kr.australia.communication.azure.com/emails/operations/abc",
            "https://evil.example.com/emails/operations/abc",
            "https://kr.australia.communication.azure.com.evil.com/emails/operations/abc",
            "https://other.australia.communication.azure.com/emails/operations/abc",
            "https://kr.australia.communication.azure.com:8443/emails/operations/abc",
            "https://user@kr.australia.communication.azure.com/emails/operations/abc",
            "https://kr.australia.communication.azure.com/emails/operations/",
            "https://kr.australia.communication.azure.com/emails/operations/a/b",
            "https://kr.australia.communication.azure.com/elsewhere/abc",
            "https://kr.australia.communication.azure.com/emails/operations/../../x",
            "https://kr.australia.communication.azure.com/emails/operations/abc#x",
            "/emails/operations/abc",
            "",
        ] {
            assert!(checked_poll_url(bad, &o).is_none(), "{bad}");
        }
    }
}
