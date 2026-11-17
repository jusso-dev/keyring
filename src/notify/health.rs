//! Health notices: email `KEYRING_NOTIFY_ADMINS` when Keyring itself is in
//! trouble, with `health` in `KEYRING_NOTIFY_TYPES`.
//!
//! - **Audit sink degraded** for more than [`Tuning::sink_after`] (five
//!   minutes): one email when the incident starts and one when it ends,
//!   with drop counts, nothing in between.
//! - **Refusal burst:** more than `KEYRING_NOTIFY_BURST_THRESHOLD` (default
//!   20) `refused` or `denied` audit events from one person, or, with no
//!   person on the event, from one client IP, in [`Tuning::burst_window`]
//!   (15 minutes). One email per person or IP per incident. The incident
//!   ends once that person or IP has had no refusal for a whole window.
//! - **Keyring's client secret near expiry** (`KEYRING_CLIENT_SECRET_EXPIRES`):
//!   one email at each of 30, 14, 7 and 1 days left, then one once it has
//!   expired. Nothing is stored, so after a restart the current step is
//!   emailed once more.
//! - **Email itself failing:** logged at `warn` once per incident and shown
//!   on `/healthz/notify`. No email, since it couldn't be sent.
//!
//! Refusals are counted in memory as events are recorded, through
//! [`crate::audit::Observe`], so they are counted with the audit sink off.
//! Only `refused` and `denied` outcomes count; `notify.*` events never do.
//! The map of people and IPs is bounded: when full, new keys aren't
//! tracked and a `warn` line says so, so made-up IPs or names can't grow
//! memory or send a flood of email. Burst emails are also capped at
//! [`Tuning::max_burst_emails_per_hour`] across all keys.
//!
//! Every check takes its time from a [`Clock`], so tests use a fixed one.
//! Emails hold fixed text, counts, dates, reason codes, a person's sign-in
//! name (or "an unnamed caller") or a parsed IP, and a link Keyring built.
//! Never a value, token, Azure message or reason text.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use askama::Template;
use tokio::sync::watch;

use super::sender::Notifier;
use super::{
    Address, EmailBody, EmailContext, MAX_LINE_CHARS, Notification, NotifyType, Rendered,
    clean_line,
};
use crate::audit::sink::{AuditSink, Health as SinkHealth};
use crate::audit::{Action, AuditEvent, Observe, Outcome};

/// Default `KEYRING_NOTIFY_BURST_THRESHOLD`.
pub const DEFAULT_BURST_THRESHOLD: u32 = 20;

/// Largest `KEYRING_NOTIFY_BURST_THRESHOLD`.
pub const MAX_BURST_THRESHOLD: u32 = 1000;

/// Days before the client secret expires that an email is sent.
pub const SECRET_STEPS: [i64; 4] = [30, 14, 7, 1];

/// Most reason codes kept for one burst.
const MAX_CODES: usize = 8;

/// The time, for every check. [`SystemClock`] outside tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> SystemTime;
}

/// The real time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when told. For tests.
#[derive(Debug)]
pub struct ManualClock(Mutex<SystemTime>);

impl ManualClock {
    pub fn new(at: SystemTime) -> Self {
        Self(Mutex::new(at))
    }

    pub fn advance(&self, by: Duration) {
        *lock(&self.0) += by;
    }

    pub fn set(&self, at: SystemTime) {
        *lock(&self.0) = at;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *lock(&self.0)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How long from `earlier` to `later`, zero if `later` is before it.
fn since(later: SystemTime, earlier: SystemTime) -> Duration {
    later.duration_since(earlier).unwrap_or_default()
}

/// Timings and sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// How often the sink, the sender and the secret's date are checked.
    pub tick: Duration,
    /// How long the audit sink must be degraded before an email.
    pub sink_after: Duration,
    /// The window refusals are counted over.
    pub burst_window: Duration,
    /// Most people and IPs tracked at once.
    pub max_keys: usize,
    /// Most burst emails an hour, across all people and IPs.
    pub max_burst_emails_per_hour: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(30),
            sink_after: Duration::from_secs(5 * 60),
            burst_window: Duration::from_secs(15 * 60),
            max_keys: 10_000,
            max_burst_emails_per_hour: 10,
        }
    }
}

/// What the watcher needs. Built from the configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    /// More refusals than this in a window is a burst.
    pub burst_threshold: u32,
    /// `KEYRING_CLIENT_SECRET_EXPIRES`, as Unix seconds at midnight UTC.
    pub secret_expires: Option<i64>,
    /// `APP_BASE_URL`, for the link to the audit report.
    pub base_url: String,
    pub tuning: Tuning,
}

/// Who a burst is from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    /// A person, by object ID or, without one, sign-in name in lower case.
    Person(String),
    Ip(IpAddr),
}

/// One person's or IP's refusals in the window.
#[derive(Debug)]
struct Burst {
    /// Times of the latest refusals, at most threshold + 1.
    times: VecDeque<SystemTime>,
    /// Refusals in this incident, for the email.
    count: u64,
    codes: BTreeSet<String>,
    /// A sign-in name that looks like one, for the email.
    upn: Option<String>,
    /// Emailed (or passed over by the cap) for this incident.
    alerted: bool,
}

#[derive(Debug, Default)]
struct Bursts {
    map: HashMap<Key, Burst>,
    /// Times of burst emails in the last hour.
    sent: VecDeque<SystemTime>,
    /// The map is full and a `warn` line has said so.
    full_warned: bool,
    /// The email cap was met and a `warn` line has said so.
    cap_warned: bool,
}

/// The audit sink's incident.
#[derive(Debug, Default, Clone, Copy)]
struct SinkIncident {
    /// When the watcher first saw the sink degraded, and its counts then.
    since: Option<(SystemTime, SinkHealth)>,
    /// The "started" email has gone.
    alerted: bool,
}

/// What a sink check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkStep {
    Started { dropped: u64 },
    Recovered { dropped: u64, minutes: u64 },
}

fn dropped(h: &SinkHealth) -> u64 {
    h.dropped_queue_full + h.dropped_rejected + h.dropped_at_shutdown
}

impl SinkIncident {
    fn step(&mut self, h: SinkHealth, now: SystemTime, after: Duration) -> Option<SinkStep> {
        if h.degraded {
            let (start, at_start) = *self.since.get_or_insert((now, h));
            if !self.alerted && since(now, start) >= after {
                self.alerted = true;
                return Some(SinkStep::Started {
                    dropped: dropped(&h).saturating_sub(dropped(&at_start)),
                });
            }
            return None;
        }
        let was = std::mem::take(self);
        match was.since {
            Some((start, at_start)) if was.alerted => Some(SinkStep::Recovered {
                dropped: dropped(&h).saturating_sub(dropped(&at_start)),
                minutes: since(now, start).as_secs() / 60,
            }),
            _ => None,
        }
    }
}

/// A step of the client secret's expiry: days left at most this, or
/// expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretStep {
    /// At most this many days left, from [`SECRET_STEPS`].
    Within(i64),
    Expired,
}

/// The step for `days_left` whole days before the expiry date, if any.
pub fn secret_step(days_left: i64) -> Option<SecretStep> {
    if days_left <= 0 {
        return Some(SecretStep::Expired);
    }
    SECRET_STEPS
        .iter()
        .rev()
        .find(|s| days_left <= **s)
        .map(|s| SecretStep::Within(*s))
}

impl SecretStep {
    /// Higher is more urgent.
    fn urgency(self) -> i64 {
        match self {
            Self::Within(d) => -d,
            Self::Expired => 0,
        }
    }
}

/// Watches the audit sink, the email sender, refusals and the client
/// secret's date, and emails the admins. Shared by the app state.
pub struct HealthWatch {
    settings: Settings,
    clock: Arc<dyn Clock>,
    notifier: Arc<Notifier>,
    sink: Option<Arc<AuditSink>>,
    bursts: Mutex<Bursts>,
    sink_incident: Mutex<SinkIncident>,
    /// Email sending is degraded and a `warn` line has said so.
    notify_degraded: Mutex<bool>,
    /// The last secret step emailed by this process.
    secret_sent: Mutex<Option<SecretStep>>,
    stop: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for HealthWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthWatch")
            .field("tracked", &self.tracked())
            .finish_non_exhaustive()
    }
}

impl HealthWatch {
    /// A watcher with no timer. Call [`HealthWatch::start`] to run one, or
    /// [`HealthWatch::tick`] by hand in tests.
    pub fn new(
        settings: Settings,
        clock: Arc<dyn Clock>,
        notifier: Arc<Notifier>,
        sink: Option<Arc<AuditSink>>,
    ) -> Arc<Self> {
        let (stop, _) = watch::channel(false);
        Arc::new(Self {
            settings,
            clock,
            notifier,
            sink,
            bursts: Mutex::new(Bursts::default()),
            sink_incident: Mutex::new(SinkIncident::default()),
            notify_degraded: Mutex::new(false),
            secret_sent: Mutex::new(None),
            stop,
            task: Mutex::new(None),
        })
    }

    /// Run [`HealthWatch::tick`] every [`Tuning::tick`] until shutdown.
    /// Needs a Tokio runtime. The task holds no credential and handles no
    /// value.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        let mut stop = self.stop.subscribe();
        let every = self.settings.tuning.tick;
        let task = tokio::spawn(async move {
            let mut t = tokio::time::interval(every);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = t.tick() => me.tick(),
                    _ = stop.wait_for(|s| *s) => return,
                }
            }
        });
        *lock(&self.task) = Some(task);
    }

    /// Stop the timer.
    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let task = lock(&self.task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    /// People and IPs tracked now.
    pub fn tracked(&self) -> usize {
        lock(&self.bursts).map.len()
    }

    /// One round of the timed checks: the sink, the sender, the secret's
    /// date, and clearing bursts that have ended.
    pub fn tick(&self) {
        let now = self.clock.now();
        self.check_sink(now);
        self.check_notify();
        self.check_secret(now);
        self.prune(now);
    }

    fn check_sink(&self, now: SystemTime) {
        let Some(sink) = &self.sink else { return };
        let h = sink.health();
        let step = lock(&self.sink_incident).step(h, now, self.settings.tuning.sink_after);
        let n = match step {
            None => return,
            Some(SinkStep::Started { dropped }) => {
                tracing::warn!(
                    dropped,
                    "health: the audit sink has been degraded for over five minutes; emailing the admins"
                );
                HealthNotice::new("Keyring's audit sink is failing")
                    .line("Keyring hasn't been able to send its audit events to Log Analytics for over five minutes. They are still written to standard output, and are queued to be sent while there is room.")
                    .line("Check that Keyring's managed identity still has Monitoring Metrics Publisher on the data collection rule, and that the ingestion endpoint can be reached. /healthz/audit shows the current state. With KEYRING_AUDIT_REQUIRED on, reveals and private key downloads are refused until it recovers.")
                    .line("You will get one more email when it recovers.")
                    .fact("Dropped so far", dropped.to_string())
                    .fact("Waiting to be sent", h.queued.to_string())
            }
            Some(SinkStep::Recovered { dropped, minutes }) => {
                tracing::info!(dropped, minutes, "health: the audit sink has recovered");
                HealthNotice::new("Keyring's audit sink has recovered")
                    .line("Keyring is sending its audit events to Log Analytics again.")
                    .line("Events dropped while it was failing are not in KeyringAudit_CL. They are still in Keyring's standard output log for that time.")
                    .fact("Failing for about", format!("{minutes} minutes"))
                    .fact("Dropped in this incident", dropped.to_string())
            }
        };
        self.send(n);
    }

    fn check_notify(&self) {
        let degraded = self.notifier.degraded();
        match notify_change(&mut lock(&self.notify_degraded), degraded) {
            Some(true) => tracing::warn!(
                "health: email can't be sent through Azure Communication Services; health notices are not reaching the admins. /healthz/notify shows the current state"
            ),
            Some(false) => tracing::info!("health: email is being sent again"),
            None => {}
        }
    }

    fn check_secret(&self, now: SystemTime) {
        let Some(expires) = self.settings.secret_expires else {
            return;
        };
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let days_left = expires.div_euclid(86_400) - now_secs.div_euclid(86_400);
        let Some(step) = secret_step(days_left) else {
            return;
        };
        {
            let mut sent = lock(&self.secret_sent);
            if sent.is_some_and(|s| s.urgency() >= step.urgency()) {
                return;
            }
            *sent = Some(step);
        }
        let date = crate::dates::format_date(expires);
        let n = match step {
            SecretStep::Expired => {
                tracing::warn!(date = %date, "health: Keyring's client secret has expired");
                HealthNotice::new("Keyring's client secret has expired")
                    .line("The client secret Keyring signs in to Entra with has passed the date in KEYRING_CLIENT_SECRET_EXPIRES. Sign-in and every vault page will fail until it is replaced.")
            }
            SecretStep::Within(_) => {
                tracing::warn!(days_left, date = %date, "health: Keyring's client secret expires soon");
                HealthNotice::new("Keyring's client secret expires soon")
                    .line(&format!(
                        "The client secret Keyring signs in to Entra with expires in {}.",
                        if days_left == 1 {
                            "1 day".to_owned()
                        } else {
                            format!("{days_left} days")
                        }
                    ))
            }
        }
        .line("Add a new client secret to Keyring's app registration, set ENTRA_CLIENT_SECRET to it and KEYRING_CLIENT_SECRET_EXPIRES to its date, then restart Keyring. Or use the managed identity as the credential, which has no secret to expire.")
        .fact("Expiry date", date);
        self.send(n);
    }

    fn prune(&self, now: SystemTime) {
        let window = self.settings.tuning.burst_window;
        let mut b = lock(&self.bursts);
        b.map
            .retain(|_, v| v.times.back().is_some_and(|t| since(now, *t) < window));
        if b.map.len() < self.settings.tuning.max_keys {
            b.full_warned = false;
        }
    }

    /// Queue a notice. Whatever happens (queued, queue full, rate limited,
    /// nobody allowed) the notice isn't retried: the sender has counted a
    /// drop, and a later incident sends its own email.
    fn send(&self, n: HealthNotice) {
        let _ = self.notifier.enqueue(Notification {
            kind: NotifyType::Health,
            to: self.notifier.admins().to_vec(),
            item: None,
            data: n,
        });
    }

    /// Count one refusal; return the burst email to send, if this one
    /// starts a burst.
    fn count(&self, ev: &AuditEvent, now: SystemTime) -> Option<HealthNotice> {
        let (key, upn) = key_of(ev)?;
        let t = self.settings.tuning;
        let threshold = self.settings.burst_threshold as usize;
        let mut b = lock(&self.bursts);
        if !b.map.contains_key(&key) && b.map.len() >= t.max_keys {
            b.map.retain(|_, v| {
                v.times
                    .back()
                    .is_some_and(|x| since(now, *x) < t.burst_window)
            });
            if b.map.len() >= t.max_keys {
                if !b.full_warned {
                    b.full_warned = true;
                    tracing::warn!(
                        tracked = b.map.len(),
                        "health: too many people and addresses with refusals to track; new ones are not counted until older ones go quiet"
                    );
                }
                return None;
            }
        }
        let e = b.map.entry(key.clone()).or_insert_with(|| Burst {
            times: VecDeque::new(),
            count: 0,
            codes: BTreeSet::new(),
            upn: None,
            alerted: false,
        });
        // A quiet window ends the incident.
        if e.times
            .back()
            .is_some_and(|x| since(now, *x) >= t.burst_window)
        {
            e.times.clear();
            e.count = 0;
            e.codes.clear();
            e.alerted = false;
        }
        while e
            .times
            .front()
            .is_some_and(|x| since(now, *x) >= t.burst_window)
        {
            e.times.pop_front();
        }
        e.times.push_back(now);
        while e.times.len() > threshold + 1 {
            e.times.pop_front();
        }
        e.count += 1;
        if let Some(code) = ev.reason_code.as_deref().filter(|c| is_code(c))
            && e.codes.len() < MAX_CODES
        {
            e.codes.insert(code.to_owned());
        }
        if e.upn.is_none() {
            e.upn = upn;
        }
        if e.alerted || e.times.len() <= threshold {
            return None;
        }
        e.alerted = true;
        let (count, codes, upn) = (
            e.count,
            e.codes.iter().cloned().collect::<Vec<_>>(),
            e.upn.clone(),
        );
        let hour = Duration::from_secs(3600);
        while b.sent.front().is_some_and(|x| since(now, *x) >= hour) {
            b.sent.pop_front();
        }
        if b.sent.len() >= t.max_burst_emails_per_hour {
            if !b.cap_warned {
                b.cap_warned = true;
                tracing::warn!(
                    "health: more refusal bursts than health emails allowed this hour; the rest are not emailed. Check the audit log for refused and denied events"
                );
            }
            return None;
        }
        b.cap_warned = false;
        b.sent.push_back(now);
        drop(b);
        tracing::warn!(
            count,
            by = match key {
                Key::Person(_) => "person",
                Key::Ip(_) => "address",
            },
            "health: a burst of refused or denied requests; emailing the admins"
        );
        Some(self.burst_notice(&key, upn.as_deref(), count, &codes))
    }

    fn burst_notice(
        &self,
        key: &Key,
        upn: Option<&str>,
        count: u64,
        codes: &[String],
    ) -> HealthNotice {
        let minutes = self.settings.tuning.burst_window.as_secs() / 60;
        let enc = crate::auth::return_to::encode;
        let mut n = HealthNotice::new("Many refused requests in a short time");
        n = match key {
            Key::Person(_) => n
                .line(&format!(
                    "One person had more than {} requests refused or denied within {minutes} minutes. It may be a script with the wrong access, someone looking for what they can reach, or a stolen session.",
                    self.settings.burst_threshold
                ))
                .line("Check what they were trying to do in the audit report, and whether it was them. You will get no more email about this person until they have had no refusal for 15 minutes.")
                .fact("Person", upn.unwrap_or("an unnamed caller").to_owned()),
            Key::Ip(ip) => n
                .line(&format!(
                    "One address had more than {} requests refused or denied within {minutes} minutes, with nobody signed in. It may be a scanner or a broken client.",
                    self.settings.burst_threshold
                ))
                .line("Check the refused requests report and your network logs for this address. You will get no more email about it until it has had no refusal for 15 minutes.")
                .fact("Address", ip.to_string()),
        };
        n = n.fact("Refused or denied", count.to_string());
        if !codes.is_empty() {
            n = n.fact("Reason codes", codes.join(", "));
        }
        let base = &self.settings.base_url;
        match upn.filter(|u| crate::azure::audit::is_person(u)) {
            Some(u) => n.link(
                format!("{base}/audit?report=person&range=24h&person={}", enc(u)),
                "Open their activity in Keyring",
            ),
            None => n.link(
                format!("{base}/audit?report=refused&range=24h"),
                "Open refused requests in Keyring",
            ),
        }
    }
}

impl Observe for HealthWatch {
    fn observe(&self, ev: &AuditEvent) {
        if !matches!(ev.outcome, Outcome::Refused | Outcome::Denied)
            || matches!(ev.action, Action::NotifySent | Action::NotifyFailed)
        {
            return;
        }
        let now = self.clock.now();
        if let Some(n) = self.count(ev, now) {
            self.send(n);
        }
    }
}

/// Whether email sending's state changed: `Some(true)` when an incident
/// starts, `Some(false)` when it ends, so each is logged once.
fn notify_change(was: &mut bool, degraded: bool) -> Option<bool> {
    let changed = (*was != degraded).then_some(degraded);
    *was = degraded;
    changed
}

/// Who an event is from: the person when there is one, otherwise the
/// client IP. With a sign-in name that looks like one.
fn key_of(ev: &AuditEvent) -> Option<(Key, Option<String>)> {
    let upn = ev
        .actor_upn
        .as_deref()
        .filter(|u| Address::parse(u).is_ok())
        .map(str::to_owned);
    if let Some(oid) = ev.actor_oid.as_deref().filter(|o| !o.is_empty()) {
        return Some((
            Key::Person(format!("oid:{}", oid.to_ascii_lowercase())),
            upn,
        ));
    }
    if let Some(u) = ev.actor_upn.as_deref().filter(|u| !u.is_empty()) {
        return Some((Key::Person(format!("upn:{}", u.to_lowercase())), upn));
    }
    let ip: IpAddr = ev.client_ip.as_deref()?.parse().ok()?;
    Some((Key::Ip(ip), None))
}

/// A reason code as Keyring writes them: letters, digits, `_`, `.` and
/// `-`, at most 64.
fn is_code(c: &str) -> bool {
    (1..=64).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A health notice: a heading, fixed lines, a table of facts and a link
/// Keyring built. Outside text (a sign-in name or an address) only ever
/// goes in a fact's value, alone, cleaned.
#[derive(Debug, Clone, Default)]
pub struct HealthNotice {
    heading: String,
    lines: Vec<String>,
    facts: Vec<(&'static str, String)>,
    link: Option<(String, &'static str)>,
}

impl HealthNotice {
    pub fn new(heading: &str) -> Self {
        Self {
            heading: clean_line(heading, MAX_LINE_CHARS),
            ..Self::default()
        }
    }

    /// A line of fixed text.
    fn line(mut self, text: &str) -> Self {
        let l = clean_line(text, MAX_LINE_CHARS * 2);
        if !l.is_empty() {
            self.lines.push(l);
        }
        self
    }

    /// One labelled value.
    fn fact(mut self, label: &'static str, value: String) -> Self {
        self.facts.push((label, clean_line(&value, 254)));
        self
    }

    /// A link Keyring built from `APP_BASE_URL`.
    fn link(mut self, url: String, label: &'static str) -> Self {
        self.link = Some((url, label));
        self
    }
}

#[derive(Template)]
#[template(path = "notify/health.txt")]
struct HealthText<'a> {
    n: &'a HealthNotice,
}

#[derive(Template)]
#[template(path = "notify/health.html")]
struct HealthHtml<'a> {
    n: &'a HealthNotice,
}

impl EmailBody for HealthNotice {
    fn render(&self, _ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        Ok(Rendered {
            text: HealthText { n: self }.render()?,
            html: HealthHtml { n: self }.render()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(degraded: bool, dropped: u64) -> SinkHealth {
        SinkHealth {
            degraded,
            queued: 0,
            sent: 0,
            dropped_queue_full: dropped,
            dropped_rejected: 0,
            dropped_at_shutdown: 0,
            failed_attempts: 0,
        }
    }

    #[test]
    fn a_sink_incident_emails_once_at_the_start_and_once_at_the_end() {
        let five = Duration::from_secs(300);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let at = |s| t0 + Duration::from_secs(s);
        let mut i = SinkIncident::default();
        assert_eq!(i.step(h(false, 0), at(0), five), None);
        assert_eq!(i.step(h(true, 3), at(0), five), None);
        assert_eq!(i.step(h(true, 4), at(299), five), None);
        assert_eq!(
            i.step(h(true, 10), at(300), five),
            Some(SinkStep::Started { dropped: 7 })
        );
        // Nothing in between.
        assert_eq!(i.step(h(true, 50), at(900), five), None);
        assert_eq!(
            i.step(h(false, 53), at(1500), five),
            Some(SinkStep::Recovered {
                dropped: 50,
                minutes: 25
            })
        );
        assert_eq!(i.step(h(false, 53), at(1530), five), None);
        // A short blip is never emailed, start or end.
        assert_eq!(i.step(h(true, 53), at(2000), five), None);
        assert_eq!(i.step(h(false, 53), at(2100), five), None);
        assert_eq!(i.step(h(true, 53), at(2200), five), None);
        assert_eq!(i.step(h(true, 53), at(2499), five), None);
    }

    #[test]
    fn email_failing_is_logged_once_per_incident() {
        let mut was = false;
        assert_eq!(notify_change(&mut was, false), None);
        assert_eq!(notify_change(&mut was, true), Some(true));
        assert_eq!(notify_change(&mut was, true), None);
        assert_eq!(notify_change(&mut was, true), None);
        assert_eq!(notify_change(&mut was, false), Some(false));
        assert_eq!(notify_change(&mut was, false), None);
        assert_eq!(notify_change(&mut was, true), Some(true));
    }

    #[test]
    fn secret_steps_are_30_14_7_1_and_expired() {
        assert_eq!(secret_step(45), None);
        assert_eq!(secret_step(31), None);
        assert_eq!(secret_step(30), Some(SecretStep::Within(30)));
        assert_eq!(secret_step(15), Some(SecretStep::Within(30)));
        assert_eq!(secret_step(14), Some(SecretStep::Within(14)));
        assert_eq!(secret_step(8), Some(SecretStep::Within(14)));
        assert_eq!(secret_step(7), Some(SecretStep::Within(7)));
        assert_eq!(secret_step(2), Some(SecretStep::Within(7)));
        assert_eq!(secret_step(1), Some(SecretStep::Within(1)));
        assert_eq!(secret_step(0), Some(SecretStep::Expired));
        assert_eq!(secret_step(-40), Some(SecretStep::Expired));
        assert!(SecretStep::Expired.urgency() > SecretStep::Within(1).urgency());
        assert!(SecretStep::Within(7).urgency() > SecretStep::Within(14).urgency());
    }

    #[test]
    fn keys_are_the_person_then_the_address() {
        let mut ev = AuditEvent::new(Action::SecretReveal, Outcome::Refused);
        ev.client_ip = Some("203.0.113.7".into());
        assert_eq!(
            key_of(&ev).unwrap().0,
            Key::Ip("203.0.113.7".parse().unwrap())
        );
        ev.client_ip = Some("not an ip https://evil.example".into());
        assert!(key_of(&ev).is_none());
        ev.actor_upn = Some("Alex@Example.com".into());
        let (k, upn) = key_of(&ev).unwrap();
        assert_eq!(k, Key::Person("upn:alex@example.com".into()));
        assert_eq!(upn.as_deref(), Some("Alex@Example.com"));
        ev.actor_oid = Some("OID-1".into());
        assert_eq!(key_of(&ev).unwrap().0, Key::Person("oid:oid-1".into()));
        // A name that isn't a sign-in name is never shown.
        ev.actor_upn = Some("see https://evil.example now".into());
        assert_eq!(key_of(&ev).unwrap().1, None);
    }

    #[test]
    fn the_health_notice_escapes_and_cleans() {
        let n = HealthNotice::new("Heading")
            .line("Fixed")
            .fact("Person", "a<b>@example.com\r\nBcc: x".into())
            .link("https://keyring.example.com/audit?a=1&b=2".into(), "Open");
        let r = n
            .render(&EmailContext {
                kind: NotifyType::Health,
                item: None,
                link: None,
            })
            .unwrap();
        assert!(
            r.html.contains("a&#60;b&#62;@example.com Bcc: x"),
            "{}",
            r.html
        );
        assert!(r.html.contains("audit?a=1&#38;b=2"), "{}", r.html);
        assert!(!r.text.contains("\nBcc"));
        assert!(
            r.text.contains("Person: a<b>@example.com Bcc: x"),
            "{}",
            r.text
        );
    }
}
