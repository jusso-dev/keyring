//! Expiry notices pushed by Event Grid to `POST /hooks/eventgrid`.
//!
//! Key Vault raises `*NearExpiry` and `*Expired` events, and an Event Grid
//! subscription (`infra/alerts` with `notifyVia = 'keyring'`) delivers them
//! to Keyring with an Entra token ([`crate::auth::eventgrid`]). Each event
//! carries the vault, object type, name, version and expiry time, which is
//! all a notice needs, so Keyring never reads a vault here. Keyring's
//! identity has no vault access.
//!
//! - **What reaches an email.** Only the vault and item names after
//!   [`ItemRef::new`] accepts them, the object type from a fixed list, the
//!   event type from the fixed list of six, the version (32 hex digits) and
//!   the expiry time, parsed as a number and formatted by Keyring. Nothing
//!   else from the event, and no free text.
//! - **Dedupe.** Per item, version and event type, for 24 hours, in a map
//!   of at most [`HookTuning::dedupe_capacity`] entries. When it is full,
//!   expired entries are cleared, and if it is still full a new entry is
//!   refused: the event isn't sent and the delivery is answered 503, so
//!   Event Grid tries again later. Old entries are never dropped early, so
//!   filling the map can't make a repeat go out. A restart forgets the
//!   map, so one repeat can follow a restart.
//! - **Rate limit.** A fixed one-minute window on the whole route, one
//!   counter, so it can't grow.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use askama::Template;
use serde_json::Value;

use super::{EmailBody, EmailContext, ItemKind, ItemRef, Rendered};
use crate::auth::eventgrid::Expect;

/// The route Event Grid delivers to. The one path the Origin check skips.
pub const HOOK_PATH: &str = "/hooks/eventgrid";

/// Largest delivery, in bytes, refused before it is read.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Most events in one delivery.
pub const MAX_EVENTS: usize = 50;

/// Most addresses the `keyring-notify` delivery header may name.
pub const MAX_HEADER_RECIPIENTS: usize = 10;

/// The static delivery header the subscription sets with recipients.
pub const RECIPIENT_HEADER: &str = "keyring-notify";

/// The handshake Event Grid sends when a subscription is made.
pub const VALIDATION_EVENT: &str = "Microsoft.EventGrid.SubscriptionValidationEvent";

/// Timings and sizes. Always the defaults outside tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookTuning {
    /// Deliveries a minute the route takes, from anyone, before 429.
    pub per_minute: u32,
    /// Most (item, version, event type) entries remembered.
    pub dedupe_capacity: usize,
    /// How long an entry is remembered.
    pub dedupe_for: Duration,
    /// Fewest time between signing key refetches for an unknown `kid`.
    pub refetch_every: Duration,
}

impl Default for HookTuning {
    fn default() -> Self {
        Self {
            per_minute: 120,
            dedupe_capacity: 10_000,
            dedupe_for: Duration::from_secs(24 * 60 * 60),
            refetch_every: crate::auth::eventgrid::REFETCH_EVERY,
        }
    }
}

/// One of the six Key Vault expiry events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpiryEventType {
    SecretNearExpiry,
    SecretExpired,
    CertificateNearExpiry,
    CertificateExpired,
    KeyNearExpiry,
    KeyExpired,
}

impl ExpiryEventType {
    pub const ALL: [Self; 6] = [
        Self::SecretNearExpiry,
        Self::SecretExpired,
        Self::CertificateNearExpiry,
        Self::CertificateExpired,
        Self::KeyNearExpiry,
        Self::KeyExpired,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretNearExpiry => "Microsoft.KeyVault.SecretNearExpiry",
            Self::SecretExpired => "Microsoft.KeyVault.SecretExpired",
            Self::CertificateNearExpiry => "Microsoft.KeyVault.CertificateNearExpiry",
            Self::CertificateExpired => "Microsoft.KeyVault.CertificateExpired",
            Self::KeyNearExpiry => "Microsoft.KeyVault.KeyNearExpiry",
            Self::KeyExpired => "Microsoft.KeyVault.KeyExpired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    pub fn kind(self) -> ItemKind {
        match self {
            Self::SecretNearExpiry | Self::SecretExpired => ItemKind::Secret,
            Self::CertificateNearExpiry | Self::CertificateExpired => ItemKind::Certificate,
            Self::KeyNearExpiry | Self::KeyExpired => ItemKind::Key,
        }
    }

    pub fn expired(self) -> bool {
        matches!(
            self,
            Self::SecretExpired | Self::CertificateExpired | Self::KeyExpired
        )
    }

    /// The `ObjectType` Key Vault writes for this event.
    fn object_type(self) -> &'static str {
        match self.kind() {
            ItemKind::Secret => "Secret",
            ItemKind::Certificate => "Certificate",
            ItemKind::Key => "Key",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::SecretNearExpiry => "A secret expires soon",
            Self::SecretExpired => "A secret has expired",
            Self::CertificateNearExpiry => "A certificate expires soon",
            Self::CertificateExpired => "A certificate has expired",
            Self::KeyNearExpiry => "A key expires soon",
            Self::KeyExpired => "A key has expired",
        }
    }
}

/// Latest expiry time taken: the end of year 9999.
const MAX_EXP: i64 = 253_402_300_799;

/// One expiry event, every field checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryEvent {
    pub event_type: ExpiryEventType,
    pub item: ItemRef,
    /// 32 hex digits, lower case.
    pub version: String,
    /// Unix seconds.
    pub expires: i64,
}

/// What a delivery holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The subscription handshake, with its checked code.
    Validation(String),
    Events(Vec<ExpiryEvent>),
}

/// Why a delivery was refused with 400. Only the code is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadDelivery {
    /// Not a JSON array of objects, or empty.
    NotEvents,
    /// More than [`MAX_EVENTS`].
    TooMany,
    /// The handshake with a bad code, or not alone.
    BadValidation,
    /// An event that isn't one of the six, or with a field missing or
    /// malformed.
    BadEvent,
}

impl BadDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotEvents => "not_events",
            Self::TooMany => "too_many_events",
            Self::BadValidation => "bad_validation",
            Self::BadEvent => "bad_event",
        }
    }
}

/// A validation code: 1 to 64 letters, digits and hyphens. Event Grid
/// sends a GUID.
fn checked_code(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    ((1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then(|| s.to_owned())
}

/// `EXP`: a whole number of seconds, as a JSON number or a string of
/// digits (Microsoft's example writes it as a string).
fn checked_exp(v: &Value) -> Option<i64> {
    let n = match v {
        Value::Number(n) => n.as_i64()?,
        Value::String(s)
            if (1..=12).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse().ok()?
        }
        _ => return None,
    };
    (0..=MAX_EXP).contains(&n).then_some(n)
}

fn checked_event(v: &Value) -> Option<ExpiryEvent> {
    let o = v.as_object()?;
    let event_type = ExpiryEventType::parse(o.get("eventType")?.as_str()?)?;
    let data = o.get("data")?.as_object()?;
    let field = |name: &str| data.get(name).and_then(Value::as_str);
    if field("ObjectType")? != event_type.object_type() {
        return None;
    }
    let item = ItemRef::new(field("VaultName")?, event_type.kind(), field("ObjectName")?)?;
    let version = field("Version")?;
    if !crate::azure::secrets::is_valid_version(version) {
        return None;
    }
    let expires = checked_exp(data.get("EXP")?)?;
    Some(ExpiryEvent {
        event_type,
        item,
        version: version.to_ascii_lowercase(),
        expires,
    })
}

/// Parse a delivery in the Event Grid schema: a JSON array of 1 to
/// [`MAX_EVENTS`] events. All or nothing: one bad event refuses the lot.
pub fn parse_delivery(body: &[u8]) -> Result<Delivery, BadDelivery> {
    let events: Vec<Value> = serde_json::from_slice(body).map_err(|_| BadDelivery::NotEvents)?;
    if events.is_empty() {
        return Err(BadDelivery::NotEvents);
    }
    if events.len() > MAX_EVENTS {
        return Err(BadDelivery::TooMany);
    }
    let is_validation =
        |e: &Value| e.get("eventType").and_then(Value::as_str) == Some(VALIDATION_EVENT);
    if events.iter().any(is_validation) {
        let [only] = events.as_slice() else {
            return Err(BadDelivery::BadValidation);
        };
        return only
            .get("data")
            .and_then(|d| d.get("validationCode"))
            .and_then(checked_code)
            .map(Delivery::Validation)
            .ok_or(BadDelivery::BadValidation);
    }
    events
        .iter()
        .map(|e| checked_event(e).ok_or(BadDelivery::BadEvent))
        .collect::<Result<Vec<_>, _>>()
        .map(Delivery::Events)
}

/// The expiry email's data.
#[derive(Debug, Clone)]
pub struct ExpiryNotice {
    heading: &'static str,
    line: String,
    version: String,
    expires: String,
    dashboard: String,
}

impl ExpiryNotice {
    /// Built only from checked parts and Keyring's own text.
    pub fn new(e: &ExpiryEvent, now: i64, base_url: &str) -> Self {
        let date = crate::dates::format_date(e.expires);
        let rel = crate::dates::relative_days(e.expires, now);
        let verb = if e.expires <= now {
            "expired on"
        } else {
            "expires on"
        };
        Self {
            heading: e.event_type.heading(),
            line: format!(
                "{} in {} {verb} {date} ({rel}).",
                e.item.name(),
                e.item.vault()
            ),
            version: e.version.clone(),
            expires: crate::dates::format_datetime(e.expires),
            dashboard: format!("{base_url}/expiry"),
        }
    }
}

#[derive(Template)]
#[template(path = "notify/expiry.txt")]
struct ExpiryText<'a> {
    n: &'a ExpiryNotice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

#[derive(Template)]
#[template(path = "notify/expiry.html")]
struct ExpiryHtml<'a> {
    n: &'a ExpiryNotice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

impl EmailBody for ExpiryNotice {
    fn render(&self, ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        let kind = ctx.kind.as_str();
        Ok(Rendered {
            text: ExpiryText {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
            html: ExpiryHtml {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
        })
    }
}

/// What the dedupe map said about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// Not seen in the last 24 hours: now reserved.
    New,
    /// Already sent (or being sent).
    Repeat,
    /// The map is full of live entries: not reserved, don't send.
    Full,
}

type DedupeKey = (String, &'static str, String, String, ExpiryEventType);

fn key(e: &ExpiryEvent) -> DedupeKey {
    (
        e.item.vault().to_owned(),
        e.item.kind().as_str(),
        e.item.name().to_ascii_lowercase(),
        e.version.clone(),
        e.event_type,
    )
}

/// The webhook's own state: what tokens must say, the route's rate limit,
/// the dedupe map and when the signing keys were last refetched.
pub struct ExpiryHook {
    pub expect: Expect,
    pub tuning: HookTuning,
    pub base_url: String,
    window: Mutex<(Instant, u32)>,
    last_refetch: Mutex<Option<Instant>>,
    seen: Mutex<HashMap<DedupeKey, Instant>>,
}

impl std::fmt::Debug for ExpiryHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpiryHook")
            .field("tuning", &self.tuning)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ExpiryHook {
    pub fn new(expect: Expect, tuning: HookTuning, base_url: String) -> Self {
        Self {
            expect,
            tuning,
            base_url,
            window: Mutex::new((Instant::now(), 0)),
            last_refetch: Mutex::new(None),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Take one delivery from the route's budget. False when over it.
    pub fn take_rate(&self) -> bool {
        self.take_rate_at(Instant::now())
    }

    fn take_rate_at(&self, now: Instant) -> bool {
        let mut w = lock(&self.window);
        if now.duration_since(w.0) >= Duration::from_secs(60) {
            *w = (now, 0);
        }
        if w.1 >= self.tuning.per_minute {
            return false;
        }
        w.1 += 1;
        true
    }

    /// May the signing keys be refetched for an unknown `kid` now? At most
    /// once each [`HookTuning::refetch_every`].
    pub fn may_refetch(&self) -> bool {
        let mut last = lock(&self.last_refetch);
        let now = Instant::now();
        if last.is_some_and(|t| now.duration_since(t) < self.tuning.refetch_every) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// Look up and, if new, reserve an event in the dedupe map.
    pub fn reserve(&self, e: &ExpiryEvent) -> Seen {
        self.reserve_at(e, Instant::now())
    }

    fn reserve_at(&self, e: &ExpiryEvent, now: Instant) -> Seen {
        let ttl = self.tuning.dedupe_for;
        let mut seen = lock(&self.seen);
        let k = key(e);
        if let Some(t) = seen.get(&k) {
            if now.duration_since(*t) < ttl {
                return Seen::Repeat;
            }
            seen.insert(k, now);
            return Seen::New;
        }
        if seen.len() >= self.tuning.dedupe_capacity {
            seen.retain(|_, t| now.duration_since(*t) < ttl);
            if seen.len() >= self.tuning.dedupe_capacity {
                return Seen::Full;
            }
        }
        seen.insert(k, now);
        Seen::New
    }

    /// Forget a reservation for an event that couldn't be queued, so Event
    /// Grid's retry sends it.
    pub fn release(&self, e: &ExpiryEvent) {
        lock(&self.seen).remove(&key(e));
    }

    /// Entries held, for tests.
    pub fn dedupe_len(&self) -> usize {
        lock(&self.seen).len()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::notify::NotifyType;

    const V: &str = "0123456789abcdef0123456789abcdef";

    fn ev(t: &str, obj: &str, name: &str) -> Value {
        json!({
            "id": "1",
            "topic": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test",
            "subject": name,
            "eventType": t,
            "eventTime": "2026-11-17T00:00:00Z",
            "data": {
                "Id": format!("https://kv-test.vault.azure.net/secrets/{name}/{V}"),
                "VaultName": "kv-test",
                "ObjectType": obj,
                "ObjectName": name,
                "Version": V,
                "NBF": 1_700_000_000,
                "EXP": "1797465600"
            },
            "dataVersion": "1",
            "metadataVersion": "1"
        })
    }

    fn body(v: Value) -> Vec<u8> {
        v.to_string().into_bytes()
    }

    #[test]
    fn the_six_events_parse() {
        for t in ExpiryEventType::ALL {
            let d = parse_delivery(&body(json!([ev(
                t.as_str(),
                t.object_type(),
                "db-password"
            )])))
            .unwrap();
            let Delivery::Events(e) = d else { panic!() };
            assert_eq!(e[0].event_type, t);
            assert_eq!(e[0].item.kind(), t.kind());
            assert_eq!(e[0].expires, 1_797_465_600);
        }
    }

    #[test]
    fn anything_malformed_refuses_the_lot() {
        let good = ev(
            "Microsoft.KeyVault.SecretNearExpiry",
            "Secret",
            "db-password",
        );
        let mut bad = Vec::new();
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut e = good.clone();
            f(&mut e);
            e
        };
        bad.push(edit(&|e| {
            e["eventType"] = json!("Microsoft.KeyVault.SecretNewVersionCreated")
        }));
        bad.push(edit(&|e| e["eventType"] = json!(1)));
        bad.push(edit(&|e| e["data"]["ObjectType"] = json!("Key")));
        bad.push(edit(&|e| {
            e["data"]["ObjectName"] = json!("https://evil.example/x")
        }));
        bad.push(edit(&|e| e["data"]["ObjectName"] = json!("db password")));
        bad.push(edit(&|e| e["data"]["VaultName"] = json!("kv.evil.example")));
        bad.push(edit(&|e| e["data"]["Version"] = json!("not-a-version")));
        bad.push(edit(&|e| e["data"]["EXP"] = json!("soon")));
        bad.push(edit(&|e| e["data"]["EXP"] = json!(-1)));
        bad.push(edit(&|e| e["data"]["EXP"] = json!(1.5)));
        bad.push(edit(&|e| e["data"]["EXP"] = json!("99999999999999")));
        bad.push(edit(&|e| {
            e["data"].as_object_mut().unwrap().remove("EXP");
        }));
        bad.push(edit(&|e| e["data"] = json!("x")));
        for b in bad {
            assert_eq!(
                parse_delivery(&body(json!([good.clone(), b.clone()]))),
                Err(BadDelivery::BadEvent),
                "{b}"
            );
        }
        assert_eq!(parse_delivery(b"[]"), Err(BadDelivery::NotEvents));
        assert_eq!(parse_delivery(b"{}"), Err(BadDelivery::NotEvents));
        assert_eq!(parse_delivery(b"not json"), Err(BadDelivery::NotEvents));
        let many: Vec<Value> = (0..=MAX_EVENTS).map(|_| good.clone()).collect();
        assert_eq!(
            parse_delivery(&body(Value::Array(many))),
            Err(BadDelivery::TooMany)
        );
    }

    #[test]
    fn the_handshake_code_is_checked() {
        let v = |code: Value| json!({"eventType": VALIDATION_EVENT, "data": {"validationCode": code, "validationUrl": "https://evil.example/"}});
        assert_eq!(
            parse_delivery(&body(json!([v(json!(
                "512d38b6-c7b8-40c8-89fe-f46f9e9622b6"
            ))]))),
            Ok(Delivery::Validation(
                "512d38b6-c7b8-40c8-89fe-f46f9e9622b6".into()
            ))
        );
        for bad in [
            json!(""),
            json!("a b"),
            json!("<script>"),
            json!("x".repeat(65)),
            json!(5),
        ] {
            assert_eq!(
                parse_delivery(&body(json!([v(bad.clone())]))),
                Err(BadDelivery::BadValidation),
                "{bad}"
            );
        }
        let good = ev(
            "Microsoft.KeyVault.SecretNearExpiry",
            "Secret",
            "db-password",
        );
        assert_eq!(
            parse_delivery(&body(json!([v(json!("abc")), good]))),
            Err(BadDelivery::BadValidation)
        );
    }

    fn hook(cap: usize) -> ExpiryHook {
        ExpiryHook::new(
            Expect {
                tenant: String::new(),
                issuer_v1: String::new(),
                issuer_v2: String::new(),
                audience: String::new(),
            },
            HookTuning {
                per_minute: 2,
                dedupe_capacity: cap,
                ..HookTuning::default()
            },
            "https://keyring.example.com".into(),
        )
    }

    fn event(name: &str) -> ExpiryEvent {
        ExpiryEvent {
            event_type: ExpiryEventType::SecretNearExpiry,
            item: ItemRef::new("kv-test", ItemKind::Secret, name).unwrap(),
            version: V.into(),
            expires: 1_797_465_600,
        }
    }

    #[test]
    fn dedupe_is_bounded_and_refuses_when_full() {
        let h = hook(2);
        let t0 = Instant::now();
        assert_eq!(h.reserve_at(&event("a"), t0), Seen::New);
        assert_eq!(h.reserve_at(&event("a"), t0), Seen::Repeat);
        assert_eq!(
            h.reserve_at(&event("A"), t0),
            Seen::Repeat,
            "names are case-insensitive"
        );
        assert_eq!(h.reserve_at(&event("b"), t0), Seen::New);
        // Full of live entries: a new one is refused, and the old ones
        // still dedupe (nothing was dropped to make room).
        assert_eq!(h.reserve_at(&event("c"), t0), Seen::Full);
        assert_eq!(h.reserve_at(&event("a"), t0), Seen::Repeat);
        assert_eq!(h.dedupe_len(), 2);
        // A day later the entries have expired: room again, and a repeat
        // is new.
        let later = t0 + Duration::from_secs(24 * 3600);
        assert_eq!(h.reserve_at(&event("c"), later), Seen::New);
        assert_eq!(h.reserve_at(&event("a"), later), Seen::New);
        h.release(&event("a"));
        assert_eq!(h.reserve_at(&event("a"), later), Seen::New);
    }

    #[test]
    fn the_route_rate_is_one_counter() {
        let h = hook(2);
        let t0 = Instant::now();
        assert!(h.take_rate_at(t0));
        assert!(h.take_rate_at(t0));
        assert!(!h.take_rate_at(t0));
        assert!(h.take_rate_at(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn the_notice_has_only_checked_parts() {
        let e = event("db-password");
        let n = ExpiryNotice::new(
            &e,
            1_797_465_600 - 3 * 86_400,
            "https://keyring.example.com",
        );
        let link = e.item.link("https://keyring.example.com");
        let r = n
            .render(&EmailContext {
                kind: NotifyType::Expiry,
                item: Some(&e.item),
                link: Some(&link),
            })
            .unwrap();
        for b in [&r.text, &r.html] {
            assert!(
                b.contains("db-password in kv-test expires on 17 Dec 2026 (in 3 days)."),
                "{b}"
            );
            assert!(b.contains("https://keyring.example.com/expiry"), "{b}");
            assert!(b.contains(&link));
            assert!(b.contains(V));
        }
        let n = ExpiryNotice::new(&e, 1_797_465_600 + 2 * 86_400, "https://k");
        assert!(
            n.line.contains("expired on 17 Dec 2026 (2 days ago)"),
            "{}",
            n.line
        );
    }
}
