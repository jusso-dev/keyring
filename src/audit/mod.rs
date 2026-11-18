//! Keyring's own audit events: one structured record for each thing a
//! person does through Keyring, including refusals and failures.
//!
//! Not to be confused with Key Vault's audit log (`crate::azure::audit` and
//! the audit pages), which Key Vault writes for every call it receives.
//! Keyring's events add what only Keyring knows: which browser asked, why
//! Keyring refused, and the `x-ms-client-request-id` that joins an event to
//! Key Vault's own row.
//!
//! Every event goes through [`record`], which writes it to standard output
//! and, when the audit sink ([`sink`]) is set, queues it to be sent to Log
//! Analytics as well. During a request, [`layer`] keeps a
//! draft that the route, the guards (form token, origin, typed name, purge
//! off, managed item) and the Azure client add to. When the request
//! finishes, the layer writes exactly one event if the request was for an
//! audited action. Session expiry happens outside a request and calls
//! [`record`] directly.
//!
//! The field names are fixed by [`SCHEMA_VERSION`]. Renaming or removing
//! one, or changing its meaning or type, needs a version bump and a
//! CHANGELOG line. Adding an optional field, left out when not set, keeps
//! the version (`tests/audit_events.rs` pins the names and lists the
//! additions).
//! Never put a value, token, password, query string or Azure's error
//! message in an event.

pub mod sink;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::SystemTime;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::auth::session::Session;
use crate::azure::AzureError;
use crate::azure::token::TokenError;

/// Version of the event's field names and meanings.
pub const SCHEMA_VERSION: u64 = 1;

/// The `tracing` target audit events are written under.
pub const TARGET: &str = "keyring::audit";

/// Longest user agent kept, in characters.
pub const MAX_USER_AGENT: usize = 256;

/// What was done. Written as a dotted name, such as `secret.reveal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    SecretReveal,
    SecretCreate,
    SecretSet,
    SecretUpdate,
    SecretEnabledSet,
    SecretRollback,
    SecretDelete,
    SecretRecover,
    SecretPurge,
    /// A file of secrets imported. One event for the request, and one per
    /// secret written, with that secret's name and outcome.
    SecretImport,
    /// Tags, expiry or enabled changed on many secrets at once. One event
    /// for the request, and one per secret, as for an import.
    SecretBulkUpdate,
    /// A secret copied to another vault: the read from the source. The
    /// request's own event, on the source vault and name.
    SecretCopyRead,
    /// A secret copied to another vault: the write to the target. Its own
    /// event, on the target vault and name.
    SecretCopyWrite,
    CertificateDownloadPrivateKey,
    CertificateUpload,
    CertificateCreate,
    CertificatePendingCancel,
    CertificateRenewalSet,
    CertificateEnabledSet,
    /// The description and tags of a certificate's current version changed
    /// ("Edit details"). The description itself is never in the event.
    CertificateUpdate,
    CertificateDelete,
    CertificateRecover,
    CertificatePurge,
    /// Tags or enabled changed on many certificates at once.
    CertificateBulkUpdate,
    KeyCreate,
    KeyRotate,
    KeyRotationPolicySet,
    KeyEnabledSet,
    /// The description and tags of a key's current version changed ("Edit
    /// details"). The description itself is never in the event.
    KeyUpdate,
    KeyDelete,
    KeyRecover,
    KeyPurge,
    /// Tags, expiry or enabled changed on many keys at once.
    KeyBulkUpdate,
    /// A PIM eligible role turned on (`SelfActivate`) from Keyring.
    RoleActivate,
    /// A PIM activated role turned off (`SelfDeactivate`) from Keyring.
    RoleDeactivate,
    /// A person refused by Key Vault asked the vault's owners for a role
    /// (#258). Keyring emails them and grants nothing.
    AccessRequest,
    /// A secret shared with a person or group (#286): a time-limited Key
    /// Vault Secrets User assignment on the secret, made as the sharer.
    /// A share Keyring refuses is this action with outcome `refused`.
    ShareGrant,
    /// A share Keyring made, removed from the secret's page.
    ShareRevoke,
    SessionSignIn,
    SessionSignInFailed,
    SessionSignOut,
    SessionExpired,
    /// A request refused before Keyring knew what it was for, such as a
    /// cross-site form post.
    RequestRefused,
    /// An email notification accepted by Azure Communication Services.
    /// Not tied to a request: written by the sender when the email ends.
    NotifySent,
    /// An email notification that wasn't sent, or that ACS said failed.
    NotifyFailed,
    /// One delivery from Event Grid to `/hooks/eventgrid`, whatever its
    /// outcome. No person: the caller is Event Grid.
    NotifyWebhook,
}

impl Action {
    /// Every action, for tests and docs.
    pub const ALL: [Action; 46] = [
        Self::SecretReveal,
        Self::SecretCreate,
        Self::SecretSet,
        Self::SecretUpdate,
        Self::SecretEnabledSet,
        Self::SecretRollback,
        Self::SecretDelete,
        Self::SecretRecover,
        Self::SecretPurge,
        Self::SecretImport,
        Self::SecretBulkUpdate,
        Self::SecretCopyRead,
        Self::SecretCopyWrite,
        Self::CertificateDownloadPrivateKey,
        Self::CertificateUpload,
        Self::CertificateCreate,
        Self::CertificatePendingCancel,
        Self::CertificateRenewalSet,
        Self::CertificateEnabledSet,
        Self::CertificateUpdate,
        Self::CertificateDelete,
        Self::CertificateRecover,
        Self::CertificatePurge,
        Self::CertificateBulkUpdate,
        Self::KeyCreate,
        Self::KeyRotate,
        Self::KeyRotationPolicySet,
        Self::KeyEnabledSet,
        Self::KeyUpdate,
        Self::KeyDelete,
        Self::KeyRecover,
        Self::KeyPurge,
        Self::KeyBulkUpdate,
        Self::RoleActivate,
        Self::RoleDeactivate,
        Self::AccessRequest,
        Self::ShareGrant,
        Self::ShareRevoke,
        Self::SessionSignIn,
        Self::SessionSignInFailed,
        Self::SessionSignOut,
        Self::SessionExpired,
        Self::RequestRefused,
        Self::NotifySent,
        Self::NotifyFailed,
        Self::NotifyWebhook,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretReveal => "secret.reveal",
            Self::SecretCreate => "secret.create",
            Self::SecretSet => "secret.set",
            Self::SecretUpdate => "secret.update",
            Self::SecretEnabledSet => "secret.enabled.set",
            Self::SecretRollback => "secret.rollback",
            Self::SecretDelete => "secret.delete",
            Self::SecretRecover => "secret.recover",
            Self::SecretPurge => "secret.purge",
            Self::SecretImport => "secret.import",
            Self::SecretBulkUpdate => "secret.bulk_update",
            Self::SecretCopyRead => "secret.copy.read",
            Self::SecretCopyWrite => "secret.copy.write",
            Self::CertificateDownloadPrivateKey => "certificate.download_private_key",
            Self::CertificateUpload => "certificate.upload",
            Self::CertificateCreate => "certificate.create",
            Self::CertificatePendingCancel => "certificate.pending.cancel",
            Self::CertificateRenewalSet => "certificate.renewal.set",
            Self::CertificateEnabledSet => "certificate.enabled.set",
            Self::CertificateUpdate => "certificate.update",
            Self::CertificateDelete => "certificate.delete",
            Self::CertificateRecover => "certificate.recover",
            Self::CertificatePurge => "certificate.purge",
            Self::CertificateBulkUpdate => "certificate.bulk_update",
            Self::KeyCreate => "key.create",
            Self::KeyRotate => "key.rotate",
            Self::KeyRotationPolicySet => "key.rotation_policy.set",
            Self::KeyEnabledSet => "key.enabled.set",
            Self::KeyUpdate => "key.update",
            Self::KeyDelete => "key.delete",
            Self::KeyRecover => "key.recover",
            Self::KeyPurge => "key.purge",
            Self::KeyBulkUpdate => "key.bulk_update",
            Self::RoleActivate => "role.activate",
            Self::RoleDeactivate => "role.deactivate",
            Self::AccessRequest => "access.request",
            Self::ShareGrant => "share.grant",
            Self::ShareRevoke => "share.revoke",
            Self::SessionSignIn => "session.sign_in",
            Self::SessionSignInFailed => "session.sign_in_failed",
            Self::SessionSignOut => "session.sign_out",
            Self::SessionExpired => "session.expired",
            Self::RequestRefused => "request.refused",
            Self::NotifySent => "notify.sent",
            Self::NotifyFailed => "notify.failed",
            Self::NotifyWebhook => "notify.webhook",
        }
    }

    /// What the audit pages call it, in plain words. The dotted name stays
    /// in the event, the filter's options and Log Analytics.
    pub fn label(self) -> &'static str {
        // What was asked for, never how it ended: a refused or failed
        // event has the same label, and the Result column says which.
        match self {
            Self::SecretReveal => "Show secret value",
            Self::SecretCreate => "Create secret",
            Self::SecretSet => "Set new secret value",
            Self::SecretUpdate => "Edit secret details",
            Self::SecretEnabledSet => "Turn secret on or off",
            Self::SecretRollback => "Roll back secret",
            Self::SecretDelete => "Delete secret",
            Self::SecretRecover => "Recover secret",
            Self::SecretPurge => "Purge secret",
            Self::SecretImport => "Import secrets",
            Self::SecretBulkUpdate => "Bulk change secrets",
            Self::SecretCopyRead => "Copy to another vault",
            Self::SecretCopyWrite => "Copy from another vault",
            Self::CertificateDownloadPrivateKey => "Download private key",
            Self::CertificateUpload => "Upload certificate",
            Self::CertificateCreate => "Create certificate",
            Self::CertificatePendingCancel => "Cancel certificate request",
            Self::CertificateRenewalSet => "Change renewal settings",
            Self::CertificateEnabledSet => "Turn certificate on or off",
            Self::CertificateUpdate => "Edit certificate details",
            Self::CertificateDelete => "Delete certificate",
            Self::CertificateRecover => "Recover certificate",
            Self::CertificatePurge => "Purge certificate",
            Self::CertificateBulkUpdate => "Bulk change certificates",
            Self::KeyCreate => "Create key",
            Self::KeyRotate => "Rotate key",
            Self::KeyRotationPolicySet => "Change rotation policy",
            Self::KeyEnabledSet => "Turn key on or off",
            Self::KeyUpdate => "Edit key details",
            Self::KeyDelete => "Delete key",
            Self::KeyRecover => "Recover key",
            Self::KeyPurge => "Purge key",
            Self::KeyBulkUpdate => "Bulk change keys",
            Self::RoleActivate => "Turn on role",
            Self::RoleDeactivate => "Turn off role",
            Self::AccessRequest => "Request access",
            Self::ShareGrant => "Share secret",
            Self::ShareRevoke => "Revoke share",
            Self::SessionSignIn => "Sign in",
            Self::SessionSignInFailed => "Sign in (refused)",
            Self::SessionSignOut => "Sign out",
            Self::SessionExpired => "Session timeout",
            Self::RequestRefused => "Unrecognised request",
            Self::NotifySent => "Send email",
            Self::NotifyFailed => "Send email (not sent)",
            Self::NotifyWebhook => "Event Grid delivery",
        }
    }

    /// The plain label for a dotted name read back from the log, or `None`
    /// for a name this version doesn't know.
    pub fn label_for(name: &str) -> Option<&'static str> {
        Self::ALL
            .iter()
            .find(|a| a.as_str() == name)
            .map(|a| a.label())
    }

    /// `secret`, `certificate` or `key` for actions on an item. A share is
    /// always of one secret.
    pub fn item_kind(self) -> Option<&'static str> {
        let name = self.as_str();
        if name.starts_with("share.") {
            return Some("secret");
        }
        ["secret", "certificate", "key"]
            .into_iter()
            .find(|k| name.strip_prefix(k).is_some_and(|r| r.starts_with('.')))
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    /// Azure said no: a 401 or 403.
    Denied,
    /// Keyring's own check said no. See [`Refusal`].
    Refused,
    /// Anything else went wrong.
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

/// Why Keyring refused. A fixed set, written as `reason_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The form token was missing, forged, or for another vault.
    Csrf,
    /// The request didn't come from Keyring's own pages.
    CrossSite,
    /// The typed name didn't match the item.
    TypedNameMismatch,
    /// Purge is turned off (`KEYRING_ALLOW_PURGE`).
    PurgeDisabled,
    /// The item belongs to a certificate and can only be used through it.
    ManagedItem,
    /// A bulk tag change would take an item past Key Vault's 15 tags.
    TagLimit,
    /// A form post with no live session.
    NoSession,
    /// The request couldn't be used as sent: a bad name or form field, a
    /// form Keyring couldn't read, or one too large.
    InvalidRequest,
    /// The sign-in reply didn't match a sign-in Keyring started.
    StaleSignIn,
    /// Entra's ID token failed Keyring's checks.
    IdTokenRejected,
    /// `KEYRING_AUDIT_REQUIRED` is on and the audit sink is degraded, so a
    /// reveal or private key download was refused.
    AuditUnavailable,
    /// A sensitive action needs a stronger or more recent sign-in
    /// (`KEYRING_STEP_UP_*`). The person was asked to confirm it's them.
    StepUpRequired,
    /// A step-up sign-in came back without the authentication context, or
    /// without a fresh enough sign-in. Refused, not retried.
    StepUpNotMet,
    /// `KEYRING_REQUIRE_REASON` asks for a reason (and maybe a ticket), and
    /// none was given or it didn't meet the rules. The person was asked.
    ReasonRequired,
    /// A password typed into a Password or Login secret didn't meet
    /// `KEYRING_PASSWORD_POLICY`. Says nothing about the value or which
    /// rule it failed.
    PasswordPolicy,
    /// `KEYRING_REQUIRE_OWNER` is on and the item would have been saved
    /// without an `owner` tag. Says nothing about the addresses.
    OwnerRequired,
    /// The item's `keyring-reveal` tag says Keyring mustn't show, copy or
    /// export its value. Says nothing about the value.
    RevealLimited,
    /// The person asked for the same role on the same vault within the
    /// hour (`access.request`). Nothing was sent.
    RateLimited,
    /// A share to the person sharing.
    ShareToSelf,
    /// A share's end date was in the past, or past
    /// `KEYRING_SHARE_MAX_DAYS`.
    ShareDate,
    /// A share to something that isn't a user or a security group Graph
    /// found in the sharer's tenant.
    SharePrincipal,
    /// A share of a secret Keyring won't share: one with a reveal limit
    /// (`keyring-reveal`), or in a vault that uses access policies.
    ShareNotAllowed,
}

impl Refusal {
    /// Every refusal, for tests and docs.
    pub const ALL: [Refusal; 22] = [
        Self::Csrf,
        Self::CrossSite,
        Self::TypedNameMismatch,
        Self::PurgeDisabled,
        Self::ManagedItem,
        Self::TagLimit,
        Self::NoSession,
        Self::InvalidRequest,
        Self::StaleSignIn,
        Self::IdTokenRejected,
        Self::AuditUnavailable,
        Self::StepUpRequired,
        Self::StepUpNotMet,
        Self::ReasonRequired,
        Self::PasswordPolicy,
        Self::OwnerRequired,
        Self::RevealLimited,
        Self::RateLimited,
        Self::ShareToSelf,
        Self::ShareDate,
        Self::SharePrincipal,
        Self::ShareNotAllowed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csrf => "csrf",
            Self::CrossSite => "cross_site",
            Self::TypedNameMismatch => "typed_name_mismatch",
            Self::PurgeDisabled => "purge_disabled",
            Self::ManagedItem => "managed_item",
            Self::TagLimit => "tag_limit",
            Self::NoSession => "no_session",
            Self::InvalidRequest => "invalid_request",
            Self::StaleSignIn => "stale_sign_in",
            Self::IdTokenRejected => "id_token_rejected",
            Self::AuditUnavailable => "audit_unavailable",
            Self::StepUpRequired => "step_up_required",
            Self::StepUpNotMet => "step_up_not_met",
            Self::ReasonRequired => "reason_required",
            Self::PasswordPolicy => "password_policy",
            Self::OwnerRequired => "owner_required",
            Self::RevealLimited => "reveal_limited",
            Self::RateLimited => "rate_limited",
            Self::ShareToSelf => "share_to_self",
            Self::ShareDate => "share_date",
            Self::SharePrincipal => "share_principal",
            Self::ShareNotAllowed => "share_not_allowed",
        }
    }
}

/// One audit event, schema version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// UTC, RFC 3339 with milliseconds.
    pub time: String,
    pub event_id: String,
    pub action: Action,
    pub outcome: Outcome,
    /// Azure's error code or a [`Refusal`]. Never Azure's message.
    pub reason_code: Option<String>,
    pub actor_oid: Option<String>,
    pub actor_tid: Option<String>,
    pub actor_upn: Option<String>,
    /// A keyed hash of the session ID, so one person's events join up
    /// without the log holding the cookie value.
    pub session_ref: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub vault: Option<String>,
    pub item_kind: Option<&'static str>,
    pub item_name: Option<String>,
    pub item_version: Option<String>,
    /// The `x-ms-client-request-id` Keyring sent on its last Key Vault call
    /// for this request.
    pub kv_request_id: Option<String>,
    /// Why the person did it, when `KEYRING_REQUIRE_REASON` asked, or the
    /// PIM justification on `role.activate`. Cleaned by [`crate::reason`]:
    /// no control or invisible characters, 5 to 200 characters.
    pub reason: Option<String>,
    /// A change or incident ticket, when `KEYRING_REASON_TICKET_PATTERN`
    /// asked and it matched, or the PIM ticket system and number.
    pub ticket: Option<String>,
    /// The role definition GUID turned on or off (`role.*` only).
    pub role: Option<String>,
    /// The ARM scope the role was turned on or off at (`role.*` only).
    pub role_scope: Option<String>,
    /// How long it was asked for, ISO 8601 (`PT8H`), on `role.activate`.
    pub role_duration: Option<String>,
    /// The notification type (`notify.*` only), such as `expiry`.
    pub notify_type: Option<&'static str>,
    /// How many recipients the email had (`notify.*` only).
    pub notify_recipient_count: Option<u64>,
    /// The recipients' addresses, separated by commas (`notify.*` only).
    /// Personal data: set only with `KEYRING_NOTIFY_AUDIT_RECIPIENTS=true`.
    pub notify_recipients: Option<String>,
    /// How many events an Event Grid delivery held (`notify.webhook`
    /// only), when it could be read.
    pub notify_event_count: Option<u64>,
    /// A reveal limit changed (`keyring-reveal`): what it was and what it
    /// became, each `unset`, `copy-only`, `none` or `other`.
    pub reveal_limit_from: Option<&'static str>,
    pub reveal_limit_to: Option<&'static str>,
    /// The object ID a secret was shared with or revoked from (`share.*`
    /// only), checked to be a GUID.
    pub share_principal_id: Option<String>,
    /// `user`, `guest` or `group` (`share.*` only).
    pub share_principal_type: Option<&'static str>,
    /// The share's end date, `YYYY-MM-DD` UTC (`share.grant` only).
    pub share_until: Option<String>,
    /// How the share was made: `pim` (Azure removes it at the end date) or
    /// `plain` (a role assignment that stays until removed).
    pub share_path: Option<&'static str>,
}

impl AuditEvent {
    /// A new event, timed now, with a fresh ID and nothing else set.
    pub fn new(action: Action, outcome: Outcome) -> Self {
        Self {
            time: rfc3339_millis(SystemTime::now()),
            event_id: new_uuid(),
            action,
            outcome,
            reason_code: None,
            actor_oid: None,
            actor_tid: None,
            actor_upn: None,
            session_ref: None,
            client_ip: None,
            user_agent: None,
            vault: None,
            item_kind: action.item_kind(),
            item_name: None,
            item_version: None,
            kv_request_id: None,
            reason: None,
            ticket: None,
            role: None,
            role_scope: None,
            role_duration: None,
            notify_type: None,
            notify_recipient_count: None,
            notify_recipients: None,
            notify_event_count: None,
            reveal_limit_from: None,
            reveal_limit_to: None,
            share_principal_id: None,
            share_principal_type: None,
            share_until: None,
            share_path: None,
        }
    }

    /// Name the person and session.
    pub fn by(mut self, session: &Session) -> Self {
        let id = &session.user.subject;
        self.actor_oid = id.oid.clone();
        self.actor_tid = id.tid.clone();
        self.actor_upn = session.user.username.clone();
        self.session_ref = Some(session.audit_ref.clone());
        self
    }
}

/// Add the browser details of the request in progress, if there is one.
/// Only for an event about that browser's own session.
pub fn from_this_browser(mut ev: AuditEvent) -> AuditEvent {
    let _ = CTX.try_with(|d| {
        let d = lock(d);
        ev.client_ip.clone_from(&d.client_ip);
        ev.user_agent.clone_from(&d.user_agent);
    });
    ev
}

/// The Keyring build, written on every event.
pub const KEYRING_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A random ID for this process, so events from several copies of Keyring
/// can be told apart.
pub fn instance() -> &'static str {
    static INSTANCE: LazyLock<String> = LazyLock::new(new_uuid);
    &INSTANCE
}

fn opt(v: &Option<String>) -> Option<tracing::field::DisplayValue<&str>> {
    v.as_deref().map(tracing::field::display)
}

/// Something that watches audit events as they are recorded, in memory,
/// such as the health watcher's refusal count. Called after the event is
/// written, with the event only. It must return at once: no network, no
/// await, no lock held for longer than a few map operations. A panic in
/// it is caught, so it can never fail [`record_to`].
pub trait Observe: Send + Sync + std::fmt::Debug {
    fn observe(&self, ev: &AuditEvent);

    /// [`Observe::observe`] for a request's own event, with what the
    /// request noted beside it that is never written on the event: the
    /// session, a watched item's recipients and the names a bulk change
    /// changed. Same rules: return at once, no network on this thread.
    fn observe_request(&self, ev: &AuditEvent, _facts: &Facts<'_>) {
        self.observe(ev);
    }
}

/// What a request noted for observers, beside its event. Never written to
/// a log or the sink.
#[derive(Debug, Default, Clone, Copy)]
pub struct Facts<'a> {
    /// The verified session the request ran in.
    pub session: Option<&'a Arc<Session>>,
    /// The recipients of a watched item the request read.
    pub watched: Option<&'a crate::notify::activity::Watched>,
    /// Item names a bulk change changed, each already a checked name.
    pub changed: &'a [String],
}

/// Several observers, each called in turn.
#[derive(Debug)]
pub struct Fanout(pub Vec<Arc<dyn Observe>>);

impl Observe for Fanout {
    fn observe(&self, ev: &AuditEvent) {
        for o in &self.0 {
            o.observe(ev);
        }
    }

    fn observe_request(&self, ev: &AuditEvent, facts: &Facts<'_>) {
        for o in &self.0 {
            o.observe_request(ev, facts);
        }
    }
}

/// Write one audit event to standard output and, with the audit sink set,
/// queue it for Log Analytics. The actor is already on the event, from the
/// verified session. Not observed: for events Keyring writes about itself
/// (session expiry, email), which must never count as something a person
/// did. Requests use [`record_to`].
pub fn record(ev: AuditEvent, sink: Option<&sink::AuditSink>) {
    record_to(ev, sink, None);
}

/// [`record`], then hand the event to `observer`, if any. The only way an
/// event is written.
pub fn record_to(ev: AuditEvent, sink: Option<&sink::AuditSink>, observer: Option<&dyn Observe>) {
    record_with(ev, sink, observer, &Facts::default());
}

/// [`record_to`] for a request's own event, with its [`Facts`].
fn record_with(
    ev: AuditEvent,
    sink: Option<&sink::AuditSink>,
    observer: Option<&dyn Observe>,
    facts: &Facts<'_>,
) {
    // Fields from Keyring or checked on the way in are written as they are.
    // The user agent, UPN, reason and ticket are written as plain strings,
    // which the text format quotes and escapes and JSON escapes, so a
    // crafted value can't forge a line. The reason and ticket also had
    // every control character taken out before they got here.
    tracing::info!(
        target: TARGET,
        kind = tracing::field::display("audit"),
        schema_version = SCHEMA_VERSION,
        time = tracing::field::display(&ev.time),
        event_id = tracing::field::display(&ev.event_id),
        action = tracing::field::display(ev.action.as_str()),
        outcome = tracing::field::display(ev.outcome.as_str()),
        reason_code = opt(&ev.reason_code),
        actor_oid = opt(&ev.actor_oid),
        actor_tid = opt(&ev.actor_tid),
        actor_upn = ev.actor_upn.as_deref(),
        session_ref = opt(&ev.session_ref),
        client_ip = opt(&ev.client_ip),
        user_agent = ev.user_agent.as_deref(),
        vault = opt(&ev.vault),
        item_kind = ev.item_kind.map(tracing::field::display),
        item_name = opt(&ev.item_name),
        item_version = opt(&ev.item_version),
        kv_request_id = opt(&ev.kv_request_id),
        role = opt(&ev.role),
        role_scope = opt(&ev.role_scope),
        role_duration = opt(&ev.role_duration),
        notify_type = ev.notify_type.map(tracing::field::display),
        notify_recipient_count = ev.notify_recipient_count,
        notify_recipients = opt(&ev.notify_recipients),
        notify_event_count = ev.notify_event_count,
        reveal_limit_from = ev.reveal_limit_from.map(tracing::field::display),
        reveal_limit_to = ev.reveal_limit_to.map(tracing::field::display),
        share_principal_id = opt(&ev.share_principal_id),
        share_principal_type = ev.share_principal_type.map(tracing::field::display),
        share_until = opt(&ev.share_until),
        share_path = ev.share_path.map(tracing::field::display),
        keyring_version = tracing::field::display(KEYRING_VERSION),
        instance = tracing::field::display(instance()),
        // Last, so in the text format nothing typed can come before a
        // real field.
        ticket = ev.ticket.as_deref(),
        reason = ev.reason.as_deref(),
        "audit"
    );
    if let Some(sink) = sink {
        sink.enqueue(&ev);
    }
    if let Some(o) = observer {
        // Never let an observer fail the request that wrote the event.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            o.observe_request(&ev, facts);
        }));
    }
}

// ---------------------------------------------------------------------
// The per-request draft
// ---------------------------------------------------------------------

/// What a request has learned about its action so far.
#[derive(Debug, Default)]
struct Draft {
    action: Option<Action>,
    /// Set by a guard or handler that knows how it ended. First one wins.
    outcome: Option<(Outcome, String)>,
    /// The last failed Azure call, used if nothing else says how it ended.
    azure: Option<(Outcome, String)>,
    actor_oid: Option<String>,
    actor_tid: Option<String>,
    actor_upn: Option<String>,
    session_ref: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    vault: Option<String>,
    item_name: Option<String>,
    /// The item's kind, for an action that isn't on one kind of item
    /// (`access.request`).
    item_kind: Option<&'static str>,
    item_version: Option<String>,
    kv_request_id: Option<String>,
    reason: Option<String>,
    ticket: Option<String>,
    role: Option<String>,
    role_scope: Option<String>,
    role_duration: Option<String>,
    notify_type: Option<&'static str>,
    notify_event_count: Option<u64>,
    reveal_limit_from: Option<&'static str>,
    reveal_limit_to: Option<&'static str>,
    share_principal_id: Option<String>,
    share_principal_type: Option<&'static str>,
    share_until: Option<String>,
    share_path: Option<&'static str>,
    /// Watches the request's events, when the health watcher is on.
    observer: Option<Arc<dyn Observe>>,
    /// The verified session, for observers only. Never on the event.
    session: Option<Arc<Session>>,
    /// A watched item's recipients, for observers only.
    watched: Option<crate::notify::activity::Watched>,
    /// Names a bulk change changed, for observers only.
    changed: Vec<String>,
}

tokio::task_local! {
    static CTX: Arc<Mutex<Draft>>;
}

fn lock(m: &Mutex<Draft>) -> MutexGuard<'_, Draft> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Change the draft, if this is inside a request.
fn note(f: impl FnOnce(&mut Draft)) {
    let _ = CTX.try_with(|d| f(&mut lock(d)));
}

/// Say what this request does. Set by the router for audited routes, and
/// by the sign-in callback.
pub fn set_action(action: Action) {
    note(|d| d.action = Some(action));
}

/// Say what this request does, unless something already has.
pub fn set_action_if_none(action: Action) {
    note(|d| {
        d.action.get_or_insert(action);
    });
}

/// Keyring's own check refused the request.
pub fn refuse(why: Refusal) {
    note(|d| {
        d.outcome
            .get_or_insert((Outcome::Refused, why.as_str().to_owned()));
    });
}

/// Say the request's own action went through, whatever the response.
/// For a copy, whose request event is the read: when the write that
/// follows fails, the read still succeeded. First one wins.
pub fn succeed() {
    note(|d| {
        d.outcome.get_or_insert((Outcome::Success, String::new()));
    });
}

/// Say how the request ended, with a reason code. First one wins.
pub fn end(outcome: Outcome, reason_code: &str) {
    note(|d| {
        d.outcome.get_or_insert((outcome, safe_code(reason_code)));
    });
}

/// The notification type and how many events a webhook delivery held.
/// Also drops the user agent the layer took from the request: on the
/// webhook it is a header sent by whoever called, not a person's browser,
/// and request headers there are never logged.
pub fn note_notify(kind: &'static str, events: Option<u64>) {
    note(|d| {
        d.notify_type = Some(kind);
        d.notify_event_count = events;
        d.user_agent = None;
    });
}

/// The signed-in person and session.
pub fn note_session(session: &Session) {
    note(|d| {
        let id = &session.user.subject;
        d.actor_oid.clone_from(&id.oid);
        d.actor_tid.clone_from(&id.tid);
        d.actor_upn.clone_from(&session.user.username);
        d.session_ref = Some(session.audit_ref.clone());
    });
}

/// Keep the verified session beside the draft, for observers. It is never
/// written on the event.
pub fn keep_session(session: Arc<Session>) {
    note(|d| d.session = Some(session));
}

/// The recipients of a watched item this request read. Used only if the
/// request's event ends as a success. See [`crate::notify::activity`].
pub fn note_watched(w: crate::notify::activity::Watched) {
    note(|d| d.watched = Some(w));
}

/// The item names a bulk change changed. Each must be a checked name.
pub fn note_changed(names: Vec<String>) {
    note(|d| d.changed = names);
}

/// The person from a verified ID token, before any session is made for
/// them. Used when a sign-in is refused after the token passed its checks.
pub fn note_user(user: &crate::auth::session::User) {
    note(|d| {
        d.actor_oid.clone_from(&user.subject.oid);
        d.actor_tid.clone_from(&user.subject.tid);
        d.actor_upn.clone_from(&user.username);
    });
}

/// The vault acted on. Must already be a checked vault name.
pub fn note_vault(vault: &str) {
    note(|d| d.vault = Some(vault.to_owned()));
}

/// The item acted on. Must already be a checked item name.
pub fn note_item(name: &str) {
    note(|d| d.item_name = Some(name.to_owned()));
}

/// A reveal limit changed, from one fixed word to another
/// ([`crate::reveal_limit::word`]).
pub fn note_reveal_limit(from: &'static str, to: &'static str) {
    note(|d| {
        d.reveal_limit_from = Some(from);
        d.reveal_limit_to = Some(to);
    });
}

/// The item version read or restored. Must already be checked.
pub fn note_version(version: &str) {
    note(|d| d.item_version = Some(version.to_owned()));
}

/// The `x-ms-client-request-id` of a Key Vault call just sent.
pub fn note_kv_request(id: &str) {
    note(|d| d.kv_request_id = Some(id.to_owned()));
}

/// A PIM role request: the role GUID, the scope and, for an activation,
/// the duration, justification and ticket. All must already be checked:
/// the GUID and scope against ARM's rules, the text with
/// [`crate::azure::pim::clean_line`].
pub fn note_role_request(
    role: &str,
    scope: &str,
    duration: Option<&str>,
    reason: Option<&str>,
    ticket: Option<&str>,
) {
    note(|d| {
        d.role = Some(role.to_owned());
        d.role_scope = Some(scope.to_owned());
        d.role_duration = duration.map(str::to_owned);
        d.reason = reason.map(str::to_owned);
        d.ticket = ticket.map(str::to_owned);
    });
}

/// A share (#286): the role, the secret's scope, the principal, and for a
/// grant the end date and how it was made. All must already be checked:
/// the scope built by `crate::azure::share::secret_scope`, the principal
/// ID a GUID, the date `YYYY-MM-DD`.
pub fn note_share(
    scope: &str,
    principal_id: &str,
    principal_type: Option<&'static str>,
    until: Option<&str>,
    path: Option<&'static str>,
) {
    note(|d| {
        d.role = Some(crate::azure::share::SECRETS_USER.to_owned());
        d.role_scope = Some(scope.to_owned());
        d.share_principal_id = Some(principal_id.to_owned());
        if principal_type.is_some() {
            d.share_principal_type = principal_type;
        }
        if until.is_some() {
            d.share_until = until.map(str::to_owned);
        }
        if path.is_some() {
            d.share_path = path;
        }
    });
}

/// An access request (`access.request`): the role GUID, the ARM scope
/// asked for when the vault's resource ID was read, the item's kind when
/// the request is for one item, and the reason and ticket, already checked
/// by [`crate::reason`].
pub fn note_access_request(
    role: &str,
    scope: Option<&str>,
    item_kind: Option<&'static str>,
    given: Option<&crate::reason::Given>,
) {
    note(|d| {
        d.role = Some(role.to_owned());
        d.role_scope = scope.map(str::to_owned);
        d.item_kind = item_kind;
        if let Some(g) = given {
            d.reason = Some(g.reason.clone());
            d.ticket.clone_from(&g.ticket);
        }
    });
}

/// The reason and ticket the person gave, already cleaned and checked by
/// [`crate::reason`].
pub fn note_reason(given: &crate::reason::Given) {
    note(|d| {
        d.reason = Some(given.reason.clone());
        d.ticket.clone_from(&given.ticket);
    });
}

/// A failed Azure call. Only the status and code are kept.
pub fn note_azure_error(err: &AzureError) {
    let (outcome, code) = match err {
        AzureError::Status { status, code, .. } => (
            if matches!(status, 401 | 403) {
                Outcome::Denied
            } else {
                Outcome::Failed
            },
            code.clone().unwrap_or_else(|| format!("http_{status}")),
        ),
        AzureError::Token(TokenError::SignInAgain) => (Outcome::Failed, "sign_in_again".into()),
        AzureError::Token(TokenError::MfaStillNeeded { .. }) => {
            (Outcome::Denied, "mfa_still_needed".into())
        }
        AzureError::Token(TokenError::ConsentNeeded) => (Outcome::Denied, "consent_needed".into()),
        AzureError::Token(TokenError::Refused { code }) => (Outcome::Denied, code.clone()),
        AzureError::Token(TokenError::Unreachable(_)) => {
            (Outcome::Failed, "entra_unreachable".into())
        }
        AzureError::Network(_) => (Outcome::Failed, "network".into()),
        AzureError::Unreadable => (Outcome::Failed, "unreadable".into()),
    };
    note(|d| d.azure = Some((outcome, safe_code(&code))));
}

/// Who and where the request in progress came from, kept so a request
/// that changes many items can write an event for each one. Taken inside
/// the request, then usable from tasks spawned by it (which don't see the
/// request's own draft).
#[derive(Debug, Clone)]
pub struct ItemEvents {
    action: Action,
    actor_oid: Option<String>,
    actor_tid: Option<String>,
    actor_upn: Option<String>,
    session_ref: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    vault: Option<String>,
    /// The reason and ticket given for the request, repeated on each
    /// item's event.
    reason: Option<String>,
    ticket: Option<String>,
    /// The audit sink, so each item's event is sent as the request's is.
    sink: Option<Arc<sink::AuditSink>>,
    /// The request's observer, so each item's event is watched too.
    observer: Option<Arc<dyn Observe>>,
}

impl ItemEvents {
    /// The person, session, browser and vault of the request in progress.
    /// `sink` is the app's audit sink, if one is set.
    pub fn for_request(action: Action, sink: Option<Arc<sink::AuditSink>>) -> Self {
        let mut me = Self {
            action,
            sink,
            actor_oid: None,
            actor_tid: None,
            actor_upn: None,
            session_ref: None,
            client_ip: None,
            user_agent: None,
            vault: None,
            reason: None,
            ticket: None,
            observer: None,
        };
        note(|d| {
            me.actor_oid.clone_from(&d.actor_oid);
            me.actor_tid.clone_from(&d.actor_tid);
            me.actor_upn.clone_from(&d.actor_upn);
            me.session_ref.clone_from(&d.session_ref);
            me.client_ip.clone_from(&d.client_ip);
            me.user_agent.clone_from(&d.user_agent);
            me.vault.clone_from(&d.vault);
            me.reason.clone_from(&d.reason);
            me.ticket.clone_from(&d.ticket);
            me.observer.clone_from(&d.observer);
        });
        me
    }

    /// Write the events for another vault than the request's, such as the
    /// target of a copy. `vault` must be a checked vault name.
    #[must_use]
    pub fn in_vault(mut self, vault: &str) -> Self {
        self.vault = Some(vault.to_owned());
        self
    }

    /// Run `work` on one item and write one event for it: `success` if it
    /// returns `Ok`, otherwise what its failed Azure call said. The event
    /// carries the item name, and the `kv_request_id` of `work`'s own last
    /// Key Vault call. If `work` is dropped before it finishes, the event
    /// says `failed` with `cancelled`. `item` must be a checked name.
    pub async fn run<T, E>(
        &self,
        item: &str,
        work: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let draft = Arc::new(Mutex::new(Draft {
            action: Some(self.action),
            actor_oid: self.actor_oid.clone(),
            actor_tid: self.actor_tid.clone(),
            actor_upn: self.actor_upn.clone(),
            session_ref: self.session_ref.clone(),
            client_ip: self.client_ip.clone(),
            user_agent: self.user_agent.clone(),
            vault: self.vault.clone(),
            reason: self.reason.clone(),
            ticket: self.ticket.clone(),
            item_name: Some(item.to_owned()),
            observer: self.observer.clone(),
            ..Draft::default()
        }));
        let mut pending = Pending {
            draft: draft.clone(),
            sink: self.sink.clone(),
            done: false,
        };
        let res = CTX.scope(draft.clone(), work).await;
        pending.done = true;
        let mut d = std::mem::take(&mut *lock(&draft));
        let observer = d.observer.take();
        let status = if res.is_ok() {
            axum::http::StatusCode::OK
        } else {
            // A failure that wasn't an Azure call (none today) still counts.
            d.azure
                .get_or_insert((Outcome::Failed, "failed".to_owned()));
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        };
        if let Some(ev) = finish(d, status) {
            record_to(ev, self.sink.as_deref(), observer.as_deref());
        }
        res
    }
}

impl ItemEvents {
    /// Write one `refused` event for an item Keyring didn't send to Key
    /// Vault, with the fixed reason code only.
    pub async fn refused(&self, item: &str, why: Refusal) {
        let _ = self
            .run(item, async {
                refuse(why);
                Ok::<(), ()>(())
            })
            .await;
    }
}

/// Middleware, outside everything but the request log: hold a draft for
/// the request and write its event when the request finishes, if the
/// request was for an audited action.
pub async fn layer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let draft = Draft {
        client_ip: client_ip(req.headers(), peer, state.config.trusted_proxy_hops)
            .map(|ip| ip.to_string()),
        user_agent: user_agent(req.headers()),
        observer: state.audit_observer(),
        ..Draft::default()
    };
    let draft = Arc::new(Mutex::new(draft));
    let mut pending = Pending {
        draft: draft.clone(),
        sink: state.audit_sink.clone(),
        done: false,
    };
    let res = CTX.scope(draft.clone(), next.run(req)).await;
    pending.done = true;
    let mut d = std::mem::take(&mut *lock(&draft));
    let observer = d.observer.take();
    let session = d.session.take();
    let watched = d.watched.take();
    let changed = std::mem::take(&mut d.changed);
    if let Some(ev) = finish(d, res.status()) {
        let facts = Facts {
            session: session.as_ref(),
            watched: watched.as_ref(),
            changed: &changed,
        };
        record_with(ev, state.audit_sink.as_deref(), observer.as_deref(), &facts);
    }
    res
}

/// Writes the event for a request that was dropped before it answered,
/// such as when the browser closed the connection. Key Vault may already
/// have been called by then, so the request still gets its event.
struct Pending {
    draft: Arc<Mutex<Draft>>,
    sink: Option<Arc<sink::AuditSink>>,
    done: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut d = std::mem::take(&mut *lock(&self.draft));
        let observer = d.observer.take();
        if let Some(ev) = finish_cancelled(d) {
            record_to(ev, self.sink.as_deref(), observer.as_deref());
        }
    }
}

/// The event for a request dropped before it answered: `failed` with
/// `cancelled`, unless a guard had already said how it ended.
fn finish_cancelled(mut d: Draft) -> Option<AuditEvent> {
    d.outcome
        .get_or_insert((Outcome::Failed, "cancelled".to_owned()));
    finish(d, axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

/// Turn a finished request's draft into its event. `None` if the request
/// wasn't for an audited action.
fn finish(d: Draft, status: axum::http::StatusCode) -> Option<AuditEvent> {
    let action = d.action?;
    let (outcome, reason_code) = match (d.outcome, d.azure) {
        (Some((o, r)), _) => (o, (!r.is_empty()).then_some(r)),
        _ if status.is_success() || status.is_redirection() => (Outcome::Success, None),
        (None, Some((o, r))) => (o, Some(r)),
        (None, None) if status == axum::http::StatusCode::GATEWAY_TIMEOUT => {
            (Outcome::Failed, Some("timeout".into()))
        }
        (None, None) if status.is_server_error() => (Outcome::Failed, Some("server_error".into())),
        (None, None) => (
            Outcome::Refused,
            Some(Refusal::InvalidRequest.as_str().into()),
        ),
    };
    let mut ev = AuditEvent::new(action, outcome);
    ev.reason_code = reason_code;
    ev.actor_oid = d.actor_oid;
    ev.actor_tid = d.actor_tid;
    ev.actor_upn = d.actor_upn;
    ev.session_ref = d.session_ref;
    ev.client_ip = d.client_ip;
    ev.user_agent = d.user_agent;
    ev.vault = d.vault;
    ev.item_name = d.item_name;
    if d.item_kind.is_some() {
        ev.item_kind = d.item_kind;
    }
    ev.item_version = d.item_version;
    ev.kv_request_id = d.kv_request_id;
    ev.reason = d.reason;
    ev.ticket = d.ticket;
    ev.role = d.role;
    ev.role_scope = d.role_scope;
    ev.role_duration = d.role_duration;
    ev.notify_type = d.notify_type;
    ev.notify_event_count = d.notify_event_count;
    ev.reveal_limit_from = d.reveal_limit_from;
    ev.reveal_limit_to = d.reveal_limit_to;
    ev.share_principal_id = d.share_principal_id;
    ev.share_principal_type = d.share_principal_type;
    ev.share_until = d.share_until;
    ev.share_path = d.share_path;
    Some(ev)
}

/// The browser's address. With `hops` set, the address that many entries
/// from the right of `X-Forwarded-For`, which the proxies in front of
/// Keyring added. Otherwise, or if that entry isn't an address, the socket
/// peer (the proxy itself, behind one).
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, hops: u8) -> Option<IpAddr> {
    if hops == 0 {
        return peer;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    let hops = usize::from(hops);
    entries
        .len()
        .checked_sub(hops)
        .and_then(|i| parse_forwarded(entries[i]))
        .or(peer)
}

/// An address from `X-Forwarded-For`, with or without a port. App Service
/// adds the port (`203.0.113.7:51234`).
fn parse_forwarded(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// The user agent, cut to [`MAX_USER_AGENT`] characters.
fn user_agent(headers: &HeaderMap) -> Option<String> {
    let ua = headers.get(axum::http::header::USER_AGENT)?;
    let ua = String::from_utf8_lossy(ua.as_bytes());
    Some(ua.chars().take(MAX_USER_AGENT).collect())
}

/// A reason code as written: letters, digits, `_`, `.` and `-`, at most 64
/// characters. Anything else becomes `unrecognised`.
pub fn safe_code(raw: &str) -> String {
    if (1..=64).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        raw.to_owned()
    } else {
        "unrecognised".to_owned()
    }
}

/// A random (version 4) UUID.
pub fn new_uuid() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("the operating system random number generator failed");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// `2026-11-17T09:30:05.123Z`.
pub fn rfc3339_millis(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = i64::try_from(d.as_secs()).unwrap_or(0);
    let (y, m, day) = crate::dates::civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderValue, StatusCode};

    use super::*;

    #[test]
    fn action_names_are_dotted_and_unique() {
        let names: std::collections::BTreeSet<&str> =
            Action::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names.len(), Action::ALL.len());
        for n in names {
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'),
                "{n}"
            );
            assert!(n.contains('.'), "{n}");
        }
        assert_eq!(Action::SecretReveal.item_kind(), Some("secret"));
        assert_eq!(
            Action::CertificateDownloadPrivateKey.item_kind(),
            Some("certificate")
        );
        assert_eq!(Action::KeyRotationPolicySet.item_kind(), Some("key"));
        assert_eq!(Action::SessionSignOut.item_kind(), None);
        assert_eq!(Action::ShareGrant.item_kind(), Some("secret"));
        assert_eq!(Action::ShareRevoke.item_kind(), Some("secret"));
        assert_eq!(Action::RequestRefused.item_kind(), None);
    }

    #[test]
    fn uuids_look_right() {
        let a = new_uuid();
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(a, new_uuid());
    }

    #[test]
    fn time_is_rfc3339_with_millis() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(1_794_233_100_042);
        assert_eq!(rfc3339_millis(t), "2026-11-09T14:05:00.042Z");
    }

    fn xff(v: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(v));
        h
    }

    #[test]
    fn client_ip_rules() {
        let peer = Some("10.0.0.9".parse().unwrap());
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        // With no trusted proxies, the header is ignored.
        assert_eq!(client_ip(&xff("203.0.113.7"), peer, 0), peer);
        // One proxy: the entry it added, on the right.
        assert_eq!(
            client_ip(&xff("198.51.100.1, 203.0.113.7"), peer, 1),
            ip("203.0.113.7")
        );
        assert_eq!(
            client_ip(&xff("198.51.100.1, 203.0.113.7"), peer, 2),
            ip("198.51.100.1")
        );
        // App Service adds the port.
        assert_eq!(
            client_ip(&xff("203.0.113.7:51234"), peer, 1),
            ip("203.0.113.7")
        );
        assert_eq!(
            client_ip(&xff("[2001:db8::1]:443"), peer, 1),
            ip("2001:db8::1")
        );
        // Too few entries, or junk: the socket peer.
        assert_eq!(client_ip(&xff("203.0.113.7"), peer, 2), peer);
        assert_eq!(client_ip(&xff("not-an-ip"), peer, 1), peer);
        assert_eq!(client_ip(&HeaderMap::new(), peer, 1), peer);
    }

    #[test]
    fn user_agent_is_cut() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_str(&"a".repeat(1000)).unwrap(),
        );
        assert_eq!(user_agent(&h).unwrap().len(), MAX_USER_AGENT);
    }

    #[test]
    fn reason_codes_are_safe() {
        assert_eq!(safe_code("ForbiddenByRbac"), "ForbiddenByRbac");
        assert_eq!(safe_code("bad code\nx"), "unrecognised");
        assert_eq!(safe_code(""), "unrecognised");
        assert_eq!(safe_code(&"a".repeat(65)), "unrecognised");
    }

    fn draft(action: Option<Action>) -> Draft {
        Draft {
            action,
            ..Draft::default()
        }
    }

    #[test]
    fn outcome_rules() {
        assert!(finish(draft(None), StatusCode::OK).is_none());
        let ok = finish(draft(Some(Action::SecretReveal)), StatusCode::OK).unwrap();
        assert_eq!((ok.outcome, ok.reason_code), (Outcome::Success, None));
        // A refusal wins over the status.
        let mut d = draft(Some(Action::SecretDelete));
        d.outcome = Some((Outcome::Refused, "typed_name_mismatch".into()));
        let ev = finish(d, StatusCode::UNPROCESSABLE_ENTITY).unwrap();
        assert_eq!(ev.outcome, Outcome::Refused);
        assert_eq!(ev.reason_code.as_deref(), Some("typed_name_mismatch"));
        // A failed Azure call the handler got past doesn't count.
        let mut d = draft(Some(Action::SecretCreate));
        d.azure = Some((Outcome::Failed, "SecretNotFound".into()));
        assert_eq!(
            finish(d, StatusCode::SEE_OTHER).unwrap().outcome,
            Outcome::Success
        );
        // One it didn't does.
        let mut d = draft(Some(Action::SecretReveal));
        d.azure = Some((Outcome::Denied, "ForbiddenByRbac".into()));
        let ev = finish(d, StatusCode::FORBIDDEN).unwrap();
        assert_eq!(ev.outcome, Outcome::Denied);
        assert_eq!(ev.reason_code.as_deref(), Some("ForbiddenByRbac"));
        let ev = finish(draft(Some(Action::KeyRotate)), StatusCode::GATEWAY_TIMEOUT).unwrap();
        assert_eq!(
            (ev.outcome, ev.reason_code.as_deref()),
            (Outcome::Failed, Some("timeout"))
        );
        // Dropped before it answered: still an event, and a refusal a
        // guard had already made is kept.
        assert!(finish_cancelled(draft(None)).is_none());
        let ev = finish_cancelled(draft(Some(Action::SecretDelete))).unwrap();
        assert_eq!(
            (ev.outcome, ev.reason_code.as_deref()),
            (Outcome::Failed, Some("cancelled"))
        );
        let mut d = draft(Some(Action::SecretDelete));
        d.outcome = Some((Outcome::Refused, "csrf".into()));
        assert_eq!(finish_cancelled(d).unwrap().outcome, Outcome::Refused);
        let ev = finish(draft(Some(Action::KeyRotate)), StatusCode::BAD_REQUEST).unwrap();
        assert_eq!(
            (ev.outcome, ev.reason_code.as_deref()),
            (Outcome::Refused, Some("invalid_request"))
        );
    }
}
