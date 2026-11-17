//! Activity emails (#259): watched item reads, deletes, purges and bulk
//! changes, and PIM role use. Each part is on only with its type in
//! `KEYRING_NOTIFY_TYPES`: `watched-reads`, `destructive`, `role-use`.
//!
//! The trigger is the request's audit event in memory, through
//! [`crate::audit::Observe`], so it works with the audit sink off. Only a
//! `success` sends (and a bulk change that changed some items but not
//! all, since those items did change). `notify.*` events never send.
//!
//! - **Watched reads** (`secret.reveal`, `certificate.download_private_key`,
//!   `secret.copy.read`, `secret.rollback`): the handler passes the item's
//!   tags from the read it already did to [`note_read`], which keeps only
//!   the parsed `notify` and `owner` addresses on the request's draft. No
//!   extra vault call. Recipients are the `notify` addresses, and the
//!   `owner` too with `KEYRING_NOTIFY_OWNER_ON_READ=true`. One item sends
//!   at most [`READS_PER_ITEM_PER_HOUR`] emails an hour, in a bounded map.
//! - **Deletes, purges and bulk changes**, and **role use**: the vault's
//!   `keyring-owners` ARM tag, read from Resource Graph as the signed-in
//!   person in a spawned task with a [`OWNERS_TIMEOUT`] limit, after the
//!   request has answered. With no owners, or on any failure,
//!   `KEYRING_NOTIFY_ADMINS`, and nothing says why.
//! - **Not the actor.** The person who acted is taken off the recipients
//!   by mailbox, unless they are the only one left.
//!
//! An email holds fixed text, the action's fixed words, checked vault and
//! item names, the actor's sign-in name only when it is one plain address,
//! a parsed IP, Keyring-formatted times and counts, the checked role,
//! scope and duration, a ticket that matches
//! `KEYRING_REASON_TICKET_PATTERN`, and links built from `APP_BASE_URL`.
//! Never a value, token, reason, justification, description, tag value,
//! user agent or Azure's message. A reason is only said to have been
//! given.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use askama::Template;

use super::health::Clock;
use super::sender::Notifier;
use super::{
    Address, EmailBody, EmailContext, ItemKind, ItemRef, Notification, NotifyType, Rendered,
    clean_line,
};
use crate::audit::{Action, AuditEvent, Facts, Observe, Outcome};
use crate::auth::session::Session;
use crate::azure::AzureClient;

/// Most watched-read emails about one item in an hour.
pub const READS_PER_ITEM_PER_HOUR: usize = 4;

/// Most items tracked for the per-item limit.
pub const MAX_TRACKED_ITEMS: usize = 10_000;

/// Most item names listed in a bulk change email. The rest are counted.
pub const MAX_LISTED: usize = 50;

/// Longest wait for the vault's owners from Resource Graph.
pub const OWNERS_TIMEOUT: Duration = Duration::from_secs(10);

/// A watched item's recipients, parsed from its tags. `Debug` never prints
/// an address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watched {
    notify: Vec<Address>,
    owner: Option<Address>,
}

/// The recipients in an item's tags, or `None` when it has neither a
/// `notify` nor an `owner` address that parses. Only addresses are kept.
pub fn watched(tags: &BTreeMap<String, String>) -> Option<Watched> {
    let owner = crate::owner::owner_of(tags)
        .filter(|o| !o.contains(','))
        .and_then(|o| Address::parse(o.trim()).ok());
    let mut notify: Vec<Address> = Vec::new();
    for part in crate::owner::notify_of(tags)
        .into_iter()
        .flat_map(|n| n.split(','))
    {
        if let Ok(a) = Address::parse(part.trim())
            && !notify.iter().any(|x| x.mailbox_key() == a.mailbox_key())
            && notify.len() < crate::owner::MAX_NOTIFY
        {
            notify.push(a);
        }
    }
    (owner.is_some() || !notify.is_empty()).then_some(Watched { notify, owner })
}

/// Called by a read handler with the item's tags from the read it just did.
/// Keeps the parsed addresses on the request's audit draft; the email is
/// sent only if the request's event ends as a success. Takes the tags
/// only: never the value or anything about it.
pub fn note_read(tags: Option<&BTreeMap<String, String>>) {
    if let Some(w) = tags.and_then(watched) {
        crate::audit::note_watched(w);
    }
}

/// What the watcher needs. Built from the configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `APP_BASE_URL`.
    pub base_url: String,
    /// Azure Resource Manager base URL, for the vault's owners.
    pub management_url: String,
    /// `KEYRING_NOTIFY_OWNER_ON_READ`.
    pub owner_on_read: bool,
    /// `KEYRING_REASON_TICKET_PATTERN`, when set.
    pub ticket: Option<crate::reason::TicketPattern>,
    /// `KEYRING_AUDIT_WORKSPACE_ID` is set, so the Keyring activity view
    /// exists to link to.
    pub keyring_view: bool,
}

/// An item for the per-item limit: vault, kind and name in lower case.
type ItemKey = (String, &'static str, String);

/// Sends the activity emails. Shared by the app state.
pub struct ActivityWatch {
    settings: Settings,
    clock: Arc<dyn Clock>,
    notifier: Arc<Notifier>,
    azure: AzureClient,
    /// Times of watched-read emails per item, in the last hour.
    reads: Mutex<HashMap<ItemKey, VecDeque<SystemTime>>>,
}

impl std::fmt::Debug for ActivityWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivityWatch")
            .field("tracked", &self.tracked())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What kind of activity an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    Read,
    Destructive,
    Bulk,
    Role,
}

fn trigger(a: Action) -> Option<Trigger> {
    use Action as A;
    Some(match a {
        A::SecretReveal
        | A::CertificateDownloadPrivateKey
        | A::SecretCopyRead
        | A::SecretRollback => Trigger::Read,
        A::SecretDelete
        | A::SecretPurge
        | A::CertificateDelete
        | A::CertificatePurge
        | A::KeyDelete
        | A::KeyPurge => Trigger::Destructive,
        A::SecretBulkUpdate | A::CertificateBulkUpdate | A::KeyBulkUpdate => Trigger::Bulk,
        A::RoleActivate | A::RoleDeactivate => Trigger::Role,
        _ => return None,
    })
}

fn kind_of(a: Action) -> Option<ItemKind> {
    match a.item_kind()? {
        "secret" => Some(ItemKind::Secret),
        "certificate" => Some(ItemKind::Certificate),
        "key" => Some(ItemKind::Key),
        _ => None,
    }
}

/// The action in fixed words, after the person's name.
fn words(a: Action) -> &'static str {
    use Action as A;
    match a {
        A::SecretReveal => "revealed a secret's value",
        A::CertificateDownloadPrivateKey => "downloaded a certificate's private key",
        A::SecretCopyRead => "read a secret's value to copy it to another vault",
        A::SecretRollback => "rolled a secret back to an earlier version",
        A::SecretDelete => "deleted a secret",
        A::CertificateDelete => "deleted a certificate",
        A::KeyDelete => "deleted a key",
        A::SecretPurge => "purged (permanently deleted) a secret",
        A::CertificatePurge => "purged (permanently deleted) a certificate",
        A::KeyPurge => "purged (permanently deleted) a key",
        A::SecretBulkUpdate => "changed several secrets at once",
        A::CertificateBulkUpdate => "changed several certificates at once",
        A::KeyBulkUpdate => "changed several keys at once",
        A::RoleActivate => "turned on a PIM role",
        A::RoleDeactivate => "turned off a PIM role",
        _ => "acted",
    }
}

fn type_of(t: Trigger) -> NotifyType {
    match t {
        Trigger::Read => NotifyType::WatchedReads,
        Trigger::Destructive | Trigger::Bulk => NotifyType::Destructive,
        Trigger::Role => NotifyType::RoleUse,
    }
}

/// Recipients without the actor, by mailbox, unless the actor is the only
/// one. Order kept, repeats (by mailbox) kept once.
pub fn without_actor(to: Vec<Address>, actor: Option<&str>) -> Vec<Address> {
    let mut seen: Vec<Address> = Vec::new();
    for a in to {
        if !seen.iter().any(|s| s.mailbox_key() == a.mailbox_key()) {
            seen.push(a);
        }
    }
    let Some(me) = actor.and_then(|u| Address::parse(u).ok()) else {
        return seen;
    };
    let key = me.mailbox_key();
    let others: Vec<Address> = seen
        .iter()
        .filter(|a| a.mailbox_key() != key)
        .cloned()
        .collect();
    if others.is_empty() { seen } else { others }
}

/// ISO 8601 `PT8H30M` as minutes, if it is that shape.
fn duration_minutes(d: &str) -> Option<u32> {
    let rest = d.strip_prefix("PT")?;
    let (h, rest) = match rest.split_once('H') {
        Some((h, r)) => (h.parse::<u32>().ok()?, r),
        None => (0, rest),
    };
    let m = match rest {
        "" => 0,
        r => r.strip_suffix('M')?.parse::<u32>().ok()?,
    };
    let total = h.checked_mul(60)?.checked_add(m)?;
    (1..=crate::azure::pim::HARD_MAX_MINUTES)
        .contains(&total)
        .then_some(total)
}

impl ActivityWatch {
    pub fn new(
        settings: Settings,
        clock: Arc<dyn Clock>,
        notifier: Arc<Notifier>,
        azure: AzureClient,
    ) -> Arc<Self> {
        Arc::new(Self {
            settings,
            clock,
            notifier,
            azure,
            reads: Mutex::new(HashMap::new()),
        })
    }

    /// Items tracked for the per-item limit now.
    pub fn tracked(&self) -> usize {
        lock(&self.reads).len()
    }

    /// Take one watched-read email for this item. False when it has had
    /// its share this hour, or when the map is full of live entries.
    fn allow_read(&self, item: &ItemRef) -> bool {
        let now = self.clock.now();
        let hour = Duration::from_secs(3600);
        let fresh = |t: &SystemTime| now.duration_since(*t).unwrap_or_default() < hour;
        let key = (
            item.vault().to_owned(),
            item.kind().as_str(),
            item.name().to_ascii_lowercase(),
        );
        let mut m = lock(&self.reads);
        if !m.contains_key(&key) && m.len() >= MAX_TRACKED_ITEMS {
            m.retain(|_, v| v.back().is_some_and(fresh));
            if m.len() >= MAX_TRACKED_ITEMS {
                return false;
            }
        }
        let e = m.entry(key).or_default();
        while e.front().is_some_and(|t| !fresh(t)) {
            e.pop_front();
        }
        if e.len() >= READS_PER_ITEM_PER_HOUR {
            return false;
        }
        e.push_back(now);
        true
    }

    fn when(&self) -> String {
        let secs = self
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        crate::dates::format_datetime(secs)
    }

    /// A link to the vault's audit view, filtered to the item when there
    /// is one. Every part is a checked name or fixed text.
    fn audit_link(&self, vault: &str, item: Option<&str>) -> String {
        let view = if self.settings.keyring_view {
            "audit/keyring"
        } else {
            "audit"
        };
        let mut url = format!("{}/v/{vault}/{view}?range=24h", self.settings.base_url);
        if let Some(i) = item {
            url.push_str("&item=");
            url.push_str(i);
        }
        url
    }

    /// The notice's common part: who, what, when and where from.
    fn base(&self, ev: &AuditEvent, heading: &str) -> ActivityNotice {
        let who = ev
            .actor_upn
            .as_deref()
            .filter(|u| Address::parse(u).is_ok())
            .unwrap_or("an unnamed person");
        let mut n = ActivityNotice::new(heading)
            .fact("Who", who.to_owned())
            .fact("What", words(ev.action).to_owned())
            .fact("When", self.when());
        if let Some(ip) = ev
            .client_ip
            .as_deref()
            .and_then(|i| i.parse::<IpAddr>().ok())
        {
            n = n.fact("From address", ip.to_string());
        }
        n
    }

    /// The reason and ticket, for item actions: whether a reason was
    /// given, never what it says; the ticket only if it matches the pattern.
    fn reason_facts(&self, ev: &AuditEvent, mut n: ActivityNotice) -> ActivityNotice {
        if ev.reason.is_some() {
            n = n.fact(
                "Reason",
                "Given. It is on the event in Keyring's audit log.".to_owned(),
            );
        }
        if let (Some(p), Some(t)) = (&self.settings.ticket, ev.ticket.as_deref())
            && p.matches(t)
            && t.len() <= 64
            && t.bytes().all(|b| b.is_ascii_graphic())
        {
            n = n.fact("Ticket", t.to_owned());
        }
        n
    }

    fn watched_read(&self, ev: &AuditEvent, w: &Watched) {
        let (Some(kind), Some(vault), Some(name)) = (
            kind_of(ev.action),
            ev.vault.as_deref(),
            ev.item_name.as_deref(),
        ) else {
            return;
        };
        let Some(item) = ItemRef::new(vault, kind, name) else {
            return;
        };
        let mut to = w.notify.clone();
        if self.settings.owner_on_read
            && let Some(o) = &w.owner
        {
            to.insert(0, o.clone());
        }
        let to = without_actor(to, ev.actor_upn.as_deref());
        if to.is_empty() {
            return;
        }
        if !self.allow_read(&item) {
            tracing::info!(
                kind = NotifyType::WatchedReads.as_str(),
                "notify: watched item read too often this hour; not emailed again"
            );
            return;
        }
        let n = self
            .base(ev, "A watched item was read")
            .fact("Vault", item.vault().to_owned())
            .fact("Item", format!("{} {}", item.kind().as_str(), item.name()))
            .line("Someone read an item that lists you in its notify tag (or as its owner). If you expected it, there is nothing to do.");
        let n = self.reason_facts(ev, n).link(
            self.audit_link(item.vault(), Some(item.name())),
            "Open the item's activity in Keyring",
        );
        let _ = self.notifier.enqueue(Notification {
            kind: NotifyType::WatchedReads,
            to,
            item: Some(item),
            data: n,
        });
    }

    fn destructive(&self, ev: &AuditEvent) -> Option<(ActivityNotice, Option<ItemRef>)> {
        let kind = kind_of(ev.action)?;
        let item = ItemRef::new(ev.vault.as_deref()?, kind, ev.item_name.as_deref()?)?;
        let n = self
            .base(ev, "An item was deleted")
            .fact("Vault", item.vault().to_owned())
            .fact("Item", format!("{} {}", item.kind().as_str(), item.name()))
            .line("You get this as an owner of the vault (its keyring-owners tag), or as a Keyring admin when the vault names no owner.");
        let n = self.reason_facts(ev, n).link(
            self.audit_link(item.vault(), Some(item.name())),
            "Open the item's activity in Keyring",
        );
        Some((n, Some(item)))
    }

    fn bulk(&self, ev: &AuditEvent, changed: &[String]) -> Option<ActivityNotice> {
        let vault = ev.vault.as_deref()?;
        let kind = kind_of(ev.action)?;
        // Only names that pass Key Vault's rules are listed or counted.
        let names: Vec<&str> = changed
            .iter()
            .map(String::as_str)
            .filter(|n| ItemRef::new(vault, kind, n).is_some())
            .collect();
        if names.is_empty() {
            return None;
        }
        let mut n = self
            .base(ev, "Several items were changed at once")
            .fact("Vault", vault.to_ascii_lowercase())
            .fact("Changed", names.len().to_string())
            .line("You get this as an owner of the vault (its keyring-owners tag), or as a Keyring admin when the vault names no owner.");
        n.items = names
            .iter()
            .take(MAX_LISTED)
            .map(|s| (*s).to_owned())
            .collect();
        n.more = names.len().saturating_sub(MAX_LISTED);
        Some(self.reason_facts(ev, n).link(
            self.audit_link(&vault.to_ascii_lowercase(), None),
            "Open the vault's activity in Keyring",
        ))
    }

    fn role(&self, ev: &AuditEvent) -> Option<ActivityNotice> {
        let vault = ev.vault.as_deref()?;
        if !crate::azure::vaults::is_valid_vault_name(vault) {
            return None;
        }
        let role = ev.role.as_deref()?;
        let name = crate::routes::pim::offered_name(role)?;
        let scope = ev
            .role_scope
            .as_deref()
            .filter(|s| crate::azure::pim::is_safe_scope(s))?;
        let heading = if ev.action == Action::RoleActivate {
            "A PIM role was turned on"
        } else {
            "A PIM role was turned off"
        };
        let mut n = self
            .base(ev, heading)
            .fact("Vault", vault.to_ascii_lowercase())
            .fact("Role", name.to_owned())
            .fact("Scope", scope.to_owned());
        if let Some(m) = ev.role_duration.as_deref().and_then(duration_minutes) {
            n = n.fact("For", crate::routes::pim::minutes_words(m));
        }
        if ev.action == Action::RoleActivate && ev.reason.is_some() {
            n = n.fact(
                "Justification",
                "Given. It is on the event in Keyring's audit log.".to_owned(),
            );
        }
        Some(
            n.line("You get this as an owner of the vault (its keyring-owners tag), or as a Keyring admin when the vault names no owner.")
                .link(self.audit_link(&vault.to_ascii_lowercase(), None), "Open the vault's activity in Keyring"),
        )
    }

    /// Send to the vault's owners, read as the person off the request path,
    /// or to the admins.
    fn to_owners(
        self: &Arc<Self>,
        kind: NotifyType,
        ev: &AuditEvent,
        session: Option<&Arc<Session>>,
        n: ActivityNotice,
        item: Option<ItemRef>,
    ) {
        let actor = ev.actor_upn.clone();
        let send = {
            let me = self.clone();
            move |owners: Vec<Address>| {
                let to = if owners.is_empty() {
                    me.notifier.admins().to_vec()
                } else {
                    owners
                };
                let to = without_actor(to, actor.as_deref());
                if to.is_empty() {
                    return;
                }
                let _ = me.notifier.enqueue(Notification {
                    kind,
                    to,
                    item,
                    data: n,
                });
            }
        };
        let (Some(session), Some(vault), Ok(rt)) = (
            session.cloned(),
            ev.vault.clone(),
            tokio::runtime::Handle::try_current(),
        ) else {
            send(Vec::new());
            return;
        };
        let azure = self.azure.clone();
        let url = self.settings.management_url.clone();
        rt.spawn(async move {
            let read = tokio::time::timeout(
                OWNERS_TIMEOUT,
                crate::azure::vaults::vault_tags(&azure, &session, &url, &vault),
            )
            .await;
            drop(session);
            let owners = match read {
                Ok(Ok(Some(tags))) => crate::owner::vault_owners(&tags),
                _ => Vec::new(),
            };
            send(owners);
        });
    }
}

/// Watches each request's event. Returns at once: the only network call,
/// the vault's owners, runs in its own task.
pub struct Observer(pub Arc<ActivityWatch>);

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Observe for Observer {
    fn observe(&self, ev: &AuditEvent) {
        self.observe_request(ev, &Facts::default());
    }

    fn observe_request(&self, ev: &AuditEvent, facts: &Facts<'_>) {
        let me = &self.0;
        let Some(t) = trigger(ev.action) else { return };
        if !me.notifier.is_on(type_of(t)) {
            return;
        }
        let ok = ev.outcome == Outcome::Success;
        match t {
            Trigger::Read if ok => {
                if let Some(w) = facts.watched {
                    me.watched_read(ev, w);
                }
            }
            Trigger::Destructive if ok => {
                if let Some((n, item)) = me.destructive(ev) {
                    me.to_owners(NotifyType::Destructive, ev, facts.session, n, item);
                }
            }
            // The request's own event only: per-item events have no
            // names noted. Some changed and some not still sends, for
            // the ones that changed.
            Trigger::Bulk
                if ok
                    || (ev.outcome == Outcome::Failed
                        && ev.reason_code.as_deref() == Some("partly_changed")) =>
            {
                if let Some(n) = me.bulk(ev, facts.changed) {
                    me.to_owners(NotifyType::Destructive, ev, facts.session, n, None);
                }
            }
            // A request waiting for approval ends `success` with PIM's
            // status as its code: the role isn't on, so nothing is sent.
            Trigger::Role if ok && ev.reason_code.is_none() => {
                if let Some(n) = me.role(ev) {
                    me.to_owners(NotifyType::RoleUse, ev, facts.session, n, None);
                }
            }
            _ => {}
        }
    }
}

/// An activity notice: a heading, fixed lines, labelled facts, item names
/// and a link Keyring built. Outside text (a sign-in name, an IP, a
/// ticket) only goes in a fact's value, alone, cleaned.
#[derive(Debug, Clone, Default)]
pub struct ActivityNotice {
    heading: String,
    lines: Vec<String>,
    facts: Vec<(&'static str, String)>,
    items: Vec<String>,
    more: usize,
    link: Option<(String, &'static str)>,
}

impl ActivityNotice {
    fn new(heading: &str) -> Self {
        Self {
            heading: clean_line(heading, super::MAX_LINE_CHARS),
            ..Self::default()
        }
    }

    fn line(mut self, text: &str) -> Self {
        self.lines.push(clean_line(text, super::MAX_LINE_CHARS * 2));
        self
    }

    fn fact(mut self, label: &'static str, value: String) -> Self {
        self.facts.push((label, clean_line(&value, 1100)));
        self
    }

    fn link(mut self, url: String, label: &'static str) -> Self {
        self.link = Some((url, label));
        self
    }
}

#[derive(Template)]
#[template(path = "notify/activity.txt")]
struct ActivityText<'a> {
    n: &'a ActivityNotice,
}

#[derive(Template)]
#[template(path = "notify/activity.html")]
struct ActivityHtml<'a> {
    n: &'a ActivityNotice,
}

impl EmailBody for ActivityNotice {
    fn render(&self, _ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        Ok(Rendered {
            text: ActivityText { n: self }.render()?,
            html: ActivityHtml { n: self }.render()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    fn keys(v: &[Address]) -> Vec<String> {
        v.iter().map(|x| x.as_str().to_owned()).collect()
    }

    #[test]
    fn the_actor_is_left_out_unless_alone() {
        // The actor is the owner, and there is another notify address.
        let to = vec![a("alex@example.com"), a("sam@example.com")];
        assert_eq!(
            keys(&without_actor(to, Some("Alex+x@Example.com"))),
            ["sam@example.com"]
        );
        // The actor is the only address.
        let to = vec![a("alex@example.com")];
        assert_eq!(
            keys(&without_actor(to, Some("alex@example.com"))),
            ["alex@example.com"]
        );
        // The actor's sign-in name isn't a plain address: nobody dropped.
        let to = vec![a("alex@example.com"), a("sam@example.com")];
        assert_eq!(without_actor(to, Some("alex <alex@example.com>")).len(), 2);
        assert_eq!(without_actor(vec![a("a@x.com")], None).len(), 1);
    }

    #[test]
    fn watched_keeps_only_parsed_addresses() {
        let mut t = BTreeMap::new();
        assert!(watched(&t).is_none());
        t.insert("env".into(), "prod".into());
        assert!(watched(&t).is_none());
        t.insert(
            "notify".into(),
            "a@example.com, junk, A@Example.com, Bob <b@x.com>".into(),
        );
        let w = watched(&t).unwrap();
        assert_eq!(keys(&w.notify), ["a@example.com"]);
        assert!(w.owner.is_none());
        t.insert("owner".into(), "own@example.com".into());
        assert!(watched(&t).unwrap().owner.is_some());
        assert!(!format!("{:?}", watched(&t)).contains("example"));
    }

    #[test]
    fn durations_are_parsed() {
        assert_eq!(duration_minutes("PT8H"), Some(480));
        assert_eq!(duration_minutes("PT30M"), Some(30));
        assert_eq!(duration_minutes("PT1H5M"), Some(65));
        for bad in ["", "PT", "P1D", "PT0M", "8H", "PT1H https://x", "PT99999H"] {
            assert_eq!(duration_minutes(bad), None, "{bad}");
        }
    }

    #[test]
    fn triggers_and_types() {
        assert_eq!(trigger(Action::SecretCopyRead), Some(Trigger::Read));
        assert_eq!(trigger(Action::SecretCopyWrite), None);
        assert_eq!(trigger(Action::KeyPurge), Some(Trigger::Destructive));
        assert_eq!(trigger(Action::NotifySent), None);
        assert_eq!(trigger(Action::NotifyFailed), None);
        assert_eq!(type_of(Trigger::Bulk), NotifyType::Destructive);
    }

    #[test]
    fn the_notice_escapes_and_lists_names() {
        let mut n = ActivityNotice::new("Heading")
            .fact("Who", "a<b>@example.com\r\nBcc: x".into())
            .link(
                "https://k.example.com/v/kv/audit?range=24h&item=x".into(),
                "Open",
            );
        n.items = vec!["one".into(), "two".into()];
        n.more = 3;
        let r = n
            .render(&EmailContext {
                kind: NotifyType::Destructive,
                item: None,
                link: None,
            })
            .unwrap();
        assert!(
            r.html.contains("a&#60;b&#62;@example.com Bcc: x"),
            "{}",
            r.html
        );
        assert!(!r.text.contains("\nBcc"));
        assert!(r.text.contains("- one\n- two"), "{}", r.text);
        assert!(r.text.contains("and 3 more"), "{}", r.text);
        assert!(r.html.contains("and 3 more"));
    }
}
