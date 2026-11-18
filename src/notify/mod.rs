//! Email notifications, sent through Azure Communication Services (ACS) as
//! Keyring's configured managed identity.
//!
//! This module is the sender only. Each kind of notice (expiry, access
//! requests, watched reads, deletes and bulk changes, role use, health)
//! builds a [`Notification`] and hands it to
//! [`sender::Notifier::enqueue`], which returns at once and never fails the
//! request that raised it.
//!
//! - **Who sends.** Every call to ACS carries a token for
//!   [`sender::ACS_RESOURCE`] from Keyring's one managed identity. No
//!   connection string, access key, SMTP password or second identity.
//! - **Who gets it.** Only `to` recipients, each a strictly parsed
//!   [`Address`], each checked against `KEYRING_NOTIFY_ALLOWED_DOMAINS` when
//!   it is set, and each held to a rate limit per recipient per type.
//! - **What is in it.** A fixed subject (`[Keyring]`, the type, and the item
//!   when there is one) and a body from an Askama template pair, plain text
//!   and HTML. Never a secret value, token, private key, Azure error message
//!   or reason text. Free text placed in a body has control and invisible
//!   characters taken out, and the HTML part is escaped.
//! - **Personal data.** Recipient addresses appear nowhere unless
//!   `KEYRING_NOTIFY_AUDIT_RECIPIENTS=true`, which puts them on audit events
//!   (and so in the audit log line).

pub mod expiry;
pub mod health;
pub mod rate;
pub mod sender;
pub mod share;

use std::fmt;

use askama::Template;

/// Subject prefix, so mail rules can route Keyring's notices.
pub const SUBJECT_PREFIX: &str = "[Keyring]";

/// Most recipients in one email. ACS takes 50.
pub const MAX_RECIPIENTS: usize = 50;

/// Most addresses `KEYRING_NOTIFY_ADMINS` takes.
pub const MAX_ADMINS: usize = 20;

/// Largest rendered body, text and HTML together, in bytes.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Longest line of free text kept in a body, in characters.
pub const MAX_LINE_CHARS: usize = 300;

/// The kinds of notification. `KEYRING_NOTIFY_TYPES` turns each on by its
/// name. None is on by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NotifyType {
    /// Items near or past their expiry date, pushed by Event Grid.
    Expiry,
    /// Requests for access to an item or vault.
    AccessRequests,
    /// Reads of watched items.
    WatchedReads,
    /// Deletes, purges and bulk changes.
    Destructive,
    /// PIM roles turned on or off through Keyring.
    RoleUse,
    /// Keyring's own health, sent to `KEYRING_NOTIFY_ADMINS`.
    Health,
    /// A secret shared through Keyring (#286): to the person it was shared
    /// with, and a receipt to the person who shared it.
    Shares,
}

impl NotifyType {
    /// Every type, in the order the docs list them.
    pub const ALL: [NotifyType; 7] = [
        Self::Expiry,
        Self::AccessRequests,
        Self::WatchedReads,
        Self::Destructive,
        Self::RoleUse,
        Self::Health,
        Self::Shares,
    ];

    /// The name `KEYRING_NOTIFY_TYPES` uses, also written on audit events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expiry => "expiry",
            Self::AccessRequests => "access-requests",
            Self::WatchedReads => "watched-reads",
            Self::Destructive => "destructive",
            Self::RoleUse => "role-use",
            Self::Health => "health",
            Self::Shares => "shares",
        }
    }

    /// The words after the prefix in the subject.
    pub fn label(self) -> &'static str {
        match self {
            Self::Expiry => "Expiry",
            Self::AccessRequests => "Access request",
            Self::WatchedReads => "Watched item read",
            Self::Destructive => "Delete or bulk change",
            Self::RoleUse => "Role use",
            Self::Health => "Health",
            Self::Shares => "Secret shared",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }
}

impl fmt::Display for NotifyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse `KEYRING_NOTIFY_TYPES`: names separated by commas. Duplicates are
/// kept once. An unknown name is an error.
pub fn parse_types(raw: &str) -> Result<Vec<NotifyType>, String> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let name = part.trim();
        if name.is_empty() {
            continue;
        }
        let t = NotifyType::parse(name).ok_or_else(|| {
            format!(
                "unknown type {:?}. Use any of {}, separated by commas",
                clean_line(name, 40),
                NotifyType::ALL.map(NotifyType::as_str).join(", ")
            )
        })?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// One email address: `local@domain`, nothing else. No display name,
/// comment, quoting, whitespace, comma or line break, so it can't carry a
/// second address or a header. The domain is lower-cased.
///
/// `Debug` doesn't print it: addresses are personal data and stay out of
/// logs.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(String);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Address([personal data])")
    }
}

impl Address {
    /// Parse one address strictly. The local part is 1 to 64 of letters,
    /// digits and `. _ % + - '`, with no dot first, last or twice in a row.
    /// The domain is a host name of two or more labels.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        const RULE: &str = "expected one plain address, such as name@example.com, with no display name, spaces or commas";
        if raw.is_empty() || raw.len() > 254 || !raw.is_ascii() {
            return Err(RULE);
        }
        let (local, domain) = raw.split_once('@').ok_or(RULE)?;
        let local_ok = (1..=64).contains(&local.len())
            && !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._%+-'".contains(&b));
        if !local_ok || !is_domain(domain) {
            return Err(RULE);
        }
        Ok(Self(format!("{local}@{}", domain.to_ascii_lowercase())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The domain, lower case.
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }

    /// The mailbox this address reaches, for counting and for telling
    /// duplicates: the local part lower-cased with any `+tag` taken off,
    /// then the domain. `Alex@x.com`, `alex@x.com` and `alex+1@x.com` are
    /// one mailbox, so they share one rate limit and one place in an
    /// email. Mail is still sent to the address as given.
    pub fn mailbox_key(&self) -> String {
        let (local, domain) = self.0.rsplit_once('@').unwrap_or((&self.0, ""));
        let local = local.split_once('+').map_or(local, |(l, _)| l);
        format!("{}@{domain}", local.to_ascii_lowercase())
    }
}

/// A host name: 2 or more labels of letters, digits and hyphens, each 1 to
/// 63 long, not starting or ending with a hyphen, and a last label that
/// isn't all digits (so an IP address isn't taken for one).
pub fn is_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    (3..=253).contains(&d.len())
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && !labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Parse a list of addresses separated by commas, each strictly. Empty
/// entries are refused, duplicates kept once.
pub fn parse_addresses(raw: &str, max: usize) -> Result<Vec<Address>, String> {
    let mut out: Vec<Address> = Vec::new();
    for (i, part) in raw.split(',').enumerate() {
        let a = Address::parse(part.trim())
            .map_err(|rule| format!("entry {} isn't valid: {rule}", i + 1))?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.len() > max {
        return Err(format!("at most {max} addresses"));
    }
    Ok(out)
}

/// Parse a list of domains separated by commas, lower-cased.
pub fn parse_domains(raw: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for (i, part) in raw.split(',').enumerate() {
        let d = part.trim().to_ascii_lowercase();
        if !is_domain(&d) {
            return Err(format!(
                "entry {} isn't a domain such as example.com",
                i + 1
            ));
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    Ok(out)
}

/// Free text for a body: each run of whitespace and control or invisible
/// characters becomes one space, ends trimmed, cut to `max` characters.
pub fn clean_line(raw: &str, max: usize) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in raw.chars() {
        if c.is_whitespace() || crate::reason::is_unsafe(c) {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    out.chars().take(max).collect()
}

/// Which kind of Key Vault item a notice is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Secret,
    Certificate,
    Key,
}

impl ItemKind {
    /// As written in audit events' `item_kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Certificate => "certificate",
            Self::Key => "key",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Secret => "secrets",
            Self::Certificate => "certificates",
            Self::Key => "keys",
        }
    }
}

/// The item a notice is about: a vault and an item name that pass Key
/// Vault's own naming rules, so they are safe in a subject, a body and a
/// link without further escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    vault: String,
    kind: ItemKind,
    name: String,
}

impl ItemRef {
    /// `None` unless both names pass Key Vault's rules.
    pub fn new(vault: &str, kind: ItemKind, name: &str) -> Option<Self> {
        (crate::azure::vaults::is_valid_vault_name(vault)
            && crate::routes::vault_ctx::is_valid_object_name(name))
        .then(|| Self {
            vault: vault.to_ascii_lowercase(),
            kind,
            name: name.to_owned(),
        })
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    pub fn kind(&self) -> ItemKind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The item's page in Keyring.
    pub fn link(&self, base_url: &str) -> String {
        format!(
            "{base_url}/v/{}/{}/{}",
            self.vault,
            self.kind.path(),
            self.name
        )
    }
}

/// The subject: the fixed prefix, the type's label and, when there is one,
/// the item. Nothing else.
pub fn subject(kind: NotifyType, item: Option<&ItemRef>) -> String {
    match item {
        None => format!("{SUBJECT_PREFIX} {}", kind.label()),
        Some(i) => format!(
            "{SUBJECT_PREFIX} {}: {} {} in {}",
            kind.label(),
            i.kind.as_str(),
            i.name,
            i.vault
        ),
    }
}

/// What a template is given besides its own data.
#[derive(Debug, Clone, Copy)]
pub struct EmailContext<'a> {
    pub kind: NotifyType,
    pub item: Option<&'a ItemRef>,
    /// The item's page in Keyring, when there is an item.
    pub link: Option<&'a str>,
}

/// A rendered body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    pub html: String,
}

/// Template data for one kind of notice. Implement it with an Askama
/// template pair, plain text (`.txt`) and HTML (`.html`), as [`Notice`]
/// does. Never put a secret value, token, private key, Azure error message
/// or reason text in the data.
pub trait EmailBody {
    fn render(&self, ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error>;
}

/// A notification ready to queue: its type, who gets it, the item it is
/// about (if any) and its template data.
#[derive(Debug, Clone)]
pub struct Notification<B> {
    pub kind: NotifyType,
    pub to: Vec<Address>,
    pub item: Option<ItemRef>,
    pub data: B,
}

/// The built-in notice: a heading, a few lines of fixed text, and the
/// item with a link. Copy it for a new kind of notice.
#[derive(Debug, Clone, Default)]
pub struct Notice {
    heading: String,
    lines: Vec<String>,
    /// Who did it, by sign-in name, when someone did.
    actor: Option<String>,
    /// When, already formatted, such as `17 Nov 2026, 09:30 UTC`.
    when: Option<String>,
}

impl Notice {
    pub fn new(heading: &str) -> Self {
        Self {
            heading: clean_line(heading, MAX_LINE_CHARS),
            ..Self::default()
        }
    }

    /// Add a line of text. Control and invisible characters are taken out.
    pub fn line(mut self, text: &str) -> Self {
        let l = clean_line(text, MAX_LINE_CHARS);
        if !l.is_empty() {
            self.lines.push(l);
        }
        self
    }

    pub fn actor(mut self, upn: &str) -> Self {
        let a = clean_line(upn, 254);
        self.actor = (!a.is_empty()).then_some(a);
        self
    }

    pub fn when(mut self, when: &str) -> Self {
        let w = clean_line(when, 64);
        self.when = (!w.is_empty()).then_some(w);
        self
    }
}

#[derive(Template)]
#[template(path = "notify/notice.txt")]
struct NoticeText<'a> {
    n: &'a Notice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

#[derive(Template)]
#[template(path = "notify/notice.html")]
struct NoticeHtml<'a> {
    n: &'a Notice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

impl EmailBody for Notice {
    fn render(&self, ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        let kind = ctx.kind.as_str();
        Ok(Rendered {
            text: NoticeText {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
            html: NoticeHtml {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
        })
    }
}

/// What [`sender::Notifier::enqueue`] did with a notification. Never an
/// error for the request that raised it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Enqueued {
    /// Queued for this many recipients.
    Queued { recipients: usize },
    /// The queue is full: nothing was queued. A caller that can ask to be
    /// retried later (an Event Grid webhook) can answer 503.
    QueueFull,
    /// Email is off, or this type isn't in `KEYRING_NOTIFY_TYPES`.
    Off,
    /// Nobody to send to, and the rate limit isn't why: no recipient was
    /// given, or every one was outside the allow-list (or past the most an
    /// email takes). A retry wouldn't change that.
    NoRecipients,
    /// Nobody left to send to, and at least one recipient who could
    /// otherwise be sent to is over its rate limit. A caller that can ask
    /// to be retried later (an Event Grid webhook) can answer 503; the
    /// limit's window is one hour.
    RateLimited,
    /// The body couldn't be rendered, or was too large.
    Invalid,
}

impl Enqueued {
    pub fn is_queued(self) -> bool {
        matches!(self, Self::Queued { .. })
    }

    pub fn is_queue_full(self) -> bool {
        self == Self::QueueFull
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_parsed_strictly() {
        for ok in [
            "alex@example.com",
            "Alex.Smith+keyring@Example.COM",
            "o'neil@mail.example.com.au",
            "DoNotReply@0f1e2d3c-aaaa-bbbb-cccc-0123456789ab.azurecomm.net",
        ] {
            assert!(Address::parse(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            Address::parse("Alex@Example.COM").unwrap().as_str(),
            "Alex@example.com"
        );
        for bad in [
            "",
            "alex",
            "@example.com",
            "alex@",
            "alex@example",
            "alex@@example.com",
            "a@b@example.com",
            "Alex <alex@example.com>",
            "\"alex\"@example.com",
            "alex@example.com, eve@evil.com",
            "alex@example.com,eve@evil.com",
            "alex@example.com\r\nBcc: eve@evil.com",
            "alex@example.com\n",
            " alex@example.com",
            "alex smith@example.com",
            ".alex@example.com",
            "alex.@example.com",
            "al..ex@example.com",
            "alex@-example.com",
            "alex@example-.com",
            "alex@example..com",
            "alex@127.0.0.1",
            "alex@[127.0.0.1]",
            "alex@exämple.com",
            "alex(comment)@example.com",
            "alex;x@example.com",
        ] {
            assert!(Address::parse(bad).is_err(), "{bad:?} should be refused");
        }
        let long = format!("{}@example.com", "a".repeat(65));
        assert!(Address::parse(&long).is_err());
    }

    #[test]
    fn a_mailbox_is_one_whatever_its_case_or_plus_tag() {
        let key = |s: &str| Address::parse(s).unwrap().mailbox_key();
        assert_eq!(key("Alex@Example.COM"), "alex@example.com");
        assert_eq!(key("alex+billing@example.com"), "alex@example.com");
        assert_eq!(key("Alex+a+b@example.com"), "alex@example.com");
        assert_ne!(key("alexa@example.com"), key("alex@example.com"));
        // The address itself is sent as given.
        assert_eq!(
            Address::parse("Alex+x@Example.com").unwrap().as_str(),
            "Alex+x@example.com"
        );
    }

    #[test]
    fn address_debug_hides_it() {
        let a = Address::parse("alex@example.com").unwrap();
        assert!(!format!("{a:?}").contains("alex"));
    }

    #[test]
    fn lists_are_parsed() {
        let a = parse_addresses(" a@example.com , b@example.com,a@example.com", 5).unwrap();
        assert_eq!(a.len(), 2);
        assert!(parse_addresses("a@example.com,,b@example.com", 5).is_err());
        assert!(parse_addresses("a@example.com, Bob <b@example.com>", 5).is_err());
        assert!(parse_addresses("a@x.com,b@x.com,c@x.com", 2).is_err());
        assert_eq!(
            parse_domains("Example.com, contoso.com.au").unwrap(),
            ["example.com", "contoso.com.au"]
        );
        for bad in [
            "",
            "example",
            "*.example.com",
            "example.com/x",
            "a@example.com",
        ] {
            assert!(parse_domains(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn types_are_the_documented_names() {
        assert_eq!(
            NotifyType::ALL.map(NotifyType::as_str),
            [
                "expiry",
                "access-requests",
                "watched-reads",
                "destructive",
                "role-use",
                "health",
                "shares"
            ]
        );
        assert_eq!(
            parse_types("health, expiry,health").unwrap(),
            [NotifyType::Expiry, NotifyType::Health]
        );
        assert!(parse_types("").unwrap().is_empty());
        assert!(parse_types("expiry,deletes").is_err());
        assert!(parse_types("Expiry").is_err());
    }

    #[test]
    fn subjects_are_fixed_text_the_type_and_the_item() {
        let item = ItemRef::new("kv-test", ItemKind::Secret, "db-password").unwrap();
        assert_eq!(
            subject(NotifyType::Expiry, Some(&item)),
            "[Keyring] Expiry: secret db-password in kv-test"
        );
        assert_eq!(subject(NotifyType::Health, None), "[Keyring] Health");
        assert!(ItemRef::new("kv-test", ItemKind::Secret, "bad\r\nname").is_none());
        assert!(ItemRef::new("kv test", ItemKind::Key, "ok").is_none());
        assert_eq!(
            item.link("https://keyring.example.com"),
            "https://keyring.example.com/v/kv-test/secrets/db-password"
        );
    }

    #[test]
    fn the_notice_cleans_text_and_escapes_html() {
        let item = ItemRef::new("kv-test", ItemKind::Certificate, "web-tls").unwrap();
        let link = item.link("https://keyring.example.com");
        let n = Notice::new("Expires\r\nsoon")
            .line("<script>alert(1)</script>\u{202e}\u{0007} & more")
            .actor("alex@example.com\nBcc: eve@evil.com")
            .when("17 Nov 2026, 09:30 UTC");
        let r = n
            .render(&EmailContext {
                kind: NotifyType::Expiry,
                item: Some(&item),
                link: Some(&link),
            })
            .unwrap();
        assert!(!r.html.contains("<script>"), "{}", r.html);
        assert!(r.html.contains("&#60;script&#62;"), "{}", r.html);
        assert!(r.html.contains("&#38; more"));
        for body in [&r.text, &r.html] {
            assert!(!body.contains('\u{202e}'));
            assert!(!body.contains('\u{0007}'));
            assert!(!body.contains("Expires\r"));
            assert!(body.contains("Expires soon"));
            assert!(body.contains("web-tls"));
            assert!(body.contains(&link));
            // The actor's line break became a space: no new header line.
            assert!(!body.contains("\nBcc:"));
        }
        assert!(r.text.contains("<script>alert(1)</script> & more"));
    }
}
