//! Access request emails (#258): a person refused by Key Vault asks the
//! vault's owners for a role, and Keyring emails them. Keyring keeps no
//! request and grants nothing.
//!
//! - **Recipients.** The vault's `keyring-owners` ARM tag, read as the
//!   person from Resource Graph, or `KEYRING_NOTIFY_ADMINS` when it has
//!   none or can't be read; and a copy to the requester's own sign-in name
//!   from the verified session, when it is one plain address. Never an
//!   address from the form. The sender's allow-list and per-mailbox rate
//!   limit apply to every one.
//! - **What is in it.** Fixed text; the role's name from Keyring's own
//!   list; the vault and item, which passed Key Vault's naming rules; the
//!   requester's sign-in name; and the reason and ticket only when a mail
//!   client couldn't turn them into a link ([`is_quotable`],
//!   [`ticket_is_quotable`]). Otherwise the email says one was given and
//!   is in Keyring's audit log. Each outside value sits alone in its own
//!   labelled field, cleaned of control and invisible characters, capped,
//!   and escaped in the HTML part.
//! - **Links.** Built only from `APP_BASE_URL` and the portal's fixed
//!   host, with the vault's ARM resource ID from Resource Graph after it
//!   passed [`crate::notify::expiry::checked_topic`].
//! - **Limit.** One request per person, vault and role an hour
//!   ([`RequestLimit`]), on top of the sender's per-mailbox limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use askama::Template;

use super::{EmailBody, EmailContext, Rendered, clean_line};

/// The Azure portal, the one host an access request email links to
/// besides Keyring itself.
pub const PORTAL: &str = "https://portal.azure.com";

/// The portal's list of Key Vaults, for when the vault's resource ID
/// couldn't be read.
pub const PORTAL_VAULTS: &str = "https://portal.azure.com/#browse/Microsoft.KeyVault%2Fvaults";

/// One request per person, vault and role in this window.
pub const WINDOW: Duration = Duration::from_secs(3600);

/// Most person, vault and role entries tracked at once.
pub const MAX_ENTRIES: usize = 10_000;

/// Longest ticket shown when no `KEYRING_REASON_TICKET_PATTERN` is set.
pub const MAX_PLAIN_TICKET: usize = 32;

/// Characters a mail client may read as a full stop in a host name.
const DOTS: [char; 8] = [
    '.', '\u{3002}', '\u{FF0E}', '\u{FF61}', '\u{2024}', '\u{FE52}', '\u{0701}', '\u{0702}',
];
/// Characters that may stand in for a colon.
const COLONS: [char; 5] = [':', '\u{FF1A}', '\u{FE55}', '\u{A789}', '\u{2236}'];
/// Characters that may stand in for an at sign.
const ATS: [char; 3] = ['@', '\u{FF20}', '\u{FE6B}'];
/// Characters that may stand in for a slash or backslash.
const SLASHES: [char; 6] = ['/', '\\', '\u{FF0F}', '\u{FF3C}', '\u{2215}', '\u{29F8}'];

/// True when `text` holds nothing a mail client could turn into a link,
/// so it can be quoted in an email from Keyring's own domain. Strict and
/// conservative, so ordinary text such as "e.g." or "v1.2" is withheld
/// too:
///
/// - no `@` (an address), or a look-alike;
/// - no full stop, or a look-alike, with a letter or digit straight after
///   it (`word.tld`, `www.x`, `10.0.0.1`, `example。com`);
/// - no colon, or a look-alike, with anything but white space after it
///   (`https:`, `mailto:x`, `host:8080`);
/// - no two slashes or backslashes in a row (`//host`, `\\server`).
pub fn is_quotable(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let next = chars.get(i + 1).copied();
        if ATS.contains(c) {
            return false;
        }
        if DOTS.contains(c) && next.is_some_and(char::is_alphanumeric) {
            return false;
        }
        if COLONS.contains(c) && next.is_some_and(|n| !n.is_whitespace()) {
            return false;
        }
        if SLASHES.contains(c) && next.is_some_and(|n| SLASHES.contains(&n)) {
            return false;
        }
    }
    true
}

/// True when a ticket can be quoted. With `KEYRING_REASON_TICKET_PATTERN`
/// set, the ticket has already matched it; otherwise it must be 1 to
/// [`MAX_PLAIN_TICKET`] of letters, digits, `-`, `_`, `#` and `/`. Either
/// way it must also pass [`is_quotable`], so a loose pattern such as `.*`
/// can't put a link in an email.
pub fn ticket_is_quotable(ticket: &str, pattern_set: bool) -> bool {
    let shape = pattern_set
        || ((1..=MAX_PLAIN_TICKET).contains(&ticket.len())
            && ticket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'#' | b'/')));
    shape && is_quotable(ticket)
}

/// The access request email.
#[derive(Debug, Clone)]
pub struct AccessRequestNotice {
    heading: String,
    lines: Vec<String>,
    facts: Vec<(&'static str, String)>,
    links: Vec<(String, &'static str)>,
}

/// What an access request email is about. Every field must already be
/// checked: see the module notes.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The requester's sign-in name, from the verified session.
    pub requester: &'a str,
    /// The role's name, from Keyring's own list.
    pub role: &'static str,
    /// A checked vault name.
    pub vault: &'a str,
    /// `secret db-password`, or `None` for the whole vault.
    pub item: Option<(&'static str, &'a str)>,
    /// The cleaned reason.
    pub reason: &'a str,
    /// The checked ticket, if one was given.
    pub ticket: Option<&'a str>,
    /// `KEYRING_REASON_TICKET_PATTERN` is set.
    pub ticket_pattern: bool,
    /// When, already formatted.
    pub when: &'a str,
    /// The vault's ARM resource ID, already checked, if it was read.
    pub vault_id: Option<&'a str>,
    /// `APP_BASE_URL`.
    pub base_url: &'a str,
}

/// Said in place of a reason or ticket that isn't quoted.
const WITHHELD: &str = "Given, but not shown here because it holds something a mail client could turn into a link. Read it in Keyring's audit log, on the access.request event from this person at the time above.";

impl AccessRequestNotice {
    pub fn new(r: &Request<'_>) -> Self {
        let mut facts: Vec<(&'static str, String)> = vec![
            ("Asked by", clean_line(r.requester, 254)),
            ("Role", r.role.to_owned()),
            ("Vault", r.vault.to_owned()),
            (
                "Scope",
                match r.item {
                    Some((kind, name)) => format!("{kind} {name}"),
                    None => "The whole vault".to_owned(),
                },
            ),
        ];
        let reason = clean_line(r.reason, crate::reason::MAX_REASON_CHARS);
        facts.push((
            "Reason",
            if is_quotable(&reason) {
                reason
            } else {
                WITHHELD.to_owned()
            },
        ));
        if let Some(t) = r.ticket {
            let t = clean_line(t, crate::reason::MAX_TICKET_CHARS);
            facts.push((
                "Ticket",
                if ticket_is_quotable(&t, r.ticket_pattern) {
                    t
                } else {
                    WITHHELD.to_owned()
                },
            ));
        }
        facts.push(("When", clean_line(r.when, 64)));
        let portal = match r.vault_id {
            Some(id) => format!("{PORTAL}/#resource{id}/users"),
            None => PORTAL_VAULTS.to_owned(),
        };
        Self {
            heading: "Someone asked for access to a vault".to_owned(),
            lines: vec![
                "A person was refused by Key Vault in Keyring and asked for the role below. You get this because the vault's keyring-owners tag names you, or, when it names nobody, because you are one of Keyring's admins.".to_owned(),
                "Keyring can't grant access itself and keeps no request. If the request is right, grant the role in the vault's Access control (IAM) page in the Azure portal, at the scope below or the smallest scope that will do. If it isn't, there is nothing to do.".to_owned(),
            ],
            facts,
            links: vec![
                (portal, "Open the vault's Access control in the Azure portal"),
                (
                    format!("{}/v/{}/access", r.base_url, r.vault),
                    "See who has access in Keyring",
                ),
            ],
        }
    }
}

#[derive(Template)]
#[template(path = "notify/access_request.txt")]
struct NoticeText<'a> {
    n: &'a AccessRequestNotice,
}

#[derive(Template)]
#[template(path = "notify/access_request.html")]
struct NoticeHtml<'a> {
    n: &'a AccessRequestNotice,
}

impl EmailBody for AccessRequestNotice {
    fn render(&self, _ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        Ok(Rendered {
            text: NoticeText { n: self }.render()?,
            html: NoticeHtml { n: self }.render()?,
        })
    }
}

/// One request per person, vault and role in [`WINDOW`], in memory. A
/// restart resets it. The map is bounded: when full, entries whose window
/// has passed are cleared first, and if it is still full a new key is
/// refused, so filling the map can't reset anyone's limit.
#[derive(Debug)]
pub struct RequestLimit {
    window: Duration,
    max: usize,
    seen: Mutex<HashMap<String, Instant>>,
}

impl Default for RequestLimit {
    fn default() -> Self {
        Self::new(WINDOW, MAX_ENTRIES)
    }
}

impl RequestLimit {
    pub fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max: max.max(1),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Take the one request for `key`. False when it was taken within the
    /// window, or the map is full.
    pub fn take(&self, key: &str) -> bool {
        self.take_at(key, Instant::now())
    }

    pub fn take_at(&self, key: &str, now: Instant) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = self.window;
        if let Some(t) = seen.get(key) {
            if now.duration_since(*t) < window {
                return false;
            }
        } else if seen.len() >= self.max {
            seen.retain(|_, t| now.duration_since(*t) < window);
            if seen.len() >= self.max {
                return false;
            }
        }
        seen.insert(key.to_owned(), now);
        true
    }

    /// Give a request back, when nothing was sent for it.
    pub fn release(&self, key: &str) {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

    /// Keys tracked now.
    pub fn tracked(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_reasons_are_quoted() {
        for ok in [
            "Fixing INC-42 in production",
            "Need to read the db password for the release",
            "Deploy at 10: approved by the team lead",
            "Rotating after the incident. Then closing it",
            "日本語のテスト",
            "ticket #42 / step 3",
        ] {
            assert!(is_quotable(ok), "{ok}");
        }
    }

    #[test]
    fn anything_a_mail_client_could_link_is_withheld() {
        for bad in [
            "see https://evil.example/login",
            "see http://x",
            "hxxps://evil",
            "go to www.evil.example now",
            "WWW.EVIL.EXAMPLE",
            "evil.com",
            "visit evil.co please",
            "mail alex@example.com",
            "alex＠example",
            "ping 10.0.0.1",
            "v1.2 upgrade",
            "e.g.",
            "evil。com",
            "evil．com",
            "evil｡com",
            "evil․com",
            "evil﹒com",
            "mailto:alex",
            "tel:+61400000000",
            "javascript:alert(1)",
            "host:8080",
            "https：//x",
            "//evil/x",
            "\\\\server\\share",
            "file:///etc/passwd",
            "xn--80ak6aa92e.com",
        ] {
            assert!(!is_quotable(bad), "{bad} should be withheld");
        }
    }

    #[test]
    fn tickets_are_quoted_only_when_plain() {
        for ok in ["INC0012345", "CHG-42", "JIRA_7", "#42", "ops/42"] {
            assert!(ticket_is_quotable(ok, false), "{ok}");
        }
        for bad in [
            "evil.com",
            "a@b",
            "http://x",
            "x:y",
            "a b",
            "a.b",
            "",
            &"a".repeat(33),
            "ü",
        ] {
            assert!(!ticket_is_quotable(bad, false), "{bad}");
        }
        // A pattern can let a ticket's shape through, never a link.
        assert!(ticket_is_quotable("ABC.", true));
        assert!(!ticket_is_quotable("evil.com", true));
        assert!(!ticket_is_quotable("//x", true));
    }

    fn request<'a>(reason: &'a str, ticket: Option<&'a str>) -> Request<'a> {
        Request {
            requester: "alex@example.com",
            role: "Key Vault Secrets User",
            vault: "kv-test",
            item: Some(("secret", "db-password")),
            reason,
            ticket,
            ticket_pattern: false,
            when: "18 Nov 2026, 09:30 UTC",
            vault_id: Some(
                "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test",
            ),
            base_url: "https://keyring.example.com",
        }
    }

    fn body(r: &Request<'_>) -> Rendered {
        AccessRequestNotice::new(r)
            .render(&EmailContext {
                kind: super::super::NotifyType::AccessRequests,
                item: None,
                link: None,
            })
            .unwrap()
    }

    #[test]
    fn the_email_holds_the_fields_and_links() {
        let b = body(&request("Fixing INC-42 <b>now</b>", Some("CHG-42")));
        for part in [&b.text, &b.html] {
            assert!(part.contains("alex@example.com"));
            assert!(part.contains("Key Vault Secrets User"));
            assert!(part.contains("secret db-password"));
            assert!(part.contains("CHG-42"));
            assert!(part.contains("grant access itself"));
            assert!(part.contains("https://portal.azure.com/#resource/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test/users"));
            assert!(part.contains("https://keyring.example.com/v/kv-test/access"));
        }
        assert!(b.text.contains("Fixing INC-42 <b>now</b>"));
        assert!(b.html.contains("Fixing INC-42 &#60;b&#62;now&#60;/b&#62;"));
        assert!(!b.html.contains("<b>now"));
    }

    #[test]
    fn a_linkable_reason_or_ticket_is_not_quoted() {
        let b = body(&request(
            "log in at https://evil.example\u{202e} now",
            Some("evil.example"),
        ));
        for part in [&b.text, &b.html] {
            assert!(!part.contains("evil"), "{part}");
            assert!(part.contains("Given, but not shown here"));
        }
        let mut r = request("Fixing it", None);
        r.vault_id = None;
        let b = body(&r);
        assert!(b.text.contains(PORTAL_VAULTS));
        assert!(!b.text.contains("Ticket:"));
    }

    #[test]
    fn one_request_per_key_an_hour() {
        let l = RequestLimit::new(Duration::from_secs(3600), 100);
        let t0 = Instant::now();
        assert!(l.take_at("a", t0));
        assert!(!l.take_at("a", t0 + Duration::from_secs(3599)));
        assert!(l.take_at("b", t0));
        assert!(l.take_at("a", t0 + Duration::from_secs(3600)));
        l.release("b");
        assert!(l.take_at("b", t0));
    }

    #[test]
    fn a_full_map_refuses_new_keys_and_never_forgets_a_live_one() {
        let l = RequestLimit::new(Duration::from_secs(3600), 2);
        let t0 = Instant::now();
        assert!(l.take_at("a", t0));
        assert!(l.take_at("b", t0));
        // Full of live entries: a new key is refused, and the old ones
        // are still limited.
        assert!(!l.take_at("c", t0));
        assert!(!l.take_at("a", t0));
        assert_eq!(l.tracked(), 2);
        // Once their windows pass, room is made.
        let later = t0 + Duration::from_secs(3600);
        assert!(l.take_at("c", later));
        assert_eq!(l.tracked(), 1);
    }
}
