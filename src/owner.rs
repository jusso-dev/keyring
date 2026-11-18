//! Who a secret, certificate, key or vault belongs to, kept in tags (#255).
//!
//! - `owner` (item tag): one address, a person's UPN or a team address.
//! - `notify` (item tag): up to [`MAX_NOTIFY`] more addresses, separated
//!   by commas.
//! - `keyring-owners` (vault ARM tag): the vault's owners, read from
//!   Resource Graph. Keyring never writes it.
//!
//! Like the `description` note ([`crate::description`]) they are ordinary
//! tags: Keyring stores nothing, the portal and the CLI see them, and they
//! count towards an item's 15 tags. The rules for writing them live here,
//! so every form, import and bulk change applies the same ones.
//!
//! **Addresses are personal data.** Anyone who can read an item's tags can
//! read them, so the pages show them, escaped, and a parsed address as a
//! `mailto:` link ([`Shown::mailto`]). They are never logged, never put in
//! an audit event or a flash message, and never put in a URL Keyring
//! builds: a query string, a redirect, or a filter, suggestion or pager
//! link. A person can type `owner=<address>` into a tag filter, which puts
//! it in their own address bar; Keyring never logs query strings. Error
//! messages name an entry by its place ("the second address"), never by
//! quoting it.
//!
//! **Values Keyring didn't write.** A tag set in the portal or the CLI may
//! not be a plain address. It is shown as it is, with a note, and a save
//! that leaves its field untouched keeps it exactly: it is not checked,
//! rewritten or refused, so it never blocks a change to another field.
//! "Untouched" means the posted text is the stored value, or the stored
//! value as a browser's text input gives it back (line breaks dropped, a
//! NUL read as U+FFFD), so a value an input can't hold isn't rewritten
//! either.

use std::collections::BTreeMap;

use crate::notify::Address;
use crate::routes::forms::FieldErrors;

/// The tag that holds an item's owner.
pub const OWNER_TAG: &str = "owner";
/// The tag that holds an item's extra addresses.
pub const NOTIFY_TAG: &str = "notify";
/// The vault ARM tag that holds the vault's owners.
pub const VAULT_TAG: &str = "keyring-owners";

/// Most addresses in `notify`. Five full-length addresses fit a tag value
/// of 256 characters only when they are short, so the joined length is
/// checked too.
pub const MAX_NOTIFY: usize = 5;

/// Longest tag value Key Vault takes, in characters. Addresses are ASCII,
/// so characters, bytes and UTF-16 units agree.
pub const MAX_VALUE: usize = 256;

/// Most owner addresses suggested in the owner field.
pub const MAX_SUGGESTED: usize = 50;

/// Most vault owners shown or returned. An ARM tag value holds 256
/// characters, so this is never reached by real addresses.
pub const MAX_VAULT_OWNERS: usize = 20;

/// True for a tag name Keyring keeps for owners. Exact, as Key Vault keeps
/// tag names: a tag called `Owner` is an ordinary tag.
pub fn is_reserved(name: &str) -> bool {
    matches!(name.trim(), OWNER_TAG | NOTIFY_TAG)
}

/// The settings the checks follow.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rules<'a> {
    /// `KEYRING_NOTIFY_ALLOWED_DOMAINS`, when set: every address must be
    /// in one of these (lower case).
    pub allowed: Option<&'a [String]>,
    /// `KEYRING_REQUIRE_OWNER`: an item created or edited through a form
    /// that shows the owner field must end up with an owner.
    pub require: bool,
}

impl<'a> Rules<'a> {
    pub const OFF: Rules<'static> = Rules {
        allowed: None,
        require: false,
    };

    pub fn of(config: &'a crate::config::Config) -> Self {
        Self {
            allowed: config
                .notify
                .as_ref()
                .and_then(|n| n.allowed_domains.as_deref()),
            require: config.require_owner,
        }
    }

    fn domain_ok(&self, a: &Address) -> bool {
        self.allowed
            .is_none_or(|list| list.iter().any(|d| d == a.domain()))
    }

    fn domains(&self) -> String {
        self.allowed.map(|l| l.join(", ")).unwrap_or_default()
    }
}

/// "first", "second" and so on, for naming an entry without quoting it.
pub fn ordinal(n: usize) -> String {
    const WORDS: [&str; 10] = [
        "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
        "tenth",
    ];
    WORDS
        .get(n.wrapping_sub(1))
        .map_or_else(|| format!("number {n}"), |w| (*w).to_owned())
}

/// The owner from a form. `Ok(None)` when it is empty, which removes the
/// tag. The message never quotes what was typed.
pub fn clean_owner(raw: &str, rules: Rules<'_>) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let a = Address::parse(raw).map_err(|_| {
        "The owner isn't one plain email address, such as alex@example.com. Use one address with no name, spaces or commas. To name more people, use Notify.".to_owned()
    })?;
    if !rules.domain_ok(&a) {
        return Err(format!(
            "The owner's address isn't in a domain Keyring is set to email ({}).",
            rules.domains()
        ));
    }
    Ok(Some(a.as_str().to_owned()))
}

/// The notify list from a form: addresses separated by commas, empty
/// entries skipped, repeats (ignoring case) kept once, at most
/// [`MAX_NOTIFY`], stored as `a@x.com, b@x.com`. `Ok(None)` when nothing
/// is left, which removes the tag.
pub fn clean_notify(raw: &str, rules: Rules<'_>) -> Result<Option<String>, String> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() > MAX_NOTIFY {
        return Err(format!(
            "Notify can hold up to {MAX_NOTIFY} addresses. This has {}. For more people, use a team address.",
            entries.len()
        ));
    }
    let mut out: Vec<Address> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let a = Address::parse(e).map_err(|_| {
            format!(
                "The {} address in Notify isn't a plain email address, such as alex@example.com. Separate addresses with commas.",
                ordinal(i + 1)
            )
        })?;
        if !rules.domain_ok(&a) {
            return Err(format!(
                "The {} address in Notify isn't in a domain Keyring is set to email ({}).",
                ordinal(i + 1),
                rules.domains()
            ));
        }
        if !out
            .iter()
            .any(|o| o.as_str().eq_ignore_ascii_case(a.as_str()))
        {
            out.push(a);
        }
    }
    let joined = out
        .iter()
        .map(Address::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if joined.len() > MAX_VALUE {
        return Err(format!(
            "The addresses in Notify come to {} characters, and a tag holds {MAX_VALUE}. Use fewer addresses, or a team address.",
            joined.len()
        ));
    }
    Ok(Some(joined))
}

/// The stored value as a browser's text input sends it back: line breaks
/// dropped (the HTML value sanitisation for text inputs), and a NUL read
/// as U+FFFD (the HTML parser's rule for attribute values).
fn as_an_input_gives_it(stored: &str) -> String {
    stored
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .map(|c| if c == '\0' { '\u{FFFD}' } else { c })
        .collect()
}

/// Did the person leave this field as the form showed it?
pub fn untouched(posted: &str, stored: Option<&str>) -> bool {
    match stored {
        None => posted.trim().is_empty(),
        Some(s) => posted == s || posted == as_an_input_gives_it(s),
    }
}

/// Put `value` into `tags` under `name`, or take it out when `None`. Every
/// other tag is kept. Refused when adding it would take the item past
/// [`crate::description::MAX_TAGS`].
pub fn merge(
    tags: &BTreeMap<String, String>,
    name: &str,
    value: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = tags.clone();
    match value {
        None => {
            out.remove(name);
        }
        Some(v) => {
            let max = crate::description::MAX_TAGS;
            if !out.contains_key(name) && out.len() >= max {
                return Err(format!(
                    "This already has {} tags, the most Key Vault allows, and the {name} tag would be one more. Remove a tag first, or leave this empty.",
                    out.len()
                ));
            }
            out.insert(name.to_owned(), v.to_owned());
        }
    }
    Ok(out)
}

/// Said when an item would be saved with no owner while
/// `KEYRING_REQUIRE_OWNER` is on.
pub const OWNER_NEEDED: &str = "Enter an owner. Keyring is set to need one on every item it creates or edits: the address of the person or team who looks after it.";

/// Said when the bulk change is asked to remove owners while
/// `KEYRING_REQUIRE_OWNER` is on.
pub const REMOVE_REFUSED: &str = "Keyring is set to need an owner on every item, so it can't remove owners. Set a new owner instead.";

/// One owner field as posted: `None` when the form didn't have it (a page
/// opened before an upgrade), which keeps the tag as it is.
#[derive(Clone, Copy, Default)]
pub struct Posted<'a> {
    pub owner: Option<&'a str>,
    pub notify: Option<&'a str>,
}

/// The tags from a form with the posted owner and notify merged in.
/// `current` is the item's tags as they are (empty for a new item). An
/// untouched field keeps its tag exactly; a changed one is checked, and a
/// problem goes on its field (`owner` or `notify`). With
/// [`Rules::require`], an item left with no owner gets an error on
/// `owner` and the request's audit event is marked `owner_required`.
pub fn with_owners(
    tags: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    posted: Posted<'_>,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) -> BTreeMap<String, String> {
    let mut out = tags.clone();
    for (name, field, raw) in [
        (OWNER_TAG, "owner", posted.owner),
        (NOTIFY_TAG, "notify", posted.notify),
    ] {
        let stored = current.get(name).map(String::as_str);
        let wanted: Result<Option<String>, String> = match raw {
            None => Ok(stored.map(str::to_owned)),
            Some(r) if untouched(r, stored) => Ok(stored.map(str::to_owned)),
            Some(r) if name == OWNER_TAG => clean_owner(r, rules),
            Some(r) => clean_notify(r, rules),
        };
        let merged = wanted.and_then(|v| merge(&out, name, v.as_deref()));
        match merged {
            Ok(t) => out = t,
            Err(m) => {
                errors.push(field, m);
                // Keep what is there, so the rest of the form is checked
                // against the item as it is.
                if let Some(s) = stored {
                    out.insert(name.to_owned(), s.to_owned());
                }
            }
        }
    }
    if rules.require && owner_of(&out).is_none() && errors.error_for("owner").is_none() {
        crate::audit::refuse(crate::audit::Refusal::OwnerRequired);
        errors.push("owner", OWNER_NEEDED);
    }
    out
}

/// The item's owner tag, if it has one that isn't blank.
pub fn owner_of(tags: &BTreeMap<String, String>) -> Option<&str> {
    tags.get(OWNER_TAG)
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
}

/// The item's notify tag, if it has one that isn't blank.
pub fn notify_of(tags: &BTreeMap<String, String>) -> Option<&str> {
    tags.get(NOTIFY_TAG)
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
}

/// True for a tag name Keyring shows in its own field rather than as a
/// tag: the description, the owner and notify, and the reveal limit
/// (`keyring-reveal` in any case, [`crate::reveal_limit::is_tag`]).
pub fn has_own_field(name: &str) -> bool {
    name == crate::description::TAG
        || name == OWNER_TAG
        || name == NOTIFY_TAG
        || crate::reveal_limit::is_tag(name)
}

/// The tags without the ones that have their own field, for tag rows and
/// tag lists.
pub fn without_fields(tags: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    tags.iter()
        .filter(|(k, _)| !has_own_field(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Is the signed-in person named in this item's `owner` or `notify`?
/// `upn` is from the verified session. Compared without regard to case,
/// each notify entry on its own.
pub fn names(owner: &str, notify: &str, upn: &str) -> bool {
    let upn = upn.trim();
    if upn.is_empty() {
        return false;
    }
    owner.trim().eq_ignore_ascii_case(upn)
        || notify
            .split(',')
            .any(|e| e.trim().eq_ignore_ascii_case(upn))
}

/// An item's owner and notify tags as stored, for lists and detail pages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfItem {
    pub owner: String,
    pub notify: String,
}

impl OfItem {
    pub fn of(tags: &BTreeMap<String, String>) -> Self {
        Self {
            owner: owner_of(tags).unwrap_or_default().to_owned(),
            notify: notify_of(tags).unwrap_or_default().to_owned(),
        }
    }

    pub fn owner_shown(&self) -> Display {
        Display::of_owner(&self.owner)
    }

    pub fn notify_shown(&self) -> Display {
        Display::of(&self.notify)
    }

    /// The "Owned by me" filter: `upn` from the verified session. No UPN
    /// matches nothing.
    pub fn names(&self, upn: Option<&str>) -> bool {
        upn.is_some_and(|u| names(&self.owner, &self.notify, u))
    }
}

/// True when the "Owned by me" box was ticked: any non-empty `mine`.
pub fn mine_on(raw: &str) -> bool {
    !raw.trim().is_empty()
}

/// One entry of an owner value as shown: a parsed address (a `mailto:`
/// link is fine) or plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    Address(String),
    Text(String),
}

impl Shown {
    pub fn text(&self) -> &str {
        match self {
            Self::Address(s) | Self::Text(s) => s,
        }
    }
    /// The `mailto:` link for a parsed address, percent-encoded as RFC
    /// 6068 asks: letters, digits, `-`, `.`, `_`, `~` and the `@` stay as
    /// they are, every other byte (`%`, `+`, `'` and so on) is `%XX`, so a
    /// mail client opens the same mailbox. The link text stays the address.
    pub fn mailto(&self) -> Option<String> {
        match self {
            Self::Address(s) => Some(format!("mailto:{}", mailto_encode(s))),
            Self::Text(_) => None,
        }
    }
}

fn mailto_encode(address: &str) -> String {
    let mut out = String::with_capacity(address.len());
    for b in address.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A tag value split into what is shown: each entry separated by commas,
/// as an address when it parses on its own and as plain text when it
/// doesn't. `odd` is true when anything didn't parse. Empty entries are
/// skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Display {
    pub entries: Vec<Shown>,
    pub odd: bool,
}

impl Display {
    pub fn of(value: &str) -> Self {
        let mut d = Self::default();
        for e in value.split(',') {
            let e = e.trim();
            if e.is_empty() {
                continue;
            }
            match Address::parse(e) {
                Ok(_) => d.entries.push(Shown::Address(e.to_owned())),
                Err(_) => {
                    d.odd = true;
                    d.entries.push(Shown::Text(e.to_owned()));
                }
            }
        }
        d
    }

    /// An owner holds one address, so a comma makes it odd too.
    pub fn of_owner(value: &str) -> Self {
        let mut d = Self::of(value);
        if d.entries.len() > 1 {
            d = Self {
                entries: vec![Shown::Text(value.trim().to_owned())],
                odd: true,
            };
        }
        d
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The item's notify recipients: the owner, then each notify address,
/// parsed strictly, repeats (by [`Address::mailbox_key`]) kept once, and
/// anything that doesn't parse dropped. The sender checks
/// `KEYRING_NOTIFY_ALLOWED_DOMAINS` again when anything is sent. For the
/// access request (#258) and activity (#259) emails.
pub fn item_recipients(tags: &BTreeMap<String, String>) -> Vec<Address> {
    let owner = owner_of(tags).into_iter().filter(|o| !o.contains(','));
    let notify = notify_of(tags).into_iter().flat_map(|n| n.split(','));
    unique(owner.chain(notify))
}

/// The vault's `keyring-owners` ARM tag, if it has one. ARM tag names
/// ignore case, so `Keyring-Owners` is the same tag.
pub fn vault_tag(tags: &BTreeMap<String, String>) -> Option<&str> {
    tags.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(VAULT_TAG))
        .map(|(_, v)| v.as_str())
}

/// The vault's owners from its `keyring-owners` ARM tag: addresses
/// separated by commas or semicolons, parsed strictly, repeats kept once,
/// anything else dropped, at most [`MAX_VAULT_OWNERS`]. For the access
/// request emails (#258). The sender's allow-list applies again on send.
pub fn vault_owners(tags: &BTreeMap<String, String>) -> Vec<Address> {
    let mut v = unique(
        vault_tag(tags)
            .into_iter()
            .flat_map(|t| t.split([',', ';'])),
    );
    v.truncate(MAX_VAULT_OWNERS);
    v
}

/// The vault tag for a page: each entry, parsed or plain text.
pub fn vault_display(tags: &BTreeMap<String, String>) -> Display {
    let mut d = vault_tag(tags)
        .map(|t| Display::of(&t.replace(';', ",")))
        .unwrap_or_default();
    d.entries.truncate(MAX_VAULT_OWNERS);
    d
}

/// The owner and notify fields on a form page.
#[derive(Debug, Clone, Default)]
pub struct Fields {
    pub owner: String,
    pub notify: String,
    /// The stored value isn't what Keyring would write, and is shown as it
    /// is with a note.
    pub owner_odd: bool,
    pub notify_odd: bool,
}

impl Fields {
    /// Filled from an item's tags (or none, for a new item).
    pub fn of(tags: &BTreeMap<String, String>) -> Self {
        let owner = tags.get(OWNER_TAG).cloned().unwrap_or_default();
        let notify = tags.get(NOTIFY_TAG).cloned().unwrap_or_default();
        Self {
            owner_odd: odd_owner(&owner),
            notify_odd: odd_notify(&notify),
            owner,
            notify,
        }
    }

    /// Filled back from a post that had a problem. A field left as it was
    /// keeps its note.
    pub fn posted(p: Posted<'_>, current: &BTreeMap<String, String>) -> Self {
        let stored = Self::of(current);
        let owner = p.owner.map_or(stored.owner.clone(), str::to_owned);
        let notify = p.notify.map_or(stored.notify.clone(), str::to_owned);
        Self {
            owner_odd: stored.owner_odd
                && untouched(&owner, current.get(OWNER_TAG).map(String::as_str)),
            notify_odd: stored.notify_odd
                && untouched(&notify, current.get(NOTIFY_TAG).map(String::as_str)),
            owner,
            notify,
        }
    }
}

/// A stored owner Keyring wouldn't have written: not one plain address.
fn odd_owner(v: &str) -> bool {
    !v.is_empty() && clean_owner(v, Rules::OFF).ok().flatten().as_deref() != Some(v)
}

/// A stored notify list Keyring wouldn't have written.
fn odd_notify(v: &str) -> bool {
    !v.is_empty() && clean_notify(v, Rules::OFF).ok().flatten().as_deref() != Some(v)
}

fn unique<'a>(entries: impl Iterator<Item = &'a str>) -> Vec<Address> {
    let mut out: Vec<Address> = Vec::new();
    for e in entries {
        if let Ok(a) = Address::parse(e.trim())
            && !out.iter().any(|o| o.mailbox_key() == a.mailbox_key())
        {
            out.push(a);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    fn domains() -> Vec<String> {
        vec!["example.com".into(), "contoso.com".into()]
    }

    fn post<'a>(owner: &'a str, notify: &'a str) -> Posted<'a> {
        Posted {
            owner: Some(owner),
            notify: Some(notify),
        }
    }

    fn merged(
        current: &BTreeMap<String, String>,
        p: Posted<'_>,
        rules: Rules<'_>,
    ) -> (BTreeMap<String, String>, FieldErrors) {
        let mut e = FieldErrors::new();
        let base = without_fields(current);
        let t = with_owners(&base, current, p, rules, &mut e);
        (t, e)
    }

    #[test]
    fn owner_is_one_plain_address() {
        assert_eq!(
            clean_owner(" Alex@Example.COM ", Rules::OFF)
                .unwrap()
                .as_deref(),
            Some("Alex@example.com")
        );
        assert_eq!(clean_owner("  ", Rules::OFF), Ok(None));
        let m = clean_owner("Pat <pat@corp.test>", Rules::OFF).unwrap_err();
        assert!(!m.contains("pat"), "never quoted: {m}");
        for bad in [
            "Alex <alex@example.com>",
            "alex@example.com, sam@example.com",
            "alex@example.com\nBcc: x@evil.com",
            "alex",
            "alex@localhost",
            "alex@exa\u{202E}mple.com",
            "ålex@example.com",
        ] {
            let m = clean_owner(bad, Rules::OFF).unwrap_err();
            assert!(m.contains("one plain email address"), "{bad:?}");
            assert!(!m.contains(bad) || bad == "alex", "never quoted: {m}");
        }
    }

    #[test]
    fn notify_names_the_entry_by_place() {
        assert_eq!(
            clean_notify("a@example.com, ,B@Example.com,a@EXAMPLE.com,", Rules::OFF)
                .unwrap()
                .as_deref(),
            Some("a@example.com, B@example.com")
        );
        let m = clean_notify("a@example.com, not an address", Rules::OFF).unwrap_err();
        assert!(m.contains("The second address"), "{m}");
        assert!(!m.contains("not an address"));
        let six = (0..6)
            .map(|i| format!("p{i}@example.com"))
            .collect::<Vec<_>>();
        let m = clean_notify(&six.join(","), Rules::OFF).unwrap_err();
        assert!(m.contains("up to 5") && m.contains("This has 6"), "{m}");
        assert_eq!(clean_notify(" , ", Rules::OFF), Ok(None));
    }

    #[test]
    fn notify_must_fit_one_tag_value() {
        let long = |c: char| format!("{}@example.com", c.to_string().repeat(60));
        let five: Vec<String> = "abcde".chars().map(long).collect();
        let m = clean_notify(&five.join(","), Rules::OFF).unwrap_err();
        assert!(m.contains("a tag holds 256"), "{m}");
        let three: Vec<String> = "abc".chars().map(long).collect();
        assert!(clean_notify(&three.join(","), Rules::OFF).is_ok());
    }

    #[test]
    fn allowed_domains_apply_to_each_address() {
        let d = domains();
        let rules = Rules {
            allowed: Some(&d),
            require: false,
        };
        assert!(clean_owner("alex@contoso.com", rules).is_ok());
        let m = clean_owner("alex@evil.com", rules).unwrap_err();
        assert!(m.contains("example.com, contoso.com"));
        assert!(!m.contains("evil"));
        let m = clean_notify("a@example.com, b@sub.example.com", rules).unwrap_err();
        assert!(m.contains("The second address"), "{m}");
    }

    #[test]
    fn merge_keeps_other_tags_and_counts_to_fifteen() {
        let cur = tags(&[("env", "prod"), ("description", "note")]);
        let (t, e) = merged(
            &cur,
            post("alex@example.com", "sam@example.com"),
            Rules::OFF,
        );
        assert!(e.is_empty());
        assert_eq!(t["env"], "prod");
        assert_eq!(t[OWNER_TAG], "alex@example.com");
        assert_eq!(t[NOTIFY_TAG], "sam@example.com");
        // The note isn't this function's: the caller merges it after.
        assert!(!t.contains_key("description"));
        // Empty removes, and keeps the rest.
        let with = tags(&[("env", "prod"), ("owner", "alex@example.com")]);
        let (t, _) = merged(&with, post("", ""), Rules::OFF);
        assert_eq!(t, tags(&[("env", "prod")]));
        // A sixteenth tag is refused on its field.
        let full: BTreeMap<String, String> =
            (0..15).map(|i| (format!("k{i}"), "v".into())).collect();
        let (_, e) = merged(&full, post("alex@example.com", ""), Rules::OFF);
        assert!(e.error_for("owner").unwrap().contains("15 tags"));
    }

    #[test]
    fn untouched_odd_values_are_kept_exactly_and_never_block() {
        let d = domains();
        let strict = Rules {
            allowed: Some(&d),
            require: true,
        };
        for odd in [
            "Payments Team",
            "alex@other.org",
            "Alex@EXAMPLE.com",
            " padded@example.com ",
            "two\nlines@example.com",
            "nul\0@example.com",
            "a@example.com; b@example.com",
        ] {
            let cur = tags(&[("owner", odd), ("notify", odd), ("env", "prod")]);
            // As the form shows it and a browser sends it back.
            let back = as_an_input_gives_it(odd);
            let (t, e) = merged(&cur, post(&back, &back), strict);
            assert!(
                e.is_empty(),
                "{odd:?}: {:?}",
                e.iter().map(|e| &e.message).collect::<Vec<_>>()
            );
            assert_eq!(t[OWNER_TAG], odd, "kept byte for byte");
            assert_eq!(t[NOTIFY_TAG], odd);
            // Not posted at all (an old page): kept too.
            let (t, e) = merged(&cur, Posted::default(), strict);
            assert!(e.is_empty());
            assert_eq!(
                t,
                cur.clone()
                    .into_iter()
                    .filter(|(k, _)| k != "description")
                    .collect()
            );
        }
        // Changed, it is checked.
        let cur = tags(&[("owner", "Payments Team")]);
        let (_, e) = merged(&cur, post("Payments Team!", ""), Rules::OFF);
        assert!(e.error_for("owner").is_some());
    }

    #[test]
    fn require_owner_refuses_an_ownerless_save() {
        let on = Rules {
            allowed: None,
            require: true,
        };
        let (_, e) = merged(&BTreeMap::new(), post("", "sam@example.com"), on);
        assert_eq!(e.error_for("owner"), Some(OWNER_NEEDED));
        let (_, e) = merged(&BTreeMap::new(), post("  ", ""), on);
        assert_eq!(e.error_for("owner"), Some(OWNER_NEEDED));
        // Clearing an existing owner is refused too.
        let cur = tags(&[("owner", "alex@example.com")]);
        let (_, e) = merged(&cur, post("", ""), on);
        assert_eq!(e.error_for("owner"), Some(OWNER_NEEDED));
        // A bad owner gets its own message, not a second one.
        let (_, e) = merged(&BTreeMap::new(), post("nope", ""), on);
        assert_eq!(e.len(), 1);
        assert!(e.error_for("owner").unwrap().contains("plain email"));
        let (t, e) = merged(&BTreeMap::new(), post("alex@example.com", ""), on);
        assert!(e.is_empty());
        assert_eq!(owner_of(&t), Some("alex@example.com"));
    }

    #[test]
    fn mailto_links_percent_encode_the_address() {
        let shown = |a: &str| {
            let d = Display::of(a);
            assert!(!d.odd, "{a} parses");
            d.entries[0].clone()
        };
        let p = shown("ops%41@example.com");
        assert_eq!(p.mailto().unwrap(), "mailto:ops%2541@example.com");
        assert_eq!(p.text(), "ops%41@example.com");
        let q = shown("o'neil+keys@example.com");
        assert_eq!(q.mailto().unwrap(), "mailto:o%27neil%2Bkeys@example.com");
        assert_eq!(q.text(), "o'neil+keys@example.com");
        assert_eq!(
            shown("Alex.B_c-d@sub.example.com").mailto().unwrap(),
            "mailto:Alex.B_c-d@sub.example.com"
        );
        assert_eq!(Shown::Text("a b".into()).mailto(), None);
    }

    #[test]
    fn only_exact_names_are_reserved() {
        assert!(is_reserved("owner") && is_reserved(" notify "));
        assert!(!is_reserved("Owner") && !is_reserved("owners") && !is_reserved("NOTIFY"));
        assert!(has_own_field("description") && has_own_field("owner"));
        assert_eq!(
            without_fields(&tags(&[
                ("owner", "a"),
                ("notify", "b"),
                ("description", "c"),
                ("x", "")
            ])),
            tags(&[("x", "")])
        );
    }

    #[test]
    fn owned_by_me_matches_owner_or_any_notify_entry_ignoring_case() {
        assert!(names("Alex@Example.com", "", "alex@example.com"));
        assert!(names(
            "",
            "sam@example.com, ALEX@example.com",
            "alex@example.com"
        ));
        assert!(!names("alex@example.com.au", "", "alex@example.com"));
        assert!(!names(
            "team@example.com",
            "xalex@example.com",
            "alex@example.com"
        ));
        assert!(!names("", "", ""));
        assert!(!names("", "", "  "));
    }

    #[test]
    fn display_marks_what_does_not_parse() {
        let d = Display::of_owner("alex@example.com");
        assert!(!d.odd);
        assert_eq!(
            d.entries[0].mailto().as_deref(),
            Some("mailto:alex@example.com")
        );
        let d = Display::of_owner("Payments <p@example.com>");
        assert!(d.odd);
        assert!(d.entries[0].mailto().is_none());
        assert!(Display::of_owner("a@example.com, b@example.com").odd);
        let d = Display::of("a@example.com, javascript:alert(1)");
        assert!(d.odd);
        assert_eq!(d.entries.len(), 2);
        assert!(d.entries[1].mailto().is_none());
    }

    #[test]
    fn item_recipients_parse_dedupe_and_drop() {
        let t = tags(&[
            ("owner", "Alex@example.com"),
            (
                "notify",
                "alex+x@EXAMPLE.com, sam@example.com, nope, ,team@contoso.com",
            ),
        ]);
        let r: Vec<String> = item_recipients(&t)
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect();
        assert_eq!(
            r,
            ["Alex@example.com", "sam@example.com", "team@contoso.com"]
        );
        assert!(item_recipients(&tags(&[("owner", "a@x.com, b@x.com")])).is_empty());
        assert!(item_recipients(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn vault_owners_from_the_arm_tag() {
        let t = tags(&[(
            "Keyring-Owners",
            "a@example.com; b@example.com,bad , A@example.com",
        )]);
        let r: Vec<String> = vault_owners(&t)
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect();
        assert_eq!(r, ["a@example.com", "b@example.com"]);
        let d = vault_display(&t);
        assert!(d.odd);
        assert_eq!(d.entries.len(), 4);
        assert!(vault_owners(&BTreeMap::new()).is_empty());
        assert!(vault_display(&tags(&[("keyring-owners", " ")])).is_empty());
    }

    #[test]
    fn fields_note_values_keyring_would_not_write() {
        let f = Fields::of(&tags(&[
            ("owner", "alex@example.com"),
            ("notify", "a@example.com, b@example.com"),
        ]));
        assert!(!f.owner_odd && !f.notify_odd);
        let cur = tags(&[
            ("owner", "Alex@EXAMPLE.com"),
            ("notify", "a@example.com,b@example.com"),
        ]);
        let f = Fields::of(&cur);
        assert!(f.owner_odd && f.notify_odd);
        // Left alone on a refused post, the note stays; changed, it goes.
        let f = Fields::posted(post("Alex@EXAMPLE.com", "x"), &cur);
        assert!(f.owner_odd && !f.notify_odd);
        assert_eq!(f.notify, "x");
    }

    #[test]
    fn untouched_compares_as_a_browser_sends_it() {
        assert!(untouched("a\u{FFFD}b", Some("a\0b")));
        assert!(untouched("ab", Some("a\r\nb")));
        assert!(!untouched("a b", Some("a\nb")));
        assert!(untouched("", None));
        assert!(!untouched("x", None));
        assert!(!untouched("", Some("x")));
    }
}
