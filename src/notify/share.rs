//! The share emails (#286): one to the person a secret was shared with,
//! and a receipt to the person who shared it, with `shares` in
//! `KEYRING_NOTIFY_TYPES`.
//!
//! Each holds fixed text, the secret and vault names (checked to Key
//! Vault's rules), the end date, and a link Keyring built to the secret's
//! page. A display name from Microsoft Graph is outside text: it is
//! cleaned and put alone in its own labelled field, never in a sentence,
//! the subject or a link. Never a value, reason text, justification or
//! Azure message.

use askama::Template;

use super::{EmailBody, EmailContext, ItemRef, MAX_LINE_CHARS, Rendered, clean_line};

/// Which of the two emails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// To the person or group member the secret was shared with.
    Recipient,
    /// The sharer's receipt.
    Sharer,
}

/// What a share email says. Names are personal data, so `Debug` leaves
/// them out.
#[derive(Clone)]
pub struct ShareNotice {
    side: Side,
    /// The other person, as Graph names them, cleaned.
    other: String,
    /// The end date, `DD-MM-YYYY`.
    until: String,
    /// Azure removes the access at the end date (PIM), or not (plain).
    removed_by_azure: bool,
}

impl std::fmt::Debug for ShareNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareNotice")
            .field("side", &self.side)
            .field("until", &self.until)
            .finish_non_exhaustive()
    }
}

impl ShareNotice {
    /// `other` is the sharer's name in the recipient's email, and the
    /// recipient's in the receipt. `until` is Unix seconds.
    pub fn new(side: Side, other: &str, until: i64, removed_by_azure: bool) -> Self {
        let (y, m, d) = crate::dates::civil_from_days(until.div_euclid(86_400));
        Self {
            side,
            other: clean_line(other, MAX_LINE_CHARS),
            until: format!("{d:02}-{m:02}-{y:04}"),
            removed_by_azure,
        }
    }

    fn heading(&self) -> &'static str {
        match self.side {
            Side::Recipient => "A secret was shared with you",
            Side::Sharer => "You shared a secret",
        }
    }

    fn other_label(&self) -> &'static str {
        match self.side {
            Side::Recipient => "Shared by",
            Side::Sharer => "Shared with",
        }
    }
}

#[derive(Template)]
#[template(path = "notify/share.txt")]
struct Text<'a> {
    n: &'a ShareNotice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

#[derive(Template)]
#[template(path = "notify/share.html")]
struct Html<'a> {
    n: &'a ShareNotice,
    item: Option<&'a ItemRef>,
    link: Option<&'a str>,
    kind: &'a str,
}

impl EmailBody for ShareNotice {
    fn render(&self, ctx: &EmailContext<'_>) -> Result<Rendered, askama::Error> {
        let kind = ctx.kind.as_str();
        Ok(Rendered {
            text: Text {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
            html: Html {
                n: self,
                item: ctx.item,
                link: ctx.link,
                kind,
            }
            .render()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{ItemKind, NotifyType};

    #[test]
    fn a_hostile_name_stays_in_its_field() {
        let item = ItemRef::new("kv-test", ItemKind::Secret, "db-password").unwrap();
        let link = item.link("https://keyring.example.com");
        let n = ShareNotice::new(
            Side::Recipient,
            "Alex <a href=\"https://evil.example\">click</a>\r\nBcc: eve@evil.example\u{202e}",
            crate::dates::parse_iso_date("2026-11-25").unwrap(),
            true,
        );
        let r = n
            .render(&EmailContext {
                kind: NotifyType::Shares,
                item: Some(&item),
                link: Some(&link),
            })
            .unwrap();
        assert!(!r.html.contains("<a href=\"https://evil"), "{}", r.html);
        assert_eq!(r.html.matches("<a ").count(), 1, "only Keyring's link");
        assert!(r.html.contains(&format!("href=\"{link}\"")));
        for body in [&r.text, &r.html] {
            assert!(!body.contains('\u{202e}'));
            assert!(!body.contains("\nBcc:"));
            assert!(body.contains("25-11-2026"));
            assert!(body.contains("db-password"));
            assert!(body.contains("kv-test"));
        }
        assert!(r.text.contains("Shared by: Alex <a href="), "{}", r.text);
        assert!(!format!("{n:?}").contains("Alex"));
    }
}
