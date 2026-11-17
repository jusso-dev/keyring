//! Reveal limits for sensitive items (#261 part 2), kept in the item's
//! `keyring-reveal` tag.
//!
//! - `copy-only`: Keyring doesn't show the value on screen. Copy still
//!   works, with the clipboard cleared after a while. The value still
//!   reaches the browser (that is how a copy works): this keeps it off the
//!   screen, not out of the browser.
//! - `none`: Keyring refuses to show or copy the value, to copy the secret
//!   to another vault, and to download a certificate's private key.
//!
//! It is a Keyring control, like step-up. Key Vault doesn't know about it:
//! the Azure CLI, the portal and the SDKs aren't limited, and anyone who
//! can change the item's tags can change it there. Through Keyring, the
//! tag has its own control, and loosening it goes through step-up and the
//! reason gate and is audited.
//!
//! **Unknown values are the strictest.** A tag Keyring didn't write
//! (`keyring-reveal=maybe`, `Copy-Only`, an empty value, or the tag name in
//! another case such as `Keyring-Reveal`) counts as `none`, is shown as it
//! is, and is kept until someone changes it. An unknown value never means
//! "no limit".
//!
//! **Which version counts.** Tags are per version. Every check takes the
//! strictest of the current version's tags and the tags of the version
//! acted on, so an old version from before the tag was set is no way
//! around it.

use std::collections::BTreeMap;

use crate::routes::forms::FieldErrors;

/// The tag that holds the limit.
pub const TAG: &str = "keyring-reveal";

/// The written values.
pub const COPY_ONLY: &str = "copy-only";
pub const NONE: &str = "none";

/// The posted value that keeps the tag exactly as it is.
pub const KEEP: &str = "keep";

/// How far Keyring will go with an item's value. Ordered from the least to
/// the most strict, so `max` is the stricter of two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Limit {
    /// No tag: Keyring shows and copies the value as usual.
    #[default]
    Open,
    /// Copy only: the value isn't shown on screen.
    CopyOnly,
    /// Not shown or copied in Keyring at all.
    NoReveal,
}

impl Limit {
    /// The tag value Keyring writes for this limit, `None` for no tag.
    pub fn value(self) -> Option<&'static str> {
        match self {
            Self::Open => None,
            Self::CopyOnly => Some(COPY_ONLY),
            Self::NoReveal => Some(NONE),
        }
    }

    pub fn copy_only(self) -> bool {
        self == Self::CopyOnly
    }

    pub fn refuses_reveal(self) -> bool {
        self == Self::NoReveal
    }

    /// A private key download is a value leaving Keyring as a file, with no
    /// clipboard to clear, so `copy-only` refuses it too.
    pub fn refuses_download(self) -> bool {
        self != Self::Open
    }
}

/// True for a tag name that holds the limit: `keyring-reveal` in any case,
/// with any spaces around it. Wider than Key Vault's exact match on
/// purpose, so a tag set elsewhere as `Keyring-Reveal` still counts and
/// can't be removed as an ordinary tag.
pub fn is_tag(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(TAG)
}

/// The limit an item's tags set. No tag is [`Limit::Open`]; a tag Keyring
/// didn't write is [`Limit::NoReveal`].
pub fn of(tags: &BTreeMap<String, String>) -> Limit {
    tags.iter()
        .filter(|(k, _)| is_tag(k))
        .map(|(k, v)| match (k.as_str(), v.as_str()) {
            (TAG, COPY_ONLY) => Limit::CopyOnly,
            (TAG, NONE) => Limit::NoReveal,
            _ => Limit::NoReveal,
        })
        .max()
        .unwrap_or(Limit::Open)
}

/// The stricter limit of several tag sets, such as the current version's
/// and an old version's.
pub fn strictest<'a>(sets: impl IntoIterator<Item = &'a BTreeMap<String, String>>) -> Limit {
    sets.into_iter().map(of).max().unwrap_or(Limit::Open)
}

/// The item's limit tag as it is, in one of a fixed set of words for the
/// audit event: `unset`, `copy-only`, `none` or `other` (a value Keyring
/// didn't write, never quoted).
pub fn word(tags: &BTreeMap<String, String>) -> &'static str {
    let found: Vec<(&String, &String)> = tags.iter().filter(|(k, _)| is_tag(k)).collect();
    match found.as_slice() {
        [] => "unset",
        [(k, v)] if k.as_str() == TAG && v.as_str() == COPY_ONLY => COPY_ONLY,
        [(k, v)] if k.as_str() == TAG && v.as_str() == NONE => NONE,
        _ => "other",
    }
}

/// `tags` with the limit set to `limit` and every other spelling of the
/// tag taken out. For a copy or a new version that must carry a limit.
pub fn with(tags: &BTreeMap<String, String>, limit: Limit) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = tags
        .iter()
        .filter(|(k, _)| !is_tag(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(v) = limit.value() {
        out.insert(TAG.to_owned(), v.to_owned());
    }
    out
}

/// `tags` carrying at least `limit`: unchanged when its own limit is as
/// strict already, which keeps a value set elsewhere exactly; otherwise
/// written as `limit`.
pub fn at_least(tags: &BTreeMap<String, String>, limit: Limit) -> BTreeMap<String, String> {
    if of(tags) >= limit {
        tags.clone()
    } else {
        with(tags, limit)
    }
}

/// `tags` with the limit tags of `from` brought over when `from` is
/// stricter, kept exactly as `from` has them (an unknown value stays as it
/// is). For a new version or a copy whose tags would otherwise lose a
/// limit: the result is never less strict than either.
pub fn carry(
    tags: &BTreeMap<String, String>,
    from: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    if of(tags) >= of(from) {
        return tags.clone();
    }
    let mut out: BTreeMap<String, String> = tags
        .iter()
        .filter(|(k, _)| !is_tag(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in from.iter().filter(|(k, _)| is_tag(k)) {
        out.insert(k.clone(), v.clone());
    }
    out
}

/// Said when a tag row or a bulk tag change names the limit.
pub const IS_A_FIELD: &str = "The keyring-reveal tag is set with the Reveal limit control on the item's Edit details, so loosening it is checked and recorded. Leave it out of Tags.";

/// The tags from a form with the posted limit merged in. `tags` has no
/// limit tag; `current` is the item's tags as they are. Not posted, or
/// [`KEEP`], keeps the current limit tags exactly. Empty removes them;
/// `copy-only` or `none` writes that. Anything else is an error on the
/// `reveal` field, and the current tags are kept.
pub fn merge_posted(
    tags: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    posted: Option<&str>,
    errors: &mut FieldErrors,
) -> BTreeMap<String, String> {
    let keep = || {
        let mut out = tags.clone();
        for (k, v) in current.iter().filter(|(k, _)| is_tag(k)) {
            out.insert(k.clone(), v.clone());
        }
        out
    };
    let wanted = match posted.map(str::trim) {
        None | Some(KEEP) => return keep(),
        Some("") => Limit::Open,
        Some(COPY_ONLY) => Limit::CopyOnly,
        Some(NONE) => Limit::NoReveal,
        Some(_) => {
            errors.push("reveal", "Choose a reveal limit from the list.");
            return keep();
        }
    };
    let out = with(tags, wanted);
    if out.len() > crate::description::MAX_TAGS {
        errors.push(
            "reveal",
            format!(
                "This would have {} tags, and Key Vault allows {}. Remove a tag first.",
                out.len(),
                crate::description::MAX_TAGS
            ),
        );
        return keep();
    }
    out
}

/// The control on a form.
#[derive(Debug, Clone, Default)]
pub struct Field {
    /// `""`, `copy-only`, `none` or [`KEEP`].
    pub selected: String,
    /// The tag as set elsewhere, `name=value`, when Keyring didn't write
    /// it. Shown as it is, with a note.
    pub odd: Option<String>,
}

impl Field {
    pub fn of(tags: &BTreeMap<String, String>) -> Self {
        let found: Vec<(&String, &String)> = tags.iter().filter(|(k, _)| is_tag(k)).collect();
        match found.as_slice() {
            [] => Self::default(),
            [(k, v)] if k.as_str() == TAG && matches!(v.as_str(), COPY_ONLY | NONE) => Self {
                selected: (*v).clone(),
                odd: None,
            },
            _ => Self {
                selected: KEEP.into(),
                odd: Some(
                    found
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            },
        }
    }

    /// Filled back from a post with a problem.
    pub fn posted(posted: Option<&str>, current: &BTreeMap<String, String>) -> Self {
        let mut f = Self::of(current);
        if let Some(p) = posted.map(str::trim)
            && matches!(p, "" | COPY_ONLY | NONE | KEEP)
            && !(p == KEEP && f.odd.is_none())
        {
            f.selected = p.to_owned();
        }
        f
    }

    pub fn is(&self, v: &str) -> bool {
        self.selected == v
    }
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

    #[test]
    fn values_and_unknowns() {
        assert_eq!(of(&tags(&[])), Limit::Open);
        assert_eq!(
            of(&tags(&[("keyring-reveal", "copy-only")])),
            Limit::CopyOnly
        );
        assert_eq!(of(&tags(&[("keyring-reveal", "none")])), Limit::NoReveal);
        // Anything Keyring didn't write is the strictest.
        for (k, v) in [
            ("keyring-reveal", "maybe"),
            ("keyring-reveal", "Copy-Only"),
            ("keyring-reveal", ""),
            ("keyring-reveal", " copy-only"),
            ("Keyring-Reveal", "copy-only"),
            (" keyring-reveal ", "copy-only"),
            ("KEYRING-REVEAL", "none"),
        ] {
            assert_eq!(of(&tags(&[(k, v)])), Limit::NoReveal, "{k}={v}");
        }
        // Two spellings: the stricter.
        assert_eq!(
            of(&tags(&[
                ("keyring-reveal", "copy-only"),
                ("Keyring-Reveal", "x")
            ])),
            Limit::NoReveal
        );
        assert!(!is_tag("keyring-reveals"));
    }

    #[test]
    fn strictest_of_versions() {
        let cur = tags(&[("keyring-reveal", "none")]);
        let old = tags(&[]);
        assert_eq!(strictest([&cur, &old]), Limit::NoReveal);
        assert_eq!(strictest([&old, &old]), Limit::Open);
    }

    #[test]
    fn carrying_never_weakens() {
        let odd = tags(&[("Keyring-Reveal", "maybe"), ("env", "prod")]);
        // Already at least as strict: kept exactly.
        assert_eq!(at_least(&odd, Limit::CopyOnly), odd);
        let open = tags(&[("env", "prod")]);
        assert_eq!(
            at_least(&open, Limit::CopyOnly),
            tags(&[("env", "prod"), ("keyring-reveal", "copy-only")])
        );
        assert_eq!(at_least(&open, Limit::Open), open);
        let c = tags(&[("keyring-reveal", "copy-only")]);
        assert_eq!(
            at_least(&c, Limit::NoReveal),
            tags(&[("keyring-reveal", "none")])
        );
    }

    #[test]
    fn carry_keeps_the_stricter_exactly() {
        let from = tags(&[("Keyring-Reveal", "maybe")]);
        let t = tags(&[("env", "prod"), ("keyring-reveal", "copy-only")]);
        assert_eq!(
            carry(&t, &from),
            tags(&[("env", "prod"), ("Keyring-Reveal", "maybe")])
        );
        assert_eq!(carry(&from, &t), from);
        assert_eq!(carry(&t, &tags(&[])), t);
    }

    #[test]
    fn posted_values() {
        let cur = tags(&[("Keyring-Reveal", "maybe"), ("env", "prod")]);
        let base = tags(&[("env", "prod")]);
        let mut e = FieldErrors::new();
        assert_eq!(merge_posted(&base, &cur, None, &mut e), cur);
        assert_eq!(merge_posted(&base, &cur, Some("keep"), &mut e), cur);
        assert_eq!(merge_posted(&base, &cur, Some(""), &mut e), base);
        assert_eq!(
            merge_posted(&base, &cur, Some("none"), &mut e),
            tags(&[("env", "prod"), ("keyring-reveal", "none")])
        );
        assert!(e.is_empty());
        assert_eq!(merge_posted(&base, &cur, Some("open"), &mut e), cur);
        assert!(e.error_for("reveal").is_some());
    }

    #[test]
    fn words_never_quote() {
        assert_eq!(word(&tags(&[])), "unset");
        assert_eq!(word(&tags(&[("keyring-reveal", "none")])), "none");
        assert_eq!(word(&tags(&[("keyring-reveal", "secret stuff")])), "other");
    }

    #[test]
    fn the_field() {
        let f = Field::of(&tags(&[("keyring-reveal", "copy-only")]));
        assert!(f.is("copy-only") && f.odd.is_none());
        let f = Field::of(&tags(&[("keyring-reveal", "maybe")]));
        assert!(f.is("keep"));
        assert_eq!(f.odd.as_deref(), Some("keyring-reveal=maybe"));
        let f = Field::posted(Some("keep"), &tags(&[]));
        assert!(f.is(""));
    }
}
