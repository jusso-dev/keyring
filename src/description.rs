//! The note on a secret, certificate or key, kept in Key Vault as the
//! reserved tag `description`. Key Vault has no description field, so a
//! tag keeps "Keyring stores nothing": the note shows in the portal and the
//! CLI too. The rules for writing one live here, so every form, import and
//! bulk change applies the same ones.
//!
//! A note is a tag: anyone who can read the item's properties can read it,
//! and it counts as one of the item's 15 tags. It is never logged and never
//! put in an audit event.

use std::collections::BTreeMap;

/// The tag that holds the note.
pub const TAG: &str = "description";

/// Longest note, in UTF-16 code units. Key Vault allows tag values of 256
/// characters and, as a .NET service, counts a string's length in UTF-16
/// code units. That is also what a browser's `maxlength` and a script's
/// `value.length` count, so the form, the counter and the server agree. A
/// character outside the Basic Multilingual Plane (most emoji) counts as
/// two.
pub const MAX_UNITS: usize = 256;

/// Most tags Key Vault allows on one item, the note included.
pub const MAX_TAGS: usize = 15;

/// Longest note shown in a list cell, in characters, before it is cut.
pub const SHORT_CHARS: usize = 80;

/// True for a tag name that means the note. Exact, as Key Vault keeps tag
/// names: a tag called `Description` is an ordinary tag.
pub fn is_reserved(name: &str) -> bool {
    name.trim() == TAG
}

/// A note from a form. Line breaks become `\n` and the ends are trimmed.
/// `Ok(None)` when nothing is left, which removes the tag. Refused when it
/// holds a control character other than a line break, an invisible format
/// character (as [`crate::reason`] defines them), or is over
/// [`MAX_UNITS`]. The message never quotes the note.
pub fn clean(raw: &str) -> Result<Option<String>, String> {
    let text = raw.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text
        .chars()
        .any(|c| c != '\n' && crate::reason::is_unsafe(c))
    {
        return Err("The description has a hidden character in it, such as a tab, a control character or an invisible formatting mark. Remove it and try again.".into());
    }
    let n = text.encode_utf16().count();
    if n > MAX_UNITS {
        return Err(format!(
            "The description can be up to {MAX_UNITS} characters. This one has {n}."
        ));
    }
    Ok(Some(text.to_owned()))
}

/// The item's note, if it has one.
pub fn of(tags: &BTreeMap<String, String>) -> Option<&str> {
    tags.get(TAG).map(String::as_str).filter(|s| !s.is_empty())
}

/// The tags without the note, for the tag editor and tag lists.
pub fn without(tags: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    tags.iter()
        .filter(|(k, _)| k.as_str() != TAG)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Put `note` into `tags`, or take the note out when it is `None`. Every
/// other tag is kept. Refused, before anything is sent to Key Vault, when
/// adding the note would take the item past [`MAX_TAGS`].
pub fn merge(
    tags: &BTreeMap<String, String>,
    note: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = tags.clone();
    match note {
        None => {
            out.remove(TAG);
        }
        Some(n) => {
            if !out.contains_key(TAG) && out.len() >= MAX_TAGS {
                return Err(format!(
                    "This already has {} tags, the most Key Vault allows, and a description would be one more. Remove a tag first, or leave Description empty.",
                    out.len()
                ));
            }
            out.insert(TAG.to_owned(), n.to_owned());
        }
    }
    Ok(out)
}

/// The note for a list cell: on one line, cut to [`SHORT_CHARS`]
/// characters with an ellipsis. The page puts the whole note in the cell's
/// accessible text.
pub fn short(note: &str) -> String {
    let flat: String = note
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if flat.chars().count() <= SHORT_CHARS {
        return flat;
    }
    let cut: String = flat.chars().take(SHORT_CHARS - 1).collect();
    format!("{}…", cut.trim_end())
}

/// True when [`short`] would cut the note.
pub fn is_cut(note: &str) -> bool {
    short(note) != note
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
    fn limit_is_256_utf16_units() {
        assert_eq!(clean(&"a".repeat(256)).unwrap().unwrap().len(), 256);
        assert!(clean(&"a".repeat(257)).unwrap_err().contains("257"));
        // Letters outside ASCII count once, as in a browser.
        assert!(clean(&"é".repeat(256)).unwrap().is_some());
        assert!(clean(&"日".repeat(257)).is_err());
        // An emoji is two UTF-16 units, as Key Vault and a browser count it.
        assert!(clean(&"😀".repeat(128)).unwrap().is_some());
        assert!(clean(&"😀".repeat(129)).is_err());
    }

    #[test]
    fn line_breaks_are_kept_as_lf() {
        assert_eq!(
            clean("  first\r\nsecond\rthird\n ").unwrap().as_deref(),
            Some("first\nsecond\nthird")
        );
        // A CRLF counts once.
        let crlf = format!("{}\r\n{}", "a".repeat(127), "b".repeat(128));
        assert_eq!(clean(&crlf).unwrap().unwrap().len(), 256);
    }

    #[test]
    fn empty_removes() {
        assert_eq!(clean(""), Ok(None));
        assert_eq!(clean(" \r\n\n "), Ok(None));
    }

    #[test]
    fn hidden_characters_are_refused() {
        for bad in [
            '\t',
            '\u{1b}',
            '\u{7f}',
            '\u{85}',
            '\u{200B}',
            '\u{202E}',
            '\u{2066}',
            '\u{FEFF}',
            '\u{2028}',
            '\u{E0041}',
            '\u{E000}',
            '\u{00AD}',
        ] {
            let e = clean(&format!("ok{bad}ok")).unwrap_err();
            assert!(e.contains("hidden character"), "U+{:04X}", bad as u32);
        }
        for kept in ["Größe prüfen", "مرحبا", "日本語", "a=b; \"q\" <x>"] {
            assert_eq!(clean(kept).unwrap().as_deref(), Some(kept));
        }
    }

    #[test]
    fn merge_keeps_other_tags() {
        let t = tags(&[("env", "prod"), ("team", "data")]);
        let m = merge(&t, Some("For payments")).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m["env"], "prod");
        assert_eq!(of(&m), Some("For payments"));
        let m = merge(&m, None).unwrap();
        assert_eq!(m, t);
        assert_eq!(without(&tags(&[("description", "x"), ("a", "")])).len(), 1);
    }

    #[test]
    fn the_note_counts_towards_fifteen() {
        let full: BTreeMap<String, String> =
            (0..15).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(merge(&full, Some("n")).unwrap_err().contains("15 tags"));
        // Removing one is always allowed.
        assert_eq!(merge(&full, None).unwrap().len(), 15);
        // Changing an existing note doesn't add a tag.
        let mut with = (0..14)
            .map(|i| (format!("k{i}"), "v".into()))
            .collect::<BTreeMap<String, String>>();
        with.insert(TAG.into(), "old".into());
        assert_eq!(merge(&with, Some("new")).unwrap()[TAG], "new");
    }

    #[test]
    fn only_the_exact_name_is_reserved() {
        assert!(is_reserved("description"));
        assert!(is_reserved(" description "));
        assert!(!is_reserved("Description"));
        assert!(!is_reserved("descriptions"));
    }

    #[test]
    fn short_is_one_line() {
        assert_eq!(short("a\n\nb"), "a b");
        let long = "x".repeat(200);
        let s = short(&long);
        assert_eq!(s.chars().count(), SHORT_CHARS);
        assert!(s.ends_with('…'));
    }
}
