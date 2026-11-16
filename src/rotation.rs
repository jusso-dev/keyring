//! The rotation line: what a secret's `rotation`, `rotation-last` and
//! `rotation-status` tags claim about its last rotation.
//!
//! Keyring doesn't rotate anything. A rotator outside Keyring writes these
//! tags, and anyone with tag rights on the vault can write them too, so they
//! are untrusted text: cleaned, cut short and shown as a claim. Anything that
//! doesn't follow the convention in `docs/rotation.md` shows as "unknown".

use crate::dates;

/// Tag names. Exact and lower-case: `Rotation` isn't read.
pub(crate) const TAG_NAME: &str = "rotation";
pub(crate) const TAG_LAST: &str = "rotation-last";
pub(crate) const TAG_STATUS: &str = "rotation-status";

/// Most characters of the rotator's name shown.
pub(crate) const MAX_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    Failed,
    Unknown,
}

impl Status {
    fn parse(tag: Option<&str>) -> Self {
        match tag {
            Some("ok") => Self::Ok,
            Some("failed") => Self::Failed,
            _ => Self::Unknown,
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Failed => "Failed",
            Self::Unknown => "Unknown",
        }
    }
    /// Badge classes from design.md: a glyph and a word, never colour alone.
    pub(crate) fn css(self) -> &'static str {
        match self {
            Self::Ok => "badge badge-ok",
            Self::Failed => "badge badge-error",
            Self::Unknown => "badge badge-muted",
        }
    }
}

/// What the tags claim, ready to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rotation {
    /// The rotator's name, cleaned and cut short, or "unknown".
    pub by: String,
    /// The last attempt's date (UTC) as shown elsewhere, or "unknown".
    pub last: String,
    pub status: Status,
}

impl Rotation {
    /// `None` when none of the three tags is set.
    pub(crate) fn from_tags(tags: &[(String, String)]) -> Option<Self> {
        let get = |name: &str| {
            tags.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        let (name, last, status) = (get(TAG_NAME), get(TAG_LAST), get(TAG_STATUS));
        if name.is_none() && last.is_none() && status.is_none() {
            return None;
        }
        let by = name.map(clean).unwrap_or_default();
        Some(Self {
            by: if by.is_empty() { "unknown".into() } else { by },
            last: last
                .and_then(parse_last)
                .map(dates::format_date)
                .unwrap_or_else(|| "unknown".into()),
            status: Status::parse(status),
        })
    }

    /// The tags say the last rotation failed.
    pub(crate) fn failed(&self) -> bool {
        self.status == Status::Failed
    }
}

/// Drop control and direction-changing characters, trim, and cut to
/// [`MAX_NAME_CHARS`] with an ellipsis.
fn clean(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .collect();
    let kept = kept.trim();
    if kept.chars().count() <= MAX_NAME_CHARS {
        return kept.to_owned();
    }
    let mut out: String = kept.chars().take(MAX_NAME_CHARS).collect();
    out.push('…');
    out
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `YYYY-MM-DD`, or an RFC 3339 date-time such as `2026-11-02T03:00:00Z`
/// or `2026-11-02T13:00:00+10:00`, to a Unix time. `None` for anything else.
fn parse_last(s: &str) -> Option<i64> {
    if s.len() == 10 {
        return dates::parse_iso_date(s);
    }
    if s.len() > 64 || !s.is_ascii() {
        return None;
    }
    let (date, rest) = (s.get(..10)?, s.get(10..)?);
    let day = dates::parse_iso_date(date)?;
    let rest = rest.strip_prefix(['T', 't'])?;
    let (h, m, sec) = (
        num(rest.get(0..2)?)?,
        num(rest.get(3..5)?)?,
        num(rest.get(6..8)?)?,
    );
    if rest.get(2..3)? != ":" || rest.get(5..6)? != ":" || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    let mut zone = rest.get(8..)?;
    if let Some(frac) = zone.strip_prefix('.') {
        let digits = frac.chars().take_while(char::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        zone = &frac[digits..];
    }
    let offset = match zone {
        "Z" | "z" => 0,
        _ => {
            let sign = match zone.get(0..1)? {
                "+" => 1,
                "-" => -1,
                _ => return None,
            };
            if zone.len() != 6 || zone.get(3..4)? != ":" {
                return None;
            }
            let (oh, om) = (num(zone.get(1..3)?)?, num(zone.get(4..6)?)?);
            if oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    Some(day + h * 3600 + m * 60 + sec.min(59) - offset)
}

fn num(s: &str) -> Option<i64> {
    if s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn no_rotation_tags_no_line() {
        assert_eq!(Rotation::from_tags(&tags(&[("env", "prod")])), None);
        assert_eq!(Rotation::from_tags(&tags(&[("Rotation", "x")])), None);
    }

    #[test]
    fn all_three_tags() {
        let r = Rotation::from_tags(&tags(&[
            ("rotation", "storage-key-rotator"),
            ("rotation-last", "2026-11-02"),
            ("rotation-status", "ok"),
        ]))
        .unwrap();
        assert_eq!(r.by, "storage-key-rotator");
        assert_eq!(r.last, "2 Nov 2026");
        assert_eq!(r.status, Status::Ok);
    }

    #[test]
    fn dates() {
        let day = |s| parse_last(s).map(dates::iso_date);
        assert_eq!(day("2026-11-02"), Some("2026-11-02".into()));
        assert_eq!(day("2026-11-02T03:04:05Z"), Some("2026-11-02".into()));
        assert_eq!(day("2026-11-02t03:04:05.123z"), Some("2026-11-02".into()));
        // Shown as the UTC date.
        assert_eq!(day("2026-11-02T08:00:00+10:00"), Some("2026-11-01".into()));
        assert_eq!(day("2026-11-01T20:00:00-05:00"), Some("2026-11-02".into()));
        for bad in [
            "",
            "yesterday",
            "02-11-2026",
            "2026-02-31",
            "2026-11-02 03:04:05Z",
            "2026-11-02T03:04:05",
            "2026-11-02T25:00:00Z",
            "2026-11-02T03:04:05.Z",
            "2026-11-02T03:04:05+1000",
            "2026-11-02T03:04:05Z<b>",
            "２０２６-11-02",
        ] {
            assert_eq!(parse_last(bad), None, "{bad}");
        }
    }

    #[test]
    fn odd_values_show_as_unknown() {
        let r = Rotation::from_tags(&tags(&[
            ("rotation-last", "soon"),
            ("rotation-status", "OK"),
        ]))
        .unwrap();
        assert_eq!(
            r,
            Rotation {
                by: "unknown".into(),
                last: "unknown".into(),
                status: Status::Unknown
            }
        );
        let f = |s| {
            Rotation::from_tags(&tags(&[("rotation-status", s)]))
                .unwrap()
                .failed()
        };
        assert!(f("failed"));
        assert!(!f("Failed"));
    }

    #[test]
    fn names_are_cleaned_and_cut() {
        assert_eq!(clean("a\u{0}b\u{1b}[31m\u{202E}c\n"), "ab[31mc");
        let long = "x".repeat(500);
        let c = clean(&long);
        assert_eq!(c.chars().count(), MAX_NAME_CHARS + 1);
        assert!(c.ends_with('…'));
        assert_eq!(clean(" \u{7}\t "), "");
    }
}
