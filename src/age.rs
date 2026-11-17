//! How long since a value last changed, from the current version's
//! `created` date. Pure functions, tested with fixed dates.
//!
//! Key Vault makes a new version for every new value, so the current
//! version's `created` is when the value last changed. Editing properties
//! (tags, dates, enabled) changes `updated` but not `created`, so `updated`
//! is never used here. Certificate-backed secrets and keys change with
//! their certificate, so callers leave them out and show the certificate.

#[cfg(test)]
use crate::config::DEFAULT_STALE_AFTER_DAYS;
use crate::dates;
use crate::expiry::{Item, csv_field};

const DAY: i64 = 86_400;

/// Time since the value last changed, in four bands, plus one for an item
/// Key Vault gave no `created` date for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Band {
    Under90,
    Days90To180,
    Days180To365,
    OverYear,
    Unknown,
}

impl Band {
    pub(crate) const ALL: [Band; 5] = [
        Band::OverYear,
        Band::Days180To365,
        Band::Days90To180,
        Band::Under90,
        Band::Unknown,
    ];

    /// The band for a value made at `created`. A date in the future (clock
    /// skew) counts as new. Under 90 days means less than 90 whole days;
    /// "over a year" means more than 365 days.
    pub(crate) fn of(created: Option<i64>, now: i64) -> Self {
        let Some(c) = created else {
            return Self::Unknown;
        };
        let age = now - c;
        if age < 90 * DAY {
            Self::Under90
        } else if age < 180 * DAY {
            Self::Days90To180
        } else if age <= 365 * DAY {
            Self::Days180To365
        } else {
            Self::OverYear
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Under90 => "Under 90 days",
            Self::Days90To180 => "90 to 180 days",
            Self::Days180To365 => "180 to 365 days",
            Self::OverYear => "Over a year",
            Self::Unknown => "Date not given",
        }
    }

    pub(crate) fn slug(self) -> &'static str {
        match self {
            Self::Under90 => "90",
            Self::Days90To180 => "180",
            Self::Days180To365 => "365",
            Self::OverYear => "older",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn css(self) -> &'static str {
        match self {
            Self::OverYear => "badge-warn",
            _ => "badge-muted",
        }
    }
}

/// True when a value made at `created` is more than `after_days` old.
pub(crate) fn is_stale(created: Option<i64>, after_days: u32, now: i64) -> bool {
    created.is_some_and(|c| now - c > i64::from(after_days) * DAY)
}

/// "over a year", or "over N days", for a threshold of `after_days`.
pub(crate) fn stale_phrase(after_days: u32) -> String {
    match after_days {
        365 => "over a year".into(),
        1 => "over a day".into(),
        n => format!("over {n} days"),
    }
}

/// The badge's words for a threshold of `after_days`.
pub(crate) fn stale_label(after_days: u32) -> String {
    format!("Not changed in {}", stale_phrase(after_days))
}

/// The badge for an item, or empty when it doesn't get one. Items managed
/// by a certificate never do: they change with the certificate.
pub(crate) fn stale_badge(
    created: Option<i64>,
    managed: bool,
    after_days: u32,
    now: i64,
) -> String {
    if !managed && is_stale(created, after_days, now) {
        stale_label(after_days)
    } else {
        String::new()
    }
}

/// Whole days since `created`, never below zero.
pub(crate) fn days_since(created: i64, now: i64) -> i64 {
    ((now - created) / DAY).max(0)
}

/// Sort for display: oldest value first, then by vault, type and name.
/// Items with no date go last.
pub(crate) fn sort(items: &mut [Item]) {
    items.sort_by(|a, b| {
        (a.created.is_none(), a.created, &a.vault, a.kind, &a.name).cmp(&(
            b.created.is_none(),
            b.created,
            &b.vault,
            b.kind,
            &b.name,
        ))
    });
}

/// Count items in each band, in [`Band::ALL`] order.
pub(crate) fn counts(items: &[Item], now: i64) -> [usize; 5] {
    let mut out = [0; 5];
    for i in items {
        let b = Band::of(i.created, now);
        let idx = Band::ALL.iter().position(|x| *x == b).unwrap_or(4);
        out[idx] += 1;
    }
    out
}

/// The CSV header. [`to_csv`] and [`not_read_row`] line up with it.
const CSV_HEADER: &str =
    "Vault,Type,Name,Enabled,Value changed (UTC),Days since,Band,Description,Owner,Notify,Tags\r\n";
const CSV_COLUMNS: usize = 11;

/// CSV of items. No values, only names and dates. Every free-text field
/// goes through [`csv_field`], which stops a spreadsheet reading it as a
/// formula.
pub(crate) fn to_csv(items: &[Item], now: i64) -> String {
    let mut out = String::from(CSV_HEADER);
    for i in items {
        let row = [
            csv_field(&i.vault),
            i.kind.label().to_owned(),
            csv_field(&i.name),
            if i.enabled { "Yes" } else { "No" }.to_owned(),
            i.created.map(dates::iso_date).unwrap_or_default(),
            i.created
                .map(|c| days_since(c, now).to_string())
                .unwrap_or_default(),
            Band::of(i.created, now).label().to_owned(),
            csv_field(i.description()),
            csv_field(i.owner()),
            csv_field(i.notify()),
            csv_field(&i.tags_text()),
        ];
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// A row for a vault that isn't in the export: the vault, `NOT READ` in
/// the Type column and the reason in the Name column.
pub(crate) fn not_read_row(vault: &str, reason: &str) -> String {
    let mut row = vec![String::new(); CSV_COLUMNS];
    row[0] = csv_field(vault);
    row[1] = "NOT READ".to_owned();
    row[2] = csv_field(reason);
    let mut out = row.join(",");
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expiry::ItemType;

    const NOW: i64 = 1_800_000_000;

    fn item(name: &str, created: Option<i64>) -> Item {
        Item {
            vault: "kv".into(),
            kind: ItemType::Secret,
            name: name.into(),
            enabled: true,
            expires: None,
            not_before: None,
            created,
            content_type: String::new(),
            managed: false,
            tags: vec![("env".into(), "prod".into())],
        }
    }

    #[test]
    fn bands_at_the_edges() {
        assert_eq!(Band::of(None, NOW), Band::Unknown);
        assert_eq!(Band::of(Some(NOW + DAY), NOW), Band::Under90, "future");
        assert_eq!(Band::of(Some(NOW), NOW), Band::Under90);
        assert_eq!(Band::of(Some(NOW - 90 * DAY + 1), NOW), Band::Under90);
        assert_eq!(Band::of(Some(NOW - 90 * DAY), NOW), Band::Days90To180);
        assert_eq!(Band::of(Some(NOW - 180 * DAY + 1), NOW), Band::Days90To180);
        assert_eq!(Band::of(Some(NOW - 180 * DAY), NOW), Band::Days180To365);
        assert_eq!(Band::of(Some(NOW - 365 * DAY), NOW), Band::Days180To365);
        assert_eq!(Band::of(Some(NOW - 365 * DAY - 1), NOW), Band::OverYear);
        assert_eq!(Band::of(Some(NOW - 3000 * DAY), NOW), Band::OverYear);
    }

    #[test]
    fn badge_threshold() {
        // Default: more than 365 days, the same edge as "Over a year".
        let d = DEFAULT_STALE_AFTER_DAYS;
        assert!(!is_stale(Some(NOW - 365 * DAY), d, NOW));
        assert!(is_stale(Some(NOW - 365 * DAY - 1), d, NOW));
        assert!(!is_stale(None, d, NOW));
        assert_eq!(
            stale_badge(Some(NOW - 400 * DAY), false, d, NOW),
            "Not changed in over a year"
        );
        // A certificate's backing secret or key never gets one.
        assert_eq!(stale_badge(Some(NOW - 400 * DAY), true, d, NOW), "");
        // Another threshold changes both the edge and the words.
        assert!(!is_stale(Some(NOW - 30 * DAY), 30, NOW));
        assert!(is_stale(Some(NOW - 30 * DAY - 1), 30, NOW));
        assert_eq!(
            stale_badge(Some(NOW - 31 * DAY), false, 30, NOW),
            "Not changed in over 30 days"
        );
        assert_eq!(stale_label(1), "Not changed in over a day");
    }

    #[test]
    fn counts_and_sorting() {
        let mut items = vec![
            item("new", Some(NOW - DAY)),
            item("none", None),
            item("old", Some(NOW - 800 * DAY)),
            item("half", Some(NOW - 200 * DAY)),
            item("quarter", Some(NOW - 100 * DAY)),
            item("older", Some(NOW - 900 * DAY)),
        ];
        assert_eq!(counts(&items, NOW), [2, 1, 1, 1, 1]);
        sort(&mut items);
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["older", "old", "half", "quarter", "new", "none"]);
        assert_eq!(days_since(NOW - 3 * DAY - 5, NOW), 3);
        assert_eq!(days_since(NOW + DAY, NOW), 0);
    }

    #[test]
    fn csv_has_dates_only_and_is_safe() {
        let mut evil = item("=HYPERLINK(\"x\")", Some(NOW - 400 * DAY));
        evil.tags = vec![("note".into(), "+a,b".into())];
        let csv = to_csv(&[item("db-password", Some(NOW - 10 * DAY)), evil], NOW);
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "Vault,Type,Name,Enabled,Value changed (UTC),Days since,Band,Description,Owner,Notify,Tags"
        );
        assert_eq!(
            lines[1],
            "kv,Secret,db-password,Yes,2027-01-05,10,Under 90 days,,,,env=prod"
        );
        assert!(
            lines[2].starts_with("kv,Secret,\"'=HYPERLINK(\"\"x\"\")\""),
            "{}",
            lines[2]
        );
        assert!(lines[2].contains(",400,Over a year,"));
        assert!(lines[2].ends_with("\"note=+a,b\""));
        let mut noted = item("noted", None);
        noted.tags.push(("description".into(), "@SUM(1)".into()));
        let csv = to_csv(&[noted], NOW);
        assert!(csv.contains(",'@SUM(1),,,env=prod\r\n"), "{csv}");
        // The owner and notify get their own guarded columns, not the tags.
        let mut owned = item("owned", None);
        owned.tags.push(("owner".into(), "=cmd@example.com".into()));
        owned
            .tags
            .push(("notify".into(), "a@example.com, b@example.com".into()));
        let csv = to_csv(&[owned], NOW);
        assert!(
            csv.contains(",'=cmd@example.com,\"a@example.com, b@example.com\",env=prod\r\n"),
            "{csv}"
        );
        let nr = not_read_row("-kv", "a, b");
        assert_eq!(nr, "'-kv,NOT READ,\"a, b\",,,,,,,,\r\n");
        assert_eq!(nr.matches(',').count() - 1, CSV_COLUMNS - 1);
    }
}
