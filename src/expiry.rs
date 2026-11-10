//! Group secrets, certificates and keys by when they expire, and write the
//! result as CSV. Pure functions, tested with fixed dates.

use crate::dates;

const DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Expired,
    Within7,
    Within30,
    Within90,
    Later,
    NoExpiry,
}

impl Group {
    pub const ALL: [Group; 6] = [
        Group::Expired,
        Group::Within7,
        Group::Within30,
        Group::Within90,
        Group::Later,
        Group::NoExpiry,
    ];

    pub fn of(expires: Option<i64>, now: i64) -> Self {
        match expires {
            None => Self::NoExpiry,
            Some(e) if e <= now => Self::Expired,
            Some(e) if e - now <= 7 * DAY => Self::Within7,
            Some(e) if e - now <= 30 * DAY => Self::Within30,
            Some(e) if e - now <= 90 * DAY => Self::Within90,
            Some(_) => Self::Later,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Expired => "Expired",
            Self::Within7 => "Next 7 days",
            Self::Within30 => "8 to 30 days",
            Self::Within90 => "31 to 90 days",
            Self::Later => "More than 90 days",
            Self::NoExpiry => "No expiry set",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Within7 => "7",
            Self::Within30 => "30",
            Self::Within90 => "90",
            Self::Later => "later",
            Self::NoExpiry => "none",
        }
    }

    pub fn css(self) -> &'static str {
        match self {
            Self::Expired | Self::Within7 => "badge-error",
            Self::Within30 => "badge-warn",
            _ => "badge-muted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemType {
    Secret,
    Certificate,
    Key,
}

impl ItemType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secret => "Secret",
            Self::Certificate => "Certificate",
            Self::Key => "Key",
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Certificate => "certificate",
            Self::Key => "key",
        }
    }
    pub fn path(self) -> &'static str {
        match self {
            Self::Secret => "/secrets",
            Self::Certificate => "/certificates",
            Self::Key => "/keys",
        }
    }
}

/// One item with a date, from any vault. Properties only, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub vault: String,
    pub kind: ItemType,
    pub name: String,
    pub enabled: bool,
    pub expires: Option<i64>,
    pub tags: Vec<(String, String)>,
    /// Certificates and keys that belong to a certificate show up once,
    /// as the certificate.
    pub managed: bool,
}

impl Item {
    pub fn group(&self, now: i64) -> Group {
        Group::of(self.expires, now)
    }
    pub fn expires_text(&self) -> String {
        self.expires.map(dates::format_date).unwrap_or_default()
    }
    pub fn expires_note(&self, now: i64) -> String {
        self.expires
            .map(|e| dates::relative_days(e, now))
            .unwrap_or_default()
    }
    pub fn tags_text(&self) -> String {
        self.tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Sort for display: soonest first, items with no expiry last, then by
/// vault and name.
pub fn sort(items: &mut [Item]) {
    items.sort_by(|a, b| {
        (a.expires.is_none(), a.expires, &a.vault, a.kind, &a.name).cmp(&(
            b.expires.is_none(),
            b.expires,
            &b.vault,
            b.kind,
            &b.name,
        ))
    });
}

/// Count items in each group, in [`Group::ALL`] order.
pub fn counts(items: &[Item], now: i64) -> [usize; 6] {
    let mut out = [0; 6];
    for i in items {
        let g = i.group(now);
        let idx = Group::ALL.iter().position(|x| *x == g).unwrap_or(5);
        out[idx] += 1;
    }
    out
}

/// One CSV field. Quotes when needed, and stops spreadsheets treating a
/// value as a formula (CSV injection) by prefixing `'`.
pub fn csv_field(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

/// CSV of items. Columns: vault, type, name, status, expires (ISO), group,
/// tags. No values.
pub fn to_csv(items: &[Item], now: i64) -> String {
    let mut out = String::from("Vault,Type,Name,Enabled,Expires (UTC),Group,Tags\r\n");
    for i in items {
        let row = [
            csv_field(&i.vault),
            i.kind.label().to_owned(),
            csv_field(&i.name),
            if i.enabled { "Yes" } else { "No" }.to_owned(),
            i.expires.map(dates::iso_date).unwrap_or_default(),
            i.group(now).label().to_owned(),
            csv_field(&i.tags_text()),
        ];
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// A CSV row for a vault that isn't in the export, so the file can't be
/// taken for a complete report. The columns line up with [`to_csv`]: the
/// vault, `NOT READ` in the Type column and the reason in the Name column.
pub fn not_read_row(vault: &str, reason: &str) -> String {
    let row = [
        csv_field(vault),
        "NOT READ".to_owned(),
        csv_field(reason),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ];
    let mut out = row.join(",");
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn item(name: &str, exp: Option<i64>) -> Item {
        Item {
            vault: "kv".into(),
            kind: ItemType::Secret,
            name: name.into(),
            enabled: true,
            expires: exp,
            tags: vec![("env".into(), "prod".into())],
            managed: false,
        }
    }

    #[test]
    fn groups_at_the_edges() {
        assert_eq!(Group::of(None, NOW), Group::NoExpiry);
        assert_eq!(Group::of(Some(NOW), NOW), Group::Expired);
        assert_eq!(Group::of(Some(NOW - 1), NOW), Group::Expired);
        assert_eq!(Group::of(Some(NOW + 1), NOW), Group::Within7);
        assert_eq!(Group::of(Some(NOW + 7 * DAY), NOW), Group::Within7);
        assert_eq!(Group::of(Some(NOW + 7 * DAY + 1), NOW), Group::Within30);
        assert_eq!(Group::of(Some(NOW + 30 * DAY), NOW), Group::Within30);
        assert_eq!(Group::of(Some(NOW + 30 * DAY + 1), NOW), Group::Within90);
        assert_eq!(Group::of(Some(NOW + 90 * DAY), NOW), Group::Within90);
        assert_eq!(Group::of(Some(NOW + 90 * DAY + 1), NOW), Group::Later);
    }

    #[test]
    fn counts_and_sorting() {
        let mut items = vec![
            item("none", None),
            item("later", Some(NOW + 200 * DAY)),
            item("gone", Some(NOW - DAY)),
            item("soon", Some(NOW + 2 * DAY)),
            item("month", Some(NOW + 20 * DAY)),
            item("quarter", Some(NOW + 60 * DAY)),
            item("gone2", Some(NOW - 5 * DAY)),
        ];
        assert_eq!(counts(&items, NOW), [2, 1, 1, 1, 1, 1]);
        sort(&mut items);
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["gone2", "gone", "soon", "month", "quarter", "later", "none"]
        );
    }

    #[test]
    fn csv_has_properties_only_and_is_safe() {
        let mut evil = item("=HYPERLINK(\"x\")", Some(NOW + DAY));
        evil.tags = vec![("note".into(), "a,b".into())];
        let csv = to_csv(&[item("db-password", Some(NOW + 3 * DAY)), evil], NOW);
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines[0], "Vault,Type,Name,Enabled,Expires (UTC),Group,Tags");
        assert_eq!(
            lines[1],
            "kv,Secret,db-password,Yes,2027-01-18,Next 7 days,env=prod"
        );
        assert!(
            lines[2].starts_with("kv,Secret,\"'=HYPERLINK(\"\"x\"\")\""),
            "{}",
            lines[2]
        );
        assert!(lines[2].ends_with("\"note=a,b\""));
        assert_eq!(csv_field("-1+1"), "'-1+1");
        assert_eq!(csv_field("plain"), "plain");
    }
}
