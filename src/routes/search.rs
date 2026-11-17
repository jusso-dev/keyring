//! Search for a secret, certificate or key across every vault.
//!
//! Reads the same lists as the expiry dashboard (names and properties,
//! never values) through [`super::every_vault`], and matches the search
//! text against each item's name, tags and content type. The search text
//! is in the query string, which is never logged.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::fanout::Skipped;
use crate::azure::secrets::now_ts;
use crate::dates;
use crate::expiry::{Item, ItemType};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault::{self, MAX_VAULTS};
use crate::routes::shell::Shell;

/// Longest search text, in characters. Key Vault names are at most 127,
/// but nobody types that much to find one.
pub const MAX_QUERY_CHARS: usize = 100;
/// Most results shown. A broad search past this is asked to narrow.
pub const MAX_RESULTS: usize = 500;

const DAY: i64 = 86_400;

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct SearchQuery {
    #[serde(default)]
    pub q: String,
    /// One vault, or empty for all.
    #[serde(default)]
    pub vault: String,
    /// `secret`, `certificate`, `key` or empty.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// `expiring`, `expired`, `disabled` or empty.
    #[serde(default)]
    pub status: String,
}

/// Where an item stands, as its own list page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Status {
    pub enabled: bool,
    pub expired: bool,
    pub within30: bool,
    /// Certificates only: their list shows a 90 day band too.
    pub within90: bool,
    /// Secrets only, as on the secrets list.
    pub not_yet: bool,
    pub managed: bool,
}

impl Status {
    pub(super) fn of(i: &Item, now: i64) -> Self {
        let left = i.expires.map(|e| e - now);
        let expired = left.is_some_and(|d| d <= 0);
        let within30 = !expired && left.is_some_and(|d| d <= 30 * DAY);
        Self {
            enabled: i.enabled,
            expired,
            within30,
            within90: i.kind == ItemType::Certificate
                && !expired
                && !within30
                && left.is_some_and(|d| d <= 90 * DAY),
            not_yet: i.kind == ItemType::Secret && i.not_before.is_some_and(|n| n > now),
            managed: i.managed,
        }
    }
}

impl SearchQuery {
    /// The search text, trimmed.
    fn text(&self) -> &str {
        self.q.trim()
    }

    fn too_long(&self) -> bool {
        self.text().chars().count() > MAX_QUERY_CHARS
    }

    /// Case-insensitive substring of the name, a tag as `name=value`
    /// (`owner` and `notify` included, so an address finds them), the
    /// description, or the content type: the same match as each vault's
    /// own list filter.
    fn matches_text(&self, i: &Item) -> bool {
        let q = self.text().to_lowercase();
        i.name.to_lowercase().contains(&q)
            || i.tags
                .iter()
                .any(|(k, v)| format!("{k}={v}").to_lowercase().contains(&q))
            || i.content_type.to_lowercase().contains(&q)
            || i.description().to_lowercase().contains(&q)
    }

    fn matches(&self, i: &Item, now: i64) -> bool {
        if !self.kind.is_empty() && i.kind.slug() != self.kind {
            return false;
        }
        let s = Status::of(i, now);
        let status_ok = match self.status.as_str() {
            "expiring" => s.within30,
            "expired" => s.expired,
            "disabled" => !s.enabled,
            _ => true,
        };
        status_ok && self.matches_text(i)
    }
}

pub(super) struct Row {
    pub kind: ItemType,
    pub name: String,
    pub status: Status,
    pub content_type: String,
    pub expires: String,
    pub expires_note: String,
    /// Tags, without the description.
    pub tags: Vec<(String, String)>,
    pub description: String,
    pub owner: crate::owner::Display,
}

pub(super) struct VaultResults {
    pub vault: String,
    pub rows: Vec<Row>,
}

#[derive(Template)]
#[template(path = "search.html")]
struct SearchPage {
    shell: Shell,
    query: SearchQuery,
    /// A search was run (there was text, and it wasn't too long).
    searched: bool,
    too_long: bool,
    groups: Vec<VaultResults>,
    /// Every match, before [`MAX_RESULTS`] cut it off.
    total: usize,
    shown: usize,
    skipped: Vec<Skipped>,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    max_vaults: usize,
    max_query: usize,
    /// Suggestions for the search box: `name` and `name=value` from the
    /// items read. Empty before a search.
    tag_options: Vec<String>,
}

impl SearchPage {
    fn kind_options(&self) -> [(&'static str, &'static str, bool); 4] {
        let k = self.query.kind.as_str();
        [
            ("", "Everything", k.is_empty()),
            ("secret", "Secrets", k == "secret"),
            ("certificate", "Certificates", k == "certificate"),
            ("key", "Keys", k == "key"),
        ]
    }

    fn status_options(&self) -> [(&'static str, &'static str, bool); 4] {
        let s = self.query.status.as_str();
        [
            ("", "Any status", s.is_empty()),
            ("expiring", "Expires within 30 days", s == "expiring"),
            ("expired", "Expired", s == "expired"),
            ("disabled", "Disabled", s == "disabled"),
        ]
    }
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(query): Query<SearchQuery>,
) -> PageResult {
    let too_long = query.too_long();
    let searched = !query.text().is_empty() && !too_long;
    let mut out = SearchPage {
        shell,
        searched,
        too_long,
        groups: Vec::new(),
        total: 0,
        shown: 0,
        skipped: Vec::new(),
        vault_names: Vec::new(),
        capped: false,
        unknown_vault: false,
        max_vaults: MAX_VAULTS,
        max_query: MAX_QUERY_CHARS,
        tag_options: Vec::new(),
        query,
    };
    if !searched {
        return Ok(render(&out).into_response());
    }
    let chosen = match every_vault::choose(&state, &session, &out.query.vault).await {
        Ok(c) => c,
        Err(e) => {
            return Err(PageError::new(
                out.shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/search"),
            )
            .into());
        }
    };
    let read = every_vault::read(&state, &session, chosen.wanted).await;
    let now = now_ts();
    out.tag_options =
        crate::routes::tag_rows::filter_options_of(read.read.iter().flat_map(|(_, v)| v.iter()));
    let mut hits: Vec<&Item> = read
        .read
        .iter()
        .flat_map(|(_, v)| v.iter())
        .filter(|i| out.query.matches(i, now))
        .collect();
    hits.sort_by(|a, b| (&a.vault, a.kind, &a.name).cmp(&(&b.vault, b.kind, &b.name)));
    out.total = hits.len();
    hits.truncate(MAX_RESULTS);
    out.shown = hits.len();
    for i in hits {
        let row = Row {
            kind: i.kind,
            name: i.name.clone(),
            status: Status::of(i, now),
            content_type: i.content_type.clone(),
            expires: i.expires.map(dates::format_date).unwrap_or_default(),
            expires_note: i
                .expires
                .map(|e| dates::relative_days(e, now))
                .unwrap_or_default(),
            tags: i
                .tags
                .iter()
                .filter(|(k, _)| !crate::owner::has_own_field(k))
                .cloned()
                .collect(),
            description: i.description().to_owned(),
            owner: crate::owner::Display::of_owner(i.owner()),
        };
        match out.groups.last_mut() {
            Some(g) if g.vault == i.vault => g.rows.push(row),
            _ => out.groups.push(VaultResults {
                vault: i.vault.clone(),
                rows: vec![row],
            }),
        }
    }
    out.skipped = read.skipped;
    out.vault_names = chosen.vault_names;
    out.capped = chosen.capped;
    out.unknown_vault = chosen.unknown_vault;
    Ok(render(&out).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn item(kind: ItemType, name: &str) -> Item {
        Item {
            vault: "kv".into(),
            kind,
            name: name.into(),
            enabled: true,
            expires: None,
            not_before: None,
            created: None,
            content_type: String::new(),
            managed: false,
            tags: Vec::new(),
        }
    }

    fn q(text: &str) -> SearchQuery {
        SearchQuery {
            q: text.into(),
            ..SearchQuery::default()
        }
    }

    #[test]
    fn matches_name_tags_and_content_type_ignoring_case() {
        let mut i = item(ItemType::Secret, "Db-Password");
        i.tags = vec![("Owner".into(), "Payments".into())];
        i.content_type = "application/JSON".into();
        for hit in [
            "db-pass",
            "PASSWORD",
            "owner",
            "payments",
            "owner=pay",
            "json",
            "  db  ",
        ] {
            assert!(q(hit).matches(&i, NOW), "{hit}");
        }
        for miss in ["dbpassword", "team", "password owner"] {
            assert!(!q(miss).matches(&i, NOW), "{miss}");
        }
    }

    #[test]
    fn matches_the_owner_and_each_notify_address() {
        let mut i = item(ItemType::Key, "k");
        i.tags = vec![
            ("owner".into(), "Ops@example.com".into()),
            (
                "notify".into(),
                "sam@example.com, backup@example.com".into(),
            ),
        ];
        for hit in [
            "ops@example.com",
            "owner=ops@",
            "BACKUP@example.com",
            "notify=sam@",
        ] {
            assert!(q(hit).matches(&i, NOW), "{hit}");
        }
        assert!(!q("pat@example.com").matches(&i, NOW));
    }

    #[test]
    fn matches_the_description() {
        let mut i = item(ItemType::Certificate, "web-tls");
        i.tags = vec![(
            "description".into(),
            "Front door for the Payments site".into(),
        )];
        assert!(q("payments site").matches(&i, NOW));
        assert!(!q("billing").matches(&i, NOW));
    }

    #[test]
    fn filters_by_kind_and_status() {
        let mut gone = item(ItemType::Key, "app-gone");
        gone.expires = Some(NOW - DAY);
        let mut soon = item(ItemType::Secret, "app-soon");
        soon.expires = Some(NOW + 10 * DAY);
        let mut off = item(ItemType::Certificate, "app-off");
        off.enabled = false;
        let all = [&gone, &soon, &off];
        let names = |query: SearchQuery| -> Vec<&str> {
            all.iter()
                .filter(|i| query.matches(i, NOW))
                .map(|i| i.name.as_str())
                .collect()
        };
        let with = |kind: &str, status: &str| SearchQuery {
            q: "app".into(),
            kind: kind.into(),
            status: status.into(),
            ..SearchQuery::default()
        };
        assert_eq!(names(with("", "")), ["app-gone", "app-soon", "app-off"]);
        assert_eq!(names(with("key", "")), ["app-gone"]);
        assert_eq!(names(with("", "expired")), ["app-gone"]);
        assert_eq!(names(with("", "expiring")), ["app-soon"]);
        assert_eq!(names(with("", "disabled")), ["app-off"]);
    }

    #[test]
    fn status_bands_follow_each_list_page() {
        let mut cert = item(ItemType::Certificate, "c");
        cert.expires = Some(NOW + 60 * DAY);
        assert!(Status::of(&cert, NOW).within90);
        let mut key = item(ItemType::Key, "k");
        key.expires = Some(NOW + 60 * DAY);
        assert!(!Status::of(&key, NOW).within90, "keys show no 90 day band");
        let mut s = item(ItemType::Secret, "s");
        s.not_before = Some(NOW + DAY);
        assert!(Status::of(&s, NOW).not_yet);
    }

    #[test]
    fn long_queries_are_refused() {
        assert!(!q(&"a".repeat(MAX_QUERY_CHARS)).too_long());
        assert!(q(&"a".repeat(MAX_QUERY_CHARS + 1)).too_long());
        // Characters, not bytes.
        assert!(!q(&"\u{e9}".repeat(MAX_QUERY_CHARS)).too_long());
    }
}
