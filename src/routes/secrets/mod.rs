//! Secrets pages: list, search and detail.

pub(super) mod delete;
pub(super) mod edit;
pub(super) mod form;
pub(super) mod reveal;
pub(super) mod versions;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::age;
use crate::auth::CurrentSession;
use crate::azure::secrets::{ExpiryState, SecretItem, SecretsApi, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::lifecycle::Kind;
use crate::routes::paging::{Pager, paginate};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, vault_path};
pub(super) use crate::routes::vault_ctx::{azure_problem, checked_name};

/// One row in the list, ready to show.
pub(super) struct SecretRow {
    pub name: String,
    pub enabled: bool,
    pub content_type: String,
    /// When the current version was made: when the value last changed.
    pub changed: String,
    /// "N days ago" for [`Self::changed`].
    pub changed_note: String,
    pub created_at: Option<i64>,
    /// The "Not changed in over ..." badge, or empty. Set by
    /// [`Self::mark_stale`].
    pub stale: String,
    pub expires: String,
    pub expires_note: String,
    pub expiry: ExpiryState,
    pub not_yet_valid: bool,
    pub tags: Vec<(String, String)>,
    pub managed: bool,
    pub filter_text: String,
}

impl SecretRow {
    pub(super) fn from_item(item: &SecretItem, now: i64) -> Self {
        let a = &item.attributes;
        let tags: Vec<(String, String)> = item
            .tags()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut filter_text = item.name().to_lowercase();
        for (k, v) in &tags {
            filter_text.push(' ');
            filter_text.push_str(&format!("{k}={v}").to_lowercase());
        }
        Self {
            name: item.name().to_owned(),
            enabled: a.is_enabled(),
            content_type: item.content_type.clone().unwrap_or_default(),
            changed: a.created.map(dates::format_date).unwrap_or_default(),
            changed_note: a
                .created
                .map(|c| dates::relative_days(c, now))
                .unwrap_or_default(),
            created_at: a.created,
            stale: String::new(),
            expires: a.expires.map(dates::format_date).unwrap_or_default(),
            expires_note: a
                .expires
                .map(|e| dates::relative_days(e, now))
                .unwrap_or_default(),
            expiry: a.expiry_state(now),
            not_yet_valid: a.not_yet_valid(now),
            tags,
            managed: item.managed.unwrap_or(false),
            filter_text,
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        self.expiry == ExpiryState::Expired
    }

    pub(super) fn is_expiring(&self) -> bool {
        self.expiry == ExpiryState::Soon
    }

    /// Set the badge for a value unchanged in more than `after_days`.
    pub(super) fn mark_stale(mut self, after_days: u32, now: i64) -> Self {
        self.stale = age::stale_badge(self.created_at, self.managed, after_days, now);
        self
    }

    /// The value hasn't changed in more than `days`. Never true for a
    /// certificate's backing secret, which changes with the certificate.
    fn older_than(&self, days: u32, now: i64) -> bool {
        !self.managed && age::is_stale(self.created_at, days, now)
    }
}

/// Most days the "Not changed in over" filter takes: a hundred years.
const MAX_OLDER_DAYS: u32 = 36_500;

/// List filters. All optional.
#[derive(Debug, Default, Clone, Deserialize)]
pub(super) struct SecretFilter {
    #[serde(default)]
    pub q: String,
    /// `key` or `key=value`.
    #[serde(default)]
    pub tag: String,
    /// `expiring` (within 30 days, not yet expired), `expired` or
    /// `disabled`.
    #[serde(default)]
    pub show: String,
    /// "Not changed in over N days": a whole number of days, or empty.
    #[serde(default)]
    pub older: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl SecretFilter {
    pub(super) fn is_empty(&self) -> bool {
        self.q.trim().is_empty()
            && self.tag.trim().is_empty()
            && self.show.is_empty()
            && self.older.trim().is_empty()
    }

    /// The days in the "Not changed in over" filter. `Ok(None)` when it is
    /// empty, `Err(())` when it isn't a whole number from 1 to
    /// [`MAX_OLDER_DAYS`].
    pub(super) fn older_days(&self) -> Result<Option<u32>, ()> {
        let v = self.older.trim();
        if v.is_empty() {
            return Ok(None);
        }
        v.parse::<u32>()
            .ok()
            .filter(|d| (1..=MAX_OLDER_DAYS).contains(d))
            .map(Some)
            .ok_or(())
    }

    pub(super) fn matches(&self, row: &SecretRow, now: i64) -> bool {
        if let Ok(Some(days)) = self.older_days()
            && !row.older_than(days, now)
        {
            return false;
        }
        // The same text the browser's live filter searches: the name and
        // every tag as `key=value`.
        let q = self.q.trim().to_lowercase();
        if !q.is_empty() && !row.filter_text.contains(&q) {
            return false;
        }
        let tag = self.tag.trim();
        if !tag.is_empty() {
            let (key, value) = match tag.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (tag, None),
            };
            let hit = row.tags.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case(key) && value.is_none_or(|want| v.eq_ignore_ascii_case(want))
            });
            if !hit {
                return false;
            }
        }
        match self.show.as_str() {
            "expiring" => row.expiry == ExpiryState::Soon,
            "expired" => row.expiry == ExpiryState::Expired,
            "disabled" => !row.enabled,
            _ => true,
        }
    }

    fn page_url(&self, vault: &str, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        vault_path(
            vault,
            &format!(
                "/secrets?q={}&tag={}&show={}&older={}&page={page}",
                enc(&self.q),
                enc(&self.tag),
                enc(&self.show),
                enc(self.older.trim())
            ),
        )
    }
}

pub(super) struct ShowOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "secrets/list.html")]
struct ListPage {
    shell: Shell,
    vault: String,
    rows: Vec<SecretRow>,
    total: usize,
    expired_count: usize,
    expiring_count: usize,
    disabled_count: usize,
    /// Values unchanged past `KEYRING_STALE_AFTER_DAYS`.
    stale_count: usize,
    stale_after_days: u32,
    /// "over a year", or "over N days".
    stale_phrase: String,
    /// The "Not changed in over" filter isn't a usable number.
    older_error: bool,
    filter: SecretFilter,
    show_options: Vec<ShowOption>,
    pager: Pager,
}

/// The chosen vault, or the page to show when there isn't one.
pub(super) fn current_vault(
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
) -> Result<(String, Shell), Halt> {
    vault_ctx::path_vault(session, shell, Section::Secrets, vault)
}

pub(super) fn api<'a>(
    state: &'a AppState,
    session: &'a CurrentSession,
    vault: &str,
) -> SecretsApi<'a> {
    SecretsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

pub(super) async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(filter): Query<SecretFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let items = match api(&state, &session, &vault).list().await {
        Ok(items) => items,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ReadSecrets,
                &vault_path(&vault, "/secrets"),
            ));
        }
    };
    let now = now_ts();
    let after = state.config.stale_after_days;
    let all: Vec<SecretRow> = items
        .iter()
        .map(|i| SecretRow::from_item(i, now).mark_stale(after, now))
        .collect();
    let total = all.len();
    let stale_count = all.iter().filter(|r| !r.stale.is_empty()).count();
    let expired_count = all.iter().filter(|r| r.is_expired()).count();
    let expiring_count = all.iter().filter(|r| r.is_expiring()).count();
    let disabled_count = all.iter().filter(|r| !r.enabled).count();

    let matching: Vec<SecretRow> = all.into_iter().filter(|r| filter.matches(r, now)).collect();
    let (rows, pager) = paginate(matching, filter.page, "secrets", |p| {
        filter.page_url(&vault, p)
    });

    let show_options = [
        ("", "All secrets"),
        ("expiring", "Expiring within 30 days"),
        ("expired", "Expired"),
        ("disabled", "Disabled"),
    ]
    .into_iter()
    .map(|(value, label)| ShowOption {
        value,
        label,
        selected: filter.show == value,
    })
    .collect();

    Ok(render(&ListPage {
        pager,
        shell,
        vault,
        rows,
        total,
        expired_count,
        expiring_count,
        disabled_count,
        stale_count,
        stale_after_days: after,
        stale_phrase: age::stale_phrase(after),
        older_error: filter.older_days().is_err(),
        filter,
        show_options,
    })
    .into_response())
}

#[derive(Template)]
#[template(path = "secrets/detail.html")]
struct DetailPage {
    shell: Shell,
    vault: String,
    row: SecretRow,
    version: String,
    created: String,
    updated: String,
    not_before: String,
    /// What happens if it's deleted, in a sentence.
    recovery: String,
    used_by: crate::routes::used_by::UsedBy,
    /// What the rotation tags claim, if any are set.
    rotation: Option<crate::rotation::Rotation>,
    access: crate::routes::access::Access,
}

pub(super) async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    uri: axum::http::Uri,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let secrets = api(&state, &session, &vault);
    let (item, used_by, access) = tokio::join!(
        secrets.properties(&name),
        crate::routes::used_by::for_item(&state, &session, &vault, Kind::Secret, &name),
        crate::routes::access::for_item(&state, &session, &vault, Kind::Secret, &name),
    );
    let item = match item {
        Ok(item) => item,
        Err(err) => {
            if let Some(res) =
                crate::routes::moved::missing_item(&vault, Kind::Secret, &name, &err, &uri)
            {
                return Ok(res);
            }
            let path = vault_path(&vault, &format!("/secrets/{name}"));
            return Err(azure_problem(shell, &err, Need::ReadSecrets, &path));
        }
    };
    let now = now_ts();
    let a = &item.attributes;
    let row = SecretRow::from_item(&item, now).mark_stale(state.config.stale_after_days, now);
    Ok(render(&DetailPage {
        version: item.version().to_owned(),
        created: a.created.map(dates::format_datetime).unwrap_or_default(),
        updated: a.updated.map(dates::format_datetime).unwrap_or_default(),
        not_before: a.not_before.map(dates::format_datetime).unwrap_or_default(),
        recovery: crate::routes::lifecycle::Recovery::new(
            a.recovery_level.as_deref(),
            a.recoverable_days,
        )
        .sentence(Kind::Secret),
        rotation: crate::rotation::Rotation::from_tags(&row.tags),
        row,
        shell,
        vault,
        used_by,
        access,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, enabled: bool, expiry: ExpiryState, tags: &[(&str, &str)]) -> SecretRow {
        SecretRow {
            name: name.into(),
            enabled,
            content_type: String::new(),
            changed: String::new(),
            changed_note: String::new(),
            created_at: None,
            stale: String::new(),
            expires: String::new(),
            expires_note: String::new(),
            expiry,
            not_yet_valid: false,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            managed: false,
            filter_text: std::iter::once(name.to_lowercase())
                .chain(tags.iter().map(|(k, v)| format!("{k}={v}").to_lowercase()))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    fn f(q: &str, tag: &str, show: &str) -> SecretFilter {
        SecretFilter {
            q: q.into(),
            tag: tag.into(),
            show: show.into(),
            older: String::new(),
            page: None,
        }
    }

    #[test]
    fn filters() {
        let r = row("db-password", true, ExpiryState::Soon, &[("env", "prod")]);
        assert!(f("DB", "", "").matches(&r, 0));
        assert!(!f("api", "", "").matches(&r, 0));
        assert!(f("", "env=PROD", "").matches(&r, 0));
        assert!(!f("", "env=test", "").matches(&r, 0));
        assert!(f("", "", "expiring").matches(&r, 0));
        assert!(!f("", "", "expired").matches(&r, 0));
        assert!(!f("", "", "disabled").matches(&r, 0));
        // The search box matches tags too, as the live filter does.
        assert!(f("prod", "", "").matches(&r, 0));
        assert!(f("env=pr", "", "").matches(&r, 0));
        assert!(!f("staging", "", "").matches(&r, 0));
        let d = row("old", false, ExpiryState::Expired, &[]);
        assert!(f("", "", "disabled").matches(&d, 0));
        assert!(f("", "", "expired").matches(&d, 0));
        // "Expiring" means soon, not already expired, to match its count.
        assert!(!f("", "", "expiring").matches(&d, 0));
    }

    #[test]
    fn not_changed_in_over_n_days() {
        const DAY: i64 = 86_400;
        let now = 1_800_000_000;
        let mut r = row("old", true, ExpiryState::None, &[]);
        r.created_at = Some(now - 100 * DAY);
        let older = |days: &str| SecretFilter {
            older: days.into(),
            ..f("", "", "")
        };
        assert!(older("99").matches(&r, now));
        assert!(
            !older("100").matches(&r, now),
            "exactly 100 days isn't over"
        );
        assert!(older("").matches(&r, now));
        // A bad number filters nothing, and the page says so.
        assert!(older("abc").matches(&r, now));
        assert_eq!(older("abc").older_days(), Err(()));
        assert_eq!(older("0").older_days(), Err(()));
        assert_eq!(older("36501").older_days(), Err(()));
        assert_eq!(older(" 30 ").older_days(), Ok(Some(30)));
        // A certificate's backing secret changes with the certificate.
        r.managed = true;
        assert!(!older("99").matches(&r, now));
        assert_eq!(r.mark_stale(30, now).stale, "");
        let mut n = row("new", true, ExpiryState::None, &[]);
        n.created_at = Some(now - 400 * DAY);
        assert_eq!(n.mark_stale(365, now).stale, "Not changed in over a year");
    }
}
