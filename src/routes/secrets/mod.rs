//! Secrets pages: list, search and detail.

pub mod delete;
pub mod edit;
pub mod form;
pub mod reveal;
pub mod versions;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::{ExpiryState, SecretItem, SecretsApi, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx;
pub use crate::routes::vault_ctx::{azure_problem, checked_name};

/// Secrets shown per page of the list.
pub const PER_PAGE: usize = 100;

/// One row in the list, ready to show.
pub struct SecretRow {
    pub name: String,
    pub enabled: bool,
    pub content_type: String,
    pub updated: String,
    pub expires: String,
    pub expires_note: String,
    pub expiry: ExpiryState,
    pub not_yet_valid: bool,
    pub tags: Vec<(String, String)>,
    pub managed: bool,
    pub filter_text: String,
}

impl SecretRow {
    pub fn from_item(item: &SecretItem, now: i64) -> Self {
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
            updated: a.updated.map(dates::format_date).unwrap_or_default(),
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

    pub fn is_expired(&self) -> bool {
        self.expiry == ExpiryState::Expired
    }

    pub fn is_expiring(&self) -> bool {
        self.expiry == ExpiryState::Soon
    }
}

/// List filters. All optional.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SecretFilter {
    #[serde(default)]
    pub q: String,
    /// `key` or `key=value`.
    #[serde(default)]
    pub tag: String,
    /// `expiring`, `expired` or `disabled`.
    #[serde(default)]
    pub show: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl SecretFilter {
    pub fn is_empty(&self) -> bool {
        self.q.trim().is_empty() && self.tag.trim().is_empty() && self.show.is_empty()
    }

    pub fn matches(&self, row: &SecretRow) -> bool {
        let q = self.q.trim().to_lowercase();
        if !q.is_empty() && !row.name.to_lowercase().contains(&q) {
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
            "expiring" => matches!(row.expiry, ExpiryState::Soon | ExpiryState::Expired),
            "expired" => row.expiry == ExpiryState::Expired,
            "disabled" => !row.enabled,
            _ => true,
        }
    }

    fn page_url(&self, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/secrets?q={}&tag={}&show={}&page={page}",
            enc(&self.q),
            enc(&self.tag),
            enc(&self.show)
        )
    }
}

pub struct ShowOption {
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
    filter: SecretFilter,
    show_options: Vec<ShowOption>,
    page: usize,
    pages: usize,
    shown_from: usize,
    prev_url: Option<String>,
    next_url: Option<String>,
}

/// The chosen vault, or the page to show when there isn't one.
pub fn current_vault(session: &CurrentSession, shell: Shell) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, Section::Secrets)
}

pub fn api<'a>(state: &'a AppState, session: &'a CurrentSession, vault: &str) -> SecretsApi<'a> {
    SecretsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

pub async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<SecretFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let items = match api(&state, &session, &vault).list().await {
        Ok(items) => items,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, "/secrets")),
    };
    let now = now_ts();
    let all: Vec<SecretRow> = items.iter().map(|i| SecretRow::from_item(i, now)).collect();
    let total = all.len();
    let expired_count = all.iter().filter(|r| r.is_expired()).count();
    let expiring_count = all.iter().filter(|r| r.is_expiring()).count();
    let disabled_count = all.iter().filter(|r| !r.enabled).count();

    let matching: Vec<SecretRow> = all.into_iter().filter(|r| filter.matches(r)).collect();
    let pages = matching.len().div_ceil(PER_PAGE).max(1);
    let page = filter.page.unwrap_or(1).clamp(1, pages);
    let shown_from = (page - 1) * PER_PAGE;
    let rows: Vec<SecretRow> = matching
        .into_iter()
        .skip(shown_from)
        .take(PER_PAGE)
        .collect();

    let show_options = [
        ("", "All secrets"),
        ("expiring", "Expired or expiring within 30 days"),
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
        prev_url: (page > 1).then(|| filter.page_url(page - 1)),
        next_url: (page < pages).then(|| filter.page_url(page + 1)),
        shell,
        vault,
        rows,
        total,
        expired_count,
        expiring_count,
        disabled_count,
        filter,
        show_options,
        page,
        pages,
        shown_from,
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
}

pub async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let item = match api(&state, &session, &vault).properties(&name).await {
        Ok(item) => item,
        Err(err) => {
            let path = format!("/secrets/{name}");
            return Err(azure_problem(shell, &err, Need::ReadSecrets, &path));
        }
    };
    let now = now_ts();
    let a = &item.attributes;
    Ok(render(&DetailPage {
        version: item.version().to_owned(),
        created: a.created.map(dates::format_datetime).unwrap_or_default(),
        updated: a.updated.map(dates::format_datetime).unwrap_or_default(),
        not_before: a.not_before.map(dates::format_datetime).unwrap_or_default(),
        recovery: crate::routes::lifecycle::Recovery::new(
            a.recovery_level.as_deref(),
            a.recoverable_days,
        )
        .sentence(crate::routes::lifecycle::Kind::Secret),
        row: SecretRow::from_item(&item, now),
        shell,
        vault,
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
            updated: String::new(),
            expires: String::new(),
            expires_note: String::new(),
            expiry,
            not_yet_valid: false,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            managed: false,
            filter_text: String::new(),
        }
    }

    fn f(q: &str, tag: &str, show: &str) -> SecretFilter {
        SecretFilter {
            q: q.into(),
            tag: tag.into(),
            show: show.into(),
            page: None,
        }
    }

    #[test]
    fn filters() {
        let r = row("db-password", true, ExpiryState::Soon, &[("env", "prod")]);
        assert!(f("DB", "", "").matches(&r));
        assert!(!f("api", "", "").matches(&r));
        assert!(f("", "env=PROD", "").matches(&r));
        assert!(!f("", "env=test", "").matches(&r));
        assert!(f("", "", "expiring").matches(&r));
        assert!(!f("", "", "expired").matches(&r));
        assert!(!f("", "", "disabled").matches(&r));
        let d = row("old", false, ExpiryState::Expired, &[]);
        assert!(f("", "", "disabled").matches(&d));
        assert!(f("", "", "expired").matches(&d));
        assert!(f("", "", "expiring").matches(&d));
    }
}
