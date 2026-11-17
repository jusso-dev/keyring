//! Expiry dashboard across vaults, and its CSV export.
//!
//! Vaults are read through [`crate::azure::fanout`], by way of
//! [`super::every_vault`]: a few at a time, each with its own time limit,
//! and the whole read within a deadline, so the page always comes back with
//! what it found. Vaults that can't be read, or weren't reached in time,
//! are listed with the reason. Lists read in the last minute, by this page
//! or by search, are reused.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::fanout::Skipped;
use crate::azure::secrets::now_ts;
use crate::expiry::{self, Group, Item, ItemType};
use crate::rotation::Rotation;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault::{self, MAX_VAULTS};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct ExpiryFilter {
    /// One vault, or empty for all.
    #[serde(default)]
    pub vault: String,
    /// `secret`, `certificate`, `key` or empty.
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: String,
    /// A group slug, or empty for all.
    #[serde(default)]
    pub group: String,
}

impl ExpiryFilter {
    fn matches(&self, i: &Item, now: i64) -> bool {
        if !self.kind.is_empty() && i.kind.slug() != self.kind {
            return false;
        }
        if !self.group.is_empty() && i.group(now).slug() != self.group {
            return false;
        }
        i.has_tag(&self.tag)
    }

    fn query(&self) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "vault={}&type={}&tag={}&group={}",
            enc(&self.vault),
            enc(&self.kind),
            enc(&self.tag),
            enc(&self.group)
        )
    }
}

pub(super) struct Loaded {
    pub items: Vec<Item>,
    pub skipped: Vec<Skipped>,
    pub vault_names: Vec<String>,
    pub capped: bool,
    /// The vault filter names a vault that isn't in the list.
    pub unknown_vault: bool,
}

/// Every vault's items, or the one in `vault`, for this page and the age
/// view.
pub(super) async fn load(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
) -> Result<Loaded, AzureError> {
    let chosen = every_vault::choose(state, session, vault).await?;
    let read = every_vault::read(state, session, chosen.wanted).await;
    // Secrets and keys that back a certificate expire and change with it,
    // so only the certificate is listed.
    let items = read
        .read
        .iter()
        .flat_map(|(_, v)| v.iter())
        .filter(|i| !i.managed)
        .cloned()
        .collect();
    Ok(Loaded {
        items,
        skipped: read.skipped,
        vault_names: chosen.vault_names,
        capped: chosen.capped,
        unknown_vault: chosen.unknown_vault,
    })
}

pub(super) struct GroupView {
    pub group: Group,
    pub count: usize,
    pub rows: Vec<RowView>,
}

pub(super) struct RowView {
    pub vault: String,
    pub kind: ItemType,
    pub name: String,
    pub enabled: bool,
    pub expires: String,
    pub note: String,
    pub tags: String,
}

/// A secret whose `rotation-status` tag says `failed`.
pub(super) struct FailedView {
    pub vault: String,
    pub name: String,
    pub rotation: Rotation,
}

#[derive(Template)]
#[template(path = "expiry.html")]
struct ExpiryPage {
    shell: Shell,
    groups: Vec<GroupView>,
    failed: Vec<FailedView>,
    total: usize,
    skipped: Vec<Skipped>,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    filter: ExpiryFilter,
    csv_url: String,
    max_vaults: usize,
    /// Suggestions for the tag filter, from the items read.
    tag_options: Vec<String>,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<ExpiryFilter>,
) -> PageResult {
    let shell = shell.at(Section::Expiry);
    let loaded = match load(&state, &session, &filter.vault).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/expiry"),
            )
            .into());
        }
    };
    let now = now_ts();
    let tag_options = crate::routes::tag_rows::filter_options_of(&loaded.items);
    let mut items: Vec<Item> = loaded
        .items
        .into_iter()
        .filter(|i| filter.matches(i, now))
        .collect();
    expiry::sort(&mut items);
    let counts = expiry::counts(&items, now);
    let total = items.len();
    // From the tags the list calls already gave: no extra reads.
    let failed = items
        .iter()
        .filter(|i| i.kind == ItemType::Secret)
        .filter_map(|i| {
            let rotation = Rotation::from_tags(&i.tags).filter(Rotation::failed)?;
            Some(FailedView {
                vault: i.vault.clone(),
                name: i.name.clone(),
                rotation,
            })
        })
        .collect();
    let groups = Group::ALL
        .iter()
        .enumerate()
        .map(|(idx, g)| GroupView {
            group: *g,
            count: counts[idx],
            rows: items
                .iter()
                .filter(|i| i.group(now) == *g)
                .map(|i| RowView {
                    vault: i.vault.clone(),
                    kind: i.kind,
                    name: i.name.clone(),
                    enabled: i.enabled,
                    expires: i.expires_text(),
                    note: i.expires_note(now),
                    tags: i.tags_text(),
                })
                .collect(),
        })
        .collect();
    Ok(render(&ExpiryPage {
        csv_url: format!("/expiry.csv?{}", filter.query()),
        shell,
        groups,
        failed,
        total,
        skipped: loaded.skipped,
        vault_names: loaded.vault_names,
        capped: loaded.capped,
        unknown_vault: loaded.unknown_vault,
        filter,
        max_vaults: MAX_VAULTS,
        tag_options,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<ExpiryFilter>,
) -> PageResult {
    let loaded = match load(&state, &session, &filter.vault).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell.at(Section::Expiry),
                Problem::from_azure(&e, Need::ListVaults),
            )
            .into());
        }
    };
    let now = now_ts();
    let mut items: Vec<Item> = loaded
        .items
        .into_iter()
        .filter(|i| filter.matches(i, now))
        .collect();
    expiry::sort(&mut items);
    let mut body = expiry::to_csv(&items, now);
    // The export says what it leaves out, so it can't pass for a full report.
    if loaded.unknown_vault {
        body.push_str(&expiry::not_read_row(
            &filter.vault,
            "Not in the list of vaults you can see",
        ));
    }
    for s in &loaded.skipped {
        body.push_str(&expiry::not_read_row(&s.vault, &s.reason));
    }
    if loaded.capped {
        body.push_str(&expiry::not_read_row(
            "",
            &format!(
                "Only the first {MAX_VAULTS} of {} vaults by name were read. Filter by vault to export others",
                loaded.vault_names.len()
            ),
        ));
    }
    let mut res: Response = (StatusCode::OK, body).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"keyring-expiry.csv\""),
    );
    Ok(no_store(res))
}

#[cfg(test)]
mod tests {
    use crate::azure::fanout::{DEADLINE, VAULT_TIMEOUT};
    use std::time::Duration;

    #[test]
    fn deadline_sits_well_inside_the_request_limit() {
        assert!(DEADLINE + Duration::from_secs(20) <= crate::routes::headers::REQUEST_TIMEOUT);
        assert!(VAULT_TIMEOUT < DEADLINE);
    }
}
