//! Age view across vaults, and its CSV export: every secret, certificate
//! and key grouped by how long since its value last changed.
//!
//! Reads the same lists as the expiry dashboard and search, through
//! [`super::every_vault`], so it shares their limits, their notes on vaults
//! not read and the session's one-minute list cache. Only list calls are
//! made, never a value. The date is the current version's `created`, which
//! Key Vault gives on the list calls (see [`crate::age`]).

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::age::{self, Band};
use crate::auth::CurrentSession;
use crate::azure::fanout::Skipped;
use crate::azure::secrets::now_ts;
use crate::dates;
use crate::expiry::{Item, ItemType};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault::MAX_VAULTS;
use crate::routes::expiry::{Loaded, load};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct AgeFilter {
    /// One vault, or empty for all.
    #[serde(default)]
    pub vault: String,
    /// `secret`, `certificate`, `key` or empty.
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: String,
    /// A band slug, or empty for all.
    #[serde(default)]
    pub band: String,
}

impl AgeFilter {
    fn matches(&self, i: &Item, now: i64) -> bool {
        (self.kind.is_empty() || i.kind.slug() == self.kind)
            && (self.band.is_empty() || Band::of(i.created, now).slug() == self.band)
            && i.has_tag(&self.tag)
    }

    fn query(&self) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "vault={}&type={}&tag={}&band={}",
            enc(&self.vault),
            enc(&self.kind),
            enc(&self.tag),
            enc(&self.band)
        )
    }
}

pub(super) struct BandView {
    pub band: Band,
    pub count: usize,
    pub rows: Vec<RowView>,
}

pub(super) struct RowView {
    pub vault: String,
    pub kind: ItemType,
    pub name: String,
    pub enabled: bool,
    pub changed: String,
    pub note: String,
    pub stale: String,
    pub tags: String,
}

#[derive(Template)]
#[template(path = "age.html")]
struct AgePage {
    shell: Shell,
    bands: Vec<BandView>,
    total: usize,
    skipped: Vec<Skipped>,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    filter: AgeFilter,
    csv_url: String,
    max_vaults: usize,
    /// Suggestions for the tag filter, from the items read.
    tag_options: Vec<String>,
}

/// The vaults' items that match, oldest value first.
fn filtered(loaded: &mut Loaded, filter: &AgeFilter, now: i64) -> Vec<Item> {
    let mut items: Vec<Item> = std::mem::take(&mut loaded.items)
        .into_iter()
        .filter(|i| filter.matches(i, now))
        .collect();
    age::sort(&mut items);
    items
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<AgeFilter>,
) -> PageResult {
    let shell = shell.at(Section::Expiry);
    let mut loaded = match load(&state, &session, &filter.vault).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/expiry/age"),
            )
            .into());
        }
    };
    let now = now_ts();
    let after = state.config.stale_after_days;
    let tag_options = crate::routes::tag_rows::filter_options_of(&loaded.items);
    let items = filtered(&mut loaded, &filter, now);
    let counts = age::counts(&items, now);
    let bands = Band::ALL
        .iter()
        .enumerate()
        .map(|(idx, b)| BandView {
            band: *b,
            count: counts[idx],
            rows: items
                .iter()
                .filter(|i| Band::of(i.created, now) == *b)
                .map(|i| RowView {
                    vault: i.vault.clone(),
                    kind: i.kind,
                    name: i.name.clone(),
                    enabled: i.enabled,
                    changed: i.created.map(dates::format_date).unwrap_or_default(),
                    note: i
                        .created
                        .map(|c| dates::relative_days(c, now))
                        .unwrap_or_default(),
                    stale: age::stale_badge(i.created, i.managed, after, now),
                    tags: i.tags_text(),
                })
                .collect(),
        })
        .collect();
    Ok(render(&AgePage {
        csv_url: format!("/expiry/age.csv?{}", filter.query()),
        shell,
        bands,
        total: items.len(),
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
    Query(filter): Query<AgeFilter>,
) -> PageResult {
    let mut loaded = match load(&state, &session, &filter.vault).await {
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
    let items = filtered(&mut loaded, &filter, now);
    let mut body = age::to_csv(&items, now);
    // The export says what it leaves out, so it can't pass for a full report.
    if loaded.unknown_vault {
        body.push_str(&age::not_read_row(
            &filter.vault,
            "Not in the list of vaults you can see",
        ));
    }
    for s in &loaded.skipped {
        body.push_str(&age::not_read_row(&s.vault, &s.reason));
    }
    if loaded.capped {
        body.push_str(&age::not_read_row(
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
        HeaderValue::from_static("attachment; filename=\"keyring-age.csv\""),
    );
    Ok(no_store(res))
}
