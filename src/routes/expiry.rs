//! Expiry dashboard across vaults, and its CSV export.
//!
//! Vaults are read through [`crate::azure::fanout`]: a few at a time, each
//! with its own time limit, and the whole read within a deadline, so the
//! page always comes back with what it found. Vaults that can't be read,
//! or weren't reached in time, are listed with the reason.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::auth::session::Session;
use crate::azure::certs::CertsApi;
use crate::azure::fanout::{self, Skipped, reason};
use crate::azure::keys::KeysApi;
use crate::azure::secrets::{SecretsApi, now_ts};
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::azure::{AzureClient, AzureError};
use crate::expiry::{self, Group, Item, ItemType};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

/// Most vaults read for one dashboard. More than this, and you pick.
pub(super) const MAX_VAULTS: usize = 100;

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
        let tag = self.tag.trim();
        if !tag.is_empty() {
            let (k, v) = match tag.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (tag, None),
            };
            if !i.tags.iter().any(|(a, b)| {
                a.eq_ignore_ascii_case(k) && v.is_none_or(|v| b.eq_ignore_ascii_case(v))
            }) {
                return false;
            }
        }
        true
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

/// "You don't have..." becomes "you don't have...", leaving names like
/// "Key Vault" and "Azure" alone.
fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}

async fn read_vault(
    azure: AzureClient,
    session: Arc<Session>,
    vault_url: String,
    vault: String,
) -> (Vec<Item>, Option<String>) {
    let secrets = SecretsApi {
        azure: &azure,
        session: &session,
        vault_url: vault_url.clone(),
    };
    let certs = CertsApi {
        azure: &azure,
        session: &session,
        vault_url: vault_url.clone(),
    };
    let keys = KeysApi {
        azure: &azure,
        session: &session,
        vault_url,
    };
    let work = async { tokio::join!(secrets.list(), certs.list(), keys.list()) };
    let (s, c, k) = work.await;
    let mut items = Vec::new();
    // Which kinds failed, and why.
    let mut failed: Vec<(&'static str, AzureError)> = Vec::new();
    let tag_vec = |t: &std::collections::BTreeMap<String, String>| {
        t.iter().map(|(a, b)| (a.clone(), b.clone())).collect()
    };
    match s {
        Ok(list) => items.extend(
            list.iter()
                .filter(|x| !x.managed.unwrap_or(false))
                .map(|x| Item {
                    vault: vault.clone(),
                    kind: ItemType::Secret,
                    name: x.name().to_owned(),
                    enabled: x.attributes.is_enabled(),
                    expires: x.attributes.expires,
                    tags: tag_vec(x.tags()),
                }),
        ),
        Err(e) => failed.push(("secrets", e)),
    }
    match c {
        Ok(list) => items.extend(list.iter().map(|x| Item {
            vault: vault.clone(),
            kind: ItemType::Certificate,
            name: x.name().to_owned(),
            enabled: x.attributes.is_enabled(),
            expires: x.attributes.expires,
            tags: tag_vec(x.tags()),
        })),
        Err(e) => failed.push(("certificates", e)),
    }
    match k {
        Ok(list) => items.extend(
            list.iter()
                .filter(|x| !x.managed.unwrap_or(false))
                .map(|x| Item {
                    vault: vault.clone(),
                    kind: ItemType::Key,
                    name: x.name().to_owned(),
                    enabled: x.attributes.is_enabled(),
                    expires: x.attributes.expires,
                    tags: tag_vec(x.tags()),
                }),
        ),
        Err(e) => failed.push(("keys", e)),
    }
    // Show what could be read, and say what couldn't. With every kind
    // failing, the whole vault is listed as not read.
    let why = match failed.as_slice() {
        [] => None,
        [(_, e), _, _] => Some(reason(e)),
        some => {
            let kinds: Vec<&str> = some.iter().map(|(k, _)| *k).collect();
            Some(format!(
                "Its {} couldn't be read ({}). The rest is included",
                kinds.join(" and "),
                lower_first(&reason(&some[0].1))
            ))
        }
    };
    (items, why)
}

struct Loaded {
    items: Vec<Item>,
    skipped: Vec<Skipped>,
    vault_names: Vec<String>,
    capped: bool,
    /// The vault filter names a vault that isn't in the list.
    unknown_vault: bool,
}

async fn load(
    state: &AppState,
    session: &CurrentSession,
    filter: &ExpiryFilter,
) -> Result<Loaded, AzureError> {
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    let mut vault_names: Vec<String> = all
        .iter()
        .map(|v| v.name.clone())
        .filter(|n| is_valid_vault_name(n))
        .collect();
    vault_names.sort();
    vault_names.dedup();
    let wanted: Vec<String> = if filter.vault.is_empty() {
        vault_names.iter().take(MAX_VAULTS).cloned().collect()
    } else {
        vault_names
            .iter()
            .filter(|n| **n == filter.vault)
            .cloned()
            .collect()
    };
    let capped = filter.vault.is_empty() && vault_names.len() > MAX_VAULTS;
    let unknown_vault = !filter.vault.is_empty() && wanted.is_empty();
    let read = fanout::read_each(wanted, |vault| {
        let azure = state.azure.clone();
        let sess = session.0.clone();
        let url = state.config.vault_url(&vault);
        read_vault(azure, sess, url, vault)
    })
    .await;
    let items = read.read.into_iter().flat_map(|(_, v)| v).collect();
    let skipped = read.skipped;
    Ok(Loaded {
        items,
        skipped,
        vault_names,
        capped,
        unknown_vault,
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

#[derive(Template)]
#[template(path = "expiry.html")]
struct ExpiryPage {
    shell: Shell,
    groups: Vec<GroupView>,
    total: usize,
    skipped: Vec<Skipped>,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    filter: ExpiryFilter,
    csv_url: String,
    max_vaults: usize,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<ExpiryFilter>,
) -> PageResult {
    let shell = shell.at(Section::Expiry);
    let loaded = match load(&state, &session, &filter).await {
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
    let mut items: Vec<Item> = loaded
        .items
        .into_iter()
        .filter(|i| filter.matches(i, now))
        .collect();
    expiry::sort(&mut items);
    let counts = expiry::counts(&items, now);
    let total = items.len();
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
        total,
        skipped: loaded.skipped,
        vault_names: loaded.vault_names,
        capped: loaded.capped,
        unknown_vault: loaded.unknown_vault,
        filter,
        max_vaults: MAX_VAULTS,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<ExpiryFilter>,
) -> PageResult {
    let loaded = match load(&state, &session, &filter).await {
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
