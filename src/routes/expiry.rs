//! Expiry dashboard across vaults, and its CSV export.
//!
//! Vaults are read in parallel, a few at a time, each with its own time
//! limit, so one slow or throttled vault doesn't hold up the rest. The
//! whole read also has a deadline, well inside the request limit, so the
//! page always comes back with what it found. Vaults that can't be read,
//! or weren't reached in time, are listed with the reason.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::auth::session::Session;
use crate::azure::certs::CertsApi;
use crate::azure::keys::KeysApi;
use crate::azure::secrets::{SecretsApi, now_ts};
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::azure::{AzureClient, AzureError};
use crate::expiry::{self, Group, Item, ItemType};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

/// Vaults read at the same time.
pub(super) const CONCURRENCY: usize = 6;
/// Most vaults read for one dashboard. More than this, and you pick.
pub(super) const MAX_VAULTS: usize = 100;
/// Time limit for reading one vault.
pub(super) const VAULT_TIMEOUT: Duration = Duration::from_secs(20);
/// Time limit for the whole dashboard. Well under the 90 second request
/// limit in `routes::headers`, so there is time left to build the page.
pub(super) const DEADLINE: Duration = Duration::from_secs(60);

/// Why a vault not finished by [`DEADLINE`] is missing.
const OUT_OF_TIME: &str = "Not read in time. The dashboard stops after a minute so it can show what it has. Pick this vault on its own to see it";
/// Why a vault whose read failed inside Keyring is missing.
const TASK_FAILED: &str = "Keyring hit a problem reading it";

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

/// A vault that couldn't be read, and why in plain words.
pub(super) struct Skipped {
    pub vault: String,
    pub reason: String,
}

fn reason(err: &AzureError) -> String {
    match err {
        AzureError::Status {
            status: 403, code, ..
        } if code
            .as_deref()
            .is_some_and(|c| c == "ForbiddenByFirewall" || c == "ForbiddenByConnection") =>
        {
            "Blocked by the vault's firewall".into()
        }
        AzureError::Status { status: 403, .. } => "You don't have a Key Vault role on it".into(),
        AzureError::Status { status: 429, .. } => {
            "Azure was throttling requests. Try again in a minute".into()
        }
        AzureError::Network(_) => {
            "Couldn't reach it. It may only be reachable on a private network".into()
        }
        AzureError::Token(_) => "Sign-in needs refreshing".into(),
        _ => "Azure returned an error".into(),
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
) -> (Vec<Item>, Option<Skipped>) {
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
    let (s, c, k) = match tokio::time::timeout(VAULT_TIMEOUT, work).await {
        Ok(r) => r,
        Err(_) => {
            let reason = "Took too long to answer".into();
            return (Vec::new(), Some(Skipped { vault, reason }));
        }
    };
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
    let skipped = match failed.as_slice() {
        [] => None,
        [(_, e), _, _] => Some(Skipped {
            vault,
            reason: reason(e),
        }),
        some => {
            let kinds: Vec<&str> = some.iter().map(|(k, _)| *k).collect();
            Some(Skipped {
                reason: format!(
                    "Its {} couldn't be read ({}). The rest is included",
                    kinds.join(" and "),
                    lower_first(&reason(&some[0].1))
                ),
                vault,
            })
        }
    };
    (items, skipped)
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
    let limit = Arc::new(Semaphore::new(CONCURRENCY));
    let reads = wanted.into_iter().map(|vault| {
        let limit = limit.clone();
        let azure = state.azure.clone();
        let sess = session.0.clone();
        let url = state.config.vault_url(&vault);
        let name = vault.clone();
        let read = async move {
            let _permit = limit.acquire_owned().await;
            read_vault(azure, sess, url, vault).await
        };
        (name, read)
    });
    let (items, skipped) = gather(reads, DEADLINE).await;
    Ok(Loaded {
        items,
        skipped,
        vault_names,
        capped,
        unknown_vault,
    })
}

/// Run each vault read as its own task and collect the results, giving up
/// on whatever is left after `deadline`. A vault whose task panicked or
/// didn't finish in time is listed as skipped, with the reason.
async fn gather<F>(
    reads: impl IntoIterator<Item = (String, F)>,
    deadline: Duration,
) -> (Vec<Item>, Vec<Skipped>)
where
    F: std::future::Future<Output = (Vec<Item>, Option<Skipped>)> + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + deadline;
    let mut set = JoinSet::new();
    // Task ID to vault name, so a task that panics or runs out of time
    // can still be reported by name.
    let mut pending: HashMap<tokio::task::Id, String> = HashMap::new();
    for (vault, read) in reads {
        let handle = set.spawn(read);
        pending.insert(handle.id(), vault);
    }
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    loop {
        let done = match tokio::time::timeout_at(deadline, set.join_next_with_id()).await {
            Ok(Some(done)) => done,
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    unfinished = pending.len(),
                    "expiry dashboard ran out of time"
                );
                set.abort_all();
                skipped.extend(pending.drain().map(|(_, vault)| Skipped {
                    vault,
                    reason: OUT_OF_TIME.into(),
                }));
                break;
            }
        };
        match done {
            Ok((id, (mut v, skip))) => {
                pending.remove(&id);
                items.append(&mut v);
                skipped.extend(skip);
            }
            Err(e) => {
                tracing::error!(error = ?e.to_string(), "expiry task failed");
                if let Some(vault) = pending.remove(&e.id()) {
                    skipped.push(Skipped {
                        vault,
                        reason: TASK_FAILED.into(),
                    });
                }
            }
        }
    }
    skipped.sort_by(|a, b| a.vault.cmp(&b.vault));
    (items, skipped)
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
    use super::*;

    fn one(vault: &str) -> (Vec<Item>, Option<Skipped>) {
        let item = Item {
            vault: vault.into(),
            kind: ItemType::Secret,
            name: "s".into(),
            enabled: true,
            expires: None,
            tags: Vec::new(),
        };
        (vec![item], None)
    }

    #[test]
    fn deadline_sits_well_inside_the_request_limit() {
        assert!(DEADLINE + Duration::from_secs(20) <= crate::routes::headers::REQUEST_TIMEOUT);
        assert!(VAULT_TIMEOUT < DEADLINE);
    }

    #[tokio::test]
    async fn slow_vaults_past_the_deadline_are_skipped_not_lost() {
        type Read = std::pin::Pin<Box<dyn Future<Output = (Vec<Item>, Option<Skipped>)> + Send>>;
        let reads: Vec<(String, Read)> = vec![
            ("kv-fast".into(), Box::pin(async { one("kv-fast") })),
            (
                "kv-slow".into(),
                Box::pin(async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    one("kv-slow")
                }),
            ),
            (
                "kv-broken".into(),
                Box::pin(async { panic!("read failed inside the task") }),
            ),
        ];
        let started = std::time::Instant::now();
        let (items, skipped) = gather(reads, Duration::from_millis(300)).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stopped at the deadline"
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].vault, "kv-fast");
        let got: Vec<(&str, &str)> = skipped
            .iter()
            .map(|s| (s.vault.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            got,
            [("kv-broken", TASK_FAILED), ("kv-slow", OUT_OF_TIME)],
            "a panic and a timeout both name the vault"
        );
    }
}
