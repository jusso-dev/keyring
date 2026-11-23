//! Reading the lists of every vault the person can see, for the expiry
//! dashboard, the age view and search.
//!
//! Vaults are read through [`crate::azure::fanout`]. Each vault's secrets,
//! certificates and keys are list calls only: names and properties, never
//! values. A vault read in full is kept in the session for
//! [`LIST_TTL`](crate::auth::session::LIST_TTL), so a second search, or the
//! dashboard after a search, doesn't read every vault again.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{RawPathParams, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::auth::session::Session;
use crate::azure::certs::{CertItem, CertsApi};
use crate::azure::fanout::{self, Fanned, reason};
use crate::azure::keys::{KeyItem, KeysApi};
use crate::azure::secrets::{SecretItem, SecretsApi};
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::azure::{AzureClient, AzureError};
use crate::expiry::{Item, ItemType};

/// Most vaults read at once. More than this, and you pick one.
pub(super) const MAX_VAULTS: usize = 100;

/// Which vaults to read for a page.
pub(super) struct Chosen {
    /// Every vault the person can see, sorted, for the vault filter.
    pub vault_names: Vec<String>,
    /// The ones to read.
    pub wanted: Vec<String>,
    /// More than [`MAX_VAULTS`] and no vault picked, so only the first are read.
    pub capped: bool,
    /// The vault filter names a vault that isn't in the list.
    pub unknown_vault: bool,
    /// Each wanted vault's name and ARM resource ID, for pages that read
    /// through ARM (the audit reports across vaults).
    pub ids: Vec<(String, String)>,
}

/// The vaults the person can see, and which of them to read: `vault`, or
/// the first [`MAX_VAULTS`] by name when it is empty.
pub(super) async fn choose(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
) -> Result<Chosen, AzureError> {
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    let mut vault_names: Vec<String> = all
        .iter()
        .map(|v| v.name.clone())
        .filter(|n| is_valid_vault_name(n))
        .collect();
    vault_names.sort();
    vault_names.dedup();
    let wanted: Vec<String> = if vault.is_empty() {
        vault_names.iter().take(MAX_VAULTS).cloned().collect()
    } else {
        vault_names
            .iter()
            .filter(|n| *n == vault)
            .cloned()
            .collect()
    };
    let ids = wanted
        .iter()
        .filter_map(|n| {
            all.iter()
                .find(|v| v.name == *n)
                .map(|v| (n.clone(), v.id.clone()))
        })
        .collect();
    Ok(Chosen {
        ids,
        capped: vault.is_empty() && vault_names.len() > MAX_VAULTS,
        unknown_vault: !vault.is_empty() && wanted.is_empty(),
        vault_names,
        wanted,
    })
}

/// Read each vault's lists, from the session's copy when it is fresh.
pub(super) async fn read(
    state: &AppState,
    session: &CurrentSession,
    wanted: Vec<String>,
) -> Fanned<Arc<Vec<Item>>> {
    let limits = state.fanout;
    fanout::read_each_within(
        wanted,
        |vault| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.vault_url(&vault);
            async move {
                if let Some(items) = sess.cached_list(&vault) {
                    return (items, None);
                }
                let (items, why) = read_vault(&azure, &sess, url, &vault).await;
                // Only a vault read in full is kept, so one that failed is
                // asked again next time.
                if why.is_none() {
                    sess.keep_list(&vault, items.clone());
                }
                (Arc::new(items), why)
            }
        },
        limits,
    )
    .await
}

/// Read only each vault's secret list (or reuse the full cached list when
/// fresh), so an unrelated certificate or key RBAC denial never hides a
/// vault's secrets on the Environments comparison matrix.
pub(super) async fn read_secrets(
    state: &AppState,
    session: &CurrentSession,
    wanted: Vec<String>,
) -> Fanned<Arc<Vec<Item>>> {
    let limits = state.fanout;
    fanout::read_each_within(
        wanted,
        |vault| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.vault_url(&vault);
            async move {
                if let Some(items) = sess.cached_list(&vault) {
                    return (items, None);
                }
                let secrets = SecretsApi {
                    azure: &azure,
                    session: &sess,
                    vault_url: url,
                };
                match secrets.list().await {
                    Ok(list) => {
                        let items = list
                            .iter()
                            .map(|x| Item {
                                vault: vault.clone(),
                                kind: ItemType::Secret,
                                name: x.name().to_owned(),
                                enabled: x.attributes.is_enabled(),
                                expires: x.attributes.expires,
                                not_before: x.attributes.not_before,
                                created: x.attributes.created,
                                content_type: x.content_type.clone().unwrap_or_default(),
                                managed: x.managed.unwrap_or(false),
                                tags: tag_vec(x.tags()),
                            })
                            .collect();
                        (Arc::new(items), None)
                    }
                    Err(e) => (Arc::new(Vec::new()), Some(reason(&e))),
                }
            }
        },
        limits,
    )
    .await
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

fn tag_vec(t: &BTreeMap<String, String>) -> Vec<(String, String)> {
    t.iter().map(|(a, b)| (a.clone(), b.clone())).collect()
}

async fn read_vault(
    azure: &AzureClient,
    session: &Session,
    vault_url: String,
    vault: &str,
) -> (Vec<Item>, Option<String>) {
    let lists = read_lists(azure, session, vault_url).await;
    let (items, failed) = items_of(vault, &lists);
    (items, failed_reason(&failed))
}

/// One vault's three list calls, made together.
pub(super) struct Lists {
    pub secrets: Result<Vec<SecretItem>, AzureError>,
    pub certs: Result<Vec<CertItem>, AzureError>,
    pub keys: Result<Vec<KeyItem>, AzureError>,
}

pub(super) async fn read_lists(azure: &AzureClient, session: &Session, vault_url: String) -> Lists {
    let secrets = SecretsApi {
        azure,
        session,
        vault_url: vault_url.clone(),
    };
    let certs = CertsApi {
        azure,
        session,
        vault_url: vault_url.clone(),
    };
    let keys = KeysApi {
        azure,
        session,
        vault_url,
    };
    let (secrets, certs, keys) = tokio::join!(secrets.list(), certs.list(), keys.list());
    Lists {
        secrets,
        certs,
        keys,
    }
}

/// The items in `lists`, and which kinds couldn't be read, and why.
pub(super) fn items_of<'a>(
    vault: &str,
    lists: &'a Lists,
) -> (Vec<Item>, Vec<(&'static str, &'a AzureError)>) {
    let mut items = Vec::new();
    let mut failed = Vec::new();
    match &lists.secrets {
        Ok(list) => items.extend(list.iter().map(|x| Item {
            vault: vault.to_owned(),
            kind: ItemType::Secret,
            name: x.name().to_owned(),
            enabled: x.attributes.is_enabled(),
            expires: x.attributes.expires,
            not_before: x.attributes.not_before,
            created: x.attributes.created,
            content_type: x.content_type.clone().unwrap_or_default(),
            managed: x.managed.unwrap_or(false),
            tags: tag_vec(x.tags()),
        })),
        Err(e) => failed.push(("secrets", e)),
    }
    match &lists.certs {
        // The list call doesn't give a certificate's content type.
        Ok(list) => items.extend(list.iter().map(|x| Item {
            vault: vault.to_owned(),
            kind: ItemType::Certificate,
            name: x.name().to_owned(),
            enabled: x.attributes.is_enabled(),
            expires: x.attributes.expires,
            not_before: x.attributes.not_before,
            created: x.attributes.created,
            content_type: String::new(),
            managed: false,
            tags: tag_vec(x.tags()),
        })),
        Err(e) => failed.push(("certificates", e)),
    }
    match &lists.keys {
        Ok(list) => items.extend(list.iter().map(|x| Item {
            vault: vault.to_owned(),
            kind: ItemType::Key,
            name: x.name().to_owned(),
            enabled: x.attributes.is_enabled(),
            expires: x.attributes.expires,
            not_before: x.attributes.not_before,
            created: x.attributes.created,
            content_type: String::new(),
            managed: x.managed.unwrap_or(false),
            tags: tag_vec(x.tags()),
        })),
        Err(e) => failed.push(("keys", e)),
    }
    (items, failed)
}

/// Show what could be read, and say what couldn't. With every kind
/// failing, the whole vault is listed as not read.
pub(super) fn failed_reason(failed: &[(&'static str, &AzureError)]) -> Option<String> {
    match failed {
        [] => None,
        [(_, e), _, _] => Some(reason(e)),
        some => {
            let kinds: Vec<&str> = some.iter().map(|(k, _)| *k).collect();
            Some(format!(
                "Its {} couldn't be read ({}). The rest is included",
                kinds.join(" and "),
                lower_first(&reason(some[0].1))
            ))
        }
    }
}

/// Middleware on the vault pages: a form posted to a vault drops that
/// vault's kept list, so search and the dashboard show the change straight
/// away rather than up to a minute later. Dropped again once the change is
/// made, in case a search in another tab read the vault in between.
pub(super) async fn forget_on_change(params: RawPathParams, req: Request, next: Next) -> Response {
    let changes = !matches!(*req.method(), Method::GET | Method::HEAD);
    let target = req.extensions().get::<CurrentSession>().cloned().zip(
        params
            .iter()
            .find(|(k, _)| *k == "vault")
            .map(|(_, v)| v.to_owned()),
    );
    let Some((session, vault)) = target.filter(|_| changes) else {
        return next.run(req).await;
    };
    session.0.forget_list(&vault);
    let res = next.run(req).await;
    session.0.forget_list(&vault);
    res
}
