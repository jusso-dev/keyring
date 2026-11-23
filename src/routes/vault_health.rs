//! Vault health: how every vault the person can see is set up, and its CSV.
//!
//! Resource Graph gives the access model, soft delete, purge protection and
//! network settings. Each vault's diagnostic settings (ARM, Reader) and its
//! secrets list (Key Vault Reader) are read through
//! [`crate::azure::fanout`]. Each vault's three lists are read once, for
//! the expiry, expiring-soon and not-cycled checks. Defender for Key Vault
//! is one Resource Graph read for every vault on the page. Certificate
//! renewal and key rotation need a call per item, so they're only read
//! when one vault is picked.

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
use crate::azure::audit::{self, AuditSinks};
use crate::azure::certs::CertsApi;
use crate::azure::defender as azure_defender;
use crate::azure::fanout::{self, reason};
use crate::azure::keys::KeysApi;
use crate::azure::secrets::now_ts;
use crate::azure::vaults::{self, Vault, is_valid_vault_name};
use crate::azure::{AzureClient, AzureError};
use crate::config::Thresholds;
use crate::defender::VaultDefender;
use crate::health::{self, Count, Finding, Kind, Lifecycle, Reads, Row, Status, lower_first};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

/// Most vaults checked on one page. More than this, and you pick.
pub(super) const MAX_VAULTS: usize = super::every_vault::MAX_VAULTS;
/// Most certificates, and most keys, given a call each in one vault.
pub(crate) const MAX_ITEM_CHECKS: usize = 200;
/// Per-item calls at once within the one vault.
const ITEM_CONCURRENCY: usize = 6;
/// Time for the per-item calls, inside the fan-out's limit for the vault.
const ITEM_DEADLINE: Duration = Duration::from_secs(15);

const ITEMS_OUT_OF_TIME: &str = "Not checked in time";

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct HealthFilter {
    /// One vault, or empty for all.
    #[serde(default)]
    pub vault: String,
}

/// Plain words for an ARM error on the diagnostic settings read. A 403
/// here is the Reader role, not a Key Vault role.
fn arm_reason(e: &AzureError) -> String {
    match e {
        AzureError::Status { status: 403, .. } => {
            "You don't have Reader on it, which is needed to see its diagnostic settings".into()
        }
        AzureError::Unreadable => "Its resource ID isn't one Keyring will use".into(),
        other => reason(other),
    }
}

/// Run `check` on each name, a few at a time, until [`ITEM_DEADLINE`].
/// Returns how many failed the check, how many couldn't be read, and the
/// first reason one couldn't.
async fn per_item<F, Fut>(names: Vec<String>, check: F) -> Count
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<bool, AzureError>> + Send + 'static,
{
    let skipped_by_cap = names.len().saturating_sub(MAX_ITEM_CHECKS);
    let permits = Arc::new(Semaphore::new(ITEM_CONCURRENCY));
    let mut set = JoinSet::new();
    for name in names.into_iter().take(MAX_ITEM_CHECKS) {
        let work = check(name);
        let permits = permits.clone();
        set.spawn(async move {
            let _permit = permits.acquire_owned().await;
            work.await
        });
    }
    let deadline = tokio::time::Instant::now() + ITEM_DEADLINE;
    let (mut failing, mut unread) = (0, skipped_by_cap);
    let mut why: Option<String> = (skipped_by_cap > 0)
        .then(|| format!("Keyring checks the first {MAX_ITEM_CHECKS} in a vault"));
    loop {
        match tokio::time::timeout_at(deadline, set.join_next()).await {
            Ok(Some(Ok(Ok(true)))) => failing += 1,
            Ok(Some(Ok(Ok(false)))) => {}
            Ok(Some(Ok(Err(e)))) => {
                unread += 1;
                why.get_or_insert_with(|| reason(&e));
            }
            Ok(Some(Err(_))) => {
                unread += 1;
                why.get_or_insert_with(|| "Keyring hit a problem reading it".into());
            }
            Ok(None) => break,
            Err(_) => {
                unread += set.len();
                set.abort_all();
                why.get_or_insert_with(|| ITEMS_OUT_OF_TIME.into());
                break;
            }
        }
    }
    Count::Read {
        failing,
        unread,
        unread_why: why.unwrap_or_default(),
    }
}

/// Everything read from one vault besides Resource Graph. Failures are
/// kept in the result as reasons, so the fan-out only skips a vault that
/// ran out of time. The vault's three lists are read once and used for
/// every check that needs them.
async fn read_vault(
    azure: AzureClient,
    session: Arc<Session>,
    vault: String,
    urls: (String, String, String),
    per_item_checks: bool,
    thresholds: Thresholds,
) -> (Reads, Option<String>) {
    let (management_url, vault_url, vault_id) = urls;
    let (sinks, lists) = tokio::join!(
        audit::audit_sinks(&azure, &session, &management_url, &vault_id),
        every_vault::read_lists(&azure, &session, vault_url.clone()),
    );
    let audit = sinks.map_err(|e| arm_reason(&e));
    let secrets_without_expiry = match &lists.secrets {
        Ok(list) => Count::all_read(
            list.iter()
                .filter(|s| !s.managed.unwrap_or(false))
                .filter(|s| s.attributes.is_enabled() && s.attributes.expires.is_none())
                .count(),
        ),
        Err(e) => Count::Failed(reason(e)),
    };
    let (items, failed) = every_vault::items_of(&vault, &lists);
    let lifecycle = if failed.len() == 3 {
        Err(reason(failed[0].1))
    } else {
        let partly = (!failed.is_empty()).then(|| {
            let kinds: Vec<&str> = failed.iter().map(|(k, _)| *k).collect();
            format!(
                "Its {} couldn't be read: {}",
                kinds.join(" and "),
                lower_first(&reason(failed[0].1))
            )
        });
        Ok(Lifecycle::of(&items, thresholds, partly, now_ts()))
    };
    let (certs_not_renewing, keys_without_rotation) = if per_item_checks {
        let cert_names = lists.certs.as_ref().map(|list| {
            list.iter()
                .filter(|c| c.attributes.is_enabled())
                .map(|c| c.name().to_owned())
                .filter(|n| crate::routes::vault_ctx::is_valid_object_name(n))
                .collect::<Vec<_>>()
        });
        let key_names = lists.keys.as_ref().map(|list| {
            list.iter()
                .filter(|k| !k.managed.unwrap_or(false) && k.attributes.is_enabled())
                .map(|k| k.name().to_owned())
                .filter(|n| crate::routes::vault_ctx::is_valid_object_name(n))
                .collect::<Vec<_>>()
        });
        tokio::join!(
            certs_not_renewing(
                azure.clone(),
                session.clone(),
                vault_url.clone(),
                cert_names
            ),
            keys_without_rotation(azure.clone(), session.clone(), vault_url, key_names),
        )
    } else {
        (Count::Deferred, Count::Deferred)
    };
    (
        Reads {
            audit,
            secrets_without_expiry,
            certs_not_renewing,
            keys_without_rotation,
            lifecycle,
            // Filled in from the one Resource Graph read for every vault.
            defender: VaultDefender::default(),
            not_read: None,
        },
        None,
    )
}

/// Enabled certificates whose policy has no AutoRenew action.
async fn certs_not_renewing(
    azure: AzureClient,
    session: Arc<Session>,
    vault_url: String,
    names: Result<Vec<String>, &AzureError>,
) -> Count {
    let names = match names {
        Ok(n) => n,
        Err(e) => return Count::Failed(reason(e)),
    };
    per_item(names, |name| {
        let (azure, session, vault_url) = (azure.clone(), session.clone(), vault_url.clone());
        async move {
            let api = CertsApi {
                azure: &azure,
                session: &session,
                vault_url,
            };
            let policy = api.policy(&name).await?;
            Ok(!policy
                .lifetime_actions
                .iter()
                .any(|a| a.action.action_type.eq_ignore_ascii_case("AutoRenew")))
        }
    })
    .await
}

/// Enabled keys, other than a certificate's own, with no Rotate action.
async fn keys_without_rotation(
    azure: AzureClient,
    session: Arc<Session>,
    vault_url: String,
    names: Result<Vec<String>, &AzureError>,
) -> Count {
    let names = match names {
        Ok(n) => n,
        Err(e) => return Count::Failed(reason(e)),
    };
    per_item(names, |name| {
        let (azure, session, vault_url) = (azure.clone(), session.clone(), vault_url.clone());
        async move {
            let api = KeysApi {
                azure: &azure,
                session: &session,
                vault_url,
            };
            let policy = api.rotation_policy(&name).await?;
            Ok(policy.rotate_at().is_none())
        }
    })
    .await
}

struct Loaded {
    rows: Vec<Row>,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    per_item_checks: bool,
}

async fn load(
    state: &AppState,
    session: &CurrentSession,
    filter: &HealthFilter,
) -> Result<Loaded, AzureError> {
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    // Vault names are unique across Azure; keep the first of any repeat.
    let mut by_name: HashMap<String, Vault> = HashMap::new();
    for v in all {
        if is_valid_vault_name(&v.name) {
            by_name.entry(v.name.clone()).or_insert(v);
        }
    }
    let mut vault_names: Vec<String> = by_name.keys().cloned().collect();
    vault_names.sort();
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
    let per_item_checks = !filter.vault.is_empty();
    let ids: HashMap<String, String> = wanted
        .iter()
        .map(|n| (n.clone(), by_name[n].id.clone()))
        .collect();
    let thresholds = state.config.thresholds();
    let (read, defender) = tokio::join!(
        fanout::read_each(wanted.clone(), |vault| {
            let urls = (
                state.config.management_url.clone(),
                state.config.vault_url(&vault),
                ids.get(&vault).cloned().unwrap_or_default(),
            );
            read_vault(
                state.azure.clone(),
                session.0.clone(),
                vault,
                urls,
                per_item_checks,
                thresholds,
            )
        }),
        azure_defender::read(&state.azure, &session.0, &state.config.management_url),
    );
    let mut reads: HashMap<String, Reads> = read.read.into_iter().collect();
    for s in read.skipped {
        reads.insert(s.vault.clone(), Reads::none(&s.reason));
    }
    let rows = wanted
        .iter()
        .map(|n| {
            let v = &by_name[n];
            let mut r = reads
                .remove(n)
                .unwrap_or_else(|| Reads::none(fanout::TASK_FAILED));
            r.defender = defender.for_vault(&v.name, &v.subscription_id);
            Row::new(v, &r)
        })
        .collect();
    Ok(Loaded {
        rows,
        vault_names,
        capped,
        unknown_vault,
        per_item_checks,
    })
}

/// A finding to look into, for the list under the table.
pub(super) struct Issue {
    pub vault: String,
    pub finding: Finding,
}

#[derive(Template)]
#[template(path = "vault_health.html")]
struct HealthPage {
    shell: Shell,
    rows: Vec<Row>,
    issues: Vec<Issue>,
    kinds: [Kind; 13],
    warnings: usize,
    unknowns: usize,
    vault_names: Vec<String>,
    capped: bool,
    unknown_vault: bool,
    per_item_checks: bool,
    filter: HealthFilter,
    csv_url: String,
    max_vaults: usize,
    max_item_checks: usize,
    expiry_warn_days: u32,
    stale_after_days: u32,
}

fn csv_url(filter: &HealthFilter) -> String {
    format!(
        "/vault-health.csv?vault={}",
        crate::auth::return_to::encode(&filter.vault)
    )
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<HealthFilter>,
) -> PageResult {
    let shell = shell.at(Section::Health);
    let loaded = match load(&state, &session, &filter).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/vault-health"),
            )
            .into());
        }
    };
    let issues: Vec<Issue> = loaded
        .rows
        .iter()
        .flat_map(|r| {
            r.findings
                .iter()
                .filter(|f| f.status != Status::Pass && !f.deferred)
                .map(|f| Issue {
                    vault: r.vault.clone(),
                    finding: f.clone(),
                })
        })
        .collect();
    let count = |s: Status| issues.iter().filter(|i| i.finding.status == s).count();
    Ok(render(&HealthPage {
        warnings: count(Status::Warn),
        unknowns: count(Status::Unknown),
        csv_url: csv_url(&filter),
        shell,
        rows: loaded.rows,
        issues,
        kinds: Kind::ALL,
        vault_names: loaded.vault_names,
        capped: loaded.capped,
        unknown_vault: loaded.unknown_vault,
        per_item_checks: loaded.per_item_checks,
        filter,
        max_vaults: MAX_VAULTS,
        max_item_checks: MAX_ITEM_CHECKS,
        expiry_warn_days: state.config.expiry_warn_days,
        stale_after_days: state.config.stale_after_days,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<HealthFilter>,
) -> PageResult {
    let loaded = match load(&state, &session, &filter).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell.at(Section::Health),
                Problem::from_azure(&e, Need::ListVaults),
            )
            .into());
        }
    };
    let mut body = health::to_csv(&loaded.rows);
    // The export says what it leaves out, so it can't pass for a full report.
    if loaded.unknown_vault {
        body.push_str(&health::not_read_row(
            &filter.vault,
            "Not in the list of vaults you can see",
        ));
    }
    if loaded.capped {
        body.push_str(&health::not_read_row(
            "",
            &format!(
                "Only the first {MAX_VAULTS} of {} vaults by name were checked. Filter by vault to export others",
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
        HeaderValue::from_static("attachment; filename=\"keyring-vault-health.csv\""),
    );
    Ok(no_store(res))
}

/// The audit log column on the vault list: read the diagnostic settings of
/// the vaults on the page, with a short deadline so the list stays quick.
/// A vault missing from the result wasn't checked.
pub(super) async fn audit_status(
    state: &AppState,
    session: &CurrentSession,
    shown: &[Vault],
) -> HashMap<String, Result<AuditSinks, String>> {
    let ids: HashMap<String, String> = shown
        .iter()
        .map(|v| (v.name.clone(), v.id.clone()))
        .collect();
    let limits = fanout::Limits {
        vault_timeout: LIST_AUDIT_TIMEOUT,
        deadline: LIST_AUDIT_DEADLINE,
        ..fanout::Limits::STANDARD
    };
    let read = fanout::read_each_within(
        shown.iter().map(|v| v.name.clone()),
        |vault| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.management_url.clone();
            let id = ids.get(&vault).cloned().unwrap_or_default();
            async move {
                let r = audit::audit_sinks(&azure, &sess, &url, &id)
                    .await
                    .map_err(|e| arm_reason(&e));
                (r, None)
            }
        },
        limits,
    )
    .await;
    read.read.into_iter().collect()
}

/// Each diagnostic settings read on the vault list.
pub(super) const LIST_AUDIT_TIMEOUT: Duration = Duration::from_secs(5);
/// All of them. Vaults not read by then show "Not checked".
pub(super) const LIST_AUDIT_DEADLINE: Duration = Duration::from_secs(10);
