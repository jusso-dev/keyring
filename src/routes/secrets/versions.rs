//! A secret's version history, and rolling back to an older value.
//!
//! Rollback reads the old version's value and saves it as a new version.
//! Nothing is deleted, so history is kept and the rollback can itself be
//! undone.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::{SecretItem, SetSecret, is_valid_version, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::secrets::{SecretRow, api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;

pub struct VersionRow {
    pub version: String,
    pub short: String,
    pub created: String,
    pub enabled: bool,
    pub expires: String,
    pub is_current: bool,
    pub content_type: String,
}

impl VersionRow {
    fn from_item(item: &SecretItem, is_current: bool) -> Self {
        let a = &item.attributes;
        let version = item.version().to_owned();
        Self {
            short: version.chars().take(8).collect(),
            version,
            created: a.created.map(dates::format_datetime).unwrap_or_default(),
            enabled: a.is_enabled(),
            expires: a.expires.map(dates::format_date).unwrap_or_default(),
            is_current,
            content_type: item.content_type.clone().unwrap_or_default(),
        }
    }
}

#[derive(Template)]
#[template(path = "secrets/versions.html")]
struct VersionsPage {
    shell: Shell,
    vault: String,
    row: SecretRow,
    versions: Vec<VersionRow>,
}

async fn load_versions(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    name: &str,
) -> Result<(String, Shell, String, Vec<SecretItem>), Halt> {
    let (vault, shell) = current_vault(session, shell)?;
    let (name, shell) = checked_name(name, shell)?;
    let (shell, v) = fetch_versions(state, session, shell, &vault, &name).await?;
    Ok((vault, shell, name, v))
}

/// Every version, newest first. An empty list is "not found".
async fn fetch_versions(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, Vec<SecretItem>), Halt> {
    match api(state, session, vault).versions(name).await {
        Ok(v) if !v.is_empty() => Ok((shell, v)),
        Ok(_) => Err(PageError::new(shell, Problem::not_found()).into()),
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ReadSecrets,
            &format!("/secrets/{name}/versions"),
        )),
    }
}

pub async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell, _, items) = load_versions(&state, &session, shell, &name).await?;
    let now = now_ts();
    let row = SecretRow::from_item(&items[0], now);
    let versions = items
        .iter()
        .enumerate()
        .map(|(i, item)| VersionRow::from_item(item, i == 0))
        .collect();
    Ok(render(&VersionsPage {
        shell,
        vault,
        row,
        versions,
    })
    .into_response())
}

#[derive(Template)]
#[template(path = "secrets/rollback.html")]
struct RollbackPage {
    shell: Shell,
    vault: String,
    name: String,
    target: VersionRow,
    current: VersionRow,
    /// The current expiry has passed, so the new version won't have one.
    expiry_dropped: bool,
}

/// The current version's expiry, if it hasn't passed. A new version with
/// an expiry in the past couldn't be read, so a passed one isn't copied.
fn carried_expiry(current: &SecretItem, now: i64) -> Option<i64> {
    current.attributes.expires.filter(|e| *e > now)
}

#[derive(Deserialize)]
pub struct RollbackQuery {
    #[serde(default)]
    version: String,
}

/// Find `version` in the list, refusing the current one.
fn pick<'a>(
    items: &'a [SecretItem],
    version: &str,
    shell: Shell,
    name: &str,
) -> Result<(Shell, &'a SecretItem), Halt> {
    if !is_valid_version(version) {
        return Err(PageError::new(shell, Problem::not_found()).into());
    }
    match items
        .iter()
        .position(|i| i.version().eq_ignore_ascii_case(version))
    {
        Some(0) => Err(PageError::new(
            shell,
            Problem::new(
                axum::http::StatusCode::BAD_REQUEST,
                "That's already the current version",
                "There's nothing to roll back to. Pick an older version from the history.",
            )
            .returning_to(&format!("/secrets/{name}/versions")),
        )
        .into()),
        // Key Vault won't hand out a disabled version's value.
        Some(i) if !items[i].attributes.is_enabled() => Err(PageError::new(
            shell,
            Problem::new(
                axum::http::StatusCode::BAD_REQUEST,
                "That version is disabled",
                "Key Vault won't read the value of a disabled version, so Keyring can't copy it. Pick an enabled version.",
            )
            .returning_to(&format!("/secrets/{name}/versions")),
        )
        .into()),
        Some(i) => Ok((shell, &items[i])),
        None => Err(PageError::new(shell, Problem::not_found()).into()),
    }
}

pub async fn confirm(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Query(q): Query<RollbackQuery>,
) -> PageResult {
    let (vault, shell, name, items) = load_versions(&state, &session, shell, &name).await?;
    let (shell, target) = pick(&items, &q.version, shell, &name)?;
    Ok(render(&RollbackPage {
        target: VersionRow::from_item(target, false),
        current: VersionRow::from_item(&items[0], true),
        expiry_dropped: items[0].attributes.expires.is_some()
            && carried_expiry(&items[0], now_ts()).is_none(),
        shell,
        vault,
        name,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct RollbackForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    version: String,
}

pub async fn rollback(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<RollbackForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = crate::routes::vault_ctx::check_csrf(&session, &vault, &f.csrf, shell)?;
    let (shell, items) = fetch_versions(&state, &session, shell, &vault, &name).await?;
    if items[0].managed.unwrap_or(false) {
        return Err(crate::routes::secrets::reveal::managed_problem(
            shell, &name,
        ));
    }
    let (shell, target) = pick(&items, &f.version, shell, &name)?;
    let back = format!("/secrets/{name}/versions");
    let secrets = api(&state, &session, &vault);
    let old = match secrets.get_value(&name, Some(target.version())).await {
        Ok(b) => b,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &back)),
    };
    // The new version takes the old value and content type. Enabled,
    // dates and tags come from the current version, so rolling back a
    // value doesn't also turn a disabled secret back on or bring back an
    // old expiry date. The confirm page says so.
    let current = &items[0].attributes;
    let body = SetSecret {
        value: old.value,
        content_type: old.item.content_type.clone(),
        attributes: crate::azure::secrets::Attributes {
            enabled: Some(current.is_enabled()),
            expires: carried_expiry(&items[0], now_ts()),
            not_before: current.not_before,
            ..Default::default()
        },
        tags: items[0].tags.clone(),
    };
    match secrets.set(&name, &body).await {
        Ok(new) => {
            tracing::info!(
                subject = %session.0.user.subject,
                vault = %vault,
                secret = %name,
                from_version = %target.version(),
                version = %new.version(),
                "secret rolled back"
            );
            let short: String = target.version().chars().take(8).collect();
            let mut res = Redirect::to(&back).into_response();
            let new_short: String = new.version().chars().take(8).collect();
            flash::set(
                &state,
                &mut res,
                &Flash::success(format!(
                    "Rolled back {name}. Version {new_short} is a copy of {short} and is now current. Nothing was deleted."
                )),
            );
            Ok(res)
        }
        Err(err) => Err(azure_problem(shell, &err, Need::ManageSecrets, &back)),
    }
}
