//! Delete (soft), the deleted secrets list, recover and purge.
//!
//! Delete needs the secret's name typed in, checked on the server. Purge is
//! off unless `KEYRING_ALLOW_PURGE=true`; with it off the purge routes
//! refuse every request, whatever the browser sends. On a vault with purge
//! protection purge isn't offered, and is refused before Azure is asked.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::{DeletedSecretItem, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::confirm::{ConfirmForm, ConfirmView};
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::lifecycle::{self, Kind, Recovery};
use crate::routes::secrets::{api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;

const KIND: Kind = Kind::Secret;

pub struct DeletedRow {
    pub name: String,
    pub deleted: String,
    pub purge: String,
    pub purge_note: String,
    pub content_type: String,
    /// What the vault allows, from the item's recovery level.
    pub recovery: Recovery,
}

impl DeletedRow {
    fn from_item(d: &DeletedSecretItem, now: i64) -> Self {
        Self {
            name: d.name().to_owned(),
            deleted: d
                .deleted_date
                .map(dates::format_datetime)
                .unwrap_or_default(),
            purge: d
                .scheduled_purge_date
                .map(dates::format_date)
                .unwrap_or_default(),
            purge_note: d
                .scheduled_purge_date
                .map(|p| dates::relative_days(p, now))
                .unwrap_or_default(),
            content_type: d.content_type.clone().unwrap_or_default(),
            recovery: recovery_of(&d.attributes),
        }
    }
}

fn recovery_of(a: &crate::azure::secrets::Attributes) -> Recovery {
    Recovery::new(a.recovery_level.as_deref(), a.recoverable_days)
}

#[derive(Template)]
#[template(path = "secrets/deleted.html")]
struct DeletedList {
    shell: Shell,
    vault: String,
    rows: Vec<DeletedRow>,
}

#[derive(Template)]
#[template(path = "secrets/deleted_detail.html")]
struct DeletedDetail {
    shell: Shell,
    vault: String,
    row: DeletedRow,
    allow_purge: bool,
}

impl DeletedDetail {
    fn recovery_sentence(&self) -> String {
        self.row.recovery.sentence(KIND)
    }
}

/// The current version, refusing a certificate's backing secret.
async fn current(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, Recovery), Halt> {
    match api(state, session, vault).properties(name).await {
        Ok(item) if item.managed.unwrap_or(false) => {
            Err(crate::routes::secrets::reveal::managed_problem(shell, name))
        }
        Ok(item) => Ok((shell, recovery_of(&item.attributes))),
        Err(err) => {
            let path = format!("/secrets/{name}");
            Err(azure_problem(shell, &err, Need::ManageSecrets, &path))
        }
    }
}

fn delete_view(vault: &str, name: &str, recovery: Recovery) -> ConfirmView {
    lifecycle::delete_view_for(KIND, vault, name, recovery)
}

pub async fn delete_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    // Read the secret first, so a missing or certificate-owned secret gets
    // its own page, and the warning can give the vault's real retention.
    let (shell, recovery) = current(&state, &session, shell, &vault, &name).await?;
    Ok(lifecycle::confirm_page(
        shell,
        delete_view(&vault, &name, recovery),
        StatusCode::OK,
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = lifecycle::verify(
        &session,
        &vault,
        &form,
        &name,
        shell,
        delete_view(&vault, &name, Recovery::default()),
    )?;
    // Refuse a certificate's backing secret, and refuse if we can't tell.
    let (shell, recovery) = current(&state, &session, shell, &vault, &name).await?;
    match api(&state, &session, &vault).delete(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret deleted");
            Ok(lifecycle::redirect_with(
                &state,
                "/secrets",
                format!(
                    "Deleted {name}. You can recover it from deleted secrets {}.",
                    recovery.period()
                ),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/{name}"),
        )),
    }
}

pub async fn list_deleted(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let items = match api(&state, &session, &vault).list_deleted().await {
        Ok(i) => i,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                "/secrets/deleted",
            ));
        }
    };
    let now = now_ts();
    Ok(render(&DeletedList {
        rows: items
            .iter()
            .map(|d| DeletedRow::from_item(d, now))
            .collect(),
        shell,
        vault,
    })
    .into_response())
}

async fn load_deleted(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, DeletedSecretItem), Halt> {
    match api(state, session, vault).get_deleted(name).await {
        Ok(i) => Ok((shell, i)),
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            "/secrets/deleted",
        )),
    }
}

pub async fn deleted_detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, item) = load_deleted(&state, &session, shell, &vault, &name).await?;
    Ok(render(&DeletedDetail {
        row: DeletedRow::from_item(&item, now_ts()),
        allow_purge: state.config.allow_purge,
        shell,
        vault,
    })
    .into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

pub async fn recover(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = crate::routes::vault_ctx::check_csrf(&session, &vault, &form.csrf, shell)?;
    match api(&state, &session, &vault).recover(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret recovered");
            Ok(lifecycle::recovered(&state, KIND, &name))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/deleted/{name}"),
        )),
    }
}

pub async fn purge_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let shell = lifecycle::purge_allowed(&state, shell, KIND)?;
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, item) = load_deleted(&state, &session, shell, &vault, &name).await?;
    let shell = lifecycle::purge_not_protected(shell, KIND, &name, recovery_of(&item.attributes))?;
    Ok(lifecycle::confirm_page(
        shell,
        lifecycle::purge_view(KIND, &vault, &name),
        StatusCode::OK,
    ))
}

pub async fn purge(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let shell = lifecycle::purge_allowed(&state, shell, KIND)?;
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = lifecycle::verify(
        &session,
        &vault,
        &form,
        &name,
        shell,
        lifecycle::purge_view(KIND, &vault, &name),
    )?;
    let (shell, item) = load_deleted(&state, &session, shell, &vault, &name).await?;
    let shell = lifecycle::purge_not_protected(shell, KIND, &name, recovery_of(&item.attributes))?;
    match api(&state, &session, &vault).purge(&name).await {
        Ok(()) => {
            tracing::warn!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret purged");
            Ok(lifecycle::redirect_with(
                &state,
                "/secrets/deleted",
                format!("Permanently deleted {name}."),
            ))
        }
        Err(err) => Err(lifecycle::purge_problem(
            shell,
            &err,
            KIND,
            &name,
            Need::ManageSecrets,
        )),
    }
}
