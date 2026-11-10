//! Delete, deleted list, recover and purge for keys.

use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::now_ts;
use crate::routes::confirm::ConfirmForm;
use crate::routes::error::{Need, PageResult};
use crate::routes::lifecycle::{self, DeletedRow, Kind};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name};

use super::{api, current_vault, unmanaged_key};

const KIND: Kind = Kind::Key;

pub async fn delete_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    Ok(lifecycle::confirm_page(
        shell,
        lifecycle::delete_view(KIND, &vault, &name),
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
        &form,
        &name,
        shell,
        lifecycle::delete_view(KIND, &vault, &name),
    )?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    match api(&state, &session, &vault).delete(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key deleted");
            Ok(lifecycle::redirect_with(
                &state,
                "/keys",
                format!("Deleted {name}. You can recover it from deleted keys."),
            ))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageKeys,
            &format!("/keys/{name}"),
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
        Err(e) => {
            return Err(azure_problem(shell, &e, Need::ManageKeys, "/keys/deleted"));
        }
    };
    let now = now_ts();
    let rows: Vec<DeletedRow> = items
        .iter()
        .map(|d| DeletedRow::new(d.name(), d.deleted_date, d.scheduled_purge_date, now))
        .collect();
    Ok(lifecycle::deleted_list(shell, vault, KIND, &rows))
}

pub async fn deleted_detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let d = match api(&state, &session, &vault).get_deleted(&name).await {
        Ok(d) => d,
        Err(e) => {
            return Err(azure_problem(shell, &e, Need::ManageKeys, "/keys/deleted"));
        }
    };
    let row = DeletedRow::new(d.name(), d.deleted_date, d.scheduled_purge_date, now_ts());
    Ok(lifecycle::deleted_detail(&state, shell, vault, KIND, &row))
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
    let shell = check_csrf(&session, &form.csrf, shell)?;
    match api(&state, &session, &vault).recover(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key recovered");
            Ok(lifecycle::recovered(&state, KIND, &name))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageKeys,
            &format!("/keys/deleted/{name}"),
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
        &form,
        &name,
        shell,
        lifecycle::purge_view(KIND, &vault, &name),
    )?;
    match api(&state, &session, &vault).purge(&name).await {
        Ok(()) => {
            tracing::warn!(subject = %session.0.user.subject, vault = %vault, key = %name, "key purged");
            Ok(lifecycle::redirect_with(
                &state,
                "/keys/deleted",
                format!("Permanently deleted {name}."),
            ))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageKeys,
            &format!("/keys/deleted/{name}"),
        )),
    }
}
