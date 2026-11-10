//! Delete, deleted list, recover and purge handlers, written once for every
//! kind of item. Each kind gives its Azure calls and checks through
//! [`Lifecycle`], and the router names it, as in `delete::<Keys>`.

use std::future::Future;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::now_ts;
use crate::routes::confirm::ConfirmForm;
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::forms::CsrfForm;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name};

use super::{DeletedRow, Kind, Recovery};

/// Where a delete check runs: showing the confirm form, or acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Form,
    Submit,
}

/// One kind of item's part in delete, recover and purge.
pub trait Lifecycle: Send + Sync + 'static {
    const KIND: Kind;
    /// What delete, recover and purge need.
    const MANAGE: Need;

    fn delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> impl Future<Output = Result<(), AzureError>> + Send;

    fn recover(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> impl Future<Output = Result<(), AzureError>> + Send;

    fn purge(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> impl Future<Output = Result<(), AzureError>> + Send;

    /// Checks before a delete, such as refusing an item that belongs to a
    /// certificate. Gives what the item says about recovery, when it says.
    fn check_delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
        stage: Stage,
    ) -> impl Future<Output = Result<(Shell, Recovery), Halt>> + Send;

    /// Checks before a purge, on the form and on submit. None by default:
    /// Key Vault has the final say.
    fn check_purge(
        _state: &AppState,
        _session: &CurrentSession,
        _vault: &str,
        _name: &str,
        shell: Shell,
    ) -> impl Future<Output = Result<Shell, Halt>> + Send {
        async { Ok(shell) }
    }

    /// The message after a delete.
    fn deleted_message(name: &str, _recovery: Recovery) -> String {
        format!(
            "Deleted {name}. You can recover it from deleted {}.",
            Self::KIND.plural()
        )
    }

    /// The page for a failed purge.
    fn purge_error(shell: Shell, err: &AzureError, name: &str) -> Halt {
        azure_problem(shell, err, Self::MANAGE, &Self::KIND.deleted_url(name))
    }
}

/// The deleted list and deleted item page, for kinds that use the shared
/// templates.
pub trait DeletedPages: Lifecycle {
    fn list_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<DeletedRow>, AzureError>> + Send;

    fn get_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        now: i64,
    ) -> impl Future<Output = Result<DeletedRow, AzureError>> + Send;
}

/// Log a change, with the item under a field named for its kind (`secret`,
/// `certificate` or `key`), as every other change is logged.
macro_rules! log_change {
    ($level:ident, $kind:expr, $session:expr, $vault:expr, $name:expr, $what:literal) => {
        match $kind {
            Kind::Secret => tracing::$level!(
                subject = %$session.0.user.subject, vault = %$vault, secret = %$name,
                concat!("secret ", $what)
            ),
            Kind::Certificate => tracing::$level!(
                subject = %$session.0.user.subject, vault = %$vault, certificate = %$name,
                concat!("certificate ", $what)
            ),
            Kind::Key => tracing::$level!(
                subject = %$session.0.user.subject, vault = %$vault, key = %$name,
                concat!("key ", $what)
            ),
        }
    };
}

fn current_vault<L: Lifecycle>(
    session: &CurrentSession,
    shell: Shell,
) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, L::KIND.section())
}

pub async fn delete_form<L: Lifecycle>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    // Check first, so a missing item gets its own page before the name is
    // asked for, and the warning can give the vault's real retention.
    let (shell, recovery) =
        L::check_delete(&state, &session, &vault, &name, shell, Stage::Form).await?;
    Ok(super::confirm_page(
        shell,
        super::delete_view_for(L::KIND, &vault, &name, recovery),
        StatusCode::OK,
    ))
}

pub async fn delete<L: Lifecycle>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = super::verify(
        &session,
        &vault,
        &form,
        &name,
        shell,
        super::delete_view(L::KIND, &vault, &name),
    )?;
    let (shell, recovery) =
        L::check_delete(&state, &session, &vault, &name, shell, Stage::Submit).await?;
    match L::delete(&state, &session, &vault, &name).await {
        Ok(()) => {
            log_change!(info, L::KIND, session, vault, name, "deleted");
            Ok(super::redirect_with(
                &state,
                L::KIND.base(),
                L::deleted_message(&name, recovery),
            ))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            L::MANAGE,
            &L::KIND.item_url(&name),
        )),
    }
}

pub async fn list_deleted<L: DeletedPages>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
) -> PageResult {
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    match L::list_deleted(&state, &session, &vault, now_ts()).await {
        Ok(rows) => Ok(super::deleted_list(shell, vault, L::KIND, &rows)),
        Err(e) => Err(azure_problem(
            shell,
            &e,
            L::MANAGE,
            &L::KIND.deleted_list_url(),
        )),
    }
}

pub async fn deleted_detail<L: DeletedPages>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    match L::get_deleted(&state, &session, &vault, &name, now_ts()).await {
        Ok(row) => Ok(super::deleted_detail(&state, shell, vault, L::KIND, &row)),
        Err(e) => Err(azure_problem(
            shell,
            &e,
            L::MANAGE,
            &L::KIND.deleted_list_url(),
        )),
    }
}

pub async fn recover<L: Lifecycle>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &form.csrf, shell)?;
    match L::recover(&state, &session, &vault, &name).await {
        Ok(()) => {
            log_change!(info, L::KIND, session, vault, name, "recovered");
            Ok(super::recovered(&state, L::KIND, &name))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            L::MANAGE,
            &L::KIND.deleted_url(&name),
        )),
    }
}

pub async fn purge_form<L: Lifecycle>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let shell = super::purge_allowed(&state, shell, L::KIND)?;
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = L::check_purge(&state, &session, &vault, &name, shell).await?;
    Ok(super::confirm_page(
        shell,
        super::purge_view(L::KIND, &vault, &name),
        StatusCode::OK,
    ))
}

pub async fn purge<L: Lifecycle>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let shell = super::purge_allowed(&state, shell, L::KIND)?;
    let (vault, shell) = current_vault::<L>(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = super::verify(
        &session,
        &vault,
        &form,
        &name,
        shell,
        super::purge_view(L::KIND, &vault, &name),
    )?;
    let shell = L::check_purge(&state, &session, &vault, &name, shell).await?;
    match L::purge(&state, &session, &vault, &name).await {
        Ok(()) => {
            log_change!(warn, L::KIND, session, vault, name, "purged");
            Ok(super::redirect_with(
                &state,
                &L::KIND.deleted_list_url(),
                format!("Permanently deleted {name}."),
            ))
        }
        Err(e) => Err(L::purge_error(shell, &e, &name)),
    }
}
