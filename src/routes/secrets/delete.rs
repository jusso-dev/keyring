//! Delete (soft), the deleted secrets list, recover and purge.
//!
//! Delete needs the secret's name typed in, checked on the server. Purge is
//! off unless `KEYRING_ALLOW_PURGE=true`; with it off the purge routes
//! refuse every request, whatever the browser sends. On a vault with purge
//! protection purge isn't offered, and is refused before Azure is asked.
//!
//! Delete, recover and purge use the shared handlers in
//! [`crate::routes::lifecycle::handlers`]. Secrets differ from the other
//! kinds in three ways, all kept here: a certificate's backing secret is
//! refused on the form and on submit, the delete message gives the vault's
//! real retention, and purge reads the deleted secret first so purge
//! protection is refused before Azure is asked. The deleted list and
//! deleted page have their own templates, because they show the content
//! type and the vault's retention.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::{DeletedSecretItem, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::lifecycle::handlers::{Lifecycle, Stage};
use crate::routes::lifecycle::{self, Kind, Recovery};
use crate::routes::paging::{PageQuery, Pager};
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
    pager: Pager,
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

pub async fn list_deleted(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(query): Query<PageQuery>,
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
    let rows = items
        .iter()
        .map(|d| DeletedRow::from_item(d, now))
        .collect();
    let (rows, pager) = lifecycle::deleted_page(KIND, rows, query.page);
    Ok(render(&DeletedList {
        rows,
        pager,
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

/// Secrets, for the shared lifecycle handlers.
pub struct Secrets;

impl Lifecycle for Secrets {
    const KIND: Kind = KIND;
    const MANAGE: Need = Need::ManageSecrets;

    async fn delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> Result<(), AzureError> {
        api(state, session, vault).delete(name).await
    }

    async fn recover(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> Result<(), AzureError> {
        api(state, session, vault).recover(name).await
    }

    async fn purge(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
    ) -> Result<(), AzureError> {
        api(state, session, vault).purge(name).await
    }

    /// Read the secret first, on the form and on submit, so a missing or
    /// certificate-owned secret gets its own page and the warning can give
    /// the vault's real retention. Refuse if we can't tell.
    async fn check_delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
        _stage: Stage,
    ) -> Result<(Shell, Recovery), Halt> {
        current(state, session, shell, vault, name).await
    }

    /// Refuse early when the deleted secret says the vault has purge
    /// protection.
    async fn check_purge(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
    ) -> Result<Shell, Halt> {
        let (shell, item) = load_deleted(state, session, shell, vault, name).await?;
        lifecycle::purge_not_protected(shell, KIND, name, recovery_of(&item.attributes))
    }

    fn deleted_message(name: &str, recovery: Recovery) -> String {
        format!(
            "Deleted {name}. You can recover it from deleted secrets {}.",
            recovery.period()
        )
    }

    fn purge_error(shell: Shell, err: &AzureError, name: &str) -> Halt {
        lifecycle::purge_problem(shell, err, KIND, name, Need::ManageSecrets)
    }
}
