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
//! deleted page are the shared ones too; a secret's row also carries its
//! content type.

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::DeletedSecretItem;
use crate::routes::error::{Halt, Need};
use crate::routes::lifecycle::handlers::{DeletedPages, Lifecycle, Stage};
use crate::routes::lifecycle::{self, DeletedRow, Kind, Recovery};
use crate::routes::secrets::{api, azure_problem};
use crate::routes::shell::Shell;

const KIND: Kind = Kind::Secret;

fn recovery_of(a: &crate::azure::secrets::Attributes) -> Recovery {
    Recovery::new(a.recovery_level.as_deref(), a.recoverable_days)
}

fn row(d: &DeletedSecretItem, now: i64) -> DeletedRow {
    DeletedRow::new(d.name(), d.deleted_date, d.scheduled_purge_date, now)
        .with_recovery(&d.attributes)
        .with_content_type(d.content_type.as_deref())
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
        Ok(item) if item.managed.unwrap_or(false) => Err(
            crate::routes::secrets::reveal::managed_problem(shell, vault, name),
        ),
        Ok(item) => Ok((shell, recovery_of(&item.attributes))),
        Err(err) => {
            let path = KIND.item_url(vault, name);
            Err(azure_problem(shell, &err, Need::ManageSecrets, &path))
        }
    }
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
            &KIND.deleted_list_url(vault),
        )),
    }
}

/// Secrets, for the shared lifecycle handlers.
pub(crate) struct Secrets;

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
        lifecycle::purge_not_protected(shell, KIND, vault, name, recovery_of(&item.attributes))
    }

    fn deleted_message(name: &str, recovery: Recovery) -> String {
        format!(
            "Deleted {name}. You can recover it from deleted secrets {}.",
            recovery.period()
        )
    }

    fn purge_error(shell: Shell, err: &AzureError, vault: &str, name: &str) -> Halt {
        lifecycle::purge_problem(shell, err, KIND, vault, name, Need::ManageSecrets)
    }
}

impl DeletedPages for Secrets {
    async fn list_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        now: i64,
    ) -> Result<Vec<DeletedRow>, AzureError> {
        let items = api(state, session, vault).list_deleted().await?;
        Ok(items.iter().map(|d| row(d, now)).collect())
    }

    async fn get_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        now: i64,
    ) -> Result<DeletedRow, AzureError> {
        let d = api(state, session, vault).get_deleted(name).await?;
        Ok(row(&d, now))
    }
}
