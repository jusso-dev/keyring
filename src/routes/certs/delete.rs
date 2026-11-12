//! Delete, deleted list, recover and purge for certificates. The handlers
//! are in [`crate::routes::lifecycle::handlers`]; this is the certificates
//! part.

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::routes::error::{Halt, Need};
use crate::routes::lifecycle::handlers::{DeletedPages, Lifecycle, Stage};
use crate::routes::lifecycle::{DeletedRow, Kind, Recovery};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::azure_problem;

use super::api;

/// Certificates, for the shared lifecycle handlers.
pub(crate) struct Certificates;

impl Lifecycle for Certificates {
    const KIND: Kind = Kind::Certificate;
    const MANAGE: Need = Need::ManageCertificates;

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

    /// Make sure there's something to delete before asking for the name.
    /// On submit Key Vault's own answer is enough.
    async fn check_delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
        stage: Stage,
    ) -> Result<(Shell, Recovery), Halt> {
        if stage == Stage::Form
            && let Err(e) = api(state, session, vault).get_cert(name, None).await
        {
            return Err(azure_problem(
                shell,
                &e,
                Need::ReadCertificates,
                &Kind::Certificate.item_url(vault, name),
            ));
        }
        Ok((shell, Recovery::default()))
    }
}

impl DeletedPages for Certificates {
    async fn list_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        now: i64,
    ) -> Result<Vec<DeletedRow>, AzureError> {
        let items = api(state, session, vault).list_deleted().await?;
        Ok(items
            .iter()
            .map(|d| {
                DeletedRow::new(d.name(), d.deleted_date, d.scheduled_purge_date, now)
                    .with_recovery(&d.attributes)
            })
            .collect())
    }

    async fn get_deleted(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        now: i64,
    ) -> Result<DeletedRow, AzureError> {
        let d = api(state, session, vault).get_deleted(name).await?;
        Ok(
            DeletedRow::new(d.name(), d.deleted_date, d.scheduled_purge_date, now)
                .with_recovery(&d.attributes),
        )
    }
}
