//! Delete, deleted list, recover and purge for keys. The handlers are in
//! [`crate::routes::lifecycle::handlers`]; this is the keys part.

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::routes::error::{Halt, Need};
use crate::routes::lifecycle::handlers::{DeletedPages, Lifecycle, Stage};
use crate::routes::lifecycle::{DeletedRow, Kind, Recovery};
use crate::routes::shell::Shell;

use super::{api, unmanaged_key};

/// Keys, for the shared lifecycle handlers.
pub struct Keys;

impl Lifecycle for Keys {
    const KIND: Kind = Kind::Key;
    const MANAGE: Need = Need::ManageKeys;

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

    /// A certificate's key is refused, on the form and on submit.
    async fn check_delete(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
        _stage: Stage,
    ) -> Result<(Shell, Recovery), Halt> {
        let (_, shell) = unmanaged_key(state, session, vault, name, shell).await?;
        Ok((shell, Recovery::default()))
    }
}

impl DeletedPages for Keys {
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
