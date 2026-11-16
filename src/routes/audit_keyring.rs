//! Keyring activity: Keyring's own audit events for one vault, from
//! `KeyringAudit_CL`, beside the audit page's Key Vault log. Only when
//! `KEYRING_AUDIT_WORKSPACE_ID` is set. Read as the signed-in person with
//! their Log Analytics token, never Keyring's managed identity.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::audit::Action;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::audit::{MAX_ROWS, Range};
use crate::azure::audit_keyring::{self, KeyringEvent, KeyringQuery};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::forms::FieldErrors;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, vault_path};

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct KeyringFilter {
    #[serde(default)]
    pub range: String,
    #[serde(default)]
    pub item: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub person: String,
}

pub(super) struct Row {
    pub time: String,
    pub who: String,
    pub action: String,
    pub item: String,
    /// `ok`, `denied`, `refused`, `failed` or empty.
    pub outcome: String,
    pub reason_code: String,
    pub client_ip: String,
    /// Free text a person typed. Askama escapes it.
    pub reason: String,
    pub ticket: String,
}

impl Row {
    fn from(e: &KeyringEvent) -> Self {
        Self {
            time: e
                .time
                .replace('T', " ")
                .trim_end_matches('Z')
                .split('.')
                .next()
                .unwrap_or_default()
                .to_owned()
                + " UTC",
            who: [&e.actor_upn, &e.actor_oid]
                .into_iter()
                .find(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "Nobody signed in".into()),
            action: e.action.clone(),
            item: e.item_name.clone(),
            outcome: e.outcome.clone(),
            reason_code: e.reason_code.clone(),
            client_ip: e.client_ip.clone(),
            reason: e.reason.clone(),
            ticket: e.ticket.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "audit_keyring.html")]
struct KeyringPage {
    shell: Shell,
    vault: String,
    filter: KeyringFilter,
    ranges: [Range; 4],
    range: Range,
    actions: Vec<&'static str>,
    rows: Vec<Row>,
    /// The person can't read the workspace.
    no_access: bool,
    capped: bool,
    errors: FieldErrors,
}

impl KeyringPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(filter): Query<KeyringFilter>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Audit, &vault)?;
    // Without the setting there is no such view.
    let Some(workspace) = state.config.audit_workspace_id.clone() else {
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    let range = Range::parse(&filter.range);
    let mut page = KeyringPage {
        shell,
        vault: vault.clone(),
        filter: filter.clone(),
        ranges: Range::ALL,
        range,
        actions: Action::ALL.iter().map(|a| a.as_str()).collect(),
        rows: Vec::new(),
        no_access: false,
        capped: false,
        errors: FieldErrors::new(),
    };
    let q = match KeyringQuery::new(&vault, range, &filter.item, &filter.action, &filter.person) {
        Ok(q) => q,
        Err(e) => {
            let (field, message) = match e.0 {
                "item" => ("item", "Item names use letters, numbers and hyphens."),
                "person" => (
                    "person",
                    "Search for a person by part of their sign-in name, email or ID: letters, numbers, @, dots, _ and - only.",
                ),
                "operation" => ("action", "Pick an action from the list."),
                _ => ("", "Pick a vault first."),
            };
            page.errors.push(field, message);
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
        }
    };
    match audit_keyring::query(
        &state.azure,
        &session.0,
        &state.config.loganalytics_url,
        &workspace,
        &q,
    )
    .await
    {
        Ok(events) => {
            page.capped = events.len() >= MAX_ROWS as usize;
            page.rows = events.iter().map(Row::from).collect();
        }
        Err(AzureError::Status { status: 403, .. }) => page.no_access = true,
        Err(e) => {
            return Err(PageError::new(
                page.shell,
                Problem::from_azure(&e, Need::ReadAuditLogs)
                    .returning_to(&vault_path(&vault, "/audit")),
            )
            .into());
        }
    }
    Ok(render(&page).into_response())
}
