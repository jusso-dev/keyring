//! Audit view: who did what in a vault, from its diagnostic logs in Log
//! Analytics. Read as the signed-in user, with the Log Analytics OBO token.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::audit::{self, AuditQuery, Event, OPERATIONS, Range};
use crate::azure::vaults;
use crate::expiry::csv_field;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AuditFilter {
    #[serde(default)]
    pub range: String,
    #[serde(default)]
    pub item: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub person: String,
    /// `secret`, `certificate` or `key`, for the link back to the item.
    #[serde(default)]
    pub from: String,
}

impl AuditFilter {
    fn query_string(&self) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "range={}&item={}&operation={}&person={}",
            enc(&self.range),
            enc(&self.item),
            enc(&self.operation),
            enc(&self.person)
        )
    }
}

pub struct EventRow {
    pub time: String,
    pub who: String,
    pub what: String,
    pub operation: String,
    pub item: String,
    pub ok: bool,
    pub result: String,
    pub client_ip: String,
}

impl EventRow {
    fn from(e: &Event) -> Self {
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
            who: if e.who.is_empty() {
                "Unknown".into()
            } else {
                e.who.clone()
            },
            what: audit::describe(&e.operation),
            operation: e.operation.clone(),
            item: e.item.clone(),
            ok: e.result.eq_ignore_ascii_case("OK") || e.result.starts_with('2'),
            result: e.result.clone(),
            client_ip: e.client_ip.clone(),
        }
    }
}

/// What's missing, so there's nothing to show.
pub enum Unavailable {
    Logging,
    WorkspaceAccess,
    SettingsAccess,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    shell: Shell,
    vault: String,
    filter: AuditFilter,
    ranges: [Range; 4],
    range: Range,
    operations: &'static [(&'static str, &'static str)],
    rows: Vec<EventRow>,
    unavailable: Option<Unavailable>,
    capped: bool,
    csv_url: String,
    error: Option<String>,
}

impl AuditPage {
    /// Link back to the item this view is filtered to, if we know its kind.
    fn back_url(&self) -> Option<String> {
        let base = match self.filter.from.as_str() {
            "secret" => "/secrets",
            "certificate" => "/certificates",
            "key" => "/keys",
            _ => return None,
        };
        crate::routes::vault_ctx::is_valid_object_name(&self.filter.item)
            .then(|| format!("{base}/{}", self.filter.item))
    }

    fn is_no_logging(&self) -> bool {
        matches!(self.unavailable, Some(Unavailable::Logging))
    }
    fn is_no_workspace_access(&self) -> bool {
        matches!(self.unavailable, Some(Unavailable::WorkspaceAccess))
    }
    fn is_no_settings_access(&self) -> bool {
        matches!(self.unavailable, Some(Unavailable::SettingsAccess))
    }
}

/// The chosen vault's ARM ID, from the session or Resource Graph.
async fn vault_id(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
) -> Result<Option<String>, AzureError> {
    if let Some(id) = session.0.selected_vault_id() {
        return Ok(Some(id));
    }
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    let id = all
        .into_iter()
        .find(|v| v.name.eq_ignore_ascii_case(vault))
        .map(|v| v.id);
    if let Some(id) = &id {
        session.0.set_selected_vault_id(id.clone());
    }
    Ok(id)
}

/// Load events for the current vault and filter.
pub async fn load(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    q: &AuditQuery,
) -> Result<Result<Vec<Event>, Unavailable>, AzureError> {
    let Some(id) = vault_id(state, session, vault).await? else {
        return Err(AzureError::Status {
            status: 404,
            code: Some("VaultNotFound".into()),
            message: None,
        });
    };
    let workspaces = match audit::workspaces(
        &state.azure,
        &session.0,
        &state.config.management_url,
        &id,
    )
    .await
    {
        Ok(w) => w,
        Err(AzureError::Status { status: 403, .. }) => {
            return Ok(Err(Unavailable::SettingsAccess));
        }
        Err(e) => return Err(e),
    };
    if workspaces.is_empty() {
        return Ok(Err(Unavailable::Logging));
    }
    let mut events = Vec::new();
    let mut denied = 0;
    for ws in &workspaces {
        match audit::query(
            &state.azure,
            &session.0,
            &state.config.loganalytics_url,
            ws,
            q,
        )
        .await
        {
            Ok(mut e) => events.append(&mut e),
            Err(AzureError::Status { status: 403, .. }) => denied += 1,
            Err(e) => return Err(e),
        }
    }
    if denied == workspaces.len() {
        return Ok(Err(Unavailable::WorkspaceAccess));
    }
    events.sort_by(|a, b| b.time.cmp(&a.time));
    events.truncate(audit::MAX_ROWS as usize);
    Ok(Ok(events))
}

fn build_query(vault: &str, f: &AuditFilter) -> Result<AuditQuery, &'static str> {
    AuditQuery::new(vault, Range::parse(&f.range), &f.item, &f.operation, &f.person).map_err(|e| match e.0 {
        "item" => "Item names use letters, numbers and hyphens.",
        "person" => "Search for a person by part of their sign-in name, email or ID: letters, numbers, @, dots, _ and - only.",
        "operation" => "Pick an action from the list.",
        _ => "Pick a vault first.",
    })
}

fn current_vault(session: &CurrentSession, shell: Shell) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, Section::Audit)
}

pub async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<AuditFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let range = Range::parse(&filter.range);
    let mut page = AuditPage {
        csv_url: format!("/audit.csv?{}", filter.query_string()),
        shell,
        vault: vault.clone(),
        filter: filter.clone(),
        ranges: Range::ALL,
        range,
        operations: &OPERATIONS,
        rows: Vec::new(),
        unavailable: None,
        capped: false,
        error: None,
    };
    let q = match build_query(&vault, &filter) {
        Ok(q) => q,
        Err(m) => {
            page.error = Some(m.into());
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
        }
    };
    match load(&state, &session, &vault, &q).await {
        Ok(Ok(events)) => {
            page.capped = events.len() >= audit::MAX_ROWS as usize;
            page.rows = events.iter().map(EventRow::from).collect();
        }
        Ok(Err(u)) => page.unavailable = Some(u),
        Err(e) => {
            return Err(PageError::new(
                page.shell,
                Problem::from_azure(&e, Need::ReadAuditLogs).returning_to("/audit"),
            )
            .into());
        }
    }
    Ok(render(&page).into_response())
}

/// CSV of the same rows the page shows for these filters.
pub fn to_csv(events: &[Event]) -> String {
    let mut out = String::from("Time (UTC),Who,Action,Operation,Item,Result,Client IP\r\n");
    for e in events {
        let r = EventRow::from(e);
        let row = [
            csv_field(&e.time),
            csv_field(&r.who),
            csv_field(&r.what),
            csv_field(&r.operation),
            csv_field(&r.item),
            csv_field(&r.result),
            csv_field(&r.client_ip),
        ];
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

pub async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<AuditFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let q = match build_query(&vault, &filter) {
        Ok(q) => q,
        Err(m) => {
            return Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Those filters aren't valid",
                    m,
                ),
            )
            .into());
        }
    };
    let events = match load(&state, &session, &vault, &q).await {
        Ok(Ok(e)) => e,
        Ok(Err(_)) => Vec::new(),
        Err(e) => {
            return Err(PageError::new(shell, Problem::from_azure(&e, Need::ReadAuditLogs)).into());
        }
    };
    let mut res: Response = (StatusCode::OK, to_csv(&events)).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"keyring-audit-{vault}.csv\""
    )) {
        h.insert(CONTENT_DISPOSITION, v);
    }
    Ok(no_store(res))
}
