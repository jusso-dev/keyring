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
use crate::routes::forms::{FieldError, FieldErrors};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx;

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct AuditFilter {
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

pub(super) struct EventRow {
    pub time: String,
    pub who: String,
    pub what: String,
    pub operation: String,
    pub item: String,
    pub ok: bool,
    /// The log row has no result, so it can't be called allowed or refused.
    pub unknown: bool,
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
            unknown: e.result.trim().is_empty(),
            result: e.result.clone(),
            client_ip: e.client_ip.clone(),
        }
    }
}

/// What's missing, so there's nothing to show.
pub(super) enum Unavailable {
    Logging,
    WorkspaceAccess,
    SettingsAccess,
}

impl Unavailable {
    /// Status for a CSV export that has nothing to export.
    fn status(&self) -> StatusCode {
        match self {
            Self::Logging => StatusCode::NOT_FOUND,
            Self::WorkspaceAccess | Self::SettingsAccess => StatusCode::FORBIDDEN,
        }
    }
}

/// Events from the workspaces that answered, and a count of those that
/// didn't.
pub(super) struct Loaded {
    pub events: Vec<Event>,
    /// Workspaces the vault logs to.
    pub workspaces: usize,
    /// Workspaces that refused the user (403).
    pub denied: usize,
    /// Workspaces that failed some other way (throttling, a 5xx, no answer).
    pub failed: usize,
}

impl Loaded {
    fn unread(&self) -> usize {
        self.denied + self.failed
    }

    /// Plain words for the workspaces left out, or `None` if every one
    /// was read.
    fn partial_notice(&self) -> Option<String> {
        if self.unread() == 0 {
            return None;
        }
        let why = match (self.denied, self.failed) {
            (_, 0) => "you don't have the Log Analytics Reader role on it",
            (0, _) => "Azure didn't answer in time or returned an error. Try again in a minute",
            _ => {
                "you don't have the Log Analytics Reader role on some, and others returned an error"
            }
        };
        let (n, m) = (self.unread(), self.workspaces);
        let noun = if m == 1 { "workspace" } else { "workspaces" };
        Some(format!(
            "{n} of {m} Log Analytics {noun} this vault logs to couldn't be read ({why}), so some events may be missing."
        ))
    }
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
    /// Some workspaces couldn't be read, in plain words.
    partial: Option<String>,
    capped: bool,
    csv_url: String,
    /// A filter that isn't valid, tied to its field.
    errors: FieldErrors,
}

impl AuditPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }

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

/// Load events for the current vault and filter. A workspace that can't be
/// read doesn't hide the others: the result says how many were left out.
/// Only when none could be read is it an error or [`Unavailable`].
pub(super) async fn load(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    q: &AuditQuery,
) -> Result<Result<Loaded, Unavailable>, AzureError> {
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
    let mut failure = None;
    let mut failed = 0;
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
            Err(e) => {
                tracing::warn!(error = %e, "audit workspace query failed");
                failed += 1;
                failure.get_or_insert(e);
            }
        }
    }
    if denied == workspaces.len() {
        return Ok(Err(Unavailable::WorkspaceAccess));
    }
    if denied + failed == workspaces.len()
        && let Some(e) = failure
    {
        return Err(e);
    }
    events.sort_by(|a, b| b.time.cmp(&a.time));
    events.truncate(audit::MAX_ROWS as usize);
    Ok(Ok(Loaded {
        events,
        workspaces: workspaces.len(),
        denied,
        failed,
    }))
}

/// On a bad filter, the field at fault (empty for the vault, which has no
/// field on the page) and what to do about it.
fn build_query(vault: &str, f: &AuditFilter) -> Result<AuditQuery, FieldError> {
    AuditQuery::new(vault, Range::parse(&f.range), &f.item, &f.operation, &f.person).map_err(|e| {
        let (field, message) = match e.0 {
            "item" => ("item", "Item names use letters, numbers and hyphens."),
            "person" => ("person", "Search for a person by part of their sign-in name, email or ID: letters, numbers, @, dots, _ and - only."),
            "operation" => ("operation", "Pick an action from the list."),
            _ => ("", "Pick a vault first."),
        };
        FieldError { field, message: message.into() }
    })
}

fn current_vault(session: &CurrentSession, shell: Shell) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, Section::Audit)
}

fn empty_page(shell: Shell, vault: &str, filter: &AuditFilter) -> AuditPage {
    AuditPage {
        csv_url: format!("/audit.csv?{}", filter.query_string()),
        shell,
        vault: vault.to_owned(),
        filter: filter.clone(),
        ranges: Range::ALL,
        range: Range::parse(&filter.range),
        operations: &OPERATIONS,
        rows: Vec::new(),
        unavailable: None,
        partial: None,
        capped: false,
        errors: FieldErrors::new(),
    }
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<AuditFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let mut page = empty_page(shell, &vault, &filter);
    let q = match build_query(&vault, &filter) {
        Ok(q) => q,
        Err(e) => {
            page.errors.push(e.field, e.message);
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
        }
    };
    match load(&state, &session, &vault, &q).await {
        Ok(Ok(loaded)) => {
            page.capped = loaded.events.len() >= audit::MAX_ROWS as usize;
            page.rows = loaded.events.iter().map(EventRow::from).collect();
            page.partial = loaded.partial_notice();
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
pub(super) fn to_csv(events: &[Event]) -> String {
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

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<AuditFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let q = match build_query(&vault, &filter) {
        Ok(q) => q,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Those filters aren't valid",
                    e.message,
                ),
            )
            .into());
        }
    };
    let loaded = match load(&state, &session, &vault, &q).await {
        Ok(Ok(l)) => l,
        // Nothing to export. Show the same explanation as the page, with
        // a status that says so, rather than an empty file that reads as
        // "no events".
        Ok(Err(u)) => {
            let status = u.status();
            let mut page = empty_page(shell, &vault, &filter);
            page.unavailable = Some(u);
            return Ok((status, render(&page)).into_response());
        }
        Err(e) => {
            return Err(PageError::new(shell, Problem::from_azure(&e, Need::ReadAuditLogs)).into());
        }
    };
    let mut body = to_csv(&loaded.events);
    if let Some(note) = loaded.partial_notice() {
        let row = ["NOT READ".to_owned(), csv_field(&note)];
        body.push_str(&row.join(","));
        body.push_str(",,,,,\r\n");
    }
    let mut res: Response = (StatusCode::OK, body).into_response();
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
