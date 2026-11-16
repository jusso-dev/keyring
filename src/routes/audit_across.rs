//! Audit across every vault the person can see: fixed reports, such as
//! secret values read in the last 7 days, over the Log Analytics
//! workspaces the vaults send their audit logs to.
//!
//! 1. List the vaults (Resource Graph), the first [`MAX_VAULTS`] by name.
//! 2. Read each vault's diagnostic settings through the shared fan-out.
//! 3. Group the vaults by workspace and table, and send one query per
//!    group, a few at a time.
//!
//! All of it as the signed-in person, with their ARM and Log Analytics
//! on-behalf-of tokens. Vaults that log nowhere, vaults whose settings
//! can't be read and workspaces that can't be read are listed, on the page
//! and in the CSV. This page only reads, so it writes no action line.

use std::collections::HashMap;
use std::time::Duration;

use askama::Template;
use axum::extract::{Query, Request, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::audit::{self, Range, Workspace};
use crate::azure::audit_across::{
    self, Answer, Refusal, Report, ReportQuery, VaultEvent, WorkspaceGroup,
};
use crate::azure::fanout::{self, Limits};
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::azure::{AzureError, TokenError};
use crate::expiry::csv_field;
use crate::routes::assets::render;
use crate::routes::audit::EventRow;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::expiry::MAX_VAULTS;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{is_valid_object_name, vault_path};

/// Limits for reading diagnostic settings. With [`QUERY_LIMITS`], well
/// inside the 90 second request limit in `routes::headers`.
const SETTINGS_LIMITS: Limits = Limits {
    concurrency: fanout::CONCURRENCY,
    vault_timeout: Duration::from_secs(15),
    deadline: Duration::from_secs(35),
};

/// Limits for the workspace queries, after the settings are read.
const QUERY_LIMITS: Limits = Limits {
    concurrency: fanout::CONCURRENCY,
    vault_timeout: Duration::from_secs(25),
    deadline: Duration::from_secs(30),
};

const SETTINGS_OUT_OF_TIME: &str =
    "Not read in time. Open the vault's own audit page to see its events";
const WORKSPACE_OUT_OF_TIME: &str =
    "Not read in time. Open one of its vaults' own audit page to see its events";

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct ReportFilter {
    #[serde(default)]
    pub report: String,
    #[serde(default)]
    pub range: String,
    #[serde(default)]
    pub person: String,
}

impl ReportFilter {
    fn range(&self, report: Report) -> Range {
        if self.range.is_empty() {
            report.default_range()
        } else {
            Range::parse(&self.range)
        }
    }
}

/// True for a query without a report: the per-vault audit page's filters
/// from before the vault was in the path (`/audit?item=db&from=secret`),
/// so the old bookmark still goes to the last vault used. Bare `/audit` is
/// the page across vaults.
fn is_old_vault_query(query: Option<&str>) -> bool {
    query.is_some_and(|q| {
        !q.is_empty() && !q.split('&').any(|p| p.split('=').next() == Some("report"))
    })
}

/// A vault that couldn't be covered, and why in plain words.
pub(super) struct NotRead {
    pub name: String,
    pub reason: String,
}

/// A workspace that couldn't be read, the vaults it covers, and why.
pub(super) struct WorkspaceNotRead {
    pub name: String,
    pub vaults: String,
    pub reason: String,
}

struct Loaded {
    answer: Answer,
    /// Rows were left out to stay within [`audit::MAX_ROWS`].
    capped: bool,
    /// Vaults read, so the page can say what it covers.
    vaults_read: usize,
    workspaces_read: usize,
    no_logging: Vec<String>,
    settings_not_read: Vec<NotRead>,
    workspaces_not_read: Vec<WorkspaceNotRead>,
    /// More vaults than [`MAX_VAULTS`], so only the first were read.
    vaults_total: usize,
    capped_vaults: bool,
    /// ARM ID (lower case) to vault name, for the rows.
    names: HashMap<String, String>,
}

fn settings_reason(err: &AzureError) -> String {
    match err {
        AzureError::Status { status: 403, .. } => {
            "You can't see where it sends its logs. Ask for the Reader role on the vault".into()
        }
        other => fanout::reason(other),
    }
}

fn workspace_reason(err: &AzureError) -> String {
    match err {
        AzureError::Status { status: 403, .. } => {
            "You don't have the Log Analytics Reader role on it".into()
        }
        AzureError::Status { status: 404, .. } => {
            "Not found. It may have been deleted, or be in another tenant".into()
        }
        other => fanout::reason(other),
    }
}

/// The last part of an ARM ID, for showing a workspace.
fn last_segment(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

async fn load(
    state: &AppState,
    session: &CurrentSession,
    q: &ReportQuery,
) -> Result<Loaded, AzureError> {
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    let mut vaults: Vec<(String, String)> = all
        .into_iter()
        .filter(|v| is_valid_vault_name(&v.name) && audit::is_safe_resource_id(&v.id))
        .map(|v| (v.name, v.id))
        .collect();
    vaults.sort();
    vaults.dedup_by(|a, b| a.0 == b.0);
    let vaults_total = vaults.len();
    vaults.truncate(MAX_VAULTS);
    let ids: HashMap<String, String> = vaults.iter().cloned().collect();
    let names: HashMap<String, String> = vaults
        .iter()
        .map(|(n, id)| (id.to_ascii_lowercase(), n.clone()))
        .collect();

    // Each vault's diagnostic settings.
    let settings = fanout::read_each_within(
        vaults.iter().map(|(n, _)| n.clone()),
        |vault| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.management_url.clone();
            let id = ids.get(&vault).cloned().unwrap_or_default();
            async move {
                match audit::workspaces(&azure, &sess, &url, &id).await {
                    Ok(w) => ((id, w), None),
                    Err(e) => ((id, Vec::new()), Some(settings_reason(&e))),
                }
            }
        },
        SETTINGS_LIMITS,
    )
    .await;
    let mut no_logging = Vec::new();
    let mut logging: Vec<(String, Vec<Workspace>)> = Vec::new();
    let skipped: Vec<&str> = settings.skipped.iter().map(|s| s.vault.as_str()).collect();
    for (name, (id, ws)) in settings.read {
        if skipped.contains(&name.as_str()) {
            continue;
        }
        if ws.is_empty() {
            no_logging.push(name);
        } else {
            logging.push((id, ws));
        }
    }
    no_logging.sort();
    let settings_not_read: Vec<NotRead> = settings
        .skipped
        .into_iter()
        .map(|s| NotRead {
            reason: if s.reason == fanout::OUT_OF_TIME {
                SETTINGS_OUT_OF_TIME.into()
            } else {
                s.reason
            },
            name: s.vault,
        })
        .collect();

    // One query per workspace and table.
    let groups = audit_across::group(&logging);
    let by_key: HashMap<String, WorkspaceGroup> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| (i.to_string(), g.clone()))
        .collect();
    let answers = fanout::read_each_within(
        (0..groups.len()).map(|i| i.to_string()),
        |key| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.loganalytics_url.clone();
            let group = by_key.get(&key).cloned();
            let q = q.clone();
            async move {
                let Some(group) = group else {
                    return (Err(AzureError::Unreadable), None);
                };
                (
                    audit_across::query(&azure, &sess, &url, &group, &q).await,
                    None,
                )
            }
        },
        QUERY_LIMITS,
    )
    .await;
    let vault_list = |g: &WorkspaceGroup| {
        let mut v: Vec<&str> = g
            .vault_ids
            .iter()
            .map(|id| {
                names
                    .get(&id.to_ascii_lowercase())
                    .map(String::as_str)
                    .unwrap_or_else(|| last_segment(id))
            })
            .collect();
        v.sort();
        v.join(", ")
    };
    let mut ok = Vec::new();
    let mut workspaces_not_read = Vec::new();
    let mut vaults_read = 0;
    let mut first_error = None;
    for (key, result) in answers.read {
        let Some(group) = by_key.get(&key) else {
            continue;
        };
        match result {
            Ok(a) => {
                vaults_read += group.vault_ids.len();
                ok.push(a);
            }
            Err(e) => {
                if !matches!(e, AzureError::Status { status: 403, .. }) {
                    tracing::warn!(error = %e, "audit workspace query failed");
                }
                workspaces_not_read.push(WorkspaceNotRead {
                    name: last_segment(&group.workspace.resource_id).to_owned(),
                    vaults: vault_list(group),
                    reason: workspace_reason(&e),
                });
                first_error.get_or_insert(e);
            }
        }
    }
    for s in answers.skipped {
        let Some(group) = by_key.get(&s.vault) else {
            continue;
        };
        workspaces_not_read.push(WorkspaceNotRead {
            name: last_segment(&group.workspace.resource_id).to_owned(),
            vaults: vault_list(group),
            reason: if s.reason == fanout::OUT_OF_TIME {
                WORKSPACE_OUT_OF_TIME.into()
            } else {
                s.reason
            },
        });
    }
    workspaces_not_read.sort_by(|a, b| a.name.cmp(&b.name));
    // Sign-in trouble (consent for Log Analytics, an expired session) is
    // the same for every workspace: show it as the page's error.
    if ok.is_empty()
        && let Some(e @ AzureError::Token(_)) = first_error
    {
        return Err(e);
    }
    let workspaces_read = ok.len();
    let (answer, capped) = audit_across::merge(ok, q.report.grouped());
    Ok(Loaded {
        answer,
        capped,
        vaults_read,
        workspaces_read,
        no_logging,
        settings_not_read,
        workspaces_not_read,
        capped_vaults: vaults_total > MAX_VAULTS,
        vaults_total,
        names,
    })
}

/// The vault name for an ARM ID in a row.
fn vault_name(names: &HashMap<String, String>, id: &str) -> String {
    if let Some(n) = names.get(&id.to_ascii_lowercase()) {
        return n.clone();
    }
    let last = last_segment(id);
    if is_valid_vault_name(last) {
        last.to_owned()
    } else {
        String::new()
    }
}

/// The kind an operation is about, for the way back from the vault's
/// audit page to the item.
fn kind_of(operation: &str) -> &'static str {
    if operation.starts_with("Secret") {
        "secret"
    } else if operation.starts_with("Certificate") {
        "certificate"
    } else if operation.starts_with("Key") {
        "key"
    } else {
        ""
    }
}

pub(super) struct Row {
    pub vault: String,
    pub event: EventRow,
    /// The vault's own audit page, filtered to the item where there is one.
    pub detail_url: String,
}

pub(super) struct RefusalRow {
    pub vault: String,
    pub who: String,
    pub count: u64,
    pub last: String,
    pub operations: String,
    pub detail_url: String,
}

fn detail_url(vault: &str, range: Range, item: &str, person: &str, from: &str) -> String {
    if vault.is_empty() {
        return String::new();
    }
    let enc = crate::auth::return_to::encode;
    let mut url = vault_path(vault, &format!("/audit?range={}", range.slug()));
    if is_valid_object_name(item) {
        url.push_str(&format!("&item={}", enc(item)));
        if !from.is_empty() {
            url.push_str(&format!("&from={from}"));
        }
    }
    if !person.is_empty() && crate::azure::audit::is_person(person) {
        url.push_str(&format!("&person={}", enc(person)));
    }
    url
}

fn rows(events: &[VaultEvent], names: &HashMap<String, String>, range: Range) -> Vec<Row> {
    events
        .iter()
        .map(|e| {
            let vault = vault_name(names, &e.vault_id);
            Row {
                detail_url: detail_url(
                    &vault,
                    range,
                    &e.event.item,
                    "",
                    kind_of(&e.event.operation),
                ),
                vault,
                event: EventRow::from(&e.event),
            }
        })
        .collect()
}

fn refusal_rows(
    list: &[Refusal],
    names: &HashMap<String, String>,
    range: Range,
) -> Vec<RefusalRow> {
    list.iter()
        .map(|r| {
            let vault = vault_name(names, &r.vault_id);
            RefusalRow {
                detail_url: detail_url(&vault, range, "", &r.who, ""),
                vault,
                who: if r.who.is_empty() {
                    "Unknown".into()
                } else {
                    r.who.clone()
                },
                count: r.count,
                last: r
                    .last
                    .replace('T', " ")
                    .trim_end_matches('Z')
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
                    + " UTC",
                operations: r.operations.clone(),
            }
        })
        .collect()
}

#[derive(Template)]
#[template(path = "audit_across.html")]
struct AcrossPage {
    shell: Shell,
    reports: [Report; 5],
    report: Option<Report>,
    filter: ReportFilter,
    ranges: [Range; 4],
    range: Range,
    /// The person report is open with no person given yet.
    needs_person: bool,
    ran: bool,
    rows: Vec<Row>,
    refusals: Vec<RefusalRow>,
    capped: bool,
    vaults_read: usize,
    workspaces_read: usize,
    no_logging: Vec<String>,
    settings_not_read: Vec<NotRead>,
    workspaces_not_read: Vec<WorkspaceNotRead>,
    capped_vaults: bool,
    vaults_total: usize,
    max_vaults: usize,
    csv_url: String,
    errors: crate::routes::forms::FieldErrors,
}

impl AcrossPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }

    fn is_report(&self, r: &Report) -> bool {
        self.report == Some(*r)
    }

    fn is_person_report(&self) -> bool {
        self.report == Some(Report::Person)
    }

    fn is_grouped(&self) -> bool {
        self.report.is_some_and(Report::grouped)
    }
}

fn empty_page(shell: Shell, filter: ReportFilter, report: Option<Report>) -> AcrossPage {
    let range = report.map_or(Range::Week, |r| filter.range(r));
    let enc = crate::auth::return_to::encode;
    AcrossPage {
        csv_url: report.map_or_else(String::new, |r| {
            format!(
                "/audit.csv?report={}&range={}&person={}",
                r.slug(),
                range.slug(),
                enc(filter.person.trim())
            )
        }),
        shell: shell.at(Section::Audit),
        reports: Report::ALL,
        report,
        needs_person: false,
        filter,
        ranges: Range::ALL,
        range,
        ran: false,
        rows: Vec::new(),
        refusals: Vec::new(),
        capped: false,
        vaults_read: 0,
        workspaces_read: 0,
        no_logging: Vec::new(),
        settings_not_read: Vec::new(),
        workspaces_not_read: Vec::new(),
        capped_vaults: false,
        vaults_total: 0,
        max_vaults: MAX_VAULTS,
        errors: crate::routes::forms::FieldErrors::new(),
    }
}

const PERSON_HELP: &str = "Search for a person by part of their sign-in name, email or ID: letters, numbers, @, dots, _ and - only.";

/// `/audit`. An old per-vault bookmark goes to the last vault used, as
/// before; anything else is the page across vaults.
pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    req: Request,
) -> PageResult {
    if is_old_vault_query(req.uri().query()) {
        return Ok(super::moved::legacy(session, shell, req).await);
    }
    let Query(filter) = Query::<ReportFilter>::try_from_uri(req.uri()).unwrap_or_default();
    let report = Report::parse(&filter.report);
    let mut page = empty_page(shell, filter.clone(), report);
    let Some(report) = report else {
        return Ok(render(&page).into_response());
    };
    if report == Report::Person && filter.person.trim().is_empty() {
        page.needs_person = true;
        return Ok(render(&page).into_response());
    }
    let q = match ReportQuery::new(report, page.range, &filter.person) {
        Ok(q) => q,
        Err(_) => {
            page.errors.push("person", PERSON_HELP);
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
        }
    };
    let loaded = match load(&state, &session, &q).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                page.shell,
                Problem::from_azure(&e, need_for(&e)).returning_to("/audit"),
            )
            .into());
        }
    };
    page.ran = true;
    page.capped = loaded.capped;
    match &loaded.answer {
        Answer::Events(e) => page.rows = rows(e, &loaded.names, q.range),
        Answer::Refusals(r) => page.refusals = refusal_rows(r, &loaded.names, q.range),
    }
    page.vaults_read = loaded.vaults_read;
    page.workspaces_read = loaded.workspaces_read;
    page.no_logging = loaded.no_logging;
    page.settings_not_read = loaded.settings_not_read;
    page.workspaces_not_read = loaded.workspaces_not_read;
    page.capped_vaults = loaded.capped_vaults;
    page.vaults_total = loaded.vaults_total;
    Ok(render(&page).into_response())
}

/// A Resource Graph failure is about listing vaults; a token failure on
/// the queries is about Log Analytics.
fn need_for(e: &AzureError) -> Need {
    match e {
        AzureError::Token(TokenError::ConsentNeeded) => Need::ReadAuditLogs,
        _ => Need::ListVaults,
    }
}

/// CSV of the report. Rows that couldn't be read are named at the end, so
/// the file can't pass for a full report.
fn to_csv(loaded: &Loaded, range: Range) -> String {
    let mut out = String::new();
    let not_read = |out: &mut String, cols: usize, what: &str, why: &str| {
        let mut row = vec![csv_field(what), "NOT READ".to_owned(), csv_field(why)];
        row.resize(cols, String::new());
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    };
    let cols = match &loaded.answer {
        Answer::Events(events) => {
            out.push_str("Vault,Time (UTC),Who,Action,Operation,Item,Result,Client IP\r\n");
            for r in rows(events, &loaded.names, range) {
                let e = &r.event;
                let row = [
                    csv_field(&r.vault),
                    csv_field(&e.time),
                    csv_field(&e.who),
                    csv_field(&e.what),
                    csv_field(&e.operation),
                    csv_field(&e.item),
                    csv_field(&e.result),
                    csv_field(&e.client_ip),
                ];
                out.push_str(&row.join(","));
                out.push_str("\r\n");
            }
            8
        }
        Answer::Refusals(list) => {
            out.push_str("Vault,Who,Refused,Last refused (UTC),Operations\r\n");
            for r in refusal_rows(list, &loaded.names, range) {
                let row = [
                    csv_field(&r.vault),
                    csv_field(&r.who),
                    r.count.to_string(),
                    csv_field(&r.last),
                    csv_field(&r.operations),
                ];
                out.push_str(&row.join(","));
                out.push_str("\r\n");
            }
            5
        }
    };
    for v in &loaded.no_logging {
        not_read(
            &mut out,
            cols,
            v,
            "Doesn't send its audit logs to a Log Analytics workspace",
        );
    }
    for v in &loaded.settings_not_read {
        not_read(&mut out, cols, &v.name, &v.reason);
    }
    for w in &loaded.workspaces_not_read {
        not_read(
            &mut out,
            cols,
            &w.vaults,
            &format!("Workspace {}: {}", w.name, w.reason),
        );
    }
    if loaded.capped_vaults {
        not_read(
            &mut out,
            cols,
            "",
            &format!(
                "Only the first {MAX_VAULTS} of {} vaults by name were read",
                loaded.vaults_total
            ),
        );
    }
    if loaded.capped {
        not_read(
            &mut out,
            cols,
            "",
            &format!(
                "Only the first {} rows are included. Use a shorter time range",
                audit::MAX_ROWS
            ),
        );
    }
    out
}

/// `/audit.csv`. Without a report, an old per-vault address, sent to the
/// last vault used as before.
pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    req: Request,
) -> PageResult {
    let Query(filter) = Query::<ReportFilter>::try_from_uri(req.uri()).unwrap_or_default();
    let Some(report) = Report::parse(&filter.report) else {
        return Ok(super::moved::legacy(session, shell, req).await);
    };
    let range = filter.range(report);
    let q = match ReportQuery::new(report, range, &filter.person) {
        Ok(q) => q,
        Err(_) => {
            return Err(PageError::new(
                shell.at(Section::Audit),
                Problem::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Those filters aren't valid",
                    PERSON_HELP,
                ),
            )
            .into());
        }
    };
    let loaded = match load(&state, &session, &q).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell.at(Section::Audit),
                Problem::from_azure(&e, need_for(&e)),
            )
            .into());
        }
    };
    let mut res: Response = (StatusCode::OK, to_csv(&loaded, range)).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"keyring-audit-{}.csv\"",
        report.slug()
    )) {
        h.insert(CONTENT_DISPOSITION, v);
    }
    Ok(no_store(res))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_stages_fit_inside_the_request_limit() {
        assert!(
            SETTINGS_LIMITS.deadline + QUERY_LIMITS.deadline + Duration::from_secs(20)
                <= crate::routes::headers::REQUEST_TIMEOUT
        );
        assert!(SETTINGS_LIMITS.vault_timeout < SETTINGS_LIMITS.deadline);
        assert!(QUERY_LIMITS.vault_timeout < QUERY_LIMITS.deadline);
    }

    #[test]
    fn old_vault_bookmarks_are_recognised() {
        assert!(is_old_vault_query(Some("item=db&from=secret")));
        assert!(is_old_vault_query(Some("range=7d&operation=SecretGet")));
        assert!(is_old_vault_query(Some("person=alex")));
        assert!(!is_old_vault_query(Some("report=reads&range=7d")));
        assert!(!is_old_vault_query(Some(
            "range=7d&report=person&person=alex"
        )));
        assert!(!is_old_vault_query(Some("")));
        assert!(!is_old_vault_query(None));
    }

    #[test]
    fn detail_links_stay_on_the_vaults_own_page() {
        assert_eq!(
            detail_url("kv-a", Range::Week, "db-password", "", "secret"),
            "/v/kv-a/audit?range=7d&item=db-password&from=secret"
        );
        assert_eq!(
            detail_url("kv-a", Range::Month, "", "sam@example.com", ""),
            "/v/kv-a/audit?range=30d&person=sam%40example.com"
        );
        // Values that couldn't be a name or a person are left out.
        assert_eq!(
            detail_url("kv-a", Range::Day, "a b", "x\"y", "secret"),
            "/v/kv-a/audit?range=24h"
        );
        assert_eq!(detail_url("", Range::Day, "db", "", ""), "");
    }
}
