//! Continuous white-label executive client reports and org-wide stats loading.
//!
//! All routes here are read-only metadata views (no secret values, no private
//! keys, no stored state). White-label branding options ride in GET query
//! parameters so teams can bookmark and re-export client reports continuously.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::now_ts;
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::executive::{
    OrgSnapshot, ReportOptions, ReportScope, ReportTheme, default_period, format_generated_utc,
    safe_filename_slug, to_csv, to_json,
};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault::{self, MAX_VAULTS};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

/// Load an organisation-wide metadata snapshot for the signed-in user.
///
/// Reuses the session's short-lived metadata cache (`every_vault::read`).
/// Only names and properties are read, never secret values.
pub(crate) async fn load_org_snapshot(
    state: &AppState,
    session: &CurrentSession,
    scope: ReportScope,
) -> Result<OrgSnapshot, AzureError> {
    let now = now_ts();
    let all_vaults =
        vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await?;
    let mut matching: Vec<_> = all_vaults
        .into_iter()
        .filter(|v| is_valid_vault_name(&v.name) && scope.matches_vault(v))
        .collect();
    matching.sort_by(|a, b| a.name.cmp(&b.name));
    let capped = matching.len() > MAX_VAULTS;
    if capped {
        matching.truncate(MAX_VAULTS);
    }

    let wanted: Vec<String> = matching.iter().map(|v| v.name.clone()).collect();
    let lists = async {
        if wanted.is_empty() {
            crate::azure::fanout::Fanned {
                read: Vec::new(),
                skipped: Vec::new(),
            }
        } else {
            every_vault::read(state, session, wanted).await
        }
    };
    let (read, defender) = tokio::join!(
        lists,
        crate::azure::defender::read(&state.azure, &session.0, &state.config.management_url),
    );
    let items: Vec<_> = read
        .read
        .iter()
        .flat_map(|(_, list)| list.iter())
        .filter(|i| !i.managed)
        .cloned()
        .collect();

    Ok(OrgSnapshot::build(
        &matching,
        &items,
        &read.skipped,
        capped,
        state.config.thresholds(),
        &defender,
        now,
    ))
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct ReportQuery {
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub prepared_by: String,
    #[serde(default)]
    pub period: String,
    #[serde(default)]
    pub theme: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub white_label: String,
    #[serde(default)]
    pub charts: String,
    #[serde(default)]
    pub vaults: String,
    #[serde(default)]
    pub envs: String,
    #[serde(default)]
    pub actions: String,
    #[serde(default)]
    pub format: String,
    /// Present when the form has been submitted so unchecked checkboxes turn off.
    #[serde(default)]
    pub submitted: String,
}

impl ReportQuery {
    fn flag(&self, val: &str, default_when_fresh: bool) -> bool {
        if val == "1" || val == "on" || val.eq_ignore_ascii_case("true") {
            return true;
        }
        if val == "0" || val.eq_ignore_ascii_case("false") {
            return false;
        }
        if self.submitted == "1" {
            false
        } else {
            default_when_fresh
        }
    }

    fn options(&self, now: i64) -> ReportOptions {
        let def_period = default_period(now);
        ReportOptions::sanitized(
            &self.client,
            &self.title,
            &self.prepared_by,
            &self.period,
            &self.theme,
            &self.scope,
            self.flag(&self.white_label, false),
            self.flag(&self.charts, true),
            self.flag(&self.vaults, true),
            self.flag(&self.envs, true),
            self.flag(&self.actions, true),
            &def_period,
        )
    }
}

#[derive(Template)]
#[template(path = "reports/executive.html")]
struct ExecutiveBuilderPage {
    shell: Shell,
    opts: ReportOptions,
    snap: OrgSnapshot,
    generated_utc: String,
    html_export_url: String,
    csv_export_url: String,
    json_export_url: String,
    continuous_url: String,
    themes: [ReportTheme; 6],
    scopes: [ReportScope; 3],
}

impl ExecutiveBuilderPage {
    fn is_theme(&self, t: &ReportTheme) -> bool {
        self.opts.theme == *t
    }

    fn is_scope(&self, s: &ReportScope) -> bool {
        self.opts.scope == *s
    }
}

#[derive(Template)]
#[template(path = "reports/export.html")]
struct StandaloneExportReport {
    opts: ReportOptions,
    snap: OrgSnapshot,
    generated_utc: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(query): Query<ReportQuery>,
) -> PageResult {
    let shell = shell.at(Section::Reports);
    let now = now_ts();
    let opts = query.options(now);
    let snap = match load_org_snapshot(&state, &session, opts.scope).await {
        Ok(s) => s,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/reports/executive"),
            )
            .into());
        }
    };
    let generated_utc = format_generated_utc(now);

    let html_export_url = format!(
        "/reports/executive/export?{}",
        opts.query_string(Some("html"))
    );
    let csv_export_url = format!(
        "/reports/executive/export?{}",
        opts.query_string(Some("csv"))
    );
    let json_export_url = format!(
        "/reports/executive/export?{}",
        opts.query_string(Some("json"))
    );
    let continuous_url = format!(
        "{}/reports/executive?{}",
        state.config.base_url.trim_end_matches('/'),
        opts.query_string(None)
    );

    Ok(no_store(
        render(&ExecutiveBuilderPage {
            shell,
            opts,
            snap,
            generated_utc,
            html_export_url,
            csv_export_url,
            json_export_url,
            continuous_url,
            themes: ReportTheme::ALL,
            scopes: [
                ReportScope::All,
                ReportScope::Production,
                ReportScope::NonProduction,
            ],
        })
        .into_response(),
    ))
}

pub(super) async fn export(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(query): Query<ReportQuery>,
) -> PageResult {
    let shell = shell.at(Section::Reports);
    let now = now_ts();
    let opts = query.options(now);
    let snap = match load_org_snapshot(&state, &session, opts.scope).await {
        Ok(s) => s,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/reports/executive"),
            )
            .into());
        }
    };
    let generated_utc = format_generated_utc(now);
    let slug = safe_filename_slug(&opts.client_name, opts.white_label);

    match query.format.trim().to_ascii_lowercase().as_str() {
        "csv" => {
            let body = to_csv(&snap, &opts, &generated_utc);
            let disp = format!("attachment; filename=\"{slug}-executive-report.csv\"");
            Ok(download_response("text/csv; charset=utf-8", &disp, body))
        }
        "json" => {
            let body = to_json(&snap, &opts, &generated_utc);
            let disp = format!("attachment; filename=\"{slug}-executive-report.json\"");
            Ok(download_response(
                "application/json; charset=utf-8",
                &disp,
                body,
            ))
        }
        _ => {
            let body = StandaloneExportReport {
                opts,
                snap,
                generated_utc,
            }
            .render()
            .expect("standalone executive report template renders");
            let disp = format!("attachment; filename=\"{slug}-executive-report.html\"");
            Ok(download_response("text/html; charset=utf-8", &disp, body))
        }
    }
}

fn download_response(content_type: &'static str, disposition: &str, body: String) -> Response {
    let mut res = (StatusCode::OK, body).into_response();
    res.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(val) = HeaderValue::from_str(disposition) {
        res.headers_mut().insert(CONTENT_DISPOSITION, val);
    }
    no_store(res)
}
