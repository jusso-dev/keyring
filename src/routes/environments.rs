//! Multi-environment collaboration: compare secrets across environment vaults,
//! export parity reports to CSV, and set distinct per-environment values for a
//! secret in one audited workflow.
//!
//! Nothing is stored outside Azure. Environment labels and groups come from
//! each vault's ARM tags (or standard suffixes such as `-dev`, `-test`,
//! `-prod`). The comparison matrix reads only names and properties via
//! [`super::every_vault`]; values are never read.

use std::collections::{BTreeMap, BTreeSet};

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::audit::{Action, ItemEvents, Outcome, Refusal};
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::{Attributes, SecretsApi, SetSecret, now_ts};
use crate::azure::vaults::{self, Vault, is_valid_vault_name};
use crate::dates;
use crate::description;
use crate::environments::{
    self, CellState, EnvGroup, EnvLabel, EnvVault, MAX_COMPARE_VAULTS, Matrix, MatrixColumn,
    MatrixCounts, MatrixRow, SiblingEnv,
};
use crate::owner;
use crate::reveal_limit::{self, Field as RevealField, Limit};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::every_vault;
use crate::routes::forms::{FieldErrors, name_problem};
use crate::routes::lifecycle::Kind;
use crate::routes::secrets::form::{MAX_CONTENT_TYPE, MAX_TAGS, MAX_VALUE_BYTES};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::tag_rows::{self, Suggestions, TagField, TagPost};
use crate::secret::Secret;

/// Query parameters for `/environments` and `/environments.csv`.
#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct EnvQuery {
    /// A discovered environment group name.
    #[serde(default)]
    pub group: String,
    /// Comma-separated list of vault names (2 to 8). Overrides `group`.
    #[serde(default)]
    pub vaults: String,
    /// Repeated `v=<vault>` checkboxes from the custom vault picker form.
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub tag: String,
    /// `missing`, `attention`, `drift`, `complete` or empty.
    #[serde(default)]
    pub parity: String,
    /// "Owned by me" filter (`1`).
    #[serde(default)]
    pub mine: String,
}

impl EnvQuery {
    pub(super) fn mine_on(&self) -> bool {
        owner::mine_on(&self.mine)
    }

    pub(super) fn has_filters(&self) -> bool {
        !self.q.trim().is_empty()
            || !self.tag.trim().is_empty()
            || !self.parity.is_empty()
            || self.mine_on()
    }

    fn matches(&self, row: &MatrixRow, upn: Option<&str>) -> bool {
        if self.mine_on() && !row.owned_by(upn) {
            return false;
        }
        if !self.parity.is_empty() && row.parity.slug() != self.parity {
            return false;
        }
        let q = self.q.trim().to_ascii_lowercase();
        if !q.is_empty() && !row.filter_text.contains(&q) {
            return false;
        }
        row.has_tag(&self.tag)
    }
}

/// Extract repeated `v=...` query parameters from the raw query string
/// (because `serde_urlencoded` doesn't deserialize repeated keys into `Vec`).
fn repeated_vaults(raw_query: Option<&str>) -> Vec<String> {
    let Some(q) = raw_query else {
        return Vec::new();
    };
    openidconnect::url::form_urlencoded::parse(q.as_bytes())
        .filter_map(|(k, v)| (k == "v").then(|| v.trim().to_owned()))
        .filter(|v| !v.is_empty())
        .collect()
}

/// Resolve which vaults to compare, given visible vaults and query params.
struct Selection {
    groups: Vec<EnvGroup>,
    all_vaults: Vec<EnvVault>,
    selected: Vec<EnvVault>,
    active_group: Option<String>,
    /// True when the requested selection had more than `MAX_COMPARE_VAULTS`.
    capped: bool,
}

fn select_vaults(
    all: Vec<Vault>,
    group_param: &str,
    vaults_csv: &str,
    picked: &[String],
) -> Selection {
    let groups = environments::discover_groups(&all);
    let mut all_vaults: Vec<EnvVault> = all.into_iter().map(EnvVault::from_vault).collect();
    environments::sort_env_vaults(&mut all_vaults);

    // Explicit vault list (either checkboxes `v=...` or `vaults=a,b,c`).
    let requested: Vec<String> = if !picked.is_empty() {
        picked.to_vec()
    } else if !vaults_csv.trim().is_empty() {
        vaults_csv
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let mut capped = false;
    let (mut selected, active_group) = if !requested.is_empty() {
        let mut seen = BTreeSet::new();
        let mut matched = Vec::new();
        for name in requested {
            if let Some(ev) = all_vaults
                .iter()
                .find(|v| v.vault.name.eq_ignore_ascii_case(&name))
                && seen.insert(ev.vault.name.to_ascii_lowercase())
            {
                matched.push(ev.clone());
            }
        }
        environments::sort_env_vaults(&mut matched);
        if matched.len() > MAX_COMPARE_VAULTS {
            matched.truncate(MAX_COMPARE_VAULTS);
            capped = true;
        }
        (matched, None)
    } else if !group_param.trim().is_empty() {
        if let Some(g) = groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(group_param.trim()))
        {
            let mut v = g.vaults.clone();
            if v.len() > MAX_COMPARE_VAULTS {
                v.truncate(MAX_COMPARE_VAULTS);
                capped = true;
            }
            (v, Some(g.name.clone()))
        } else {
            (Vec::new(), None)
        }
    } else if let Some(first) = groups.first() {
        let mut v = first.vaults.clone();
        if v.len() > MAX_COMPARE_VAULTS {
            v.truncate(MAX_COMPARE_VAULTS);
            capped = true;
        }
        (v, Some(first.name.clone()))
    } else {
        let mut v = all_vaults.clone();
        if v.len() > MAX_COMPARE_VAULTS {
            v.truncate(MAX_COMPARE_VAULTS);
            capped = true;
        }
        (v, None)
    };

    environments::sort_env_vaults(&mut selected);
    Selection {
        groups,
        all_vaults,
        selected,
        active_group,
        capped,
    }
}

fn vaults_param(selected: &[EnvVault]) -> String {
    selected
        .iter()
        .map(|v| v.vault.name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

struct GroupTab {
    name: String,
    count: usize,
    active: bool,
    href: String,
}

struct VaultPick {
    name: String,
    env: EnvLabel,
    selected: bool,
}

#[derive(Template)]
#[template(path = "environments/index.html")]
struct MatrixPage {
    shell: Shell,
    groups: Vec<GroupTab>,
    vault_picks: Vec<VaultPick>,
    columns: Vec<MatrixColumn>,
    rows: Vec<MatrixRow>,
    counts: MatrixCounts,
    query: EnvQuery,
    vaults_csv: String,
    capped: bool,
    max_vaults: usize,
    tag_options: Vec<String>,
    csv_url: String,
    set_url: String,
    clear_url: String,
    total_visible_vaults: usize,
}

impl MatrixPage {
    fn parity_options(&self) -> [(&'static str, &'static str, bool); 5] {
        let p = self.query.parity.as_str();
        [
            ("", "All", p.is_empty()),
            ("missing", "Missing in an environment", p == "missing"),
            ("attention", "Needs attention", p == "attention"),
            ("drift", "Metadata differs", p == "drift"),
            ("complete", "In sync", p == "complete"),
        ]
    }

    fn filter_url(&self, parity: &str) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/environments?vaults={}&q={}&tag={}&parity={}{}",
            enc(&self.vaults_csv),
            enc(&self.query.q),
            enc(&self.query.tag),
            enc(parity),
            if self.query.mine_on() { "&mine=1" } else { "" }
        )
    }

    fn create_href(&self, vault: &str, name: &str, type_slug: &str) -> String {
        let enc = crate::auth::return_to::encode;
        if type_slug.is_empty() {
            format!("/v/{vault}/secrets/-/new?name={}", enc(name))
        } else {
            format!(
                "/v/{vault}/secrets/-/new?name={}&type={}",
                enc(name),
                enc(type_slug)
            )
        }
    }

    fn copy_href(&self, src_vault: &str, name: &str, to_vault: &str) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/v/{src_vault}/secrets/{name}/copy?to_vault={}&to_name={}",
            enc(to_vault),
            enc(name)
        )
    }

    fn set_secret_href(&self, name: &str) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/environments/set?vaults={}&name={}",
            enc(&self.vaults_csv),
            enc(name)
        )
    }
}

async fn load_matrix(state: &AppState, session: &CurrentSession, selected: &[EnvVault]) -> Matrix {
    let wanted: Vec<String> = selected.iter().map(|v| v.vault.name.clone()).collect();
    let fanned = every_vault::read(state, session, wanted).await;
    let skipped_map: BTreeMap<String, String> = fanned
        .skipped
        .into_iter()
        .map(|s| (s.vault.to_ascii_lowercase(), s.reason))
        .collect();
    let items_map: BTreeMap<String, Vec<crate::expiry::Item>> = fanned
        .read
        .into_iter()
        .map(|(v, items)| (v, (*items).clone()))
        .collect();

    let columns: Vec<MatrixColumn> = selected
        .iter()
        .map(|ev| MatrixColumn {
            vault: ev.vault.name.clone(),
            env: ev.env.clone(),
            read_error: skipped_map
                .get(&ev.vault.name.to_ascii_lowercase())
                .cloned(),
        })
        .collect();

    Matrix::build(columns, &items_map, now_ts(), state.config.stale_after_days)
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    uri: axum::http::Uri,
    Query(query): Query<EnvQuery>,
) -> PageResult {
    let shell = shell.at(Section::Environments);
    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                return Err(PageError::new(
                    shell,
                    Problem::from_azure(&err, Need::ListVaults).returning_to("/environments"),
                )
                .into());
            }
        };
    let total_visible_vaults = all.len();
    let picked = repeated_vaults(uri.query());
    let sel = select_vaults(all, &query.group, &query.vaults, &picked);
    let vaults_csv = vaults_param(&sel.selected);
    let matrix = if sel.selected.is_empty() {
        Matrix {
            columns: Vec::new(),
            rows: Vec::new(),
            counts: MatrixCounts::default(),
        }
    } else {
        load_matrix(&state, &session, &sel.selected).await
    };

    let tag_options = {
        let mut all_tags = Vec::new();
        for row in &matrix.rows {
            for cell in &row.cells {
                if let CellState::Present(p) = cell {
                    all_tags.push(&p.tags);
                }
            }
        }
        tag_rows::Suggestions::from_sets(
            all_tags
                .into_iter()
                .map(|t| t.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
        )
        .filter_options()
    };

    let upn = session.0.user.username.clone();
    let rows: Vec<MatrixRow> = matrix
        .rows
        .into_iter()
        .filter(|r| query.matches(r, upn.as_deref()))
        .collect();

    let enc = crate::auth::return_to::encode;
    let groups: Vec<GroupTab> = sel
        .groups
        .iter()
        .map(|g| GroupTab {
            name: g.name.clone(),
            count: g.vaults.len(),
            active: sel
                .active_group
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(&g.name)),
            href: format!("/environments?group={}", enc(&g.name)),
        })
        .collect();

    let selected_set: BTreeSet<String> = sel
        .selected
        .iter()
        .map(|v| v.vault.name.to_ascii_lowercase())
        .collect();
    let vault_picks: Vec<VaultPick> = sel
        .all_vaults
        .iter()
        .map(|v| VaultPick {
            name: v.vault.name.clone(),
            env: v.env.clone(),
            selected: selected_set.contains(&v.vault.name.to_ascii_lowercase()),
        })
        .collect();

    let csv_url = format!(
        "/environments.csv?vaults={}&q={}&tag={}&parity={}{}",
        enc(&vaults_csv),
        enc(&query.q),
        enc(&query.tag),
        enc(&query.parity),
        if query.mine_on() { "&mine=1" } else { "" }
    );
    let set_url = if vaults_csv.is_empty() {
        "/environments/set".to_owned()
    } else {
        format!("/environments/set?vaults={}", enc(&vaults_csv))
    };
    let clear_url = if vaults_csv.is_empty() {
        "/environments".to_owned()
    } else {
        format!("/environments?vaults={}", enc(&vaults_csv))
    };

    Ok(render(&MatrixPage {
        shell,
        groups,
        vault_picks,
        columns: matrix.columns,
        rows,
        counts: matrix.counts,
        query,
        vaults_csv,
        capped: sel.capped,
        max_vaults: MAX_COMPARE_VAULTS,
        tag_options,
        csv_url,
        set_url,
        clear_url,
        total_visible_vaults,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    uri: axum::http::Uri,
    Query(query): Query<EnvQuery>,
) -> PageResult {
    let shell = shell.at(Section::Environments);
    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                return Err(PageError::new(
                    shell,
                    Problem::from_azure(&err, Need::ListVaults).returning_to("/environments"),
                )
                .into());
            }
        };
    let picked = repeated_vaults(uri.query());
    let sel = select_vaults(all, &query.group, &query.vaults, &picked);
    let mut matrix = load_matrix(&state, &session, &sel.selected).await;
    let upn = session.0.user.username.clone();
    matrix.rows.retain(|r| query.matches(r, upn.as_deref()));

    let body = matrix.to_csv();
    Ok(no_store(
        (
            [
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/csv; charset=utf-8"),
                ),
                (
                    CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"keyring-environments.csv\""),
                ),
            ],
            body,
        )
            .into_response(),
    ))
}

// ---------------------------------------------------------------------------
// Cross-environment sibling panel on a secret's detail page
// ---------------------------------------------------------------------------

/// Summary shown on `/v/{vault}/secrets/{name}` when the vault is part of an
/// environment group (or another vault has a secret of the same name).
pub(crate) struct SiblingsView {
    pub group_name: String,
    pub rows: Vec<SiblingEnv>,
    pub compare_url: String,
    pub set_url: String,
    pub type_slug: String,
    pub can_copy_from_here: bool,
}

impl SiblingsView {
    pub(crate) fn create_href(&self, target_vault: &str, name: &str) -> String {
        let enc = crate::auth::return_to::encode;
        if self.type_slug.is_empty() {
            format!("/v/{target_vault}/secrets/-/new?name={}", enc(name))
        } else {
            format!(
                "/v/{target_vault}/secrets/-/new?name={}&type={}",
                enc(name),
                enc(self.type_slug.as_str())
            )
        }
    }

    pub(crate) fn copy_href(&self, src_vault: &str, name: &str, target_vault: &str) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/v/{src_vault}/secrets/{name}/copy?to_vault={}&to_name={}",
            enc(target_vault),
            enc(name)
        )
    }
}

/// Look up sibling environments for `vault` and `name`. Never fails the detail
/// page: if vaults can't be listed, returns `None`.
pub(crate) async fn siblings_for_secret(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
    content_type: &str,
    can_copy_from_here: bool,
) -> Option<SiblingsView> {
    let all = vaults::list_vaults(&state.azure, &session.0, &state.config.management_url)
        .await
        .ok()?;
    let group = environments::group_for_vault(&all, vault)?;
    let mut env_vaults = group.vaults;
    if env_vaults.len() < 2 {
        return None;
    }
    if env_vaults.len() > MAX_COMPARE_VAULTS {
        // Ensure the current vault stays included.
        let mut kept: Vec<EnvVault> = env_vaults
            .iter()
            .filter(|v| v.vault.name.eq_ignore_ascii_case(vault))
            .cloned()
            .collect();
        for ev in env_vaults {
            if kept.len() >= MAX_COMPARE_VAULTS {
                break;
            }
            if !kept
                .iter()
                .any(|k| k.vault.name.eq_ignore_ascii_case(&ev.vault.name))
            {
                kept.push(ev);
            }
        }
        environments::sort_env_vaults(&mut kept);
        env_vaults = kept;
    }

    let matrix = load_matrix(state, session, &env_vaults).await;
    let matched_row = matrix
        .rows
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(name));

    let mut rows = Vec::with_capacity(matrix.columns.len());
    for (idx, col) in matrix.columns.iter().enumerate() {
        let state = if col.read_error.is_some() {
            CellState::NotRead
        } else if let Some(r) = matched_row {
            r.cells[idx].clone()
        } else {
            CellState::Missing
        };
        rows.push(SiblingEnv {
            vault: col.vault.clone(),
            env: col.env.clone(),
            is_current: col.vault.eq_ignore_ascii_case(vault),
            state,
        });
    }

    let enc = crate::auth::return_to::encode;
    let csv = vaults_param(&env_vaults);
    let type_slug =
        match crate::secret_types::classify((!content_type.is_empty()).then_some(content_type)) {
            crate::secret_types::ContentKind::Typed(t) => t.slug().to_owned(),
            _ => String::new(),
        };

    Some(SiblingsView {
        group_name: group.name,
        rows,
        compare_url: format!("/environments?vaults={}&q={}", enc(&csv), enc(name)),
        set_url: format!("/environments/set?vaults={}&name={}", enc(&csv), enc(name)),
        type_slug,
        can_copy_from_here,
    })
}

// ---------------------------------------------------------------------------
// Multi-environment secret creation / value update (/environments/set)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub(super) struct SetQuery {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub vaults: String,
    #[serde(default)]
    pub name: String,
}

/// Static field IDs for up to [`MAX_COMPARE_VAULTS`] per-environment values,
/// so [`FieldErrors`] can name each environment's input directly.
const ENV_VAL_IDS: [&str; MAX_COMPARE_VAULTS] = [
    "env-val-1",
    "env-val-2",
    "env-val-3",
    "env-val-4",
    "env-val-5",
    "env-val-6",
    "env-val-7",
    "env-val-8",
];

/// One target vault row shown on the multi-environment set form.
struct EnvTargetRow {
    vault: String,
    env: EnvLabel,
    /// Short note about the current state of `name` in this vault, if known.
    status_note: String,
    /// Static input id and name (`env-val-1` .. `env-val-8`).
    field_id: &'static str,
    /// `aria-describedby` help IDs for this environment's input.
    help_ids: String,
}

#[derive(Default)]
struct SetFormView {
    name: String,
    content_type: String,
    expires: String,
    not_before: String,
    description: String,
    owners: owner::Fields,
    reveal: RevealField,
    tags: TagField,
    enabled: bool,
    allow_duplicate: bool,
}

#[derive(Template)]
#[template(path = "environments/set.html")]
struct SetPage {
    shell: Shell,
    targets: Vec<EnvTargetRow>,
    vaults_csv: String,
    form: SetFormView,
    errors: FieldErrors,
    /// True when a duplicate value was detected so the confirmation checkbox
    /// is shown prominently.
    show_duplicate_confirm: bool,
    back_url: String,
    owner_options: Vec<String>,
}

impl SetPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }

    fn policy_help(&self) -> String {
        if !self.shell.password_policy.is_on() {
            return String::new();
        }
        format!(
            "Keyring's password policy applies to each non-empty value: {}.",
            self.shell.password_policy.describe()
        )
    }
}

fn target_rows(selected: &[EnvVault], mut notes: BTreeMap<String, String>) -> Vec<EnvTargetRow> {
    selected
        .iter()
        .enumerate()
        .take(MAX_COMPARE_VAULTS)
        .map(|(i, ev)| {
            let field_id = ENV_VAL_IDS[i];
            let status_note = notes.remove(&ev.vault.name).unwrap_or_default();
            let help_ids = if status_note.is_empty() {
                "env-values-help".to_owned()
            } else {
                format!("env-values-help {field_id}-note")
            };
            EnvTargetRow {
                field_id,
                help_ids,
                status_note,
                vault: ev.vault.name.clone(),
                env: ev.env.clone(),
            }
        })
        .collect()
}

fn render_set_page(page: SetPage) -> Response {
    let status = if page.errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    no_store((status, render(&page)).into_response())
}

pub(super) async fn set_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    uri: axum::http::Uri,
    Query(q): Query<SetQuery>,
) -> PageResult {
    let shell = shell.at(Section::Environments);
    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                return Err(PageError::new(
                    shell,
                    Problem::from_azure(&err, Need::ListVaults).returning_to("/environments"),
                )
                .into());
            }
        };
    let picked = repeated_vaults(uri.query());
    let sel = select_vaults(all, &q.group, &q.vaults, &picked);
    if sel.selected.is_empty() {
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::BAD_REQUEST,
                "No vaults to write to",
                "You can't see any vaults yet. You need Reader on the vaults and Key Vault Secrets Officer on the ones you want to write to.",
            )
            .returning_to("/environments"),
        )
        .into());
    }

    let safe_name = q.name.trim().to_owned();
    let safe_name =
        if !safe_name.is_empty() && crate::routes::vault_ctx::is_valid_object_name(&safe_name) {
            safe_name
        } else {
            String::new()
        };

    // Inspect cached lists (or read them) to show existing status per vault
    // when a secret name is pre-filled, never reading values.
    let mut existing_notes: BTreeMap<String, String> = BTreeMap::new();
    let mut tag_suggest = Suggestions::default();
    if !safe_name.is_empty() {
        let matrix = load_matrix(&state, &session, &sel.selected).await;
        let row = matrix
            .rows
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case(&safe_name));
        let mut all_tags = Vec::new();
        for (idx, col) in matrix.columns.iter().enumerate() {
            let note = if col.read_error.is_some() {
                "Couldn't check current state".to_owned()
            } else if let Some(r) = row {
                match &r.cells[idx] {
                    CellState::Present(p) => {
                        all_tags.push(p.tags.clone());
                        if p.changed.is_empty() {
                            "Exists (will add a new version)".to_owned()
                        } else {
                            format!(
                                "Exists, last changed {} (will add a new version)",
                                p.changed
                            )
                        }
                    }
                    CellState::Missing => "Not in this vault yet (will create)".to_owned(),
                    CellState::NotRead => "Couldn't check current state".to_owned(),
                }
            } else {
                "Not in this vault yet (will create)".to_owned()
            };
            existing_notes.insert(col.vault.clone(), note);
        }
        tag_suggest = Suggestions::from_sets(
            all_tags
                .iter()
                .map(|t| t.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
        );
    }

    let targets = target_rows(&sel.selected, existing_notes);

    let vaults_csv = vaults_param(&sel.selected);
    let enc = crate::auth::return_to::encode;
    let back_url = format!("/environments?vaults={}", enc(&vaults_csv));
    let mut tags = TagField::of(&BTreeMap::new());
    tags.suggest = tag_suggest;

    Ok(render_set_page(SetPage {
        shell,
        targets,
        vaults_csv,
        form: SetFormView {
            name: safe_name,
            enabled: true,
            tags,
            ..SetFormView::default()
        },
        errors: FieldErrors::new(),
        show_duplicate_confirm: false,
        back_url,
        owner_options: Vec::new(),
    }))
}

/// Outcome for one vault in a multi-environment write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnvWriteStatus {
    Created,
    NewVersion,
    SkippedBlank,
    BlockedManaged,
    BlockedDeleted,
    Denied,
    Failed,
}

struct EnvResultRow {
    vault: String,
    env: EnvLabel,
    status: EnvWriteStatus,
    version: String,
    why: String,
}

#[derive(Template)]
#[template(path = "environments/results.html")]
struct ResultsPage {
    shell: Shell,
    name: String,
    rows: Vec<EnvResultRow>,
    written: usize,
    failed: usize,
    compare_url: String,
}

/// Normalise CRLF/CR line breaks to LF as browsers send CRLF.
fn normalise_lf(raw: &str) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

/// Parse and apply a multi-environment set request.
pub(super) async fn apply(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    body: Bytes,
) -> PageResult {
    let shell = shell.at(Section::Environments);

    // Parse URL-encoded body manually so per-vault secret values go straight
    // into `Secret` and never sit in a debuggable map.
    let mut csrf = String::new();
    let mut vaults_csv = String::new();
    let mut name = String::new();
    let mut content_type = String::new();
    let mut expires = String::new();
    let mut not_before = String::new();
    let mut desc = String::new();
    let mut owner_raw = String::new();
    let mut notify_raw = String::new();
    let mut reveal_raw = String::new();
    let mut enabled = false;
    let mut allow_duplicate = false;
    let mut tag_post = TagPost::default();
    let mut values_by_id: BTreeMap<String, Secret> = BTreeMap::new();

    for (k, v) in openidconnect::url::form_urlencoded::parse(&body) {
        let key = k.as_ref();
        if tag_post.take(key, v.to_string()) {
            continue;
        }
        match key {
            "csrf" => csrf = v.into_owned(),
            "vaults" => vaults_csv = v.into_owned(),
            "name" => name = v.into_owned(),
            "content_type" => content_type = v.into_owned(),
            "expires" => expires = v.into_owned(),
            "not_before" => not_before = v.into_owned(),
            "description" => desc = v.into_owned(),
            "owner" => owner_raw = v.into_owned(),
            "notify" => notify_raw = v.into_owned(),
            "reveal" => reveal_raw = v.into_owned(),
            "enabled" => enabled = true,
            "allow_duplicate" => allow_duplicate = true,
            other if ENV_VAL_IDS.contains(&other) => {
                values_by_id.insert(other.to_owned(), Secret::new(normalise_lf(&v)));
            }
            _ => {}
        }
    }

    if !session.0.csrf_matches_any(&csrf) {
        crate::audit::refuse(Refusal::Csrf);
        return Err(PageError::new(shell, Problem::stale_form()).into());
    }

    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                return Err(PageError::new(
                    shell,
                    Problem::from_azure(&err, Need::ListVaults).returning_to("/environments"),
                )
                .into());
            }
        };

    let sel = select_vaults(all, "", &vaults_csv, &[]);
    if sel.selected.is_empty() {
        crate::audit::refuse(Refusal::InvalidRequest);
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::BAD_REQUEST,
                "No valid vaults selected",
                "Pick the vaults to write to from the Environments page and try again.",
            )
            .returning_to("/environments"),
        )
        .into());
    }

    let trimmed_name = name.trim().to_owned();
    let mut errors = FieldErrors::new();
    let mut refusal_code: Option<Refusal> = None;

    if let Some(msg) = name_problem(Kind::Secret, &trimmed_name) {
        errors.push("name", msg);
    } else {
        crate::audit::note_item(&trimmed_name);
    }

    // Content type: optional, max 255, and never Keyring's typed JSON prefix
    // (typed secrets use the structured form on the vault's create page).
    let ct = content_type.trim().to_owned();
    if ct.chars().count() > MAX_CONTENT_TYPE {
        errors.push(
            "content_type",
            format!("Content type can be at most {MAX_CONTENT_TYPE} characters."),
        );
    } else if ct
        .to_ascii_lowercase()
        .starts_with("application/vnd.keyring.")
    {
        errors.push(
            "content_type",
            "Keyring's structured content types can't be set here. Use a plain content type or create a typed secret in each vault.",
        );
    }

    // Dates
    let now = now_ts();
    let parsed_nbf = if not_before.trim().is_empty() {
        None
    } else {
        match dates::parse_iso_date(not_before.trim()) {
            Some(ts) => Some(ts),
            None => {
                errors.push("not_before", "Enter a real date as YYYY-MM-DD.");
                None
            }
        }
    };
    let parsed_exp = if expires.trim().is_empty() {
        None
    } else {
        match dates::parse_iso_date(expires.trim()) {
            Some(ts) if ts <= now => {
                errors.push("expires", "The expiry date has already passed.");
                None
            }
            Some(ts) => Some(ts),
            None => {
                errors.push("expires", "Enter a real date as YYYY-MM-DD.");
                None
            }
        }
    };
    if let (Some(nbf), Some(exp)) = (parsed_nbf, parsed_exp)
        && exp <= nbf
    {
        errors.push(
            "expires",
            "The expiry date must be after the active from date.",
        );
    }

    // Description, owner, notify, reveal limit, tags
    let mut base_tags = tag_rows::check(&tag_post, &BTreeMap::new(), &mut errors);
    match description::clean(&desc) {
        Ok(Some(clean)) => {
            base_tags.insert(description::TAG.to_owned(), clean);
        }
        Ok(None) => {}
        Err(msg) => errors.push("description", msg),
    }
    let owner_rules = owner::Rules::of(&state.config);
    match owner::clean_owner(&owner_raw, owner_rules) {
        Ok(Some(o)) => {
            base_tags.insert(owner::OWNER_TAG.to_owned(), o);
        }
        Ok(None) if owner_rules.require => {
            refusal_code.get_or_insert(Refusal::OwnerRequired);
            errors.push(
                "owner",
                "Give an owner email address. Keyring is set to need an owner on every secret.",
            );
        }
        Ok(None) => {}
        Err(msg) => errors.push("owner", msg),
    }
    match owner::clean_notify(&notify_raw, owner_rules) {
        Ok(Some(n)) => {
            base_tags.insert(owner::NOTIFY_TAG.to_owned(), n);
        }
        Ok(None) => {}
        Err(msg) => errors.push("notify", msg),
    }
    let chosen_limit = match reveal_raw.trim() {
        "" => Limit::Open,
        "copy-only" => Limit::CopyOnly,
        "none" => Limit::NoReveal,
        _ => {
            errors.push("reveal", "Pick a reveal limit from the list.");
            Limit::Open
        }
    };
    let base_tags = reveal_limit::with(&base_tags, chosen_limit);
    if base_tags.len() > MAX_TAGS {
        refusal_code.get_or_insert(Refusal::TagLimit);
        errors.push(
            "tags",
            format!(
                "Key Vault allows at most {MAX_TAGS} tags on a secret (description, owner, notify and reveal limit each count as one). This has {}.",
                base_tags.len()
            ),
        );
    }

    // Collect non-empty per-vault values and run password policy + duplicate check.
    let mut non_empty: Vec<(&EnvVault, &Secret)> = Vec::new();
    for (idx, ev) in sel.selected.iter().enumerate().take(MAX_COMPARE_VAULTS) {
        let field_id = ENV_VAL_IDS[idx];
        if let Some(sec) = values_by_id.get(field_id) {
            if sec.expose().is_empty() {
                continue;
            }
            if sec.expose().len() > MAX_VALUE_BYTES {
                errors.push(
                    field_id,
                    format!(
                        "Value for {} is over {} KB, which is Key Vault's limit.",
                        ev.vault.name,
                        MAX_VALUE_BYTES / 1024
                    ),
                );
                continue;
            }
            if let Some(problem) = state
                .config
                .password_policy
                .check(&format!("Value for {}", ev.vault.name), sec)
            {
                refusal_code.get_or_insert(Refusal::PasswordPolicy);
                errors.push(field_id, problem);
            }
            non_empty.push((ev, sec));
        }
    }

    if non_empty.is_empty() && errors.is_empty() {
        errors.push(
            ENV_VAL_IDS[0],
            "Enter a value for at least one environment.",
        );
    }

    let check_pairs: Vec<(&str, bool, &Secret)> = non_empty
        .iter()
        .map(|(ev, s)| (ev.vault.name.as_str(), ev.env.is_production(), *s))
        .collect();
    let dupes = environments::find_duplicate_values(&check_pairs);
    let show_duplicate_confirm = !dupes.is_empty();
    if !dupes.is_empty() && !allow_duplicate {
        refusal_code.get_or_insert(Refusal::InvalidRequest);
        for d in &dupes {
            let joined = d.vaults.join(", ");
            let msg = if d.includes_production {
                format!(
                    "The same value was entered for {joined}, which includes a production environment. Use a separate value for production, or tick \"Allow the same value in more than one environment\" if this credential is intentionally shared."
                )
            } else {
                format!(
                    "The same value was entered for {joined}. Enter a distinct value per environment, or tick \"Allow the same value in more than one environment\" if this credential is intentionally shared."
                )
            };
            errors.push("allow_duplicate", msg);
        }
    }

    let enc = crate::auth::return_to::encode;
    let selected_csv = vaults_param(&sel.selected);
    let back_url = format!("/environments?vaults={}", enc(&selected_csv));

    if !errors.is_empty() {
        crate::audit::refuse(refusal_code.unwrap_or(Refusal::InvalidRequest));
        let targets = target_rows(&sel.selected, BTreeMap::new());
        return Ok(render_set_page(SetPage {
            shell,
            targets,
            vaults_csv: selected_csv,
            form: SetFormView {
                name: trimmed_name,
                content_type: ct,
                expires,
                not_before,
                description: desc,
                owners: owner::Fields {
                    owner: owner_raw,
                    notify: notify_raw,
                    owner_odd: false,
                    notify_odd: false,
                },
                reveal: RevealField {
                    selected: reveal_raw,
                    odd: None,
                    limited: false,
                },
                tags: TagField::posted(&tag_post, &BTreeMap::new()),
                enabled,
                allow_duplicate,
            },
            errors,
            show_duplicate_confirm,
            back_url,
            owner_options: Vec::new(),
        }));
    }

    // Write each target vault. Each write is wrapped in its own per-vault
    // ItemEvents audit record so Keyring's audit table tracks every vault
    // separately.
    let mut rows = Vec::with_capacity(sel.selected.len());
    let mut written = 0usize;
    let mut tried = 0usize;
    let mut all_denied = true;

    for (idx, ev) in sel.selected.iter().enumerate().take(MAX_COMPARE_VAULTS) {
        let vault_name = &ev.vault.name;
        if !is_valid_vault_name(vault_name) {
            continue;
        }
        let Some(secret_val) = values_by_id.remove(ENV_VAL_IDS[idx]) else {
            rows.push(EnvResultRow {
                vault: vault_name.clone(),
                env: ev.env.clone(),
                status: EnvWriteStatus::SkippedBlank,
                version: String::new(),
                why: "Left blank".to_owned(),
            });
            continue;
        };
        if secret_val.expose().is_empty() {
            rows.push(EnvResultRow {
                vault: vault_name.clone(),
                env: ev.env.clone(),
                status: EnvWriteStatus::SkippedBlank,
                version: String::new(),
                why: "Left blank".to_owned(),
            });
            continue;
        }

        tried += 1;
        session.0.forget_list(vault_name);
        let api = SecretsApi {
            azure: &state.azure,
            session: &session.0,
            vault_url: state.config.vault_url(vault_name),
        };

        // Inspect existing state before writing: refuse certificate-managed
        // secrets and soft-deleted names, and carry any stricter reveal limit.
        let existing_versions = match api.versions(&trimmed_name).await {
            Ok(v) => Some(v),
            Err(AzureError::Status { status: 404, .. }) => Some(Vec::new()),
            Err(AzureError::Status {
                status: 401 | 403, ..
            }) => {
                // Can't list versions, try the write directly so Key Vault
                // gives the definitive RBAC answer and audit record.
                None
            }
            Err(_) => None,
        };

        if let Some(ref versions) = existing_versions {
            if versions.first().is_some_and(|i| i.managed.unwrap_or(false)) {
                all_denied = false;
                ItemEvents::for_request(Action::SecretSet, state.audit_sink.clone())
                    .in_vault(vault_name)
                    .refused(&trimmed_name, Refusal::ManagedItem)
                    .await;
                rows.push(EnvResultRow {
                    vault: vault_name.clone(),
                    env: ev.env.clone(),
                    status: EnvWriteStatus::BlockedManaged,
                    version: String::new(),
                    why: "Belongs to a certificate; not overwritten.".to_owned(),
                });
                continue;
            }
            if versions.is_empty() && api.get_deleted(&trimmed_name).await.is_ok() {
                all_denied = false;
                ItemEvents::for_request(Action::SecretCreate, state.audit_sink.clone())
                    .in_vault(vault_name)
                    .refused(&trimmed_name, Refusal::InvalidRequest)
                    .await;
                rows.push(EnvResultRow {
                    vault: vault_name.clone(),
                    env: ev.env.clone(),
                    status: EnvWriteStatus::BlockedDeleted,
                    version: String::new(),
                    why: "A deleted secret with this name is still kept in this vault. Recover it first.".to_owned(),
                });
                continue;
            }
        }

        let existed = existing_versions.as_ref().is_some_and(|v| !v.is_empty());
        let carried_tags = match existing_versions.as_ref().and_then(|v| v.first()) {
            Some(cur) => reveal_limit::carry(&base_tags, cur.tags()),
            None => base_tags.clone(),
        };
        if carried_tags.len() > MAX_TAGS {
            all_denied = false;
            ItemEvents::for_request(Action::SecretSet, state.audit_sink.clone())
                .in_vault(vault_name)
                .refused(&trimmed_name, Refusal::TagLimit)
                .await;
            rows.push(EnvResultRow {
                vault: vault_name.clone(),
                env: ev.env.clone(),
                status: EnvWriteStatus::Failed,
                version: String::new(),
                why: format!(
                    "Carrying this vault's reveal limit would pass Key Vault's {MAX_TAGS} tags."
                ),
            });
            continue;
        }

        let action = if existed {
            Action::SecretSet
        } else {
            Action::SecretCreate
        };
        let req_body = SetSecret {
            value: secret_val,
            content_type: (!ct.is_empty()).then(|| ct.clone()),
            attributes: Attributes {
                enabled: Some(enabled),
                not_before: parsed_nbf,
                expires: parsed_exp,
                ..Attributes::default()
            },
            tags: Some(carried_tags),
        };

        let events = ItemEvents::for_request(action, state.audit_sink.clone()).in_vault(vault_name);
        let result = events
            .run(&trimmed_name, async {
                let res = api.set(&trimmed_name, &req_body).await;
                if let Ok(ref item) = res {
                    crate::audit::note_version(item.version());
                }
                res
            })
            .await;
        session.0.forget_list(vault_name);

        match result {
            Ok(item) => {
                written += 1;
                all_denied = false;
                rows.push(EnvResultRow {
                    vault: vault_name.clone(),
                    env: ev.env.clone(),
                    status: if existed {
                        EnvWriteStatus::NewVersion
                    } else {
                        EnvWriteStatus::Created
                    },
                    version: item.version().to_owned(),
                    why: String::new(),
                });
            }
            Err(AzureError::Status {
                status: 401 | 403, ..
            }) => {
                rows.push(EnvResultRow {
                    vault: vault_name.clone(),
                    env: ev.env.clone(),
                    status: EnvWriteStatus::Denied,
                    version: String::new(),
                    why: "Needs Key Vault Secrets Officer on this vault.".to_owned(),
                });
            }
            Err(err) => {
                all_denied = false;
                let why = match err {
                    AzureError::Status {
                        status: 409, code, ..
                    } if code.as_deref().is_some_and(|c| {
                        c.eq_ignore_ascii_case("ObjectIsDeletedButRecoverable")
                            || c.eq_ignore_ascii_case("Conflict")
                    }) =>
                    {
                        "A deleted secret with this name is still kept in this vault. Recover it first.".to_owned()
                    }
                    AzureError::Status { status, code, .. } => match code.as_deref() {
                        Some(c) if !c.is_empty() => format!("Key Vault refused it ({c})."),
                        _ => format!("Key Vault returned HTTP {status}."),
                    },
                    _ => "Couldn't reach Key Vault.".to_owned(),
                };
                rows.push(EnvResultRow {
                    vault: vault_name.clone(),
                    env: ev.env.clone(),
                    status: EnvWriteStatus::Failed,
                    version: String::new(),
                    why,
                });
            }
        }
    }

    if written < tried {
        let outcome = if written == 0 && all_denied {
            Outcome::Denied
        } else {
            Outcome::Failed
        };
        let code = if written == 0 {
            "none_written"
        } else {
            "partly_written"
        };
        crate::audit::end(outcome, code);
    }

    let failed = tried - written;
    let compare_url = format!(
        "/environments?vaults={}&q={}",
        enc(&selected_csv),
        enc(&trimmed_name)
    );

    Ok(no_store(
        render(&ResultsPage {
            shell,
            name: trimmed_name,
            rows,
            written,
            failed,
            compare_url,
        })
        .into_response(),
    ))
}
