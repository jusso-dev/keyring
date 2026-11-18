//! Access review: one page and one CSV per vault, for a reviewer to export
//! each quarter. A row per secret, certificate and key, with its owner,
//! description, expiry, when its value last changed, who used it in the
//! last 90 days, who has access to it and what its rotation tags claim.
//!
//! It only reads, as the signed-in person, so like the access view and the
//! audit reports it writes none of Keyring's own audit events. It never
//! reads a value: the lists are list calls, the access is ARM's role
//! assignments and the vault resource, and "used by" is one query per Log
//! Analytics workspace the vault logs to, whatever the number of items
//! (see [`crate::azure::access_review`]).
//!
//! The three reads run side by side, each within the fan-out's limits, so
//! the page comes back inside the request limit with what it has. What it
//! couldn't read is said once at the top and marked on every cell it
//! touches ("Not known"), on the page and in the CSV, so neither can pass
//! for a full report when it isn't one. An empty cell never reads as
//! "unused" or "nobody has access".

use std::collections::HashMap;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::age::{self, Band};
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::access_review::{self as review, Answer, ItemUse, ReviewQuery};
use crate::azure::audit;
use crate::azure::fanout::{self, Limits};
use crate::azure::secrets::now_ts;
use crate::azure::used_by::{self, Caller};
use crate::dates;
use crate::expiry::{Item, ItemType, csv_field};
use crate::owner;
use crate::rotation::Rotation;
use crate::routes::access::{self, Access, Entry, Origin, PolicyRow};
use crate::routes::assets::render;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::used_by::{
    CallerRow, HINT_ARRIVED, HINT_CONSENT, HINT_LOGGING, HINT_READER, HINT_WORKSPACE,
};
use crate::routes::vault_ctx;

/// Most access entries in one CSV cell, before "and N more".
pub(crate) const MAX_ACCESS_IN_CELL: usize = 50;

/// "Used by" for the whole report: what was looked at, and what wasn't.
#[derive(Debug, Default)]
pub(crate) struct Usage {
    /// Why nothing could be told about any item. `None` when some of the
    /// log was read and events from the vault were found.
    pub unavailable: Option<String>,
    /// What to ask for. May be empty.
    pub hint: String,
    /// Gaps in what was read, in plain words. Any gap marks every empty
    /// cell "Not known".
    pub notes: Vec<String>,
    /// Workspaces the vault logs to. Zero when not known.
    pub workspaces: usize,
    pub answered: usize,
    pub newest: String,
    answers: Vec<Answer>,
}

impl Usage {
    fn unavailable(mut self, why: impl Into<String>, hint: &str) -> Self {
        self.unavailable = Some(why.into());
        self.hint = hint.to_owned();
        self
    }

    /// What was looked at, when the workspaces are known.
    pub(crate) fn coverage(&self) -> Option<String> {
        if self.workspaces == 0 {
            return None;
        }
        let noun = if self.workspaces == 1 {
            "workspace"
        } else {
            "workspaces"
        };
        let mut s = format!(
            "Looked at: the last {} days in {} of {} Log Analytics {noun} this vault logs to.",
            review::DAYS,
            self.answered,
            self.workspaces
        );
        if !self.newest.is_empty() {
            s.push_str(&format!(
                " Newest event from this vault: {}.",
                crate::routes::used_by::time(&self.newest)
            ));
        }
        Some(s)
    }

    pub(crate) fn limits(&self) -> &'static str {
        "Only allowed reads of a secret's value, reads of a certificate's backing secret (its private key) and key operations (sign, verify, wrap, unwrap, encrypt, decrypt) that the vault's diagnostic setting sends to Log Analytics are counted. Events can take a while to arrive, and nothing from before the setting was turned on, or past the workspace's retention, is there. Listing an item or reading its properties isn't counted."
    }

    /// The callers of one item, from every workspace that answered.
    fn of(&self, kind: ItemType, name: &str) -> UseCell {
        if self.unavailable.is_some() {
            return UseCell::NotKnown;
        }
        let name = name.to_ascii_lowercase();
        let keys: Vec<(String, String)> = match kind {
            ItemType::Secret => vec![(review::SECRET.into(), name)],
            ItemType::Key => vec![(review::KEY.into(), name)],
            // A certificate's private key is read through its backing
            // secret, and signing goes through its backing key.
            ItemType::Certificate => vec![
                (review::SECRET.into(), name.clone()),
                (review::KEY.into(), name),
            ],
        };
        let mut lists: Vec<Vec<Caller>> = Vec::new();
        let (mut more, mut cut) = (false, false);
        for a in &self.answers {
            for k in &keys {
                cut |= a.cut_before(k);
                if let Some(ItemUse { callers, capped }) = a.items.get(k) {
                    more |= *capped;
                    lists.push(callers.clone());
                }
            }
        }
        let (mut callers, _) = used_by::merge(lists);
        if callers.len() > review::MAX_PER_ITEM {
            callers.truncate(review::MAX_PER_ITEM);
            more = true;
        }
        let gaps = !self.notes.is_empty() || cut;
        if callers.is_empty() {
            return if gaps {
                UseCell::NotKnown
            } else {
                UseCell::NoneFound
            };
        }
        UseCell::Callers {
            callers: callers.iter().map(CallerRow::from).collect(),
            more,
            gaps,
        }
    }
}

/// One item's "used by" cell.
pub(crate) enum UseCell {
    /// The log couldn't tell, or some of it is missing and nothing was found.
    NotKnown,
    /// Every workspace answered in full and none had a use of it.
    NoneFound,
    Callers {
        callers: Vec<CallerRow>,
        /// More callers than [`review::MAX_PER_ITEM`].
        more: bool,
        /// Some of the log is missing, so there may be others.
        gaps: bool,
    },
}

impl UseCell {
    fn csv(&self) -> String {
        match self {
            Self::NotKnown => "NOT KNOWN: see the notes at the end".into(),
            Self::NoneFound => "None found in the available logs".into(),
            Self::Callers {
                callers,
                more,
                gaps,
            } => {
                let mut list: Vec<String> = callers
                    .iter()
                    .map(|c| {
                        let mut s = format!("{} ({}", c.who, c.kind);
                        if !c.object_id.is_empty() {
                            s.push_str(&format!(", object ID {}", c.object_id));
                        }
                        s.push_str(&format!(", {} uses, last {})", c.reads, c.last));
                        s
                    })
                    .collect();
                if *more {
                    list.push(format!(
                        "and more: only the {} most recent are listed",
                        review::MAX_PER_ITEM
                    ));
                }
                if *gaps {
                    list.push("some of the log is missing, so there may be others".into());
                }
                list.join("; ")
            }
        }
    }
}

/// One item's "access on this item" cell.
pub(crate) enum AccessCell {
    NotKnown,
    /// No assignment is made on the item itself: what reaches it is the
    /// vault's.
    AsVault,
    Own(Vec<Entry>),
}

/// One row of the report.
pub(crate) struct Row {
    pub kind: ItemType,
    pub name: String,
    pub enabled: bool,
    pub expires: String,
    pub expires_note: String,
    pub expires_iso: String,
    pub owner: owner::Display,
    pub owner_raw: String,
    pub notify: String,
    pub description: String,
    pub changed: String,
    pub changed_note: String,
    pub changed_iso: String,
    pub days: String,
    pub band: Band,
    pub stale: String,
    pub used: UseCell,
    pub access: AccessCell,
    /// Everything that reaches the item, for the CSV, complete per row.
    pub access_all: String,
    pub rotation: Option<Rotation>,
    pub open_url: String,
}

/// The whole report.
pub(crate) struct Report {
    pub vault: String,
    pub rows: Vec<Row>,
    /// Why the vault's lists were read only in part, or not at all.
    pub lists_not_read: Option<String>,
    pub usage: Usage,
    /// Access to the whole vault, without the assignments made on single
    /// items (those are on each row).
    pub access: Access,
}

fn plural(kind: ItemType) -> &'static str {
    kind.path().trim_start_matches('/')
}

/// The entries made on this one item.
fn own_entries(access: &Access, kind: ItemType, name: &str) -> Vec<Entry> {
    let tail = format!("/{}/{}", plural(kind), name).to_ascii_lowercase();
    access
        .entries
        .iter()
        .filter(|e| {
            e.origin == Origin::Item
                && e.scope
                    .trim_end_matches('/')
                    .to_ascii_lowercase()
                    .ends_with(&tail)
        })
        .cloned()
        .collect()
}

fn policy_kind(kind: ItemType) -> &'static str {
    match kind {
        ItemType::Secret => "Secrets",
        ItemType::Certificate => "Certificates",
        ItemType::Key => "Keys",
    }
}

fn entry_text(e: &Entry) -> String {
    let mut s = format!("{} ({}): {}", e.principal_id, e.principal_type, e.role);
    if e.eligible {
        s.push_str(", eligible");
    }
    if e.can_grant {
        s.push_str(", can grant itself access");
    }
    if e.has_condition {
        s.push_str(", with a condition");
    }
    if let Some(d) = &e.overdue_share {
        s.push_str(&format!(", shared through Keyring until {d}, OVERDUE"));
    }
    let scope = if e.scope.is_empty() { "/" } else { &e.scope };
    s.push_str(&format!(" at {} {scope}", e.origin.label()));
    s
}

fn policy_text(p: &PolicyRow, kind: ItemType) -> Option<String> {
    let (_, words) = p.lines.iter().find(|(k, _)| *k == policy_kind(kind))?;
    let mut s = format!("{}: access policy, {words}", p.object_id);
    if !p.application_id.is_empty() {
        s.push_str(&format!(", only through app {}", p.application_id));
    }
    Some(s)
}

/// Everything that reaches one item, capped at [`MAX_ACCESS_IN_CELL`].
fn access_all(access: &Access, kind: ItemType, name: &str) -> String {
    if access.unavailable.is_some() {
        return "NOT KNOWN: see the notes at the end".into();
    }
    let mut list: Vec<String> = Vec::new();
    if !access.rbac {
        list.extend(access.policies.iter().filter_map(|p| policy_text(p, kind)));
    }
    if access.assignments_unavailable.is_none() {
        let vault_wide = access.entries.iter().filter(|e| e.origin != Origin::Item);
        let own = own_entries(access, kind, name);
        list.extend(vault_wide.chain(own.iter()).map(entry_text));
    }
    let mut out = if list.len() > MAX_ACCESS_IN_CELL {
        let n = list.len() - MAX_ACCESS_IN_CELL;
        list.truncate(MAX_ACCESS_IN_CELL);
        list.push(format!(
            "and {n} more: see the vault's Access CSV for the full list"
        ));
        list.join("; ")
    } else {
        list.join("; ")
    };
    if access.assignments_unavailable.is_some() {
        let prefix = "NOT KNOWN: role assignments couldn't be read";
        out = if out.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix}; {out}")
        };
    } else if out.is_empty() {
        out = "No role assignment or access policy found that reaches it".into();
    }
    out
}

fn access_cell(access: &Access, kind: ItemType, name: &str) -> AccessCell {
    if access.unavailable.is_some() || access.assignments_unavailable.is_some() {
        return AccessCell::NotKnown;
    }
    let own = own_entries(access, kind, name);
    if own.is_empty() {
        AccessCell::AsVault
    } else {
        AccessCell::Own(own)
    }
}

/// Plain words for an error that stopped the whole "used by" read, as the
/// panel says them.
fn usage_failed(u: Usage, e: &AzureError) -> Usage {
    match e {
        AzureError::Token(crate::azure::TokenError::ConsentNeeded) => u.unavailable(
            "Keyring isn't allowed to read Log Analytics for you yet, so it can't tell who used these items.",
            HINT_CONSENT,
        ),
        AzureError::Status { status: 403, .. } => u.unavailable(
            "You don't have access to this vault's audit log, so Keyring can't tell who used these items.",
            HINT_WORKSPACE,
        ),
        _ => u.unavailable(
            "Azure didn't answer or returned an error, so Keyring can't tell who used these items. Refresh the page to try again.",
            "",
        ),
    }
}

const NOT_ARRIVED: &str = "No audit events from this vault have arrived in its Log Analytics workspace in the last 90 days, so Keyring can't tell who used these items. A diagnostic setting that was just turned on can take a while to send its first events.";

/// Who used every item, one query per workspace, within `limits`.
async fn read_usage(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    limits: Limits,
) -> Usage {
    let start = tokio::time::Instant::now();
    let u = Usage::default();
    let Ok(q) = ReviewQuery::new(vault) else {
        return u.unavailable("Keyring can't read the audit log for this vault name.", "");
    };
    let setup = async {
        let id = crate::routes::audit::vault_id(state, session, vault).await?;
        let Some(id) = id else {
            return Ok(None);
        };
        audit::workspaces(&state.azure, &session.0, &state.config.management_url, &id)
            .await
            .map(Some)
    };
    let workspaces = match tokio::time::timeout(limits.vault_timeout, setup).await {
        Err(_) => {
            return u.unavailable(
                format!(
                    "Azure didn't say where this vault's audit log goes within {} seconds, so Keyring stopped waiting. Refresh the page to try again.",
                    limits.vault_timeout.as_secs()
                ),
                "",
            );
        }
        Ok(Ok(Some(w))) => w,
        Ok(Ok(None)) => {
            return u.unavailable(
                "Keyring couldn't find this vault in Azure Resource Graph, so it can't find its audit log.",
                HINT_READER,
            );
        }
        Ok(Err(AzureError::Status { status: 403, .. })) => {
            return u.unavailable(
                "You can't read this vault's diagnostic settings, so Keyring can't find its audit log.",
                HINT_READER,
            );
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "access review diagnostic settings read failed");
            return usage_failed(u, &e);
        }
    };
    if workspaces.is_empty() {
        return u.unavailable(
            "This vault doesn't send its audit log to a Log Analytics workspace, so Keyring can't tell who used its items.",
            HINT_LOGGING,
        );
    }
    // One query per workspace, a few at a time, in what is left of the
    // deadline.
    let left = limits.deadline.saturating_sub(start.elapsed());
    let ws_limits = Limits {
        concurrency: limits.concurrency,
        vault_timeout: limits.vault_timeout.min(left),
        deadline: left,
    };
    let by_key: HashMap<String, audit::Workspace> = workspaces
        .iter()
        .enumerate()
        .map(|(i, w)| (i.to_string(), w.clone()))
        .collect();
    let fanned = fanout::read_each_within(
        (0..workspaces.len()).map(|i| i.to_string()),
        |key| {
            let azure = state.azure.clone();
            let sess = session.0.clone();
            let url = state.config.loganalytics_url.clone();
            let ws = by_key.get(&key).cloned();
            let q = q.clone();
            async move {
                let Some(ws) = ws else {
                    return (Err(AzureError::Unreadable), None);
                };
                (review::query(&azure, &sess, &url, &ws, &q).await, None)
            }
        },
        ws_limits,
    )
    .await;
    let mut u = u;
    let m = workspaces.len();
    u.workspaces = m;
    let (mut denied, mut failed, mut missing) = (0, 0, 0);
    let mut failure = None;
    for (_, r) in fanned.read {
        match r {
            Ok(a) => u.answers.push(a),
            Err(AzureError::Status { status: 403, .. }) => denied += 1,
            Err(e) if used_by::is_missing_table(&e) => missing += 1,
            Err(e) => {
                tracing::warn!(error = %e, "access review workspace query failed");
                failed += 1;
                failure.get_or_insert(e);
            }
        }
    }
    // Workspaces not reached in time.
    failed += fanned.skipped.len();
    u.answered = u.answers.len() + missing;
    if denied == m {
        return u.unavailable(
            "You don't have access to the Log Analytics workspace this vault logs to, so Keyring can't tell who used its items.",
            HINT_WORKSPACE,
        );
    }
    if u.answered == 0 {
        if let Some(e) = failure {
            return usage_failed(u, &e);
        }
        return u.unavailable(
            "Log Analytics didn't answer in time, so Keyring can't tell who used these items. Refresh the page to try again.",
            "",
        );
    }
    u.newest = u
        .answers
        .iter()
        .map(|a| a.newest.as_str())
        .max()
        .unwrap_or_default()
        .to_owned();
    let with_events = u
        .answers
        .iter()
        .filter(|a| a.vault_events > 0 || !a.items.is_empty())
        .count();
    let quiet = u.answered - with_events;
    let of = |n: usize| {
        let noun = if m == 1 { "workspace" } else { "workspaces" };
        format!("{n} of {m} Log Analytics {noun} this vault logs to")
    };
    let unread = denied + failed;
    if unread > 0 {
        u.notes.push(format!(
            "{} couldn't be read, so some callers may be missing.",
            of(unread)
        ));
    }
    if u.answers.iter().any(|a| a.incomplete) {
        u.notes.push(
            "Log Analytics returned only part of the answer, so some callers may be missing."
                .into(),
        );
    }
    if u.answers.iter().any(|a| a.cut_at.is_some()) {
        u.notes.push(format!(
            "The log had more than {} item and caller pairs for this vault, so Keyring stopped there. Items it didn't reach are marked \"Not known\". Each item's own page shows its callers for the last 30 days.",
            review::MAX_ROWS
        ));
    }
    if with_events == 0 {
        return u.unavailable(NOT_ARRIVED, HINT_ARRIVED);
    }
    if quiet > 0 {
        u.notes.push(format!(
            "{} had no events from this vault in the last 90 days, so its callers, if any, aren't shown.",
            of(quiet)
        ));
    }
    u
}

/// Read everything the report needs, side by side, each within the
/// fan-out's limits.
async fn read(state: &AppState, session: &CurrentSession, vault: &str) -> Report {
    let limits = state.fanout;
    let access_limit = access::PAGE_TIMEOUT.min(limits.deadline);
    let (lists, access, usage) = tokio::join!(
        crate::routes::every_vault::read(state, session, vec![vault.to_owned()]),
        access::with_items_within(state, session, vault, access_limit),
        read_usage(state, session, vault, limits),
    );
    let lists_not_read = lists.skipped.first().map(|s| s.reason.clone());
    // Secrets and keys that back a certificate change with it and are
    // listed as the certificate, as on the age view.
    let mut items: Vec<Item> = lists
        .read
        .iter()
        .flat_map(|(_, v)| v.iter())
        .filter(|i| !i.managed)
        .cloned()
        .collect();
    items.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    let now = now_ts();
    let after = state.config.stale_after_days;
    let rows = items
        .iter()
        .map(|i| Row {
            kind: i.kind,
            name: i.name.clone(),
            enabled: i.enabled,
            expires: i.expires_text(),
            expires_note: i.expires_note(now),
            expires_iso: i.expires.map(dates::iso_date).unwrap_or_default(),
            owner: owner::Display::of_owner(i.owner()),
            owner_raw: i.owner().to_owned(),
            notify: i.notify().to_owned(),
            description: i.description().to_owned(),
            changed: i.created.map(dates::format_date).unwrap_or_default(),
            changed_note: i
                .created
                .map(|c| dates::relative_days(c, now))
                .unwrap_or_default(),
            changed_iso: i.created.map(dates::iso_date).unwrap_or_default(),
            days: i
                .created
                .map(|c| age::days_since(c, now).to_string())
                .unwrap_or_default(),
            band: Band::of(i.created, now),
            stale: age::stale_badge(i.created, i.managed, after, now),
            used: usage.of(i.kind, &i.name),
            access: access_cell(&access, i.kind, &i.name),
            access_all: access_all(&access, i.kind, &i.name),
            rotation: Rotation::from_tags(&i.tags),
            open_url: vault_ctx::vault_path(vault, &format!("{}/{}", i.kind.path(), i.name)),
        })
        .collect();
    let mut vault_access = access;
    vault_access.entries.retain(|e| e.origin != Origin::Item);
    Report {
        vault: vault.to_owned(),
        rows,
        lists_not_read,
        usage,
        access: vault_access,
    }
}

const CSV_HEADER: &str = "Vault,Type,Name,Enabled,Expires (UTC),Owner,Notify,Description,Value changed (UTC),Days since,Band,Used by (last 90 days),Access on this item,Who has access,Rotation status,Rotated by,Last rotation\r\n";
const CSV_COLUMNS: usize = 17;

/// A row for something the report couldn't read: the vault, `NOT READ` in
/// the Type column and the reason in the Name column, as the other exports.
fn not_read_row(vault: &str, reason: &str) -> String {
    let mut row = vec![String::new(); CSV_COLUMNS];
    row[0] = csv_field(vault);
    row[1] = "NOT READ".to_owned();
    row[2] = csv_field(reason);
    let mut out = row.join(",");
    out.push_str("\r\n");
    out
}

/// The report as CSV. Every free-text field goes through [`csv_field`].
/// Notes on what wasn't read come last, one row each.
pub(crate) fn to_csv(r: &Report) -> String {
    let mut out = String::from(CSV_HEADER);
    for row in &r.rows {
        let own = match &row.access {
            AccessCell::NotKnown => "NOT KNOWN: see the notes at the end".to_owned(),
            AccessCell::AsVault => "As the vault".to_owned(),
            AccessCell::Own(list) => list.iter().map(entry_text).collect::<Vec<_>>().join("; "),
        };
        let (status, by, last) = match &row.rotation {
            Some(rot) => (rot.status.label(), rot.by.as_str(), rot.last.as_str()),
            None => ("Not tagged", "", ""),
        };
        let cols = [
            csv_field(&r.vault),
            row.kind.label().to_owned(),
            csv_field(&row.name),
            if row.enabled { "Yes" } else { "No" }.to_owned(),
            row.expires_iso.clone(),
            csv_field(&row.owner_raw),
            csv_field(&row.notify),
            csv_field(&row.description),
            row.changed_iso.clone(),
            row.days.clone(),
            row.band.label().to_owned(),
            csv_field(&row.used.csv()),
            csv_field(&own),
            csv_field(&row.access_all),
            status.to_owned(),
            csv_field(by),
            csv_field(last),
        ];
        out.push_str(&cols.join(","));
        out.push_str("\r\n");
    }
    for n in notes(r) {
        out.push_str(&not_read_row(&r.vault, &n));
    }
    out
}

/// Everything the report couldn't read, in plain words, for the CSV.
fn notes(r: &Report) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(why) = &r.lists_not_read {
        out.push(format!(
            "Secrets, certificates and keys: {why}. Items not read aren't in this file"
        ));
    }
    if let Some(why) = &r.usage.unavailable {
        out.push(format!("Used by: {why}"));
    }
    for n in &r.usage.notes {
        out.push(format!("Used by: {n}"));
    }
    if let Some(c) = r.usage.coverage() {
        out.push(format!("Used by: {c}"));
    }
    if let Some(u) = &r.access.unavailable {
        out.push(format!("Access: {}", u.message));
    }
    if let Some(u) = &r.access.assignments_unavailable {
        out.push(format!("Access: {}", u.message));
    }
    for n in &r.access.notes {
        out.push(format!("Access: {n}"));
    }
    out
}

#[derive(Template)]
#[template(path = "access_review.html")]
struct ReviewPage {
    shell: Shell,
    vault: String,
    report: Report,
    access: Access,
    csv_url: String,
    access_url: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> crate::routes::error::PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Access, &vault)?;
    let mut report = read(&state, &session, &vault).await;
    let access = std::mem::take(&mut report.access);
    Ok(render(&ReviewPage {
        csv_url: vault_ctx::vault_path(&vault, "/access/review.csv"),
        access_url: vault_ctx::vault_path(&vault, "/access"),
        shell,
        vault,
        report,
        access,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> crate::routes::error::PageResult {
    let (vault, _) = vault_ctx::path_vault(&session, shell, Section::Access, &vault)?;
    let report = read(&state, &session, &vault).await;
    let mut res: Response = (StatusCode::OK, to_csv(&report)).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    let date = dates::iso_date(now_ts());
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"keyring-access-review-{vault}-{date}.csv\""
    )) {
        h.insert(CONTENT_DISPOSITION, v);
    }
    Ok(no_store(res))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, origin: Origin, scope: &str) -> Entry {
        Entry {
            principal_id: id.into(),
            principal_type: "User",
            is_group: false,
            portal_url: String::new(),
            role: "Key Vault Secrets User".into(),
            origin,
            scope: scope.into(),
            eligible: false,
            can_grant: false,
            has_condition: false,
            overdue_share: None,
        }
    }

    const V: &str = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv";

    #[test]
    fn item_cells_show_only_their_own_and_the_csv_is_complete() {
        let access = Access {
            rbac: true,
            entries: vec![
                entry("=a", Origin::Vault, V),
                entry("b", Origin::Item, &format!("{V}/secrets/DB")),
                entry("c", Origin::Item, &format!("{V}/keys/db")),
            ],
            ..Access::default()
        };
        match access_cell(&access, ItemType::Secret, "db") {
            AccessCell::Own(l) => assert_eq!(l.len(), 1),
            _ => panic!("own"),
        }
        assert!(matches!(
            access_cell(&access, ItemType::Certificate, "db"),
            AccessCell::AsVault
        ));
        let all = access_all(&access, ItemType::Secret, "db");
        assert!(all.starts_with("=a (User)") && all.contains("b (User)") && !all.contains("c ("));
        assert!(csv_field(&all).starts_with("'=a"));
    }

    #[test]
    fn unknown_access_is_never_an_empty_list() {
        let access = Access {
            rbac: true,
            assignments_unavailable: Some(access::Unavailable {
                message: "x".into(),
                hint: String::new(),
            }),
            ..Access::default()
        };
        assert!(matches!(
            access_cell(&access, ItemType::Key, "k"),
            AccessCell::NotKnown
        ));
        assert!(access_all(&access, ItemType::Key, "k").starts_with("NOT KNOWN"));
        let none = Access {
            rbac: true,
            ..Access::default()
        };
        assert_eq!(
            access_all(&none, ItemType::Key, "k"),
            "No role assignment or access policy found that reaches it"
        );
    }

    #[test]
    fn long_access_lists_are_capped_with_a_count() {
        let access = Access {
            rbac: true,
            entries: (0..MAX_ACCESS_IN_CELL + 7)
                .map(|i| entry(&format!("p{i}"), Origin::Vault, V))
                .collect(),
            ..Access::default()
        };
        let all = access_all(&access, ItemType::Secret, "s");
        assert!(all.ends_with("and 7 more: see the vault's Access CSV for the full list"));
        assert_eq!(all.matches(" (User)").count(), MAX_ACCESS_IN_CELL);
    }

    #[test]
    fn gaps_turn_empty_cells_into_not_known() {
        let mut u = Usage {
            answers: vec![Answer::default()],
            ..Usage::default()
        };
        assert!(matches!(u.of(ItemType::Secret, "x"), UseCell::NoneFound));
        u.notes.push("one workspace couldn't be read".into());
        assert!(matches!(u.of(ItemType::Secret, "x"), UseCell::NotKnown));
        let u = Usage::default().unavailable("no log", "");
        assert!(matches!(u.of(ItemType::Key, "x"), UseCell::NotKnown));
    }

    #[test]
    fn csv_rows_line_up_with_the_header() {
        assert_eq!(CSV_HEADER.trim_end().split(',').count(), CSV_COLUMNS);
        assert_eq!(
            not_read_row("kv", "why, then")
                .trim_end()
                .matches(',')
                .count(),
            CSV_COLUMNS - 1 + 1,
            "one comma inside the quoted reason"
        );
    }
}
