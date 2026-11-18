//! The "Used by in the last 30 days" panel, on an item's page and on the
//! forms that change it. Advice, not a gate: it reads Key Vault's audit
//! log as the signed-in person, within a short time limit of its own, and
//! when it can't it says why and the form works as before. It changes
//! nothing, so it writes none of Keyring's own audit events.
//!
//! An empty list is never told as proof that nothing uses the item: logs
//! arrive late, a new diagnostic setting has no history, and a workspace
//! that can't be read hides its callers. The panel tells these apart and
//! always says what it looked at.

use std::time::Duration;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::audit;
use crate::azure::used_by::{self, Answer, Caller, Usage, UsedByQuery};
use crate::routes::lifecycle::Kind;
use crate::routes::vault_ctx::vault_path;

/// Most time the panel may add to a page. Run beside the page's own reads,
/// so a slow workspace never holds up the form for longer than this.
pub(crate) const TIME_LIMIT: Duration = Duration::from_secs(5);

/// One caller, ready to show.
pub(crate) struct CallerRow {
    pub kind: &'static str,
    /// Sign-in name, or app ID, or "Unknown".
    pub who: String,
    /// The app ID, when `who` is a sign-in name.
    pub app_id: String,
    pub object_id: String,
    pub last: String,
    /// `last` for the cell: short to show, ISO in `<time>`.
    pub last_when: crate::dates::LogTime,
    pub reads: u64,
    pub client_info: String,
    pub ip: String,
}

impl CallerRow {
    pub(crate) fn from(c: &Caller) -> Self {
        let who = if !c.upn.is_empty() {
            c.upn.clone()
        } else if !c.app_id.is_empty() {
            c.app_id.clone()
        } else {
            "Unknown".into()
        };
        Self {
            kind: c.kind().label(),
            app_id: if c.upn.is_empty() {
                String::new()
            } else {
                c.app_id.clone()
            },
            who,
            object_id: c.object_id.clone(),
            last: time(&c.last),
            last_when: crate::dates::log_time(&c.last),
            reads: c.reads,
            client_info: c.client_info.clone(),
            ip: c.ip.clone(),
        }
    }
}

/// `2026-11-09T10:00:00.123Z` as `2026-11-09 10:00:00 UTC`.
pub(crate) fn time(t: &str) -> String {
    if t.is_empty() {
        return String::new();
    }
    t.replace('T', " ")
        .trim_end_matches('Z')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_owned()
        + " UTC"
}

/// The panel.
pub(crate) struct UsedBy {
    /// "secret", "certificate" or "key".
    pub noun: &'static str,
    pub callers: Vec<CallerRow>,
    /// More callers than the panel shows.
    pub capped: bool,
    /// Why the history is unknown, in plain words. `None` when the log
    /// was read and events from the vault were found.
    pub unavailable: Option<String>,
    /// What to ask for, with the reason. May be empty.
    pub hint: String,
    /// Gaps in what was read (workspaces left out, workspaces with no
    /// events from this vault yet, a partial answer), in plain words.
    pub notes: Vec<String>,
    /// What an empty list means. Never says the change is safe.
    pub empty: String,
    /// Workspaces the vault logs to. Zero when not known.
    pub workspaces: usize,
    /// Workspaces that answered.
    pub answered: usize,
    /// Time of the newest event from this vault in any workspace.
    pub newest: String,
    /// The vault's audit view, filtered to this item.
    pub audit_url: String,
}

impl UsedBy {
    fn new(vault: &str, kind: Kind, name: &str) -> Self {
        let from = match kind {
            Kind::Secret => "secret",
            Kind::Certificate => "certificate",
            Kind::Key => "key",
        };
        Self {
            noun: kind.noun(),
            callers: Vec::new(),
            capped: false,
            unavailable: None,
            hint: String::new(),
            notes: Vec::new(),
            empty: fill(kind.noun(), EMPTY),
            workspaces: 0,
            answered: 0,
            newest: String::new(),
            audit_url: vault_path(vault, &format!("/audit?item={name}&range=30d&from={from}")),
        }
    }

    fn unavailable(mut self, why: impl Into<String>, hint: &str) -> Self {
        self.unavailable = Some(why.into());
        self.hint = hint.to_owned();
        self
    }

    /// What was counted, for the sentence above the table.
    pub(crate) fn counted(&self) -> &'static str {
        match self.noun {
            "key" => {
                "Apps and people that signed, verified, wrapped, unwrapped, encrypted or decrypted with this key"
            }
            "certificate" => {
                "Apps and people that read this certificate's backing secret, which holds its private key"
            }
            _ => "Apps and people that read this secret's value",
        }
    }

    pub(crate) fn column(&self) -> &'static str {
        if self.noun == "key" { "Uses" } else { "Reads" }
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
            used_by::DAYS,
            self.answered,
            self.workspaces
        );
        if !self.newest.is_empty() {
            s.push_str(&format!(
                " Newest event from this vault: {}.",
                time(&self.newest)
            ));
        }
        Some(s)
    }

    /// What the log can't show, whatever it found.
    pub(crate) fn limits(&self) -> String {
        format!(
            "Only allowed {} the vault's diagnostic setting sends to Log Analytics is counted. Events can take a while to arrive, and nothing from before the setting was turned on, or past the workspace's retention, is there.",
            activity(self.noun)
        )
    }
}

/// What counts as a use, in a few words, by kind.
fn activity(noun: &str) -> &'static str {
    match noun {
        "key" => "key use (sign, verify, wrap, unwrap, encrypt or decrypt)",
        "certificate" => "certificate private-key access (reads of its backing secret)",
        _ => "secret reads",
    }
}

/// A message with `{activity}` and `{noun}` filled in for the kind.
fn fill(noun: &str, template: &str) -> String {
    template
        .replace("{activity}", activity(noun))
        .replace("{noun}", noun)
}

/// Every workspace answered and events from the vault arrived, but none
/// were uses of this item.
const EMPTY: &str = "No {activity} found in the available logs for this period. Logs may be delayed or incomplete; check consumers before changing this {noun}.";
/// None found, but some of the log was left out.
const EMPTY_PARTIAL: &str = "No {activity} found in the logs Keyring could read for this period. Some of the log is missing (see below), so check consumers before changing this {noun}.";
/// The workspaces answered, but nothing from this vault has arrived.
const NOT_ARRIVED: &str = "No audit events from this vault have arrived in its Log Analytics workspace for this period, so Keyring can't tell what uses this {noun}. A diagnostic setting that was just turned on can take a while to send its first events. Check consumers before changing this {noun}.";
pub(crate) const HINT_ARRIVED: &str = "someone who manages the vault to check its diagnostic setting sends the \"audit\" log category to the workspace, then try again later.";

pub(crate) const HINT_READER: &str = "the Reader role on the vault (or its resource group), so Keyring can find where its audit log goes.";
pub(crate) const HINT_LOGGING: &str = "a diagnostic setting on the vault that sends the \"audit\" log category to a Log Analytics workspace.";
pub(crate) const HINT_WORKSPACE: &str =
    "the Log Analytics Reader role on the workspace the vault's diagnostic setting uses.";
pub(crate) const HINT_CONSENT: &str = "the delegated permission Log Analytics API, Data.Read, on the Keyring app registration, with admin consent.";

/// Plain words for an error that stopped the whole read.
fn failed(panel: UsedBy, e: &AzureError) -> UsedBy {
    match e {
        AzureError::Token(crate::azure::TokenError::ConsentNeeded) => panel.unavailable(
            "Keyring isn't allowed to read Log Analytics for you yet, so it can't tell who used this.",
            HINT_CONSENT,
        ),
        AzureError::Status { status: 403, .. } => panel.unavailable(
            "You don't have access to this vault's audit log, so Keyring can't tell who used this.",
            HINT_WORKSPACE,
        ),
        _ => panel.unavailable(
            "Azure didn't answer or returned an error, so Keyring can't tell who used this. Refresh the page to try again.",
            "",
        ),
    }
}

async fn read(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    kind: Kind,
    name: &str,
) -> UsedBy {
    let panel = UsedBy::new(vault, kind, name);
    let usage = match kind {
        Kind::Key => Usage::KeyOperations,
        Kind::Secret | Kind::Certificate => Usage::SecretReads,
    };
    let Ok(q) = UsedByQuery::new(vault, name, usage) else {
        return panel.unavailable("Keyring can't read the audit log for this name.", "");
    };
    let id = match crate::routes::audit::vault_id(state, session, vault).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return panel.unavailable(
                "Keyring couldn't find this vault in Azure Resource Graph, so it can't find its audit log.",
                HINT_READER,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "used-by vault lookup failed");
            return failed(panel, &e);
        }
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
            return panel.unavailable(
                "You can't read this vault's diagnostic settings, so Keyring can't find its audit log.",
                HINT_READER,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "used-by diagnostic settings read failed");
            return failed(panel, &e);
        }
    };
    if workspaces.is_empty() {
        return panel.unavailable(
            "This vault doesn't send its audit log to a Log Analytics workspace, so Keyring can't tell who used it.",
            HINT_LOGGING,
        );
    }
    let mut answers: Vec<Answer> = Vec::new();
    let (mut denied, mut failed_count, mut missing) = (0, 0, 0);
    let mut failure = None;
    for ws in &workspaces {
        match used_by::query(
            &state.azure,
            &session.0,
            &state.config.loganalytics_url,
            ws,
            &q,
        )
        .await
        {
            Ok(a) => answers.push(a),
            Err(AzureError::Status { status: 403, .. }) => denied += 1,
            // The table appears with the first event, so a missing one is
            // a workspace that answered with nothing from this vault yet.
            Err(e) if used_by::is_missing_table(&e) => missing += 1,
            Err(e) => {
                tracing::warn!(error = %e, "used-by workspace query failed");
                failed_count += 1;
                failure.get_or_insert(e);
            }
        }
    }
    // Coverage stays on the panel whatever happens next.
    let mut panel = panel;
    let m = workspaces.len();
    panel.workspaces = m;
    panel.answered = answers.len() + missing;
    if denied == workspaces.len() {
        return panel.unavailable(
            "You don't have access to the Log Analytics workspace this vault logs to, so Keyring can't tell who used it.",
            HINT_WORKSPACE,
        );
    }
    if answers.is_empty()
        && missing == 0
        && let Some(e) = failure
    {
        return failed(panel, &e);
    }
    panel.newest = answers
        .iter()
        .map(|a| a.newest.as_str())
        .max()
        .unwrap_or_default()
        .to_owned();
    // A partial answer may carry callers but not the vault's count row:
    // callers are events from the vault too.
    let with_events = answers
        .iter()
        .filter(|a| a.vault_events > 0 || !a.callers.is_empty())
        .count();
    let quiet = panel.answered - with_events;
    let incomplete = answers.iter().any(|a| a.incomplete);
    let unread = denied + failed_count;
    let of = |n: usize| {
        let noun = if m == 1 { "workspace" } else { "workspaces" };
        format!("{n} of {m} Log Analytics {noun} this vault logs to")
    };
    if unread > 0 {
        panel.notes.push(format!(
            "{} couldn't be read, so some callers may be missing.",
            of(unread)
        ));
    }
    if incomplete {
        panel.notes.push(
            "Log Analytics returned only part of the answer, so some callers may be missing."
                .to_owned(),
        );
    }
    if with_events == 0 {
        // Nothing from the vault at all: the history is unknown, not empty.
        let why = fill(panel.noun, NOT_ARRIVED);
        return panel.unavailable(why, HINT_ARRIVED);
    }
    if quiet > 0 {
        panel.notes.push(format!(
            "{} had no events from this vault for this period, so its callers, if any, aren't shown.",
            of(quiet)
        ));
    }
    if !panel.notes.is_empty() {
        panel.empty = fill(panel.noun, EMPTY_PARTIAL);
    }
    let (callers, capped) = used_by::merge(answers.into_iter().map(|a| a.callers).collect());
    panel.callers = callers.iter().map(CallerRow::from).collect();
    panel.capped = capped;
    panel
}

/// The panel for one item, within [`TIME_LIMIT`]. Never an error: when the
/// log can't be read, the panel says why. Run it beside the page's other
/// reads with `tokio::join!`.
pub(crate) async fn for_item(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    kind: Kind,
    name: &str,
) -> UsedBy {
    within(state, session, vault, kind, name, TIME_LIMIT).await
}

pub(crate) async fn within(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    kind: Kind,
    name: &str,
    limit: Duration,
) -> UsedBy {
    match tokio::time::timeout(limit, read(state, session, vault, kind, name)).await {
        Ok(p) => p,
        Err(_) => UsedBy::new(vault, kind, name).unavailable(
            format!(
                "Key Vault's audit log didn't answer within {} seconds, so Keyring stopped waiting. Refresh the page to try again.",
                limit.as_secs()
            ),
            "",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_name_the_caller_plainly() {
        let mut c = Caller {
            upn: "alex@example.com".into(),
            app_id: "app-1".into(),
            object_id: "oid-1".into(),
            managed: false,
            reads: 3,
            last: "2026-11-09T10:00:00.123Z".into(),
            client_info: "Mozilla/5.0".into(),
            ip: "203.0.113.5".into(),
        };
        let r = CallerRow::from(&c);
        assert_eq!(r.kind, "Person");
        assert_eq!(r.who, "alex@example.com");
        assert_eq!(r.app_id, "app-1");
        assert_eq!(r.last, "2026-11-09 10:00:00 UTC");
        c.upn.clear();
        c.managed = true;
        let r = CallerRow::from(&c);
        assert_eq!(
            (r.kind, r.who.as_str(), r.app_id.as_str()),
            ("Managed identity", "app-1", "")
        );
        c.app_id.clear();
        c.managed = false;
        assert_eq!(CallerRow::from(&c).who, "Unknown");
    }

    #[test]
    fn empty_wording_fits_the_kind() {
        assert_eq!(
            UsedBy::new("kv", Kind::Secret, "db").empty,
            "No secret reads found in the available logs for this period. Logs may be delayed or incomplete; check consumers before changing this secret."
        );
        assert!(
            UsedBy::new("kv", Kind::Certificate, "c").empty.starts_with(
                "No certificate private-key access (reads of its backing secret) found"
            )
        );
        let k = UsedBy::new("kv", Kind::Key, "k");
        assert!(k.empty.starts_with("No key use (sign, verify, wrap"));
        assert!(k.empty.ends_with("before changing this key."));
        assert!(fill("key", EMPTY_PARTIAL).contains("Some of the log is missing"));
        for t in [EMPTY, EMPTY_PARTIAL, NOT_ARRIVED] {
            assert!(
                t.to_lowercase().contains("check consumers before changing"),
                "{t}"
            );
        }
        assert!(k.limits().starts_with("Only allowed key use (sign"));
        assert_eq!(k.coverage(), None);
        assert_eq!(
            UsedBy::new("kv", Kind::Key, "k").audit_url,
            "/v/kv/audit?item=k&range=30d&from=key"
        );
    }
}
