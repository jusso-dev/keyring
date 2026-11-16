//! Keyring's own audit events for one vault, from `KeyringAudit_CL`, read
//! as the signed-in person with their Log Analytics token.
//!
//! Not Key Vault's log (`super::audit`): this is the table the audit sink
//! writes (`crate::audit::sink`). Keyring's managed identity can only write
//! to it, and is never used to read it: reading as the identity would show
//! people rows they have no right to see.
//!
//! The workspace is `KEYRING_AUDIT_WORKSPACE_ID`, checked at start. As in
//! [`super::audit`], user input never goes into the query as raw text: every
//! value is checked against a strict pattern, then written as a KQL string
//! literal in a `let` line at the top.

use serde::Deserialize;
use serde_json::Value;

use super::audit::{BadFilter, MAX_ROWS, Range, is_person, is_safe_resource_id, kql_string};
use crate::audit::Action;
use crate::auth::session::Session;
use crate::azure::{AzureClient, AzureError, Resource};

/// The table the audit sink writes.
pub const TABLE: &str = "KeyringAudit_CL";

/// The columns the query reads, all from `crate::audit::sink::COLUMNS`
/// (`tests/audit_keyring.rs` checks).
pub const COLUMNS_READ: [&str; 11] = [
    "TimeGenerated",
    "Action",
    "Outcome",
    "ReasonCode",
    "ActorUpn",
    "ActorObjectId",
    "ItemKind",
    "ItemName",
    "ClientIp",
    "Reason",
    "Ticket",
];

/// Filters, already checked. Build with [`KeyringQuery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringQuery {
    pub vault: String,
    pub range: Range,
    /// Item name, exact match (ignoring case).
    pub item: Option<String>,
    /// One of Keyring's own action names, from [`Action::ALL`] only.
    pub action: Option<String>,
    /// Part of a sign-in name, or an object ID.
    pub person: Option<String>,
}

impl KeyringQuery {
    pub fn new(
        vault: &str,
        range: Range,
        item: &str,
        action: &str,
        person: &str,
    ) -> Result<Self, BadFilter> {
        if !crate::azure::vaults::is_valid_vault_name(vault) {
            return Err(BadFilter("vault"));
        }
        let item = item.trim();
        if !item.is_empty() && !crate::routes::vault_ctx::is_valid_object_name(item) {
            return Err(BadFilter("item"));
        }
        let action = action.trim();
        if !action.is_empty() && !Action::ALL.iter().any(|a| a.as_str() == action) {
            return Err(BadFilter("operation"));
        }
        let person = person.trim();
        if !person.is_empty() && !is_person(person) {
            return Err(BadFilter("person"));
        }
        let some = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        Ok(Self {
            vault: vault.to_owned(),
            range,
            item: some(item),
            action: some(action),
            person: some(person),
        })
    }

    /// The KQL. Values only appear as escaped string literals in `let`
    /// lines; the rest is fixed text.
    pub fn kql(&self) -> String {
        let lit = |v: &Option<String>| kql_string(v.as_deref().unwrap_or(""));
        format!(
            "let vaultName = {vault};\n\
             let itemName = {item};\n\
             let act = {action};\n\
             let who = {person};\n\
             {TABLE}\n\
             | where TimeGenerated > ago({range})\n\
             | where Vault =~ vaultName\n\
             | where isempty(itemName) or ItemName =~ itemName\n\
             | where isempty(act) or Action == act\n\
             | where isempty(who) or ActorUpn contains who or ActorObjectId =~ who\n\
             | project {columns}\n\
             | order by TimeGenerated desc\n\
             | take {MAX_ROWS}",
            vault = kql_string(&self.vault),
            item = lit(&self.item),
            action = lit(&self.action),
            person = lit(&self.person),
            range = self.range.kql(),
            columns = COLUMNS_READ.join(", "),
        )
    }
}

/// One of Keyring's own events. `reason` and `ticket` are free text a
/// person typed: show them escaped, never as markup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyringEvent {
    pub time: String,
    pub action: String,
    pub outcome: String,
    pub reason_code: String,
    pub actor_upn: String,
    pub actor_oid: String,
    pub item_kind: String,
    pub item_name: String,
    pub client_ip: String,
    pub reason: String,
    pub ticket: String,
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    tables: Vec<Table>,
}

#[derive(Deserialize)]
struct Table {
    #[serde(default)]
    columns: Vec<Column>,
    #[serde(default)]
    rows: Vec<Vec<Value>>,
}

#[derive(Deserialize)]
struct Column {
    name: String,
}

fn parse(result: QueryResult) -> Vec<KeyringEvent> {
    let Some(t) = result.tables.into_iter().next() else {
        return Vec::new();
    };
    let idx = |name: &str| t.columns.iter().position(|c| c.name == name);
    let at: Vec<Option<usize>> = COLUMNS_READ.iter().map(|c| idx(c)).collect();
    let get = |row: &[Value], i: usize| -> String {
        at[i]
            .and_then(|i| row.get(i))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    t.rows
        .iter()
        .take(MAX_ROWS as usize)
        .map(|r| KeyringEvent {
            time: get(r, 0),
            action: get(r, 1),
            outcome: get(r, 2),
            reason_code: get(r, 3),
            actor_upn: get(r, 4),
            actor_oid: get(r, 5),
            item_kind: get(r, 6),
            item_name: get(r, 7),
            client_ip: get(r, 8),
            reason: get(r, 9),
            ticket: get(r, 10),
        })
        .collect()
}

/// Run the query against the workspace, as the person. `workspace_id` is
/// the ARM resource ID from `KEYRING_AUDIT_WORKSPACE_ID`.
pub async fn query(
    azure: &AzureClient,
    session: &Session,
    loganalytics_url: &str,
    workspace_id: &str,
    q: &KeyringQuery,
) -> Result<Vec<KeyringEvent>, AzureError> {
    if !is_safe_resource_id(workspace_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!("{loganalytics_url}/v1{workspace_id}/query");
    let body = serde_json::json!({
        "query": q.kql(),
        "timespan": q.range.iso(),
    });
    let result: QueryResult = azure
        .send_json(
            session,
            Resource::LogAnalytics,
            reqwest::Method::POST,
            &url,
            &body,
        )
        .await?;
    Ok(parse(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_every_filter() {
        let ok = KeyringQuery::new(
            "kv-test",
            Range::Day,
            "db-password",
            "secret.reveal",
            "a@b.c",
        );
        assert!(ok.is_ok());
        assert_eq!(
            KeyringQuery::new("kv test", Range::Day, "", "", ""),
            Err(BadFilter("vault"))
        );
        assert_eq!(
            KeyringQuery::new("kv-test", Range::Day, "x\"|", "", ""),
            Err(BadFilter("item"))
        );
        assert_eq!(
            KeyringQuery::new("kv-test", Range::Day, "", "SecretGet", ""),
            Err(BadFilter("operation"))
        );
        assert_eq!(
            KeyringQuery::new("kv-test", Range::Day, "", "", "a\";"),
            Err(BadFilter("person"))
        );
    }

    #[test]
    fn values_are_only_literals_in_let_lines() {
        let q = KeyringQuery::new("kv-test", Range::Week, "db", "secret.reveal", "alex")
            .unwrap()
            .kql();
        assert!(q.starts_with("let vaultName = \"kv-test\";\nlet itemName = \"db\";\nlet act = \"secret.reveal\";\nlet who = \"alex\";\nKeyringAudit_CL\n"));
        assert!(q.contains("ago(7d)"));
        assert!(q.ends_with("| take 500"));
        // After the let lines, no value appears.
        let body = &q[q.find("KeyringAudit_CL").unwrap()..];
        for v in ["kv-test", "\"db\"", "secret.reveal", "alex"] {
            assert!(!body.contains(v), "{v} in the query body");
        }
    }

    #[test]
    fn reads_rows_by_column_name() {
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "columns": [{"name": "Reason"}, {"name": "TimeGenerated"}, {"name": "Action"}],
            "rows": [["<b>why</b>", "2026-11-17T01:02:03Z", "secret.reveal"], [null, "t", "x"]]
        }]}))
        .unwrap();
        let e = parse(r);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].reason, "<b>why</b>");
        assert_eq!(e[0].action, "secret.reveal");
        assert_eq!(e[1].reason, "");
        assert_eq!(e[1].outcome, "");
    }
}
