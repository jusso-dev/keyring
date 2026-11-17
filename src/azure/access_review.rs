//! Who used each item in a vault in the last 90 days, for the access
//! review report, from Key Vault's audit log in Log Analytics, read as the
//! signed-in person.
//!
//! "Used by" on an item's page asks about one item. A report over a whole
//! vault can't ask once per item, so this is one fixed query per workspace
//! that groups allowed uses by item and caller, keeps the most recent
//! [`MAX_PER_ITEM`] callers of each item (plus one, to tell when there
//! were more), and at most [`MAX_ROWS`] rows in all (plus one). It ends with
//! the same `VaultEvents` row as "Used by", so a log with no events from
//! the vault can be told apart from items nobody read in it.
//!
//! The vault name reaches the query only as an escaped string literal in
//! the `let vaultName` line (see [`kql_string`]); the rest is fixed text.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::auth::session::Session;
use crate::azure::audit::{BadFilter, Workspace, is_safe_resource_id, kql_string, outcome_kql};
use crate::azure::used_by::{Caller, KEY_OPERATIONS};
use crate::azure::{AzureClient, AzureError, Resource};

/// Days looked back. The report's own: "Used by" keeps its 30.
pub const DAYS: u32 = 90;
/// Most callers kept for one item, most recent first.
pub const MAX_PER_ITEM: usize = 20;
/// Most item and caller rows one workspace returns.
pub const MAX_ROWS: usize = 2000;

/// What a use is, as the query names it: `secret` for a read of a
/// secret's value (a certificate's private key is read through its
/// backing secret, so certificates use it too), `key` for a cryptographic
/// operation with a key.
pub const SECRET: &str = "secret";
pub const KEY: &str = "key";

/// The vault, already checked. Build with [`ReviewQuery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewQuery {
    pub vault: String,
}

impl ReviewQuery {
    pub fn new(vault: &str) -> Result<Self, BadFilter> {
        if !crate::azure::vaults::is_valid_vault_name(vault) {
            return Err(BadFilter("vault"));
        }
        Ok(Self {
            vault: vault.to_owned(),
        })
    }

    /// The KQL. The vault name only appears as an escaped string literal
    /// in the `let vaultName` line; the rest is fixed text. Rows come back
    /// sorted by use and item, so when the row cap cuts the answer, the
    /// last row says where.
    pub fn kql(&self, resource_specific: bool) -> String {
        let mut q = format!("let vaultName = {};\n", kql_string(&self.vault));
        let ops = std::iter::once("SecretGet")
            .chain(KEY_OPERATIONS)
            .map(|o| format!("'{o}'"))
            .collect::<Vec<_>>()
            .join(", ");
        if resource_specific {
            q.push_str(&format!(
                "let vaultEvents = AZKVAuditLogs\n\
                 | where TimeGenerated > ago({DAYS}d)\n\
                 | where _ResourceId endswith strcat('/vaults/', tolower(vaultName));\n\
                 let callers = vaultEvents\n\
                 | where OperationName in ({ops})\n\
                 | extend Item = tolower(tostring(split(tostring(parse_url(column_ifexists('RequestUri', '')).Path), '/')[2]))\n\
                 | extend Status = toint(column_ifexists('HttpStatusCode', int(null)))\n\
                 | extend Claims = column_ifexists('Identity', dynamic(null)).claim\n\
                 | extend Upn = coalesce(\n\
                     tostring(Claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn']),\n\
                     tostring(Claims.upn))\n\
                 | extend AppId = tostring(Claims.appid)\n\
                 | extend ObjectId = coalesce(\n\
                     tostring(Claims['http://schemas.microsoft.com/identity/claims/objectidentifier']),\n\
                     tostring(Claims.oid))\n\
                 | extend ManagedId = tostring(Claims.xms_mirid)\n"
            ));
        } else {
            // AzureDiagnostics only has a column once data with it has
            // arrived, so every optional column goes through column_ifexists.
            q.push_str(&format!(
                "let vaultEvents = AzureDiagnostics\n\
                 | where TimeGenerated > ago({DAYS}d)\n\
                 | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'\n\
                 | where Resource =~ vaultName;\n\
                 let callers = vaultEvents\n\
                 | where OperationName in ({ops})\n\
                 | extend Item = tolower(tostring(split(tostring(parse_url(tostring(column_ifexists('requestUri_s', ''))).Path), '/')[2]))\n\
                 | extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))\n\
                 | extend Upn = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_upn_s', '')))\n\
                 | extend AppId = tostring(column_ifexists('identity_claim_appid_g', ''))\n\
                 | extend ObjectId = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')),\n\
                     tostring(column_ifexists('identity_claim_oid_g', '')))\n\
                 | extend ManagedId = tostring(column_ifexists('identity_claim_xms_mirid_s', ''))\n"
            ));
        }
        q.push_str("| where isnotempty(Item)\n");
        q.push_str(&format!(
            "| extend Use = iff(OperationName == 'SecretGet', '{SECRET}', '{KEY}')\n"
        ));
        // Allowed or accepted, by the audit view's one rule.
        q.push_str(&outcome_kql());
        q.push_str("| where Outcome in ('allowed', 'accepted')\n");
        q.push_str(&format!(
            "| summarize Uses = count(), LastUse = max(TimeGenerated), Managed = countif(isnotempty(ManagedId)) by Use, Item, ObjectId, AppId, Upn\n\
             | sort by Use asc, Item asc, LastUse desc\n\
             | extend Rank = row_number(1, prev(Use) != Use or prev(Item) != Item)\n\
             | where Rank <= {per_item}\n\
             | take {rows};\n\
             union callers, (vaultEvents | summarize VaultEvents = count(), Newest = max(TimeGenerated))",
            per_item = MAX_PER_ITEM + 1,
            rows = MAX_ROWS + 1,
        ));
        q
    }
}

/// The callers of one item in one workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemUse {
    /// The most recent callers, at most [`MAX_PER_ITEM`].
    pub callers: Vec<Caller>,
    /// It had more callers than that.
    pub capped: bool,
}

/// One workspace's answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    /// By ([`SECRET`] or [`KEY`], item name in lower case).
    pub items: BTreeMap<(String, String), ItemUse>,
    /// Audit events from this vault, of any kind, in the period. Zero
    /// means the vault's logs haven't arrived in this workspace, not that
    /// its items went unread.
    pub vault_events: u64,
    /// Time of the vault's newest event, as Log Analytics gave it.
    pub newest: String,
    /// Log Analytics said the answer was only partial.
    pub incomplete: bool,
    /// The answer reached [`MAX_ROWS`]. Items after this one (in the
    /// query's order) weren't returned, and this one may be short.
    pub cut_at: Option<(String, String)>,
}

impl Answer {
    /// True when this workspace's answer may be missing callers of
    /// `(use, item)` because the row cap cut it there or before.
    pub fn cut_before(&self, key: &(String, String)) -> bool {
        self.cut_at.as_ref().is_some_and(|c| key >= c)
    }
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    tables: Vec<Table>,
    /// Set on a 200 when Log Analytics gave only part of the answer.
    #[serde(default)]
    error: Option<Value>,
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

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn parse(result: QueryResult) -> Answer {
    let incomplete = result.error.is_some();
    let Some(t) = result.tables.into_iter().next() else {
        return Answer {
            incomplete,
            ..Answer::default()
        };
    };
    let idx = |name: &str| t.columns.iter().position(|c| c.name == name);
    let get = |row: &Vec<Value>, i: Option<usize>| text(i.and_then(|i| row.get(i)));
    let (vi, ni) = (idx("VaultEvents"), idx("Newest"));
    let summary = |r: &Vec<Value>| !get(r, vi).is_empty();
    let (vault_events, newest) = t
        .rows
        .iter()
        .find(|r| summary(r))
        .map(|r| (get(r, vi).parse().unwrap_or(0), get(r, ni)))
        .unwrap_or_default();
    let (usei, ii, oi, ai, ui, ci, li, mi) = (
        idx("Use"),
        idx("Item"),
        idx("ObjectId"),
        idx("AppId"),
        idx("Upn"),
        idx("Uses"),
        idx("LastUse"),
        idx("Managed"),
    );
    let mut rows: Vec<((String, String), Caller)> = t
        .rows
        .iter()
        .filter(|r| !summary(r))
        .filter_map(|r| {
            let kind = get(r, usei);
            let kind = match kind.as_str() {
                SECRET | KEY => kind,
                _ => return None,
            };
            let item = get(r, ii).to_ascii_lowercase();
            if item.is_empty() {
                return None;
            }
            Some((
                (kind, item),
                Caller {
                    object_id: get(r, oi),
                    app_id: get(r, ai),
                    upn: get(r, ui),
                    reads: get(r, ci).parse().unwrap_or(0),
                    last: get(r, li),
                    managed: get(r, mi).parse::<u64>().unwrap_or(0) > 0,
                    client_info: String::new(),
                    ip: String::new(),
                },
            ))
        })
        .collect();
    // The query's order, kept whatever order the union gave.
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.last.cmp(&a.1.last)));
    let mut cut_at = None;
    if rows.len() > MAX_ROWS {
        rows.truncate(MAX_ROWS);
        cut_at = rows.last().map(|(k, _)| k.clone());
    }
    let mut items: BTreeMap<(String, String), ItemUse> = BTreeMap::new();
    for (key, caller) in rows {
        let entry = items.entry(key).or_default();
        if entry.callers.len() < MAX_PER_ITEM {
            entry.callers.push(caller);
        } else {
            entry.capped = true;
        }
    }
    Answer {
        items,
        vault_events,
        newest,
        incomplete,
        cut_at,
    }
}

/// Run the query against one workspace, as the signed-in person.
pub async fn query(
    azure: &AzureClient,
    session: &Session,
    loganalytics_url: &str,
    workspace: &Workspace,
    q: &ReviewQuery,
) -> Result<Answer, AzureError> {
    if !is_safe_resource_id(&workspace.resource_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!("{loganalytics_url}/v1{}/query", workspace.resource_id);
    let body = serde_json::json!({
        "query": q.kql(workspace.resource_specific),
        "timespan": format!("P{DAYS}D"),
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
    fn the_vault_name_is_checked_first() {
        assert!(ReviewQuery::new("kv-test").is_ok());
        for bad in ["bad vault", "kv\"x", "kv'x", "", "kv\n|take 1"] {
            assert_eq!(
                ReviewQuery::new(bad).err(),
                Some(BadFilter("vault")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn kql_puts_the_name_only_in_its_let_literal() {
        let q = ReviewQuery::new("kv-test").unwrap();
        for resource_specific in [true, false] {
            let k = q.kql(resource_specific);
            assert!(k.starts_with("let vaultName = \"kv-test\";\nlet vaultEvents = "));
            assert_eq!(k.matches("kv-test").count(), 1);
            assert_eq!(k.lines().filter(|l| l.starts_with("let ")).count(), 3);
            assert!(!k.contains("materialize"));
            assert!(k.contains("ago(90d)") && !k.contains("ago(30d)"));
            assert!(k.contains(&outcome_kql()));
            assert!(k.contains("| where Outcome in ('allowed', 'accepted')"));
            assert!(k.contains(
                "| summarize Uses = count(), LastUse = max(TimeGenerated), Managed = countif(isnotempty(ManagedId)) by Use, Item, ObjectId, AppId, Upn\n"
            ));
            assert!(k.contains(&format!("| where Rank <= {}\n", MAX_PER_ITEM + 1)));
            assert!(k.contains(&format!("| take {};\n", MAX_ROWS + 1)));
            assert!(k.contains(
                "| where OperationName in ('SecretGet', 'KeySign', 'KeyVerify', 'KeyWrap', 'KeyUnwrap', 'KeyEncrypt', 'KeyDecrypt')\n"
            ));
            assert!(k.ends_with(
                "union callers, (vaultEvents | summarize VaultEvents = count(), Newest = max(TimeGenerated))"
            ));
            // No item name: one query covers every item.
            assert!(!k.contains("itemName"));
        }
        assert!(q.kql(true).contains("AZKVAuditLogs") && !q.kql(true).contains("AzureDiagnostics"));
        assert!(q.kql(false).contains("identity_claim_appid_g"));
    }

    fn row(kind: &str, item: &str, oid: &str, uses: u64, last: &str) -> Value {
        serde_json::json!([kind, item, oid, "app", "", uses, last, 0, null, null])
    }

    fn result(rows: Vec<Value>, partial: bool) -> QueryResult {
        let mut v = serde_json::json!({"tables": [{
            "columns": [{"name": "Use"}, {"name": "Item"}, {"name": "ObjectId"}, {"name": "AppId"},
                        {"name": "Upn"}, {"name": "Uses"}, {"name": "LastUse"}, {"name": "Managed"},
                        {"name": "VaultEvents"}, {"name": "Newest"}],
            "rows": rows
        }]});
        if partial {
            v["error"] = serde_json::json!({"code": "PartialError"});
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn groups_by_item_and_keeps_the_vault_row_apart() {
        let a = parse(result(
            vec![
                row("secret", "DB", "o1", 2, "2026-11-10"),
                serde_json::json!([
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    9,
                    "2026-11-12"
                ]),
                row("key", "k", "o2", 1, "2026-11-01"),
                row("secret", "db", "o3", 5, "2026-11-11"),
                row("other", "x", "o4", 1, "2026-11-11"),
            ],
            true,
        ));
        assert_eq!(a.vault_events, 9);
        assert_eq!(a.newest, "2026-11-12");
        assert!(a.incomplete);
        assert_eq!(a.cut_at, None);
        let db = &a.items[&(SECRET.into(), "db".into())];
        assert_eq!(db.callers.len(), 2);
        assert_eq!(db.callers[0].object_id, "o3", "latest first");
        assert!(!db.capped);
        assert_eq!(a.items.len(), 2);
    }

    #[test]
    fn caps_per_item_and_overall() {
        let rows: Vec<Value> = (0..=MAX_PER_ITEM)
            .map(|i| {
                row(
                    "secret",
                    "busy",
                    &format!("o{i}"),
                    1,
                    &format!("2026-11-{:02}", i % 28 + 1),
                )
            })
            .collect();
        let a = parse(result(rows, false));
        let busy = &a.items[&(SECRET.into(), "busy".into())];
        assert_eq!(busy.callers.len(), MAX_PER_ITEM);
        assert!(busy.capped);
        assert_eq!(a.cut_at, None);

        let rows: Vec<Value> = (0..=MAX_ROWS)
            .map(|i| row("secret", &format!("s{i:05}"), "o", 1, "2026-11-01"))
            .collect();
        let a = parse(result(rows, false));
        let cut = a.cut_at.clone().expect("cut");
        assert_eq!(cut, (SECRET.to_owned(), format!("s{:05}", MAX_ROWS - 1)));
        assert!(a.cut_before(&(SECRET.into(), format!("s{:05}", MAX_ROWS))));
        assert!(a.cut_before(&cut));
        assert!(!a.cut_before(&(SECRET.into(), "s00000".into())));
        assert!(
            !a.cut_before(&(KEY.into(), "zzz".into())),
            "keys sort first"
        );
    }
}
