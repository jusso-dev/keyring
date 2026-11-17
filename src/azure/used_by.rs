//! Who used a secret, certificate or key in the last 30 days, from Key
//! Vault's audit log in Log Analytics, read as the signed-in person.
//!
//! One fixed query per workspace counts allowed reads (or, for a key, the
//! cryptographic operations) by caller identity with `summarize`. The vault
//! and item names reach the query only as escaped string literals in `let`
//! lines at the top (see [`kql_string`]); the rest is fixed text.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::auth::session::Session;
use crate::azure::audit::{BadFilter, Workspace, is_safe_resource_id, kql_string};
use crate::azure::{AzureClient, AzureError, Resource};

/// Days looked back. Fixed: the query text and the API's timespan.
pub const DAYS: u32 = 30;
/// Most callers one query returns, and the panel shows.
pub const MAX_CALLERS: usize = 100;
/// Most distinct client infos or IP addresses kept for one caller.
const MAX_SEEN: usize = 3;

/// Operations that count as using a key. All are in
/// [`super::audit::OPERATIONS`].
pub const KEY_OPERATIONS: [&str; 6] = [
    "KeySign",
    "KeyVerify",
    "KeyWrap",
    "KeyUnwrap",
    "KeyEncrypt",
    "KeyDecrypt",
];

/// What counts as a use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Reads of a secret's value (`SecretGet`). A certificate's private key
    /// is read through its backing secret, so certificates use this too.
    SecretReads,
    /// Sign, verify, wrap, unwrap, encrypt and decrypt with a key.
    KeyOperations,
}

/// What kind of caller, from the identity claims Key Vault logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    Person,
    ManagedIdentity,
    App,
    Unknown,
}

impl CallerKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Person => "Person",
            Self::ManagedIdentity => "Managed identity",
            Self::App => "App",
            Self::Unknown => "Unknown",
        }
    }
}

/// One distinct caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Sign-in name, for a person.
    pub upn: String,
    /// The app the token was issued to.
    pub app_id: String,
    pub object_id: String,
    /// The token carried a managed identity's resource ID.
    pub managed: bool,
    pub reads: u64,
    /// Time of the latest, as Log Analytics gave it.
    pub last: String,
    /// Up to three user agents, comma separated.
    pub client_info: String,
    /// Up to three IP addresses, comma separated.
    pub ip: String,
}

impl Caller {
    pub fn kind(&self) -> CallerKind {
        if !self.upn.is_empty() {
            CallerKind::Person
        } else if self.managed {
            CallerKind::ManagedIdentity
        } else if !self.app_id.is_empty() {
            CallerKind::App
        } else {
            CallerKind::Unknown
        }
    }
}

/// The vault and item, already checked. Build with [`UsedByQuery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedByQuery {
    pub vault: String,
    pub item: String,
    pub usage: Usage,
}

impl UsedByQuery {
    pub fn new(vault: &str, item: &str, usage: Usage) -> Result<Self, BadFilter> {
        if !crate::azure::vaults::is_valid_vault_name(vault) {
            return Err(BadFilter("vault"));
        }
        if !crate::routes::vault_ctx::is_valid_object_name(item) {
            return Err(BadFilter("item"));
        }
        Ok(Self {
            vault: vault.to_owned(),
            item: item.to_owned(),
            usage,
        })
    }

    /// The KQL. Values only appear as escaped string literals in `let`
    /// lines; the rest of the query is fixed text.
    pub fn kql(&self, resource_specific: bool) -> String {
        let mut q = String::new();
        q.push_str(&format!("let vaultName = {};\n", kql_string(&self.vault)));
        q.push_str(&format!("let itemName = {};\n", kql_string(&self.item)));
        let ops = match self.usage {
            Usage::SecretReads => "'SecretGet'".to_owned(),
            Usage::KeyOperations => KEY_OPERATIONS
                .iter()
                .map(|o| format!("'{o}'"))
                .collect::<Vec<_>>()
                .join(", "),
        };
        if resource_specific {
            q.push_str(&format!(
                "AZKVAuditLogs\n\
                 | where TimeGenerated > ago({DAYS}d)\n\
                 | where _ResourceId endswith strcat('/vaults/', tolower(vaultName))\n\
                 | where OperationName in ({ops})\n\
                 | extend Item = tostring(split(tostring(parse_url(column_ifexists('RequestUri', '')).Path), '/')[2])\n\
                 | where Item =~ itemName\n\
                 | extend Status = toint(column_ifexists('HttpStatusCode', int(null)))\n\
                 | extend Claims = column_ifexists('Identity', dynamic(null)).claim\n\
                 | extend Upn = coalesce(\n\
                     tostring(Claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn']),\n\
                     tostring(Claims.upn))\n\
                 | extend AppId = tostring(Claims.appid)\n\
                 | extend ObjectId = coalesce(\n\
                     tostring(Claims['http://schemas.microsoft.com/identity/claims/objectidentifier']),\n\
                     tostring(Claims.oid))\n\
                 | extend ManagedId = tostring(Claims.xms_mirid)\n\
                 | extend ClientInfo = tostring(column_ifexists('ClientInfo', ''))\n\
                 | extend CallerIp = tostring(column_ifexists('CallerIpAddress', ''))\n"
            ));
        } else {
            // AzureDiagnostics only has a column once data with it has
            // arrived, so every optional column goes through column_ifexists.
            q.push_str(&format!(
                "AzureDiagnostics\n\
                 | where TimeGenerated > ago({DAYS}d)\n\
                 | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'\n\
                 | where Resource =~ vaultName\n\
                 | where OperationName in ({ops})\n\
                 | extend Item = tostring(split(tostring(parse_url(tostring(column_ifexists('requestUri_s', ''))).Path), '/')[2])\n\
                 | where Item =~ itemName\n\
                 | extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))\n\
                 | extend Upn = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_upn_s', '')))\n\
                 | extend AppId = tostring(column_ifexists('identity_claim_appid_g', ''))\n\
                 | extend ObjectId = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')),\n\
                     tostring(column_ifexists('identity_claim_oid_g', '')))\n\
                 | extend ManagedId = tostring(column_ifexists('identity_claim_xms_mirid_s', ''))\n\
                 | extend ClientInfo = tostring(column_ifexists('clientInfo_s', ''))\n\
                 | extend CallerIp = tostring(column_ifexists('CallerIPAddress', ''))\n"
            ));
        }
        // Allowed or accepted, by the audit view's one rule.
        q.push_str(&crate::azure::audit::outcome_kql());
        q.push_str("| where Outcome in ('allowed', 'accepted')\n");
        q.push_str(&format!(
            "| summarize Reads = count(), LastRead = max(TimeGenerated), Managed = countif(isnotempty(ManagedId)), ClientInfo = strcat_array(make_set(ClientInfo, {MAX_SEEN}), ', '), CallerIp = strcat_array(make_set(CallerIp, {MAX_SEEN}), ', ') by ObjectId, AppId, Upn\n\
             | order by LastRead desc\n\
             | take {MAX_CALLERS}"
        ));
        q
    }
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

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn parse(result: QueryResult) -> Vec<Caller> {
    let Some(t) = result.tables.into_iter().next() else {
        return Vec::new();
    };
    let idx = |name: &str| t.columns.iter().position(|c| c.name == name);
    let get = |row: &Vec<Value>, i: Option<usize>| text(i.and_then(|i| row.get(i)));
    let (oi, ai, ui, ri, li, mi, ci, pi) = (
        idx("ObjectId"),
        idx("AppId"),
        idx("Upn"),
        idx("Reads"),
        idx("LastRead"),
        idx("Managed"),
        idx("ClientInfo"),
        idx("CallerIp"),
    );
    t.rows
        .iter()
        .map(|r| Caller {
            object_id: get(r, oi),
            app_id: get(r, ai),
            upn: get(r, ui),
            reads: get(r, ri).parse().unwrap_or(0),
            last: get(r, li),
            managed: get(r, mi).parse::<u64>().unwrap_or(0) > 0,
            client_info: get(r, ci),
            ip: get(r, pi),
        })
        .collect()
}

/// Run the query against one workspace, as the signed-in person.
pub async fn query(
    azure: &AzureClient,
    session: &Session,
    loganalytics_url: &str,
    workspace: &Workspace,
    q: &UsedByQuery,
) -> Result<Vec<Caller>, AzureError> {
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

/// Add `more` to a comma separated list of up to [`MAX_SEEN`] values,
/// skipping repeats.
fn add_seen(list: &mut String, more: &str) {
    for v in more.split(", ").filter(|v| !v.is_empty()) {
        if list.split(", ").count() >= MAX_SEEN && !list.is_empty() {
            return;
        }
        if !list.split(", ").any(|x| x == v) {
            if !list.is_empty() {
                list.push_str(", ");
            }
            list.push_str(v);
        }
    }
}

/// Callers from several workspaces as one: the same caller's reads added
/// up, latest first, at most [`MAX_CALLERS`]. The flag says whether any
/// were left out.
pub fn merge(answers: Vec<Vec<Caller>>) -> (Vec<Caller>, bool) {
    let mut capped = false;
    let mut by: BTreeMap<(String, String, String), Caller> = BTreeMap::new();
    for list in answers {
        capped |= list.len() >= MAX_CALLERS;
        for c in list {
            let key = (
                c.object_id.to_ascii_lowercase(),
                c.app_id.to_ascii_lowercase(),
                c.upn.to_ascii_lowercase(),
            );
            match by.get_mut(&key) {
                Some(e) => {
                    e.reads += c.reads;
                    e.managed |= c.managed;
                    if c.last > e.last {
                        e.last = c.last;
                    }
                    add_seen(&mut e.client_info, &c.client_info);
                    add_seen(&mut e.ip, &c.ip);
                }
                None => {
                    by.insert(key, c);
                }
            }
        }
    }
    let mut list: Vec<Caller> = by.into_values().collect();
    list.sort_by(|a, b| b.last.cmp(&a.last).then_with(|| b.reads.cmp(&a.reads)));
    capped |= list.len() > MAX_CALLERS;
    list.truncate(MAX_CALLERS);
    (list, capped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(oid: &str, upn: &str, reads: u64, last: &str, ip: &str) -> Caller {
        Caller {
            upn: upn.into(),
            app_id: "app-1".into(),
            object_id: oid.into(),
            managed: false,
            reads,
            last: last.into(),
            client_info: String::new(),
            ip: ip.into(),
        }
    }

    #[test]
    fn names_are_checked_first() {
        assert!(UsedByQuery::new("kv-test", "db-password", Usage::SecretReads).is_ok());
        for bad in [
            "x\" or 1==1",
            "a\nb",
            "",
            "-",
            "db\"; AzureActivity | take 1; //",
            "db'",
            "db\\",
        ] {
            assert_eq!(
                UsedByQuery::new("kv-test", bad, Usage::SecretReads).err(),
                Some(BadFilter("item")),
                "{bad:?}"
            );
        }
        for bad in ["bad vault", "kv\"x", "kv'x", ""] {
            assert_eq!(
                UsedByQuery::new(bad, "db", Usage::KeyOperations).err(),
                Some(BadFilter("vault")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn kql_puts_names_only_in_let_literals() {
        for usage in [Usage::SecretReads, Usage::KeyOperations] {
            let q = UsedByQuery::new("kv-test", "db-password", usage).unwrap();
            for resource_specific in [true, false] {
                let k = q.kql(resource_specific);
                assert!(k.starts_with(
                    "let vaultName = \"kv-test\";\nlet itemName = \"db-password\";\n"
                ));
                for v in ["kv-test", "db-password"] {
                    assert_eq!(k.matches(v).count(), 1, "{v} appears once");
                }
                assert_eq!(k.matches("let ").count(), 2, "only the two let lines");
                assert!(k.contains("ago(30d)"));
                assert!(k.contains("| summarize Reads = count(), LastRead = max(TimeGenerated)"));
                assert!(k.contains("by ObjectId, AppId, Upn"));
                assert!(k.ends_with(&format!("| take {MAX_CALLERS}")));
            }
        }
    }

    #[test]
    fn each_table_uses_its_own_column_names() {
        let q = UsedByQuery::new("kv-test", "db", Usage::SecretReads).unwrap();
        let rs = q.kql(true);
        assert!(rs.contains("AZKVAuditLogs"));
        assert!(rs.contains("_ResourceId endswith"));
        for col in [
            "column_ifexists('Identity', dynamic(null))",
            "column_ifexists('ClientInfo', '')",
            "column_ifexists('CallerIpAddress', '')",
            "column_ifexists('HttpStatusCode', int(null))",
        ] {
            assert!(rs.contains(col), "{col}");
        }
        assert!(!rs.contains("AzureDiagnostics") && !rs.contains("_g'"));
        let d = q.kql(false);
        assert!(d.contains("AzureDiagnostics"));
        for col in [
            "column_ifexists('identity_claim_appid_g', '')",
            "column_ifexists('identity_claim_oid_g', '')",
            "column_ifexists('identity_claim_upn_s', '')",
            "column_ifexists('identity_claim_xms_mirid_s', '')",
            "column_ifexists('clientInfo_s', '')",
            "column_ifexists('CallerIPAddress', '')",
            "column_ifexists('httpStatusCode_d', real(null))",
        ] {
            assert!(d.contains(col), "{col}");
        }
        assert!(!d.contains("AZKVAuditLogs") && !d.contains("'CallerIpAddress'"));
    }

    #[test]
    fn what_counts_as_a_use() {
        let s = UsedByQuery::new("kv-test", "db", Usage::SecretReads)
            .unwrap()
            .kql(true);
        assert!(s.contains("| where OperationName in ('SecretGet')\n"));
        let k = UsedByQuery::new("kv-test", "db", Usage::KeyOperations)
            .unwrap()
            .kql(false);
        assert!(k.contains(
            "| where OperationName in ('KeySign', 'KeyVerify', 'KeyWrap', 'KeyUnwrap', 'KeyEncrypt', 'KeyDecrypt')\n"
        ));
        for op in KEY_OPERATIONS {
            assert!(
                super::super::audit::OPERATIONS
                    .iter()
                    .any(|(o, _)| *o == op),
                "{op}"
            );
        }
        // Only allowed calls count, by the audit view's one rule.
        assert!(s.contains(&crate::azure::audit::outcome_kql()));
        assert!(s.contains("| where Outcome in ('allowed', 'accepted')"));
    }

    #[test]
    fn parses_summarised_rows() {
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "columns": [{"name": "ObjectId"}, {"name": "AppId"}, {"name": "Upn"}, {"name": "Reads"},
                        {"name": "LastRead"}, {"name": "Managed"}, {"name": "ClientInfo"}, {"name": "CallerIp"}],
            "rows": [
                ["oid-1", "app-1", "alex@example.com", 12, "2026-11-10T10:00:00Z", 0, "Mozilla/5.0", "203.0.113.5"],
                ["oid-2", "app-2", "", 400, "2026-11-11T10:00:00Z", 400, "azsdk-net", "10.0.0.4"],
                ["oid-3", "app-3", null, 2, "2026-11-09T10:00:00Z", 0, "", ""],
                ["", "", "", 1, "2026-11-08T10:00:00Z", 0, "", ""]
            ]
        }]}))
        .unwrap();
        let c = parse(r);
        assert_eq!(c.len(), 4);
        assert_eq!(c[0].kind(), CallerKind::Person);
        assert_eq!(c[0].reads, 12);
        assert_eq!(c[1].kind(), CallerKind::ManagedIdentity);
        assert_eq!(c[2].kind(), CallerKind::App);
        assert_eq!(c[3].kind(), CallerKind::Unknown);
        assert!(parse(QueryResult { tables: vec![] }).is_empty());
    }

    #[test]
    fn merges_the_same_caller_across_workspaces() {
        let (list, capped) = merge(vec![
            vec![
                caller("oid-1", "alex@example.com", 3, "2026-11-10", "203.0.113.5"),
                caller("oid-2", "", 1, "2026-11-01", ""),
            ],
            vec![caller(
                "OID-1",
                "Alex@example.com",
                2,
                "2026-11-12",
                "198.51.100.7",
            )],
        ]);
        assert!(!capped);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].reads, 5);
        assert_eq!(list[0].last, "2026-11-12");
        assert_eq!(list[0].ip, "203.0.113.5, 198.51.100.7");
        let many: Vec<Caller> = (0..MAX_CALLERS + 5)
            .map(|i| caller(&format!("oid-{i}"), "", 1, "2026-11-01", ""))
            .collect();
        let (list, capped) = merge(vec![many]);
        assert!(capped);
        assert_eq!(list.len(), MAX_CALLERS);
    }

    #[test]
    fn keeps_at_most_three_of_each() {
        let mut s = "a, b".to_owned();
        add_seen(&mut s, "b, c, d");
        assert_eq!(s, "a, b, c");
        let mut e = String::new();
        add_seen(&mut e, "x");
        assert_eq!(e, "x");
    }
}
