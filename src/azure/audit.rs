//! Key Vault audit events from Log Analytics, read as the signed-in user.
//!
//! 1. Read the vault's diagnostic settings (ARM) to find Log Analytics
//!    workspaces it sends `AuditEvent` logs to.
//! 2. Query the workspace with the Log Analytics query API.
//!
//! User input never goes into the query as raw text. Every value is first
//! checked against a strict pattern, then written as a KQL string literal
//! by [`kql_string`], and only referenced through `let` bindings at the
//! top of the query.

use serde::Deserialize;
use serde_json::Value;

use crate::auth::session::Session;
use crate::azure::{AzureClient, AzureError, Resource};

pub const DIAGNOSTICS_API: &str = "2021-05-01-preview";
/// Most rows one query returns.
pub const MAX_ROWS: u32 = 500;

/// A workspace a vault sends audit logs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// ARM resource ID of the workspace.
    pub resource_id: String,
    /// Whether the setting uses the resource-specific table
    /// (`AZKVAuditLogs`) rather than `AzureDiagnostics`.
    pub resource_specific: bool,
}

#[derive(Deserialize)]
struct SettingsList {
    #[serde(default)]
    value: Vec<Setting>,
}

#[derive(Deserialize)]
struct Setting {
    #[serde(default)]
    properties: SettingProps,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SettingProps {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    log_analytics_destination_type: Option<String>,
    #[serde(default)]
    logs: Vec<LogSetting>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LogSetting {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    category_group: Option<String>,
    #[serde(default)]
    enabled: bool,
}

/// Pick the workspaces that receive `AuditEvent` logs.
fn workspaces_from(settings: SettingsList) -> Vec<Workspace> {
    let mut out: Vec<Workspace> = Vec::new();
    for s in settings.value {
        let p = s.properties;
        let audits = p.logs.iter().any(|l| {
            l.enabled
                && (l.category.as_deref() == Some("AuditEvent")
                    || matches!(l.category_group.as_deref(), Some("audit") | Some("allLogs")))
        });
        if let (true, Some(ws)) = (audits, p.workspace_id)
            && !out.iter().any(|w| w.resource_id.eq_ignore_ascii_case(&ws))
        {
            out.push(Workspace {
                resource_id: ws,
                resource_specific: p.log_analytics_destination_type.as_deref() == Some("Dedicated"),
            });
        }
    }
    out
}

/// An ARM resource ID Keyring will put into a URL path: starts with
/// `/subscriptions/`, and only letters, digits and `/ - _ . ( )`. Rules out
/// anything that could change the host or add a query (`@`, `?`, `#`,
/// `:`, `\`) or climb the path (`..`).
pub fn is_safe_resource_id(id: &str) -> bool {
    id.len() <= 1024
        && id.to_ascii_lowercase().starts_with("/subscriptions/")
        && !id.contains("..")
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'(' | b')')
        })
}

/// Workspaces for a vault. `vault_id` is the vault's ARM resource ID.
pub async fn workspaces(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
) -> Result<Vec<Workspace>, AzureError> {
    if !is_safe_resource_id(vault_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{vault_id}/providers/Microsoft.Insights/diagnosticSettings?api-version={DIAGNOSTICS_API}"
    );
    let list: SettingsList = azure.get_json(session, Resource::Management, &url).await?;
    Ok(workspaces_from(list))
}

/// Time ranges offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Hour,
    Day,
    Week,
    Month,
}

impl Range {
    pub const ALL: [Range; 4] = [Range::Hour, Range::Day, Range::Week, Range::Month];

    pub fn parse(s: &str) -> Self {
        match s {
            "1h" => Self::Hour,
            "7d" => Self::Week,
            "30d" => Self::Month,
            _ => Self::Day,
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            Self::Hour => "1h",
            Self::Day => "24h",
            Self::Week => "7d",
            Self::Month => "30d",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Hour => "Last hour",
            Self::Day => "Last 24 hours",
            Self::Week => "Last 7 days",
            Self::Month => "Last 30 days",
        }
    }
    /// KQL timespan. A fixed constant, never user text.
    fn kql(self) -> &'static str {
        match self {
            Self::Hour => "1h",
            Self::Day => "24h",
            Self::Week => "7d",
            Self::Month => "30d",
        }
    }
    /// ISO 8601 duration for the API's `timespan` parameter.
    pub fn iso(self) -> &'static str {
        match self {
            Self::Hour => "PT1H",
            Self::Day => "P1D",
            Self::Week => "P7D",
            Self::Month => "P30D",
        }
    }
}

/// Filters, already checked. Build with [`AuditQuery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub vault: String,
    pub range: Range,
    /// Item name (secret, certificate or key), exact match.
    pub item: Option<String>,
    /// Key Vault operation name, from [`OPERATIONS`] only.
    pub operation: Option<String>,
    /// Who: part of a UPN, app ID or object ID.
    pub person: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BadFilter(pub &'static str);

fn is_object_name(s: &str) -> bool {
    (1..=127).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Letters, digits and `@ . _ -` only: enough for UPNs, emails and GUIDs.
fn is_person(s: &str) -> bool {
    (1..=256).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-'))
}

impl AuditQuery {
    pub fn new(
        vault: &str,
        range: Range,
        item: &str,
        operation: &str,
        person: &str,
    ) -> Result<Self, BadFilter> {
        if !crate::azure::vaults::is_valid_vault_name(vault) {
            return Err(BadFilter("vault"));
        }
        let item = item.trim();
        if !item.is_empty() && !is_object_name(item) {
            return Err(BadFilter("item"));
        }
        let operation = operation.trim();
        if !operation.is_empty() && !OPERATIONS.iter().any(|(op, _)| *op == operation) {
            return Err(BadFilter("operation"));
        }
        let person = person.trim();
        if !person.is_empty() && !is_person(person) {
            return Err(BadFilter("person"));
        }
        Ok(Self {
            vault: vault.to_owned(),
            range,
            item: (!item.is_empty()).then(|| item.to_owned()),
            operation: (!operation.is_empty()).then(|| operation.to_owned()),
            person: (!person.is_empty()).then(|| person.to_owned()),
        })
    }

    /// The KQL. Values only appear as escaped string literals in `let`
    /// lines; the rest of the query is fixed text.
    pub fn kql(&self, resource_specific: bool) -> String {
        let lit = |v: &Option<String>| kql_string(v.as_deref().unwrap_or(""));
        let mut q = String::new();
        q.push_str(&format!("let vaultName = {};\n", kql_string(&self.vault)));
        q.push_str(&format!("let itemName = {};\n", lit(&self.item)));
        q.push_str(&format!("let op = {};\n", lit(&self.operation)));
        q.push_str(&format!("let who = {};\n", lit(&self.person)));
        if resource_specific {
            q.push_str(&format!(
                "AZKVAuditLogs\n\
                 | where TimeGenerated > ago({range})\n\
                 | where Resource =~ vaultName\n\
                 | extend Item = tostring(split(tostring(parse_url(RequestUri).Path), '/')[2])\n\
                 | extend Who = coalesce(tostring(Identity.claim.upn), tostring(Identity.claim.appid), tostring(Identity.claim.oid))\n\
                 | project TimeGenerated, Who, OperationName, Item, ResultSignature, CallerIpAddress\n",
                range = self.range.kql()
            ));
        } else {
            q.push_str(&format!(
                "AzureDiagnostics\n\
                 | where TimeGenerated > ago({range})\n\
                 | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'\n\
                 | where Resource =~ vaultName\n\
                 | extend Item = tostring(split(tostring(parse_url(requestUri_s).Path), '/')[2])\n\
                 | extend Who = coalesce(identity_claim_upn_s, identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s, identity_claim_appid_g, identity_claim_oid_g)\n\
                 | project TimeGenerated, Who, OperationName, Item, ResultSignature, CallerIpAddress\n",
                range = self.range.kql()
            ));
        }
        q.push_str("| where isempty(itemName) or Item =~ itemName\n");
        q.push_str("| where isempty(op) or OperationName == op\n");
        q.push_str("| where isempty(who) or Who contains who\n");
        q.push_str(&format!("| order by TimeGenerated desc\n| take {MAX_ROWS}"));
        q
    }
}

/// A KQL string literal. Double-quoted, with `\` and `"` escaped and any
/// control characters written as escapes, so the value can't end the
/// string or add query text. Callers also validate first; this is the
/// second guard.
pub fn kql_string(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Key Vault operation names and what they mean in plain words.
pub const OPERATIONS: [(&str, &str); 40] = [
    ("SecretGet", "Viewed secret value"),
    ("SecretList", "Listed secrets"),
    ("SecretListVersions", "Listed secret versions"),
    ("SecretSet", "Set secret value"),
    ("SecretUpdate", "Changed secret details"),
    ("SecretDelete", "Deleted secret"),
    ("SecretRecover", "Recovered secret"),
    ("SecretPurge", "Permanently deleted secret"),
    ("SecretListDeleted", "Listed deleted secrets"),
    ("SecretGetDeleted", "Viewed deleted secret"),
    ("SecretBackup", "Backed up secret"),
    ("SecretRestore", "Restored secret from backup"),
    ("CertificateGet", "Viewed certificate"),
    ("CertificateList", "Listed certificates"),
    ("CertificateListVersions", "Listed certificate versions"),
    ("CertificateCreate", "Created certificate"),
    ("CertificateImport", "Uploaded certificate"),
    ("CertificateUpdate", "Changed certificate details"),
    ("CertificateDelete", "Deleted certificate"),
    ("CertificateRecover", "Recovered certificate"),
    ("CertificatePurge", "Permanently deleted certificate"),
    ("CertificatePolicyGet", "Viewed certificate policy"),
    ("CertificatePolicyUpdate", "Changed certificate policy"),
    (
        "CertificatePendingGet",
        "Checked pending certificate request",
    ),
    ("KeyGet", "Viewed key"),
    ("KeyList", "Listed keys"),
    ("KeyListVersions", "Listed key versions"),
    ("KeyCreate", "Created key"),
    ("KeyUpdate", "Changed key details"),
    ("KeyRotate", "Rotated key"),
    ("KeyDelete", "Deleted key"),
    ("KeyRecover", "Recovered key"),
    ("KeyPurge", "Permanently deleted key"),
    ("KeyEncrypt", "Encrypted with key"),
    ("KeyDecrypt", "Decrypted with key"),
    ("KeySign", "Signed with key"),
    ("KeyVerify", "Verified signature"),
    ("KeyWrap", "Wrapped a key"),
    ("KeyUnwrap", "Unwrapped a key"),
    ("VaultGet", "Viewed vault settings"),
];

/// Plain words for an operation. Unknown names are split at capitals
/// (`KeyRotationPolicyGet` becomes `Key rotation policy get`).
pub fn describe(op: &str) -> String {
    if let Some((_, label)) = OPERATIONS.iter().find(|(o, _)| *o == op) {
        return (*label).to_owned();
    }
    let mut out = String::new();
    for (i, c) in op.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push(' ');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// One audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub time: String,
    pub who: String,
    pub operation: String,
    pub item: String,
    pub result: String,
    pub client_ip: String,
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

fn parse_events(result: QueryResult) -> Vec<Event> {
    let Some(t) = result.tables.into_iter().next() else {
        return Vec::new();
    };
    let idx = |name: &str| t.columns.iter().position(|c| c.name == name);
    let (ti, wi, oi, ii, ri, ci) = (
        idx("TimeGenerated"),
        idx("Who"),
        idx("OperationName"),
        idx("Item"),
        idx("ResultSignature"),
        idx("CallerIpAddress"),
    );
    let get = |row: &Vec<Value>, i: Option<usize>| -> String {
        i.and_then(|i| row.get(i))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    t.rows
        .iter()
        .map(|r| Event {
            time: get(r, ti),
            who: get(r, wi),
            operation: get(r, oi),
            item: get(r, ii),
            result: get(r, ri),
            client_ip: get(r, ci),
        })
        .collect()
}

/// Run the query against a workspace, as the user.
pub async fn query(
    azure: &AzureClient,
    session: &Session,
    loganalytics_url: &str,
    workspace: &Workspace,
    q: &AuditQuery,
) -> Result<Vec<Event>, AzureError> {
    // The resource-centric endpoint takes the workspace's ARM ID, so no
    // separate workspace GUID lookup is needed.
    if !is_safe_resource_id(&workspace.resource_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!("{loganalytics_url}/v1{}/query", workspace.resource_id);
    let body = serde_json::json!({
        "query": q.kql(workspace.resource_specific),
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
    Ok(parse_events(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_audit_workspaces() {
        let s: SettingsList = serde_json::from_value(serde_json::json!({"value": [
            {"properties": {"workspaceId": "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w1",
              "logAnalyticsDestinationType": "Dedicated",
              "logs": [{"category": "AuditEvent", "enabled": true}]}},
            {"properties": {"workspaceId": "/w2", "logs": [{"categoryGroup": "allLogs", "enabled": true}]}},
            {"properties": {"workspaceId": "/w3", "logs": [{"category": "AuditEvent", "enabled": false}]}},
            {"properties": {"storageAccountId": "/st", "logs": [{"category": "AuditEvent", "enabled": true}]}}
        ]}))
        .unwrap();
        let w = workspaces_from(s);
        assert_eq!(w.len(), 2);
        assert!(w[0].resource_specific);
        assert!(!w[1].resource_specific);
    }

    #[test]
    fn filters_are_validated() {
        assert!(
            AuditQuery::new(
                "kv-test",
                Range::Day,
                "db-password",
                "SecretGet",
                "alex@example.com"
            )
            .is_ok()
        );
        assert_eq!(
            AuditQuery::new("bad vault", Range::Day, "", "", "").err(),
            Some(BadFilter("vault"))
        );
        assert_eq!(
            AuditQuery::new("kv-test", Range::Day, "x\" or 1==1", "", "").err(),
            Some(BadFilter("item"))
        );
        assert_eq!(
            AuditQuery::new("kv-test", Range::Day, "", "SecretGet | take 1", "").err(),
            Some(BadFilter("operation"))
        );
        assert_eq!(
            AuditQuery::new("kv-test", Range::Day, "", "", "a\"; drop").err(),
            Some(BadFilter("person"))
        );
        assert_eq!(
            AuditQuery::new("kv-test", Range::Day, "", "", "a b").err(),
            Some(BadFilter("person"))
        );
    }

    #[test]
    fn kql_puts_values_only_in_let_literals() {
        let q = AuditQuery::new(
            "kv-test",
            Range::Week,
            "db-password",
            "SecretGet",
            "alex@example.com",
        )
        .unwrap();
        let k = q.kql(true);
        assert!(k.starts_with("let vaultName = \"kv-test\";\nlet itemName = \"db-password\";\nlet op = \"SecretGet\";\nlet who = \"alex@example.com\";\n"));
        assert!(k.contains("AZKVAuditLogs"));
        assert!(k.contains("ago(7d)"));
        // Each value appears exactly once: in its let line.
        for v in ["kv-test", "db-password", "SecretGet\"", "alex@example.com"] {
            assert_eq!(k.matches(v).count(), 1, "{v}");
        }
        assert!(q.kql(false).contains("AzureDiagnostics"));
        let empty = AuditQuery::new("kv-test", Range::Day, "", "", "")
            .unwrap()
            .kql(true);
        assert!(empty.contains("let itemName = \"\";"));
    }

    #[test]
    fn kql_string_escapes() {
        assert_eq!(kql_string("plain"), "\"plain\"");
        assert_eq!(kql_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(kql_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(kql_string("a\nb"), "\"a\\nb\"");
        assert_eq!(kql_string("\u{1}"), "\"\\u0001\"");
        // Whatever goes in, the result is one literal: starts and ends with
        // a quote and has no unescaped quote inside.
        for nasty in ["\"; AzureActivity | take 1; //", "\\\"", "x\" | union *"] {
            let lit = kql_string(nasty);
            let inner = &lit[1..lit.len() - 1];
            let mut prev_backslashes = 0;
            for c in inner.chars() {
                if c == '"' {
                    assert!(prev_backslashes % 2 == 1, "unescaped quote in {lit}");
                }
                prev_backslashes = if c == '\\' { prev_backslashes + 1 } else { 0 };
            }
        }
    }

    #[test]
    fn resource_ids_that_could_change_the_url_are_refused() {
        assert!(is_safe_resource_id(
            "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv"
        ));
        assert!(is_safe_resource_id(
            "/SUBSCRIPTIONS/s/resourceGroups/rg(1)/providers/x/y"
        ));
        for bad in [
            "@evil.example/x",
            ".evil.example/x",
            "/subscriptions/x?y",
            "/subscriptions/x#y",
            "/subscriptions/../../x",
            "/subscriptions/x@evil",
            "https://evil",
            "/subscriptions/x:443",
            "",
        ] {
            assert!(!is_safe_resource_id(bad), "{bad}");
        }
    }

    #[test]
    fn plain_words_for_operations() {
        assert_eq!(describe("SecretGet"), "Viewed secret value");
        assert_eq!(describe("KeyRotate"), "Rotated key");
        assert_eq!(describe("KeyRotationPolicyGet"), "Key rotation policy get");
    }

    #[test]
    fn parses_query_results() {
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "name": "PrimaryResult",
            "columns": [{"name": "TimeGenerated"}, {"name": "Who"}, {"name": "OperationName"}, {"name": "Item"}, {"name": "ResultSignature"}, {"name": "CallerIpAddress"}],
            "rows": [["2026-11-09T10:00:00Z", "alex@example.com", "SecretGet", "db-password", "OK", "203.0.113.5"]]
        }]}))
        .unwrap();
        let e = parse_events(r);
        assert_eq!(e[0].who, "alex@example.com");
        assert_eq!(e[0].operation, "SecretGet");
    }
}
