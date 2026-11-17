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
    storage_account_id: Option<String>,
    #[serde(default)]
    event_hub_authorization_rule_id: Option<String>,
    #[serde(default)]
    marketplace_partner_id: Option<String>,
    #[serde(default)]
    logs: Vec<LogSetting>,
}

impl SettingProps {
    /// True when the setting has `AuditEvent` (or the `audit` or `allLogs`
    /// group) turned on.
    fn sends_audit(&self) -> bool {
        self.logs.iter().any(|l| {
            l.enabled
                && (l.category.as_deref() == Some("AuditEvent")
                    || matches!(l.category_group.as_deref(), Some("audit") | Some("allLogs")))
        })
    }

    /// True when the setting names somewhere to send logs.
    fn has_destination(&self) -> bool {
        [
            &self.workspace_id,
            &self.storage_account_id,
            &self.event_hub_authorization_rule_id,
            &self.marketplace_partner_id,
        ]
        .iter()
        .any(|d| d.as_deref().is_some_and(|d| !d.trim().is_empty()))
    }
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
        if let (true, Some(ws)) = (p.sends_audit(), p.workspace_id)
            && !out.iter().any(|w| w.resource_id.eq_ignore_ascii_case(&ws))
        {
            out.push(Workspace {
                resource_id: ws,
                resource_specific: p
                    .log_analytics_destination_type
                    .as_deref()
                    .is_some_and(|t| t.eq_ignore_ascii_case("Dedicated")),
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

/// Where a vault's audit logs go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSinks {
    /// Diagnostic settings that send audit logs anywhere: a workspace, a
    /// storage account, an event hub or a partner.
    pub any: usize,
    /// Log Analytics workspaces among them, which the audit view reads.
    pub workspaces: usize,
}

fn audit_sinks_from(settings: SettingsList) -> AuditSinks {
    let any = settings
        .value
        .iter()
        .filter(|s| s.properties.sends_audit() && s.properties.has_destination())
        .count();
    AuditSinks {
        any,
        workspaces: workspaces_from(settings).len(),
    }
}

/// A vault's diagnostic settings, read through ARM. Needs Reader.
async fn settings(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
) -> Result<SettingsList, AzureError> {
    if !is_safe_resource_id(vault_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{vault_id}/providers/Microsoft.Insights/diagnosticSettings?api-version={DIAGNOSTICS_API}"
    );
    azure.get_json(session, Resource::Management, &url).await
}

/// Workspaces for a vault. `vault_id` is the vault's ARM resource ID.
pub async fn workspaces(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
) -> Result<Vec<Workspace>, AzureError> {
    Ok(workspaces_from(
        settings(azure, session, management_url, vault_id).await?,
    ))
}

/// Where a vault sends its audit logs. `any == 0` means it keeps none.
pub async fn audit_sinks(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
) -> Result<AuditSinks, AzureError> {
    Ok(audit_sinks_from(
        settings(azure, session, management_url, vault_id).await?,
    ))
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
    pub(crate) fn kql(self) -> &'static str {
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

/// Letters, digits and `@ . _ -` only: enough for UPNs, emails and GUIDs.
pub(crate) fn is_person(s: &str) -> bool {
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
        if !item.is_empty() && !crate::routes::vault_ctx::is_valid_object_name(item) {
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
                 | where _ResourceId endswith strcat('/vaults/', tolower(vaultName))\n\
                 | extend Item = tostring(split(tostring(parse_url(column_ifexists('RequestUri', '')).Path), '/')[2])\n\
                 | extend Claims = column_ifexists('Identity', dynamic(null)).claim\n\
                 | extend Who = coalesce(\n\
                     tostring(Claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn']),\n\
                     tostring(Claims.upn),\n\
                     tostring(Claims.appid),\n\
                     tostring(Claims['http://schemas.microsoft.com/identity/claims/objectidentifier']),\n\
                     tostring(Claims.oid))\n\
                 | extend Client = tostring(column_ifexists('CallerIpAddress', ''))\n\
                 | extend Status = toint(column_ifexists('HttpStatusCode', int(null)))\n\
                 | project TimeGenerated, Who, OperationName, Item, ResultSignature = tostring(column_ifexists('ResultSignature', '')), CallerIpAddress = Client, Status, ResultType = tostring(column_ifexists('ResultType', ''))\n",
                range = self.range.kql()
            ));
        } else {
            // AzureDiagnostics only has a column once data with it has
            // arrived, so every optional column goes through column_ifexists.
            q.push_str(&format!(
                "AzureDiagnostics\n\
                 | where TimeGenerated > ago({range})\n\
                 | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'\n\
                 | where Resource =~ vaultName\n\
                 | extend Item = tostring(split(tostring(parse_url(tostring(column_ifexists('requestUri_s', ''))).Path), '/')[2])\n\
                 | extend Who = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_appid_g', '')),\n\
                     tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')),\n\
                     tostring(column_ifexists('identity_claim_oid_g', '')))\n\
                 | extend Client = tostring(column_ifexists('CallerIPAddress', ''))\n\
                 | extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))\n\
                 | project TimeGenerated, Who, OperationName, Item, ResultSignature = tostring(column_ifexists('ResultSignature', '')), CallerIpAddress = Client, Status, ResultType = tostring(column_ifexists('ResultType', ''))\n",
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
    /// `ResultSignature`, such as `OK`, `Accepted` or `Forbidden`.
    pub result: String,
    pub client_ip: String,
    /// The HTTP status Key Vault answered with (`HttpStatusCode` or
    /// `httpStatusCode_d`), when the row has one.
    pub status: Option<u16>,
    /// `ResultType`, such as `Success`.
    pub result_type: String,
}

impl Event {
    /// How the request ended. See [`Outcome::of`].
    pub fn outcome(&self) -> Outcome {
        Outcome::of(self.status, &self.result, &self.result_type)
    }
}

/// How a Key Vault request in the audit log ended. The page, the CSVs and
/// the reports across vaults all use this one rule; the reports' KQL
/// ([`outcome_kql`]) is built from the same lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Done: 200, 201, 204 or any other 2xx but 202.
    Allowed,
    /// 202 Accepted: Key Vault took the request and finishes it shortly,
    /// as for every certificate create. Never a refusal.
    Accepted,
    /// 401 or 403.
    Refused,
    /// Any other 4xx or a 5xx, such as 404, 409, 429 or 500.
    Failed,
    /// No result, or one this rule doesn't know.
    Unknown,
}

/// `ResultSignature` values that mean done, when there is no status.
const SIGNATURES_ALLOWED: [&str; 3] = ["OK", "Created", "NoContent"];
/// `ResultSignature` values that mean accepted, when there is no status.
const SIGNATURES_ACCEPTED: [&str; 1] = ["Accepted"];
/// `ResultSignature` values that mean refused, when there is no status.
const SIGNATURES_REFUSED: [&str; 2] = ["Forbidden", "Unauthorized"];
/// `ResultType` that means done, when nothing above decides.
const RESULT_TYPE_SUCCESS: &str = "Success";

impl Outcome {
    /// The rule. The numeric HTTP status wins: it is the status, then a
    /// `ResultSignature` that is a number. Without one, a known
    /// `ResultSignature`, then `ResultType` `Success`. Anything else is
    /// [`Outcome::Unknown`], never a refusal.
    pub fn of(status: Option<u16>, signature: &str, result_type: &str) -> Self {
        let signature = signature.trim();
        if let Some(code) = status.or_else(|| signature.parse().ok()) {
            return match code {
                202 => Self::Accepted,
                200..=299 => Self::Allowed,
                401 | 403 => Self::Refused,
                400..=599 => Self::Failed,
                _ => Self::Unknown,
            };
        }
        let is = |list: &[&str]| list.iter().any(|s| s.eq_ignore_ascii_case(signature));
        if is(&SIGNATURES_ACCEPTED) {
            Self::Accepted
        } else if is(&SIGNATURES_ALLOWED) {
            Self::Allowed
        } else if is(&SIGNATURES_REFUSED) {
            Self::Refused
        } else if result_type.trim().eq_ignore_ascii_case(RESULT_TYPE_SUCCESS) {
            Self::Allowed
        } else {
            Self::Unknown
        }
    }

    /// The word shown on the page and written to the CSV.
    pub fn label(self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::Accepted => "Accepted",
            Self::Refused => "Refused",
            Self::Failed => "Failed",
            Self::Unknown => "Unknown",
        }
    }

    /// The value of the `Outcome` column [`outcome_kql`] adds.
    pub fn kql(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Accepted => "accepted",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    /// Allowed or accepted: the request went through.
    pub fn went_through(self) -> bool {
        matches!(self, Self::Allowed | Self::Accepted)
    }
}

/// KQL that adds an `Outcome` column holding [`Outcome::kql`], by the same
/// rule as [`Outcome::of`]. Needs a `Status` column (int, may be null) and
/// reads `ResultSignature` and `ResultType` through `column_ifexists`. Fixed
/// text.
pub(crate) fn outcome_kql() -> String {
    let list = |l: &[&str]| {
        l.iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let sig = "tostring(column_ifexists('ResultSignature', ''))";
    format!(
        "| extend ResultCode = coalesce(Status, toint({sig}))\n\
         | extend Outcome = case(\
         ResultCode == 202, '{accepted}', \
         ResultCode between (200 .. 299), '{allowed}', \
         ResultCode in (401, 403), '{refused}', \
         ResultCode between (400 .. 599), '{failed}', \
         isnotnull(ResultCode), '{unknown}', \
         {sig} in~ ({sig_accepted}), '{accepted}', \
         {sig} in~ ({sig_allowed}), '{allowed}', \
         {sig} in~ ({sig_refused}), '{refused}', \
         tostring(column_ifexists('ResultType', '')) =~ '{RESULT_TYPE_SUCCESS}', '{allowed}', \
         '{unknown}')\n",
        accepted = Outcome::Accepted.kql(),
        allowed = Outcome::Allowed.kql(),
        refused = Outcome::Refused.kql(),
        failed = Outcome::Failed.kql(),
        unknown = Outcome::Unknown.kql(),
        sig_accepted = list(&SIGNATURES_ACCEPTED),
        sig_allowed = list(&SIGNATURES_ALLOWED),
        sig_refused = list(&SIGNATURES_REFUSED),
    )
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
    let (si, yi) = (idx("Status"), idx("ResultType"));
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
            status: status(si.and_then(|i| r.get(i))),
            result_type: get(r, yi),
        })
        .collect()
}

/// An HTTP status from a query result cell: a number, or a string of one.
/// Null, empty or anything else is `None`.
pub(crate) fn status(v: Option<&Value>) -> Option<u16> {
    match v? {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f as u64))
            .and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
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
    fn counts_every_kind_of_audit_destination() {
        let s: SettingsList = serde_json::from_value(serde_json::json!({"value": [
            {"properties": {"workspaceId": "/w1", "logs": [{"category": "AuditEvent", "enabled": true}]}},
            {"properties": {"storageAccountId": "/st", "logs": [{"categoryGroup": "audit", "enabled": true}]}},
            {"properties": {"eventHubAuthorizationRuleId": "/eh", "logs": [{"categoryGroup": "allLogs", "enabled": true}]}},
            {"properties": {"marketplacePartnerId": "/p", "logs": [{"category": "AuditEvent", "enabled": true}]}},
            // Off, a metrics-only setting and one with nowhere to go.
            {"properties": {"workspaceId": "/w2", "logs": [{"category": "AuditEvent", "enabled": false}]}},
            {"properties": {"workspaceId": "/w3", "logs": [], "metrics": [{"category": "AllMetrics", "enabled": true}]}},
            {"properties": {"logs": [{"category": "AuditEvent", "enabled": true}]}}
        ]}))
        .unwrap();
        assert_eq!(
            audit_sinks_from(s),
            AuditSinks {
                any: 4,
                workspaces: 1
            }
        );
        let none: SettingsList = serde_json::from_value(serde_json::json!({"value": []})).unwrap();
        assert_eq!(audit_sinks_from(none).any, 0);
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
        assert!(
            k.contains("_ResourceId endswith"),
            "resource-specific tables have _ResourceId, not Resource"
        );
        let d = q.kql(false);
        assert!(d.contains("AzureDiagnostics"));
        assert!(
            d.contains("column_ifexists('CallerIPAddress', '')"),
            "AzureDiagnostics spells it CallerIPAddress"
        );
        assert!(d.contains("column_ifexists('identity_claim_upn_s', '')"));
        assert!(
            !d.contains("CallerIpAddress)"),
            "no bare reference to a column that may not exist"
        );
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
    fn one_rule_for_every_outcome() {
        use Outcome::*;
        let cases: &[(Option<u16>, &str, &str, Outcome)] = &[
            // Numeric status, any signature.
            (Some(200), "OK", "Success", Allowed),
            (Some(201), "Created", "Success", Allowed),
            (Some(202), "Accepted", "Success", Accepted),
            (Some(204), "NoContent", "Success", Allowed),
            (Some(401), "Unauthorized", "Failure", Refused),
            (Some(403), "Forbidden", "Failure", Refused),
            (Some(404), "NotFound", "Failure", Failed),
            (Some(409), "Conflict", "Failure", Failed),
            (Some(429), "TooManyRequests", "Failure", Failed),
            (Some(500), "InternalServerError", "Failure", Failed),
            (Some(503), "ServiceUnavailable", "Failure", Failed),
            // Conflicting fields: the numeric status wins.
            (Some(403), "OK", "Success", Refused),
            (Some(202), "Forbidden", "Failure", Accepted),
            (Some(500), "OK", "Success", Failed),
            // A status no rule knows is unknown, whatever the text says.
            (Some(102), "OK", "Success", Unknown),
            (Some(302), "Forbidden", "", Unknown),
            // No status: a signature that is a number counts as one.
            (None, "202", "", Accepted),
            (None, "204", "", Allowed),
            (None, "403", "Success", Refused),
            (None, "429", "", Failed),
            // No status: known signatures, any case.
            (None, "OK", "", Allowed),
            (None, "ok", "", Allowed),
            (None, "Created", "", Allowed),
            (None, "Accepted", "", Accepted),
            (None, "NoContent", "", Allowed),
            (None, "Forbidden", "", Refused),
            (None, "Unauthorized", "", Refused),
            // No status: a signature that is known wins over ResultType.
            (None, "Forbidden", "Success", Refused),
            (None, "Accepted", "Failure", Accepted),
            // Then ResultType Success.
            (None, "", "Success", Allowed),
            (None, "SomethingNew", "Success", Allowed),
            // Absent or unrecognised stays unknown, never refused.
            (None, "", "", Unknown),
            (None, "  ", "", Unknown),
            (None, "SomethingNew", "", Unknown),
            (None, "SomethingNew", "Failure", Unknown),
        ];
        for (status, sig, rt, want) in cases {
            assert_eq!(
                Outcome::of(*status, sig, rt),
                *want,
                "{status:?} {sig} {rt}"
            );
        }
        assert!(Accepted.went_through() && Allowed.went_through());
        assert!(!Refused.went_through() && !Failed.went_through() && !Unknown.went_through());
    }

    /// The reports' KQL is built from the same lists as [`Outcome::of`],
    /// in the same order: status first, then the signature, then ResultType.
    #[test]
    fn outcome_kql_follows_the_same_rule() {
        let k = outcome_kql();
        let at = |needle: &str| k.find(needle).unwrap_or_else(|| panic!("{needle} in {k}"));
        assert!(
            k.contains("coalesce(Status, toint(tostring(column_ifexists('ResultSignature', ''))))")
        );
        assert!(
            at("ResultCode == 202, 'accepted'") < at("ResultCode between (200 .. 299), 'allowed'")
        );
        assert!(
            at("ResultCode in (401, 403), 'refused'")
                < at("ResultCode between (400 .. 599), 'failed'")
        );
        assert!(at("isnotnull(ResultCode), 'unknown'") < at("in~ ('Accepted'), 'accepted'"));
        assert!(k.contains("in~ ('OK', 'Created', 'NoContent'), 'allowed'"));
        assert!(k.contains("in~ ('Forbidden', 'Unauthorized'), 'refused'"));
        assert!(at("in~ ('Forbidden', 'Unauthorized'), 'refused'") < at("=~ 'Success', 'allowed'"));
        assert!(k.trim_end().ends_with("'unknown')"));
        for o in [
            Outcome::Allowed,
            Outcome::Accepted,
            Outcome::Refused,
            Outcome::Failed,
            Outcome::Unknown,
        ] {
            assert!(k.contains(&format!("'{}'", o.kql())), "{o:?}");
        }
    }

    #[test]
    fn kql_reads_the_status_and_result_type_of_both_tables() {
        let q = AuditQuery::new("kv-test", Range::Day, "", "", "").unwrap();
        let rs = q.kql(true);
        assert!(
            rs.contains("| extend Status = toint(column_ifexists('HttpStatusCode', int(null)))")
        );
        let d = q.kql(false);
        assert!(
            d.contains("| extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))")
        );
        for k in [rs, d] {
            assert!(
                k.contains(", Status, ResultType = tostring(column_ifexists('ResultType', ''))")
            );
        }
    }

    #[test]
    fn reads_the_status_as_a_number_or_text() {
        assert_eq!(status(Some(&serde_json::json!(202))), Some(202));
        assert_eq!(status(Some(&serde_json::json!(202.0))), Some(202));
        assert_eq!(status(Some(&serde_json::json!("202"))), Some(202));
        assert_eq!(status(Some(&serde_json::json!(null))), None);
        assert_eq!(status(Some(&serde_json::json!(""))), None);
        assert_eq!(status(Some(&serde_json::json!(70000))), None);
        assert_eq!(status(None), None);
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
        assert_eq!((e[0].status, e[0].outcome()), (None, Outcome::Allowed));

        // A certificate create, as Key Vault logs it: queued, not refused.
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "columns": [{"name": "TimeGenerated"}, {"name": "Who"}, {"name": "OperationName"}, {"name": "Item"}, {"name": "ResultSignature"}, {"name": "CallerIpAddress"}, {"name": "Status"}, {"name": "ResultType"}],
            "rows": [["2026-11-17T03:12:45Z", "alex@example.com", "CertificateCreate", "web-tls", "Accepted", "203.0.113.5", 202, "Success"]]
        }]}))
        .unwrap();
        let e = parse_events(r);
        assert_eq!(e[0].status, Some(202));
        assert_eq!(e[0].result_type, "Success");
        assert_eq!(e[0].outcome(), Outcome::Accepted);
    }
}
