//! Audit across vaults: fixed reports over the Log Analytics workspaces the
//! person's vaults send their audit logs to, read as the signed-in person.
//!
//! Vaults that log to the same workspace and table are covered by one
//! query. Their ARM resource IDs reach the query only as escaped string
//! literals in `let` lines at the top (see [`kql_string`]), and the person
//! filter is checked first and then goes in the same way. The rest of the
//! query is fixed text: each report is a fixed body, and time ranges come
//! from a fixed list.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::auth::session::Session;
use crate::azure::audit::{
    BadFilter, Event, MAX_ROWS, Range, Workspace, is_person, is_safe_resource_id, kql_string,
};
use crate::azure::{AzureClient, AzureError, Resource};

/// The fixed reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// Secret values read (allowed `SecretGet`).
    Reads,
    /// Secret reads of a certificate's backing secret, which carries the
    /// private key.
    PrivateKeys,
    /// Deletes, purges and recoveries.
    Changes,
    /// Refused requests (403), grouped by person and vault.
    Refused,
    /// Everything one person did.
    Person,
}

/// Operations the deletes report covers. All are in [`super::audit::OPERATIONS`].
pub const CHANGE_OPERATIONS: [&str; 9] = [
    "SecretDelete",
    "SecretPurge",
    "SecretRecover",
    "CertificateDelete",
    "CertificatePurge",
    "CertificateRecover",
    "KeyDelete",
    "KeyPurge",
    "KeyRecover",
];

impl Report {
    pub const ALL: [Report; 5] = [
        Report::Reads,
        Report::PrivateKeys,
        Report::Changes,
        Report::Refused,
        Report::Person,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.slug() == s)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Reads => "reads",
            Self::PrivateKeys => "private-keys",
            Self::Changes => "deletes",
            Self::Refused => "refused",
            Self::Person => "person",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Reads => "Secret values read",
            Self::PrivateKeys => "Private keys downloaded",
            Self::Changes => "Deletes, purges and recoveries",
            Self::Refused => "Refused requests",
            Self::Person => "Activity by one person",
        }
    }

    /// What the report shows, in one or two plain sentences.
    pub fn about(self) -> &'static str {
        match self {
            Self::Reads => "Every allowed read of a secret's value.",
            Self::PrivateKeys => {
                "Reads of a certificate's backing secret, which holds its private key. A secret read counts when the same vault's logs name a certificate with that name in the same period. Keyring's own download always does, other tools may not."
            }
            Self::Changes => {
                "Every delete, permanent delete (purge) and recovery of a secret, certificate or key, allowed or refused."
            }
            Self::Refused => {
                "Requests Key Vault refused (403), counted by person and vault, most refused first."
            }
            Self::Person => {
                "Everything one person did, by part of their sign-in name, email or ID."
            }
        }
    }

    /// The range a fixed link opens with.
    pub fn default_range(self) -> Range {
        match self {
            Self::PrivateKeys | Self::Changes => Range::Month,
            Self::Reads | Self::Refused | Self::Person => Range::Week,
        }
    }

    /// True for the report whose rows are counts, not events.
    pub fn grouped(self) -> bool {
        matches!(self, Self::Refused)
    }

    /// The fixed text after the `let` lines and the shared source.
    fn body(self) -> String {
        let allowed =
            "| where Status between (200 .. 299) or (isnull(Status) and ResultSignature =~ 'OK')\n";
        let latest = format!("| order by TimeGenerated desc\n| take {MAX_ROWS}");
        match self {
            Self::Reads => {
                format!("audit\n| where OperationName == 'SecretGet'\n{allowed}{latest}")
            }
            Self::PrivateKeys => format!(
                "let certificates = audit\n\
                 | where OperationName startswith 'Certificate' and isnotempty(Item)\n\
                 | extend Key = tolower(Item)\n\
                 | distinct VaultId, Key;\n\
                 audit\n\
                 | where OperationName == 'SecretGet'\n\
                 {allowed}\
                 | extend Key = tolower(Item)\n\
                 | join kind=leftsemi certificates on VaultId, Key\n\
                 | project-away Key\n\
                 {latest}"
            ),
            Self::Changes => {
                let ops: Vec<String> = CHANGE_OPERATIONS.iter().map(|o| format!("'{o}'")).collect();
                format!(
                    "audit\n| where OperationName in ({})\n{latest}",
                    ops.join(", ")
                )
            }
            Self::Refused => format!(
                "audit\n\
                 | where Status == 403 or (isnull(Status) and ResultSignature =~ 'Forbidden')\n\
                 | summarize Refused = count(), LastSeen = max(TimeGenerated), Operations = strcat_array(make_set(OperationName, 10), ', ') by VaultId, Who\n\
                 | order by Refused desc\n\
                 | take {MAX_ROWS}"
            ),
            Self::Person => format!("audit\n| where Who contains who\n{latest}"),
        }
    }
}

/// A report with its filters, already checked. Build with [`ReportQuery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportQuery {
    pub report: Report,
    pub range: Range,
    /// Only for [`Report::Person`], where it is required.
    pub person: Option<String>,
}

impl ReportQuery {
    pub fn new(report: Report, range: Range, person: &str) -> Result<Self, BadFilter> {
        let person = person.trim();
        let person = if report == Report::Person {
            if !is_person(person) {
                return Err(BadFilter("person"));
            }
            Some(person.to_owned())
        } else {
            None
        };
        Ok(Self {
            report,
            range,
            person,
        })
    }

    /// The KQL for one workspace and table, covering `vault_ids` (ARM
    /// resource IDs). Values only appear as escaped string literals in
    /// `let` lines; everything else is fixed text.
    pub fn kql(&self, vault_ids: &[String], resource_specific: bool) -> String {
        let mut q = String::new();
        let mut names = Vec::with_capacity(vault_ids.len());
        for (i, id) in vault_ids.iter().enumerate() {
            q.push_str(&format!("let vault{i} = {};\n", kql_string(id)));
            names.push(format!("vault{i}"));
        }
        q.push_str(&format!(
            "let who = {};\n",
            kql_string(self.person.as_deref().unwrap_or(""))
        ));
        let range = self.range.kql();
        let vaults = names.join(", ");
        if resource_specific {
            q.push_str(&format!(
                "let audit = AZKVAuditLogs\n\
                 | where TimeGenerated > ago({range})\n\
                 | where _ResourceId in~ ({vaults})\n\
                 | extend Item = tostring(split(tostring(parse_url(column_ifexists('RequestUri', '')).Path), '/')[2])\n\
                 | extend Claims = column_ifexists('Identity', dynamic(null)).claim\n\
                 | extend Who = coalesce(\n\
                     tostring(Claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn']),\n\
                     tostring(Claims.upn),\n\
                     tostring(Claims.appid),\n\
                     tostring(Claims['http://schemas.microsoft.com/identity/claims/objectidentifier']),\n\
                     tostring(Claims.oid))\n\
                 | extend Client = tostring(column_ifexists('CallerIpAddress', ''))\n\
                 | extend Status = toint(column_ifexists('HttpStatusCode', int(null)))\n"
            ));
        } else {
            q.push_str(&format!(
                "let audit = AzureDiagnostics\n\
                 | where TimeGenerated > ago({range})\n\
                 | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'\n\
                 | where _ResourceId in~ ({vaults})\n\
                 | extend Item = tostring(split(tostring(parse_url(tostring(column_ifexists('requestUri_s', ''))).Path), '/')[2])\n\
                 | extend Who = coalesce(\n\
                     tostring(column_ifexists('identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_upn_s', '')),\n\
                     tostring(column_ifexists('identity_claim_appid_g', '')),\n\
                     tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')),\n\
                     tostring(column_ifexists('identity_claim_oid_g', '')))\n\
                 | extend Client = tostring(column_ifexists('CallerIPAddress', ''))\n\
                 | extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))\n"
            ));
        }
        q.push_str("| project TimeGenerated, VaultId = _ResourceId, Who, OperationName, Item, ResultSignature = tostring(column_ifexists('ResultSignature', '')), CallerIpAddress = Client, Status;\n");
        q.push_str(&self.report.body());
        q
    }
}

/// One query's worth: a workspace and table, and the vaults that log there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceGroup {
    pub workspace: Workspace,
    /// ARM resource IDs of the vaults, in the order given.
    pub vault_ids: Vec<String>,
}

/// Group vaults by the workspace and table they log to, so vaults that
/// share one are covered by one query. `vaults` is each vault's ARM ID and
/// its audit workspaces. Sorted by workspace ID, so the order is stable.
pub fn group(vaults: &[(String, Vec<Workspace>)]) -> Vec<WorkspaceGroup> {
    let mut by: BTreeMap<(String, bool), WorkspaceGroup> = BTreeMap::new();
    for (vault_id, workspaces) in vaults {
        for ws in workspaces {
            let key = (ws.resource_id.to_ascii_lowercase(), ws.resource_specific);
            let g = by.entry(key).or_insert_with(|| WorkspaceGroup {
                workspace: ws.clone(),
                vault_ids: Vec::new(),
            });
            if !g.vault_ids.iter().any(|v| v.eq_ignore_ascii_case(vault_id)) {
                g.vault_ids.push(vault_id.clone());
            }
        }
    }
    by.into_values().collect()
}

/// An event, with the ARM ID of the vault it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEvent {
    pub vault_id: String,
    pub event: Event,
}

/// Refused requests from one person to one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub vault_id: String,
    pub who: String,
    pub count: u64,
    /// Time of the latest, as Log Analytics gave it.
    pub last: String,
    /// Operation names, comma separated.
    pub operations: String,
}

/// What one query returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Events(Vec<VaultEvent>),
    Refusals(Vec<Refusal>),
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

fn parse(result: QueryResult, grouped: bool) -> Answer {
    let Some(t) = result.tables.into_iter().next() else {
        return if grouped {
            Answer::Refusals(Vec::new())
        } else {
            Answer::Events(Vec::new())
        };
    };
    let idx = |name: &str| t.columns.iter().position(|c| c.name == name);
    let get = |row: &Vec<Value>, i: Option<usize>| text(i.and_then(|i| row.get(i)));
    let vi = idx("VaultId");
    let wi = idx("Who");
    if grouped {
        let (ci, li, oi) = (idx("Refused"), idx("LastSeen"), idx("Operations"));
        return Answer::Refusals(
            t.rows
                .iter()
                .map(|r| Refusal {
                    vault_id: get(r, vi),
                    who: get(r, wi),
                    count: get(r, ci).parse().unwrap_or(0),
                    last: get(r, li),
                    operations: get(r, oi),
                })
                .collect(),
        );
    }
    let (ti, oi, ii, ri, pi) = (
        idx("TimeGenerated"),
        idx("OperationName"),
        idx("Item"),
        idx("ResultSignature"),
        idx("CallerIpAddress"),
    );
    Answer::Events(
        t.rows
            .iter()
            .map(|r| VaultEvent {
                vault_id: get(r, vi),
                event: Event {
                    time: get(r, ti),
                    who: get(r, wi),
                    operation: get(r, oi),
                    item: get(r, ii),
                    result: get(r, ri),
                    client_ip: get(r, pi),
                },
            })
            .collect(),
    )
}

/// Run the report against one workspace, for the vaults in `group`, as the
/// signed-in person.
pub async fn query(
    azure: &AzureClient,
    session: &Session,
    loganalytics_url: &str,
    group: &WorkspaceGroup,
    q: &ReportQuery,
) -> Result<Answer, AzureError> {
    if !is_safe_resource_id(&group.workspace.resource_id)
        || group.vault_ids.is_empty()
        || !group.vault_ids.iter().all(|v| is_safe_resource_id(v))
    {
        return Err(AzureError::Unreadable);
    }
    let url = format!("{loganalytics_url}/v1{}/query", group.workspace.resource_id);
    let body = serde_json::json!({
        "query": q.kql(&group.vault_ids, group.workspace.resource_specific),
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
    Ok(parse(result, q.report.grouped()))
}

/// Answers from several workspaces as one: events newest first, refusals
/// summed by vault and person, most first. At most [`MAX_ROWS`] either way.
/// The flag says whether rows were left out.
pub fn merge(answers: Vec<Answer>, grouped: bool) -> (Answer, bool) {
    let max = MAX_ROWS as usize;
    if grouped {
        let mut by: BTreeMap<(String, String), Refusal> = BTreeMap::new();
        let mut capped = false;
        for a in answers {
            let Answer::Refusals(list) = a else { continue };
            capped |= list.len() >= max;
            for r in list {
                let key = (r.vault_id.to_ascii_lowercase(), r.who.clone());
                match by.get_mut(&key) {
                    Some(e) => {
                        e.count += r.count;
                        if r.last > e.last {
                            e.last = r.last;
                        }
                        for op in r.operations.split(", ").filter(|o| !o.is_empty()) {
                            if !e.operations.split(", ").any(|x| x == op) {
                                if !e.operations.is_empty() {
                                    e.operations.push_str(", ");
                                }
                                e.operations.push_str(op);
                            }
                        }
                    }
                    None => {
                        by.insert(key, r);
                    }
                }
            }
        }
        let mut list: Vec<Refusal> = by.into_values().collect();
        list.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.last.cmp(&a.last)));
        capped |= list.len() > max;
        list.truncate(max);
        (Answer::Refusals(list), capped)
    } else {
        let mut list = Vec::new();
        let mut capped = false;
        for a in answers {
            let Answer::Events(mut e) = a else { continue };
            capped |= e.len() >= max;
            list.append(&mut e);
        }
        list.sort_by(|a, b| b.event.time.cmp(&a.event.time));
        capped |= list.len() > max;
        list.truncate(max);
        (Answer::Events(list), capped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KV_A: &str =
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-a";
    const KV_B: &str =
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-b";

    fn ws(name: &str, resource_specific: bool) -> Workspace {
        Workspace {
            resource_id: format!(
                "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/{name}"
            ),
            resource_specific,
        }
    }

    /// The query's shape: `let` lines first, each a name and one string
    /// literal (or the fixed tabular lets), quotes and brackets balanced,
    /// pipes only at the start of a line, and one of the two Key Vault
    /// tables. Not a full KQL parser, but it catches a value that escaped
    /// its literal or a body that lost a bracket.
    fn assert_shape(k: &str) {
        let mut lines = k.lines().peekable();
        let mut lets = 0;
        while let Some(line) = lines.peek() {
            let Some(rest) = line.strip_prefix("let ") else {
                break;
            };
            if rest.starts_with("audit = ") {
                break;
            }
            let (name, lit) = rest.split_once(" = ").expect("let name = value");
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric()),
                "let name {name}"
            );
            let lit = lit.strip_suffix(';').expect("let ends with ;");
            assert!(lit.starts_with('"') && lit.ends_with('"') && lit.len() >= 2);
            let inner = &lit[1..lit.len() - 1];
            let mut slashes = 0;
            for c in inner.chars() {
                if c == '"' {
                    assert!(slashes % 2 == 1, "unescaped quote in {line}");
                }
                slashes = if c == '\\' { slashes + 1 } else { 0 };
            }
            lets += 1;
            lines.next();
        }
        assert!(lets >= 2, "a vault and who");
        let rest: Vec<&str> = lines.collect();
        assert!(
            rest[0] == "let audit = AZKVAuditLogs" || rest[0] == "let audit = AzureDiagnostics",
            "{}",
            rest[0]
        );
        let body = rest.join("\n");
        // Outside the let lines, no double quotes at all: every value is a
        // let literal, and fixed text uses single quotes.
        assert!(!body.contains('"'), "double quote in the fixed text");
        let mut depth = 0i32;
        let mut in_single = false;
        for c in body.chars() {
            match c {
                '\'' => in_single = !in_single,
                '(' | '[' if !in_single => depth += 1,
                ')' | ']' if !in_single => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "closing bracket before opening");
        }
        assert_eq!(depth, 0, "brackets balance");
        assert!(!in_single, "single quotes balance");
        for line in &rest[1..] {
            let t = line.trim_start();
            assert!(
                t.starts_with("| ")
                    || t.starts_with("tostring(")
                    || t.starts_with("audit")
                    || t.starts_with("let certificates = audit"),
                "unexpected line: {line}"
            );
        }
        assert!(body.ends_with(&format!("| take {MAX_ROWS}")));
    }

    #[test]
    fn every_report_has_a_well_formed_query_on_both_tables() {
        for report in Report::ALL {
            let q = ReportQuery::new(report, report.default_range(), "alex@example.com").unwrap();
            for resource_specific in [true, false] {
                let k = q.kql(&[KV_A.into(), KV_B.into()], resource_specific);
                assert_shape(&k);
                assert!(k.contains("| where _ResourceId in~ (vault0, vault1)"));
                assert!(k.contains(&format!("ago({})", report.default_range().kql())));
            }
        }
    }

    #[test]
    fn reports_have_their_own_filters() {
        let k = |r: Report| {
            ReportQuery::new(r, Range::Week, "alex")
                .unwrap()
                .kql(&[KV_A.into()], true)
        };
        assert!(k(Report::Reads).contains("| where OperationName == 'SecretGet'"));
        assert!(k(Report::Reads).contains("Status between (200 .. 299)"));
        assert!(k(Report::PrivateKeys).contains("join kind=leftsemi certificates on VaultId, Key"));
        let changes = k(Report::Changes);
        for op in CHANGE_OPERATIONS {
            assert!(changes.contains(&format!("'{op}'")), "{op}");
            assert!(
                crate::azure::audit::OPERATIONS
                    .iter()
                    .any(|(o, _)| *o == op),
                "{op} has plain words"
            );
        }
        assert!(k(Report::Refused).contains("summarize Refused = count()"));
        assert!(k(Report::Refused).contains("by VaultId, Who"));
        assert!(k(Report::Person).contains("| where Who contains who"));
        assert!(k(Report::Person).contains("let who = \"alex\";"));
        // Other reports carry an empty who and never filter on it.
        assert!(k(Report::Reads).contains("let who = \"\";"));
        assert!(!k(Report::Reads).contains("Who contains"));
    }

    #[test]
    fn the_person_filter_is_checked_and_required() {
        assert!(ReportQuery::new(Report::Person, Range::Week, "alex@example.com").is_ok());
        for bad in ["", "a b", "a\"; drop", "x\" | union *"] {
            assert_eq!(
                ReportQuery::new(Report::Person, Range::Week, bad).err(),
                Some(BadFilter("person")),
                "{bad}"
            );
        }
        // Other reports ignore it, so a stale value can't reach a query.
        let q = ReportQuery::new(Report::Reads, Range::Week, "a\"; drop").unwrap();
        assert_eq!(q.person, None);
    }

    #[test]
    fn vault_ids_only_appear_as_let_literals() {
        let q = ReportQuery::new(Report::Reads, Range::Week, "").unwrap();
        let k = q.kql(&[KV_A.into(), KV_B.into()], false);
        assert!(k.starts_with(&format!(
            "let vault0 = \"{KV_A}\";\nlet vault1 = \"{KV_B}\";\nlet who = \"\";\n"
        )));
        for id in [KV_A, KV_B] {
            assert_eq!(k.matches(id).count(), 1, "{id}");
        }
        // An ID that tries to end its literal stays one literal. These are
        // refused before a query is sent (see `query`), and escaped here
        // as the second guard.
        for nasty in [
            "/subscriptions/x\"); AzureActivity | take 1; //",
            "/subscriptions/x\\\") | union *",
            "/subscriptions/x\n| union *",
        ] {
            let k = q.kql(&[nasty.into()], true);
            assert_shape(&k);
            assert!(!k.contains("\n| union *"));
            assert!(!is_safe_resource_id(nasty));
        }
    }

    #[test]
    fn vaults_sharing_a_workspace_are_one_group() {
        let groups = group(&[
            (KV_A.into(), vec![ws("logs", true)]),
            (KV_B.into(), vec![ws("LOGS", true), ws("logs", false)]),
            ("/subscriptions/s/x/vaults/kv-c".into(), vec![]),
        ]);
        assert_eq!(groups.len(), 2);
        let rs = groups
            .iter()
            .find(|g| g.workspace.resource_specific)
            .unwrap();
        assert_eq!(rs.vault_ids, [KV_A, KV_B]);
        let diag = groups
            .iter()
            .find(|g| !g.workspace.resource_specific)
            .unwrap();
        assert_eq!(diag.vault_ids, [KV_B]);
    }

    #[test]
    fn parses_events_and_refusals() {
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "columns": [{"name": "TimeGenerated"}, {"name": "VaultId"}, {"name": "Who"}, {"name": "OperationName"}, {"name": "Item"}, {"name": "ResultSignature"}, {"name": "CallerIpAddress"}, {"name": "Status"}],
            "rows": [["2026-11-09T10:00:00Z", KV_A, "alex@example.com", "SecretGet", "db", "OK", "203.0.113.5", 200]]
        }]}))
        .unwrap();
        let Answer::Events(e) = parse(r, false) else {
            panic!("events")
        };
        assert_eq!(e[0].vault_id, KV_A);
        assert_eq!(e[0].event.item, "db");
        let r: QueryResult = serde_json::from_value(serde_json::json!({"tables": [{
            "columns": [{"name": "VaultId"}, {"name": "Who"}, {"name": "Refused"}, {"name": "LastSeen"}, {"name": "Operations"}],
            "rows": [[KV_A, "sam@example.com", 4, "2026-11-09T10:00:00Z", "SecretGet, SecretList"]]
        }]}))
        .unwrap();
        let Answer::Refusals(r) = parse(r, true) else {
            panic!("refusals")
        };
        assert_eq!(r[0].count, 4);
        assert_eq!(r[0].operations, "SecretGet, SecretList");
    }

    #[test]
    fn merge_sums_refusals_and_keeps_the_newest_events() {
        let refusal = |n, last: &str, ops: &str| Refusal {
            vault_id: KV_A.into(),
            who: "sam".into(),
            count: n,
            last: last.into(),
            operations: ops.into(),
        };
        let (a, capped) = merge(
            vec![
                Answer::Refusals(vec![refusal(2, "2026-11-01", "SecretGet")]),
                Answer::Refusals(vec![refusal(3, "2026-11-02", "SecretGet, KeyGet")]),
            ],
            true,
        );
        assert!(!capped);
        let Answer::Refusals(r) = a else { panic!() };
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].count, r[0].last.as_str()), (5, "2026-11-02"));
        assert_eq!(r[0].operations, "SecretGet, KeyGet");

        let ev = |t: &str| VaultEvent {
            vault_id: KV_A.into(),
            event: Event {
                time: t.into(),
                who: String::new(),
                operation: String::new(),
                item: String::new(),
                result: String::new(),
                client_ip: String::new(),
            },
        };
        let many: Vec<VaultEvent> = (0..MAX_ROWS).map(|_| ev("2026-11-01")).collect();
        let (a, capped) = merge(
            vec![Answer::Events(many), Answer::Events(vec![ev("2026-11-09")])],
            false,
        );
        assert!(capped);
        let Answer::Events(e) = a else { panic!() };
        assert_eq!(e.len(), MAX_ROWS as usize);
        assert_eq!(e[0].event.time, "2026-11-09");
    }
}
