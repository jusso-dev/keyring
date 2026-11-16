//! The Sentinel content in `infra/sentinel` (ASIM parser, analytic rules,
//! hunting queries and workbook) reads `KeyringAudit_CL`. These tests fail
//! when it drifts from the table or the event: a column that isn't in
//! `COLUMNS` (`src/audit/sink.rs`), an action, outcome or reason code
//! Keyring never writes, a rule that is on by default, or a rule with no
//! sample-row case. They read the files at build time, so they need no
//! network and no Azure. Running the rules on the sample rows needs a
//! workspace (docs/real-vault-checklist.md).

use std::collections::BTreeSet;

use keyring::audit::sink::COLUMNS;
use keyring::audit::{Action, Outcome, Refusal};

const MAIN: &str = include_str!("../infra/sentinel/main.bicep");
const EXAMPLE: &str = include_str!("../infra/sentinel/main.example.bicepparam");
const WORKBOOK: &str = include_str!("../infra/sentinel/workbook.json");
const SAMPLE_ROWS: &str = include_str!("fixtures/sentinel/sample-rows.kql");
const CASES: &str = include_str!("fixtures/sentinel/cases.json");
const SENTINEL_DOC: &str = include_str!("../docs/sentinel.md");

/// Every KQL file, by its path under `infra/sentinel`.
const KQL: &[(&str, &str)] = &[
    (
        "parsers/vimAuditEventKeyring.kql",
        include_str!("../infra/sentinel/parsers/vimAuditEventKeyring.kql"),
    ),
    (
        "parsers/ASimAuditEventKeyring.kql",
        include_str!("../infra/sentinel/parsers/ASimAuditEventKeyring.kql"),
    ),
    (
        "rules/many-reveals.kql",
        include_str!("../infra/sentinel/rules/many-reveals.kql"),
    ),
    (
        "rules/reveal-new-ip.kql",
        include_str!("../infra/sentinel/rules/reveal-new-ip.kql"),
    ),
    (
        "rules/denied-probing.kql",
        include_str!("../infra/sentinel/rules/denied-probing.kql"),
    ),
    (
        "rules/off-hours.kql",
        include_str!("../infra/sentinel/rules/off-hours.kql"),
    ),
    (
        "rules/app-attack.kql",
        include_str!("../infra/sentinel/rules/app-attack.kql"),
    ),
    (
        "rules/audit-gap.kql",
        include_str!("../infra/sentinel/rules/audit-gap.kql"),
    ),
    (
        "rules/unmatched-secret-get.kql",
        include_str!("../infra/sentinel/rules/unmatched-secret-get.kql"),
    ),
    (
        "rules/keyvault-azkv.kql",
        include_str!("../infra/sentinel/rules/keyvault-azkv.kql"),
    ),
    (
        "rules/keyvault-diagnostics.kql",
        include_str!("../infra/sentinel/rules/keyvault-diagnostics.kql"),
    ),
    (
        "hunting/secret-values-read.kql",
        include_str!("../infra/sentinel/hunting/secret-values-read.kql"),
    ),
    (
        "hunting/private-keys-downloaded.kql",
        include_str!("../infra/sentinel/hunting/private-keys-downloaded.kql"),
    ),
    (
        "hunting/deletes-purges-recoveries.kql",
        include_str!("../infra/sentinel/hunting/deletes-purges-recoveries.kql"),
    ),
    (
        "hunting/refused-and-denied.kql",
        include_str!("../infra/sentinel/hunting/refused-and-denied.kql"),
    ),
    (
        "hunting/person-activity.kql",
        include_str!("../infra/sentinel/hunting/person-activity.kql"),
    ),
    (
        "hunting/side-by-side.kql",
        include_str!("../infra/sentinel/hunting/side-by-side.kql"),
    ),
];

/// Tables a query may name.
const TABLES: &[&str] = &[
    "KeyringAudit_CL",
    "AZKVAuditLogs",
    "AzureDiagnostics",
    "KeyVaultCalls",
];

/// Columns Log Analytics adds to every table.
const STANDARD: &[&str] = &["_ItemId", "_ResourceId"];

/// Key Vault's own columns, allowed only in a query over Key Vault's log.
/// Optional ones go through `column_ifexists`, which these tests don't see.
const KEY_VAULT: &[&str] = &[
    "ResourceProvider",
    "Category",
    "Resource",
    "OperationName",
    "ResultSignature",
    "CallerIpAddress",
];

/// A query split into its code (string literals and comments blanked) and
/// its string literals.
fn scan(kql: &str) -> (String, Vec<String>) {
    let mut code = String::with_capacity(kql.len());
    let mut strings = Vec::new();
    let mut chars = kql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                let mut s = String::new();
                while let Some(d) = chars.next() {
                    match d {
                        '\\' => {
                            if let Some(e) = chars.next() {
                                s.push(e);
                            }
                        }
                        d if d == c => break,
                        d => s.push(d),
                    }
                }
                strings.push(s);
                code.push_str(" \"\" ");
            }
            '/' if chars.peek() == Some(&'/') => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        code.push('\n');
                        break;
                    }
                }
            }
            c => code.push(c),
        }
    }
    (code, strings)
}

/// Identifiers that could be columns or tables: they start with a capital
/// letter or `_`. KQL's own functions and operators are lower case.
fn names(code: &str) -> Vec<(String, bool)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = &code[start..i];
            let rest = code[i..].trim_start();
            let assigned = rest.starts_with('=') && !rest.starts_with("==");
            let first = word.as_bytes()[0];
            // `x.Path` and `Claims.oid` are properties, not columns.
            let property = start > 0 && bytes[start - 1] == b'.';
            if !property && (first.is_ascii_uppercase() || first == b'_') {
                out.push((word.to_owned(), assigned));
            }
        } else {
            i += 1;
        }
    }
    out
}

fn workbook_queries() -> Vec<String> {
    let wb: serde_json::Value = serde_json::from_str(WORKBOOK).expect("workbook is JSON");
    wb["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|i| i["content"]["query"].as_str().map(str::to_owned))
        .collect()
}

/// Every query, named, including the workbook's.
fn all_queries() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = KQL
        .iter()
        .map(|(n, q)| ((*n).to_owned(), (*q).to_owned()))
        .collect();
    for (i, q) in workbook_queries().into_iter().enumerate() {
        out.push((format!("workbook.json query {i}"), q));
    }
    out
}

fn columns() -> BTreeSet<&'static str> {
    COLUMNS.iter().map(|c| c.name).collect()
}

#[test]
fn every_column_used_is_in_the_table() {
    let table = columns();
    // Names a query makes itself (`X = ...` or `let X = ...`) anywhere in
    // the content, so a rule may use what keyvault-*.kql projects.
    let made: BTreeSet<String> = all_queries()
        .iter()
        .flat_map(|(_, q)| names(&scan(q).0))
        .filter(|(_, assigned)| *assigned)
        .map(|(n, _)| n)
        .chain(key_vault_calls_columns())
        .collect();
    let mut checked = 0;
    for (file, q) in all_queries() {
        let reads_key_vault = q.contains("AZKVAuditLogs") || q.contains("AzureDiagnostics");
        for (name, _) in names(&scan(&q).0) {
            let known = table.contains(name.as_str())
                || made.contains(&name)
                || TABLES.contains(&name.as_str())
                || STANDARD.contains(&name.as_str())
                || (reads_key_vault && KEY_VAULT.contains(&name.as_str()));
            assert!(
                known,
                "{file} uses {name}, which isn't a KeyringAudit_CL column in src/audit/sink.rs (COLUMNS)"
            );
            checked += 1;
        }
    }
    assert!(checked > 200, "the scanner found too few names: {checked}");
}

/// The columns of `KeyVaultCalls`, which each `rules/keyvault-*.kql`
/// projects for the two rules that read Key Vault's log.
const KEY_VAULT_CALLS: &[&str] = &[
    "TimeGenerated",
    "ResourceId",
    "OperationName",
    "Item",
    "CallerIpAddress",
    "CorrelationId",
    "CallerObjectId",
];

fn key_vault_calls_columns() -> impl Iterator<Item = String> {
    KEY_VAULT_CALLS.iter().map(|c| (*c).to_owned())
}

#[test]
fn key_vault_calls_has_the_same_columns_from_either_table() {
    for (name, q) in KQL.iter().filter(|(n, _)| n.starts_with("rules/keyvault-")) {
        let project = &q[q.find("| project ").expect("project")..];
        for c in KEY_VAULT_CALLS {
            let needle = if *c == "TimeGenerated" || *c == "OperationName" {
                format!("{c},")
            } else {
                format!("{c} = ")
            };
            assert!(project.contains(&needle), "{name} doesn't project {c}");
        }
    }
}

/// String literals that name an action, outcome or reason code.
fn literals() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (file, q) in all_queries() {
        for s in scan(&q).1 {
            out.push((file.clone(), s));
        }
    }
    out
}

#[test]
fn actions_outcomes_and_reason_codes_are_ones_keyring_writes() {
    let actions: BTreeSet<&str> = Action::ALL.iter().map(|a| a.as_str()).collect();
    let outcomes = [
        Outcome::Success,
        Outcome::Denied,
        Outcome::Refused,
        Outcome::Failed,
    ]
    .map(Outcome::as_str);
    let refusals: BTreeSet<&str> = Refusal::ALL.iter().map(|r| r.as_str()).collect();
    for (file, s) in literals() {
        // A dotted lower-case literal is an action or an action prefix.
        let dotted = s.contains('.')
            && s.bytes().any(|b| b.is_ascii_lowercase())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_');
        if dotted {
            assert!(
                actions.contains(s.as_str())
                    || (s.ends_with('.') && actions.iter().any(|a| a.starts_with(&s))),
                "{file} names the action {s}, which Keyring never writes (Action::ALL in src/audit/mod.rs)"
            );
        }
    }
    // Every Outcome == / in (...) and ReasonCode in (...) literal.
    for (file, q) in all_queries() {
        for (column, allowed) in [
            ("Outcome", outcomes.iter().copied().collect::<BTreeSet<_>>()),
            ("ReasonCode", refusals.clone()),
        ] {
            for s in compared_with(&q, column) {
                assert!(
                    allowed.contains(s.as_str()),
                    "{file} compares {column} with \"{s}\", which Keyring never writes"
                );
            }
        }
    }
    // The parser's verbs are the last part of real actions.
    for s in compared_with(KQL[0].1, "Verb") {
        assert!(
            actions
                .iter()
                .any(|a| a.rsplit('.').next() == Some(s.as_str())),
            "the parser maps the verb {s}, which ends no action"
        );
    }
}

/// The string literals a column is compared with: `Column == "x"`,
/// `Column in ("x", "y")` and `Column !in (...)`.
fn compared_with(q: &str, column: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in q.match_indices(column) {
        // Whole word only.
        let before = q[..i].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
            continue;
        }
        let rest = q[i + column.len()..].trim_start();
        let rest = rest.strip_prefix('!').unwrap_or(rest);
        let list = if let Some(r) = rest.strip_prefix("==") {
            let r = r.trim_start();
            match r.strip_prefix('"') {
                Some(r) => &r[..=r.find('"').unwrap_or(0)],
                None => continue,
            }
        } else if let Some(r) = rest.strip_prefix("in") {
            let r = r.trim_start();
            match r.strip_prefix('(') {
                Some(r) => &r[..r.find(')').unwrap_or(0)],
                None => continue,
            }
        } else {
            continue;
        };
        for part in list.split(',') {
            let s = part.trim().trim_matches('"');
            if !s.is_empty() && !part.trim().starts_with(|c: char| c.is_alphabetic()) {
                out.push(s.to_owned());
            }
        }
    }
    out
}

#[test]
fn the_parser_sets_the_mandatory_audit_event_fields() {
    let (code, strings) = scan(KQL[0].1);
    let made: BTreeSet<String> = names(&code)
        .into_iter()
        .filter(|(_, a)| *a)
        .map(|(n, _)| n)
        .collect();
    // Mandatory in the Audit Event schema 1.0.0 and the common fields, and
    // the conditional fields for the ones the parser fills in.
    for field in [
        "EventCount",
        "EventStartTime",
        "EventEndTime",
        "EventType",
        "EventResult",
        "EventProduct",
        "EventVendor",
        "EventSchema",
        "EventSchemaVersion",
        "Dvc",
        "Operation",
        "Object",
        "ObjectType",
        "ActorUserId",
        "ActorUserIdType",
        "ActorUsername",
        "ActorUsernameType",
        "SrcIpAddr",
        "HttpUserAgent",
        "TargetAppName",
        "TargetAppType",
        "EventUid",
        "EventResultDetails",
        "EventSeverity",
        "User",
        "IpAddr",
        "Application",
    ] {
        assert!(made.contains(field), "the parser doesn't set {field}");
    }
    for value in [
        "AuditEvent",
        "1.0.0",
        "AADID",
        "UPN",
        "Keyring",
        "Cloud Resource",
        "Service",
    ] {
        assert!(
            strings.iter().any(|s| s == value),
            "the parser should use \"{value}\""
        );
    }
    // Only the event types and results the schema allows.
    for s in &strings {
        if ["Read", "Create", "Delete", "Set", "Other"].contains(&s.as_str()) {
            continue;
        }
        assert!(
            !["Modify", "Update", "Get", "Error"].contains(&s.as_str()),
            "the parser uses {s}, which the Audit Event schema doesn't allow"
        );
    }
    assert!(!code.contains("join"), "an ASIM parser mustn't join");
    assert!(
        !code.contains("summarize"),
        "an ASIM parser mustn't summarise"
    );
}

#[test]
fn the_parser_declares_the_audit_event_filtering_parameters() {
    for p in [
        "starttime:datetime",
        "endtime:datetime",
        "srcipaddr_has_any_prefix:dynamic",
        "eventtype_in:dynamic",
        "eventresult:string",
        "actorusername_has_any:dynamic",
        "operation_has_any:dynamic",
        "object_has_any:dynamic",
        "newvalue_has_any:dynamic",
        "disabled:bool",
        "pack:bool",
    ] {
        assert!(MAIN.contains(p), "main.bicep should declare {p}");
        let name = p.split(':').next().unwrap();
        if name != "pack" {
            assert!(
                KQL[0].1.contains(name),
                "vimAuditEventKeyring should use {name}"
            );
        }
    }
}

/// Rule files, by key: the KQL files under `rules/` that main.bicep makes a
/// rule from.
fn rule_keys() -> Vec<&'static str> {
    KQL.iter()
        .filter_map(|(n, _)| n.strip_prefix("rules/")?.strip_suffix(".kql"))
        .filter(|k| !k.starts_with("keyvault-"))
        .collect()
}

#[test]
fn every_rule_is_off_unless_its_parameter_turns_it_on() {
    let keys = rule_keys();
    assert_eq!(keys.len(), 7);
    for key in &keys {
        let entry = MAIN
            .find(&format!("key: '{key}'"))
            .unwrap_or_else(|| panic!("main.bicep has no rule {key}"));
        let block = &MAIN[entry..entry + MAIN[entry..].find("\n  }").expect("entry ends")];
        let line = block
            .lines()
            .find(|l| l.trim_start().starts_with("enabled: "))
            .unwrap_or_else(|| panic!("rule {key} has no enabled line"));
        let param = line.trim().trim_start_matches("enabled: ");
        assert!(
            param.starts_with("enable"),
            "rule {key} is enabled by {param}"
        );
        assert!(
            MAIN.contains(&format!("param {param} bool = false")),
            "{param} must default to false"
        );
        assert!(
            block.contains(&format!("loadTextContent('rules/{key}.kql')")),
            "rule {key} should load rules/{key}.kql"
        );
    }
    // The rules that need Keyring's address aren't created without one.
    for key in ["audit-gap", "unmatched-secret-get"] {
        let entry = MAIN.find(&format!("key: '{key}'")).unwrap();
        assert!(
            MAIN[entry..]
                .lines()
                .nth(1)
                .unwrap()
                .contains("create: hasIps")
        );
    }
    assert!(MAIN.contains("var hasIps = !empty(keyringOutboundIps)"));
    assert!(MAIN.contains("param keyringOutboundIps array = []"));
    assert!(MAIN.contains("var rules = filter(allRules, r => r.create)"));
    // The rule waiting on the real-vault check says so where it's turned on.
    assert!(MAIN.contains("Not yet checked on a real vault"));
    assert!(EXAMPLE.contains("param enableUnmatchedSecretGet = false"));
}

#[test]
fn parameters_reach_kql_only_as_numbers_or_json() {
    for (i, line) in MAIN.lines().enumerate() {
        if !line.trim_start().starts_with("query: ") {
            continue;
        }
        for bad in [
            "${offHoursActions}",
            "${offHoursTerms}",
            "${workDays}",
            "${keyringOutboundIps}",
        ] {
            assert!(
                !line.contains(bad),
                "line {} puts an array into KQL without dynamic(string(...))",
                i + 1
            );
        }
    }
    assert!(MAIN.contains("var ipsLiteral = 'dynamic(${string(keyringOutboundIps)})'"));
}

#[test]
fn every_variable_a_rule_needs_is_set_by_the_template() {
    for key in rule_keys() {
        let q = KQL
            .iter()
            .find(|(n, _)| *n == format!("rules/{key}.kql"))
            .unwrap()
            .1;
        let set = q
            .lines()
            .find_map(|l| l.strip_prefix("// Set by main.bicep: "))
            .unwrap_or_else(|| panic!("rules/{key}.kql has no 'Set by main.bicep' line"));
        for name in set.split(',').map(str::trim) {
            assert!(
                MAIN.contains(&format!("let {name} = ")),
                "main.bicep never sets {name} for rules/{key}.kql"
            );
        }
    }
}

#[derive(serde::Deserialize)]
struct Case {
    rule: String,
    lets: String,
    rows: u32,
    why: String,
}

#[test]
fn every_rule_has_a_sample_row_case() {
    let cases: Vec<Case> = serde_json::from_str(CASES).expect("cases.json");
    for key in rule_keys() {
        assert!(
            cases.iter().any(|c| c.rule == key),
            "rules/{key}.kql has no case in tests/fixtures/sentinel/cases.json"
        );
    }
    for c in &cases {
        let q = KQL
            .iter()
            .find(|(n, _)| *n == format!("rules/{}.kql", c.rule))
            .unwrap_or_else(|| panic!("case for unknown rule {}", c.rule))
            .1;
        let set = q
            .lines()
            .find_map(|l| l.strip_prefix("// Set by main.bicep: "))
            .unwrap();
        for name in set.split(',').map(str::trim) {
            assert!(
                c.lets.contains(&format!("let {name} = ")),
                "the {} case doesn't set {name}",
                c.rule
            );
        }
        assert!(c.lets.contains("let KeyringAudit_CL = KeyringRows"));
        assert!(!c.why.is_empty());
        let _ = c.rows;
    }
}

#[test]
fn the_sample_rows_use_table_columns() {
    let table = columns();
    let start = SAMPLE_ROWS
        .find("let KeyringRows = datatable(")
        .expect("KeyringRows");
    let header = &SAMPLE_ROWS[start..start + SAMPLE_ROWS[start..].find(")\n").unwrap()];
    let header = header.trim_start_matches("let KeyringRows = datatable(");
    let mut n = 0;
    for col in header.split(',') {
        let name = col.split(':').next().unwrap().trim();
        if name == "MinutesAgo" {
            continue;
        }
        assert!(table.contains(name), "sample rows use {name}, not a column");
        n += 1;
    }
    assert!(n >= 10);
    // Every reason code in the sample rows is real, so the attack rule's
    // expected count rests on codes Keyring writes.
    for code in ["csrf", "cross_site", "typed_name_mismatch"] {
        assert!(Refusal::ALL.iter().any(|r| r.as_str() == code));
        assert!(SAMPLE_ROWS.contains(&format!("\"{code}\"")));
    }
}

#[test]
fn the_docs_cover_each_rule_and_its_switch() {
    for key in rule_keys() {
        assert!(
            SENTINEL_DOC.contains(&format!("`rules/{key}.kql`")),
            "docs/sentinel.md should list rules/{key}.kql"
        );
    }
    for line in MAIN.lines() {
        if let Some(rest) = line.strip_prefix("param enable") {
            let name = format!("enable{}", rest.split_whitespace().next().unwrap());
            assert!(
                SENTINEL_DOC.contains(&format!("`{name}`")),
                "docs/sentinel.md should name {name}"
            );
        }
    }
}
