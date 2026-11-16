//! The access alert template (`infra/alerts/access.bicep`) queries the same
//! audit logs as Keyring's audit view. These tests fail when the two drift
//! apart: an operation name the audit view doesn't know, or a column read
//! differently from `src/azure/audit.rs`. They read the files at build time,
//! so they need no network and no Azure.

use keyring::azure::audit::{AuditQuery, OPERATIONS, Range};

const TEMPLATE: &str = include_str!("../infra/alerts/access.bicep");

/// The text of a `var name = '''...'''` block in the template.
fn block(name: &str) -> &'static str {
    let start = format!("var {name} = '''\n");
    let from = TEMPLATE
        .find(&start)
        .unwrap_or_else(|| panic!("access.bicep has no {name}"))
        + start.len();
    let len = TEMPLATE[from..].find("'''").expect("block is closed");
    &TEMPLATE[from..from + len]
}

/// Every `'Name'` inside `OperationName in (...)`.
fn operations_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in text.split("OperationName in (").skip(1) {
        let list = &part[..part.find(')').expect("list is closed")];
        for name in list.split(',') {
            out.push(name.trim().trim_matches('\'').to_owned());
        }
    }
    out
}

/// Every column named through `column_ifexists('Name'`.
fn optional_columns(text: &str) -> Vec<String> {
    text.split("column_ifexists('")
        .skip(1)
        .map(|s| s[..s.find('\'').expect("name is closed")].to_owned())
        .collect()
}

/// Lines with runs of spaces collapsed, so indentation doesn't matter.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn audit_kql(resource_specific: bool) -> String {
    AuditQuery::new("kv-test", Range::Day, "", "", "")
        .expect("valid filter")
        .kql(resource_specific)
}

#[test]
fn template_operations_are_ones_the_audit_view_knows() {
    let ops: Vec<String> = ["readsQuery", "purgeQuery"]
        .iter()
        .flat_map(|b| operations_in(block(b)))
        .collect();
    assert_eq!(
        ops,
        [
            "SecretGet",
            "CertificateGet",
            "SecretPurge",
            "CertificatePurge",
            "KeyPurge"
        ]
    );
    for op in &ops {
        assert!(
            OPERATIONS.iter().any(|(known, _)| known == op),
            "{op} is in access.bicep but not in audit::OPERATIONS"
        );
    }
}

#[test]
fn template_reads_columns_the_way_the_audit_view_does() {
    // The status code is only used by the alert, so it is the one column
    // the audit view doesn't read.
    for (name, resource_specific, status_column) in [
        ("diagnosticsSource", false, "httpStatusCode_d"),
        ("resourceSpecificSource", true, "HttpStatusCode"),
    ] {
        let template = block(name);
        let audit = audit_kql(resource_specific);
        let audit_columns = optional_columns(&audit);
        for column in optional_columns(template) {
            assert!(
                column == status_column || audit_columns.contains(&column),
                "{name} reads {column}, which src/azure/audit.rs doesn't"
            );
        }
        // Table, vault filter, item, who and caller IP lines match exactly.
        let squashed_audit = squash(&audit);
        for line in template.split("\n| ") {
            let line = squash(line);
            if line.contains("Status") {
                continue;
            }
            assert!(
                squashed_audit.contains(&line),
                "{name} line differs from src/azure/audit.rs: {line}"
            );
        }
    }
}

#[test]
fn template_projects_the_audit_view_columns() {
    let project = "| project TimeGenerated, Who, OperationName, Item, ResultSignature = tostring(column_ifexists(\\'ResultSignature\\', \\'\\')), CallerIpAddress = Client";
    assert!(
        TEMPLATE.contains(project),
        "access.bicep should project the same columns as the audit view"
    );
    let audit = audit_kql(true).replace('\'', "\\'");
    assert!(audit.contains(project));
}

#[test]
fn template_puts_names_into_kql_only_as_json() {
    // Names reach the query only through dynamic(...) built with string(),
    // so a name can't end a literal and add query text.
    assert!(
        TEMPLATE.contains("var vaultLiteral = 'tostring(dynamic(${string(vaultNameList)})[0])'")
    );
    assert!(TEMPLATE.contains("var namesLiteral = 'dynamic(${string(watchedSecretNames)})'"));
    for (i, line) in TEMPLATE.lines().enumerate() {
        if line.contains("query:") || line.starts_with("var source") {
            assert!(
                !line.contains("${vaultName}") && !line.contains("${watchedSecretNames"),
                "line {} puts a raw parameter into KQL",
                i + 1
            );
        }
    }
}
