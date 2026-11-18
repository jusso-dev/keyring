//! Keyring activity on the audit page: Keyring's own events from
//! `KeyringAudit_CL`, read as the person, only when
//! `KEYRING_AUDIT_WORKSPACE_ID` is set.

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};

const WS: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/law-sentinel";

async fn world() -> support::World {
    let w = support::world_with(&[("KEYRING_AUDIT_WORKSPACE_ID", WS)]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w
}

fn event(vault: &str, action: &str, outcome: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("TimeGenerated", json!("2026-11-17T01:02:03.456Z")),
        ("Vault", json!(vault)),
        ("Action", json!(action)),
        ("Outcome", json!(outcome)),
        ("ActorUpn", json!("alex@example.com")),
        (
            "ActorObjectId",
            json!("11111111-1111-1111-1111-111111111111"),
        ),
        ("ItemKind", json!("secret")),
        ("ItemName", json!("db-password")),
        ("ClientIp", json!("203.0.113.5")),
    ]
}

/// The events table's body, apart from the filter form.
fn rows_of(html: &str) -> &str {
    let at = html.find("id=\"keyring-caption\"").expect("events table");
    let body = &html[at..];
    &body[body.find("<tbody>").unwrap()..body.find("</tbody>").unwrap()]
}

/// The action's label is in a row of the events table, and its code is
/// an option of the Action filter: each checked where it lives, so one
/// can't stand in for the other.
fn assert_row_and_option(html: &str, a: keyring::audit::Action) {
    let rows = rows_of(html);
    assert!(
        rows.contains(&format!(
            "<th scope=\"row\" class=\"cell-text\">{}<data",
            a.label()
        )),
        "no {a} row"
    );
    let select = &html[html.find("<select id=\"action\"").unwrap()..];
    let select = &select[..select.find("</select>").unwrap()];
    assert!(
        select.contains(&format!("<option value=\"{}\">", a.as_str())),
        "no {a} option"
    );
}

#[tokio::test]
async fn shows_keyring_events_read_as_the_person() {
    let w = world().await;
    let mut refused = event("kv-test", "secret.purge", "refused");
    refused.push(("ReasonCode", json!("purge_disabled")));
    *w.arm.state.keyring_rows.lock().unwrap() = vec![
        event("kv-test", "secret.reveal", "success"),
        refused,
        event("kv-other", "secret.delete", "success"),
    ];
    let (status, html) = w.page("/v/kv-test/audit/keyring").await;
    assert_eq!(status, StatusCode::OK);
    assert_row_and_option(&html, keyring::audit::Action::SecretReveal);
    assert!(html.contains("Refused by Keyring"));
    assert!(html.contains("purge_disabled"));
    assert!(html.contains("alex@example.com"));
    assert!(html.contains("<time datetime=\"2026-11-17T01:02:03.456Z\">17 Nov 2026, 01:02</time>"));
    assert!(
        !rows_of(&html).contains(keyring::audit::Action::SecretDelete.label()),
        "another vault's row"
    );
    assert!(html.contains("aria-current=\"page\">Keyring activity"));

    // Against the configured workspace, with the person's Log Analytics
    // token, never the managed identity's.
    let paths = w.arm.state.audit_paths.lock().unwrap().clone();
    assert_eq!(paths, [format!("/v1{WS}/query")]);
    let bearers = w.arm.state.audit_bearers.lock().unwrap().clone();
    assert!(bearers[0].starts_with("Bearer obo:https://api.loganalytics.io/.default"));
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.starts_with("let vaultName = \"kv-test\";"));
    assert!(q.contains("\nKeyringAudit_CL\n") && q.ends_with("| take 500"));
}

#[tokio::test]
async fn reason_and_ticket_are_shown_as_text() {
    let w = world().await;
    let mut e = event("kv-test", "secret.reveal", "success");
    e.push((
        "Reason",
        json!("<script>alert(1)</script> needed for <b>INC</b>"),
    ));
    e.push(("Ticket", json!("CHG-1\" onmouseover=\"x")));
    *w.arm.state.keyring_rows.lock().unwrap() = vec![e];
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("<b>INC</b>"));
    assert!(html.contains("&#60;script&#62;alert(1)&#60;/script&#62;"));
    assert!(!html.contains("\" onmouseover=\""));
    assert!(html.contains(">CHG-1&#34; onmouseover=&#34;x</td>"));
}

#[tokio::test]
async fn filters_go_in_as_literals_and_bad_input_is_refused() {
    let w = world().await;
    let (status, _) = w
        .page("/v/kv-test/audit/keyring?range=30d&item=db-password&action=secret.reveal&person=alex%40example.com")
        .await;
    assert_eq!(status, StatusCode::OK);
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("let itemName = \"db-password\";"));
    assert!(q.contains("let act = \"secret.reveal\";"));
    assert!(q.contains("let who = \"alex@example.com\";"));
    assert!(q.contains("ago(30d)"));

    for bad in [
        "/v/kv-test/audit/keyring?item=x%22%20%7C%20union%20*",
        "/v/kv-test/audit/keyring?person=a%22%3B%20AzureActivity",
        "/v/kv-test/audit/keyring?action=SecretGet",
        "/v/kv-test/audit/keyring?action=secret.reveal%22%20or%201%3D%3D1",
    ] {
        let (status, _) = w.page(bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    assert_eq!(
        w.arm.state.audit_queries.lock().unwrap().len(),
        1,
        "bad filters never reach Log Analytics"
    );
}

#[tokio::test]
async fn explains_when_the_workspace_cant_be_read() {
    let w = world().await;
    *w.arm.state.audit_forbidden.lock().unwrap() = true;
    let (status, html) = w.page("/v/kv-test/audit/keyring").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Log Analytics Reader role"));
    assert!(html.contains("KeyringAudit_CL"));
}

#[tokio::test]
async fn caps_at_500_rows() {
    let w = world().await;
    *w.arm.state.keyring_rows.lock().unwrap() = (0..600)
        .map(|_| event("kv-test", "secret.reveal", "success"))
        .collect();
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    assert!(html.contains("Showing the 500 most recent events"));
    assert_eq!(
        html.matches("<th scope=\"row\" class=\"cell-text\">")
            .count(),
        500
    );
}

#[tokio::test]
async fn without_the_setting_there_is_no_view_and_no_link() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let (status, _) = w.page("/v/kv-test/audit/keyring").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, html) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("Keyring activity"));
    assert!(!html.contains("/audit/keyring"));
    assert!(
        w.arm
            .state
            .audit_queries
            .lock()
            .unwrap()
            .iter()
            .all(|q| !q.contains("KeyringAudit_CL"))
    );
}

#[tokio::test]
async fn the_vault_audit_page_links_to_it_when_set() {
    let w = world().await;
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(html.contains("href=\"/v/kv-test/audit/keyring\">Keyring activity</a>"));
    assert!(
        html.contains("aria-current=\"page\">Key Vault&#39;s log")
            || html.contains("aria-current=\"page\">Key Vault's log")
    );
}

#[test]
fn the_query_reads_only_table_columns() {
    use keyring::audit::sink::COLUMNS;
    for c in keyring::azure::audit_keyring::COLUMNS_READ {
        assert!(
            COLUMNS.iter().any(|k| k.name == c),
            "{c} isn't a KeyringAudit_CL column"
        );
    }
    let q = keyring::azure::audit_keyring::KeyringQuery::new(
        "kv-test",
        keyring::azure::audit::Range::Day,
        "",
        "",
        "",
    )
    .unwrap()
    .kql();
    for c in ["Vault", "ItemName", "Action", "ActorUpn", "ActorObjectId"] {
        assert!(COLUMNS.iter().any(|k| k.name == c));
        assert!(q.contains(c));
    }
}

#[tokio::test]
async fn says_when_log_analytics_returned_only_part() {
    let w = world().await;
    *w.arm.state.keyring_rows.lock().unwrap() = vec![event("kv-test", "secret.reveal", "success")];
    *w.arm.state.keyring_partial.lock().unwrap() = true;
    let (status, html) = w.page("/v/kv-test/audit/keyring").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("only part of the result"));
    assert_row_and_option(&html, keyring::audit::Action::SecretReveal);
    *w.arm.state.keyring_partial.lock().unwrap() = false;
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    assert!(!html.contains("only part of the result"));
}
