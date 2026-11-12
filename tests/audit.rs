//! Audit view and per-item history.

mod support;

use axum::http::StatusCode;
use support::body_text;

fn row(time: &str, who: &str, op: &str, item: &str, result: &str) -> [String; 6] {
    [
        time.into(),
        who.into(),
        op.into(),
        item.into(),
        result.into(),
        "203.0.113.5".into(),
    ]
}

fn setup(w: &support::World) {
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
}

#[tokio::test]
async fn shows_recent_events_in_plain_words() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.audit_rows.lock().unwrap() = vec![
        row(
            "2026-11-09T10:00:00.123Z",
            "alex@example.com",
            "SecretGet",
            "db-password",
            "OK",
        ),
        row(
            "2026-11-09T09:00:00Z",
            "",
            "KeyRotate",
            "app-key",
            "Forbidden",
        ),
    ];
    let (status, html) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Viewed secret value"));
    assert!(html.contains("Rotated key"));
    assert!(html.contains("alex@example.com"));
    assert!(html.contains("2026-11-09 10:00:00 UTC"));
    assert!(html.contains("Refused (Forbidden)"));
    assert!(html.contains("Unknown"));
    // Queried with the Log Analytics OBO token, against the resource-specific table.
    let bearers = w.arm.state.audit_bearers.lock().unwrap().clone();
    assert!(bearers[0].starts_with("Bearer obo:https://api.loganalytics.io/.default"));
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("AZKVAuditLogs") && q.contains("let vaultName = \"kv-test\";"));
}

#[tokio::test]
async fn filters_go_in_as_literals_and_bad_input_is_refused() {
    let w = support::world().await;
    setup(&w);
    let (status, _) = w
        .page("/v/kv-test/audit?range=7d&item=db-password&operation=SecretGet&person=alex%40example.com")
        .await;
    assert_eq!(status, StatusCode::OK);
    let q = w
        .arm
        .state
        .audit_queries
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert!(q.contains("let itemName = \"db-password\";"));
    assert!(q.contains("let op = \"SecretGet\";"));
    assert!(q.contains("let who = \"alex@example.com\";"));
    assert!(q.contains("ago(7d)"));

    let before = w.arm.state.audit_queries.lock().unwrap().len();
    for bad in [
        "/v/kv-test/audit?item=x%22%20%7C%20union%20*",
        "/v/kv-test/audit?person=a%22%3B%20AzureActivity",
        "/v/kv-test/audit?operation=SecretGet%20%7C%20take%201",
    ] {
        let (status, _) = w.page(bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    assert_eq!(
        w.arm.state.audit_queries.lock().unwrap().len(),
        before,
        "bad filters never reach Log Analytics"
    );
}

#[tokio::test]
async fn explains_missing_logging_and_permissions() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(
        html.contains("isn&#39;t sending its audit logs")
            || html.contains("isn't sending its audit logs")
    );
    assert!(html.contains("diagnostic setting"));

    *w.arm.state.diagnostics.lock().unwrap() = None;
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(
        html.contains("can&#39;t see where this vault sends its logs")
            || html.contains("can't see where this vault sends its logs")
    );

    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(false));
    *w.arm.state.audit_forbidden.lock().unwrap() = true;
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(html.contains("Log Analytics Reader role"));
}

#[tokio::test]
async fn uses_azure_diagnostics_table_when_not_dedicated() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(false));
    w.page("/v/kv-test/audit").await;
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("AzureDiagnostics") && q.contains("Category == 'AuditEvent'"));
}

#[tokio::test]
async fn item_history_and_csv_match() {
    let w = support::world().await;
    setup(&w);
    w.kv.state.put("db-password", "TOPSECRET");
    *w.arm.state.audit_rows.lock().unwrap() = vec![
        row(
            "2026-11-09T10:00:00Z",
            "alex@example.com",
            "SecretGet",
            "db-password",
            "OK",
        ),
        row(
            "2026-11-09T09:00:00Z",
            "=cmd|' /C calc'!A0",
            "SecretSet",
            "db-password",
            "OK",
        ),
    ];
    let (_, detail) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(
        detail.contains("href=\"/v/kv-test/audit?item=db-password&amp;range=30d&amp;from=secret\"")
    );
    let (_, html) = w.page("/v/kv-test/audit?item=db-password&range=30d").await;
    assert!(html.contains("Who used <span class=\"mono\">db-password</span>"));
    let q = w
        .arm
        .state
        .audit_queries
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert!(q.contains("let itemName = \"db-password\";"));

    let res = w
        .get("/v/kv-test/audit.csv?item=db-password&range=30d")
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let csv = body_text(res).await;
    let lines: Vec<_> = csv.lines().collect();
    assert_eq!(lines.len(), 3, "header plus the two visible rows");
    assert_eq!(
        lines[1],
        "2026-11-09T10:00:00Z,alex@example.com,Viewed secret value,SecretGet,db-password,OK,203.0.113.5"
    );
    assert!(
        lines[2].contains(",'=cmd|"),
        "formula guarded: {}",
        lines[2]
    );
    assert!(!csv.contains("TOPSECRET"));
}

#[tokio::test]
async fn needs_a_vault() {
    let w = support::world().await;
    let id = w.cookie.split('=').nth(1).unwrap();
    let s = w.state.sessions.get(id).unwrap();
    let fresh = w.state.sessions.create(s.user.clone(), s.tokens());
    let mut w = w;
    w.cookie = format!("keyring_session={fresh}");
    let (_, html) = w.page("/audit").await;
    assert!(html.contains("Choose a vault first"));
}

#[tokio::test]
async fn item_history_links_back_to_the_item() {
    let w = support::world().await;
    setup(&w);
    let (_, html) = w
        .page("/v/kv-test/audit?item=db-password&range=30d&from=secret")
        .await;
    assert!(html.contains("href=\"/v/kv-test/secrets/db-password\">Back to db-password</a>"));
    let (_, html) = w
        .page("/v/kv-test/audit?item=db-password&range=30d&from=bogus")
        .await;
    assert!(!html.contains("Back to db-password"));
}

fn two_workspaces() -> serde_json::Value {
    let ws = |n: &str| {
        serde_json::json!({"properties": {
            "workspaceId": format!("/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/{n}"),
            "logAnalyticsDestinationType": "Dedicated",
            "logs": [{"categoryGroup": "audit", "enabled": true}]
        }})
    };
    serde_json::json!({"value": [ws("logs-a"), ws("logs-b")]})
}

#[tokio::test]
async fn workspaces_that_cannot_be_read_are_reported() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.diagnostics.lock().unwrap() = Some(two_workspaces());
    *w.arm.state.audit_rows.lock().unwrap() = vec![row(
        "2026-11-09T10:00:00Z",
        "alex@example.com",
        "SecretGet",
        "db-password",
        "OK",
    )];
    // One of two workspaces refuses: the other's events still show, with a notice.
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs-b".into(), 403)];
    let (status, html) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Viewed secret value"));
    assert!(
        html.contains("1 of 2 Log Analytics workspaces this vault logs to couldn&#39;t be read"),
        "{html}"
    );
    let csv = body_text(w.get("/v/kv-test/audit.csv").await).await;
    let lines: Vec<_> = csv.lines().collect();
    assert_eq!(lines.len(), 3, "{csv}");
    assert!(
        lines[2].starts_with("NOT READ,\"1 of 2 Log Analytics workspaces"),
        "{}",
        lines[2]
    );

    // A server error on one no longer fails the page.
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs-b".into(), 503)];
    let (status, html) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Viewed secret value"));
    assert!(html.contains("returned an error"));

    // Every workspace failing is still an error page.
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![
        ("/workspaces/logs-a".into(), 503),
        ("/workspaces/logs-b".into(), 503),
    ];
    let (status, _) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn csv_without_logs_is_not_an_empty_success() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.diagnostics.lock().unwrap() = Some(serde_json::json!({"value": []}));
    let res = w.get("/v/kv-test/audit.csv").await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let html = body_text(res).await;
    assert!(html.contains("sending its audit logs"));

    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    *w.arm.state.audit_forbidden.lock().unwrap() = true;
    let res = w.get("/v/kv-test/audit.csv").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Log Analytics Reader role"));
}

#[tokio::test]
async fn empty_result_reads_unknown_not_refused() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.audit_rows.lock().unwrap() = vec![row(
        "2026-11-09T10:00:00Z",
        "alex@example.com",
        "SecretGet",
        "db-password",
        "",
    )];
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(!html.contains("Refused ()"));
    assert!(html.contains("<span class=\"muted\">Unknown</span>"));
}

#[tokio::test]
async fn filter_form_keeps_the_way_back() {
    let w = support::world().await;
    setup(&w);
    let (_, html) = w
        .page("/v/kv-test/audit?item=db-password&range=30d&from=secret")
        .await;
    assert!(html.contains("<input type=\"hidden\" name=\"from\" value=\"secret\">"));
    let (_, html) = w.page("/v/kv-test/audit").await;
    assert!(!html.contains("name=\"from\""));
}

#[tokio::test]
async fn no_vault_page_has_its_own_words_for_audit() {
    let w = support::world().await;
    let id = w.cookie.split('=').nth(1).unwrap();
    let s = w.state.sessions.get(id).unwrap();
    let fresh = w.state.sessions.create(s.user.clone(), s.tokens());
    let mut w = w;
    w.cookie = format!("keyring_session={fresh}");
    let (_, html) = w.page("/audit").await;
    assert!(!html.contains("Secrets live in a vault"));
    assert!(html.contains("The audit view shows who used one vault"));
}

/// The session keeps one vault's ARM ID. Opening another vault's audit page
/// must look up that vault, not reuse the first one's.
#[tokio::test]
async fn each_vaults_audit_page_reads_its_own_settings() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![
        support::vault_row("kv-a", "sub-a", true),
        support::vault_row("kv-b", "sub-a", true),
    ];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let (status, _) = w.page("/v/kv-a/audit").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = w.page("/v/kv-b/audit").await;
    assert_eq!(status, StatusCode::OK);
    let paths = w.arm.state.diagnostics_paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(paths[0].contains("/vaults/kv-a/"), "{paths:?}");
    assert!(paths[1].contains("/vaults/kv-b/"), "{paths:?}");
    let queries = w.arm.state.audit_queries.lock().unwrap().clone();
    assert!(
        queries[0].contains("let vaultName = \"kv-a\";"),
        "{queries:?}"
    );
    assert!(
        queries[1].contains("let vaultName = \"kv-b\";"),
        "{queries:?}"
    );
    // Going back to the first reads its settings again, not the second's.
    let (status, _) = w.page("/v/kv-a/audit").await;
    assert_eq!(status, StatusCode::OK);
    let paths = w.arm.state.diagnostics_paths.lock().unwrap().clone();
    assert!(paths[2].contains("/vaults/kv-a/"), "{paths:?}");
}
