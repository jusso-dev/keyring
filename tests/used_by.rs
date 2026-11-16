//! "Used by in the last 30 days" on item pages and the forms that change
//! them: advice from Key Vault's audit log, never a gate.

mod support;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use support::{RawEvent, body_text, location, settings_to, vault_row};

const EMPTY: &str = "No reads in the last 30 days, so nothing should break.";

/// kv-test logs to the workspace `logs`, resource-specific or not.
fn setup(w: &support::World, dedicated: bool, events: Vec<RawEvent>) {
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(settings_to("logs", dedicated));
    *w.arm.state.workspace_events.lock().unwrap() = vec![("/workspaces/logs".into(), events)];
}

fn read(time: &str, who: &str, item: &str) -> RawEvent {
    RawEvent::new("kv-test", time, who, "SecretGet", item, 200)
}

/// A person twice, a managed identity, an app, a refused read, another
/// secret and another vault.
fn secret_reads() -> Vec<RawEvent> {
    vec![
        read("2026-11-09T10:00:00Z", "alex@example.com", "db-password"),
        read("2026-11-10T10:00:00.5Z", "alex@example.com", "db-password"),
        read("2026-11-11T08:00:00Z", "", "db-password").by_app(
            "11111111-aaaa-4aaa-8aaa-111111111111",
            "22222222-bbbb-4bbb-8bbb-222222222222",
            true,
        ),
        read("2026-11-08T08:00:00Z", "", "db-password").by_app(
            "33333333-cccc-4ccc-8ccc-333333333333",
            "44444444-dddd-4ddd-8ddd-444444444444",
            false,
        ),
        RawEvent::new(
            "kv-test",
            "2026-11-12T08:00:00Z",
            "eve@example.com",
            "SecretGet",
            "db-password",
            403,
        ),
        read("2026-11-12T08:00:00Z", "sam@example.com", "api-token"),
        RawEvent::new(
            "kv-other",
            "2026-11-12T08:00:00Z",
            "kim@example.com",
            "SecretGet",
            "db-password",
            200,
        ),
    ]
}

fn panel(html: &str) -> &str {
    let start = html
        .find("Used by in the last 30 days")
        .expect("the page has the panel");
    &html[start..]
}

fn check_secret_panel(html: &str) {
    let p = panel(html);
    assert!(p.contains("alex@example.com"));
    assert!(p.contains("Person"));
    assert!(p.contains("Managed identity"));
    assert!(p.contains("11111111-aaaa-4aaa-8aaa-111111111111"));
    assert!(p.contains("22222222-bbbb-4bbb-8bbb-222222222222"));
    assert!(p.contains(">App<"));
    assert!(p.contains("33333333-cccc-4ccc-8ccc-333333333333"));
    assert!(
        p.contains("2026-11-10 10:00:00 UTC"),
        "latest read, plainly"
    );
    assert!(p.contains("<td>2</td>"), "alex read it twice");
    assert!(p.contains("203.0.113.5") && p.contains("10.0.0.4"));
    assert!(p.contains("azsdk-net-Security.KeyVault.Secrets/4.6.0"));
    // Refused reads, other secrets and other vaults don't count.
    assert!(!p.contains("eve@example.com"));
    assert!(!p.contains("sam@example.com"));
    assert!(!p.contains("kim@example.com"));
    // Most recent first.
    assert!(p.find("11111111-aaaa").unwrap() < p.find("alex@example.com").unwrap());
}

#[tokio::test]
async fn secret_page_lists_who_read_it_from_azkvauditlogs() {
    let w = support::world().await;
    w.kv.state.put("db-password", "v");
    setup(&w, true, secret_reads());
    let (status, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    check_secret_panel(&html);
    // One query, as the person, with the names only in let lines.
    let queries = w.arm.state.audit_queries.lock().unwrap().clone();
    assert_eq!(queries.len(), 1);
    let q = &queries[0];
    assert!(q.starts_with("let vaultName = \"kv-test\";\nlet itemName = \"db-password\";\n"));
    assert!(q.contains("AZKVAuditLogs"));
    assert!(q.contains("| summarize Reads = count(), LastRead = max(TimeGenerated)"));
    let bearers = w.arm.state.audit_bearers.lock().unwrap().clone();
    assert!(bearers[0].starts_with("Bearer obo:https://api.loganalytics.io/.default"));
    // Reading the log reads no secret value.
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn secret_page_lists_who_read_it_from_azurediagnostics() {
    let w = support::world().await;
    w.kv.state.put("db-password", "v");
    setup(&w, false, secret_reads());
    let (status, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    check_secret_panel(&html);
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("AzureDiagnostics"));
    assert!(q.contains("identity_claim_appid_g") && q.contains("clientInfo_s"));
}

#[tokio::test]
async fn nothing_read_says_nothing_should_break() {
    let w = support::world().await;
    w.kv.state.put("quiet", "v");
    setup(&w, true, secret_reads());
    let (status, html) = w.page("/v/kv-test/secrets/quiet").await;
    assert_eq!(status, StatusCode::OK);
    assert!(panel(&html).contains(EMPTY));
}

#[tokio::test]
async fn every_change_form_shows_the_panel() {
    let w = support::world().await;
    let v1 = w.kv.state.put("db-password", "one");
    w.kv.state.put("db-password", "two");
    setup(&w, true, secret_reads());
    for path in [
        "/v/kv-test/secrets/db-password/value".to_owned(),
        format!("/v/kv-test/secrets/db-password/rollback?version={v1}"),
        "/v/kv-test/secrets/db-password/disable".to_owned(),
        "/v/kv-test/secrets/db-password/delete".to_owned(),
    ] {
        let (status, html) = w.page(&path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        check_secret_panel(&html);
        // The form itself is all there, above the panel.
        let form = html.find("<form method=\"post\"").expect(&path);
        assert!(
            form < html.find("Used by in the last 30 days").unwrap(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_forbidden_workspace_says_why_and_the_change_still_goes_ahead() {
    let w = support::world().await;
    w.kv.state.put("db-password", "one");
    setup(&w, true, secret_reads());
    *w.arm.state.audit_forbidden.lock().unwrap() = true;
    let (status, html) = w.page("/v/kv-test/secrets/db-password/value").await;
    assert_eq!(status, StatusCode::OK);
    let p = panel(&html);
    assert!(p.contains("You don&#39;t have access to the Log Analytics workspace"));
    assert!(p.contains("You can still go ahead."));
    assert!(p.contains("Log Analytics Reader"));
    // The form posts as normal.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[("value", "three"), ("content_type", "")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/secrets/db-password");
    assert_eq!(w.kv.state.version_count("db-password"), 2);
}

#[tokio::test]
async fn no_diagnostic_setting_or_no_reader_says_so() {
    let w = support::world().await;
    w.kv.state.put("db-password", "one");
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(serde_json::json!({"value": []}));
    let (status, html) = w.page("/v/kv-test/secrets/db-password/delete").await;
    assert_eq!(status, StatusCode::OK);
    assert!(panel(&html).contains("doesn&#39;t send its audit log to a Log Analytics workspace"));
    assert!(panel(&html).contains("diagnostic setting"));
    assert!(w.arm.state.audit_queries.lock().unwrap().is_empty());

    *w.arm.state.diagnostics.lock().unwrap() = None;
    let (status, html) = w.page("/v/kv-test/secrets/db-password/disable").await;
    assert_eq!(status, StatusCode::OK);
    assert!(panel(&html).contains("diagnostic settings"));
    assert!(panel(&html).contains("Reader role"));
}

#[tokio::test]
async fn one_workspace_of_two_failing_still_shows_the_rest() {
    let w = support::world().await;
    w.kv.state.put("db-password", "one");
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    let mut both = settings_to("logs", true);
    both["value"]
        .as_array_mut()
        .unwrap()
        .push(settings_to("logs-b", false)["value"][0].clone());
    *w.arm.state.diagnostics.lock().unwrap() = Some(both);
    *w.arm.state.workspace_events.lock().unwrap() =
        vec![("/workspaces/logs".into(), secret_reads())];
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs-b".into(), 500)];
    let (status, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    let p = panel(&html);
    assert!(p.contains("alex@example.com"));
    assert!(p.contains("1 of 2 Log Analytics workspaces this vault logs to couldn&#39;t be read"));
}

#[tokio::test]
async fn a_slow_workspace_never_holds_up_the_form() {
    let w = support::world().await;
    w.kv.state.put("db-password", "one");
    setup(&w, true, secret_reads());
    *w.arm.state.workspace_delay.lock().unwrap() =
        vec![("/workspaces/logs".into(), Duration::from_secs(30))];
    let started = Instant::now();
    let (status, html) = w.page("/v/kv-test/secrets/db-password/value").await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "stopped waiting at the panel's own limit"
    );
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("name=\"value\""), "the form is there");
    assert!(panel(&html).contains("didn&#39;t answer within 5 seconds"));
}

#[tokio::test]
async fn keys_count_cryptographic_operations() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let op = |time: &str, op: &str, status: u16| {
        RawEvent::new("kv-test", time, "", op, "app-key", status).by_app(
            "55555555-eeee-4eee-8eee-555555555555",
            "66666666-ffff-4fff-8fff-666666666666",
            true,
        )
    };
    setup(
        &w,
        false,
        vec![
            op("2026-11-09T10:00:00Z", "KeySign", 200),
            op("2026-11-09T11:00:00Z", "KeyWrap", 200),
            op("2026-11-09T12:00:00Z", "KeyDecrypt", 200),
            op("2026-11-09T13:00:00Z", "KeyGet", 200),
            op("2026-11-09T14:00:00Z", "KeyUnwrap", 403),
        ],
    );
    for path in [
        "/v/kv-test/keys/app-key",
        "/v/kv-test/keys/app-key/rotate",
        "/v/kv-test/keys/app-key/disable",
        "/v/kv-test/keys/app-key/delete",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let p = panel(&html);
        assert!(p.contains("55555555-eeee-4eee-8eee-555555555555"), "{path}");
        assert!(p.contains("Managed identity"), "{path}");
        // Sign, wrap and decrypt: not the read of the key, not the refusal.
        assert!(p.contains("<td>3</td>"), "{path}");
        assert!(p.contains("2026-11-09 12:00:00 UTC"), "{path}");
    }
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("'KeySign'") && q.contains("'KeyWrap'") && q.contains("'KeyDecrypt'"));
}

#[tokio::test]
async fn certificates_count_reads_of_the_backing_secret() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "pfx");
    setup(
        &w,
        true,
        vec![
            read("2026-11-09T10:00:00Z", "alex@example.com", "web-tls"),
            RawEvent::new(
                "kv-test",
                "2026-11-09T11:00:00Z",
                "sam@example.com",
                "CertificateGet",
                "web-tls",
                200,
            ),
        ],
    );
    for path in [
        "/v/kv-test/certificates/web-tls",
        "/v/kv-test/certificates/web-tls/disable",
        "/v/kv-test/certificates/web-tls/delete",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let p = panel(&html);
        assert!(p.contains("alex@example.com"), "{path}");
        assert!(p.contains("backing secret"), "{path}");
        assert!(!p.contains("sam@example.com"), "{path}");
    }
}

#[tokio::test]
async fn a_name_that_tries_to_change_the_query_never_reaches_it() {
    let w = support::world().await;
    setup(&w, true, Vec::new());
    for name in ["x%22%20or%201%3D%3D1", "x%27", "x%5C", "x%0Ab"] {
        let res = w.get(&format!("/v/kv-test/secrets/{name}/value")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{name}");
        let _ = body_text(res).await;
    }
    assert!(w.arm.state.audit_queries.lock().unwrap().is_empty());
}
