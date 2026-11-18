//! Audit across vaults: the fixed reports at `/audit`.

mod support;

use axum::http::StatusCode;
use support::{RawEvent, body_text, location, settings_to, vault_row};

/// kv-a and kv-b log to `shared` (AZKVAuditLogs), kv-c to `own`
/// (AzureDiagnostics), kv-quiet logs nowhere.
fn setup(w: &support::World) {
    *w.arm.state.vaults.lock().unwrap() = ["kv-a", "kv-b", "kv-c", "kv-quiet"]
        .iter()
        .map(|n| vault_row(n, "sub-a", true))
        .collect();
    *w.arm.state.diagnostics.lock().unwrap() = Some(serde_json::json!({"value": []}));
    *w.arm.state.diagnostics_for.lock().unwrap() = vec![
        ("kv-a".into(), Some(settings_to("shared", true))),
        ("kv-b".into(), Some(settings_to("shared", true))),
        ("kv-c".into(), Some(settings_to("own", false))),
    ];
    let shared = vec![
        RawEvent::new(
            "kv-a",
            "2026-11-09T10:00:00Z",
            "alex@example.com",
            "SecretGet",
            "db-password",
            200,
        ),
        RawEvent::new(
            "kv-b",
            "2026-11-09T11:00:00Z",
            "sam@example.com",
            "SecretGet",
            "api-token",
            200,
        ),
        RawEvent::new(
            "kv-b",
            "2026-11-09T11:05:00Z",
            "sam@example.com",
            "SecretGet",
            "web-tls",
            200,
        ),
        RawEvent::new(
            "kv-b",
            "2026-11-09T11:04:00Z",
            "sam@example.com",
            "CertificateGet",
            "web-tls",
            200,
        ),
        RawEvent::new(
            "kv-a",
            "2026-11-09T12:00:00Z",
            "eve@example.com",
            "SecretGet",
            "db-password",
            403,
        ),
        RawEvent::new(
            "kv-a",
            "2026-11-09T12:01:00Z",
            "eve@example.com",
            "SecretList",
            "",
            403,
        ),
        RawEvent::new(
            "kv-a",
            "2026-11-09T09:00:00Z",
            "alex@example.com",
            "SecretPurge",
            "old",
            200,
        ),
        // A vault not in this person's list: never in a query, never shown.
        RawEvent::new(
            "kv-hidden",
            "2026-11-09T13:00:00Z",
            "alex@example.com",
            "SecretGet",
            "x",
            200,
        ),
    ];
    let own = vec![
        RawEvent::new(
            "kv-c",
            "2026-11-09T08:00:00Z",
            "alex@example.com",
            "KeyDelete",
            "app-key",
            200,
        ),
        RawEvent::new(
            "kv-c",
            "2026-11-09T08:30:00Z",
            "alex@example.com",
            "SecretGet",
            "=cmd",
            200,
        ),
    ];
    *w.arm.state.workspace_events.lock().unwrap() = vec![
        ("/workspaces/shared".into(), shared),
        ("/workspaces/own".into(), own),
    ];
}

#[tokio::test]
async fn vaults_sharing_a_workspace_are_one_query() {
    let w = support::world().await;
    setup(&w);
    let (status, html) = w.page("/audit?report=reads&range=7d").await;
    assert_eq!(status, StatusCode::OK, "{html}");
    let paths = w.arm.state.audit_paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 2, "one query per workspace: {paths:?}");
    let queries = w.arm.state.audit_queries.lock().unwrap().clone();
    let shared = queries
        .iter()
        .find(|q| q.contains("AZKVAuditLogs"))
        .expect("shared workspace query");
    assert!(shared.contains("/vaults/kv-a\";"));
    assert!(shared.contains("/vaults/kv-b\";"));
    assert!(shared.contains("_ResourceId in~ (vault0, vault1)"));
    let own = queries
        .iter()
        .find(|q| q.contains("AzureDiagnostics"))
        .expect("own workspace query");
    assert!(own.contains("/vaults/kv-c\";") && !own.contains("kv-a"));
    // Rows from both workspaces, newest first, each linking to its vault.
    assert!(html.contains("api-token") && html.contains("db-password"));
    assert!(html.find("api-token").unwrap() < html.find("db-password").unwrap());
    assert!(html.contains("href=\"/v/kv-a/audit?range=7d&#38;item=db-password&#38;from=secret\""));
    assert!(!html.contains("kv-hidden"));
    assert!(html.contains("Covers 3 vaults through 2 Log Analytics workspaces."));
    // Read as the person, with the Log Analytics and ARM OBO tokens.
    for b in w.arm.state.audit_bearers.lock().unwrap().iter() {
        assert!(
            b.starts_with("Bearer obo:https://api.loganalytics.io/.default"),
            "{b}"
        );
    }
    let diag = w.arm.state.diagnostics_paths.lock().unwrap().len();
    assert_eq!(diag, 4, "each vault's settings read once");
}

#[tokio::test]
async fn a_vault_with_no_diagnostics_is_listed() {
    let w = support::world().await;
    setup(&w);
    let (_, html) = w.page("/audit?report=reads").await;
    assert!(
        html.contains("1 vault doesn't send audit logs to Log Analytics"),
        "{html}"
    );
    assert!(html.contains("kv-quiet"));
    let csv = body_text(w.get("/audit.csv?report=reads&range=7d").await).await;
    assert!(
        csv.contains("kv-quiet,NOT READ,Doesn't send its audit logs to a Log Analytics workspace"),
        "{csv}"
    );
}

#[tokio::test]
async fn a_forbidden_workspace_is_listed_and_the_rest_still_show() {
    let w = support::world().await;
    setup(&w);
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/own".into(), 403)];
    let (status, html) = w.page("/audit?report=reads").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("api-token"), "shared workspace still read");
    assert!(html.contains("Some Log Analytics workspaces couldn't be read"));
    assert!(html.contains(
        "<span class=\"item-name\">own</span> (for <span class=\"item-name\">kv-c</span>): You don&#39;t have the Log Analytics Reader role on it."
    ), "{html}");
    let csv = body_text(w.get("/audit.csv?report=reads").await).await;
    assert!(
        csv.contains(
            "kv-c,NOT READ,Workspace own: You don't have the Log Analytics Reader role on it"
        ),
        "{csv}"
    );
    // Settings that can't be read are listed too.
    w.arm.state.diagnostics_for.lock().unwrap()[0].1 = None;
    let (_, html) = w.page("/audit?report=reads").await;
    assert!(html.contains("couldn't find where these vaults send their logs"));
    assert!(html.contains(
        "<span class=\"item-name\">kv-a</span>: You can&#39;t see where it sends its logs."
    ));
}

#[tokio::test]
async fn each_report_returns_its_rows_on_both_tables() {
    for dedicated in [true, false] {
        let w = support::world().await;
        setup(&w);
        // Put kv-a and kv-b on the chosen table.
        for (_, s) in w
            .arm
            .state
            .diagnostics_for
            .lock()
            .unwrap()
            .iter_mut()
            .take(2)
        {
            *s = Some(settings_to("shared", dedicated));
        }
        let table = if dedicated {
            "AZKVAuditLogs"
        } else {
            "AzureDiagnostics"
        };

        let (_, html) = w.page("/audit?report=reads&range=7d").await;
        assert!(
            html.contains("api-token") && html.contains("web-tls"),
            "{table}"
        );
        assert!(
            !html.contains("Refused (403 Forbidden)"),
            "{table}: only allowed reads"
        );

        let (_, html) = w.page("/audit?report=private-keys&range=30d").await;
        assert!(html.contains("web-tls"), "{table}: {html}");
        assert!(!html.contains("api-token"), "{table}: not a certificate");

        let (_, html) = w.page("/audit?report=deletes&range=30d").await;
        assert!(html.contains("Permanently deleted secret"), "{table}");
        assert!(html.contains("Deleted key"), "{table}");
        assert!(!html.contains("api-token"), "{table}");

        let (_, html) = w.page("/audit?report=refused&range=7d").await;
        assert!(html.contains("eve@example.com"), "{table}");
        assert!(
            html.contains("<span class=\"badge badge-error\">2</span>"),
            "{table}: {html}"
        );
        assert!(html.contains("SecretGet, SecretList"), "{table}");
        assert!(html.contains("href=\"/v/kv-a/audit?range=7d&#38;person=eve%40example.com\""));

        let (_, html) = w
            .page("/audit?report=person&range=7d&person=sam%40example")
            .await;
        assert!(
            html.contains("api-token") && !html.contains("db-password"),
            "{table}"
        );

        let queries = w.arm.state.audit_queries.lock().unwrap().clone();
        assert!(
            queries
                .iter()
                .filter(|q| q.contains("/vaults/kv-a\";"))
                .all(|q| q.contains(table)),
            "{table}"
        );
    }
}

#[tokio::test]
async fn the_person_filter_is_checked_before_any_query() {
    let w = support::world().await;
    setup(&w);
    let (status, html) = w.page("/audit?report=person").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Enter part of a person"));
    for bad in [
        "/audit?report=person&person=a%22%3B%20AzureActivity",
        "/audit?report=person&person=x%22%20%7C%20union%20*",
    ] {
        let (status, html) = w.page(bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert!(html.contains("<a href=\"#person\">"));
        let res = w.get(&bad.replace("/audit?", "/audit.csv?")).await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(
        w.arm.state.audit_queries.lock().unwrap().is_empty(),
        "bad filters never reach Log Analytics"
    );
    // A good one goes in as a let literal only.
    w.page("/audit?report=person&person=sam%40example.com")
        .await;
    let q = w.arm.state.audit_queries.lock().unwrap()[0].clone();
    assert!(q.contains("let who = \"sam@example.com\";"));
    assert_eq!(q.matches("sam@example.com").count(), 1);
}

#[tokio::test]
async fn csv_has_the_vault_and_guards_formulas() {
    let w = support::world().await;
    setup(&w);
    let res = w.get("/audit.csv?report=reads&range=7d").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/csv; charset=utf-8");
    assert!(
        res.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("keyring-audit-reads.csv")
    );
    assert!(
        res.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let csv = body_text(res).await;
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "Vault,Time (UTC),Who,Action,Operation,Item,Outcome,Result,Client IP"
    );
    assert!(lines.iter().any(|l| l.starts_with("kv-b,2026-11-09 11:00:00 UTC,sam@example.com,Viewed secret value,SecretGet,api-token,Allowed,200 OK")), "{csv}");
    assert!(csv.contains(",'=cmd,"), "formula guarded: {csv}");

    let csv = body_text(w.get("/audit.csv?report=refused").await).await;
    assert!(csv.starts_with("Vault,Who,Refused,Last refused (UTC),Operations\r\n"));
    assert!(
        csv.contains("kv-a,eve@example.com,2,2026-11-09 12:01:00 UTC,\"SecretGet, SecretList\""),
        "{csv}"
    );
}

#[tokio::test]
async fn the_page_lists_the_reports_as_fixed_links() {
    let w = support::world().await;
    setup(&w);
    let (status, html) = w.page("/audit").await;
    assert_eq!(status, StatusCode::OK);
    for (slug, range) in [
        ("reads", "7d"),
        ("private-keys", "30d"),
        ("deletes", "30d"),
        ("refused", "7d"),
        ("person", "7d"),
    ] {
        assert!(
            html.contains(&format!("href=\"/audit?report={slug}&amp;range={range}\"")),
            "{slug}"
        );
    }
    assert!(html.contains("Pick a report"));
    assert!(
        w.arm.state.audit_queries.lock().unwrap().is_empty(),
        "nothing is read until a report is picked"
    );
    // The side nav's Audit is current here.
    assert!(html.contains("aria-current=\"page\">Audit</a>"));
}

#[tokio::test]
async fn old_per_vault_addresses_still_go_to_the_last_vault() {
    let w = support::world().await;
    for (old, new) in [
        (
            "/audit?item=db&from=secret",
            "/v/kv-test/audit?item=db&from=secret",
        ),
        (
            "/audit?range=7d&operation=SecretGet",
            "/v/kv-test/audit?range=7d&operation=SecretGet",
        ),
        ("/audit.csv", "/v/kv-test/audit.csv"),
        ("/audit.csv?item=db", "/v/kv-test/audit.csv?item=db"),
    ] {
        let res = w.get(old).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }
}

#[tokio::test]
async fn too_many_rows_are_capped_with_a_note() {
    let w = support::world().await;
    setup(&w);
    let many: Vec<RawEvent> = (0..520)
        .map(|i| {
            RawEvent::new(
                "kv-a",
                &format!("2026-11-09T10:{:02}:{:02}Z", i / 60, i % 60),
                "alex@example.com",
                "SecretGet",
                "db-password",
                200,
            )
        })
        .collect();
    w.arm.state.workspace_events.lock().unwrap()[0].1 = many;
    let (_, html) = w.page("/audit?report=reads").await;
    assert!(html.contains("Showing the first 500 rows"));
    assert_eq!(html.matches("<td class=\"cell-time\">").count(), 500);
    let csv = body_text(w.get("/audit.csv?report=reads").await).await;
    assert!(csv.contains("NOT READ,Only the first 500 rows are included"));
}

#[tokio::test]
async fn a_slow_workspace_is_listed_and_the_rest_still_show() {
    let w = support::world_within(keyring::azure::fanout::Limits {
        concurrency: 6,
        vault_timeout: std::time::Duration::from_millis(400),
        deadline: std::time::Duration::from_secs(4),
    })
    .await;
    setup(&w);
    *w.arm.state.workspace_delay.lock().unwrap() =
        vec![("/workspaces/own".into(), std::time::Duration::from_secs(5))];
    let started = std::time::Instant::now();
    let (status, html) = w.page("/audit?report=reads").await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "per-workspace limit"
    );
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("api-token"), "shared workspace still read");
    assert!(
        html.contains("<span class=\"item-name\">own</span> (for <span class=\"item-name\">kv-c</span>): Took too long to answer."),
        "{html}"
    );
}

/// A 202 Accepted is allowed in every report, never counted as refused; a
/// 401 is refused; a 429 is a failure, not a refusal.
#[tokio::test]
async fn reports_use_the_same_outcome_rule() {
    let w = support::world().await;
    setup(&w);
    let extra = [
        ("2026-11-09T13:00:00Z", "SecretGet", "queued", 202),
        ("2026-11-09T13:01:00Z", "CertificateCreate", "queued", 202),
        ("2026-11-09T13:02:00Z", "SecretGet", "nope", 401),
        ("2026-11-09T13:03:00Z", "SecretGet", "busy", 429),
    ];
    w.arm.state.workspace_events.lock().unwrap()[0].1.extend(
        extra
            .iter()
            .map(|(t, op, item, s)| RawEvent::new("kv-a", t, "kim@example.com", op, item, *s)),
    );

    let (_, html) = w.page("/audit?report=person&person=kim&range=7d").await;
    assert!(
        html.contains("<span class=\"result-ok\">Accepted</span> <span class=\"muted small\">(202 Accepted)</span>"),
        "{html}"
    );
    assert!(html.contains("<span class=\"badge badge-error\">Refused (401 Unauthorized)</span>"));
    assert!(html.contains("<span class=\"badge badge-muted\">Failed (429 TooManyRequests)</span>"));
    assert!(!html.contains("Refused (202"));
    let csv = body_text(w.get("/audit.csv?report=person&person=kim&range=7d").await).await;
    assert!(
        csv.contains(",CertificateCreate,queued,Accepted,202 Accepted,"),
        "{csv}"
    );
    assert!(csv.contains(",nope,Refused,401 Unauthorized,"), "{csv}");
    assert!(csv.contains(",busy,Failed,429 TooManyRequests,"), "{csv}");

    let (_, html) = w.page("/audit?report=reads&range=7d").await;
    assert!(html.contains("queued"), "an accepted read is a read");
    assert!(!html.contains("busy") && !html.contains(">nope<"));

    let csv = body_text(w.get("/audit.csv?report=refused&range=7d").await).await;
    assert!(
        csv.contains("kv-a,kim@example.com,1,"),
        "only the 401: {csv}"
    );
    // The KQL the reports send counts by the shared rule.
    let q = w.arm.state.audit_queries.lock().unwrap().clone();
    assert!(
        q.iter().any(|k| k.contains("| where Outcome == 'refused'")
            && k.contains("ResultCode in (401, 403)")),
        "{q:?}"
    );
}
