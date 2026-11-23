//! Defender alerts page and its CSV, and the Defender pieces of Home, against
//! mock Resource Graph rows shaped like Defender for Cloud's
//! `securityresources` table.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::body_text;

fn seed(w: &support::World) {
    *w.arm.state.vaults.lock().unwrap() = vec![
        support::vault_row("kv-prod", "sub-a", true),
        support::vault_row("kv-dev", "sub-b", true),
    ];
    *w.arm.state.subscriptions.lock().unwrap() = vec![
        json!({"id": "/subscriptions/sub-a", "subscriptionId": "sub-a", "name": "Prod"}),
        json!({"id": "/subscriptions/sub-b", "subscriptionId": "sub-b", "name": "Dev"}),
    ];
    *w.arm.state.defender_plans.lock().unwrap() = vec![
        support::defender_plan("sub-a", "Standard"),
        support::defender_plan("sub-b", "Free"),
    ];
    let mut evil = support::defender_alert("kv-prod", "sub-a", "Medium", "Active");
    evil["displayName"] = json!("<img src=x onerror=alert(1)> from 203.0.113.9");
    evil["compromisedEntity"] = json!("=HYPERLINK(\"http://evil\")");
    evil["alertUri"] = json!("javascript:alert(1)");
    evil["resourceIdentifiers"] = json!([]);
    *w.arm.state.defender_alerts.lock().unwrap() = vec![
        support::defender_alert("kv-prod", "sub-a", "High", "Active"),
        support::defender_alert("kv-prod", "sub-a", "Low", "Dismissed"),
        evil,
    ];
}

#[tokio::test]
async fn page_shows_coverage_and_open_alerts_as_plain_text() {
    let w = support::world().await;
    seed(&w);
    let (status, html) = w.page("/defender").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("href=\"/defender\" aria-current=\"page\">Defender alerts</a>"));
    // Coverage: on for Prod, off for Dev.
    assert!(html.contains("Defender for Key Vault is off on 1 subscription."));
    // Two open (the dismissed one is hidden by default), the high first.
    assert!(html.contains("2 open alerts: 1 high, 1 medium."));
    assert!(html.contains("<a href=\"/v/kv-prod/secrets\">kv-prod</a>"));
    assert!(html.contains("https://portal.azure.com/#blade/"));
    // Alert text is escaped, and only portal links are kept.
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&#60;img src=x onerror=alert(1)&#62;"));
    assert!(!html.contains("javascript:alert"));
    // The CSP-safe page has no inline styles.
    assert!(!html.contains(" style=\""));

    let (_, all) = w.page("/defender?status=all&severity=low").await;
    assert!(all.contains("Dismissed"));
    assert!(!all.contains(">High</span>"));

    // Every read went to Resource Graph as the person.
    let bearers = w.arm.state.bearers.lock().unwrap().clone();
    assert!(bearers.iter().all(|b| b.starts_with("Bearer obo:")));
}

#[tokio::test]
async fn without_security_reader_it_says_so_rather_than_none() {
    let w = support::world().await;
    seed(&w);
    *w.arm.state.defender_forbidden.lock().unwrap() = true;
    let (status, html) = w.page("/defender").await;
    let html = html.replace("&#39;", "'");
    assert_eq!(status, StatusCode::OK, "the vault list still loads");
    assert!(html.contains("Couldn't read Defender's alerts: You don't have Security Reader"));
    assert!(html.contains("This isn't the same as having none."));
    assert!(html.contains("Couldn't read the Defender plans"));

    let body = body_text(w.get("/defender.csv").await).await;
    assert!(
        body.contains(",,NOT READ,You don't have Security Reader"),
        "{body}"
    );
}

#[tokio::test]
async fn csv_guards_formulas_and_follows_the_filters() {
    let w = support::world().await;
    seed(&w);
    let res = w.get("/defender.csv").await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    assert_eq!(h["content-type"], "text/csv; charset=utf-8");
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .contains("keyring-defender-alerts.csv")
    );
    assert!(h["cache-control"].to_str().unwrap().contains("no-store"));
    let body = body_text(res).await;
    let lines: Vec<&str> = body.lines().collect();
    assert!(lines[0].starts_with("Time (UTC),Severity,Status,Alert,"));
    assert_eq!(lines.len(), 3, "two open alerts: {body}");
    assert!(body.contains(",High,Active,"));
    assert!(
        body.contains("\"'=HYPERLINK(\"\"http://evil\"\")\""),
        "{body}"
    );
    assert!(!body.contains("javascript:"));

    let body = body_text(w.get("/defender.csv?vault=kv-dev").await).await;
    assert_eq!(body.lines().count(), 1, "no alerts on kv-dev: {body}");
}

#[tokio::test]
async fn home_shows_defender_alerts_and_unprotected_vaults() {
    let w = support::world().await;
    seed(&w);
    let (status, html) = w.page("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<span class=\"kpi-label\">Defender alerts</span>"));
    assert!(html.contains("1 high · 1 vault(s) unprotected"));
    assert!(html.contains("Open Defender for Key Vault alerts"));
    assert!(html.contains("Expired &amp; &lt;= 30 days"));
}

#[tokio::test]
async fn an_empty_alert_list_without_a_plan_row_is_unknown_not_zero() {
    let w = support::world().await;
    seed(&w);
    // sub-b's plan row is gone, as when the person lacks Security Reader there.
    *w.arm.state.defender_plans.lock().unwrap() = vec![support::defender_plan("sub-a", "Standard")];
    let (_, html) = w.page("/").await;
    assert!(html.contains("1 unknown"), "Home says coverage is unknown");
    let (_, html) = w.page("/defender").await;
    let html = html.replace("&#39;", "'");
    assert!(html.contains("Keyring couldn't read Defender's plan for 1 subscription"));
    let (_, html) = w.page("/vault-health").await;
    let html = html.replace("&#39;", "'");
    assert!(html.contains(
        "kv-dev</span>, Defender for Key Vault: Couldn't tell whether Defender for Key Vault is on"
    ));
}
