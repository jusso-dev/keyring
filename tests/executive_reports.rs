//! Home screen org-wide charts & widgets, plus continuous white-label
//! executive client reports (HTML/PDF pack, CSV and JSON).

mod support;

use axum::http::StatusCode;
use serde_json::json;

fn tagged_vault(
    name: &str,
    env: &str,
    purge: bool,
    net_deny: bool,
    owned: bool,
) -> serde_json::Value {
    let mut row = support::vault_row(name, "sub-exec", true);
    let mut tags = serde_json::Map::new();
    tags.insert("app".into(), json!("payments"));
    tags.insert("env".into(), json!(env));
    if owned {
        tags.insert("keyring-owners".into(), json!("secops@contoso.com"));
    }
    row["tags"] = serde_json::Value::Object(tags);
    row["enablePurgeProtection"] = json!(purge);
    row["publicNetworkAccess"] = json!(if net_deny { "Disabled" } else { "Enabled" });
    row["networkDefaultAction"] = json!(if net_deny { "Deny" } else { "Allow" });
    row["privateEndpointConnections"] = if net_deny {
        json!([{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}])
    } else {
        json!([])
    };
    row
}

#[tokio::test]
async fn home_shows_org_wide_kpis_charts_and_never_leaks_secret_values() {
    let dev = std::sync::Arc::new(support::keyvault::KvState::default());
    let prod = std::sync::Arc::new(support::keyvault::KvState::default());
    let w = support::world_of_vaults_with(
        vec![
            ("kv-payments-dev", dev.clone()),
            ("kv-payments-prod", prod.clone()),
        ],
        &[],
    )
    .await;
    *w.arm.state.vaults.lock().unwrap() = vec![
        tagged_vault("kv-payments-dev", "dev", false, false, false),
        tagged_vault("kv-payments-prod", "prod", true, true, true),
    ];
    let now = keyring::azure::secrets::now_ts();
    let day = 86_400;
    prod.put_with("db-conn", "SUPER-SECRET-PROD-VAL", |v| {
        v.exp = Some(now - 2 * day);
    });
    dev.put_with("api-key", "SUPER-SECRET-DEV-VAL", |v| {
        v.exp = Some(now + 120 * day);
    });
    prod.add_cert("web-tls", true, "CERT");
    prod.add_key_with("signing-key", "RSA", |_| {});

    let (status, html) = w.page("/").await;
    assert_eq!(status, StatusCode::OK);
    // Executive KPI strip, 4 SVG charts and watchlist render with zero inline styles.
    assert!(html.contains("Security posture"), "{html}");
    assert!(html.contains("Credential health &amp; lifecycle"));
    assert!(html.contains("Security posture controls"));
    assert!(html.contains("Expiry &amp; renewal horizon"));
    assert!(html.contains("Estate by environment"));
    assert!(html.contains("Vault risk &amp; compliance watchlist"));
    assert!(html.contains("Export executive report"));
    assert!(
        !html.contains(" style=\""),
        "CSP forbids inline style attrs"
    );
    // Secret values are NEVER read or rendered.
    assert!(!html.contains("SUPER-SECRET-PROD-VAL"));
    assert!(!html.contains("SUPER-SECRET-DEV-VAL"));
    assert!(prod.value_reads().is_empty());
    assert!(dev.value_reads().is_empty());
}

#[tokio::test]
async fn continuous_white_label_executive_reports_export_html_csv_and_json() {
    let dev = std::sync::Arc::new(support::keyvault::KvState::default());
    let prod = std::sync::Arc::new(support::keyvault::KvState::default());
    let w = support::world_of_vaults_with(
        vec![
            ("kv-payments-dev", dev.clone()),
            ("kv-payments-prod", prod.clone()),
        ],
        &[],
    )
    .await;
    *w.arm.state.vaults.lock().unwrap() = vec![
        tagged_vault("kv-payments-dev", "dev", false, false, false),
        tagged_vault("kv-payments-prod", "prod", true, true, true),
    ];
    prod.put("prod-secret", "NEVER-LEAK-IN-REPORT");

    let qs = "submitted=1&client=Contoso+Bank&title=Q4+Board+Security+Brief&prepared_by=Meridian+Advisory&period=Q4+2026&theme=emerald&scope=all&white_label=1&charts=1&vaults=1&envs=1&actions=1";

    // 1. Report builder & live preview page
    let (status, page_html) = w.page(&format!("/reports/executive?{qs}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page_html.contains("Contoso Bank"));
    assert!(page_html.contains("Q4 Board Security Brief"));
    assert!(page_html.contains("Meridian Advisory"));
    assert!(page_html.contains("Continuous reporting URL"));
    assert!(!page_html.contains(" style=\""));
    assert!(!page_html.contains("NEVER-LEAK-IN-REPORT"));

    // 2. White-label HTML / printable PDF export hides Keyring brand & includes SVG charts
    let res = w
        .get(&format!("/reports/executive/export?{qs}&format=html"))
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
    let disp = res
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        disp.contains("contoso-bank-executive-report.html"),
        "{disp}"
    );
    let export_html = support::body_text(res).await;
    assert!(export_html.contains("Contoso Bank"));
    assert!(export_html.contains("Meridian Advisory"));
    assert!(export_html.contains("Q4 Board Security Brief"));
    assert!(export_html.contains("#0f764a"), "emerald theme applied");
    assert!(
        !export_html.contains("Keyring Privileged Access"),
        "white-label hides Keyring issuer"
    );
    assert!(!export_html.contains("NEVER-LEAK-IN-REPORT"));

    // 3. Executive CSV export
    let res = w
        .get(&format!("/reports/executive/export?{qs}&format=csv"))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let csv = support::body_text(res).await;
    assert!(csv.contains("Contoso Bank"));
    assert!(csv.contains("kv-payments-prod"));
    assert!(!csv.contains("NEVER-LEAK-IN-REPORT"));

    // 4. Structured JSON snapshot for continuous BI automation
    let res = w
        .get(&format!("/reports/executive/export?{qs}&format=json"))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = support::body_text(res).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["branding"]["client_name"], "Contoso Bank");
    assert_eq!(parsed["branding"]["white_label"], true);
    assert_eq!(parsed["snapshot"]["total_vaults"], 2);
    assert!(!body.contains("NEVER-LEAK-IN-REPORT"));

    // 5. Production-only scope filters out dev vault
    let res = w
        .get("/reports/executive/export?scope=prod&format=json")
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let prod_json: serde_json::Value =
        serde_json::from_str(&support::body_text(res).await).expect("valid JSON");
    assert_eq!(prod_json["snapshot"]["total_vaults"], 1);
    assert_eq!(
        prod_json["snapshot"]["vault_rows"][0]["name"],
        "kv-payments-prod"
    );
}
