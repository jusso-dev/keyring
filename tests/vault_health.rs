//! Vault health page and its CSV, against mock Resource Graph, ARM and
//! Key Vault. Each check is driven to pass, warn and unknown.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::body_text;

/// A vault row with every health setting on.
fn healthy(name: &str) -> serde_json::Value {
    let mut v = support::vault_row(name, "sub-a", true);
    v["tags"] = json!({"env": "prod", "keyring-owners": "ops@example.com, Platform team"});
    v["enablePurgeProtection"] = json!(true);
    v["publicNetworkAccess"] = json!("Disabled");
    v["networkDefaultAction"] = json!("Deny");
    v["privateEndpointConnections"] = json!([{
        "id": "/pe",
        "properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}
    }]);
    v
}

/// The cells of one vault's row, as (check, status) in order.
fn row_statuses(html: &str, vault: &str) -> Vec<String> {
    let start = html
        .find(&format!(
            "<th scope=\"row\" class=\"item-name\">{vault}</th>"
        ))
        .unwrap_or_else(|| panic!("no row for {vault}"));
    let row = &html[start..];
    let row = &row[..row.find("</tr>").unwrap()];
    row.split("<td>")
        .skip(1)
        .map(|cell| {
            if cell.contains("Pick this vault") {
                "Deferred".to_owned()
            } else {
                let after = cell.split("\">").nth(1).unwrap_or_default();
                after.split('<').next().unwrap_or_default().to_owned()
            }
        })
        .collect()
}

const CHECKS: usize = 10;

/// The page with apostrophes unescaped, so assertions read as the text.
async fn page(w: &support::World, path: &str) -> (StatusCode, String) {
    let (status, html) = w.page(path).await;
    (status, html.replace("&#39;", "'"))
}

fn seed_content(w: &support::World, healthy_content: bool) {
    let n = keyring::azure::secrets::now_ts();
    if healthy_content {
        w.kv.state
            .put_with("db-password", "VALUE-1", |v| v.exp = Some(n + 86_400 * 30));
    } else {
        w.kv.state.put("db-password", "VALUE-1");
    }
    let mut policy = support::certs::default_policy(false, false);
    if !healthy_content {
        policy["lifetime_actions"] = json!([{
            "trigger": {"days_before_expiry": 30}, "action": {"action_type": "EmailContacts"}
        }]);
    }
    w.kv.state.add_cert_version(
        "web-tls",
        support::pem_first_cert(support::TEST_CERT_PEM),
        policy,
        |_| {},
    );
    w.kv.state.add_key_with("signer", "RSA", |_| {});
    if healthy_content {
        w.kv.state
            .keys
            .lock()
            .unwrap()
            .get_mut("signer")
            .unwrap()
            .rotation = json!({
            "lifetimeActions": [{"trigger": {"timeAfterCreate": "P90D"}, "action": {"type": "Rotate"}}],
            "attributes": {"expiryTime": "P1Y"}
        });
    }
}

#[tokio::test]
async fn every_check_passes_on_a_well_set_vault() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![healthy("kv-test")];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    seed_content(&w, true);
    let (status, html) = page(&w, "/vault-health?vault=kv-test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_statuses(&html, "kv-test"), vec!["Pass"; CHECKS]);
    assert!(html.contains("0 warnings and 0 checks Keyring couldn't read"));
    assert!(!html.contains("What to look at"));
    assert!(!html.contains("VALUE-"), "never values");
    assert!(w.kv.state.value_reads().is_empty(), "no value reads");
    // The one-vault view made a call per certificate and per key.
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|l| l == "GET /kv-test/certificates/web-tls/policy")
    );
    assert!(
        log.iter()
            .any(|l| l == "GET /kv-test/keys/signer/rotationpolicy")
    );
}

#[tokio::test]
async fn every_check_warns_on_a_badly_set_vault() {
    let w = support::world().await;
    let mut v = support::vault_row("kv-test", "sub-a", false);
    v["enableSoftDelete"] = json!(false);
    v["publicNetworkAccess"] = json!("Enabled");
    v["networkDefaultAction"] = json!("Allow");
    v["privateEndpointConnections"] = json!([]);
    *w.arm.state.vaults.lock().unwrap() = vec![v];
    seed_content(&w, false);
    let (status, html) = page(&w, "/vault-health?vault=kv-test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_statuses(&html, "kv-test"), vec!["Warn"; CHECKS]);
    assert!(html.contains("10 warnings and 0 checks"));
    for (check, words, guide) in [
        (
            "Audit logs",
            "No diagnostic setting sends its audit logs anywhere",
            "general/logging",
        ),
        ("Azure RBAC", "It uses access policies", "rbac-migration"),
        ("Soft delete", "can't be recovered", "soft-delete-overview"),
        (
            "Purge protection",
            "turn purge protection on",
            "#purge-protection",
        ),
        (
            "Network access",
            "Anyone on the internet can reach it",
            "network-security",
        ),
        (
            "Private endpoint",
            "It has no private endpoint",
            "private-link-service",
        ),
        (
            "Secret expiry",
            "1 enabled secret has no expiry date",
            "secrets-best-practices",
        ),
        (
            "Certificate renewal",
            "1 certificate doesn't renew automatically",
            "overview-renew-certificate",
        ),
        (
            "Key rotation",
            "1 key has no rotation policy",
            "how-to-configure-key-rotation",
        ),
        (
            "Owners",
            "It has no keyring-owners tag",
            "management/tag-resources",
        ),
    ] {
        let at = html
            .find(&format!("kv-test</span>, {check}:"))
            .unwrap_or_else(|| panic!("{check} missing"));
        let line = &html[at..at + html[at..].find("</li>").unwrap()];
        assert!(line.contains(words), "{check}: {line}");
        assert!(
            line.contains("https://learn.microsoft.com/azure/") && line.contains(guide),
            "{check}: {line}"
        );
    }
}

#[tokio::test]
async fn checks_that_cant_be_read_are_unknown_with_the_reason() {
    let w = support::world().await;
    let mut v = healthy("kv-test");
    v["enableSoftDelete"] = json!(null);
    v["publicNetworkAccess"] = json!("SecuredByPerimeter");
    v["networkDefaultAction"] = json!(null);
    *w.arm.state.vaults.lock().unwrap() = vec![v];
    // No Reader on the diagnostic settings, and no Key Vault role.
    *w.arm.state.diagnostics.lock().unwrap() = None;
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = page(&w, "/vault-health?vault=kv-test").await;
    assert_eq!(status, StatusCode::OK);
    let got = row_statuses(&html, "kv-test");
    assert_eq!(
        got,
        [
            "Unknown", "Pass", "Unknown", "Pass", "Unknown", "Pass", "Unknown", "Unknown",
            "Unknown", "Pass"
        ]
    );
    for words in [
        "Audit logs: Couldn't read its diagnostic settings: you don't have Reader on it",
        "Soft delete: Azure didn't say whether soft delete is on",
        "Network access: Its network setting (SecuredByPerimeter) isn't one Keyring knows",
        "Secret expiry: Couldn't list its secrets: you don't have a Key Vault role on it",
        "Certificate renewal: Couldn't list its certificates",
        "Key rotation: Couldn't list its keys",
    ] {
        assert!(html.contains(words), "{words}");
    }
    assert!(!html.contains("mock Key Vault error"), "never Azure's text");
}

#[tokio::test]
async fn a_policy_that_cant_be_read_is_unknown_not_a_pass() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![healthy("kv-test")];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    seed_content(&w, true);
    *w.kv.state.fail_path.lock().unwrap() = Some("/rotationpolicy".into());
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (_, html) = page(&w, "/vault-health?vault=kv-test").await;
    assert_eq!(row_statuses(&html, "kv-test")[8], "Unknown");
    assert!(html.contains(
        "Key rotation: 1 key couldn't be checked: you don't have a Key Vault role on it. The rest pass"
    ));
}

#[tokio::test]
async fn all_vaults_leave_per_item_checks_for_the_one_vault_view() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![healthy("kv-a"), healthy("kv-b")];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(false));
    seed_content(&w, false);
    let (status, html) = page(&w, "/vault-health").await;
    assert_eq!(status, StatusCode::OK);
    for vault in ["kv-a", "kv-b"] {
        let got = row_statuses(&html, vault);
        assert_eq!(got[6], "Warn", "secrets are counted from the list");
        assert_eq!(&got[7..9], ["Deferred", "Deferred"]);
        assert_eq!(got[9], "Pass", "owners come from Resource Graph");
    }
    assert!(
        html.contains("Certificate renewal and key rotation are checked when you pick one vault")
    );
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        !log.iter()
            .any(|l| l.ends_with("/policy") || l.ends_with("/rotationpolicy")),
        "no per-item calls across all vaults: {log:?}"
    );
    // Diagnostic settings read once per vault, as the person.
    let paths = w.arm.state.diagnostics_paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 2);
    let bearers = w.arm.state.bearers.lock().unwrap().clone();
    assert!(
        bearers
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://management.azure.com/.default"))
    );
    let kv_bearers = w.kv.state.bearers.lock().unwrap().clone();
    assert!(kv_bearers.iter().all(|b| b.starts_with("Bearer obo:")));
}

#[tokio::test]
async fn audit_logs_sent_elsewhere_still_pass() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![healthy("kv-test")];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::storage_audit_settings());
    let (_, html) = page(&w, "/vault-health").await;
    assert_eq!(row_statuses(&html, "kv-test")[0], "Pass");
}

#[tokio::test]
async fn csv_lists_every_check_and_says_what_it_leaves_out() {
    let w = support::world().await;
    let mut evil = healthy("kv-test");
    evil["resourceGroup"] = json!("=HYPERLINK(\"x\")");
    evil["enableRbacAuthorization"] = json!(false);
    *w.arm.state.vaults.lock().unwrap() = vec![evil];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let res = w.get("/vault-health.csv").await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    assert_eq!(h["content-type"], "text/csv; charset=utf-8");
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .contains("keyring-vault-health.csv")
    );
    assert!(h["cache-control"].to_str().unwrap().contains("no-store"));
    let body = body_text(res).await;
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines[0],
        "Vault,Subscription,Resource group,Check,Result,Detail,Guide"
    );
    assert_eq!(lines.len(), 1 + CHECKS);
    assert!(
        lines[1].starts_with("kv-test,sub-a,\"'=HYPERLINK(\"\"x\"\")\",Audit logs,Pass,"),
        "{}",
        lines[1]
    );
    let rbac = lines.iter().find(|l| l.contains(",Azure RBAC,")).unwrap();
    assert!(rbac.contains(",Warn,") && rbac.ends_with("rbac-migration"));
    let cert = lines
        .iter()
        .find(|l| l.contains(",Certificate renewal,"))
        .unwrap();
    assert!(cert.contains(",Unknown,") && cert.contains("pick this vault on its own"));

    let body = body_text(w.get("/vault-health.csv?vault=kv-gone").await).await;
    assert!(body.contains("kv-gone,,,,NOT READ,Not in the list of vaults you can see"));
}

#[tokio::test]
async fn vault_list_badges_vaults_without_audit_logs() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![
        healthy("kv-logged"),
        healthy("kv-silent"),
        healthy("kv-locked"),
        healthy("kv-storage"),
    ];
    {
        let mut by = w.arm.state.diagnostics_by_vault.lock().unwrap();
        by.insert("kv-logged".into(), Some(support::audit_settings(true)));
        by.insert("kv-silent".into(), Some(json!({"value": []})));
        by.insert("kv-locked".into(), None);
        by.insert("kv-storage".into(), Some(support::storage_audit_settings()));
    }
    let (status, html) = page(&w, "/vaults").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<th scope=\"col\">Audit logs</th>"));
    let cell = |vault: &str| {
        let at = html
            .find(&format!("class=\"item-name\">{vault}"))
            .unwrap_or_else(|| panic!("{vault}"));
        let row = &html[at..at + html[at..].find("</tr>").unwrap()];
        row.split("<td>").nth(7).unwrap().to_owned()
    };
    assert!(cell("kv-logged").starts_with("On</td>"));
    assert!(cell("kv-silent").starts_with("<span class=\"badge badge-warn\">Off</span>"));
    assert!(cell("kv-locked").contains("Unknown: You don't have Reader on it"));
    assert!(cell("kv-storage").starts_with("On, not in Log Analytics"));
    assert!(html.contains("href=\"/vault-health\""));
}

#[tokio::test]
async fn nav_links_to_vault_health() {
    let w = support::world().await;
    let (_, html) = page(&w, "/vault-health").await;
    assert!(html.contains("href=\"/vault-health\" aria-current=\"page\">Vault health</a>"));
    assert!(html.contains("You can't see any vaults yet"));
}

#[tokio::test]
async fn vault_owners_are_shown_and_a_missing_tag_warns() {
    let w = support::world().await;
    let mut bare = healthy("kv-bare");
    bare["tags"] = json!({"env": "prod"});
    let mut empty = healthy("kv-empty");
    empty["tags"] = json!({"keyring-owners": " "});
    let mut odd = healthy("kv-odd");
    odd["tags"] = json!({"Keyring-Owners": "<script>x</script>; ops@example.com"});
    *w.arm.state.vaults.lock().unwrap() = vec![healthy("kv-ok"), bare, empty, odd];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let (status, html) = page(&w, "/vault-health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_statuses(&html, "kv-ok")[9], "Pass");
    assert_eq!(row_statuses(&html, "kv-bare")[9], "Warn");
    assert_eq!(row_statuses(&html, "kv-empty")[9], "Warn");
    assert_eq!(row_statuses(&html, "kv-odd")[9], "Pass");
    assert!(html.contains("kv-bare</span>, Owners: It has no keyring-owners tag"));
    assert!(html.contains("kv-empty</span>, Owners: Its keyring-owners tag is empty"));
    // A parsed address is a mailto link; anything else is escaped text.
    assert!(html.contains("<a href=\"mailto:ops@example.com\">ops@example.com</a>"));
    assert!(html.contains("<span class=\"mono\">Platform team</span>"));
    assert!(html.contains("&#60;script&#62;x&#60;/script&#62;"));
    assert!(!html.contains("<script>x"));
    assert!(!html.contains("mailto:&#60;"));
    // Where to set it, since Keyring never writes vault tags.
    assert!(html.contains("Tags blade") && html.contains("az tag update"));
    // No more calls than before: the tag comes with the Resource Graph rows.
    let queries = w.arm.state.requests.lock().unwrap().len();
    assert_eq!(queries, 2, "the vault and subscription queries only");

    // The vault list shows them too.
    let (status, html) = w.page("/vaults").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<th scope=\"col\">Owners</th>"));
    assert!(html.contains("<a href=\"mailto:ops@example.com\">ops@example.com</a>"));
    assert!(html.contains("&#60;script&#62;x&#60;/script&#62;"));
    assert!(html.contains("az tag update"));
}
