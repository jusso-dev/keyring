//! Secrets list and detail against a mock Key Vault.

mod support;

use axum::http::StatusCode;
use support::keyvault::BASE_TIME;

const DAY: i64 = 86_400;

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

#[tokio::test]
async fn needs_a_vault_first() {
    let w = support::world().await;
    let id = w.cookie.split('=').nth(1).unwrap();
    // A fresh session with no vault picked.
    let fresh = w.state.sessions.create(
        w.state.sessions.get(id).unwrap().user.clone(),
        w.state.sessions.get(id).unwrap().tokens(),
    );
    let mut w2 = w;
    w2.cookie = format!("keyring_session={fresh}");
    let (status, html) = w2.page("/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Choose a vault first"));
}

#[tokio::test]
async fn lists_properties_without_reading_values() {
    let w = support::world().await;
    w.kv.state.put_with("db-password", "s3cret-db", |v| {
        v.content_type = Some("text/plain".into());
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put("api-key", "s3cret-api");
    let (status, html) = w.page("/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(">api-key<") && html.contains(">db-password<"));
    assert!(html.contains("text/plain"));
    assert!(html.contains("env=prod"));
    assert!(
        !html.contains("s3cret"),
        "values must not be on the list page"
    );
    assert!(
        w.kv.state.value_reads().is_empty(),
        "{:?}",
        w.kv.state.value_reads()
    );
    // Called as the user, with the Key Vault OBO token.
    let bearers = w.kv.state.bearers.lock().unwrap().clone();
    assert!(
        bearers
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://vault.azure.net/.default"))
    );
}

#[tokio::test]
async fn marks_expired_expiring_disabled_and_not_yet_active() {
    let w = support::world().await;
    let n = now();
    w.kv.state
        .put_with("expired-one", "x", |v| v.exp = Some(n - DAY));
    w.kv.state
        .put_with("soon-one", "x", |v| v.exp = Some(n + 3 * DAY));
    w.kv.state
        .put_with("later-one", "x", |v| v.exp = Some(n + 300 * DAY));
    w.kv.state.put_with("off-one", "x", |v| v.enabled = false);
    w.kv.state
        .put_with("future-one", "x", |v| v.nbf = Some(n + 5 * DAY));
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains("1 expired"));
    assert!(html.contains("1 expiring within 30 days"));
    assert!(html.contains("1 disabled"));
    assert!(html.contains("badge-error\">Expired"));
    assert!(html.contains("badge-warn\">Expires within 30 days"));
    assert!(html.contains(">Disabled<"));
    assert!(html.contains("Not active yet"));
    assert!(html.contains("in 3 days") || html.contains("in 2 days"));
}

#[tokio::test]
async fn search_and_filters() {
    let w = support::world().await;
    let n = now();
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("team".into(), "data".into());
    });
    w.kv.state
        .put_with("api-key", "x", |v| v.exp = Some(n + DAY));
    w.kv.state.put_with("old-token", "x", |v| v.enabled = false);
    let (_, html) = w.page("/secrets?q=DB").await;
    assert!(html.contains(">db-password<") && !html.contains(">api-key<"));
    let (_, html) = w.page("/secrets?tag=team%3Ddata").await;
    assert!(html.contains(">db-password<") && !html.contains(">old-token<"));
    let (_, html) = w.page("/secrets?show=expiring").await;
    assert!(html.contains(">api-key<") && !html.contains(">db-password<"));
    let (_, html) = w.page("/secrets?show=disabled").await;
    assert!(html.contains(">old-token<") && !html.contains(">api-key<"));
    // Live filtering text includes tags.
    assert!(html.contains("data-live-filter=\"secret-table\""));
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains("data-filter-text=\"db-password team=data\""));
}

#[tokio::test]
async fn pages_through_many_secrets() {
    let w = support::world().await;
    for i in 0..260 {
        w.kv.state.put(&format!("s{i:04}"), "x");
    }
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains("260 secrets"));
    // Key Vault pages of 25 were all followed.
    let lists =
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.as_str() == "GET /kv-test/secrets")
            .count();
    assert_eq!(lists, 11);
    assert!(html.contains("Page 1 of 3"));
    assert!(html.contains(">s0000<") && !html.contains(">s0100<"));
    let (_, html) = w.page("/secrets?page=3").await;
    assert!(html.contains(">s0259<"));
}

#[tokio::test]
async fn empty_vault_and_errors() {
    let w = support::world().await;
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains("This vault has no secrets yet"));

    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = w.page("/secrets").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Key Vault Secrets User role on this vault"));
    assert!(!html.contains("private detail"));
}

#[tokio::test]
async fn detail_shows_current_version_without_value() {
    let w = support::world().await;
    let n = now();
    w.kv.state.put("db-password", "first-value");
    let v2 = w.kv.state.put_with("db-password", "second-value", |v| {
        v.content_type = Some("text/plain".into());
        v.exp = Some(n + 100 * DAY);
        v.tags.insert("env".into(), "prod".into());
    });
    let (status, html) = w.page("/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(&v2), "shows the newest version");
    assert!(html.contains("text/plain") && html.contains("env=prod"));
    assert!(html.contains("The value is hidden"));
    assert!(!html.contains("first-value") && !html.contains("second-value"));
    assert!(w.kv.state.value_reads().is_empty());
    let _ = BASE_TIME;
}

#[tokio::test]
async fn detail_handles_missing_and_bad_names() {
    let w = support::world().await;
    let (status, html) = w.page("/secrets/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(html.contains("It may have been deleted"));
    let (status, _) = w.page("/secrets/bad_name").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Nothing odd reached Key Vault.
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.contains("bad_name"))
    );
}

#[tokio::test]
async fn unreachable_vault_explains_private_networks() {
    // Point Key Vault at a closed port, as if the vault were private.
    let w = support::world_with(&[("KEYRING_TEST_KEYVAULT_URL", "http://127.0.0.1:9")]).await;
    let (status, html) = w.page("/secrets").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(html.contains("Can&#39;t reach this vault"));
    assert!(html.contains("private network"));
}

#[tokio::test]
async fn firewall_blocks_use_key_vaults_inner_code() {
    let w = support::world().await;
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByFirewall"));
    let (status, html) = w.page("/secrets").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        html.contains("This vault is blocked from here"),
        "outer code is Forbidden, inner is ForbiddenByFirewall"
    );
}
