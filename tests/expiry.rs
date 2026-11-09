//! Expiry dashboard across vaults.

mod support;

use axum::http::StatusCode;
use support::body_text;

const DAY: i64 = 86_400;

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

fn seed_vaults(w: &support::World, names: &[&str]) {
    *w.arm.state.vaults.lock().unwrap() = names
        .iter()
        .map(|n| support::vault_row(n, "sub-a", true))
        .collect();
}

#[tokio::test]
async fn groups_across_vaults_and_types() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    let n = now();
    w.kv.state
        .put_with("gone", "VALUE-1", |v| v.exp = Some(n - DAY));
    w.kv.state
        .put_with("week", "VALUE-2", |v| v.exp = Some(n + 3 * DAY));
    w.kv.state
        .put_with("month", "VALUE-3", |v| v.exp = Some(n + 20 * DAY));
    w.kv.state.put("forever", "VALUE-4");
    w.kv.state.add_cert_version(
        "tls",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(false, false),
        |v| v.exp = Some(n + 60 * DAY),
    );
    w.kv.state
        .add_key_with("signer", "RSA", |v| v.exp = Some(n + 200 * DAY));
    let (status, html) = w.page("/expiry").await;
    assert_eq!(status, StatusCode::OK);
    for (label, count) in [
        ("Expired", 1),
        ("Next 7 days", 1),
        ("8 to 30 days", 1),
        ("31 to 90 days", 1),
        ("More than 90 days", 1),
        ("No expiry set", 1),
    ] {
        assert!(
            html.contains(&format!("{label} <span class=\"muted\">({count})</span>")),
            "{label}"
        );
    }
    assert!(html.contains(">Certificate<") && html.contains(">Key<"));
    assert!(!html.contains("VALUE-"), "never values");
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn several_vaults_and_skipped_ones() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-a", "kv-b", "kv-test"]);
    w.kv.state.put("shared-name", "x");
    let (_, html) = w.page("/expiry").await;
    // The mock serves the same data under every vault path.
    assert_eq!(html.matches(">shared-name<").count(), 3);
    assert!(html.contains(">kv-a<") && html.contains(">kv-b<"));

    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = w.page("/expiry").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "partial failures don't fail the page"
    );
    assert!(html.contains("couldn't be read"));
    assert_eq!(
        html.matches("You don&#39;t have a Key Vault role on it")
            .count(),
        3
    );
    assert!(html.contains("You don&#39;t have a Key Vault role on it"));
}

#[tokio::test]
async fn throttling_is_retried() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    w.kv.state.put("a", "x");
    *w.kv.state.throttle_next.lock().unwrap() = 2;
    let (status, html) = w.page("/expiry").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(">a<"),
        "throttled calls retried and succeeded"
    );
    assert!(!html.contains("couldn't be read"));
}

#[tokio::test]
async fn filters_by_vault_type_tag_and_group() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-a", "kv-test"]);
    let n = now();
    w.kv.state.put_with("tagged", "x", |v| {
        v.exp = Some(n + DAY);
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.add_key_with("k1", "RSA", |_| {});
    let (_, html) = w.page("/expiry?vault=kv-a").await;
    assert_eq!(html.matches(">tagged<").count(), 1);
    let (_, html) = w.page("/expiry?type=key").await;
    assert!(html.contains(">k1<") && !html.contains(">tagged<"));
    let (_, html) = w.page("/expiry?tag=env%3Dprod").await;
    assert!(html.contains(">tagged<") && !html.contains(">k1<"));
}

#[tokio::test]
async fn csv_matches_view_without_values() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    let n = now();
    w.kv.state
        .put_with("db-password", "TOPSECRET", |v| v.exp = Some(n + 2 * DAY));
    w.kv.state.add_key_with("k1", "RSA", |_| {});
    let (_, html) = w.page("/expiry?type=secret").await;
    assert!(html.contains("href=\"/expiry.csv?vault=&#38;type=secret"));
    let res = w.get("/expiry.csv?type=secret").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "text/csv; charset=utf-8"
    );
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
    assert_eq!(lines.len(), 2, "{csv}");
    assert!(lines[1].starts_with("kv-test,Secret,db-password,Yes,"));
    assert!(lines[1].contains("Next 7 days"));
    assert!(!csv.contains("TOPSECRET"));
}

#[tokio::test]
async fn no_vaults() {
    let w = support::world().await;
    let (status, html) = w.page("/expiry").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Nothing to show"));
}

#[tokio::test]
async fn partly_readable_vaults_say_what_is_missing() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    w.kv.state.put("a-secret", "x");
    w.kv.state.add_key_with("a-key", "RSA", |_| {});
    // Keys are forbidden, secrets and certificates work.
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    *w.kv.state.fail_path.lock().unwrap() = Some("/keys".into());
    let (_, html) = w.page("/expiry").await;
    assert!(html.contains(">a-secret<"), "what could be read is shown");
    assert!(!html.contains(">a-key<"));
    assert!(
        html.contains("Its keys couldn&#39;t be read (you don&#39;t have a Key Vault role on it)"),
        "{}",
        &html[html.find("notice-warn").unwrap_or(0)..][..300]
    );
}

#[tokio::test]
async fn open_switches_vault_and_goes_to_the_item() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-other"]);
    w.kv.state
        .put_with("db-password", "x", |v| v.exp = Some(now() + DAY));
    let (_, html) = w.page("/expiry").await;
    assert!(html.contains("name=\"return_to\" value=\"/secrets/db-password\""));
    let res = w
        .post(
            "/vaults/select",
            &[("name", "kv-other"), ("return_to", "/secrets/db-password")],
        )
        .await;
    assert_eq!(support::location(&res), "/secrets/db-password");
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("<strong>kv-other</strong>"));
    // An outside address is never followed.
    let res = w
        .post(
            "/vaults/select",
            &[("name", "kv-other"), ("return_to", "https://evil.example")],
        )
        .await;
    assert_eq!(support::location(&res), "/");
}
