//! Versions and rollback.

mod support;

use axum::http::StatusCode;
use support::{body_text, location};

#[tokio::test]
async fn lists_every_version_newest_first() {
    let w = support::world().await;
    let v1 = w.kv.state.put("db-password", "one");
    let v2 =
        w.kv.state
            .put_with("db-password", "two", |v| v.enabled = false);
    let v3 = w.kv.state.put("db-password", "three");
    let (status, html) = w.page("/secrets/db-password/versions").await;
    assert_eq!(status, StatusCode::OK);
    let p3 = html.find(&v3[..8]).unwrap();
    let p2 = html.find(&v2[..8]).unwrap();
    let p1 = html.find(&v1[..8]).unwrap();
    assert!(p3 < p2 && p2 < p1, "newest first");
    assert!(html.contains("Current"));
    assert!(html.contains("Disabled"));
    // Lists without reading any value.
    assert!(w.kv.state.value_reads().is_empty());
    assert!(!html.contains(">one<") && !html.contains(">three<"));
    // Older versions offer rollback; the current one doesn't.
    assert!(html.contains(&format!("rollback?version={v1}")));
    assert!(!html.contains(&format!("rollback?version={v3}")));
}

#[tokio::test]
async fn any_version_can_be_revealed_on_demand() {
    let w = support::world().await;
    let v1 = w.kv.state.put("db-password", "first-value");
    w.kv.state.put("db-password", "second-value");
    let (_, html) = w.page("/secrets/db-password/versions").await;
    assert!(html.contains(&format!("name=\"version\" value=\"{v1}\"")));
    let res = w
        .post("/secrets/db-password/reveal", &[("version", &v1)])
        .await;
    let html = body_text(res).await;
    assert!(html.contains("first-value"));
}

#[tokio::test]
async fn rollback_confirms_then_makes_a_new_version_with_the_old_value() {
    let w = support::world().await;
    let v1 = w.kv.state.put_with("db-password", "good", |v| {
        v.content_type = Some("text/plain".into())
    });
    w.kv.state.put_with("db-password", "oops", |v| {
        v.tags.insert("env".into(), "prod".into());
        v.exp = Some(keyring::azure::secrets::now_ts() + 50 * 86_400);
    });

    let (status, html) = w
        .page(&format!("/secrets/db-password/rollback?version={v1}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("into a <strong>new version</strong>"));
    assert!(html.contains("Nothing is deleted"));
    // The confirm page itself changes nothing.
    assert_eq!(w.kv.state.version_count("db-password"), 2);

    let res = w
        .post("/secrets/db-password/rollback", &[("version", &v1)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/secrets/db-password/versions");
    assert_eq!(w.kv.state.version_count("db-password"), 3, "history kept");
    let current = w.kv.state.current("db-password").unwrap();
    assert_eq!(current.value, "good");
    assert_ne!(current.version, v1, "a new version, not a reorder");
    assert_eq!(current.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        current.tags.get("env").map(String::as_str),
        Some("prod"),
        "current tags kept"
    );
    assert!(current.exp.is_some(), "current expiry kept");
    let versions =
        w.kv.state
            .secrets
            .lock()
            .unwrap()
            .get("db-password")
            .unwrap()
            .versions
            .clone();
    assert_eq!(
        versions[1].value, "oops",
        "the bad value is still in history"
    );
}

#[tokio::test]
async fn rollback_refuses_current_unknown_and_forged() {
    let mut w = support::world().await;
    w.kv.state.put("db-password", "a");
    let v2 = w.kv.state.put("db-password", "b");
    let res = w
        .post("/secrets/db-password/rollback", &[("version", &v2)])
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(res).await.contains("already the current version"));
    let res = w
        .post(
            "/secrets/db-password/rollback",
            &[("version", "ffffffffffffffffffffffffffffffff")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = w
        .post("/secrets/db-password/rollback", &[("version", "../x")])
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    w.csrf = "forged".into();
    let v1 = w.kv.state.secrets.lock().unwrap()["db-password"].versions[0]
        .version
        .clone();
    let res = w
        .post("/secrets/db-password/rollback", &[("version", &v1)])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(w.kv.state.version_count("db-password"), 2);
}

#[tokio::test]
async fn rollback_without_write_access_explains() {
    let w = support::world().await;
    let v1 = w.kv.state.put("db-password", "a");
    w.kv.state.put("db-password", "b");
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::PUT);
    let res = w
        .post("/secrets/db-password/rollback", &[("version", &v1)])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Key Vault Secrets Officer"));
    assert_eq!(w.kv.state.version_count("db-password"), 2);
}

#[tokio::test]
async fn detail_links_to_history() {
    let w = support::world().await;
    w.kv.state.put("db-password", "a");
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("href=\"/secrets/db-password/versions\""));
    assert!(html.contains("href=\"/audit?item=db-password&amp;range=30d\""));
}
