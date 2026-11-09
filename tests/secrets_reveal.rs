//! Reveal and copy. Values only on request, never logged, never cached.

mod support;

use axum::http::StatusCode;

const VALUE: &str = "Sup3r-S3cret-Value-<&>\"'";

#[tokio::test]
async fn detail_does_not_fetch_value_until_asked() {
    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("Show value"));
    assert!(html.contains("action=\"/secrets/db-password/reveal\""));
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn reveal_is_a_post_that_works_without_js_and_is_not_cached() {
    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    let res = w.post("/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cc = res
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cc.contains("no-store"), "{cc}");
    let html = support::body_text(res).await;
    // The value is in the page, HTML-escaped, inside a plain textarea, so it
    // shows with JavaScript off.
    assert!(
        html.contains("Sup3r-S3cret-Value-&#60;&#38;&#62;&#34;&#39;"),
        "{html}"
    );
    assert!(!html.contains(VALUE));
    assert!(html.contains("<textarea"));
    assert!(html.contains("data-clear-after=\"30\""));
    assert_eq!(w.kv.state.value_reads().len(), 1);
    // GET on the reveal URL doesn't reveal anything.
    let (status, _) = w.page("/secrets/db-password/reveal").await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(w.kv.state.value_reads().len(), 1);
}

#[tokio::test]
async fn reveal_needs_the_form_token() {
    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    let mut w = w;
    let real = std::mem::replace(&mut w.csrf, "forged".into());
    let res = w.post("/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.value_reads().is_empty());
    w.csrf = real;
}

#[tokio::test]
async fn reveal_a_specific_version() {
    let w = support::world().await;
    let v1 = w.kv.state.put("db-password", "old-value");
    w.kv.state.put("db-password", "new-value");
    let res = w
        .post("/secrets/db-password/reveal", &[("version", &v1)])
        .await;
    let html = support::body_text(res).await;
    assert!(html.contains("old-value") && !html.contains("new-value"));
    assert!(html.contains(&format!("of version {v1}")));
    let res = w
        .post("/secrets/db-password/reveal", &[("version", "../../keys")])
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reveal_errors_are_explained() {
    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let res = w.post("/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = support::body_text(res).await;
    assert!(html.contains("Key Vault Secrets User"));
}

#[test]
fn script_is_small_dependency_free_and_same_origin() {
    let js = include_str!("../static/app.js");
    assert!(js.lines().count() < 250, "keep app.js small");
    for banned in [
        "import ",
        "require(",
        "eval(",
        "new Function",
        "innerHTML",
        "http://",
        "https://",
        "localStorage",
        "sessionStorage",
    ] {
        assert!(!js.contains(banned), "app.js must not use {banned}");
    }
    assert!(js.contains("navigator.clipboard.writeText(\"\")"));
}
