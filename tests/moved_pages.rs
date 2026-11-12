//! The fixed pages moved under `/-/` (#99), and every vault page moved
//! under `/v/{vault}/`. Old addresses still work.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::location;
use tower::ServiceExt;

#[tokio::test]
async fn old_fixed_page_addresses_redirect() {
    let w = support::world().await;
    // Before the vault was in the address: the first hop adds the vault
    // last used, and the next one applies the fixed-page move.
    for (old, first, last) in [
        (
            "/secrets/new",
            "/v/kv-test/secrets/new",
            "/v/kv-test/secrets/-/new",
        ),
        (
            "/secrets/deleted?page=2",
            "/v/kv-test/secrets/deleted?page=2",
            "/v/kv-test/secrets/-/deleted?page=2",
        ),
        (
            "/secrets/deleted/old/purge",
            "/v/kv-test/secrets/deleted/old/purge",
            "/v/kv-test/secrets/-/deleted/old/purge",
        ),
        (
            "/certificates/upload",
            "/v/kv-test/certificates/upload",
            "/v/kv-test/certificates/-/upload",
        ),
        ("/keys/new", "/v/kv-test/keys/new", "/v/kv-test/keys/-/new"),
    ] {
        let res = w.get(old).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), first, "{old}");
        let res = w.get(first).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{first}");
        assert_eq!(location(&res), last, "{first}");
    }
    // Under a vault, the fixed-page move still applies.
    for (old, new) in [
        ("/v/kv-test/secrets/new", "/v/kv-test/secrets/-/new"),
        ("/v/kv-test/secrets/deleted", "/v/kv-test/secrets/-/deleted"),
        (
            "/v/kv-test/secrets/deleted?page=2",
            "/v/kv-test/secrets/-/deleted?page=2",
        ),
        (
            "/v/kv-test/secrets/deleted/old/purge",
            "/v/kv-test/secrets/-/deleted/old/purge",
        ),
        (
            "/v/kv-test/certificates/upload",
            "/v/kv-test/certificates/-/upload",
        ),
        (
            "/v/kv-test/certificates/new",
            "/v/kv-test/certificates/-/new",
        ),
        (
            "/v/kv-test/certificates/deleted",
            "/v/kv-test/certificates/-/deleted",
        ),
        (
            "/v/kv-test/certificates/deleted/old",
            "/v/kv-test/certificates/-/deleted/old",
        ),
        ("/v/kv-test/keys/new", "/v/kv-test/keys/-/new"),
        ("/v/kv-test/keys/deleted", "/v/kv-test/keys/-/deleted"),
        (
            "/v/kv-test/keys/deleted/old",
            "/v/kv-test/keys/-/deleted/old",
        ),
    ] {
        let res = w.get(old).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }
}

#[tokio::test]
async fn old_form_posts_are_sent_on_with_308() {
    let w = support::world().await;
    for (old, new) in [
        ("/v/kv-test/secrets/new", "/v/kv-test/secrets/-/new"),
        (
            "/v/kv-test/certificates/new",
            "/v/kv-test/certificates/-/new",
        ),
        ("/v/kv-test/keys/new", "/v/kv-test/keys/-/new"),
        (
            "/v/kv-test/secrets/deleted/old/recover",
            "/v/kv-test/secrets/-/deleted/old/recover",
        ),
        (
            "/v/kv-test/certificates/upload/confirm",
            "/v/kv-test/certificates/-/upload/confirm",
        ),
        // From before the vault was in the address.
        ("/secrets/new", "/v/kv-test/secrets/new"),
        ("/secrets/db/reveal", "/v/kv-test/secrets/db/reveal"),
    ] {
        let res = w.post(old, &[]).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }
    // Nothing else posts to an item's page.
    let res = w.post("/v/kv-test/secrets/db", &[]).await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn an_item_called_new_opens_instead_of_the_old_redirect() {
    let w = support::world().await;
    w.kv.state.put("new", "x");
    w.kv.state.put("deleted", "x");
    for name in ["new", "deleted"] {
        let (status, html) = w.page(&format!("/v/kv-test/secrets/{name}")).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert!(
            html.contains(&format!("<h1 class=\"mono\">{name}</h1>")),
            "{name}"
        );
    }
    // Its own pages under the name work too.
    let (status, _) = w.page("/v/kv-test/secrets/deleted/delete").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = w.page("/v/kv-test/secrets/new/edit").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn new_fixed_pages_answer() {
    let w = support::world().await;
    for path in [
        "/v/kv-test/secrets/-/new",
        "/v/kv-test/secrets/-/deleted",
        "/v/kv-test/certificates/-/new",
        "/v/kv-test/certificates/-/upload",
        "/v/kv-test/certificates/-/deleted",
        "/v/kv-test/keys/-/new",
        "/v/kv-test/keys/-/deleted",
    ] {
        let (status, _) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    // `-` is never an item name.
    let (status, _) = w.page("/v/kv-test/secrets/-").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn old_form_posts_are_still_origin_checked() {
    let w = support::world().await;
    let req = Request::post("/secrets/new")
        .header("cookie", &w.cookie)
        .header("origin", "https://evil.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={}&name=x&value=v", w.csrf)))
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
