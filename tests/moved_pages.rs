//! The fixed pages moved under `/-/` (#99). Old addresses still work.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::location;
use tower::ServiceExt;

#[tokio::test]
async fn old_fixed_page_addresses_redirect() {
    let w = support::world().await;
    for (old, new) in [
        ("/secrets/new", "/secrets/-/new"),
        ("/secrets/deleted", "/secrets/-/deleted"),
        ("/secrets/deleted?page=2", "/secrets/-/deleted?page=2"),
        ("/secrets/deleted/old/purge", "/secrets/-/deleted/old/purge"),
        ("/certificates/upload", "/certificates/-/upload"),
        ("/certificates/new", "/certificates/-/new"),
        ("/certificates/deleted", "/certificates/-/deleted"),
        ("/certificates/deleted/old", "/certificates/-/deleted/old"),
        ("/keys/new", "/keys/-/new"),
        ("/keys/deleted", "/keys/-/deleted"),
        ("/keys/deleted/old", "/keys/-/deleted/old"),
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
        ("/secrets/new", "/secrets/-/new"),
        ("/certificates/new", "/certificates/-/new"),
        ("/keys/new", "/keys/-/new"),
        (
            "/secrets/deleted/old/recover",
            "/secrets/-/deleted/old/recover",
        ),
        (
            "/certificates/upload/confirm",
            "/certificates/-/upload/confirm",
        ),
    ] {
        let res = w.post(old, &[]).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }
    // Nothing else posts to an item's page.
    let res = w.post("/secrets/db", &[]).await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn an_item_called_new_opens_instead_of_the_old_redirect() {
    let w = support::world().await;
    w.kv.state.put("new", "x");
    w.kv.state.put("deleted", "x");
    for name in ["new", "deleted"] {
        let (status, html) = w.page(&format!("/secrets/{name}")).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert!(
            html.contains(&format!("<h1 class=\"mono\">{name}</h1>")),
            "{name}"
        );
    }
    // Its own pages under the name work too.
    let (status, _) = w.page("/secrets/deleted/delete").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = w.page("/secrets/new/edit").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn new_fixed_pages_answer() {
    let w = support::world().await;
    for path in [
        "/secrets/-/new",
        "/secrets/-/deleted",
        "/certificates/-/new",
        "/certificates/-/upload",
        "/certificates/-/deleted",
        "/keys/-/new",
        "/keys/-/deleted",
    ] {
        let (status, _) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    // `-` is never an item name.
    let (status, _) = w.page("/secrets/-").await;
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
