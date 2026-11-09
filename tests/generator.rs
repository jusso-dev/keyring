//! Generator page.

mod support;

use axum::http::StatusCode;
use support::body_text;

fn value_of(html: &str) -> String {
    let start = html.find("data-secret-value>").unwrap() + "data-secret-value>".len();
    let end = html[start..].find("</textarea>").unwrap() + start;
    html[start..end].to_owned()
}

#[tokio::test]
async fn page_explains_options() {
    let w = support::world().await;
    let (status, html) = w.page("/generator").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("24 characters is plenty"));
    assert!(html.contains("Leave out characters that look alike"));
    assert!(html.contains("32 bytes (256 bits)"));
    assert!(
        !html.contains("data-secret-value"),
        "nothing generated on a GET"
    );
}

#[tokio::test]
async fn generates_each_kind_with_no_store() {
    let w = support::world().await;
    let res = w
        .post(
            "/generator",
            &[
                ("kind", "password"),
                ("length", "30"),
                ("lower", "on"),
                ("digits", "on"),
            ],
        )
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
    let html = body_text(res).await;
    let v = value_of(&html);
    assert_eq!(v.len(), 30);
    assert!(
        v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
    assert!(
        html.contains("data-clear-after=\"30\""),
        "same auto clear as secrets"
    );

    let html = body_text(w.post("/generator", &[("kind", "guid")]).await).await;
    assert_eq!(value_of(&html).len(), 36);

    let html = body_text(
        w.post(
            "/generator",
            &[
                ("kind", "api_key"),
                ("bytes", "16"),
                ("format", "hex"),
                ("prefix", "kr_"),
            ],
        )
        .await,
    )
    .await;
    let v = value_of(&html);
    assert!(v.starts_with("kr_") && v.len() == 35);
}

#[tokio::test]
async fn bad_options_are_explained() {
    let w = support::world().await;
    let html = body_text(
        w.post("/generator", &[("kind", "password"), ("length", "24")])
            .await,
    )
    .await;
    assert!(html.contains("Tick at least one kind of character"));
    let html = body_text(
        w.post(
            "/generator",
            &[("kind", "password"), ("length", "3"), ("lower", "on")],
        )
        .await,
    )
    .await;
    assert!(html.contains("Pick a length from 8 to 256"));
    let html = body_text(
        w.post(
            "/generator",
            &[
                ("kind", "api_key"),
                ("bytes", "32"),
                ("prefix", "has space"),
            ],
        )
        .await,
    )
    .await;
    assert!(html.contains("The prefix can use"));
}

#[tokio::test]
async fn needs_form_token() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    assert_eq!(
        w.post("/generator", &[("kind", "guid")]).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn secret_form_links_to_generator_with_use_this_value() {
    let w = support::world().await;
    let (_, html) = w.page("/secrets/new").await;
    assert!(html.contains("href=\"/generator?for_secret=1\""));
    let (_, html) = w.page("/generator?for_secret=1").await;
    assert!(html.contains("name=\"for_secret\" value=\"1\""));
    let html = body_text(
        w.post("/generator", &[("kind", "guid"), ("for_secret", "1")])
            .await,
    )
    .await;
    assert!(html.contains("data-use-value"));
}
