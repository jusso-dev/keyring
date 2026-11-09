use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use keyring::config::Config;
use tower::ServiceExt;

fn test_config() -> Config {
    Config::from_lookup(|k| {
        Some(
            match k {
                "ENTRA_TENANT_ID" => "00000000-0000-0000-0000-000000000000",
                "ENTRA_CLIENT_ID" => "11111111-1111-1111-1111-111111111111",
                "ENTRA_CLIENT_SECRET" => "test-secret",
                "APP_BASE_URL" => "http://localhost:3000",
                "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef",
                _ => return None,
            }
            .to_owned(),
        )
    })
    .expect("test config")
}

async fn get(path: &str) -> (StatusCode, String, Option<String>) {
    let app = keyring::app(keyring::AppState::new(test_config()));
    let res = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let ctype = res
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap(), ctype)
}

#[tokio::test]
async fn home_page_renders_with_shared_css() {
    let (status, body, _) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<link rel=\"stylesheet\" href=\"/static/style.css\">"));
    assert!(body.contains("Keyring"));
}

#[tokio::test]
async fn healthz_is_ok() {
    let (status, body, _) = get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn css_is_served_and_unknown_assets_are_not() {
    let (status, _, ctype) = get("/static/style.css").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("text/css; charset=utf-8"));
    let (status, _, _) = get("/static/../Cargo.toml").await;
    assert_ne!(status, StatusCode::OK);
    let (status, _, _) = get("/static/nope.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
