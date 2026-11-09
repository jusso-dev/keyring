//! App shell: navigation, error pages, flash messages and security headers.

mod support;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn get(app: &axum::Router, path: &str, cookie: Option<&str>) -> Response<Body> {
    let mut req = Request::get(path);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn text(res: Response<Body>) -> String {
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn shell_has_nav_vault_picker_and_no_scripts() {
    let (_, app, cookie) = support::signed_in_app(support::config());
    let res = get(&app, "/", Some(&cookie)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = text(res).await;
    for label in [
        "Secrets",
        "Certificates",
        "Keys",
        "Expiry",
        "Generator",
        "Audit",
    ] {
        assert!(html.contains(&format!(">{label}</a>")), "{label} missing");
    }
    assert!(html.contains("Choose a vault"));
    assert!(html.contains("Skip to content"));
    // Pages work without JavaScript: there's none yet, and never inline.
    assert!(!html.contains("<script>"));
    assert!(!html.contains(" style=\""));
    assert!(!html.contains(" onclick="));
}

#[tokio::test]
async fn every_section_has_a_page_with_an_empty_state() {
    let (_, app, cookie) = support::signed_in_app(support::config());
    for path in ["/secrets", "/certificates", "/keys", "/audit"] {
        // With no vault chosen, each says to choose one.
        let res = get(&app, path, Some(&cookie)).await;
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        let html = text(res).await;
        assert!(html.contains("aria-current=\"page\""), "{path}");
        assert!(html.contains("class=\"empty-state\""), "{path}");
    }
    // The generator needs no vault and has no empty state.
    let res = get(&app, "/generator", Some(&cookie)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(text(res).await.contains("aria-current=\"page\""));
}

#[tokio::test]
async fn sections_need_sign_in() {
    let app = keyring::app(keyring::AppState::new(support::config()));
    let res = get(&app, "/secrets", None).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn unknown_pages_get_a_plain_404() {
    let (_, app, cookie) = support::signed_in_app(support::config());
    let res = get(&app, "/no/such/page", Some(&cookie)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let html = text(res).await;
    assert!(html.contains("Page not found"));
    assert!(html.contains("Back to home"));
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let (_, app, cookie) = support::signed_in_app(support::config());
    for (path, c) in [
        ("/", Some(cookie.as_str())),
        ("/auth/sign-in", None),
        ("/nope", None),
        ("/healthz", None),
    ] {
        let res = get(&app, path, c).await;
        let h = res.headers();
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("script-src 'self'"), "{path}");
        assert!(csp.contains("style-src 'self'"), "{path}");
        assert!(csp.contains("frame-ancestors 'none'"), "{path}");
        assert!(!csp.contains("unsafe-inline"), "{path}");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("referrer-policy").unwrap(), "same-origin");
    }
    // HTML isn't cached; static files are.
    let res = get(&app, "/", Some(&cookie)).await;
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    let res = get(&app, "/static/style.css", None).await;
    assert_ne!(res.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn hsts_only_over_https() {
    let (_, app, cookie) = support::signed_in_app(support::config());
    let res = get(&app, "/", Some(&cookie)).await;
    assert!(res.headers().get("strict-transport-security").is_none());

    let config = support::config_with("http://127.0.0.1:9", "https://keyring.example.com");
    let app = keyring::app(keyring::AppState::new(config));
    let res = get(&app, "/healthz", None).await;
    assert!(res.headers().get("strict-transport-security").is_some());
}

#[tokio::test]
async fn flash_messages_show_once() {
    use axum::response::IntoResponse;
    use keyring::routes::flash::{self, Flash};

    let (state, app, cookie) = support::signed_in_app(support::config());
    // Make the flash cookie the way a handler would.
    let mut res = axum::response::Redirect::to("/").into_response();
    flash::set(&state, &mut res, &Flash::success("Secret saved"));
    let set = res.headers().get("set-cookie").unwrap().to_str().unwrap();
    let flash_cookie = set.split(';').next().unwrap().to_owned();
    assert!(!flash_cookie.contains("Secret saved"), "flash is encrypted");

    let res = get(&app, "/", Some(&format!("{cookie}; {flash_cookie}"))).await;
    let cleared = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("keyring_flash=;"));
    assert!(cleared, "flash cookie is cleared after showing");
    let html = text(res).await;
    assert!(html.contains("Secret saved"));
    assert!(html.contains("role=\"status\""));

    // A forged flash cookie is ignored.
    let res = get(&app, "/", Some(&format!("{cookie}; keyring_flash=forged"))).await;
    assert!(!text(res).await.contains("notice-ok"));
}
