//! Pinned and recently opened items (static/pins.js). The script keeps its
//! list in the browser, so the server only serves it and renders the hooks
//! it reads. Without JavaScript the hooks do nothing.

mod support;

use axum::http::StatusCode;

/// The `<script>` tag for pins.js, with its content hash.
fn pins_tag(html: &str) -> &str {
    let start = html
        .find("<script src=\"/static/pins.js?v=")
        .expect("pins.js script tag");
    let tag = &html[start..];
    &tag[..tag.find("</script>").unwrap()]
}

#[tokio::test]
async fn script_is_served_versioned_and_cached_like_app_js() {
    let w = support::world().await;
    let (_, html) = w.page("/").await;
    let tag = pins_tag(&html);
    assert!(tag.ends_with(" defer>"), "{tag}");
    let url = tag
        .trim_start_matches("<script src=\"")
        .split('"')
        .next()
        .unwrap();
    let res = w.get(url).await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers();
    assert_eq!(
        h.get("content-type").unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        h.get("cache-control").unwrap(),
        "public, max-age=31536000, immutable"
    );
    let body = support::body_text(res).await;
    assert_eq!(body, include_str!("../static/pins.js"));
    let res = w.get("/static/pins.js").await;
    assert_eq!(
        res.headers().get("cache-control").unwrap(),
        "public, max-age=300"
    );
}

#[tokio::test]
async fn csp_is_unchanged_and_allows_no_inline_script() {
    let w = support::world().await;
    let (_, home) = w.page("/").await;
    let res = w.get("/").await;
    let csp = res
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(!csp.contains("unsafe-"), "{csp}");
    // The scripts are same-origin files; no page carries inline script or
    // inline handlers for the pins.
    // app.js, behaviors.js, pins.js and tags.js.
    assert_eq!(home.matches("<script").count(), 4);
    assert!(!home.contains("<script>"));
    assert!(!home.contains("onsubmit") && !home.contains("onclick"));
}

#[tokio::test]
async fn home_and_vault_list_have_an_empty_hidden_mount() {
    let w = support::world().await;
    for path in ["/", "/vaults"] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            html.contains("<div class=\"pins-box\" data-pins hidden></div>"),
            "{path}"
        );
        // Straight after the page header (heading, description and About),
        // and before the command bar and the page's content.
        let desc = html.find("class=\"page-desc\"").unwrap();
        let head_end = html[desc..].find("</div>").unwrap() + desc;
        let mount = html.find("data-pins hidden").unwrap();
        assert!(mount > head_end, "{path}: below the description");
        assert!(
            html[head_end..mount].lines().count() <= 3,
            "{path}: straight after the page header"
        );
        if let Some(bar) = html.find("class=\"commandbar\"") {
            assert!(mount < bar, "{path}: above the command bar");
        }
        assert!(
            html.find("<main").unwrap() < mount,
            "{path}: in the work area"
        );
        // Nothing to pin until the script runs: no star in the HTML.
        assert!(!html.contains("pin-button"), "{path}");
    }
}

#[tokio::test]
async fn item_and_vault_pages_name_what_to_pin() {
    let w = support::world().await;
    w.kv.state.put("db-password", "VALUE-1");
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    for (path, hook) in [
        (
            "/v/kv-test/secrets/db-password",
            "<h1 class=\"item-name\" data-pin=\"secret\" data-pin-vault=\"kv-test\" data-pin-name=\"db-password\">db-password</h1>",
        ),
        (
            "/v/kv-test/certificates/web-tls",
            "<h1 class=\"item-name\" data-pin=\"certificate\" data-pin-vault=\"kv-test\" data-pin-name=\"web-tls\">web-tls</h1>",
        ),
        (
            "/v/kv-test/keys/app-key",
            "<h1 class=\"item-name\" data-pin=\"key\" data-pin-vault=\"kv-test\" data-pin-name=\"app-key\">app-key</h1>",
        ),
        (
            "/v/kv-test/secrets",
            "<h1 data-pin=\"vault\" data-pin-vault=\"kv-test\">Secrets",
        ),
        (
            "/v/kv-test/certificates",
            "<h1 data-pin=\"vault\" data-pin-vault=\"kv-test\">Certificates",
        ),
        (
            "/v/kv-test/keys",
            "<h1 data-pin=\"vault\" data-pin-vault=\"kv-test\">Keys",
        ),
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(html.contains(hook), "{path}");
        assert!(
            !html.contains("pin-button"),
            "{path}: the star comes from the script"
        );
        assert!(
            !html.contains("data-pins hidden"),
            "{path}: lists are on home and vaults only"
        );
    }
}

#[tokio::test]
async fn sign_out_form_and_signed_out_page_clear_the_list() {
    let w = support::world().await;
    let (_, html) = w.page("/").await;
    assert!(html.contains("<form method=\"post\" action=\"/auth/sign-out\" data-pins-clear>"));
    let (status, out) = w.page("/auth/signed-out").await;
    assert_eq!(status, StatusCode::OK);
    assert!(out.contains("data-pins-signed-out"));
    pins_tag(&out);
}
