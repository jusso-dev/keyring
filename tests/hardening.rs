//! Security checks across every route that changes something.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Every POST route, with a name that exists in the seeded mock.
const MUTATING: &[&str] = &[
    "/vaults/select",
    "/secrets/-/new",
    "/secrets/db-password/value",
    "/secrets/db-password/edit",
    "/secrets/db-password/enabled",
    "/secrets/db-password/rollback",
    "/secrets/db-password/reveal",
    "/secrets/db-password/delete",
    "/secrets/-/deleted/old-secret/recover",
    "/secrets/-/deleted/old-secret/purge",
    "/certificates/-/upload",
    "/certificates/-/upload/confirm",
    "/certificates/-/upload/cancel",
    "/certificates/-/new",
    "/certificates/web-tls/enabled",
    "/certificates/web-tls/pending/cancel",
    "/certificates/web-tls/delete",
    "/certificates/web-tls/download-key",
    "/certificates/-/deleted/old-cert/recover",
    "/certificates/-/deleted/old-cert/purge",
    "/keys/-/new",
    "/keys/app-key/rotate",
    "/keys/app-key/rotation",
    "/keys/app-key/enabled",
    "/keys/app-key/delete",
    "/keys/-/deleted/old-key/recover",
    "/keys/-/deleted/old-key/purge",
    "/generator",
    "/auth/sign-out",
];

async fn seeded() -> support::World {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    let s = &w.kv.state;
    let v1 = s.put("db-password", "one");
    s.put("db-password", "two");
    s.put("old-secret", "x");
    s.soft_delete("old-secret");
    s.add_cert("web-tls", true, "UEZY");
    s.add_cert("old-cert", false, "x");
    w.post(
        "/certificates/old-cert/delete",
        &[("confirm_name", "old-cert")],
    )
    .await;
    s.add_key_with("app-key", "RSA", |_| {});
    s.add_key_with("old-key", "RSA", |_| {});
    w.post("/keys/old-key/delete", &[("confirm_name", "old-key")])
        .await;
    let _ = v1;
    w
}

/// A form body that would succeed if the checks weren't there.
fn fields_for(path: &str) -> Vec<(&'static str, String)> {
    let name = path
        .split('/')
        .filter(|p| !p.is_empty())
        .nth(1)
        .unwrap_or_default();
    // `/secrets/-/deleted/{name}/...`
    let name = if name == "-" {
        path.split('/').nth(4).unwrap_or_default()
    } else {
        name
    };
    vec![
        ("confirm_name", name.to_owned()),
        ("name", "new-item".into()),
        ("value", "v".into()),
        ("state", "off".into()),
        ("enabled", "on".into()),
        ("kind", "guid".into()),
        ("common_name", "a.example.com".into()),
        ("validity_months", "12".into()),
    ]
}

async fn post_raw(w: &support::World, path: &str, csrf: &str, origin: Option<&str>) -> StatusCode {
    let mut all: Vec<(&str, String)> = vec![("csrf", csrf.to_owned())];
    all.extend(fields_for(path));
    let body: String = openidconnect::url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(all.iter().map(|(k, v)| (*k, v.as_str())))
        .finish();
    let mut req = Request::post(path)
        .header("cookie", &w.cookie)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    w.app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

fn kv_snapshot(w: &support::World) -> String {
    let s = &w.kv.state;
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?}",
        s.secrets
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (
                k.clone(),
                v.versions.len(),
                v.versions.last().map(|x| x.enabled)
            ))
            .collect::<Vec<_>>(),
        s.deleted.lock().unwrap().keys().collect::<Vec<_>>(),
        s.certs.lock().unwrap().keys().collect::<Vec<_>>(),
        s.deleted_certs.lock().unwrap().keys().collect::<Vec<_>>(),
        s.keys
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.versions.len()))
            .collect::<Vec<_>>(),
        s.deleted_keys.lock().unwrap().keys().collect::<Vec<_>>(),
    )
}

#[tokio::test]
async fn every_mutating_route_refuses_a_forged_token() {
    let w = seeded().await;
    let before = kv_snapshot(&w);
    let reads_before = w.kv.state.value_reads().len();
    for path in MUTATING {
        let status = if *path == "/certificates/-/upload" {
            // Multipart, with a real file, so only the token is wrong.
            let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
            w.post_multipart_with_csrf(
                "forged-token",
                path,
                &[
                    support::Part::File("file", "a.pfx", pfx),
                    support::Part::Text("name", "new-cert"),
                ],
            )
            .await
            .status()
        } else {
            post_raw(&w, path, "forged-token", Some("http://localhost:3000")).await
        };
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(kv_snapshot(&w), before, "nothing changed in Key Vault");
    assert_eq!(
        w.kv.state.value_reads().len(),
        reads_before,
        "no values read"
    );
}

#[tokio::test]
async fn every_mutating_route_refuses_cross_site_posts() {
    let w = seeded().await;
    let before = kv_snapshot(&w);
    let csrf = w.csrf.clone();
    for origin in [
        Some("https://evil.example"),
        Some("http://localhost:3000.evil.example"),
        None,
    ] {
        for path in MUTATING {
            // Even with the right token, a post from another site is refused.
            let status = post_raw(&w, path, &csrf, origin).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} from {origin:?}");
        }
    }
    assert_eq!(kv_snapshot(&w), before);
}

#[tokio::test]
async fn mutating_routes_list_is_complete() {
    // Any new POST route must be added to MUTATING above.
    let src = include_str!("../src/routes/mod.rs");
    // The posts on item pages only redirect old form addresses (#99) and
    // change nothing; `tests/moved_pages.rs` covers them.
    let redirects = src.matches("post(moved::post_item)").count();
    assert_eq!(redirects, 3);
    let posts = src.matches("post(").count() - redirects;
    assert_eq!(
        posts,
        MUTATING.len(),
        "routes::mod has {posts} post handlers; update MUTATING"
    );
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let w = support::world().await;
    let big = "a".repeat(300 * 1024);
    let res = w
        .post("/secrets/-/new", &[("name", "x"), ("value", &big)])
        .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn headers_on_every_kind_of_response() {
    let w = seeded().await;
    let pages = [
        "/",
        "/vaults",
        "/secrets",
        "/secrets/db-password",
        "/certificates",
        "/keys",
        "/expiry",
        "/generator",
        "/audit",
        "/nope",
        "/auth/sign-in",
        "/healthz",
        "/static/app.js",
    ];
    for path in pages {
        let res = w.get(path).await;
        let h = res.headers();
        let csp = h
            .get("content-security-policy")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        assert!(
            csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
            "{path}: {csp}"
        );
        assert!(!csp.contains("unsafe-"), "{path}");
        assert_eq!(
            h.get("x-content-type-options").unwrap(),
            "nosniff",
            "{path}"
        );
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY", "{path}");
        assert_eq!(h.get("referrer-policy").unwrap(), "same-origin", "{path}");
    }
}

#[test]
fn no_unsafe_code() {
    let toml = include_str!("../Cargo.toml");
    assert!(toml.contains("unsafe_code = \"forbid\""));
}

/// What a real browser sends on a same-origin form post under Keyring's
/// own referrer policy: `Sec-Fetch-Site`, an `Origin`, and (with
/// `same-origin`) a same-site `Referer`. Older browsers send only the last
/// two. Both must be accepted.
#[tokio::test]
async fn browser_shaped_same_origin_posts_are_accepted() {
    let w = support::world().await;
    for headers in [
        vec![
            ("sec-fetch-site", "same-origin"),
            ("origin", "http://localhost:3000"),
        ],
        vec![("sec-fetch-site", "same-origin"), ("origin", "null")],
        vec![
            ("origin", "http://localhost:3000"),
            ("referer", "http://localhost:3000/generator"),
        ],
        vec![("referer", "http://localhost:3000/generator")],
    ] {
        let body = format!("csrf={}&kind=guid", w.csrf);
        let mut req = Request::post("/generator")
            .header("cookie", &w.cookie)
            .header("content-type", "application/x-www-form-urlencoded");
        for (k, v) in &headers {
            req = req.header(*k, *v);
        }
        let res = w
            .app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{headers:?}");
    }
    // And the referrer policy the pages send keeps Origin and Referer on
    // same-origin requests.
    let res = w.get("/generator").await;
    let policy = res
        .headers()
        .get("referrer-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        matches!(
            policy,
            "same-origin" | "strict-origin" | "strict-origin-when-cross-origin"
        ),
        "{policy}"
    );
}

#[test]
fn fixed_pages_cant_collide_with_item_names() {
    // Every fixed page beside `/secrets/{name}`, `/certificates/{name}` and
    // `/keys/{name}` must sit under `/-/`, which Key Vault can't use as a
    // name, or an item with that name couldn't be opened.
    let src = include_str!("../src/routes/mod.rs");
    for prefix in ["\"/secrets/", "\"/certificates/", "\"/keys/"] {
        for chunk in src.split(prefix).skip(1) {
            let first = chunk.split(['/', '"']).next().unwrap_or_default();
            assert!(
                first == "{name}" || first == "-",
                "{prefix}{first} is a fixed page that could be an item name"
            );
        }
    }
}

#[tokio::test]
async fn static_files_are_versioned_and_cached_for_a_year() {
    let w = support::world().await;
    let (_, html) = w.page("/").await;
    let start = html
        .find("/static/app.js?v=")
        .expect("versioned script tag");
    let url = &html[start..];
    let url = &url[..url.find('"').unwrap()];
    let res = w.get(url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("cache-control").unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert!(html.contains("/static/style.css?v="));
    // Pages left open across an upgrade still get the file, briefly cached.
    for old in ["/static/app.js", "/static/app.js?v=0123456789abcdef"] {
        let res = w.get(old).await;
        assert_eq!(res.status(), StatusCode::OK, "{old}");
        assert_eq!(
            res.headers().get("cache-control").unwrap(),
            "public, max-age=300",
            "{old}"
        );
    }
}

#[tokio::test]
async fn favicon_is_a_short_empty_answer() {
    let w = support::world().await;
    let res = w.get("/favicon.ico").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(support::body_text(res).await.is_empty());
}

#[tokio::test]
async fn cross_site_refusal_is_a_styled_page() {
    let w = support::world().await;
    let req = Request::post("/generator")
        .header("cookie", &w.cookie)
        .header("origin", "https://evil.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={}&kind=guid", w.csrf)))
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        res.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let html = support::body_text(res).await;
    assert!(html.contains("<html lang=\"en-AU\">"));
    assert!(html.contains("/static/style.css?v="));
    assert!(html.contains("didn't come from Keyring"));
    assert!(html.contains("href=\"/\">Back to home</a>"));
}
