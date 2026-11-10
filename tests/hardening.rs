//! Security checks across every route that changes something.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Every POST route, with a name that exists in the seeded mock.
const MUTATING: &[&str] = &[
    "/vaults/select",
    "/secrets/new",
    "/secrets/db-password/value",
    "/secrets/db-password/edit",
    "/secrets/db-password/enabled",
    "/secrets/db-password/rollback",
    "/secrets/db-password/reveal",
    "/secrets/db-password/delete",
    "/secrets/deleted/old-secret/recover",
    "/secrets/deleted/old-secret/purge",
    "/certificates/upload",
    "/certificates/upload/confirm",
    "/certificates/new",
    "/certificates/web-tls/delete",
    "/certificates/web-tls/download-key",
    "/certificates/deleted/old-cert/recover",
    "/certificates/deleted/old-cert/purge",
    "/keys/new",
    "/keys/app-key/rotate",
    "/keys/app-key/rotation",
    "/keys/app-key/enabled",
    "/keys/app-key/delete",
    "/keys/deleted/old-key/recover",
    "/keys/deleted/old-key/purge",
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
    let name = if name == "deleted" {
        path.split('/').nth(3).unwrap_or_default()
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
        let status = if *path == "/certificates/upload" {
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
    let posts = src.matches("post(").count();
    assert_eq!(
        posts,
        MUTATING.len(),
        "routes::mod has {posts} post handlers; update MUTATING"
    );
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let w = support::world().await;
    let big = "a".repeat(100 * 1024);
    let res = w
        .post("/secrets/new", &[("name", "x"), ("value", &big)])
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
fn fixed_certificate_and_key_pages_are_reserved_names() {
    // Every fixed page beside `/certificates/{name}` and `/keys/{name}`
    // must be a name Keyring refuses on create and upload, or an object
    // with that name couldn't be opened.
    let src = include_str!("../src/routes/mod.rs");
    for (prefix, reserved) in [
        ("\"/certificates/", &["new", "deleted", "upload"][..]),
        ("\"/keys/", &["new", "deleted"][..]),
    ] {
        for chunk in src.split(prefix).skip(1) {
            let first = chunk.split(['/', '"']).next().unwrap_or_default();
            if first.starts_with('{') {
                continue;
            }
            assert!(
                reserved.contains(&first),
                "{prefix}{first} is a fixed page but not a reserved name"
            );
        }
    }
}
