//! Certificate upload: check, preview, import.

mod support;

use axum::http::StatusCode;
use base64::Engine;
use support::{Part, body_text, hidden_value, location};

const PLAIN: &[u8] = include_bytes!("fixtures/test-plain.pfx");
const ENCRYPTED: &[u8] = include_bytes!("fixtures/test-encrypted.pfx");
const BUNDLE: &str = include_str!("fixtures/test-bundle.pem");
const CERT: &str = include_str!("fixtures/test-cert.pem");

async fn preview(
    w: &support::World,
    file: &[u8],
    file_name: &str,
    extra: &[Part<'_>],
) -> (StatusCode, String) {
    let mut parts = vec![
        Part::File("file", file_name, file),
        Part::Text("name", "web-tls"),
        Part::Text("enabled", "on"),
        Part::Text("exportable", "on"),
    ];
    for p in extra {
        parts.push(match p {
            Part::Text(a, b) => Part::Text(a, b),
            Part::File(a, b, c) => Part::File(a, b, c),
        });
    }
    let res = w.post_multipart("/certificates/upload", &parts).await;
    let status = res.status();
    (status, body_text(res).await)
}

#[tokio::test]
async fn pfx_with_password_previews_then_imports() {
    let w = support::world().await;
    let (status, html) = preview(
        &w,
        PLAIN,
        "web.pfx",
        &[
            Part::Text("password", "test-password"),
            Part::Text("tags", "env=prod"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains("CN=keyring.test"),
        "subject shown before confirming"
    );
    assert!(html.contains("Valid until"));
    assert!(html.contains("Nothing has been saved yet"));
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
    // The file and password never come back to the browser.
    assert!(!html.contains("test-password"));
    assert!(!html.contains(&base64::engine::general_purpose::STANDARD.encode(PLAIN)[..40]));

    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/certificates/web-tls");
    let imports = w.kv.state.imports.lock().unwrap().clone();
    assert_eq!(imports.len(), 1);
    let body = &imports[0].body;
    assert_eq!(body["pwd"], "test-password");
    assert_eq!(
        body["value"],
        base64::engine::general_purpose::STANDARD.encode(PLAIN)
    );
    assert_eq!(
        body["policy"]["secretProps"]["contentType"],
        "application/x-pkcs12"
    );
    assert_eq!(body["policy"]["keyProps"]["exportable"], true);
    assert_eq!(body["tags"]["env"], "prod");
    // The same upload can't be imported twice.
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::GONE);
}

#[tokio::test]
async fn pfx_without_readable_certs_still_imports() {
    let w = support::world().await;
    let (status, html) = preview(
        &w,
        ENCRYPTED,
        "web.p12",
        &[Part::Text("password", "test-password")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("protected by its password"));
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn pfx_without_password_omits_it() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    w.post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    let body = w.kv.state.imports.lock().unwrap()[0].body.clone();
    assert!(body.get("pwd").is_none());
}

#[tokio::test]
async fn pem_with_cert_and_key_imports() {
    let w = support::world().await;
    let (status, html) = preview(&w, BUNDLE.as_bytes(), "web.pem", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("CN=keyring.test"));
    assert!(!html.contains("PRIVATE KEY"));
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = w.kv.state.imports.lock().unwrap()[0].body.clone();
    assert_eq!(
        body["policy"]["secretProps"]["contentType"],
        "application/x-pem-file"
    );
    assert_eq!(body["value"], BUNDLE);
    // It shows up in the list.
    let (_, html) = w.page("/certificates").await;
    assert!(html.contains(">web-tls<"));
}

#[tokio::test]
async fn bad_files_get_plain_errors() {
    let w = support::world().await;
    for (bytes, file_name, expect) in [
        (CERT.as_bytes(), "only.pem", "no private key"),
        (
            b"just some text".as_slice(),
            "x.pfx",
            "can&#39;t read this file",
        ),
        (b"".as_slice(), "empty.pfx", "Choose a file"),
    ] {
        let (status, html) = preview(&w, bytes, file_name, &[]).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{file_name}");
        assert!(html.contains(expect), "{file_name}: {expect}");
    }
    let big = vec![0u8; 300 * 1024];
    let (status, html) = preview(&w, &big, "big.pfx", &[]).await;
    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::PAYLOAD_TOO_LARGE,
        "{status}"
    );
    if status == StatusCode::UNPROCESSABLE_ENTITY {
        assert!(html.contains("KB"));
    }
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bad_name_keeps_other_fields_not_the_password() {
    let w = support::world().await;
    let res = w
        .post_multipart(
            "/certificates/upload",
            &[
                Part::File("file", "web.pfx", PLAIN),
                Part::Text("name", "web tls"),
                Part::Text("password", "test-password"),
                Part::Text("tags", "team=web"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("spaces"));
    assert!(html.contains("team=web"));
    assert!(!html.contains("test-password"));
}

#[tokio::test]
async fn wrong_password_is_explained() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[Part::Text("password", "wrong")]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("The password is probably wrong"));
    assert!(!html.contains("private detail"));
}

#[tokio::test]
async fn upload_needs_the_form_token() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    let (status, _) = preview(&w, PLAIN, "web.pfx", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", "x")])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_upload_id_is_refused() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let _real = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/upload/confirm", &[("upload_id", "guessed")])
        .await;
    assert_eq!(res.status(), StatusCode::GONE);
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}
