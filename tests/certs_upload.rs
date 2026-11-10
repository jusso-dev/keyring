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
    let res = w.post_multipart("/certificates/-/upload", &parts).await;
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
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
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
        body["policy"]["secret_props"]["contentType"],
        "application/x-pkcs12"
    );
    assert_eq!(body["policy"]["key_props"]["exportable"], true);
    assert_eq!(body["tags"]["env"], "prod");
    // The same upload can't be imported twice.
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
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
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn pfx_without_password_omits_it() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    w.post("/certificates/-/upload/confirm", &[("upload_id", &id)])
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
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = w.kv.state.imports.lock().unwrap()[0].body.clone();
    assert_eq!(
        body["policy"]["secret_props"]["contentType"],
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
            "/certificates/-/upload",
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
    *w.kv.state.cert_extra.pfx_password.lock().unwrap() = Some("test-password".into());
    let (_, html) = preview(
        &w,
        PLAIN,
        "web.pfx",
        &[Part::Text("password", "N0t-The-Passw0rd")],
    )
    .await;
    let id = hidden_value(&html, "upload_id").unwrap();
    // The mock answers a wrong PFX password with Key Vault's 400.
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("The password is probably wrong"));
    // The form comes back with its values, and Key Vault's reason.
    assert!(html.contains("value=\"web-tls\""));
    assert!(html.contains("Key Vault said:"));
    assert!(html.contains("can not be read"));
    assert!(
        !html.contains("N0t-The-Passw0rd"),
        "the password is not echoed"
    );
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn upload_needs_the_form_token() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    let (status, _) = preview(&w, PLAIN, "web.pfx", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", "x")])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_upload_id_is_refused() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let _real = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post(
            "/certificates/-/upload/confirm",
            &[("upload_id", "guessed")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::GONE);
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

const CHAIN: &str = include_str!("fixtures/test-chain.pem");

#[tokio::test]
async fn oversized_file_says_so_and_keeps_the_form() {
    let w = support::world().await;
    // Just over the file limit but under the body limit: the rest of the
    // fields after the file are still read.
    let big = vec![0u8; 260 * 1024];
    let (status, html) = preview(&w, &big, "big.pfx", &[Part::Text("tags", "team=web")]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{html}");
    assert!(html.contains("id=\"file-error\""), "{html}");
    assert!(html.contains("That file is over 256 KB"));
    assert!(html.contains("value=\"web-tls\""));
    assert!(html.contains("team=web"), "fields after the file are kept");
    assert!(html.contains("id=\"enabled\" name=\"enabled\" type=\"checkbox\" checked"));

    // Over the whole request limit: the body is cut off, but the size
    // message still shows and the tick boxes are as the form first opened.
    let huge = vec![0u8; 300 * 1024];
    let (status, html) = preview(&w, &huge, "huge.pfx", &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("id=\"file-error\""));
    assert!(html.contains("That file is over 256 KB"));
    assert!(html.contains("id=\"enabled\" name=\"enabled\" type=\"checkbox\" checked"));
    assert!(html.contains("id=\"exportable\" name=\"exportable\" type=\"checkbox\" checked"));
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn oversized_upload_with_a_forged_token_reaches_nothing() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    // Under the body limit the token arrives and is refused.
    let big = vec![0u8; 260 * 1024];
    let (status, _) = preview(&w, &big, "big.pfx", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Over it the body may stop before the token; the size message shows,
    // and Key Vault isn't asked anything.
    let huge = vec![0u8; 300 * 1024];
    let (status, html) = preview(&w, &huge, "huge.pfx", &[]).await;
    assert_ne!(status, StatusCode::OK);
    assert!(!html.contains("upload_id"));
    assert!(w.kv.state.log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn uploading_onto_an_existing_name_says_so() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "x");
    let (status, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("There's already a certificate called web-tls"),
        "{html}"
    );
    assert!(html.contains("Current thumbprint"));
    assert!(html.contains("Upload as a new version"));
    // A free name gets the usual button.
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[Part::Text("name", "other-tls")]).await;
    assert!(!html.contains("already a certificate"));
    let id = hidden_value(&html, "upload_id").unwrap();
    w.post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
}

#[tokio::test]
async fn pem_keys_key_vault_refuses_are_caught_at_preview() {
    let w = support::world().await;
    let pkcs1 =
        format!("{CERT}-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n");
    let (status, html) = preview(&w, pkcs1.as_bytes(), "web.pem", &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("openssl pkcs8 -topk8 -nocrypt"), "{html}");
    let sec1 =
        format!("{CERT}-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n");
    let (status, html) = preview(&w, sec1.as_bytes(), "web.pem", &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("PKCS #8"));
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pem_refused_by_key_vault_gets_pem_advice() {
    let w = support::world().await;
    let (_, html) = preview(&w, BUNDLE.as_bytes(), "web.pem", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    *w.kv.state.fail_path.lock().unwrap() = Some("/import".into());
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("unencrypted PKCS #8"), "{html}");
    assert!(!html.contains("password is probably wrong"));
    assert!(html.contains("Key Vault said:"));
}

#[tokio::test]
async fn the_mock_refuses_a_pkcs1_pem_import_like_key_vault() {
    // Straight to the mock over plain HTTP: Key Vault answers 400 for a
    // PKCS #1 key in a PEM import.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = support::world().await;
    let body = serde_json::json!({
        "value": format!("{CERT}-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"),
        "policy": {"secret_props": {"contentType": "application/x-pem-file"}}
    })
    .to_string();
    let addr = w.kv.url().trim_start_matches("http://").to_owned();
    let mut conn = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let req = format!(
        "POST /kv-test/certificates/x/import?api-version=7.5 HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(req.as_bytes()).await.unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn opening_the_form_or_starting_again_forgets_the_file() {
    let w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    assert!(html.contains("action=\"/certificates/-/upload/cancel\""));
    let (status, _) = w.page("/certificates/-/upload").await;
    assert_eq!(status, StatusCode::OK);
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::GONE, "GET dropped the file");

    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w.post("/certificates/-/upload/cancel", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/certificates/-/upload");
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(
        res.status(),
        StatusCode::GONE,
        "Start again dropped the file"
    );
    assert!(w.kv.state.imports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_forged_confirm_leaves_the_file_waiting() {
    let mut w = support::world().await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    let real = std::mem::replace(&mut w.csrf, "forged".into());
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w.post("/certificates/-/upload/cancel", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    w.csrf = real;
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn names_that_were_fixed_pages_can_be_uploaded() {
    let w = support::world().await;
    for name in ["upload", "new", "deleted"] {
        let (status, html) = preview(&w, PLAIN, "web.pfx", &[Part::Text("name", name)]).await;
        // The helper sends `web-tls` first; the later field wins.
        assert_eq!(status, StatusCode::OK, "{name}");
        assert!(!html.contains("own pages"), "{name}");
    }
}

#[tokio::test]
async fn preview_describes_the_leaf_not_the_ca() {
    let w = support::world().await;
    let key = BUNDLE.split("-----BEGIN PRIVATE KEY-----").nth(1).unwrap();
    let pem = format!("{CHAIN}-----BEGIN PRIVATE KEY-----{key}");
    let (status, html) = preview(&w, pem.as_bytes(), "chain.pem", &[]).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    let subject = html.find("CN=leaf.keyring.test").unwrap();
    let also = html.find("Also in the file").unwrap();
    let ca = html.rfind("CN=Keyring Test CA").unwrap();
    assert!(subject < also && also < ca, "leaf first, CA listed after");
    assert!(!html.contains("couldn't tell which certificate"));
}

#[tokio::test]
async fn password_notice_only_when_a_password_was_given() {
    let w = support::world().await;
    let (_, html) = preview(&w, ENCRYPTED, "web.p12", &[]).await;
    assert!(!html.contains("protected by its password"));
    assert!(html.contains("If the file has a password, start again"));
}

#[tokio::test]
async fn ber_encoded_pfx_can_still_be_uploaded() {
    let w = support::world().await;
    // Re-write the outer SEQUENCE with an indefinite length.
    let len_bytes = (PLAIN[1] & 0x7f) as usize;
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&PLAIN[2 + len_bytes..]);
    ber.extend_from_slice(&[0, 0]);
    let (status, html) = preview(&w, &ber, "old.pfx", &[]).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains("Keyring can't show what's in this file, but Key Vault may still accept it"),
        "{html}"
    );
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn import_409_names_the_deleted_certificate() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    w.post(
        "/certificates/web-tls/delete",
        &[("confirm_name", "web-tls")],
    )
    .await;
    let (_, html) = preview(&w, PLAIN, "web.pfx", &[]).await;
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post("/certificates/-/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let html = body_text(res).await;
    assert!(html.contains("A deleted certificate called web-tls can still be recovered"));
}
