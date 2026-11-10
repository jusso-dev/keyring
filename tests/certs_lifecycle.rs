//! Create, delete, recover and purge certificates.

mod support;

use axum::http::StatusCode;
use support::{body_text, location};

fn create_fields<'a>(name: &'a str, issuer: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("name", name),
        ("common_name", "app.example.com"),
        ("dns_names", "www.example.com"),
        ("validity_months", "12"),
        ("issuer", issuer),
        ("key", "RSA-2048"),
        ("exportable", "on"),
        ("format", "pfx"),
        ("renewal", "auto"),
        ("renew_days", "30"),
    ]
}

#[tokio::test]
async fn create_form_has_plain_help_and_defaults() {
    let w = support::world().await;
    let (status, html) = w.page("/certificates/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("RSA 2048 works with almost everything"));
    assert!(html.contains("Self for self-signed"));
    assert!(html.contains("value=\"12\""));
    assert!(
        html.contains("<details class=\"advanced\">"),
        "advanced options tucked away"
    );
}

#[tokio::test]
async fn self_signed_creates_and_shows_in_list() {
    let w = support::world().await;
    let res = w
        .post("/certificates/new", &create_fields("web-tls", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/certificates/web-tls");
    let body = w.kv.state.creates.lock().unwrap()[0].body.clone();
    assert_eq!(body["policy"]["issuer"]["name"], "Self");
    assert_eq!(
        body["policy"]["x509_props"]["subject"],
        "CN=app.example.com"
    );
    let sans = body["policy"]["x509_props"]["sans"]["dns_names"]
        .as_array()
        .unwrap()
        .clone();
    assert!(sans.contains(&"app.example.com".into()) && sans.contains(&"www.example.com".into()));
    let (_, html) = w.page("/certificates").await;
    assert!(html.contains(">web-tls<"));
}

#[tokio::test]
async fn ca_issued_shows_pending_status() {
    let w = support::world().await;
    let res = w
        .post(
            "/certificates/new",
            &create_fields("public-tls", "DigiCert-OV"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (status, html) = w.page("/certificates/public-tls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Certificate request: Waiting for the issuer"),
        "{html}"
    );
    assert!(html.contains("Waiting for the CA to approve the request."));
    assert!(html.contains("no issued certificate in this version yet"));
}

#[tokio::test]
async fn create_validation_and_existing_names() {
    let w = support::world().await;
    let mut f = create_fields("web tls", "Self");
    f[1] = ("common_name", "");
    let res = w.post("/certificates/new", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("spaces"));
    assert!(html.contains("Enter the main name"));
    assert!(w.kv.state.creates.lock().unwrap().is_empty());

    w.kv.state.add_cert("taken", false, "x");
    let res = w
        .post("/certificates/new", &create_fields("taken", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body_text(res)
            .await
            .contains("already a certificate called taken")
    );
}

#[tokio::test]
async fn delete_needs_typed_name_then_recover() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    let (_, html) = w.page("/certificates/web-tls/delete").await;
    assert!(html.contains("Type <strong class=\"mono\">web-tls</strong> to confirm"));
    let res = w
        .post("/certificates/web-tls/delete", &[("confirm_name", "web")])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(w.kv.state.certs.lock().unwrap().contains_key("web-tls"));

    let res = w
        .post(
            "/certificates/web-tls/delete",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!w.kv.state.certs.lock().unwrap().contains_key("web-tls"));
    let (_, html) = w.page("/certificates/deleted").await;
    assert!(html.contains(">web-tls<") && html.contains("Gone for good on"));

    let res = w.post("/certificates/deleted/web-tls/recover", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(support::location(&res), "/certificates/deleted");
    assert!(w.kv.state.certs.lock().unwrap().contains_key("web-tls"));
}

#[tokio::test]
async fn purge_off_by_default() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    w.post(
        "/certificates/web-tls/delete",
        &[("confirm_name", "web-tls")],
    )
    .await;
    let (_, html) = w.page("/certificates/deleted/web-tls").await;
    assert!(!html.contains("Permanently delete"));
    let (status, _) = w.page("/certificates/deleted/web-tls/purge").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let res = w
        .post(
            "/certificates/deleted/web-tls/purge",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        w.kv.state
            .deleted_certs
            .lock()
            .unwrap()
            .contains_key("web-tls")
    );
}

#[tokio::test]
async fn purge_when_enabled() {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    w.kv.state.add_cert("web-tls", false, "x");
    w.post(
        "/certificates/web-tls/delete",
        &[("confirm_name", "web-tls")],
    )
    .await;
    let (_, html) = w.page("/certificates/deleted/web-tls").await;
    assert!(html.contains("Permanently delete"));
    let res = w
        .post(
            "/certificates/deleted/web-tls/purge",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        !w.kv
            .state
            .deleted_certs
            .lock()
            .unwrap()
            .contains_key("web-tls")
    );
}

#[tokio::test]
async fn forged_tokens_refused() {
    let mut w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    w.csrf = "forged".into();
    let res = w
        .post("/certificates/new", &create_fields("new-one", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w
        .post(
            "/certificates/web-tls/delete",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.certs.lock().unwrap().contains_key("web-tls"));
}
