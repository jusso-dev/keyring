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
    let (status, html) = w.page("/certificates/-/new").await;
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
        .post("/certificates/-/new", &create_fields("web-tls", "Self"))
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
    w.kv.state
        .cert_extra
        .issuers
        .lock()
        .unwrap()
        .push("DigiCert-OV".into());
    let res = w
        .post(
            "/certificates/-/new",
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
    let res = w.post("/certificates/-/new", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("spaces"));
    assert!(html.contains("Enter the main name"));
    assert!(w.kv.state.creates.lock().unwrap().is_empty());

    w.kv.state.add_cert("taken", false, "x");
    let res = w
        .post("/certificates/-/new", &create_fields("taken", "Self"))
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
    let (_, html) = w.page("/certificates/-/deleted").await;
    assert!(html.contains(">web-tls<") && html.contains("Permanently deleted on"));

    let res = w.post("/certificates/-/deleted/web-tls/recover", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(support::location(&res), "/certificates/-/deleted");
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
    let (_, html) = w.page("/certificates/-/deleted/web-tls").await;
    assert!(!html.contains("/purge\""), "no purge link");
    let (status, _) = w.page("/certificates/-/deleted/web-tls/purge").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let res = w
        .post(
            "/certificates/-/deleted/web-tls/purge",
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
    let (_, html) = w.page("/certificates/-/deleted/web-tls").await;
    assert!(html.contains("Permanently delete"));
    let res = w
        .post(
            "/certificates/-/deleted/web-tls/purge",
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
        .post("/certificates/-/new", &create_fields("new-one", "Self"))
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

#[tokio::test]
async fn self_signed_is_created_in_progress_then_completes() {
    let w = support::world().await;
    *w.kv.state.cert_extra.hold_self_signed.lock().unwrap() = true;
    let res = w
        .post("/certificates/-/new", &create_fields("web-tls", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let flash = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join(";");
    assert!(!flash.is_empty());
    // Key Vault is still making it: the page says so, not "waiting for the issuer".
    let (status, html) = w.page("/certificates/web-tls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Certificate request: Being created"),
        "{html}"
    );
    assert!(html.contains("usually takes a few seconds"));
    assert!(html.contains("Check again"));
    assert!(!html.contains("Waiting for the issuer"));
    // A few seconds later it's done.
    *w.kv.state.cert_extra.hold_self_signed.lock().unwrap() = false;
    let (_, html) = w.page("/certificates/web-tls").await;
    assert!(!html.contains("Certificate request:"), "{html}");
    assert!(html.contains("CN=keyring.test"));
}

#[tokio::test]
async fn issuer_is_a_list_from_the_vault() {
    let w = support::world().await;
    w.kv.state
        .cert_extra
        .issuers
        .lock()
        .unwrap()
        .push("DigiCert-OV".into());
    let (_, html) = w.page("/certificates/-/new").await;
    assert!(html.contains("<select id=\"issuer\" name=\"issuer\""));
    assert!(html.contains("<option value=\"Self\" selected>"));
    assert!(html.contains("<option value=\"DigiCert-OV\">DigiCert-OV</option>"));
    // Unknown, or a name not on the vault, is refused before Key Vault.
    for issuer in ["Unknown", "Typo-CA"] {
        let res = w
            .post("/certificates/-/new", &create_fields("pub-tls", issuer))
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{issuer}");
        let html = body_text(res).await;
        assert!(html.contains("Pick an issuer from the list"), "{issuer}");
    }
    assert!(w.kv.state.creates.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issuer_list_refused_offers_self_only() {
    let w = support::world().await;
    *w.kv.state.fail_path.lock().unwrap() = Some("/certificates/issuers".into());
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = w.page("/certificates/-/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<option value=\"Self\" selected>"));
    assert!(
        html.contains("can&#39;t see this vault&#39;s issuers"),
        "{html}"
    );
    let res = w
        .post("/certificates/-/new", &create_fields("web-tls", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn pending_request_can_be_cancelled() {
    let w = support::world().await;
    w.kv.state
        .cert_extra
        .issuers
        .lock()
        .unwrap()
        .push("DigiCert-OV".into());
    w.post(
        "/certificates/-/new",
        &create_fields("pub-tls", "DigiCert-OV"),
    )
    .await;
    let (_, html) = w.page("/certificates/pub-tls").await;
    assert!(html.contains("action=\"/certificates/pub-tls/pending/cancel\""));
    let res = w.post("/certificates/pub-tls/pending/cancel", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let log = w.kv.state.log.lock().unwrap().clone();
    let patch = log
        .iter()
        .position(|l| l == "PATCH /kv-test/certificates/pub-tls/pending")
        .expect("cancellation requested");
    let delete = log
        .iter()
        .position(|l| l == "DELETE /kv-test/certificates/pub-tls/pending")
        .expect("operation deleted");
    assert!(patch < delete);
    assert!(
        w.kv.state.certs.lock().unwrap()["pub-tls"]
            .pending
            .is_none()
    );
    let (_, html) = w.page("/certificates/pub-tls").await;
    assert!(!html.contains("Certificate request:"));
}

#[tokio::test]
async fn existing_name_check_reads_both_key_vault_replies() {
    // Real Key Vault: 200 with an empty list for an unknown name.
    let w = support::world().await;
    let res = w
        .post("/certificates/-/new", &create_fields("fresh", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // Some replies are 404. Both mean the name is free.
    let w = support::world().await;
    *w.kv.state.cert_extra.versions_404.lock().unwrap() = true;
    let res = w
        .post("/certificates/-/new", &create_fields("fresh", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn names_that_were_fixed_pages_can_be_created_and_opened() {
    let w = support::world().await;
    for name in ["new", "deleted", "upload"] {
        let res = w
            .post("/certificates/-/new", &create_fields(name, "Self"))
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{name}");
        assert_eq!(location(&res), format!("/certificates/{name}"));
        let (status, html) = w.page(&format!("/certificates/{name}")).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert!(
            html.contains(&format!("<h1 class=\"mono\">{name}</h1>")),
            "{name}"
        );
    }
}

#[tokio::test]
async fn key_vault_400_keeps_the_form_and_shows_its_reason() {
    let w = support::world().await;
    *w.kv.state.fail_path.lock().unwrap() = Some("/create".into());
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post("/certificates/-/new", &create_fields("web-tls", "Self"))
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("Key Vault said:"));
    assert!(html.contains("mock Key Vault error with private detail"));
    assert!(html.contains("value=\"web-tls\""), "form kept");
    assert!(html.contains("value=\"app.example.com\""));
}

#[tokio::test]
async fn one_month_certificate_with_blank_renewal_is_accepted() {
    let w = support::world().await;
    let mut f = create_fields("short", "Self");
    f[3] = ("validity_months", "1");
    f[9] = ("renew_days", "");
    let res = w.post("/certificates/-/new", &f).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = w.kv.state.creates.lock().unwrap()[0].body.clone();
    assert_eq!(
        body["policy"]["lifetime_actions"][0]["trigger"]["days_before_expiry"],
        27
    );
}

#[tokio::test]
async fn delete_form_needs_the_certificate_to_exist() {
    let w = support::world().await;
    let (status, html) = w.page("/certificates/no-such-thing/delete").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!html.contains("to confirm"));
}

#[tokio::test]
async fn enable_and_disable() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    let (_, html) = w.page("/certificates/web-tls").await;
    // Disable goes through a confirmation page that posts here.
    assert!(html.contains("href=\"/certificates/web-tls/disable\">Disable<"));
    let (_, html) = w.page("/certificates/web-tls/disable").await;
    assert!(html.contains("action=\"/certificates/web-tls/enabled\""));
    let res = w
        .post("/certificates/web-tls/enabled", &[("state", "off")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!w.kv.state.certs.lock().unwrap()["web-tls"].versions[0].enabled);
    let (_, html) = w.page("/certificates/web-tls").await;
    assert!(html.contains(">Enable<"));
    let res = w
        .post("/certificates/web-tls/enabled", &[("state", "on")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(w.kv.state.certs.lock().unwrap()["web-tls"].versions[0].enabled);
    let res = w
        .post("/certificates/web-tls/enabled", &[("state", "maybe")])
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
