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
    let (status, html) = w.page("/v/kv-test/certificates/-/new").await;
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
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("web-tls", "Self"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/certificates/web-tls");
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
    let (_, html) = w.page("/v/kv-test/certificates").await;
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
            "/v/kv-test/certificates/-/new",
            &create_fields("public-tls", "DigiCert-OV"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (status, html) = w.page("/v/kv-test/certificates/public-tls").await;
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
    let res = w.post("/v/kv-test/certificates/-/new", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("spaces"));
    assert!(html.contains("Enter the main name"));
    assert!(w.kv.state.creates.lock().unwrap().is_empty());

    w.kv.state.add_cert("taken", false, "x");
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("taken", "Self"),
        )
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
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/delete").await;
    assert!(html.contains("Type <strong class=\"mono\">web-tls</strong> to confirm"));
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/delete",
            &[("confirm_name", "web")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(w.kv.state.certs.lock().unwrap().contains_key("web-tls"));

    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/delete",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!w.kv.state.certs.lock().unwrap().contains_key("web-tls"));
    let (_, html) = w.page("/v/kv-test/certificates/-/deleted").await;
    assert!(html.contains(">web-tls<") && html.contains("Permanently deleted on"));

    let res = w
        .post("/v/kv-test/certificates/-/deleted/web-tls/recover", &[])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(support::location(&res), "/v/kv-test/certificates/-/deleted");
    assert!(w.kv.state.certs.lock().unwrap().contains_key("web-tls"));
}

#[tokio::test]
async fn purge_off_by_default() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    w.post(
        "/v/kv-test/certificates/web-tls/delete",
        &[("confirm_name", "web-tls")],
    )
    .await;
    let (_, html) = w.page("/v/kv-test/certificates/-/deleted/web-tls").await;
    assert!(!html.contains("/purge\""), "no purge link");
    assert!(html.contains("Deleted certificates in this vault can be recovered for 90 days."));
    assert!(
        !html.contains("its value"),
        "only secrets bring back a value"
    );
    let (status, _) = w
        .page("/v/kv-test/certificates/-/deleted/web-tls/purge")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let res = w
        .post(
            "/v/kv-test/certificates/-/deleted/web-tls/purge",
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
        "/v/kv-test/certificates/web-tls/delete",
        &[("confirm_name", "web-tls")],
    )
    .await;
    let (_, html) = w.page("/v/kv-test/certificates/-/deleted/web-tls").await;
    assert!(html.contains("Permanently delete"));
    let res = w
        .post(
            "/v/kv-test/certificates/-/deleted/web-tls/purge",
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
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("new-one", "Self"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/delete",
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
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("web-tls", "Self"),
        )
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
    let (status, html) = w.page("/v/kv-test/certificates/web-tls").await;
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
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
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
    let (_, html) = w.page("/v/kv-test/certificates/-/new").await;
    assert!(html.contains("<select id=\"issuer\" name=\"issuer\""));
    assert!(html.contains("<option value=\"Self\" selected>"));
    assert!(html.contains("<option value=\"DigiCert-OV\">DigiCert-OV</option>"));
    // Unknown, or a name not on the vault, is refused before Key Vault.
    for issuer in ["Unknown", "Typo-CA"] {
        let res = w
            .post(
                "/v/kv-test/certificates/-/new",
                &create_fields("pub-tls", issuer),
            )
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
    let (status, html) = w.page("/v/kv-test/certificates/-/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<option value=\"Self\" selected>"));
    assert!(
        html.contains("can&#39;t see this vault&#39;s issuers"),
        "{html}"
    );
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("web-tls", "Self"),
        )
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
        "/v/kv-test/certificates/-/new",
        &create_fields("pub-tls", "DigiCert-OV"),
    )
    .await;
    let (_, html) = w.page("/v/kv-test/certificates/pub-tls").await;
    assert!(html.contains("action=\"/v/kv-test/certificates/pub-tls/pending/cancel\""));
    let res = w
        .post("/v/kv-test/certificates/pub-tls/pending/cancel", &[])
        .await;
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
    let (_, html) = w.page("/v/kv-test/certificates/pub-tls").await;
    assert!(!html.contains("Certificate request:"));
}

#[tokio::test]
async fn existing_name_check_reads_both_key_vault_replies() {
    // Real Key Vault: 200 with an empty list for an unknown name.
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("fresh", "Self"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // Some replies are 404. Both mean the name is free.
    let w = support::world().await;
    *w.kv.state.cert_extra.versions_404.lock().unwrap() = true;
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("fresh", "Self"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn names_that_were_fixed_pages_can_be_created_and_opened() {
    let w = support::world().await;
    for name in ["new", "deleted", "upload"] {
        let res = w
            .post(
                "/v/kv-test/certificates/-/new",
                &create_fields(name, "Self"),
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{name}");
        assert_eq!(location(&res), format!("/v/kv-test/certificates/{name}"));
        let (status, html) = w.page(&format!("/v/kv-test/certificates/{name}")).await;
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
        .post(
            "/v/kv-test/certificates/-/new",
            &create_fields("web-tls", "Self"),
        )
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
    let res = w.post("/v/kv-test/certificates/-/new", &f).await;
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
    let (status, html) = w.page("/v/kv-test/certificates/no-such-thing/delete").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!html.contains("to confirm"));
}

#[tokio::test]
async fn enable_and_disable() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    // Disable goes through a confirmation page that posts here.
    assert!(html.contains("href=\"/v/kv-test/certificates/web-tls/disable\">Disable<"));
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/disable").await;
    assert!(html.contains("action=\"/v/kv-test/certificates/web-tls/enabled\""));
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/enabled",
            &[("state", "off")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!w.kv.state.certs.lock().unwrap()["web-tls"].versions[0].enabled);
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(html.contains(">Enable<"));
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/enabled",
            &[("state", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(w.kv.state.certs.lock().unwrap()["web-tls"].versions[0].enabled);
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/enabled",
            &[("state", "maybe")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// Put a lifetime action list and issuer on a certificate the mock holds.
fn set_policy(w: &support::World, name: &str, actions: serde_json::Value, issuer: &str) {
    let mut certs = w.kv.state.certs.lock().unwrap();
    let p = &mut certs.get_mut(name).unwrap().policy;
    p["lifetime_actions"] = actions;
    p["issuer"] = serde_json::json!({ "name": issuer });
}

fn auto_30() -> serde_json::Value {
    serde_json::json!([{"trigger": {"days_before_expiry": 30}, "action": {"action_type": "AutoRenew"}}])
}

fn policy_of(w: &support::World, name: &str) -> serde_json::Value {
    w.kv.state.certs.lock().unwrap()[name].policy.clone()
}

fn patches(w: &support::World) -> usize {
    w.kv.state.cert_extra.policy_patches.lock().unwrap().len()
}

fn flash_cookie(res: &axum::http::Response<axum::body::Body>) -> Option<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_flash="))
}

#[tokio::test]
async fn renewal_form_is_prefilled_from_the_policy() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(
        html.contains("href=\"/v/kv-test/certificates/web-tls/renewal\">Change<"),
        "{html}"
    );
    let (status, html) = w.page("/v/kv-test/certificates/web-tls/renewal").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("action=\"/v/kv-test/certificates/web-tls/renewal\""));
    assert!(
        html.contains("id=\"renew-auto\" name=\"renewal\" type=\"radio\" value=\"auto\" checked")
    );
    assert!(
        html.contains("name=\"renew_days\" type=\"number\" min=\"1\" max=\"324\" value=\"30\"")
    );
    assert!(
        !html.contains("can't show"),
        "no warning for a plain policy"
    );
    // A percentage trigger is shown with a warning that saving replaces it.
    set_policy(
        &w,
        "web-tls",
        serde_json::json!([{"trigger": {"lifetime_percentage": 80}, "action": {"action_type": "AutoRenew"}}]),
        "Self",
    );
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/renewal").await;
    assert!(html.contains("80% of the certificate"), "{html}");
    assert!(html.contains("Saving replaces it"));
}

#[tokio::test]
async fn renewal_can_be_changed_to_email() {
    let mut w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    let before = policy_of(&w, "web-tls");
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "email"), ("renew_days", "14")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/certificates/web-tls");
    let flash = flash_cookie(&res).unwrap();
    let after = policy_of(&w, "web-tls");
    assert_eq!(
        after["lifetime_actions"][0]["action"]["action_type"],
        "EmailContacts"
    );
    assert_eq!(
        after["lifetime_actions"][0]["trigger"]["days_before_expiry"],
        14
    );
    assert_eq!(after["lifetime_actions"].as_array().unwrap().len(), 1);
    // Only the lifetime actions were sent, and nothing else changed.
    let sent = w.kv.state.cert_extra.policy_patches.lock().unwrap()[0].clone();
    assert_eq!(sent.as_object().unwrap().len(), 1, "{sent}");
    let mut expected = before;
    expected["lifetime_actions"] = after["lifetime_actions"].clone();
    assert_eq!(after, expected);
    w.cookie = format!("{}; {flash}", w.cookie);
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(
        html.contains("Saved what happens near expiry for web-tls."),
        "{html}"
    );
    assert!(
        html.contains("Emails the vault&#39;s contacts 14 days before it expires"),
        "{html}"
    );
}

#[tokio::test]
async fn renewal_can_be_turned_off() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "none"), ("renew_days", "")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        policy_of(&w, "web-tls")["lifetime_actions"],
        serde_json::json!([])
    );
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(html.contains("Nothing happens automatically"), "{html}");
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/renewal").await;
    assert!(
        html.contains("id=\"renew-none\" name=\"renewal\" type=\"radio\" value=\"none\" checked")
    );
}

#[tokio::test]
async fn renewal_days_above_the_limit_are_refused_before_key_vault() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    // The mock policy is valid for 12 months: 12 x 27 = 324.
    for days in ["325", "0", "-1", "abc"] {
        let res = w
            .post(
                "/v/kv-test/certificates/web-tls/renewal",
                &[("renewal", "auto"), ("renew_days", days)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{days}");
        let html = body_text(res).await;
        assert!(
            html.contains("Pick a number of days from 1 to 324"),
            "{days}"
        );
        assert!(html.contains("id=\"renew_days-error\""), "{days}");
    }
    assert_eq!(patches(&w), 0, "nothing reached Key Vault");
    assert_eq!(policy_of(&w, "web-tls")["lifetime_actions"], auto_30());
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "auto"), ("renew_days", "324")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn imported_certificates_cannot_be_set_to_renew() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Unknown");
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/renewal").await;
    assert!(html.contains("signed outside Key Vault"), "{html}");
    assert!(
        html.contains("id=\"renew-auto\" name=\"renewal\" type=\"radio\" value=\"auto\" disabled")
    );
    assert!(
        html.contains("id=\"renew-email\" name=\"renewal\" type=\"radio\" value=\"email\" checked")
    );
    // The server refuses it too, whatever the form says.
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "auto"), ("renew_days", "30")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("id=\"renewal-error\""), "{html}");
    assert_eq!(patches(&w), 0);
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "email"), ("renew_days", "30")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn renewal_needs_a_good_token_and_a_real_choice() {
    let mut w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    w.csrf = "forged".into();
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "none")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    w.csrf = String::new();
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "none")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(patches(&w), 0);
    assert_eq!(policy_of(&w, "web-tls")["lifetime_actions"], auto_30());
    // With a good token, an unknown choice is a field error.
    let w2 = support::world().await;
    w2.kv.state.add_cert("web-tls", false, "x");
    let res = w2
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "sometimes")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(patches(&w2), 0);
}

#[tokio::test]
async fn renewal_key_vault_400_shows_its_reason() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    set_policy(&w, "web-tls", auto_30(), "Self");
    *w.kv.state.fail_path.lock().unwrap() = Some("/policy".into());
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::PATCH);
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/renewal",
            &[("renewal", "email"), ("renew_days", "14")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("Key Vault said:"), "{html}");
    assert!(html.contains("mock Key Vault error with private detail"));
    assert!(
        html.contains("id=\"renew-email\" name=\"renewal\" type=\"radio\" value=\"email\" checked")
    );
    assert!(html.contains("value=\"14\""), "form kept");
    assert_eq!(policy_of(&w, "web-tls")["lifetime_actions"], auto_30());
}

#[tokio::test]
async fn renewal_for_a_missing_certificate_is_not_found() {
    let w = support::world().await;
    let (status, _) = w.page("/v/kv-test/certificates/nope/renewal").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let res = w
        .post(
            "/v/kv-test/certificates/nope/renewal",
            &[("renewal", "none")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
