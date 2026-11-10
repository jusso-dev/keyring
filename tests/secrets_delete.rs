//! Soft delete, recover, and purge behind its flag.

mod support;

use axum::http::StatusCode;
use support::{body_text, location};

/// The flash cookie a redirect set, as `name=value`.
fn flash_cookie(res: &axum::http::Response<axum::body::Body>) -> Option<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_flash="))
}

#[tokio::test]
async fn delete_needs_the_name_typed() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let (status, html) = w.page("/secrets/db-password/delete").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Type <strong class=\"mono\">db-password</strong> to confirm"));

    for typed in ["", "db-passwor", "DB-PASSWORD"] {
        let res = w
            .post("/secrets/db-password/delete", &[("confirm_name", typed)])
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{typed:?}");
        assert!(body_text(res).await.contains("Nothing was deleted"));
    }
    // A post with no confirm field at all, as if the form were bypassed.
    let res = w.post("/secrets/db-password/delete", &[]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(w.kv.state.current("db-password").is_some());
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("DELETE"))
    );

    let res = w
        .post(
            "/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/secrets");
    assert!(w.kv.state.current("db-password").is_none());
    assert!(
        w.kv.state
            .deleted
            .lock()
            .unwrap()
            .contains_key("db-password")
    );
}

#[tokio::test]
async fn delete_with_forged_token_is_refused() {
    let mut w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.csrf = "forged".into();
    let res = w
        .post(
            "/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.current("db-password").is_some());
}

#[tokio::test]
async fn deleted_list_shows_purge_dates_and_recover_restores() {
    let w = support::world().await;
    w.kv.state.put("db-password", "keep-this");
    w.kv.state.put("db-password", "and-this");
    w.kv.state.soft_delete("db-password");
    let (status, html) = w.page("/secrets/-/deleted").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(">db-password<"));
    assert!(html.contains("Gone for good on"));
    let purge = w.kv.state.deleted.lock().unwrap()["db-password"].purge;
    assert!(html.contains(&keyring::dates::format_date(purge)));

    let res = w.post("/secrets/-/deleted/db-password/recover", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // Not the detail page, which may not be readable for a few seconds.
    assert_eq!(location(&res), "/secrets/-/deleted");
    let (_, html) = w.page("/secrets/-/deleted").await;
    assert!(html.contains("No deleted secrets"));
    // Like Key Vault, the mock answers 404 for a moment after a recover.
    let (status, _) = w.page("/secrets/db-password").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = w.page("/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        w.kv.state.version_count("db-password"),
        2,
        "history comes back"
    );
    assert_eq!(w.kv.state.current("db-password").unwrap().value, "and-this");
}

#[tokio::test]
async fn recover_flash_says_it_can_take_a_few_seconds() {
    let mut w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.kv.state.soft_delete("db-password");
    let res = w.post("/secrets/-/deleted/db-password/recover", &[]).await;
    let flash = flash_cookie(&res).unwrap();
    w.cookie = format!("{}; {flash}", w.cookie);
    let (_, html) = w.page("/secrets/-/deleted").await;
    assert!(html.contains("Recovering db-password"), "{html}");
    assert!(html.contains("can take a few seconds"));
}

#[tokio::test]
async fn delete_warning_uses_the_vaults_retention() {
    let w = support::world().await;
    *w.kv.state.retention.lock().unwrap() = Some(("CustomizedRecoverable+Purgeable", 7));
    w.kv.state.put("db-password", "x");
    let (status, html) = w.page("/secrets/db-password/delete").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("You can recover it for 7 days after it&#39;s deleted"),
        "{html}"
    );
    assert!(!html.contains("usually 90"));
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("Deleted secrets in this vault can be recovered for 7 days."));
    assert!(
        !html.contains("CustomizedRecoverable"),
        "raw level not shown"
    );
}

#[tokio::test]
async fn delete_form_for_a_missing_secret_is_not_found() {
    let w = support::world().await;
    let (status, html) = w.page("/secrets/no-such-thing/delete").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!html.contains("to confirm"));
}

#[tokio::test]
async fn purge_is_not_offered_on_a_purge_protected_vault() {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    *w.kv.state.retention.lock().unwrap() = Some(("Recoverable", 90));
    w.kv.state.put("db-password", "x");
    w.kv.state.soft_delete("db-password");
    let (_, html) = w.page("/secrets/-/deleted/db-password").await;
    assert!(!html.contains("/purge\""), "no purge link");
    assert!(html.contains("purge protection"));

    let (status, html) = w.page("/secrets/-/deleted/db-password/purge").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("This vault has purge protection"));
    let res = w
        .post(
            "/secrets/-/deleted/db-password/purge",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("This vault has purge protection"));
    assert!(!html.contains("Secrets Officer"), "not blamed on a role");
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("DELETE /kv-test/deletedsecrets")),
        "Key Vault isn't asked"
    );
}

#[tokio::test]
async fn purge_is_off_by_default_everywhere() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.kv.state.soft_delete("db-password");
    let (_, html) = w.page("/secrets/-/deleted/db-password").await;
    assert!(!html.contains("Permanently delete"), "no purge button");
    assert!(html.contains("Recover db-password"));

    let (status, _) = w.page("/secrets/-/deleted/db-password/purge").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Even a correct, well-formed post is refused on the server.
    let res = w
        .post(
            "/secrets/-/deleted/db-password/purge",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("KEYRING_ALLOW_PURGE"));
    assert!(
        w.kv.state
            .deleted
            .lock()
            .unwrap()
            .contains_key("db-password")
    );
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("DELETE /kv-test/deletedsecrets"))
    );
}

#[tokio::test]
async fn purge_when_enabled_needs_typed_name_and_warns_twice() {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    w.kv.state.put("db-password", "x");
    w.kv.state.soft_delete("db-password");
    let (_, html) = w.page("/secrets/-/deleted/db-password").await;
    assert!(html.contains("href=\"/secrets/-/deleted/db-password/purge\""));
    let (status, html) = w.page("/secrets/-/deleted/db-password/purge").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("for good"));
    assert!(html.contains("notice-error"), "second warning");

    let res = w
        .post(
            "/secrets/-/deleted/db-password/purge",
            &[("confirm_name", "db")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        w.kv.state
            .deleted
            .lock()
            .unwrap()
            .contains_key("db-password")
    );

    let res = w
        .post(
            "/secrets/-/deleted/db-password/purge",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        !w.kv
            .state
            .deleted
            .lock()
            .unwrap()
            .contains_key("db-password")
    );
}

#[tokio::test]
async fn delete_without_rights_explains() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::DELETE);
    let res = w
        .post(
            "/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Key Vault Secrets Officer"));
}

#[tokio::test]
async fn deleted_list_pages() {
    let w = support::world().await;
    for i in 0..101 {
        let name = format!("old-{i:03}");
        w.kv.state.put(&name, "x");
        w.kv.state.soft_delete(&name);
    }
    let (_, html) = w.page("/secrets/-/deleted").await;
    assert_eq!(html.matches("<th scope=\"row\"").count(), 100);
    assert!(html.contains("Page 1 of 2, deleted secrets 1 to 100"));
    let (_, html) = w.page("/secrets/-/deleted?page=2").await;
    assert_eq!(html.matches("<th scope=\"row\"").count(), 1);
    assert!(html.contains(">old-100<"));
}
