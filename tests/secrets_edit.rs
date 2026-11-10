//! Create, new value, edit properties, enable and disable.

mod support;

use axum::http::StatusCode;
use support::{body_text, hidden_value, location};

/// The hidden fields the edit form carries: the version it was opened on
/// and that version's `updated` time.
async fn edit_stamp(w: &support::World, name: &str) -> (String, String) {
    let (_, html) = w.page(&format!("/secrets/{name}/edit")).await;
    (
        hidden_value(&html, "version").expect("version field"),
        hidden_value(&html, "updated").expect("updated field"),
    )
}

#[tokio::test]
async fn create_adds_a_secret_with_its_properties() {
    let w = support::world().await;
    let (status, html) = w.page("/secrets/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Letters, numbers and hyphens only"));
    assert!(html.contains("Generate a value"), "generator hook is there");

    let res = w
        .post(
            "/secrets/new",
            &[
                ("name", "db-password"),
                ("value", "  hunter2 "),
                ("content_type", "text/plain"),
                ("expires", "2099-01-31"),
                ("tags", "env=prod\nteam=data"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/secrets/db-password");
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.value, "  hunter2 ");
    assert_eq!(v.content_type.as_deref(), Some("text/plain"));
    assert_eq!(v.tags.get("team").map(String::as_str), Some("data"));
    assert!(v.enabled);
    assert_eq!(keyring::dates::iso_date(v.exp.unwrap()), "2099-01-31");
    // Shown in the list.
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains(">db-password<"));
}

#[tokio::test]
async fn create_explains_bad_names_and_keeps_other_fields() {
    let w = support::world().await;
    let res = w
        .post(
            "/secrets/new",
            &[
                ("name", "db_password"),
                ("value", "x"),
                ("tags", "env=prod"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("Names can only use letters, numbers and hyphens. Remove &#34;_&#34;."));
    assert!(html.contains("env=prod"), "tags kept");
    assert!(
        !html.contains(">x</textarea>"),
        "the value isn't echoed back"
    );
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("PUT"))
    );
}

#[tokio::test]
async fn create_does_not_overwrite_an_existing_secret() {
    let w = support::world().await;
    w.kv.state.put("db-password", "original");
    let res = w
        .post(
            "/secrets/new",
            &[("name", "db-password"), ("value", "new"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body_text(res)
            .await
            .contains("There&#39;s already a secret called db-password")
    );
    assert_eq!(w.kv.state.version_count("db-password"), 1);
}

#[tokio::test]
async fn create_offers_recovery_when_name_is_soft_deleted() {
    let w = support::world().await;
    w.kv.state.put("old-key", "x");
    let res = w
        .post("/secrets/old-key/delete", &[("confirm_name", "old-key")])
        .await;
    // Delete arrives in a later change; put the secret in the bin directly if needed.
    if res.status() != StatusCode::SEE_OTHER {
        let sec =
            w.kv.state
                .secrets
                .lock()
                .unwrap()
                .remove("old-key")
                .unwrap();
        w.kv.state.deleted.lock().unwrap().insert(
            "old-key".into(),
            support::keyvault::Deleted {
                secret: sec,
                deleted: 1,
                purge: 2,
            },
        );
    }
    let res = w
        .post(
            "/secrets/new",
            &[("name", "old-key"), ("value", "x"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("A deleted secret called old-key is still being kept"));
    assert!(html.contains("href=\"/secrets/deleted/old-key\""));
}

#[tokio::test]
async fn new_value_makes_a_new_version() {
    let w = support::world().await;
    w.kv.state.put_with("db-password", "v1", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/secrets/db-password/value").await;
    assert!(html.contains("Saving makes a new version"));
    assert!(html.contains("env=prod"), "properties carried over");
    assert!(!html.contains(">v1<"), "old value not shown");
    let res = w
        .post(
            "/secrets/db-password/value",
            &[("value", "v2"), ("tags", "env=prod"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.version_count("db-password"), 2);
    assert_eq!(w.kv.state.current("db-password").unwrap().value, "v2");
}

#[tokio::test]
async fn editing_properties_does_not_make_a_new_version() {
    let w = support::world().await;
    let ver = w.kv.state.put("db-password", "keep-me");
    let (_, html) = w.page("/secrets/db-password/edit").await;
    assert!(html.contains("no new version is made"));
    assert!(!html.contains("name=\"value\""), "no value field");
    let (version, updated) = edit_stamp(&w, "db-password").await;
    assert_eq!(version, ver);
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("content_type", "text/plain"),
                ("tags", "owner=ops"),
                ("expires", "2099-06-01"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.version_count("db-password"), 1);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.version, ver);
    assert_eq!(v.value, "keep-me");
    assert_eq!(v.content_type.as_deref(), Some("text/plain"));
    assert_eq!(v.tags.get("owner").map(String::as_str), Some("ops"));
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|l| l == &format!("PATCH /kv-test/secrets/db-password/{ver}"))
    );
    assert!(!log.iter().any(|l| l.starts_with("PUT")));
}

#[tokio::test]
async fn enable_and_disable() {
    let w = support::world().await;
    let ver = w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    let res = w
        .post("/secrets/db-password/enabled", &[("state", "off")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert!(!v.enabled);
    assert_eq!(v.version, ver);
    assert_eq!(
        v.tags.get("env").map(String::as_str),
        Some("prod"),
        "other properties kept"
    );
    let (_, html) = w.page("/secrets").await;
    assert!(html.contains(">Disabled<"));
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("value=\"on\""), "offers Enable");

    w.post("/secrets/db-password/enabled", &[("state", "on")])
        .await;
    assert!(w.kv.state.current("db-password").unwrap().enabled);
}

#[tokio::test]
async fn forms_need_the_token() {
    let mut w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.csrf = "forged".into();
    for (path, fields) in [
        ("/secrets/new", vec![("name", "a"), ("value", "b")]),
        ("/secrets/db-password/value", vec![("value", "b")]),
        ("/secrets/db-password/edit", vec![]),
        ("/secrets/db-password/enabled", vec![("state", "off")]),
    ] {
        let res = w.post(path, &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(w.kv.state.version_count("db-password"), 1);
    assert!(w.kv.state.current("db-password").unwrap().enabled);
}

#[tokio::test]
async fn forbidden_writes_name_the_officer_role() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::PUT);
    let res = w
        .post(
            "/secrets/db-password/value",
            &[("value", "y"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("Key Vault Secrets Officer role on this vault"));
}

#[tokio::test]
async fn success_flash_is_shown() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let res = w
        .post(
            "/secrets/db-password/value",
            &[("value", "y"), ("enabled", "on")],
        )
        .await;
    let flash = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_flash="))
        .unwrap();
    let mut w = w;
    w.cookie = format!("{}; {flash}", w.cookie);
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("Saved a new version of db-password"));
}

#[tokio::test]
async fn editing_tags_keeps_the_exact_expiry_and_clearing_works() {
    let w = support::world().await;
    // Expires at 10:00 UTC, 100 days out.
    let day = 86_400;
    let n = keyring::azure::secrets::now_ts();
    let exp = (n / day + 100) * day + 10 * 3600;
    w.kv.state
        .put_with("db-password", "x", |v| v.exp = Some(exp));
    let shown = keyring::dates::iso_date(exp);
    let (version, updated) = edit_stamp(&w, "db-password").await;
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("expires", &shown),
                ("tags", "env=prod"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.exp, Some(exp), "expiry time unchanged by a tag edit");
    assert_eq!(v.tags.get("env").map(String::as_str), Some("prod"));

    let (version, updated) = edit_stamp(&w, "db-password").await;
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("expires", ""),
                ("tags", "env=prod"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        w.kv.state.current("db-password").unwrap().exp,
        None,
        "cleared"
    );
}

#[tokio::test]
async fn create_checks_for_a_name_that_is_taken_by_its_versions() {
    let w = support::world().await;
    // Key Vault answers an unknown name with 200 and an empty list.
    let res = w
        .post(
            "/secrets/new",
            &[("name", "fresh"), ("value", "x"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "empty list is free");
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "GET /kv-test/secrets/fresh/versions")
    );
    // A 404 also means free.
    *w.kv.state.fail.lock().unwrap() = Some((404, "SecretNotFound"));
    *w.kv.state.fail_path.lock().unwrap() = Some("/other/versions".into());
    let res = w
        .post(
            "/secrets/new",
            &[("name", "other"), ("value", "x"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "404 is free");
    assert_eq!(w.kv.state.version_count("other"), 1);
}

#[tokio::test]
async fn create_refuses_keyrings_own_page_names() {
    let w = support::world().await;
    for name in ["new", "deleted"] {
        let res = w
            .post(
                "/secrets/new",
                &[("name", name), ("value", "x"), ("enabled", "on")],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{name}");
        assert!(
            body_text(res)
                .await
                .contains(&format!("Keyring uses /secrets/{name} for its own page"))
        );
    }
    assert!(
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("PUT"))
    );
}

#[tokio::test]
async fn line_breaks_are_saved_as_lf_and_shown_as_saved() {
    let w = support::world().await;
    let res = w
        .post(
            "/secrets/new",
            &[("name", "pem"), ("value", "\r\na\r\nb"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("pem").unwrap().value, "\na\nb");
    let res = w
        .post(
            "/secrets/pem/value",
            &[("value", "c\r\nd\r\n"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("pem").unwrap().value, "c\nd\n");

    // On reveal, the one line break the HTML parser drops after
    // <textarea> is Keyring's, so a leading line break in the value stays.
    w.kv.state.put("lead", "\nkey");
    let res = w.post("/secrets/lead/reveal", &[]).await;
    let html = body_text(res).await;
    assert!(
        html.contains("data-secret-value>\n\nkey</textarea>"),
        "{html}"
    );
}

#[tokio::test]
async fn a_full_size_non_ascii_value_gets_the_form_not_a_413() {
    let w = support::world().await;
    // 24 KB of three-byte characters is about 72 KB once URL encoded, and
    // more again with each byte as %XX.
    let value = "\u{20ac}".repeat(8 * 1024);
    assert!(value.len() <= 25 * 1024);
    let res = w
        .post(
            "/secrets/new",
            &[("name", "euro"), ("value", &value), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("euro").unwrap().value, value);
    // Just over the value limit: the form's own message.
    let value = "\u{20ac}".repeat(9 * 1024);
    let res = w
        .post(
            "/secrets/new",
            &[("name", "euro-2"), ("value", &value), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("Values can be up to 25 KB"));
}

#[tokio::test]
async fn an_oversized_body_gets_the_error_page() {
    let w = support::world().await;
    let big = "\u{20ac}".repeat(64 * 1024);
    let res = w
        .post("/secrets/new", &[("name", "x"), ("value", &big)])
        .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let html = body_text(res).await;
    assert!(html.contains("That was too much to send"), "{html}");
    assert!(html.contains("up to 25 KB"));
}

#[tokio::test]
async fn editing_refuses_a_form_opened_on_an_older_state() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let (version, updated) = edit_stamp(&w, "db-password").await;
    // Someone else disables it after the form was opened.
    w.post("/secrets/db-password/enabled", &[("state", "off")])
        .await;
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("content_type", "text/plain"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(
        body_text(res)
            .await
            .contains("This secret changed since you opened it")
    );
    let v = w.kv.state.current("db-password").unwrap();
    assert!(!v.enabled, "not turned back on");
    assert_eq!(v.content_type, None);

    // And a newer version saved since.
    let (version, updated) = edit_stamp(&w, "db-password").await;
    w.kv.state.put("db-password", "y");
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    // A form without the fields, as from an old page, is refused too.
    let res = w
        .post("/secrets/db-password/edit", &[("enabled", "on")])
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn tags_the_form_cant_show_are_listed_and_kept() {
    let w = support::world().await;
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("a=b".into(), " padded ".into());
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/secrets/db-password/edit").await;
    assert!(html.contains("can't show them without changing them"));
    assert!(!html.contains("id=\"tags\""), "no tag textarea");
    let (version, updated) = edit_stamp(&w, "db-password").await;
    let res = w
        .post(
            "/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("content_type", "text/plain"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.content_type.as_deref(), Some("text/plain"));
    assert_eq!(v.tags.get("a=b").map(String::as_str), Some(" padded "));
    assert_eq!(v.tags.get("env").map(String::as_str), Some("prod"));

    // A new value keeps them too.
    let res = w
        .post(
            "/secrets/db-password/value",
            &[("value", "y"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.tags.get("a=b").map(String::as_str), Some(" padded "));
}

#[tokio::test]
async fn repeated_tag_names_are_reported() {
    let w = support::world().await;
    let res = w
        .post(
            "/secrets/new",
            &[
                ("name", "dup"),
                ("value", "x"),
                ("tags", "env=prod\nenv=test"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("repeats the tag name env"));
}

#[tokio::test]
async fn a_new_value_keeps_the_exact_expiry_and_start_times() {
    let w = support::world().await;
    let day = 86_400;
    let n = keyring::azure::secrets::now_ts();
    let exp = (n / day + 100) * day + 10 * 3600;
    let nbf = (n / day - 3) * day + 9 * 3600;
    w.kv.state.put_with("db-password", "x", |v| {
        v.exp = Some(exp);
        v.nbf = Some(nbf);
    });
    let (_, html) = w.page("/secrets/db-password/value").await;
    let shown_exp = keyring::dates::iso_date(exp);
    let shown_nbf = keyring::dates::iso_date(nbf);
    assert!(html.contains(&shown_exp) && html.contains(&shown_nbf));
    let res = w
        .post(
            "/secrets/db-password/value",
            &[
                ("value", "y"),
                ("expires", &shown_exp),
                ("not_before", &shown_nbf),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.value, "y");
    assert_eq!(v.exp, Some(exp), "10:00 kept, not moved to 23:59:59");
    assert_eq!(v.nbf, Some(nbf), "09:00 kept, not moved to midnight");
}

#[tokio::test]
async fn a_bad_token_is_refused_before_azure_is_asked() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    // A name that doesn't exist: if Azure were asked first, this would be
    // a 404, not the uniform 403.
    for (path, fields) in [
        ("/secrets/no-such/value", vec![("value", "b")]),
        ("/secrets/no-such/edit", vec![]),
        ("/secrets/no-such/enabled", vec![("state", "off")]),
        (
            "/secrets/no-such/rollback",
            vec![("version", "0123456789abcdef0123456789abcdef")],
        ),
        ("/secrets/no-such/reveal", vec![]),
        ("/secrets/no-such/delete", vec![("confirm_name", "no-such")]),
    ] {
        let res = w.post(path, &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(
        w.kv.state.log.lock().unwrap().is_empty(),
        "Key Vault never called: {:?}",
        w.kv.state.log.lock().unwrap()
    );
}
