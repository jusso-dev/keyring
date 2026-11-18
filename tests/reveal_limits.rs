//! Reveal limits (`keyring-reveal=none|copy-only`, #261 part 2). Every
//! path that can show, copy, export or re-tag a value, posted to directly.
//! The audit events and logs are checked in `tests/reveal_limits_log.rs`
//! and `tests/no_secrets_in_logs.rs`.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use keyring::auth::step_up::{SignInFacts, unix};
use support::keyvault::KvState;
use support::{Part, World, body_text, hidden_value};

const VALUE: &str = "Limited-S3cret-Value-<&>";
const OLD: &str = "Older-Value-Before-Limit";
const SECRET: &str = "/v/kv-test/secrets/db-password";
const REFUSED: &str = "Not shown in Keyring";

fn limit(v: &str) -> BTreeMap<String, String> {
    [("keyring-reveal".to_owned(), v.to_owned())].into()
}

/// A secret with an old version from before the limit, and a current
/// version with `tag=value`.
async fn seeded(tag: &str, value: &str, extra: &[(&'static str, &'static str)]) -> (World, String) {
    let w = support::world_with(extra).await;
    let old = w.kv.state.put("db-password", OLD);
    let (t, v) = (tag.to_owned(), value.to_owned());
    w.kv.state.put_with("db-password", VALUE, move |ver| {
        ver.tags = [(t, v), ("env".to_owned(), "prod".to_owned())].into();
    });
    (w, old)
}

async fn post(w: &World, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let res = w.post(path, fields).await;
    let s = res.status();
    (s, body_text(res).await)
}

fn current_tags(w: &World) -> BTreeMap<String, String> {
    w.kv.state.current("db-password").unwrap().tags
}

#[tokio::test]
async fn none_refuses_reveal_of_every_version_without_reading_a_value() {
    let (w, old) = seeded("keyring-reveal", "none", &[]).await;
    let _guard = w.kv.state.no_value_reads();
    for fields in [vec![], vec![("version", old.as_str())]] {
        let (s, html) = post(&w, &format!("{SECRET}/reveal"), &fields).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{html}");
        assert!(html.contains(REFUSED), "{html}");
        assert!(html.contains("own identity"), "{html}");
        assert!(html.contains("Azure CLI"), "{html}");
        assert!(!html.contains(VALUE) && !html.contains(OLD));
    }
    // The page has no Show value button, says why, and the versions list
    // has no reveal either.
    let (_, html) = w.page(SECRET).await;
    assert!(!html.contains("/reveal\""), "{html}");
    assert!(!html.contains("Copy to another vault"));
    assert!(html.contains("set not to be shown or copied in Keyring"));
    let (_, html) = w.page(&format!("{SECRET}/versions")).await;
    assert!(!html.contains("/reveal\""), "{html}");
}

#[tokio::test]
async fn unknown_values_and_other_spellings_are_none() {
    for (k, v) in [
        ("keyring-reveal", "maybe"),
        ("keyring-reveal", "Copy-Only"),
        ("keyring-reveal", ""),
        ("Keyring-Reveal", "copy-only"),
    ] {
        let (w, _) = seeded(k, v, &[]).await;
        let _guard = w.kv.state.no_value_reads();
        let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{k}={v}");
        assert!(!html.contains(VALUE));
        // Shown as it is, with a note, and kept by an edit that leaves it.
        let (_, html) = w.page(&format!("{SECRET}/edit")).await;
        assert!(html.contains("Keep as set elsewhere"), "{k}={v}: {html}");
    }
}

#[tokio::test]
async fn an_old_version_follows_the_current_versions_limit() {
    // The old version has no tag; the current says none: refused.
    let (w, old) = seeded("keyring-reveal", "none", &[]).await;
    let (s, _) = post(&w, &format!("{SECRET}/reveal"), &[("version", &old)]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // And the other way: an old version with none, current open.
    let w = support::world().await;
    let old =
        w.kv.state
            .put_with("db-password", OLD, |v| v.tags = limit("none"));
    w.kv.state.put("db-password", VALUE);
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[("version", &old)]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{html}");
    assert!(!html.contains(OLD));
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        html.contains("Limited-S3cret-Value-&#60;&#38;&#62;"),
        "{html}"
    );
}

#[tokio::test]
async fn copy_only_keeps_the_value_off_the_screen() {
    let (w, old) = seeded("keyring-reveal", "copy-only", &[]).await;
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::OK, "{html}");
    let escaped = "Limited-S3cret-Value-&#60;&#38;&#62;";
    // Only in a hidden input, for Copy: no textarea, no visible input, no
    // text node.
    assert!(
        html.contains(&format!(
            "type=\"hidden\" value=\"{escaped}\" data-secret-value"
        )),
        "{html}"
    );
    assert_eq!(
        html.matches(escaped).count(),
        1,
        "once, in the hidden input"
    );
    assert!(!html.contains("<textarea id=\"secret-value\""));
    assert!(!html.contains("data-extend"), "nothing to show for longer");
    assert!(html.contains("data-copy"));
    assert!(html.contains("keeps it off the screen, not out of the browser"));
    // The old version is copy only too.
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[("version", &old)]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!html.contains("<textarea id=\"secret-value\""), "{html}");
    let (_, html) = w.page(SECRET).await;
    assert!(html.contains("Copy value"), "{html}");
}

#[tokio::test]
async fn copy_only_typed_secret_fields_are_hidden_inputs() {
    let w = support::world().await;
    let ct = "application/vnd.keyring.login+json;v=1".to_owned();
    let value = r#"{"username":"svc-user","password":"Typed-Pa55-<x>","url":"","notes":""}"#;
    w.kv.state.put_with("login", value, move |v| {
        v.content_type = Some(ct);
        v.tags = limit("copy-only");
    });
    let (s, html) = post(&w, "/v/kv-test/secrets/login/reveal", &[]).await;
    assert_eq!(s, StatusCode::OK, "{html}");
    assert!(
        html.contains("id=\"field-password\" type=\"hidden\""),
        "{html}"
    );
    assert!(
        !html.contains("class=\"secret-value"),
        "no visible field: {html}"
    );
    assert!(html.contains("Copy Password"));
}

#[tokio::test]
async fn a_tag_added_between_the_list_and_the_read_still_refuses() {
    // The versions list says open; the value response says none.
    let (w, _) = seeded("env", "test", &[]).await;
    *w.kv.state.tags_on_value_read.lock().unwrap() = Some(limit("none"));
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(html.contains(REFUSED));
    assert!(!html.contains(VALUE));
    // And copy-only on the read turns the page copy only.
    *w.kv.state.tags_on_value_read.lock().unwrap() = Some(limit("copy-only"));
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!html.contains("<textarea id=\"secret-value\""));
}

#[tokio::test]
async fn the_limit_comes_before_step_up_and_the_reason() {
    let (w, _) = seeded(
        "keyring-reveal",
        "none",
        &[
            ("KEYRING_STEP_UP_AUTH_CONTEXT", "c1"),
            ("KEYRING_REQUIRE_REASON", "reveal"),
        ],
    )
    .await;
    let _guard = w.kv.state.no_value_reads();
    let (s, html) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        html.contains(REFUSED),
        "not the reason or step-up page: {html}"
    );
    let (s, html) = post(
        &w,
        &format!("{SECRET}/copy"),
        &[("to_vault", "kv-test"), ("to_name", "x")],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(html.contains(REFUSED), "{html}");
    // A bad form token still comes first.
    let res = {
        use tower::ServiceExt;
        let req = axum::http::Request::post(format!("{SECRET}/reveal"))
            .header("origin", "http://localhost:3000")
            .header("cookie", &w.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("csrf=wrong"))
            .unwrap();
        w.app.clone().oneshot(req).await.unwrap()
    };
    let html = body_text(res).await;
    assert!(!html.contains(REFUSED), "{html}");
}

async fn two(tag: &str) -> (World, Arc<KvState>, Arc<KvState>) {
    let source = Arc::new(KvState::default());
    let target = Arc::new(KvState::default());
    let w = support::world_of_vaults_with(
        vec![("kv-test", source.clone()), ("kv-prod", target.clone())],
        &[],
    )
    .await;
    let t = tag.to_owned();
    source.put_with("db-password", VALUE, move |v| {
        v.tags = [
            ("keyring-reveal".to_owned(), t),
            ("env".to_owned(), "prod".to_owned()),
        ]
        .into();
    });
    (w, source, target)
}

#[tokio::test]
async fn copy_to_another_vault_none_is_refused_before_the_read() {
    let (w, source, target) = two("none").await;
    let _guard = source.no_value_reads();
    let (s, html) = post(
        &w,
        &format!("{SECRET}/copy"),
        &[
            ("to_vault", "kv-prod"),
            ("to_name", "db-copy"),
            ("tags", "on"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{html}");
    assert!(html.contains(REFUSED));
    assert!(!html.contains(VALUE));
    assert!(target.current("db-copy").is_none());
    let (s, _) = w.page(&format!("{SECRET}/copy")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_copy_option_weakens_copy_only() {
    let (w, _, target) = two("copy-only").await;
    // Every combination of the boxes, and onto an existing secret whose
    // limit is stricter.
    let boxes = ["content_type", "tags", "dates", "enabled"];
    for mask in 0..16u8 {
        let name = format!("db-copy-{mask}");
        let mut f: Vec<(&str, &str)> = vec![("to_vault", "kv-prod"), ("to_name", &name)];
        for (i, b) in boxes.iter().enumerate() {
            if mask & (1 << i) != 0 {
                f.push((b, "on"));
            }
        }
        let (s, html) = post(&w, &format!("{SECRET}/copy"), &f).await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{mask}: {html}");
        let t = target.current(&name).unwrap().tags;
        assert_eq!(
            t.get("keyring-reveal").map(String::as_str),
            Some("copy-only"),
            "{mask}"
        );
    }
    target.put_with("strict", "x", |v| v.tags = limit("none"));
    let (s, _) = post(
        &w,
        &format!("{SECRET}/copy"),
        &[
            ("to_vault", "kv-prod"),
            ("to_name", "strict"),
            ("tags", "on"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        target.current("strict").unwrap().tags["keyring-reveal"],
        "none"
    );
}

#[tokio::test]
async fn rollback_keeps_the_stricter_limit() {
    // Current none, old version without: rollback allowed (nothing shown),
    // and the new version keeps none.
    let (w, old) = seeded("keyring-reveal", "none", &[]).await;
    let (s, html) = post(&w, &format!("{SECRET}/rollback"), &[("version", &old)]).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
    let cur = w.kv.state.current("db-password").unwrap();
    assert_eq!(cur.value, OLD);
    assert_eq!(cur.tags["keyring-reveal"], "none");
    let (s, _) = post(&w, &format!("{SECRET}/reveal"), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Old version with a limit, current without: the new version gets it.
    let w = support::world().await;
    let old =
        w.kv.state
            .put_with("db-password", OLD, |v| v.tags = limit("copy-only"));
    w.kv.state.put("db-password", VALUE);
    let (s, _) = post(&w, &format!("{SECRET}/rollback"), &[("version", &old)]).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(current_tags(&w)["keyring-reveal"], "copy-only");
}

fn met(w: &World) {
    let id = w.cookie.split('=').nth(1).unwrap();
    w.state
        .sessions
        .get(id)
        .unwrap()
        .set_sign_in_facts(SignInFacts {
            acrs: vec!["c1".into()],
            auth_time: Some(unix(std::time::SystemTime::now())),
        });
}

fn edit_fields<'a>(w: &'a World, reveal: Option<&'a str>) -> Vec<(&'a str, String)> {
    let cur = w.kv.state.current("db-password").unwrap();
    let mut f = vec![
        ("version", cur.version.clone()),
        ("updated", cur.updated.to_string()),
        ("enabled", "on".to_owned()),
        ("tag-rows", "1".to_owned()),
        ("tag-name-1", "env".to_owned()),
        ("tag-value-1", "prod".to_owned()),
    ];
    if let Some(r) = reveal {
        f.push(("reveal", r.to_owned()));
    }
    f
}

async fn post_owned(w: &World, path: &str, f: &[(&str, String)]) -> (StatusCode, String) {
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    post(w, path, &f).await
}

#[tokio::test]
async fn edit_details_keeps_the_limit_unless_changed_and_loosening_steps_up() {
    let (w, _) = seeded(
        "keyring-reveal",
        "none",
        &[("KEYRING_STEP_UP_AUTH_CONTEXT", "c1")],
    )
    .await;
    // A form without the control (from before the upgrade) keeps it.
    let (s, html) = post_owned(&w, &format!("{SECRET}/edit"), &edit_fields(&w, None)).await;
    assert!(s == StatusCode::SEE_OTHER, "{html}");
    assert_eq!(current_tags(&w)["keyring-reveal"], "none");
    // A tag row can't set or remove it.
    let mut f = edit_fields(&w, Some("none"));
    f.extend([
        ("tag-name-2", "keyring-reveal".to_owned()),
        ("tag-value-2", "".to_owned()),
    ]);
    let (s, html) = post_owned(&w, &format!("{SECRET}/edit"), &f).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("Reveal limit control"), "{html}");
    // Loosening without step-up: refused, nothing changed.
    let (s, html) = post_owned(&w, &format!("{SECRET}/edit"), &edit_fields(&w, Some(""))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{html}");
    assert!(html.contains("Confirm it"));
    assert_eq!(current_tags(&w)["keyring-reveal"], "none");
    // Strengthening needs nothing extra... and loosening after step-up works.
    met(&w);
    let (s, _) = post_owned(
        &w,
        &format!("{SECRET}/edit"),
        &edit_fields(&w, Some("copy-only")),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(current_tags(&w)["keyring-reveal"], "copy-only");
    let (s, _) = post_owned(&w, &format!("{SECRET}/edit"), &edit_fields(&w, Some(""))).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(!current_tags(&w).contains_key("keyring-reveal"));
}

#[tokio::test]
async fn strengthening_needs_no_step_up_and_loosening_asks_a_reason() {
    let w = support::world_with(&[
        ("KEYRING_STEP_UP_AUTH_CONTEXT", "c1"),
        ("KEYRING_REQUIRE_REASON", "reveal"),
    ])
    .await;
    w.kv.state.put_with("db-password", VALUE, |v| {
        v.tags = [("env".to_owned(), "prod".to_owned())].into()
    });
    let (s, html) = post_owned(
        &w,
        &format!("{SECRET}/edit"),
        &edit_fields(&w, Some("none")),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
    assert_eq!(current_tags(&w)["keyring-reveal"], "none");
    met(&w);
    let (s, html) = post_owned(&w, &format!("{SECRET}/edit"), &edit_fields(&w, Some(""))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{html}");
    assert!(html.contains("Loosening the reveal limit needs a reason"));
    assert_eq!(current_tags(&w)["keyring-reveal"], "none");
    let mut f = edit_fields(&w, Some(""));
    f.push(("reason", "Moving to copy via CLI only".into()));
    let (s, html) = post_owned(&w, &format!("{SECRET}/edit"), &f).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
    assert!(!current_tags(&w).contains_key("keyring-reveal"));
}

#[tokio::test]
async fn set_a_new_value_carries_the_limit() {
    let (w, _) = seeded("keyring-reveal", "copy-only", &[]).await;
    // No reveal field posted: kept.
    let (s, html) = post(
        &w,
        &format!("{SECRET}/value"),
        &[
            ("value", "New-Value-1"),
            ("enabled", "on"),
            ("tag-rows", "1"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
    assert_eq!(current_tags(&w)["keyring-reveal"], "copy-only");
    // The form shows the control with copy only chosen.
    let (_, html) = w.page(&format!("{SECRET}/value")).await;
    assert!(
        html.contains("<option value=\"copy-only\" selected>"),
        "{html}"
    );
}

#[tokio::test]
async fn bulk_changes_cant_touch_the_limit() {
    let (w, _) = seeded("keyring-reveal", "none", &[]).await;
    for op in ["tag_remove", "tag_set"] {
        for name in ["keyring-reveal", "Keyring-Reveal"] {
            let (s, html) = post(
                &w,
                "/v/kv-test/secrets/-/bulk/apply",
                &[
                    ("item", "db-password"),
                    ("op", op),
                    ("tag_name", name),
                    ("tag_value", ""),
                ],
            )
            .await;
            assert_ne!(s, StatusCode::SEE_OTHER, "{op} {name}");
            assert!(
                html.contains("can&#39;t be changed in bulk")
                    || html.contains("can't be changed in bulk"),
                "{op} {name}: {html}"
            );
        }
    }
    // Another tag change keeps it.
    let (s, html) = post(
        &w,
        "/v/kv-test/secrets/-/bulk/apply",
        &[
            ("item", "db-password"),
            ("op", "tag_remove"),
            ("tag_name", "env"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{html}");
    let t = current_tags(&w);
    assert_eq!(t.get("keyring-reveal").map(String::as_str), Some("none"));
    assert!(!t.contains_key("env"));
}

#[tokio::test]
async fn import_over_an_existing_secret_keeps_its_limit() {
    let (w, _) = seeded("keyring-reveal", "none", &[]).await;
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", "a.env", b"db-password=Imported-1\n")],
        )
        .await;
    let html = body_text(res).await;
    let id = hidden_value(&html, "import_id").expect(&html);
    let (s, html) = post(
        &w,
        "/v/kv-test/secrets/-/import/confirm",
        &[("import_id", &id)],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{html}");
    let cur = w.kv.state.current("db-password").unwrap();
    assert_eq!(cur.value, "Imported-1");
    assert_eq!(cur.tags["keyring-reveal"], "none");
    // A CSV can't set it.
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File(
                "file",
                "a.csv",
                b"name,value,tags\nfresh,v1,keyring-reveal=\n",
            )],
        )
        .await;
    let html = body_text(res).await;
    assert!(
        html.contains("can&#39;t set the keyring-reveal tag")
            || html.contains("can't set the keyring-reveal tag"),
        "{html}"
    );
}

#[tokio::test]
async fn private_key_download_is_refused_for_any_limit() {
    for v in ["none", "copy-only", "odd"] {
        let w = support::world().await;
        w.kv.state.add_cert("web-tls", true, "UEZY");
        let vv = v.to_owned();
        w.kv.state
            .certs
            .lock()
            .unwrap()
            .get_mut("web-tls")
            .unwrap()
            .versions[0]
            .tags = limit(&vv);
        let _guard = w.kv.state.no_value_reads();
        let (s, html) = post(
            &w,
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}: {html}");
        assert!(html.contains(REFUSED), "{html}");
        assert!(!html.contains("UEZY"));
        let (s, _) = w.page("/v/kv-test/certificates/web-tls/download-key").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        // The public certificate is not a value: still allowed.
        let res = w.get("/v/kv-test/certificates/web-tls/cer").await;
        assert_eq!(res.status(), StatusCode::OK);
        let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
        assert!(!html.contains("Download with private key"), "{html}");
    }
}

#[tokio::test]
async fn a_limit_on_the_backing_secret_also_refuses_the_download() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state
        .secrets
        .lock()
        .unwrap()
        .get_mut("web-tls")
        .unwrap()
        .versions[0]
        .tags = limit("none");
    let (s, html) = post(
        &w,
        "/v/kv-test/certificates/web-tls/download-key",
        &[("confirm_name", "web-tls")],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{html}");
    assert!(!html.contains("UEZY"));
}

#[tokio::test]
async fn certificate_edit_details_has_the_control_and_keys_dont() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("signing", "RSA", |_| {});
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/details").await;
    assert!(html.contains("name=\"reveal\""), "{html}");
    let (_, html) = w.page("/v/kv-test/keys/signing/details").await;
    assert!(!html.contains("name=\"reveal\""), "{html}");
}
