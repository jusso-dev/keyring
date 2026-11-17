//! A reason (and optionally a ticket) before a value is shown or anything
//! is changed: `KEYRING_REQUIRE_REASON` and `KEYRING_REASON_TICKET_PATTERN`.
//!
//! The audit events and log escaping are in `tests/reason_log.rs`.

mod support;

use axum::http::StatusCode;
use keyring::auth::step_up::{SignInFacts, unix};
use support::{World, body_text};

const REVEAL: (&str, &str) = ("KEYRING_REQUIRE_REASON", "reveal");
const ALL: (&str, &str) = ("KEYRING_REQUIRE_REASON", "all");
const PATTERN: (&str, &str) = ("KEYRING_REASON_TICKET_PATTERN", "(INC|CHG)[0-9]{7}");
const SECRET: &str = "Very-Secret-Value-123";

async fn seeded(extra: &[(&'static str, &'static str)]) -> World {
    let mut env = vec![("KEYRING_ALLOW_PURGE", "true")];
    env.extend_from_slice(extra);
    let w = support::world_with(&env).await;
    w.kv.state.put("db-password", "first-value");
    w.kv.state.put("db-password", SECRET);
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.put("old-secret", "x");
    w.kv.state.soft_delete("old-secret");
    w
}

fn kv_calls(w: &World) -> usize {
    w.kv.state.log.lock().unwrap().len()
}

#[tokio::test]
async fn off_changes_nothing() {
    let w = seeded(&[]).await;
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(!html.contains("name=\"reason\""), "no reason field");
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains(SECRET));
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn reveal_is_refused_without_a_reason() {
    let w = seeded(&[REVEAL]).await;
    // The page asks for one, and tells people what not to type.
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("name=\"reason\""), "{html}");
    assert!(html.contains("minlength=\"5\" maxlength=\"200\""));
    assert!(html.contains("Don't type secrets, passwords or personal details here."));
    assert!(!html.contains("name=\"ticket\""), "no pattern, no ticket");

    let before = kv_calls(&w);
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        res.headers().get("cache-control").unwrap(),
        "no-store, max-age=0"
    );
    let html = body_text(res).await;
    assert!(
        html.contains("Why do you need to see this value?"),
        "{html}"
    );
    assert!(!html.contains(SECRET));
    assert!(
        !html.contains("Please fix"),
        "the first ask isn't an error: {html}"
    );
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");

    // Too short, then only spaces and control characters.
    for bad in ["abcd", " \n\t\u{1b} ", ""] {
        let res = w
            .post("/v/kv-test/secrets/db-password/reveal", &[("reason", bad)])
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
        let html = body_text(res).await;
        assert!(
            html.contains("Give a reason of 5 to 200 characters."),
            "{html}"
        );
        assert!(html.contains("aria-invalid=\"true\""));
        assert!(!html.contains(SECRET));
    }
    // Too long: 201 characters, even though 200 two-byte ones pass.
    let long = "é".repeat(201);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", &long)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
    let ok = "é".repeat(200);
    let res = w
        .post("/v/kv-test/secrets/db-password/reveal", &[("reason", &ok)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains(SECRET));
}

#[tokio::test]
async fn the_reason_page_posts_the_same_form_again() {
    let w = seeded(&[REVEAL]).await;
    let old = w.kv.state.put("db-password", "older-value-here");
    w.kv.state.put("db-password", "newest-value-here");
    // The versions page's button has no reason field: the page asks, and
    // carries the version.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("version", &old)],
        )
        .await;
    let html = body_text(res).await;
    assert!(html.contains("action=\"/v/kv-test/secrets/db-password/reveal\""));
    assert!(
        html.contains(&format!("name=\"version\" value=\"{old}\"")),
        "{html}"
    );
    assert!(
        html.contains("href=\"/v/kv-test/secrets/db-password\""),
        "cancel"
    );
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("version", &old), ("reason", "Checking the old value")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("older-value-here"));
}

#[tokio::test]
async fn private_key_download_needs_a_reason() {
    let w = seeded(&[REVEAL]).await;
    let (_, html) = w.page("/v/kv-test/certificates/web-tls/download-key").await;
    assert!(html.contains("name=\"reason\""), "{html}");
    let before = kv_calls(&w);
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("Why do you need the private key?"));
    assert!(html.contains("name=\"confirm_name\" value=\"web-tls\""));
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[
                ("confirm_name", "web-tls"),
                ("reason", "Moving to new host"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()
            .get("content-disposition")
            .is_some_and(|v| v.to_str().unwrap().contains("web-tls"))
    );
    // With `reveal`, a change needs no reason.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn ticket_pattern_is_enforced() {
    let w = seeded(&[REVEAL, PATTERN]).await;
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("name=\"ticket\""));
    assert!(html.contains("(INC|CHG)[0-9]{7}"));
    let before = kv_calls(&w);
    for bad in ["", "INC123", "INC00123456", "xCHG0000001", "CHG0000001\nx"] {
        let res = w
            .post(
                "/v/kv-test/secrets/db-password/reveal",
                &[("reason", "Investigating an outage"), ("ticket", bad)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
        let html = body_text(res).await;
        assert!(
            html.contains("Give a ticket reference that matches (INC|CHG)[0-9]{7}."),
            "{html}"
        );
        // The good reason is kept, so only the ticket needs fixing.
        assert!(html.contains("value=\"Investigating an outage\""));
    }
    assert_eq!(kv_calls(&w), before);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[
                ("reason", "Investigating an outage"),
                ("ticket", "INC0012345"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn all_covers_changes() {
    let w = seeded(&[ALL]).await;
    // Confirmation pages and change forms ask.
    for page in [
        "/v/kv-test/secrets/db-password/delete",
        "/v/kv-test/secrets/db-password/edit",
        "/v/kv-test/secrets/db-password/disable",
        "/v/kv-test/secrets/-/deleted/old-secret/purge",
        "/v/kv-test/secrets/-/new",
        "/v/kv-test/keys/-/new",
    ] {
        let (status, html) = w.page(page).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(html.contains("name=\"reason\""), "{page}");
    }
    let before = kv_calls(&w);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        body_text(res)
            .await
            .contains("Why are you making this change?")
    );
    let res = w
        .post("/v/kv-test/secrets/-/deleted/old-secret/recover", &[])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
    assert!(w.kv.state.current("db-password").is_some(), "not deleted");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[
                ("confirm_name", "db-password"),
                ("reason", "No longer used"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_secret_value_is_never_written_back_into_the_reason_page() {
    let w = seeded(&[ALL]).await;
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[("value", "Brand-New-Value-999")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(!html.contains("Brand-New-Value-999"), "{html}");
    assert!(html.contains("type the value again"));
    assert!(
        !html.contains("<form method=\"post\" action=\"/v/kv-test/secrets/db-password/value\"")
    );
    // The form itself has the field, so it can be filled in first time.
    let (_, html) = w.page("/v/kv-test/secrets/db-password/value").await;
    assert!(html.contains("name=\"reason\""));
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[
                ("value", "Brand-New-Value-999"),
                ("reason", "Rotating after a leak"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        w.kv.state.current("db-password").unwrap().value,
        "Brand-New-Value-999"
    );
}

#[tokio::test]
async fn order_is_csrf_then_step_up_then_reason() {
    let w = seeded(&[REVEAL, ("KEYRING_STEP_UP_AUTH_CONTEXT", "c1")]).await;
    // A forged token is refused as a forged token, reason or not.
    let before = kv_calls(&w);
    let body = format!("csrf=forged&reason={}", "Looking%20into%20it");
    let res = support_post_raw(&w, "/v/kv-test/secrets/db-password/reveal", &body).await;
    assert_eq!(res, StatusCode::FORBIDDEN);
    // Step-up is asked for before the reason, and its return path has no
    // reason in it.
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("Confirm it&#39;s you"), "{html}");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", "Secret-Reason-Text")],
        )
        .await;
    let html = body_text(res).await;
    assert!(html.contains("Confirm it&#39;s you"));
    assert!(
        !html.contains("Secret-Reason-Text"),
        "the reason isn't carried through step-up: {html}"
    );
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
    // Once step-up is met, the reason is asked for.
    let id = w.cookie.split('=').nth(1).unwrap();
    w.state
        .sessions
        .get(id)
        .unwrap()
        .set_sign_in_facts(SignInFacts {
            acrs: vec!["c1".into()],
            auth_time: Some(unix(std::time::SystemTime::now())),
        });
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        body_text(res)
            .await
            .contains("Why do you need to see this value?")
    );
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", "Looking into it")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// POST a raw form body with the session cookie and same-site origin.
async fn support_post_raw(w: &World, path: &str, body: &str) -> StatusCode {
    use tower::ServiceExt;
    let req = axum::http::Request::post(path)
        .header("origin", "http://localhost:3000")
        .header("cookie", &w.cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap();
    w.app.clone().oneshot(req).await.unwrap().status()
}

#[test]
fn bad_settings_stop_keyring_at_start() {
    let base = |k: &str| -> Option<String> {
        match k {
            "ENTRA_TENANT_ID" => Some("00000000-0000-0000-0000-000000000000".into()),
            "ENTRA_CLIENT_ID" => Some("11111111-1111-1111-1111-111111111111".into()),
            "ENTRA_CLIENT_SECRET" => Some("x".into()),
            "APP_BASE_URL" => Some("http://localhost:3000".into()),
            "SESSION_SECRET" => Some("0123456789abcdef0123456789abcdef0123456789abcdef".into()),
            _ => None,
        }
    };
    let with = |extra: &'static [(&'static str, &'static str)]| {
        keyring::config::Config::from_lookup(move |k| {
            extra
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
                .or_else(|| base(k))
        })
    };
    assert!(with(&[]).is_ok());
    let err = with(&[("KEYRING_REQUIRE_REASON", "yes")]).unwrap_err();
    assert!(err.to_string().contains("KEYRING_REQUIRE_REASON"), "{err}");
    let err = with(&[
        ("KEYRING_REQUIRE_REASON", "reveal"),
        ("KEYRING_REASON_TICKET_PATTERN", "(INC"),
    ])
    .unwrap_err();
    assert!(
        err.to_string().contains("KEYRING_REASON_TICKET_PATTERN"),
        "{err}"
    );
}

#[tokio::test]
async fn a_bulk_change_asks_for_the_reason_on_its_review_page() {
    let w = seeded(&[ALL]).await;
    w.kv.state.put("api-key", "v");
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk",
            &[
                ("item", "db-password"),
                ("item", "api-key"),
                ("op", "tag_set"),
                ("tag_name", "rota"),
                ("tag_value", "payments"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("name=\"reason\""), "{html}");
    let patches = |w: &World| {
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PATCH"))
            .count()
    };
    let fields = [
        ("item", "db-password"),
        ("item", "api-key"),
        ("op", "tag_set"),
        ("tag_name", "rota"),
        ("tag_value", "payments"),
    ];
    // Without a reason nothing is changed.
    let res = w.post("/v/kv-test/secrets/-/bulk/apply", &fields).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(patches(&w), 0);
    let mut with_reason = fields.to_vec();
    with_reason.push(("reason", "Tagging the payments secrets"));
    let res = w
        .post("/v/kv-test/secrets/-/bulk/apply", &with_reason)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(patches(&w), 2);
}

/// The gate reads the same decoded vault and item the handler does, so a
/// percent-encoded segment can't get a value shown without a reason.
#[tokio::test]
async fn an_encoded_path_segment_still_needs_a_reason() {
    let w = seeded(&[ALL]).await;
    // A third version, so there is an older one to roll back to.
    let old = w.kv.state.put("db-password", "first-value");
    w.kv.state.put("db-password", SECRET);
    let before = kv_calls(&w);
    // `%6b` is `k`, `%64` is `d`, `%77` is `w`: the handler sees kv-test,
    // db-password and web-tls.
    for (path, fields) in [
        ("/v/%6bv-test/secrets/db-password/reveal", vec![]),
        ("/v/kv-test/secrets/%64b-password/reveal", vec![]),
        ("/v/%6Bv-test/secrets/%64b-password/reveal", vec![]),
        (
            "/v/%6bv-test/certificates/web-tls/download-key",
            vec![("confirm_name", "web-tls")],
        ),
        (
            "/v/kv-test/certificates/%77eb-tls/download-key",
            vec![("confirm_name", "web-tls")],
        ),
        (
            "/v/%6bv-test/secrets/db-password/rollback",
            vec![("version", old.as_str())],
        ),
        (
            "/v/kv-test/secrets/%64b-password/rollback",
            vec![("version", old.as_str())],
        ),
    ] {
        let res = w.post(path, &fields).await;
        // Asked for the reason, as for the plain address.
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        let html = body_text(res).await;
        assert!(html.contains("name=\"reason\""), "{path}: {html}");
        assert!(!html.contains(SECRET), "{path}");
        assert!(!html.contains("first-value"), "{path}");
    }
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
    assert_eq!(w.kv.state.version_count("db-password"), 4);

    // With the reason, the encoded address works like the plain one.
    let res = w
        .post(
            "/v/%6bv-test/secrets/db-password/reveal",
            &[("reason", "Checking the encoded path")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains(SECRET));
}

/// A request the gate can't place is refused, never handed on.
#[tokio::test]
async fn a_path_the_gate_cannot_place_is_refused() {
    let w = seeded(&[REVEAL]).await;
    let before = kv_calls(&w);
    for path in [
        // Not vault names, encoded or not.
        "/v/%2e%2e/secrets/db-password/reveal",
        "/v/kv%20test/secrets/db-password/reveal",
        "/v/x/secrets/db-password/reveal",
        "/v/kv-test%2fsecrets/secrets/db-password/reveal",
        "/v/%00/secrets/db-password/reveal",
    ] {
        for fields in [vec![], vec![("reason", "A perfectly good reason")]] {
            let res = w.post(path, &fields).await;
            assert!(res.status().is_client_error(), "{path}: {}", res.status());
            let html = body_text(res).await;
            assert!(!html.contains(SECRET), "{path}");
        }
    }
    assert_eq!(kv_calls(&w), before, "nothing reached Key Vault");
}
