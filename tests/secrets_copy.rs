//! Copy a secret to another vault without showing its value (#215).
//! Against a mock Key Vault serving two vaults, `kv-test` (the source)
//! and `kv-prod` (the target), and mock Resource Graph listing both.

mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use support::keyvault::KvState;
use support::{World, body_text, location};
use tower::ServiceExt;

const VALUE: &str = "C0py-Me-Secret-<&>\"'";
const COPY: &str = "/v/kv-test/secrets/db-password/copy";

struct Two {
    w: World,
    source: Arc<KvState>,
    target: Arc<KvState>,
}

impl Two {
    /// Key Vault calls other than the source's versions list, which the
    /// reveal limit check reads (properties only) before step-up and the
    /// reason.
    fn kv_calls(&self) -> usize {
        let not_list = |l: &&String| !(l.starts_with("GET ") && l.ends_with("/versions"));
        self.source
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(not_list)
            .count()
            + self.target.log.lock().unwrap().len()
    }

    fn value_reads(&self) -> usize {
        self.source
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("GET ") && l.ends_with("/secrets/db-password"))
            .count()
    }

    fn writes(&self) -> usize {
        self.target
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PUT "))
            .count()
    }
}

async fn two(extra: &[(&'static str, &'static str)]) -> Two {
    let source = Arc::new(KvState::default());
    let target = Arc::new(KvState::default());
    let w = support::world_of_vaults_with(
        vec![("kv-test", source.clone()), ("kv-prod", target.clone())],
        extra,
    )
    .await;
    source.put_with("db-password", VALUE, |v| {
        v.content_type = Some("text/plain".into());
        v.tags = [("env".to_owned(), "test".to_owned())].into();
        v.nbf = Some(1_700_000_000);
        v.exp = Some(4_000_000_000);
    });
    source.add_cert("web-tls", true, "UEZY");
    Two { w, source, target }
}

fn all_fields(name: &str) -> Vec<(&'static str, String)> {
    vec![
        ("to_vault", "kv-prod".into()),
        ("to_name", name.into()),
        ("content_type", "on".into()),
        ("tags", "on".into()),
        ("dates", "on".into()),
        ("enabled", "on".into()),
    ]
}

async fn post(t: &Two, path: &str, fields: &[(&'static str, String)]) -> (StatusCode, String) {
    let f: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let res = t.w.post(path, &f).await;
    let status = res.status();
    assert_eq!(
        res.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store, max-age=0"),
        "{path}: every answer in the flow is no-store"
    );
    (status, body_text(res).await)
}

#[tokio::test]
async fn the_form_lists_the_vaults_you_can_see() {
    let t = two(&[]).await;
    let res = t.w.get(COPY).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("cache-control").unwrap(),
        "no-store, max-age=0"
    );
    let html = body_text(res).await;
    assert!(html.contains("<option value=\"kv-prod\">kv-prod</option>"));
    assert!(
        html.contains("value=\"db-password\""),
        "same name by default"
    );
    assert!(html.contains("name=\"tags\" type=\"checkbox\" value=\"on\" checked"));
    assert!(!html.contains("C0py-Me"));
    assert_eq!(t.value_reads(), 0);
    // The secret's page links to it.
    let (_, html) = t.w.page("/v/kv-test/secrets/db-password").await;
    assert!(
        html.contains("href=\"/v/kv-test/secrets/db-password/copy\">Copy to another vault</a>")
    );
}

#[tokio::test]
async fn copy_to_a_new_name() {
    let t = two(&[]).await;
    // The review names both vaults and reads no value.
    let res = t
        .w
        .get(&format!(
            "{COPY}/review?to_vault=kv-prod&to_name=db-copy&content_type=on&tags=on&dates=on&enabled=on"
        ))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("cache-control").unwrap(),
        "no-store, max-age=0"
    );
    let html = body_text(res).await;
    assert!(html.contains(
        "There's no secret called <span class=\"item-name\">db-copy</span> in kv-prod yet."
    ));
    assert!(html.contains("The value isn't shown"));
    assert!(html.contains("<dd><span class=\"item-name\">db-password</span> in kv-test</dd>"));
    assert!(!html.contains("C0py-Me"));
    assert_eq!(t.value_reads(), 0, "the review reads no value");

    let (status, _) = {
        let f = all_fields("db-copy");
        let fv: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let res = t.w.post(COPY, &fv).await;
        assert_eq!(location(&res), "/v/kv-test/secrets/db-password");
        assert!(!location(&res).contains("C0py"));
        (res.status(), body_text(res).await)
    };
    assert_eq!(status, StatusCode::SEE_OTHER);
    let copied = t.target.current("db-copy").unwrap();
    assert_eq!(copied.value, VALUE);
    assert_eq!(copied.content_type.as_deref(), Some("text/plain"));
    assert_eq!(copied.tags.get("env").map(String::as_str), Some("test"));
    assert_eq!(
        (copied.nbf, copied.exp),
        (Some(1_700_000_000), Some(4_000_000_000))
    );
    assert!(copied.enabled);
    // The source is untouched, and the next page doesn't show the value.
    assert_eq!(t.source.version_count("db-password"), 1);
    let (_, html) = t.w.page("/v/kv-test/secrets/db-password").await;
    assert!(!html.contains("C0py-Me"));
    // Every call went as the person (their on-behalf-of token).
    for b in t.target.bearers.lock().unwrap().iter() {
        assert!(b.starts_with("Bearer obo:"), "as the person");
    }
}

#[tokio::test]
async fn bring_only_the_value() {
    let t = two(&[]).await;
    let (status, _) = post(
        &t,
        COPY,
        &[("to_vault", "kv-prod".into()), ("to_name", "bare".into())],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let copied = t.target.current("bare").unwrap();
    assert_eq!(copied.value, VALUE);
    assert_eq!(copied.content_type, None);
    assert!(copied.tags.is_empty());
    assert_eq!((copied.nbf, copied.exp), (None, None));
    assert!(!copied.enabled, "unticked enabled makes the copy disabled");
}

#[tokio::test]
async fn copy_onto_an_existing_name_adds_a_version() {
    let t = two(&[]).await;
    t.target.put("db-password", "old-target-value");
    let (status, html) = {
        let res =
            t.w.get(&format!(
                "{COPY}/review?to_vault=kv-prod&to_name=db-password"
            ))
            .await;
        (res.status(), body_text(res).await)
    };
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<strong>new version</strong>"), "{html}");
    assert!(!html.contains("old-target-value"));
    let (status, _) = post(&t, COPY, &all_fields("db-password")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(t.target.version_count("db-password"), 2);
    assert_eq!(t.target.current("db-password").unwrap().value, VALUE);
}

#[tokio::test]
async fn copy_onto_a_deleted_name_is_refused() {
    let t = two(&[]).await;
    t.target.put("gone", "x");
    t.target.soft_delete("gone");
    let res =
        t.w.get(&format!("{COPY}/review?to_vault=kv-prod&to_name=gone"))
            .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let html = body_text(res).await;
    assert!(html.contains(
        "A deleted secret called <span class=\"item-name\">gone</span> is still kept in kv-prod"
    ));
    assert!(!html.contains("Copy to kv-prod</button>"), "no copy button");
    // A post anyway stops before the value is read.
    let (status, html) = post(&t, COPY, &all_fields("gone")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(html.contains("Recover it first"), "{html}");
    assert_eq!(t.value_reads(), 0);
    assert_eq!(t.writes(), 0);
}

#[tokio::test]
async fn a_source_read_refused_writes_nothing() {
    let t = two(&[]).await;
    t.source.fail_each.lock().unwrap().push((
        Method::GET,
        "/secrets/db-password$".into(),
        403,
        "ForbiddenByRbac",
    ));
    let (status, html) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Key Vault Secrets User"), "{html}");
    assert!(!html.contains("private detail"));
    assert_eq!(t.writes(), 0, "nothing written");
    assert!(t.target.current("db-copy").is_none());
}

#[tokio::test]
async fn a_target_write_refused_says_not_copied() {
    let t = two(&[]).await;
    t.target.fail_each.lock().unwrap().push((
        Method::PUT,
        "/secrets/db-copy$".into(),
        403,
        "ForbiddenByRbac",
    ));
    let (status, html) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Not copied"), "{html}");
    assert!(
        html.contains("db-password wasn&#39;t copied to kv-prod")
            || html.contains("db-password wasn't copied to kv-prod"),
        "{html}"
    );
    assert!(html.contains("Key Vault Secrets Officer"), "{html}");
    assert!(!html.contains("C0py-Me"));
    assert!(!html.contains("private detail"), "never Azure's message");
    assert!(t.target.current("db-copy").is_none());
    assert_eq!(t.source.version_count("db-password"), 1);

    // Another failure: the status and code, never the message.
    t.target.fail_each.lock().unwrap().clear();
    t.target.fail_each.lock().unwrap().push((
        Method::PUT,
        "/secrets/db-copy$".into(),
        400,
        "BadParameter",
    ));
    let (status, html) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(html.contains("400 BadParameter"), "{html}");
    assert!(!html.contains("private detail"));
}

#[tokio::test]
async fn a_certificate_backing_secret_is_refused() {
    let t = two(&[]).await;
    let (status, _) = t.w.page("/v/kv-test/secrets/web-tls/copy").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, html) = post(
        &t,
        "/v/kv-test/secrets/web-tls/copy",
        &[
            ("to_vault", "kv-prod".into()),
            ("to_name", "web-tls".into()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("This secret belongs to a certificate"));
    assert_eq!(t.writes(), 0);
    // Nor written over one in the target.
    t.target.add_cert("prod-tls", true, "UEZY");
    let (status, html) = post(&t, COPY, &all_fields("prod-tls")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(html.contains("belongs to a certificate"), "{html}");
    assert_eq!(t.value_reads(), 0);
    assert_eq!(t.writes(), 0);
}

#[tokio::test]
async fn targets_that_are_not_allowed_are_refused_before_any_call() {
    let t = two(&[]).await;
    let cases: Vec<(&str, &str)> = vec![
        // Valid-looking, but not a vault the person can see.
        ("kv-other", "db-copy"),
        // Hostile vault names.
        ("evil.example.com", "db-copy"),
        ("kv-prod/../kv-test", "db-copy"),
        ("kv-prod%2f..", "db-copy"),
        ("", "db-copy"),
        ("kv-prod.vault.azure.net", "db-copy"),
        // Hostile names.
        ("kv-prod", "../db"),
        ("kv-prod", "a/b"),
        ("kv-prod", "-x"),
        ("kv-prod", ""),
        ("kv-prod", "db?x=1"),
        // The source itself.
        ("kv-test", "db-password"),
        ("KV-TEST", "DB-PASSWORD"),
    ];
    for (vault, name) in cases {
        let before = t.kv_calls();
        let (status, html) = post(
            &t,
            COPY,
            &[("to_vault", vault.into()), ("to_name", name.into())],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{vault} {name}");
        assert!(html.contains("Nothing was copied"), "{vault} {name}");
        assert_eq!(t.value_reads(), 0, "{vault} {name}");
        assert_eq!(t.writes(), 0, "{vault} {name}");
        assert!(
            t.kv_calls() - before <= 1,
            "{vault} {name}: only the source's properties"
        );
        // The review says so on the form instead.
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("to_vault", vault), ("to_name", name)])
            .finish();
        let res = t.w.get(&format!("{COPY}/review?{q}")).await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{vault} {name}"
        );
    }
    // A copy within the same vault under another name is fine.
    let (status, _) = post(
        &t,
        COPY,
        &[
            ("to_vault", "kv-test".into()),
            ("to_name", "db-other".into()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(t.source.current("db-other").unwrap().value, VALUE);
}

/// POST with a given token and origin.
async fn raw_post(t: &Two, path: &str, csrf: &str, origin: &str) -> StatusCode {
    let body = format!("csrf={csrf}&to_vault=kv-prod&to_name=db-copy");
    let req = Request::post(path)
        .header("origin", origin)
        .header("cookie", &t.w.cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    t.w.app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn form_token_and_cross_site_posts_are_refused() {
    let t = two(&[]).await;
    let before = t.kv_calls();
    assert_eq!(
        raw_post(&t, COPY, "forged", "http://localhost:3000").await,
        StatusCode::FORBIDDEN
    );
    // A token for the target vault isn't one for the source.
    let id = t.w.cookie.split('=').nth(1).unwrap();
    let prod_token =
        t.w.state
            .sessions
            .get(id)
            .unwrap()
            .csrf_for(Some("kv-prod"));
    assert_eq!(
        raw_post(&t, COPY, &prod_token, "http://localhost:3000").await,
        StatusCode::FORBIDDEN
    );
    // A good token from another site.
    assert_eq!(
        raw_post(&t, COPY, &t.w.csrf, "https://evil.example").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(t.kv_calls(), before, "nothing reached Key Vault");
    assert!(t.target.current("db-copy").is_none());
}

#[tokio::test]
async fn step_up_is_needed_as_for_a_reveal() {
    let t = two(&[("KEYRING_STEP_UP_AUTH_CONTEXT", "c1")]).await;
    let before = t.kv_calls();
    let (status, html) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Confirm it"), "{html}");
    assert!(
        html.contains("return_to=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password%2Fcopy"),
        "{html}"
    );
    assert_eq!(t.kv_calls(), before, "nothing reached Key Vault");
    // The review asks too.
    let res =
        t.w.get(&format!("{COPY}/review?to_vault=kv-prod&to_name=db-copy"))
            .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // Met: the copy goes ahead.
    let id = t.w.cookie.split('=').nth(1).unwrap();
    t.w.state
        .sessions
        .get(id)
        .unwrap()
        .set_sign_in_facts(keyring::auth::step_up::SignInFacts {
            acrs: vec!["c1".into()],
            auth_time: Some(keyring::auth::step_up::unix(std::time::SystemTime::now())),
        });
    let (status, _) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_reason_is_needed_as_for_a_reveal() {
    let t = two(&[("KEYRING_REQUIRE_REASON", "reveal")]).await;
    // The confirmation asks for it.
    let res =
        t.w.get(&format!("{COPY}/review?to_vault=kv-prod&to_name=db-copy"))
            .await;
    let html = body_text(res).await;
    assert!(html.contains("name=\"reason\""), "{html}");
    let before = t.kv_calls();
    let (status, html) = post(&t, COPY, &all_fields("db-copy")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Why are you copying this value?"), "{html}");
    // The reason page carries the target, never a value.
    assert!(html.contains("value=\"kv-prod\""), "{html}");
    assert!(!html.contains("C0py-Me"));
    assert_eq!(t.kv_calls(), before, "nothing reached Key Vault");
    // An encoded vault in the address is asked the same.
    let (status, html) = post(
        &t,
        "/v/%6bv-test/secrets/%64b-password/copy",
        &all_fields("db-copy"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("name=\"reason\""), "{html}");
    assert_eq!(t.kv_calls(), before, "nothing reached Key Vault");
    // With one, it goes ahead, from the encoded address too.
    let mut f = all_fields("db-copy");
    f.push(("reason", "Promoting to production".into()));
    let (status, _) = post(&t, "/v/%6bv-test/secrets/db-password/copy", &f).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(t.target.current("db-copy").unwrap().value, VALUE);
}

#[tokio::test]
async fn the_button_is_disabled_without_read_access() {
    let t = two(&[]).await;
    t.w.arm.state.authz.lock().unwrap().permissions =
        Some(vec![support::role_data_actions("Key Vault Reader")]);
    let (_, html) = t.w.page("/v/kv-test/secrets/db-password").await;
    assert!(
        html.contains("disabled aria-describedby=\"copy-needs\">Copy to another vault</button>"),
        "{html}"
    );
    assert!(html.contains(
        "<span class=\"needs-role\" id=\"copy-needs\">Needs Key Vault Secrets User</span>"
    ));
}

#[test]
fn copy_actions_need_step_up_and_count_as_reveals() {
    use keyring::audit::Action;
    assert_eq!(Action::SecretCopyRead.as_str(), "secret.copy.read");
    assert_eq!(Action::SecretCopyWrite.as_str(), "secret.copy.write");
    assert!(keyring::reason::is_reveal(Action::SecretCopyRead));
    assert_eq!(Action::SecretCopyRead.item_kind(), Some("secret"));
    assert_eq!(Action::SecretCopyWrite.item_kind(), Some("secret"));
}
