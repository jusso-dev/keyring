//! Multi-environment collaboration: environment grouping, parity matrix, CSV
//! export, sibling links on secret detail pages, and writing distinct values
//! across multiple environments in one audited workflow.

mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::keyvault::KvState;
use tower::ServiceExt;

const DAY: i64 = 86_400;

struct MultiEnvWorld {
    app: axum::Router,
    cookie: String,
    csrf: String,
    dev: Arc<KvState>,
    test: Arc<KvState>,
    prod: Arc<KvState>,
    _arm: support::MockArm,
}

async fn multi_world(extra: &[(&'static str, &'static str)]) -> MultiEnvWorld {
    let idp = support::start_idp().await;
    let arm = support::start_arm().await;

    let dev = Arc::new(KvState::default());
    let test = Arc::new(KvState::default());
    let prod = Arc::new(KvState::default());

    let kv_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kv_url = format!("http://{}", kv_listener.local_addr().unwrap());
    let kv_app = support::keyvault::several_vaults(vec![
        ("kv-payments-dev", dev.clone()),
        ("kv-payments-test", test.clone()),
        ("kv-payments-prod", prod.clone()),
    ]);
    tokio::spawn(async move { axum::serve(kv_listener, kv_app).await.unwrap() });

    let mut row_prod = support::vault_row("kv-payments-prod", "sub-prod", true);
    row_prod["tags"] = json!({"app": "payments", "env": "prod"});
    let mut row_test = support::vault_row("kv-payments-test", "sub-nonprod", true);
    row_test["tags"] = json!({"app": "payments", "env": "test"});
    let mut row_dev = support::vault_row("kv-payments-dev", "sub-nonprod", true);
    row_dev["tags"] = json!({"app": "payments", "env": "dev"});
    // Deliberately unsorted so promotion ordering (dev -> test -> prod) is verified.
    *arm.state.vaults.lock().unwrap() = vec![row_prod, row_test, row_dev];
    *arm.state.subscriptions.lock().unwrap() = vec![
        json!({"id": "/subscriptions/sub-prod", "subscriptionId": "sub-prod", "name": "Prod"}),
        json!({"id": "/subscriptions/sub-nonprod", "subscriptionId": "sub-nonprod", "name": "NonProd"}),
    ];

    let mut env = std::collections::HashMap::from([
        ("ENTRA_TENANT_ID", support::TENANT.to_owned()),
        ("ENTRA_CLIENT_ID", support::CLIENT_ID.to_owned()),
        ("ENTRA_CLIENT_SECRET", support::CLIENT_SECRET.to_owned()),
        ("ENTRA_AUTHORITY_HOST", idp.authority()),
        ("KEYRING_TEST_MANAGEMENT_URL", arm.url()),
        ("KEYRING_TEST_KEYVAULT_URL", kv_url),
        ("KEYRING_TEST_LOGANALYTICS_URL", arm.url()),
        ("APP_BASE_URL", "http://localhost:3000".to_owned()),
        (
            "SESSION_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        ),
    ]);
    for (k, v) in extra {
        env.insert(k, (*v).to_owned());
    }
    let config = keyring::config::Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let state = keyring::AppState::new(config);
    let session_id = state.sessions.create(
        keyring::auth::session::User {
            name: "Alex Taylor".into(),
            username: Some("alex@example.com".into()),
            subject: keyring::auth::session::UserId {
                sub: "sub-alex".into(),
                oid: Some(support::USER_OID.into()),
                tid: Some(support::TENANT.into()),
            },
        },
        keyring::auth::session::UserTokens {
            access_token: keyring::secret::Secret::new("user-token"),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            refresh_token: None,
        },
    );
    let csrf = state.sessions.get(&session_id).unwrap().csrf_token();
    let app = keyring::app(state);
    MultiEnvWorld {
        app,
        cookie: format!("keyring_session={session_id}"),
        csrf,
        dev,
        test,
        prod,
        _arm: arm,
    }
}

impl MultiEnvWorld {
    async fn get(&self, path: &str) -> (StatusCode, String) {
        let res = self
            .app
            .clone()
            .oneshot(
                Request::get(path)
                    .header("cookie", &self.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let text = support::body_text(res).await;
        (status, text)
    }

    async fn post(&self, path: &str, pairs: &[(&str, &str)]) -> (StatusCode, String) {
        let mut form: Vec<(&str, &str)> = vec![("csrf", &self.csrf)];
        form.extend_from_slice(pairs);
        let body = form
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    keyring::auth::return_to::encode(k),
                    keyring::auth::return_to::encode(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let res = self
            .app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", &self.cookie)
                    .header("origin", "http://localhost:3000")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let text = support::body_text(res).await;
        (status, text)
    }
}

#[tokio::test]
async fn matrix_discovers_groups_spots_missing_and_drift_and_never_reads_values() {
    let w = multi_world(&[]).await;
    let now = keyring::azure::secrets::now_ts();

    // Missing in prod
    w.dev
        .put_with("new-feature-key", "dev-secret-never-shown", |v| {
            v.tags.insert("owner".into(), "alex@example.com".into());
        });
    w.test
        .put_with("new-feature-key", "test-secret-never-shown", |v| {
            v.tags.insert("owner".into(), "alex@example.com".into());
        });

    // In sync across all three
    for (kv, val) in [
        (&w.dev, "dev-db-val"),
        (&w.test, "test-db-val"),
        (&w.prod, "prod-db-val"),
    ] {
        kv.put_with("db-password", val, |v| {
            v.created = now - 5 * DAY;
            v.exp = Some(now + 90 * DAY);
            v.tags.insert("owner".into(), "team@example.com".into());
        });
    }

    // Owner drift between dev/test and prod
    w.dev.put_with("stripe-key", "dev-stripe", |v| {
        v.tags.insert("owner".into(), "dev-team@example.com".into());
    });
    w.test.put_with("stripe-key", "test-stripe", |v| {
        v.tags.insert("owner".into(), "dev-team@example.com".into());
    });
    w.prod.put_with("stripe-key", "prod-stripe", |v| {
        v.tags
            .insert("owner".into(), "prod-team@example.com".into());
    });

    let (status, html) = w.get("/environments").await;
    assert_eq!(status, StatusCode::OK);
    // Promotion order: dev before test before prod.
    let p_dev = html.find("kv-payments-dev").unwrap();
    let p_test = html.find("kv-payments-test").unwrap();
    let p_prod = html.find("kv-payments-prod").unwrap();
    assert!(
        p_dev < p_test && p_test < p_prod,
        "dev -> test -> prod order"
    );
    assert!(html.contains("Missing in an environment"));
    assert!(html.contains("Metadata differs"));
    assert!(html.contains("Owner differs"));
    assert!(html.contains("In sync"));
    // Direct create & copy links for missing secret in prod.
    assert!(
        html.contains("/v/kv-payments-prod/secrets/-/new?name=new-feature-key"),
        "create link pre-fills secret name"
    );
    assert!(
        html.contains("/v/kv-payments-dev/secrets/new-feature-key/copy?to_vault=kv-payments-prod"),
        "copy link pre-fills target vault"
    );

    // No secret values were read or rendered!
    for secret in [
        "dev-secret-never-shown",
        "test-secret-never-shown",
        "dev-db-val",
        "prod-db-val",
    ] {
        assert!(!html.contains(secret), "matrix must never show {secret}");
    }
    for (label, kv) in [("dev", &w.dev), ("test", &w.test), ("prod", &w.prod)] {
        let log = kv.log.lock().unwrap();
        assert!(
            log.iter().all(|req| !req.contains("/secrets/db-password")),
            "{label} should only list properties, never read values: {log:?}"
        );
    }

    // CSV export works and includes parity and drift notes, never values.
    let (status, csv) = w.get("/environments.csv").await;
    assert_eq!(status, StatusCode::OK);
    assert!(csv.contains("new-feature-key,Missing in an environment"));
    assert!(csv.contains("stripe-key,Metadata differs,Owner differs"));
    assert!(!csv.contains("prod-db-val"));

    // Filter by parity=missing shows only new-feature-key.
    let (status, filtered) = w
        .get(
            "/environments?vaults=kv-payments-dev,kv-payments-test,kv-payments-prod&parity=missing",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(filtered.contains("new-feature-key"));
    assert!(!filtered.contains(">db-password<"));

    // Filter by Owned by me (alex@example.com) shows only new-feature-key.
    let (status, mine) = w
        .get("/environments?vaults=kv-payments-dev,kv-payments-test,kv-payments-prod&mine=1")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(mine.contains("new-feature-key"));
    assert!(!mine.contains(">db-password<"));
}

#[tokio::test]
async fn unreadable_vault_shows_not_read_instead_of_missing() {
    let w = multi_world(&[]).await;
    w.dev.put("api-token", "dev-val");
    *w.prod.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));

    let (status, html) = w.get("/environments").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Couldn&#x27;t read") || html.contains("Couldn't read"));
    assert!(html.contains(">Not read<"));
    let (_, csv) = w.get("/environments.csv").await;
    assert!(csv.contains("kv-payments-prod,NOT READ,"));
}

#[tokio::test]
async fn secret_detail_shows_sibling_environments_and_prefill_links_work() {
    let w = multi_world(&[]).await;
    w.dev.put("shared-api-key", "dev-v1");
    w.test.put("shared-api-key", "test-v1");

    let (status, html) = w.get("/v/kv-payments-dev/secrets/shared-api-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Across environments"));
    assert!(html.contains("kv-payments-test"));
    assert!(html.contains("kv-payments-prod"));
    assert!(html.contains(">Missing<"));
    assert!(html.contains("/v/kv-payments-prod/secrets/-/new?name=shared-api-key"));
    assert!(
        html.contains("/v/kv-payments-dev/secrets/shared-api-key/copy?to_vault=kv-payments-prod")
    );

    // Following the pre-filled Create link populates #name.
    let (status, new_html) = w
        .get("/v/kv-payments-prod/secrets/-/new?name=shared-api-key")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(new_html.contains("value=\"shared-api-key\""));

    // Following the pre-filled Copy link pre-selects kv-payments-prod.
    let (status, copy_html) = w
        .get("/v/kv-payments-dev/secrets/shared-api-key/copy?to_vault=kv-payments-prod&to_name=shared-api-key")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(copy_html.contains("value=\"kv-payments-prod\" selected"));
}

#[tokio::test]
async fn set_across_environments_writes_distinct_values_and_guards_duplicates() {
    let w = multi_world(&[]).await;
    let vaults = "kv-payments-dev,kv-payments-test,kv-payments-prod";

    // Form renders with three labelled environment inputs.
    let (status, form_html) = w
        .get(&format!(
            "/environments/set?vaults={vaults}&name=webhook-secret"
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(form_html.contains("id=\"env-val-1\""));
    assert!(form_html.contains("id=\"env-val-2\""));
    assert!(form_html.contains("id=\"env-val-3\""));
    assert!(form_html.contains("value=\"webhook-secret\""));

    // 1. Accidental reuse of the same value in dev and prod is refused!
    let (status, err_html) = w
        .post(
            "/environments/set",
            &[
                ("vaults", vaults),
                ("name", "webhook-secret"),
                ("env-val-1", "AccidentallyReused!99"),
                ("env-val-2", "UniqueTestSecret!88"),
                ("env-val-3", "AccidentallyReused!99"),
                ("enabled", "1"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(err_html.contains("includes a production environment"));
    assert!(err_html.contains("allow_duplicate"));
    // Values are never echoed back into the form!
    assert!(!err_html.contains("AccidentallyReused!99"));
    assert!(!err_html.contains("UniqueTestSecret!88"));
    assert!(w.dev.current("webhook-secret").is_none());
    assert!(w.prod.current("webhook-secret").is_none());

    // 2. Distinct values per environment succeed (leaving test blank skips test).
    let (status, res_html) = w
        .post(
            "/environments/set",
            &[
                ("vaults", vaults),
                ("name", "webhook-secret"),
                ("env-val-1", "DevOnlySecretValue!11"),
                ("env-val-2", ""),
                ("env-val-3", "ProdOnlySecretValue!33"),
                ("description", "Webhook HMAC secret"),
                ("owner", "alex@example.com"),
                ("reveal", "copy-only"),
                ("enabled", "1"),
                ("tag-rows", "1"),
                ("tag-name-1", "service"),
                ("tag-value-1", "payments"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{res_html}");
    assert!(res_html.contains("2 environments written"));
    assert!(res_html.contains(">Created<"));
    assert!(res_html.contains(">Skipped<"));
    assert!(!res_html.contains("DevOnlySecretValue!11"));
    assert!(!res_html.contains("ProdOnlySecretValue!33"));

    let dev_cur = w.dev.current("webhook-secret").expect("written in dev");
    assert_eq!(dev_cur.value, "DevOnlySecretValue!11");
    assert_eq!(
        dev_cur.tags.get("owner").map(String::as_str),
        Some("alex@example.com")
    );
    assert_eq!(
        dev_cur.tags.get("keyring-reveal").map(String::as_str),
        Some("copy-only")
    );
    assert_eq!(
        dev_cur.tags.get("service").map(String::as_str),
        Some("payments")
    );
    assert!(w.test.current("webhook-secret").is_none(), "blank skipped");
    let prod_cur = w.prod.current("webhook-secret").expect("written in prod");
    assert_eq!(prod_cur.value, "ProdOnlySecretValue!33");
}

#[tokio::test]
async fn set_across_environments_enforces_password_policy_owner_reveal_carry_and_partial_rbac() {
    let w = multi_world(&[
        ("KEYRING_PASSWORD_POLICY", "min=12,upper,digit"),
        ("KEYRING_REQUIRE_OWNER", "true"),
        ("KEYRING_REQUIRE_REASON", "all"),
    ])
    .await;
    let vaults = "kv-payments-dev,kv-payments-test,kv-payments-prod";

    // Pre-seed dev with a stricter reveal limit (`none`) to verify carry-forward.
    w.dev.put_with("db-pass", "OldDevPass1234", |v| {
        v.tags.insert("keyring-reveal".into(), "none".into());
    });
    // Deny writes on prod (simulate dev having Secrets Officer in dev/test only).
    w.prod.fail_each.lock().unwrap().push((
        Method::PUT,
        "/secrets/db-pass".into(),
        403,
        "ForbiddenByRbac",
    ));

    // Missing reason is stopped by the reason gate without echoing values.
    let (status, reason_html) = w
        .post(
            "/environments/set",
            &[
                ("vaults", vaults),
                ("name", "db-pass"),
                ("env-val-1", "StrongDevPass1234"),
                ("owner", "alex@example.com"),
                ("enabled", "1"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(reason_html.contains("Why are you making this change?"));
    assert!(!reason_html.contains("StrongDevPass1234"));

    // Weak password + missing owner refused with reason supplied.
    let (status, err_html) = w
        .post(
            "/environments/set",
            &[
                ("vaults", vaults),
                ("name", "db-pass"),
                ("env-val-1", "weak"),
                ("reason", "Quarterly database password rotation"),
                ("enabled", "1"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(err_html.contains("at least 12 characters"));
    assert!(err_html.contains("Give an owner email address"));

    // Valid values with partial RBAC failure on prod: dev & test succeed, prod
    // reports Refused with a link to My access, and dev keeps `keyring-reveal=none`.
    let (status, res_html) = w
        .post(
            "/environments/set",
            &[
                ("vaults", vaults),
                ("name", "db-pass"),
                ("env-val-1", "StrongDevPass1234"),
                ("env-val-2", "StrongTestPass5678"),
                ("env-val-3", "StrongProdPass9012"),
                ("owner", "alex@example.com"),
                ("reveal", ""), // attempting to leave blank must NOT loosen dev's `none`!
                ("reason", "Quarterly database password rotation"),
                ("enabled", "1"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{res_html}");
    assert!(res_html.contains("2 environments written, 1 not written"));
    assert!(res_html.contains(">New version<"));
    assert!(res_html.contains(">Created<"));
    assert!(res_html.contains(">Refused<"));
    assert!(res_html.contains("/v/kv-payments-prod/my-access"));

    let dev_cur = w.dev.current("db-pass").unwrap();
    assert_eq!(dev_cur.value, "StrongDevPass1234");
    assert_eq!(
        dev_cur.tags.get("keyring-reveal").map(String::as_str),
        Some("none"),
        "stricter reveal limit on existing secret must be carried forward"
    );
    assert_eq!(
        w.test.current("db-pass").unwrap().value,
        "StrongTestPass5678"
    );
    assert!(w.prod.current("db-pass").is_none());
}
