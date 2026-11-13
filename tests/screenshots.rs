//! A demo of Keyring for the README screenshots. Not a test: it serves the
//! real app, signed in, over the mocks in `tests/support`, with made-up
//! data, until it is stopped. `#[ignore]`d, so `cargo test` and CI skip it.
//!
//! ```sh
//! cargo test --test screenshots -- --ignored --nocapture
//! node scripts/screenshots.mjs
//! ```
//!
//! It listens on `127.0.0.1:3999` (or `KEYRING_DEMO_PORT`) and prints a
//! line `KEYRING_DEMO_COOKIE=keyring_session=...` once it is ready. Nothing
//! here talks to Azure. Every value is fake.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use serde_json::json;
use support::keyvault::KvState;

const DAY: i64 = 86_400;

/// A throwaway self-signed certificate, `CN=payments-api.demo.example`.
const DEMO_CERT_PEM: &str = include_str!("fixtures/demo-cert.pem");
/// A throwaway self-signed certificate that ends on 25 Nov 2026.
const DEMO_CERT_SOON_PEM: &str = include_str!("fixtures/demo-cert-soon.pem");

const PAYMENTS: &str = "kv-payments-prod";
const PLATFORM: &str = "kv-platform-dev";
const IDENTITY: &str = "kv-identity-test";

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn der(pem: &str) -> Option<Vec<u8>> {
    support::pem_first_cert(pem)
}

/// The vault the main screenshots use.
fn seed_payments(kv: &KvState) {
    let n = now();
    // Older versions first, so the detail page has a history.
    kv.put_with("db-connection-string", "demo-old-connection-string", |v| {
        v.content_type = Some("text/plain".into());
        v.created = n - 120 * DAY;
        v.updated = n - 120 * DAY;
    });
    kv.put_with(
        "db-connection-string",
        "Server=demo-sql.example;Database=payments;User Id=demo-app;Password=demo-not-a-real-password",
        |v| {
            v.content_type = Some("text/plain".into());
            v.created = n - 12 * DAY;
            v.updated = n - 12 * DAY;
            v.exp = Some(n + 18 * DAY);
            v.tags = tags(&[("owner", "payments-team"), ("rotation", "quarterly")]);
        },
    );
    kv.put_with("stripe-webhook-secret", "demo-whsec-0000000000", |v| {
        v.content_type = Some("text/plain".into());
        v.created = n - 400 * DAY;
        v.updated = n - 400 * DAY;
        v.exp = Some(n - 6 * DAY);
        v.tags = tags(&[("owner", "payments-team")]);
    });
    kv.put_with("legacy-ftp-password", "demo-legacy-value", |v| {
        v.enabled = false;
        v.created = n - 700 * DAY;
        v.updated = n - 90 * DAY;
        v.tags = tags(&[("status", "retired")]);
    });
    kv.put_with("partner-api-key", "demo-partner-key-0000", |v| {
        v.content_type = Some("application/x-api-key".into());
        v.created = n - DAY;
        v.updated = n - DAY;
        v.nbf = Some(n + 5 * DAY);
        v.exp = Some(n + 370 * DAY);
        v.tags = tags(&[("owner", "integrations")]);
    });
    kv.put_with(
        "jwt-signing-config",
        r#"{"issuer":"https://auth.demo.example","audience":"demo-api"}"#,
        |v| {
            v.content_type = Some("application/json".into());
            v.created = n - 30 * DAY;
            v.updated = n - 30 * DAY;
            v.exp = Some(n + 200 * DAY);
            v.tags = tags(&[("owner", "platform"), ("env", "prod")]);
        },
    );
    kv.put_with("smtp-relay-password", "demo-smtp-value", |v| {
        v.created = n - 60 * DAY;
        v.updated = n - 60 * DAY;
        v.exp = Some(n + 4 * DAY);
        v.tags = tags(&[("owner", "notifications")]);
    });
    kv.put_with("redis-access-key", "demo-redis-value", |v| {
        v.created = n - 45 * DAY;
        v.updated = n - 45 * DAY;
    });

    // Certificates. Each one also makes the key behind it.
    let policy = |subject: &str, exportable: bool, actions: serde_json::Value| {
        let mut p = support::certs::default_policy(exportable, false);
        p["x509_props"]["subject"] = json!(subject);
        p["lifetime_actions"] = actions;
        p
    };
    let version = kv.add_cert_version(
        "payments-api-tls",
        der(DEMO_CERT_PEM),
        policy(
            "CN=payments-api.demo.example",
            true,
            json!([{"trigger": {"days_before_expiry": 30}, "action": {"action_type": "AutoRenew"}}]),
        ),
        |v| {
            v.created = n - 12 * DAY;
            v.nbf = Some(n - 12 * DAY);
            v.exp = Some(n + 353 * DAY);
            v.tags = tags(&[("owner", "payments-team")]);
        },
    );
    kv.put_with("payments-api-tls", "demo-pfx-placeholder", |v| {
        v.content_type = Some("application/x-pkcs12".into());
        v.version = version.clone();
    });
    mark_managed(kv, "payments-api-tls");

    let version = kv.add_cert_version(
        "internal-gateway",
        der(DEMO_CERT_SOON_PEM),
        policy(
            "CN=internal-gateway.demo.example",
            false,
            json!([{"trigger": {"days_before_expiry": 30}, "action": {"action_type": "EmailContacts"}}]),
        ),
        |v| {
            v.created = n - 353 * DAY;
            v.nbf = Some(n - 353 * DAY);
            v.exp = Some(n + 12 * DAY);
            v.tags = tags(&[("owner", "platform")]);
        },
    );
    kv.put_with("internal-gateway", "demo-pfx-placeholder", |v| {
        v.content_type = Some("application/x-pkcs12".into());
        v.version = version.clone();
    });
    mark_managed(kv, "internal-gateway");

    // Keys: RSA with a rotation policy, EC, and one about to expire.
    kv.add_key_with("payments-signing", "RSA", |v| {
        v.created = n - 200 * DAY;
        v.exp = Some(n + 165 * DAY);
        v.ops = vec!["sign".into(), "verify".into()];
        v.tags = tags(&[("owner", "payments-team")]);
    });
    kv.add_key_with("payments-signing", "RSA", |v| {
        v.created = n - 20 * DAY;
        v.exp = Some(n + 345 * DAY);
        v.ops = vec!["sign".into(), "verify".into()];
        v.tags = tags(&[("owner", "payments-team")]);
    });
    kv.keys
        .lock()
        .unwrap()
        .get_mut("payments-signing")
        .unwrap()
        .rotation = json!({
        "lifetimeActions": [
            {"trigger": {"timeAfterCreate": "P335D"}, "action": {"type": "Rotate"}},
            {"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}
        ],
        "attributes": {"expiryTime": "P365D", "created": n - 200 * DAY, "updated": n - 20 * DAY}
    });
    kv.add_key_with("card-data-wrap", "RSA-HSM", |v| {
        v.created = n - 90 * DAY;
        v.ops = vec!["wrapKey".into(), "unwrapKey".into()];
        v.tags = tags(&[("pci", "in-scope")]);
    });
    kv.add_key_with("webhook-signer", "EC", |v| {
        v.crv = Some("P-256".into());
        v.created = n - 340 * DAY;
        v.exp = Some(n + 25 * DAY);
        v.ops = vec!["sign".into(), "verify".into()];
    });
    *kv.premium.lock().unwrap() = true;

    // Deleted items.
    kv.put_with("old-merchant-token", "demo-deleted-value", |v| {
        v.created = n - 300 * DAY;
        v.updated = n - 300 * DAY;
        v.tags = tags(&[("owner", "payments-team")]);
    });
    kv.soft_delete("old-merchant-token");
    kv.put_with("test-card-processor-key", "demo-deleted-value", |v| {
        v.created = n - 100 * DAY;
        v.updated = n - 100 * DAY;
    });
    kv.soft_delete("test-card-processor-key");
    let mut deleted = kv.deleted.lock().unwrap();
    for (i, d) in deleted.values_mut().enumerate() {
        d.deleted = n - (3 + 9 * i as i64) * DAY;
        d.purge = d.deleted + 90 * DAY;
    }
}

/// Make the secret and key Key Vault keeps behind a certificate read as
/// managed, as they do for real.
fn mark_managed(kv: &KvState, name: &str) {
    if let Some(s) = kv.secrets.lock().unwrap().get_mut(name) {
        s.managed = true;
    }
}

fn seed_platform(kv: &KvState) {
    let n = now();
    kv.put_with("github-actions-token", "demo-gha-token", |v| {
        v.created = n - 80 * DAY;
        v.updated = n - 80 * DAY;
        v.exp = Some(n + 10 * DAY);
        v.tags = tags(&[("owner", "platform")]);
    });
    kv.put_with("container-registry-password", "demo-acr-value", |v| {
        v.created = n - 340 * DAY;
        v.updated = n - 340 * DAY;
        v.exp = Some(n - 2 * DAY);
    });
    kv.put_with("grafana-admin", "demo-grafana-value", |v| {
        v.created = n - 20 * DAY;
        v.updated = n - 20 * DAY;
        v.exp = Some(n + 70 * DAY);
    });
    kv.put("feature-flags-sdk-key", "demo-flags-value");
    kv.add_key_with("terraform-state", "RSA", |v| {
        v.created = n - 150 * DAY;
        v.exp = Some(n + 215 * DAY);
    });
}

fn seed_identity(kv: &KvState) {
    let n = now();
    kv.put_with("oidc-client-secret", "demo-oidc-value", |v| {
        v.created = n - 170 * DAY;
        v.updated = n - 170 * DAY;
        v.exp = Some(n + 26 * DAY);
        v.tags = tags(&[("owner", "identity")]);
    });
    kv.put_with("saml-signing-passphrase", "demo-saml-value", |v| {
        v.created = n - 500 * DAY;
        v.updated = n - 500 * DAY;
        v.exp = Some(n + 140 * DAY);
    });
    let version = kv.add_cert_version(
        "sso-signing",
        der(DEMO_CERT_PEM),
        support::certs::default_policy(false, false),
        |v| {
            v.created = n - 40 * DAY;
            v.nbf = Some(n - 40 * DAY);
            v.exp = Some(n + 50 * DAY);
        },
    );
    kv.put_with("sso-signing", "demo-pfx-placeholder", |v| {
        v.content_type = Some("application/x-pkcs12".into());
        v.version = version.clone();
    });
    mark_managed(kv, "sso-signing");
}

fn vault_row(name: &str, sub: &str, env: &str, location: &str) -> serde_json::Value {
    let mut row = support::vault_row(name, sub, true);
    row["tags"] = json!({"env": env, "owner": "platform"});
    row["location"] = json!(location);
    row["enablePurgeProtection"] = json!(env == "prod");
    row
}

fn audit_row(ago_minutes: i64, who: &str, op: &str, item: &str, result: &str) -> [String; 6] {
    let t = now() - ago_minutes * 60;
    let secs = t.rem_euclid(DAY);
    [
        format!(
            "{}T{:02}:{:02}:{:02}Z",
            keyring::dates::iso_date(t),
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        ),
        who.into(),
        op.into(),
        item.into(),
        result.into(),
        "203.0.113.24".into(),
    ]
}

/// One mock Key Vault per vault name, all behind one address: requests
/// start `/{vault}/...`, so the first path segment picks the vault.
fn several_vaults(vaults: Vec<(&'static str, Arc<KvState>)>) -> Router {
    let routers: Vec<(&'static str, Router)> = vaults
        .into_iter()
        .map(|(name, state)| (name, support::keyvault::router(state)))
        .collect();
    Router::new().fallback(move |req: Request| {
        let routers = routers.clone();
        async move {
            use tower::ServiceExt;
            let vault = req.uri().path().split('/').nth(1).unwrap_or_default();
            let router = routers
                .iter()
                .find(|(n, _)| *n == vault)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| routers[0].1.clone());
            router.oneshot(req).await.unwrap()
        }
    })
}

#[tokio::test]
#[ignore = "serves a demo for the README screenshots until stopped"]
async fn serve_demo_for_screenshots() {
    let port: u16 = std::env::var("KEYRING_DEMO_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3999);
    let base_url: &'static str = format!("http://127.0.0.1:{port}").leak();

    let idp = support::start_idp().await;
    let arm = support::start_arm().await;

    let vaults: Vec<(&'static str, Arc<KvState>)> = [PAYMENTS, PLATFORM, IDENTITY]
        .into_iter()
        .map(|n| (n, Arc::new(KvState::default())))
        .collect();
    seed_payments(&vaults[0].1);
    seed_platform(&vaults[1].1);
    seed_identity(&vaults[2].1);
    let kv_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kv_url = format!("http://{}", kv_listener.local_addr().unwrap());
    let kv_app = several_vaults(vaults);
    tokio::spawn(async move { axum::serve(kv_listener, kv_app).await.unwrap() });

    *arm.state.subscriptions.lock().unwrap() = vec![
        json!({"id": "/subscriptions/sub-a", "subscriptionId": "sub-a", "name": "Demo Production"}),
        json!({"id": "/subscriptions/sub-b", "subscriptionId": "sub-b", "name": "Demo Development"}),
    ];
    *arm.state.vaults.lock().unwrap() = vec![
        vault_row(PAYMENTS, "sub-a", "prod", "australiaeast"),
        vault_row(IDENTITY, "sub-b", "test", "australiasoutheast"),
        vault_row(PLATFORM, "sub-b", "dev", "australiaeast"),
    ];
    *arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    *arm.state.audit_rows.lock().unwrap() = vec![
        audit_row(
            4,
            "alex.taylor@demo.example",
            "SecretGet",
            "db-connection-string",
            "OK",
        ),
        audit_row(
            38,
            "alex.taylor@demo.example",
            "SecretSet",
            "db-connection-string",
            "OK",
        ),
        audit_row(
            95,
            "deploy-pipeline (app)",
            "SecretGet",
            "stripe-webhook-secret",
            "OK",
        ),
        audit_row(
            160,
            "sam.nguyen@demo.example",
            "KeyRotate",
            "payments-signing",
            "OK",
        ),
        audit_row(
            300,
            "jordan.lee@demo.example",
            "SecretGet",
            "legacy-ftp-password",
            "Forbidden",
        ),
        audit_row(
            420,
            "sam.nguyen@demo.example",
            "CertificatePolicyUpdate",
            "payments-api-tls",
            "OK",
        ),
        audit_row(
            1500,
            "alex.taylor@demo.example",
            "SecretDelete",
            "old-merchant-token",
            "OK",
        ),
        audit_row(
            2900,
            "deploy-pipeline (app)",
            "KeySign",
            "webhook-signer",
            "OK",
        ),
    ];

    let env: std::collections::HashMap<&str, String> = std::collections::HashMap::from([
        ("ENTRA_TENANT_ID", support::TENANT.to_owned()),
        ("ENTRA_CLIENT_ID", support::CLIENT_ID.to_owned()),
        ("ENTRA_CLIENT_SECRET", support::CLIENT_SECRET.to_owned()),
        ("ENTRA_AUTHORITY_HOST", idp.authority()),
        ("KEYRING_TEST_MANAGEMENT_URL", arm.url()),
        ("KEYRING_TEST_KEYVAULT_URL", kv_url),
        ("KEYRING_TEST_LOGANALYTICS_URL", arm.url()),
        ("APP_BASE_URL", base_url.to_owned()),
        (
            "SESSION_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        ),
    ]);
    let config =
        keyring::config::Config::from_lookup(|k| env.get(k).cloned()).expect("demo config");

    use keyring::auth::session::{User, UserId, UserTokens};
    let state = keyring::AppState::new(config);
    let id = state.sessions.create(
        User {
            name: "Alex Taylor".into(),
            username: Some("alex.taylor@demo.example".into()),
            subject: UserId {
                sub: "demo-subject".into(),
                oid: Some(support::USER_OID.into()),
                tid: Some(support::TENANT.into()),
            },
        },
        UserTokens {
            access_token: keyring::secret::Secret::new("demo-user-token"),
            // Sessions end after the absolute timeout whatever this says.
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(8 * 3600),
            refresh_token: None,
        },
    );
    state
        .sessions
        .get(&id)
        .unwrap()
        .select_vault(PAYMENTS.into());

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("demo port is free");
    println!("Keyring demo at {base_url}");
    println!("KEYRING_DEMO_COOKIE=keyring_session={id}");
    keyring::serve::serve(listener, keyring::app(state), std::future::pending())
        .await
        .unwrap();
}
