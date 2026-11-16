//! Permission hints: buttons the person's roles don't allow are disabled,
//! with the role they need, and never hidden. Against mock ARM's
//! `permissions` and mock Key Vault. Key Vault still decides: a POST from
//! a person whose button was disabled still reaches it.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{body_text, role_data_actions};

const VAULT: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";

async fn world(rbac: bool, roles: Option<&[&str]>) -> support::World {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", rbac)];
    w.arm.state.authz.lock().unwrap().permissions =
        roles.map(|r| r.iter().map(|n| role_data_actions(n)).collect());
    w.kv.state.put("db-password", "VALUE-1");
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w
}

async fn page(w: &support::World, path: &str) -> String {
    let (status, html) = w.page(path).await;
    assert_eq!(status, StatusCode::OK, "{path}");
    html
}

/// The control labelled `label`: disabled, with "Needs {role}" tied to it.
fn assert_disabled(html: &str, id: &str, label: &str, role: &str) {
    let needs = format!("<span class=\"needs-role\" id=\"{id}-needs\">Needs {role}</span>");
    assert!(html.contains(&needs), "no '{needs}' for {label}");
    let button = html
        .split("<button")
        .find(|b| b.contains(&format!("aria-describedby=\"{id}-needs\"")))
        .unwrap_or_else(|| panic!("no button described by {id}-needs"));
    assert!(button.contains(" disabled"), "{label}: {button}");
    assert!(
        button.contains(&format!(">{label}</button>")),
        "{label}: {button}"
    );
}

/// The control labelled `label` is there and usable.
fn assert_enabled(html: &str, label: &str) {
    assert!(
        html.contains(&format!("\">{label}</a>")) || html.contains(&format!(">{label}</button>")),
        "{label} missing"
    );
    for chunk in html.split("<button").skip(1) {
        let tag = &chunk[..chunk.find("</button>").unwrap_or(chunk.len())];
        if tag.ends_with(&format!(">{label}")) {
            assert!(!tag.contains(" disabled"), "{label} is disabled: {tag}");
        }
    }
    assert!(!html.contains("class=\"needs-role\""), "a role note shown");
}

#[tokio::test]
async fn reader_sees_change_buttons_disabled_with_the_role() {
    let w = world(true, Some(&["Key Vault Reader"])).await;

    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_disabled(
        &html,
        "set-value",
        "Set a new value",
        "Key Vault Secrets Officer",
    );
    assert_disabled(&html, "edit", "Edit details", "Key Vault Secrets Officer");
    assert_disabled(&html, "delete", "Delete", "Key Vault Secrets Officer");
    assert_disabled(&html, "disable", "Disable", "Key Vault Secrets Officer");
    assert_disabled(&html, "reveal", "Show value", "Key Vault Secrets User");
    assert!(
        !html.contains("/secrets/db-password/delete\""),
        "no link left"
    );
    // Reading pages stay links.
    assert!(html.contains("/secrets/db-password/versions\">Versions</a>"));

    let html = page(&w, "/v/kv-test/certificates/web-tls").await;
    assert_disabled(&html, "delete", "Delete", "Key Vault Certificates Officer");
    assert_disabled(
        &html,
        "disable",
        "Disable",
        "Key Vault Certificates Officer",
    );
    assert!(html.contains("/certificates/web-tls/cer\">Download .cer</a>"));
    assert!(
        html.contains("/download-key\">Download with private key</a>"),
        "never hinted: its backing secret's own scope isn't asked"
    );

    let html = page(&w, "/v/kv-test/keys/app-key").await;
    assert_disabled(&html, "rotate", "Rotate now", "Key Vault Crypto Officer");
    assert_disabled(&html, "delete", "Delete", "Key Vault Crypto Officer");

    let html = page(&w, "/v/kv-test/secrets").await;
    assert_disabled(
        &html,
        "create",
        "Create a secret",
        "Key Vault Secrets Officer",
    );
    let html = page(&w, "/v/kv-test/certificates").await;
    assert_disabled(
        &html,
        "upload",
        "Upload a certificate",
        "Key Vault Certificates Officer",
    );
    assert_disabled(
        &html,
        "create",
        "Create a certificate",
        "Key Vault Certificates Officer",
    );
    let html = page(&w, "/v/kv-test/keys").await;
    assert_disabled(&html, "create", "Create a key", "Key Vault Crypto Officer");
}

#[tokio::test]
async fn officer_sees_them_enabled() {
    let w = world(true, Some(&["Key Vault Secrets Officer"])).await;
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    for label in [
        "Set a new value",
        "Edit details",
        "Delete",
        "Disable",
        "Show value",
    ] {
        assert_enabled(&html, label);
    }
    assert_enabled(&page(&w, "/v/kv-test/secrets").await, "Create a secret");
    // Secrets Officer only: the key page still says what it needs.
    let keys = page(&w, "/v/kv-test/keys/app-key").await;
    assert_disabled(&keys, "rotate", "Rotate now", "Key Vault Crypto Officer");
}

#[tokio::test]
async fn not_data_actions_disable_just_what_they_take_away() {
    let w = world(true, None).await;
    w.arm.state.authz.lock().unwrap().permissions = Some(vec![(
        vec!["microsoft.keyvault/vaults/SECRETS/*".into()],
        vec!["Microsoft.KeyVault/vaults/secrets/delete".into()],
    )]);
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_disabled(&html, "delete", "Delete", "Key Vault Secrets Officer");
    assert!(html.contains("/secrets/db-password/value\">Set a new value</a>"));
}

#[tokio::test]
async fn arm_failure_leaves_every_button_enabled() {
    for broken in ["status", "garbled", "slow", "not given"] {
        let w = world(true, Some(&["Key Vault Reader"])).await;
        {
            let mut m = w.arm.state.authz.lock().unwrap();
            match broken {
                "status" => m.permissions_status = Some(500),
                "garbled" => m.permissions_garbled = true,
                "slow" => m.permissions_delay = Duration::from_secs(4),
                _ => m.permissions = None,
            }
        }
        let started = std::time::Instant::now();
        let html = page(&w, "/v/kv-test/secrets/db-password").await;
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{broken}: waited"
        );
        for label in ["Set a new value", "Delete", "Show value"] {
            assert_enabled(&html, label);
        }
        assert_enabled(&page(&w, "/v/kv-test/secrets").await, "Create a secret");
    }
}

#[tokio::test]
async fn vault_lookup_failure_leaves_every_button_enabled() {
    let w = world(true, Some(&["Key Vault Reader"])).await;
    w.arm.state.vaults.lock().unwrap().clear();
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_enabled(&html, "Set a new value");
}

#[tokio::test]
async fn access_policy_vault_leaves_every_button_enabled() {
    let w = world(false, Some(&["Key Vault Reader"])).await;
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    for label in ["Set a new value", "Delete", "Show value"] {
        assert_enabled(&html, label);
    }
    assert_enabled(&page(&w, "/v/kv-test/keys/app-key").await, "Rotate now");
}

#[tokio::test]
async fn item_pages_ask_at_the_items_scope() {
    let w = world(true, Some(&["Key Vault Reader"])).await;
    // An Officer role given on this one secret only.
    w.arm.state.authz.lock().unwrap().permissions_at = vec![(
        format!("{VAULT}/secrets/db-password"),
        vec![role_data_actions("Key Vault Secrets Officer")],
    )];
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_enabled(&html, "Set a new value");
    // The vault-scope answer still says Reader, for the list.
    let list = page(&w, "/v/kv-test/secrets").await;
    assert_disabled(
        &list,
        "create",
        "Create a secret",
        "Key Vault Secrets Officer",
    );
    let paths = w.arm.state.authz.lock().unwrap().paths.clone();
    assert!(
        paths.contains(&format!(
            "{VAULT}/secrets/db-password/providers/Microsoft.Authorization/permissions"
        )),
        "{paths:?}"
    );
}

#[tokio::test]
async fn item_scope_refused_leaves_buttons_enabled_even_if_the_vault_says_reader() {
    let w = world(true, None).await;
    // Reader at the vault, and the item's own scope refused.
    w.arm.state.authz.lock().unwrap().permissions_at = vec![(
        VAULT.to_owned(),
        vec![role_data_actions("Key Vault Reader")],
    )];
    assert_disabled(
        &page(&w, "/v/kv-test/secrets").await,
        "create",
        "Create a secret",
        "Key Vault Secrets Officer",
    );
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_enabled(&html, "Set a new value");
    assert_enabled(&html, "Delete");
}

#[tokio::test]
async fn permissions_are_read_once_per_scope_and_session_with_the_persons_token() {
    let w = world(true, Some(&["Key Vault Reader"])).await;
    page(&w, "/v/kv-test/secrets").await;
    page(&w, "/v/kv-test/secrets").await;
    page(&w, "/v/kv-test/keys").await;
    let m = w.arm.state.authz.lock().unwrap();
    let reads: Vec<_> = m
        .paths
        .iter()
        .zip(&m.bearers)
        .filter(|(p, _)| p.ends_with("/providers/Microsoft.Authorization/permissions"))
        .collect();
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(
        reads[0]
            .1
            .starts_with("Bearer obo:https://management.azure.com/.default:for:user-api-token"),
        "{}",
        reads[0].1
    );
}

#[tokio::test]
async fn a_post_from_a_disabled_button_still_reaches_key_vault() {
    let w = world(true, Some(&["Key Vault Reader"])).await;
    let html = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_disabled(
        &html,
        "set-value",
        "Set a new value",
        "Key Vault Secrets Officer",
    );

    // The hint was wrong (a role it couldn't see): Key Vault allows it.
    let before = w.kv.state.version_count("db-password");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[("value", "new"), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.version_count("db-password"), before + 1);

    // Key Vault refuses: its own 403 page, with the role.
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    for (path, fields) in [
        (
            "/v/kv-test/secrets/db-password/value",
            vec![("value", "again"), ("enabled", "on")],
        ),
        (
            "/v/kv-test/secrets/db-password/delete",
            vec![("confirm_name", "db-password")],
        ),
        ("/v/kv-test/keys/app-key/rotate", vec![]),
    ] {
        let before = w.kv.state.log.lock().unwrap().len();
        let res = w.post(path, &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        assert!(
            w.kv.state.log.lock().unwrap().len() > before,
            "{path} reached Key Vault"
        );
        let html = body_text(res).await;
        assert!(html.contains("role on this vault"), "{path}");
    }
}

#[tokio::test]
async fn deleted_item_recover_and_purge_are_hinted_at_the_items_scope() {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.arm.state.authz.lock().unwrap().permissions =
        Some(vec![role_data_actions("Key Vault Reader")]);
    w.kv.state.put("old-one", "x");
    w.kv.state.soft_delete("old-one");
    let html = page(&w, "/v/kv-test/secrets/-/deleted/old-one").await;
    assert_disabled(
        &html,
        "recover",
        "Recover old-one",
        "Key Vault Secrets Officer",
    );
    assert_disabled(
        &html,
        "purge",
        "Permanently delete",
        "Key Vault Secrets Officer",
    );
    let paths = w.arm.state.authz.lock().unwrap().paths.clone();
    assert!(
        paths.contains(&format!(
            "{VAULT}/secrets/old-one/providers/Microsoft.Authorization/permissions"
        )),
        "{paths:?}"
    );
}
