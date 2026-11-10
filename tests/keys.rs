//! Keys: list, view, create, rotate, rotation policy, delete and recover.

mod support;

use axum::http::StatusCode;
use support::{body_text, location};

const RSA_PEM: &str = include_str!("fixtures/test-rsa-pub.pem");
const EC_PEM: &str = include_str!("fixtures/test-ec-pub.pem");

/// Every key request path the app made must be a public or management one.
fn assert_no_private_material(w: &support::World) {
    for line in w.kv.state.log.lock().unwrap().iter() {
        for bad in [
            "/export",
            "/backup",
            "/release",
            "/decrypt",
            "/unwrapkey",
            "/sign",
        ] {
            assert!(
                !line.to_lowercase().ends_with(bad),
                "unexpected request {line}"
            );
        }
    }
}

#[tokio::test]
async fn list_and_empty_and_forbidden() {
    let w = support::world().await;
    let (_, html) = w.page("/keys").await;
    assert!(html.contains("This vault has no keys yet"));
    w.kv.state.add_key_with("app-key", "RSA", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state
        .add_key_with("old-key", "EC", |v| v.enabled = false);
    let (status, html) = w.page("/keys").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(">app-key<") && html.contains(">old-key<"));
    assert!(html.contains("env=prod") && html.contains(">Disabled<"));
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = w.page("/keys").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Key Vault Reader role on this vault"));
}

#[tokio::test]
async fn detail_shows_public_key_as_pem_and_jwk() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (status, html) = w.page("/keys/app-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("RSA 2048"));
    assert!(html.contains("Encrypt, Decrypt, Sign, Verify signatures"));
    // Askama escapes, so compare the PEM's base64 body.
    let body_line = RSA_PEM.lines().nth(1).unwrap();
    assert!(html.contains(body_line), "PEM shown");
    assert!(html.contains("&#34;kty&#34;: &#34;RSA&#34;"), "JWK shown");
    assert!(html.contains("data-copy-plain=\"public-pem\""));
    assert!(
        html.contains("Versions") && html.matches("<span class=\"mono version-id\">").count() == 2
    );
    assert_no_private_material(&w);

    w.kv.state
        .add_key_with("signer", "EC", |v| v.crv = Some("P-256".into()));
    let (_, html) = w.page("/keys/signer").await;
    assert!(html.contains("EC P-256"));
    assert!(html.contains(EC_PEM.lines().nth(1).unwrap()));
}

#[tokio::test]
async fn create_with_defaults_in_one_step() {
    let w = support::world().await;
    let (_, html) = w.page("/keys/new").await;
    assert!(
        html.contains("<details class=\"advanced\">"),
        "advanced options tucked away"
    );
    let res = w.post("/keys/new", &[("name", "app-key")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/keys/app-key");
    let body = w.kv.state.key_creates.lock().unwrap()[0].clone();
    assert_eq!(body["kty"], "RSA");
    assert_eq!(body["key_size"], 3072);
    assert_eq!(body["key_ops"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn create_options_and_errors() {
    let w = support::world().await;
    let res = w
        .post("/keys/new", &[("name", "sig"), ("key_type", "EC-P-384")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = w.kv.state.key_creates.lock().unwrap()[0].clone();
    assert_eq!(body["crv"], "P-384");
    assert_eq!(body["key_ops"], serde_json::json!(["sign", "verify"]));

    let res = w
        .post(
            "/keys/new",
            &[
                ("name", "bad name"),
                ("key_type", "EC-P-256"),
                ("ops", "encrypt"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("spaces") && html.contains("EC keys can only sign"));

    let res = w
        .post("/keys/new", &[("name", "hsm-key"), ("hsm", "on")])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("needs the Premium tier"));

    w.kv.state.add_key_with("taken", "RSA", |_| {});
    let res = w.post("/keys/new", &[("name", "taken")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("already a key called taken"));
}

#[tokio::test]
async fn rotate_now_makes_a_new_version() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, html) = w.page("/keys/app-key/rotate").await;
    assert!(html.contains("<strong>new version</strong>"));
    assert_eq!(
        w.kv.state.key_versions("app-key"),
        1,
        "confirm page changes nothing"
    );
    let res = w.post("/keys/app-key/rotate", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.key_versions("app-key"), 2);
}

#[tokio::test]
async fn rotation_policy_read_and_save() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains("No rotation policy"));
    let res = w
        .post(
            "/keys/app-key/rotation",
            &[
                ("rotate_when", "create"),
                ("rotate_days", "90"),
                ("expiry", "365"),
                ("notify_before", "30"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let saved = w.kv.state.keys.lock().unwrap()["app-key"].rotation.clone();
    assert_eq!(
        saved["lifetimeActions"][0]["trigger"]["timeAfterCreate"],
        "P90D"
    );
    assert_eq!(saved["attributes"]["expiryTime"], "P365D");
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains("90 days after each version is made"));
    assert!(html.contains("30 days before expiry"));
    let (_, html) = w.page("/keys/app-key/rotation").await;
    assert!(html.contains("value=\"90\"") && html.contains("value=\"365\""));

    let res = w
        .post(
            "/keys/app-key/rotation",
            &[("rotate_days", "400"), ("expiry", "365")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body_text(res)
            .await
            .contains("Rotate the key at least 7 days before it expires")
    );
}

#[tokio::test]
async fn delete_recover_and_purge_flag() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, html) = w.page("/keys/app-key/delete").await;
    assert!(html.contains("Type <strong class=\"mono\">app-key</strong> to confirm"));
    assert!(html.contains("stop working straight away"));
    let res = w
        .post("/keys/app-key/delete", &[("confirm_name", "app")])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let res = w
        .post("/keys/app-key/delete", &[("confirm_name", "app-key")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (_, html) = w.page("/keys/deleted").await;
    assert!(html.contains(">app-key<"));
    let (_, html) = w.page("/keys/deleted/app-key").await;
    assert!(!html.contains("/purge\""), "no purge link");
    let res = w
        .post(
            "/keys/deleted/app-key/purge",
            &[("confirm_name", "app-key")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w.post("/keys/deleted/app-key/recover", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(support::location(&res), "/keys/deleted");
    assert_eq!(w.kv.state.key_versions("app-key"), 1);
}

#[tokio::test]
async fn purge_when_enabled() {
    let w = support::world_with(&[("KEYRING_ALLOW_PURGE", "true")]).await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.post("/keys/app-key/delete", &[("confirm_name", "app-key")])
        .await;
    let (_, html) = w.page("/keys/deleted/app-key/purge").await;
    assert!(html.contains("can never be decrypted again"));
    let res = w
        .post(
            "/keys/deleted/app-key/purge",
            &[("confirm_name", "app-key")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(w.kv.state.deleted_keys.lock().unwrap().is_empty());
}

#[tokio::test]
async fn forged_tokens_refused() {
    let mut w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.csrf = "forged".into();
    for (path, fields) in [
        ("/keys/new", vec![("name", "x")]),
        ("/keys/app-key/rotate", vec![]),
        ("/keys/app-key/rotation", vec![("rotate_days", "90")]),
        ("/keys/app-key/enabled", vec![("state", "off")]),
        ("/keys/app-key/delete", vec![("confirm_name", "app-key")]),
    ] {
        assert_eq!(
            w.post(path, &fields).await.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    assert_eq!(w.kv.state.key_versions("app-key"), 1);
}

#[test]
fn no_route_can_reach_private_key_operations() {
    // Static check over the source: the keys client has no export, backup,
    // release, decrypt, unwrap or sign calls.
    let src = include_str!("../src/azure/keys.rs");
    for bad in [
        "/export",
        "/backup",
        "/release",
        "/decrypt",
        "/unwrapkey",
        "/sign\"",
    ] {
        assert!(
            !src.to_lowercase().contains(bad),
            "keys client mentions {bad}"
        );
    }
}

#[tokio::test]
async fn managed_keys_are_refused_on_the_server() {
    let w = support::world().await;
    // Every certificate has a key of the same name that Key Vault manages.
    w.kv.state.add_cert("web-tls", true, "x");
    let (_, html) = w.page("/keys/web-tls").await;
    assert!(html.contains("Managed by a certificate"));
    assert!(!html.contains("/keys/web-tls/delete"));
    assert!(!html.contains("/keys/web-tls/rotate\""));
    assert!(!html.contains("action=\"/keys/web-tls/enabled\""));
    for path in [
        "/keys/web-tls/delete",
        "/keys/web-tls/rotate",
        "/keys/web-tls/rotation",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "GET {path}");
        assert!(html.contains("Change it from the certificate"), "{path}");
    }
    for (path, fields) in [
        ("/keys/web-tls/delete", vec![("confirm_name", "web-tls")]),
        ("/keys/web-tls/rotate", vec![]),
        (
            "/keys/web-tls/rotation",
            vec![("rotate_days", "90"), ("expiry", "365")],
        ),
        ("/keys/web-tls/enabled", vec![("state", "off")]),
    ] {
        let res = w.post(path, &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "POST {path}");
        assert!(body_text(res).await.contains("belongs to the certificate"));
    }
    assert_eq!(w.kv.state.key_versions("web-tls"), 1);
    assert!(w.kv.state.keys.lock().unwrap().contains_key("web-tls"));
}

#[tokio::test]
async fn forms_for_missing_keys_are_not_found() {
    let w = support::world().await;
    for path in [
        "/keys/nope/delete",
        "/keys/nope/rotate",
        "/keys/nope/rotation",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!html.contains("to confirm"), "{path}");
    }
}

#[tokio::test]
async fn key_vault_default_policy_shows_as_none_and_saves_untouched() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    // The mock returns Key Vault's default: Notify P30D, no expiry.
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains("No rotation policy"), "{html}");
    let (_, html) = w.page("/keys/app-key/rotation").await;
    assert!(
        html.contains("name=\"notify_before\" type=\"number\" min=\"7\" max=\"36500\" value=\"\"")
    );
    // Pressing Save on the untouched form works.
    let res = w
        .post(
            "/keys/app-key/rotation",
            &[
                ("rotate_when", "create"),
                ("rotate_days", ""),
                ("expiry", ""),
                ("notify_before", ""),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn before_expiry_policy_survives_a_notify_change() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.kv.state
        .keys
        .lock()
        .unwrap()
        .get_mut("app-key")
        .unwrap()
        .rotation = serde_json::json!({
        "lifetimeActions": [
            {"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Rotate"}},
            {"trigger": {"timeBeforeExpiry": "P10D"}, "action": {"type": "Notify"}}
        ],
        "attributes": {"expiryTime": "P18M"}
    });
    let (_, html) = w.page("/keys/app-key/rotation").await;
    assert!(html.contains("value=\"expiry\" checked"), "{html}");
    assert!(
        html.contains("name=\"rotate_days\" type=\"number\" min=\"7\" max=\"36500\" value=\"30\"")
    );
    assert!(html.contains("value=\"540\""));
    let res = w
        .post(
            "/keys/app-key/rotation",
            &[
                ("rotate_when", "expiry"),
                ("rotate_days", "30"),
                ("expiry", "540"),
                ("notify_before", "14"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let saved = w.kv.state.keys.lock().unwrap()["app-key"].rotation.clone();
    assert_eq!(
        saved["lifetimeActions"][0]["trigger"]["timeBeforeExpiry"],
        "P30D"
    );
    assert_eq!(saved["lifetimeActions"][0]["action"]["type"], "Rotate");
    assert_eq!(
        saved["attributes"]["expiryTime"], "P18M",
        "unchanged, so kept"
    );
    assert_eq!(
        saved["lifetimeActions"][1]["trigger"]["timeBeforeExpiry"],
        "P14D"
    );
}

#[tokio::test]
async fn policy_with_a_time_part_needs_replace() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.kv.state
        .keys
        .lock()
        .unwrap()
        .get_mut("app-key")
        .unwrap()
        .rotation = serde_json::json!({
        "lifetimeActions": [{"trigger": {"timeAfterCreate": "PT48H"}, "action": {"type": "Rotate"}}]
    });
    let (_, html) = w.page("/keys/app-key/rotation").await;
    assert!(html.contains("parts this form can't show"), "{html}");
    assert!(html.contains("PT48H"));
    let fields = [("rotate_days", "90"), ("expiry", "365")];
    let res = w.post("/keys/app-key/rotation", &fields).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("Tick the box to replace"));
    let mut with_replace = fields.to_vec();
    with_replace.push(("replace", "on"));
    let res = w.post("/keys/app-key/rotation", &with_replace).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn rotation_policy_400_keeps_the_form() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    *w.kv.state.fail_path.lock().unwrap() = Some("/rotationpolicy".into());
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::PUT);
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post(
            "/keys/app-key/rotation",
            &[
                ("rotate_days", "90"),
                ("expiry", "365"),
                ("notify_before", "30"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("Key Vault said:"));
    assert!(html.contains("value=\"90\"") && html.contains("value=\"365\""));
}

#[tokio::test]
async fn create_400s_are_not_all_blamed_on_hsm() {
    let w = support::world().await;
    *w.kv.state.fail_path.lock().unwrap() = Some("/create".into());
    *w.kv.state.fail.lock().unwrap() = Some((400, "BadParameter"));
    let res = w
        .post("/keys/new", &[("name", "hsm-key"), ("hsm", "on")])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(!html.contains("needs the Premium tier"), "{html}");
    assert!(html.contains("Key Vault said:"));
    assert!(html.contains("value=\"hsm-key\""));
}

#[tokio::test]
async fn existing_key_check_reads_an_empty_list_as_free() {
    // Key Vault answers versions of an unknown name with an empty list.
    let w = support::world().await;
    let res = w.post("/keys/new", &[("name", "fresh")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let res = w.post("/keys/new", &[("name", "new")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("own pages"));
}

#[tokio::test]
async fn detail_says_when_a_section_couldnt_load() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    *w.kv.state.fail_path.lock().unwrap() = Some("/rotationpolicy".into());
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let (status, html) = w.page("/keys/app-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Couldn&#39;t load the rotation policy just now"),
        "{html}"
    );
    assert!(!html.contains("No rotation policy"));
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains(
        "You can&#39;t see the rotation policy. That needs the Key Vault Crypto Officer role."
    ));
    *w.kv.state.fail_path.lock().unwrap() = Some("/versions".into());
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains("Couldn&#39;t load this key&#39;s versions just now"));
}

#[tokio::test]
async fn enable_and_disable() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, html) = w.page("/keys/app-key").await;
    // Disable goes through a confirmation page that posts here.
    assert!(html.contains("href=\"/keys/app-key/disable\">Disable<"));
    let (_, html) = w.page("/keys/app-key/disable").await;
    assert!(html.contains("action=\"/keys/app-key/enabled\""));
    let res = w.post("/keys/app-key/enabled", &[("state", "off")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!w.kv.state.keys.lock().unwrap()["app-key"].versions[0].enabled);
    let res = w.post("/keys/app-key/enabled", &[("state", "on")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(w.kv.state.keys.lock().unwrap()["app-key"].versions[0].enabled);
}

#[tokio::test]
async fn list_pages_like_secrets() {
    let w = support::world().await;
    for i in 0..105 {
        w.kv.state
            .add_key_with(&format!("key-{i:03}"), "RSA", |_| {});
    }
    let (_, html) = w.page("/keys").await;
    assert_eq!(html.matches("<th scope=\"row\">").count(), 100);
    assert!(html.contains("Page 1 of 2, keys 1 to 100"));
    assert!(html.contains(">Next</a>"), "{html}");
    let (_, html) = w.page("/keys?page=2").await;
    assert_eq!(html.matches("<th scope=\"row\">").count(), 5);
    assert!(html.contains(">key-104<"));
}
