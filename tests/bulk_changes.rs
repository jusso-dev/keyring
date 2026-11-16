//! Changing tags, expiry or enabled on many items at once (#216): the
//! "With selected" form on each list, the review page, and the results.

mod support;

use axum::http::{Method, StatusCode};
use support::body_text;

const VALUE: &str = "Bulk-S3cret-Value";

fn items<'a>(names: &[&'a str]) -> Vec<(&'static str, &'a str)> {
    names.iter().map(|n| ("item", *n)).collect()
}

async fn post(w: &support::World, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let res = w.post(path, fields).await;
    let status = res.status();
    (status, body_text(res).await)
}

/// The review page's hidden `item` fields.
fn review_items(html: &str) -> Vec<String> {
    html.split("name=\"item\" value=\"")
        .skip(1)
        .map(|c| c[..c.find('"').unwrap()].to_owned())
        .collect()
}

fn patches(w: &support::World) -> usize {
    w.kv.state
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.starts_with("PATCH"))
        .count()
}

#[tokio::test]
async fn list_has_a_with_selected_form_outside_the_filter_form() {
    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    for (path, expiry) in [
        ("/v/kv-test/secrets", true),
        ("/v/kv-test/keys", true),
        ("/v/kv-test/certificates", false),
    ] {
        match path {
            "/v/kv-test/keys" => {
                w.kv.state.add_key_with("app-key", "RSA", |_| {});
            }
            "/v/kv-test/certificates" => {
                w.kv.state.add_cert("web-tls", true, "UEZY");
            }
            _ => {}
        }
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("id=\"bulk-form\""), "{path}");
        assert!(html.contains("form=\"bulk-form\""), "{path}: checkboxes");
        assert_eq!(html.contains("value=\"expiry\""), expiry, "{path}");
        assert!(!html.contains("value=\"delete\""), "{path}: never delete");
        // The filter form ends before the bulk form starts: not nested.
        let filter_end = html.find("</form>").unwrap();
        assert!(
            filter_end < html.find("id=\"bulk-form\"").unwrap(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn add_a_tag_to_secrets_end_to_end() {
    let w = support::world().await;
    let s = &w.kv.state;
    s.put("db-password", VALUE);
    s.put("api-key", VALUE);
    s.secrets
        .lock()
        .unwrap()
        .get_mut("api-key")
        .unwrap()
        .versions[0]
        .tags
        .insert("env".into(), "prod".into());
    s.add_cert("web-tls", true, "UEZY");
    let _guard = s.no_value_reads();
    // Warm the list cache, so a stale list would show.
    let _ = w.page("/v/kv-test/secrets").await;

    let mut f = items(&["db-password", "api-key", "web-tls"]);
    f.extend([
        ("op", "tag_set"),
        ("tag_name", "owner"),
        ("tag_value", "ops"),
    ]);
    let (status, html) = post(&w, "/v/kv-test/secrets/-/bulk", &f).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains("Set the tag owner=ops on 2 secrets?"),
        "{html}"
    );
    assert!(html.contains("Adds owner=ops."));
    assert!(html.contains("This secret belongs to the certificate web-tls"));
    assert_eq!(review_items(&html), ["db-password", "api-key"]);
    assert_eq!(patches(&w), 0, "the review changes nothing");
    assert!(!html.contains(VALUE));

    let picked = review_items(&html);
    let mut f: Vec<(&str, &str)> = picked.iter().map(|n| ("item", n.as_str())).collect();
    f.extend([
        ("op", "tag_set"),
        ("tag_name", "owner"),
        ("tag_value", "ops"),
    ]);
    let (status, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("Changed 2 secrets"), "{html}");
    assert!(!html.contains(VALUE));
    let tags = s.current("api-key").unwrap().tags;
    assert_eq!(tags.get("owner").map(String::as_str), Some("ops"));
    assert_eq!(tags.get("env").map(String::as_str), Some("prod"), "kept");
    assert_eq!(s.version_count("api-key"), 1, "no new version");
    assert_eq!(patches(&w), 2);

    // The list shows it straight away.
    let (_, html) = w.page("/v/kv-test/secrets?tag=owner%3Dops").await;
    assert!(
        html.contains(">db-password<") && html.contains(">api-key<"),
        "{html}"
    );
}

#[tokio::test]
async fn mixed_results_refused_deleted_and_managed() {
    let w = support::world().await;
    let s = &w.kv.state;
    for n in ["one", "two", "three", "four"] {
        s.put(n, VALUE);
    }
    s.add_cert("web-tls", true, "UEZY");
    let _guard = s.no_value_reads();
    // `two` refused by Azure; `three` deleted between review and apply;
    // `web-tls` is a certificate's backing secret.
    s.fail_each.lock().unwrap().push((
        Method::PATCH,
        "/secrets/two/".into(),
        403,
        "ForbiddenByRbac",
    ));
    s.soft_delete("three");
    let mut f = items(&["one", "two", "three", "four", "web-tls"]);
    f.push(("op", "disable"));
    f.push(("confirm_count", "5"));
    let (status, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("Changed 2 secrets"), "{html}");
    assert!(html.contains("3 secrets weren't changed"));
    assert!(html.contains("Refused by Azure"));
    assert!(html.contains("Key Vault Secrets Officer"), "names the role");
    assert!(html.contains(">Not found<"));
    assert!(html.contains("belongs to the certificate web-tls"));
    assert!(!html.contains("private detail"), "never Azure's message");
    assert!(!s.current("one").unwrap().enabled);
    assert!(!s.current("four").unwrap().enabled);
    assert!(s.current("two").unwrap().enabled);
    assert!(s.current("web-tls").unwrap().enabled, "managed left alone");
}

#[tokio::test]
async fn disable_needs_the_count_typed() {
    let w = support::world().await;
    w.kv.state.put("one", VALUE);
    w.kv.state.put("two", VALUE);
    let mut f = items(&["one", "two"]);
    f.push(("op", "disable"));
    let (_, html) = post(&w, "/v/kv-test/secrets/-/bulk", &f).await;
    assert!(html.contains("id=\"confirm_count\""), "{html}");
    for typed in ["", "1", "3", "two"] {
        let mut g = f.clone();
        g.push(("confirm_count", typed));
        let (status, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &g).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{typed:?}");
        assert!(html.contains("type 2 exactly"), "{html}");
    }
    assert_eq!(patches(&w), 0);
    f.push(("confirm_count", " 2 "));
    let (status, _) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!w.kv.state.current("two").unwrap().enabled);
}

#[tokio::test]
async fn bad_selections_are_refused_before_key_vault() {
    let w = support::world().await;
    w.kv.state.put("one", VALUE);
    let before = w.kv.state.log.lock().unwrap().len();
    let many: Vec<String> = (0..101).map(|i| format!("s{i}")).collect();
    let mut over: Vec<(&str, &str)> = many.iter().map(|n| ("item", n.as_str())).collect();
    over.push(("op", "enable"));
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (over, "up to 100 secrets at a time"),
        (
            vec![("item", "one"), ("item", "../x"), ("op", "enable")],
            "a name that isn",
        ),
        (vec![("op", "enable")], "Tick at least one"),
        (vec![("item", "one"), ("op", "delete")], "Choose one of"),
        (
            vec![("item", "one"), ("op", "expiry"), ("expires", "2001-01-01")],
            "already passed",
        ),
        (
            vec![("item", "one"), ("op", "expiry"), ("expires", "")],
            "Key Vault can",
        ),
    ];
    for path in [
        "/v/kv-test/secrets/-/bulk",
        "/v/kv-test/secrets/-/bulk/apply",
    ] {
        for (fields, says) in &cases {
            let (status, html) = post(&w, path, fields).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path} {says}");
            assert!(html.contains(says), "{path}: {says}: {html}");
        }
    }
    // Certificates: no bulk expiry.
    let (status, _) = post(
        &w,
        "/v/kv-test/certificates/-/bulk",
        &[("item", "x"), ("op", "expiry"), ("expires", "2099-01-01")],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(w.kv.state.log.lock().unwrap().len(), before, "nothing sent");
}

#[tokio::test]
async fn a_tag_past_the_limit_is_refused_per_item() {
    let w = support::world().await;
    let s = &w.kv.state;
    s.put("full", VALUE);
    s.put("roomy", VALUE);
    {
        let mut secrets = s.secrets.lock().unwrap();
        let tags = &mut secrets.get_mut("full").unwrap().versions[0].tags;
        for i in 0..15 {
            tags.insert(format!("t{i}"), "x".into());
        }
    }
    let mut f = items(&["full", "roomy"]);
    f.extend([("op", "tag_set"), ("tag_name", "owner"), ("tag_value", "a")]);
    let (_, html) = post(&w, "/v/kv-test/secrets/-/bulk", &f).await;
    assert!(html.contains("Already has 15 tags"), "{html}");
    let (_, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert!(html.contains("Changed 1 secret"), "{html}");
    assert!(html.contains("Refused by Keyring"));
    assert_eq!(s.current("full").unwrap().tags.len(), 15, "nothing dropped");
    assert!(s.current("roomy").unwrap().tags.contains_key("owner"));
    // Removing a tag writes back the others.
    let mut f = items(&["full"]);
    f.extend([("op", "tag_remove"), ("tag_name", "t3")]);
    let (_, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert!(html.contains("Changed 1 secret"), "{html}");
    let tags = s.current("full").unwrap().tags;
    assert_eq!(tags.len(), 14);
    assert!(!tags.contains_key("t3"));
}

#[tokio::test]
async fn expiry_on_secrets_and_keys() {
    let w = support::world().await;
    let s = &w.kv.state;
    s.put("db", VALUE);
    s.add_key_with("app-key", "RSA", |_| {});
    s.add_managed_key("cert-key", "0123456789abcdef0123456789abcdef");
    let f = [("item", "db"), ("op", "expiry"), ("expires", "2099-03-01")];
    let (_, html) = post(&w, "/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert!(html.contains("Changed 1 secret"), "{html}");
    let exp = s.current("db").unwrap().exp.unwrap();
    assert_eq!(exp % 86_400, 86_399, "end of the day");

    let f = [
        ("item", "app-key"),
        ("item", "cert-key"),
        ("op", "expiry"),
        ("expires", "2099-03-01"),
    ];
    let (_, html) = post(&w, "/v/kv-test/keys/-/bulk/apply", &f).await;
    assert!(html.contains("Changed 1 key"), "{html}");
    assert!(
        html.contains("belongs to the certificate cert-key"),
        "{html}"
    );
    let keys = s.keys.lock().unwrap();
    assert_eq!(keys["app-key"].versions[0].exp, Some(exp));
}

#[tokio::test]
async fn certificates_take_tags_and_enabled() {
    let w = support::world().await;
    let s = &w.kv.state;
    s.add_cert("web-tls", true, "UEZY");
    s.add_cert("api-tls", true, "UEZY");
    let f = [
        ("item", "web-tls"),
        ("item", "api-tls"),
        ("op", "tag_set"),
        ("tag_name", "team"),
        ("tag_value", "web"),
    ];
    let (_, html) = post(&w, "/v/kv-test/certificates/-/bulk/apply", &f).await;
    assert!(html.contains("Changed 2 certificates"), "{html}");
    let team = s.certs.lock().unwrap()["web-tls"].versions[0].tags["team"].clone();
    assert_eq!(team, "web");
    let f = [("item", "web-tls"), ("op", "enable")];
    let (_, html) = post(&w, "/v/kv-test/certificates/-/bulk/apply", &f).await;
    assert!(html.contains("No change needed"), "{html}");
    assert!(html.contains("Changed 0 certificates"), "{html}");
}

#[tokio::test]
async fn readers_see_the_button_disabled_with_the_role() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.arm.state.authz.lock().unwrap().permissions =
        Some(vec![support::role_data_actions("Key Vault Reader")]);
    w.kv.state.put("db", VALUE);
    let (_, html) = w.page("/v/kv-test/secrets").await;
    let at = html.find(">Review changes<").unwrap();
    let tag = &html[html[..at].rfind("<button").unwrap()..at];
    assert!(tag.contains(" disabled"), "{tag}");
    assert!(html.contains("id=\"bulk-needs\">Needs Key Vault Secrets Officer"));
}
