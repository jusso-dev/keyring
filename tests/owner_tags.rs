//! Owner and notify tags (#255): the fields on every item form, the checks,
//! values set outside Keyring, KEYRING_REQUIRE_OWNER on each route, the
//! "Owned by me" filter, the bulk change, import, copy, search and exports.

mod support;

use axum::http::StatusCode;
use support::{Part, body_text, hidden_value, location};

const ME: &str = "alex@example.com";

fn tags_of(v: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v["tags"].as_object().cloned().unwrap_or_default()
}

async fn require_on() -> support::World {
    support::world_with(&[("KEYRING_REQUIRE_OWNER", "true")]).await
}

/// The edit form's version stamp.
/// The page with apostrophes unescaped, so assertions read as the text.
fn text(html: String) -> String {
    html.replace("&#39;", "'")
}

async fn stamp(w: &support::World, path: &str) -> (String, String) {
    let (_, html) = w.page(path).await;
    (
        hidden_value(&html, "version").unwrap(),
        hidden_value(&html, "updated").unwrap(),
    )
}

#[tokio::test]
async fn secret_create_edit_and_set_value_keep_owner_and_notify() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "db-password"),
                ("value", "x"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("owner", " Alex@Example.COM "),
                (
                    "notify",
                    "sam@example.com, ,team@example.com, SAM@example.com",
                ),
                ("description", "Billing"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let flash_free = location(&res);
    assert!(!flash_free.contains('@'), "no address in the URL");
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.tags["owner"], "Alex@example.com", "domain lower-cased");
    assert_eq!(v.tags["notify"], "sam@example.com, team@example.com");
    assert_eq!(v.tags["env"], "prod");
    assert_eq!(v.tags["description"], "Billing");

    // The detail page, list and edit form show them; the tag list doesn't.
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains(
        "<dt>Owner</dt><dd><a href=\"mailto:Alex@example.com\">Alex@example.com</a></dd>"
    ));
    assert!(html.contains("<a href=\"mailto:team@example.com\">team@example.com</a>"));
    assert!(!html.contains("<span class=\"tag\">owner"));
    assert!(!html.contains("?tag=owner"));
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert!(html.contains("<th scope=\"col\">Owner</th>"));
    assert!(html.contains("<td class=\"owner-cell\"><span class=\"clip clip-lg\"><a href=\"mailto:Alex@example.com\">"));
    let (_, html) = w.page("/v/kv-test/secrets/db-password/edit").await;
    assert!(html.contains(
        "id=\"owner\" name=\"owner\" type=\"text\" inputmode=\"email\" value=\"Alex@example.com\""
    ));
    assert!(html.contains("value=\"sam@example.com, team@example.com\""));
    assert!(
        !html.contains("type=\"text\" value=\"owner\""),
        "no row for owner"
    );
    assert!(
        html.contains("<option value=\"Alex@example.com\">"),
        "owner suggested"
    );

    // Edit: empty notify removes it, the rest stays.
    let (version, updated) = stamp(&w, "/v/kv-test/secrets/db-password/edit").await;
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-rows", "1"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("owner", "Alex@example.com"),
                ("notify", ""),
                ("description", "Billing"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert!(!v.tags.contains_key("notify"));
    assert_eq!(v.tags["owner"], "Alex@example.com");

    // Set a new value carries the owner.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[
                ("value", "y"),
                ("tag-rows", "1"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("owner", "Alex@example.com"),
                ("notify", "ops@example.com"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.tags["owner"], "Alex@example.com");
    assert_eq!(v.tags["notify"], "ops@example.com");
    assert_eq!(w.kv.state.version_count("db-password"), 2);
}

#[tokio::test]
async fn bad_addresses_are_refused_by_position_without_echoing_them() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "s"),
                ("value", "x"),
                ("owner", "Pat Q <pat@example.com>"),
                ("notify", "a@example.com, b@@example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = text(body_text(res).await);
    assert!(html.contains("id=\"owner-error\">The owner isn't one plain email address"));
    assert!(
        html.contains(
            "id=\"notify-error\">The second address in Notify isn't a plain email address"
        )
    );
    assert!(
        html.contains("<a href=\"#owner\">"),
        "the summary links to the field"
    );
    // The field is filled back (escaped), but the messages never quote it.
    assert!(html.contains("value=\"Pat Q &#60;pat@example.com&#62;\""));
    let errors: String = html
        .split("field-error")
        .skip(1)
        .map(|s| s.split("</p>").next().unwrap_or_default())
        .collect();
    assert!(
        !errors.contains("Pat") && !errors.contains("b@@"),
        "{errors}"
    );
    assert!(w.kv.state.current("s").is_none(), "nothing sent");

    // Six notify addresses are one too many.
    let six: Vec<String> = (1..=6).map(|i| format!("p{i}@example.com")).collect();
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "s"), ("value", "x"), ("notify", &six.join(","))],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("Notify can hold up to 5 addresses. This has 6."));

    // Typed as a tag row: refused, pointing at the field.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "s"),
                ("value", "x"),
                ("tag-rows", "1"),
                ("tag-name-1", "owner"),
                ("tag-value-1", "a@example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("set with the Owner and Notify fields"));
}

#[tokio::test]
async fn allowed_domains_apply_to_owner_and_notify() {
    let w = support::world_configured(Vec::new(), |c| {
        // As KEYRING_NOTIFY_ALLOWED_DOMAINS sets it, without starting email.
        let mut n = support::world_notify_settings();
        n.allowed_domains = Some(vec!["example.com".into()]);
        c.notify = Some(n);
    })
    .await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "s"),
                ("value", "x"),
                ("owner", "alex@example.com"),
                ("notify", "ok@example.com, out@elsewhere.org"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = text(body_text(res).await);
    assert!(html.contains(
        "The second address in Notify isn't in a domain Keyring is set to email (example.com)."
    ));
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "s"),
                ("value", "x"),
                ("owner", "alex@sub.example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        text(body_text(res).await)
            .contains("The owner's address isn't in a domain Keyring is set to email")
    );
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "s"), ("value", "x"), ("owner", "alex@EXAMPLE.com")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

/// A value set in the portal or the CLI that Keyring wouldn't write: shown
/// as it is with a note, never rewritten while untouched, and never in the
/// way of another change, even with the policy on and an allow-list set.
#[tokio::test]
async fn odd_values_from_outside_are_kept_until_changed() {
    let w = support::world_configured(vec![("KEYRING_REQUIRE_OWNER", "true".to_owned())], |c| {
        let mut n = support::world_notify_settings();
        n.allowed_domains = Some(vec!["example.com".into()]);
        c.notify = Some(n);
    })
    .await;
    let odd_owner = "Payments <payments@other.org>";
    let odd_notify = "a@example.com;b@example.com\u{200B}";
    w.kv.state.put_with("odd", "x", |v| {
        v.tags.insert("owner".into(), odd_owner.into());
        v.tags.insert("notify".into(), odd_notify.into());
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/v/kv-test/secrets/odd").await;
    assert!(html.contains("<span class=\"mono\">Payments &#60;payments@other.org&#62;</span> <span class=\"muted small\">(not a plain address)</span>"));
    assert!(!html.contains("mailto:Payments"));
    let (_, html) = w.page("/v/kv-test/secrets/odd/edit").await;
    let html = text(html);
    assert!(html.contains("id=\"owner-note\">This owner was set outside Keyring"));
    assert!(html.contains("id=\"notify-note\">This list was set outside Keyring"));
    assert!(html.contains("aria-describedby=\"owner-help owner-note\""));

    // Change only the expiry, posting the fields back as the form showed them.
    let (version, updated) = stamp(&w, "/v/kv-test/secrets/odd/edit").await;
    let res = w
        .post(
            "/v/kv-test/secrets/odd/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-rows", "1"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("owner", odd_owner),
                ("notify", odd_notify),
                ("expires", "2099-06-01"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "an untouched odd value never blocks"
    );
    let v = w.kv.state.current("odd").unwrap();
    assert_eq!(v.tags["owner"], odd_owner, "kept byte for byte");
    assert_eq!(v.tags["notify"], odd_notify);
    let patch =
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PATCH"))
            .count();
    assert_eq!(patch, 1);

    // Changed, it is checked: here the new owner is outside the domains.
    let (version, updated) = stamp(&w, "/v/kv-test/secrets/odd/edit").await;
    let res = w
        .post(
            "/v/kv-test/secrets/odd/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("owner", "payments@other.org"),
                ("notify", odd_notify),
                ("expires", "2099-06-01"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = text(body_text(res).await);
    assert!(html.contains("isn't in a domain Keyring is set to email"));
    assert!(
        html.contains("id=\"notify-note\""),
        "the untouched one keeps its note"
    );
}

#[tokio::test]
async fn certificate_and_key_forms_and_edit_details() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &[
                ("name", "web-tls"),
                ("common_name", "app.example.com"),
                ("validity_months", "12"),
                ("issuer", "Self"),
                ("owner", "web@example.com"),
                ("notify", "oncall@example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let created = w.kv.state.creates.lock().unwrap()[0].body.clone();
    assert_eq!(tags_of(&created)["owner"], "web@example.com");
    assert_eq!(tags_of(&created)["notify"], "oncall@example.com");

    // Upload: the preview shows them, the import sends them.
    let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
    let res = w
        .post_multipart(
            "/v/kv-test/certificates/-/upload",
            &[
                Part::File("file", "web.pfx", pfx),
                Part::Text("name", "api-tls"),
                Part::Text("password", "test-password"),
                Part::Text("owner", "api@example.com"),
                Part::Text("notify", ""),
                Part::Text("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = text(body_text(res).await);
    assert!(
        html.contains(
            "<dt>Owner</dt><dd><a href=\"mailto:api@example.com\">api@example.com</a></dd>"
        )
    );
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post(
            "/v/kv-test/certificates/-/upload/confirm",
            &[("upload_id", &id)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let imported = w.kv.state.imports.lock().unwrap()[0].body.clone();
    assert_eq!(tags_of(&imported)["owner"], "api@example.com");
    assert!(!tags_of(&imported).contains_key("notify"));

    // Key create, then Edit details sets notify and keeps the owner.
    let res = w
        .post(
            "/v/kv-test/keys/-/new",
            &[("name", "signing"), ("owner", "keys@example.com")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        tags_of(&w.kv.state.key_creates.lock().unwrap()[0])["owner"],
        "keys@example.com"
    );
    let (_, html) = w.page("/v/kv-test/keys").await;
    assert!(html.contains("<a href=\"mailto:keys@example.com\">keys@example.com</a>"));
    let (version, updated) = stamp(&w, "/v/kv-test/keys/signing/details").await;
    let res = w
        .post(
            "/v/kv-test/keys/signing/details",
            &[
                ("version", &version),
                ("updated", &updated),
                ("owner", "keys@example.com"),
                ("notify", "sec@example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let keys = w.kv.state.keys.lock().unwrap();
    let tags = &keys["signing"].versions[0].tags;
    assert_eq!(tags["owner"], "keys@example.com");
    assert_eq!(tags["notify"], "sec@example.com");
}

#[tokio::test]
async fn owner_and_notify_count_towards_fifteen_tags() {
    let w = support::world().await;
    w.kv.state.add_key_with("full", "RSA", |v| {
        for i in 0..15 {
            v.tags.insert(format!("k{i}"), "v".into());
        }
    });
    let (version, updated) = stamp(&w, "/v/kv-test/keys/full/details").await;
    let mut f: Vec<(String, String)> = vec![
        ("version".into(), version),
        ("updated".into(), updated),
        ("tag-rows".into(), "1".into()),
        ("owner".into(), "a@example.com".into()),
    ];
    for i in 0..15 {
        f.push((format!("tag-name-{}", i + 1), format!("k{i}")));
        f.push((format!("tag-value-{}", i + 1), "v".into()));
    }
    let f: Vec<(&str, &str)> = f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let res = w.post("/v/kv-test/keys/full/details", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("the owner tag would be one more"));
}

/// KEYRING_REQUIRE_OWNER on every path that writes an item.
#[tokio::test]
async fn require_owner_refuses_each_form_path_with_a_field_error() {
    let w = require_on().await;
    let refused =
        |html: &str| html.contains("id=\"owner-error\">Enter an owner. Keyring is set to need one");
    // The form says it's needed.
    let (_, html) = w.page("/v/kv-test/secrets/-/new").await;
    assert!(html.contains("<label for=\"owner\">Owner</label>"));
    assert!(html.contains("Keyring is set to need one."));

    // Secret create.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "s"), ("value", "x"), ("owner", "")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    // Certificate create.
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &[
                ("name", "c"),
                ("common_name", "a.example.com"),
                ("validity_months", "12"),
                ("issuer", "Self"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    // Certificate upload: refused at the preview, nothing kept.
    let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
    let res = w
        .post_multipart(
            "/v/kv-test/certificates/-/upload",
            &[
                Part::File("file", "web.pfx", pfx),
                Part::Text("name", "u"),
                Part::Text("password", "test-password"),
                Part::Text("owner", " "),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    // Key create.
    let res = w.post("/v/kv-test/keys/-/new", &[("name", "k")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    assert!(w.kv.state.key_creates.lock().unwrap().is_empty());
    assert!(w.kv.state.creates.lock().unwrap().is_empty());

    // Edit, set value and Edit details on an existing ownerless item.
    w.kv.state.put("old", "x");
    let (version, updated) = stamp(&w, "/v/kv-test/secrets/old/edit").await;
    let res = w
        .post(
            "/v/kv-test/secrets/old/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("owner", ""),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    let res = w
        .post(
            "/v/kv-test/secrets/old/value",
            &[("value", "y"), ("owner", "")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    w.kv.state.add_key_with("oldkey", "RSA", |_| {});
    let (version, updated) = stamp(&w, "/v/kv-test/keys/oldkey/details").await;
    let res = w
        .post(
            "/v/kv-test/keys/oldkey/details",
            &[("version", &version), ("updated", &updated), ("owner", "")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused(&text(body_text(res).await)));
    assert_eq!(w.kv.state.version_count("old"), 1);
    let patches =
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PATCH"))
            .count();
    assert_eq!(patches, 0, "nothing written");

    // With an owner each goes through.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "s"), ("value", "x"), ("owner", ME)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (version, updated) = stamp(&w, "/v/kv-test/secrets/old/edit").await;
    let res = w
        .post(
            "/v/kv-test/secrets/old/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("owner", ME),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn require_owner_on_import_bulk_and_copy() {
    let target = std::sync::Arc::new(support::keyvault::KvState::default());
    let w = support::world_of_vaults_with(
        vec![
            (
                "kv-test",
                std::sync::Arc::new(support::keyvault::KvState::default()),
            ),
            ("kv-prod", target.clone()),
        ],
        &[("KEYRING_REQUIRE_OWNER", "true")],
    )
    .await;

    // Import: a row with no owner is refused, with its own event; one with
    // an owner is written. An .env file has no owner column, so every row
    // is refused.
    let csv = b"name,value,owner,notify\r\nWITH,v,a@example.com,\"b@example.com, c@example.com\"\r\nWITHOUT,v,,\r\n";
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", "s.csv", csv)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = text(body_text(res).await);
    assert!(
        html.contains("It has no owner, and Keyring is set to need one."),
        "{html}"
    );
    let id = hidden_value(&html, "import_id").unwrap();
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = body_text(res).await;
    let v = w.kv.state.current("WITH").unwrap();
    assert_eq!(v.tags["owner"], "a@example.com");
    assert_eq!(v.tags["notify"], "b@example.com, c@example.com");
    assert!(w.kv.state.current("WITHOUT").is_none());
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", ".env", b"E=1\n")],
        )
        .await;
    let html = text(body_text(res).await);
    assert!(html.contains("It has no owner"), "{html}");

    // Bulk: Remove the owner isn't offered and is refused; setting works.
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert!(!html.contains("value=\"owner_remove\""));
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk",
            &[("item", "WITH"), ("op", "owner_remove")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("can't remove owners"));
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk/apply",
            &[
                ("item", "WITH"),
                ("op", "owner_set"),
                ("owner", "new@example.com"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = body_text(res).await;
    assert_eq!(
        w.kv.state.current("WITH").unwrap().tags["owner"],
        "new@example.com"
    );

    // Copy: brings the source's owner; a source without one is refused
    // before its value is read.
    w.kv.state.put("ownerless", "x");
    let copy = |name: &'static str, tags: bool| {
        let mut f = vec![("to_vault", "kv-prod"), ("to_name", name)];
        if tags {
            f.push(("tags", "on"));
        }
        f
    };
    let res = w
        .post(
            "/v/kv-test/secrets/ownerless/copy",
            &copy("ownerless", true),
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("this copy wouldn't have one"));
    assert!(target.current("ownerless").is_none());
    assert!(
        w.kv.state
            .value_reads()
            .iter()
            .all(|r| !r.contains("ownerless"))
    );
    let res = w
        .post("/v/kv-test/secrets/WITH/copy", &copy("WITH", false))
        .await;
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "tags not brought"
    );
    let res = w
        .post("/v/kv-test/secrets/WITH/copy", &copy("WITH", true))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        target.current("WITH").unwrap().tags["owner"],
        "new@example.com"
    );
    // The review says so too.
    let (_, html) = w
        .page("/v/kv-test/secrets/ownerless/copy/review?to_vault=kv-prod&to_name=x&tags=on")
        .await;
    let html = text(html);
    assert!(
        html.contains("has no owner. Give it one with Edit details first"),
        "{html}"
    );
}

#[tokio::test]
async fn owned_by_me_matches_owner_or_notify_from_the_session() {
    let w = support::world().await;
    w.kv.state.put_with("mine-owner", "x", |v| {
        v.tags.insert("owner".into(), "ALEX@example.com".into());
    });
    w.kv.state.put_with("mine-notify", "x", |v| {
        v.tags.insert("owner".into(), "team@example.com".into());
        v.tags
            .insert("notify".into(), "sam@example.com, alex@EXAMPLE.com".into());
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put_with("not-mine", "x", |v| {
        v.tags.insert("owner".into(), "alex@example.com.au".into());
        v.tags.insert("notify".into(), "xalex@example.com".into());
    });
    // A tag called Owner is an ordinary tag.
    w.kv.state.put_with("ordinary", "x", |v| {
        v.tags.insert("Owner".into(), ME.into());
    });
    let (_, html) = w.page("/v/kv-test/secrets?mine=1").await;
    assert!(
        html.contains(">mine-owner<") && html.contains(">mine-notify<"),
        "{html}"
    );
    assert!(!html.contains(">not-mine<") && !html.contains(">ordinary<"));
    assert!(html.contains("id=\"mine\" name=\"mine\" type=\"checkbox\" value=\"1\" checked"));
    // With another filter.
    let (_, html) = w.page("/v/kv-test/secrets?mine=1&tag=env%3Dprod").await;
    assert!(html.contains(">mine-notify<") && !html.contains(">mine-owner<"));
    // A posted address is ignored: only the session's UPN counts.
    let (_, html) = w.page("/v/kv-test/secrets?mine=team%40example.com").await;
    assert!(html.contains(">mine-owner<") && !html.contains(">not-mine<"));

    // Certificates and keys.
    w.kv.state.add_key_with("k-mine", "RSA", |v| {
        v.tags.insert("owner".into(), ME.into());
    });
    w.kv.state.add_key_with("k-other", "RSA", |_| {});
    let (_, html) = w.page("/v/kv-test/keys?mine=1").await;
    assert!(html.contains(">k-mine<") && !html.contains(">k-other<"));
    w.kv.state.add_cert_version(
        "c-mine",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(true, false),
        |v| {
            v.tags.insert("notify".into(), ME.into());
        },
    );
    w.kv.state.add_cert("c-other", false, "x");
    let (_, html) = w.page("/v/kv-test/certificates?mine=1").await;
    assert!(html.contains(">c-mine<") && !html.contains(">c-other<"));

    // Paging keeps the flag, never the address.
    for i in 0..110 {
        w.kv.state.put_with(&format!("p{i:03}"), "x", |v| {
            v.tags.insert("owner".into(), ME.into());
        });
    }
    let (_, html) = w.page("/v/kv-test/secrets?mine=1").await;
    assert!(html.contains("mine=1&#38;page=2"), "{html}");
    let pager = &html[html.find("class=\"pager\"").unwrap()..];
    assert!(!pager.contains("alex"));
}

#[tokio::test]
async fn bulk_sets_and_removes_owner_and_notify() {
    let w = support::world().await;
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put("b", "x");
    let (status, html) = w.page("/v/kv-test/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<option value=\"owner_set\">Set the owner</option>"));
    assert!(html.contains("<option value=\"owner_remove\">Remove the owner</option>"));
    let review = w
        .post(
            "/v/kv-test/secrets/-/bulk",
            &[
                ("item", "a"),
                ("item", "b"),
                ("op", "owner_set"),
                ("owner", "ops@example.com"),
            ],
        )
        .await;
    assert_eq!(review.status(), StatusCode::OK);
    let html = body_text(review).await;
    assert!(html.contains("Set the owner on 2 secrets"));
    assert!(html.contains("Adds the owner."));
    // The address rides in the hidden field only, never in the words.
    let words = html.replace("value=\"ops@example.com\"", "");
    assert!(!words.contains("ops@example.com"));
    for op in [
        vec![("op", "owner_set"), ("owner", "ops@example.com")],
        vec![
            ("op", "notify_set"),
            ("notify", "a@example.com, b@example.com"),
        ],
    ] {
        let mut f = vec![("item", "a"), ("item", "b")];
        f.extend(op);
        let res = w.post("/v/kv-test/secrets/-/bulk/apply", &f).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(text(body_text(res).await).contains("Changed 2 secrets"));
    }
    let a = w.kv.state.current("a").unwrap();
    assert_eq!(a.tags["owner"], "ops@example.com");
    assert_eq!(a.tags["notify"], "a@example.com, b@example.com");
    assert_eq!(a.tags["env"], "prod", "kept");
    for op in ["owner_remove", "notify_remove"] {
        let res = w
            .post(
                "/v/kv-test/secrets/-/bulk/apply",
                &[("item", "a"), ("op", op)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let _ = body_text(res).await;
    }
    let a = w.kv.state.current("a").unwrap();
    assert_eq!(a.tags.len(), 1);
    assert_eq!(a.tags["env"], "prod");
    // A bad address is refused before Key Vault.
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk",
            &[
                ("item", "a"),
                ("op", "notify_set"),
                ("notify", "x@example.com, nope"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(text(body_text(res).await).contains("The second address in Notify"));
}

#[tokio::test]
async fn search_and_exports_include_the_owner() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("owner".into(), "=payroll@example.com".into());
        v.tags
            .insert("notify".into(), "a@example.com, b@example.com".into());
    });
    w.kv.state.put("other", "x");
    let (_, html) = w.page("/search?q=payroll%40").await;
    assert!(html.contains(">db-password<") && !html.contains(">other<"));
    assert!(html.contains("<th scope=\"col\">Owner</th>"));
    for path in ["/expiry.csv?show=all", "/expiry/age.csv"] {
        let csv = body_text(w.get(path).await).await;
        assert!(
            csv.lines()
                .next()
                .unwrap()
                .contains(",Description,Owner,Notify,Tags"),
            "{path}"
        );
        let row = csv.lines().find(|l| l.contains("db-password")).unwrap();
        assert!(
            row.contains(",'=payroll@example.com,\"a@example.com, b@example.com\","),
            "{path}: {row}"
        );
    }
}

#[test]
fn recipients_for_later_emails() {
    // The two functions #258 and #259 call.
    use std::collections::BTreeMap;
    let tags: BTreeMap<String, String> = [
        ("owner".to_owned(), "Alex@example.com".to_owned()),
        (
            "notify".to_owned(),
            "alex@EXAMPLE.com, bad, sam@example.com".to_owned(),
        ),
    ]
    .into();
    let r: Vec<String> = keyring::owner::item_recipients(&tags)
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(r, ["Alex@example.com", "sam@example.com"]);
    let vault: BTreeMap<String, String> = [(
        "keyring-owners".to_owned(),
        "ops@example.com; Platform".to_owned(),
    )]
    .into();
    let r: Vec<String> = keyring::owner::vault_owners(&vault)
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(r, ["ops@example.com"]);
}

#[tokio::test]
async fn tag_filter_and_search_find_owner_and_notify_everywhere() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put_with("owned", "x", |v| {
        v.tags.insert("owner".into(), "ops@example.com".into());
        v.tags.insert(
            "notify".into(),
            "sam@example.com, backup@example.com".into(),
        );
        v.tags.insert("description".into(), "Billing".into());
    });
    w.kv.state.put("other", "x");
    w.kv.state.add_key_with("k-owned", "RSA", |v| {
        v.tags.insert("owner".into(), "ops@example.com".into());
    });
    w.kv.state.add_key_with("k-other", "RSA", |_| {});
    w.kv.state.add_cert_version(
        "c-owned",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(true, false),
        |v| {
            v.tags.insert("notify".into(), "sam@example.com".into());
        },
    );
    w.kv.state.add_cert("c-other", false, "x");
    for filter in [
        "tag=owner",
        "tag=OWNER%3Dops%40example.com",
        "tag=notify",
        "tag=notify%3DSam%40example.com",
        "tag=notify%3Dsam%40example.com%2C+backup%40example.com",
        "q=backup%40example.com",
        "q=owner%3Dops%40example.com",
        "q=ops%40example.com",
        "q=notify%3Dsam",
    ] {
        let (_, html) = w.page(&format!("/v/kv-test/secrets?{filter}")).await;
        assert!(
            html.contains(">owned<") && !html.contains(">other<"),
            "{filter}"
        );
    }
    // The description stays out of the tag filter.
    let (_, html) = w.page("/v/kv-test/secrets?tag=description").await;
    assert!(!html.contains(">owned<"));
    let (_, html) = w
        .page("/v/kv-test/keys?tag=owner%3Dops%40example.com")
        .await;
    assert!(html.contains(">k-owned<") && !html.contains(">k-other<"));
    let (_, html) = w
        .page("/v/kv-test/certificates?tag=notify%3Dsam%40example.com")
        .await;
    assert!(html.contains(">c-owned<") && !html.contains(">c-other<"));
    // The live filter's text holds both, as `name=value`.
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert!(html.contains("owner=ops@example.com"), "{html}");
    assert!(html.contains("notify=sam@example.com, backup@example.com"));
    // The tags column and the suggestions still leave them out, and Keyring
    // never builds a link with an address in it.
    assert!(!html.contains("<span class=\"tag\">owner"));
    assert!(!html.contains("?tag=owner") && !html.contains("tag=owner%3D"));
    let start = html.find("<datalist id=\"tag-filter-options\"").unwrap();
    let list = &html[start..start + html[start..].find("</datalist>").unwrap()];
    assert!(!list.contains("owner") && !list.contains("notify") && !list.contains('@'));

    // Expiry, age and search: the same tag filter, and search finds a
    // notify address.
    for path in [
        "/expiry?show=all&tag=notify%3Dbackup%40example.com",
        "/expiry/age?tag=owner%3Dops%40example.com",
        "/search?q=backup%40example.com",
    ] {
        let (_, html) = w.page(path).await;
        assert!(
            html.contains(">owned<") && !html.contains(">other<"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn expiry_and_age_pages_show_the_owner() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put_with("owned", "x", |v| {
        v.tags.insert("owner".into(), "ops%41@example.com".into());
        v.tags.insert("notify".into(), "sam@example.com".into());
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put_with("odd", "x", |v| {
        v.tags
            .insert("owner".into(), "Payments <p@example.com>".into());
    });
    for path in ["/expiry?show=all", "/expiry/age"] {
        let (_, html) = w.page(path).await;
        assert!(
            html.contains("<th scope=\"col\">Owner</th><th scope=\"col\">Tags</th>"),
            "{path}"
        );
        assert!(
            html.contains(
                "<td class=\"owner-cell\"><a href=\"mailto:ops%2541@example.com\">ops%41@example.com</a></td>"
            ),
            "{path}: {html}"
        );
        assert!(html.contains(
            "<span class=\"mono\">Payments &#60;p@example.com&#62;</span> <span class=\"muted small\">(not a plain address)</span>"
        ));
        assert!(!html.contains("mailto:Payments"));
        // The tags column has the other tags; notify is in the CSV only.
        assert!(html.contains("env=prod") && !html.contains("sam@example.com"));
    }
}

#[tokio::test]
async fn a_padded_owner_tag_from_the_portal_never_blocks_a_save() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |v| {
        v.tags.insert(" owner ".into(), "set in the portal".into());
        v.tags.insert(" description ".into(), "also".into());
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/v/kv-test/keys/app-key/details").await;
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    // Rows in name order: " description ", " owner ", env.
    assert!(html.contains("name=\"tag-name-1\" type=\"text\" value=\" description \""));
    assert!(html.contains("name=\"tag-name-2\" type=\"text\" value=\" owner \""));
    let post = |env: &'static str, extra: Option<(&'static str, &'static str)>| {
        let mut f = vec![
            ("version", version.clone()),
            ("updated", updated.clone()),
            ("tag-rows", "1".into()),
            ("tag-name-1", " description ".into()),
            ("tag-value-1", "also".into()),
            ("tag-name-2", " owner ".into()),
            ("tag-value-2", "set in the portal".into()),
            ("tag-name-3", "env".into()),
            ("tag-value-3", env.into()),
            ("owner", String::new()),
            ("notify", String::new()),
        ];
        if let Some((n, v)) = extra {
            f.push(("tag-name-4", n.into()));
            f.push(("tag-value-4", v.into()));
        }
        f
    };
    // Adding a new padded `owner` row is refused with the pointer.
    let f = post("prod", Some(("  owner", "a@example.com")));
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let res = w.post("/v/kv-test/keys/app-key/details", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        text(body_text(res).await)
            .contains("The owner and notify tags are set with the Owner and Notify fields")
    );
    // An unrelated change saves, and the padded tags stay as they were.
    let f = post("test", None);
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let res = w.post("/v/kv-test/keys/app-key/details", &f).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", location(&res));
    let keys = w.kv.state.keys.lock().unwrap();
    let tags = &keys["app-key"].versions[0].tags;
    assert_eq!(tags[" owner "], "set in the portal");
    assert_eq!(tags[" description "], "also");
    assert_eq!(tags["env"], "test");
    assert!(!tags.contains_key("owner"));
}
