//! Notes on secrets, certificates and keys, kept in the `description` tag
//! (#254): round trips for each item type, the limits, and Edit details for
//! certificates and keys.

mod support;

use axum::http::StatusCode;
use support::{Part, body_text, hidden_value, location};

const NOTE: &str = "Used by the billing job.\nAsk the payments team before rotating.";

fn tags_of(v: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v["tags"].as_object().cloned().unwrap_or_default()
}

#[tokio::test]
async fn secret_round_trip_with_line_breaks() {
    let w = support::world().await;
    let posted = NOTE.replace('\n', "\r\n");
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "db-password"),
                ("value", "x"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", &posted),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.tags["description"], NOTE, "stored with \\n");
    assert_eq!(v.tags["env"], "prod");

    // Shown under the heading, and not in the tag list.
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(
        html.contains("<p class=\"item-note\">Used by the billing job.\nAsk the payments team")
    );
    assert!(!html.contains("<span class=\"tag\">description"));
    // The list has the column; the filter finds it.
    let (_, html) = w.page("/v/kv-test/secrets?q=billing").await;
    assert!(html.contains(">Description</th>"));
    assert!(html.contains(">db-password<"));

    // The edit form has it in its own field, not in the tags box.
    let (_, html) = w.page("/v/kv-test/secrets/db-password/edit").await;
    assert!(
        html.contains(
            ">Used by the billing job.\nAsk the payments team before rotating.</textarea>"
        )
    );
    assert!(html.contains("name=\"tag-name-1\" type=\"text\" value=\"env\""));
    assert!(html.contains("name=\"tag-value-1\" type=\"text\" value=\"prod\""));
    assert!(
        !html.contains("value=\"description\""),
        "the note has no row"
    );
    assert!(html.contains("data-count-for=\"description\""));
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();

    // Change it, and the tags are kept.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", "Billing only"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert_eq!(v.tags["description"], "Billing only");
    assert_eq!(v.tags["env"], "prod");

    // Set a new value keeps it unless changed.
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/value",
            &[
                ("value", "y"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", "Billing only"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        w.kv.state.current("db-password").unwrap().tags["description"],
        "Billing only"
    );

    // An empty field removes the tag.
    let (_, html) = w.page("/v/kv-test/secrets/db-password/edit").await;
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", ""),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("db-password").unwrap();
    assert!(!v.tags.contains_key("description"));
    assert_eq!(v.tags.len(), 1);
}

#[tokio::test]
async fn limits_are_checked_before_azure() {
    let w = support::world().await;
    let create = |desc: String, tags: &[(&str, &str)]| {
        let mut f = vec![
            ("name".to_owned(), "n".to_owned()),
            ("value".to_owned(), "x".to_owned()),
            ("description".to_owned(), desc),
        ];
        for (i, (k, v)) in tags.iter().enumerate() {
            f.push((format!("tag-name-{}", i + 1), (*k).to_owned()));
            f.push((format!("tag-value-{}", i + 1), (*v).to_owned()));
        }
        f
    };
    let post = |fields: Vec<(String, String)>| {
        let w = &w;
        async move {
            let f: Vec<(&str, &str)> = fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            w.post("/v/kv-test/secrets/-/new", &f).await
        }
    };
    // 256 accepted, 257 refused.
    let res = post(create("a".repeat(256), &[])).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let before = w.kv.state.log.lock().unwrap().len();
    let res = post(create("a".repeat(257), &[])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("up to 256 characters. This one has 257."));
    assert!(
        html.contains("href=\"#description\""),
        "linked from the summary"
    );
    // An emoji counts as two, as Key Vault and the browser count it.
    let res = post(create("😀".repeat(129), &[])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Invisible characters are refused.
    let res = post(create("pay\u{200B}ments".into(), &[])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("hidden character"));
    // `description` typed as a tag is refused, pointing at the field.
    let res = post(create(String::new(), &[("description", "sneaky")])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("Description field"));
    // 15 tags and a description: 16, refused.
    let names: Vec<String> = (0..15).map(|i| format!("k{i}")).collect();
    let fifteen: Vec<(&str, &str)> = names.iter().map(|k| (k.as_str(), "v")).collect();
    let res = post(create("note".into(), &fifteen)).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("15 tags"));
    // None of the refused ones reached Key Vault.
    let log = w.kv.state.log.lock().unwrap();
    assert!(
        log[before..].iter().all(|l| !l.starts_with("PUT")),
        "{:?}",
        &log[before..]
    );
}

#[tokio::test]
async fn editing_tags_never_drops_a_tag_the_form_cant_show() {
    let w = support::world().await;
    w.kv.state.put_with("odd", "x", |v| {
        v.tags.insert("a=b".into(), " c ".into());
        v.tags.insert("two".into(), "lines\nhere".into());
        v.tags.insert("description".into(), "old".into());
    });
    let (_, html) = w.page("/v/kv-test/secrets/odd/edit").await;
    assert!(html.contains(">old</textarea>"));
    // a=b fits a row now; the tag with a line break is listed and kept.
    assert!(html.contains("value=\"a=b\""));
    assert!(html.contains("value=\" c \""));
    assert!(html.contains("<li class=\"mono\">two: lines\nhere</li>"));
    assert!(
        !html.contains("description: old"),
        "not listed as a locked tag"
    );
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let res = w
        .post(
            "/v/kv-test/secrets/odd/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-rows", "1"),
                ("tag-name-1", "a=b"),
                ("tag-value-1", " c "),
                ("description", "new"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let v = w.kv.state.current("odd").unwrap();
    assert_eq!(v.tags["a=b"], " c ");
    assert_eq!(v.tags["two"], "lines\nhere");
    assert_eq!(v.tags["description"], "new");
}

#[tokio::test]
async fn certificate_create_upload_and_edit_details() {
    let w = support::world().await;
    // Create.
    let res = w
        .post(
            "/v/kv-test/certificates/-/new",
            &[
                ("name", "web-tls"),
                ("common_name", "app.example.com"),
                ("validity_months", "12"),
                ("issuer", "Self"),
                ("tag-name-1", "team"),
                ("tag-value-1", "web"),
                ("description", "Front door"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", location(&res));
    let created = w.kv.state.creates.lock().unwrap()[0].body.clone();
    assert_eq!(tags_of(&created)["description"], "Front door");
    assert_eq!(tags_of(&created)["team"], "web");

    // Upload: the preview shows it, the import sends it.
    let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
    let res = w
        .post_multipart(
            "/v/kv-test/certificates/-/upload",
            &[
                Part::File("file", "web.pfx", pfx),
                Part::Text("name", "api-tls"),
                Part::Text("password", "test-password"),
                Part::Text("description", "API\r\nedge"),
                Part::Text("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("<dd class=\"note\">API\nedge</dd>"), "{html}");
    let id = hidden_value(&html, "upload_id").unwrap();
    let res = w
        .post(
            "/v/kv-test/certificates/-/upload/confirm",
            &[("upload_id", &id)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let imported = w.kv.state.imports.lock().unwrap()[0].body.clone();
    assert_eq!(tags_of(&imported)["description"], "API\nedge");

    // Edit details on an existing certificate: read, merge, write.
    w.kv.state.add_cert_version(
        "edge",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(true, false),
        |v| {
            v.tags.insert("env".into(), "prod".into());
            v.tags.insert("owner".into(), "ops@example.com".into());
        },
    );
    let (status, html) = w.page("/v/kv-test/certificates/edge").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("/certificates/edge/details\">Edit details</a>"));
    let (status, html) = w.page("/v/kv-test/certificates/edge/details").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("name=\"tag-name-1\" type=\"text\" value=\"env\""));
    assert!(html.contains("name=\"tag-value-2\" type=\"text\" value=\"ops@example.com\""));
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let before = w.kv.state.certs.lock().unwrap()["edge"].clone();
    let res = w
        .post(
            "/v/kv-test/certificates/edge/details",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("tag-name-2", "owner"),
                ("tag-value-2", "ops@example.com"),
                ("description", "Edge proxy"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/certificates/edge");
    // Only tags were sent, and every other tag was kept.
    let patches =
        w.kv.state
            .cert_extra
            .version_patches
            .lock()
            .unwrap()
            .clone();
    assert_eq!(patches.len(), 1);
    let body = patches[0].as_object().unwrap();
    assert_eq!(body.keys().collect::<Vec<_>>(), ["attributes", "tags"]);
    assert_eq!(patches[0]["attributes"], serde_json::json!({}));
    let after = w.kv.state.certs.lock().unwrap()["edge"].clone();
    let (b, a) = (&before.versions[0], &after.versions[0]);
    assert_eq!(a.tags.len(), 3);
    assert_eq!(a.tags["description"], "Edge proxy");
    assert_eq!(a.tags["owner"], "ops@example.com");
    assert_eq!((a.enabled, a.exp, a.nbf), (b.enabled, b.exp, b.nbf));
    assert_eq!(after.policy, before.policy);
    assert_eq!(after.versions.len(), 1, "no new version");
    let (_, html) = w.page("/v/kv-test/certificates/edge").await;
    assert!(html.contains("<p class=\"item-note\">Edge proxy</p>"));

    // Nothing changed: nothing sent.
    let (_, html) = w.page("/v/kv-test/certificates/edge/details").await;
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let same = [
        ("version", version.as_str()),
        ("updated", updated.as_str()),
        ("tag-name-1", "env"),
        ("tag-value-1", "prod"),
        ("tag-name-2", "owner"),
        ("tag-value-2", "ops@example.com"),
        ("description", "Edge proxy"),
    ];
    let res = w.post("/v/kv-test/certificates/edge/details", &same).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        w.kv.state.cert_extra.version_patches.lock().unwrap().len(),
        1
    );

    // A form from an older version saves nothing.
    let stale = [
        ("version", "0".repeat(32)),
        ("updated", updated.clone()),
        ("description", "x".into()),
    ];
    let f: Vec<(&str, &str)> = stale.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let res = w.post("/v/kv-test/certificates/edge/details", &f).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // 15 tags and no description: refused with a message, before Azure.
    w.kv.state.add_cert_version(
        "full",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(true, false),
        |v| {
            for i in 0..15 {
                v.tags.insert(format!("k{i}"), "v".into());
            }
        },
    );
    let (_, html) = w.page("/v/kv-test/certificates/full/details").await;
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let mut full: Vec<(String, String)> = vec![
        ("version".into(), version),
        ("updated".into(), updated),
        ("description".into(), "one more".into()),
    ];
    for i in 0..15 {
        full.push((format!("tag-name-{}", i + 1), format!("k{i}")));
        full.push((format!("tag-value-{}", i + 1), "v".into()));
    }
    let f: Vec<(&str, &str)> = full.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let res = w.post("/v/kv-test/certificates/full/details", &f).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("already has 15 tags"));
    assert_eq!(
        w.kv.state.cert_extra.version_patches.lock().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn key_create_and_edit_details() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/keys/-/new",
            &[
                ("name", "signing"),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", "Signs invoices"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = w.kv.state.key_creates.lock().unwrap()[0].clone();
    assert_eq!(tags_of(&body)["description"], "Signs invoices");
    let (_, html) = w.page("/v/kv-test/keys").await;
    assert!(html.contains("<td class=\"note-cell\">Signs invoices</td>"));
    let (_, html) = w.page("/v/kv-test/keys/signing/details").await;
    assert!(html.contains(">Signs invoices</textarea>"));
    assert!(html.contains("name=\"tag-value-1\" type=\"text\" value=\"prod\""));
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    let res = w
        .post(
            "/v/kv-test/keys/signing/details",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("description", ""),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let keys = w.kv.state.keys.lock().unwrap();
    let tags = &keys["signing"].versions[0].tags;
    assert_eq!(tags.len(), 1);
    assert_eq!(tags["env"], "prod");
}

#[tokio::test]
async fn long_notes_are_cut_in_lists_with_the_whole_note_for_screen_readers() {
    let w = support::world().await;
    let long = format!("{} end", "word ".repeat(30));
    w.kv.state.put_with("long", "x", |v| {
        v.tags.insert("description".into(), long.trim().into());
    });
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert!(html.contains("<span aria-hidden=\"true\">word word"));
    assert!(html.contains("…</span><span class=\"visually-hidden\">word word"));
    assert!(html.contains(" end</span>"));
}

#[tokio::test]
async fn copy_brings_the_note_with_the_tags() {
    let target = std::sync::Arc::new(support::keyvault::KvState::default());
    let w = support::world_of_vaults_with(
        vec![
            (
                "kv-test",
                std::sync::Arc::new(support::keyvault::KvState::default()),
            ),
            ("kv-prod", target.clone()),
        ],
        &[],
    )
    .await;
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("description".into(), "Copied note".into());
    });
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/copy",
            &[
                ("to_vault", "kv-prod"),
                ("to_name", "db-password"),
                ("tags", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        target.current("db-password").unwrap().tags["description"],
        "Copied note"
    );
}

#[tokio::test]
async fn search_matches_the_note() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags
            .insert("description".into(), "Payroll database".into());
    });
    w.kv.state.put("other", "x");
    let (_, html) = w.page("/search?q=payroll").await;
    assert!(html.contains(">db-password<"));
    assert!(!html.contains(">other<"));
    assert!(html.contains("Payroll database"));
}

#[tokio::test]
async fn bulk_sets_and_removes_the_note() {
    let w = support::world().await;
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put("b", "x");
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk/apply",
            &[
                ("item", "a"),
                ("item", "b"),
                ("op", "description_set"),
                ("description", "Team A"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let a = w.kv.state.current("a").unwrap();
    assert_eq!(a.tags["description"], "Team A");
    assert_eq!(a.tags["env"], "prod");
    assert_eq!(
        w.kv.state.current("b").unwrap().tags["description"],
        "Team A"
    );
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk/apply",
            &[("item", "a"), ("op", "description_remove")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let a = w.kv.state.current("a").unwrap();
    assert!(!a.tags.contains_key("description"));
    assert_eq!(a.tags["env"], "prod");
}
