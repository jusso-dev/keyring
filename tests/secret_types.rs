//! Secret types with several fields (Login, Database, API key, SSH key):
//! create, reveal, set a new value and roll back, malformed values, the
//! reason gate, and old secrets left as they were.

mod support;

use axum::http::StatusCode;
use support::{body_text, location};

/// Every built-in type, with a value for each field that has a marker of
/// its own and characters JSON and HTML must escape.
/// A type's slug, its name, and a value for each field.
type Sample = (
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
);

fn samples() -> Vec<Sample> {
    vec![
        (
            "login",
            "Login",
            vec![
                ("url", "https://LOGINURL.test/?a=\"b\""),
                ("username", "LOGINUSER-o'brien"),
                ("password", "LOGINPASS-<&>\"';{}"),
                ("notes", "LOGINNOTES line one\nline two ü 🔑"),
            ],
        ),
        (
            "database",
            "Database",
            vec![
                ("server", "DBSERVER.test"),
                ("database", "DBNAME"),
                ("username", "DBUSER"),
                ("password", "DBPASS;x='y'@h:1/z {}"),
            ],
        ),
        (
            "api-key",
            "API key",
            vec![
                ("key", "APIKEY-0123456789"),
                ("endpoint", "https://APIENDPOINT.test"),
                ("notes", "APINOTES"),
            ],
        ),
        (
            "ssh-key",
            "SSH private key",
            vec![
                ("username", "SSHUSER"),
                ("host", "SSHHOST.test"),
                (
                    "private_key",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nSSHKEYBODY\n-----END OPENSSH PRIVATE KEY-----\n",
                ),
                ("passphrase", "SSHPASSPHRASE"),
            ],
        ),
    ]
}

/// How Askama writes a value into a page.
fn escaped(s: &str) -> String {
    s.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// The stored JSON, read back as a map.
fn stored(w: &support::World, name: &str) -> serde_json::Map<String, serde_json::Value> {
    let v = w.kv.state.current(name).unwrap().value;
    serde_json::from_str(&v).unwrap()
}

#[tokio::test]
async fn each_type_round_trips_create_reveal_set_and_roll_back() {
    let w = support::world().await;
    for (slug, label, fields) in samples() {
        let name = format!("typed-{slug}");
        // The create form for the type has one input per field.
        let (status, html) = w
            .page(&format!("/v/kv-test/secrets/-/new?type={slug}"))
            .await;
        assert_eq!(status, StatusCode::OK);
        for (k, _) in &fields {
            assert!(html.contains(&format!("name=\"{k}\"")), "{slug}: {k} input");
        }
        assert!(
            !html.contains("name=\"value\""),
            "{slug}: no plain value box"
        );

        // Create.
        let mut post = vec![
            ("name", name.as_str()),
            ("secret_type", slug),
            ("enabled", "on"),
        ];
        post.extend(fields.iter().copied());
        let res = w.post("/v/kv-test/secrets/-/new", &post).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{slug}");
        let v = w.kv.state.current(&name).unwrap();
        assert_eq!(
            v.content_type.as_deref(),
            Some(format!("application/vnd.keyring.{slug}+json;v=1").as_str())
        );
        let json = stored(&w, &name);
        assert_eq!(
            json.len(),
            fields.len(),
            "{slug}: exactly the type's fields"
        );
        for (k, val) in &fields {
            assert_eq!(json[*k], *val, "{slug}: {k} round-trips");
        }
        let first = v.version.clone();

        // The list and detail show the type's name, with no value read.
        let reads = w.kv.state.value_reads().len();
        let (_, list) = w.page("/v/kv-test/secrets").await;
        assert!(
            list.contains(&format!(
                "<td class=\"tech col-p3 cell-fluid\"><span class=\"clip clip-sm\">{}</span></td>",
                escaped(label)
            )),
            "{slug}"
        );
        let (_, detail) = w.page(&format!("/v/kv-test/secrets/{name}")).await;
        assert!(detail.contains(&format!("<dd>{}</dd>", escaped(label))));
        assert_eq!(w.kv.state.value_reads().len(), reads, "no value read");

        // Reveal shows each field with its own Copy.
        let res = w
            .post(&format!("/v/kv-test/secrets/{name}/reveal"), &[])
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers()["cache-control"]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        let html = body_text(res).await;
        assert!(html.contains("showing any of them is a read of the secret"));
        for (k, val) in &fields {
            assert!(
                html.contains(&format!("data-copy=\"field-{k}\"")),
                "{slug}: {k}"
            );
            assert!(html.contains(&escaped(val)), "{slug}: {k} shown");
        }
        assert!(!html.contains("isn't in that type's format"));

        // Set a new value: the same fields, and the type is kept.
        let (_, form) = w.page(&format!("/v/kv-test/secrets/{name}/value")).await;
        for (k, val) in &fields {
            assert!(form.contains(&format!("name=\"{k}\"")));
            assert!(
                !form.contains(&escaped(val)),
                "{slug}: {k} not put in the form"
            );
        }
        let changed: Vec<(&str, String)> = fields
            .iter()
            .map(|(k, v)| (*k, format!("{v}-NEW").replace("\n-NEW", "-NEW\n")))
            .collect();
        let mut post: Vec<(&str, &str)> = vec![("enabled", "on")];
        post.extend(changed.iter().map(|(k, v)| (*k, v.as_str())));
        // A content type posted by hand doesn't change the type.
        post.push(("content_type", "text/plain"));
        let res = w
            .post(&format!("/v/kv-test/secrets/{name}/value"), &post)
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{slug}");
        let v = w.kv.state.current(&name).unwrap();
        assert!(
            v.content_type.unwrap().contains(slug),
            "{slug}: still typed"
        );
        let json = stored(&w, &name);
        for (k, val) in &changed {
            assert_eq!(json[*k], val.as_str());
        }

        // Roll back to the first version: the type comes with it.
        let res = w
            .post(
                &format!("/v/kv-test/secrets/{name}/rollback"),
                &[("version", &first)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let v = w.kv.state.current(&name).unwrap();
        assert!(v.content_type.unwrap().contains(slug));
        let json = stored(&w, &name);
        for (k, val) in &fields {
            assert_eq!(json[*k], *val, "{slug}: {k} rolled back");
        }
    }
}

#[tokio::test]
async fn database_reveal_offers_connection_strings() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "app-db"),
                ("secret_type", "database"),
                ("enabled", "on"),
                ("server", "db.test"),
                ("database", "app"),
                ("username", "svc"),
                ("password", "a;b'c\"d"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let html = body_text(w.post("/v/kv-test/secrets/app-db/reveal", &[]).await).await;
    assert!(html.contains("Connection strings"));
    // SqlClient: double quotes, with a double quote doubled.
    assert!(html.contains(&escaped(
        "Server=\"db.test\";Database=\"app\";User ID=\"svc\";Password=\"a;b'c\"\"d\""
    )));
    // libpq: single quotes, with a single quote escaped by a backslash.
    assert!(html.contains(&escaped(
        "host='db.test' dbname='app' user='svc' password='a;b\\'c\"d'"
    )));
}

#[tokio::test]
async fn validation_errors_name_the_field_and_echo_no_secret_material() {
    let w = support::world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "bad name"),
                ("secret_type", "login"),
                ("url", "https://ECHOURL.test"),
                ("username", "ECHOUSER"),
                ("password", ""),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        res.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let html = body_text(res).await;
    assert!(html.contains("Enter the password."));
    assert!(html.contains("For safety, type the fields again."));
    assert!(!html.contains("ECHOURL") && !html.contains("ECHOUSER"));
    // The type is kept, so the same fields come back.
    assert!(html.contains("name=\"secret_type\" value=\"login\""));
    assert!(w.kv.state.current("bad-name").is_none());

    // Over the limit once encoded: the error names the field to shorten.
    let key = format!("{}\n", "\"".repeat(16 * 1024 - 1));
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "big-key"),
                ("secret_type", "ssh-key"),
                ("private_key", &key),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("over Key Vault&#39;s limit of 25,600 characters. Shorten Private key."));
    assert!(html.contains("id=\"private_key-error\""));
    assert!(w.kv.state.current("big-key").is_none());
}

#[tokio::test]
async fn malformed_typed_values_show_as_plain_with_a_warning() {
    let w = support::world().await;
    let cases = [
        (
            "application/vnd.keyring.login+json;v=1",
            "MALFORMED not json",
        ),
        (
            "application/vnd.keyring.login+json;v=1",
            r#"{"url":"","username":"","password":"MALFORMED"}"#,
        ),
        (
            "application/vnd.keyring.api-key+json;v=1",
            r#"{"key":"MALFORMED","endpoint":"","notes":"","extra":""}"#,
        ),
        (
            "application/vnd.keyring.api-key+json;v=1",
            r#"{"key":7,"endpoint":"MALFORMED","notes":""}"#,
        ),
        (
            "application/vnd.keyring.login+json;v=2",
            r#"{"url":"","username":"","password":"MALFORMED","notes":""}"#,
        ),
        ("application/vnd.keyring.wifi+json;v=1", "MALFORMED wifi"),
    ];
    for (i, (ct, value)) in cases.iter().enumerate() {
        let name = format!("odd-{i}");
        w.kv.state
            .put_with(&name, value, |v| v.content_type = Some((*ct).into()));
        let res = w
            .post(&format!("/v/kv-test/secrets/{name}/reveal"), &[])
            .await;
        assert_eq!(res.status(), StatusCode::OK, "case {i}");
        let html = body_text(res).await;
        assert!(html.contains("isn't in that type's format"), "case {i}");
        assert!(html.contains("id=\"secret-value\""), "case {i}: plain box");
        assert!(html.contains("MALFORMED"), "case {i}: value shown");
    }
}

#[tokio::test]
async fn other_content_types_behave_as_before() {
    let w = support::world().await;
    for (i, ct) in [None, Some("text/plain"), Some("application/json")]
        .into_iter()
        .enumerate()
    {
        let name = format!("plain-{i}");
        w.kv.state.put_with(&name, "{\"a\":\"PLAINVALUE\"}", |v| {
            v.content_type = ct.map(str::to_owned)
        });
        let html = body_text(
            w.post(&format!("/v/kv-test/secrets/{name}/reveal"), &[])
                .await,
        )
        .await;
        assert!(html.contains("id=\"secret-value\""));
        assert!(!html.contains("data-copy=\"field-"));
        assert!(!html.contains("isn't in that type's format"));
        let (_, form) = w.page(&format!("/v/kv-test/secrets/{name}/value")).await;
        assert!(form.contains("name=\"value\""));
        let res = w
            .post(
                &format!("/v/kv-test/secrets/{name}/value"),
                &[
                    ("value", "next"),
                    ("content_type", ct.unwrap_or_default()),
                    ("enabled", "on"),
                ],
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let v = w.kv.state.current(&name).unwrap();
        assert_eq!(v.value, "next");
        assert_eq!(v.content_type.as_deref(), ct);
    }
    // A Keyring content type typed by hand on a plain secret is refused.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "sneaky"),
                ("value", "x"),
                ("content_type", "application/vnd.keyring.login+json;v=1"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(w.kv.state.current("sneaky").is_none());
}

#[tokio::test]
async fn edit_details_keeps_the_type() {
    let w = support::world().await;
    let ct = "application/vnd.keyring.api-key+json;v=1";
    w.kv.state
        .put_with("api", r#"{"key":"k","endpoint":"","notes":""}"#, |v| {
            v.content_type = Some(ct.into())
        });
    let (_, html) = w.page("/v/kv-test/secrets/api/edit").await;
    assert!(!html.contains("name=\"content_type\""), "not editable");
    let version = support::hidden_value(&html, "version").unwrap();
    let updated = support::hidden_value(&html, "updated").unwrap();
    let res = w
        .post(
            "/v/kv-test/secrets/api/edit",
            &[
                ("version", &version),
                ("updated", &updated),
                ("tag-name-1", "env"),
                ("tag-value-1", "prod"),
                ("enabled", "on"),
                ("content_type", "text/plain"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", location(&res));
    let v = w.kv.state.current("api").unwrap();
    assert_eq!(v.content_type.as_deref(), Some(ct));
    assert_eq!(v.tags.get("env").map(String::as_str), Some("prod"));
}

#[tokio::test]
async fn the_reason_page_never_carries_typed_fields() {
    let w = support::world_with(&[("KEYRING_REQUIRE_REASON", "all")]).await;
    // The forms ask for the reason themselves.
    let (_, html) = w.page("/v/kv-test/secrets/-/new?type=login").await;
    assert!(html.contains("name=\"reason\""));

    let mut markers = Vec::new();
    for (slug, _, fields) in samples() {
        let mut post = vec![("name", "gated"), ("secret_type", slug)];
        post.extend(fields.iter().copied());
        markers.extend(fields.iter().map(|(_, v)| *v));
        let res = w.post("/v/kv-test/secrets/-/new", &post).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{slug}");
        let html = body_text(res).await;
        assert!(html.contains("Go back to the form"), "{slug}: sent back");
        assert!(!html.contains("type=\"hidden\" name=\"password\""));
        for (k, v) in &fields {
            let shown = html.contains(*v) || html.contains(&escaped(v));
            assert!(!shown, "{slug}: {k} written into the reason page");
        }
    }
    // Set a new value is never carried either.
    w.kv.state.put_with(
        "gated-api",
        r#"{"key":"k","endpoint":"","notes":""}"#,
        |v| v.content_type = Some("application/vnd.keyring.api-key+json;v=1".into()),
    );
    let res = w
        .post(
            "/v/kv-test/secrets/gated-api/value",
            &[("key", "SETVALUEKEY"), ("endpoint", "SETVALUEEND")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(!html.contains("SETVALUEKEY") && !html.contains("SETVALUEEND"));
    assert!(w.kv.state.current("gated").is_none(), "nothing saved");
    assert!(!markers.is_empty());
}
