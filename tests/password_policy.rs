//! `KEYRING_PASSWORD_POLICY`: checked on every route that saves a typed
//! password into a Password or Login secret, and nowhere else.

mod support;

use axum::http::StatusCode;
use support::{Part, body_text, hidden_value};

const POLICY: &str = "min=14,upper,lower,digit,symbol,max-repeat=3,common";
/// Meets every rule.
const GOOD: &str = "Corr3ct-Horse-Battery";
/// Long enough, every class, but four of one character in a row.
const REPEATS: &str = "Abcd1234!xxxxy";
const COMMON_MSG: &str = "is a common password, on Keyring&#39;s built-in list. Choose another.";

async fn policy_world() -> support::World {
    support::world_with(&[("KEYRING_PASSWORD_POLICY", POLICY)]).await
}

fn puts(w: &support::World) -> usize {
    w.kv.state
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.starts_with("PUT"))
        .count()
}

#[tokio::test]
async fn the_form_says_what_the_policy_asks_for_before_typing() {
    let w = policy_world().await;
    let (_, html) = w.page("/v/kv-test/secrets/-/new").await;
    assert!(
        html.contains(
            "Keyring&#39;s password policy: at least 14 characters, an upper case letter"
        )
    );
    assert!(html.contains("The Azure CLI and portal don&#39;t apply it."));
    assert!(html.contains(r#"name="value" rows="3" required minlength="14""#));
    assert!(html.contains(r#"aria-describedby="value-help value-policy""#));

    // Login: on the password field only.
    let (_, html) = w.page("/v/kv-test/secrets/-/new?type=login").await;
    assert!(html.contains(r#"id="password-policy""#));
    assert!(html.contains(r#"name="password" type="password" minlength="14""#));
    assert!(html.contains(r#"aria-describedby="password-policy""#));
    assert_eq!(html.matches("minlength=").count(), 1);

    // Other types: no policy anywhere.
    for t in ["database", "api-key", "ssh-key"] {
        let (_, html) = w.page(&format!("/v/kv-test/secrets/-/new?type={t}")).await;
        assert!(!html.contains("password policy"), "{t}");
        assert!(!html.contains("minlength="), "{t}");
    }

    // Set a new value shows it; Edit details has no value, so doesn't.
    w.kv.state.put("plain", GOOD);
    let (_, html) = w.page("/v/kv-test/secrets/plain/value").await;
    assert!(html.contains("password policy"));
    let (_, html) = w.page("/v/kv-test/secrets/plain/edit").await;
    assert!(!html.contains("password policy"));

    // No policy: the form is as before.
    let plain = support::world().await;
    let (_, html) = plain.page("/v/kv-test/secrets/-/new").await;
    assert!(!html.contains("password policy") && !html.contains("minlength="));
    assert!(html.contains(r#"aria-describedby="value-help""#));
}

#[tokio::test]
async fn create_a_password_is_checked() {
    let w = policy_world().await;
    let cases: [(&str, &str); 4] = [
        (
            "short",
            "Value needs at least 14 characters, an upper case letter, a digit (0 to 9) and a symbol, such as ! # or %.",
        ),
        (
            REPEATS,
            "Value can&#39;t have the same character more than 3 times in a row.",
        ),
        ("password", "Value needs at least 14 characters"),
        // On the list whatever the case.
        ("Password", COMMON_MSG),
    ];
    for (value, msg) in cases {
        let res = w
            .post(
                "/v/kv-test/secrets/-/new",
                &[("name", "db-password"), ("value", value), ("enabled", "on")],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{value}");
        let html = body_text(res).await;
        assert!(html.contains(msg), "{value}: {html}");
        assert!(html.contains(r##"href="#value""##), "on the value field");
        assert!(html.contains("></textarea>"), "the value box is empty");
        assert!(!html.contains(&format!("{value}</textarea>")), "not echoed");
        assert!(html.contains("For safety, type it again."));
    }
    assert_eq!(puts(&w), 0, "nothing saved");

    // "password" posted as the type is the same Password.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "db-password"),
                ("secret_type", "password"),
                ("value", "abc"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "db-password"), ("value", GOOD), ("enabled", "on")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("db-password").unwrap().value, GOOD);
}

#[tokio::test]
async fn create_a_login_checks_its_password_only() {
    let w = policy_world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "site"),
                ("secret_type", "login"),
                ("username", "a"),
                ("password", "letmein"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(
        html.contains("Password needs at least 14 characters"),
        "{html}"
    );
    assert!(html.contains(&format!("Password {COMMON_MSG}")));
    assert!(html.contains(r##"href="#password""##));
    assert!(!html.contains("letmein"));
    assert_eq!(puts(&w), 0);

    // Username, URL and notes aren't checked.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "site"),
                ("secret_type", "login"),
                ("url", "x"),
                ("username", "a"),
                ("notes", "password"),
                ("password", GOOD),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn other_types_and_their_password_fields_are_not_checked() {
    let w = policy_world().await;
    let posts: [&[(&str, &str)]; 3] = [
        &[
            ("name", "db"),
            ("secret_type", "database"),
            ("server", "s"),
            ("username", "u"),
            ("password", "password"),
        ],
        &[
            ("name", "api"),
            ("secret_type", "api-key"),
            ("key", "password"),
        ],
        &[
            ("name", "ssh"),
            ("secret_type", "ssh-key"),
            ("private_key", "k"),
            ("passphrase", "password"),
        ],
    ];
    for post in posts {
        let res = w.post("/v/kv-test/secrets/-/new", post).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{post:?}");
    }
}

#[tokio::test]
async fn set_a_new_value_takes_the_type_from_the_secret_not_the_post() {
    let w = policy_world().await;
    // A Password (no Keyring content type): checked, whatever the post
    // claims the type is.
    w.kv.state.put("plain", GOOD);
    for claim in ["", "database", "api-key", "login"] {
        let res = w
            .post(
                "/v/kv-test/secrets/plain/value",
                &[
                    ("secret_type", claim),
                    ("content_type", "application/vnd.keyring.database+json;v=1"),
                    ("value", "password"),
                    ("key", "x"),
                ],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{claim}");
        assert!(body_text(res).await.contains("Value needs at least 14"));
    }
    assert_eq!(w.kv.state.version_count("plain"), 1);
    let res = w
        .post("/v/kv-test/secrets/plain/value", &[("value", GOOD)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.version_count("plain"), 2);

    // A Login: its password is checked.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "site"),
                ("secret_type", "login"),
                ("password", GOOD),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    for claim in ["", "database", "password"] {
        let res = w
            .post(
                "/v/kv-test/secrets/site/value",
                &[
                    ("secret_type", claim),
                    ("password", REPEATS),
                    ("value", GOOD),
                ],
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{claim}");
        let html = body_text(res).await;
        assert!(html.contains("Password can&#39;t have the same character"));
        assert!(!html.contains(REPEATS));
    }
    assert_eq!(w.kv.state.version_count("site"), 1);

    // A Database: not checked, even if the post claims Login.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "db"),
                ("secret_type", "database"),
                ("server", "s"),
                ("username", "u"),
                ("password", "x"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let res = w
        .post(
            "/v/kv-test/secrets/db/value",
            &[
                ("secret_type", "login"),
                ("server", "s"),
                ("username", "u"),
                ("password", "y"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn edit_details_cant_turn_a_secret_into_a_login() {
    let w = policy_world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "db"),
                ("secret_type", "database"),
                ("server", "s"),
                ("username", "u"),
                ("password", "password"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // A Database's content type is never sent on Edit details, and a
    // Keyring content type can't be typed onto a plain secret either.
    w.kv.state.put("plain", "x");
    for name in ["db", "plain"] {
        let (_, html) = w.page(&format!("/v/kv-test/secrets/{name}/edit")).await;
        let version = hidden_value(&html, "version").unwrap();
        let updated = hidden_value(&html, "updated").unwrap();
        let _ = w
            .post(
                &format!("/v/kv-test/secrets/{name}/edit"),
                &[
                    ("version", version.as_str()),
                    ("updated", updated.as_str()),
                    ("content_type", "application/vnd.keyring.login+json;v=1"),
                    ("enabled", "on"),
                ],
            )
            .await;
        let ct = w.kv.state.current(name).unwrap().content_type;
        assert_ne!(
            ct.as_deref(),
            Some("application/vnd.keyring.login+json;v=1"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn import_copy_and_rollback_are_not_typed_values() {
    let w = policy_world().await;
    // Import: values in a file are stored as written.
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", ".env", b"WEAK=password\n")],
        )
        .await;
    let html = body_text(res).await;
    let id = hidden_value(&html, "import_id").expect("preview");
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(w.kv.state.current("WEAK").unwrap().value, "password");

    // Rollback restores an old value as it was.
    let v1 = w.kv.state.put("rolled", "password");
    w.kv.state.put("rolled", GOOD);
    let res = w
        .post("/v/kv-test/secrets/rolled/rollback", &[("version", &v1)])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("rolled").unwrap().value, "password");
}

#[tokio::test]
async fn a_generated_default_password_passes_a_typical_policy() {
    let w = policy_world().await;
    let res = w
        .post(
            "/generator",
            &[
                ("kind", "password"),
                ("length", "24"),
                ("lower", "on"),
                ("upper", "on"),
                ("digits", "on"),
                ("symbols", "on"),
                ("no_look_alikes", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    let start = html.find("data-secret-value>").unwrap() + "data-secret-value>".len();
    let end = start + html[start..].find("</textarea>").unwrap();
    let value = html[start..end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&#34;", "\"")
        .replace("&#39;", "'");
    let value = value.trim_start_matches('\n');
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "generated"), ("value", value)],
        )
        .await;
    // A run of four of one character in 24 is possible but rare; the
    // unit test in src/password_policy.rs covers many at once.
    if res.status() != StatusCode::SEE_OTHER {
        let html = body_text(res).await;
        assert!(html.contains("more than 3 times in a row"), "{html}");
    }
}
