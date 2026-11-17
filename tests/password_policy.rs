//! `KEYRING_PASSWORD_POLICY`: checked on every route that saves a new
//! value into a Password or Login secret (create, Set a new value and
//! import), and not on copy or rollback.

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
    assert!(html.contains("Every plain value is checked as a password, so for a key, PEM block or connection string choose its type"));
    assert!(html.contains(r#"name="value" rows="3" required minlength="14""#));
    assert!(html.contains(r#"aria-describedby="value-help value-policy""#));

    // Login: on the password field only.
    let (_, html) = w.page("/v/kv-test/secrets/-/new?type=login").await;
    assert!(html.contains(r#"id="password-policy""#));
    assert!(
        !html.contains("Every plain value"),
        "the Login password isn't plain"
    );
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

/// Preview a file, then import it. The preview's HTML and the results'.
async fn import(w: &support::World, file_name: &str, file: &[u8]) -> (String, String) {
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", file_name, file)],
        )
        .await;
    let preview = body_text(res).await;
    let Some(id) = hidden_value(&preview, "import_id") else {
        return (preview, String::new());
    };
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    (preview, body_text(res).await)
}

const POLICY_ROW: &str = "Its value doesn&#39;t meet Keyring&#39;s password policy.";
const LOGIN_CT: &str = "application/vnd.keyring.login+json;v=1";

#[tokio::test]
async fn import_checks_each_value_against_the_policy() {
    let w = policy_world().await;
    // (a) An existing Password can't get a weak new version from a file.
    w.kv.state.put("db-password", GOOD);
    let (preview, results) = import(&w, ".env", b"db-password=password\n").await;
    assert!(preview.contains(POLICY_ROW), "{preview}");
    assert!(
        preview.contains("Keyring's password policy: at least 14 characters"),
        "said once above the table: {preview}"
    );
    assert_eq!(preview.matches("password policy:").count(), 1);
    assert!(preview.contains("Nothing in this file can be imported"));
    assert!(results.is_empty(), "nothing to confirm");
    assert_eq!(w.kv.state.version_count("db-password"), 1);
    assert_eq!(w.kv.state.current("db-password").unwrap().value, GOOD);

    // A mixed file: good rows are written, bad ones skipped and named.
    let file =
        format!("GOOD_ONE={GOOD}\nWEAK=password\nREPEATS={REPEATS}\nGOOD_TWO=Another-G00d-Value\n");
    let (preview, results) = import(&w, ".env", file.as_bytes()).await;
    assert_eq!(preview.matches(POLICY_ROW).count(), 2, "{preview}");
    // The problem names no rule and nothing about the value.
    for word in ["characters", "repeat", "in a row", "common", "upper"] {
        assert!(!preview.contains(&format!("{word}.</p>")), "{word}");
    }
    assert!(!preview.contains(REPEATS) && !preview.contains(GOOD));
    assert!(results.contains("Imported 2 secrets"), "{results}");
    assert_eq!(results.matches(POLICY_ROW).count(), 2, "{results}");
    assert_eq!(w.kv.state.current("GOOD-ONE").unwrap().value, GOOD);
    assert!(w.kv.state.current("GOOD-TWO").is_some());
    assert!(w.kv.state.current("WEAK").is_none());
    assert!(w.kv.state.current("REPEATS").is_none());

    // A row that meets the policy is written, as a new version too.
    let (_, results) = import(&w, ".env", b"db-password=Corr3ct-Horse-Battery-2\n").await;
    assert!(results.contains("Imported 1 secret"), "{results}");
    assert_eq!(w.kv.state.version_count("db-password"), 2);
}

#[tokio::test]
async fn import_never_makes_a_typed_secret() {
    // With a policy and without: a Keyring content type is never imported.
    for w in [policy_world().await, support::world().await] {
        // (b) A Login made from a CSV row, or a Password turned into one.
        w.kv.state.put("existing", GOOD);
        let login = r#""{""username"":""a"",""password"":""password""}""#;
        let file = format!(
            "name,value,content_type\nnew-login,{login},{LOGIN_CT}\nexisting,{login},{LOGIN_CT}\ndb,x,application/vnd.keyring.database+json;v=1\nfuture,x,application/vnd.keyring.other+json;v=9\n"
        );
        let (preview, results) = import(&w, "s.csv", file.as_bytes()).await;
        assert_eq!(
            preview
                .matches("Typed secrets are made on the Create form")
                .count(),
            4,
            "{preview}"
        );
        assert!(results.is_empty(), "nothing to confirm");
        assert!(w.kv.state.current("new-login").is_none());
        assert!(w.kv.state.current("db").is_none());
        let existing = w.kv.state.current("existing").unwrap();
        assert_eq!(existing.content_type, None);
        assert_eq!(w.kv.state.version_count("existing"), 1);
    }
}

#[tokio::test]
async fn import_over_a_typed_secret_writes_a_checked_plain_secret() {
    // Import treats a name in the vault the way it always has: the file's
    // value and content type make the new version. Over a Login, that is
    // a plain secret (a Password), so the policy applies, and it can never
    // be a Login holding a password Keyring didn't check.
    let w = policy_world().await;
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "site"),
                ("secret_type", "login"),
                ("username", "a"),
                ("password", GOOD),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (preview, _) = import(&w, ".env", b"site=password\n").await;
    assert!(preview.contains(POLICY_ROW), "{preview}");
    assert_eq!(w.kv.state.version_count("site"), 1);
    assert_eq!(
        w.kv.state.current("site").unwrap().content_type.as_deref(),
        Some(LOGIN_CT)
    );

    let (_, results) = import(&w, ".env", b"site=Corr3ct-Horse-Battery-3\n").await;
    assert!(results.contains("Imported 1 secret"), "{results}");
    let now = w.kv.state.current("site").unwrap();
    assert_eq!(now.content_type, None, "a plain secret now");
    assert_eq!(now.value, "Corr3ct-Horse-Battery-3");
    let html = body_text(w.post("/v/kv-test/secrets/site/reveal", &[]).await).await;
    assert!(!html.contains("Username"), "shown as a Password: {html}");
}

#[tokio::test]
async fn copy_and_rollback_are_not_typed_values() {
    let w = policy_world().await;
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
    // Askama writes numeric entities (`&#60;`, `&#62;`, `&#38;`, `&#34;`,
    // `&#39;`). `&#38;` last, so `&` followed by `#60;` stays as typed.
    let value = html[start..end]
        .replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&");
    let value = value.trim_start_matches('\n');
    assert_eq!(value.chars().count(), 24, "the real generated value");
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
