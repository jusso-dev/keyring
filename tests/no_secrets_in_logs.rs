//! Secret values and tokens never reach the logs.
//!
//! Kept in its own test binary with a single log capture test: `tracing` caches whether
//! a log line is wanted, and other tests running alongside without a
//! subscriber can switch lines off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::json;

/// Collects everything `tracing` writes, at every level.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

const VALUE: &str = "Sup3r-S3cret-Value-<&>\"'";

#[tokio::test]
async fn values_never_reach_the_logs() {
    use tracing_subscriber::layer::SubscriberExt;
    // Both formats at once: text as before, and KEYRING_LOG_FORMAT=json.
    let capture = Capture::default();
    let json = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .event_format(keyring::telemetry::JsonLines)
                .with_writer(json.clone()),
        );
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    // An error path too.
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let _ = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    *w.kv.state.fail.lock().unwrap() = None;

    // A copy to another vault: the value passes through memory only. A
    // copy that the target refuses, and one that goes through.
    let target = std::sync::Arc::new(support::keyvault::KvState::default());
    let wc = support::world_of_vaults_with(
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
    wc.kv.state.put("db-password", VALUE);
    let copy = [
        ("to_vault", "kv-prod"),
        ("to_name", "db-copy"),
        ("tags", "on"),
    ];
    let res = wc
        .get("/v/kv-test/secrets/db-password/copy/review?to_vault=kv-prod&to_name=db-copy")
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!support::body_text(res).await.contains("Sup3r-S3cret"));
    target.fail_each.lock().unwrap().push((
        axum::http::Method::PUT,
        "/secrets/db-copy$".into(),
        403,
        "ForbiddenByRbac",
    ));
    let res = wc.post("/v/kv-test/secrets/db-password/copy", &copy).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(!support::body_text(res).await.contains("Sup3r-S3cret"));
    target.fail_each.lock().unwrap().clear();
    let res = wc.post("/v/kv-test/secrets/db-password/copy", &copy).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let flash = res
        .headers()
        .get("set-cookie")
        .map(|c| c.to_str().unwrap().to_owned());
    assert!(!flash.unwrap_or_default().contains("Sup3r-S3cret"));
    assert!(!support::location(&res).contains("Sup3r-S3cret"));
    let _ = support::body_text(res).await;
    assert_eq!(target.current("db-copy").unwrap().value, VALUE);
    // With a reason, which goes on both events.
    let wcr = support::world_of_vaults_with(
        vec![
            (
                "kv-test",
                std::sync::Arc::new(support::keyvault::KvState::default()),
            ),
            (
                "kv-stage",
                std::sync::Arc::new(support::keyvault::KvState::default()),
            ),
        ],
        &[("KEYRING_REQUIRE_REASON", "reveal")],
    )
    .await;
    wcr.kv.state.put("db-password", VALUE);
    let res = wcr
        .post(
            "/v/kv-test/secrets/db-password/copy",
            &[
                ("to_vault", "kv-stage"),
                ("to_name", "db-staged"),
                ("reason", "Promote to staging"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    // With a reason asked for: the reason is logged, the value isn't, and
    // a value posted to the reason page isn't either.
    let wr = support::world_with(&[("KEYRING_REQUIRE_REASON", "all")]).await;
    wr.kv.state.put("db-password", VALUE);
    let res = wr
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", "Checking the value")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    let res = wr
        .post("/v/kv-test/secrets/db-password/value", &[("value", VALUE)])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(!support::body_text(res).await.contains("Sup3r-S3cret"));

    // Typed secrets: create, set a new value and reveal, with a marker in
    // every field, including the ones that aren't masked.
    let typed: [(&str, &[(&str, &str)]); 4] = [
        (
            "login",
            &[
                ("url", "TYPLEAK-url"),
                ("username", "TYPLEAK-user"),
                ("password", "TYPLEAK-pass"),
                ("notes", "TYPLEAK-notes"),
            ],
        ),
        (
            "database",
            &[
                ("server", "TYPLEAK-server"),
                ("database", "TYPLEAK-db"),
                ("username", "TYPLEAK-dbuser"),
                ("password", "TYPLEAK-dbpass"),
            ],
        ),
        (
            "api-key",
            &[
                ("key", "TYPLEAK-key"),
                ("endpoint", "TYPLEAK-endpoint"),
                ("notes", "TYPLEAK-apinotes"),
            ],
        ),
        (
            "ssh-key",
            &[
                ("username", "TYPLEAK-sshuser"),
                ("host", "TYPLEAK-host"),
                ("private_key", "TYPLEAK-pk\nline"),
                ("passphrase", "TYPLEAK-phrase"),
            ],
        ),
    ];
    for (slug, fields) in typed {
        let name = format!("typed-{slug}");
        let mut post = vec![
            ("name", name.as_str()),
            ("secret_type", slug),
            ("enabled", "on"),
        ];
        post.extend_from_slice(fields);
        let res = w.post("/v/kv-test/secrets/-/new", &post).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = w
            .post(&format!("/v/kv-test/secrets/{name}/value"), &post[1..])
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = w
            .post(&format!("/v/kv-test/secrets/{name}/reveal"), &[])
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(support::body_text(res).await.contains("TYPLEAK"));
        // A failed check, and the reason page.
        let res = w
            .post(
                "/v/kv-test/secrets/-/new",
                &[
                    ("name", "bad name"),
                    ("secret_type", slug),
                    ("password", "TYPLEAK-bad"),
                ],
            )
            .await;
        assert!(!support::body_text(res).await.contains("TYPLEAK"));
        let res = wr.post("/v/kv-test/secrets/-/new", &post).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(!support::body_text(res).await.contains("TYPLEAK"));
    }

    // Password policy (#261): refused and accepted typed values, on a
    // Password and a Login, one of them on the common list. Only the
    // fixed reason code is recorded, never the value, its length or the
    // list entry.
    let wp = support::world_with(&[(
        "KEYRING_PASSWORD_POLICY",
        "min=20,upper,lower,digit,symbol,max-repeat=2,common",
    )])
    .await;
    wp.kv.state.put("pol-existing", "POLLEAK-Old-Value-1!");
    for (path, post) in [
        // Refused: too short and missing a class, too many repeats, and
        // on the common list (in any case).
        (
            "/v/kv-test/secrets/-/new",
            vec![("name", "pol-a"), ("value", "POLLEAKshort")],
        ),
        (
            "/v/kv-test/secrets/-/new",
            vec![
                ("name", "pol-b"),
                ("value", "POLLEAK-Baaa-1!-xyz-long-enough"),
            ],
        ),
        (
            "/v/kv-test/secrets/-/new",
            vec![("name", "pol-c"), ("value", "TrustNo1")],
        ),
        (
            "/v/kv-test/secrets/-/new",
            vec![
                ("name", "pol-d"),
                ("secret_type", "login"),
                ("username", "POLLEAK-user"),
                ("password", "POLLEAKpw"),
            ],
        ),
        (
            "/v/kv-test/secrets/pol-existing/value",
            vec![("value", "trustno1")],
        ),
    ] {
        let res = wp.post(path, &post).await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{post:?}");
        let html = support::body_text(res).await;
        assert!(!html.contains("POLLEAK") && !html.to_lowercase().contains("trustno1"));
    }
    for (path, post) in [
        (
            "/v/kv-test/secrets/-/new",
            vec![("name", "pol-e"), ("value", "POLLEAK-Accepted-Value-9")],
        ),
        (
            "/v/kv-test/secrets/-/new",
            vec![
                ("name", "pol-f"),
                ("secret_type", "login"),
                ("password", "POLLEAK-Login-Accepted-7"),
            ],
        ),
        (
            "/v/kv-test/secrets/pol-existing/value",
            vec![("value", "POLLEAK-Newer-Value-42")],
        ),
    ] {
        let res = wp.post(path, &post).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{post:?}");
    }
    // Set a new value on a Login (pol-f), refused and accepted.
    let res = wp
        .post(
            "/v/kv-test/secrets/pol-f/value",
            &[("password", "POLLEAKloginpw")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!support::body_text(res).await.contains("POLLEAK"));
    let res = wp
        .post(
            "/v/kv-test/secrets/pol-f/value",
            &[("password", "POLLEAK-Login-Newer-Value-8")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // An import with one row the policy refuses and one it accepts.
    let res = wp
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File(
                "file",
                ".env",
                b"POL_IMP_BAD=POLLEAKimp\nPOL_IMP_OK=POLLEAK-Import-Accepted-5\n",
            )],
        )
        .await;
    let html = support::body_text(res).await;
    assert!(!html.contains("POLLEAK"));
    let id = support::hidden_value(&html, "import_id").unwrap();
    let res = wp
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!support::body_text(res).await.contains("POLLEAK"));
    assert!(wp.kv.state.current("POL-IMP-OK").is_some());
    assert!(wp.kv.state.current("POL-IMP-BAD").is_none());

    // Descriptions (#254): the note is a tag, which could hold sensitive
    // context, so it never reaches a log line or an audit event. Create,
    // edit, a refused edit, and Edit details on a certificate and a key,
    // with a failure from Key Vault on each Edit details path.
    {
        let note = "NOTELEAK one\r\nNOTELEAK two";
        let res = w
            .post(
                "/v/kv-test/secrets/-/new",
                &[("name", "noted"), ("value", "v"), ("description", note)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let (_, html) = w.page("/v/kv-test/secrets/noted/edit").await;
        let version = support::hidden_value(&html, "version").unwrap();
        let updated = support::hidden_value(&html, "updated").unwrap();
        let edit = |d: &'static str| {
            [
                ("version", version.clone()),
                ("updated", updated.clone()),
                ("description", d.to_owned()),
            ]
        };
        for d in ["NOTELEAK \u{202E}refused", "NOTELEAK edited"] {
            let f = edit(d);
            let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let _ = w.post("/v/kv-test/secrets/noted/edit", &f).await;
        }
        assert_eq!(
            w.kv.state.current("noted").unwrap().tags["description"],
            "NOTELEAK edited"
        );
        w.kv.state.add_cert("noted-cert", false, "x");
        w.kv.state.add_key_with("noted-key", "RSA", |_| {});
        for (path, fail) in [
            (
                "/v/kv-test/certificates/noted-cert/details",
                "/certificates/noted-cert/",
            ),
            ("/v/kv-test/keys/noted-key/details", "/keys/noted-key/"),
        ] {
            let (_, html) = w.page(path).await;
            let version = support::hidden_value(&html, "version").unwrap();
            let updated = support::hidden_value(&html, "updated").unwrap();
            let f = [
                ("version", version.as_str()),
                ("updated", updated.as_str()),
                ("description", "NOTELEAK on the details form"),
            ];
            // Key Vault refuses the write first, then takes it.
            w.kv.state.fail_each.lock().unwrap().push((
                axum::http::Method::PATCH,
                fail.into(),
                403,
                "ForbiddenByRbac",
            ));
            let res = w.post(path, &f).await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
            assert!(!support::body_text(res).await.contains("NOTELEAK"));
            w.kv.state.fail_each.lock().unwrap().clear();
            let res = w.post(path, &f).await;
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path}");
            // The flash cookie is sealed, so looking at the cookie proves
            // nothing. Follow the redirect with it and read the message
            // the page shows.
            let flash = res
                .headers()
                .get_all("set-cookie")
                .iter()
                .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
                .find(|c| c.starts_with("keyring_flash="))
                .expect("a saved change sets a flash message");
            let item = support::location(&res).to_owned();
            let _ = support::body_text(res).await;
            let shown = {
                use tower::ServiceExt;
                let req = axum::http::Request::get(&item)
                    .header("cookie", format!("{}; {flash}", w.cookie))
                    .body(axum::body::Body::empty())
                    .unwrap();
                support::body_text(w.app.clone().oneshot(req).await.unwrap()).await
            };
            let message = shown
                .split("data-flash>")
                .nth(1)
                .and_then(|rest| rest.split("</p>").next())
                .expect("the page shows the flash message");
            assert!(message.starts_with("Saved changes to noted-"), "{message}");
            assert!(!message.contains("NOTELEAK"), "{path}: {message}");
        }
        assert_eq!(
            w.kv.state.certs.lock().unwrap()["noted-cert"].versions[0].tags["description"],
            "NOTELEAK on the details form"
        );
    }

    // Owner and notify (#255): addresses are personal data, so they never
    // reach a log line, an audit event, a flash message or a URL. Create,
    // edit, a refused edit, Edit details (with Key Vault refusing first),
    // the bulk change and the import, with KEYRING_REQUIRE_OWNER on so its
    // refusals run too.
    {
        let wo = support::world_with(&[("KEYRING_REQUIRE_OWNER", "true")]).await;
        let res = wo
            .post(
                "/v/kv-test/secrets/-/new",
                &[
                    ("name", "owned"),
                    ("value", "v"),
                    ("owner", "ownerleak@example.com"),
                    ("notify", "notifyleak@example.com, notifyleak2@example.com"),
                ],
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert!(!support::location(&res).contains("leak"));
        // Refused: no owner, then an owner that isn't an address.
        for owner in ["", "OWNERLEAK not an address"] {
            let res = wo
                .post(
                    "/v/kv-test/secrets/-/new",
                    &[("name", "ownerless"), ("value", "v"), ("owner", owner)],
                )
                .await;
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        let (_, html) = wo.page("/v/kv-test/secrets/owned/edit").await;
        let version = support::hidden_value(&html, "version").unwrap();
        let updated = support::hidden_value(&html, "updated").unwrap();
        for (owner, notify) in [
            ("ownerleak@example.com", "bad OWNERLEAK, x"),
            ("ownerleak2@example.com", "notifyleak3@example.com"),
        ] {
            let _ = wo
                .post(
                    "/v/kv-test/secrets/owned/edit",
                    &[
                        ("version", &version),
                        ("updated", &updated),
                        ("owner", owner),
                        ("notify", notify),
                    ],
                )
                .await;
        }
        assert_eq!(
            wo.kv.state.current("owned").unwrap().tags["owner"],
            "ownerleak2@example.com"
        );
        wo.kv.state.add_key_with("owned-key", "RSA", |_| {});
        let path = "/v/kv-test/keys/owned-key/details";
        let (_, html) = wo.page(path).await;
        let version = support::hidden_value(&html, "version").unwrap();
        let updated = support::hidden_value(&html, "updated").unwrap();
        let f = [
            ("version", version.as_str()),
            ("updated", updated.as_str()),
            ("owner", "ownerleak3@example.com"),
            ("notify", "notifyleak4@example.com"),
        ];
        wo.kv.state.fail_each.lock().unwrap().push((
            axum::http::Method::PATCH,
            "/keys/owned-key/".into(),
            403,
            "ForbiddenByRbac",
        ));
        let res = wo.post(path, &f).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(!support::body_text(res).await.contains("leak@"));
        wo.kv.state.fail_each.lock().unwrap().clear();
        let res = wo.post(path, &f).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        // The bulk change: set the owner and notify, and a refused remove.
        for op in [
            vec![("op", "owner_set"), ("owner", "ownerleak4@example.com")],
            vec![("op", "notify_set"), ("notify", "notifyleak5@example.com")],
            vec![("op", "owner_remove")],
            vec![("op", "owner_set"), ("owner", "OWNERLEAK bad")],
        ] {
            let mut f = vec![("item", "owned")];
            f.extend(op);
            let res = wo.post("/v/kv-test/secrets/-/bulk", &f).await;
            let _ = support::body_text(res).await;
            let res = wo.post("/v/kv-test/secrets/-/bulk/apply", &f).await;
            let _ = support::body_text(res).await;
        }
        assert_eq!(
            wo.kv.state.current("owned").unwrap().tags["notify"],
            "notifyleak5@example.com"
        );
        // An import with an owned row, an ownerless row the policy refuses,
        // and a row whose owner isn't an address.
        let res = wo
            .post_multipart(
                "/v/kv-test/secrets/-/import",
                &[support::Part::File(
                    "file",
                    "s.csv",
                    b"name,value,owner,notify\r\nOWN-IMP,v,ownerleak5@example.com,\"notifyleak6@example.com, notifyleak7@example.com\"\r\nOWN-NONE,v,,\r\nOWN-BAD,v,OWNERLEAK x,\r\n",
                )],
            )
            .await;
        let html = support::body_text(res).await;
        let id = support::hidden_value(&html, "import_id").unwrap();
        let res = wo
            .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let _ = support::body_text(res).await;
        assert_eq!(
            wo.kv.state.current("OWN-IMP").unwrap().tags["owner"],
            "ownerleak5@example.com"
        );
        assert!(wo.kv.state.current("OWN-NONE").is_none());
        // The filter and the lists show the address; the filter's link
        // carries only a flag.
        let (_, html) = wo.page("/v/kv-test/secrets?mine=1").await;
        assert!(!html.contains("mine=alex"));
        // The tag filter and the search box find an owner or a notify
        // address typed into them; the expiry and age pages show the owner.
        *wo.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
        for path in [
            "/v/kv-test/secrets?tag=owner%3Downerleak5%40example.com",
            "/v/kv-test/secrets?tag=notify%3Dnotifyleak6%40example.com",
            "/v/kv-test/secrets?q=notifyleak7%40example.com",
            "/search?q=notifyleak6%40example.com",
            "/expiry?show=all&tag=owner%3Downerleak5%40example.com",
            "/expiry/age?tag=notify%3Dnotifyleak7%40example.com",
        ] {
            let (status, html) = wo.page(path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(html.contains(">OWN-IMP<"), "{path}");
        }
    }

    // Tag rows (#253): a tag value refused beside its row, one saved, and
    // the suggestions read back on a form. Tags aren't secret, but a row's
    // text is never logged either.
    {
        let rows = |name: &'static str, value: &'static str| {
            vec![
                ("name", "tagged"),
                ("value", "v"),
                ("tag-rows", "1"),
                ("tag-name-1", name),
                ("tag-value-1", value),
            ]
        };
        let res = w
            .post("/v/kv-test/secrets/-/new", &rows("", "TAGLEAK refused"))
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let res = w
            .post(
                "/v/kv-test/secrets/-/new",
                &rows("TAGLEAK-name", "TAGLEAK value"),
            )
            .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let (_, html) = w.page("/v/kv-test/keys/-/new").await;
        assert!(html.contains("TAGLEAK value"), "suggested");
    }

    // A certificate upload with a password, through to import.
    let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
    let res = w
        .post_multipart(
            "/v/kv-test/certificates/-/upload",
            &[
                support::Part::File("file", "web.pfx", pfx),
                support::Part::Text("name", "web-tls"),
                support::Part::Text("password", "Upl0ad-Passw0rd"),
            ],
        )
        .await;
    let html = support::body_text(res).await;
    *w.kv.state.fail.lock().unwrap() = None;
    let id = support::hidden_value(&html, "upload_id").unwrap();
    let _ = w
        .post(
            "/v/kv-test/certificates/-/upload/confirm",
            &[("upload_id", &id)],
        )
        .await;
    assert_eq!(w.kv.state.imports.lock().unwrap().len(), 1);

    // A secrets import, a write refused part way, and a CSV parse error
    // on a row holding a value.
    let quoted = VALUE.replace('"', "\\\"");
    let env = format!("IMPORT_ONE=\"{quoted}\"\nIMPORT_TWO=Imp0rtLeak-2\n");
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File("file", ".env", env.as_bytes())],
        )
        .await;
    let html = support::body_text(res).await;
    assert!(!html.contains("Sup3r-S3cret") && !html.contains("Imp0rtLeak"));
    let id = support::hidden_value(&html, "import_id").unwrap();
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    *w.kv.state.fail_path.lock().unwrap() = Some("IMPORT-TWO".into());
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    let html = support::body_text(res).await;
    *w.kv.state.fail.lock().unwrap() = None;
    *w.kv.state.fail_path.lock().unwrap() = None;
    assert!(html.contains("Imported 1 secret"), "{html}");
    assert!(!html.contains("Sup3r-S3cret") && !html.contains("Imp0rtLeak"));
    assert_eq!(w.kv.state.current("IMPORT-ONE").unwrap().value, VALUE);
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File(
                "file",
                "a.csv",
                b"name,value\nx,Imp0rtLeak-3,extra\n",
            )],
        )
        .await;
    let html = support::body_text(res).await;
    assert!(html.contains("Line 2 has 3 fields"), "{html}");
    assert!(!html.contains("Imp0rtLeak"));

    // A bulk change: a review, then a run with one item refused and one
    // failing, so every result path is logged.
    let _ = w
        .post(
            "/v/kv-test/secrets/-/bulk",
            &[
                ("item", "IMPORT-ONE"),
                ("op", "tag_set"),
                ("tag_name", "owner"),
            ],
        )
        .await;
    *w.kv.state.fail_each.lock().unwrap() = vec![(
        axum::http::Method::PATCH,
        "/secrets/IMPORT-TWO/".into(),
        500,
        "InternalError",
    )];
    let res = w
        .post(
            "/v/kv-test/secrets/-/bulk/apply",
            &[
                ("item", "IMPORT-ONE"),
                ("item", "IMPORT-TWO"),
                ("item", "no-such-one"),
                ("op", "tag_set"),
                ("tag_name", "rota"),
                ("tag_value", "ops"),
            ],
        )
        .await;
    let html = support::body_text(res).await;
    w.kv.state.fail_each.lock().unwrap().clear();
    assert!(
        html.contains("Changed 0 secrets") || html.contains("Changed 1 secret"),
        "{html}"
    );
    assert!(!html.contains("Sup3r-S3cret") && !html.contains("Imp0rtLeak"));
    assert!(!html.contains("private detail"));

    // A generated value.
    let res = w
        .post(
            "/generator",
            &[("kind", "api_key"), ("bytes", "32"), ("prefix", "GENLEAK_")],
        )
        .await;
    let html = support::body_text(res).await;
    assert!(html.contains("GENLEAK_"));

    // Query strings never reach the log, but the request line does.
    let res = w
        .get("/v/kv-test/secrets?q=QUERYLEAK-hunter2&filter=QUERYLEAK2")
        .await;
    let _ = support::body_text(res).await;
    let res = w.get("/auth/sign-in?return_to=%2FQUERYLEAK3").await;
    let _ = support::body_text(res).await;
    // A search across vaults: the search text is a query string too.
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    let res = w.get("/search?q=QUERYLEAK4-db&status=QUERYLEAK5").await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    let res = w.get("/search?q=db-password").await;
    let html = support::body_text(res).await;
    assert!(html.contains(">db-password<"), "found by search");
    assert!(!html.contains("Sup3r-S3cret"), "search never shows a value");

    // "Used by" on Set a new value, with a workspace that fails: the
    // failure is logged, but never the query or Azure's message.
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::settings_to("logs", true));
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs".into(), 500)];
    let res = w.get("/v/kv-test/secrets/db-password/value").await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = support::body_text(res).await;
    assert!(html.contains("Used by in the last 30 days"));
    assert!(
        !html.contains("Sup3r-S3cret"),
        "the form never shows the value"
    );
    // The access review: callers' sign-in names and the item's owner and
    // notify addresses go on the page and in the CSV, never in a log
    // line; one workspace fails so the failure is logged, without the
    // query or Azure's message.
    w.kv.state.put_with("reviewed", "x", |v| {
        v.tags
            .insert("owner".into(), "reviewownerleak@example.com".into());
        v.tags
            .insert("notify".into(), "reviewnotifyleak@example.com".into());
    });
    *w.arm.state.diagnostics.lock().unwrap() = Some(json!({"value": [
        support::settings_to("logs", true)["value"][0].clone(),
        support::settings_to("logs-b", false)["value"][0].clone(),
    ]}));
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs-b".into(), 500)];
    *w.arm.state.workspace_events.lock().unwrap() = vec![(
        "/workspaces/logs".into(),
        vec![support::RawEvent::new(
            "kv-test",
            "2026-11-10T10:00:00Z",
            "reviewcallerleak@example.com",
            "SecretGet",
            "reviewed",
            200,
        )],
    )];
    // Added behind the session's list cache, which the search above filled.
    let sid = w.cookie.split('=').nth(1).unwrap().to_owned();
    w.state.sessions.get(&sid).unwrap().forget_list("kv-test");
    for path in ["/v/kv-test/access/review", "/v/kv-test/access/review.csv"] {
        let res = w.get(path).await;
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        let body = support::body_text(res).await;
        assert!(body.contains("reviewcallerleak@example.com"), "{path}");
        assert!(body.contains("reviewownerleak@example.com"), "{path}");
        assert!(!body.contains("Sup3r-S3cret"), "{path}");
    }
    *w.arm.state.audit_fail_workspace.lock().unwrap() = Vec::new();
    *w.arm.state.workspace_events.lock().unwrap() = Vec::new();

    // The audit sink: a world that sends events to Log Analytics with the
    // managed identity, through a refusal, a retry and a success. Neither
    // the identity's token, its header nor a row's body reaches the log.
    let ingest = support::ingestion::start().await;
    let identity = support::start_identity().await;
    let sw = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                support::IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", identity.endpoint()),
            ("IDENTITY_HEADER", support::IDENTITY_HEADER.to_owned()),
            (
                "KEYRING_AUDIT_INGESTION_ENDPOINT",
                "https://keyring-audit.australiaeast-1.ingest.monitor.azure.com".to_owned(),
            ),
            (
                "KEYRING_AUDIT_DCR_ID",
                support::ingestion::DCR_ID.to_owned(),
            ),
            ("KEYRING_TEST_AUDIT_INGESTION_URL", ingest.url()),
        ],
        |c| {
            let t = &mut c.audit_sink.as_mut().unwrap().tuning;
            t.backoff_first = std::time::Duration::from_millis(10);
        },
    )
    .await;
    sw.kv.state.put("db-password", VALUE);
    {
        let mut script = ingest.state.script.lock().unwrap();
        script.push_back((403, None));
        script.push_back((500, None));
        script.push_back((400, None));
    }
    for _ in 0..2 {
        let res = sw.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
        let _ = support::body_text(res).await;
    }
    let sink = sw.state.audit_sink.clone().unwrap();
    sink.shutdown().await;
    assert!(ingest.state.violations().is_empty());
    assert!(sink.health().dropped_rejected >= 1, "{:?}", sink.health());

    // PIM: an activation refused with a claims challenge, and one refused
    // with Azure's own message. Neither the challenge, Azure's message nor
    // a token reaches the log. The justification goes only to the audit
    // event's `reason`, never to any other line.
    {
        *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
        let rg = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
        {
            let mut m = w.arm.state.authz.lock().unwrap();
            m.pim.eligible = vec![(rg.into(), support::SECRETS_USER.into(), "/s/sched".into())];
            m.pim.reply = Some((
                400,
                serde_json::json!({"error": {"code": "RoleAssignmentRequestAcrsValidationFailed",
                "message": "PIMLEAK &claims=%7B%22access_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22c7%22%7D%7D%7D"}}),
            ));
        }
        let fields = [
            ("role", support::SECRETS_USER),
            ("scope", rg),
            ("schedule", "/s/sched"),
            ("minutes", "60"),
            ("justification", "JUSTLEAK for the audit only"),
        ];
        let res = w.post("/v/kv-test/my-access/activate", &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let _ = support::body_text(res).await;
        w.arm.state.authz.lock().unwrap().pim.reply = Some((
            403,
            serde_json::json!({"error": {"code": "AuthorizationFailed", "message": "PIMLEAK private detail"}}),
        ));
        let res = w.post("/v/kv-test/my-access/activate", &fields).await;
        let _ = support::body_text(res).await;
        w.arm.state.authz.lock().unwrap().pim = Default::default();
    }

    // Email through a mock ACS, as the managed identity: one delivered, one
    // that ACS says failed (with Azure's message in the result), one after
    // a 429 and a 500 (both with Azure's message in the body), and one with
    // a hostile item name and free text. The same world revealed the value
    // with a reason first.
    let acs = support::acs::start().await;
    let mi = support::start_identity().await;
    let we = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                support::IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", mi.endpoint()),
            ("IDENTITY_HEADER", support::IDENTITY_HEADER.to_owned()),
            (
                "KEYRING_NOTIFY_ACS_ENDPOINT",
                "https://keyring-mail.australia.communication.azure.com".to_owned(),
            ),
            (
                "KEYRING_NOTIFY_SENDER",
                "DoNotReply@mail.example.com".to_owned(),
            ),
            ("KEYRING_NOTIFY_TYPES", "expiry,health".to_owned()),
            // For the webhook's email. No allow-list, so its
            // `keyring-notify` header is ignored.
            ("KEYRING_NOTIFY_ADMINS", "hookadmin@example.com".to_owned()),
            // Only the support events' subscription may send.
            (
                "KEYRING_EVENTGRID_SUBSCRIPTIONS",
                "00000000-0000-0000-0000-000000000000".to_owned(),
            ),
            ("KEYRING_REQUIRE_REASON", "reveal".to_owned()),
            ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
        ],
        |c| {
            let t = &mut c.notify.as_mut().unwrap().tuning;
            t.backoff_first = std::time::Duration::from_millis(10);
            t.poll_wait_default = std::time::Duration::from_millis(10);
            t.poll_wait_max = std::time::Duration::from_millis(20);
            let h = &mut c.notify.as_mut().unwrap().hook_tuning;
            h.unauth_per_minute = 5;
            h.rate_window = std::time::Duration::from_millis(1500);
        },
    )
    .await;
    we.kv.state.put("db-password", VALUE);
    let res = we
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", "MAILREASONLEAK checking")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    {
        use keyring::notify::{Address, ItemKind, ItemRef, Notice, Notification, NotifyType};
        let n = we.state.notifier.clone().expect("email is on");
        let to = |a: &str| vec![Address::parse(a).unwrap()];
        let mail = |kind, addr: &str, heading: &str| Notification {
            kind,
            to: to(addr),
            item: ItemRef::new("kv-test", ItemKind::Secret, "db-password"),
            data: Notice::new(heading)
                .line("It expires in 7 days.\r\nBcc: eve@evil.com <b>bold</b>")
                .actor("alex@example.com"),
        };
        acs.state.statuses.lock().unwrap().push_back("Succeeded");
        acs.state.statuses.lock().unwrap().push_back("Failed");
        assert!(
            n.enqueue(mail(
                NotifyType::Expiry,
                "mailone@example.com",
                "A secret expires soon"
            ))
            .is_queued()
        );
        assert!(
            n.enqueue(mail(
                NotifyType::Expiry,
                "mailtwo@example.com",
                "Another expires"
            ))
            .is_queued()
        );
        let start = std::time::Instant::now();
        while n.health().delivered + n.health().failed < 2 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "first two"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        {
            let mut sc = acs.state.script.lock().unwrap();
            sc.push_back(support::acs::Answer::Status(429, None));
            sc.push_back(support::acs::Answer::Status(500, None));
        }
        assert!(
            n.enqueue(mail(NotifyType::Health, "mailthree@example.com", "Health"))
                .is_queued()
        );
        // Not on: never sent.
        let _ = n.enqueue(mail(NotifyType::RoleUse, "mailfour@example.com", "Role"));
        while n.health().delivered + n.health().failed < 3 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(8),
                "the third"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(n.health().failed, 1, "one failed result");
    }
    let bodies = acs.state.all_bodies();
    assert_eq!(acs.state.attempts().len(), 5);
    assert!(
        acs.state.violations().is_empty(),
        "{:?}",
        acs.state.violations()
    );
    for leak in [
        "Sup3r-S3cret",
        "MAILREASONLEAK",
        support::acs::AZURE_MESSAGE,
        "ACSLEAK",
        support::MI_ACS_TOKEN,
        support::MI_MONITOR_TOKEN,
        support::MI_ASSERTION,
        support::IDENTITY_HEADER,
        "user-api-token",
        "obo:",
        "\\r\\nBcc",
        "\\nBcc",
        "mailfour@",
        we.cookie.as_str(),
        we.csrf.as_str(),
    ] {
        assert!(!bodies.contains(leak), "{leak} reached an email:\n{bodies}");
    }
    for a in acs.state.attempts() {
        let html = a.body["content"]["html"].as_str().unwrap();
        assert!(!html.contains("<b>bold"), "HTML part not escaped: {html}");
        assert!(html.contains("&#60;b&#62;bold"), "{html}");
    }

    // The Event Grid webhook on the same world (expiry is on): a good
    // delivery, a handshake, a bad token, a malformed batch and a token
    // for another app. Canaries in the token, the body, a header and the
    // validation code must reach no log line and no email.
    let webhook_token = {
        use support::eventgrid as eg;
        let mut c = eg::claims_v1(&we.idp);
        c.insert("TOKENCLAIMLEAK".into(), serde_json::json!("TOKENCLAIMLEAK"));
        eg::sign(&we.idp, &c)
    };
    {
        use axum::body::Body;
        use axum::http::Request;
        use support::eventgrid as eg;
        use tower::ServiceExt;
        let hook = |token: &str, body: String, extra: Option<(&str, &str)>| {
            let mut r = Request::post("/hooks/eventgrid")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("user-agent", "HEADERLEAK-agent");
            if let Some((k, v)) = extra {
                r = r.header(k, v);
            }
            r.body(Body::from(body)).unwrap()
        };
        let before = acs.state.attempts().len();
        let mut ev = eg::event(
            "SecretNearExpiry",
            "Secret",
            "db-password",
            eg::now() + 5 * 86_400,
        );
        ev["subject"] = serde_json::json!("BODYLEAK subject https://evil.example/");
        ev["data"]["Id"] = serde_json::json!("https://evil.example/BODYLEAK");
        ev["data"]["Extra"] = serde_json::json!("BODYLEAK extra");
        // A topic that passes the check and still carries a canary (in the
        // resource group), so the delivery that is sent shows nothing
        // from `topic` reaches a line or an email either.
        ev["topic"] = serde_json::json!(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/TOPICLEAK-rg/providers/Microsoft.KeyVault/vaults/kv-test"
        );
        let body = serde_json::json!([ev]).to_string();
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                body.clone(),
                Some(("keyring-notify", "HDRLEAK@example.com")),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                eg::validation("VALCODELEAK-1").to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = we
            .app
            .clone()
            .oneshot(hook("BADTOKENLEAK.x.y", body.clone(), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let mut other = eg::claims_v1(&we.idp);
        other.insert(
            "appid".into(),
            serde_json::json!("22222222-2222-2222-2222-222222222222"),
        );
        let res = we
            .app
            .clone()
            .oneshot(hook(&eg::sign(&we.idp, &other), body.clone(), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let mut bad = ev.clone();
        bad["data"]["ObjectName"] = serde_json::json!("BODYLEAK\nFORGEDLINE");
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                serde_json::json!([bad]).to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // An event from a custom topic: refused, and nothing from `topic`
        // reaches a line or an email.
        let mut custom = ev.clone();
        custom["topic"] = serde_json::json!(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/TOPICLEAK/providers/Microsoft.EventGrid/topics/TOPICLEAK"
        );
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                serde_json::json!([custom]).to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let mut not_topic = ev.clone();
        not_topic["topic"] = serde_json::json!("TOPICLEAK\nFORGEDLINE");
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                serde_json::json!([not_topic]).to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // A Key Vault in a subscription that isn't listed: refused, and
        // its subscription ID, resource group and vault reach no line and
        // no email.
        let mut unlisted = ev.clone();
        unlisted["data"]["VaultName"] = serde_json::json!("kv-subleak");
        unlisted["topic"] = serde_json::json!(
            "/subscriptions/5ab1eaed-0bad-4bad-8bad-5ec0ffee5ab1/resourceGroups/SUBRGLEAK/providers/Microsoft.KeyVault/vaults/kv-subleak"
        );
        let res = we
            .app
            .clone()
            .oneshot(hook(
                &webhook_token,
                serde_json::json!([unlisted]).to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // A flood of bad tokens: two above already counted, three more
        // under the unauthenticated counter of 5, then 95 answered 429
        // with no audit event and no line of their own.
        let mut flood = Vec::new();
        for _ in 0..98 {
            let res = we
                .app
                .clone()
                .oneshot(hook("FLOODLEAK.x.y", body.clone(), None))
                .await
                .unwrap();
            flood.push(res.status());
        }
        assert!(flood[..3].iter().all(|s| *s == StatusCode::UNAUTHORIZED));
        assert!(
            flood[3..]
                .iter()
                .all(|s| *s == StatusCode::TOO_MANY_REQUESTS)
        );
        // The next window: one warn line with how many were dropped.
        tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
        let res = we
            .app
            .clone()
            .oneshot(hook("FLOODLEAK.x.y", body.clone(), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let start = std::time::Instant::now();
        while acs.state.attempts().len() < before + 1 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "the webhook's email"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mail: String = acs.state.attempts()[before..]
            .iter()
            .map(|a| a.raw.clone())
            .collect();
        assert!(mail.contains("db-password in kv-test expires on"), "{mail}");
        assert!(mail.contains("hookadmin@example.com"), "to the admins");
        for leak in [
            "Sup3r-S3cret",
            "BODYLEAK",
            "evil.example",
            "HDRLEAK",
            "HEADERLEAK",
            "VALCODELEAK",
            "TOKENCLAIMLEAK",
            "BADTOKENLEAK",
            "TOPICLEAK",
            "FLOODLEAK",
            "5ab1eaed",
            "SUBRGLEAK",
            "subleak",
            webhook_token.as_str(),
            eg::EVENT_GRID_APP,
        ] {
            assert!(!mail.contains(leak), "{leak} reached an email:\n{mail}");
        }
    }

    // Health: a burst of refused deletes, each with a reason (on its audit
    // event) and a canary typed into the form. The burst email names the
    // person, the count and the reason code, never the reason text or
    // anything typed.
    let hacs = support::acs::start().await;
    let hmi = support::start_identity().await;
    let wh = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                support::IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", hmi.endpoint()),
            ("IDENTITY_HEADER", support::IDENTITY_HEADER.to_owned()),
            (
                "KEYRING_NOTIFY_ACS_ENDPOINT",
                "https://keyring-mail.australia.communication.azure.com".to_owned(),
            ),
            (
                "KEYRING_NOTIFY_SENDER",
                "DoNotReply@mail.example.com".to_owned(),
            ),
            ("KEYRING_NOTIFY_TYPES", "health".to_owned()),
            ("KEYRING_NOTIFY_ADMINS", "ops@example.com".to_owned()),
            ("KEYRING_NOTIFY_BURST_THRESHOLD", "2".to_owned()),
            ("KEYRING_REQUIRE_REASON", "all".to_owned()),
            ("KEYRING_TEST_NOTIFY_ACS_URL", hacs.url()),
        ],
        |c| {
            let t = &mut c.notify.as_mut().unwrap().tuning;
            t.poll_wait_default = std::time::Duration::from_millis(10);
            t.poll_wait_max = std::time::Duration::from_millis(20);
        },
    )
    .await;
    wh.kv.state.put("db-password", VALUE);
    for _ in 0..4 {
        let res = wh
            .post(
                "/v/kv-test/secrets/db-password/delete",
                &[
                    ("reason", "BURSTREASONLEAK clearing out"),
                    ("confirm_name", "BURSTBODYLEAK https://evil.example/x"),
                ],
            )
            .await;
        let _ = support::body_text(res).await;
    }
    {
        let n = wh.state.notifier.clone().expect("email is on");
        let start = std::time::Instant::now();
        while n.health().delivered < 1 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "the burst email"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    let hbodies = hacs.state.all_bodies();
    assert_eq!(hacs.state.attempts().len(), 1, "one burst email");
    assert!(hbodies.contains("Many refused requests"), "{hbodies}");
    assert!(hbodies.contains("typed_name_mismatch"), "{hbodies}");
    assert!(hbodies.contains("alex@example.com"), "{hbodies}");
    for leak in [
        "BURSTREASONLEAK",
        "BURSTBODYLEAK",
        "evil.example",
        "Sup3r-S3cret",
        support::MI_ACS_TOKEN,
        support::IDENTITY_HEADER,
        "user-api-token",
        "obo:",
        wh.cookie.as_str(),
        wh.csrf.as_str(),
    ] {
        assert!(
            !hbodies.contains(leak),
            "{leak} reached a health email:\n{hbodies}"
        );
    }

    // Activity emails (#259): every trigger, with canaries in the reason,
    // the ticket, the PIM justification, the description and a tag value.
    // None may reach an email body, and no address may reach a log line.
    let acs2 = support::acs::start().await;
    let mi2 = support::start_identity().await;
    let wa = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                support::IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", mi2.endpoint()),
            ("IDENTITY_HEADER", support::IDENTITY_HEADER.to_owned()),
            (
                "KEYRING_NOTIFY_ACS_ENDPOINT",
                "https://keyring-mail.australia.communication.azure.com".to_owned(),
            ),
            (
                "KEYRING_NOTIFY_SENDER",
                "DoNotReply@mail.example.com".to_owned(),
            ),
            (
                "KEYRING_NOTIFY_TYPES",
                "watched-reads,destructive,role-use".to_owned(),
            ),
            ("KEYRING_NOTIFY_ADMINS", "actadmin@example.com".to_owned()),
            ("KEYRING_NOTIFY_OWNER_ON_READ", "true".to_owned()),
            ("KEYRING_REQUIRE_REASON", "all".to_owned()),
            ("KEYRING_REASON_TICKET_PATTERN", "[A-Z]+-[0-9]+".to_owned()),
            ("KEYRING_ALLOW_PURGE", "true".to_owned()),
            ("KEYRING_TEST_NOTIFY_ACS_URL", acs2.url()),
        ],
        |c| {
            let t = &mut c.notify.as_mut().unwrap().tuning;
            t.backoff_first = std::time::Duration::from_millis(10);
            t.poll_wait_default = std::time::Duration::from_millis(10);
            t.poll_wait_max = std::time::Duration::from_millis(20);
        },
    )
    .await;
    {
        let mut row = support::vault_row("kv-test", "sub-a", true);
        row["tags"]["keyring-owners"] = serde_json::json!("actowner@example.com");
        *wa.arm.state.vaults.lock().unwrap() = vec![row];
        let mut m = wa.arm.state.authz.lock().unwrap();
        let rg = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
        let sched = "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/b1477448-2cc6-4ceb-93b4-54a202a89413";
        m.pim.eligible = vec![(rg.into(), support::SECRETS_USER.into(), sched.into())];
        m.pim.policies.insert(
            support::SECRETS_USER.into(),
            support::pim_rules("PT8H", true, true, false),
        );
    }
    let tagged = |name: &str| {
        let first = wa.kv.state.put_with(name, VALUE, |v| {
            v.tags
                .insert("notify".into(), "actwatch@example.com".into());
            v.tags
                .insert("owner".into(), "actitemowner@example.com".into());
            v.tags.insert("description".into(), "DESCLEAK note".into());
            v.tags.insert("env".into(), "TAGVALUELEAK".into());
        });
        let _ = wa.kv.state.put_with(name, VALUE, |v| {
            v.tags
                .insert("notify".into(), "actwatch@example.com".into());
            v.tags.insert("description".into(), "DESCLEAK note".into());
            v.tags.insert("env".into(), "TAGVALUELEAK".into());
        });
        first
    };
    let why = [
        ("reason", "REASONACTLEAK checking https://evil.example/"),
        ("ticket", "INC-4242"),
    ];
    let first = tagged("act-one");
    for (path, extra) in [
        ("/v/kv-test/secrets/act-one/reveal", vec![]),
        (
            "/v/kv-test/secrets/act-one/rollback",
            vec![("version", first.as_str())],
        ),
        (
            "/v/kv-test/secrets/act-one/delete",
            vec![("confirm_name", "act-one")],
        ),
    ] {
        let mut f = why.to_vec();
        f.extend(extra);
        let res = wa.post(path, &f).await;
        assert!(
            res.status().is_success() || res.status().is_redirection(),
            "{path}"
        );
        let _ = support::body_text(res).await;
    }
    tagged("act-two");
    let mut f = why.to_vec();
    f.extend([
        ("item", "act-two"),
        ("op", "tag_set"),
        ("tag_name", "rota"),
        ("tag_value", "BULKTAGLEAK"),
    ]);
    let res = wa.post("/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    let res = wa
        .post(
            "/v/kv-test/my-access/activate",
            &[
                ("role", support::SECRETS_USER),
                ("scope", "/subscriptions/sub-a/resourceGroups/rg-kv-test"),
                (
                    "schedule",
                    "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/b1477448-2cc6-4ceb-93b4-54a202a89413",
                ),
                ("back", "/v/kv-test/secrets"),
                ("minutes", "60"),
                ("justification", "JUSTIFYACTLEAK https://evil.example/"),
                ("ticket_system", "TKTSYSLEAK"),
                ("ticket_number", "TKTNUMLEAK"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    let start = std::time::Instant::now();
    while acs2.state.attempts().len() < 5 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "activity emails: {}",
            acs2.state.attempts().len()
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let abodies = acs2.state.all_bodies();
    assert!(abodies.contains("Ticket: INC-4242"), "{abodies}");
    for leak in [
        "Sup3r-S3cret",
        "REASONACTLEAK",
        "JUSTIFYACTLEAK",
        "TKTSYSLEAK",
        "TKTNUMLEAK",
        "DESCLEAK",
        "TAGVALUELEAK",
        "BULKTAGLEAK",
        "evil.example",
        "user-api-token",
        support::MI_ACS_TOKEN,
    ] {
        assert!(
            !abodies.contains(leak),
            "{leak} reached an activity email:\n{abodies}"
        );
    }
    drop(mi2);

    // Access requests (#258): canaries in the reason, the ticket and the
    // form body. A linkable reason and ticket never reach the email; a
    // plain one does. Neither reaches a log line except the request's own
    // audit event. Nothing else typed reaches either.
    let aacs = support::acs::start().await;
    let ami = support::start_identity().await;
    let wa = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                support::IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", ami.endpoint()),
            ("IDENTITY_HEADER", support::IDENTITY_HEADER.to_owned()),
            (
                "KEYRING_NOTIFY_ACS_ENDPOINT",
                "https://keyring-mail.australia.communication.azure.com".to_owned(),
            ),
            (
                "KEYRING_NOTIFY_SENDER",
                "DoNotReply@mail.example.com".to_owned(),
            ),
            ("KEYRING_NOTIFY_TYPES", "access-requests".to_owned()),
            ("KEYRING_NOTIFY_ADMINS", "ops@example.com".to_owned()),
            ("KEYRING_TEST_NOTIFY_ACS_URL", aacs.url()),
        ],
        |c| {
            let t = &mut c.notify.as_mut().unwrap().tuning;
            t.poll_wait_default = std::time::Duration::from_millis(10);
            t.poll_wait_max = std::time::Duration::from_millis(20);
        },
    )
    .await;
    {
        let mut row = support::vault_row("kv-test", "00000000-0000-0000-0000-00000000000a", true);
        row["tags"] = serde_json::json!({"keyring-owners": "reqowner@example.com"});
        *wa.arm.state.vaults.lock().unwrap() = vec![row];
    }
    wa.kv.state.put("db-password", VALUE);
    for (role, reason, ticket) in [
        (
            support::SECRETS_USER,
            "REQLINKLEAK see https://evil.example/login now",
            "REQTICKLEAK.evil.example",
        ),
        (
            support::CERT_OFFICER,
            "REQPLAINREASON needed for the release",
            "REQPLAINTICKET-7",
        ),
    ] {
        let res = wa
            .post(
                "/v/kv-test/my-access/request",
                &[
                    ("role", role),
                    ("scope", "item"),
                    ("kind", "secret"),
                    ("name", "db-password"),
                    ("back", "/v/kv-test/secrets/db-password"),
                    ("reason", reason),
                    ("ticket", ticket),
                    ("extra", "REQBODYLEAK attacker@evil.example"),
                    ("to", "REQTOLEAK@evil.example"),
                ],
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let _ = support::body_text(res).await;
    }
    // A repeat within the hour: refused, nothing more sent.
    let res = wa
        .post(
            "/v/kv-test/my-access/request",
            &[
                ("role", support::SECRETS_USER),
                ("scope", "vault"),
                ("reason", "REQREPEAT asking again"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let _ = support::body_text(res).await;
    {
        let start = std::time::Instant::now();
        while aacs.state.attempts().len() < 2 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "two access request emails"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    let abodies = aacs.state.all_bodies();
    assert!(
        abodies.contains("REQPLAINREASON needed for the release"),
        "{abodies}"
    );
    assert!(abodies.contains("REQPLAINTICKET-7"), "{abodies}");
    assert!(abodies.contains("reqowner@example.com"));
    for leak in [
        "REQLINKLEAK",
        "REQTICKLEAK",
        "evil.example",
        "REQBODYLEAK",
        "REQTOLEAK",
        "Sup3r-S3cret",
        support::MI_ACS_TOKEN,
        support::IDENTITY_HEADER,
        "user-api-token",
        wa.cookie.as_str(),
        wa.csrf.as_str(),
    ] {
        assert!(
            !abodies.contains(leak),
            "{leak} reached an access request email:\n{abodies}"
        );
    }

    // A crafted sign-in error can't add a line to the log.
    let res = w
        .get("/auth/callback?error=x%0AFORGEDLINE%20secret%20purged&state=x")
        .await;
    let _ = support::body_text(res).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("action=secret.reveal outcome=success"),
        "the reveal itself is logged: {logs}"
    );
    assert!(
        logs.contains("action=secret.import outcome=success")
            && logs.contains("item_name=IMPORT-ONE"),
        "the import is logged per secret: {logs}"
    );
    assert!(!logs.contains("Imp0rtLeak"), "import value leaked:\n{logs}");
    assert!(!logs.contains("NOTELEAK"), "a description leaked:\n{logs}");
    for leak in [
        "ownerleak",
        "notifyleak",
        "OWNERLEAK",
        "actwatch@",
        "actitemowner@",
        "actowner@",
        "actadmin@",
    ] {
        assert!(!logs.contains(leak), "an address leaked ({leak}):\n{logs}");
    }
    assert!(
        logs.contains("reason_code=owner_required"),
        "the owner policy's refusals are recorded: {logs}"
    );
    assert!(!logs.contains("TAGLEAK"), "a tag row leaked:\n{logs}");
    for (action, item) in [
        ("secret.create", "noted"),
        ("secret.update", "noted"),
        ("certificate.update", "noted-cert"),
        ("key.update", "noted-key"),
    ] {
        assert!(
            logs.lines().any(|l| l.contains("kind=audit")
                && l.contains(&format!("action={action} outcome=success"))
                && l.contains(&format!("item_name={item}"))),
            "{action} on {item} is an audit event:\n{logs}"
        );
    }
    assert!(
        logs.lines()
            .any(|l| l.contains("action=certificate.update outcome=denied")),
        "a refused Edit details is an audit event:\n{logs}"
    );
    // Password policy: no value, list entry or length; the refusals carry
    // the fixed code only.
    assert!(
        !logs.to_lowercase().contains("polleak"),
        "a policy value leaked:\n{logs}"
    );
    assert!(
        !logs.to_lowercase().contains("trustno1"),
        "a common-list entry leaked:\n{logs}"
    );
    let refused: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("reason_code=password_policy"))
        .collect();
    assert_eq!(refused.len(), 7, "one per refused save:\n{logs}");
    for l in &refused {
        assert!(
            l.contains("kind=audit") && l.contains("outcome=refused"),
            "{l}"
        );
        assert!(
            l.contains("action=secret.create")
                || l.contains("action=secret.set")
                || (l.contains("action=secret.import") && l.contains("item_name=POL-IMP-BAD")),
            "{l}"
        );
        for word in ["length", "common", "upper", "repeat", "characters"] {
            assert!(!l.contains(word), "{word} in {l}");
        }
    }
    assert!(
        !logs.contains("TYPLEAK"),
        "a typed secret's field leaked:\n{logs}"
    );
    assert!(
        logs.contains("action=secret.create outcome=success")
            && logs.contains("item_name=typed-login"),
        "typed creates are logged: {logs}"
    );
    assert!(
        !logs.contains("Sup3r-S3cret"),
        "value leaked into logs:\n{logs}"
    );
    assert!(!logs.contains("QUERYLEAK"), "query string leaked:\n{logs}");
    for leak in ["reviewcallerleak", "reviewownerleak", "reviewnotifyleak"] {
        assert!(!logs.contains(leak), "an address leaked ({leak}):\n{logs}");
    }
    assert!(
        logs.contains("access review workspace query failed"),
        "the failed review read is logged: {logs}"
    );
    for kql in ["let vaultName", "summarize Uses", "row_number"] {
        assert!(!logs.contains(kql), "review KQL leaked into logs:\n{logs}");
    }

    assert!(
        logs.contains("used-by workspace query failed"),
        "the failed panel read is logged: {logs}"
    );
    for kql in ["let vaultName", "summarize Reads", "itemName"] {
        assert!(!logs.contains(kql), "KQL leaked into logs:\n{logs}");
    }
    assert!(
        logs.lines().any(|l| l.contains("request")
            && l.contains("method=GET")
            && l.contains("path=/v/kv-test/secrets ")
            && l.contains("status=200")
            && l.contains("ms=")),
        "request line missing:\n{logs}"
    );
    assert!(
        logs.contains("path=/v/kv-test/secrets/db-password/reveal") && logs.contains("method=POST"),
        "{logs}"
    );
    assert!(
        logs.contains("path=/search "),
        "the search is logged without its text"
    );
    // Actions name the person by Entra object and tenant ID.
    assert!(
        logs.contains("actor_oid=aaaaaaaa-0000-0000-0000-000000000001 actor_tid="),
        "{logs}"
    );
    // Headers are never logged: no cookies, no session ID.
    assert!(!logs.contains(&w.cookie), "session cookie leaked");
    assert!(!logs.contains(&w.csrf), "form token leaked");
    assert!(!logs.contains("user-api-token"), "token leaked into logs");
    assert!(!logs.contains("obo:"), "token leaked into logs");
    assert!(
        !logs.contains("PIMLEAK"),
        "Azure's PIM message leaked:\n{logs}"
    );
    assert!(
        !logs.contains("%22acrs%22"),
        "claims challenge leaked:\n{logs}"
    );
    // The justification is on the audit events only.
    for line in logs.lines().filter(|l| l.contains("JUSTLEAK")) {
        assert!(
            line.contains("kind=audit") && line.contains("action=role.activate"),
            "{line}"
        );
    }
    assert!(
        !logs.contains(support::MI_MONITOR_TOKEN),
        "identity token leaked"
    );
    assert!(
        !logs.contains(support::IDENTITY_HEADER),
        "identity header leaked"
    );
    assert!(
        !logs.contains("WriterIdentityClientId"),
        "a sink row was logged"
    );
    assert!(
        logs.contains("audit sink: ingestion refused a batch; dropped status=400")
            || logs.contains("status=400"),
        "the sink logs the status: {logs}"
    );
    assert!(
        !logs.contains("private detail"),
        "Azure message leaked into logs"
    );

    // Health: the burst is logged without the reason text, the typed
    // name, the person or the address. The reason is only on the delete's
    // own audit events.
    assert!(
        logs.contains("health: a burst of refused or denied requests"),
        "{logs}"
    );
    assert!(
        !logs.contains("BURSTBODYLEAK"),
        "typed text leaked:\n{logs}"
    );
    assert!(
        logs.contains("reason=\"BURSTREASONLEAK"),
        "the reason was on the refused events: {logs}"
    );
    for line in logs.lines().filter(|l| l.contains("BURSTREASONLEAK")) {
        assert!(
            line.contains("kind=audit") && line.contains("action=secret.delete"),
            "{line}"
        );
    }
    for line in logs.lines().filter(|l| l.contains("health:")) {
        assert!(!line.contains("alex@example.com"), "{line}");
        assert!(!line.contains("ops@example.com"), "{line}");
    }

    // Access requests: the reason and ticket only on the request's own
    // audit event; nothing else typed and no address anywhere.
    for leak in ["REQBODYLEAK", "REQTOLEAK", "reqowner@", "attacker@"] {
        assert!(!logs.contains(leak), "{leak} leaked into logs:\n{logs}");
    }
    // One event per request: two sent, one refused for the hour.
    let req_events: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("kind=audit") && l.contains("action=access.request"))
        .collect();
    assert_eq!(req_events.len(), 3, "{req_events:#?}");
    assert_eq!(
        req_events
            .iter()
            .filter(|l| l.contains("outcome=success")
                && l.contains("role_scope=/subscriptions/00000000-0000-0000-0000-00000000000a/")
                && l.contains("item_kind=secret")
                && l.contains("item_name=db-password"))
            .count(),
        2,
        "{req_events:#?}"
    );
    assert!(
        req_events
            .iter()
            .any(|l| l.contains("outcome=refused") && l.contains("reason_code=rate_limited")),
        "{req_events:#?}"
    );
    for canary in [
        "REQLINKLEAK",
        "REQTICKLEAK",
        "REQPLAINREASON",
        "REQPLAINTICKET",
        "REQREPEAT",
    ] {
        assert!(logs.contains(canary), "{canary} is on its audit event");
        for line in logs.lines().filter(|l| l.contains(canary)) {
            assert!(
                line.contains("kind=audit") && line.contains("action=access.request"),
                "{line}"
            );
        }
    }

    // Email: no address, Azure message, ACS token or body in any line,
    // and the reason only on the reveal's audit event.
    for leak in [
        "ACSLEAK",
        support::MI_ACS_TOKEN,
        "mailone@",
        "mailtwo@",
        "mailthree@",
        "mailfour@",
        "It expires in 7 days",
        "plainText",
    ] {
        assert!(!logs.contains(leak), "{leak} leaked into logs:\n{logs}");
    }
    for line in logs.lines().filter(|l| l.contains("MAILREASONLEAK")) {
        assert!(
            line.contains("kind=audit") && line.contains("action=secret.reveal"),
            "{line}"
        );
    }
    assert!(
        logs.contains("action=notify.sent") && logs.contains("action=notify.failed"),
        "email is audited: {logs}"
    );
    assert!(
        logs.contains("notify_type=expiry") && logs.contains("notify_recipient_count=1"),
        "{logs}"
    );

    // The webhook: no token, claim, body, header or validation code in
    // any line, in either format; one audit event per delivery, with a
    // fixed reason code.
    let json_text = String::from_utf8(json.0.lock().unwrap().clone()).unwrap();
    for leak in [
        "BODYLEAK",
        "HDRLEAK",
        "HEADERLEAK",
        "VALCODELEAK",
        "TOKENCLAIMLEAK",
        "BADTOKENLEAK",
        "TOPICLEAK",
        "FLOODLEAK",
        "5ab1eaed",
        "SUBRGLEAK",
        "subleak",
        "FORGEDLINE",
        "FORGEDLINE subject",
        "hookadmin@",
        support::eventgrid::EVENT_GRID_APP,
        "22222222-2222-2222-2222-222222222222",
        webhook_token.as_str(),
        &webhook_token[..40],
    ] {
        assert!(!logs.contains(leak), "{leak} leaked into logs:\n{logs}");
        assert!(!json_text.contains(leak), "{leak} leaked into JSON logs");
    }
    let hook_events: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("action=notify.webhook"))
        .collect();
    // Good, handshake, bad token, other app, bad event, two bad topics,
    // an unlisted subscription, three of the flood under the counter and
    // one in the next window: the 95 over the counter wrote nothing.
    assert_eq!(hook_events.len(), 12, "bounded: {hook_events:#?}");
    assert_eq!(
        hook_events
            .iter()
            .filter(|l| l.contains("reason_code=token_malformed"))
            .count(),
        5,
        "{hook_events:#?}"
    );
    let dropped: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("eventgrid: requests with a refused token over the limit"))
        .collect();
    assert_eq!(dropped.len(), 1, "{dropped:#?}");
    assert!(dropped[0].contains("dropped=95"), "{}", dropped[0]);
    assert_eq!(
        logs.lines()
            .filter(|l| l.contains("eventgrid: delivery"))
            .count(),
        12,
        "one line per audited request, none for the dropped"
    );
    for code in [
        "token_caller",
        "token_malformed",
        "bad_event",
        "bad_topic",
        "subscription_not_allowed",
    ] {
        assert!(
            hook_events
                .iter()
                .any(|l| l.contains(&format!("reason_code={code}"))),
            "{code}: {hook_events:#?}"
        );
    }
    assert!(
        hook_events
            .iter()
            .any(|l| l.contains("reason_code=queued") && l.contains("notify_event_count=1")),
        "{hook_events:#?}"
    );
    for l in &hook_events {
        assert!(l.contains("notify_type=expiry"), "{l}");
        assert!(!l.contains("actor_"), "no person: {l}");
        assert!(!l.contains("notify_recipients="), "no address: {l}");
    }

    // The same rules for the JSON lines, which must each parse.
    let json = String::from_utf8(json.0.lock().unwrap().clone()).unwrap();
    for leak in [
        "Sup3r-S3cret",
        "QUERYLEAK",
        "Upl0ad-Passw0rd",
        "GENLEAK_",
        "Imp0rtLeak",
        "NOTELEAK",
        "ownerleak",
        "notifyleak",
        "OWNERLEAK",
        "POLLEAK",
        "user-api-token",
        "obo:",
        support::MI_MONITOR_TOKEN,
        support::IDENTITY_HEADER,
        "WriterIdentityClientId",
        "private detail",
        "PIMLEAK",
        "%22acrs%22",
        "ACSLEAK",
        support::MI_ACS_TOKEN,
        "mailone@",
        "mailthree@",
        w.cookie.as_str(),
        w.csrf.as_str(),
    ] {
        assert!(!json.contains(leak), "{leak} leaked into JSON logs");
    }
    // In any case: `TrustNo1` was submitted as typed.
    for leak in ["polleak", "trustno1"] {
        assert!(
            !json.to_lowercase().contains(leak),
            "{leak} leaked into JSON logs"
        );
    }
    let lines: Vec<serde_json::Value> = json
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l["kind"] == "audit" && l["action"] == "secret.reveal"),
        "the reveal is an audit event"
    );
    assert!(
        lines.iter().any(|l| l["kind"] == "audit"
            && l["action"] == "secret.import"
            && l["item_name"] == "POL-IMP-BAD"
            && l["outcome"] == "refused"
            && l["reason_code"] == "password_policy"),
        "a refused import row is an audit event"
    );
    assert!(
        lines.iter().any(|l| l["kind"] == "audit"
            && l["action"] == "secret.copy.write"
            && l["vault"] == "kv-prod"
            && l["outcome"] == "denied"),
        "a refused copy write is an audit event on the target"
    );
    // The read of that same copy went through: its own event, on the
    // source, says so.
    let copy_events: Vec<(String, String, String, String)> = lines
        .iter()
        .filter(|l| {
            l["kind"] == "audit"
                && l["action"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("secret.copy.")
        })
        .map(|l| {
            let s = |k: &str| l[k].as_str().unwrap_or_default().to_owned();
            (s("action"), s("vault"), s("item_name"), s("outcome"))
        })
        .collect();
    let expect = |a: &str, v: &str, n: &str, o: &str| {
        (a.to_owned(), v.to_owned(), n.to_owned(), o.to_owned())
    };
    assert_eq!(
        copy_events,
        vec![
            expect("secret.copy.write", "kv-prod", "db-copy", "denied"),
            expect("secret.copy.read", "kv-test", "db-password", "success"),
            expect("secret.copy.write", "kv-prod", "db-copy", "success"),
            expect("secret.copy.read", "kv-test", "db-password", "success"),
            expect("secret.copy.write", "kv-stage", "db-staged", "success"),
            expect("secret.copy.read", "kv-test", "db-password", "success"),
        ],
        "one read and one write event per copy, each on its own vault"
    );
    let denied_write = lines
        .iter()
        .find(|l| l["action"] == "secret.copy.write" && l["outcome"] == "denied")
        .unwrap();
    assert_eq!(denied_write["reason_code"], "ForbiddenByRbac");
    assert!(denied_write["kv_request_id"].is_string());
    for action in ["secret.copy.read", "secret.copy.write"] {
        assert!(
            lines
                .iter()
                .any(|l| l["action"] == action && l["reason"] == "Promote to staging"),
            "{action} carries the reason"
        );
    }
    assert!(
        lines
            .iter()
            .filter(|l| l["action"] == "secret.copy.read")
            .all(|l| l["item_version"].is_string()),
        "the read names the version read"
    );
    assert!(
        lines.iter().any(|l| l["kind"] == "audit"
            && l["action"] == "secret.import"
            && l["item_name"] == "IMPORT-TWO"
            && l["outcome"] == "failed"),
        "a failed import write is an audit event"
    );
    assert!(
        lines.iter().any(|l| l["kind"] == "log"
            && l["message"] == "request"
            && l["path"] == "/v/kv-test/secrets"),
        "request lines are JSON too"
    );
    // A crafted sign-in error is one escaped string, not a new line.
    assert!(!json.lines().any(|l| l.starts_with("FORGEDLINE")));
}

/// Every action goes through `audit::record`: no handler writes its own
/// free-text action line naming a person any more.
#[test]
fn no_handler_writes_its_own_action_line() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for level in ["info", "warn", "error", "debug", "trace"] {
            let bad = format!("tracing::{level}!( subject =");
            let bad2 = format!("tracing::{level}!(subject =");
            assert!(
                !flat.contains(&bad) && !flat.contains(&bad2),
                "{} writes an action line itself. Use crate::audit instead",
                f.display()
            );
        }
    }
}
