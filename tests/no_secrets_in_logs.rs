//! Secret values and tokens never reach the logs.
//!
//! Kept in its own test binary with a single log capture test: `tracing` caches whether
//! a log line is wanted, and other tests running alongside without a
//! subscriber can switch lines off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;

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
                ("tag_name", "owner"),
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

    // The same rules for the JSON lines, which must each parse.
    let json = String::from_utf8(json.0.lock().unwrap().clone()).unwrap();
    for leak in [
        "Sup3r-S3cret",
        "QUERYLEAK",
        "Upl0ad-Passw0rd",
        "GENLEAK_",
        "Imp0rtLeak",
        "user-api-token",
        "obo:",
        support::MI_MONITOR_TOKEN,
        support::IDENTITY_HEADER,
        "WriterIdentityClientId",
        "private detail",
        "PIMLEAK",
        "%22acrs%22",
        w.cookie.as_str(),
        w.csrf.as_str(),
    ] {
        assert!(!json.contains(leak), "{leak} leaked into JSON logs");
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
