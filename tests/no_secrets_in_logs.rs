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
        !logs.contains("Sup3r-S3cret"),
        "value leaked into logs:\n{logs}"
    );
    assert!(!logs.contains("QUERYLEAK"), "query string leaked:\n{logs}");
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
        "private detail",
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
