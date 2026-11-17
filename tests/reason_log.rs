//! The reason and ticket on the audit event, escaped in both log formats,
//! and the `reason_required` refusal.
//!
//! One test in its own binary, like `no_secrets_in_logs`: `tracing` caches
//! whether a line is wanted, and tests running alongside without a
//! subscriber can switch lines off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;

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

impl Capture {
    fn take(&self) -> String {
        String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
    }
}

/// A reason built to break a log: a new line that looks like an audit
/// event, quotes that try to close the field, an ANSI colour, a bell, a
/// bidi override and a Unicode line separator.
const HOSTILE: &str = "Fixing \"prod\"\nFORGED kind=audit action=secret.purge outcome=success\r\n\u{1b}[31mred\u{1b}[0m\u{7}\u{202E}x\u{2028}end \\ done";
const SECRET: &str = "Reason-Test-Secret-Value";

#[tokio::test]
async fn reasons_are_logged_escaped_in_both_formats() {
    let text = Capture::default();
    let json = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(text.clone())
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .event_format(keyring::telemetry::JsonLines)
                .with_writer(json.clone()),
        );
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = support::world_with(&[
        ("KEYRING_REQUIRE_REASON", "reveal"),
        ("KEYRING_REASON_TICKET_PATTERN", "CHG[0-9]{4}"),
    ])
    .await;
    w.kv.state.put("db-password", SECRET);
    text.take();
    json.take();

    // --- A reveal with a hostile reason ----------------------------------
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", HOSTILE), ("ticket", "CHG1234")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let want = "Fixing \"prod\" FORGED kind=audit action=secret.purge outcome=success [31mred [0m x end \\ done";

    let j = json.take();
    let events: Vec<Value> = j
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .filter(|v| v["kind"] == "audit")
        .collect();
    assert_eq!(events.len(), 1, "{j}");
    let ev = &events[0];
    assert_eq!(ev["action"], "secret.reveal");
    assert_eq!(ev["outcome"], "success");
    assert_eq!(ev["reason"], want);
    assert_eq!(ev["ticket"], "CHG1234");
    assert!(!j.contains('\u{1b}') && !j.contains('\u{7}') && !j.contains('\u{202E}'));
    assert!(!j.lines().any(|l| l.starts_with("FORGED")), "{j}");
    assert!(!j.contains(SECRET));

    let t = text.take();
    let lines: Vec<&str> = t.lines().filter(|l| l.contains("kind=audit")).collect();
    assert_eq!(
        lines.len(),
        1,
        "one audit line, the forged one isn't a line: {t}"
    );
    let line = lines[0];
    assert!(line.contains("action=secret.reveal"), "{line}");
    // Quoted and escaped, last on the line, so nothing typed can come
    // before a real field.
    assert!(
        line.ends_with(
            "ticket=\"CHG1234\" reason=\"Fixing \\\"prod\\\" FORGED kind=audit action=secret.purge outcome=success [31mred [0m x end \\\\ done\""
        ),
        "{line}"
    );
    assert!(!t.contains('\u{1b}') && !t.contains('\u{7}') && !t.contains('\u{202E}'));
    assert!(!t.lines().any(|l| l.starts_with("FORGED")), "{t}");
    assert!(!t.contains(SECRET));

    // --- Refused: no reason ----------------------------------------------
    let kv = w.kv.state.log.lock().unwrap().len();
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(w.kv.state.log.lock().unwrap().len(), kv);
    let j = json.take();
    let ev: Value = j
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|v| v["kind"] == "audit")
        .expect("an event");
    assert_eq!(ev["action"], "secret.reveal");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "reason_required");
    assert_eq!(ev["vault"], "kv-test");
    assert_eq!(ev["item_name"], "db-password");
    assert!(ev.get("reason").is_none() && ev.get("ticket").is_none());
    let t = text.take();
    assert!(t.contains("reason_code=reason_required"), "{t}");

    // --- Refused: a bad ticket, whose text is never logged ----------------
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("reason", "Fine reason"), ("ticket", "BAD\nFORGED")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let j = json.take();
    assert!(j.contains("\"reason_code\":\"reason_required\""), "{j}");
    assert!(!j.contains("BAD") && !j.contains("Fine reason"), "{j}");
    let t = text.take();
    assert!(!t.contains("BAD") && !t.contains("Fine reason"), "{t}");
}
