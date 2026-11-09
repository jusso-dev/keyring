//! Secret values and tokens never reach the logs.
//!
//! Kept in its own test binary with a single test: `tracing` caches whether
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
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = support::world().await;
    w.kv.state.put("db-password", VALUE);
    let res = w.post("/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    // An error path too.
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let _ = w.post("/secrets/db-password/reveal", &[]).await;

    // A certificate upload with a password, through to import.
    let pfx: &[u8] = include_bytes!("fixtures/test-plain.pfx");
    let res = w
        .post_multipart(
            "/certificates/upload",
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
        .post("/certificates/upload/confirm", &[("upload_id", &id)])
        .await;
    assert_eq!(w.kv.state.imports.lock().unwrap().len(), 1);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("secret value revealed"),
        "the reveal itself is logged: {logs}"
    );
    assert!(
        !logs.contains("Sup3r-S3cret"),
        "value leaked into logs:\n{logs}"
    );
    assert!(!logs.contains("user-api-token"), "token leaked into logs");
    assert!(!logs.contains("obo:"), "token leaked into logs");
    assert!(
        !logs.contains("private detail"),
        "Azure message leaked into logs"
    );
}
