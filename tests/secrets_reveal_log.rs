//! The reveal and rollback log lines say which version was read.
//!
//! Its own test binary, like `no_secrets_in_logs`: `tracing` caches whether
//! a line is wanted, and tests running alongside without a subscriber can
//! switch lines off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;

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

#[tokio::test]
async fn reveal_and_rollback_log_the_version() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = support::world().await;
    let old = w.kv.state.put("db-password", "Old-Value-Here");
    let cur = w.kv.state.put("db-password", "New-Value-Here");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/reveal",
            &[("version", &old)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/rollback",
            &[("version", &old)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let new = w.kv.state.current("db-password").unwrap().version;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let reveals: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("secret value revealed"))
        .collect();
    assert_eq!(reveals.len(), 2, "{logs}");
    assert!(reveals[0].contains(&format!("version={old}")), "{logs}");
    assert!(reveals[1].contains(&format!("version={cur}")), "{logs}");
    let rollback = logs
        .lines()
        .find(|l| l.contains("secret rolled back"))
        .unwrap();
    assert!(rollback.contains(&format!("from_version={old}")));
    assert!(rollback.contains(&format!("version={new}")));
    assert!(!logs.contains("-Value-Here"), "values never logged");
}
