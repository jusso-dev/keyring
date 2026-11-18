//! The audit event for a reveal limit change, in its own test binary:
//! `tracing` caches whether a line is wanted, and other tests running
//! alongside without a subscriber can switch lines off for this one.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use support::{World, body_text};

const SECRET: &str = "/v/kv-test/secrets/db-password";

async fn post(w: &World, path: &str, f: &[(&str, String)]) -> StatusCode {
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let res = w.post(path, &f).await;
    let s = res.status();
    let _ = body_text(res).await;
    s
}

#[tokio::test]
async fn a_limit_change_is_audited_from_and_to() {
    use std::io::Write;
    use tracing_subscriber::layer::SubscriberExt;
    #[derive(Clone, Default)]
    struct Cap(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Cap {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Cap {
        type Writer = Cap;
        fn make_writer(&'a self) -> Cap {
            self.clone()
        }
    }
    let cap = Cap::default();
    let sub = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .event_format(keyring::telemetry::JsonLines)
            .with_writer(cap.clone()),
    );
    let _g = tracing::subscriber::set_default(sub);
    let w = support::world().await;
    w.kv.state.put_with("db-password", "v", |v| {
        v.tags = BTreeMap::from([("keyring-reveal".to_owned(), "maybe".to_owned())]);
    });
    let cur = w.kv.state.current("db-password").unwrap();
    let f = vec![
        ("version", cur.version.clone()),
        ("updated", cur.updated.to_string()),
        ("enabled", "on".to_owned()),
        ("tag-rows", "1".to_owned()),
        ("reveal", "copy-only".to_owned()),
    ];
    let s = post(&w, &format!("{SECRET}/edit"), &f).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    // The event is written as the response finishes: one more request
    // makes sure it is out.
    let _ = w.page(SECRET).await;
    let out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    let events: Vec<serde_json::Value> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["kind"] == "audit")
        .collect();
    assert_eq!(events.len(), 1, "{out}");
    assert_eq!(events[0]["action"], "secret.update");
    assert_eq!(
        events[0]["reveal_limit_from"], "other",
        "never the odd value"
    );
    assert_eq!(events[0]["reveal_limit_to"], "copy-only");
    assert!(!out.contains("maybe"));
}
