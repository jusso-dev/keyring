//! The audit sink (`src/audit/sink.rs`): Keyring's own audit events, also
//! sent to Log Analytics through the Logs Ingestion API with Keyring's
//! managed identity, each row naming the person who acted.
//!
//! Not Key Vault's audit log (`tests/audit.rs`), and not the events
//! themselves (`tests/audit_events.rs`).
//!
//! Every test checks the mock ingestion endpoint saw no request with any
//! token but the mock managed identity's.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use keyring::audit::sink::{AuditSink, Tuning};
use keyring::audit::{Action, AuditEvent, Outcome};
use keyring::auth::assertion::ManagedIdentityTokens;
use keyring::secret::Secret;
use serde_json::Value;
use support::ingestion::{self, DCR_ID, MockIngestion, STREAM};
use support::{IDENTITY_CLIENT_ID, IDENTITY_HEADER, MockIdentity};
use tower::ServiceExt;

/// Quick timings, so tests don't wait out the real ones.
fn quick() -> Tuning {
    Tuning {
        queue_capacity: 1000,
        batch_max: 500,
        flush_every: Duration::from_millis(100),
        max_body_bytes: 1_000_000,
        degraded_after: Duration::from_millis(300),
        shutdown_grace: Duration::from_secs(2),
        backoff_first: Duration::from_millis(20),
        backoff_max: Duration::from_millis(100),
    }
}

struct Rig {
    sink: Arc<AuditSink>,
    ingest: MockIngestion,
    identity: MockIdentity,
}

impl Drop for Rig {
    fn drop(&mut self) {
        // Every request carried the identity's token and nothing else.
        let v = self.ingest.state.violations();
        if !std::thread::panicking() {
            assert!(v.is_empty(), "ingestion rule broken: {v:?}");
        }
    }
}

/// A sink on its own, against the mocks.
async fn rig(tuning: Tuning) -> Rig {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let tokens = Arc::new(ManagedIdentityTokens::new(
        identity.endpoint(),
        Secret::new(IDENTITY_HEADER),
        IDENTITY_CLIENT_ID.into(),
        keyring::http::local_client().unwrap(),
    ));
    let url = format!(
        "{}/dataCollectionRules/{DCR_ID}/streams/{STREAM}?api-version=2023-01-01",
        ingest.url()
    );
    let sink = AuditSink::start(url, tuning, tokens, keyring::http::client(false).unwrap());
    Rig {
        sink,
        ingest,
        identity,
    }
}

fn event(n: usize) -> AuditEvent {
    let mut ev = AuditEvent::new(Action::SecretReveal, Outcome::Success);
    ev.item_name = Some(format!("item-{n}"));
    ev
}

fn item_names(r: &Rig) -> Vec<String> {
    r.ingest
        .state
        .rows()
        .iter()
        .map(|row| row["ItemName"].as_str().unwrap().to_owned())
        .collect()
}

/// Wait until `f` is true, or fail after a few seconds.
async fn until(what: &str, f: impl Fn() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_full_batch_goes_at_once_and_the_rest_on_the_timer() {
    let r = rig(Tuning {
        batch_max: 3,
        flush_every: Duration::from_millis(400),
        ..quick()
    })
    .await;
    let started = Instant::now();
    for n in 0..4 {
        r.sink.enqueue(&event(n));
    }
    until("the full batch", || {
        r.ingest.state.accepted.lock().unwrap().len() == 1
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "a full batch waited for the timer"
    );
    assert_eq!(r.ingest.state.accepted.lock().unwrap()[0].rows.len(), 3);
    until("the timer", || {
        r.ingest.state.accepted.lock().unwrap().len() == 2
    })
    .await;
    assert!(started.elapsed() >= Duration::from_millis(350));
    let calls = r.ingest.state.accepted.lock().unwrap().clone();
    assert_eq!(calls[1].rows.len(), 1);
    assert!(calls.iter().all(|c| c.gzipped), "bodies are gzipped");
    assert_eq!(
        item_names(&r),
        ["item-0", "item-1", "item-2", "item-3"],
        "in order"
    );
    // The mock records a batch before the sink counts it as sent.
    until("the count", || r.sink.health().sent == 4).await;
    // One identity token, for the monitor resource, reused.
    assert_eq!(
        *r.identity.state.resources.lock().unwrap(),
        ["https://monitor.azure.com"]
    );
}

#[tokio::test]
async fn batches_stay_under_one_megabyte() {
    let r = rig(Tuning {
        flush_every: Duration::from_millis(50),
        ..quick()
    })
    .await;
    // 400 events of about 4 KB each: about 1.6 MB, under the 500 a batch.
    for n in 0..400 {
        let mut ev = event(n);
        ev.user_agent = Some("a".repeat(4000));
        r.sink.enqueue(&ev);
    }
    until("all 400", || r.ingest.state.rows().len() == 400).await;
    let calls = r.ingest.state.accepted.lock().unwrap().clone();
    assert!(calls.len() >= 2, "split into {} calls", calls.len());
    for c in &calls {
        assert!(c.raw_len <= 1_000_000, "{}", c.raw_len);
    }
}

#[tokio::test]
async fn a_429_waits_for_retry_after() {
    let r = rig(quick()).await;
    r.ingest
        .state
        .script
        .lock()
        .unwrap()
        .push_back((429, Some(1)));
    let started = Instant::now();
    r.sink.enqueue(&event(0));
    until("the retry", || r.ingest.state.rows().len() == 1).await;
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "retried before Retry-After: {:?}",
        started.elapsed()
    );
    assert_eq!(*r.ingest.state.attempts.lock().unwrap(), 2);
    // The mock records a batch before the sink counts it as sent.
    until("the count", || r.sink.health().sent == 1).await;
    let h = r.sink.health();
    assert_eq!((h.sent, h.failed_attempts, h.dropped_rejected), (1, 1, 0));
}

#[tokio::test]
async fn a_5xx_is_retried_with_backoff() {
    let r = rig(quick()).await;
    {
        let mut s = r.ingest.state.script.lock().unwrap();
        s.push_back((500, None));
        s.push_back((503, None));
    }
    r.sink.enqueue(&event(0));
    until("the retry", || r.ingest.state.rows().len() == 1).await;
    assert_eq!(*r.ingest.state.attempts.lock().unwrap(), 3);
    until("the count", || r.sink.health().sent == 1).await;
    let h = r.sink.health();
    assert_eq!((h.sent, h.failed_attempts), (1, 2));
    assert!(!h.degraded, "recovered");
}

#[tokio::test]
async fn a_400_drops_the_batch_and_counts_it() {
    let r = rig(quick()).await;
    r.ingest.state.script.lock().unwrap().push_back((400, None));
    r.sink.enqueue(&event(0));
    r.sink.enqueue(&event(1));
    until("the drop", || r.sink.health().dropped_rejected == 2).await;
    // Not retried; the next event goes through.
    r.sink.enqueue(&event(2));
    until("the next", || r.ingest.state.rows().len() == 1).await;
    assert_eq!(*r.ingest.state.attempts.lock().unwrap(), 2);
    assert_eq!(r.ingest.state.rows()[0]["ItemName"], "item-2");
    // One refused batch doesn't leave the sink degraded: the accepted one
    // after it cleared the clock.
    until("the count", || r.sink.health().sent == 1).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(!r.sink.degraded());
}

#[tokio::test]
async fn batches_refused_one_after_another_mean_degraded() {
    let r = rig(quick()).await;
    *r.ingest.state.always.lock().unwrap() = Some(400);
    r.sink.enqueue(&event(0));
    until("the drop", || r.sink.health().dropped_rejected == 1).await;
    // Nothing has been accepted since, so once the limit passes the sink is
    // degraded even though it isn't retrying anything.
    until("degraded", || r.sink.degraded()).await;
    *r.ingest.state.always.lock().unwrap() = None;
    r.sink.enqueue(&event(1));
    until("recovered", || !r.sink.degraded()).await;
    assert_eq!(r.sink.health().dropped_rejected, 1);
}

#[tokio::test]
async fn a_full_queue_drops_the_oldest() {
    let r = rig(Tuning {
        queue_capacity: 3,
        flush_every: Duration::from_millis(300),
        ..quick()
    })
    .await;
    for n in 0..5 {
        r.sink.enqueue(&event(n));
    }
    assert_eq!(r.sink.health().dropped_queue_full, 2);
    assert_eq!(r.sink.health().queued, 3);
    until("the flush", || r.ingest.state.rows().len() == 3).await;
    assert_eq!(item_names(&r), ["item-2", "item-3", "item-4"]);
}

#[tokio::test]
async fn shutdown_sends_what_is_queued() {
    let r = rig(Tuning {
        flush_every: Duration::from_secs(3600),
        ..quick()
    })
    .await;
    for n in 0..3 {
        r.sink.enqueue(&event(n));
    }
    assert!(r.ingest.state.rows().is_empty());
    r.sink.shutdown().await;
    assert_eq!(r.ingest.state.rows().len(), 3);
    assert_eq!(r.sink.health().dropped_at_shutdown, 0);
}

#[tokio::test]
async fn shutdown_gives_up_after_its_grace() {
    let r = rig(Tuning {
        flush_every: Duration::from_secs(3600),
        shutdown_grace: Duration::from_millis(300),
        ..quick()
    })
    .await;
    *r.ingest.state.always.lock().unwrap() = Some(503);
    r.sink.enqueue(&event(0));
    let started = Instant::now();
    r.sink.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(r.sink.health().dropped_at_shutdown, 1);
}

#[tokio::test]
async fn a_refused_identity_degrades_the_sink_until_it_recovers() {
    let r = rig(quick()).await;
    // The role was taken away: the endpoint refuses the identity.
    *r.ingest.state.always.lock().unwrap() = Some(403);
    r.sink.enqueue(&event(0));
    until("degraded", || r.sink.degraded()).await;
    // A fresh token is asked for after each refusal.
    assert!(r.identity.state.resources.lock().unwrap().len() >= 2);
    *r.ingest.state.always.lock().unwrap() = None;
    until("recovered", || !r.sink.degraded()).await;
    assert_eq!(r.ingest.state.rows().len(), 1);
}

#[tokio::test]
async fn the_ingestion_client_refuses_plain_http_and_redirects() {
    // The main client, as Keyring builds it outside tests.
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let tokens = Arc::new(ManagedIdentityTokens::new(
        identity.endpoint(),
        Secret::new(IDENTITY_HEADER),
        IDENTITY_CLIENT_ID.into(),
        keyring::http::local_client().unwrap(),
    ));
    let url = format!(
        "{}/dataCollectionRules/{DCR_ID}/streams/{STREAM}?api-version=2023-01-01",
        ingest.url()
    );
    let sink = AuditSink::start(
        url,
        quick(),
        tokens.clone(),
        keyring::http::client(true).unwrap(),
    );
    sink.enqueue(&event(0));
    until("degraded", || sink.degraded()).await;
    assert_eq!(*ingest.state.attempts.lock().unwrap(), 0, "plain HTTP sent");

    // A redirect is not followed: the batch is dropped, never re-sent
    // somewhere else with the token.
    let followed = Arc::new(std::sync::Mutex::new(0usize));
    let f = followed.clone();
    let app = axum::Router::new()
        .route(
            "/elsewhere",
            axum::routing::post(move || {
                *f.lock().unwrap() += 1;
                async { StatusCode::NO_CONTENT }
            }),
        )
        .fallback(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/elsewhere")]) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let sink = AuditSink::start(
        format!("http://{addr}/dataCollectionRules/{DCR_ID}/streams/{STREAM}"),
        quick(),
        tokens,
        keyring::http::client(false).unwrap(),
    );
    sink.enqueue(&event(0));
    until("the drop", || sink.health().dropped_rejected == 1).await;
    assert_eq!(*followed.lock().unwrap(), 0, "a redirect was followed");
}

// ---------------------------------------------------------------------
// Through the app
// ---------------------------------------------------------------------

/// A signed-in world with the sink on, writing as the mock identity.
async fn sink_world(
    ingest: &MockIngestion,
    identity: &MockIdentity,
    required: bool,
) -> support::World {
    let mut extra = sink_settings(ingest, identity);
    if required {
        extra.push(("KEYRING_AUDIT_REQUIRED", "true".to_owned()));
    }
    sink_world_with(extra).await
}

fn sink_settings(ingest: &MockIngestion, identity: &MockIdentity) -> Vec<(&'static str, String)> {
    vec![
        (
            "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
            IDENTITY_CLIENT_ID.to_owned(),
        ),
        ("IDENTITY_ENDPOINT", identity.endpoint()),
        ("IDENTITY_HEADER", IDENTITY_HEADER.to_owned()),
        (
            "KEYRING_AUDIT_INGESTION_ENDPOINT",
            "https://keyring-audit.australiaeast-1.ingest.monitor.azure.com".to_owned(),
        ),
        ("KEYRING_AUDIT_DCR_ID", DCR_ID.to_owned()),
        ("KEYRING_TEST_AUDIT_INGESTION_URL", ingest.url()),
    ]
}

async fn sink_world_with(extra: Vec<(&'static str, String)>) -> support::World {
    support::world_configured(extra, |c| {
        c.audit_sink.as_mut().unwrap().tuning = quick();
    })
    .await
}

async fn get(app: &axum::Router, path: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut req = Request::get(path);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Sign in through the mock IdP as `oid`/`upn` and return the session
/// cookie and its form token.
async fn sign_in_as(w: &support::World, oid: &'static str, upn: &'static str) -> (String, String) {
    *w.idp.state.user.lock().unwrap() = Some((oid, upn));
    let res = get(&w.app, "/auth/start?return_to=%2F", None).await;
    let url = url::Url::parse(&support::location(&res)).unwrap();
    let login = cookie_from(&res, "keyring_login=");
    let q = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap()
    };
    *w.idp.state.nonce.lock().unwrap() = Some(q("nonce"));
    let res = get(
        &w.app,
        &format!("/auth/callback?code=abc&state={}", q("state")),
        Some(&login),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cookie = cookie_from(&res, "keyring_session=");
    let id = cookie.split('=').nth(1).unwrap();
    let session = w.state.sessions.get(id).unwrap();
    session.select_vault("kv-test".into());
    (cookie, session.csrf_token())
}

fn cookie_from(res: &axum::response::Response, prefix: &str) -> String {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with(prefix))
        .unwrap()
}

async fn reveal(w: &support::World, cookie: &str, csrf: &str) -> StatusCode {
    let body = format!(
        "csrf={}",
        url::form_urlencoded::byte_serialize(csrf.as_bytes()).collect::<String>()
    );
    let req = Request::post("/v/kv-test/secrets/db-password/reveal")
        .header("origin", "http://localhost:3000")
        .header("cookie", cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let res = w.app.clone().oneshot(req).await.unwrap();
    res.status()
}

const OID_A: &str = "aaaaaaaa-0000-0000-0000-00000000000a";
const OID_B: &str = "bbbbbbbb-0000-0000-0000-00000000000b";

#[tokio::test]
async fn every_row_names_the_person_and_the_writer() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let w = sink_world(&ingest, &identity, false).await;
    w.kv.state.put("db-password", "v");

    let (a, a_csrf) = sign_in_as(&w, OID_A, "ana@example.com").await;
    let (b, b_csrf) = sign_in_as(&w, OID_B, "ben@example.com").await;
    assert_eq!(reveal(&w, &a, &a_csrf).await, StatusCode::OK);
    assert_eq!(reveal(&w, &b, &b_csrf).await, StatusCode::OK);
    // A failed sign-in: nobody to name.
    let res = get(&w.app, "/auth/callback?code=abc&state=forged", None).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let sink = w.state.audit_sink.clone().unwrap();
    sink.shutdown().await;
    let rows = ingest.state.rows();
    let by = |action: &str, oid: &str| -> Vec<Value> {
        rows.iter()
            .filter(|r| r["Action"] == action && r["ActorObjectId"] == oid)
            .cloned()
            .collect()
    };
    for (oid, upn) in [(OID_A, "ana@example.com"), (OID_B, "ben@example.com")] {
        let signed_in = by("session.sign_in", oid);
        assert_eq!(signed_in.len(), 1, "{oid}: {rows:#?}");
        let revealed = by("secret.reveal", oid);
        assert_eq!(revealed.len(), 1, "{oid}: {rows:#?}");
        let r = &revealed[0];
        assert_eq!(r["ActorUpn"], upn);
        assert_eq!(r["ActorTenantId"], support::TENANT);
        assert_eq!(r["Outcome"], "success");
        assert_eq!(r["Vault"], "kv-test");
        assert_eq!(r["ItemName"], "db-password");
        assert!(r["time"].is_string());
    }
    let failed: Vec<&Value> = rows
        .iter()
        .filter(|r| r["Action"] == "session.sign_in_failed")
        .collect();
    assert_eq!(failed.len(), 1);
    for col in ["ActorObjectId", "ActorTenantId", "ActorUpn"] {
        assert!(failed[0].get(col).is_none(), "{col} on a failed sign-in");
    }
    // The writer is always Keyring's identity, never the person.
    for r in &rows {
        assert_eq!(r["WriterIdentityClientId"], IDENTITY_CLIENT_ID);
        assert_eq!(r["KeyringVersion"], env!("CARGO_PKG_VERSION"));
        assert!(r["KeyringInstance"].is_string());
    }
    assert!(
        ingest.state.violations().is_empty(),
        "{:?}",
        ingest.state.violations()
    );
    // The only identity tokens asked for: the monitor resource. The
    // federated credential wasn't asked for, since a client secret is set
    // alongside the identity in this world.
    assert!(
        identity
            .state
            .resources
            .lock()
            .unwrap()
            .iter()
            .all(|r| r == "https://monitor.azure.com")
    );
}

#[tokio::test]
async fn audit_required_refuses_a_reveal_while_degraded() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let w = sink_world(&ingest, &identity, true).await;
    w.kv.state.put("db-password", "Sup3r-value");
    let sink = w.state.audit_sink.clone().unwrap();

    // Healthy: the reveal goes ahead.
    assert_eq!(
        w.post("/v/kv-test/secrets/db-password/reveal", &[])
            .await
            .status(),
        StatusCode::OK
    );
    let (status, body) = health(&w).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("status=ok\n"), "{body}");

    // Ingestion fails for longer than the limit.
    *ingest.state.always.lock().unwrap() = Some(503);
    // An event queued after the failure starts, in case the reveal's own
    // event had already gone out.
    sink.enqueue(&event(99));
    until("degraded", || sink.degraded()).await;
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let page = support::body_text(res).await;
    assert!(page.contains("Auditing is unavailable"));
    assert!(!page.contains("Sup3r-value"));
    let (status, body) = health(&w).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.starts_with("status=degraded\n"), "{body}");
    assert!(body.contains("failed_attempts="), "{body}");

    // A private key download too, before Key Vault is asked anything.
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    // A copy to another vault reads a value too: refused, nothing read.
    let calls = w.kv.state.log.lock().unwrap().len();
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/copy",
            &[("to_vault", "kv-test"), ("to_name", "db-copy")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!support::body_text(res).await.contains("Sup3r-value"));
    assert_eq!(
        w.kv.state.log.lock().unwrap().len(),
        calls,
        "no Key Vault call"
    );
    assert!(w.kv.state.current("db-copy").is_none());

    // Recovered: allowed again.
    *ingest.state.always.lock().unwrap() = None;
    until("recovered", || !sink.degraded()).await;
    assert_eq!(
        w.post("/v/kv-test/secrets/db-password/reveal", &[])
            .await
            .status(),
        StatusCode::OK
    );

    sink.shutdown().await;
    let refused: Vec<Value> = ingest
        .state
        .rows()
        .into_iter()
        .filter(|r| r["ReasonCode"] == "audit_unavailable")
        .collect();
    assert_eq!(refused.len(), 3, "every refusal recorded once it recovered");
    assert!(refused.iter().any(|r| r["Action"] == "secret.copy.read"));
    assert_eq!(refused[0]["Outcome"], "refused");
    assert!(ingest.state.violations().is_empty());
}

#[tokio::test]
async fn degraded_without_audit_required_still_reveals() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let w = sink_world(&ingest, &identity, false).await;
    w.kv.state.put("db-password", "v");
    let sink = w.state.audit_sink.clone().unwrap();
    *ingest.state.always.lock().unwrap() = Some(503);
    w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    until("degraded", || sink.degraded()).await;
    assert_eq!(
        w.post("/v/kv-test/secrets/db-password/reveal", &[])
            .await
            .status(),
        StatusCode::OK
    );
}

async fn health(w: &support::World) -> (StatusCode, String) {
    let res = get(&w.app, "/healthz/audit", None).await;
    let status = res.status();
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    (status, support::body_text(res).await)
}

#[tokio::test]
async fn healthz_audit_is_off_without_the_sink() {
    let w = support::world().await;
    let res = get(&w.app, "/healthz/audit", None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(support::body_text(res).await, "status=off\n");
    assert!(w.state.audit_sink.is_none());
}

#[tokio::test]
async fn an_import_sends_one_row_for_each_secret_it_writes() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let w = sink_world(&ingest, &identity, false).await;
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File("file", ".env", b"ONE=v1\nTWO=v2\n")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = support::body_text(res).await;
    let id = support::hidden_value(&html, "import_id").expect("import id on the preview");
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);

    let sink = w.state.audit_sink.clone().unwrap();
    sink.shutdown().await;
    let rows = ingest.state.rows();
    let mut names: Vec<String> = rows
        .iter()
        .filter(|r| r["Action"] == "secret.import" && r["ItemName"].is_string())
        .map(|r| r["ItemName"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["ONE", "TWO"], "{rows:#?}");
    assert!(
        !format!("{rows:?}").contains("v1"),
        "a value in the audit rows"
    );
}

#[tokio::test]
async fn an_import_with_a_reason_puts_it_on_each_secrets_row() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let mut extra = sink_settings(&ingest, &identity);
    extra.push(("KEYRING_REQUIRE_REASON", "all".to_owned()));
    let w = sink_world_with(extra).await;
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File("file", ".env", b"ONE=v1\nTWO=v2\n")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = support::body_text(res).await;
    // The preview's own form asks for the reason.
    assert!(html.contains("name=\"reason\""), "{html}");
    let id = support::hidden_value(&html, "import_id").expect("import id on the preview");

    // Without one, nothing is written.
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let writes = |w: &support::World| {
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PUT"))
            .count()
    };
    assert_eq!(writes(&w), 0);

    let res = w
        .post(
            "/v/kv-test/secrets/-/import/confirm",
            &[("import_id", &id), ("reason", "Moving the app's settings")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(writes(&w), 2);

    let sink = w.state.audit_sink.clone().unwrap();
    sink.shutdown().await;
    let rows = ingest.state.rows();
    // Audit rows hold names and the typed reason, never a value.
    let item_rows: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            r["Action"] == "secret.import" && r["ItemName"].is_string() && r["Outcome"] == "success"
        })
        .collect();
    assert_eq!(item_rows.len(), 2);
    for r in item_rows {
        assert_eq!(r["Reason"], "Moving the app's settings");
    }
}

#[tokio::test]
async fn an_import_row_the_password_policy_refuses_has_its_own_refused_row() {
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let mut extra = sink_settings(&ingest, &identity);
    extra.push(("KEYRING_PASSWORD_POLICY", "min=14,common".to_owned()));
    let w = sink_world_with(extra).await;
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File(
                "file",
                ".env",
                b"WEAK=PolLeakShort\nGOOD=PolLeak-Long-Enough-Value\n",
            )],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = support::body_text(res).await;
    let id = support::hidden_value(&html, "import_id").expect("import id on the preview");
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    assert_eq!(res.status(), StatusCode::OK);

    let sink = w.state.audit_sink.clone().unwrap();
    sink.shutdown().await;
    let rows = ingest.state.rows();
    let item = |name: &str| {
        rows.iter()
            .find(|r| r["Action"] == "secret.import" && r["ItemName"] == name)
            .unwrap_or_else(|| panic!("no row for {name}: {rows:#?}"))
    };
    let weak = item("WEAK");
    assert_eq!(weak["Outcome"], "refused");
    assert_eq!(weak["ReasonCode"], "password_policy");
    assert!(weak["KvRequestId"].is_null(), "never sent to Key Vault");
    let good = item("GOOD");
    assert_eq!(good["Outcome"], "success");
    let all = format!("{rows:?}");
    assert!(!all.contains("PolLeak"), "a value in the audit rows");
    // Only the fixed code: no rule, length or anything about the value.
    let keys: Vec<&str> = weak
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for k in ["Reason", "Ticket", "ItemVersion"] {
        assert!(!keys.contains(&k), "{k} on {weak}");
    }
    for word in ["characters", "common", "length"] {
        assert!(!weak.to_string().contains(word), "{word} in {weak}");
    }
    assert!(w.kv.state.current("WEAK").is_none());
}
