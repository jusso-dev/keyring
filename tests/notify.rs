//! Email notifications (`src/notify/`): sent through a mock Azure
//! Communication Services endpoint as the mock managed identity.
//!
//! Every test checks the mock ACS saw no request with any token but the
//! managed identity's, and no request that broke the API's rules.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use keyring::audit::sink::{AuditSink, Tuning as SinkTuning};
use keyring::auth::assertion::ManagedIdentityTokens;
use keyring::notify::sender::{Notifier, Settings, Tuning};
use keyring::notify::{Address, Enqueued, ItemKind, ItemRef, Notice, Notification, NotifyType};
use keyring::secret::Secret;
use serde_json::Value;
use support::acs::{self, AZURE_MESSAGE, Answer, MockAcs};
use support::ingestion::{self, DCR_ID, MockIngestion, STREAM};
use support::{IDENTITY_CLIENT_ID, IDENTITY_HEADER, MockIdentity};
use tower::ServiceExt;

fn quick() -> Tuning {
    Tuning {
        queue_capacity: 100,
        give_up_after: Duration::from_secs(2),
        backoff_first: Duration::from_millis(20),
        backoff_max: Duration::from_millis(100),
        poll_wait_max: Duration::from_millis(100),
        poll_wait_default: Duration::from_millis(20),
        retry_after_max: Duration::from_secs(2),
        degraded_after: Duration::from_millis(200),
        shutdown_grace: Duration::from_secs(2),
        rate_window: Duration::from_secs(3600),
    }
}

struct Rig {
    n: Arc<Notifier>,
    acs: MockAcs,
    identity: MockIdentity,
    ingest: MockIngestion,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let v = self.acs.state.violations();
            assert!(v.is_empty(), "ACS rule broken: {v:?}");
            let v = self.ingest.state.violations();
            assert!(v.is_empty(), "ingestion rule broken: {v:?}");
        }
    }
}

fn settings(acs: &MockAcs, tuning: Tuning) -> Settings {
    Settings {
        send_url: acs.send_url(),
        sender: Address::parse("DoNotReply@mail.example.com").unwrap(),
        admins: vec![Address::parse("ops@example.com").unwrap()],
        allowed_domains: None,
        types: NotifyType::ALL.to_vec(),
        audit_recipients: false,
        per_hour: 20,
        base_url: "https://keyring.example.com".into(),
        tuning,
    }
}

async fn rig_with(f: impl FnOnce(&mut Settings)) -> Rig {
    let acs = acs::start().await;
    let ingest = ingestion::start().await;
    let identity = support::start_identity().await;
    let tokens = Arc::new(ManagedIdentityTokens::new(
        identity.endpoint(),
        Secret::new(IDENTITY_HEADER),
        IDENTITY_CLIENT_ID.into(),
        keyring::http::local_client().unwrap(),
    ));
    let sink = AuditSink::start(
        format!(
            "{}/dataCollectionRules/{DCR_ID}/streams/{STREAM}?api-version=2023-01-01",
            ingest.url()
        ),
        SinkTuning {
            flush_every: Duration::from_millis(50),
            ..SinkTuning::default()
        },
        tokens.clone(),
        keyring::http::client(false).unwrap(),
    );
    let mut s = settings(&acs, quick());
    f(&mut s);
    let n = Notifier::start(s, tokens, keyring::http::client(false).unwrap(), Some(sink));
    Rig {
        n,
        acs,
        identity,
        ingest,
    }
}

async fn rig() -> Rig {
    rig_with(|_| {}).await
}

fn addr(s: &str) -> Address {
    Address::parse(s).unwrap()
}

fn notice(to: &[&str]) -> Notification<Notice> {
    Notification {
        kind: NotifyType::Expiry,
        to: to.iter().map(|a| addr(a)).collect(),
        item: ItemRef::new("kv-test", ItemKind::Secret, "db-password"),
        data: Notice::new("A secret expires soon")
            .line("It expires in 7 days.")
            .actor("alex@example.com")
            .when("17 Nov 2026, 09:30 UTC"),
    }
}

async fn until(what: &str, f: impl Fn() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Audit rows for notify events, from the mock ingestion endpoint.
async fn notify_rows(r: &Rig, n: usize) -> Vec<Value> {
    let rows = || {
        r.ingest
            .state
            .rows()
            .into_iter()
            .filter(|row| {
                row["Action"]
                    .as_str()
                    .is_some_and(|a| a.starts_with("notify."))
            })
            .collect::<Vec<_>>()
    };
    until("the audit rows", || rows().len() >= n).await;
    rows()
}

#[tokio::test]
async fn an_email_is_sent_polled_and_audited() {
    let r = rig().await;
    let got = r.n.enqueue(notice(&[
        "alex@example.com",
        "sam@example.com",
        "alex@example.com",
        // The same mailbox written another way is listed once too.
        "Alex+other@example.com",
    ]));
    assert_eq!(got, Enqueued::Queued { recipients: 2 });
    until("delivered", || r.n.health().delivered == 1).await;
    let a = r.acs.state.attempts();
    assert_eq!(a.len(), 1);
    let b = &a[0].body;
    assert_eq!(b["senderAddress"], "DoNotReply@mail.example.com");
    let to: Vec<&str> = b["recipients"]["to"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["address"].as_str().unwrap())
        .collect();
    assert_eq!(to, ["alex@example.com", "sam@example.com"]);
    assert_eq!(
        b["content"]["subject"],
        "[Keyring] Expiry: secret db-password in kv-test"
    );
    let text = b["content"]["plainText"].as_str().unwrap();
    let html = b["content"]["html"].as_str().unwrap();
    for body in [text, html] {
        assert!(body.contains("A secret expires soon"));
        assert!(body.contains("https://keyring.example.com/v/kv-test/secrets/db-password"));
    }
    // Polled once, for the operation the 202 named.
    assert_eq!(
        *r.acs.state.polls.lock().unwrap(),
        [a[0].request_id.clone()]
    );
    // One ACS token, reused.
    assert_eq!(
        r.identity
            .state
            .resources
            .lock()
            .unwrap()
            .iter()
            .filter(|x| x.as_str() == "https://communication.azure.com")
            .count(),
        1
    );
    let rows = notify_rows(&r, 1).await;
    let row = &rows[0];
    assert_eq!(row["Action"], "notify.sent");
    assert_eq!(row["Outcome"], "success");
    assert_eq!(row["NotifyType"], "expiry");
    assert_eq!(row["NotifyRecipientCount"], 2);
    assert_eq!(row["Vault"], "kv-test");
    assert_eq!(row["ItemName"], "db-password");
    assert_eq!(row["ItemKind"], "secret");
    // Addresses are personal data: not on the event by default.
    assert!(row.get("NotifyRecipients").is_none());
    assert!(!row.to_string().contains("sam@example.com"));
}

#[tokio::test]
async fn recipients_go_on_the_event_only_when_asked() {
    let r = rig_with(|s| s.audit_recipients = true).await;
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    let rows = notify_rows(&r, 1).await;
    assert_eq!(rows[0]["NotifyRecipients"], "alex@example.com");
}

#[tokio::test]
async fn a_429_waits_for_retry_after_and_resends_the_same_request() {
    let r = rig().await;
    r.acs
        .state
        .script
        .lock()
        .unwrap()
        .push_back(Answer::Status(429, Some(1)));
    let started = Instant::now();
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("delivered", || r.n.health().delivered == 1).await;
    assert!(started.elapsed() >= Duration::from_secs(1));
    let a = r.acs.state.attempts();
    assert_eq!(a.len(), 2);
    // The same ID, first-sent time and body: ACS can tell it's a retry.
    assert_eq!(a[0].request_id, a[1].request_id);
    assert_eq!(a[0].first_sent, a[1].first_sent);
    assert_eq!(a[0].raw, a[1].raw);
    assert_eq!(r.n.health().failed_attempts, 1);
}

#[tokio::test]
async fn a_5xx_and_a_409_are_retried_with_the_same_headers() {
    let r = rig().await;
    {
        let mut s = r.acs.state.script.lock().unwrap();
        s.push_back(Answer::Status(500, None));
        s.push_back(Answer::Status(503, None));
        s.push_back(Answer::Status(409, None));
    }
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("delivered", || r.n.health().delivered == 1).await;
    let a = r.acs.state.attempts();
    assert_eq!(a.len(), 4);
    assert!(a.iter().all(|x| x.request_id == a[0].request_id
        && x.first_sent == a[0].first_sent
        && x.raw == a[0].raw));
}

#[tokio::test]
async fn a_4xx_drops_the_email_and_counts_it() {
    let r = rig().await;
    r.acs
        .state
        .script
        .lock()
        .unwrap()
        .push_back(Answer::Status(400, None));
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("failed", || r.n.health().failed == 1).await;
    assert_eq!(r.acs.state.attempts().len(), 1, "not retried");
    let rows = notify_rows(&r, 1).await;
    assert_eq!(rows[0]["Action"], "notify.failed");
    assert_eq!(rows[0]["ReasonCode"], "rejected");
    // The next one goes through.
    assert!(r.n.enqueue(notice(&["sam@example.com"])).is_queued());
    until("delivered", || r.n.health().delivered == 1).await;
}

#[tokio::test]
async fn a_412_gives_up_without_a_new_id() {
    let r = rig().await;
    {
        let mut s = r.acs.state.script.lock().unwrap();
        s.push_back(Answer::Status(500, None));
        s.push_back(Answer::Status(412, None));
    }
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("given up", || r.n.health().unknown == 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let a = r.acs.state.attempts();
    assert_eq!(a.len(), 2, "never sent again");
    assert_eq!(a[0].request_id, a[1].request_id);
    let rows = notify_rows(&r, 1).await;
    assert_eq!(rows[0]["Action"], "notify.failed");
    assert_eq!(rows[0]["ReasonCode"], "gave_up_maybe_sent");
}

#[tokio::test]
async fn an_email_is_given_up_at_the_end_of_the_repeat_window() {
    let r = rig_with(|s| {
        s.tuning.give_up_after = Duration::from_millis(400);
    })
    .await;
    for _ in 0..50 {
        r.acs
            .state
            .script
            .lock()
            .unwrap()
            .push_back(Answer::Status(503, None));
    }
    let started = Instant::now();
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("given up", || r.n.health().unknown == 1).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    let a = r.acs.state.attempts();
    assert!(a.len() >= 2);
    assert!(
        a.iter().all(|x| x.request_id == a[0].request_id),
        "never retried under a new ID"
    );
    assert!(r.n.degraded(), "failing past degraded_after");
}

#[tokio::test]
async fn polls_at_most_three_times_then_counts_unknown() {
    let r = rig().await;
    {
        let mut s = r.acs.state.statuses.lock().unwrap();
        for st in ["NotStarted", "Running", "Running", "Succeeded"] {
            s.push_back(st);
        }
    }
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("unknown", || r.n.health().unknown == 1).await;
    assert_eq!(r.acs.state.polls.lock().unwrap().len(), 3);
    let rows = notify_rows(&r, 1).await;
    assert_eq!(rows[0]["Action"], "notify.sent");
    assert_eq!(rows[0]["ReasonCode"], "status_unknown");
}

#[tokio::test]
async fn a_failed_result_records_only_its_status() {
    let r = rig().await;
    r.acs.state.statuses.lock().unwrap().push_back("Failed");
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("failed", || r.n.health().failed == 1).await;
    let rows = notify_rows(&r, 1).await;
    assert_eq!(rows[0]["Action"], "notify.failed");
    assert_eq!(rows[0]["ReasonCode"], "delivery_failed");
    assert!(!rows[0].to_string().contains("ACSLEAK"));
    assert!(!r.acs.state.all_bodies().contains("ACSLEAK"));
    let _ = AZURE_MESSAGE;
}

#[tokio::test]
async fn the_token_is_never_sent_to_another_host() {
    let trap = acs::trap().await;
    let r = rig().await;
    let other = format!("http://{}/emails/operations/abc", trap.addr);
    {
        let mut s = r.acs.state.script.lock().unwrap();
        s.push_back(Answer::AcceptAt(other));
        s.push_back(Answer::AcceptAt(format!(
            "https://{}/emails/operations/abc",
            r.acs.addr
        )));
        s.push_back(Answer::AcceptAt(format!("{}/elsewhere/abc", r.acs.url())));
        s.push_back(Answer::AcceptWithout);
    }
    for to in [
        "a@example.com",
        "b@example.com",
        "c@example.com",
        "d@example.com",
    ] {
        assert!(r.n.enqueue(notice(&[to])).is_queued());
    }
    until("all four", || r.n.health().unknown == 4).await;
    assert!(trap.hits.lock().unwrap().is_empty(), "the trap was called");
    assert!(r.acs.state.polls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_rate_limit_holds_each_recipient_and_type() {
    let r = rig_with(|s| s.per_hour = 2).await;
    for _ in 0..2 {
        assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    }
    // Only the rate limit left alex out, so a later try could send.
    assert_eq!(
        r.n.enqueue(notice(&["alex@example.com"])),
        Enqueued::RateLimited
    );
    // Others still get it, and alex is left out.
    assert_eq!(
        r.n.enqueue(notice(&["alex@example.com", "sam@example.com"])),
        Enqueued::Queued { recipients: 1 }
    );
    // Another type has its own limit.
    let mut health = notice(&["alex@example.com"]);
    health.kind = NotifyType::Health;
    assert!(r.n.enqueue(health).is_queued());
    assert_eq!(r.n.health().rate_limited, 2);
    until("sent", || r.n.health().delivered == 4).await;
}

#[tokio::test]
async fn the_allow_list_holds_every_recipient() {
    let r = rig_with(|s| s.allowed_domains = Some(vec!["example.com".into()])).await;
    assert_eq!(
        r.n.enqueue(notice(&["eve@evil.com"])),
        Enqueued::NoRecipients
    );
    // A subdomain isn't the domain.
    assert_eq!(
        r.n.enqueue(notice(&[
            "eve@mail.example.com.evil.com",
            "x@sub.example.com"
        ])),
        Enqueued::NoRecipients
    );
    assert_eq!(
        r.n.enqueue(notice(&["eve@evil.com", "alex@Example.com"])),
        Enqueued::Queued { recipients: 1 }
    );
    until("sent", || r.n.health().delivered == 1).await;
    let a = r.acs.state.attempts();
    assert!(!a[0].raw.contains("evil.com"));
    assert_eq!(r.n.health().not_allowed, 4);
    // Over the limit, with someone else outside the allow-list: a later
    // try can still reach the one over the limit, so it isn't permanent.
    let r = rig_with(|s| {
        s.allowed_domains = Some(vec!["example.com".into()]);
        s.per_hour = 1;
    })
    .await;
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    assert_eq!(
        r.n.enqueue(notice(&["alex@example.com", "eve@evil.com"])),
        Enqueued::RateLimited
    );
    // Nobody given at all is not the rate limit's doing.
    assert_eq!(r.n.enqueue(notice(&[])), Enqueued::NoRecipients);
    assert_eq!(
        r.n.enqueue(notice(&["alex@example.com"])),
        Enqueued::RateLimited
    );
}

#[tokio::test]
async fn types_that_are_off_send_nothing() {
    let r = rig_with(|s| s.types = vec![NotifyType::Health]).await;
    assert_eq!(r.n.enqueue(notice(&["alex@example.com"])), Enqueued::Off);
    assert_eq!(
        keyring::notify::sender::enqueue::<Notice>(None, notice(&["alex@example.com"])),
        Enqueued::Off
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(r.acs.state.attempts().is_empty());
}

#[tokio::test]
async fn a_full_queue_says_so_and_never_blocks() {
    let r = rig_with(|s| s.tuning.queue_capacity = 2).await;
    // Hold the sender on retries so the queue fills.
    for _ in 0..200 {
        r.acs
            .state
            .script
            .lock()
            .unwrap()
            .push_back(Answer::Status(503, Some(1)));
    }
    let started = Instant::now();
    let mut results = Vec::new();
    for n in 0..6 {
        results.push(r.n.enqueue(notice(&[&format!("u{n}@example.com")])));
    }
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "enqueue blocked"
    );
    assert!(results.iter().any(|e| e.is_queue_full()), "{results:?}");
    assert!(results.iter().filter(|e| e.is_queued()).count() >= 2);
    assert!(r.n.health().dropped_queue_full >= 1);
    let rows = notify_rows(&r, 1).await;
    assert!(
        rows.iter()
            .any(|row| row["ReasonCode"] == "queue_full" && row["Action"] == "notify.failed")
    );
    r.acs.state.script.lock().unwrap().clear();
}

#[tokio::test]
async fn a_refused_identity_is_retried_with_a_new_token() {
    let r = rig().await;
    r.acs
        .state
        .script
        .lock()
        .unwrap()
        .push_back(Answer::Status(403, None));
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("delivered", || r.n.health().delivered == 1).await;
    let acs_tokens = r
        .identity
        .state
        .resources
        .lock()
        .unwrap()
        .iter()
        .filter(|x| x.as_str() == "https://communication.azure.com")
        .count();
    assert_eq!(acs_tokens, 2, "the refused token was dropped");
}

#[tokio::test]
async fn an_identity_refused_twice_is_rejected_at_once_not_retried_for_minutes() {
    // A missing role on the Communication Services resource: every email
    // would otherwise retry for the whole repeat window, holding up the
    // queue behind it.
    let r = rig().await;
    {
        let mut script = r.acs.state.script.lock().unwrap();
        script.push_back(Answer::Status(403, None));
        script.push_back(Answer::Status(403, None));
    }
    let started = Instant::now();
    assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
    until("failed", || r.n.health().failed == 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "gave up after {:?}, not at the end of the window",
        started.elapsed()
    );
    assert_eq!(r.n.health().delivered, 0);
    // The next email gets its own fresh try.
    assert!(r.n.enqueue(notice(&["sam@example.com"])).is_queued());
    until("delivered", || r.n.health().delivered == 1).await;
}

#[tokio::test]
async fn shutdown_sends_what_is_queued() {
    let r = rig().await;
    for n in 0..3 {
        assert!(
            r.n.enqueue(notice(&[&format!("u{n}@example.com")]))
                .is_queued()
        );
    }
    r.n.shutdown().await;
    assert_eq!(r.n.health().delivered, 3);
}

// ---------------------------------------------------------------------
// Through the app
// ---------------------------------------------------------------------

async fn get(app: &axum::Router, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn text(res: axum::response::Response) -> String {
    support::body_text(res).await
}

#[tokio::test]
async fn healthz_notify_is_off_without_email() {
    let w = support::world().await;
    assert!(w.state.notifier.is_none());
    let res = get(&w.app, "/healthz/notify").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(text(res).await, "status=off\n");
}

#[tokio::test]
async fn healthz_notify_counts_and_goes_503_when_degraded() {
    let acs = acs::start().await;
    let identity = support::start_identity().await;
    let w = support::world_configured(
        vec![
            (
                "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                IDENTITY_CLIENT_ID.to_owned(),
            ),
            ("IDENTITY_ENDPOINT", identity.endpoint()),
            ("IDENTITY_HEADER", IDENTITY_HEADER.to_owned()),
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
            ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
        ],
        |c| c.notify.as_mut().unwrap().tuning = quick(),
    )
    .await;
    let n = w.state.notifier.clone().expect("email is on");
    assert!(
        w.state
            .config
            .test_overrides()
            .contains(&"KEYRING_TEST_NOTIFY_ACS_URL")
    );
    let health = Notification {
        kind: NotifyType::Health,
        to: n.admins().to_vec(),
        item: None,
        data: Notice::new("Keyring's audit sink is degraded"),
    };
    assert!(n.enqueue(health.clone()).is_queued());
    until("delivered", || n.health().delivered == 1).await;
    let res = get(&w.app, "/healthz/notify").await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = text(res).await;
    assert!(body.starts_with("status=ok\n"), "{body}");
    assert!(body.contains("delivered=1\n"));
    assert!(!body.contains("ops@example.com"));
    assert_eq!(
        acs.state.attempts()[0].body["content"]["subject"],
        "[Keyring] Health"
    );

    for _ in 0..200 {
        acs.state
            .script
            .lock()
            .unwrap()
            .push_back(Answer::Status(500, None));
    }
    assert!(n.enqueue(health).is_queued());
    until("degraded", || n.degraded()).await;
    let res = get(&w.app, "/healthz/notify").await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(text(res).await.starts_with("status=degraded\n"));
    acs.state.script.lock().unwrap().clear();
    assert!(
        acs.state.violations().is_empty(),
        "{:?}",
        acs.state.violations()
    );
}

// ---------------------------------------------------------------------
// The Bicep module
// ---------------------------------------------------------------------

/// The custom role holds exactly the two actions the owner approved, is
/// assigned straight to the identity on the one resource, and nothing in
/// the module reads, outputs or sets a key or connection string.
#[test]
fn the_notify_module_grants_two_actions_and_no_keys() {
    let bicep = include_str!("../infra/modules/notify.bicep");
    let code: String = bicep
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let start = code.find("actions: [").expect("actions");
    let end = start + code[start..].find(']').unwrap();
    let actions: Vec<&str> = code[start..end]
        .lines()
        .filter_map(|l| l.trim().strip_prefix('\'')?.strip_suffix('\''))
        .collect();
    assert_eq!(
        actions,
        [
            "Microsoft.Communication/CommunicationServices/Read",
            "Microsoft.Communication/CommunicationServices/Write",
        ]
    );
    assert!(code.contains("notActions: []"));
    assert!(code.contains("dataActions: []"));
    assert!(code.contains("assignableScopes: [resourceGroup().id]"));
    assert!(code.contains("scope: communication"));
    assert!(code.contains("principalType: 'ServicePrincipal'"));
    assert!(!code.contains('*'), "no wildcard anywhere");
    let lower = code.to_ascii_lowercase();
    for banned in [
        "listkeys",
        "regeneratekey",
        "connectionstring",
        "primarykey",
        "secondarykey",
        "smtp",
    ] {
        assert!(!lower.contains(banned), "{banned} in notify.bicep");
    }
    // The role's permissions name nothing but Communication Services.
    let perms_start = code.find("permissions: [").expect("permissions");
    let perms_end = perms_start + code[perms_start..].find("assignableScopes").unwrap();
    let perms = code[perms_start..perms_end].to_ascii_lowercase();
    assert!(!perms.contains("emailservices"), "{perms}");
    assert_eq!(perms.matches("microsoft.").count(), 2, "{perms}");
    // Every output is wired to a setting both host templates set.
    for t in [
        include_str!("../infra/app-service/main.bicep"),
        include_str!("../infra/container-apps/main.bicep"),
    ] {
        assert!(t.contains("module notify '../modules/notify.bicep'"));
        assert!(t.contains("'KEYRING_NOTIFY_ACS_ENDPOINT', value: notify!.outputs.endpoint"));
        assert!(t.contains("'KEYRING_NOTIFY_SENDER', value: notify!.outputs.senderAddress"));
        assert!(t.contains("useFederatedCredential || useAuditSink || !empty(notifyDomain)"));
        // The only listKeys in either template is the Container Apps log
        // workspace's, never anything of ACS's.
        for l in t.lines().filter(|l| l.contains("listKeys")) {
            assert!(l.contains("logs!.listKeys()"), "{l}");
        }
    }
}

// ---------------------------------------------------------------------
// Health notices (`src/notify/health.rs`), with fixed clocks
// ---------------------------------------------------------------------

mod health {
    use super::*;
    use keyring::audit::{Action, AuditEvent, Observe, Outcome};
    use keyring::notify::health::{self, Clock, HealthWatch, ManualClock};
    use std::time::SystemTime;

    /// 17 Nov 2026, 00:00 UTC.
    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_873_600)
    }

    fn min(m: u64) -> Duration {
        Duration::from_secs(m * 60)
    }

    fn tuning() -> health::Tuning {
        health::Tuning {
            tick: Duration::from_secs(3600),
            ..health::Tuning::default()
        }
    }

    fn watch(
        r: &Rig,
        clock: &Arc<ManualClock>,
        sink: Option<Arc<AuditSink>>,
        f: impl FnOnce(&mut health::Settings),
    ) -> Arc<HealthWatch> {
        let mut s = health::Settings {
            burst_threshold: 20,
            secret_expires: None,
            base_url: "https://keyring.example.com".into(),
            tuning: tuning(),
        };
        f(&mut s);
        HealthWatch::new(s, clock.clone() as Arc<dyn Clock>, r.n.clone(), sink)
    }

    /// Health emails ACS has been sent, by subject and plain text.
    fn health_mail(r: &Rig) -> Vec<(String, String, String)> {
        r.acs
            .state
            .attempts()
            .into_iter()
            .filter(|a| a.body["content"]["subject"] == "[Keyring] Health")
            .map(|a| {
                (
                    a.body["content"]["plainText"].as_str().unwrap().to_owned(),
                    a.body["content"]["html"].as_str().unwrap().to_owned(),
                    a.body["recipients"]["to"][0]["address"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
            })
            .collect()
    }

    async fn mails(r: &Rig, n: usize) -> Vec<(String, String, String)> {
        until("health emails", || health_mail(r).len() >= n).await;
        // Nothing more is on its way.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let m = health_mail(r);
        assert_eq!(m.len(), n, "{m:#?}");
        m
    }

    fn refused(upn: Option<&str>, ip: &str, code: &str) -> AuditEvent {
        let mut ev = AuditEvent::new(Action::SecretReveal, Outcome::Refused);
        ev.actor_upn = upn.map(str::to_owned);
        ev.actor_oid = upn.map(|u| format!("oid-{u}"));
        ev.client_ip = Some(ip.to_owned());
        ev.reason_code = Some(code.to_owned());
        ev.reason = Some("REASONTEXT never in an email".into());
        ev
    }

    #[tokio::test]
    async fn the_audit_sink_failing_emails_once_at_the_start_and_once_at_the_end() {
        let r = rig().await;
        let tokens = Arc::new(ManagedIdentityTokens::new(
            r.identity.endpoint(),
            Secret::new(IDENTITY_HEADER),
            IDENTITY_CLIENT_ID.into(),
            keyring::http::local_client().unwrap(),
        ));
        let sink = AuditSink::start(
            format!(
                "{}/dataCollectionRules/{DCR_ID}/streams/{STREAM}?api-version=2023-01-01",
                r.ingest.url()
            ),
            SinkTuning {
                flush_every: Duration::from_millis(20),
                degraded_after: Duration::from_millis(100),
                backoff_first: Duration::from_millis(10),
                backoff_max: Duration::from_millis(20),
                ..SinkTuning::default()
            },
            tokens,
            keyring::http::client(false).unwrap(),
        );
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, Some(sink.clone()), |_| {});

        // Healthy: nothing.
        w.tick();
        *r.ingest.state.always.lock().unwrap() = Some(500);
        for _ in 0..5 {
            sink.enqueue(&AuditEvent::new(Action::SessionSignOut, Outcome::Success));
        }
        until("degraded", || sink.degraded()).await;
        // Seen degraded, but not for five minutes yet.
        w.tick();
        clock.advance(min(4));
        w.tick();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(health_mail(&r).is_empty());
        clock.advance(min(1));
        w.tick();
        let m = mails(&r, 1).await;
        assert!(
            m[0].0.contains("Keyring's audit sink is failing"),
            "{}",
            m[0].0
        );
        assert!(m[0].0.contains("Dropped so far: 0"), "{}", m[0].0);
        assert_eq!(m[0].2, "ops@example.com");
        // Still failing: nothing in between.
        for _ in 0..5 {
            clock.advance(min(5));
            w.tick();
        }
        mails(&r, 1).await;

        // Recovers.
        *r.ingest.state.always.lock().unwrap() = None;
        sink.enqueue(&AuditEvent::new(Action::SessionSignOut, Outcome::Success));
        until("recovered", || !sink.degraded() && sink.health().sent > 0).await;
        clock.advance(min(1));
        w.tick();
        let m = mails(&r, 2).await;
        assert!(m[1].0.contains("has recovered"), "{}", m[1].0);
        assert!(
            m[1].0.contains("Failing for about: 31 minutes"),
            "{}",
            m[1].0
        );
        assert!(m[1].0.contains("Dropped in this incident: 0"), "{}", m[1].0);
        // Healthy again: nothing more.
        clock.advance(min(5));
        w.tick();
        mails(&r, 2).await;
        sink.shutdown().await;
    }

    #[tokio::test]
    async fn a_refusal_burst_emails_once_per_person_per_incident() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |_| {});
        let alex = Some("alex.ops@example.com");
        // 20 in the window is not a burst.
        for i in 0..20 {
            let code = if i % 2 == 0 {
                "step_up_required"
            } else {
                "invalid_request"
            };
            w.observe(&refused(alex, "203.0.113.7", code));
            clock.advance(Duration::from_secs(40));
        }
        // Successes and failures don't count.
        w.observe(&AuditEvent::new(Action::SecretReveal, Outcome::Failed));
        w.observe(&AuditEvent::new(Action::SecretReveal, Outcome::Success));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(health_mail(&r).is_empty());
        // The 21st, with an Azure code, is.
        let mut denied = refused(alex, "203.0.113.7", "ForbiddenByRbac");
        denied.outcome = Outcome::Denied;
        w.observe(&denied);
        let m = mails(&r, 1).await;
        let (text, html, _) = &m[0];
        assert!(text.contains("Many refused requests"), "{text}");
        assert!(text.contains("Person: alex.ops@example.com"), "{text}");
        assert!(text.contains("Refused or denied: 21"), "{text}");
        assert!(
            text.contains("Reason codes: ForbiddenByRbac, invalid_request, step_up_required"),
            "{text}"
        );
        let link = "https://keyring.example.com/audit?report=person&range=24h&person=alex.ops%40example.com";
        assert!(text.contains(link), "{text}");
        assert!(
            html.contains(&format!("href=\"{}\"", link.replace('&', "&#38;"))),
            "{html}"
        );
        for body in [text, html] {
            assert!(!body.contains("REASONTEXT"));
            assert!(
                !body.contains("203.0.113.7"),
                "a person's burst names them, not the IP"
            );
        }

        // More in the same incident: no more email.
        for _ in 0..50 {
            clock.advance(Duration::from_secs(10));
            w.observe(&refused(alex, "203.0.113.7", "csrf"));
        }
        mails(&r, 1).await;
        // 15 quiet minutes end it; the next burst is a new incident.
        clock.advance(min(15));
        w.tick();
        assert_eq!(w.tracked(), 0);
        for _ in 0..21 {
            w.observe(&refused(alex, "203.0.113.7", "csrf"));
        }
        let m = mails(&r, 2).await;
        assert!(m[1].0.contains("Refused or denied: 21"), "{}", m[1].0);
        assert!(m[1].0.contains("Reason codes: csrf\n"), "{}", m[1].0);
    }

    #[tokio::test]
    async fn refusals_spread_out_are_not_a_burst() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |s| s.burst_threshold = 3);
        // Four refusals, but never more than three within 15 minutes.
        for _ in 0..12 {
            w.observe(&refused(Some("alex@example.com"), "203.0.113.7", "csrf"));
            clock.advance(min(6));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(health_mail(&r).is_empty());
    }

    #[tokio::test]
    async fn with_nobody_signed_in_the_burst_is_by_address() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |s| s.burst_threshold = 3);
        for _ in 0..4 {
            w.observe(&refused(None, "2001:db8::7", "no_session"));
        }
        // A made-up "address" is never counted or shown.
        for _ in 0..10 {
            w.observe(&refused(None, "https://evil.example/x", "no_session"));
        }
        // A sign-in name that isn't one is shown as an unnamed caller.
        for _ in 0..4 {
            let mut ev = refused(None, "203.0.113.9", "id_token_rejected");
            ev.actor_upn = Some("visit https://evil.example now".into());
            w.observe(&ev);
        }
        let m = mails(&r, 2).await;
        assert!(m[0].0.contains("Address: 2001:db8::7"), "{}", m[0].0);
        assert!(m[0].0.contains("nobody signed in"), "{}", m[0].0);
        assert!(
            m[0].0
                .contains("https://keyring.example.com/audit?report=refused&range=24h"),
            "{}",
            m[0].0
        );
        assert!(m[1].0.contains("Person: an unnamed caller"), "{}", m[1].0);
        for (text, html, _) in &m {
            assert!(!text.contains("evil.example") && !html.contains("evil.example"));
        }
    }

    #[tokio::test]
    async fn email_events_never_count_towards_a_burst() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |s| s.burst_threshold = 1);
        for action in [Action::NotifyFailed, Action::NotifySent] {
            for _ in 0..10 {
                let mut ev = AuditEvent::new(action, Outcome::Refused);
                ev.client_ip = Some("203.0.113.7".into());
                ev.actor_upn = Some("alex@example.com".into());
                w.observe(&ev);
            }
        }
        assert_eq!(w.tracked(), 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(health_mail(&r).is_empty());
    }

    #[tokio::test]
    async fn the_map_is_bounded_and_emails_are_capped() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |s| {
            s.burst_threshold = 1;
            s.tuning.max_keys = 5;
            s.tuning.max_burst_emails_per_hour = 3;
        });
        // A flood of made-up addresses: only five are tracked.
        for i in 0..1000u32 {
            let ip = format!("198.51.{}.{}", i / 250, i % 250);
            w.observe(&refused(None, &ip, "csrf"));
            w.observe(&refused(None, &ip, "csrf"));
        }
        assert_eq!(w.tracked(), 5);
        // Five bursts, but only three emails this hour.
        mails(&r, 3).await;
        // Once they go quiet, room is made again.
        clock.advance(min(61));
        w.observe(&refused(None, "192.0.2.1", "csrf"));
        assert_eq!(w.tracked(), 1);
        w.observe(&refused(None, "192.0.2.1", "csrf"));
        mails(&r, 4).await;
    }

    #[tokio::test]
    async fn the_client_secret_is_emailed_at_30_14_7_and_1_days_then_expired() {
        let r = rig_with(|s| s.per_hour = 100).await;
        let expires = keyring::dates::parse_iso_date("2026-12-31").unwrap();
        let day = |d: i64| {
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(expires - d * 86_400 + 3600).unwrap())
        };
        let clock = Arc::new(ManualClock::new(day(45)));
        let w = watch(&r, &clock, None, |s| s.secret_expires = Some(expires));
        let mut expect = 0;
        for (days_left, emails) in [
            (45, false),
            (31, false),
            (30, true),
            (30, false),
            (20, false),
            (14, true),
            (9, false),
            (5, true),
            (2, false),
            (1, true),
            (0, true),
            (-1, false),
            (-30, false),
        ] {
            clock.set(day(days_left));
            w.tick();
            w.tick();
            if emails {
                expect += 1;
            }
            mails(&r, expect).await;
        }
        let m = health_mail(&r);
        assert!(m[0].0.contains("expires in 30 days"), "{}", m[0].0);
        assert!(m[0].0.contains("Expiry date: 31 Dec 2026"), "{}", m[0].0);
        assert!(m[2].0.contains("expires in 5 days"), "{}", m[2].0);
        assert!(m[3].0.contains("expires in 1 day."), "{}", m[3].0);
        assert!(m[4].0.contains("has expired"), "{}", m[4].0);

        // After a restart nothing is remembered: the current step once more.
        let w = watch(&r, &clock, None, |s| s.secret_expires = Some(expires));
        clock.set(day(3));
        w.tick();
        w.tick();
        let m = mails(&r, expect + 1).await;
        assert!(m.last().unwrap().0.contains("expires in 3 days"));
    }

    #[tokio::test]
    async fn email_failing_sends_no_email_about_itself() {
        let r = rig().await;
        let clock = Arc::new(ManualClock::new(t0()));
        let w = watch(&r, &clock, None, |_| {});
        for _ in 0..200 {
            r.acs
                .state
                .script
                .lock()
                .unwrap()
                .push_back(Answer::Status(500, None));
        }
        assert!(r.n.enqueue(notice(&["alex@example.com"])).is_queued());
        until("degraded", || r.n.degraded()).await;
        for _ in 0..3 {
            clock.advance(min(5));
            w.tick();
        }
        // The ticks queued nothing: the one email being tried is off the
        // queue, and none of its tries is a health email.
        assert_eq!(r.n.health().queued, 0);
        assert!(health_mail(&r).is_empty());
        r.acs.state.script.lock().unwrap().clear();
    }

    /// Through the app: refused requests as they are recorded, with the
    /// audit sink off.
    #[tokio::test]
    async fn refused_requests_through_the_app_raise_one_burst_email() {
        let acs = acs::start().await;
        let identity = support::start_identity().await;
        let w = support::world_configured(
            vec![
                (
                    "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
                    IDENTITY_CLIENT_ID.to_owned(),
                ),
                ("IDENTITY_ENDPOINT", identity.endpoint()),
                ("IDENTITY_HEADER", IDENTITY_HEADER.to_owned()),
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
                ("KEYRING_NOTIFY_BURST_THRESHOLD", "3".to_owned()),
                ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
            ],
            |c| c.notify.as_mut().unwrap().tuning = quick(),
        )
        .await;
        assert!(w.state.audit_sink.is_none());
        assert!(w.state.health.is_some());
        w.kv.state.put("db-password", "value");
        for _ in 0..6 {
            let res = w
                .post(
                    "/v/kv-test/secrets/db-password/delete",
                    &[("confirm_name", "not-the-name")],
                )
                .await;
            let _ = support::body_text(res).await;
        }
        let n = w.state.notifier.clone().unwrap();
        until("sent", || n.health().delivered >= 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let a = acs.state.attempts();
        assert_eq!(a.len(), 1, "one email per incident");
        let text = a[0].body["content"]["plainText"].as_str().unwrap();
        assert!(text.contains("Person: alex@example.com"), "{text}");
        assert!(text.contains("Reason codes: typed_name_mismatch"), "{text}");
        assert!(
            text.contains(
                "http://localhost:3000/audit?report=person&range=24h&person=alex%40example.com"
            ),
            "{text}"
        );
        assert!(acs.state.violations().is_empty());
    }
}
