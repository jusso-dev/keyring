//! `POST /hooks/eventgrid`: expiry events pushed by Event Grid, checked
//! with an Entra token from the mock Entra, emailed through the mock ACS.
//!
//! Every test checks nothing reached Key Vault: Keyring never reads a vault
//! here.

mod support;

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use support::acs::{self, MockAcs};
use support::eventgrid::{self as eg, SIX};
use tower::ServiceExt;

const HOOK: &str = "/hooks/eventgrid";
const VALUE: &str = "Sup3r-S3cret-Value";

struct Rig {
    w: support::World,
    acs: MockAcs,
    _mi: support::MockIdentity,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let v = self.acs.state.violations();
            assert!(v.is_empty(), "ACS rule broken: {v:?}");
            assert!(
                self.w.kv.state.log.lock().unwrap().is_empty(),
                "Key Vault was called: {:?}",
                self.w.kv.state.log.lock().unwrap()
            );
        }
    }
}

async fn rig_with(
    extra: &[(&'static str, &str)],
    tweak: impl FnOnce(&mut keyring::config::Config),
) -> Rig {
    let acs = acs::start().await;
    let mi = support::start_identity().await;
    let mut env: Vec<(&'static str, String)> = vec![
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
        ("KEYRING_NOTIFY_TYPES", "expiry".to_owned()),
        ("KEYRING_NOTIFY_ADMINS", "ops@example.com".to_owned()),
        ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
    ];
    for (k, v) in extra {
        env.retain(|(n, _)| n != k);
        env.push((k, (*v).to_owned()));
    }
    let w = support::world_configured(env, |c| {
        let n = c.notify.as_mut().unwrap();
        n.tuning.backoff_first = Duration::from_millis(10);
        n.tuning.poll_wait_default = Duration::from_millis(10);
        n.tuning.poll_wait_max = Duration::from_millis(20);
        tweak(c);
    })
    .await;
    // A value in the vault, which must never reach an email.
    w.kv.state.put("db-password", VALUE);
    w.kv.state.log.lock().unwrap().clear();
    Rig { w, acs, _mi: mi }
}

async fn rig() -> Rig {
    rig_with(&[], |_| {}).await
}

fn good_token(r: &Rig) -> String {
    eg::sign(&r.w.idp, &eg::claims_v1(&r.w.idp))
}

async fn send(
    r: &Rig,
    token: Option<&str>,
    body: &Value,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    send_raw(r, "POST", token, body.to_string(), headers).await
}

async fn send_raw(
    r: &Rig,
    method: &str,
    token: Option<&str>,
    body: String,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(HOOK)
        .header("content-type", "application/json")
        // Event Grid is no browser: no Origin, no Referer, no
        // Sec-Fetch-Site.
        .header("aeg-event-type", "Notification");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res =
        r.w.app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
    let status = res.status();
    (status, support::body_text(res).await)
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

fn soon() -> i64 {
    eg::now() + 10 * 86_400 + 3600
}

fn one(event_type: &str, object: &str, name: &str) -> Value {
    json!([eg::event(event_type, object, name, soon())])
}

/// Wait a little to show nothing more is sent.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

#[tokio::test]
async fn the_handshake_needs_a_valid_token() {
    let r = rig().await;
    let code = "512d38b6-c7b8-40c8-89fe-f46f9e9622b6";
    let (s, body) = send(&r, None, &eg::validation(code), &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "", "no detail in a 401");
    let (s, body) = send(&r, Some(&good_token(&r)), &eg::validation(code), &[]).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v, json!({ "validationResponse": code }));
    // A code that isn't a plain token of letters, digits and hyphens is
    // never echoed.
    for bad in ["<script>alert(1)</script>", "", &"a".repeat(65)] {
        let (s, body) = send(&r, Some(&good_token(&r)), &eg::validation(bad), &[]).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        assert!(!body.contains("script"));
    }
    settle().await;
    assert!(r.acs.state.attempts().is_empty());
}

#[tokio::test]
async fn bad_tokens_are_refused_with_401_and_nothing_sent() {
    let r = rig().await;
    let idp = &r.w.idp;
    let body = one("SecretNearExpiry", "Secret", "db-password");
    let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut c = eg::claims_v1(idp);
        f(&mut c);
        eg::sign(idp, &c)
    };
    let cases: Vec<(&str, String)> = vec![
        (
            "wrong audience",
            edit(&|c| {
                c.insert(
                    "aud".into(),
                    json!("api://22222222-2222-2222-2222-222222222222"),
                );
            }),
        ),
        (
            "audience is the client ID, not the URI",
            edit(&|c| {
                c.insert("aud".into(), json!(support::CLIENT_ID));
            }),
        ),
        (
            "wrong issuer",
            edit(&|c| {
                c.insert(
                    "iss".into(),
                    json!("https://sts.windows.net/99999999-0000-0000-0000-000000000000/"),
                );
            }),
        ),
        (
            "another tenant",
            edit(&|c| {
                c.insert("tid".into(), json!("99999999-0000-0000-0000-000000000000"));
            }),
        ),
        (
            "expired",
            edit(&|c| {
                c.insert("exp".into(), json!(eg::now() - 120));
            }),
        ),
        (
            "not yet valid",
            edit(&|c| {
                c.insert("nbf".into(), json!(eg::now() + 600));
            }),
        ),
        (
            "another app in the tenant",
            edit(&|c| {
                c.insert(
                    "appid".into(),
                    json!("22222222-2222-2222-2222-222222222222"),
                );
            }),
        ),
        (
            "no app role",
            edit(&|c| {
                c.remove("roles");
            }),
        ),
        (
            "another app role",
            edit(&|c| {
                c.insert("roles".into(), json!(["Reader"]));
            }),
        ),
        (
            "a person's delegated token",
            edit(&|c| {
                c.insert("scp".into(), json!("access_as_user"));
            }),
        ),
        ("alg none", eg::unsigned(&eg::claims_v1(idp))),
        (
            "HS256 header",
            eg::sign_with(
                &idp.state.key,
                json!({"alg": "HS256", "kid": "k1"}),
                &eg::claims_v1(idp),
            ),
        ),
        (
            "signed by a key Entra never published",
            eg::sign_with(
                &idp.state.other_key,
                json!({"alg": "RS256", "kid": "k1"}),
                &eg::claims_v1(idp),
            ),
        ),
        (
            "unknown kid",
            eg::sign_with(
                &idp.state.key,
                json!({"alg": "RS256", "kid": "nope"}),
                &eg::claims_v1(idp),
            ),
        ),
        ("tampered claims", {
            let t = good_token(&r);
            let mut parts: Vec<String> = t.split('.').map(str::to_owned).collect();
            let mut c = eg::claims_v1(idp);
            c.insert("roles".into(), json!([eg::ROLE, "Admin"]));
            use base64::Engine;
            parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Value::Object(c).to_string());
            parts.join(".")
        }),
        ("garbage", "not.a.token".into()),
    ];
    for (what, token) in &cases {
        let (s, text) = send(&r, Some(token), &body, &[]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{what}");
        assert_eq!(text, "", "{what}: no detail in the body");
    }
    for header in ["Basic abc", "Bearer", "bearer  "] {
        let (s, _) = send(&r, None, &body, &[("authorization", header)]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{header}");
    }
    let (s, _) = send(&r, None, &body, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    settle().await;
    assert!(r.acs.state.attempts().is_empty(), "nothing sent");
}

#[tokio::test]
async fn v1_and_v2_tokens_are_both_taken() {
    let r = rig().await;
    let v2 = eg::sign(&r.w.idp, &eg::claims_v2(&r.w.idp));
    let (s, _) = send(
        &r,
        Some(&v2),
        &one("SecretNearExpiry", "Secret", "a-one"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &r,
        Some(&good_token(&r)),
        &one("SecretNearExpiry", "Secret", "a-two"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
}

#[tokio::test]
async fn each_of_the_six_events_is_emailed_with_no_value() {
    let r = rig().await;
    let token = good_token(&r);
    let exp = soon();
    let events: Vec<Value> = SIX
        .iter()
        .map(|(t, o)| eg::event(t, o, "db-password", exp))
        .collect();
    let (s, _) = send(&r, Some(&token), &Value::Array(events), &[]).await;
    assert_eq!(s, StatusCode::OK);
    until("six emails", || r.acs.state.attempts().len() == 6).await;
    let date = keyring::dates::format_date(exp);
    let mut subjects: Vec<String> = Vec::new();
    for a in r.acs.state.attempts() {
        let to = &a.body["recipients"]["to"];
        assert_eq!(to, &json!([{ "address": "ops@example.com" }]), "the admins");
        let subject = a.body["content"]["subject"].as_str().unwrap().to_owned();
        let text = a.body["content"]["plainText"].as_str().unwrap();
        let html = a.body["content"]["html"].as_str().unwrap();
        for b in [text, html] {
            assert!(
                b.contains(&format!(
                    "db-password in kv-test expires on {date} (in 10 days)."
                )),
                "{b}"
            );
            assert!(b.contains("http://localhost:3000/expiry"), "{b}");
            assert!(b.contains("http://localhost:3000/v/kv-test/"), "{b}");
            assert!(b.contains(eg::VERSION));
        }
        assert!(!a.raw.contains(VALUE), "a value reached an email");
        assert!(
            !a.raw.contains("vault.azure.net"),
            "the event's Id URL reached an email"
        );
        subjects.push(subject);
    }
    subjects.sort();
    assert_eq!(
        subjects,
        [
            "[Keyring] Expiry: certificate db-password in kv-test",
            "[Keyring] Expiry: certificate db-password in kv-test",
            "[Keyring] Expiry: key db-password in kv-test",
            "[Keyring] Expiry: key db-password in kv-test",
            "[Keyring] Expiry: secret db-password in kv-test",
            "[Keyring] Expiry: secret db-password in kv-test",
        ]
    );
    let headings: Vec<String> = r
        .acs
        .state
        .attempts()
        .iter()
        .map(|a| {
            a.body["content"]["plainText"]
                .as_str()
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    for h in [
        "A secret expires soon",
        "A secret has expired",
        "A certificate expires soon",
        "A certificate has expired",
        "A key expires soon",
        "A key has expired",
    ] {
        assert!(headings.iter().any(|x| x == h), "{h}: {headings:?}");
    }
}

#[tokio::test]
async fn repeats_are_sent_once() {
    let r = rig().await;
    let token = good_token(&r);
    let body = one("SecretNearExpiry", "Secret", "db-password");
    for _ in 0..3 {
        let (s, _) = send(&r, Some(&token), &body, &[]).await;
        assert_eq!(s, StatusCode::OK, "a repeat is still 200");
    }
    // The same item in another case is the same item.
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "DB-Password"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
    // Another event type for the same item and version is sent.
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretExpired", "Secret", "db-password"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
    settle().await;
    assert_eq!(r.acs.state.attempts().len(), 2);
}

#[tokio::test]
async fn a_full_queue_is_503_and_the_retry_sends() {
    let r = rig_with(&[], |c| {
        c.notify.as_mut().unwrap().tuning.queue_capacity = 0;
    })
    .await;
    let token = good_token(&r);
    let body = one("KeyNearExpiry", "Key", "app-key");
    let (s, _) = send(&r, Some(&token), &body, &[]).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // Not remembered, so Event Grid's retry isn't taken for a repeat.
    let hook = r.w.state.expiry_hook.clone().unwrap();
    assert_eq!(hook.dedupe_len(), 0);
    let (s, _) = send(&r, Some(&token), &body, &[]).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    settle().await;
    assert!(r.acs.state.attempts().is_empty());
}

#[tokio::test]
async fn a_full_dedupe_map_is_503_and_never_repeats() {
    let r = rig_with(&[], |c| {
        c.notify.as_mut().unwrap().hook_tuning.dedupe_capacity = 2;
    })
    .await;
    let token = good_token(&r);
    for name in ["one", "two"] {
        let (s, _) = send(
            &r,
            Some(&token),
            &one("SecretNearExpiry", "Secret", name),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }
    // Full: a new item waits (503, Event Grid retries), and the two
    // already sent stay remembered, so flooding the map can't make them go
    // out again.
    for _ in 0..3 {
        let (s, _) = send(
            &r,
            Some(&token),
            &one("SecretNearExpiry", "Secret", "three"),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "one"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
    settle().await;
    assert_eq!(r.acs.state.attempts().len(), 2);
}

#[tokio::test]
async fn a_mixed_batch_is_refused_whole() {
    let r = rig().await;
    let token = good_token(&r);
    let good = eg::event("SecretNearExpiry", "Secret", "db-password", soon());
    let mut bad = eg::event("SecretNearExpiry", "Secret", "other", soon());
    bad["data"]["ObjectName"] = json!("x\r\nBcc: eve@evil.example");
    let (s, body) = send(&r, Some(&token), &json!([good.clone(), bad]), &[]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body, "");
    // An event type outside the six is bad too, not skipped.
    let other = eg::event("SecretNewVersionCreated", "Secret", "db-password", soon());
    let (s, _) = send(&r, Some(&token), &json!([good.clone(), other]), &[]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    settle().await;
    assert!(
        r.acs.state.attempts().is_empty(),
        "nothing from a bad batch"
    );
    // The good event alone still goes: the refusal remembered nothing.
    let (s, _) = send(&r, Some(&token), &json!([good]), &[]).await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
}

#[tokio::test]
async fn limits_on_size_count_type_and_method() {
    let r = rig().await;
    let token = good_token(&r);
    let ev = eg::event("SecretNearExpiry", "Secret", "db-password", soon());
    let many = Value::Array((0..51).map(|_| ev.clone()).collect());
    let (s, _) = send(&r, Some(&token), &many, &[]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "more than 50 events");
    let fifty = Value::Array((0..50).map(|_| ev.clone()).collect());
    let (s, _) = send(&r, Some(&token), &fifty, &[]).await;
    assert_eq!(s, StatusCode::OK, "50 events");
    // Over 1 MB, refused by Content-Length before it is read.
    let big = format!("[{}]", " ".repeat(1024 * 1024 + 1));
    let (s, _) = send_raw(
        &r,
        "POST",
        Some(&token),
        big.clone(),
        &[("content-length", &big.len().to_string())],
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    // JSON only.
    let mut req = Request::post(HOOK)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "text/plain")
        .body(Body::from(json!([ev]).to_string()))
        .unwrap();
    let res = r.w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // POST only.
    for m in ["GET", "PUT", "DELETE", "PATCH"] {
        let (s, _) = send_raw(&r, m, Some(&token), "[]".into(), &[]).await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED, "{m}");
    }
    // Not JSON at all, with a good token.
    req = Request::post(HOOK)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let res = r.w.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // A big body without a token is refused 401 before it is read.
    let (s, _) = send_raw(&r, "POST", None, big.clone(), &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_route_is_rate_limited() {
    let r = rig_with(&[], |c| {
        c.notify.as_mut().unwrap().hook_tuning.per_minute = 3;
    })
    .await;
    let token = good_token(&r);
    for name in ["a", "b", "c"] {
        let (s, _) = send(
            &r,
            Some(&token),
            &one("SecretNearExpiry", "Secret", name),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{name}");
    }
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "d"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_flood_of_bad_tokens_does_not_stop_a_good_delivery() {
    let r = rig_with(&[], |c| {
        let t = &mut c.notify.as_mut().unwrap().hook_tuning;
        t.per_minute = 3;
        t.unauth_per_minute = 5;
    })
    .await;
    let body = one("SecretNearExpiry", "Secret", "db-password");
    // Many more bad tokens than either budget, in the same minute.
    let mut answers = Vec::new();
    for _ in 0..200 {
        answers.push(send(&r, Some("x.y.z"), &body, &[]).await.0);
    }
    let unauthorised = answers
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!(
        unauthorised, 5,
        "401 while under the unauthenticated counter"
    );
    assert!(
        answers[5..]
            .iter()
            .all(|s| *s == StatusCode::TOO_MANY_REQUESTS),
        "then 429"
    );
    // Event Grid's budget is untouched.
    let token = good_token(&r);
    for name in ["a", "b", "c"] {
        let (s, _) = send(
            &r,
            Some(&token),
            &one("SecretNearExpiry", "Secret", name),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{name}");
    }
    until("three emails", || r.acs.state.attempts().len() == 3).await;
}

#[tokio::test]
async fn the_unauthenticated_counter_resets_each_window() {
    let r = rig_with(&[], |c| {
        let t = &mut c.notify.as_mut().unwrap().hook_tuning;
        t.unauth_per_minute = 2;
        t.rate_window = Duration::from_millis(300);
    })
    .await;
    let body = one("SecretNearExpiry", "Secret", "db-password");
    let mut first = Vec::new();
    for _ in 0..4 {
        first.push(send(&r, Some("x.y.z"), &body, &[]).await.0);
    }
    assert_eq!(
        first,
        [
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    let (s, _) = send(&r, Some("x.y.z"), &body, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a new window");
}

#[tokio::test]
async fn every_recipient_over_the_rate_limit_is_503_and_retried() {
    let r = rig_with(&[], |c| {
        let n = c.notify.as_mut().unwrap();
        n.tuning.rate_window = Duration::from_millis(1500);
    })
    .await;
    let token = good_token(&r);
    let hook = r.w.state.expiry_hook.clone().unwrap();
    // 25 distinct events, one admin, the default 20 an hour.
    let events: Vec<Value> = (0..25)
        .map(|i| eg::event("SecretNearExpiry", "Secret", &format!("s{i:02}"), soon()))
        .collect();
    let mut answers = Vec::new();
    for e in &events {
        answers.push(send(&r, Some(&token), &json!([e]), &[]).await.0);
    }
    assert!(
        answers[..20].iter().all(|s| *s == StatusCode::OK),
        "{answers:?}"
    );
    assert!(
        answers[20..]
            .iter()
            .all(|s| *s == StatusCode::SERVICE_UNAVAILABLE),
        "{answers:?}"
    );
    assert_eq!(hook.dedupe_len(), 20, "the five refused aren't remembered");
    until("twenty emails", || r.acs.state.attempts().len() == 20).await;

    // The same five again in one delivery, still inside the window: 503.
    let rest = json!(events[20..].to_vec());
    let (s, _) = send(&r, Some(&token), &rest, &[]).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(hook.dedupe_len(), 20);

    // Event Grid retries the whole lot after the window: the five are
    // sent and the first 20 are not sent again.
    tokio::time::sleep(Duration::from_millis(1600)).await;
    for chunk in events.chunks(10) {
        let (s, _) = send(&r, Some(&token), &json!(chunk.to_vec()), &[]).await;
        assert_eq!(s, StatusCode::OK);
    }
    until("25 emails", || r.acs.state.attempts().len() == 25).await;
    settle().await;
    assert_eq!(r.acs.state.attempts().len(), 25);
    assert_eq!(hook.dedupe_len(), 25);
}

#[tokio::test]
async fn a_delivery_cut_short_by_the_rate_limit_keeps_what_it_queued() {
    let r = rig_with(&[("KEYRING_NOTIFY_RATE_PER_HOUR", "2")], |_| {}).await;
    let token = good_token(&r);
    let hook = r.w.state.expiry_hook.clone().unwrap();
    let events: Vec<Value> = (0..4)
        .map(|i| eg::event("SecretNearExpiry", "Secret", &format!("s{i}"), soon()))
        .collect();
    let (s, _) = send(&r, Some(&token), &json!(events), &[]).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // The two queued stay remembered; the rest aren't.
    assert_eq!(hook.dedupe_len(), 2);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
}

#[tokio::test]
async fn partly_rate_limited_recipients_count_as_sent() {
    let r = rig_with(
        &[
            ("KEYRING_NOTIFY_ALLOWED_DOMAINS", "example.com"),
            ("KEYRING_NOTIFY_RATE_PER_HOUR", "1"),
        ],
        |_| {},
    )
    .await;
    let token = good_token(&r);
    let hook = r.w.state.expiry_hook.clone().unwrap();
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "a"),
        &[("keyring-notify", "alex@example.com")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // alex is over the limit, sam isn't: sam gets it, and it's done.
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "b"),
        &[("keyring-notify", "alex@example.com,sam@example.com")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hook.dedupe_len(), 2);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
    assert_eq!(
        r.acs.state.attempts()[1].body["recipients"]["to"],
        json!([{ "address": "sam@example.com" }])
    );
    // Outside the allow-list is permanent: 200, and remembered.
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "c"),
        &[("keyring-notify", "eve@evil.example")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hook.dedupe_len(), 3);
}

#[tokio::test]
async fn only_key_vault_topics_are_taken() {
    let r = rig().await;
    let token = good_token(&r);
    let sub = "/subscriptions/00000000-0000-0000-0000-000000000000";
    let base = eg::event("SecretNearExpiry", "Secret", "db-password", soon());
    let with_topic = |t: Option<String>| {
        let mut e = base.clone();
        match t {
            Some(t) => e["topic"] = json!(t),
            None => {
                e.as_object_mut().unwrap().remove("topic");
            }
        }
        json!([e])
    };
    let refused = [
        Some(format!(
            "{sub}/resourceGroups/rg/providers/Microsoft.EventGrid/topics/kv-test"
        )),
        Some(format!(
            "{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-other"
        )),
        None,
        Some(format!(
            "{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test/secrets/db-password"
        )),
        Some(format!(
            "{sub}/resourceGroups/rg/providers/Microsoft.EventGrid/systemTopics/kv-test"
        )),
    ];
    for t in refused {
        let (s, body) = send(&r, Some(&token), &with_topic(t.clone()), &[]).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{t:?}");
        assert_eq!(body, "", "{t:?}");
    }
    settle().await;
    assert!(r.acs.state.attempts().is_empty());
    // Any case is the same resource ID.
    let odd = format!(
        "{}/RESOURCEGROUPS/rg/PROVIDERS/microsoft.keyvault/VAULTS/KV-TEST",
        sub.to_ascii_uppercase()
    );
    let (s, _) = send(&r, Some(&token), &with_topic(Some(odd)), &[]).await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
}

#[tokio::test]
async fn off_unless_expiry_is_on() {
    // Email off.
    let w = support::world().await;
    let req = Request::post(HOOK)
        .header("content-type", "application/json")
        .body(Body::from("[]"))
        .unwrap();
    assert_eq!(
        w.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // Email on, expiry not.
    let r = rig_with(&[("KEYRING_NOTIFY_TYPES", "health")], |_| {}).await;
    assert!(r.w.state.expiry_hook.is_none());
    let (s, _) = send(
        &r,
        Some(&good_token(&r)),
        &one("SecretNearExpiry", "Secret", "a"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A path near it isn't the hook, and isn't exempt from the session
    // and Origin checks.
    let req = Request::post("/hooks/eventgrid/")
        .header("content-type", "application/json")
        .body(Body::from("[]"))
        .unwrap();
    assert_eq!(
        r.w.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn recipients_come_from_the_header_only_with_an_allow_list() {
    // No allow-list: the header is ignored, the admins get it.
    let r = rig().await;
    let token = good_token(&r);
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "a"),
        &[("keyring-notify", "team@example.com")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
    assert_eq!(
        r.acs.state.attempts()[0].body["recipients"]["to"],
        json!([{ "address": "ops@example.com" }])
    );

    // With an allow-list: the header's addresses, each held to it.
    let r = rig_with(&[("KEYRING_NOTIFY_ALLOWED_DOMAINS", "example.com")], |_| {}).await;
    let token = good_token(&r);
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "a"),
        &[("keyring-notify", "team@example.com,eve@evil.example")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
    assert_eq!(
        r.acs.state.attempts()[0].body["recipients"]["to"],
        json!([{ "address": "team@example.com" }])
    );
    // Only outside addresses: nobody to send to, nothing sent, still 200
    // (a retry wouldn't change it).
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "b"),
        &[("keyring-notify", "eve@evil.example")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // A malformed header is a bad delivery.
    for bad in ["Eve <eve@example.com>", "a@example.com\tBcc: b@example.com"] {
        let (s, _) = send(
            &r,
            Some(&token),
            &one("SecretNearExpiry", "Secret", "c"),
            &[("keyring-notify", bad)],
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    // No header: the admins.
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "d"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("two emails", || r.acs.state.attempts().len() == 2).await;
    assert_eq!(
        r.acs.state.attempts()[1].body["recipients"]["to"],
        json!([{ "address": "ops@example.com" }])
    );
    settle().await;
    assert_eq!(r.acs.state.attempts().len(), 2);
}

#[tokio::test]
async fn a_key_rollover_refetches_the_keys_once() {
    let r = rig().await;
    let token = good_token(&r);
    let (s, _) = send(
        &r,
        Some(&token),
        &one("SecretNearExpiry", "Secret", "a"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "keys cached");
    let hits = *r.w.idp.state.discovery_hits.lock().unwrap();
    *r.w.idp.state.rolled_over.lock().unwrap() = true;
    let rolled = eg::sign(&r.w.idp, &eg::claims_v1(&r.w.idp));
    let (s, _) = send(
        &r,
        Some(&rolled),
        &one("SecretNearExpiry", "Secret", "b"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "a new key is fetched");
    assert_eq!(*r.w.idp.state.discovery_hits.lock().unwrap(), hits + 1);
    // Unknown key IDs can't make Keyring fetch again and again.
    for _ in 0..3 {
        let t = eg::sign_with(
            &r.w.idp.state.key,
            json!({"alg": "RS256", "kid": "unknown"}),
            &eg::claims_v1(&r.w.idp),
        );
        let (s, _) = send(&r, Some(&t), &one("SecretNearExpiry", "Secret", "c"), &[]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(*r.w.idp.state.discovery_hits.lock().unwrap(), hits + 1);
    // And a token that fails its claims never causes a fetch.
    let mut c = eg::claims_v1(&r.w.idp);
    c.insert("aud".into(), json!("api://other"));
    let t = eg::sign_with(&r.w.idp.state.key, json!({"alg": "RS256", "kid": "x2"}), &c);
    let (s, _) = send(&r, Some(&t), &one("SecretNearExpiry", "Secret", "c"), &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(*r.w.idp.state.discovery_hits.lock().unwrap(), hits + 1);
}

#[tokio::test]
async fn a_set_audience_replaces_the_app_id_uri() {
    let r = rig_with(
        &[("KEYRING_EVENTGRID_AUDIENCE", "api://keyring-events")],
        |_| {},
    )
    .await;
    let (s, _) = send(
        &r,
        Some(&good_token(&r)),
        &one("SecretNearExpiry", "Secret", "a"),
        &[],
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "the app ID URI is no longer it"
    );
    let mut c = eg::claims_v1(&r.w.idp);
    c.insert("aud".into(), json!("api://keyring-events"));
    let (s, _) = send(
        &r,
        Some(&eg::sign(&r.w.idp, &c)),
        &one("SecretNearExpiry", "Secret", "a"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

const LISTED: &str = "00000000-0000-0000-0000-000000000000";
const UNLISTED: &str = "5ab1eaed-0bad-4bad-8bad-5ec0ffee5ab1";

/// The support event, with its vault in subscription `sub`.
fn in_subscription(name: &str, sub: &str) -> Value {
    let mut e = eg::event("SecretNearExpiry", "Secret", name, soon());
    e["topic"] = json!(format!(
        "/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test"
    ));
    e
}

#[tokio::test]
async fn only_listed_subscriptions_are_taken() {
    // Listed in another case, with a second entry and spaces.
    let list = format!(" 11111111-2222-3333-4444-555555555555 , {}", LISTED);
    let r = rig_with(&[("KEYRING_EVENTGRID_SUBSCRIPTIONS", &list)], |_| {}).await;
    let hook = r.w.state.expiry_hook.clone().unwrap();
    let token = good_token(&r);
    // Another subscription: 400 with no body, nothing sent, nothing
    // remembered.
    let (s, body) = send(
        &r,
        Some(&token),
        &json!([in_subscription("db-password", UNLISTED)]),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body, "");
    // A mixed batch with one event from an unlisted subscription is
    // refused whole.
    let (s, _) = send(
        &r,
        Some(&token),
        &json!([
            in_subscription("db-password", LISTED),
            in_subscription("other", UNLISTED)
        ]),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    settle().await;
    assert!(r.acs.state.attempts().is_empty(), "nothing sent");
    assert_eq!(hook.dedupe_len(), 0, "nothing remembered");
    // A topic that isn't a Key Vault ID is still bad_topic: same answer.
    let mut custom = in_subscription("db-password", UNLISTED);
    custom["topic"] = json!(format!(
        "/subscriptions/{UNLISTED}/resourceGroups/rg/providers/Microsoft.EventGrid/topics/kv-test"
    ));
    let (s, _) = send(&r, Some(&token), &json!([custom]), &[]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The listed subscription delivers, and its ID in upper case too.
    let (s, _) = send(
        &r,
        Some(&token),
        &json!([in_subscription("db-password", LISTED)]),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let upper = "0A1B2C3D-4E5F-6789-ABCD-EF0123456789";
    let r2 = rig_with(
        &[(
            "KEYRING_EVENTGRID_SUBSCRIPTIONS",
            &upper.to_ascii_lowercase(),
        )],
        |_| {},
    )
    .await;
    let (s, _) = send(
        &r2,
        Some(&good_token(&r2)),
        &json!([in_subscription("db-password", upper)]),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
    until("one email", || r2.acs.state.attempts().len() == 1).await;
}

#[tokio::test]
async fn with_no_list_any_subscription_is_taken() {
    let r = rig().await;
    assert_eq!(r.w.state.expiry_hook.as_ref().unwrap().subscriptions, None);
    let (s, _) = send(
        &r,
        Some(&good_token(&r)),
        &json!([in_subscription("db-password", UNLISTED)]),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    until("one email", || r.acs.state.attempts().len() == 1).await;
}

#[test]
fn a_bad_subscription_list_stops_start_up() {
    let base: Vec<(&str, &str)> = vec![
        ("ENTRA_TENANT_ID", support::TENANT),
        ("ENTRA_CLIENT_ID", support::CLIENT_ID),
        (
            "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
            support::IDENTITY_CLIENT_ID,
        ),
        ("IDENTITY_ENDPOINT", "http://127.0.0.1:9/token"),
        ("IDENTITY_HEADER", support::IDENTITY_HEADER),
        ("APP_BASE_URL", "http://localhost:3000"),
        (
            "SESSION_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "KEYRING_NOTIFY_ACS_ENDPOINT",
            "https://keyring-mail.australia.communication.azure.com",
        ),
        ("KEYRING_NOTIFY_SENDER", "DoNotReply@mail.example.com"),
        ("KEYRING_NOTIFY_TYPES", "expiry"),
    ];
    let load = |value: &str| {
        keyring::config::Config::from_lookup(|k| {
            if k == "KEYRING_EVENTGRID_SUBSCRIPTIONS" {
                return Some(value.to_owned());
            }
            base.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        })
    };
    assert!(load(LISTED).is_ok());
    for bad in ["SUBLISTLEAK", "00000000-0000-0000-0000-000000000000,", ","] {
        let err = load(bad).unwrap_err().to_string();
        assert!(err.contains("KEYRING_EVENTGRID_SUBSCRIPTIONS"), "{err}");
        assert!(!err.contains("SUBLISTLEAK"), "{err}");
    }
}
