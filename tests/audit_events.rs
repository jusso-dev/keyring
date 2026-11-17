//! Keyring's own audit events (`src/audit.rs`): every audited route writes
//! exactly one, for every outcome, and the JSON field names are pinned.
//!
//! Not Key Vault's audit log, which `tests/audit.rs` covers.
//!
//! One test in its own binary, like `no_secrets_in_logs`: `tracing` caches
//! whether a line is wanted, and tests running alongside without a
//! subscriber can switch lines off for this one.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

/// POST routes that write no audit event, each with why. Nothing here
/// changes or reads anything in Key Vault. A new POST route must either go
/// through `audited(...)` in `src/routes/mod.rs` or be added here with a
/// reason.
const EXEMPT: &[(&str, &str)] = &[
    (
        "/vaults/select",
        "chooses the vault for the session; nothing in Key Vault",
    ),
    (
        "/generator",
        "makes a random value in memory; nothing in Key Vault",
    ),
    (
        "/v/{vault}/certificates/-/upload",
        "preview: reads the file and holds it in memory; nothing sent to Key Vault",
    ),
    (
        "/v/{vault}/certificates/-/upload/cancel",
        "forgets the file held in memory; nothing sent to Key Vault",
    ),
    (
        "/v/{vault}/secrets/-/import",
        "preview: reads the file of secrets and holds it in memory; only lists names in Key Vault, nothing written or read back",
    ),
    (
        "/v/{vault}/secrets/-/import/cancel",
        "forgets the file of secrets held in memory; nothing sent to Key Vault",
    ),
    (
        "/v/{vault}/secrets/-/bulk",
        "bulk change review: lists names and properties only; nothing written or read back",
    ),
    (
        "/v/{vault}/certificates/-/bulk",
        "bulk change review: lists names and properties only; nothing written",
    ),
    (
        "/v/{vault}/keys/-/bulk",
        "bulk change review: lists names and properties only; nothing written",
    ),
    (
        "/v/{vault}/secrets/{name}",
        "only redirects an old form address",
    ),
    (
        "/v/{vault}/certificates/{name}",
        "only redirects an old form address",
    ),
    (
        "/v/{vault}/keys/{name}",
        "only redirects an old form address",
    ),
    (
        "/secrets",
        "old address: only redirects to the vault's own address",
    ),
    (
        "/secrets/{*rest}",
        "old address: only redirects to the vault's own address",
    ),
    (
        "/certificates",
        "old address: only redirects to the vault's own address",
    ),
    (
        "/certificates/{*rest}",
        "old address: only redirects to the vault's own address",
    ),
    (
        "/keys",
        "old address: only redirects to the vault's own address",
    ),
    (
        "/keys/{*rest}",
        "old address: only redirects to the vault's own address",
    ),
];

/// One route in `src/routes/mod.rs` that takes a POST.
#[derive(Debug)]
struct PostRoute {
    path: String,
    audited: bool,
}

/// Every route in the router that takes a POST, read from its source:
/// `audited(...)`, `post(...)` or `any(...)`. Routes in `vault_routes` are
/// nested under `/v/{vault}`.
fn post_routes() -> Vec<PostRoute> {
    let src = include_str!("../src/routes/mod.rs");
    let vault_start = src.find("fn vault_routes()").expect("vault_routes");
    let vault_end = src.find("pub fn router(").expect("router");
    let mut out = Vec::new();
    for (at, _) in src.match_indices(".route(") {
        // Skip the test module.
        if src[..at].contains("#[cfg(test)]") {
            continue;
        }
        let rest = &src[at + ".route(".len()..];
        // The route's own text, to its closing bracket.
        let mut depth = 1;
        let mut end = 0;
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &rest[..end];
        let q = body.find('"').expect("route path") + 1;
        let path = &body[q..q + body[q..].find('"').unwrap()];
        let audited = body.contains("audited(");
        let posts = audited || body.contains("post(") || body.contains("any(");
        if !posts {
            continue;
        }
        let path = if (vault_start..vault_end).contains(&at) {
            format!("/v/{{vault}}{path}")
        } else {
            path.to_owned()
        };
        out.push(PostRoute { path, audited });
    }
    out
}

/// A real address for a route, with names that exist in [`seeded`].
fn concrete(path: &str) -> String {
    let name = if path.contains("/secrets/-/deleted/") {
        "old-secret"
    } else if path.contains("/certificates/-/deleted/") {
        "old-cert"
    } else if path.contains("/keys/-/deleted/") {
        "old-key"
    } else if path.contains("/secrets/") {
        "db-password"
    } else if path.contains("/certificates/") {
        "web-tls"
    } else {
        "app-key"
    };
    path.replace("{vault}", "kv-test").replace("{name}", name)
}

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
    /// Audit events written since the last call, oldest first.
    fn take_events(&self) -> Vec<Value> {
        let bytes = std::mem::take(&mut *self.0.lock().unwrap());
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).expect("every line is JSON"))
            .filter(|v| v["kind"] == "audit")
            .collect()
    }

    fn one_event(&self, what: &str) -> Value {
        let mut events = self.take_events();
        assert_eq!(events.len(), 1, "{what}: {events:#?}");
        events.remove(0)
    }
}

async fn seeded(extra: &[(&'static str, &'static str)]) -> support::World {
    let mut env = vec![("KEYRING_ALLOW_PURGE", "true")];
    env.extend_from_slice(extra);
    let w = support::world_with(&env).await;
    let s = &w.kv.state;
    s.put("db-password", "one");
    s.put("db-password", "two");
    s.put("old-secret", "x");
    s.soft_delete("old-secret");
    s.add_cert("web-tls", true, "UEZY");
    s.add_cert("old-cert", false, "x");
    w.post(
        "/v/kv-test/certificates/old-cert/delete",
        &[("confirm_name", "old-cert")],
    )
    .await;
    s.add_key_with("app-key", "RSA", |_| {});
    s.add_key_with("old-key", "RSA", |_| {});
    w.post(
        "/v/kv-test/keys/old-key/delete",
        &[("confirm_name", "old-key")],
    )
    .await;
    w
}

/// POST a form with the given token and headers.
async fn post(
    w: &support::World,
    path: &str,
    csrf: &str,
    fields: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> StatusCode {
    let mut all = vec![("csrf", csrf)];
    all.extend_from_slice(fields);
    let body: String = openidconnect::url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(all)
        .finish();
    let mut req = Request::post(path)
        .header("cookie", &w.cookie)
        .header("content-type", "application/x-www-form-urlencoded");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = w
        .app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let _ = support::body_text(res).await;
    status
}

const SAME_SITE: (&str, &str) = ("origin", "http://localhost:3000");
const OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";

/// The field names of schema version 1, pinned. Changing this list needs a
/// new `SCHEMA_VERSION` and a CHANGELOG line.
const SCHEMA_V1_FIELDS: &[&str] = &[
    "action",
    "actor_oid",
    "actor_tid",
    "actor_upn",
    "client_ip",
    "event_id",
    "instance",
    "item_kind",
    "item_name",
    "item_version",
    "keyring_version",
    "kind",
    "kv_request_id",
    "level",
    "message",
    "outcome",
    "reason",
    "reason_code",
    "role",
    "role_duration",
    "role_scope",
    "schema_version",
    "session_ref",
    "ticket",
    "time",
    "user_agent",
    "vault",
];

/// The audit sink's columns, `COLUMNS` in `src/audit/sink.rs`, are the one
/// list: the Bicep stream and table must match it, and every schema field
/// must have a column. Fails if any of the three drift apart.
#[test]
fn sink_columns_match_the_bicep_and_the_schema() {
    use keyring::audit::sink::{COLUMNS, WRITER};
    let bicep = include_str!("../infra/modules/audit-sink.bicep");
    // `{ name: 'X', type: 'y' }` lines in the stream declaration.
    let start = bicep.find("var streamColumns = [").expect("streamColumns");
    let end = start + bicep[start..].find("\n]").expect("end of streamColumns");
    let declared: Vec<(String, String)> = bicep[start..end]
        .lines()
        .filter_map(|l| {
            let name = l.split("name: '").nth(1)?.split('\'').next()?;
            let kind = l.split("type: '").nth(1)?.split('\'').next()?;
            Some((name.to_owned(), kind.to_owned()))
        })
        .collect();
    let ours: Vec<(String, String)> = COLUMNS
        .iter()
        .map(|c| (c.stream.to_owned(), c.kind.to_owned()))
        .collect();
    assert_eq!(
        declared, ours,
        "infra/modules/audit-sink.bicep streamColumns"
    );
    // The table is the stream with `time` as TimeGenerated.
    assert!(bicep.contains("[{ name: 'TimeGenerated', type: 'datetime' }]"));
    assert!(bicep.contains("filter(streamColumns, c => c.name != 'time')"));
    assert!(bicep.contains("source | extend TimeGenerated = todatetime(time) | project-away time"));
    let time = COLUMNS.iter().find(|c| c.field == "time").unwrap();
    assert_eq!((time.name, time.stream), ("TimeGenerated", "time"));
    for c in COLUMNS.iter().filter(|c| c.field != "time") {
        assert_eq!(c.name, c.stream, "only time is renamed");
    }

    // Every schema field has a column, and every column is a schema field
    // or the writer. `kind`, `level` and `message` are log line fields.
    let fields: Vec<&str> = COLUMNS
        .iter()
        .map(|c| c.field)
        .filter(|f| *f != WRITER)
        .collect();
    let mut want: Vec<&str> = SCHEMA_V1_FIELDS
        .iter()
        .copied()
        .filter(|f| !matches!(*f, "kind" | "level" | "message"))
        .collect();
    let mut got = fields.clone();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want, "COLUMNS and SCHEMA_V1_FIELDS");
    // The writer and actor columns the issue names.
    for name in [
        "WriterIdentityClientId",
        "KeyringInstance",
        "KeyringVersion",
        "ActorObjectId",
        "ActorTenantId",
        "ActorUpn",
    ] {
        assert!(COLUMNS.iter().any(|c| c.name == name), "{name}");
    }
}

#[tokio::test]
async fn audited_routes_write_exactly_one_event() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(keyring::telemetry::filter(
            tracing_subscriber::filter::LevelFilter::WARN,
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .event_format(keyring::telemetry::JsonLines)
                .with_writer(capture.clone()),
        );
    let _guard = tracing::subscriber::set_default(subscriber);

    // --- Golden: the JSON field names of schema version 1 ---------------
    {
        use keyring::audit::{Action, AuditEvent, Outcome, SCHEMA_VERSION, record};
        assert_eq!(SCHEMA_VERSION, 1, "update SCHEMA_V1_FIELDS and CHANGELOG");
        let mut ev = AuditEvent::new(Action::SecretReveal, Outcome::Denied);
        ev.reason_code = Some("ForbiddenByRbac".into());
        ev.actor_oid = Some(OID.into());
        ev.actor_tid = Some("bbbbbbbb-0000-0000-0000-000000000002".into());
        ev.actor_upn = Some("alex@example.com".into());
        ev.session_ref = Some("ref".into());
        ev.client_ip = Some("203.0.113.7".into());
        ev.user_agent = Some("Agent \"x\"\nFORGED".into());
        ev.vault = Some("kv-test".into());
        ev.item_name = Some("db-password".into());
        ev.item_version = Some("abc".into());
        ev.kv_request_id = Some("11111111-2222-4333-8444-555555555555".into());
        ev.reason = Some("why".into());
        ev.ticket = Some("CHG-1".into());
        ev.role = Some("4633458b-17de-408a-b874-0445c86b69e6".into());
        ev.role_scope = Some("/subscriptions/s/resourceGroups/rg".into());
        ev.role_duration = Some("PT1H".into());
        record(ev.clone(), None);
        let raw = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_eq!(raw.lines().count(), 1, "one line, newline escaped: {raw}");
        let got = capture.one_event("golden");
        let keys: Vec<&str> = got
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, SCHEMA_V1_FIELDS, "schema version 1 field names");
        assert_eq!(got["kind"], "audit");
        assert_eq!(got["schema_version"], 1);
        assert_eq!(got["action"], "secret.reveal");
        assert_eq!(got["outcome"], "denied");
        assert_eq!(got["item_kind"], "secret");
        assert_eq!(got["user_agent"], "Agent \"x\"\nFORGED");
        assert_eq!(got["time"], ev.time.as_str());
        assert_eq!(got["event_id"], ev.event_id.as_str());
        assert_eq!(got["keyring_version"], env!("CARGO_PKG_VERSION"));
        // Absent fields are left out, not null.
        record(
            AuditEvent::new(Action::SessionSignOut, Outcome::Success),
            None,
        );
        let bare = capture.one_event("bare");
        let keys: Vec<&str> = bare
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "action",
                "event_id",
                "instance",
                "keyring_version",
                "kind",
                "level",
                "message",
                "outcome",
                "schema_version",
                "time"
            ]
        );
    }

    let w = seeded(&[]).await;
    capture.take_events();

    // --- Coverage: every POST route is audited or exempt with a reason --
    let routes = post_routes();
    assert!(routes.len() > 20, "parsed the router: {routes:#?}");
    for (path, reason) in EXEMPT {
        assert!(!reason.is_empty());
        let r = routes
            .iter()
            .find(|r| r.path == *path)
            .unwrap_or_else(|| panic!("{path} is exempt but no longer a POST route"));
        assert!(!r.audited, "{path} is audited, so take it off EXEMPT");
    }
    let audited: Vec<&PostRoute> = routes.iter().filter(|r| r.audited).collect();
    for r in &routes {
        assert!(
            r.audited || EXEMPT.iter().any(|(p, _)| *p == r.path),
            "{} takes a POST but writes no audit event. Use audited(...) in src/routes/mod.rs, or add it to EXEMPT with why",
            r.path
        );
    }

    // Each audited route writes one event on a forged form token, with
    // nothing reaching Key Vault.
    for r in &audited {
        let path = concrete(&r.path);
        let kv_calls = w.kv.state.log.lock().unwrap().len();
        let status = post(&w, &path, "forged", &[], &[SAME_SITE]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        let ev = capture.one_event(&path);
        assert_eq!(ev["outcome"], "refused", "{path}: {ev}");
        assert_eq!(ev["reason_code"], "csrf", "{path}: {ev}");
        assert_eq!(ev["actor_oid"], OID, "{path}");
        assert!(ev["session_ref"].is_string(), "{path}");
        assert_eq!(
            w.kv.state.log.lock().unwrap().len(),
            kv_calls,
            "{path} reached Key Vault"
        );
    }
    // And exempt routes write none.
    for (path, _) in EXEMPT {
        let path = concrete(path).replace("{*rest}", "x");
        let _ = post(&w, &path, &w.csrf, &[], &[SAME_SITE]).await;
        assert_eq!(capture.take_events(), Vec::<Value>::new(), "{path}");
    }

    // --- A successful reveal ---------------------------------------------
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE, ("user-agent", "TestBrowser/1.0")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ev = capture.one_event("reveal");
    assert_eq!(ev["action"], "secret.reveal");
    assert_eq!(ev["outcome"], "success");
    assert!(ev.get("reason_code").is_none(), "{ev}");
    assert_eq!(ev["vault"], "kv-test");
    assert_eq!(ev["item_kind"], "secret");
    assert_eq!(ev["item_name"], "db-password");
    assert!(ev["item_version"].is_string());
    assert_eq!(ev["user_agent"], "TestBrowser/1.0");
    assert_eq!(ev["actor_upn"], "alex@example.com");
    // The request ID is one Key Vault was sent, and every Key Vault call
    // got a different one.
    let sent = w.kv.state.client_request_ids.lock().unwrap().clone();
    let id = ev["kv_request_id"].as_str().unwrap();
    assert_eq!(sent.last().map(String::as_str), Some(id));
    let unique: std::collections::BTreeSet<&String> = sent.iter().collect();
    assert_eq!(unique.len(), sent.len(), "a new ID per call");
    assert!(sent.iter().all(|s| s.len() == 36));

    // --- A denied reveal (Key Vault 403) ----------------------------------
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE],
    )
    .await;
    *w.kv.state.fail.lock().unwrap() = None;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let ev = capture.one_event("denied reveal");
    assert_eq!(ev["action"], "secret.reveal");
    assert_eq!(ev["outcome"], "denied");
    assert_eq!(ev["reason_code"], "ForbiddenByRbac");
    assert!(ev["kv_request_id"].is_string());
    let text = ev.to_string();
    assert!(!text.contains("private detail"), "no Azure message: {text}");

    // --- Other failures from Key Vault -------------------------------------
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let _ = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE],
    )
    .await;
    *w.kv.state.fail.lock().unwrap() = None;
    let ev = capture.one_event("failed reveal");
    assert_eq!(ev["outcome"], "failed");
    assert_eq!(ev["reason_code"], "InternalError");

    // --- A typed-name mismatch --------------------------------------------
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/delete",
        &w.csrf,
        &[("confirm_name", "db-passwor")],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let ev = capture.one_event("typed name");
    assert_eq!(ev["action"], "secret.delete");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "typed_name_mismatch");
    assert_eq!(ev["item_name"], "db-password");
    assert!(w.kv.state.current("db-password").is_some(), "not deleted");

    // --- A delete that goes through ------------------------------------
    let status = post(
        &w,
        "/v/kv-test/keys/app-key/delete",
        &w.csrf,
        &[("confirm_name", "app-key")],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let ev = capture.one_event("key delete");
    assert_eq!(
        (ev["action"].as_str(), ev["outcome"].as_str()),
        (Some("key.delete"), Some("success"))
    );

    // --- A PIM activation: role, scope, duration, justification, ticket --
    {
        *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
        let rg = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
        {
            let mut m = w.arm.state.authz.lock().unwrap();
            m.pim.eligible = vec![(rg.into(), support::SECRETS_USER.into(), "/s/sched".into())];
            m.pim.policies.insert(
                support::SECRETS_USER.into(),
                support::pim_rules("PT8H", true, true, false),
            );
        }
        capture.take_events();
        let status = post(
            &w,
            "/v/kv-test/my-access/activate",
            &w.csrf,
            &[
                ("role", support::SECRETS_USER),
                ("minutes", "90"),
                ("justification", "Fix\nprod\u{202E} FORGED=1"),
                ("ticket_system", "SNOW"),
                ("ticket_number", "CHG-9"),
            ],
            &[SAME_SITE],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ev = capture.one_event("role activate");
        assert_eq!(ev["action"], "role.activate");
        assert_eq!(ev["outcome"], "success");
        assert_eq!(ev["vault"], "kv-test");
        assert_eq!(ev["role"], support::SECRETS_USER);
        assert_eq!(ev["role_scope"], rg);
        assert_eq!(ev["role_duration"], "PT1H30M");
        assert_eq!(ev["reason"], "Fix prod FORGED=1");
        assert_eq!(ev["ticket"], "SNOW CHG-9");
        assert!(ev.get("item_kind").is_none());
        // Waiting for approval still counts as done; a refusal is denied.
        w.arm.state.authz.lock().unwrap().pim.reply = Some((
            403,
            serde_json::json!({"error": {"code": "AuthorizationFailed", "message": "private detail"}}),
        ));
        let _ = post(
            &w,
            "/v/kv-test/my-access/activate",
            &w.csrf,
            &[
                ("role", support::SECRETS_USER),
                ("minutes", "60"),
                ("justification", "Fix prod now"),
                ("ticket_number", "1"),
            ],
            &[SAME_SITE],
        )
        .await;
        let ev = capture.one_event("refused activate");
        assert_eq!(ev["outcome"], "denied");
        assert_eq!(ev["reason_code"], "AuthorizationFailed");
        assert!(!ev.to_string().contains("private detail"));
        // Deactivate.
        {
            let mut m = w.arm.state.authz.lock().unwrap();
            m.pim.reply = None;
            m.pim.active = vec![(
                rg.into(),
                support::SECRETS_USER.into(),
                "Activated".into(),
                None,
            )];
        }
        let status = post(
            &w,
            "/v/kv-test/my-access/deactivate",
            &w.csrf,
            &[("role", support::SECRETS_USER), ("scope", rg)],
            &[SAME_SITE],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let ev = capture.one_event("role deactivate");
        assert_eq!(ev["action"], "role.deactivate");
        assert_eq!(ev["outcome"], "success");
        assert_eq!(ev["role_scope"], rg);
        assert!(ev.get("role_duration").is_none() && ev.get("reason").is_none());
        w.arm.state.authz.lock().unwrap().pim = Default::default();
    }

    // --- An import: one event for the request, one per secret written ---
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File(
                "file",
                ".env",
                b"NEW_ONE=a\ndb-password=b\nold-secret=c\n",
            )],
        )
        .await;
    let html = support::body_text(res).await;
    assert_eq!(
        capture.take_events(),
        Vec::<Value>::new(),
        "preview writes none"
    );
    let id = support::hidden_value(&html, "import_id").unwrap();
    let status = post(
        &w,
        "/v/kv-test/secrets/-/import/confirm",
        &w.csrf,
        &[("import_id", &id)],
        &[SAME_SITE, ("user-agent", "ImportBrowser/1.0")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = capture.take_events();
    assert_eq!(events.len(), 3, "two secrets and the request: {events:#?}");
    assert!(events.iter().all(|e| e["action"] == "secret.import"));
    assert!(events.iter().all(|e| e["actor_oid"] == OID
        && e["session_ref"].is_string()
        && e["user_agent"] == "ImportBrowser/1.0"
        && e["vault"] == "kv-test"
        && e["outcome"] == "success"));
    let mut items: Vec<&str> = events
        .iter()
        .filter_map(|e| e["item_name"].as_str())
        .collect();
    items.sort_unstable();
    assert_eq!(
        items,
        ["NEW-ONE", "db-password"],
        "old-secret is blocked, so not sent"
    );
    assert!(
        events
            .iter()
            .filter(|e| e.get("item_name").is_some())
            .all(|e| e["kv_request_id"].is_string())
    );
    // A refused write: its own event says denied, and so does the request.
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[support::Part::File("file", ".env", b"A=1\n")],
        )
        .await;
    let html = support::body_text(res).await;
    let id = support::hidden_value(&html, "import_id").unwrap();
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    let _ = post(
        &w,
        "/v/kv-test/secrets/-/import/confirm",
        &w.csrf,
        &[("import_id", &id)],
        &[SAME_SITE],
    )
    .await;
    *w.kv.state.fail.lock().unwrap() = None;
    let events = capture.take_events();
    assert_eq!(events.len(), 2, "{events:#?}");
    let item = events.iter().find(|e| e["item_name"] == "A").unwrap();
    assert_eq!(item["outcome"], "denied");
    assert_eq!(item["reason_code"], "ForbiddenByRbac");
    let whole = events
        .iter()
        .find(|e| e.get("item_name").is_none())
        .unwrap();
    assert_eq!(whole["outcome"], "denied");
    assert_eq!(whole["reason_code"], "none_written");
    assert!(!format!("{events:?}").contains("private detail"));

    // --- A bulk change: one event for the request, one per item ---------
    w.kv.state.put("bulk-a", "x");
    w.kv.state.put("bulk-b", "x");
    w.kv.state.put("bulk-gone", "x");
    w.kv.state.soft_delete("bulk-gone");
    w.kv.state.fail_each.lock().unwrap().push((
        axum::http::Method::PATCH,
        "/secrets/bulk-b/".into(),
        403,
        "ForbiddenByRbac",
    ));
    let status = post(
        &w,
        "/v/kv-test/secrets/-/bulk",
        &w.csrf,
        &[("item", "bulk-a"), ("op", "enable")],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        capture.take_events(),
        Vec::<Value>::new(),
        "the review writes none"
    );
    let status = post(
        &w,
        "/v/kv-test/secrets/-/bulk/apply",
        &w.csrf,
        &[
            ("item", "bulk-a"),
            ("item", "bulk-b"),
            ("item", "bulk-gone"),
            ("item", "web-tls"),
            ("op", "tag_set"),
            ("tag_name", "owner"),
            ("tag_value", "ops"),
        ],
        &[SAME_SITE, ("user-agent", "BulkBrowser/1.0")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    w.kv.state.fail_each.lock().unwrap().clear();
    let events = capture.take_events();
    assert_eq!(events.len(), 5, "four items and the request: {events:#?}");
    assert!(events.iter().all(|e| e["action"] == "secret.bulk_update"
        && e["actor_oid"] == OID
        && e["user_agent"] == "BulkBrowser/1.0"
        && e["vault"] == "kv-test"));
    let by = |name: &str| {
        events
            .iter()
            .find(|e| e["item_name"] == name)
            .unwrap_or_else(|| panic!("no event for {name}: {events:#?}"))
    };
    assert_eq!(by("bulk-a")["outcome"], "success");
    assert!(by("bulk-a")["kv_request_id"].is_string());
    assert_eq!(by("bulk-b")["outcome"], "denied");
    assert_eq!(by("bulk-b")["reason_code"], "ForbiddenByRbac");
    assert_eq!(by("bulk-gone")["outcome"], "failed");
    assert_eq!(by("bulk-gone")["reason_code"], "SecretNotFound");
    assert_eq!(by("web-tls")["outcome"], "refused");
    assert_eq!(by("web-tls")["reason_code"], "managed_item");
    let whole = events
        .iter()
        .find(|e| e.get("item_name").is_none())
        .unwrap();
    assert_eq!(whole["outcome"], "failed");
    assert_eq!(whole["reason_code"], "partly_changed");
    assert!(!format!("{events:?}").contains("private detail"));
    // Disable without the count typed: one refused event, nothing sent.
    let kv_calls = w.kv.state.log.lock().unwrap().len();
    let status = post(
        &w,
        "/v/kv-test/secrets/-/bulk/apply",
        &w.csrf,
        &[
            ("item", "bulk-a"),
            ("op", "disable"),
            ("confirm_count", "2"),
        ],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let ev = capture.one_event("bulk disable mismatch");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "typed_name_mismatch");
    assert_eq!(w.kv.state.log.lock().unwrap().len(), kv_calls);

    // --- A managed item -------------------------------------------------
    w.kv.state.put("managed-one", "x");
    w.kv.state
        .secrets
        .lock()
        .unwrap()
        .get_mut("managed-one")
        .unwrap()
        .managed = true;
    let status = post(
        &w,
        "/v/kv-test/secrets/managed-one/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let ev = capture.one_event("managed");
    assert_eq!(ev["reason_code"], "managed_item");

    // --- A cross-site post ----------------------------------------------
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[("origin", "https://evil.example")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let ev = capture.one_event("cross site");
    assert_eq!(ev["action"], "request.refused");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "cross_site");

    // --- Sign-out ---------------------------------------------------------
    let status = post(&w, "/auth/sign-out", &w.csrf, &[], &[SAME_SITE]).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let ev = capture.one_event("sign out");
    assert_eq!(ev["action"], "session.sign_out");
    assert_eq!(ev["outcome"], "success");
    assert_eq!(ev["actor_oid"], OID);
    // A post after that has no session.
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let ev = capture.one_event("no session");
    assert_eq!(ev["action"], "request.refused");
    assert_eq!(ev["reason_code"], "no_session");

    // --- Purge turned off -----------------------------------------------
    let w = support::world().await;
    w.kv.state.put("gone", "x");
    w.kv.state.soft_delete("gone");
    capture.take_events();
    let status = post(
        &w,
        "/v/kv-test/secrets/-/deleted/gone/purge",
        &w.csrf,
        &[("confirm_name", "gone")],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let ev = capture.one_event("purge off");
    assert_eq!(ev["action"], "secret.purge");
    assert_eq!(ev["reason_code"], "purge_disabled");

    // --- Sign-in, a failed sign-in and session expiry --------------------
    let w = support::world().await;
    capture.take_events();
    let get = |path: String, cookie: Option<String>| {
        let app = w.app.clone();
        async move {
            let mut req = Request::get(path);
            if let Some(c) = cookie {
                req = req.header("cookie", c);
            }
            app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
        }
    };
    let res = get("/auth/start?return_to=%2F".into(), None).await;
    let url = url::Url::parse(&support::location(&res)).unwrap();
    let login = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_login="))
        .unwrap();
    let q = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap()
    };
    *w.idp.state.nonce.lock().unwrap() = Some(q("nonce"));
    let res = get(
        format!("/auth/callback?code=abc&state={}", q("state")),
        Some(login),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let ev = capture.one_event("sign in");
    assert_eq!(ev["action"], "session.sign_in");
    assert_eq!(ev["outcome"], "success");
    assert_eq!(ev["actor_oid"], OID);
    assert!(ev["session_ref"].is_string());
    let res = get("/auth/callback?code=abc&state=forged".into(), None).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let ev = capture.one_event("sign in failed");
    assert_eq!(ev["action"], "session.sign_in_failed");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "stale_sign_in");
    assert!(ev.get("actor_oid").is_none(), "who isn't known yet");
    // Expiry, found by the sweep.
    let id = w.cookie.split('=').nth(1).unwrap();
    let session_ref = w.state.sessions.get(id).unwrap().audit_ref.clone();
    w.state
        .sessions
        .sweep_at(std::time::Instant::now() + keyring::auth::session::ABSOLUTE_TIMEOUT);
    let expired: Vec<Value> = capture
        .take_events()
        .into_iter()
        .filter(|e| e["session_ref"] == session_ref.as_str())
        .collect();
    assert_eq!(expired.len(), 1, "{expired:#?}");
    assert_eq!(expired[0]["action"], "session.expired");
    assert_eq!(expired[0]["actor_oid"], OID);

    // --- Step-up: a sensitive action sent off to confirm it's you ------
    let w = seeded(&[("KEYRING_STEP_UP_AUTH_CONTEXT", "c1")]).await;
    capture.take_events();
    let kv_calls = w.kv.state.log.lock().unwrap().len();
    let status = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let ev = capture.one_event("step-up required");
    assert_eq!(ev["action"], "secret.reveal");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "step_up_required");
    assert_eq!(ev["actor_oid"], OID);
    assert_eq!(ev["item_name"], "db-password");
    assert_eq!(
        w.kv.state.log.lock().unwrap().len(),
        kv_calls,
        "nothing reached Key Vault"
    );
    // The step-up sign-in comes back without the context: refused.
    let start = w
        .app
        .clone()
        .oneshot(
            Request::get("/auth/start?return_to=%2F&reason=step_up")
                .header("cookie", &w.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(&support::location(&start)).unwrap();
    let login = start
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|c| c.starts_with("keyring_login="))
        .unwrap();
    let q = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap()
    };
    *w.idp.state.nonce.lock().unwrap() = Some(q("nonce"));
    let res = w
        .app
        .clone()
        .oneshot(
            Request::get(format!("/auth/callback?code=abc&state={}", q("state")))
                .header("cookie", format!("{}; {login}", w.cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let ev = capture.one_event("step-up not met");
    assert_eq!(ev["action"], "session.sign_in_failed");
    assert_eq!(ev["outcome"], "refused");
    assert_eq!(ev["reason_code"], "step_up_not_met");
    assert_eq!(
        ev["actor_oid"], OID,
        "the ID token was verified, so who is known"
    );

    // --- The client's address behind a trusted proxy --------------------
    let w = seeded(&[("KEYRING_TRUSTED_PROXY_HOPS", "1")]).await;
    capture.take_events();
    let _ = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[
            SAME_SITE,
            ("x-forwarded-for", "198.51.100.1, 203.0.113.7:5123"),
        ],
    )
    .await;
    let ev = capture.one_event("proxy");
    assert_eq!(ev["client_ip"], "203.0.113.7");
    // Without trusted hops the header is ignored.
    let w = seeded(&[]).await;
    capture.take_events();
    let _ = post(
        &w,
        "/v/kv-test/secrets/db-password/reveal",
        &w.csrf,
        &[],
        &[SAME_SITE, ("x-forwarded-for", "203.0.113.7")],
    )
    .await;
    let ev = capture.one_event("no proxy");
    assert!(ev.get("client_ip").is_none(), "{ev}");
}
