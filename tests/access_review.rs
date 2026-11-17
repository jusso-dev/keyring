//! Access review: a page and a CSV per vault, with a row per secret,
//! certificate and key, against mock Key Vault, ARM and Log Analytics.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use support::{OWNER_ROLE, RawEvent, SECRETS_USER, settings_to, vault_row};

const VAULT: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";
const ALICE: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const BOB: &str = "dddddddd-0000-0000-0000-000000000004";
const CAROL: &str = "eeeeeeee-0000-0000-0000-000000000005";
const MI_APP: &str = "11111111-aaaa-4aaa-8aaa-111111111111";
const MI_OID: &str = "22222222-bbbb-4bbb-8bbb-222222222222";

fn a(scope: &str, role: &str, who: &str, kind: &str) -> (String, String, String, String) {
    (scope.into(), role.into(), who.into(), kind.into())
}

/// Words that would tell a reviewer an item is unused or safe to change.
const ASSURANCES: [&str; 8] = [
    "is unused",
    "isn't used",
    "not in use",
    "no one uses",
    "nobody uses",
    "nobody has access",
    "no one has access",
    "safe to",
];

fn no_assurance(text: &str) {
    let lower = text.to_ascii_lowercase().replace("&#39;", "'");
    for w in ASSURANCES {
        assert!(!lower.contains(w), "says {w:?}");
    }
}

/// kv-test with a secret, a certificate, a key, an untagged secret and a
/// disabled one; one workspace; access at the vault and on one item.
async fn world(dedicated: bool) -> support::World {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(settings_to("logs", dedicated));
    let s = &w.kv.state;
    s.put_with("db-password", "Sup3r-S3cret", |v| {
        v.tags.insert("owner".into(), "alex@example.com".into());
        v.tags.insert(
            "notify".into(),
            "ops@example.com,=sum(1)@example.com".into(),
        );
        v.tags
            .insert("description".into(), "=HYPERLINK(\"x\") main db".into());
        v.tags.insert("rotation".into(), "rotator\u{202E}fn".into());
        v.tags.insert("rotation-last".into(), "2026-11-02".into());
        v.tags.insert("rotation-status".into(), "failed".into());
        v.exp = Some(1_900_000_000);
    });
    s.put("quiet", "x");
    s.put_with("off", "x", |v| v.enabled = false);
    s.add_cert("web-tls", true, "UEZY");
    s.add_key_with("app-key", "RSA", |_| {});
    *w.arm.state.workspace_events.lock().unwrap() = vec![(
        "/workspaces/logs".into(),
        vec![
            RawEvent::new(
                "kv-test",
                "2026-11-10T10:00:00Z",
                "alex@example.com",
                "SecretGet",
                "db-password",
                200,
            ),
            RawEvent::new(
                "kv-test",
                "2026-11-11T10:00:00Z",
                "",
                "SecretGet",
                "db-password",
                200,
            )
            .by_app(MI_APP, MI_OID, true),
            // Refused: not a use.
            RawEvent::new(
                "kv-test",
                "2026-11-12T10:00:00Z",
                "eve@example.com",
                "SecretGet",
                "db-password",
                403,
            ),
            // The certificate's private key, through its backing secret.
            RawEvent::new(
                "kv-test",
                "2026-11-09T10:00:00Z",
                "sam@example.com",
                "SecretGet",
                "web-tls",
                200,
            ),
            RawEvent::new(
                "kv-test",
                "2026-11-08T10:00:00Z",
                "kim@example.com",
                "KeySign",
                "app-key",
                200,
            ),
            // Another vault.
            RawEvent::new(
                "kv-other",
                "2026-11-12T10:00:00Z",
                "lee@example.com",
                "SecretGet",
                "quiet",
                200,
            ),
        ],
    )];
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments = vec![
            a("/subscriptions/sub-a", OWNER_ROLE, ALICE, "User"),
            a(VAULT, SECRETS_USER, CAROL, "Group"),
            a(
                &format!("{VAULT}/secrets/db-password"),
                SECRETS_USER,
                BOB,
                "User",
            ),
        ];
    }
    w
}

async fn page(w: &support::World) -> String {
    let (status, html) = w.page("/v/kv-test/access/review").await;
    assert_eq!(status, StatusCode::OK);
    html.replace("&#39;", "'").replace("&#34;", "\"")
}

async fn get_csv(w: &support::World) -> (axum::http::HeaderMap, String) {
    let res = w.get("/v/kv-test/access/review.csv").await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    (h, support::body_text(res).await)
}

/// The table row for one item.
fn row<'a>(html: &'a str, name: &str) -> &'a str {
    let start = html
        .find(&format!(">{name}</a>"))
        .unwrap_or_else(|| panic!("no row for {name}"));
    let rest = &html[start..];
    &rest[..rest.find("</tr>").unwrap()]
}

/// The CSV line for one item, split on the commas outside quotes.
fn line(csv: &str, name: &str) -> Vec<String> {
    let l = csv
        .lines()
        .find(|l| l.split(',').nth(2) == Some(name))
        .unwrap_or_else(|| panic!("no line for {name}"));
    let mut out = vec![String::new()];
    let mut quoted = false;
    for c in l.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(String::new()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    out
}

fn notes(csv: &str) -> Vec<&str> {
    csv.lines().filter(|l| l.contains(",NOT READ,")).collect()
}

#[tokio::test]
async fn page_and_csv_agree_row_for_row() {
    for dedicated in [true, false] {
        let w = world(dedicated).await;
        let html = page(&w).await;
        let (headers, csv) = get_csv(&w).await;
        assert!(html.contains("aria-current=\"page\">Access review</a>"));
        assert!(
            html.contains("aria-current=\"page\">Access</a>"),
            "Access in the nav"
        );

        // Headers: CSV, not cached, named by vault and date.
        assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
        assert!(
            headers["cache-control"]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        let cd = headers["content-disposition"].to_str().unwrap();
        assert!(cd.starts_with("attachment; filename=\"keyring-access-review-kv-test-20"));
        assert!(cd.ends_with(".csv\""));
        assert!(csv.contains("\r\n"));
        assert!(csv.starts_with("Vault,Type,Name,Enabled,Expires (UTC),Owner,Notify,Description,Value changed (UTC),Days since,Band,Used by (last 90 days),Access on this item,Who has access,Rotation status,Rotated by,Last rotation\r\n"));

        // The same items, in the same order, on both.
        let names = ["db-password", "off", "quiet", "web-tls", "app-key"];
        let csv_names: Vec<String> = csv
            .lines()
            .skip(1)
            .filter(|l| !l.contains(",NOT READ,"))
            .map(|l| l.split(',').nth(2).unwrap().to_owned())
            .collect();
        let mut sorted = csv_names.clone();
        sorted.sort();
        let mut want: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(sorted, want, "every item once, no backing secret or key");
        let mut last = 0;
        for n in &csv_names {
            let at = html.find(&format!(">{n}</a>")).unwrap();
            assert!(at > last, "{n} in the same order");
            last = at;
        }

        // db-password: owner, notify, description, expiry, users, access,
        // rotation, on both.
        let r = row(&html, "db-password");
        assert!(r.contains("mailto:alex@example.com"));
        assert!(r.contains("main db"));
        assert!(r.contains("alex@example.com <span class=\"muted\">(Person, 1,"));
        assert!(r.contains(&format!(
            "{MI_APP} <span class=\"muted\">(Managed identity, 1,"
        )));
        assert!(!r.contains("eve@example.com"), "refused reads don't count");
        assert!(r.contains(BOB) && r.contains("As the vault, and:"));
        assert!(
            !r.contains(CAROL) && !r.contains(ALICE),
            "vault-wide access is once, above"
        );
        assert!(r.contains("badge badge-error\">Failed"));
        assert!(!r.contains('\u{202E}'), "rotation tags are cleaned");
        let l = line(&csv, "db-password");
        assert_eq!(l[0], "kv-test");
        assert_eq!(l[1], "Secret");
        assert_eq!(l[3], "Yes");
        assert_eq!(l[4], "2030-03-17");
        assert_eq!(l[5], "alex@example.com");
        assert_eq!(l[6], "ops@example.com,=sum(1)@example.com");
        assert!(
            csv.contains(",\"'=HYPERLINK(\"\"x\"\") main db\","),
            "formula guarded and quoted"
        );
        assert!(l[11].contains("alex@example.com (Person"));
        assert!(l[11].contains(&format!("{MI_APP} (Managed identity, object ID {MI_OID}")));
        assert!(!l[11].contains("eve@example.com"));
        assert!(l[12].starts_with(&format!("{BOB} (User): Key Vault Secrets User")));
        // The complete column has the vault's and the item's.
        for who in [ALICE, CAROL, BOB] {
            assert!(l[13].contains(who), "{who} in Who has access");
        }
        assert!(l[13].contains("at Subscription /subscriptions/sub-a"));
        assert_eq!(l[14], "Failed");
        assert_eq!(l[15], "rotatorfn");
        assert_eq!(l[16], "2 Nov 2026");

        // A certificate counts reads of its backing secret; a key its
        // operations.
        assert!(row(&html, "web-tls").contains("sam@example.com"));
        assert!(line(&csv, "web-tls")[11].contains("sam@example.com"));
        assert!(row(&html, "app-key").contains("kim@example.com"));
        assert!(line(&csv, "app-key")[11].contains("kim@example.com"));

        // An item with no uses in a complete answer: neutral words.
        assert!(row(&html, "quiet").contains("None found"));
        assert!(row(&html, "quiet").contains("As the vault"));
        assert!(
            !row(&html, "quiet").contains("lee@example.com"),
            "another vault"
        );
        let q = line(&csv, "quiet");
        assert_eq!(q[11], "None found in the available logs");
        assert_eq!(q[12], "As the vault");
        assert_eq!(q[14], "Not tagged");
        assert_eq!(line(&csv, "off")[3], "No");
        assert!(row(&html, "off").contains("Disabled"));

        // Vault-wide access once, above the table.
        let above = &html[..html.find("review-caption").unwrap()];
        assert!(above.contains(ALICE) && above.contains(CAROL));
        assert!(!above.contains(BOB), "item-scoped access is on its row");

        // The only notes: what was looked at.
        let n = notes(&csv);
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].contains("Looked at: the last 90 days in 1 of 1"));
        assert!(html.contains("Looked at: the last 90 days in 1 of 1 Log Analytics workspace"));

        // One query, as the person, and no value read.
        let queries = w.arm.state.audit_queries.lock().unwrap().clone();
        assert_eq!(
            queries.len(),
            2,
            "one per workspace, for the page and the CSV"
        );
        assert!(queries[0].starts_with("let vaultName = \"kv-test\";\n"));
        assert!(queries[0].contains("ago(90d)"));
        for b in w.arm.state.audit_bearers.lock().unwrap().iter() {
            assert!(b.starts_with("Bearer obo:https://api.loganalytics.io/.default"));
        }
        for b in w.arm.state.authz.lock().unwrap().bearers.iter() {
            assert!(b.starts_with("Bearer obo:"), "{b}");
        }
        assert!(w.kv.state.value_reads().is_empty());
        assert!(!html.contains("Sup3r-S3cret") && !csv.contains("Sup3r-S3cret"));
        assert!(!html.contains("UEZY") && !csv.contains("UEZY"));
        no_assurance(&html);
        no_assurance(&csv);
    }
}

#[tokio::test]
async fn one_query_per_workspace_however_many_items() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(json!({"value": [
        settings_to("logs", true)["value"][0].clone(),
        settings_to("logs-b", false)["value"][0].clone(),
    ]}));
    for i in 0..60 {
        w.kv.state.put(&format!("s-{i:02}"), "x");
    }
    let events = vec![RawEvent::new(
        "kv-test",
        "2026-11-10T10:00:00Z",
        "alex@example.com",
        "SecretGet",
        "s-07",
        200,
    )];
    *w.arm.state.workspace_events.lock().unwrap() = vec![
        ("/workspaces/logs".into(), events.clone()),
        ("/workspaces/logs-b".into(), events),
    ];
    let html = page(&w).await;
    let queries = w.arm.state.audit_queries.lock().unwrap().clone();
    assert_eq!(queries.len(), 2, "one per workspace, not one per item");
    assert!(queries.iter().any(|q| q.contains("AZKVAuditLogs")));
    assert!(queries.iter().any(|q| q.contains("AzureDiagnostics")));
    for q in &queries {
        assert!(!q.contains("s-07") && !q.contains("itemName"));
    }
    assert!(html.contains("in 2 of 2 Log Analytics workspaces"));
    // The same caller in both workspaces, added up.
    assert!(row(&html, "s-07").contains("(Person, 2,"));
}

#[tokio::test]
async fn caps_are_said_on_the_page_and_in_the_csv() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(settings_to("logs", true));
    w.kv.state.put("busy", "x");
    w.kv.state.put("other", "x");
    let mut events: Vec<RawEvent> = (0..25)
        .map(|i| {
            RawEvent::new(
                "kv-test",
                &format!("2026-11-{:02}T10:00:00Z", i + 1),
                &format!("p{i:02}@example.com"),
                "SecretGet",
                "busy",
                200,
            )
        })
        .collect();
    // Enough item and caller pairs to pass the overall cap: one use each
    // of many items the vault no longer has, sorting after "busy".
    let max = keyring::azure::access_review::MAX_ROWS;
    for i in 0..max {
        events.push(RawEvent::new(
            "kv-test",
            "2026-11-01T10:00:00Z",
            "",
            "SecretGet",
            &format!("zz-{i:04}"),
            200,
        ));
    }
    w.kv.state.put("zz-9999", "x");
    *w.arm.state.workspace_events.lock().unwrap() = vec![("/workspaces/logs".into(), events)];
    let html = page(&w).await;
    let busy = row(&html, "busy");
    assert_eq!(busy.matches("(Person,").count(), 20, "the 20 most recent");
    assert!(busy.contains("p24@example.com") && !busy.contains("p04@example.com"));
    assert!(busy.contains("More not listed"));
    assert!(html.contains(&format!("more than {max} item and caller pairs")));
    let (_, csv) = get_csv(&w).await;
    let b = line(&csv, "busy");
    assert!(b[11].contains("and more: only the 20 most recent are listed"));
    assert!(
        notes(&csv)
            .iter()
            .any(|n| n.contains(&format!("more than {max} item and caller pairs")))
    );
    // Past where the answer was cut: not known, never "none found".
    assert_eq!(
        line(&csv, "zz-9999")[11],
        "NOT KNOWN: see the notes at the end"
    );
    // "other" wasn't used: with a gap in the log, it's not known rather
    // than none.
    assert_eq!(
        line(&csv, "other")[11],
        "NOT KNOWN: see the notes at the end"
    );
    assert!(row(&html, "other").contains("Not known"));
}

/// Each "used by" gap: said once at the top, every empty cell "Not known"
/// on the page and in the CSV, never "None found".
async fn check_usage_gap(w: &support::World, top: &str) {
    let html = page(w).await;
    assert!(html.contains(top), "page says {top:?}");
    assert!(row(&html, "quiet").contains("Not known"));
    assert!(!html.contains(">None found<"));
    let (_, csv) = get_csv(w).await;
    assert!(
        notes(&csv).iter().any(|n| n.contains(top)),
        "csv says {top:?}: {csv}"
    );
    assert_eq!(
        line(&csv, "quiet")[11],
        "NOT KNOWN: see the notes at the end"
    );
    assert!(!csv.contains("None found"));
    no_assurance(&html);
    no_assurance(&csv);
}

#[tokio::test]
async fn no_diagnostic_setting() {
    let w = world(true).await;
    *w.arm.state.diagnostics.lock().unwrap() = Some(json!({"value": []}));
    check_usage_gap(
        &w,
        "This vault doesn't send its audit log to a Log Analytics workspace",
    )
    .await;
    assert!(w.arm.state.audit_queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn diagnostic_settings_not_readable() {
    let w = world(true).await;
    *w.arm.state.diagnostics.lock().unwrap() = None;
    check_usage_gap(&w, "You can't read this vault's diagnostic settings").await;
}

#[tokio::test]
async fn a_workspace_the_person_cant_read() {
    let w = world(true).await;
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs".into(), 403)];
    check_usage_gap(
        &w,
        "You don't have access to the Log Analytics workspace this vault logs to",
    )
    .await;
}

#[tokio::test]
async fn no_events_from_the_vault_yet() {
    let w = world(true).await;
    *w.arm.state.workspace_events.lock().unwrap() = vec![("/workspaces/logs".into(), vec![])];
    check_usage_gap(&w, "No audit events from this vault have arrived").await;
}

#[tokio::test]
async fn a_missing_table_is_no_events_yet() {
    let w = world(true).await;
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs".into(), 400)];
    check_usage_gap(&w, "No audit events from this vault have arrived").await;
}

#[tokio::test]
async fn a_partial_answer() {
    let w = world(true).await;
    *w.arm.state.used_by_partial.lock().unwrap() = true;
    check_usage_gap(&w, "Log Analytics returned only part of the answer").await;
    // What was found still shows, with a warning that there may be more.
    let (_, csv) = get_csv(&w).await;
    let l = line(&csv, "db-password");
    assert!(l[11].contains("alex@example.com") && l[11].contains("there may be others"));
}

#[tokio::test]
async fn one_of_two_workspaces_failing() {
    let w = world(true).await;
    *w.arm.state.diagnostics.lock().unwrap() = Some(json!({"value": [
        settings_to("logs", true)["value"][0].clone(),
        settings_to("logs-b", false)["value"][0].clone(),
    ]}));
    *w.arm.state.audit_fail_workspace.lock().unwrap() = vec![("/workspaces/logs-b".into(), 500)];
    check_usage_gap(
        &w,
        "1 of 2 Log Analytics workspaces this vault logs to couldn't be read",
    )
    .await;
    let html = page(&w).await;
    assert!(html.contains("in 1 of 2 Log Analytics workspaces"));
}

#[tokio::test]
async fn a_slow_workspace_still_returns_the_page() {
    let w = support::world_within(keyring::azure::fanout::Limits {
        concurrency: 2,
        vault_timeout: Duration::from_millis(300),
        deadline: Duration::from_secs(2),
    })
    .await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(settings_to("logs", true));
    w.kv.state.put("quiet", "x");
    *w.arm.state.workspace_delay.lock().unwrap() =
        vec![("/workspaces/logs".into(), Duration::from_secs(5))];
    let start = std::time::Instant::now();
    check_usage_gap(&w, "so Keyring can't tell who used these items").await;
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// Each access gap: said at the top, the column "Not known", never an
/// empty "nobody".
#[tokio::test]
async fn access_that_cant_be_read() {
    // Role assignments refused.
    let w = world(true).await;
    w.arm.state.authz.lock().unwrap().assignments_forbidden = true;
    let html = page(&w).await;
    assert!(html.contains("You can't read the role assignments here"));
    assert!(row(&html, "db-password").contains("Not known"));
    assert!(!row(&html, "quiet").contains("As the vault"));
    let (_, csv) = get_csv(&w).await;
    let l = line(&csv, "quiet");
    assert_eq!(l[12], "NOT KNOWN: see the notes at the end");
    assert!(l[13].starts_with("NOT KNOWN: role assignments couldn't be read"));
    assert!(
        notes(&csv)
            .iter()
            .any(|n| n.contains("Access: You can't read the role assignments here"))
    );
    no_assurance(&html);

    // The vault resource refused.
    let w = world(true).await;
    w.arm.state.authz.lock().unwrap().vault_forbidden = true;
    let html = page(&w).await;
    assert!(html.contains("You can't read this vault's settings in Azure"));
    let (_, csv) = get_csv(&w).await;
    assert_eq!(
        line(&csv, "quiet")[13],
        "NOT KNOWN: see the notes at the end"
    );
    assert!(
        notes(&csv)
            .iter()
            .any(|n| n.contains("Access: You can't read this vault's settings"))
    );

    // Role definitions and eligibility not read: said, and the roles
    // marked.
    let w = world(true).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.definitions_status = Some(500);
        m.eligible_status = Some(403);
    }
    let html = page(&w).await;
    assert!(html.contains("Role not read"));
    assert!(html.contains("Eligible (PIM) assignments aren't listed"));
    let (_, csv) = get_csv(&w).await;
    assert!(line(&csv, "quiet")[13].contains("Role not read"));
    assert!(
        notes(&csv)
            .iter()
            .any(|n| n.contains("Eligible (PIM) assignments aren't listed"))
    );
    assert!(notes(&csv).iter().any(|n| n.contains("couldn't look up")));
}

#[tokio::test]
async fn an_access_policy_vault() {
    let w = world(true).await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", false)];
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.policies.insert(
            "kv-test".into(),
            json!([
                {"tenantId": support::TENANT, "objectId": ALICE, "permissions": {"secrets": ["Get", "List"], "keys": [], "certificates": []}},
                {"tenantId": support::TENANT, "objectId": BOB, "permissions": {"keys": ["sign"]}}
            ]),
        );
        m.assignments = vec![a("/subscriptions/sub-a", OWNER_ROLE, CAROL, "User")];
    }
    let html = page(&w).await;
    assert!(html.contains("uses <strong>access policies</strong>"));
    assert!(html.contains("Reads secret values"));
    let (_, csv) = get_csv(&w).await;
    let s = line(&csv, "quiet");
    assert!(s[13].contains(&format!("{ALICE}: access policy, read values, list")));
    assert!(
        !s[13].contains(BOB),
        "a keys-only policy doesn't reach a secret"
    );
    assert!(s[13].contains(&format!("{CAROL} (User): Owner, can grant itself access")));
    let k = line(&csv, "app-key");
    assert!(k[13].contains(&format!("{BOB}: access policy, sign")));
    assert!(!k[13].contains(ALICE));
}

#[tokio::test]
async fn a_vault_with_no_items() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(settings_to("logs", true));
    let html = page(&w).await;
    assert!(html.contains("This vault has no secrets, certificates or keys you can list."));
    assert!(!html.contains("review-caption\">"));
    let (_, csv) = get_csv(&w).await;
    assert_eq!(csv.lines().filter(|l| !l.contains(",NOT READ,")).count(), 1);
}

#[tokio::test]
async fn lists_that_cant_be_read_are_said() {
    let w = world(true).await;
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let html = page(&w).await;
    assert!(html.contains("couldn't be listed: You don't have a Key Vault role on it"));
    assert!(html.contains("Keyring couldn't list this vault's secrets"));
    let (_, csv) = get_csv(&w).await;
    assert!(
        notes(&csv)
            .iter()
            .any(|n| n.contains("Items not read aren't in this file"))
    );
}

#[tokio::test]
async fn many_item_assignments_are_capped_in_the_csv_cell() {
    let w = world(true).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        for i in 0..55 {
            m.assignments.push(a(
                VAULT,
                SECRETS_USER,
                &format!("ffffffff-0000-0000-0000-{i:012}"),
                "User",
            ));
        }
    }
    let (_, csv) = get_csv(&w).await;
    let l = line(&csv, "quiet");
    assert!(
        l[13].ends_with("more: see the vault's Access CSV for the full list"),
        "{}",
        l[13]
    );
}

#[tokio::test]
async fn reached_from_the_access_page() {
    let w = world(true).await;
    let (_, html) = w.page("/v/kv-test/access").await;
    assert!(html.contains("href=\"/v/kv-test/access/review\">Access review</a>"));
    let res = w.get("/v/bad%20name/access/review").await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
