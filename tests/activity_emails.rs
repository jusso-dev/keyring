//! Activity emails (#259): watched reads, deletes and bulk changes, and
//! role use, through the app against mock Key Vault, ARM and ACS, with the
//! audit sink off.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::acs::{self, MockAcs};
use support::{IDENTITY_CLIENT_ID, IDENTITY_HEADER, SECRETS_USER, pim_rules};

const VAULT_ID: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";
const RG: &str = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
const SCHEDULE: &str = "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/b1477448-2cc6-4ceb-93b4-54a202a89413";

async fn world_with(types: &str, extra: &[(&'static str, &str)]) -> (support::World, MockAcs) {
    let acs = acs::start().await;
    let identity = support::start_identity().await;
    let mut env = vec![
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
        ("KEYRING_NOTIFY_TYPES", types.to_owned()),
        ("KEYRING_NOTIFY_ADMINS", "ops@example.com".to_owned()),
        ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
    ];
    for (k, v) in extra {
        env.push((k, (*v).to_owned()));
    }
    let w = support::world_configured(env, |c| {
        let t = &mut c.notify.as_mut().unwrap().tuning;
        t.backoff_first = Duration::from_millis(10);
        t.poll_wait_default = Duration::from_millis(10);
        t.poll_wait_max = Duration::from_millis(20);
    })
    .await;
    assert!(w.state.audit_sink.is_none(), "the audit sink is off");
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    // Leak the identity mock: it must outlive the world.
    std::mem::forget(identity);
    (w, acs)
}

fn tag(w: &support::World, name: &str, k: &str, v: &str) {
    w.kv.state
        .secrets
        .lock()
        .unwrap()
        .get_mut(name)
        .unwrap()
        .versions
        .last_mut()
        .unwrap()
        .tags
        .insert(k.into(), v.into());
}

fn owners(w: &support::World, value: &str) {
    let mut row = support::vault_row("kv-test", "sub-a", true);
    row["tags"]["keyring-owners"] = json!(value);
    *w.arm.state.vaults.lock().unwrap() = vec![row];
}

/// Wait until `n` emails were sent, then a little more, and return them.
async fn mails(acs: &MockAcs, n: usize) -> Vec<Value> {
    let start = std::time::Instant::now();
    while acs.state.attempts().len() < n {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "waited for {n} emails, got {}",
            acs.state.attempts().len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    acs.state.attempts().into_iter().map(|a| a.body).collect()
}

/// No email arrives in a short while.
async fn none(acs: &MockAcs) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(acs.state.attempts().len(), 0, "{}", acs.state.all_bodies());
}

fn to(m: &Value) -> Vec<String> {
    m["recipients"]["to"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["address"].as_str().unwrap().to_owned())
        .collect()
}

fn text(m: &Value) -> String {
    m["content"]["plainText"].as_str().unwrap().to_owned()
}

async fn reveal(w: &support::World) -> StatusCode {
    let res = w.post("/v/kv-test/secrets/db-password/reveal", &[]).await;
    let s = res.status();
    let _ = support::body_text(res).await;
    s
}

#[tokio::test]
async fn a_watched_reveal_emails_the_notify_list_not_the_actor() {
    let (w, acs) = world_with("watched-reads", &[]).await;
    w.kv.state.put("db-password", "VALUELEAK");
    tag(
        &w,
        "db-password",
        "notify",
        "sam@example.com, alex@example.com",
    );
    tag(&w, "db-password", "owner", "own@example.com");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    let m = mails(&acs, 1).await;
    assert_eq!(m.len(), 1);
    // Not the actor, and not the owner (the setting is off).
    assert_eq!(to(&m[0]), ["sam@example.com"]);
    let t = text(&m[0]);
    assert!(t.contains("Who: alex@example.com"), "{t}");
    assert!(t.contains("What: revealed a secret's value"), "{t}");
    assert!(t.contains("Item: secret db-password"), "{t}");
    assert!(
        t.contains("http://localhost:3000/v/kv-test/audit?range=24h&item=db-password"),
        "{t}"
    );
    assert_eq!(
        m[0]["content"]["subject"],
        "[Keyring] Watched item read: secret db-password in kv-test"
    );
    assert!(!acs.state.all_bodies().contains("VALUELEAK"));
    assert!(acs.state.violations().is_empty());
}

#[tokio::test]
async fn the_owner_gets_it_with_the_setting_and_the_actor_when_alone() {
    let (w, acs) = world_with("watched-reads", &[("KEYRING_NOTIFY_OWNER_ON_READ", "true")]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "owner", "own@example.com");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["own@example.com"]);

    // The actor is the only address left: they get it.
    let (w, acs) = world_with("watched-reads", &[]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "notify", "Alex+watch@Example.com");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["Alex+watch@example.com"]);
}

#[tokio::test]
async fn untagged_denied_and_off_send_nothing() {
    // Untagged.
    let (w, acs) = world_with("watched-reads", &[]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "env", "prod");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    none(&acs).await;
    // Denied by Key Vault.
    tag(&w, "db-password", "notify", "sam@example.com");
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    assert_eq!(reveal(&w).await, StatusCode::FORBIDDEN);
    none(&acs).await;
    // The owner only, with the setting off.
    let (w, acs) = world_with("watched-reads", &[]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "owner", "own@example.com");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    none(&acs).await;
    // The type is off.
    let (w, acs) = world_with("destructive", &[]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "notify", "sam@example.com");
    assert_eq!(reveal(&w).await, StatusCode::OK);
    none(&acs).await;
}

#[tokio::test]
async fn one_item_read_in_a_loop_sends_a_few_an_hour() {
    use keyring::notify::activity::READS_PER_ITEM_PER_HOUR;
    let (w, acs) = world_with("watched-reads", &[]).await;
    w.kv.state.put("db-password", "v");
    tag(&w, "db-password", "notify", "sam@example.com");
    for _ in 0..READS_PER_ITEM_PER_HOUR + 5 {
        assert_eq!(reveal(&w).await, StatusCode::OK);
    }
    let m = mails(&acs, READS_PER_ITEM_PER_HOUR).await;
    assert_eq!(m.len(), READS_PER_ITEM_PER_HOUR, "the per-item limit");
}

#[tokio::test]
async fn the_other_watched_reads_send() {
    let (w, acs) = world_with("watched-reads", &[]).await;
    // Rollback.
    let first = w.kv.state.put("db-password", "one");
    w.kv.state.put("db-password", "two");
    tag(&w, "db-password", "notify", "sam@example.com");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/rollback",
            &[("version", &first)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let m = mails(&acs, 1).await;
    assert!(
        text(&m[0]).contains("rolled a secret back"),
        "{}",
        text(&m[0])
    );
    // Private key download.
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state
        .certs
        .lock()
        .unwrap()
        .get_mut("web-tls")
        .unwrap()
        .versions
        .last_mut()
        .unwrap()
        .tags
        .insert("notify".into(), "sam@example.com".into());
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let m = mails(&acs, 2).await;
    assert!(
        text(&m[1]).contains("downloaded a certificate's private key"),
        "{}",
        text(&m[1])
    );
}

#[tokio::test]
async fn a_delete_emails_the_vault_owners_or_the_admins() {
    let (w, acs) = world_with("destructive", &[]).await;
    owners(&w, "lead@example.com; alex@example.com");
    w.kv.state.put("db-password", "v");
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["lead@example.com"], "the owners, not the actor");
    assert!(text(&m[0]).contains("What: deleted a secret"));

    // No owners tag: the admins.
    let (w, acs) = world_with("destructive", &[]).await;
    w.kv.state.put("db-password", "v");
    let _ = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["ops@example.com"]);

    // Resource Graph fails: the admins, and nothing says why.
    let (w, acs) = world_with("destructive", &[]).await;
    *w.arm.state.fail.lock().unwrap() = Some((403, "AuthorizationFailed"));
    w.kv.state.put("db-password", "v");
    let _ = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "db-password")],
        )
        .await;
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["ops@example.com"]);
    assert!(!acs.state.all_bodies().contains("AuthorizationFailed"));

    // A refused delete (wrong name) sends nothing.
    let (w, acs) = world_with("destructive", &[]).await;
    w.kv.state.put("db-password", "v");
    let _ = w
        .post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "nope")],
        )
        .await;
    none(&acs).await;
}

#[tokio::test]
async fn a_bulk_change_is_one_email_with_up_to_50_names() {
    let (w, acs) = world_with("destructive", &[]).await;
    owners(&w, "lead@example.com");
    let names: Vec<String> = (0..60).map(|i| format!("s{i:02}")).collect();
    for n in &names {
        w.kv.state.put(n, "v");
    }
    let mut f: Vec<(&str, &str)> = names.iter().map(|n| ("item", n.as_str())).collect();
    f.extend([
        ("op", "tag_set"),
        ("tag_name", "rota"),
        ("tag_value", "TAGLEAK"),
    ]);
    let res = w.post("/v/kv-test/secrets/-/bulk/apply", &f).await;
    assert_eq!(res.status(), StatusCode::OK);
    let _ = support::body_text(res).await;
    let m = mails(&acs, 1).await;
    assert_eq!(m.len(), 1, "one email for the request");
    let t = text(&m[0]);
    assert!(t.contains("Changed: 60"), "{t}");
    assert!(t.contains("- s00\n") && t.contains("- s49\n"), "{t}");
    assert!(!t.contains("- s50"), "{t}");
    assert!(t.contains("and 10 more"), "{t}");
    assert!(!acs.state.all_bodies().contains("TAGLEAK"));
}

#[tokio::test]
async fn role_use_emails_the_owners_with_role_scope_and_duration() {
    let (w, acs) = world_with("role-use", &[]).await;
    owners(&w, "lead@example.com");
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible = vec![(RG.into(), SECRETS_USER.into(), SCHEDULE.into())];
        m.pim
            .policies
            .insert(SECRETS_USER.into(), pim_rules("PT8H", true, false, false));
    }
    let res = w
        .post(
            "/v/kv-test/my-access/activate",
            &[
                ("role", SECRETS_USER),
                ("scope", RG),
                ("schedule", SCHEDULE),
                ("back", "/v/kv-test/secrets"),
                ("minutes", "90"),
                ("justification", "JUSTIFYLEAK https://evil.example/"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let m = mails(&acs, 1).await;
    assert_eq!(to(&m[0]), ["lead@example.com"]);
    let t = text(&m[0]);
    assert!(t.contains("Role: Key Vault Secrets User"), "{t}");
    assert!(t.contains(&format!("Scope: {RG}")), "{t}");
    assert!(t.contains("For: 1 hour 30 minutes"), "{t}");
    assert!(t.contains("Justification: Given."), "{t}");
    assert!(!acs.state.all_bodies().contains("JUSTIFYLEAK"));
    assert!(!acs.state.all_bodies().contains("evil.example"));
    let _ = VAULT_ID;
}
