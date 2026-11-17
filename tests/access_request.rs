//! Request access from the 403 page (#258), against mock ARM, Key Vault and
//! ACS: shown only with no PIM offer and access requests on, emailed to the
//! vault's owners (or the admins) with a copy to the requester, one per
//! person, vault and role an hour.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use support::acs::{self, MockAcs};
use support::{SECRETS_USER, body_text, hidden_value};

const VAULT_ID: &str = "/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";
const REVEAL: &str = "/v/kv-test/secrets/db-password/reveal";
const FORM: &str = "/v/kv-test/my-access/request";

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
        }
    }
}

async fn rig_with(types: &str, owners: Option<&str>, extra: &[(&'static str, &str)]) -> Rig {
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
        ("KEYRING_NOTIFY_TYPES", types.to_owned()),
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
    })
    .await;
    let mut row = support::vault_row("kv-test", "00000000-0000-0000-0000-00000000000a", true);
    if let Some(o) = owners {
        row["tags"] = json!({"env": "prod", "keyring-owners": o});
    }
    *w.arm.state.vaults.lock().unwrap() = vec![row];
    w.kv.state.put("db-password", "VALUE-1");
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    Rig { w, acs, _mi: mi }
}

async fn rig(owners: Option<&str>) -> Rig {
    rig_with("access-requests", owners, &[]).await
}

async fn refused_page(w: &support::World) -> String {
    let res = w.post(REVEAL, &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    body_text(res).await
}

fn fields<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut f = vec![
        ("role", SECRETS_USER),
        ("scope", "item"),
        ("kind", "secret"),
        ("name", "db-password"),
        ("back", "/v/kv-test/secrets/db-password"),
        ("reason", "Fixing INC-42 in production"),
        ("ticket", "CHG-42"),
    ];
    for (k, v) in extra {
        f.retain(|(n, _)| n != k);
        f.push((k, v));
    }
    f
}

async fn until_mail(r: &Rig, n: usize) -> Vec<serde_json::Value> {
    let start = std::time::Instant::now();
    while r.acs.state.attempts().len() < n {
        assert!(start.elapsed() < Duration::from_secs(5), "{n} emails");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    r.acs.state.attempts().into_iter().map(|a| a.body).collect()
}

fn recipients(body: &serde_json::Value) -> Vec<String> {
    body["recipients"]["to"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["address"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn no_pim_offer_shows_request_access() {
    let r = rig(Some("owner@example.com")).await;
    let html = refused_page(&r.w).await;
    assert!(html.contains("What to ask for:"));
    assert!(html.contains(">Request access</a>"), "{html}");
    assert!(html.contains(&format!(
        "{FORM}?role={SECRETS_USER}&#38;kind=secret&#38;name=db-password&#38;back="
    )));
    assert!(!html.contains("Activate"));
    // The form names the role and offers the item or the vault.
    let (status, form) = r
        .w
        .page(&format!(
            "{FORM}?role={SECRETS_USER}&kind=secret&name=db-password&back=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password"
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(form.contains("Key Vault Secrets User"));
    assert!(form.contains("Only the secret db-password"));
    assert!(form.contains("The whole vault kv-test"));
    assert_eq!(hidden_value(&form, "role").as_deref(), Some(SECRETS_USER));
    // Not the vault's owners on the page.
    assert!(!form.contains("owner@example.com"));
}

#[tokio::test]
async fn a_pim_offer_shows_instead() {
    let r = rig(Some("owner@example.com")).await;
    {
        let mut m = r.w.arm.state.authz.lock().unwrap();
        m.pim.eligible = vec![(
            "/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/rg-kv-test".into(),
            SECRETS_USER.into(),
            "/subscriptions/x/providers/Microsoft.Authorization/roleEligibilitySchedules/s".into(),
        )];
    }
    let html = refused_page(&r.w).await;
    assert!(
        html.contains(">Activate Key Vault Secrets User</a>"),
        "{html}"
    );
    assert!(!html.contains("Request access"));
}

#[tokio::test]
async fn off_unless_access_requests_is_on() {
    let r = rig_with("expiry", Some("owner@example.com"), &[]).await;
    let html = refused_page(&r.w).await;
    assert!(!html.contains("Request access"), "{html}");
    let (status, _) = r.w.page(&format!("{FORM}?role={SECRETS_USER}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let res = r.w.post(FORM, &fields(&[])).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(r.acs.state.attempts().is_empty());
    // Email off altogether: the 403 page as before.
    let plain = support::world().await;
    *plain.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    plain.kv.state.put("db-password", "v");
    *plain.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    assert!(!refused_page(&plain).await.contains("Request access"));
}

#[tokio::test]
async fn sent_to_the_owners_with_a_copy() {
    let r = rig(Some(
        "owner@example.com; second@example.com, not an address",
    ))
    .await;
    let res = r.w.post(FORM, &fields(&[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(
        html.contains("Sent to the vault&#39;s owners")
            || html.contains("Sent to the vault's owners"),
        "{html}"
    );
    assert!(!html.contains("owner@example.com"));
    let mail = until_mail(&r, 2).await;
    assert_eq!(
        recipients(&mail[0]),
        ["owner@example.com", "second@example.com"]
    );
    // The requester's copy is its own email: it names nobody else, says
    // it is a copy and has no links.
    assert_eq!(recipients(&mail[1]), ["alex@example.com"]);
    let copy = mail[1]["content"]["plainText"].as_str().unwrap();
    assert!(copy.contains("Your access request was sent"), "{copy}");
    assert!(copy.contains("Role: Key Vault Secrets User"), "{copy}");
    assert!(!copy.contains("owner@example.com") && !copy.contains("portal.azure.com"));
    assert!(!copy.contains("names you"), "{copy}");
    let text = mail[0]["content"]["plainText"].as_str().unwrap();
    assert_eq!(mail[0]["content"]["subject"], "[Keyring] Access request");
    for want in [
        "Asked by: alex@example.com",
        "Role: Key Vault Secrets User",
        "Vault: kv-test",
        "Scope: secret db-password",
        "Reason: Fixing INC-42 in production",
        "Ticket: CHG-42",
        "can't grant access itself",
        &format!("https://portal.azure.com/#resource{VAULT_ID}/users"),
        "http://localhost:3000/v/kv-test/access",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    assert!(!text.contains("VALUE-1"));
}

#[tokio::test]
async fn admins_when_the_vault_names_nobody_or_cannot_be_read() {
    let r = rig(None).await;
    let res = r.w.post(FORM, &fields(&[("scope", "vault")])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let mail = until_mail(&r, 2).await;
    assert_eq!(recipients(&mail[0]), ["ops@example.com"]);
    assert_eq!(recipients(&mail[1]), ["alex@example.com"]);
    let text = mail[0]["content"]["plainText"].as_str().unwrap();
    assert!(text.contains("Scope: The whole vault"), "{text}");

    // Resource Graph fails: the admins, and nothing of Azure's error.
    *r.w.arm.state.fail.lock().unwrap() = Some((500, "InternalServerError"));
    let res =
        r.w.post(FORM, &fields(&[("role", support::CERT_OFFICER)]))
            .await;
    let html = body_text(res).await;
    assert!(!html.contains("mock failure") && !html.contains("InternalServerError"));
    let mail = until_mail(&r, 4).await;
    assert_eq!(recipients(&mail[2]), ["ops@example.com"]);
    let text = mail[2]["content"]["plainText"].as_str().unwrap();
    assert!(!text.contains("mock failure") && !text.contains("InternalServerError"));
    assert!(text.contains("https://portal.azure.com/#browse/Microsoft.KeyVault%2Fvaults"));
}

#[tokio::test]
async fn the_allow_list_holds_every_recipient() {
    let r = rig_with(
        "access-requests",
        Some("owner@example.com, eve@evil.example"),
        &[("KEYRING_NOTIFY_ALLOWED_DOMAINS", "example.com")],
    )
    .await;
    let res = r.w.post(FORM, &fields(&[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let mail = until_mail(&r, 2).await;
    assert_eq!(recipients(&mail[0]), ["owner@example.com"]);
    assert_eq!(recipients(&mail[1]), ["alex@example.com"]);
}

#[tokio::test]
async fn one_request_per_person_vault_and_role_an_hour() {
    let r = rig(Some("owner@example.com")).await;
    assert_eq!(r.w.post(FORM, &fields(&[])).await.status(), StatusCode::OK);
    let again = r.w.post(FORM, &fields(&[("scope", "vault")])).await;
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
    let html = body_text(again).await;
    assert!(html.contains("already asked"), "{html}");
    // Another role is its own request.
    let other =
        r.w.post(FORM, &fields(&[("role", support::CERT_OFFICER)]))
            .await;
    assert_eq!(other.status(), StatusCode::OK);
    until_mail(&r, 4).await;
    assert_eq!(r.acs.state.attempts().len(), 4);
}
