//! Access: who can reach a vault or an item, against mock Resource Graph
//! and ARM (role assignments, eligibility, role definitions and the vault
//! resource).

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use support::{CERT_OFFICER, OWNER_ROLE, READER_ROLE, SECRETS_USER};

const SUB: &str = "/subscriptions/sub-a";
const RG: &str = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
const VAULT: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";

const ALICE: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const OPS_GROUP: &str = "bbbbbbbb-0000-0000-0000-000000000002";
const APP: &str = "cccccccc-0000-0000-0000-000000000003";
const BOB: &str = "dddddddd-0000-0000-0000-000000000004";
const CAROL: &str = "eeeeeeee-0000-0000-0000-000000000005";

fn a(scope: &str, role: &str, who: &str, kind: &str) -> (String, String, String, String) {
    (scope.into(), role.into(), who.into(), kind.into())
}

async fn world(rbac: bool) -> support::World {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", rbac)];
    w
}

/// The page with apostrophes and quotes unescaped, so assertions read as
/// the text.
async fn page(w: &support::World, path: &str) -> (StatusCode, String) {
    let (status, html) = w.page(path).await;
    (status, html.replace("&#39;", "'").replace("&#34;", "\""))
}

/// The table row for one principal.
fn row<'a>(html: &'a str, who: &str) -> &'a str {
    let start = html
        .find(&format!(">{who}<"))
        .unwrap_or_else(|| panic!("no row for {who}"));
    let rest = &html[start..];
    &rest[..rest.find("</tr>").unwrap()]
}

#[tokio::test]
async fn vault_page_lists_inherited_and_vault_assignments_and_drops_the_rest() {
    let w = world(true).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments = vec![
            a(SUB, OWNER_ROLE, ALICE, "User"),
            a(RG, SECRETS_USER, OPS_GROUP, "Group"),
            a(VAULT, CERT_OFFICER, APP, "ServicePrincipal"),
            // Reader reaches nothing inside the vault: left out.
            a(VAULT, READER_ROLE, CAROL, "User"),
            // Below the vault: on the vault page, left out.
            a(
                &format!("{VAULT}/secrets/db-password"),
                SECRETS_USER,
                BOB,
                "User",
            ),
            // Another vault in the same group: not above this one.
            a(
                &format!("{RG}/providers/Microsoft.KeyVault/vaults/kv-other"),
                SECRETS_USER,
                CAROL,
                "User",
            ),
        ];
        m.eligible = vec![a(VAULT, SECRETS_USER, BOB, "User")];
    }
    let (status, html) = page(&w, "/v/kv-test/access").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("aria-current=\"page\">Access</a>"));

    let owner = row(&html, ALICE);
    assert!(owner.contains("Owner") && owner.contains("Can grant itself access"));
    assert!(owner.contains("Subscription"));
    assert!(html.contains(&format!("UserProfileMenuBlade/~/overview/userId/{ALICE}\"")));

    let group = row(&html, OPS_GROUP);
    assert!(group.contains("Group") && group.contains("Key Vault Secrets User"));
    assert!(group.contains("Resource group"));

    let app = row(&html, APP);
    assert!(app.contains("App or managed identity") && app.contains("The vault"));

    let eligible = row(&html, BOB);
    assert!(eligible.contains("Eligible") && eligible.contains("The vault"));
    assert!(
        !html.contains("This item"),
        "item-scope assignment left out"
    );
    assert!(!html.contains(CAROL), "Reader and other vaults left out");
    assert!(html.contains("Keyring doesn't look up their names"));
    assert!(html.contains("4 assignments, 1 of them to groups"));
}

#[tokio::test]
async fn item_section_shows_item_scope_and_inherited() {
    let w = world(true).await;
    w.kv.state.put("db-password", "VALUE-1");
    w.kv.state.put("other", "VALUE-2");
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments = vec![
            a(SUB, OWNER_ROLE, ALICE, "User"),
            a(
                &format!("{VAULT}/secrets/db-password"),
                SECRETS_USER,
                BOB,
                "User",
            ),
            a(
                &format!("{VAULT}/secrets/other"),
                SECRETS_USER,
                CAROL,
                "User",
            ),
        ];
    }
    let (status, html) = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("id=\"access-heading\">Access</h2>"));
    assert!(row(&html, BOB).contains("This item"));
    assert!(row(&html, ALICE).contains("Subscription"));
    assert!(
        !html.contains(CAROL),
        "another secret's assignment left out"
    );
    assert!(!html.contains("VALUE-1"), "the page never shows the value");

    let paths = w.arm.state.authz.lock().unwrap().paths.clone();
    assert!(
        paths.iter().any(|p| p
            == &format!(
                "{VAULT}/secrets/db-password/providers/Microsoft.Authorization/roleAssignments"
            )),
        "asked at the item's scope: {paths:?}"
    );
}

#[tokio::test]
async fn certificate_and_key_pages_have_access_at_their_scope() {
    let w = world(true).await;
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    w.arm.state.authz.lock().unwrap().assignments = vec![a(
        &format!("{VAULT}/certificates/web-tls"),
        CERT_OFFICER,
        BOB,
        "User",
    )];
    let (_, cert) = page(&w, "/v/kv-test/certificates/web-tls").await;
    assert!(row(&cert, BOB).contains("This item"));
    let (_, key) = page(&w, "/v/kv-test/keys/app-key").await;
    assert!(key.contains("id=\"access-heading\">Access</h2>"));
    assert!(!key.contains(BOB));
    let paths = w.arm.state.authz.lock().unwrap().paths.clone();
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with(&format!("{VAULT}/certificates/web-tls/providers/")))
    );
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with(&format!("{VAULT}/keys/app-key/providers/")))
    );
}

#[tokio::test]
async fn access_policy_vault_lists_policies_in_plain_words() {
    let w = world(false).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.policies.insert(
            "kv-test".into(),
            json!([
                {"tenantId": support::TENANT, "objectId": ALICE, "permissions": {"secrets": ["Get", "List"], "keys": [], "certificates": ["all"]}},
                {"tenantId": support::TENANT, "objectId": BOB, "applicationId": APP, "permissions": {"keys": ["get", "sign"]}}
            ]),
        );
        m.assignments = vec![
            a(RG, OWNER_ROLE, CAROL, "User"),
            // A data role does nothing on an access policy vault.
            a(VAULT, SECRETS_USER, OPS_GROUP, "Group"),
        ];
    }
    let (status, html) = page(&w, "/v/kv-test/access").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("uses <strong>access policies</strong>"));
    let alice = row(&html, ALICE);
    assert!(alice.contains("read values, list") && alice.contains("everything"));
    assert!(alice.contains("Reads secret values"));
    let bob = row(&html, BOB);
    assert!(bob.contains("Only through the app") && bob.contains("read the public key, sign"));
    assert!(row(&html, CAROL).contains("Can grant itself access"));
    assert!(!html.contains(OPS_GROUP), "data roles don't apply");

    // On a key's page, only the policies that cover keys.
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, key) = page(&w, "/v/kv-test/keys/app-key").await;
    assert!(key.contains(BOB));
    assert!(!key.contains(ALICE));

    let csv = support::body_text(w.get("/v/kv-test/access.csv").await).await;
    assert!(csv.contains(&format!("{ALICE},Type not given,\"Secrets: read values, list; Certificates: everything\",Access policy")));
}

#[tokio::test]
async fn no_permission_to_read_assignments_is_explained_not_empty() {
    let w = world(true).await;
    w.arm.state.authz.lock().unwrap().assignments_forbidden = true;
    let (status, html) = page(&w, "/v/kv-test/access").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("You can't read the role assignments here"));
    assert!(html.contains("That doesn't mean nobody has it"));
    assert!(html.contains("What to ask for:</strong> the Reader role"));
    assert!(!html.contains("<table"), "no empty table");

    // The CSV has nothing to give: the explanation with a 403, not a file.
    let res = w.get("/v/kv-test/access.csv").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = support::body_text(res).await.replace("&#39;", "'");
    assert!(body.contains("You can't read the role assignments here"));

    // The vault resource refused too.
    w.arm.state.authz.lock().unwrap().vault_forbidden = true;
    let (_, html) = page(&w, "/v/kv-test/access").await;
    assert!(html.contains("You can't read this vault's settings in Azure"));
}

#[tokio::test]
async fn a_tenant_without_pim_still_shows_active_assignments() {
    let w = world(true).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments = vec![a(VAULT, SECRETS_USER, ALICE, "User")];
        m.eligible_status = Some(400);
    }
    let (_, html) = page(&w, "/v/kv-test/access").await;
    assert!(row(&html, ALICE).contains("Key Vault Secrets User"));
    assert!(html.contains("Eligible (PIM) assignments aren't listed"));
}

#[tokio::test]
async fn every_call_carries_the_persons_management_token() {
    let w = world(true).await;
    w.kv.state.put("db-password", "VALUE-1");
    w.arm.state.authz.lock().unwrap().assignments = vec![a(VAULT, SECRETS_USER, ALICE, "User")];
    page(&w, "/v/kv-test/access").await;
    page(&w, "/v/kv-test/secrets/db-password").await;
    let m = w.arm.state.authz.lock().unwrap();
    assert!(m.paths.iter().any(|p| p.ends_with("/roleAssignments")));
    assert!(
        m.paths
            .iter()
            .any(|p| p.ends_with("/roleEligibilityScheduleInstances"))
    );
    assert!(m.paths.iter().any(|p| p.contains("/roleDefinitions/")));
    assert!(m.paths.iter().any(|p| p == VAULT));
    assert!(!m.bearers.is_empty());
    for b in &m.bearers {
        assert!(
            b.starts_with("Bearer obo:https://management.azure.com/.default:for:user-api-token"),
            "{b}"
        );
    }
}

#[tokio::test]
async fn a_slow_access_read_doesnt_hold_up_the_item_page() {
    let w = world(true).await;
    w.kv.state.put("db-password", "VALUE-1");
    w.arm.state.authz.lock().unwrap().delay = Duration::from_secs(30);
    let started = std::time::Instant::now();
    let (status, html) = page(&w, "/v/kv-test/secrets/db-password").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "page took {:?}",
        started.elapsed()
    );
    assert!(html.contains("Azure didn't answer within 5 seconds"));
    assert!(
        html.contains("Current version"),
        "the rest of the page is there"
    );
}

#[tokio::test]
async fn csv_lists_the_vaults_access_with_formula_guarding() {
    let w = world(true).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments = vec![
            a(SUB, OWNER_ROLE, ALICE, "User"),
            a(VAULT, SECRETS_USER, "=HYPERLINK(1)", "User"),
        ];
        m.eligible = vec![a(VAULT, SECRETS_USER, BOB, "User")];
    }
    let res = w.get("/v/kv-test/access.csv").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/csv; charset=utf-8");
    assert!(
        res.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert!(
        res.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("keyring-access-kv-test.csv")
    );
    let csv = support::body_text(res).await;
    assert!(csv.starts_with("Principal object ID,Principal type,Role or permissions,"));
    assert!(csv.contains(&format!(
        "{ALICE},User,Owner,Active,Subscription,{SUB},Yes,No"
    )));
    assert!(csv.contains(&format!(
        "{BOB},User,Key Vault Secrets User,Eligible,The vault,"
    )));
    assert!(csv.contains("'=HYPERLINK(1)"));
}

#[tokio::test]
async fn bare_access_address_goes_to_the_vault_last_used() {
    let w = world(true).await;
    let res = w.get("/access").await;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(support::location(&res), "/v/kv-test/access");
    let (status, _) = page(&w, "/v/bad..name/access").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
