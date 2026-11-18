//! Sharing a secret (#286), against mock ARM, PIM, Graph and Key Vault:
//! the setting, the form and the picker, grants through PIM and the plain
//! fallback, the Shared with panel and Revoke, My shares, every refusal,
//! and the emails.

mod support;

use axum::http::StatusCode;
use support::share::{LEAK, MockGraph, Person, start_graph};
use support::{SECRETS_USER, USER_OID, body_text, location};

const VAULT_ID: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";
const SECRET_SCOPE: &str = "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test/secrets/db-password";
const BLAIR: &str = "aaaaaaaa-0000-0000-0000-000000000002";
const GUEST: &str = "aaaaaaaa-0000-0000-0000-000000000003";
const TEAM: &str = "cccccccc-0000-0000-0000-000000000001";
const M365: &str = "cccccccc-0000-0000-0000-000000000002";
const FORM: &str = "/v/kv-test/secrets/db-password/share";
const VALUE: &str = "Sup3r-S3cret-Share-Value";

struct World {
    w: support::World,
    graph: MockGraph,
}

async fn world_with(extra: &[(&'static str, String)]) -> World {
    let graph = start_graph().await;
    let mut env = vec![
        ("KEYRING_SHARING", "true".to_owned()),
        ("KEYRING_TEST_GRAPH_URL", graph.url()),
    ];
    env.extend(extra.iter().cloned());
    let w = support::world_configured(env, |_| {}).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put("db-password", VALUE);
    graph.add(Person::user(USER_OID, "Alex Example", "alex@example.com"));
    graph.add(Person::user(BLAIR, "Blair Example", "blair@example.com"));
    let mut guest = Person::user(GUEST, "Gale Guest", "gale@partner.example");
    guest.upn = "gale_partner.example#EXT#@contoso.onmicrosoft.com".into();
    graph.add(guest);
    graph.add(Person::group(TEAM, "Payments team", true));
    graph.add(Person::group(M365, "Payments chat", false));
    World { w, graph }
}

async fn world() -> World {
    world_with(&[]).await
}

fn in_days(d: i64) -> String {
    let t = chrono::Utc::now().date_naive() + chrono::Duration::days(d);
    t.format("%Y-%m-%d").to_string()
}

fn dmy(d: i64) -> String {
    let t = chrono::Utc::now().date_naive() + chrono::Duration::days(d);
    t.format("%d-%m-%Y").to_string()
}

fn writes(w: &support::World) -> Vec<(String, String)> {
    w.arm.state.share.lock().unwrap().writes.clone()
}

fn bodies(w: &support::World) -> Vec<(String, serde_json::Value)> {
    w.arm.state.share.lock().unwrap().bodies.clone()
}

async fn share_with(
    w: &support::World,
    principal: &str,
    who: &str,
    until: &str,
) -> axum::http::Response<axum::body::Body> {
    w.post(
        FORM,
        &[("principal", principal), ("who", who), ("until", until)],
    )
    .await
}

#[tokio::test]
async fn off_by_default_every_route_is_not_found_and_pages_are_unchanged() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put("db-password", VALUE);
    for path in [
        FORM,
        "/v/kv-test/secrets/db-password/share/revoke",
        "/v/kv-test/share/people?q=bl",
        "/v/kv-test/my-access/shares",
    ] {
        let (status, _) = w.page(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let res = w
        .post(FORM, &[("principal", BLAIR), ("until", &in_days(7))])
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/share/revoke",
            &[("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(!html.contains("Shared with"));
    assert!(!html.contains("/share\""));
    assert!(!html.contains("share.js"));
    assert!(writes(&w).is_empty());
}

#[tokio::test]
async fn grant_through_pim_with_an_end_date() {
    let World { w, graph } = world().await;
    let (status, html) = w.page(FORM).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("data-share-picker=\"/v/kv-test/share/people\""));
    assert!(html.contains("share.js"));
    assert!(
        html.contains(&format!("value=\"{}\"", in_days(7))),
        "default 7 days"
    );
    assert!(
        html.contains(&format!("max=\"{}\"", in_days(30))),
        "default max 30 days"
    );

    let res = share_with(&w, BLAIR, "Blair Example", &in_days(7)).await;
    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "{}",
        body_text(res).await
    );
    assert_eq!(location(&res), "/v/kv-test/secrets/db-password");
    let b = bodies(&w);
    assert_eq!(b.len(), 1, "one PIM request, no plain assignment");
    let (path, body) = &b[0];
    assert!(
        path.starts_with(&format!(
            "{SECRET_SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
        )),
        "{path}"
    );
    let p = &body["properties"];
    assert_eq!(p["requestType"], "AdminAssign");
    assert_eq!(p["principalId"], BLAIR);
    assert!(
        p["roleDefinitionId"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/roleDefinitions/{SECRETS_USER}"))
    );
    assert_eq!(p["scheduleInfo"]["expiration"]["type"], "AfterDateTime");
    assert_eq!(
        p["scheduleInfo"]["expiration"]["endDateTime"],
        format!("{}T23:59:59Z", in_days(7))
    );
    assert_eq!(
        p["justification"],
        format!("Shared by Keyring by {USER_OID} until {}", dmy(7))
    );
    // Made as the person, with their own Management token.
    let bearers = w.arm.state.authz.lock().unwrap().bearers.clone();
    assert!(
        bearers
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://management.azure.com/.default"))
    );
    assert!(
        graph
            .state
            .bearers
            .lock()
            .unwrap()
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://graph.microsoft.com/.default"))
    );

    // The panel shows it, made by Keyring, with Revoke.
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("Shared with"));
    assert!(html.contains("Blair Example"), "named through Graph");
    assert!(html.contains(&format!("By Alex Example, until {}", dmy(7))));
    assert!(html.contains("(Azure removes it)"));
    assert!(html.contains(&format!(
        "/v/kv-test/secrets/db-password/share/revoke?principal={BLAIR}"
    )));
}

#[tokio::test]
async fn falls_back_to_a_plain_assignment_when_pim_isnt_licensed() {
    let World { w, .. } = world().await;
    w.arm.state.share.lock().unwrap().pim_fail = Some((400, "AadPremiumLicenseRequired"));
    let res = share_with(&w, TEAM, "", &in_days(10)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let b = bodies(&w);
    assert_eq!(b.len(), 2);
    assert_eq!(
        b[0].1["properties"]["requestType"], "AdminAssign",
        "PIM was tried first"
    );
    let (path, body) = &b[1];
    assert!(
        path.starts_with(&format!(
            "{SECRET_SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
        )),
        "{path}"
    );
    let p = &body["properties"];
    assert_eq!(p["principalId"], TEAM);
    assert_eq!(p["principalType"], "Group");
    assert_eq!(
        p["description"],
        format!("Shared by Keyring by {USER_OID} until {}", dmy(10))
    );
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("Payments team"));
    assert!(
        html.contains("(Azure won&#39;t remove it)") || html.contains("(Azure won't remove it)"),
        "{html}"
    );
    assert!(html.contains("share/revoke?assignment="));
}

#[tokio::test]
async fn a_pim_setting_that_refuses_is_not_stepped_round() {
    let World { w, .. } = world().await;
    w.arm.state.share.lock().unwrap().pim_fail =
        Some((400, "RoleAssignmentRequestPolicyValidationFailed"));
    let res = share_with(&w, BLAIR, "", &in_days(10)).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let html = body_text(res).await;
    assert!(html.contains("Not shared"), "{html}");
    assert!(html.contains("no end date"), "{html}");
    // PIM was asked, and no plain assignment was made in its place.
    let b = bodies(&w);
    assert_eq!(b.len(), 1, "{b:?}");
    assert_eq!(b[0].1["properties"]["requestType"], "AdminAssign");
}

#[tokio::test]
async fn an_overdue_plain_share_is_flagged_on_the_panel_and_the_review() {
    let World { w, .. } = world().await;
    let past = chrono::Utc::now().date_naive() - chrono::Duration::days(3);
    w.arm
        .state
        .share
        .lock()
        .unwrap()
        .assignments
        .push(support::share::Assigned {
            name: "dddddddd-0000-0000-0000-000000000001".into(),
            scope: SECRET_SCOPE.into(),
            role: SECRETS_USER.into(),
            principal_id: BLAIR.into(),
            principal_type: "User".into(),
            description: Some(format!(
                "Shared by Keyring by {USER_OID} until {}",
                past.format("%d-%m-%Y")
            )),
        });
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("Overdue"), "{html}");
    // The access review: the item's own access says the share is overdue,
    // on the page and in the CSV.
    let (status, html) = w.page("/v/kv-test/access/review").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Overdue share"), "{html}");
    let (_, csv) = w.page("/v/kv-test/access/review.csv").await;
    assert!(csv.contains("OVERDUE"), "{csv}");
}

#[tokio::test]
async fn revoke_a_plain_share_and_a_pim_share() {
    let World { w, .. } = world().await;
    w.arm.state.share.lock().unwrap().pim_fail = Some((400, "AadPremiumLicenseRequired"));
    assert_eq!(
        share_with(&w, BLAIR, "", &in_days(5)).await.status(),
        StatusCode::SEE_OTHER
    );
    let name = w.arm.state.share.lock().unwrap().assignments[0]
        .name
        .clone();
    let path = "/v/kv-test/secrets/db-password/share/revoke";
    let (status, html) = w.page(&format!("{path}?assignment={name}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Blair Example"));
    // A wrong typed name changes nothing.
    let res = w
        .post(
            path,
            &[("assignment", &name), ("confirm_name", "db-passwor")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!writes(&w).iter().any(|(m, _)| m == "DELETE"));
    let res = w
        .post(
            path,
            &[("assignment", &name), ("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let deletes: Vec<_> = writes(&w)
        .into_iter()
        .filter(|(m, _)| m == "DELETE")
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(
        deletes[0].1,
        format!("{SECRET_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{name}")
    );

    // Through PIM: AdminRemove at the secret's scope.
    assert_eq!(
        share_with(&w, BLAIR, "", &in_days(5)).await.status(),
        StatusCode::SEE_OTHER
    );
    let res = w
        .post(
            path,
            &[("principal", BLAIR), ("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let last = bodies(&w).last().unwrap().clone();
    assert!(last.0.starts_with(&format!(
        "{SECRET_SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
    )));
    assert_eq!(last.1["properties"]["requestType"], "AdminRemove");
    assert_eq!(last.1["properties"]["principalId"], BLAIR);
}

#[tokio::test]
async fn revoke_is_only_for_keyrings_own_shares_at_the_secrets_scope() {
    let World { w, .. } = world().await;
    let path = "/v/kv-test/secrets/db-password/share/revoke";
    let add = |name: &str, scope: &str, desc: Option<String>| {
        w.arm
            .state
            .share
            .lock()
            .unwrap()
            .assignments
            .push(support::share::Assigned {
                name: name.into(),
                scope: scope.into(),
                role: SECRETS_USER.into(),
                principal_id: BLAIR.into(),
                principal_type: "User".into(),
                description: desc,
            });
    };
    let mark = format!("Shared by Keyring by {USER_OID} until {}", dmy(3));
    // Not Keyring's: no description, or another one.
    add("dddddddd-0000-0000-0000-000000000001", SECRET_SCOPE, None);
    add(
        "dddddddd-0000-0000-0000-000000000002",
        SECRET_SCOPE,
        Some(format!("{mark} by hand")),
    );
    // Keyring's, but at the vault, not the secret.
    add(
        "dddddddd-0000-0000-0000-000000000003",
        VAULT_ID,
        Some(mark.clone()),
    );
    for name in [
        "dddddddd-0000-0000-0000-000000000001",
        "dddddddd-0000-0000-0000-000000000002",
        "dddddddd-0000-0000-0000-000000000003",
        "not-a-guid",
        "../../x",
    ] {
        let res = w
            .post(
                path,
                &[("assignment", name), ("confirm_name", "db-password")],
            )
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{name}");
    }
    assert!(!writes(&w).iter().any(|(m, _)| m == "DELETE"));
}

async fn refused_with(w: &support::World, fields: &[(&str, &str)], status: StatusCode, text: &str) {
    let res = w.post(FORM, fields).await;
    assert_eq!(res.status(), status, "{fields:?}");
    let html = body_text(res).await;
    assert!(html.contains(text), "{fields:?}: {html}");
    assert!(
        writes(w).is_empty(),
        "nothing changed in Azure for {fields:?}"
    );
}

#[tokio::test]
async fn refusals_before_anything_changes() {
    let World { w, .. } = world().await;
    let ok = in_days(7);
    // Yourself.
    refused_with(
        &w,
        &[("principal", USER_OID), ("until", &ok)],
        StatusCode::UNPROCESSABLE_ENTITY,
        "share a secret with yourself",
    )
    .await;
    // Dates: past, past the maximum, not a date.
    refused_with(
        &w,
        &[("principal", BLAIR), ("until", &in_days(-1))],
        StatusCode::UNPROCESSABLE_ENTITY,
        "in the past",
    )
    .await;
    refused_with(
        &w,
        &[("principal", BLAIR), ("until", &in_days(31))],
        StatusCode::UNPROCESSABLE_ENTITY,
        "at most 30 days",
    )
    .await;
    refused_with(
        &w,
        &[("principal", BLAIR), ("until", "soon")],
        StatusCode::UNPROCESSABLE_ENTITY,
        "real date",
    )
    .await;
    // Not a user or security group Graph knows, or not a GUID at all.
    for p in ["dddddddd-0000-0000-0000-00000000dead", M365] {
        refused_with(
            &w,
            &[("principal", p), ("until", &ok)],
            StatusCode::UNPROCESSABLE_ENTITY,
            "find a person or security group",
        )
        .await;
    }
    for p in ["Blair", "' or 1 eq 1", "../x"] {
        refused_with(
            &w,
            &[("principal", p), ("until", &ok)],
            StatusCode::UNPROCESSABLE_ENTITY,
            "Pick someone",
        )
        .await;
    }
    // A role GUID or anything else in the form is never used: only the
    // fixed role is assigned.
    let res = w
        .post(
            FORM,
            &[
                ("principal", BLAIR),
                ("until", &ok),
                ("role", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let b = bodies(&w);
    assert!(
        b[0].1["properties"]["roleDefinitionId"]
            .as_str()
            .unwrap()
            .ends_with(SECRETS_USER)
    );
}

#[tokio::test]
async fn without_the_picker_an_exact_email_or_object_id_works() {
    let World { w, .. } = world().await;
    let res = w
        .post(
            FORM,
            &[("who", "blair@example.com"), ("until", &in_days(7))],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(bodies(&w)[0].1["properties"]["principalId"], BLAIR);
}

#[tokio::test]
async fn managed_and_reveal_limited_secrets_and_policy_vaults_are_refused() {
    let World { w, .. } = world().await;
    w.kv.state.add_cert("web-tls", true, "UEZY");
    let res = w
        .post(
            "/v/kv-test/secrets/web-tls/share",
            &[("principal", BLAIR), ("until", &in_days(7))],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("belongs to a certificate"));
    for v in ["copy-only", "none", "anything"] {
        w.kv.state.put_with("limited", "x", |ver| {
            ver.tags.insert("keyring-reveal".into(), v.into());
        });
        let res = w
            .post(
                "/v/kv-test/secrets/limited/share",
                &[("principal", BLAIR), ("until", &in_days(7))],
            )
            .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "{v}");
        assert!(body_text(res).await.contains("reveal limit"));
    }
    // An older version with the tag counts too.
    w.kv.state.put_with("old-limit", "x", |ver| {
        ver.tags.insert("Keyring-Reveal".into(), "none".into());
    });
    w.kv.state.put("old-limit", "y");
    let res = w
        .post(
            "/v/kv-test/secrets/old-limit/share",
            &[("principal", BLAIR), ("until", &in_days(7))],
        )
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(writes(&w).is_empty());
    // Access policies: no Share button, and refused on the server.
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", false)];
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(!html.contains("db-password/share\""), "no Share button");
    assert!(html.contains("access policies"));
    let res = share_with(&w, BLAIR, "", &in_days(7)).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(writes(&w).is_empty());
}

#[tokio::test]
async fn a_403_names_who_can_share_and_hides_azures_message() {
    let World { w, .. } = world().await;
    w.arm.state.share.lock().unwrap().pim_fail = Some((403, "AuthorizationFailed"));
    let res = share_with(&w, BLAIR, "", &in_days(7)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("What to ask for"));
    assert!(html.contains("User Access Administrator"));
    assert!(html.contains("Key Vault Data Access Administrator"));
    assert!(!html.contains(LEAK));
    // The plain path's 403 too.
    {
        let mut s = w.arm.state.share.lock().unwrap();
        s.pim_fail = Some((400, "AadPremiumLicenseRequired"));
        s.assign_fail = Some((403, "AuthorizationFailed"));
    }
    let res = share_with(&w, BLAIR, "", &in_days(7)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(!body_text(res).await.contains(LEAK));
}

#[tokio::test]
async fn the_picker_escapes_limits_and_lists_only_five_fields() {
    let World { w, graph } = world().await;
    let res = w.get("/v/kv-test/share/people?q=bl").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body: serde_json::Value = serde_json::from_str(&body_text(res).await).unwrap();
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    let mut keys: Vec<&str> = results[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "mail", "name", "type", "upn"]);
    assert_eq!(results[0]["name"], "Blair Example");
    // Security groups only.
    let res = w.get("/v/kv-test/share/people?q=pay").await;
    let body: serde_json::Value = serde_json::from_str(&body_text(res).await).unwrap();
    let names: Vec<&str> = body["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Payments team"]);
    // Quotes and backslashes are escaped inside the clause; nothing else
    // can add a clause or a parameter.
    let _ = w
        .get("/v/kv-test/share/people?q=a%22%20OR%20%22mail%3Ax%5C")
        .await;
    let q = graph.queries().last().unwrap().clone();
    assert!(
        q.contains(r#"$search="displayName:a\" OR \"mail:x\\""#),
        "{q}"
    );
    let _ = w.get("/v/kv-test/share/people?q=a%26%24top%3D999").await;
    let q = graph.queries().last().unwrap().clone();
    assert!(q.contains("$top=10"), "{q}");
    assert!(!q.contains("$top=999&"), "{q}");
    // Too short or too long: no call to Graph.
    let before = graph.queries().len();
    for q in ["a", &"x".repeat(65)] {
        let res = w.get(&format!("/v/kv-test/share/people?q={q}")).await;
        let body: serde_json::Value = serde_json::from_str(&body_text(res).await).unwrap();
        assert!(body["results"].as_array().unwrap().is_empty());
    }
    assert_eq!(graph.queries().len(), before);
}

#[tokio::test]
async fn the_picker_says_when_consent_is_missing_and_the_form_still_works() {
    let World { w, graph } = world().await;
    *graph.state.groups_fail.lock().unwrap() = Some((403, "Authorization_RequestDenied"));
    let res = w.get("/v/kv-test/share/people?q=bl").await;
    let body: serde_json::Value = serde_json::from_str(&body_text(res).await).unwrap();
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        1,
        "people still listed"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("GroupMember.Read.All")
    );
    *graph.state.fail.lock().unwrap() = Some((403, "Authorization_RequestDenied"));
    let res = w.get("/v/kv-test/share/people?q=bl").await;
    let text = body_text(res).await;
    assert!(text.contains("User.ReadBasic.All"));
    assert!(!text.contains(LEAK));
}

#[tokio::test]
async fn the_picker_is_rate_limited_and_needs_a_session() {
    let World { w, .. } = world().await;
    let mut last = StatusCode::OK;
    for _ in 0..40 {
        last = w.get("/v/kv-test/share/people?q=bl").await.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    use tower::ServiceExt;
    let res = w
        .app
        .clone()
        .oneshot(
            axum::http::Request::get("/v/kv-test/share/people?q=bl")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_redirection() || res.status() == StatusCode::UNAUTHORIZED,
        "{}",
        res.status()
    );
}

#[tokio::test]
async fn forged_and_cross_site_posts_change_nothing() {
    let World { w, .. } = world().await;
    use tower::ServiceExt;
    let post = |csrf: String, origin: Option<&'static str>, path: &'static str| {
        let w = &w;
        async move {
            let body = format!(
                "csrf={csrf}&principal={BLAIR}&until={}&confirm_name=db-password",
                in_days(7)
            );
            let mut req = axum::http::Request::post(path)
                .header("cookie", &w.cookie)
                .header("content-type", "application/x-www-form-urlencoded");
            if let Some(o) = origin {
                req = req.header("origin", o);
            }
            w.app
                .clone()
                .oneshot(req.body(axum::body::Body::from(body)).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    for path in [FORM, "/v/kv-test/secrets/db-password/share/revoke"] {
        assert_eq!(
            post("forged".into(), Some("http://localhost:3000"), path).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(w.csrf.clone(), Some("https://evil.example"), path).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(w.csrf.clone(), None, path).await,
            StatusCode::FORBIDDEN
        );
    }
    assert!(writes(&w).is_empty());
}

#[tokio::test]
async fn the_reason_gate_and_step_up_apply_as_for_reveal() {
    let World { w, .. } = world_with(&[("KEYRING_REQUIRE_REASON", "reveal".into())]).await;
    let res = share_with(&w, BLAIR, "", &in_days(7)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        body_text(res)
            .await
            .contains("Why are you sharing this secret?")
    );
    assert!(writes(&w).is_empty());
    let res = w
        .post(
            FORM,
            &[
                ("principal", BLAIR),
                ("until", &in_days(7)),
                ("reason", "Handing over INC-42"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    let World { w, .. } = world_with(&[("KEYRING_STEP_UP_MAX_AGE", "15".into())]).await;
    let res = share_with(&w, BLAIR, "", &in_days(7)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Confirm it"));
    let res = w
        .post(
            "/v/kv-test/secrets/db-password/share/revoke",
            &[("principal", BLAIR), ("confirm_name", "db-password")],
        )
        .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "revoke asks for step-up too"
    );
    assert!(writes(&w).is_empty());
}

#[tokio::test]
async fn my_shares_lists_both_sides() {
    let World { w, .. } = world().await;
    w.kv.state.put("api-key", "x");
    w.arm.state.share.lock().unwrap().pim_fail = Some((400, "AadPremiumLicenseRequired"));
    assert_eq!(
        share_with(&w, BLAIR, "", &in_days(5)).await.status(),
        StatusCode::SEE_OTHER
    );
    // Shared with me, by Blair, on another secret.
    w.arm
        .state
        .share
        .lock()
        .unwrap()
        .assignments
        .push(support::share::Assigned {
            name: "dddddddd-0000-0000-0000-000000000009".into(),
            scope: format!("{VAULT_ID}/secrets/api-key"),
            role: SECRETS_USER.into(),
            principal_id: USER_OID.into(),
            principal_type: "User".into(),
            description: Some(format!("Shared by Keyring by {BLAIR} until {}", dmy(2))),
        });
    let (status, html) = w.page("/v/kv-test/my-access/shares").await;
    assert_eq!(status, StatusCode::OK);
    let mine = &html[html.find("Shared with me").unwrap()..html.find("Shared by me").unwrap()];
    assert!(
        mine.contains("api-key") && mine.contains("Blair Example") && mine.contains(&dmy(2)),
        "{mine}"
    );
    let made = &html[html.find("Shared by me").unwrap()..];
    assert!(
        made.contains("db-password") && made.contains("Blair Example") && made.contains(&dmy(5)),
        "{made}"
    );
    let (_, my) = w.page("/v/kv-test/my-access").await;
    assert!(my.contains("/v/kv-test/my-access/shares"));
}

#[tokio::test]
async fn emails_go_to_graph_mail_and_carry_no_value_reason_or_azure_text() {
    let acs = support::acs::start().await;
    let identity = support::start_identity().await;
    let World { w, graph } = world_with(&[
        (
            "KEYRING_MANAGED_IDENTITY_CLIENT_ID",
            support::IDENTITY_CLIENT_ID.into(),
        ),
        ("IDENTITY_ENDPOINT", identity.endpoint()),
        ("IDENTITY_HEADER", support::IDENTITY_HEADER.into()),
        (
            "KEYRING_NOTIFY_ACS_ENDPOINT",
            "https://keyring-mail.australia.communication.azure.com".into(),
        ),
        (
            "KEYRING_NOTIFY_SENDER",
            "DoNotReply@mail.example.com".into(),
        ),
        ("KEYRING_NOTIFY_TYPES", "shares".into()),
        ("KEYRING_TEST_NOTIFY_ACS_URL", acs.url()),
        ("KEYRING_REQUIRE_REASON", "reveal".into()),
    ])
    .await;
    // A hostile display name for the sharer.
    graph.state.people.lock().unwrap()[0].name =
        "Alex <a href=\"https://evil.example\">x</a>".into();
    let res = w
        .post(
            FORM,
            &[
                ("principal", BLAIR),
                ("until", &in_days(7)),
                ("reason", "Reason-Text-Never-Mailed"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    for _ in 0..100 {
        if acs.state.attempts().len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let attempts = acs.state.attempts();
    assert_eq!(attempts.len(), 2, "recipient and receipt");
    let to: Vec<String> = attempts
        .iter()
        .map(|a| {
            a.body["recipients"]["to"][0]["address"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(to.contains(&"blair@example.com".to_owned()));
    assert!(to.contains(&"alex@example.com".to_owned()));
    let all = acs.state.all_bodies();
    for bad in [
        VALUE,
        "Reason-Text-Never-Mailed",
        LEAK,
        "<a href=\\\"https://evil.example",
    ] {
        assert!(!all.contains(bad), "{bad}");
    }
    assert!(all.contains("db-password") && all.contains(&dmy(7)));
    assert!(all.contains("http://localhost:3000/v/kv-test/secrets/db-password"));
    assert!(acs.state.violations().is_empty());
    // A group gets no email.
    let before = acs.state.attempts().len();
    let res = w
        .post(
            FORM,
            &[
                ("principal", TEAM),
                ("until", &in_days(7)),
                ("reason", "Team handover"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let after: Vec<String> = acs.state.attempts()[before..]
        .iter()
        .map(|a| {
            a.body["recipients"]["to"][0]["address"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(after, ["alex@example.com"], "only the receipt");
}
