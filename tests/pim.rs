//! PIM role activation (#203), against mock ARM and mock Key Vault: the
//! "Activate" offer on a 403 page, the activation form and its results,
//! and My access with Deactivate.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{SECRETS_USER, body_text, hidden_value, location, pim_rules};

const VAULT: &str =
    "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test";
const RG: &str = "/subscriptions/sub-a/resourceGroups/rg-kv-test";
const SCHEDULE: &str = "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/b1477448-2cc6-4ceb-93b4-54a202a89413";
const REVEAL: &str = "/v/kv-test/secrets/db-password/reveal";
const FORM: &str = "/v/kv-test/my-access/activate";

async fn world() -> support::World {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put("db-password", "VALUE-1");
    w
}

/// A world where Key Vault refuses with `code`, and the person is eligible
/// for Key Vault Secrets User on the resource group, with these PIM rules.
async fn eligible(rules: serde_json::Value) -> support::World {
    let w = world().await;
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible = vec![(RG.into(), SECRETS_USER.into(), SCHEDULE.into())];
        m.pim.policies.insert(SECRETS_USER.into(), rules);
    }
    w
}

fn puts(w: &support::World) -> Vec<(String, serde_json::Value)> {
    w.arm.state.authz.lock().unwrap().pim.requests.clone()
}

fn pim_reads(w: &support::World) -> usize {
    w.arm.state.authz.lock().unwrap().pim.reads.len()
}

fn reply(w: &support::World, status: u16, body: serde_json::Value) {
    w.arm.state.authz.lock().unwrap().pim.reply = Some((status, body));
}

async fn refused_page(w: &support::World) -> String {
    let res = w.post(REVEAL, &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    body_text(res).await
}

/// What the activation form posts for the eligibility at the resource
/// group, as `eligible()` sets up. `scope` and `schedule` say which
/// eligibility the form showed.
fn form_fields<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut f = vec![
        ("role", SECRETS_USER),
        ("scope", RG),
        ("schedule", SCHEDULE),
        ("back", "/v/kv-test/secrets/db-password"),
        ("minutes", "60"),
        ("justification", "Fixing INC-42 in production"),
    ];
    for (k, v) in extra {
        f.retain(|(n, _)| n != k);
        f.push((k, v));
    }
    f
}

#[tokio::test]
async fn without_eligibility_the_403_page_is_unchanged() {
    let w = world().await;
    // A plain 403 (not RBAC) never looks for PIM: the page as it always was.
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let before = refused_page(&w).await;
    assert_eq!(pim_reads(&w), 0, "no lookup for a 403 that isn't RBAC");
    assert!(before.contains("Key Vault Secrets User"));

    // An RBAC refusal with no eligibility, PIM not licensed (400), no
    // permission (403), not found (404), a server error, and a lookup that
    // takes too long: byte for byte the same page every time.
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    assert_eq!(refused_page(&w).await, before, "no eligibility");
    for status in [400, 403, 404, 500] {
        w.arm.state.authz.lock().unwrap().pim.eligible_status = Some(status);
        assert_eq!(
            refused_page(&w).await,
            before,
            "eligibility answered {status}"
        );
    }
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible_status = None;
        m.pim.eligible = vec![(RG.into(), SECRETS_USER.into(), SCHEDULE.into())];
        m.pim.eligible_delay = Duration::from_secs(7);
    }
    let started = std::time::Instant::now();
    assert_eq!(refused_page(&w).await, before, "lookup timed out");
    assert!(
        started.elapsed() < Duration::from_secs(7),
        "gave up at the limit"
    );
    // Eligible only for another role: still unchanged.
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible_delay = Duration::ZERO;
        m.pim.eligible = vec![(RG.into(), support::CERT_OFFICER.into(), SCHEDULE.into())];
    }
    assert_eq!(refused_page(&w).await, before, "another role");
    // Eligible on another vault's resource group: unchanged.
    w.arm.state.authz.lock().unwrap().pim.eligible = vec![(
        "/subscriptions/sub-a/resourceGroups/rg-other".into(),
        SECRETS_USER.into(),
        SCHEDULE.into(),
    )];
    assert_eq!(refused_page(&w).await, before, "another scope");
    assert!(!before.contains("Activate"));
    assert!(puts(&w).is_empty());
}

#[tokio::test]
async fn eligible_and_activated() {
    let w = eligible(pim_rules("PT7H", true, false, false)).await;
    let html = refused_page(&w).await;
    assert!(html.contains("What to ask for:"), "the hint stays");
    assert!(
        html.contains(">Activate Key Vault Secrets User</a>"),
        "{html}"
    );
    // The link names the eligibility it is for, so the form opens on it.
    let enc = |s: &str| s.replace('/', "%2F");
    let href = format!(
        "{FORM}?role={SECRETS_USER}&#38;scope={}&#38;schedule={}&#38;back=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password",
        enc(RG),
        enc(SCHEDULE)
    );
    assert!(html.contains(&href), "{html}");

    let (status, form) = w
        .page(&format!(
            "{FORM}?role={SECRETS_USER}&back=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{form}");
    assert!(form.contains("Activate <span class=\"muted\">Key Vault Secrets User</span>"));
    assert!(
        form.contains("the vault&#39;s whole resource group"),
        "{form}"
    );
    assert!(form.contains("Up to 7 hours"), "the policy's maximum");
    assert!(form.contains("<option value=\"420\""));
    assert!(
        !form.contains("<option value=\"480\""),
        "nothing above the maximum"
    );
    assert!(form.contains("t type secrets or personal details"));
    assert_eq!(hidden_value(&form, "role").as_deref(), Some(SECRETS_USER));

    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("Role turned on"), "{html}");
    assert!(html.contains("Key Vault can take a few minutes"));
    assert!(
        html.contains("href=\"/v/kv-test/secrets/db-password\">Try again</a>"),
        "{html}"
    );

    let sent = puts(&w);
    assert_eq!(sent.len(), 1);
    let (path, body) = &sent[0];
    assert!(
        path.starts_with(&format!(
            "{RG}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
        )),
        "at the eligibility's scope: {path}"
    );
    let p = &body["properties"];
    assert_eq!(p["requestType"], "SelfActivate");
    assert_eq!(p["principalId"], support::USER_OID);
    assert!(
        p["roleDefinitionId"]
            .as_str()
            .unwrap()
            .ends_with(SECRETS_USER)
    );
    assert_eq!(p["linkedRoleEligibilityScheduleId"], SCHEDULE);
    assert_eq!(p["scheduleInfo"]["expiration"]["type"], "AfterDuration");
    assert_eq!(p["scheduleInfo"]["expiration"]["duration"], "PT1H");
    assert_eq!(p["justification"], "Fixing INC-42 in production");
    assert!(p.get("ticketInfo").is_none());
    // The bearer was the person's Management token.
    let bearers = w.arm.state.authz.lock().unwrap().bearers.clone();
    assert!(
        bearers
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://management.azure.com/.default:for:")),
        "{bearers:?}"
    );
}

#[tokio::test]
async fn approval_needed() {
    let w = eligible(pim_rules("PT8H", true, false, true)).await;
    let (_, form) = w.page(&format!("{FORM}?role={SECRETS_USER}")).await;
    assert!(form.contains("PIM needs someone to approve this"), "{form}");
    assert!(form.contains("kv-approvers (Group)"));
    reply(
        &w,
        201,
        serde_json::json!({"properties": {"status": "PendingApproval"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("Waiting for approval"), "{html}");
    assert!(html.contains("kv-approvers (Group)"));
    assert!(html.contains("portal.azure.com"));
    // My access reads it back from ARM: nothing kept by Keyring.
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.pending = vec![(RG.into(), SECRETS_USER.into(), "PendingApproval".into())];
    }
    let (_, mine) = w.page("/v/kv-test/my-access").await;
    assert!(mine.contains("Waiting for approval"), "{mine}");
}

#[tokio::test]
async fn policy_needs_a_ticket() {
    let w = eligible(pim_rules("PT8H", true, true, false)).await;
    let (_, form) = w.page(&format!("{FORM}?role={SECRETS_USER}")).await;
    assert!(
        form.contains("Ticket number</label>"),
        "not marked optional: {form}"
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body_text(res)
            .await
            .contains("Give the ticket number. PIM asks for one.")
    );
    assert!(puts(&w).is_empty());

    let res = w
        .post(
            FORM,
            &form_fields(&[
                ("ticket_system", "ServiceNow"),
                ("ticket_number", "CHG-1234"),
            ]),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let sent = puts(&w);
    assert_eq!(
        sent[0].1["properties"]["ticketInfo"]["ticketNumber"],
        "CHG-1234"
    );
    assert_eq!(
        sent[0].1["properties"]["ticketInfo"]["ticketSystem"],
        "ServiceNow"
    );
}

#[tokio::test]
async fn acrs_challenge_sends_the_person_through_sign_in() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    reply(
        &w,
        400,
        serde_json::json!({"error": {"code": "RoleAssignmentRequestAcrsValidationFailed",
            "message": "&claims=%7B%22access_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22c1%22%7D%7D%7D"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("PIM wants you to confirm it"), "{html}");
    assert!(
        !html.contains("Fixing INC-42"),
        "the justification is never in the page or a URL"
    );
    let start = html
        .split("href=\"")
        .find(|s| s.starts_with("/auth/start"))
        .and_then(|s| s.split('"').next())
        .unwrap()
        .replace("&#38;", "&")
        .replace("&amp;", "&");
    assert!(
        start.contains("return_to=%2Fv%2Fkv-test%2Fmy-access%2Factivate%3Frole%3D"),
        "{start}"
    );
    assert!(!start.contains("Fixing"), "{start}");
    // Sign-in carries the checked challenge to Entra.
    let res = w.get(&start).await;
    let entra = location(&res);
    let claims = url::Url::parse(&entra)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "claims")
        .map(|(_, v)| v.into_owned());
    assert_eq!(
        claims.as_deref(),
        Some(r#"{"access_token":{"acrs":{"essential":true,"value":"c1"}}}"#)
    );
    assert!(!entra.contains("Fixing"));

    // A challenge that isn't one Keyring understands is never passed on:
    // the refusal shows ARM's code only.
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    reply(
        &w,
        400,
        serde_json::json!({"error": {"code": "RoleAssignmentRequestAcrsValidationFailed",
            "message": "&claims=%7B%22userinfo%22%3A%7B%7D%7D <script>"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    let html = body_text(res).await;
    assert!(
        html.contains("RoleAssignmentRequestAcrsValidationFailed"),
        "{html}"
    );
    assert!(!html.contains("userinfo") && !html.contains("<script>"));
}

#[tokio::test]
async fn request_refused() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    reply(
        &w,
        403,
        serde_json::json!({"error": {"code": "AuthorizationFailed", "message": "private Azure detail"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(html.contains("PIM didn"), "{html}");
    assert!(html.contains("AuthorizationFailed"));
    assert!(
        !html.contains("private Azure detail"),
        "never Azure's message"
    );

    // A request PIM accepted but then denied.
    reply(
        &w,
        201,
        serde_json::json!({"properties": {"status": "Denied"}}),
    );
    let html = body_text(w.post(FORM, &form_fields(&[])).await).await;
    assert!(html.contains("Nothing was turned on"), "{html}");

    // A policy rule ARM names puts the person back on the form.
    reply(
        &w,
        400,
        serde_json::json!({"error": {"code": "RoleAssignmentRequestPolicyValidationFailed",
        "message": "The following policy rules failed: [\"ExpirationRule\"]"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body_text(res)
            .await
            .contains("won&#39;t allow this role for that long")
    );
}

#[tokio::test]
async fn duration_above_the_maximum_is_refused_on_the_server() {
    let w = eligible(pim_rules("PT7H", true, false, false)).await;
    for minutes in ["480", "100000", "-1", "0", "abc", ""] {
        let res = w.post(FORM, &form_fields(&[("minutes", minutes)])).await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{minutes}");
    }
    assert!(puts(&w).is_empty());
    // Settings that can't be read: 8 hours at most.
    w.arm.state.authz.lock().unwrap().pim.policy_status = Some(403);
    let res = w.post(FORM, &form_fields(&[("minutes", "540")])).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let res = w.post(FORM, &form_fields(&[("minutes", "480")])).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn hostile_justification_is_cleaned_or_refused() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    let res = w
        .post(
            FORM,
            &form_fields(&[(
                "justification",
                "Fix\u{202E} prod\r\nFORGED=1\u{0000}\u{200B} now",
            )]),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        puts(&w)[0].1["properties"]["justification"],
        "Fix prod FORGED=1 now"
    );
    for bad in [
        "abc",
        "\u{0007}\u{0007}\u{0007}\u{0007}\u{0007}\u{0007}",
        &"x".repeat(201),
    ] {
        let res = w.post(FORM, &form_fields(&[("justification", bad)])).await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
    }
    let res = w
        .post(FORM, &form_fields(&[("ticket_number", &"9".repeat(65))]))
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(puts(&w).len(), 1);
    // Not eligible for a role named in the form: nothing sent.
    let res = w
        .post(FORM, &form_fields(&[("role", support::CERT_OFFICER)]))
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = w.post(FORM, &form_fields(&[("role", "../../x")])).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(puts(&w).len(), 1);
}

#[tokio::test]
async fn forged_and_cross_site_posts_are_refused() {
    use tower::ServiceExt;
    let w = eligible(pim_rules("PT8H", false, false, false)).await;
    for (path, fields) in [
        (FORM, form_fields(&[])),
        (
            "/v/kv-test/my-access/deactivate",
            vec![("role", SECRETS_USER), ("scope", RG)],
        ),
    ] {
        for (csrf, origin) in [
            ("forged", "http://localhost:3000"),
            (w.csrf.as_str(), "https://evil.example"),
        ] {
            let mut all = vec![("csrf", csrf)];
            all.extend_from_slice(&fields);
            let body: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(all)
                .finish();
            let req = axum::http::Request::post(path)
                .header("origin", origin)
                .header("cookie", &w.cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(body))
                .unwrap();
            let res = w.app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path} {origin}");
        }
    }
    assert!(puts(&w).is_empty());
}

#[tokio::test]
async fn my_access_lists_roles_and_deactivates() {
    let w = world().await;
    let end = chrono::Utc::now() + chrono::Duration::minutes(130);
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.active = vec![
            (
                VAULT.into(),
                SECRETS_USER.into(),
                "Activated".into(),
                Some(end.to_rfc3339()),
            ),
            (
                "/subscriptions/sub-a".into(),
                support::CERT_OFFICER.into(),
                "Assigned".into(),
                None,
            ),
            (
                "/subscriptions/sub-b".into(),
                SECRETS_USER.into(),
                "Activated".into(),
                None,
            ),
            (
                VAULT.into(),
                support::READER_ROLE.into(),
                "Assigned".into(),
                None,
            ),
        ];
        m.pim.eligible = vec![(RG.into(), SECRETS_USER.into(), SCHEDULE.into())];
    }
    let (status, html) = w.page("/v/kv-test/my-access").await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains("aria-current=\"page\">My access</a>"),
        "in the vault's navigation"
    );
    assert!(
        html.contains("Key Vault Secrets User <span class=\"badge badge-ok\">Activated</span>"),
        "{html}"
    );
    assert!(
        html.contains("2 hours 9 minutes left") || html.contains("2 hours 10 minutes left"),
        "{html}"
    );
    assert!(html.contains("Key Vault Certificates Officer"));
    assert!(html.contains("No end date"));
    assert!(!html.contains(">Reader<"), "not a Key Vault data role");
    assert_eq!(
        html.matches(">Deactivate</button>").count(),
        1,
        "only the PIM activation"
    );
    assert!(
        html.contains(&format!("{FORM}?role={SECRETS_USER}")),
        "eligible row offers Activate"
    );

    let res = w
        .post(
            "/v/kv-test/my-access/deactivate",
            &[("role", SECRETS_USER), ("scope", VAULT)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&res), "/v/kv-test/my-access");
    let sent = puts(&w);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].0.starts_with(&format!(
        "{VAULT}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
    )));
    let p = &sent[0].1["properties"];
    assert_eq!(p["requestType"], "SelfDeactivate");
    assert_eq!(p["principalId"], support::USER_OID);
    assert!(p.get("scheduleInfo").is_none() && p.get("justification").is_none());

    // Only a role PIM lists as activated for this person here can be
    // turned off: a permanent one, another vault's, or a made-up scope
    // sends nothing.
    for (role, scope) in [
        (support::CERT_OFFICER, "/subscriptions/sub-a"),
        (SECRETS_USER, "/subscriptions/sub-b"),
        (SECRETS_USER, "/subscriptions/sub-a/x/../y"),
        ("not-a-guid", VAULT),
    ] {
        let res = w
            .post(
                "/v/kv-test/my-access/deactivate",
                &[("role", role), ("scope", scope)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{role} {scope}");
    }
    assert_eq!(puts(&w).len(), 1);
}

#[tokio::test]
async fn my_access_without_pim() {
    let w = world().await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible_status = Some(400);
    }
    let (status, html) = w.page("/v/kv-test/my-access").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("PIM isn&#39;t available here"), "{html}");
    assert!(!html.contains("private Azure detail"));
}

const SUB: &str = "/subscriptions/sub-a";
/// A management group whose ID is longer than the subscription's.
const MG: &str =
    "/providers/Microsoft.Management/managementGroups/a-very-long-management-group-name";
const ROOT_MG: &str = "/providers/Microsoft.Management/managementGroups/root";

/// The scope the one schedule request was sent to.
fn put_scope(w: &support::World) -> String {
    let sent = puts(w);
    assert_eq!(sent.len(), 1, "one request sent");
    sent[0]
        .0
        .split("/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/")
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn activates_at_the_nearest_scope_not_the_longest_id() {
    // Eligible at the subscription and at a management group with a longer
    // ID: the subscription is nearer the vault, so the role is turned on
    // there, not for everything under the management group.
    for (offered, want) in [
        (vec![SUB, MG], SUB),
        (vec![MG, SUB], SUB),
        (vec![ROOT_MG, MG, SUB, RG], RG),
        (vec![MG, RG, VAULT, SUB], VAULT),
        // Only a management group on offer: it is used, as ARM returned it.
        (vec![MG], MG),
    ] {
        let w = eligible(pim_rules("PT8H", true, false, false)).await;
        w.arm.state.authz.lock().unwrap().pim.eligible = offered
            .iter()
            .map(|s| {
                (
                    (*s).to_owned(),
                    SECRETS_USER.to_owned(),
                    SCHEDULE.to_owned(),
                )
            })
            .collect();
        // Open the form with no eligibility named, as an old link would:
        // it shows the nearest one, and posting what it shows uses it.
        let (status, form) = w
            .page(&format!(
                "{FORM}?role={SECRETS_USER}&back=/v/kv-test/secrets"
            ))
            .await;
        assert_eq!(status, StatusCode::OK);
        let shown = hidden_value(&form, "scope").expect("scope on the form");
        assert_eq!(shown.to_lowercase(), want.to_lowercase());
        let schedule = hidden_value(&form, "schedule").expect("schedule on the form");
        let res = w
            .post(
                FORM,
                &form_fields(&[("scope", &shown), ("schedule", &schedule)]),
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(put_scope(&w).to_lowercase(), want.to_lowercase());
    }
}

#[tokio::test]
async fn only_key_vault_roles_can_be_turned_on_or_off() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        // Eligible for Owner and Reader as well, and Owner is on.
        m.pim
            .eligible
            .push((RG.into(), support::OWNER_ROLE.into(), SCHEDULE.into()));
        m.pim
            .eligible
            .push((RG.into(), support::READER_ROLE.into(), SCHEDULE.into()));
        m.pim.active = vec![(
            RG.into(),
            support::OWNER_ROLE.into(),
            "Activated".into(),
            None,
        )];
    }
    for role in [support::OWNER_ROLE, support::READER_ROLE] {
        // The form says there is nothing to activate, and reads nothing.
        let reads = pim_reads(&w);
        let (status, html) = w
            .page(&format!("{FORM}?role={role}&back=/v/kv-test/secrets"))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{role}");
        assert!(html.contains("Nothing to activate"));
        assert_eq!(pim_reads(&w), reads, "{role}: refused before any ARM call");
        // The post sends nothing.
        let res = w.post(FORM, &form_fields(&[("role", role)])).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{role}");
        // Nor does turning it off.
        let res = w
            .post(
                "/v/kv-test/my-access/deactivate",
                &[("role", role), ("scope", RG)],
            )
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{role}");
    }
    assert!(puts(&w).is_empty(), "no request reached ARM");
    // The Key Vault role still works.
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(puts(&w).len(), 1);
}

#[tokio::test]
async fn a_role_that_is_not_a_guid_never_reaches_an_address() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    for role in [
        "x&back=https://evil.example",
        "../../secrets",
        "4633458b-17de-408a-b874-0445c86b69e6%26admin%3D1",
        "\"><script>",
    ] {
        // Step-up isn't set here, so the form is reached and refuses.
        let res = w.post(FORM, &form_fields(&[("role", role)])).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{role}");
        let html = body_text(res).await;
        assert!(!html.contains("evil.example"), "{role}");
        assert!(!html.contains("<script>"), "{role}");
    }
    assert!(puts(&w).is_empty());
}

#[tokio::test]
async fn an_invisible_justification_is_refused() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    for only in ['\u{061C}', '\u{00AD}', '\u{E0041}', '\u{200B}', '\u{FE0F}'] {
        // Enough of them to pass a length check made before cleaning.
        let j = only.to_string().repeat(12);
        let res = w.post(FORM, &form_fields(&[("justification", &j)])).await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "U+{:04X}",
            only as u32
        );
        // Three letters padded out with invisible ones is still too
        // short: they become one space, and "ab c" is four characters.
        let padded = format!("ab{only}{only}{only}{only}c");
        let res = w
            .post(FORM, &form_fields(&[("justification", &padded)]))
            .await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "padded U+{:04X}",
            only as u32
        );
    }
    assert!(puts(&w).is_empty(), "nothing reached ARM");
}

#[tokio::test]
async fn hostile_values_from_arm_send_nothing() {
    // ARM is trusted, but what it returns still goes into a request
    // address and body. Anything that isn't a plain scope or ID is dropped.
    let good_schedule = SCHEDULE;
    for (scope, schedule) in [
        (
            "/subscriptions/sub-a/resourceGroups/rg-kv-test?x=1",
            good_schedule,
        ),
        (
            "/subscriptions/sub-a/resourceGroups/rg-kv-test%2F..%2F..",
            good_schedule,
        ),
        (
            "/subscriptions/sub-a/resourceGroups/../../providers/x",
            good_schedule,
        ),
        (
            "/subscriptions/sub-a/resourceGroups/rg-kv-test#frag",
            good_schedule,
        ),
        ("https://evil.example/subscriptions/sub-a", good_schedule),
        (RG, "/subscriptions/sub-a/providers/x?api-version=1"),
        (RG, "/subscriptions/sub-a/providers/..%2F..%2Fx"),
        (RG, "/subscriptions/sub-a/providers/../x"),
        (RG, "sched\r\nX-Injected: 1"),
    ] {
        let w = eligible(pim_rules("PT8H", true, false, false)).await;
        w.arm.state.authz.lock().unwrap().pim.eligible =
            vec![(scope.into(), SECRETS_USER.into(), schedule.into())];
        let res = w.post(FORM, &form_fields(&[])).await;
        assert!(
            res.status().is_client_error(),
            "{scope} {schedule}: {}",
            res.status()
        );
        assert!(
            puts(&w).is_empty(),
            "{scope} {schedule}: a request was sent"
        );
    }
}

#[tokio::test]
async fn hostile_role_definition_ids_from_arm_send_nothing() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    for id in [
        format!(
            "/subscriptions/sub-a/providers/Microsoft.Authorization/roleDefinitions/{SECRETS_USER}?x=1"
        ),
        format!("/subscriptions/sub-a/providers/../roleDefinitions/{SECRETS_USER}"),
        format!("https://evil.example/roleDefinitions/{SECRETS_USER}"),
        format!("/subscriptions/sub-a%2Fx/roleDefinitions/{SECRETS_USER}"),
    ] {
        w.arm.state.authz.lock().unwrap().pim.eligible_role_id = Some(id.clone());
        let res = w.post(FORM, &form_fields(&[])).await;
        assert!(res.status().is_client_error(), "{id}: {}", res.status());
        assert!(puts(&w).is_empty(), "{id}: a request was sent");
    }
}

#[tokio::test]
async fn an_acrs_challenge_with_step_up_set() {
    // Step-up asks for c1 before the form; PIM then asks for c2. Both end
    // up asked for at sign-in, and neither comes from the request.
    let w = support::world_with(&[("KEYRING_STEP_UP_AUTH_CONTEXT", "c1")]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.eligible = vec![(RG.into(), SECRETS_USER.into(), SCHEDULE.into())];
        m.pim
            .policies
            .insert(SECRETS_USER.into(), pim_rules("PT8H", true, false, false));
    }
    // Without the step-up context the activation is stopped first: no
    // read of eligibility and no request.
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Confirm it&#39;s you"));
    assert!(puts(&w).is_empty());

    // With step-up met, PIM's own challenge is passed on.
    let id = w.cookie.split('=').nth(1).unwrap();
    let session = w.state.sessions.get(id).unwrap();
    session.set_sign_in_facts(keyring::auth::step_up::SignInFacts {
        acrs: vec!["c1".into()],
        auth_time: Some(keyring::auth::step_up::unix(std::time::SystemTime::now())),
    });
    reply(
        &w,
        400,
        serde_json::json!({"error": {"code": "RoleAssignmentRequestAcrsValidationFailed",
            "message": "&claims=%7B%22access_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22c2%22%7D%7D%7D"}}),
    );
    let res = w.post(FORM, &form_fields(&[])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = body_text(res).await;
    assert!(
        html.contains("PIM wants you to confirm it&#39;s you"),
        "{html}"
    );
    assert!(
        !html.contains("Fixing INC-42"),
        "the justification isn't carried into the sign-in link"
    );
    assert_eq!(puts(&w).len(), 1, "one request, refused by PIM");
}

/// A second schedule, for the same role at the subscription.
const SUB_SCHEDULE: &str = "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/c2588559-3dd7-5dfc-a4c5-65b313b9a524";
const VAULT_SCHEDULE: &str = "/subscriptions/sub-a/providers/Microsoft.Authorization/roleEligibilitySchedules/d3699660-4ee8-6e0d-b5d6-76c424cab635";

#[tokio::test]
async fn activation_is_tied_to_the_eligibility_the_form_showed() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    // Eligible at the vault and at the subscription: the form shows the
    // vault, the nearer one.
    w.arm.state.authz.lock().unwrap().pim.eligible = vec![
        (VAULT.into(), SECRETS_USER.into(), VAULT_SCHEDULE.into()),
        (SUB.into(), SECRETS_USER.into(), SUB_SCHEDULE.into()),
    ];
    let (status, form) = w
        .page(&format!(
            "{FORM}?role={SECRETS_USER}&back=/v/kv-test/secrets"
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let scope = hidden_value(&form, "scope").unwrap();
    let schedule = hidden_value(&form, "schedule").unwrap();
    assert_eq!(scope.to_lowercase(), VAULT.to_lowercase());
    assert!(form.contains("the vault kv-test"), "{form}");

    // The vault eligibility goes before the form is posted. Only the
    // subscription is left: nothing is sent, and the form comes back
    // showing the subscription and saying it changed.
    w.arm.state.authz.lock().unwrap().pim.eligible =
        vec![(SUB.into(), SECRETS_USER.into(), SUB_SCHEDULE.into())];
    let posted = form_fields(&[("scope", &scope), ("schedule", &schedule)]);
    let res = w.post(FORM, &posted).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let again = body_text(res).await;
    assert!(puts(&w).is_empty(), "nothing was sent to a broader scope");
    assert!(again.contains("Your eligible roles changed"), "{again}");
    assert!(again.contains("whole subscription"), "{again}");
    assert_eq!(
        hidden_value(&again, "scope").unwrap().to_lowercase(),
        SUB.to_lowercase()
    );
    // What was typed is kept for the second go.
    assert!(again.contains("Fixing INC-42 in production"));

    // Posting what the new form shows is the confirmation: it goes to
    // the subscription, as shown.
    let res = w
        .post(
            FORM,
            &form_fields(&[("scope", SUB), ("schedule", SUB_SCHEDULE)]),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(put_scope(&w).to_lowercase(), SUB.to_lowercase());
}

#[tokio::test]
async fn a_post_that_does_not_name_its_eligibility_sends_nothing() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    for (scope, schedule) in [
        // None named, as a hand-made post would be.
        ("", ""),
        // Same scope, another schedule: the eligibility was replaced.
        (RG, SUB_SCHEDULE),
        // Same schedule, another scope.
        (SUB, SCHEDULE),
        // Not plain ARM values: never used, never echoed as a target.
        (
            "/subscriptions/sub-a/resourceGroups/rg-kv-test?x=1",
            SCHEDULE,
        ),
        ("https://evil.example/subscriptions/sub-a", SCHEDULE),
        (RG, "/a/../b"),
    ] {
        let res = w
            .post(
                FORM,
                &form_fields(&[("scope", scope), ("schedule", schedule)]),
            )
            .await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{scope} {schedule}"
        );
        let html = body_text(res).await;
        assert!(html.contains("Your eligible roles changed"), "{scope}");
        // The form that comes back names what ARM lists, not what was posted.
        assert_eq!(
            hidden_value(&html, "scope").unwrap().to_lowercase(),
            RG.to_lowercase(),
            "{scope}"
        );
        assert!(!html.contains("evil.example"));
    }
    assert!(puts(&w).is_empty(), "nothing reached ARM");
}

#[tokio::test]
async fn my_access_links_name_their_eligibility() {
    let w = world().await;
    w.arm.state.authz.lock().unwrap().pim.eligible = vec![
        (VAULT.into(), SECRETS_USER.into(), VAULT_SCHEDULE.into()),
        (SUB.into(), SECRETS_USER.into(), SUB_SCHEDULE.into()),
    ];
    let (status, html) = w.page("/v/kv-test/my-access").await;
    assert_eq!(status, StatusCode::OK);
    let enc = |s: &str| s.replace('/', "%2F");
    for (scope, schedule) in [(VAULT, VAULT_SCHEDULE), (SUB, SUB_SCHEDULE)] {
        let link = format!(
            "{FORM}?role={SECRETS_USER}&#38;scope={}&#38;schedule={}",
            enc(scope),
            enc(schedule)
        );
        assert!(html.contains(&link), "{scope}: {html}");
    }
    // The subscription's link opens the form on the subscription, even
    // though the vault's is nearer.
    let (status, form) = w
        .page(&format!(
            "{FORM}?role={SECRETS_USER}&scope={}&schedule={}&back=/v/kv-test/my-access",
            enc(SUB),
            enc(SUB_SCHEDULE)
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hidden_value(&form, "scope").unwrap().to_lowercase(),
        SUB.to_lowercase()
    );
    assert!(!form.contains("Your eligible roles changed"));
}

#[tokio::test]
async fn an_active_key_vault_role_is_listed_when_its_definition_cannot_be_read() {
    let w = world().await;
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.pim.active = vec![
            (VAULT.into(), SECRETS_USER.into(), "Activated".into(), None),
            (
                VAULT.into(),
                "11111111-2222-3333-4444-555555555555".into(),
                "Assigned".into(),
                None,
            ),
        ];
        // No role definition can be read.
        m.definitions_status = Some(403);
    }
    let (status, html) = w.page("/v/kv-test/my-access").await;
    assert_eq!(status, StatusCode::OK);
    // The built-in role is known by its GUID: named, and can be turned off.
    assert!(
        html.contains("Key Vault Secrets User <span class=\"badge badge-ok\">Activated</span>"),
        "{html}"
    );
    assert_eq!(html.matches(">Deactivate</button>").count(), 1);
    // The other one can't be told apart, so the page says so.
    assert!(html.contains("This list may be incomplete"), "{html}");
    assert!(!html.contains("No Key Vault role that reaches this vault is on"));
}

#[tokio::test]
async fn already_on_names_no_duration() {
    let w = eligible(pim_rules("PT8H", true, false, false)).await;
    reply(
        &w,
        409,
        serde_json::json!({"error": {"code": "RoleAssignmentExists", "message": "x"}}),
    );
    let res = w.post(FORM, &form_fields(&[("minutes", "60")])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("This role is already on"), "{html}");
    assert!(html.contains("was already on"), "{html}");
    assert!(!html.contains("for 1 hour"), "{html}");
}
