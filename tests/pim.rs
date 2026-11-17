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

fn form_fields<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut f = vec![
        ("role", SECRETS_USER),
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
    let href =
        format!("{FORM}?role={SECRETS_USER}&#38;back=%2Fv%2Fkv-test%2Fsecrets%2Fdb-password");
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
