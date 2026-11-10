//! Vault discovery with a mock Resource Graph.

mod support;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

struct Harness {
    app: axum::Router,
    cookie: String,
    arm: support::MockArm,
    csrf: String,
    _idp: support::MockIdp,
}

async fn harness() -> Harness {
    let idp = support::start_idp().await;
    let arm = support::start_arm().await;
    let (state, app, cookie) = support::signed_in_app(support::config_with_arm(&idp, &arm));
    let id = cookie.split('=').nth(1).unwrap();
    let csrf = state.sessions.get(id).unwrap().csrf.clone();
    Harness {
        app,
        cookie,
        arm,
        csrf,
        _idp: idp,
    }
}

impl Harness {
    async fn get(&self, path: &str) -> Response<Body> {
        let req = Request::get(path)
            .header("cookie", &self.cookie)
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }

    async fn post(&self, path: &str, form: &str) -> Response<Body> {
        let req = Request::post(path)
            .header("origin", "http://localhost:3000")
            .header("cookie", &self.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap()
    }
}

async fn text(res: Response<Body>) -> String {
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

fn seed(h: &Harness) {
    *h.arm.state.vaults.lock().unwrap() = vec![
        support::vault_row("kv-prod", "sub-a", true),
        support::vault_row("kv-test", "sub-b", false),
        support::vault_row("kv-data", "sub-a", true),
    ];
    *h.arm.state.subscriptions.lock().unwrap() = vec![
        json!({"id": "/subscriptions/sub-a", "subscriptionId": "sub-a", "name": "Production"}),
        json!({"id": "/subscriptions/sub-b", "subscriptionId": "sub-b", "name": "Testing"}),
    ];
}

#[tokio::test]
async fn lists_vaults_from_several_subscriptions() {
    let h = harness().await;
    seed(&h);
    let res = h.get("/vaults").await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = text(res).await;
    for v in ["kv-prod", "kv-test", "kv-data", "Production", "Testing"] {
        assert!(html.contains(v), "{v}");
    }
    assert!(html.contains("Azure RBAC"));
    assert!(html.contains("Access policies"));
    assert!(html.contains("You can see 3 vaults"));
    // Sorted by name.
    let a = html.find("kv-data").unwrap();
    let b = html.find("kv-prod").unwrap();
    let c = html.find("kv-test").unwrap();
    assert!(a < b && b < c);
    // Queries went to Resource Graph with the user's OBO management token.
    let bearers = h.arm.state.bearers.lock().unwrap().clone();
    assert!(bearers.iter().all(|b| {
        b.starts_with("Bearer obo:https://management.azure.com/.default:for:user-api-token")
    }));
}

#[tokio::test]
async fn filters_by_name_subscription_and_tag() {
    let h = harness().await;
    seed(&h);
    let html = text(h.get("/vaults?q=prod").await).await;
    assert!(html.contains("kv-prod") && !html.contains(">kv-test<"));
    let html = text(h.get("/vaults?subscription=sub-b").await).await;
    assert!(html.contains(">kv-test<") && !html.contains(">kv-prod<"));
    let html = text(h.get("/vaults?tag=env%3Dstaging").await).await;
    assert!(html.contains("No vaults match"));
    // The search box is wired for filter-as-you-type.
    assert!(html.contains("data-live-filter=\"vault-table\""));
}

#[tokio::test]
async fn pages_through_more_than_1000_vaults() {
    let h = harness().await;
    let rows: Vec<_> = (0..2500)
        .map(|i| support::vault_row(&format!("kv{i:05}"), "sub-a", true))
        .collect();
    *h.arm.state.vaults.lock().unwrap() = rows;
    let html = text(h.get("/vaults").await).await;
    assert!(html.contains("You can see 2500 vaults"));
    // Three Resource Graph pages of up to 1000, with the skip token passed on.
    let reqs = h.arm.state.requests.lock().unwrap().clone();
    let vault_reqs: Vec<_> = reqs
        .iter()
        .filter(|r| r["query"].as_str().unwrap().contains("keyvault"))
        .collect();
    assert_eq!(vault_reqs.len(), 3);
    assert!(vault_reqs[0]["options"].get("$skipToken").is_none());
    assert_eq!(vault_reqs[1]["options"]["$skipToken"], "skip-1000");
    assert_eq!(vault_reqs[2]["options"]["$skipToken"], "skip-2000");
    // The page shows the first 200 and links to the next page.
    assert!(html.contains("Page 1 of 13"));
    assert!(html.contains("kv00000") && !html.contains("kv00200"));
    let html = text(h.get("/vaults?page=13").await).await;
    assert!(html.contains("kv02499") && html.contains("Page 13 of 13"));
}

#[tokio::test]
async fn no_vaults_shows_a_friendly_explanation() {
    let h = harness().await;
    let html = text(h.get("/vaults").await).await;
    assert!(html.contains("You can't see any vaults yet"));
    assert!(html.contains("Reader role"));
}

#[tokio::test]
async fn resource_graph_errors_are_explained() {
    let h = harness().await;
    *h.arm.state.fail.lock().unwrap() = Some((403, "AuthorizationFailed"));
    let res = h.get("/vaults").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = text(res).await;
    assert!(html.contains("Reader role on the subscription or resource group"));
    assert!(!html.contains("mock failure"));

    *h.arm.state.fail.lock().unwrap() = Some((429, "RateLimiting"));
    let res = h.get("/vaults").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn picking_a_vault_is_remembered_in_the_session() {
    let h = harness().await;
    seed(&h);
    let res = h
        .post("/vaults/select", &format!("csrf={}&name=kv-prod", h.csrf))
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let html = text(h.get("/secrets").await).await;
    assert!(html.contains("<strong>kv-prod</strong>"));
}

#[tokio::test]
async fn picking_rejects_bad_names_and_forged_forms() {
    let h = harness().await;
    let res = h
        .post(
            "/vaults/select",
            &format!("csrf={}&name=evil.com%2F", h.csrf),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = h.post("/vaults/select", "csrf=forged&name=kv-prod").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let html = text(h.get("/secrets").await).await;
    assert!(html.contains("Choose a vault"));
}

#[tokio::test]
async fn picking_a_vault_not_in_the_list_is_refused() {
    let h = harness().await;
    seed(&h);
    let res = h
        .post("/vaults/select", &format!("csrf={}&name=kv-gone", h.csrf))
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let html = text(res).await;
    assert!(html.contains("That vault isn"));
    assert!(html.contains("href=\"/vaults\">Choose a vault</a>"));
    let html = text(h.get("/secrets").await).await;
    assert!(html.contains("Choose a vault first"), "nothing was stored");
}
