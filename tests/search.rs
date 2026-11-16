//! Search across every vault (#209).

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use keyring::azure::fanout::Limits;
use support::keyvault::KvState;

const DAY: i64 = 86_400;

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

/// Short limits, so the slow vault is given up on quickly.
fn quick() -> Limits {
    Limits {
        concurrency: 6,
        vault_timeout: Duration::from_millis(500),
        deadline: Duration::from_secs(5),
    }
}

/// Three vaults: one readable with a mix of items, one that refuses
/// everything, one too slow to answer in time, and a fourth readable one.
async fn three_vaults() -> (support::World, [Arc<KvState>; 4]) {
    let payments = Arc::new(KvState::default());
    let locked = Arc::new(KvState::default());
    let slow = Arc::new(KvState::default());
    let platform = Arc::new(KvState::default());
    let n = now();
    payments.put_with("db-password", "PAYMENTS-VALUE", |v| {
        v.exp = Some(n + 10 * DAY);
        v.tags.insert("team".into(), "Payments".into());
        v.content_type = Some("text/plain".into());
    });
    payments.put_with("api-config", "CONFIG-VALUE", |v| {
        v.content_type = Some("application/json".into());
    });
    payments.add_key_with("db-signing", "RSA", |v| v.exp = Some(n - DAY));
    platform.put_with("DB-admin", "PLATFORM-VALUE", |v| v.enabled = false);
    platform.add_cert_version(
        "web-tls",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(false, false),
        |v| {
            v.exp = Some(n + 60 * DAY);
            v.tags.insert("env".into(), "prod".into());
        },
    );
    locked.put("db-hidden", "LOCKED-VALUE");
    *locked.fail.lock().unwrap() = Some((403, "Forbidden"));
    slow.put("db-late", "SLOW-VALUE");
    *slow.delay.lock().unwrap() = Duration::from_secs(3);
    let w = support::world_of_vaults(
        vec![
            ("kv-payments", payments.clone()),
            ("kv-locked", locked.clone()),
            ("kv-slow", slow.clone()),
            ("kv-platform", platform.clone()),
        ],
        quick(),
    )
    .await;
    (w, [payments, locked, slow, platform])
}

fn no_value_reads(vaults: &[Arc<KvState>]) -> Vec<support::keyvault::NoValueReads> {
    vaults.iter().map(|v| v.no_value_reads()).collect()
}

#[tokio::test]
async fn finds_matches_across_vaults_and_says_which_were_not_read() {
    let (w, vaults) = three_vaults().await;
    let _guard = no_value_reads(&vaults);
    let (status, html) = w.page("/search?q=DB").await;
    assert_eq!(status, StatusCode::OK);
    // Results from the two readable vaults, grouped by vault.
    for (vault, name, path) in [
        ("kv-payments", "db-password", "secrets"),
        ("kv-payments", "db-signing", "keys"),
        ("kv-platform", "DB-admin", "secrets"),
    ] {
        assert!(
            html.contains(&format!("href=\"/v/{vault}/{path}/{name}\"")),
            "{vault} {name}"
        );
    }
    assert!(html.contains("<h2 id=\"vault-kv-payments\">"));
    assert!(html.contains("<h2 id=\"vault-kv-platform\">"));
    assert!(
        html.find("<h2 id=\"vault-kv-payments\">").unwrap()
            > html.find("kv-locked</span>:").unwrap(),
        "notes come before results"
    );
    assert!(!html.contains("api-config"), "only matches are listed");
    // The same status badges as each vault's list.
    assert!(html.contains("<span class=\"badge badge-error\">Expires within 30 days</span>"));
    assert!(html.contains("<span class=\"badge badge-error\">Expired</span>"));
    assert!(html.contains("<span class=\"badge badge-muted\">Disabled</span>"));
    // A note for each vault that couldn't be read.
    assert!(html.contains(
        "<span class=\"mono\">kv-locked</span>: You don&#39;t have a Key Vault role on it."
    ));
    assert!(html.contains("<span class=\"mono\">kv-slow</span>: Took too long to answer."));
    assert!(!html.contains("db-hidden") && !html.contains("db-late"));
    // Never a value.
    assert!(!html.contains("-VALUE"));
}

#[tokio::test]
async fn matches_tags_and_content_types_ignoring_case() {
    let (w, vaults) = three_vaults().await;
    let _guard = no_value_reads(&vaults);
    let (_, html) = w.page("/search?q=team%3Dpay").await;
    assert!(html.contains(">db-password<") && !html.contains(">db-signing<"));
    let (_, html) = w.page("/search?q=JSON").await;
    assert!(html.contains(">api-config<") && !html.contains(">db-password<"));
    let (_, html) = w.page("/search?q=Prod").await;
    assert!(html.contains(">web-tls<"));
    assert!(html.contains("<span class=\"badge badge-warn\">Expires within 90 days</span>"));
    let (_, html) = w.page("/search?q=nothing-like-this").await;
    assert!(html.contains("Nothing matches"));
}

#[tokio::test]
async fn filters_by_kind_vault_and_status() {
    let (w, vaults) = three_vaults().await;
    let _guard = no_value_reads(&vaults);
    let (_, html) = w.page("/search?q=db&type=key").await;
    assert!(html.contains(">db-signing<") && !html.contains(">db-password<"));
    let (_, html) = w.page("/search?q=db&vault=kv-platform").await;
    assert!(html.contains(">DB-admin<") && !html.contains(">db-password<"));
    assert!(
        !html.contains("kv-locked</span>:"),
        "only the chosen vault is read"
    );
    let (_, html) = w.page("/search?q=db&status=expiring").await;
    assert!(html.contains(">db-password<") && !html.contains(">db-signing<"));
    let (_, html) = w.page("/search?q=db&status=expired").await;
    assert!(html.contains(">db-signing<") && !html.contains(">db-password<"));
    let (_, html) = w.page("/search?q=db&status=disabled").await;
    assert!(html.contains(">DB-admin<") && !html.contains(">db-password<"));
    let (_, html) = w.page("/search?q=db&vault=kv-gone").await;
    assert!(html.contains("isn't one of the vaults you can see"));
}

#[tokio::test]
async fn a_second_search_within_a_minute_reads_no_vault_again() {
    let (w, vaults) = three_vaults().await;
    let [payments, locked, _, platform] = &vaults;
    let _ = w.page("/search?q=db").await;
    let lists = |v: &KvState| v.log.lock().unwrap().len();
    let before = (lists(payments), lists(platform), lists(locked));
    let (_, html) = w.page("/search?q=web").await;
    assert!(html.contains(">web-tls<"));
    assert_eq!(
        (lists(payments), lists(platform)),
        (before.0, before.1),
        "vaults read in full are reused"
    );
    assert!(
        lists(locked) > before.2,
        "a vault that failed is asked again"
    );
    // The expiry dashboard shares the same lists.
    let (_, html) = w.page("/expiry").await;
    assert!(html.contains(">db-password<"));
    assert_eq!((lists(payments), lists(platform)), (before.0, before.1));
}

#[tokio::test]
async fn a_change_to_a_vault_drops_its_kept_list() {
    let (w, vaults) = three_vaults().await;
    let platform = &vaults[3];
    let (_, html) = w.page("/search?q=db-admin").await;
    assert!(html.contains("row-muted"), "disabled at first");
    // A form token for the vault the change is made in.
    let id = w.cookie.split('=').nth(1).unwrap();
    let session = w.state.sessions.get(id).unwrap();
    let mut w = w;
    w.csrf = session.csrf_for(Some("kv-platform"));
    let res = w
        .post(
            "/v/kv-platform/secrets/DB-admin/enabled",
            &[("state", "on")],
        )
        .await;
    assert!(res.status().is_redirection(), "{}", res.status());
    assert!(platform.current("DB-admin").unwrap().enabled);
    let (_, html) = w.page("/search?q=db-admin").await;
    assert!(
        !html.contains("row-muted"),
        "the change shows straight away"
    );
}

#[tokio::test]
async fn the_query_length_is_capped() {
    let (w, vaults) = three_vaults().await;
    let _guard = no_value_reads(&vaults);
    let calls = |v: &KvState| v.log.lock().unwrap().len();
    let long = "a".repeat(keyring::routes::search::MAX_QUERY_CHARS + 1);
    let (status, html) = w.page(&format!("/search?q={long}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("That search is too long"));
    assert_eq!(calls(&vaults[0]), 0, "no vault is read");
    assert!(html.contains("maxlength=\"100\""));
}

#[tokio::test]
async fn an_empty_search_reads_nothing_and_the_top_bar_has_the_box() {
    let (w, vaults) = three_vaults().await;
    let (status, html) = w.page("/search?q=%20%20").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Type part of a name"));
    assert_eq!(vaults[0].log.lock().unwrap().len(), 0);
    // Every signed-in page has the search box: a plain GET form, no script.
    let (_, html) = w.page("/vaults").await;
    let bar = &html[html.find("<header").unwrap()..html.find("</header>").unwrap()];
    assert!(bar.contains(
        "<form class=\"site-search\" method=\"get\" action=\"/search\" role=\"search\">"
    ));
    assert!(bar.contains("<label for=\"site-search-q\""));
    assert!(bar.contains("name=\"q\" type=\"search\""));
    // Signed-out pages don't.
    let res = w.get("/auth/sign-in").await;
    let html = support::body_text(res).await;
    assert!(!html.contains("site-search"));
}
