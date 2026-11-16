//! How long since each value last changed, across vaults (#210).

mod support;

use std::sync::Arc;

use axum::http::StatusCode;
use support::body_text;
use support::keyvault::KvState;

const DAY: i64 = 86_400;

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

fn seed_vaults(w: &support::World, names: &[&str]) {
    *w.arm.state.vaults.lock().unwrap() = names
        .iter()
        .map(|n| support::vault_row(n, "sub-a", true))
        .collect();
}

/// One of each band, plus a certificate (whose backing secret and key are
/// left out) and a key.
fn seed_items(kv: &KvState) {
    let n = now();
    kv.put_with("fresh", "VALUE-1", |v| v.created = n - 10 * DAY);
    kv.put_with("quarter", "VALUE-2", |v| v.created = n - 100 * DAY);
    kv.put_with("half", "VALUE-3", |v| v.created = n - 200 * DAY);
    kv.put_with("ancient", "VALUE-4", |v| {
        v.created = n - 800 * DAY;
        // Editing properties moves `updated`, not `created`.
        v.updated = n - DAY;
    });
    kv.add_cert("tls", false, "CERT-VALUE");
    // The mock dates a new certificate from a fixed clock. Date it from
    // now, like the rest, so its band doesn't move as real time passes.
    if let Some(c) = kv.certs.lock().unwrap().get_mut("tls") {
        for v in &mut c.versions {
            v.created = n - 20 * DAY;
        }
    }
    kv.add_key_with("signer", "RSA", |v| v.created = n - 500 * DAY);
}

/// The text of the section for one band.
fn band<'a>(html: &'a str, slug: &str) -> &'a str {
    let start = html
        .find(&format!("<h2 id=\"band-{slug}\""))
        .unwrap_or_else(|| panic!("no band {slug}"));
    let rest = &html[start..];
    &rest[..rest.find("</section>").unwrap()]
}

#[tokio::test]
async fn groups_every_type_by_when_the_value_last_changed() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    seed_items(&w.kv.state);
    let _guard = w.kv.state.no_value_reads();
    let (status, html) = w.page("/expiry/age").await;
    assert_eq!(status, StatusCode::OK);
    for (label, count) in [
        ("Over a year", 2),
        ("180 to 365 days", 1),
        ("90 to 180 days", 1),
        ("Under 90 days", 2),
    ] {
        assert!(
            html.contains(&format!("{label} <span class=\"muted\">({count})</span>")),
            "{label}\n{html}"
        );
    }
    assert!(band(&html, "older").contains(">ancient<"));
    assert!(band(&html, "older").contains(">signer<"));
    assert!(band(&html, "365").contains(">half<"));
    assert!(band(&html, "180").contains(">quarter<"));
    // The certificate is shown once, by its own version; its backing
    // secret and key are left out.
    let under = band(&html, "90");
    assert!(under.contains(">fresh<") && under.contains(">tls<"));
    assert_eq!(html.matches(">tls<").count(), 1);
    assert!(under.contains(">Certificate<"));
    // The badge, at the default threshold, on items past a year only.
    assert_eq!(
        html.matches("<span class=\"badge badge-warn\">Not changed in over a year</span>")
            .count(),
        2
    );
    assert!(band(&html, "older").contains("800 days ago"));
    // No unknown band when every item has a date.
    assert!(!html.contains("Date not given"));
    // Both views link to each other.
    assert!(html.contains("<a href=\"/expiry/age\" aria-current=\"page\">"));
    let (_, expiry) = w.page("/expiry").await;
    assert!(expiry.contains("<a href=\"/expiry\" aria-current=\"page\">"));
    assert!(expiry.contains("<a href=\"/expiry/age\">"));
    assert!(!html.contains("VALUE-"), "never values");
}

#[tokio::test]
async fn lists_vaults_it_could_not_read_on_the_page_and_in_the_csv() {
    let good = Arc::new(KvState::default());
    let locked = Arc::new(KvState::default());
    good.put_with("old", "x", |v| v.created = now() - 400 * DAY);
    *locked.fail.lock().unwrap() = Some((403, "Forbidden"));
    let w = support::world_of_vaults(
        vec![("kv-good", good.clone()), ("kv-locked", locked.clone())],
        keyring::azure::fanout::Limits::STANDARD,
    )
    .await;
    let (status, html) = w.page("/expiry/age").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("couldn't be read"));
    assert!(html.contains(
        "<span class=\"mono\">kv-locked</span>: You don&#39;t have a Key Vault role on it"
    ));
    assert!(band(&html, "older").contains(">old<"));
    let csv = body_text(w.get("/expiry/age.csv").await).await;
    let lines: Vec<_> = csv.lines().collect();
    assert_eq!(lines.len(), 3, "{csv}");
    assert!(lines[1].starts_with("kv-good,Secret,old,Yes,"));
    assert!(lines[2].starts_with("kv-locked,NOT READ,You don't have a Key Vault role on it"));
}

#[tokio::test]
async fn shares_the_kept_lists_with_search_and_the_expiry_dashboard() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    seed_items(&w.kv.state);
    let calls = || w.kv.state.log.lock().unwrap().len();
    let _ = w.page("/expiry").await;
    let before = calls();
    let (_, html) = w.page("/expiry/age").await;
    assert!(html.contains(">ancient<"));
    let _ = w.page("/expiry/age.csv").await;
    let _ = w.page("/search?q=fresh").await;
    assert_eq!(calls(), before, "no vault is read again within a minute");
}

#[tokio::test]
async fn filters_and_csv_without_values() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-a", "kv-test"]);
    seed_items(&w.kv.state);
    // Key Vault names are letters, digits and hyphens, so a name can
    // start with `-`; tags can hold anything.
    w.kv.state.put_with("-cmd", "EVIL-VALUE", |v| {
        v.created = now() - 400 * DAY;
        v.tags.insert("env".into(), "prod".into());
        v.tags.insert("@sum".into(), "1".into());
    });
    let _guard = w.kv.state.no_value_reads();
    let (_, html) = w.page("/expiry/age?type=key").await;
    assert!(html.contains(">signer<") && !html.contains(">ancient<"));
    let (_, html) = w.page("/expiry/age?vault=kv-a&tag=env%3Dprod").await;
    assert_eq!(html.matches(">-cmd<").count(), 1);
    assert!(!html.contains(">ancient<"));
    assert!(html.contains("href=\"/expiry/age.csv?vault=kv-a&#38;type=&#38;tag=env%3Dprod"));

    let res = w.get("/expiry/age.csv?vault=kv-a&band=older").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "text/csv; charset=utf-8"
    );
    assert!(
        res.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("keyring-age.csv")
    );
    assert!(
        res.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let csv = body_text(res).await;
    let lines: Vec<_> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "Vault,Type,Name,Enabled,Value changed (UTC),Days since,Band,Tags"
    );
    // Oldest first, and only the band asked for.
    assert_eq!(lines.len(), 4, "{csv}");
    assert!(lines[1].starts_with("kv-a,Secret,ancient,Yes,"));
    assert!(lines[1].contains(",800,Over a year,"));
    assert!(lines[2].starts_with("kv-a,Key,signer,"));
    // Fields that look like formulas are defused.
    assert!(lines[3].starts_with("kv-a,Secret,'-cmd,"), "{}", lines[3]);
    assert!(lines[3].ends_with(",'@sum=1; env=prod"), "{}", lines[3]);
    assert!(!csv.contains("VALUE"));
}

#[tokio::test]
async fn secrets_list_shows_when_the_value_changed_and_filters_on_it() {
    let w = support::world().await;
    seed_items(&w.kv.state);
    let _guard = w.kv.state.no_value_reads();
    let (status, html) = w.page("/v/kv-test/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<th scope=\"col\">Value changed</th>"));
    assert!(!html.contains("<th scope=\"col\">Updated</th>"));
    assert!(html.contains("800 days ago"));
    assert!(
        html.contains("<a href=\"/v/kv-test/secrets?older=365\">1 not changed in over a year</a>")
    );
    // The certificate's backing secret is old too, but never flagged.
    assert_eq!(html.matches("Not changed in over a year").count(), 1);

    let (_, html) = w.page("/v/kv-test/secrets?older=150").await;
    assert!(html.contains(">ancient<") && html.contains(">half<"));
    assert!(!html.contains(">quarter<") && !html.contains(">fresh<"));
    assert!(!html.contains(">tls<"), "backing secret left out");
    assert!(html.contains("value=\"150\""));

    let (_, html) = w.page("/v/kv-test/secrets?older=soon").await;
    assert!(html.contains("Use a whole number of days"));
    assert!(html.contains("aria-invalid=\"true\""));
    assert!(html.contains(">fresh<"), "a bad number filters nothing");

    // The secret's own page has the badge too.
    let (_, html) = w.page("/v/kv-test/secrets/ancient").await;
    assert!(html.contains("<span class=\"badge badge-warn\">Not changed in over a year</span>"));
    assert!(html.contains("800 days ago, when the value last changed"));
    let (_, html) = w.page("/v/kv-test/secrets/fresh").await;
    assert!(!html.contains("Not changed in"));
}

#[tokio::test]
async fn the_badge_follows_keyring_stale_after_days() {
    let w = support::world_with(&[("KEYRING_STALE_AFTER_DAYS", "30")]).await;
    seed_vaults(&w, &["kv-test"]);
    let n = now();
    w.kv.state
        .put_with("edge", "x", |v| v.created = n - 30 * DAY + 60);
    w.kv.state
        .put_with("past", "x", |v| v.created = n - 31 * DAY);
    w.kv.state
        .add_key_with("old-key", "RSA", |v| v.created = n - 40 * DAY);
    w.kv.state.add_cert_version(
        "old-cert",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(false, false),
        |v| v.created = n - 40 * DAY,
    );
    let badge = "<span class=\"badge badge-warn\">Not changed in over 30 days</span>";
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert_eq!(html.matches(badge).count(), 1, "only past the threshold");
    assert!(html.contains("?older=30\">1 not changed in over 30 days</a>"));
    let (_, html) = w.page("/v/kv-test/keys").await;
    // The certificate's own key is never flagged.
    assert_eq!(html.matches(badge).count(), 1);
    let (_, html) = w.page("/v/kv-test/keys/old-key").await;
    assert!(html.contains(badge));
    let (_, html) = w.page("/v/kv-test/certificates").await;
    assert_eq!(html.matches(badge).count(), 1);
    let (_, html) = w.page("/v/kv-test/certificates/old-cert").await;
    assert!(html.contains(badge));
    // The bands stay fixed; only the badge moves.
    let (_, html) = w.page("/expiry/age").await;
    assert!(html.contains("Under 90 days <span class=\"muted\">(4)</span>"));
    assert_eq!(html.matches(badge).count(), 3);
}

#[tokio::test]
async fn no_vaults_and_unknown_vault() {
    let w = support::world().await;
    let (status, html) = w.page("/expiry/age").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Nothing to show"));
    seed_vaults(&w, &["kv-test"]);
    let (_, html) = w.page("/expiry/age?vault=kv-gone").await;
    assert!(html.contains("isn't one of the vaults you can see"));
    let csv = body_text(w.get("/expiry/age.csv?vault=kv-gone").await).await;
    assert!(csv.contains("kv-gone,NOT READ,Not in the list of vaults you can see"));
}
