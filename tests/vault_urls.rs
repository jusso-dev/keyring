//! The vault is in every item address (`/v/{vault}/...`), so a link can be
//! sent to someone and two tabs can hold two vaults.

mod support;

use axum::http::StatusCode;
use support::{body_text, hidden_value, location};

fn seed_vaults(w: &support::World, names: &[&str]) {
    *w.arm.state.vaults.lock().unwrap() = names
        .iter()
        .map(|n| support::vault_row(n, "sub-a", true))
        .collect();
}

fn selected(w: &support::World) -> Option<String> {
    let id = w.cookie.split('=').nth(1).unwrap();
    w.state.sessions.get(id).unwrap().selected_vault()
}

/// A world whose session has no vault chosen yet.
fn without_a_vault(w: support::World) -> support::World {
    let id = w.cookie.split('=').nth(1).unwrap();
    let s = w.state.sessions.get(id).unwrap();
    let fresh = w.state.sessions.create(s.user.clone(), s.tokens());
    let mut w = w;
    w.cookie = format!("keyring_session={fresh}");
    w
}

/// The address decides the vault, whatever the session had picked.
#[tokio::test]
async fn the_address_decides_the_vault() {
    let w = support::world().await;
    w.kv.state.put("db", "x");
    // The session's last used vault is another one.
    let id = w.cookie.split('=').nth(1).unwrap();
    w.state
        .sessions
        .get(id)
        .unwrap()
        .select_vault("kv-other".into());
    let (status, html) = w.page("/v/kv-test/secrets/db").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<h1 class=\"mono\">db</h1>"));
    // It was read from kv-test, not kv-other.
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        log.iter().any(|l| l.starts_with("GET /kv-test/secrets/db")),
        "{log:?}"
    );
    assert!(!log.iter().any(|l| l.contains("/kv-other/")), "{log:?}");
    // The header and the form token follow the address, and it is now the
    // last used vault.
    assert!(html.contains("<strong>kv-test</strong>"));
    assert_eq!(selected(&w).as_deref(), Some("kv-test"));
}

/// Two tabs on two vaults: a form from the first still works after the
/// second is opened.
#[tokio::test]
async fn two_tabs_can_hold_two_vaults() {
    let mut w = support::world().await;
    let (_, form_a) = w.page("/v/kv-a/secrets/-/new").await;
    let token_a = hidden_value(&form_a, "csrf").unwrap();
    assert!(token_a.starts_with("kv-a."));
    // The second tab.
    let (status, form_b) = w.page("/v/kv-b/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(form_b.contains("<strong>kv-b</strong>"));
    assert_eq!(selected(&w).as_deref(), Some("kv-b"));
    // The first tab's form is accepted at its own address.
    w.csrf = token_a;
    let res = w
        .post(
            "/v/kv-a/secrets/-/new",
            &[("name", "from-a"), ("value", "v"), ("enabled", "on")],
        )
        .await;
    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "no \"You switched vaults\""
    );
    assert_eq!(location(&res), "/v/kv-a/secrets/from-a");
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|l| l.starts_with("PUT /kv-a/secrets/from-a")),
        "{log:?}"
    );
}

/// The security property: a form for one vault does nothing at another
/// vault's address. This must fail closed.
#[tokio::test]
async fn a_form_for_one_vault_is_refused_at_another() {
    let mut w = support::world().await;
    w.kv.state.put("db", "x");
    let (_, form_a) = w.page("/v/kv-a/secrets/db/delete").await;
    w.csrf = hidden_value(&form_a, "csrf").unwrap();
    assert!(w.csrf.starts_with("kv-a."));
    let before = w.kv.state.log.lock().unwrap().len();
    for path in [
        "/v/kv-b/secrets/db/delete",
        "/v/kv-b/secrets/-/new",
        "/v/kv-b/keys/-/new",
    ] {
        let res = w
            .post(
                path,
                &[("confirm_name", "db"), ("name", "db"), ("value", "v")],
            )
            .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        let html = body_text(res).await;
        assert!(html.contains("This page was for kv-a"), "{path}: {html}");
    }
    // Nothing reached Key Vault for kv-b.
    let log = w.kv.state.log.lock().unwrap().clone();
    assert!(
        !log[before..].iter().any(|l| l.starts_with("DELETE")
            || l.starts_with("PUT")
            || l.starts_with("POST /kv-b")),
        "{:?}",
        &log[before..]
    );
    assert!(w.kv.state.current("db").is_some(), "nothing deleted");
    // The same form works at its own address.
    let res = w
        .post("/v/kv-a/secrets/db/delete", &[("confirm_name", "db")])
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_bad_vault_name_is_not_found_and_reaches_nothing() {
    let w = support::world().await;
    for path in [
        "/v/not_a_vault!/secrets",
        "/v/ab/secrets",
        "/v/-bad/secrets/db",
        "/v/kv--x/certificates",
        "/v/has.dot/keys",
        "/v/has%2Fslash/audit",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(
            html.contains("Not found") || html.contains("not found"),
            "{path}"
        );
    }
    // Forms too: a bad name is refused before anything is done or redirected.
    for path in [
        "/v/not_a_vault!/certificates/-/upload/cancel",
        "/v/bad%0d%0aname/certificates/-/upload/cancel",
    ] {
        let res = w.post(path, &[]).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert!(
        w.kv.state.log.lock().unwrap().is_empty(),
        "no request reached Key Vault"
    );
    assert_ne!(selected(&w).as_deref(), Some("not_a_vault!"));
}

#[tokio::test]
async fn old_addresses_go_to_the_last_used_vault() {
    let w = support::world().await;
    w.kv.state.put("db", "x");
    for (old, new) in [
        ("/secrets/db", "/v/kv-test/secrets/db"),
        ("/secrets", "/v/kv-test/secrets"),
        ("/secrets?show=expired", "/v/kv-test/secrets?show=expired"),
        ("/certificates/-/new", "/v/kv-test/certificates/-/new"),
        ("/keys/app-key/rotate", "/v/kv-test/keys/app-key/rotate"),
        (
            "/audit?item=db&from=secret",
            "/v/kv-test/audit?item=db&from=secret",
        ),
        ("/audit.csv", "/v/kv-test/audit.csv"),
    ] {
        let res = w.get(old).await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }
    // With nothing chosen, the old address asks for a vault.
    let w = without_a_vault(w);
    let (status, html) = w.page("/secrets/db").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Choose a vault first"));
}

/// A stale form post to the old address keeps its method and body, and
/// still meets the check for the vault it was rendered for.
#[tokio::test]
async fn an_old_form_post_is_sent_on_and_still_checked() {
    let w = support::world().await;
    w.kv.state.put("db", "x");
    let res = w.post("/secrets/db/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location(&res), "/v/kv-test/secrets/db/reveal");
    // Following it with the same form works.
    let res = w.post(&location(&res), &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    // A form rendered for another vault is refused after the redirect.
    let mut w = w;
    w.csrf = w
        .state
        .sessions
        .get(w.cookie.split('=').nth(1).unwrap())
        .unwrap()
        .csrf_for(Some("kv-other"));
    let res = w.post("/v/kv-test/secrets/db/reveal", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expiry_rows_link_straight_to_the_item() {
    let w = support::world().await;
    seed_vaults(&w, &["kv-test"]);
    w.kv.state.put_with("db-password", "x", |v| {
        v.exp = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 86_400,
        )
    });
    let (_, html) = w.page("/expiry").await;
    assert!(
        html.contains("<a class=\"button button-small\" href=\"/v/kv-test/secrets/db-password\">")
    );
    assert!(
        !html.contains("action=\"/vaults/select\""),
        "no form per row"
    );
}

#[tokio::test]
async fn the_nav_follows_the_last_used_vault() {
    let w = support::world().await;
    let (_, html) = w.page("/v/kv-a/secrets").await;
    for section in ["secrets", "certificates", "keys", "audit"] {
        assert!(
            html.contains(&format!("<a href=\"/v/kv-a/{section}\"")),
            "{section}"
        );
    }
    // Pages that are not about one vault stay where they are.
    assert!(html.contains("<a href=\"/expiry\""));
    assert!(html.contains("<a href=\"/generator\""));
    assert!(html.contains("<a href=\"/vaults\""));
    // With no vault chosen, the nav goes to the bare addresses.
    let w = without_a_vault(w);
    let (_, html) = w.page("/vaults").await;
    assert!(html.contains("<a href=\"/secrets\""));
    assert!(!html.contains("href=\"/v/"));
}
