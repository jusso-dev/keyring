//! Accessibility checks on rendered pages: every form control has a label,
//! one h1 per page, the skip link, landmarks, and error summaries that can
//! take focus and point at real fields.

mod support;

use axum::http::StatusCode;

fn controls_have_labels(html: &str, path: &str) {
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        rest = &rest[i..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        let is_control =
            tag.starts_with("<input") || tag.starts_with("<select") || tag.starts_with("<textarea");
        if is_control && !tag.contains("type=\"hidden\"") {
            let id = tag.split("id=\"").nth(1).and_then(|s| s.split('"').next());
            let id = id.unwrap_or_else(|| panic!("{path}: control without id: {tag}"));
            assert!(
                html.contains(&format!("for=\"{id}\"")),
                "{path}: no label for #{id}"
            );
        }
        rest = &rest[end.min(rest.len())..];
        if rest.len() <= 1 {
            break;
        }
        rest = &rest[1..];
    }
}

/// Every id that `aria-describedby` points at must exist, and attribute
/// quotes must balance (catches template edits that break markup).
fn describedby_targets_exist(html: &str, path: &str) {
    for chunk in html.split("aria-describedby=\"").skip(1) {
        let ids = chunk.split('"').next().unwrap_or_default();
        for id in ids.split_whitespace() {
            assert!(
                html.contains(&format!("id=\"{id}\"")),
                "{path}: aria-describedby points at missing #{id}"
            );
        }
    }
    for line in html.lines() {
        if line.trim_start().starts_with('<') && !line.contains("<script") {
            assert!(
                line.matches('"').count() % 2 == 0,
                "{path}: unbalanced quotes in {line}"
            );
        }
    }
}

/// Every `aria-labelledby` points at an id on the page.
fn labelledby_targets_exist(html: &str, path: &str) {
    for chunk in html.split("aria-labelledby=\"").skip(1) {
        let ids = chunk.split('"').next().unwrap_or_default();
        for id in ids.split_whitespace() {
            assert!(
                html.contains(&format!("id=\"{id}\"")),
                "{path}: aria-labelledby points at missing #{id}"
            );
        }
    }
}

/// The opening tags of every element whose tag starts with `prefix`.
fn tags<'a>(html: &'a str, prefix: &str) -> Vec<&'a str> {
    html.match_indices(prefix)
        .map(|(i, _)| {
            let rest = &html[i..];
            &rest[..rest.find('>').unwrap_or(rest.len())]
        })
        .collect()
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    tag.split(&format!(" {name}=\""))
        .nth(1)
        .and_then(|s| s.split('"').next())
}

/// Content that is on the page when it loads has no live role. Only the
/// regions the script fills later keep `role="status"`.
fn no_live_roles_on_load(html: &str, path: &str) {
    assert!(!html.contains("role=\"alert\""), "{path}: role=alert");
    for tag in tags(html, "<") {
        if tag.contains("role=\"status\"") {
            let filled_later = [
                "data-copy-status",
                "data-countdown-announce",
                "data-live-filter-empty",
                "data-copy-plain-status",
            ]
            .iter()
            .any(|a| tag.contains(a));
            assert!(
                filled_later,
                "{path}: live role on load-time content: {tag}"
            );
        }
    }
}

/// Every table wrapper is named by its own caption, and none share the old
/// generic label.
fn table_regions_are_named(html: &str, path: &str) {
    assert!(!html.contains("scrolls sideways"), "{path}: generic label");
    let mut seen = Vec::new();
    for tag in tags(html, "<div class=\"table-wrap\"") {
        let id = attr(tag, "aria-labelledby")
            .unwrap_or_else(|| panic!("{path}: table-wrap without aria-labelledby"));
        assert!(
            html.contains(&format!("<caption class=\"visually-hidden\" id=\"{id}\">")),
            "{path}: #{id} isn't a caption"
        );
        assert!(!seen.contains(&id), "{path}: two regions named #{id}");
        seen.push(id);
    }
}

/// Every `field-help` with an id is listed by some `aria-describedby`.
fn help_text_is_linked(html: &str, path: &str) {
    for tag in tags(html, "<p class=\"field-help\"") {
        let Some(id) = attr(tag, "id") else {
            panic!("{path}: field-help without an id: {tag}");
        };
        let linked = html.split("aria-describedby=\"").skip(1).any(|c| {
            c.split('"')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .any(|i| i == id)
        });
        assert!(linked, "{path}: #{id} isn't linked to a field");
    }
}

/// Fields that hold names, values or tags don't let a phone keyboard
/// change what is typed.
fn identifier_fields_keep_case(html: &str, path: &str) {
    for prefix in ["<input", "<textarea"] {
        for tag in tags(html, prefix) {
            let kind = attr(tag, "type").unwrap_or("text");
            if !matches!(kind, "text" | "search" | "password") {
                continue;
            }
            for a in [
                "autocapitalize=\"off\"",
                "autocorrect=\"off\"",
                "spellcheck=\"false\"",
            ] {
                assert!(tag.contains(a), "{path}: {a} missing on {tag}");
            }
        }
    }
}

fn page_basics(html: &str, path: &str) {
    describedby_targets_exist(html, path);
    labelledby_targets_exist(html, path);
    no_live_roles_on_load(html, path);
    table_regions_are_named(html, path);
    help_text_is_linked(html, path);
    identifier_fields_keep_case(html, path);
    assert!(
        !html.contains(" placeholder=\""),
        "{path}: hints go in help text"
    );
    assert!(
        !html.contains(" title=\""),
        "{path}: tooltips can't be reached by touch or keyboard"
    );
    assert!(
        !html.contains("<td class=\"row-actions"),
        "{path}: the cell must stay a cell"
    );
    assert_eq!(html.matches("<h1").count(), 1, "{path}: one h1");
    assert!(html.contains("<html lang=\"en-AU\">"), "{path}");
    assert!(html.contains("href=\"#main\""), "{path}: skip link");
    assert!(html.contains("<main id=\"main\""), "{path}: main landmark");
    assert!(
        html.contains("<title>") && !html.contains("<title></title>"),
        "{path}: title"
    );
    assert!(!html.contains('\u{2014}'), "{path}: no em dashes");
    controls_have_labels(html, path);
}

#[tokio::test]
async fn pages_have_labels_headings_and_landmarks() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    let s = &w.kv.state;
    s.put("db-password", "x");
    s.put("db-password", "y");
    s.add_cert("web-tls", true, "UEZY");
    s.add_key_with("app-key", "RSA", |_| {});
    s.put("old-one", "x");
    s.soft_delete("old-one");
    let v1 = s.secrets.lock().unwrap()["db-password"].versions[0]
        .version
        .clone();
    let pages = [
        "/".to_owned(),
        "/vaults".into(),
        "/secrets".into(),
        "/secrets/new".into(),
        "/secrets/db-password".into(),
        "/secrets/db-password/value".into(),
        "/secrets/db-password/edit".into(),
        "/secrets/db-password/versions".into(),
        format!("/secrets/db-password/rollback?version={v1}"),
        "/secrets/db-password/delete".into(),
        "/secrets/db-password/disable".into(),
        "/secrets/deleted".into(),
        "/secrets/deleted/old-one".into(),
        "/certificates".into(),
        "/certificates/new".into(),
        "/certificates/upload".into(),
        "/certificates/web-tls".into(),
        "/certificates/web-tls/download-key".into(),
        "/certificates/web-tls/delete".into(),
        "/certificates/web-tls/disable".into(),
        "/certificates/deleted".into(),
        "/keys".into(),
        "/keys/new".into(),
        "/keys/app-key".into(),
        "/keys/app-key/rotate".into(),
        "/keys/app-key/rotation".into(),
        "/keys/app-key/delete".into(),
        "/keys/app-key/disable".into(),
        "/keys/deleted".into(),
        "/expiry".into(),
        "/generator".into(),
        "/audit".into(),
        "/auth/sign-in".into(),
        "/no-such-page".into(),
    ];
    for p in &pages {
        let (_, html) = w.page(p).await;
        page_basics(&html, p);
    }
    // A revealed value page too.
    let html = support::body_text(w.post("/secrets/db-password/reveal", &[]).await).await;
    page_basics(&html, "reveal");
    assert!(
        html.contains("data-countdown-announce"),
        "countdown has a quiet live region"
    );
}

#[tokio::test]
async fn error_summaries_take_focus_and_link_to_fields() {
    let w = support::world().await;
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "/secrets/new",
            vec![
                ("name", "bad name"),
                ("value", ""),
                ("tags", "=x"),
                ("expires", "2020-01-01"),
            ],
        ),
        ("/keys/new", vec![("name", "k"), ("expires", "nope")]),
        (
            "/certificates/new",
            vec![("name", "bad name"), ("validity_months", "0")],
        ),
        (
            "/keys/new",
            vec![
                ("name", "bad name"),
                ("key_type", "EC-P-256"),
                ("ops", "encrypt"),
            ],
        ),
        (
            "/certificates/new",
            vec![
                ("name", "c"),
                ("common_name", "a.example.com"),
                ("validity_months", "12"),
                ("renew_days", "9999"),
                ("tags", "=x"),
            ],
        ),
    ];
    for (path, fields) in cases {
        let html = support::body_text(w.post(path, &fields).await).await;
        assert!(
            html.contains("tabindex=\"-1\" data-error-summary"),
            "{path}"
        );
        let mut rest = html.as_str();
        while let Some(i) = rest.find("<li><a href=\"#") {
            rest = &rest[i + "<li><a href=\"#".len()..];
            let id = rest.split('"').next().unwrap();
            assert!(
                html.contains(&format!("id=\"{id}\"")),
                "{path}: summary links to missing #{id}"
            );
        }
        assert!(html.contains("aria-invalid=\"true\""), "{path}");
        describedby_targets_exist(&html, path);
    }
}

#[tokio::test]
async fn confirm_mismatch_is_an_error_with_focus() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let html = support::body_text(
        w.post("/secrets/db-password/delete", &[("confirm_name", "nope")])
            .await,
    )
    .await;
    assert!(html.contains("tabindex=\"-1\" data-error-summary id=\"confirm_name-error\""));
    assert!(!html.contains("role=\"alert\""), "focused, so no live role");
    assert!(html.contains("aria-invalid=\"true\" aria-describedby=\"confirm_name-error\""));
    assert!(html.contains("Nothing was deleted."));
    describedby_targets_exist(&html, "delete mismatch");
}

/// Buttons the script hasn't switched on carry `hidden`. Author rules that
/// set `display` beat the browser's own `[hidden]` rule, so the stylesheet
/// must restate it. Nothing else would catch this going missing.
#[test]
fn stylesheet_keeps_hidden_things_hidden() {
    let css = include_str!("../static/style.css");
    assert!(
        css.contains("[hidden] { display: none !important; }"),
        "style.css needs the [hidden] rule"
    );
}

/// Pages reflow at 320 CSS pixels: grid tracks can shrink below their
/// content, so wide tables scroll inside `.table-wrap` instead of the page.
#[test]
fn stylesheet_lets_pages_reflow() {
    let css = include_str!("../static/style.css");
    assert!(css.contains("grid-template-columns: 12rem minmax(0, 1fr);"));
    assert!(css.contains(".layout { grid-template-columns: minmax(0, 1fr);"));
    assert!(css.contains(".table-wrap { overflow-x: auto; position: relative; }"));
    assert!(
        css.contains("max-width: 100%"),
        "filter inputs fit the screen"
    );
    assert!(
        !css.contains("columns: 1fr") && !css.contains("12rem 1fr"),
        "a bare 1fr track grows to fit its content"
    );
}

/// A revealed value doesn't go to paper or a PDF.
#[test]
fn stylesheet_hides_revealed_values_in_print() {
    let css = include_str!("../static/style.css");
    let print = css.split("@media print").nth(1).expect("a print rule");
    assert!(print.contains("[data-secret-value] { visibility: hidden; }"));
}

#[tokio::test]
async fn reveal_pages_say_what_really_happens() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let html = support::body_text(w.post("/secrets/db-password/reveal", &[]).await).await;
    assert!(html.contains("Reloading asks Key Vault for it again."));
    assert!(html.contains("Keyring will try to clear the clipboard"));
    assert!(!html.contains("Shown once"), "reloading does show it again");
    let html = support::body_text(w.post("/generator", &[("kind", "guid")]).await).await;
    assert!(html.contains("Reloading makes a new one."));
    assert!(html.contains("Keyring will try to clear the clipboard"));
}

fn title(html: &str) -> &str {
    html.split("<title>")
        .nth(1)
        .and_then(|s| s.split("</title>").next())
        .unwrap_or_default()
}

/// A secret, a certificate and a key with the same name, which is the usual
/// case for a certificate, give three different page titles. The page that
/// shows a value says so in its title.
#[tokio::test]
async fn titles_name_the_type_and_vault() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("web-tls", "RSA", |_| {});
    w.kv.state.put("db-password", "x");
    let (_, s) = w.page("/secrets/web-tls").await;
    let (_, c) = w.page("/certificates/web-tls").await;
    let (_, k) = w.page("/keys/web-tls").await;
    assert_eq!(title(&s), "Secret web-tls in kv-test - Keyring");
    assert_eq!(title(&c), "Certificate web-tls in kv-test - Keyring");
    assert_eq!(title(&k), "Key web-tls in kv-test - Keyring");
    let shown = support::body_text(w.post("/secrets/db-password/reveal", &[]).await).await;
    assert_eq!(title(&shown), "Value of db-password - Keyring");
    let (_, versions) = w.page("/secrets/db-password/versions").await;
    assert_eq!(
        title(&versions),
        "Versions of secret db-password in kv-test - Keyring"
    );
}

/// Disable asks first, for all three types, and says what stops working.
/// The confirmation posts to the existing route, which still does the work.
#[tokio::test]
async fn disable_asks_first_and_says_what_breaks() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    for (detail, words) in [
        (
            "/secrets/db-password",
            "Apps that read this secret will start failing",
        ),
        (
            "/certificates/web-tls",
            "can start failing on their next read",
        ),
        ("/keys/app-key", "will start failing"),
    ] {
        let (_, html) = w.page(detail).await;
        assert!(
            html.contains(&format!("href=\"{detail}/disable\">Disable</a>")),
            "{detail}: Disable is a link to the confirmation"
        );
        let (status, html) = w.page(&format!("{detail}/disable")).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert!(html.contains(words), "{detail}");
        assert!(html.contains(&format!("action=\"{detail}/enabled\"")));
        assert!(html.contains("name=\"state\" value=\"off\""));
        assert!(!html.contains("confirm_name"), "no typed name");
        page_basics(&html, detail);
    }
    let (status, _) = w.page("/secrets/no-such-thing/disable").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A disabled item is enabled again in one click, from its page.
    w.post("/secrets/db-password/enabled", &[("state", "off")])
        .await;
    let (_, html) = w.page("/secrets/db-password").await;
    assert!(html.contains("name=\"state\" value=\"on\"") && html.contains(">Enable<"));
}

/// Browsers ignore autocomplete="off" on a password field and would fill in
/// the Keyring sign-in. new-password stops that.
#[tokio::test]
async fn pfx_password_isnt_filled_from_the_sign_in() {
    let w = support::world().await;
    let (_, html) = w.page("/certificates/upload").await;
    let tag = tags(&html, "<input id=\"password\"")[0];
    assert!(tag.contains("type=\"password\""));
    assert!(tag.contains("autocomplete=\"new-password\""), "{tag}");
    assert!(tag.contains("autocapitalize=\"off\""), "{tag}");
}

/// The same expiry state looks the same for every type: red under 30 days,
/// "No expiry" when there is none, muted "None" in empty cells, and a tag
/// with no value shows its name only.
#[tokio::test]
async fn status_and_tags_look_the_same_everywhere() {
    let w = support::world().await;
    let n = keyring::azure::secrets::now_ts();
    let day = 86_400;
    let s = &w.kv.state;
    s.put_with("soon-secret", "x", |v| {
        v.exp = Some(n + 10 * day);
        v.tags.insert("env".into(), String::new());
    });
    s.put("plain-secret", "x");
    s.add_key_with("soon-key", "RSA", |k| {
        k.exp = Some(n + 10 * day);
        k.tags.insert("env".into(), String::new());
    });
    s.add_key_with("plain-key", "RSA", |_| {});
    for list in ["/secrets", "/keys"] {
        let (_, html) = w.page(list).await;
        assert!(
            html.contains("badge-error\">Expires within 30 days"),
            "{list}: red under 30 days"
        );
        assert!(html.contains(">No expiry<"), "{list}");
        assert!(
            !html.contains(">Never<") && !html.contains(">Not set<"),
            "{list}"
        );
        assert!(
            html.contains("<span class=\"tag\">env</span>"),
            "{list}: no env="
        );
        assert!(html.contains("<span class=\"muted\">None</span>"), "{list}");
    }
}

/// Version tables show the whole ID in the row, not in a tooltip, and the
/// action cell stays a table cell.
#[tokio::test]
async fn version_ids_are_shown_in_full() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let v2 = w.kv.state.put("db-password", "y");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let (_, html) = w.page("/secrets/db-password/versions").await;
    assert!(html.contains(&format!("<span class=\"mono version-id\">{v2}</span>")));
    assert!(html.contains("<td>\n        <div class=\"row-actions\">"));
    let (_, html) = w.page("/keys/app-key").await;
    assert!(html.contains("<span class=\"mono version-id\">"));
}

/// Generator and audit errors use the same summary and per-field pattern as
/// the other forms.
#[tokio::test]
async fn generator_and_audit_errors_point_at_the_field() {
    let w = support::world().await;
    let html = support::body_text(
        w.post("/generator", &[("kind", "password"), ("length", "3")])
            .await,
    )
    .await;
    assert!(html.contains("tabindex=\"-1\" data-error-summary"));
    assert!(html.contains("<a href=\"#length\">Pick a length from 8 to 256.</a>"));
    assert!(html.contains("aria-describedby=\"length-help length-error\" aria-invalid=\"true\""));
    describedby_targets_exist(&html, "generator");
    no_live_roles_on_load(&html, "generator");
    let html = support::body_text(
        w.post("/generator", &[("kind", "password"), ("length", "24")])
            .await,
    )
    .await;
    assert!(
        html.contains("<a href=\"#charsets\">"),
        "no character sets ticked"
    );

    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    let (status, html) = w.page("/audit?person=a%22b").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("<a href=\"#person\">"));
    assert!(html.contains("aria-describedby=\"person-help person-error\" aria-invalid=\"true\""));
    page_basics(&html, "audit error");
}

/// No dead or doubled rules, and the small-screen and forced-colours rules
/// still apply.
#[test]
fn stylesheet_has_no_dead_or_duplicate_rules() {
    let css = include_str!("../static/style.css");
    assert_eq!(css.matches(".visually-hidden {").count(), 1);
    assert_eq!(css.matches(".button-small {").count(), 1);
    assert!(!css.contains("datetime-local") && !css.contains("button:disabled"));
    let forced = css.split("@media (forced-colors: active)").nth(1).unwrap();
    assert!(forced.contains(".side-nav a[aria-current=\"page\"]"));
    // The small-screen query comes after the rules it overrides.
    let narrow = css.find("@media (max-width: 48rem)").unwrap();
    assert!(narrow > css.find(".side-nav a[aria-current=\"page\"] {").unwrap());
    assert!(narrow > css.find("@media (forced-colors: active)").unwrap());
}
