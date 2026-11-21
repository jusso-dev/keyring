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

/// The text of an element's content, tags dropped, entities left as they
/// are. Visually hidden text counts: it is in the accessibility tree.
fn text_of(inner: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in inner.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_owned()
}

/// Every button, link and input has an accessible name: its text, an
/// aria-label or aria-labelledby, a value on a submit input, or (for other
/// inputs) a `<label for>`. Icon-only controls must carry a label. This is
/// what an agent or a screen reader reads from the accessibility tree.
fn controls_have_names(html: &str, path: &str) {
    for (open, close) in [("<button", "</button>"), ("<a ", "</a>")] {
        for (i, _) in html.match_indices(open) {
            let rest = &html[i..];
            let end = rest.find('>').unwrap_or(rest.len());
            let tag = &rest[..end];
            let inner = rest[end..]
                .find(close)
                .map_or("", |c| &rest[end + 1..end + c]);
            let named = attr(tag, "aria-label").is_some_and(|v| !v.trim().is_empty())
                || attr(tag, "aria-labelledby").is_some()
                || !text_of(inner).is_empty();
            assert!(named, "{path}: no accessible name: {tag}>");
        }
    }
    for tag in tags(html, "<input") {
        let kind = attr(tag, "type").unwrap_or("text");
        let named = match kind {
            "hidden" => true,
            "submit" | "button" | "reset" => attr(tag, "value").is_some_and(|v| !v.is_empty()),
            _ => {
                attr(tag, "aria-label").is_some()
                    || attr(tag, "aria-labelledby").is_some()
                    || attr(tag, "id").is_some_and(|id| html.contains(&format!("for=\"{id}\"")))
            }
        };
        assert!(named, "{path}: input with no accessible name: {tag}>");
    }
}

#[test]
fn unnamed_controls_are_caught() {
    let ok = "<a href=\"/x\"><svg aria-hidden=\"true\"></svg><span class=\"visually-hidden\">Close</span></a><button aria-label=\"Pin\"></button><label for=\"q\">Q</label><input id=\"q\">";
    controls_have_names(ok, "ok");
    for bad in [
        "<a href=\"/x\"><svg aria-hidden=\"true\"></svg></a>",
        "<button type=\"button\"> </button>",
        "<input id=\"q\">",
        "<input type=\"submit\">",
    ] {
        let caught = std::panic::catch_unwind(|| controls_have_names(bad, "bad")).is_err();
        assert!(caught, "should fail: {bad}");
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
    controls_have_names(html, path);
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
    // An owner and notify list set outside Keyring, so the notes show.
    s.put_with("odd-owner", "x", |v| {
        v.tags.insert("owner".into(), "Payments team".into());
        v.tags
            .insert("notify".into(), "a@example.com;b@example.com".into());
    });
    let v1 = s.secrets.lock().unwrap()["db-password"].versions[0]
        .version
        .clone();
    let pages = [
        "/".to_owned(),
        "/vaults".into(),
        "/v/kv-test/secrets".into(),
        "/v/kv-test/secrets/-/new".into(),
        "/v/kv-test/secrets/db-password".into(),
        "/v/kv-test/secrets/db-password/value".into(),
        "/v/kv-test/secrets/db-password/edit".into(),
        "/v/kv-test/secrets/odd-owner/edit".into(),
        "/v/kv-test/secrets/odd-owner".into(),
        "/v/kv-test/secrets?mine=1".into(),
        "/v/kv-test/keys?mine=1".into(),
        "/v/kv-test/certificates?mine=1".into(),
        "/v/kv-test/secrets/db-password/versions".into(),
        format!("/v/kv-test/secrets/db-password/rollback?version={v1}"),
        "/v/kv-test/secrets/db-password/delete".into(),
        "/v/kv-test/secrets/db-password/disable".into(),
        "/v/kv-test/secrets/-/deleted".into(),
        "/v/kv-test/secrets/-/deleted/old-one".into(),
        "/v/kv-test/certificates".into(),
        "/v/kv-test/certificates/-/new".into(),
        "/v/kv-test/certificates/-/upload".into(),
        "/v/kv-test/certificates/web-tls".into(),
        "/v/kv-test/certificates/web-tls/download-key".into(),
        "/v/kv-test/certificates/web-tls/delete".into(),
        "/v/kv-test/certificates/web-tls/disable".into(),
        "/v/kv-test/certificates/web-tls/renewal".into(),
        "/v/kv-test/certificates/-/deleted".into(),
        "/v/kv-test/keys".into(),
        "/v/kv-test/keys/-/new".into(),
        "/v/kv-test/keys/app-key".into(),
        "/v/kv-test/keys/app-key/rotate".into(),
        "/v/kv-test/keys/app-key/rotation".into(),
        "/v/kv-test/keys/app-key/delete".into(),
        "/v/kv-test/keys/app-key/disable".into(),
        "/v/kv-test/keys/-/deleted".into(),
        "/v/kv-test/certificates/web-tls/details".into(),
        "/v/kv-test/keys/app-key/details".into(),
        "/expiry".into(),
        "/expiry/age".into(),
        "/vault-health".into(),
        "/vault-health?vault=kv-test".into(),
        "/reports/executive".into(),
        "/search".into(),
        "/search?q=db".into(),
        "/search?q=nothing-here".into(),
        format!("/search?q={}", "a".repeat(101)),
        "/generator".into(),
        "/v/kv-test/audit".into(),
        "/v/kv-test/access".into(),
        "/v/kv-test/access/review".into(),
        "/audit".into(),
        "/audit?report=reads".into(),
        "/audit?report=refused".into(),
        "/audit?report=person".into(),
        "/auth/sign-in".into(),
        "/no-such-page".into(),
    ];
    for p in &pages {
        let (_, html) = w.page(p).await;
        page_basics(&html, p);
    }
    // A revealed value page too.
    let html = support::body_text(w.post("/v/kv-test/secrets/db-password/reveal", &[]).await).await;
    page_basics(&html, "reveal");
    assert!(
        html.contains("data-countdown-announce"),
        "countdown has a quiet live region"
    );
}

#[tokio::test]
async fn disabled_buttons_keep_their_label_and_say_why() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.arm.state.authz.lock().unwrap().permissions =
        Some(vec![support::role_data_actions("Key Vault Reader")]);
    let s = &w.kv.state;
    s.put("db-password", "x");
    s.add_cert("web-tls", true, "UEZY");
    s.add_key_with("app-key", "RSA", |_| {});
    s.put("old-one", "x");
    s.soft_delete("old-one");
    for p in [
        "/v/kv-test/secrets",
        "/v/kv-test/secrets/db-password",
        "/v/kv-test/secrets/-/deleted/old-one",
        "/v/kv-test/certificates",
        "/v/kv-test/certificates/web-tls",
        "/v/kv-test/keys",
        "/v/kv-test/keys/app-key",
    ] {
        let (_, html) = w.page(p).await;
        page_basics(&html, p);
        let disabled: Vec<&str> = html
            .split("<button")
            .skip(1)
            .filter(|b| b[..b.find('>').unwrap()].contains(" disabled"))
            .collect();
        assert!(!disabled.is_empty(), "{p}: nothing disabled");
        for b in disabled {
            let tag = &b[..b.find('>').unwrap()];
            assert!(tag.contains("aria-describedby=\""), "{p}: {tag}");
            let label = &b[b.find('>').unwrap() + 1..b.find("</button>").unwrap()];
            assert!(
                !label.trim().is_empty(),
                "{p}: a disabled button keeps its label"
            );
        }
        assert!(html.contains("Needs Key Vault"), "{p}: the role, as text");
    }
}

#[tokio::test]
async fn error_summaries_take_focus_and_link_to_fields() {
    let w = support::world().await;
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "/v/kv-test/secrets/-/new",
            vec![
                ("name", "bad name"),
                ("value", ""),
                ("tag-rows", "1"),
                ("tag-name-1", ""),
                ("tag-value-1", "x"),
                ("expires", "2020-01-01"),
            ],
        ),
        (
            "/v/kv-test/keys/-/new",
            vec![("name", "k"), ("expires", "nope")],
        ),
        (
            "/v/kv-test/certificates/-/new",
            vec![("name", "bad name"), ("validity_months", "0")],
        ),
        (
            "/v/kv-test/keys/-/new",
            vec![
                ("name", "bad name"),
                ("key_type", "EC-P-256"),
                ("ops", "encrypt"),
            ],
        ),
        (
            "/v/kv-test/certificates/-/new",
            vec![
                ("name", "c"),
                ("common_name", "a.example.com"),
                ("validity_months", "12"),
                ("renew_days", "9999"),
                ("tag-rows", "1"),
                ("tag-name-2", "env"),
                ("tag-value-2", "a"),
                ("tag-name-3", "env"),
                ("tag-value-3", "b"),
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

/// Tag rows (#253): each name and value input has its own label, and a
/// row's error is linked to that row's input and from the summary.
#[tokio::test]
async fn tag_rows_are_labelled_and_errors_point_at_their_row() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/v/kv-test/keys/app-key/details").await;
    page_basics(&html, "details");
    controls_have_labels(&html, "details");
    assert!(html.contains("<fieldset class=\"tag-rows\" id=\"tags\""));
    assert!(html.contains("<legend>Tags <span class=\"muted\">(optional)</span></legend>"));
    for (path, fields, bad) in [
        (
            "/v/kv-test/secrets/-/new",
            vec![
                ("name", "n"),
                ("value", "x"),
                ("tag-rows", "1"),
                ("tag-name-2", "a"),
                ("tag-value-2", &*"v".repeat(257)),
            ],
            "tag-value-2",
        ),
        (
            "/v/kv-test/keys/-/new",
            vec![
                ("name", "k"),
                ("tag-rows", "1"),
                ("tag-name-1", "description"),
                ("tag-value-1", "x"),
            ],
            "tag-name-1",
        ),
    ] {
        let html = support::body_text(w.post(path, &fields).await).await;
        page_basics(&html, path);
        controls_have_labels(&html, path);
        assert!(
            html.contains(&format!("<a href=\"#{bad}\">")),
            "{path}: summary link"
        );
        assert!(
            html.contains(&format!("<p class=\"field-error\" id=\"{bad}-error\">")),
            "{path}"
        );
        let input = tags(&html, &format!("<input id=\"{bad}\""));
        assert_eq!(input.len(), 1, "{path}");
        assert_eq!(
            attr(input[0], "aria-describedby"),
            Some(&*format!("{bad}-error")),
            "{path}"
        );
        assert!(input[0].contains("aria-invalid=\"true\""), "{path}");
    }
}

#[tokio::test]
async fn confirm_mismatch_is_an_error_with_focus() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    let html = support::body_text(
        w.post(
            "/v/kv-test/secrets/db-password/delete",
            &[("confirm_name", "nope")],
        )
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
    let html = support::body_text(w.post("/v/kv-test/secrets/db-password/reveal", &[]).await).await;
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
    let (_, s) = w.page("/v/kv-test/secrets/web-tls").await;
    let (_, c) = w.page("/v/kv-test/certificates/web-tls").await;
    let (_, k) = w.page("/v/kv-test/keys/web-tls").await;
    assert_eq!(title(&s), "Secret web-tls in kv-test - Keyring");
    assert_eq!(title(&c), "Certificate web-tls in kv-test - Keyring");
    assert_eq!(title(&k), "Key web-tls in kv-test - Keyring");
    let shown =
        support::body_text(w.post("/v/kv-test/secrets/db-password/reveal", &[]).await).await;
    assert_eq!(title(&shown), "Value of db-password - Keyring");
    let (_, versions) = w.page("/v/kv-test/secrets/db-password/versions").await;
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
            "/v/kv-test/secrets/db-password",
            "Apps that read this secret will start failing",
        ),
        (
            "/v/kv-test/certificates/web-tls",
            "can start failing on their next read",
        ),
        ("/v/kv-test/keys/app-key", "will start failing"),
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
    let (status, _) = w.page("/v/kv-test/secrets/no-such-thing/disable").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A disabled item is enabled again in one click, from its page.
    w.post(
        "/v/kv-test/secrets/db-password/enabled",
        &[("state", "off")],
    )
    .await;
    let (_, html) = w.page("/v/kv-test/secrets/db-password").await;
    assert!(html.contains("name=\"state\" value=\"on\"") && html.contains(">Enable<"));
}

/// Browsers ignore autocomplete="off" on a password field and would fill in
/// the Keyring sign-in. new-password stops that.
#[tokio::test]
async fn pfx_password_isnt_filled_from_the_sign_in() {
    let w = support::world().await;
    let (_, html) = w.page("/v/kv-test/certificates/-/upload").await;
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
    for list in ["/v/kv-test/secrets", "/v/kv-test/keys"] {
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
        assert!(html.contains("<span class=\"muted\">None</span>"), "{list}");
    }
    // The lists leave tags to each item's page so rows fit at 1440px.
    for item in ["/v/kv-test/secrets/soon-secret", "/v/kv-test/keys/soon-key"] {
        let (_, html) = w.page(item).await;
        assert!(html.contains("\">env</a>"), "{item}: no env=");
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
    let (_, html) = w.page("/v/kv-test/secrets/db-password/versions").await;
    assert!(html.contains(&format!("<span class=\"mono version-id\">{v2}</span>")));
    assert!(html.contains("<td>\n        <div class=\"row-actions\">"));
    let (_, html) = w.page("/v/kv-test/keys/app-key").await;
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
    let (status, html) = w.page("/v/kv-test/audit?person=a%22b").await;
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

#[tokio::test]
async fn bulk_change_pages_have_labels_and_one_heading() {
    let w = support::world().await;
    w.kv.state.put("db-password", "x");
    w.kv.state.put("api-key", "x");
    let picked = [
        ("item", "db-password"),
        ("item", "api-key"),
        ("op", "disable"),
    ];
    let html = support::body_text(w.post("/v/kv-test/secrets/-/bulk", &picked).await).await;
    page_basics(&html, "bulk review");
    assert!(
        html.contains("for=\"confirm_count\""),
        "the count is labelled"
    );
    let mut run = picked.to_vec();
    run.push(("confirm_count", "2"));
    let html = support::body_text(w.post("/v/kv-test/secrets/-/bulk/apply", &run).await).await;
    page_basics(&html, "bulk results");
    assert!(html.contains("Changed 2 secrets"), "{html}");
}

#[tokio::test]
async fn access_review_states_keep_the_table_rules() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put("db-password", "x");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    let path = "/v/kv-test/access/review";
    // Nothing known: no diagnostic setting readable, no role assignments.
    *w.arm.state.diagnostics.lock().unwrap() = None;
    w.arm.state.authz.lock().unwrap().assignments_forbidden = true;
    let (_, html) = w.page(path).await;
    page_basics(&html, path);
    assert!(html.contains(">Not known<"));
    assert!(html.contains("<caption class=\"visually-hidden\" id=\"review-caption\">"));
    assert!(html.contains(
        "<th scope=\"row\" class=\"item-name\"><a href=\"/v/kv-test/secrets/db-password\">"
    ));
    assert_eq!(html.matches("<th scope=\"col\">").count(), 9);
    // Callers and item access shown.
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::settings_to("logs", true));
    *w.arm.state.workspace_events.lock().unwrap() = vec![(
        "/workspaces/logs".into(),
        vec![support::RawEvent::new(
            "kv-test",
            "2026-11-10T10:00:00Z",
            "alex@example.com",
            "SecretGet",
            "db-password",
            200,
        )],
    )];
    {
        let mut m = w.arm.state.authz.lock().unwrap();
        m.assignments_forbidden = false;
        m.assignments = vec![(
            "/subscriptions/sub-a/resourceGroups/rg-kv-test/providers/Microsoft.KeyVault/vaults/kv-test/secrets/db-password".into(),
            support::SECRETS_USER.into(),
            "dddddddd-0000-0000-0000-000000000004".into(),
            "User".into(),
        )];
    }
    let (_, html) = w.page(path).await;
    page_basics(&html, path);
    assert!(html.contains("alex@example.com"));
    assert!(html.contains("in the Azure portal</span>"));
}

#[tokio::test]
async fn environments_pages_have_labels_headings_and_landmarks() {
    let w = support::world().await;
    let mut r1 = support::vault_row("kv-test", "sub-a", true);
    r1["tags"] = serde_json::json!({"app": "demo", "env": "dev"});
    let mut r2 = support::vault_row("kv-test", "sub-a", true);
    r2["name"] = serde_json::json!("kv-demo-prod");
    r2["id"] = serde_json::json!(
        "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-demo-prod"
    );
    r2["tags"] = serde_json::json!({"app": "demo", "env": "prod"});
    *w.arm.state.vaults.lock().unwrap() = vec![r1, r2];
    w.kv.state.put("shared-secret", "val");

    let (status, html) = w.page("/environments").await;
    assert_eq!(status, StatusCode::OK);
    page_basics(&html, "/environments");

    let (status, html) = w
        .page("/environments/set?vaults=kv-test,kv-demo-prod&name=shared-secret")
        .await;
    assert_eq!(status, StatusCode::OK);
    page_basics(&html, "/environments/set");

    let html = support::body_text(
        w.post(
            "/environments/set",
            &[("vaults", "kv-test,kv-demo-prod"), ("name", "bad name!")],
        )
        .await,
    )
    .await;
    page_basics(&html, "/environments/set error");
    assert!(html.contains("tabindex=\"-1\" data-error-summary"));
}
