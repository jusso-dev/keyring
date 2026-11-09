//! Accessibility checks on rendered pages: every form control has a label,
//! one h1 per page, the skip link, landmarks, and error summaries that can
//! take focus and point at real fields.

mod support;

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

fn page_basics(html: &str, path: &str) {
    describedby_targets_exist(html, path);
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
        "/secrets/deleted".into(),
        "/certificates".into(),
        "/certificates/new".into(),
        "/certificates/upload".into(),
        "/certificates/web-tls".into(),
        "/certificates/web-tls/download-key".into(),
        "/certificates/web-tls/delete".into(),
        "/keys".into(),
        "/keys/new".into(),
        "/keys/app-key".into(),
        "/keys/app-key/rotate".into(),
        "/keys/app-key/rotation".into(),
        "/keys/app-key/delete".into(),
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
    assert!(
        html.contains(
            "role=\"alert\" tabindex=\"-1\" data-error-summary id=\"confirm_name-error\""
        )
    );
    assert!(html.contains("aria-invalid=\"true\" aria-describedby=\"confirm_name-error\""));
    assert!(html.contains("Nothing was deleted."));
    describedby_targets_exist(&html, "delete mismatch");
}
