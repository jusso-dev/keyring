//! The rotation line on a secret's page and the "Rotation failed" list on
//! the expiry dashboard, both read from tags the vault already returns.

mod support;

use axum::http::StatusCode;

fn seed_vault(w: &support::World) {
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
}

fn tag(w: &support::World, name: &str, tags: &[(&str, &str)]) {
    let tags: Vec<(String, String)> = tags
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    w.kv.state.put_with(name, "VALUE-X", move |v| {
        for (k, val) in &tags {
            v.tags.insert(k.clone(), val.clone());
        }
    });
}

#[tokio::test]
async fn rotation_line_from_the_tags() {
    let w = support::world().await;
    tag(
        &w,
        "storage-key",
        &[
            ("rotation", "storage-key-rotator"),
            ("rotation-last", "2026-11-02T03:00:00Z"),
            ("rotation-status", "ok"),
        ],
    );
    let (status, html) = w.page("/v/kv-test/secrets/storage-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(
        r#"Rotated by <span class="mono">storage-key-rotator</span>, last 2 Nov 2026, <span class="badge badge-ok">OK</span>"#
    ));
    assert!(html.contains("not checked by Keyring"));
    // Still in the tag list too.
    assert!(html.contains(r#"<span class="tag">rotation-status=ok</span>"#));
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn failed_rotation_on_the_page() {
    let w = support::world().await;
    tag(
        &w,
        "sql-login",
        &[
            ("rotation", "sql-rotator"),
            ("rotation-last", "2026-11-02"),
            ("rotation-status", "failed"),
        ],
    );
    let (_, html) = w.page("/v/kv-test/secrets/sql-login").await;
    assert!(html.contains(r#"<span class="badge badge-error">Failed</span>"#));
}

#[tokio::test]
async fn no_rotation_tags_no_line() {
    let w = support::world().await;
    tag(&w, "plain", &[("env", "prod")]);
    let (_, html) = w.page("/v/kv-test/secrets/plain").await;
    assert!(!html.contains("<dt>Rotation</dt>"));
    assert!(!html.contains("Rotated by"));
}

#[tokio::test]
async fn hostile_tag_values_render_safely() {
    let w = support::world().await;
    let long = "r".repeat(300);
    tag(
        &w,
        "hostile",
        &[
            ("rotation", "<script>alert(1)</script>\u{1b}[31m\u{202E}"),
            ("rotation-last", "2026-02-31"),
            ("rotation-status", "<b>ok</b>"),
        ],
    );
    tag(
        &w,
        "long",
        &[
            ("rotation", &long),
            ("rotation-last", "\"><img src=x>"),
            ("rotation-status", "OK"),
        ],
    );
    let (_, html) = w.page("/v/kv-test/secrets/hostile").await;
    assert!(!html.contains("<script>alert"));
    assert!(!html.contains("<b>ok</b>"));
    assert!(html.contains(
        r#"Rotated by <span class="mono">&#60;script&#62;alert(1)&#60;/script&#62;[31m</span>, last unknown, <span class="badge badge-muted">Unknown</span>"#
    ), "{html}");
    let (_, html) = w.page("/v/kv-test/secrets/long").await;
    assert!(!html.contains("<img src=x>"));
    let shown = format!("{}…", "r".repeat(64));
    assert!(html.contains(&format!(
        r#"Rotated by <span class="mono">{shown}</span>, last unknown, <span class="badge badge-muted">Unknown</span>"#
    )));
}

#[tokio::test]
async fn expiry_dashboard_lists_failed_rotations() {
    let w = support::world().await;
    seed_vault(&w);
    tag(
        &w,
        "sql-login",
        &[
            ("rotation", "sql-rotator"),
            ("rotation-last", "2026-11-02"),
            ("rotation-status", "failed"),
        ],
    );
    tag(
        &w,
        "storage-key",
        &[
            ("rotation", "storage-key-rotator"),
            ("rotation-status", "ok"),
        ],
    );
    tag(&w, "odd", &[("rotation-status", "FAILED<i>")]);
    let (status, html) = w.page("/expiry").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"Rotation failed <span class="muted">(1)</span>"#));
    let section = html.split(r#"id="rotation-failed""#).nth(1).unwrap();
    let section = section.split("</section>").next().unwrap();
    assert!(section.contains(r#">sql-login <span class="badge badge-error">Failed</span>"#));
    assert!(section.contains(r#"<td class="mono">sql-rotator</td>"#));
    assert!(section.contains("2 Nov 2026"));
    assert!(!section.contains("storage-key"));
    assert!(!section.contains(">odd"));
    assert!(!html.contains("<i>"));
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn no_failed_rotations_no_section() {
    let w = support::world().await;
    seed_vault(&w);
    tag(&w, "storage-key", &[("rotation-status", "ok")]);
    let (_, html) = w.page("/expiry").await;
    assert!(!html.contains("Rotation failed"));
}
