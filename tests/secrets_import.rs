//! Importing secrets from a `.env` or CSV file: preview, import, results.

mod support;

use axum::http::StatusCode;
use support::{Part, body_text, hidden_value};

const VALUE_A: &str = "Imp0rt-Value-A-<&>";
const VALUE_B: &str = "Imp0rt-Value-B";

async fn preview(w: &support::World, file: &[u8], file_name: &str) -> (StatusCode, String) {
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[Part::File("file", file_name, file)],
        )
        .await;
    let status = res.status();
    (status, body_text(res).await)
}

async fn confirm(w: &support::World, html: &str) -> (StatusCode, String) {
    let id = hidden_value(html, "import_id").expect("import id on the preview");
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", &id)])
        .await;
    let status = res.status();
    (status, body_text(res).await)
}

#[tokio::test]
async fn env_file_previews_names_then_imports() {
    let w = support::world().await;
    w.kv.state.put("API-KEY", "old");
    w.kv.state.put("gone", "x");
    w.kv.state.soft_delete("gone");
    let file =
        format!("# app settings\nDB_PASSWORD=\"{VALUE_A}\"\nAPI_KEY={VALUE_B}\ngone=x\nEMPTY=\n");
    let (status, html) = preview(&w, file.as_bytes(), ".env").await;
    assert_eq!(status, StatusCode::OK, "{html}");
    // Names, original and converted, and what happens to each.
    assert!(html.contains("DB-PASSWORD") && html.contains("DB_PASSWORD"));
    assert!(html.contains(">New<"), "{html}");
    assert!(html.contains(">New version<"));
    assert!(html.contains("Blocked by a deleted secret"));
    assert!(html.contains("no value"));
    assert!(html.contains("Import 2 secrets"));
    // Never a value.
    assert!(!html.contains("Imp0rt-Value"), "value in the preview");
    assert!(!html.contains("&lt;&amp;&gt;"));
    let writes = |w: &support::World| {
        w.kv.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("PUT"))
            .count()
    };
    assert_eq!(writes(&w), 0, "nothing written by the preview");

    let (status, html) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("Imported 2 secrets"), "{html}");
    assert!(html.contains(">Created<") && html.contains(">New version<"));
    assert!(html.contains(">Not imported<"));
    assert!(!html.contains("Imp0rt-Value"), "value in the results");
    assert_eq!(
        w.kv.state.current("DB-PASSWORD").unwrap().value,
        VALUE_A,
        "stored as written"
    );
    let api = w.kv.state.secrets.lock().unwrap()["API-KEY"].clone();
    assert_eq!(api.versions.len(), 2, "a new version");
    assert_eq!(api.versions[1].value, VALUE_B);
    assert_eq!(writes(&w), 2, "skipped rows are never sent");

    // Each import is taken once.
    let id = "anything";
    let res = w
        .post("/v/kv-test/secrets/-/import/confirm", &[("import_id", id)])
        .await;
    assert_eq!(res.status(), StatusCode::GONE);
}

#[tokio::test]
async fn csv_with_optional_columns() {
    let w = support::world().await;
    let file = "name,value,content_type,expires,tags\nweb_key,\"=SUM(A1)\",text/plain,2030-06-30,env=prod;team=ops\n";
    let (status, html) = preview(&w, file.as_bytes(), "secrets.csv").await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("web-key") && html.contains("web_key"));
    assert!(html.contains("text/plain"));
    assert!(
        html.contains("30 Jun 2030") || html.contains("2030"),
        "{html}"
    );
    assert!(html.contains("env=prod") && html.contains("team=ops"));
    assert!(!html.contains("=SUM"), "value in the preview");
    let (status, _) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::OK);
    let v = w.kv.state.current("web-key").unwrap();
    assert_eq!(
        v.value, "=SUM(A1)",
        "a formula-looking value is kept as typed"
    );
    assert_eq!(v.content_type.as_deref(), Some("text/plain"));
    assert!(v.exp.is_some());
    assert_eq!(v.tags.get("team").map(String::as_str), Some("ops"));
}

#[tokio::test]
async fn clashes_and_bad_files_are_refused_before_anything_is_kept() {
    let w = support::world().await;
    let (status, html) = preview(&w, b"DB_PASSWORD=1\ndb-password=2\n", ".env").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("both become DB-PASSWORD"), "{html}");
    assert!(hidden_value(&html, "import_id").is_none());

    let (status, html) = preview(&w, b"name,secret\na,b\n", "a.csv").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("column"), "{html}");

    let many: String = (0..501).map(|i| format!("S{i}=v\n")).collect();
    let (status, html) = preview(&w, many.as_bytes(), ".env").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("up to 500"), "{html}");
}

#[tokio::test]
async fn file_limit_is_1_mb_on_this_route_only() {
    let w = support::world().await;
    // Over 1 MB of file, under the route's body limit: the form's message.
    let big = format!("A={}\n", "x".repeat(1024 * 1024));
    let (status, html) = preview(&w, big.as_bytes(), ".env").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("over 1024 KB"), "{html}");
    // Well over: the body limit. Nothing kept, nothing sent.
    let huge = vec![b'a'; 2 * 1024 * 1024];
    let (status, _) = preview(&w, &huge, ".env").await;
    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::PAYLOAD_TOO_LARGE,
        "{status}"
    );
    // A file just under 1 MB is read.
    let rows: String = (0..400)
        .map(|i| format!("S{i}={}\n", "v".repeat(2000)))
        .collect();
    assert!(rows.len() < 1024 * 1024);
    let (status, html) = preview(&w, rows.as_bytes(), ".env").await;
    assert_eq!(status, StatusCode::OK, "{html}");
    // Other forms keep their own limits.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[("name", "x"), ("value", &"a".repeat(300 * 1024))],
        )
        .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn certificate_names_are_not_overwritten() {
    let w = support::world().await;
    w.kv.state.put("web-tls", "pfx");
    w.kv.state
        .secrets
        .lock()
        .unwrap()
        .get_mut("web-tls")
        .unwrap()
        .managed = true;
    let (status, html) = preview(&w, b"web_tls=x\nother=y\n", ".env").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Managed by a certificate"));
    assert!(html.contains("Import 1 secret<"), "{html}");
    let (_, html) = confirm(&w, &html).await;
    assert!(html.contains("Imported 1 secret"));
    assert_eq!(w.kv.state.current("web-tls").unwrap().value, "pfx");
}

#[tokio::test]
async fn refusals_are_reported_per_row() {
    let w = support::world().await;
    let (_, html) = preview(&w, b"A=1\nB=2\n", ".env").await;
    *w.kv.state.fail.lock().unwrap() = Some((403, "ForbiddenByRbac"));
    *w.kv.state.fail_method.lock().unwrap() = Some(axum::http::Method::PUT);
    let (status, html) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Imported 0 secrets"), "{html}");
    assert_eq!(html.matches("Refused by Azure").count(), 2);
    assert!(!html.contains("private detail"), "never Azure's message");
}

#[tokio::test]
async fn a_name_deleted_after_the_preview_is_reported_as_blocked() {
    let w = support::world().await;
    w.kv.state.put("late", "x");
    let (_, html) = preview(&w, b"late=new\n", ".env").await;
    assert!(html.contains(">New version<"));
    w.kv.state.soft_delete("late");
    let (_, html) = confirm(&w, &html).await;
    assert!(html.contains("Blocked by a deleted secret"), "{html}");
}

#[tokio::test]
async fn start_again_forgets_the_file() {
    let w = support::world().await;
    let (_, html) = preview(&w, b"A=1\n", ".env").await;
    let res = w.post("/v/kv-test/secrets/-/import/cancel", &[]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (status, _) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::GONE);
    assert!(w.kv.state.current("A").is_none());
    // Opening the form again also forgets one.
    let (_, html) = preview(&w, b"A=1\n", ".env").await;
    let _ = w.get("/v/kv-test/secrets/-/import").await;
    let (status, _) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn list_page_links_to_import_and_form_needs_no_script() {
    let w = support::world().await;
    let (status, html) = w.page("/v/kv-test/secrets").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("/v/kv-test/secrets/-/import\">Import secrets"));
    let (status, html) = w.page("/v/kv-test/secrets/-/import").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("enctype=\"multipart/form-data\""));
    assert!(html.contains("<button type=\"submit\">Check the file</button>"));
    assert!(!html.contains("<script>"), "no inline script");
}

#[tokio::test]
async fn a_csv_without_a_header_never_shows_its_first_line() {
    let w = support::world().await;
    let (status, html) = preview(&w, b"PASSWORD=TopSecret42\nB=2\n", "secrets.csv").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("column 1"), "{html}");
    assert!(!html.to_ascii_lowercase().contains("topsecret42"), "{html}");
}

#[tokio::test]
async fn a_second_file_is_refused() {
    let w = support::world().await;
    let res = w
        .post_multipart(
            "/v/kv-test/secrets/-/import",
            &[
                Part::File("file", ".env", b"A=1\n"),
                Part::File("file", ".env", b"B=2\n"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("one file"), "{html}");
    assert!(hidden_value(&html, "import_id").is_none(), "nothing kept");
}

#[tokio::test]
async fn an_older_preview_form_leaves_the_newer_import_waiting() {
    let w = support::world().await;
    let (_, old) = preview(&w, b"A=1\n", ".env").await;
    let (_, new) = preview(&w, b"B=2\n", ".env").await;
    let (status, _) = confirm(&w, &old).await;
    assert_eq!(status, StatusCode::GONE);
    let (status, html) = confirm(&w, &new).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(w.kv.state.current("B").is_some());
    assert!(w.kv.state.current("A").is_none());
}

#[tokio::test]
async fn start_again_during_a_preview_means_it_is_not_kept() {
    let w = support::world().await;
    // The vault lists are slow, so "Start again" lands while the preview
    // waits on them.
    *w.kv.state.delay.lock().unwrap() = std::time::Duration::from_millis(600);
    let slow = preview(&w, b"A=1\n", ".env");
    let cancel = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        w.post("/v/kv-test/secrets/-/import/cancel", &[]).await
    };
    let ((status, html), res) = tokio::join!(slow, cancel);
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{html}");
    assert!(hidden_value(&html, "import_id").is_none(), "nothing kept");
    assert!(html.contains("Choose the file again"), "{html}");
    *w.kv.state.delay.lock().unwrap() = std::time::Duration::ZERO;
    // A preview after that is kept as usual.
    let (_, html) = preview(&w, b"A=1\n", ".env").await;
    let (status, _) = confirm(&w, &html).await;
    assert_eq!(status, StatusCode::OK);
}
