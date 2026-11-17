//! Tag rows and tag suggestions (#253): a name and a value input per tag on
//! every form that sets tags, <datalist> suggestions from the vault's own
//! lists, filter box suggestions, and tag links on detail pages.

mod support;

use axum::http::StatusCode;
use support::{body_text, hidden_value, location};

/// The `<datalist id="...">` element, whole.
fn datalist<'a>(html: &'a str, id: &str) -> &'a str {
    let start = html
        .find(&format!("<datalist id=\"{id}\""))
        .unwrap_or_else(|| panic!("no datalist #{id}"));
    let rest = &html[start..];
    &rest[..rest.find("</datalist>").unwrap() + "</datalist>".len()]
}

fn options(list: &str) -> Vec<&str> {
    list.split("<option value=\"")
        .skip(1)
        .map(|o| o.split('"').next().unwrap())
        .collect()
}

#[tokio::test]
async fn every_tag_form_has_rows_and_no_textarea() {
    let w = support::world().await;
    w.kv.state.put_with("db-password", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.add_cert("web-tls", true, "UEZY");
    w.kv.state.add_key_with("app-key", "RSA", |_| {});
    for path in [
        "/v/kv-test/secrets/-/new",
        "/v/kv-test/secrets/db-password/edit",
        "/v/kv-test/secrets/db-password/value",
        "/v/kv-test/certificates/-/new",
        "/v/kv-test/certificates/-/upload",
        "/v/kv-test/certificates/web-tls/details",
        "/v/kv-test/keys/-/new",
        "/v/kv-test/keys/app-key/details",
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(!html.contains("name=\"tags\""), "{path}: no tags box");
        assert!(
            html.contains("<fieldset class=\"tag-rows\" id=\"tags\""),
            "{path}"
        );
        assert!(
            html.contains("<input type=\"hidden\" name=\"tag-rows\" value=\"1\">"),
            "{path}"
        );
        // Three empty rows at least, labelled, with the name list.
        for n in 1..=3 {
            assert!(
                html.contains(&format!("<label for=\"tag-name-{n}\">Tag {n} name</label>")),
                "{path}"
            );
            assert!(
                html.contains(&format!(
                    "<label for=\"tag-value-{n}\">Tag {n} value</label>"
                )),
                "{path}"
            );
        }
        assert!(html.contains("list=\"tag-names\""), "{path}");
        datalist(&html, "tag-names");
        datalist(&html, "tag-values-any");
    }
    // The secret's own tag is the first row; three empty rows follow.
    let (_, html) = w.page("/v/kv-test/secrets/db-password/edit").await;
    assert!(html.contains("id=\"tag-name-1\" name=\"tag-name-1\" type=\"text\" value=\"env\""));
    assert!(html.contains("id=\"tag-name-4\" name=\"tag-name-4\" type=\"text\" value=\"\""));
    assert!(!html.contains("id=\"tag-name-5\""));
}

#[tokio::test]
async fn suggestions_come_from_the_vault_most_used_first_never_the_note() {
    let w = support::world().await;
    let s = &w.kv.state;
    s.put_with("a", "VALUE-A", |v| {
        v.tags.insert("env".into(), "prod".into());
        v.tags.insert("team".into(), "data".into());
        v.tags.insert("description".into(), "PRIVATE NOTE".into());
    });
    s.put_with("b", "VALUE-B", |v| {
        v.tags.insert("env".into(), "test".into());
    });
    s.add_key_with("k", "RSA", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    let reads = s.no_value_reads();
    let (_, html) = w.page("/v/kv-test/secrets/-/new").await;
    assert_eq!(options(datalist(&html, "tag-names")), ["env", "team"]);
    assert_eq!(options(datalist(&html, "tag-values-1")), ["prod", "test"]);
    assert!(html.contains("<datalist id=\"tag-values-1\" data-tag-for=\"env\">"));
    assert_eq!(
        options(datalist(&html, "tag-values-any")),
        ["prod", "data", "test"]
    );
    assert!(!html.contains("PRIVATE NOTE"));
    assert!(!html.contains("VALUE-A") && !html.contains("VALUE-B"));
    // An existing row's value list is its name's.
    let (_, html) = w.page("/v/kv-test/secrets/a/edit").await;
    assert!(html.contains(
        "name=\"tag-value-1\" type=\"text\" value=\"prod\" maxlength=\"256\" list=\"tag-values-1\""
    ));
    assert!(html.contains(
        "name=\"tag-value-3\" type=\"text\" value=\"\" maxlength=\"256\" list=\"tag-values-any\""
    ));
    drop(reads);
}

#[tokio::test]
async fn datalists_and_rows_escape_what_they_show() {
    let w = support::world().await;
    let odd = "q\"<b>&'x";
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert(odd.into(), odd.into());
    });
    // The form's row and datalists, the list's filter list, the page's tag.
    for path in [
        "/v/kv-test/secrets/a/edit",
        "/v/kv-test/secrets",
        "/v/kv-test/secrets/a",
    ] {
        let (_, html) = w.page(path).await;
        assert!(!html.contains(odd), "{path}: raw");
        assert!(!html.contains("<b>&"), "{path}: raw");
        assert!(
            html.contains("q&#34;&#60;b&#62;&#38;&#39;x"),
            "{path}: escaped"
        );
    }
    // The detail page's link encodes the filter in the query.
    let (_, html) = w.page("/v/kv-test/secrets/a").await;
    assert!(
        html.contains("href=\"/v/kv-test/secrets?tag=q%22%3Cb%3E%26%27x%3Dq%22%3Cb%3E%26%27x\"")
    );
}

#[tokio::test]
async fn a_slow_or_refused_list_shows_the_form_without_suggestions() {
    let w = support::world().await;
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    *w.kv.state.fail_each.lock().unwrap() = vec![(
        axum::http::Method::GET,
        "/secrets$".into(),
        403,
        "ForbiddenByRbac",
    )];
    let (status, html) = w.page("/v/kv-test/keys/-/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(options(datalist(&html, "tag-names")).is_empty());
    w.kv.state.fail_each.lock().unwrap().clear();

    // Slower than the time limit: the form comes back in about that time.
    *w.kv.state.delay.lock().unwrap() = std::time::Duration::from_secs(5);
    let t = std::time::Instant::now();
    let (status, html) = w.page("/v/kv-test/secrets/-/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        t.elapsed() < std::time::Duration::from_secs(4),
        "{:?}",
        t.elapsed()
    );
    assert!(options(datalist(&html, "tag-names")).is_empty());
    *w.kv.state.delay.lock().unwrap() = std::time::Duration::ZERO;
    // Still works: a tag typed by hand is saved.
    let res = w
        .post(
            "/v/kv-test/secrets/-/new",
            &[
                ("name", "b"),
                ("value", "x"),
                ("tag-rows", "1"),
                ("tag-name-1", "team"),
                ("tag-value-1", "web"),
                ("enabled", "on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(w.kv.state.current("b").unwrap().tags["team"], "web");
}

#[tokio::test]
async fn a_round_trip_keeps_every_tag_and_a_cleared_row_removes_one() {
    let w = support::world().await;
    w.kv.state.add_key_with("app-key", "RSA", |v| {
        v.tags.insert("env".into(), "prod".into());
        v.tags.insert(" spaced ".into(), "a = b".into());
        v.tags.insert("multi".into(), "one\ntwo".into());
        v.tags.insert("description".into(), "note".into());
    });
    let (_, html) = w.page("/v/kv-test/keys/app-key/details").await;
    assert!(html.contains("<li class=\"mono\">multi: one\ntwo</li>"));
    let version = hidden_value(&html, "version").unwrap();
    let updated = hidden_value(&html, "updated").unwrap();
    // Rows are in name order: " spaced ", env.
    assert!(html.contains("name=\"tag-name-1\" type=\"text\" value=\" spaced \""));
    assert!(html.contains("name=\"tag-name-2\" type=\"text\" value=\"env\""));
    // Unchanged: nothing is sent.
    let same = [
        ("version", version.as_str()),
        ("updated", updated.as_str()),
        ("description", "note"),
        ("tag-rows", "1"),
        ("tag-name-1", " spaced "),
        ("tag-value-1", "a = b"),
        ("tag-name-2", "env"),
        ("tag-value-2", "prod"),
        ("tag-name-3", ""),
        ("tag-value-3", ""),
    ];
    let before = w.kv.state.log.lock().unwrap().len();
    let res = w.post("/v/kv-test/keys/app-key/details", &same).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        w.kv.state.log.lock().unwrap()[before..]
            .iter()
            .all(|l| !l.starts_with("PATCH"))
    );
    // Clear env, add a tag from a suggestion.
    let res = w
        .post(
            "/v/kv-test/keys/app-key/details",
            &[
                ("version", &version),
                ("updated", &updated),
                ("description", "note"),
                ("tag-rows", "1"),
                ("tag-name-1", " spaced "),
                ("tag-value-1", "a = b"),
                ("tag-name-2", ""),
                ("tag-value-2", ""),
                ("tag-name-3", "team"),
                ("tag-value-3", "data"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", location(&res));
    let keys = w.kv.state.keys.lock().unwrap();
    let tags = &keys["app-key"].versions[0].tags;
    let mut names: Vec<&str> = tags.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, [" spaced ", "description", "multi", "team"]);
    assert_eq!(tags[" spaced "], "a = b");
    assert_eq!(tags["multi"], "one\ntwo");
}

#[tokio::test]
async fn odd_posts_are_refused_beside_the_row_or_for_the_form() {
    let w = support::world().await;
    let post = |fields: Vec<(&'static str, &'static str)>| {
        let w = &w;
        async move {
            let mut f = vec![
                ("name", "n"),
                ("value", "x"),
                ("enabled", "on"),
                ("tag-rows", "1"),
            ];
            f.extend(fields);
            let res = w.post("/v/kv-test/secrets/-/new", &f).await;
            (res.status(), body_text(res).await)
        }
    };
    // A value with no name: the error is on that row's name.
    let (status, html) = post(vec![("tag-name-2", ""), ("tag-value-2", "orphan")]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("<p class=\"field-error\" id=\"tag-name-2-error\">Give this tag a name"));
    assert!(html.contains("id=\"tag-name-2\" name=\"tag-name-2\" type=\"text\" value=\"\" maxlength=\"512\" list=\"tag-names\" data-tag-name autocomplete=\"off\" autocapitalize=\"off\" autocorrect=\"off\" spellcheck=\"false\" aria-describedby=\"tag-name-2-error\" aria-invalid=\"true\""));
    // The value typed is kept in its row.
    assert!(html.contains("name=\"tag-value-2\" type=\"text\" value=\"orphan\""));
    // A row field sent twice, or numbered past the cap: the whole form.
    for bad in [
        vec![("tag-name-1", "a"), ("tag-name-1", "b")],
        vec![("tag-name-41", "a")],
        vec![("tag-name-007", "a")],
    ] {
        let (status, html) = post(bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(html.contains("tag rows it doesn&#39;t have"), "{html}");
        assert!(html.contains("<p class=\"field-error\" id=\"tags-error\">"));
    }
    // A form from before rows is refused, never read as "no tags".
    let (status, html) = post(vec![("tags", "env=prod")]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("This form changed since you opened it"));
    // `description` as a row name points at the field.
    let (status, html) = post(vec![("tag-name-1", "description"), ("tag-value-1", "x")]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        html.contains(
            "id=\"tag-name-1-error\">The description tag is set with the Description field"
        )
    );
    assert!(w.kv.state.current("n").is_none());
}

#[tokio::test]
async fn filter_boxes_suggest_tags_from_the_page() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
        v.tags.insert("description".into(), "PRIVATE NOTE".into());
    });
    w.kv.state.add_cert_version(
        "c",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(true, false),
        |v| {
            v.tags.insert("team".into(), "web".into());
        },
    );
    w.kv.state.add_key_with("k", "RSA", |v| {
        v.tags.insert("rota".into(), "ops".into());
    });
    for (path, want) in [
        ("/v/kv-test/secrets", vec!["env", "env=prod"]),
        ("/v/kv-test/certificates", vec!["team", "team=web"]),
        ("/v/kv-test/keys", vec!["rota", "rota=ops"]),
        (
            "/expiry",
            vec!["env", "env=prod", "rota", "rota=ops", "team", "team=web"],
        ),
        (
            "/expiry/age",
            vec!["env", "env=prod", "rota", "rota=ops", "team", "team=web"],
        ),
        (
            "/search?q=a",
            vec!["env", "env=prod", "rota", "rota=ops", "team", "team=web"],
        ),
        // The vault list suggests the vaults' own tags (from ARM).
        ("/vaults", vec!["env", "env=prod"]),
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let mut got = options(datalist(&html, "tag-filter-options"));
        got.sort_unstable();
        assert_eq!(got, want, "{path}");
        assert!(html.contains("list=\"tag-filter-options\""), "{path}");
        assert!(!html.contains("PRIVATE NOTE\""), "{path}");
    }
}

#[tokio::test]
async fn detail_tags_link_to_the_filtered_list() {
    let w = support::world().await;
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    w.kv.state.put("b", "x");
    w.kv.state.add_key_with("k1", "RSA", |v| {
        v.tags.insert("env".into(), "prod".into());
        v.tags.insert("a=b".into(), "c".into());
    });
    w.kv.state.add_key_with("k2", "RSA", |_| {});
    let (_, html) = w.page("/v/kv-test/secrets/a").await;
    assert!(
        html.contains("<a class=\"tag\" href=\"/v/kv-test/secrets?tag=env%3Dprod\">env=prod</a>")
    );
    let (_, html) = w.page("/v/kv-test/secrets?tag=env%3Dprod").await;
    assert!(html.contains(">a<") && !html.contains(">b<"));
    let (_, html) = w.page("/v/kv-test/keys/k1").await;
    assert!(html.contains("href=\"/v/kv-test/keys?tag=env%3Dprod\""));
    // A name with an = can't be told apart in the filter: no link.
    assert!(html.contains("<span class=\"tag\">a=b=c</span>"));
    let (_, html) = w.page("/v/kv-test/keys?tag=env%3Dprod").await;
    assert!(html.contains(">k1<") && !html.contains(">k2<"));
}

#[tokio::test]
async fn bulk_change_suggests_names_and_values() {
    let w = support::world().await;
    w.kv.state.put_with("a", "x", |v| {
        v.tags.insert("env".into(), "prod".into());
    });
    let (_, html) = w.page("/v/kv-test/secrets").await;
    assert!(html.contains(
        "id=\"bulk-tag-name\" name=\"tag_name\" type=\"text\" maxlength=\"512\" list=\"tag-names\""
    ));
    assert!(html.contains("list=\"tag-values-any\" data-tag-value"));
    assert_eq!(options(datalist(&html, "tag-names")), ["env"]);
}
