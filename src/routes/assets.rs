//! Static files compiled into the binary, so the container needs no
//! filesystem access and nothing can be swapped at run time.
//!
//! Pages link to them with a version in the query (`/static/app.js?v=...`),
//! taken from a hash of the file's bytes. A request with the current
//! version can be cached for a year, since a new build changes the URL. A
//! request without it, or with an old one (a page left open across an
//! upgrade), gets the current file with a short cache.

use std::sync::LazyLock;

use askama::Template;
use axum::extract::{Path, Query};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

const STYLE_CSS: &str = include_str!("../../static/style.css");
const APP_JS: &str = include_str!("../../static/app.js");

/// Cache header for a versioned URL that matches the file served.
pub const CACHE_VERSIONED: &str = "public, max-age=31536000, immutable";
/// Cache header for an unversioned or out-of-date URL.
pub const CACHE_UNVERSIONED: &str = "public, max-age=300";

/// Look up an embedded asset by file name.
fn lookup(file: &str) -> Option<(&'static str, &'static str)> {
    match file {
        "style.css" => Some((STYLE_CSS, "text/css; charset=utf-8")),
        "app.js" => Some((APP_JS, "text/javascript; charset=utf-8")),
        _ => None,
    }
}

/// First 16 hex digits of the SHA-256 of `body`.
fn hash(body: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, body.as_bytes());
    d.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

static STYLE_VERSION: LazyLock<String> = LazyLock::new(|| hash(STYLE_CSS));
static APP_VERSION: LazyLock<String> = LazyLock::new(|| hash(APP_JS));

fn version(file: &str) -> Option<&'static str> {
    match file {
        "style.css" => Some(STYLE_VERSION.as_str()),
        "app.js" => Some(APP_VERSION.as_str()),
        _ => None,
    }
}

/// The versioned URL for an embedded asset, for templates.
pub fn url(file: &str) -> String {
    match version(file) {
        Some(v) => format!("/static/{file}?v={v}"),
        None => format!("/static/{file}"),
    }
}

#[derive(Deserialize, Default)]
pub struct AssetQuery {
    #[serde(default)]
    v: String,
}

pub async fn serve(Path(file): Path<String>, Query(q): Query<AssetQuery>) -> Response {
    match lookup(&file) {
        Some((body, mime)) => {
            let cache = if version(&file) == Some(q.v.as_str()) {
                CACHE_VERSIONED
            } else {
                CACHE_UNVERSIONED
            };
            (
                [(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, cache)],
                body,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Browsers ask for this on every site. Keyring has no icon, so say so
/// briefly instead of rendering the full "Page not found" page.
pub async fn favicon() -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::CACHE_CONTROL, "public, max-age=86400")],
    )
        .into_response()
}

/// A short styled page for responses made outside the templates: the
/// request timeout, the cross-site refusal and a failed render. `heading`
/// and `message` are fixed text, never user input.
pub fn plain_page(heading: &str, message: &str) -> Html<String> {
    Html(format!(
        "<!doctype html>\n<html lang=\"en-AU\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{heading} - Keyring</title>\n<link rel=\"stylesheet\" href=\"{css}\">\n</head>\n\
         <body>\n<header class=\"site-header\"><a class=\"brand\" href=\"/\">Keyring</a></header>\n\
         <div class=\"layout layout-plain\"><main id=\"main\" class=\"content\">\n\
         <div class=\"panel narrow\" role=\"alert\">\n<h1>{heading}</h1>\n<p>{message}</p>\n\
         <p><a class=\"button\" href=\"/\">Back to home</a></p>\n</div>\n</main></div>\n</body>\n</html>\n",
        css = url("style.css"),
    ))
}

/// Render a template, falling back to a short styled message if rendering
/// fails. Template errors are logged without any page data.
pub fn render<T: Template>(page: &T) -> Html<String> {
    match page.render() {
        Ok(html) => Html(html),
        Err(err) => {
            tracing::error!(error = %err, "template render failed");
            plain_page(
                "Something went wrong",
                "Keyring couldn't show this page. Go back and try again. If it keeps happening, let whoever runs Keyring know.",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_carry_a_content_hash() {
        let u = url("app.js");
        let v = u.strip_prefix("/static/app.js?v=").unwrap();
        assert_eq!(v.len(), 16);
        assert!(v.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(version("style.css"), version("app.js"));
        assert_eq!(url("nope.js"), "/static/nope.js");
    }

    #[test]
    fn plain_page_is_styled_html() {
        let Html(h) = plain_page("Heading", "Message.");
        assert!(h.starts_with("<!doctype html>"));
        assert!(h.contains("<html lang=\"en-AU\">"));
        assert!(h.contains(&url("style.css")));
        assert!(h.contains("href=\"/\">Back to home</a>"));
        assert!(!h.contains('\u{2014}'));
    }
}
