//! Static files compiled into the binary, so the container needs no
//! filesystem access and nothing can be swapped at run time.

use askama::Template;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

const STYLE_CSS: &str = include_str!("../../static/style.css");
const APP_JS: &str = include_str!("../../static/app.js");

/// Look up an embedded asset by file name.
fn lookup(file: &str) -> Option<(&'static str, &'static str)> {
    match file {
        "style.css" => Some((STYLE_CSS, "text/css; charset=utf-8")),
        "app.js" => Some((APP_JS, "text/javascript; charset=utf-8")),
        _ => None,
    }
}

pub async fn serve(Path(file): Path<String>) -> Response {
    match lookup(&file) {
        Some((body, mime)) => (
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Render a template, falling back to a short plain message if rendering
/// fails. Template errors are logged without any page data.
pub fn render<T: Template>(page: &T) -> Html<String> {
    match page.render() {
        Ok(html) => Html(html),
        Err(err) => {
            tracing::error!(error = %err, "template render failed");
            Html("<!doctype html><title>Keyring</title><p>Something went wrong showing this page.</p>".into())
        }
    }
}
