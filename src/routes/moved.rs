//! Redirects from where the fixed pages used to be.
//!
//! The add, upload and deleted pages were at `/secrets/new` and the like,
//! beside `/secrets/{name}`, so an item called `new` couldn't be opened.
//! They now sit under `/-/` (`/secrets/-/new`), which can't be an item:
//! Keyring refuses any name that starts with a hyphen (see
//! `vault_ctx::is_valid_object_name`).
//!
//! Old bookmarks and forms still work, with a 308 so a form post keeps its
//! method and body. An old path that no route matches
//! (`/secrets/deleted/db/recover`) is sent on by the fallback. An old path
//! that is now an item's page (`/secrets/new`) is sent on only when Key
//! Vault has no item of that name, so a real item called `new` opens as
//! normal. A post to an item's page can only be one of the old add or
//! upload forms, so it is sent on.

use axum::extract::{Path, Request};
use axum::http::header::{ALLOW, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::azure::AzureError;
use crate::routes::lifecycle::Kind;

/// The fixed pages each kind had beside its items.
fn fixed_pages(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Secret | Kind::Key => &["new", "deleted"],
        Kind::Certificate => &["new", "deleted", "upload"],
    }
}

fn kind_for(base: &str) -> Option<Kind> {
    [Kind::Secret, Kind::Certificate, Kind::Key]
        .into_iter()
        .find(|k| k.base() == base)
}

/// Where an old fixed-page path lives now, or `None` if it isn't one.
/// The query string is kept.
pub(super) fn new_location(path_and_query: &str) -> Option<String> {
    let rest = path_and_query.strip_prefix('/')?;
    let (base, rest) = rest.split_once('/')?;
    let kind = kind_for(&format!("/{base}"))?;
    let page = rest.split(['/', '?']).next()?;
    fixed_pages(kind)
        .contains(&page)
        .then(|| format!("/{base}/-/{rest}"))
}

/// A 308, so a form post is sent on with its method and body.
fn redirect(to: &str) -> Response {
    match HeaderValue::from_str(to) {
        Ok(v) => (StatusCode::PERMANENT_REDIRECT, [(LOCATION, v)]).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// For the router's fallback: the redirect when the path is an old one.
pub(super) fn from_fallback(req: &Request) -> Option<Response> {
    let pq = req.uri().path_and_query()?.as_str();
    new_location(pq).map(|to| redirect(&to))
}

/// For an item page that Key Vault said doesn't exist: if its name was a
/// fixed page, send the old bookmark on.
/// The query string is kept.
pub(super) fn missing_item(
    kind: Kind,
    name: &str,
    err: &AzureError,
    uri: &axum::http::Uri,
) -> Option<Response> {
    if !matches!(err, AzureError::Status { status: 404, .. }) || !fixed_pages(kind).contains(&name)
    {
        return None;
    }
    let to = match uri.query() {
        Some(q) => format!("{}/-/{name}?{q}", kind.base()),
        None => format!("{}/-/{name}", kind.base()),
    };
    Some(redirect(&to))
}

/// A post to an item page. Only the old add and upload forms posted there,
/// so send those on; anything else is the 405 it always was.
pub(super) async fn post_item(Path(name): Path<String>, req: Request) -> Response {
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_default();
    match new_location(pq) {
        Some(to) if matches!(name.as_str(), "new" | "upload") => redirect(&to),
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            [(ALLOW, HeaderValue::from_static("GET,HEAD"))],
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_paths_map_to_new_ones() {
        for (old, new) in [
            ("/secrets/new", Some("/secrets/-/new")),
            ("/secrets/deleted?page=2", Some("/secrets/-/deleted?page=2")),
            (
                "/secrets/deleted/db/recover",
                Some("/secrets/-/deleted/db/recover"),
            ),
            ("/certificates/upload", Some("/certificates/-/upload")),
            (
                "/certificates/upload/confirm",
                Some("/certificates/-/upload/confirm"),
            ),
            ("/keys/deleted/k/purge", Some("/keys/-/deleted/k/purge")),
            ("/keys/upload", None),
            ("/secrets/news", None),
            ("/secrets/db/edit", None),
            ("/secrets", None),
            ("/vaults/new", None),
            ("/secrets/-/new", None),
        ] {
            assert_eq!(new_location(old).as_deref(), new, "{old}");
        }
    }

    #[test]
    fn only_a_missing_fixed_name_is_sent_on() {
        let missing = AzureError::Status {
            status: 404,
            code: None,
            message: None,
        };
        let forbidden = AzureError::Status {
            status: 403,
            code: None,
            message: None,
        };
        let bare: axum::http::Uri = "/x".parse().unwrap();
        let paged: axum::http::Uri = "/x?page=2".parse().unwrap();
        let r = missing_item(Kind::Certificate, "upload", &missing, &bare).unwrap();
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(r.headers()[LOCATION], "/certificates/-/upload");
        let r = missing_item(Kind::Secret, "deleted", &missing, &paged).unwrap();
        assert_eq!(r.headers()[LOCATION], "/secrets/-/deleted?page=2");
        assert!(missing_item(Kind::Key, "upload", &missing, &bare).is_none());
        assert!(missing_item(Kind::Secret, "db", &missing, &bare).is_none());
        assert!(missing_item(Kind::Secret, "new", &forbidden, &bare).is_none());
    }
}
