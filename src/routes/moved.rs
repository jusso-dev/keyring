//! Redirects from where pages used to be.
//!
//! Two moves, both answered with a 308 so a form post keeps its method and
//! body (and still meets the form token check for the vault it was
//! rendered for):
//!
//! - Every vault page was at `/secrets/...`, with the vault kept in the
//!   session. They now sit under `/v/{vault}/`, so a link names its vault.
//!   An old address goes to the same page under the vault last used in this
//!   session ([`legacy`]). With no vault chosen yet, the person is asked to
//!   choose one.
//! - The add, upload and deleted pages were at `/secrets/new` and the like,
//!   beside `/secrets/{name}`, so an item called `new` couldn't be opened.
//!   They now sit under `/-/` (`/secrets/-/new`), which can't be an item:
//!   Keyring refuses any name that starts with a hyphen (see
//!   `vault_ctx::is_valid_object_name`). An old path that no route matches
//!   (`/v/kv/secrets/deleted/db/recover`) is sent on by the vault router's
//!   fallback. An old path that is now an item's page
//!   (`/v/kv/secrets/new`) is sent on only when Key Vault has no item of
//!   that name, so a real item called `new` opens as normal. A post to an
//!   item's page can only be one of the old add or upload forms, so it is
//!   sent on.
//!
//! So a bookmark from before both moves takes two hops, and a form from
//! before both takes two 308s.

use axum::extract::{Path, Request};
use axum::http::header::{ALLOW, LOCATION};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::vaults::is_valid_vault_name;
use crate::routes::lifecycle::Kind;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{no_vault_page, vault_path};

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
/// `path_and_query` is the path below the vault (`/secrets/new`). The query
/// string is kept.
fn new_location(path_and_query: &str) -> Option<String> {
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

/// The section an old address belonged to, for the "choose a vault" page.
fn section_for(path: &str) -> Section {
    if path.starts_with("/certificates") {
        Section::Certificates
    } else if path.starts_with("/keys") {
        Section::Keys
    } else if path.starts_with("/audit") {
        Section::Audit
    } else {
        Section::Secrets
    }
}

/// Any method on an address from before the vault was in the path. Goes to
/// the same address under the vault last used in this session, with the
/// query string kept.
pub(super) async fn legacy(session: CurrentSession, shell: Shell, req: Request) -> Response {
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_default();
    match session.0.selected_vault() {
        Some(v) if is_valid_vault_name(&v) => redirect(&vault_path(&v, pq)),
        _ => no_vault_page(shell, section_for(pq)),
    }
}

/// For the vault router's fallback: the redirect when the path below the
/// vault is an old fixed-page one. `original` is the full request address,
/// `/v/{vault}/...`.
pub(super) fn from_vault_fallback(original: &Uri) -> Option<Response> {
    let pq = original.path_and_query()?.as_str();
    let rest = pq.strip_prefix("/v/")?;
    let (vault, below) = rest.split_once('/')?;
    if !is_valid_vault_name(vault) {
        return None;
    }
    let below = format!("/{below}");
    new_location(&below).map(|to| redirect(&vault_path(vault, &to)))
}

/// For an item page that Key Vault said doesn't exist: if its name was a
/// fixed page, send the old bookmark on.
/// The query string is kept.
pub(super) fn missing_item(
    vault: &str,
    kind: Kind,
    name: &str,
    err: &AzureError,
    uri: &Uri,
) -> Option<Response> {
    if !matches!(err, AzureError::Status { status: 404, .. }) || !fixed_pages(kind).contains(&name)
    {
        return None;
    }
    let to = match uri.query() {
        Some(q) => format!("{}/-/{name}?{q}", kind.base()),
        None => format!("{}/-/{name}", kind.base()),
    };
    Some(redirect(&vault_path(vault, &to)))
}

/// A post to an item page. Only the old add and upload forms posted there,
/// so send those on; anything else is the 405 it always was. Inside the
/// vault nest, so the request path starts below `/v/{vault}`.
pub(super) async fn post_item(
    Path((vault, name)): Path<(String, String)>,
    req: Request,
) -> Response {
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_default();
    match new_location(pq) {
        Some(to) if is_valid_vault_name(&vault) && matches!(name.as_str(), "new" | "upload") => {
            redirect(&vault_path(&vault, &to))
        }
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
    fn the_vault_fallback_keeps_the_vault() {
        for (old, new) in [
            ("/v/kv-a/secrets/new", Some("/v/kv-a/secrets/-/new")),
            (
                "/v/kv-a/secrets/deleted/db/recover?x=1",
                Some("/v/kv-a/secrets/-/deleted/db/recover?x=1"),
            ),
            (
                "/v/kv-a/certificates/upload",
                Some("/v/kv-a/certificates/-/upload"),
            ),
            ("/v/kv-a/secrets/db", None),
            ("/v/bad_vault/secrets/new", None),
            ("/v/kv-a", None),
        ] {
            let uri: Uri = old.parse().unwrap();
            let got = from_vault_fallback(&uri)
                .map(|r| r.headers()[LOCATION].to_str().unwrap().to_owned());
            assert_eq!(got.as_deref(), new, "{old}");
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
        let bare: Uri = "/x".parse().unwrap();
        let paged: Uri = "/x?page=2".parse().unwrap();
        let r = missing_item("kv", Kind::Certificate, "upload", &missing, &bare).unwrap();
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(r.headers()[LOCATION], "/v/kv/certificates/-/upload");
        let r = missing_item("kv", Kind::Secret, "deleted", &missing, &paged).unwrap();
        assert_eq!(r.headers()[LOCATION], "/v/kv/secrets/-/deleted?page=2");
        assert!(missing_item("kv", Kind::Key, "upload", &missing, &bare).is_none());
        assert!(missing_item("kv", Kind::Secret, "db", &missing, &bare).is_none());
        assert!(missing_item("kv", Kind::Secret, "new", &forbidden, &bare).is_none());
    }

    #[test]
    fn sections_follow_the_old_path() {
        assert_eq!(section_for("/secrets/db"), Section::Secrets);
        assert_eq!(section_for("/certificates"), Section::Certificates);
        assert_eq!(section_for("/keys/k"), Section::Keys);
        assert_eq!(section_for("/audit.csv"), Section::Audit);
    }
}
