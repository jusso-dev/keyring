//! Second line of defence against cross-site form posts.
//!
//! Every form also carries a per-session token checked by its handler.
//! This middleware adds a check that doesn't depend on each handler: any
//! request that can change something (anything but GET, HEAD and OPTIONS)
//! must come from this site, judged by `Sec-Fetch-Site` when the browser
//! sends it, then `Origin`, then `Referer`. Requests with none of them are
//! refused, since every browser sends at least one on a form post.

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;

/// `scheme://host[:port]` of a URL, lower-cased.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    ))
}

/// True when the request came from `expected`, judged by the browser's
/// `Sec-Fetch-Site`, then `Origin`, then `Referer`.
pub fn same_origin(headers: &axum::http::HeaderMap, expected: &str) -> bool {
    let expected = origin_of(expected);
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    // Modern browsers say outright. `same-origin` is trusted; anything
    // else (`same-site`, `cross-site`, `none`) is refused.
    if let Some(site) = get("sec-fetch-site") {
        return site == "same-origin";
    }
    match (get(header::ORIGIN.as_str()), get(header::REFERER.as_str())) {
        // Some privacy settings send the literal "null"; treat as missing.
        (Some(o), _) if o != "null" => origin_of(o) == expected,
        (_, Some(r)) => origin_of(r) == expected,
        _ => false,
    }
}

pub async fn layer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if safe || same_origin(req.headers(), &state.config.base_url) {
        return next.run(req).await;
    }
    tracing::warn!(method = %req.method(), path = %req.uri().path(), "cross-site request refused");
    (
        StatusCode::FORBIDDEN,
        crate::routes::assets::plain_page(
            "That request was refused",
            "This request didn't come from Keyring, so it was refused. Go back to Keyring and try again.",
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    fn h(origin: Option<&'static str>, referer: Option<&'static str>) -> HeaderMap {
        let mut m = HeaderMap::new();
        if let Some(o) = origin {
            m.insert(header::ORIGIN, HeaderValue::from_static(o));
        }
        if let Some(r) = referer {
            m.insert(header::REFERER, HeaderValue::from_static(r));
        }
        m
    }

    #[test]
    fn origin_rules() {
        let base = "https://keyring.example.com";
        assert!(same_origin(
            &h(Some("https://keyring.example.com"), None),
            base
        ));
        assert!(same_origin(
            &h(Some("HTTPS://Keyring.Example.com"), None),
            base
        ));
        assert!(same_origin(
            &h(None, Some("https://keyring.example.com/secrets?q=1")),
            base
        ));
        assert!(same_origin(
            &h(Some("null"), Some("https://keyring.example.com/x")),
            base
        ));
        assert!(!same_origin(&h(Some("https://evil.example"), None), base));
        assert!(!same_origin(
            &h(Some("https://keyring.example.com.evil.example"), None),
            base
        ));
        assert!(!same_origin(
            &h(Some("http://keyring.example.com"), None),
            base
        ));
        assert!(!same_origin(
            &h(Some("https://keyring.example.com:8443"), None),
            base
        ));
        assert!(!same_origin(
            &h(
                None,
                Some("https://evil.example/https://keyring.example.com")
            ),
            base
        ));
        assert!(!same_origin(&h(None, None), base));
        assert!(!same_origin(&h(Some("null"), None), base));
        assert!(same_origin(
            &h(Some("http://localhost:3000"), None),
            "http://localhost:3000"
        ));
    }

    #[test]
    fn sec_fetch_site_wins() {
        let base = "https://keyring.example.com";
        let mut m = h(Some("null"), None);
        m.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(
            same_origin(&m, base),
            "what a browser sends under a strict referrer policy"
        );
        let mut m = h(Some("https://keyring.example.com"), None);
        m.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!same_origin(&m, base));
        let mut m = HeaderMap::new();
        m.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
        assert!(!same_origin(&m, base), "a sibling subdomain isn't us");
    }
}
