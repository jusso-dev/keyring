//! Security headers on every response.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;

/// Build the Content-Security-Policy. Scripts and styles only from this
/// site, no inline code, no framing. Forms may post here, and sign-out may
/// redirect on to Entra ID (browsers apply `form-action` to redirects).
pub fn csp(authority_host: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
         connect-src 'self'; form-action 'self' {authority_host}; frame-ancestors 'none'; \
         base-uri 'none'"
    )
}

/// Longest any request may take, including Azure calls. The expiry
/// dashboard is the slowest page; it limits each vault to 20 seconds and
/// reads them in parallel.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

pub async fn layer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut res = match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(res) => res,
        Err(_) => {
            tracing::warn!("request timed out");
            (
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "That took too long, so Keyring stopped. Try again, or narrow what you asked for.",
            )
                .into_response()
        }
    };
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&csp(&state.config.authority_host)) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    if state.config.is_https() {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    // Pages can show item names and, later, secret values. Don't cache any
    // HTML; static files set their own cache header.
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_blocks_inline_and_framing() {
        let c = csp("https://login.microsoftonline.com");
        assert!(c.contains("script-src 'self';"));
        assert!(c.contains("style-src 'self';"));
        assert!(!c.contains("unsafe-inline"));
        assert!(!c.contains("unsafe-eval"));
        assert!(c.contains("frame-ancestors 'none'"));
        assert!(c.contains("form-action 'self' https://login.microsoftonline.com;"));
    }
}
