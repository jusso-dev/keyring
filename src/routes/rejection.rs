//! Turn extractor rejections into the normal error page.
//!
//! Axum answers a form or query string it can't read, or a body over the
//! size limit, with a short plain-text response. This swaps those for the
//! styled page. The rejection's own text is dropped, because it can quote
//! the query string or form field names.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::CurrentSession;
use crate::routes::error::{PageError, Problem};
use crate::routes::shell::Shell;

pub(super) async fn layer(req: Request, next: Next) -> Response {
    let mut shell = req
        .extensions()
        .get::<CurrentSession>()
        .map(Shell::for_session)
        .unwrap_or_default();
    let res = next.run(req).await;
    if !is_rejection(&res) {
        return res;
    }
    shell.flash = None;
    PageError::new(shell, problem_for(res.status())).into_response()
}

/// Pages are HTML and downloads have their own types, so a plain-text
/// client error can only be one of Axum's rejections.
fn is_rejection(res: &Response) -> bool {
    res.status().is_client_error()
        && res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/plain"))
}

fn problem_for(status: StatusCode) -> Problem {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        Problem::new(
            status,
            "That was too much to send",
            "The form was larger than Keyring accepts, so nothing was saved. Secret values can be up to 25 KB, and certificate files up to 256 KB. Go back and try something smaller.",
        )
    } else {
        Problem::new(
            status,
            "Keyring couldn't read that",
            "Part of the address or the form wasn't in the shape Keyring expects, so nothing was done. Go back and try again, or start again from the home page.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_text_client_errors_are_rejections() {
        let res = |status: StatusCode, ct: &'static str| {
            let mut r = (status, "x").into_response();
            r.headers_mut()
                .insert(CONTENT_TYPE, axum::http::HeaderValue::from_static(ct));
            r
        };
        assert!(is_rejection(&res(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8"
        )));
        assert!(is_rejection(&res(
            StatusCode::PAYLOAD_TOO_LARGE,
            "text/plain"
        )));
        assert!(!is_rejection(&res(
            StatusCode::UNPROCESSABLE_ENTITY,
            "text/html; charset=utf-8"
        )));
        assert!(!is_rejection(&res(StatusCode::OK, "text/plain")));
        assert!(!is_rejection(&res(StatusCode::BAD_GATEWAY, "text/plain")));
    }
}
