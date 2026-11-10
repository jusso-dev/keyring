//! One-off messages shown on the next page, such as "Secret saved".
//!
//! The message rides in a short-lived encrypted cookie set on a redirect, is
//! read by the next request and cleared in its response.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::SET_COOKIE;
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::auth::cookies;

pub const FLASH_COOKIE: &str = "keyring_flash";
const MAX_LEN: usize = 300;
/// How long a flash message lives, in the cookie and on the server.
const FLASH_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKind {
    Success,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flash {
    pub kind: FlashKind,
    pub message: String,
}

impl Flash {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Success,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Error,
            message: message.into(),
        }
    }

    pub fn is_error(&self) -> bool {
        self.kind == FlashKind::Error
    }

    fn encode(&self) -> Vec<u8> {
        let tag = match self.kind {
            FlashKind::Success => 's',
            FlashKind::Error => 'e',
        };
        let mut msg: String = self.message.chars().take(MAX_LEN).collect();
        msg.insert(0, tag);
        msg.into_bytes()
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(raw).ok()?;
        let mut chars = s.chars();
        let kind = match chars.next()? {
            's' => FlashKind::Success,
            'e' => FlashKind::Error,
            _ => return None,
        };
        Some(Self {
            kind,
            message: chars.as_str().to_owned(),
        })
    }
}

/// Attach a flash message to a response (normally a redirect).
pub fn set(state: &AppState, res: &mut Response, flash: &Flash) {
    let name = state.cookies.name(FLASH_COOKIE);
    let sealed = state.flash_sealer.seal(&name, &flash.encode());
    if let Ok(v) = HeaderValue::from_str(&state.cookies.set(
        &name,
        &sealed,
        Some(FLASH_MAX_AGE.as_secs()),
    )) {
        res.headers_mut().append(SET_COOKIE, v);
    }
}

/// Middleware: read any flash cookie into the request and clear it.
pub async fn layer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let name = state.cookies.name(FLASH_COOKIE);
    let present = cookies::get(req.headers(), &name).map(str::to_owned);
    if let Some(flash) = present
        .as_deref()
        .and_then(|v| state.flash_sealer.open_within(&name, v, FLASH_MAX_AGE))
        .and_then(|raw| Flash::decode(&raw))
    {
        req.extensions_mut().insert(flash);
    }
    let mut res = next.run(req).await;
    // Clear it unless the handler set a new one.
    let set_new = res
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.starts_with(&format!("{name}="))));
    if present.is_some()
        && !set_new
        && let Ok(v) = HeaderValue::from_str(&state.cookies.clear(&name))
    {
        res.headers_mut().append(SET_COOKIE, v);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_truncate() {
        let f = Flash::success("Secret saved");
        assert_eq!(Flash::decode(&f.encode()), Some(f));
        let long = Flash::error("x".repeat(1000));
        assert_eq!(
            Flash::decode(&long.encode()).unwrap().message.len(),
            MAX_LEN
        );
        assert_eq!(Flash::decode(b"zbad"), None);
        assert_eq!(Flash::decode(b""), None);
    }
}
