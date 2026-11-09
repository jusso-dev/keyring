//! Minimal cookie reading and writing. Small enough that a cookie crate isn't
//! worth the extra dependency.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

/// Find a cookie value by name in the request's `Cookie` headers.
pub fn get<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// Attributes shared by every cookie Keyring sets.
#[derive(Debug, Clone, Copy)]
pub struct CookieOptions {
    pub secure: bool,
}

impl CookieOptions {
    /// `Set-Cookie` value for an http-only, `SameSite=Lax` cookie on `/`.
    /// `max_age` of `None` makes a browser-session cookie.
    pub fn set(&self, name: &str, value: &str, max_age: Option<u64>) -> String {
        let mut out = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
        if self.secure {
            out.push_str("; Secure");
        }
        if let Some(secs) = max_age {
            out.push_str(&format!("; Max-Age={secs}"));
        }
        out
    }

    /// `Set-Cookie` value that removes a cookie.
    pub fn clear(&self, name: &str) -> String {
        self.set(name, "", Some(0))
    }

    /// Use the `__Host-` prefix over HTTPS, so the browser refuses the cookie
    /// unless it is `Secure`, host-only and on `/`.
    pub fn name(&self, base: &str) -> String {
        if self.secure {
            format!("__Host-{base}")
        } else {
            base.to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn reads_cookie_by_name() {
        let mut h = HeaderMap::new();
        h.append(COOKIE, HeaderValue::from_static("a=1; keyring_session=abc"));
        h.append(COOKIE, HeaderValue::from_static("b=2"));
        assert_eq!(get(&h, "keyring_session"), Some("abc"));
        assert_eq!(get(&h, "b"), Some("2"));
        assert_eq!(get(&h, "keyring"), None);
    }

    #[test]
    fn builds_secure_cookies() {
        let https = CookieOptions { secure: true };
        assert_eq!(https.name("keyring_session"), "__Host-keyring_session");
        let c = https.set("__Host-x", "v", Some(60));
        assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age=60") && c.contains("Path=/"));
        let local = CookieOptions { secure: false };
        assert!(!local.set("x", "v", None).contains("Secure"));
        assert!(local.clear("x").contains("Max-Age=0"));
    }
}
