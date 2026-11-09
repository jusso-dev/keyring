//! Where to send someone after they sign in. Only paths on this site are
//! allowed, so a crafted link can't bounce a signed-in user somewhere else.

const MAX_LEN: usize = 2048;

/// Return `raw` if it's a safe local path, otherwise `/`.
pub fn sanitise(raw: Option<&str>) -> String {
    match raw {
        Some(p) if is_safe(p) => p.to_owned(),
        _ => "/".to_owned(),
    }
}

fn is_safe(p: &str) -> bool {
    p.len() <= MAX_LEN
        && p.starts_with('/')
        && !p.starts_with("//")
        && !p.contains('\\')
        && !p.chars().any(char::is_control)
        && !p.starts_with("/auth/")
}

/// Percent-encode a value for a query string.
pub fn encode(v: &str) -> String {
    openidconnect::url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_local_paths() {
        assert_eq!(sanitise(Some("/vaults?q=prod")), "/vaults?q=prod");
        assert_eq!(sanitise(Some("/")), "/");
    }

    #[test]
    fn blocks_open_redirects() {
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "\\\\evil.example",
            "evil",
            "/auth/callback",
            "/ok\r\nSet-Cookie: x",
            "",
        ] {
            assert_eq!(sanitise(Some(bad)), "/", "{bad:?} should be rejected");
        }
        assert_eq!(sanitise(None), "/");
        assert_eq!(sanitise(Some(&format!("/{}", "a".repeat(MAX_LEN)))), "/");
    }
}
