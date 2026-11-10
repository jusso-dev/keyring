//! A string wrapper that never prints its contents.

use std::fmt;

use zeroize::Zeroize;

/// Holds a sensitive value such as a client secret or token.
///
/// `Debug` and `Display` print `[redacted]`, so the value can't end up in
/// logs or error messages by accident. Read it with [`Secret::expose`].
///
/// The memory is overwritten with zeros when the value is dropped, so a
/// token or uploaded private key doesn't linger in freed memory.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the raw value. Only call this where the value is sent on to
    /// the place that needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let s = Secret::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(!format!("{s}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }
}
