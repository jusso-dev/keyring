//! Form pieces shared by the secrets, certificates and keys pages: the
//! posted bodies that carry only a token, field errors, and name checks.

use serde::Deserialize;

use crate::routes::lifecycle::Kind;
use crate::routes::vault_ctx::is_valid_object_name;

/// A form that posts only its token, such as recover, rotate or cancel.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf: String,
}

/// The enable and disable buttons.
#[derive(Deserialize)]
pub struct ToggleForm {
    #[serde(default)]
    pub csrf: String,
    /// `on` or `off`.
    #[serde(default)]
    pub state: String,
}

impl ToggleForm {
    /// `Some(true)` for `on`, `Some(false)` for `off`, `None` for anything
    /// else.
    pub fn enable(&self) -> Option<bool> {
        match self.state.as_str() {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        }
    }
}

/// One problem with one field, in words for the person filling it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

/// The problems with a form, in the order they were found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldErrors(Vec<FieldError>);

impl FieldErrors {
    pub fn new() -> Self {
        Self::default()
    }

    /// A list of one.
    pub fn one(field: &'static str, message: impl Into<String>) -> Self {
        let mut e = Self::new();
        e.push(field, message);
        e
    }

    pub fn push(&mut self, field: &'static str, message: impl Into<String>) {
        self.0.push(FieldError {
            field,
            message: message.into(),
        });
    }

    /// The first message for `field`, if there is one.
    pub fn error_for(&self, field: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }

    pub fn retain(&mut self, keep: impl FnMut(&FieldError) -> bool) {
        self.0.retain(keep);
    }
}

impl std::ops::Deref for FieldErrors {
    type Target = [FieldError];

    fn deref(&self) -> &[FieldError] {
        &self.0
    }
}

impl<'a> IntoIterator for &'a FieldErrors {
    type Item = &'a FieldError;
    type IntoIter = std::slice::Iter<'a, FieldError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Explain what's wrong with a new item's name, or `None` if it's fine.
pub fn name_problem(kind: Kind, name: &str) -> Option<String> {
    if name.is_empty() {
        return Some(format!("Give the {} a name.", kind.noun()));
    }
    if name.len() > 127 {
        return Some(format!(
            "Names can be up to 127 characters. This one is {}.",
            name.len()
        ));
    }
    if name.starts_with('-') {
        return Some("Names can't start with a hyphen. Start with a letter.".into());
    }
    if !is_valid_object_name(name) {
        let shown: Vec<String> = name
            .chars()
            .filter(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
            .take(5)
            .map(|c| {
                if c == ' ' {
                    "spaces".into()
                } else {
                    format!("\"{c}\"")
                }
            })
            .collect();
        return Some(format!(
            "Names can only use letters, numbers and hyphens. Remove {}.",
            shown.join(", ")
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules_explained() {
        assert_eq!(name_problem(Kind::Secret, "ok-name-1"), None);
        assert_eq!(
            name_problem(Kind::Secret, "").unwrap(),
            "Give the secret a name."
        );
        assert_eq!(
            name_problem(Kind::Certificate, "").unwrap(),
            "Give the certificate a name."
        );
        assert_eq!(name_problem(Kind::Key, "").unwrap(), "Give the key a name.");
        let bad = name_problem(Kind::Secret, "db_password").unwrap();
        assert!(bad.contains("\"_\""), "{bad}");
        assert!(
            name_problem(Kind::Key, "my secret")
                .unwrap()
                .contains("spaces")
        );
        assert!(
            name_problem(Kind::Secret, "-new")
                .unwrap()
                .contains("start with a hyphen")
        );
        assert!(
            name_problem(Kind::Key, &"a".repeat(128))
                .unwrap()
                .contains("127")
        );
    }

    #[test]
    fn field_errors() {
        let mut e = FieldErrors::new();
        assert!(e.is_empty());
        e.push("name", "first");
        e.push("name", "second");
        e.push("tags", "bad tags");
        assert_eq!(e.len(), 3);
        assert_eq!(e.error_for("name"), Some("first"));
        assert_eq!(e.error_for("value"), None);
        e.retain(|f| f.field != "name");
        assert_eq!(e.iter().map(|f| f.field).collect::<Vec<_>>(), ["tags"]);
    }

    #[test]
    fn toggle_states() {
        let t = |s: &str| ToggleForm {
            csrf: String::new(),
            state: s.into(),
        };
        assert_eq!(t("on").enable(), Some(true));
        assert_eq!(t("off").enable(), Some(false));
        assert_eq!(t("").enable(), None);
        assert_eq!(t("ON").enable(), None);
    }
}
