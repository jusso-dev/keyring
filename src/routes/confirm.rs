//! Typed confirmation for anything that deletes. The person has to type the
//! item's name, and the server checks it before doing anything, so the check
//! can't be skipped by editing the page.

use serde::Deserialize;

use crate::auth::session::Session;
use crate::routes::error::Problem;

/// Fields every confirm form posts.
#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub confirm_name: String,
}

/// Why a confirmation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmError {
    StaleForm,
    NameMismatch,
}

/// Check the form token and that the typed name matches exactly. Surrounding
/// spaces are ignored; case is not, because Key Vault names are shown as-is.
pub fn verify(session: &Session, form: &ConfirmForm, expected: &str) -> Result<(), ConfirmError> {
    if !session.csrf_matches(&form.csrf) {
        return Err(ConfirmError::StaleForm);
    }
    if expected.is_empty() || form.confirm_name.trim() != expected {
        return Err(ConfirmError::NameMismatch);
    }
    Ok(())
}

impl ConfirmError {
    /// The message to show when the typed name didn't match, for an action
    /// such as "deleted" or "downloaded".
    pub fn mismatch(expected: &str, nothing_was: &str) -> String {
        format!("Nothing was {nothing_was}. To confirm, type {expected} exactly as shown.")
    }

    pub fn problem(&self, expected: &str) -> Problem {
        match self {
            Self::StaleForm => Problem::stale_form(),
            Self::NameMismatch => Problem::new(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "The name didn't match",
                Self::mismatch(expected, "deleted"),
            ),
        }
    }
}

/// Fields for the shared confirm template.
pub struct ConfirmView {
    pub heading: String,
    /// One or two sentences on what will happen.
    pub warning: String,
    /// Exactly what must be typed.
    pub expected: String,
    pub action: String,
    pub button: String,
    pub cancel_url: String,
    /// A second, stronger warning (used for permanent deletes).
    pub second_warning: Option<String>,
    /// Set when the typed name didn't match.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::SessionStore;
    use crate::auth::session::tests::{tokens, user};

    fn session() -> std::sync::Arc<Session> {
        let store = SessionStore::default();
        let id = store.create(user(), tokens());
        store.get(&id).unwrap()
    }

    fn form(csrf: &str, name: &str) -> ConfirmForm {
        ConfirmForm {
            csrf: csrf.into(),
            confirm_name: name.into(),
        }
    }

    #[test]
    fn accepts_exact_name_with_valid_token() {
        let s = session();
        assert_eq!(
            verify(&s, &form(&s.csrf, "db-password"), "db-password"),
            Ok(())
        );
        assert_eq!(
            verify(&s, &form(&s.csrf, "  db-password "), "db-password"),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_or_missing_name() {
        let s = session();
        for typed in ["", "db-passwor", "DB-PASSWORD", "db-password2"] {
            assert_eq!(
                verify(&s, &form(&s.csrf, typed), "db-password"),
                Err(ConfirmError::NameMismatch),
                "{typed:?}"
            );
        }
        assert_eq!(
            verify(&s, &form(&s.csrf, ""), ""),
            Err(ConfirmError::NameMismatch)
        );
    }

    #[test]
    fn rejects_bad_token_before_checking_name() {
        let s = session();
        assert_eq!(
            verify(&s, &form("forged", "db-password"), "db-password"),
            Err(ConfirmError::StaleForm)
        );
    }

    #[test]
    fn mismatch_message_says_nothing_happened() {
        // Used for deletes, purges and private key downloads alike.
        let p = ConfirmError::NameMismatch.problem("db-password");
        assert!(p.message.starts_with("Nothing was deleted."));
        assert!(ConfirmError::mismatch("a", "downloaded").starts_with("Nothing was downloaded."));
    }
}
