//! Typed confirmation for anything that deletes. The person has to type the
//! item's name, and the server checks it before doing anything, so the check
//! can't be skipped by editing the page.

use serde::Deserialize;

use crate::auth::session::Session;
use crate::routes::error::Problem;

/// Fields every confirm form posts.
#[derive(Debug, Deserialize)]
pub(crate) struct ConfirmForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub confirm_name: String,
}

/// Why a confirmation was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfirmError {
    /// The form token didn't match: an old page, or one rendered for
    /// another vault.
    StaleForm,
    NameMismatch,
}

/// Check the form token and that the typed name matches exactly. Surrounding
/// spaces are ignored; case is not, because Key Vault names are shown as-is.
pub(crate) fn verify(
    session: &Session,
    vault: &str,
    form: &ConfirmForm,
    expected: &str,
) -> Result<(), ConfirmError> {
    if !session.csrf_matches_vault(&form.csrf, vault) {
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
    pub(crate) fn mismatch(expected: &str, nothing_was: &str) -> String {
        format!("Nothing was {nothing_was}. To confirm, type {expected} exactly as shown.")
    }

    /// The page for a refused confirmation. `nothing_was` names what the
    /// form would have done, as in [`ConfirmError::mismatch`].
    pub(crate) fn problem(&self, expected: &str, nothing_was: &str) -> Problem {
        match self {
            Self::StaleForm => Problem::stale_form(),
            Self::NameMismatch => Problem::new(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "The name didn't match",
                Self::mismatch(expected, nothing_was),
            ),
        }
    }
}

/// Fields for the shared confirm template.
pub(crate) struct ConfirmView {
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
            verify(
                &s,
                &s.selected_vault().unwrap_or_default(),
                &form(&s.csrf_token(), "db-password"),
                "db-password"
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                &s,
                &s.selected_vault().unwrap_or_default(),
                &form(&s.csrf_token(), "  db-password "),
                "db-password"
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_or_missing_name() {
        let s = session();
        for typed in ["", "db-passwor", "DB-PASSWORD", "db-password2"] {
            assert_eq!(
                verify(
                    &s,
                    &s.selected_vault().unwrap_or_default(),
                    &form(&s.csrf_token(), typed),
                    "db-password"
                ),
                Err(ConfirmError::NameMismatch),
                "{typed:?}"
            );
        }
        assert_eq!(
            verify(
                &s,
                &s.selected_vault().unwrap_or_default(),
                &form(&s.csrf_token(), ""),
                ""
            ),
            Err(ConfirmError::NameMismatch)
        );
    }

    #[test]
    fn rejects_bad_token_before_checking_name() {
        let s = session();
        assert_eq!(
            verify(
                &s,
                &s.selected_vault().unwrap_or_default(),
                &form("forged", "db-password"),
                "db-password"
            ),
            Err(ConfirmError::StaleForm)
        );
    }

    #[test]
    fn form_for_another_vault_is_refused_and_named() {
        let s = session();
        s.select_vault("kv-prod".into());
        let token = s.csrf_token();
        s.select_vault("kv-dev".into());
        assert_eq!(
            verify(
                &s,
                &s.selected_vault().unwrap_or_default(),
                &form(&token, "db-password"),
                "db-password"
            ),
            Err(ConfirmError::StaleForm)
        );
    }

    #[test]
    fn mismatch_message_says_nothing_happened() {
        // Used for deletes, purges and private key downloads alike.
        let p = ConfirmError::NameMismatch.problem("db-password", "deleted");
        assert!(p.message.starts_with("Nothing was deleted."));
        let p = ConfirmError::NameMismatch.problem("db-password", "rolled back");
        assert!(p.message.starts_with("Nothing was rolled back."));
        assert!(ConfirmError::mismatch("a", "downloaded").starts_with("Nothing was downloaded."));
    }
}
