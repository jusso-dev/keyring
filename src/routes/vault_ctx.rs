//! Helpers shared by the secrets, certificates and keys pages: the chosen
//! vault, name checks and turning Azure errors into pages.

use askama::Template;
use axum::response::IntoResponse;

use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::vaults::is_valid_vault_name;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, Problem};
use crate::routes::shell::{Section, Shell};

#[derive(Template)]
#[template(path = "no_vault.html")]
struct NoVaultPage {
    shell: Shell,
    title: &'static str,
    noun: &'static str,
}

/// The chosen vault for `section`, or a "choose a vault first" page.
pub fn current_vault(
    session: &CurrentSession,
    shell: Shell,
    section: Section,
) -> Result<(String, Shell), Halt> {
    match session.0.selected_vault() {
        Some(v) if is_valid_vault_name(&v) => Ok((v, shell.at(section))),
        _ => {
            let noun = match section {
                Section::Certificates => "Certificates",
                Section::Keys => "Keys",
                _ => "Secrets",
            };
            Err(render(&NoVaultPage {
                shell: shell.at(section),
                title: section.label(),
                noun,
            })
            .into_response()
            .into())
        }
    }
}

/// Turn a failed Azure call into an error page that offers to retry `path`.
pub fn azure_problem(shell: Shell, err: &AzureError, need: Need, path: &str) -> Halt {
    PageError::new(shell, Problem::from_azure(err, need).returning_to(path)).into()
}

/// Key Vault object names (secrets, certificates, keys): 1 to 127 letters,
/// digits and hyphens.
pub fn is_valid_object_name(name: &str) -> bool {
    (1..=127).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Validate a name from the URL. Anything that couldn't be a Key Vault
/// name is "not found", so nothing odd reaches a request URL.
pub fn checked_name(name: &str, shell: Shell) -> Result<(String, Shell), Halt> {
    if is_valid_object_name(name) {
        Ok((name.to_owned(), shell))
    } else {
        Err(PageError::new(shell, Problem::not_found()).into())
    }
}

/// Check the form token: this session's, and rendered for the vault chosen
/// now. A form from another vault gets a page saying so.
pub fn check_csrf(session: &CurrentSession, presented: &str, shell: Shell) -> Result<Shell, Halt> {
    if session.0.csrf_matches(presented) {
        Ok(shell)
    } else {
        Err(PageError::new(shell, stale_form_for(&session.0, presented)).into())
    }
}

/// The "stale form" problem for a refused token, naming the vault the form
/// was for when that is why it was refused.
pub fn stale_form_for(session: &crate::auth::session::Session, presented: &str) -> Problem {
    match session.csrf_other_vault(presented) {
        Some(vault) => Problem::vault_changed(&vault),
        None => Problem::stale_form(),
    }
}
