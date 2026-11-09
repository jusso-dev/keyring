//! Plain-English error pages.
//!
//! Every failure a person can hit ends up as a [`Problem`]: a short heading,
//! one or two sentences on what happened, and where useful what to ask an
//! admin for. Raw Azure errors are never shown as-is.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::return_to;
use crate::azure::{AzureError, TokenError};
use crate::routes::assets::render;
use crate::routes::shell::Shell;

/// What the person was trying to do. Used to name the role they're missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    ListVaults,
    ReadSecrets,
    ManageSecrets,
    ReadCertificates,
    ManageCertificates,
    ReadKeys,
    ManageKeys,
    ReadAuditLogs,
}

impl Need {
    /// The Azure built-in role that allows this.
    pub fn role(self) -> &'static str {
        match self {
            Self::ListVaults => "Reader",
            Self::ReadSecrets => "Key Vault Secrets User",
            Self::ManageSecrets => "Key Vault Secrets Officer",
            Self::ReadCertificates => "Key Vault Certificate User",
            Self::ManageCertificates => "Key Vault Certificates Officer",
            Self::ReadKeys => "Key Vault Reader",
            Self::ManageKeys => "Key Vault Crypto Officer",
            Self::ReadAuditLogs => "Log Analytics Reader",
        }
    }

    /// Finishes the sentence "You don't have permission to ...".
    fn doing(self) -> &'static str {
        match self {
            Self::ListVaults => "see the vaults here",
            Self::ReadSecrets => "read secrets in this vault",
            Self::ManageSecrets => "change secrets in this vault",
            Self::ReadCertificates => "read certificates in this vault",
            Self::ManageCertificates => "change certificates in this vault",
            Self::ReadKeys => "see keys in this vault",
            Self::ManageKeys => "change keys in this vault",
            Self::ReadAuditLogs => "read this vault's logs",
        }
    }

    /// Where the role needs to be granted.
    fn scope(self) -> &'static str {
        match self {
            Self::ListVaults => "the subscription or resource group",
            Self::ReadAuditLogs => "the Log Analytics workspace",
            _ => "this vault",
        }
    }

    fn uses_vault_rbac(self) -> bool {
        !matches!(self, Self::ListVaults | Self::ReadAuditLogs)
    }
}

/// What the error page offers as the next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextStep {
    /// "Try again" back to this local path.
    Retry(String),
    /// "Sign in again", returning to this local path afterwards.
    SignIn(String),
    /// "Back to home".
    Home,
}

/// A failure, ready to show to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: StatusCode,
    pub heading: &'static str,
    pub message: String,
    /// What to ask an admin for, if anything.
    pub admin_hint: Option<String>,
    pub next: NextStep,
}

impl Problem {
    pub fn new(status: StatusCode, heading: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            heading,
            message: message.into(),
            admin_hint: None,
            next: NextStep::Home,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.admin_hint = Some(hint.into());
        self
    }

    pub fn with_next(mut self, next: NextStep) -> Self {
        self.next = next;
        self
    }

    /// Point "Try again" or "Sign in again" back at this path.
    pub fn returning_to(mut self, path: &str) -> Self {
        let path = return_to::sanitise(Some(path));
        self.next = match self.next {
            NextStep::SignIn(_) => NextStep::SignIn(path),
            NextStep::Retry(_) | NextStep::Home => NextStep::Retry(path),
        };
        self
    }

    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "Page not found",
            "There's nothing at this address. Check the link, or start again from the home page.",
        )
    }

    /// The form's hidden token didn't match the session.
    pub fn stale_form() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "That didn't go through",
            "The page was out of date, so nothing was changed. Go back, refresh the page and try again.",
        )
    }

    /// Map a failed Azure call. `need` says what the person was doing, so a
    /// 403 can name the missing role.
    pub fn from_azure(err: &AzureError, need: Need) -> Self {
        match err {
            AzureError::Token(t) => Self::from_token(t),
            AzureError::Status { status, code, .. } => {
                Self::from_status(*status, code.as_deref(), need)
            }
            // A vault call that can't connect is usually a vault that only
            // accepts private traffic, with Keyring outside that network.
            AzureError::Network(_) if need.uses_vault_rbac() => Self::new(
                StatusCode::BAD_GATEWAY,
                "Can't reach this vault",
                "Keyring couldn't connect to the vault. It may only accept connections from a private network, and Keyring isn't on that network.",
            )
            .with_hint("Ask your admin whether the vault has public access turned off. If so, Keyring needs to run in a network that can reach the vault's private endpoint, with private DNS for privatelink.vaultcore.azure.net. See docs/private-vaults.md.")
            .with_next(NextStep::Retry("/".into())),
            AzureError::Network(_) => Self::new(
                StatusCode::BAD_GATEWAY,
                "Can't reach Azure",
                "Keyring couldn't get an answer from Azure. Wait a moment and try again.",
            )
            .with_next(NextStep::Retry("/".into())),
            AzureError::Unreadable => Self::new(
                StatusCode::BAD_GATEWAY,
                "Azure sent an answer Keyring didn't understand",
                "Try again. If it keeps happening, let whoever runs Keyring know.",
            )
            .with_next(NextStep::Retry("/".into())),
        }
    }

    pub fn from_token(err: &TokenError) -> Self {
        match err {
            TokenError::SignInAgain => Self::new(
                StatusCode::UNAUTHORIZED,
                "Please sign in again",
                "Your organisation wants you to sign in again before carrying on, for example to check a second factor.",
            )
            .with_next(NextStep::SignIn("/".into())),
            TokenError::ConsentNeeded => Self::new(
                StatusCode::FORBIDDEN,
                "Your organisation needs to approve Keyring",
                "Keyring isn't allowed to reach Azure for you yet.",
            )
            .with_hint("Ask your admin to grant admin consent for the Keyring app registration in Entra ID."),
            TokenError::Refused { code } => Self::new(
                StatusCode::BAD_GATEWAY,
                "Microsoft sign-in said no",
                "Entra ID wouldn't let Keyring act for you.",
            )
            .with_hint(format!(
                "Ask your admin to check the Keyring app registration. Entra ID gave the code {code}."
            )),
            TokenError::Unreachable(_) => Self::new(
                StatusCode::BAD_GATEWAY,
                "Can't reach Microsoft sign-in",
                "Keyring couldn't reach Entra ID. Wait a moment and try again.",
            )
            .with_next(NextStep::Retry("/".into())),
        }
    }

    fn from_status(status: u16, code: Option<&str>, need: Need) -> Self {
        let code = code.unwrap_or_default();
        match status {
            401 => Self::from_token(&TokenError::SignInAgain),
            403 if code.starts_with("ForbiddenBy") => Self::new(
                StatusCode::FORBIDDEN,
                "This vault is blocked from here",
                "The vault only accepts connections from certain networks, and Keyring isn't on one of them.",
            )
            .with_hint("Ask your admin to allow Keyring through the vault's firewall, or to set up a private endpoint."),
            403 => {
                let mut hint = format!(
                    "Ask your admin for the {} role on {}.",
                    need.role(),
                    need.scope()
                );
                if need.uses_vault_rbac() {
                    hint.push_str(
                        " If the vault still uses access policies, ask for an access policy that allows this instead.",
                    );
                }
                Self::new(
                    StatusCode::FORBIDDEN,
                    "You don't have access",
                    format!("You don't have permission to {}.", need.doing()),
                )
                .with_hint(hint)
            }
            404 => Self::new(
                StatusCode::NOT_FOUND,
                "Not found",
                "Keyring couldn't find that. It may have been deleted or renamed.",
            ),
            409 => Self::new(
                StatusCode::CONFLICT,
                "That name is taken",
                "Something with this name already exists, or was deleted recently and can still be recovered. Recover the deleted one, or pick another name.",
            ),
            429 => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Azure asked Keyring to slow down",
                "Too many requests went to this vault at once. Wait a few seconds and try again.",
            )
            .with_next(NextStep::Retry("/".into())),
            500..=599 => Self::new(
                StatusCode::BAD_GATEWAY,
                "Azure had a problem",
                "Azure couldn't finish the request. Wait a moment and try again.",
            )
            .with_next(NextStep::Retry("/".into())),
            _ => Self::new(
                StatusCode::BAD_GATEWAY,
                "That didn't work",
                "Azure turned the request down.",
            )
            .with_hint(format!("Azure gave status {status} {code}.").trim_end().replace(" .", ".")),
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    shell: Shell,
    problem: &'a Problem,
    next_url: String,
    next_label: &'static str,
}

/// A [`Problem`] with the page chrome to show it in.
pub struct PageError {
    pub shell: Shell,
    pub problem: Problem,
}

impl PageError {
    pub fn new(shell: Shell, problem: Problem) -> Self {
        Self { shell, problem }
    }
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let (next_url, next_label) = match &self.problem.next {
            NextStep::Retry(p) => (p.clone(), "Try again"),
            NextStep::SignIn(p) => (
                format!("/auth/sign-in?return_to={}", return_to::encode(p)),
                "Sign in again",
            ),
            NextStep::Home => ("/".to_owned(), "Back to home"),
        };
        let page = ErrorPage {
            shell: self.shell,
            problem: &self.problem,
            next_url,
            next_label,
        };
        (self.problem.status, render(&page)).into_response()
    }
}

/// A response that ends a handler early, boxed so `Result<_, Halt>` stays
/// small. Lets handlers use `?` on checks that produce a page.
pub struct Halt(Box<Response>);

impl IntoResponse for Halt {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl From<PageError> for Halt {
    fn from(e: PageError) -> Self {
        Self(Box::new(e.into_response()))
    }
}

impl From<Response> for Halt {
    fn from(r: Response) -> Self {
        Self(Box::new(r))
    }
}

/// What most page handlers return.
pub type PageResult = Result<Response, Halt>;

#[cfg(test)]
mod tests {
    use super::*;

    fn status(code: u16, azure_code: &str) -> AzureError {
        AzureError::Status {
            status: code,
            code: Some(azure_code.into()),
            message: Some("raw Azure text".into()),
        }
    }

    #[test]
    fn forbidden_names_the_missing_role() {
        let p = Problem::from_azure(&status(403, "Forbidden"), Need::ManageSecrets);
        assert_eq!(p.status, StatusCode::FORBIDDEN);
        assert_eq!(
            p.message,
            "You don't have permission to change secrets in this vault."
        );
        let hint = p.admin_hint.unwrap();
        assert!(hint.contains("Key Vault Secrets Officer role on this vault"));
        assert!(hint.contains("access policies"));
    }

    #[test]
    fn forbidden_on_vault_list_points_at_subscription() {
        let p = Problem::from_azure(&status(403, "AuthorizationFailed"), Need::ListVaults);
        let hint = p.admin_hint.unwrap();
        assert!(hint.contains("Reader role on the subscription or resource group"));
        assert!(!hint.contains("access policies"));
    }

    #[test]
    fn firewall_blocks_get_their_own_message() {
        let p = Problem::from_azure(&status(403, "ForbiddenByFirewall"), Need::ReadSecrets);
        assert_eq!(p.heading, "This vault is blocked from here");
    }

    #[test]
    fn maps_each_status() {
        let cases = [
            (401, StatusCode::UNAUTHORIZED),
            (404, StatusCode::NOT_FOUND),
            (409, StatusCode::CONFLICT),
            (429, StatusCode::TOO_MANY_REQUESTS),
            (503, StatusCode::BAD_GATEWAY),
            (400, StatusCode::BAD_GATEWAY),
        ];
        for (code, expected) in cases {
            let p = Problem::from_azure(&status(code, "X"), Need::ReadSecrets);
            assert_eq!(p.status, expected, "{code}");
            // Azure's own message never reaches the page.
            assert!(!p.message.contains("raw Azure text"));
            assert!(!p.admin_hint.unwrap_or_default().contains("raw Azure text"));
        }
        let p = Problem::from_azure(&status(409, "Conflict"), Need::ManageSecrets);
        assert!(p.message.contains("Recover the deleted one"));
    }

    #[test]
    fn network_and_token_errors() {
        let p = Problem::from_azure(&AzureError::Network("x".into()), Need::ReadSecrets);
        assert_eq!(p.heading, "Can't reach this vault");
        assert!(
            p.admin_hint
                .unwrap()
                .contains("privatelink.vaultcore.azure.net")
        );
        let p = Problem::from_azure(&AzureError::Network("x".into()), Need::ListVaults);
        assert_eq!(p.heading, "Can't reach Azure");
        let p = Problem::from_azure(
            &AzureError::Token(TokenError::SignInAgain),
            Need::ReadSecrets,
        );
        assert!(matches!(p.next, NextStep::SignIn(_)));
        let p = Problem::from_token(&TokenError::ConsentNeeded);
        assert!(p.admin_hint.unwrap().contains("admin consent"));
    }

    #[test]
    fn returning_to_keeps_kind_and_blocks_open_redirects() {
        let p = Problem::from_token(&TokenError::SignInAgain).returning_to("/secrets?q=a");
        assert_eq!(p.next, NextStep::SignIn("/secrets?q=a".into()));
        let p = Problem::not_found().returning_to("https://evil.example");
        assert_eq!(p.next, NextStep::Retry("/".into()));
    }

    #[test]
    fn copy_has_no_em_dashes() {
        let all = [
            Problem::not_found(),
            Problem::stale_form(),
            Problem::from_token(&TokenError::SignInAgain),
            Problem::from_token(&TokenError::ConsentNeeded),
            Problem::from_token(&TokenError::Refused { code: "x".into() }),
            Problem::from_token(&TokenError::Unreachable("x".into())),
        ];
        for p in all {
            assert!(!p.message.contains('\u{2014}'));
            assert!(!p.heading.contains('\u{2014}'));
        }
    }
}
