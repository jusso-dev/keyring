//! Data every page layout needs: who's signed in, their form token, which
//! section is open, the chosen vault and any one-off message.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::CurrentSession;
use crate::auth::session::IDLE_TIMEOUT;
use crate::routes::flash::Flash;

/// The sections in the side navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Home,
    Vaults,
    Secrets,
    Certificates,
    Keys,
    Expiry,
    Generator,
    Audit,
}

impl Section {
    pub const NAV: [Section; 7] = [
        Section::Vaults,
        Section::Secrets,
        Section::Certificates,
        Section::Keys,
        Section::Expiry,
        Section::Generator,
        Section::Audit,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Vaults => "Vaults",
            Self::Secrets => "Secrets",
            Self::Certificates => "Certificates",
            Self::Keys => "Keys",
            Self::Expiry => "Expiry",
            Self::Generator => "Generator",
            Self::Audit => "Audit",
        }
    }

    /// True for the sections whose pages live under `/v/{vault}`.
    pub fn is_vault_scoped(self) -> bool {
        matches!(
            self,
            Self::Secrets | Self::Certificates | Self::Keys | Self::Audit
        )
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Home => "/",
            Self::Vaults => "/vaults",
            Self::Secrets => "/secrets",
            Self::Certificates => "/certificates",
            Self::Keys => "/keys",
            Self::Expiry => "/expiry",
            Self::Generator => "/generator",
            Self::Audit => "/audit",
        }
    }
}

pub struct ShellUser {
    pub name: String,
    /// Form token, bound to the vault chosen when the page was rendered.
    pub csrf: String,
}

/// The vault picked in the header, if any.
pub struct ShellVault {
    pub name: String,
}

#[derive(Default)]
pub struct Shell {
    pub user: Option<ShellUser>,
    pub section: Option<Section>,
    pub vault: Option<ShellVault>,
    pub flash: Option<Flash>,
}

impl Shell {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn for_session(session: &CurrentSession) -> Self {
        Self {
            user: Some(ShellUser {
                name: session.0.user.name.clone(),
                csrf: session.0.csrf_token(),
            }),
            vault: session.0.selected_vault().map(|name| ShellVault { name }),
            ..Self::default()
        }
    }

    pub fn at(mut self, section: Section) -> Self {
        self.section = Some(section);
        self
    }

    /// Show `vault` (the one in the address) and render the form token for
    /// it, not for the vault last chosen in another tab.
    pub fn for_vault(mut self, vault: &str, session: &CurrentSession) -> Self {
        if let Some(user) = self.user.as_mut() {
            user.csrf = session.0.csrf_for(Some(vault));
        }
        self.vault = Some(ShellVault {
            name: vault.to_owned(),
        });
        self
    }

    /// `/v/<vault>` for links to this vault's pages, or empty when no vault
    /// is chosen. The name is checked to be letters, digits and hyphens
    /// before it gets here, so it needs no URL encoding.
    pub fn vault_prefix(&self) -> String {
        self.vault
            .as_ref()
            .map(|v| format!("/v/{}", v.name))
            .unwrap_or_default()
    }

    /// Where a nav link goes. The vault-scoped sections go to the vault
    /// last used, or to their bare address (which asks for a vault) when
    /// there isn't one.
    pub fn nav_path(&self, section: &Section) -> String {
        let bare = section.path();
        match (&self.vault, section.is_vault_scoped()) {
            (Some(v), true) => format!("/v/{}{bare}", v.name),
            _ => bare.to_owned(),
        }
    }

    /// True when `s` is the open section, for `aria-current`.
    pub fn is_current(&self, s: &Section) -> bool {
        self.section == Some(*s)
    }

    /// The form token every form posts back. It is bound to the vault
    /// chosen when this page was rendered, so a form left open in one tab
    /// is refused after a vault switch in another.
    pub fn csrf(&self) -> &str {
        self.user
            .as_ref()
            .map(|u| u.csrf.as_str())
            .unwrap_or_default()
    }

    /// Seconds without a request before sign-out, for the idle warning
    /// script. Empty when signed out.
    pub fn idle_seconds(&self) -> String {
        if self.user.is_some() {
            IDLE_TIMEOUT.as_secs().to_string()
        } else {
            String::new()
        }
    }
}

/// Builds the shell from the request: the session if signed in, plus any
/// flash message.
impl<S: Send + Sync> FromRequestParts<S> for Shell {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let mut shell = match parts.extensions.get::<CurrentSession>() {
            Some(s) => Shell::for_session(s),
            None => Shell::anonymous(),
        };
        shell.flash = parts.extensions.get::<Flash>().cloned();
        Ok(shell)
    }
}
