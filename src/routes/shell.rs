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
    Environments,
    Secrets,
    Certificates,
    Keys,
    Expiry,
    Health,
    Defender,
    Generator,
    Audit,
    Access,
    MyAccess,
    Reports,
}

impl Section {
    pub const NAV: [Section; 13] = [
        Section::Vaults,
        Section::Environments,
        Section::Secrets,
        Section::Certificates,
        Section::Keys,
        Section::Expiry,
        Section::Health,
        Section::Defender,
        Section::Reports,
        Section::Generator,
        Section::Audit,
        Section::Access,
        Section::MyAccess,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Vaults => "Vaults",
            Self::Environments => "Environments",
            Self::Secrets => "Secrets",
            Self::Certificates => "Certificates",
            Self::Keys => "Keys",
            Self::Expiry => "Expiry",
            Self::Health => "Vault health",
            Self::Defender => "Defender alerts",
            Self::Reports => "Executive reports",
            Self::Generator => "Generator",
            Self::Audit => "Audit",
            Self::Access => "Access",
            Self::MyAccess => "My access",
        }
    }

    /// True for the sections whose pages live under `/v/{vault}`.
    pub fn is_vault_scoped(self) -> bool {
        matches!(
            self,
            Self::Secrets
                | Self::Certificates
                | Self::Keys
                | Self::Audit
                | Self::Access
                | Self::MyAccess
        )
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Home => "/",
            Self::Vaults => "/vaults",
            Self::Environments => "/environments",
            Self::Secrets => "/secrets",
            Self::Certificates => "/certificates",
            Self::Keys => "/keys",
            Self::Expiry => "/expiry",
            Self::Health => "/vault-health",
            Self::Defender => "/defender",
            Self::Reports => "/reports/executive",
            Self::Generator => "/generator",
            Self::Audit => "/audit",
            Self::Access => "/access",
            Self::MyAccess => "/my-access",
        }
    }

    /// Icon name in `templates/_ui.html` for navigation and home cards.
    pub fn icon_name(self) -> &'static str {
        match self {
            Self::Home | Self::Vaults => "vaults",
            Self::Environments => "environments",
            Self::Secrets => "secrets",
            Self::Certificates => "certificates",
            Self::Keys => "keys",
            Self::Expiry => "expiry",
            Self::Health => "health",
            Self::Defender => "defender",
            Self::Reports => "reports",
            Self::Generator => "generator",
            Self::Audit => "audit",
            Self::Access => "access",
            Self::MyAccess => "myaccess",
        }
    }

    /// Concise summary shown on the Home console cards.
    pub fn summary(self) -> &'static str {
        match self {
            Self::Home => "Workspace overview.",
            Self::Vaults => "Browse every Key Vault you can see across subscriptions.",
            Self::Environments => {
                "Compare secrets across dev, test and prod and set separate values."
            }
            Self::Secrets => "View metadata, reveal values, rotate, share and manage versions.",
            Self::Certificates => "Track TLS certificates, renewal policies and uploads.",
            Self::Keys => "Manage cryptographic keys and automatic rotation policies.",
            Self::Expiry => "Review expiring credentials and stale secrets across vaults.",
            Self::Health => {
                "Check RBAC, purge protection, private endpoints, audit logs, expiry and cycling."
            }
            Self::Defender => "Review Microsoft Defender for Key Vault alerts and plan coverage.",
            Self::Reports => {
                "Export continuous white-label HTML, CSV and JSON executive client reports."
            }
            Self::Generator => "Generate strong passwords, passphrases, API keys and GUIDs.",
            Self::Audit => "Inspect Key Vault audit logs and Keyring activity events.",
            Self::Access => "Review vault and secret RBAC assignments and run access reviews.",
            Self::MyAccess => {
                "Check your active roles, activate PIM eligibility or request access."
            }
        }
    }
}

#[derive(Clone)]
pub struct ShellUser {
    pub name: String,
    /// Form token, bound to the vault chosen when the page was rendered.
    pub csrf: String,
}

/// The vault picked in the header, if any.
#[derive(Clone)]
pub struct ShellVault {
    pub name: String,
}

#[derive(Default, Clone)]
pub struct Shell {
    pub user: Option<ShellUser>,
    pub section: Option<Section>,
    pub vault: Option<ShellVault>,
    pub flash: Option<Flash>,
    /// `KEYRING_REQUIRE_REASON`, for the reason fields on forms.
    pub reason: ReasonAsk,
    /// `KEYRING_PASSWORD_POLICY`, for the help on password fields.
    pub password_policy: crate::password_policy::PasswordPolicy,
    /// `KEYRING_REQUIRE_OWNER`, for the owner field.
    pub require_owner: bool,
}

/// What the reason fields on a form need to know.
#[derive(Default, Clone)]
pub struct ReasonAsk {
    pub require: crate::reason::RequireReason,
    /// `KEYRING_REASON_TICKET_PATTERN`, as written, when set.
    pub ticket_pattern: Option<String>,
}

impl ReasonAsk {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            require: config.reason.require,
            ticket_pattern: config.reason.ticket.as_ref().map(|t| t.source().to_owned()),
        }
    }
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

    /// True when a form for a reveal or private key download should ask
    /// for a reason.
    pub fn asks_reason_to_reveal(&self) -> bool {
        self.reason.require != crate::reason::RequireReason::Off
    }

    /// True when a form that changes something should ask for a reason.
    pub fn asks_reason_to_change(&self) -> bool {
        self.reason.require == crate::reason::RequireReason::All
    }

    /// The ticket pattern, or empty when no ticket is asked for.
    pub fn ticket_pattern(&self) -> &str {
        self.reason.ticket_pattern.as_deref().unwrap_or_default()
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
        if let Some(config) = parts
            .extensions
            .get::<std::sync::Arc<crate::config::Config>>()
        {
            shell.reason = ReasonAsk::from_config(config);
            shell.password_policy = config.password_policy;
            shell.require_owner = config.require_owner;
        }
        Ok(shell)
    }
}
