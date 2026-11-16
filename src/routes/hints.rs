//! Permission hints: grey out a button the signed-in person's roles don't
//! allow, and name the role that would.
//!
//! This is a hint only. Key Vault decides. Every handler keeps its own
//! checks and its own 403 page, and the POST routes don't look at hints at
//! all, so a disabled button is never the only thing stopping an action.
//!
//! The answer comes from ARM's
//! `{scope}/providers/Microsoft.Authorization/permissions`, read with the
//! person's on-behalf-of Management token, kept in the session for
//! [`crate::auth::session::PERMISSIONS_TTL`]. It fails open: if the read fails, is refused, is
//! slow or can't be read, or the vault uses access policies (which that
//! call doesn't cover), every button stays enabled.
//!
//! Item pages ask at the item's own scope ([`authz::item_scope`]), never
//! only at the vault's, so a role given on one item isn't missed. If that
//! read is refused, the buttons stay enabled.
//!
//! PIM activation (#203) is meant to build on [`Hints`]: where
//! [`Hints::needs`] names a role, that is the place to offer "Activate".
//! Nothing here offers it yet.
//!
//! Only reads, so it writes no audit event.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::authz::{self, Permissions};
use crate::routes::error::Need;
use crate::routes::lifecycle::Kind;

/// Longest a page waits for the hint. It runs beside the page's own Key
/// Vault reads, so it adds nothing unless ARM is slower than Key Vault.
pub(crate) const HINT_TIMEOUT: Duration = Duration::from_secs(2);

/// A Keyring action that a button starts.
///
/// The data actions are as Microsoft lists them in "Azure permissions for
/// Security" (`Microsoft.KeyVault` data actions), checked against the
/// built-in role definitions: Key Vault Secrets User
/// (`secrets/getSecret/action`, `secrets/readMetadata/action`), Secrets
/// Officer (`secrets/*`), Certificate User (`certificates/read`,
/// `secrets/getSecret/action`, `secrets/readMetadata/action`, `keys/read`),
/// Certificates Officer (`certificates/*`, `certificatecas/*`,
/// `certificatecontacts/write`), Crypto Officer (`keys/*`,
/// `keyrotationpolicies/*`), Reader (`vaults/*/read`,
/// `secrets/readMetadata/action`) and Administrator (`vaults/*`).
///
/// "Download with private key" has no hint on purpose: it reads the
/// backing secret, and a role given on `{vault}/secrets/{name}` doesn't
/// show at the certificate's scope, so a hint could disable it wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Show value. `Microsoft.KeyVault/vaults/secrets/getSecret/action`.
    RevealSecret,
    /// Create a secret, set a new value.
    /// `Microsoft.KeyVault/vaults/secrets/setSecret/action`.
    SetSecret,
    /// Edit details, enable or disable.
    /// `Microsoft.KeyVault/vaults/secrets/update/action`.
    UpdateSecret,
    /// `Microsoft.KeyVault/vaults/secrets/delete`.
    DeleteSecret,
    /// `Microsoft.KeyVault/vaults/secrets/recover/action`.
    RecoverSecret,
    /// `Microsoft.KeyVault/vaults/secrets/purge/action`. Microsoft's list
    /// has no `deletedSecrets/` data action; purge sits under `secrets/`.
    PurgeSecret,
    /// `Microsoft.KeyVault/vaults/certificates/create/action`.
    CreateCertificate,
    /// Upload a certificate.
    /// `Microsoft.KeyVault/vaults/certificates/import/action`.
    ImportCertificate,
    /// Enable or disable.
    /// `Microsoft.KeyVault/vaults/certificates/update/action`.
    UpdateCertificate,
    /// `Microsoft.KeyVault/vaults/certificates/delete`.
    DeleteCertificate,
    /// `Microsoft.KeyVault/vaults/certificates/recover/action`.
    RecoverCertificate,
    /// `Microsoft.KeyVault/vaults/certificates/purge/action`.
    PurgeCertificate,
    /// `Microsoft.KeyVault/vaults/keys/create/action`.
    CreateKey,
    /// Rotate now. `Microsoft.KeyVault/vaults/keys/rotate/action`.
    RotateKey,
    /// Enable or disable. `Microsoft.KeyVault/vaults/keys/update/action`.
    UpdateKey,
    /// `Microsoft.KeyVault/vaults/keys/delete`.
    DeleteKey,
    /// `Microsoft.KeyVault/vaults/keys/recover/action`.
    RecoverKey,
    /// `Microsoft.KeyVault/vaults/keys/purge/action`.
    PurgeKey,
}

impl Action {
    /// Every data action the action needs. All must be allowed.
    pub(crate) fn data_actions(self) -> &'static [&'static str] {
        match self {
            Self::RevealSecret => &["Microsoft.KeyVault/vaults/secrets/getSecret/action"],
            Self::SetSecret => &["Microsoft.KeyVault/vaults/secrets/setSecret/action"],
            Self::UpdateSecret => &["Microsoft.KeyVault/vaults/secrets/update/action"],
            Self::DeleteSecret => &["Microsoft.KeyVault/vaults/secrets/delete"],
            Self::RecoverSecret => &["Microsoft.KeyVault/vaults/secrets/recover/action"],
            Self::PurgeSecret => &["Microsoft.KeyVault/vaults/secrets/purge/action"],
            Self::CreateCertificate => &["Microsoft.KeyVault/vaults/certificates/create/action"],
            Self::ImportCertificate => &["Microsoft.KeyVault/vaults/certificates/import/action"],
            Self::UpdateCertificate => &["Microsoft.KeyVault/vaults/certificates/update/action"],
            Self::DeleteCertificate => &["Microsoft.KeyVault/vaults/certificates/delete"],
            Self::RecoverCertificate => &["Microsoft.KeyVault/vaults/certificates/recover/action"],
            Self::PurgeCertificate => &["Microsoft.KeyVault/vaults/certificates/purge/action"],
            Self::CreateKey => &["Microsoft.KeyVault/vaults/keys/create/action"],
            Self::RotateKey => &["Microsoft.KeyVault/vaults/keys/rotate/action"],
            Self::UpdateKey => &["Microsoft.KeyVault/vaults/keys/update/action"],
            Self::DeleteKey => &["Microsoft.KeyVault/vaults/keys/delete"],
            Self::RecoverKey => &["Microsoft.KeyVault/vaults/keys/recover/action"],
            Self::PurgeKey => &["Microsoft.KeyVault/vaults/keys/purge/action"],
        }
    }

    /// What the 403 page for this action would ask for, so the hint and
    /// the page name the same role.
    pub(crate) fn need(self) -> Need {
        match self {
            Self::RevealSecret => Need::ReadSecrets,
            Self::SetSecret
            | Self::UpdateSecret
            | Self::DeleteSecret
            | Self::RecoverSecret
            | Self::PurgeSecret => Need::ManageSecrets,
            Self::CreateCertificate
            | Self::ImportCertificate
            | Self::UpdateCertificate
            | Self::DeleteCertificate
            | Self::RecoverCertificate
            | Self::PurgeCertificate => Need::ManageCertificates,
            Self::CreateKey
            | Self::RotateKey
            | Self::UpdateKey
            | Self::DeleteKey
            | Self::RecoverKey
            | Self::PurgeKey => Need::ManageKeys,
        }
    }

    /// The delete, recover and purge actions for `kind`.
    pub(crate) fn recover(kind: Kind) -> Self {
        match kind {
            Kind::Secret => Self::RecoverSecret,
            Kind::Certificate => Self::RecoverCertificate,
            Kind::Key => Self::RecoverKey,
        }
    }

    pub(crate) fn purge(kind: Kind) -> Self {
        match kind {
            Kind::Secret => Self::PurgeSecret,
            Kind::Certificate => Self::PurgeCertificate,
            Kind::Key => Self::PurgeKey,
        }
    }
}

/// What a page knows of the person's permissions. Empty (the default)
/// means "don't know", and every button stays enabled.
#[derive(Debug, Clone, Default)]
pub(crate) struct Hints {
    perms: Option<Arc<Permissions>>,
}

impl Hints {
    /// The role to name beside a disabled button, or `None` to leave it
    /// enabled. Only `Some` when the permissions were read and none of the
    /// person's roles allows every data action `action` needs.
    pub(crate) fn needs(&self, action: Action) -> Option<&'static str> {
        let perms = self.perms.as_ref()?;
        let allowed = action
            .data_actions()
            .iter()
            .all(|a| perms.allows_data_action(a));
        (!allowed).then(|| action.need().role())
    }
}

/// Hints for a vault-wide action, such as "Create a secret". Read at the
/// vault's scope.
pub(crate) async fn for_vault(state: &AppState, session: &CurrentSession, vault: &str) -> Hints {
    within(state, session, vault, None).await
}

/// Hints for one item's buttons. Read at the item's own scope, so a role
/// given on that item counts.
pub(crate) async fn for_item(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    kind: Kind,
    name: &str,
) -> Hints {
    within(state, session, vault, Some((kind, name))).await
}

async fn within(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    item: Option<(Kind, &str)>,
) -> Hints {
    match tokio::time::timeout(HINT_TIMEOUT, read(state, session, vault, item)).await {
        Ok(perms) => Hints { perms },
        Err(_) => {
            tracing::info!("permission hint read timed out; buttons left enabled");
            Hints::default()
        }
    }
}

/// The person's permissions at the vault's or the item's scope, from the
/// session if read lately. `None` whenever they shouldn't be used.
async fn read(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    item: Option<(Kind, &str)>,
) -> Option<Arc<Permissions>> {
    let vault_id = match super::audit::vault_id(state, session, vault).await {
        Ok(Some(id)) => id,
        Ok(None) => return None,
        Err(e) => {
            tracing::info!(error = %e, "permission hint: couldn't look up the vault");
            return None;
        }
    };
    let scope = match item {
        Some((kind, name)) => authz::item_scope(&vault_id, kind.plural(), name),
        None => vault_id.clone(),
    };
    if let Some(kept) = session.0.cached_permissions_at(&scope, Instant::now()) {
        return kept;
    }
    let url = &state.config.management_url;
    let (auth, perms) = tokio::join!(
        authz::vault_authorisation(&state.azure, &session.0, url, &vault_id),
        authz::permissions(&state.azure, &session.0, url, &scope),
    );
    let perms = match (auth, perms) {
        // Access policies: the call doesn't cover data access there.
        (Ok(a), _) if !a.rbac => None,
        (Ok(_), Ok(p)) => Some(Arc::new(p)),
        (Err(e), _) | (_, Err(e)) => {
            tracing::info!(error = %e, "permission hint read failed; buttons left enabled");
            None
        }
    };
    session
        .0
        .keep_permissions_at(&scope, perms.clone(), Instant::now());
    perms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::authz::PermissionSet;

    fn hints(sets: &[(&[&str], &[&str])]) -> Hints {
        let sets = sets
            .iter()
            .map(|(data, not)| PermissionSet {
                data_actions: data.iter().map(|a| (*a).into()).collect(),
                not_data_actions: not.iter().map(|a| (*a).into()).collect(),
                ..PermissionSet::default()
            })
            .collect();
        Hints {
            perms: Some(Arc::new(Permissions { sets })),
        }
    }

    const ALL: [Action; 18] = [
        Action::RevealSecret,
        Action::SetSecret,
        Action::UpdateSecret,
        Action::DeleteSecret,
        Action::RecoverSecret,
        Action::PurgeSecret,
        Action::CreateCertificate,
        Action::ImportCertificate,
        Action::UpdateCertificate,
        Action::DeleteCertificate,
        Action::RecoverCertificate,
        Action::PurgeCertificate,
        Action::CreateKey,
        Action::RotateKey,
        Action::UpdateKey,
        Action::DeleteKey,
        Action::RecoverKey,
        Action::PurgeKey,
    ];

    #[test]
    fn unknown_means_enabled() {
        for a in ALL {
            assert_eq!(Hints::default().needs(a), None);
        }
    }

    #[test]
    fn built_in_roles_as_microsoft_defines_them() {
        let reader = hints(&[(
            &[
                "Microsoft.KeyVault/vaults/*/read",
                "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
            ],
            &[],
        )]);
        for a in ALL {
            assert!(reader.needs(a).is_some(), "Reader can't {a:?}");
        }
        assert_eq!(
            reader.needs(Action::SetSecret),
            Some("Key Vault Secrets Officer")
        );
        assert_eq!(
            reader.needs(Action::RevealSecret),
            Some("Key Vault Secrets User")
        );
        assert_eq!(
            reader.needs(Action::RotateKey),
            Some("Key Vault Crypto Officer")
        );

        let secrets_officer = hints(&[(&["Microsoft.KeyVault/vaults/secrets/*"], &[])]);
        for a in [
            Action::RevealSecret,
            Action::SetSecret,
            Action::UpdateSecret,
            Action::DeleteSecret,
            Action::RecoverSecret,
            Action::PurgeSecret,
        ] {
            assert_eq!(secrets_officer.needs(a), None, "{a:?}");
        }
        assert!(secrets_officer.needs(Action::DeleteKey).is_some());

        let secrets_user = hints(&[(
            &[
                "Microsoft.KeyVault/vaults/secrets/getSecret/action",
                "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
            ],
            &[],
        )]);
        assert_eq!(secrets_user.needs(Action::RevealSecret), None);
        assert!(secrets_user.needs(Action::SetSecret).is_some());

        let cert_user = hints(&[(
            &[
                "Microsoft.KeyVault/vaults/certificates/read",
                "Microsoft.KeyVault/vaults/secrets/getSecret/action",
                "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
                "Microsoft.KeyVault/vaults/keys/read",
            ],
            &[],
        )]);
        assert_eq!(
            cert_user.needs(Action::DeleteCertificate),
            Some("Key Vault Certificates Officer")
        );

        let cert_officer = hints(&[(
            &[
                "Microsoft.KeyVault/vaults/certificatecas/*",
                "Microsoft.KeyVault/vaults/certificates/*",
                "Microsoft.KeyVault/vaults/certificatecontacts/write",
            ],
            &[],
        )]);
        assert_eq!(cert_officer.needs(Action::ImportCertificate), None);

        let crypto_officer = hints(&[(
            &[
                "Microsoft.KeyVault/vaults/keys/*",
                "Microsoft.KeyVault/vaults/keyrotationpolicies/*",
            ],
            &[],
        )]);
        assert_eq!(crypto_officer.needs(Action::RotateKey), None);
        assert_eq!(crypto_officer.needs(Action::PurgeKey), None);

        let admin = hints(&[(&["Microsoft.KeyVault/vaults/*"], &[])]);
        let star = hints(&[(&["*"], &[])]);
        for a in ALL {
            assert_eq!(admin.needs(a), None);
            assert_eq!(star.needs(a), None);
        }
    }

    #[test]
    fn not_data_actions_subtract() {
        let no_purge = hints(&[(
            &["Microsoft.KeyVault/vaults/secrets/*"],
            &["Microsoft.KeyVault/vaults/secrets/purge/action"],
        )]);
        assert_eq!(no_purge.needs(Action::DeleteSecret), None);
        assert_eq!(
            no_purge.needs(Action::PurgeSecret),
            Some("Key Vault Secrets Officer")
        );
    }

    #[test]
    fn every_action_is_a_key_vault_data_action() {
        for a in ALL {
            for d in a.data_actions() {
                assert!(d.starts_with("Microsoft.KeyVault/vaults/"), "{d}");
                assert!(!d.contains('*'), "{d}");
            }
        }
        for k in [Kind::Secret, Kind::Certificate, Kind::Key] {
            assert!(Action::recover(k).data_actions()[0].contains(k.plural()));
            assert!(Action::purge(k).data_actions()[0].ends_with("/purge/action"));
        }
    }
}
