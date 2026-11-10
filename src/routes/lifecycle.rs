//! Delete, recover and purge pieces shared by secrets, certificates and
//! keys.
//!
//! Every delete needs the item's name typed and checked on the server.
//! Purge is refused on the server unless `KEYRING_ALLOW_PURGE=true`, and on
//! vaults with purge protection.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::dates;
use crate::routes::assets::render;
use crate::routes::confirm::{self, ConfirmForm, ConfirmView};
use crate::routes::error::{Halt, PageError, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::azure_problem;

/// What kind of item, for wording and URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Certificate,
    Key,
}

impl Kind {
    pub fn noun(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Certificate => "certificate",
            Self::Key => "key",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Self::Secret => "secrets",
            Self::Certificate => "certificates",
            Self::Key => "keys",
        }
    }

    /// URL prefix, `/secrets`, `/certificates` or `/keys`.
    pub fn base(self) -> &'static str {
        match self {
            Self::Secret => "/secrets",
            Self::Certificate => "/certificates",
            Self::Key => "/keys",
        }
    }

    /// The role that allows delete, recover and purge.
    fn officer_role(self) -> &'static str {
        match self {
            Self::Secret => "Key Vault Secrets Officer",
            Self::Certificate => "Key Vault Certificates Officer",
            Self::Key => "Key Vault Crypto Officer",
        }
    }

    fn delete_effect(self) -> &'static str {
        match self {
            Self::Secret => "Apps using it will stop being able to read it straight away.",
            Self::Certificate => {
                "Its key and backing secret go with it, and apps using it lose access straight away."
            }
            Self::Key => {
                "Anything that encrypts, decrypts or signs with it will stop working straight away. Data encrypted with it can't be read until it's recovered."
            }
        }
    }

    /// What stops working when the current version is disabled.
    fn disable_effect(self) -> &'static str {
        match self {
            Self::Secret => {
                "Key Vault will refuse to hand out its value. Apps that read this secret will start failing on their next read."
            }
            Self::Certificate => {
                "Key Vault will refuse to hand out the current version. Apps that read this certificate, or its key or secret, can start failing on their next read."
            }
            Self::Key => {
                "Key Vault will refuse to use the current version. Anything that encrypts, decrypts, signs or verifies with it will start failing."
            }
        }
    }
}

#[derive(Template)]
#[template(path = "confirm.html")]
struct ConfirmPage {
    shell: Shell,
    confirm: ConfirmView,
}

pub fn confirm_page(shell: Shell, confirm: ConfirmView, status: StatusCode) -> Response {
    (status, render(&ConfirmPage { shell, confirm })).into_response()
}

#[derive(Template)]
#[template(path = "lifecycle/disable.html")]
struct DisablePage<'a> {
    shell: Shell,
    vault: &'a str,
    kind: Kind,
    name: &'a str,
    effect: &'static str,
}

/// The confirmation before a disable. Disabling can break apps as fast as
/// a delete, so it is never one click. The form posts to the existing
/// `enabled` route.
pub fn disable_page(shell: Shell, vault: &str, kind: Kind, name: &str) -> Response {
    render(&DisablePage {
        shell,
        vault,
        kind,
        name,
        effect: kind.disable_effect(),
    })
    .into_response()
}

/// How long a deleted item can be recovered for, and whether it can be
/// purged early. Read from the item's own attributes, so it needs no extra
/// call to Azure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Recovery {
    /// The vault's retention period, when Key Vault sent it.
    pub days: Option<u32>,
    /// True when the vault has purge protection.
    pub purge_protected: bool,
}

impl Recovery {
    /// From an item's `recoveryLevel` and `recoverableDays`.
    ///
    /// Key Vault's recovery levels include "Purgeable" only when a purge is
    /// possible: `Recoverable` and `CustomizedRecoverable` (with or without
    /// `+ProtectedSubscription`) mean purge protection is on. See
    /// <https://learn.microsoft.com/rest/api/keyvault/secrets/get-secret/get-secret#deletionrecoverylevel>.
    /// An unknown level is treated as purgeable, and Key Vault has the final
    /// say.
    pub fn new(level: Option<&str>, days: Option<u32>) -> Self {
        Self {
            // 0 means soft delete is off, which Key Vault no longer allows.
            // Don't promise a figure we can't trust.
            days: days.filter(|d| *d > 0),
            purge_protected: level.is_some_and(|l| !l.is_empty() && !l.contains("Purgeable")),
        }
    }

    /// Finishes "You can recover it ...".
    pub fn period(&self) -> String {
        match self.days {
            Some(1) => "for 1 day after it's deleted".into(),
            Some(d) => format!("for {d} days after it's deleted"),
            None => "until the vault's retention period ends. Each vault sets its own, from 7 to 90 days".into(),
        }
    }

    /// One sentence for a detail page about what happens on delete.
    pub fn sentence(&self, kind: Kind) -> String {
        let mut s = match self.days {
            Some(1) => format!(
                "Deleted {} in this vault can be recovered for 1 day.",
                kind.plural()
            ),
            Some(d) => format!(
                "Deleted {} in this vault can be recovered for {d} days.",
                kind.plural()
            ),
            None => format!(
                "Deleted {} can be recovered until the vault's retention period ends.",
                kind.plural()
            ),
        };
        if self.purge_protected {
            s.push_str(
                " The vault has purge protection, so nobody can permanently delete one before then.",
            );
        }
        s
    }
}

pub fn delete_view(kind: Kind, vault: &str, name: &str) -> ConfirmView {
    delete_view_for(kind, vault, name, Recovery::default())
}

/// The delete confirmation, with the vault's real retention period when
/// the caller has read it from the item.
pub fn delete_view_for(kind: Kind, vault: &str, name: &str, recovery: Recovery) -> ConfirmView {
    ConfirmView {
        heading: format!("Delete {name}?"),
        warning: format!(
            "{name} will move to deleted {} in {vault}. {} You can recover it {}.",
            kind.plural(),
            kind.delete_effect(),
            recovery.period()
        ),
        expected: name.to_owned(),
        action: format!("{}/{name}/delete", kind.base()),
        button: format!("Delete {}", kind.noun()),
        cancel_url: format!("{}/{name}", kind.base()),
        second_warning: None,
        error: None,
    }
}

pub fn purge_view(kind: Kind, vault: &str, name: &str) -> ConfirmView {
    ConfirmView {
        heading: format!("Permanently delete {name}?"),
        warning: format!(
            "This permanently deletes {name} and every version of it from {vault}. It can't be recovered by you, Keyring or Microsoft."
        ),
        expected: name.to_owned(),
        action: format!("{}/deleted/{name}/purge", kind.base()),
        button: "Permanently delete".into(),
        cancel_url: format!("{}/deleted/{name}", kind.base()),
        second_warning: Some(match kind {
            Kind::Secret => "Only do this if you're sure nothing needs this secret any more, or a policy requires it to be destroyed.".into(),
            Kind::Key => "Anything encrypted with this key can never be decrypted again. Only do this if you're sure.".into(),
            Kind::Certificate => "Only do this if you're sure nothing needs this certificate any more, or a policy requires it to be destroyed.".into(),
        }),
        error: None,
    }
}

/// Check the form token and typed name. On a mismatch, show the confirm
/// page again saying nothing was done.
pub fn verify(
    session: &CurrentSession,
    vault: &str,
    form: &ConfirmForm,
    expected: &str,
    shell: Shell,
    view: ConfirmView,
) -> Result<Shell, Halt> {
    match confirm::verify(&session.0, vault, form, expected) {
        Ok(()) => Ok(shell),
        Err(confirm::ConfirmError::StaleForm) => Err(PageError::new(
            shell,
            crate::routes::vault_ctx::stale_form_for(&session.0, &form.csrf),
        )
        .into()),
        Err(e) => {
            let mut view = view;
            view.error = Some(e.problem(expected).message);
            Err(confirm_page(shell, view, StatusCode::UNPROCESSABLE_ENTITY).into())
        }
    }
}

/// With purge turned off, purge routes refuse everything.
pub fn purge_allowed(state: &AppState, shell: Shell, kind: Kind) -> Result<Shell, Halt> {
    if state.config.allow_purge {
        return Ok(shell);
    }
    let role = kind.officer_role();
    Err(PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "Permanent delete is turned off",
            format!(
                "This Keyring doesn't allow permanent deletes. Deleted {} are kept until Key Vault purges them on schedule, and can be recovered until then.",
                kind.plural()
            ),
        )
        .with_hint(format!(
            "Whoever runs Keyring can turn this on with KEYRING_ALLOW_PURGE=true. You'd also need the {role} role."
        )),
    )
    .into())
}

/// The page for a purge the vault won't allow.
pub fn purge_protected_problem(kind: Kind, name: &str) -> Problem {
    Problem::new(
        StatusCode::FORBIDDEN,
        "This vault has purge protection",
        format!(
            "Nobody can permanently delete {name} before its purge date, whatever their role. Key Vault permanently deletes deleted {} once the vault's retention period ends, and they can be recovered until then.",
            kind.plural()
        ),
    )
    .returning_to(&format!("{}/deleted/{name}", kind.base()))
}

/// Refuse a purge early when the deleted item says the vault has purge
/// protection.
pub fn purge_not_protected(
    shell: Shell,
    kind: Kind,
    name: &str,
    recovery: Recovery,
) -> Result<Shell, Halt> {
    if recovery.purge_protected {
        Err(PageError::new(shell, purge_protected_problem(kind, name)).into())
    } else {
        Ok(shell)
    }
}

/// Whether a failed purge was refused because of purge protection. Key
/// Vault answers 403 with a message that names it, so without this the
/// page would say a role is missing. The message is only matched, never
/// shown or logged.
fn is_purge_protection_error(err: &AzureError) -> bool {
    matches!(
        err,
        AzureError::Status { status: 403, message: Some(m), .. }
            if m.to_ascii_lowercase().contains("purge protection")
    )
}

/// Turn a failed purge into a page, naming purge protection when that's
/// the reason.
pub fn purge_problem(
    shell: Shell,
    err: &AzureError,
    kind: Kind,
    name: &str,
    need: crate::routes::error::Need,
) -> Halt {
    if is_purge_protection_error(err) {
        PageError::new(shell, purge_protected_problem(kind, name)).into()
    } else {
        azure_problem(shell, err, need, &format!("{}/deleted/{name}", kind.base()))
    }
}

/// A deleted item, ready to show.
pub struct DeletedRow {
    pub name: String,
    pub deleted: String,
    pub purge: String,
    pub purge_note: String,
    /// The vault has purge protection, so purge isn't offered.
    pub purge_protected: bool,
}

impl DeletedRow {
    pub fn new(name: &str, deleted: Option<i64>, purge: Option<i64>, now: i64) -> Self {
        Self {
            name: name.to_owned(),
            deleted: deleted.map(dates::format_datetime).unwrap_or_default(),
            purge: purge.map(dates::format_date).unwrap_or_default(),
            purge_note: purge
                .map(|p| dates::relative_days(p, now))
                .unwrap_or_default(),
            purge_protected: false,
        }
    }

    /// Take purge protection from the deleted item's `recoveryLevel`.
    pub fn with_recovery_level(mut self, level: Option<&str>) -> Self {
        self.purge_protected = Recovery::new(level, None).purge_protected;
        self
    }
}

#[derive(Template)]
#[template(path = "lifecycle/deleted.html")]
struct DeletedList<'a> {
    shell: Shell,
    vault: String,
    kind: Kind,
    rows: &'a [DeletedRow],
}

pub fn deleted_list(shell: Shell, vault: String, kind: Kind, rows: &[DeletedRow]) -> Response {
    render(&DeletedList {
        shell,
        vault,
        kind,
        rows,
    })
    .into_response()
}

#[derive(Template)]
#[template(path = "lifecycle/deleted_detail.html")]
struct DeletedDetail<'a> {
    shell: Shell,
    vault: String,
    kind: Kind,
    row: &'a DeletedRow,
    allow_purge: bool,
}

pub fn deleted_detail(
    state: &AppState,
    shell: Shell,
    vault: String,
    kind: Kind,
    row: &DeletedRow,
) -> Response {
    render(&DeletedDetail {
        shell,
        vault,
        kind,
        row,
        allow_purge: state.config.allow_purge,
    })
    .into_response()
}

pub fn redirect_with(state: &AppState, to: &str, message: String) -> Response {
    let mut res = Redirect::to(to).into_response();
    flash::set(state, &mut res, &Flash::success(message));
    res
}

/// After a recover. Key Vault accepts a recover at once but the item can
/// take a few seconds to be readable, so go to the deleted list rather
/// than a detail page that may still say "not found". Keyring doesn't
/// poll; the message says to wait.
pub fn recovered(state: &AppState, kind: Kind, name: &str) -> Response {
    let extra = match kind {
        Kind::Secret => ", with its value and versions",
        Kind::Certificate | Kind::Key => ", with every version",
    };
    redirect_with(
        state,
        &format!("{}/deleted", kind.base()),
        format!(
            "Recovering {name}{extra}. It can take a few seconds to show in {}. Refresh that list if it isn't there yet.",
            kind.plural()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_levels() {
        for (level, protected) in [
            (Some("Recoverable+Purgeable"), false),
            (Some("CustomizedRecoverable+Purgeable"), false),
            (Some("Purgeable"), false),
            (Some("Recoverable"), true),
            (Some("Recoverable+ProtectedSubscription"), true),
            (Some("CustomizedRecoverable"), true),
            (Some("CustomizedRecoverable+ProtectedSubscription"), true),
            (Some(""), false),
            (None, false),
        ] {
            assert_eq!(
                Recovery::new(level, None).purge_protected,
                protected,
                "{level:?}"
            );
        }
    }

    #[test]
    fn retention_wording() {
        let seven = Recovery::new(Some("CustomizedRecoverable+Purgeable"), Some(7));
        assert_eq!(seven.period(), "for 7 days after it's deleted");
        let unknown = Recovery::new(None, Some(0));
        assert_eq!(unknown.days, None);
        assert!(unknown.period().contains("7 to 90 days"));
        let view = delete_view_for(Kind::Secret, "kv", "db", seven);
        assert!(view.warning.contains("for 7 days"), "{}", view.warning);
        assert!(!view.warning.contains("usually 90"));
        let s = Recovery::new(Some("Recoverable"), Some(90)).sentence(Kind::Key);
        assert!(
            s.contains("90 days") && s.contains("purge protection"),
            "{s}"
        );
    }

    #[test]
    fn purge_protection_is_spotted_in_the_error() {
        let protected = AzureError::Status {
            status: 403,
            code: Some("Forbidden".into()),
            message: Some("Operation \"purge\" is not allowed because purge protection is enabled for this vault.".into()),
        };
        assert!(is_purge_protection_error(&protected));
        let role = AzureError::Status {
            status: 403,
            code: Some("Forbidden".into()),
            message: Some("Caller is not authorised".into()),
        };
        assert!(!is_purge_protection_error(&role));
    }
}
