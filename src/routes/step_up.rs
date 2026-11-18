//! The step-up guard for sensitive actions. One place, so every action that
//! needs it (reveal, private key download, rollback, purge, copy to
//! another vault, sharing a secret, and later PIM activation) behaves the
//! same.
//!
//! The rules are in [`crate::auth::step_up`]. When the session doesn't meet
//! them, the action stops before anything reaches Azure, the audit event
//! gets `step_up_required`, and the page explains why and links to
//! `/auth/start?reason=step_up`. After signing in, the person lands back on
//! the confirmation step, never in the action itself.

use std::time::SystemTime;

use axum::http::StatusCode;

use crate::AppState;
use crate::auth::return_to;
use crate::auth::session::Session;
use crate::routes::error::{Halt, NextStep, PageError, Problem};
use crate::routes::shell::Shell;

/// The `reason` `/auth/start` takes for a step-up sign-in.
pub(crate) const REASON: &str = "step_up";

/// What the page says, as the issue asks.
pub(crate) const EXPLANATION: &str =
    "Your organisation asks you to confirm it's you before showing values.";

/// The actions this guard runs before. The reason gate checks the same
/// list, so it steps aside while step-up is still to be met.
pub(crate) fn guards(action: crate::audit::Action) -> bool {
    use crate::audit::Action;
    matches!(
        action,
        Action::SecretReveal
            | Action::CertificateDownloadPrivateKey
            | Action::SecretRollback
            | Action::SecretCopyRead
            | Action::ShareGrant
            | Action::ShareRevoke
            | Action::SecretPurge
            | Action::CertificatePurge
            | Action::KeyPurge
    )
}

/// Let the action go ahead if the session meets `KEYRING_STEP_UP_*`, or
/// stop it. `confirm_path` is the local page to come back to after signing
/// in: the confirmation step for this action. `cancel_path` is where
/// "Cancel" goes.
pub(crate) fn require(
    state: &AppState,
    session: &Session,
    shell: Shell,
    confirm_path: &str,
    cancel_path: &str,
) -> Result<Shell, Halt> {
    let policy = &state.config.step_up;
    if policy
        .check(&session.sign_in_facts(), SystemTime::now())
        .is_ok()
    {
        return Ok(shell);
    }
    crate::audit::refuse(crate::audit::Refusal::StepUpRequired);
    let back = return_to::sanitise(Some(confirm_path));
    let start = format!(
        "/auth/start?return_to={}&reason={REASON}",
        return_to::encode(&back)
    );
    Err(PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "Confirm it's you",
            format!(
                "{EXPLANATION} Sign in with Microsoft again and you'll come back to this step. Nothing was shown or changed."
            ),
        )
        .with_hint("Keyring makes this check itself, from your Microsoft sign-in. Your access in Key Vault is unchanged.")
        .with_next(NextStep::Go {
            url: start,
            label: "Confirm it's you",
        })
        .with_also(NextStep::Go {
            url: return_to::sanitise(Some(cancel_path)),
            label: "Cancel",
        }),
    )
    .into())
}
