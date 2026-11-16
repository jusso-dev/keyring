//! `KEYRING_AUDIT_REQUIRED`: refuse reveals and private key downloads while
//! the audit sink is degraded, for organisations where an unrecorded read
//! isn't acceptable.

use axum::http::StatusCode;

use crate::AppState;
use crate::routes::error::{Halt, PageError, Problem};
use crate::routes::shell::Shell;

/// Pass the shell back if the read may go ahead. Refuses, with a page that
/// says auditing is unavailable, only when `KEYRING_AUDIT_REQUIRED` is on
/// and the sink has been failing for longer than its degraded limit.
pub(crate) fn require_audit(state: &AppState, shell: Shell) -> Result<Shell, Halt> {
    let degraded =
        state.config.audit_required && state.audit_sink.as_ref().is_some_and(|s| s.degraded());
    if !degraded {
        return Ok(shell);
    }
    crate::audit::refuse(crate::audit::Refusal::AuditUnavailable);
    Err(PageError::new(
        shell,
        Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Auditing is unavailable",
            "Keyring can't send its audit records right now, and this deployment doesn't allow reading a value or private key without one. Nothing was read. Try again in a few minutes, and if it keeps happening, let whoever runs Keyring know.",
        ),
    )
    .into())
}
