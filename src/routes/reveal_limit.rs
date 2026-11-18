//! Reveal limits on the server (`keyring-reveal`, [`crate::reveal_limit`]).
//!
//! Every path that can show, copy, export or re-tag a value checks the
//! limit here or through [`crate::reveal_limit`], from the same Key Vault
//! reads the action already makes:
//!
//! - Reveal, copy to another vault and private key download read the
//!   limit from properties first (the versions list or the certificate,
//!   never a value), and refuse `none` before the value is read. They
//!   check the tags on the value response again before anything from it
//!   is used, so a tag added in between still stops them.
//! - The limit is checked before step-up and before the reason gate, so
//!   nobody is sent to sign in again or give a reason for something that
//!   will be refused. The reason gate calls [`refuse_early`] for that.
//! - Loosening the limit through Keyring ([`loosening`]) needs the same
//!   step-up and reason as a reveal, and the audit event says from what
//!   to what.

use std::collections::BTreeMap;

use axum::http::StatusCode;

use crate::AppState;
use crate::audit::{Action, Refusal};
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::certs::CertsApi;
use crate::azure::secrets::{SecretItem, SecretsApi, is_valid_version};
use crate::reveal_limit::{self, Limit};
use crate::routes::error::{Halt, NextStep, PageError, Problem};
use crate::routes::forms::FieldErrors;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::vault_path;

/// What the refusal page says. Nothing about the value.
pub(crate) const HINT: &str = "This is a Keyring control, like step-up. The Azure CLI, the portal and the SDKs aren't limited by it, and anyone who can change the item's tags can change it.";

/// The page for a refused reveal, copy or private key download. Writes the
/// request's one audit event as `refused` with `reveal_limited`.
pub(crate) fn refused(shell: Shell, vault: &str, noun: &'static str, item_url: &str) -> Halt {
    refused_page(shell, vault, noun, item_url, false)
}

/// [`refused`] for the second check, after the value came back from Key
/// Vault with a limit set in between. The page says it was read and not
/// shown, since Key Vault's own log has the read.
pub(crate) fn refused_after_read(
    shell: Shell,
    vault: &str,
    noun: &'static str,
    item_url: &str,
) -> Halt {
    refused_page(shell, vault, noun, item_url, true)
}

fn refused_page(shell: Shell, vault: &str, noun: &'static str, item_url: &str, read: bool) -> Halt {
    let last = if read {
        "The limit was set while Keyring was reading it: Keyring read it from Key Vault, which Key Vault's log shows, and didn't show or keep it."
    } else {
        "Nothing was read."
    };
    crate::audit::refuse(Refusal::RevealLimited);
    crate::routes::secrets::reveal::no_store(
        axum::response::IntoResponse::into_response(PageError::new(
            shell,
            Problem::new(
                StatusCode::FORBIDDEN,
                "Not shown in Keyring",
                format!(
                    "This {noun} in {vault} is set not to be shown, copied or downloaded in Keyring, by its keyring-reveal tag. Apps should read it with their own identity. If you need it yourself, use the Azure CLI with your own access. {last}"
                ),
            )
            .with_hint(HINT)
            .with_next(NextStep::Go {
                url: item_url.to_owned(),
                label: "Back",
            }),
        )),
    )
    .into()
}

/// The limit on a secret, from its versions list (properties only, never a
/// value): the strictest of the current version's tags and, when
/// `version` is given, that version's. Also gives the list, newest first.
pub(crate) async fn of_secret(
    api: &SecretsApi<'_>,
    name: &str,
    version: Option<&str>,
) -> Result<(Limit, Vec<SecretItem>), AzureError> {
    let items = api.versions(name).await?;
    Ok((of_versions(&items, version), items))
}

/// The strictest of the current version's limit and `version`'s. A
/// version not in the list counts as the current one only.
pub(crate) fn of_versions(items: &[SecretItem], version: Option<&str>) -> Limit {
    // Every version made in the newest second counts as current: Key
    // Vault's `created` is in whole seconds, so the order of two made in
    // the same second isn't known.
    let newest = items.first().map(|i| i.attributes.created);
    let current = items
        .iter()
        .take_while(|i| Some(i.attributes.created) == newest)
        .map(SecretItem::tags);
    let asked = version.and_then(|v| {
        items
            .iter()
            .find(|i| i.version().eq_ignore_ascii_case(v))
            .map(SecretItem::tags)
    });
    reveal_limit::strictest(current.chain(asked))
}

/// The limit on a certificate, from its current version's tags.
pub(crate) async fn of_certificate(api: &CertsApi<'_>, name: &str) -> Result<Limit, AzureError> {
    let b = api.get_cert(name, None).await?;
    Ok(reveal_limit::of(&b.tags.unwrap_or_default()))
}

/// For the reason gate: when `action` reads a value and the item's limit
/// refuses it, the refusal page, so the person isn't asked for a reason
/// first. `None` lets the request go on; a Key Vault error does too, and
/// the handler says what went wrong.
pub(crate) async fn refuse_early(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    action: Action,
    vault: &str,
    name: &str,
    version: &str,
) -> Option<axum::response::Response> {
    let version = version.trim();
    let version = (!version.is_empty() && is_valid_version(version)).then_some(version);
    let (refuses, noun, url) = match action {
        Action::SecretReveal | Action::SecretCopyRead => {
            let api = crate::routes::secrets::api(state, session, vault);
            let limit = of_secret(&api, name, version).await.ok()?.0;
            (
                limit.refuses_reveal(),
                "secret",
                vault_path(vault, &format!("/secrets/{name}")),
            )
        }
        Action::CertificateDownloadPrivateKey => {
            let api = CertsApi {
                azure: &state.azure,
                session: &session.0,
                vault_url: state.config.vault_url(vault),
            };
            let limit = of_certificate(&api, name).await.ok()?;
            (
                limit.refuses_download(),
                "certificate",
                vault_path(vault, &format!("/certificates/{name}")),
            )
        }
        _ => return None,
    };
    if !refuses {
        return None;
    }
    let halt = refused(shell, vault, noun, &url);
    Some(axum::response::IntoResponse::into_response(halt))
}

/// A save that changes the limit. Notes the change on the audit event
/// (fixed words only). When it loosens the limit, the same gates as a
/// reveal: step-up, then a reason when `KEYRING_REQUIRE_REASON` asks for
/// one before a reveal and the reason gate didn't already check this
/// action. A missing or bad reason is an error on the `reason` field.
#[allow(clippy::too_many_arguments)]
pub(crate) fn loosening(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    action: Action,
    current: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    reason: &str,
    ticket: &str,
    back: &str,
) -> Result<(Shell, FieldErrors), Halt> {
    let (from, to) = (reveal_limit::word(current), reveal_limit::word(new));
    if from != to {
        crate::audit::note_reveal_limit(from, to);
    }
    if reveal_limit::of(new) >= reveal_limit::of(current) {
        return Ok((shell, FieldErrors::new()));
    }
    let shell = crate::routes::step_up::require(state, &session.0, shell, back, back)?;
    let policy = &state.config.reason;
    let mut errors = FieldErrors::new();
    if policy.require != crate::reason::RequireReason::Off && !policy.needs(action) {
        match policy.check(reason, ticket) {
            Ok(given) => crate::audit::note_reason(&given),
            Err(p) => {
                crate::audit::refuse(Refusal::ReasonRequired);
                if p.reason {
                    errors.push(
                        "reason",
                        format!(
                            "Loosening the reveal limit needs a reason of {} to {} characters.",
                            crate::reason::MIN_REASON_CHARS,
                            crate::reason::MAX_REASON_CHARS
                        ),
                    );
                }
                if p.ticket {
                    errors.push("ticket", "Give a ticket reference in the format asked for.");
                }
            }
        }
    }
    Ok((shell, errors))
}
