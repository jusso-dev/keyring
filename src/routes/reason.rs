//! The reason gate (`KEYRING_REQUIRE_REASON`). One place, run by
//! `audited(...)` for every audited route, so no handler checks a reason
//! itself.
//!
//! When the action needs a reason, the gate reads the posted form. If the
//! form token is wrong, step-up isn't met, or purge is off, it steps aside
//! and the handler refuses as it always has: the form token comes first,
//! then step-up, then the reason. Otherwise it checks the reason and
//! ticket ([`crate::reason`]) before the handler runs, so before any Key
//! Vault call. A good reason goes on the audit event. A missing or bad one
//! is refused with `reason_required`, and a page asks for it, posting the
//! same form again with the reason added. The reason is never put in an
//! address.
//!
//! The gate fails closed. Once a reason is needed, the only requests it
//! hands on unchecked are ones the handler is about to refuse anyway for a
//! bad form token, unmet step-up or purge being off. Anything it can't
//! place is refused here.

use std::sync::Arc;
use std::time::SystemTime;

use askama::Template;
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, RawPathParams, Request};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::audit::{Action, Refusal};
use crate::auth::CurrentSession;
use crate::azure::vaults::is_valid_vault_name;
use crate::config::Config;
use crate::reason::Problems;
use crate::routes::assets::render;
use crate::routes::error::{PageError, Problem};
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::is_valid_object_name;

/// Most fields carried over to the reason page. More than any of
/// Keyring's own forms post.
const MAX_CARRIED_FIELDS: usize = 64;

/// Fields the reason page never carries: its own.
const NOT_CARRIED: [&str; 3] = ["csrf", "reason", "ticket"];

/// Actions whose form holds secret material, under `value` or a typed
/// secret's field names (password, private_key, passphrase, key and the
/// rest). Their fields are never written back into a page: the person is
/// sent back to the form instead. Decided by action, not field name, so a
/// new field can't slip through.
fn holds_secret_material(action: Action) -> bool {
    matches!(
        action,
        Action::SecretCreate | Action::SecretSet | Action::SecretMultiEnvSet
    )
}

#[derive(Template)]
#[template(path = "reason.html")]
struct ReasonPage {
    shell: Shell,
    heading: &'static str,
    intro: &'static str,
    button: &'static str,
    action: String,
    cancel: String,
    /// The original form's other fields, posted again as they were.
    fields: Vec<(String, String)>,
    /// False when the form held secret material: the person goes back to
    /// the form instead.
    carry: bool,
    errors: FieldErrors,
    reason: String,
    ticket: String,
}

/// Run before an audited route's handler. Does nothing unless the
/// settings ask for a reason for `action`.
///
/// Fails closed: once the settings ask for a reason, a request this gate
/// can't place (no session, no vault it can check, an action that isn't on
/// an item) is refused here and never handed to the handler. The vault and
/// item come from the route's own decoded parameters, the same ones the
/// handler's `Path` reads, so a percent-encoded segment such as
/// `/v/%6bv-test/...` is checked as `kv-test` and can't slip past.
pub(crate) async fn gate(action: Action, req: Request, next: Next) -> Response {
    let Some(config) = req.extensions().get::<Arc<Config>>().cloned() else {
        // Only the signed-out routes (sign-out) are wired without the
        // settings. An item action without them is a wiring fault: stop.
        if action.item_kind().is_some() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "not available").into_response();
        }
        return next.run(req).await;
    };
    if !config.reason.needs(action) {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    let session = parts.extensions.get::<CurrentSession>().cloned();
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .ok();
    let target = params.as_ref().and_then(|p| Target::from_route(action, p));
    let (Some(session), Some(target)) = (session, target) else {
        return refuse_unplaced(parts).await;
    };
    let path = parts
        .extensions
        .get::<OriginalUri>()
        .map_or_else(|| parts.uri.path().to_owned(), |u| u.path().to_owned());
    // Every audited form is URL-encoded. Anything else can't carry a
    // reason, so it's refused here rather than left for the handler.
    let is_form = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "form expected").into_response();
    }

    // Read under the route's own body limit. A rejection is plain text, so
    // the rejection layer shows its page.
    let bytes = match axum::body::Bytes::from_request(Request::from_parts(parts.clone(), body), &())
        .await
    {
        Ok(b) => b,
        Err(rejection) => return rejection.into_response(),
    };
    let fields: Vec<(String, String)> = openidconnect::url::form_urlencoded::parse(&bytes)
        .into_owned()
        .collect();
    let field = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

    // The checks that come first. If any would refuse, let the handler
    // do it, with its own page and reason code.
    let csrf_val = field("csrf").unwrap_or_default();
    let csrf_ok = match &target.vault {
        Some(v) => session.0.csrf_matches_vault(csrf_val, v),
        None => session.0.csrf_matches_any(csrf_val),
    };
    let step_up_ok = !crate::routes::step_up::guards(action)
        || config
            .step_up
            .check(&session.0.sign_in_facts(), SystemTime::now())
            .is_ok();
    let purge_ok = !is_purge(action) || config.allow_purge;
    // A reveal limit that refuses this anyway is said first, before the
    // person is sent to step up or asked for a reason. Read from
    // properties only, never a value.
    if csrf_ok
        && crate::reason::is_reveal(action)
        && let (Some(state), Some(vault), Some(name)) = (
            parts.extensions.get::<crate::AppState>().cloned(),
            target.vault.as_deref(),
            target.name.clone(),
        )
    {
        let shell = Shell::from_request_parts(&mut parts, &())
            .await
            .unwrap_or_default()
            .for_vault(vault, &session)
            .at(target.section);
        crate::audit::note_vault(vault);
        crate::audit::note_item(&name);
        if let Some(res) = crate::routes::reveal_limit::refuse_early(
            &state,
            &session,
            shell,
            action,
            vault,
            &name,
            field("version").unwrap_or_default(),
        )
        .await
        {
            return res;
        }
    }
    if csrf_ok && step_up_ok && purge_ok {
        let asked = field("reason").is_some();
        match config.reason.check(
            field("reason").unwrap_or_default(),
            field("ticket").unwrap_or_default(),
        ) {
            Ok(given) => crate::audit::note_reason(&given),
            Err(problems) => {
                crate::audit::refuse(Refusal::ReasonRequired);
                if let Some(v) = &target.vault {
                    crate::audit::note_vault(v);
                }
                if let Some(name) = &target.name {
                    crate::audit::note_item(name);
                }
                let base_shell = Shell::from_request_parts(&mut parts, &())
                    .await
                    .unwrap_or_default();
                let shell = match &target.vault {
                    Some(v) => base_shell.for_vault(v, &session).at(target.section),
                    None => base_shell.at(target.section),
                };
                return ask(
                    shell,
                    action,
                    &config,
                    &target,
                    &path,
                    &fields,
                    asked.then_some(problems),
                );
            }
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// The answer for a request the gate can't place: the plain "not found"
/// page, a `refused` audit event, and nothing passed on.
async fn refuse_unplaced(mut parts: axum::http::request::Parts) -> Response {
    crate::audit::refuse(Refusal::InvalidRequest);
    let shell = Shell::from_request_parts(&mut parts, &())
        .await
        .unwrap_or_default();
    no_store(PageError::new(shell, Problem::not_found()).into_response())
}

fn is_purge(action: Action) -> bool {
    matches!(
        action,
        Action::SecretPurge | Action::CertificatePurge | Action::KeyPurge
    )
}

/// The page that asks for a reason. `problems` is `None` the first time,
/// when the form had no reason field at all.
fn ask(
    shell: Shell,
    action: Action,
    config: &Config,
    target: &Target,
    path: &str,
    fields: &[(String, String)],
    problems: Option<Problems>,
) -> Response {
    let mut errors = FieldErrors::new();
    if let Some(p) = problems {
        if p.reason {
            errors.push(
                "reason",
                format!(
                    "Give a reason of {} to {} characters.",
                    crate::reason::MIN_REASON_CHARS,
                    crate::reason::MAX_REASON_CHARS
                ),
            );
        }
        if p.ticket {
            let pattern = config
                .reason
                .ticket
                .as_ref()
                .map(|t| t.source().to_owned())
                .unwrap_or_default();
            errors.push(
                "ticket",
                format!("Give a ticket reference that matches {pattern}."),
            );
        }
    }
    let field = |k: &str| {
        fields
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let carried: Vec<(String, String)> = fields
        .iter()
        .filter(|(k, _)| !NOT_CARRIED.contains(&k.as_str()))
        .cloned()
        .collect();
    let carry = carried.len() <= MAX_CARRIED_FIELDS
        && !holds_secret_material(action)
        && !carried.iter().any(|(k, _)| k == "value");
    let (heading, intro, button) = words(action);
    let status = if errors.is_empty() {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = ReasonPage {
        shell,
        heading,
        intro,
        button,
        action: crate::auth::return_to::sanitise(Some(path)),
        cancel: target.cancel_url(),
        fields: if carry { carried } else { Vec::new() },
        carry,
        errors,
        reason: crate::reason::clean_reason(&field("reason")).unwrap_or_default(),
        ticket: field("ticket")
            .chars()
            .take(crate::reason::MAX_TICKET_CHARS)
            .collect(),
    };
    no_store((status, render(&page)).into_response())
}

/// What the page says for each kind of action.
fn words(action: Action) -> (&'static str, &'static str, &'static str) {
    match action {
        Action::SecretReveal => (
            "Why do you need to see this value?",
            "Your organisation asks for a reason before Keyring shows a secret value. Nothing has been shown yet.",
            "Show value",
        ),
        Action::SecretCopyRead => (
            "Why are you copying this value?",
            "Your organisation asks for a reason before Keyring reads a secret value, including to copy it. Nothing has been read or copied yet.",
            "Copy value",
        ),
        Action::ShareGrant => (
            "Why are you sharing this secret?",
            "Your organisation asks for a reason before Keyring gives anyone else access to a secret. Nothing has been shared yet.",
            "Share",
        ),
        Action::CertificateDownloadPrivateKey => (
            "Why do you need the private key?",
            "Your organisation asks for a reason before Keyring downloads a private key. Nothing has been downloaded yet.",
            "Download with private key",
        ),
        _ => (
            "Why are you making this change?",
            "Your organisation asks for a reason before Keyring changes anything in a vault. Nothing has been changed yet.",
            "Continue",
        ),
    }
}

/// The vault and item a request acts on, from the route's decoded
/// parameters and the action.
struct Target {
    vault: Option<String>,
    /// `secrets`, `certificates` or `keys`.
    kind: &'static str,
    section: Section,
    name: Option<String>,
    /// True for a deleted item's page (`/-/deleted/{name}`).
    deleted: bool,
}

impl Target {
    /// `None` when there is no `vault` parameter (except for cross-vault
    /// actions such as [`Action::SecretMultiEnvSet`]), the vault isn't a vault
    /// name, or the action isn't on a secret, certificate or key. The gate
    /// refuses those. A missing or malformed item name is not a reason to
    /// refuse: routes such as `/-/new` have none, and the handler rejects
    /// a bad one after the reason check.
    fn from_route(action: Action, params: &RawPathParams) -> Option<Self> {
        if action == Action::SecretMultiEnvSet {
            return Some(Self {
                vault: None,
                kind: "secrets",
                section: Section::Environments,
                name: None,
                deleted: false,
            });
        }
        let param = |k: &str| params.iter().find(|(n, _)| *n == k).map(|(_, v)| v);
        Self::from_parts(action, param("vault")?, param("name"))
    }

    fn from_parts(action: Action, vault: &str, name: Option<&str>) -> Option<Self> {
        if !is_valid_vault_name(vault) {
            return None;
        }
        let (kind, section) = match action.item_kind()? {
            "secret" => ("secrets", Section::Secrets),
            "certificate" => ("certificates", Section::Certificates),
            "key" => ("keys", Section::Keys),
            _ => return None,
        };
        let verb = action.as_str();
        Some(Self {
            vault: Some(vault.to_owned()),
            kind,
            section,
            name: name.filter(|n| is_valid_object_name(n)).map(str::to_owned),
            deleted: verb.ends_with(".recover") || verb.ends_with(".purge"),
        })
    }

    /// Where "Cancel" goes: the item's page, the list, or Environments.
    fn cancel_url(&self) -> String {
        let Some(vault) = &self.vault else {
            return "/environments".to_owned();
        };
        let base = format!("/v/{vault}/{}", self.kind);
        match (&self.name, self.deleted) {
            (Some(n), true) => format!("{base}/-/deleted/{n}"),
            (Some(n), false) => format!("{base}/{n}"),
            (None, _) => base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_come_from_the_route() {
        let t = Target::from_parts(Action::SecretReveal, "kv-test", Some("db")).unwrap();
        assert_eq!(
            (t.vault.as_deref(), t.kind, t.name.as_deref()),
            (Some("kv-test"), "secrets", Some("db"))
        );
        assert_eq!(t.cancel_url(), "/v/kv-test/secrets/db");
        let t = Target::from_parts(Action::KeyPurge, "kv-test", Some("old")).unwrap();
        assert_eq!(t.cancel_url(), "/v/kv-test/keys/-/deleted/old");
        let t = Target::from_parts(Action::CertificateUpload, "kv-test", None).unwrap();
        assert_eq!(t.cancel_url(), "/v/kv-test/certificates");
        // A bad item name isn't used, but the request is still placed.
        let t = Target::from_parts(Action::SecretReveal, "kv-test", Some("bad name")).unwrap();
        assert_eq!(t.cancel_url(), "/v/kv-test/secrets");
        // Nothing to place: the gate refuses these.
        assert!(Target::from_parts(Action::SecretReveal, "x", Some("db")).is_none());
        assert!(Target::from_parts(Action::SecretReveal, "%6bv-test", Some("db")).is_none());
        assert!(Target::from_parts(Action::SessionSignOut, "kv-test", None).is_none());
    }
}
