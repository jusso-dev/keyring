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

use std::sync::Arc;
use std::time::SystemTime;

use askama::Template;
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, Request};
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
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::is_valid_object_name;

/// Most fields carried over to the reason page. More than any of
/// Keyring's own forms post.
const MAX_CARRIED_FIELDS: usize = 64;

/// Fields the reason page never carries: its own, and a secret value,
/// which is never written back into a page.
const NOT_CARRIED: [&str; 3] = ["csrf", "reason", "ticket"];

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
    /// False when the form held a secret value: the person goes back to
    /// the form instead.
    carry: bool,
    errors: FieldErrors,
    reason: String,
    ticket: String,
}

/// Run before an audited route's handler. Does nothing unless the
/// settings ask for a reason for `action`.
pub(crate) async fn gate(action: Action, req: Request, next: Next) -> Response {
    let Some(config) = req.extensions().get::<Arc<Config>>().cloned() else {
        return next.run(req).await;
    };
    if !config.reason.needs(action) {
        return next.run(req).await;
    }
    let Some(session) = req.extensions().get::<CurrentSession>().cloned() else {
        return next.run(req).await;
    };
    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().path().to_owned(), |u| u.path().to_owned());
    let Some(target) = Target::from_path(&path) else {
        return next.run(req).await;
    };
    // Every audited form is URL-encoded. Anything else can't carry a
    // reason, so it's refused here rather than left for the handler.
    let is_form = req
        .headers()
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

    let (mut parts, body) = req.into_parts();
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
    let csrf_ok = session
        .0
        .csrf_matches_vault(field("csrf").unwrap_or_default(), &target.vault);
    let step_up_ok = !crate::routes::step_up::guards(action)
        || config
            .step_up
            .check(&session.0.sign_in_facts(), SystemTime::now())
            .is_ok();
    let purge_ok = !is_purge(action) || config.allow_purge;
    if csrf_ok && step_up_ok && purge_ok {
        let asked = field("reason").is_some();
        match config.reason.check(
            field("reason").unwrap_or_default(),
            field("ticket").unwrap_or_default(),
        ) {
            Ok(given) => crate::audit::note_reason(&given),
            Err(problems) => {
                crate::audit::refuse(Refusal::ReasonRequired);
                crate::audit::note_vault(&target.vault);
                if let Some(name) = &target.name {
                    crate::audit::note_item(name);
                }
                let shell = Shell::from_request_parts(&mut parts, &())
                    .await
                    .unwrap_or_default()
                    .for_vault(&target.vault, &session)
                    .at(target.section);
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
    let carry = carried.len() <= MAX_CARRIED_FIELDS && !carried.iter().any(|(k, _)| k == "value");
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

/// The vault and item a request acts on, read from its path.
struct Target {
    vault: String,
    /// `secrets`, `certificates` or `keys`.
    kind: &'static str,
    section: Section,
    name: Option<String>,
    /// True for a deleted item's page (`/-/deleted/{name}`).
    deleted: bool,
}

impl Target {
    /// `/v/{vault}/{kind}/{name}/...` or `/v/{vault}/{kind}/-/...`.
    fn from_path(path: &str) -> Option<Self> {
        let mut segs = path.strip_prefix("/v/")?.split('/');
        let vault = segs.next().filter(|v| is_valid_vault_name(v))?;
        let (kind, section) = match segs.next()? {
            "secrets" => ("secrets", Section::Secrets),
            "certificates" => ("certificates", Section::Certificates),
            "keys" => ("keys", Section::Keys),
            _ => return None,
        };
        let (name, deleted) = match (segs.next(), segs.next(), segs.next()) {
            (Some("-"), Some("deleted"), Some(n)) => (Some(n), true),
            (Some("-"), _, _) | (None, _, _) => (None, false),
            (Some(n), _, _) => (Some(n), false),
        };
        Some(Self {
            vault: vault.to_owned(),
            kind,
            section,
            name: name.filter(|n| is_valid_object_name(n)).map(str::to_owned),
            deleted,
        })
    }

    /// Where "Cancel" goes: the item's page, or the list.
    fn cancel_url(&self) -> String {
        let base = format!("/v/{}/{}", self.vault, self.kind);
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
    fn targets_come_from_the_path() {
        let t = Target::from_path("/v/kv-test/secrets/db/reveal").unwrap();
        assert_eq!(
            (t.vault.as_str(), t.kind, t.name.as_deref()),
            ("kv-test", "secrets", Some("db"))
        );
        assert_eq!(t.cancel_url(), "/v/kv-test/secrets/db");
        let t = Target::from_path("/v/kv-test/keys/-/deleted/old/purge").unwrap();
        assert_eq!(t.cancel_url(), "/v/kv-test/keys/-/deleted/old");
        let t = Target::from_path("/v/kv-test/certificates/-/upload/confirm").unwrap();
        assert_eq!(t.name, None);
        assert_eq!(t.cancel_url(), "/v/kv-test/certificates");
        let t = Target::from_path("/v/kv-test/secrets/bad%20name/reveal").unwrap();
        assert_eq!(t.cancel_url(), "/v/kv-test/secrets");
        assert!(Target::from_path("/auth/sign-out").is_none());
        assert!(Target::from_path("/v/x/secrets/db/reveal").is_none());
        assert!(Target::from_path("/v/kv-test/audit").is_none());
    }
}
