//! Request access (#258): when Key Vault refuses and no PIM eligibility is
//! offered, a person can ask the vault's owners for the role the 403 page
//! names. Keyring emails them (see `crate::notify::access`), keeps no
//! request and grants nothing.
//!
//! Shown only with email on and `access-requests` in
//! `KEYRING_NOTIFY_TYPES`; otherwise the 403 page and My access are as
//! they were, and the form's address is "not found".
//!
//! Nothing from the form chooses who gets the email or what it links to:
//! the role is a GUID looked up in Keyring's own list, the vault is the one
//! in the address (the form token is bound to it), the item is a kind from
//! a fixed list and a name that passes Key Vault's rules, the recipients
//! are the vault's `keyring-owners` tag (read as the person from Resource
//! Graph) or the admins, plus the requester's own sign-in name from the
//! session. Every accepted request gets the same confirmation, whatever
//! happened to the email.

use std::time::Duration;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::audit::{Outcome as AuditOutcome, Refusal};
use crate::auth::CurrentSession;
use crate::auth::return_to;
use crate::azure::authz::is_guid;
use crate::notify::access::{AccessRequestNotice, Request};
use crate::notify::{Address, ItemKind, Notification, NotifyType};
use crate::routes::assets::render;
use crate::routes::error::{Halt, PageError, PageResult, Problem};
use crate::routes::forms::FieldErrors;
use crate::routes::pim::{OFFERED_NEEDS, is_offered_role, offered_name, role_for, safe_back};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, check_csrf, is_valid_object_name, vault_path};

/// Longest wait for the vault's tags from Resource Graph. Past it, the
/// request goes to the admins.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// True when access requests are on: email on, and `access-requests` in
/// `KEYRING_NOTIFY_TYPES`.
pub(crate) fn is_on(state: &AppState) -> bool {
    state
        .notifier
        .as_ref()
        .is_some_and(|n| n.is_on(NotifyType::AccessRequests))
}

/// The item kinds a request can name, as posted, with their path part.
fn kind_of(raw: &str) -> Option<ItemKind> {
    match raw {
        "secret" => Some(ItemKind::Secret),
        "certificate" => Some(ItemKind::Certificate),
        "key" => Some(ItemKind::Key),
        _ => None,
    }
}

/// The item a local path under the vault is about, such as
/// `/v/kv/secrets/db` for the secret `db`. `None` for anything else.
pub(crate) fn item_of(vault: &str, path: &str) -> Option<(ItemKind, String)> {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let rest = path.strip_prefix(&vault_path(vault, "/"))?;
    let (kind, name) = rest.split_once('/')?;
    let kind = match kind {
        "secrets" => ItemKind::Secret,
        "certificates" => ItemKind::Certificate,
        "keys" => ItemKind::Key,
        _ => return None,
    };
    is_valid_object_name(name).then(|| (kind, name.to_owned()))
}

/// The request form's address. `role` must be one of the roles Keyring
/// names; anything else gives the address with no role, which the form
/// refuses. `back` must already be a local path under the vault.
pub(crate) fn request_url(vault: &str, role: &str, back: &str) -> String {
    let role = if is_guid(role) && is_offered_role(role) {
        role
    } else {
        ""
    };
    let item = item_of(vault, back)
        .map(|(k, n)| format!("&kind={}&name={n}", k.as_str()))
        .unwrap_or_default();
    format!(
        "{}?role={role}{item}&back={}",
        vault_path(vault, "/my-access/request"),
        return_to::encode(back)
    )
}

/// Each Key Vault role Keyring names, once, with its name: for My access.
pub(crate) fn roles() -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    for n in OFFERED_NEEDS {
        if let Some(g) = role_for(n)
            && !out.iter().any(|(r, _)| *r == g)
        {
            out.push((g, n.role()));
        }
    }
    out
}

#[derive(Deserialize, Default)]
pub(super) struct RequestQuery {
    #[serde(default)]
    role: String,
    #[serde(default)]
    kind: String,
    /// The item's name. Called `name`, as on other forms.
    #[serde(default)]
    name: String,
    #[serde(default)]
    back: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct RequestForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
    /// `vault` or `item`.
    #[serde(default)]
    scope: String,
    #[serde(default)]
    kind: String,
    /// The item's name. Called `name`, as on other forms.
    #[serde(default)]
    name: String,
    #[serde(default)]
    back: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    ticket: String,
}

#[derive(Template)]
#[template(path = "access_request/form.html")]
struct FormPage {
    shell: Shell,
    vault: String,
    role: &'static str,
    role_name: &'static str,
    /// `(kind, name)` when the request can be for one item.
    item: Option<(&'static str, String)>,
    whole_vault: bool,
    back: String,
    reason: String,
    ticket: String,
    errors: FieldErrors,
}

impl FormPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

#[derive(Template)]
#[template(path = "access_request/sent.html")]
struct SentPage {
    shell: Shell,
    role_name: &'static str,
    back: String,
}

#[derive(Template)]
#[template(path = "access_request/limited.html")]
struct LimitedPage {
    shell: Shell,
    role_name: &'static str,
    back: String,
}

/// What a form or address names, checked: the role and, when given, the
/// item. `None` refuses.
struct Named {
    role: &'static str,
    role_name: &'static str,
    item: Option<(ItemKind, String)>,
}

fn named(role: &str, kind: &str, item: &str) -> Option<Named> {
    let role = role.trim().to_ascii_lowercase();
    if !is_guid(&role) {
        return None;
    }
    let role_name = offered_name(&role)?;
    // The GUID as Keyring's own list writes it, never the posted text.
    let role = roles().into_iter().find(|(g, _)| *g == role)?.0;
    let item = match (kind.trim(), item.trim()) {
        ("", "") => None,
        (k, n) if is_valid_object_name(n) => Some((kind_of(k)?, n.to_owned())),
        _ => return None,
    };
    Some(Named {
        role,
        role_name,
        item,
    })
}

fn off(shell: Shell) -> Halt {
    crate::audit::refuse(Refusal::InvalidRequest);
    PageError::new(shell, Problem::not_found()).into()
}

pub(super) async fn form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(q): Query<RequestQuery>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    if !is_on(&state) {
        return Err(off(shell));
    }
    let Some(n) = named(&q.role, &q.kind, &q.name) else {
        return Err(off(shell));
    };
    let back = safe_back(&vault, q.back.as_deref());
    Ok(form_page(
        shell,
        vault,
        &n,
        back,
        true,
        "",
        "",
        FieldErrors::new(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn form_page(
    shell: Shell,
    vault: String,
    n: &Named,
    back: String,
    whole_vault: bool,
    reason: &str,
    ticket: &str,
    errors: FieldErrors,
) -> Response {
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = FormPage {
        shell,
        vault,
        role: n.role,
        role_name: n.role_name,
        item: n.item.as_ref().map(|(k, name)| (k.as_str(), name.clone())),
        whole_vault,
        back,
        reason: crate::reason::clean_reason(reason).unwrap_or_default(),
        ticket: ticket
            .chars()
            .filter(|c| !crate::reason::is_unsafe(*c))
            .take(crate::reason::MAX_TICKET_CHARS)
            .collect(),
        errors,
    };
    (status, render(&page)).into_response()
}

pub(super) async fn send(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(form): Form<RequestForm>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    // The token first, as on every form: a forged post is refused the
    // same way whether or not access requests are on.
    let shell = check_csrf(&session, &vault, &form.csrf, shell)?;
    let Some(notifier) = state
        .notifier
        .clone()
        .filter(|n| n.is_on(NotifyType::AccessRequests))
    else {
        return Err(off(shell));
    };
    // The scope is the vault, or the one item the form named.
    let for_item = match form.scope.as_str() {
        "vault" => false,
        "item" => true,
        _ => return Err(off(shell)),
    };
    let Some(mut n) = named(&form.role, &form.kind, &form.name) else {
        return Err(off(shell));
    };
    if for_item && n.item.is_none() {
        return Err(off(shell));
    }
    let shown_item = n.item.is_some();
    if !for_item {
        n.item = None;
    }
    let back = safe_back(&vault, Some(&form.back));
    if let Some((_, name)) = &n.item {
        crate::audit::note_item(name);
    }
    let kind = n.item.as_ref().map(|(k, _)| k.as_str());
    crate::audit::note_access_request(n.role, None, kind, None);

    let given = match state
        .config
        .reason
        .check_request(&form.reason, &form.ticket)
    {
        Ok(g) => g,
        Err(p) => {
            crate::audit::refuse(Refusal::ReasonRequired);
            let mut errors = FieldErrors::new();
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
                errors.push(
                    "ticket",
                    match &state.config.reason.ticket {
                        Some(t) => format!(
                            "Leave the ticket empty, or give one that matches {}.",
                            t.source()
                        ),
                        None => format!(
                            "Use up to {} characters with no spaces.",
                            crate::reason::MAX_TICKET_CHARS
                        ),
                    },
                );
            }
            if !for_item && shown_item {
                n.item = named(&form.role, &form.kind, &form.name).and_then(|x| x.item);
            }
            return Ok(form_page(
                shell,
                vault,
                &n,
                back,
                !for_item,
                &form.reason,
                &form.ticket,
                errors,
            ));
        }
    };
    crate::audit::note_access_request(n.role, None, kind, Some(&given));

    // One request per person, vault and role an hour.
    let who = session
        .0
        .user
        .subject
        .oid
        .clone()
        .map(|o| o.to_ascii_lowercase())
        .or_else(|| session.0.user.username.clone().map(|u| u.to_lowercase()));
    let Some(who) = who else {
        return Err(off(shell));
    };
    // The vault in lower case: the address keeps the capitals typed, and
    // each spelling must not be its own request.
    let key = format!("{who}|{}|{}", vault.to_ascii_lowercase(), n.role);
    if !state.access_requests.take(&key) {
        crate::audit::refuse(Refusal::RateLimited);
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            render(&LimitedPage {
                shell,
                role_name: n.role_name,
                back,
            }),
        )
            .into_response());
    }

    // The vault as the person sees it in Resource Graph. A vault they
    // can't see is "not found"; one that can't be read goes to the admins.
    let read = tokio::time::timeout(
        READ_TIMEOUT,
        crate::azure::vaults::list_vaults(&state.azure, &session.0, &state.config.management_url),
    )
    .await;
    let seen = match read {
        Ok(Ok(all)) => match all
            .into_iter()
            .find(|v| v.name.eq_ignore_ascii_case(&vault))
        {
            Some(v) => Some(v),
            None => {
                state.access_requests.release(&key);
                crate::audit::refuse(Refusal::InvalidRequest);
                return Err(PageError::new(shell, Problem::not_found()).into());
            }
        },
        Ok(Err(_)) | Err(_) => {
            tracing::info!(
                "access request: the vault's tags couldn't be read; sending to the admins"
            );
            None
        }
    };
    let vault_id = seen
        .as_ref()
        .map(|v| v.id.clone())
        .filter(|id| crate::notify::expiry::checked_topic(id, &vault));
    let owners: Vec<Address> = seen
        .as_ref()
        .map(|v| crate::owner::vault_owners(&v.tags))
        .unwrap_or_default()
        .into_iter()
        .filter(|a| notifier.allows(a))
        .collect();
    let to = if owners.is_empty() {
        notifier.admins().to_vec()
    } else {
        owners
    };
    let upn = session.0.user.username.clone().unwrap_or_default();
    let scope = vault_id.as_ref().map(|id| match &n.item {
        Some((k, name)) => format!("{id}/{}/{name}", k.path()),
        None => id.clone(),
    });
    crate::audit::note_access_request(n.role, scope.as_deref(), kind, Some(&given));
    let when = crate::dates::format_datetime(crate::azure::secrets::now_ts());
    let notice = AccessRequestNotice::new(&Request {
        requester: if upn.is_empty() {
            "an unnamed person"
        } else {
            &upn
        },
        role: n.role_name,
        vault: &vault,
        item: n.item.as_ref().map(|(k, name)| (k.as_str(), name.as_str())),
        reason: &given.reason,
        ticket: given.ticket.as_deref(),
        ticket_pattern: state.config.reason.ticket.is_some(),
        when: &when,
        vault_id: vault_id.as_deref(),
        base_url: &state.config.base_url,
    });
    // The requester's copy is its own email, so it never shows who the
    // owners or admins are.
    let copy = Address::parse(&upn)
        .ok()
        .filter(|me| !to.iter().any(|a| a.mailbox_key() == me.mailbox_key()))
        .map(|me| (me, notice.clone().for_requester()));
    let queued = notifier.enqueue(Notification {
        kind: NotifyType::AccessRequests,
        to,
        item: None,
        data: notice,
    });
    if let (crate::notify::Enqueued::Queued { .. }, Some((me, data))) = (&queued, copy) {
        let _ = notifier.enqueue(Notification {
            kind: NotifyType::AccessRequests,
            to: vec![me],
            item: None,
            data,
        });
    }
    // Recorded on the event; the person sees the same page either way.
    match queued {
        crate::notify::Enqueued::Queued { .. } => crate::audit::succeed(),
        other => crate::audit::end(
            AuditOutcome::Failed,
            match other {
                crate::notify::Enqueued::QueueFull => "queue_full",
                crate::notify::Enqueued::RateLimited => "recipient_rate_limited",
                crate::notify::Enqueued::NoRecipients => "no_recipients",
                _ => "not_sent",
            },
        ),
    }
    Ok(render(&SentPage {
        shell,
        role_name: n.role_name,
        back,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "4633458b-17de-408a-b874-0445c86b69e6";

    #[test]
    fn only_named_roles_and_checked_items() {
        assert!(named(R, "", "").is_some());
        assert!(named(&R.to_ascii_uppercase(), "secret", "db").is_some());
        for (role, kind, item) in [
            ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "", ""), // Owner
            ("Key Vault Secrets User", "", ""),
            (R, "vault", "db"),
            (R, "secret", "bad name"),
            (R, "secret", "a/../b"),
            (R, "", "db"),
            (R, "secret", ""),
        ] {
            assert!(named(role, kind, item).is_none(), "{role} {kind} {item}");
        }
        assert_eq!(roles().len(), 6);
    }

    #[test]
    fn items_come_from_the_vault_path_only() {
        assert_eq!(
            item_of("kv", "/v/kv/secrets/db?x=1"),
            Some((ItemKind::Secret, "db".into()))
        );
        assert!(item_of("kv", "/v/kv/secrets").is_none());
        assert!(item_of("kv", "/v/kv/secrets/db/versions").is_none());
        assert!(item_of("kv", "/v/other/secrets/db").is_none());
        assert!(item_of("kv", "/v/kv/audit/x").is_none());
        let u = request_url("kv", R, "/v/kv/keys/app-key");
        assert_eq!(
            u,
            format!(
                "/v/kv/my-access/request?role={R}&kind=key&name=app-key&back=%2Fv%2Fkv%2Fkeys%2Fapp-key"
            )
        );
        assert!(request_url("kv", "x&y=1", "/v/kv/secrets").contains("?role=&back="));
    }
}
