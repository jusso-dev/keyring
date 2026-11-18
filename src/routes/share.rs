//! Share a secret with a colleague (#286), with `KEYRING_SHARING=true`.
//!
//! A share is a real Azure role assignment, Key Vault Secrets User on the
//! one secret, made as the person sharing ([`crate::azure::share`]). People
//! are picked by name through Microsoft Graph ([`crate::azure::graph`]).
//! Keyring keeps nothing: the Shared with panel, My shares and Revoke all
//! read Azure each time.
//!
//! - `GET  /v/{vault}/secrets/{name}/share`: the form.
//! - `POST /v/{vault}/secrets/{name}/share`: `share.grant`. Guarded like a
//!   reveal, in the same order: the reason gate (in `audited(...)`), the
//!   form token, `KEYRING_AUDIT_REQUIRED`, step-up. Then the server's own
//!   refusals, before anything reaches Azure.
//! - `GET  /v/{vault}/secrets/{name}/share/revoke`: a typed-name check.
//! - `POST /v/{vault}/secrets/{name}/share/revoke`: `share.revoke`, only
//!   for a share Keyring made, at exactly the secret's scope.
//! - `GET  /v/{vault}/share/people?q=`: the picker's JSON. Signed in only,
//!   rate limited per session, `no-store`. The query is never logged.
//! - `GET  /v/{vault}/my-access/shares`: My shares.
//!
//! With sharing off, every one of these answers "not found" (see
//! [`require_on`]) and no other page changes.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::audit::Refusal;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::authz::{self, is_guid};
use crate::azure::graph::{self, GraphProblem, Principal};
use crate::azure::pim::Outcome;
use crate::azure::secrets::now_ts;
use crate::azure::share::{self, Path as SharePath};
use crate::config::Config;
use crate::notify::share::{ShareNotice, Side};
use crate::notify::{Address, ItemKind, ItemRef, Notification, NotifyType};
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::reveal::{managed_problem, no_store};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, check_csrf, checked_name, vault_path};

/// Longest the Shared with panel and My shares wait for Azure and Graph.
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Time for the share or revoke request itself.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default end date, days from today.
pub(crate) const DEFAULT_DAYS: i64 = 7;

/// Picker searches one session may make in [`PICKER_WINDOW`].
pub(crate) const PICKER_PER_WINDOW: u32 = 30;
pub(crate) const PICKER_WINDOW: Duration = Duration::from_secs(60);
/// Most sessions the picker's rate limit tracks at once.
const PICKER_MAX_SESSIONS: usize = 10_000;

/// The roles that can make a share, named on a 403.
const WHO_CAN_SHARE: &str = "You need a role that can create role assignments on this secret or its vault: Owner, User Access Administrator, or Key Vault Data Access Administrator (which can be limited to assigning Key Vault Secrets User). Ask your admin for one of them.";

/// True when the tags hold a reveal limit (`keyring-reveal`, #261 part 2)
/// under any spelling and with any value: no value is less strict than
/// the default, so any of them refuses a share.
fn has_reveal_limit(tags: &std::collections::BTreeMap<String, String>) -> bool {
    tags.keys().any(|k| crate::reveal_limit::is_tag(k))
}

/// Middleware on every sharing route: "not found" unless
/// `KEYRING_SHARING=true`. Runs before the reason gate and the handler, so
/// with sharing off nothing else happens and no audit event is written.
pub(crate) async fn require_on(req: Request, next: Next) -> Response {
    let on = req
        .extensions()
        .get::<Arc<Config>>()
        .is_some_and(|c| c.sharing);
    if on {
        return next.run(req).await;
    }
    let shell = req
        .extensions()
        .get::<CurrentSession>()
        .map(Shell::for_session)
        .unwrap_or_default();
    no_store(PageError::new(shell, Problem::not_found()).into_response())
}

fn today() -> i64 {
    now_ts().div_euclid(86_400) * 86_400
}

/// `DD-MM-YYYY`, as the issue and the emails write a share's end date.
pub(crate) fn dmy(day: i64) -> String {
    let (y, m, d) = crate::dates::civil_from_days(day.div_euclid(86_400));
    format!("{d:02}-{m:02}-{y:04}")
}

fn form_path(vault: &str, name: &str) -> String {
    vault_path(vault, &format!("/secrets/{name}/share"))
}

fn secret_path(vault: &str, name: &str) -> String {
    vault_path(vault, &format!("/secrets/{name}"))
}

/// A refused request: a page, and the reason code on the audit event.
fn refused(
    shell: Shell,
    why: Refusal,
    status: StatusCode,
    heading: &'static str,
    msg: String,
    back: &str,
) -> Halt {
    crate::audit::refuse(why);
    no_store(
        PageError::new(shell, Problem::new(status, heading, msg).returning_to(back))
            .into_response(),
    )
    .into()
}

/// The vault's resource ID, and that it uses Azure RBAC. A vault with
/// access policies can't share one secret.
async fn rbac_vault(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, String), Halt> {
    let back = secret_path(vault, name);
    let id = match crate::routes::audit::vault_id(state, session, vault).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(PageError::new(shell, Problem::not_found()).into()),
        Err(e) => return Err(vault_ctx::azure_problem(shell, &e, Need::ListVaults, &back)),
    };
    let url = &state.config.management_url;
    match authz::vault_authorisation(&state.azure, &session.0, url, &id).await {
        Ok(a) if a.rbac => Ok((shell, id)),
        Ok(_) => Err(refused(
            shell,
            Refusal::ShareNotAllowed,
            StatusCode::CONFLICT,
            "This vault can't share one secret",
            format!(
                "{vault} uses access policies, which can only give access to every secret in the vault. Sharing needs a vault that uses Azure RBAC. Nothing was shared."
            ),
            &back,
        )),
        Err(e) => Err(vault_ctx::azure_problem(shell, &e, Need::ListVaults, &back)),
    }
}

/// The secret, refusing a certificate's backing secret and one with a
/// reveal limit on any version.
async fn shareable(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<Shell, Halt> {
    let back = secret_path(vault, name);
    let api = crate::azure::secrets::SecretsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    };
    let versions = match api.versions(name).await {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return Err(PageError::new(shell, Problem::not_found()).into()),
        Err(e) => {
            return Err(vault_ctx::azure_problem(
                shell,
                &e,
                Need::ReadSecrets,
                &back,
            ));
        }
    };
    if versions.iter().any(|v| v.managed.unwrap_or(false)) {
        return Err(managed_problem(shell, vault, name));
    }
    if versions.iter().any(|v| has_reveal_limit(v.tags())) {
        return Err(refused(
            shell,
            Refusal::ShareNotAllowed,
            StatusCode::CONFLICT,
            "This secret has a reveal limit",
            format!(
                "{name} has the keyring-reveal tag, so Keyring won't give anyone else access to read it. Nothing was shared."
            ),
            &back,
        ));
    }
    Ok(shell)
}

// ---------------------------------------------------------------------
// The form
// ---------------------------------------------------------------------

/// No `Debug`: `who` can hold a typed address.
#[derive(Default, Deserialize)]
pub(crate) struct ShareForm {
    #[serde(default)]
    csrf: String,
    /// What was typed: an email address or an object ID, or a name the
    /// picker turned into `principal`.
    #[serde(default)]
    who: String,
    /// The object ID the picker chose. Only ever used as a GUID, and
    /// confirmed through Graph.
    #[serde(default)]
    principal: String,
    /// `YYYY-MM-DD`.
    #[serde(default)]
    until: String,
}

#[derive(Template)]
#[template(path = "secrets/share.html")]
struct SharePage {
    shell: Shell,
    vault: String,
    name: String,
    who: String,
    principal: String,
    until: String,
    min_date: String,
    max_date: String,
    max_days: u32,
    errors: FieldErrors,
    picker_url: String,
}

impl SharePage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

fn page_for(
    state: &AppState,
    shell: Shell,
    vault: String,
    name: String,
    f: Option<&ShareForm>,
    errors: FieldErrors,
) -> SharePage {
    let today = today();
    let max = today + i64::from(state.config.share_max_days) * 86_400;
    let default = (today + DEFAULT_DAYS * 86_400).min(max);
    SharePage {
        picker_url: vault_path(&vault, "/share/people"),
        who: f
            .map(|f| crate::azure::pim::clean_line(&f.who, 254).unwrap_or_default())
            .unwrap_or_default(),
        principal: f
            .map(|f| f.principal.trim())
            .filter(|p| is_guid(p))
            .map(str::to_ascii_lowercase)
            .unwrap_or_default(),
        until: f
            .and_then(|f| crate::dates::parse_iso_date(&f.until))
            .map(crate::dates::iso_date)
            .unwrap_or_else(|| crate::dates::iso_date(default)),
        min_date: crate::dates::iso_date(today),
        max_date: crate::dates::iso_date(max),
        max_days: state.config.share_max_days,
        errors,
        shell,
        vault,
        name,
    }
}

pub(crate) async fn form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Secrets, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, _) = rbac_vault(&state, &session, shell, &vault, &name).await?;
    let shell = shareable(&state, &session, shell, &vault, &name).await?;
    Ok(no_store(
        render(&page_for(
            &state,
            shell,
            vault,
            name,
            None,
            FieldErrors::new(),
        ))
        .into_response(),
    ))
}

/// Who the share is for, confirmed through Graph as a user or a security
/// group in the sharer's tenant.
async fn recipient(
    state: &AppState,
    session: &CurrentSession,
    f: &ShareForm,
) -> Result<Principal, (FieldErrors, Refusal)> {
    let url = &state.config.graph_url;
    let picked = f.principal.trim();
    let typed = f.who.trim();
    let bad = |msg: &str| (FieldErrors::one("who", msg), Refusal::SharePrincipal);
    let lookup = if !picked.is_empty() {
        if !is_guid(picked) {
            return Err(bad(
                "Pick someone from the list, or type their email address or object ID.",
            ));
        }
        graph::principal_by_id(&state.azure, &session.0, url, picked).await
    } else if typed.is_empty() {
        return Err((
            FieldErrors::one("who", "Type a name, an email address or an object ID."),
            Refusal::InvalidRequest,
        ));
    } else if is_guid(typed) {
        graph::principal_by_id(&state.azure, &session.0, url, typed).await
    } else if let Ok(addr) = Address::parse(typed) {
        graph::user_by_address(&state.azure, &session.0, url, &addr).await
    } else {
        return Err(bad(
            "Pick someone from the list, or type their exact email address or object ID.",
        ));
    };
    match lookup {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(bad(
            "Keyring couldn't find a person or security group with that in your directory. Check it and try again.",
        )),
        Err(e) => Err(bad(GraphProblem::of(&e).message())),
    }
}

/// The end date from the form: today or later, and no more than
/// `KEYRING_SHARE_MAX_DAYS` away. Midnight UTC.
fn checked_until(raw: &str, max_days: u32) -> Result<i64, String> {
    let day = crate::dates::parse_iso_date(raw)
        .ok_or_else(|| "Give an end date as a real date.".to_owned())?;
    let today = today();
    if day < today {
        return Err("The end date is in the past. Pick today or a later date.".into());
    }
    if day > today + i64::from(max_days) * 86_400 {
        return Err(format!(
            "A share can last at most {max_days} days. Pick an earlier end date."
        ));
    }
    Ok(day)
}

fn form_again(
    state: &AppState,
    shell: Shell,
    vault: String,
    name: String,
    f: &ShareForm,
    errors: FieldErrors,
) -> Response {
    no_store(
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            render(&page_for(state, shell, vault, name, Some(f), errors)),
        )
            .into_response(),
    )
}

/// The problem page when Azure refused a share or revoke. Never Azure's
/// message: a 403 names the roles that can share, anything else gives
/// Azure's checked code.
fn azure_refused(shell: Shell, err: &AzureError, lead: String, back: &str) -> Halt {
    let problem = match err {
        AzureError::Status { status: 403, .. } => {
            Problem::new(StatusCode::FORBIDDEN, "Not shared", lead).with_role_hint(WHO_CAN_SHARE)
        }
        AzureError::Status { status: 409, .. } => Problem::new(
            StatusCode::CONFLICT,
            "Already shared",
            format!("{lead} They already have Key Vault Secrets User on this secret."),
        ),
        AzureError::Status { code: Some(c), .. } if c == crate::azure::pim::POLICY_FAILED => {
            use crate::azure::pim::BrokenRule as B;
            // Only the rule's name is read from Azure's message.
            let why: Vec<&str> = crate::azure::pim::broken_rules(err)
                .into_iter()
                .map(|b| match b {
                    B::Expiration => "PIM won't allow this role for that long: pick an earlier end date.",
                    B::Justification => "PIM wants a reason for this role.",
                    B::Ticketing => "PIM wants a ticket number for this role, which Keyring's share doesn't send.",
                    B::Mfa => "PIM wants you to have signed in with multifactor authentication: sign out and in again with it, then try again.",
                    B::Eligibility => "PIM's settings don't allow this assignment.",
                })
                .collect();
            let why = if why.is_empty() {
                "A PIM setting for this role refused the request.".to_owned()
            } else {
                why.join(" ")
            };
            Problem::new(StatusCode::CONFLICT, "Not shared", lead).with_hint(format!(
                "{why} Keyring doesn't make a plain role assignment instead, because that would have no end date and step round the PIM setting."
            ))
        }
        AzureError::Status { status, code, .. } => {
            let code = code
                .as_deref()
                .map(crate::audit::safe_code)
                .unwrap_or_else(|| format!("http_{status}"));
            Problem::new(StatusCode::BAD_GATEWAY, "Not shared", lead)
                .with_hint(format!("Azure answered {status} {code}."))
        }
        other => {
            let p = Problem::from_azure(other, Need::ReadSecrets);
            Problem::new(p.status, "Not shared", format!("{lead} {}", p.message))
        }
    };
    no_store(PageError::new(shell, problem.returning_to(back)).into_response()).into()
}

pub(crate) async fn grant(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<ShareForm>,
) -> PageResult {
    // As a reveal, in the same order. The reason gate ran before this.
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Secrets, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let shell = crate::routes::audit_gate::require_audit(&state, shell)?;
    let back = form_path(&vault, &name);
    let shell = crate::routes::step_up::require(
        &state,
        &session.0,
        shell,
        &back,
        &secret_path(&vault, &name),
    )?;

    // The server's own checks, before any change in Azure.
    let Some(me) = session.0.user.subject.oid.clone().filter(|o| is_guid(o)) else {
        return Err(refused(shell, Refusal::InvalidRequest, StatusCode::FORBIDDEN, "Not shared", "Keyring couldn't tell your object ID from your sign-in, so it can't share as you. Sign out and in again.".into(), &back));
    };
    let until = match checked_until(&f.until, state.config.share_max_days) {
        Ok(d) => d,
        Err(msg) => {
            crate::audit::refuse(Refusal::ShareDate);
            return Ok(form_again(
                &state,
                shell,
                vault,
                name,
                &f,
                FieldErrors::one("until", msg),
            ));
        }
    };
    let (shell, vault_id) = rbac_vault(&state, &session, shell, &vault, &name).await?;
    let shell = shareable(&state, &session, shell, &vault, &name).await?;
    let to = match recipient(&state, &session, &f).await {
        Ok(p) => p,
        Err((errors, why)) => {
            crate::audit::refuse(why);
            return Ok(form_again(&state, shell, vault, name, &f, errors));
        }
    };
    let Some(scope) = share::secret_scope(&vault_id, &name) else {
        return Err(refused(
            shell,
            Refusal::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "Not shared",
            "Keyring couldn't place this secret in Azure. Nothing was shared.".into(),
            &back,
        ));
    };
    let until_iso = crate::dates::iso_date(until);
    crate::audit::note_share(
        &scope,
        &to.id,
        Some(to.kind.as_str()),
        Some(&until_iso),
        None,
    );
    if to.id == me.to_ascii_lowercase() {
        return Err(refused(
            shell,
            Refusal::ShareToSelf,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Not shared",
            "That's you. You can't share a secret with yourself. Nothing was shared.".into(),
            &back,
        ));
    }

    // PIM first, so Azure ends it; a plain assignment if PIM can't be used.
    let g = share::Grant {
        vault_id: &vault_id,
        secret: &name,
        principal_id: &to.id,
        principal_type: to.kind.arm_type(),
        sharer_oid: &me,
        until,
    };
    let url = &state.config.management_url;
    let lead = format!("{name} wasn't shared. Nothing changed in Azure.");
    let pim = tokio::time::timeout(
        REQUEST_TIMEOUT,
        share::grant_pim(&state.azure, &session.0, url, &g),
    )
    .await;
    let (path, waiting) = match pim {
        Ok(Ok(Outcome::Done)) => (SharePath::Pim, false),
        Ok(Ok(Outcome::Waiting)) => (SharePath::Pim, true),
        Ok(Ok(Outcome::Refused)) => {
            crate::audit::end(crate::audit::Outcome::Failed, "pim_refused");
            return Err(no_store(
                PageError::new(
                    shell,
                    Problem::new(
                        StatusCode::BAD_GATEWAY,
                        "Not shared",
                        format!("PIM refused the request, so {name} wasn't shared."),
                    )
                    .returning_to(&back),
                )
                .into_response(),
            )
            .into());
        }
        Ok(Err(e)) if share::falls_back(&e) => {
            match tokio::time::timeout(
                REQUEST_TIMEOUT,
                share::grant_plain(&state.azure, &session.0, url, &g),
            )
            .await
            {
                Ok(Ok(_)) => (SharePath::Plain, false),
                Ok(Err(e)) => return Err(azure_refused(shell, &e, lead, &back)),
                Err(_) => return Err(timed_out(shell, &back)),
            }
        }
        Ok(Err(e)) => return Err(azure_refused(shell, &e, lead, &back)),
        Err(_) => return Err(timed_out(shell, &back)),
    };
    crate::audit::note_share(&scope, &to.id, None, None, Some(path.as_str()));

    // While PIM waits for an approval nobody has access yet, so nobody is
    // told they do.
    if !waiting {
        send_emails(&state, &session, &vault, &name, &to, &me, until, path).await;
    }

    let who = if to.display_name.is_empty() {
        to.id.clone()
    } else {
        to.display_name.clone()
    };
    let msg = match (path, waiting) {
        (SharePath::Pim, false) => format!(
            "Shared {name} with {who} until {}. Azure removes this access at the end of that day.",
            dmy(until)
        ),
        (SharePath::Pim, true) => format!(
            "Asked to share {name} with {who} until {}. PIM needs someone to approve it first.",
            dmy(until)
        ),
        (SharePath::Plain, _) => format!(
            "Shared {name} with {who} until {}. PIM isn't licensed in this tenant, so Keyring made a plain role assignment. Azure won't remove this access on the end date. Keyring will show it as overdue.",
            dmy(until)
        ),
    };
    let mut res = Redirect::to(&secret_path(&vault, &name)).into_response();
    flash::set(&state, &mut res, &Flash::success(msg));
    Ok(res)
}

fn timed_out(shell: Shell, back: &str) -> Halt {
    crate::audit::end(crate::audit::Outcome::Failed, "timeout");
    no_store(
        PageError::new(
            shell,
            Problem::new(StatusCode::GATEWAY_TIMEOUT, "Azure took too long", "Azure didn't answer in time. Check the Shared with list on the secret's page before you try again.").returning_to(back),
        )
        .into_response(),
    )
    .into()
}

/// The recipient's email (users with a Graph `mail` only) and the
/// sharer's receipt. Fixed text, names in their own fields, never the
/// reason or anything from Azure. Nothing here can fail the share.
#[allow(clippy::too_many_arguments)]
async fn send_emails(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
    to: &Principal,
    me: &str,
    until: i64,
    path: SharePath,
) {
    let Some(n) = state.notifier.as_deref() else {
        return;
    };
    if !n.is_on(NotifyType::Shares) {
        return;
    }
    let Some(item) = ItemRef::new(vault, ItemKind::Secret, name) else {
        return;
    };
    let by_azure = path == SharePath::Pim;
    if let Some(addr) = to.mail.clone().filter(|_| !to.kind.is_group()) {
        let _ = n.enqueue(Notification {
            kind: NotifyType::Shares,
            to: vec![addr],
            item: Some(item.clone()),
            data: ShareNotice::new(Side::Recipient, &session.0.user.name, until, by_azure),
        });
    }
    // The sharer's own address, from Graph `mail` like any recipient's.
    let own = graph::user_by_id(&state.azure, &session.0, &state.config.graph_url, me).await;
    if let Ok(Some(addr)) = own.map(|p| p.and_then(|p| p.mail)) {
        let other = if to.display_name.is_empty() {
            &to.id
        } else {
            &to.display_name
        };
        let _ = n.enqueue(Notification {
            kind: NotifyType::Shares,
            to: vec![addr],
            item: Some(item),
            data: ShareNotice::new(Side::Sharer, other, until, by_azure),
        });
    }
}

// ---------------------------------------------------------------------
// The picker
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct PeopleQuery {
    #[serde(default)]
    q: String,
}

static PICKER_USE: LazyLock<Mutex<HashMap<String, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// One more search for `session_ref`, if it is within the limit.
fn picker_allowed(session_ref: &str) -> bool {
    let mut map = PICKER_USE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if map.len() >= PICKER_MAX_SESSIONS {
        map.retain(|_, (start, _)| now.duration_since(*start) < PICKER_WINDOW);
        if map.len() >= PICKER_MAX_SESSIONS && !map.contains_key(session_ref) {
            return false;
        }
    }
    let e = map.entry(session_ref.to_owned()).or_insert((now, 0));
    if now.duration_since(e.0) >= PICKER_WINDOW {
        *e = (now, 0);
    }
    e.1 += 1;
    e.1 <= PICKER_PER_WINDOW
}

fn json(status: StatusCode, v: serde_json::Value) -> Response {
    let mut res = (status, v.to_string()).into_response();
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn result_row(p: &Principal) -> serde_json::Value {
    serde_json::json!({
        "id": p.id,
        "name": p.display_name,
        "mail": p.mail.as_ref().map(Address::as_str).unwrap_or_default(),
        "upn": p.upn,
        "type": p.kind.label(),
    })
}

/// The picker's JSON: up to ten people and ten security groups, each with
/// only `id`, `name`, `mail`, `upn` and `type`.
pub(crate) async fn people(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(q): Query<PeopleQuery>,
) -> PageResult {
    let (_, _) = vault_ctx::path_vault(&session, shell, Section::Secrets, &vault)?;
    if !picker_allowed(&session.0.audit_ref) {
        return Ok(json(
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({"results": [], "problem": "busy", "message": "Too many searches. Wait a minute and try again."}),
        ));
    }
    let Some(q) = graph::checked_query(&q.q) else {
        return Ok(json(StatusCode::OK, serde_json::json!({"results": []})));
    };
    let found = graph::search(&state.azure, &session.0, &state.config.graph_url, &q).await;
    let results: Vec<serde_json::Value> = found
        .people
        .iter()
        .chain(found.groups.iter())
        .map(result_row)
        .collect();
    let mut body = serde_json::json!({ "results": results });
    if let Some(p) = found.problem.or(found.groups_problem) {
        body["problem"] = p.code().into();
        body["message"] = if found.problem.is_none() && p == GraphProblem::NoConsent {
            "Groups can't be searched: the app registration needs GroupMember.Read.All with admin consent. People are listed.".into()
        } else {
            p.message().into()
        };
    }
    Ok(json(StatusCode::OK, body))
}

// ---------------------------------------------------------------------
// Shared with, on the secret's page
// ---------------------------------------------------------------------

/// One person or group with a role on exactly this secret.
#[derive(Clone)]
pub(crate) struct SharedRow {
    pub principal_id: String,
    pub name: String,
    pub kind: String,
    pub role: String,
    /// Made by Keyring: who shared it and until when.
    pub shared_by: String,
    pub until: String,
    pub via_pim: bool,
    pub overdue: bool,
    /// Where Revoke goes, for one Keyring made.
    pub revoke_url: String,
}

/// The Shared with panel.
#[derive(Clone, Default)]
pub(crate) struct SharedWith {
    /// The vault uses Azure RBAC, so the Share button is offered.
    pub can_share: bool,
    pub rows: Vec<SharedRow>,
    pub note: Option<String>,
}

/// The panel for a secret, or `None` with sharing off.
pub(crate) async fn for_item(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
) -> Option<SharedWith> {
    if !state.config.sharing {
        return None;
    }
    // Its own task, so these reads can't change the page's audit draft.
    let (s, sess, v, n) = (
        state.clone(),
        session.clone(),
        vault.to_owned(),
        name.to_owned(),
    );
    let task = tokio::spawn(async move { read_shared_with(&s, &sess, &v, &n).await });
    Some(match tokio::time::timeout(READ_TIMEOUT, task).await {
        Ok(Ok(p)) => p,
        _ => SharedWith {
            can_share: true,
            note: Some("Keyring couldn't read who this secret is shared with in time. Refresh the page to try again.".into()),
            ..SharedWith::default()
        },
    })
}

fn kind_label(t: &str) -> String {
    match t.to_ascii_lowercase().as_str() {
        "user" => "Person",
        "group" => "Group",
        "serviceprincipal" => "App or managed identity",
        "" => "Type not given",
        _ => "Other",
    }
    .to_owned()
}

async fn read_shared_with(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
) -> SharedWith {
    let note = |m: &str| SharedWith {
        can_share: true,
        note: Some(m.to_owned()),
        ..SharedWith::default()
    };
    let vault_id = match crate::routes::audit::vault_id(state, session, vault).await {
        Ok(Some(id)) => id,
        _ => {
            return note(
                "Keyring couldn't look up this vault in Azure, so it can't show who this secret is shared with.",
            );
        }
    };
    let url = &state.config.management_url;
    match authz::vault_authorisation(&state.azure, &session.0, url, &vault_id).await {
        Ok(a) if !a.rbac => {
            return SharedWith {
                can_share: false,
                note: Some(
                    "This vault uses access policies, so one secret can't be shared on its own."
                        .into(),
                ),
                ..SharedWith::default()
            };
        }
        Ok(_) => {}
        Err(_) => {
            return note(
                "Keyring couldn't read this vault's settings, so it can't show who this secret is shared with.",
            );
        }
    }
    let Some(scope) = share::secret_scope(&vault_id, name) else {
        return note("Keyring couldn't place this secret in Azure.");
    };
    let (assigned, pim) = tokio::join!(
        share::assignments(&state.azure, &session.0, url, &scope, "atScope()"),
        share::pim_shares(&state.azure, &session.0, url, &scope, "atScope()"),
    );
    let mut out = SharedWith {
        can_share: true,
        ..SharedWith::default()
    };
    let assigned: Vec<share::Assignment> = match assigned {
        Ok(a) => a
            .into_iter()
            .filter(|a| a.scope.eq_ignore_ascii_case(&scope))
            .collect(),
        Err(_) => {
            out.note = Some("You can't read the role assignments on this secret, so Keyring can't show who it's shared with. That doesn't mean nobody has access.".into());
            return out;
        }
    };
    let pim: Vec<share::PimShare> = pim
        .map(|p| {
            p.into_iter()
                .filter(|s| s.scope.eq_ignore_ascii_case(&scope))
                .collect()
        })
        .unwrap_or_default();
    let mut ids: Vec<String> = assigned.iter().map(|a| a.principal_id.clone()).collect();
    ids.extend(
        assigned
            .iter()
            .filter_map(|a| a.keyring.as_ref().map(|k| k.0.clone())),
    );
    ids.extend(pim.iter().map(|p| p.sharer.clone()));
    ids.sort();
    ids.dedup();
    let names = graph::names(&state.azure, &session.0, &state.config.graph_url, &ids).await;
    let name_of = |id: &str| {
        names
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.display_name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.to_owned())
    };
    let today = today();
    let mut rows: Vec<SharedRow> = Vec::new();
    for a in &assigned {
        let is_su = a.role == share::SECRETS_USER;
        // A PIM share past its date has ended: an assignment still there
        // was made by someone else, and isn't Keyring's to revoke.
        let pim_share = pim
            .iter()
            .find(|p| p.principal_id == a.principal_id && is_su && p.until >= today);
        let mut row = SharedRow {
            principal_id: a.principal_id.clone(),
            name: name_of(&a.principal_id),
            kind: kind_label(&a.principal_type),
            role: if is_su {
                "Key Vault Secrets User".into()
            } else {
                a.role.clone()
            },
            shared_by: String::new(),
            until: String::new(),
            via_pim: false,
            overdue: false,
            revoke_url: String::new(),
        };
        if let (true, Some((by, until))) = (is_su, &a.keyring) {
            row.shared_by = name_of(by);
            row.until = dmy(*until);
            row.overdue = *until < today;
            row.revoke_url = format!("{}/revoke?assignment={}", form_path(vault, name), a.name);
        } else if let Some(p) = pim_share {
            row.shared_by = name_of(&p.sharer);
            row.until = dmy(p.until);
            row.via_pim = true;
            row.revoke_url = format!(
                "{}/revoke?principal={}",
                form_path(vault, name),
                p.principal_id
            );
        }
        rows.push(row);
    }
    // A PIM share that hasn't shown up as an assignment yet (waiting for
    // approval or being set up).
    for p in &pim {
        if !rows.iter().any(|r| r.principal_id == p.principal_id) && p.until >= today {
            rows.push(SharedRow {
                principal_id: p.principal_id.clone(),
                name: name_of(&p.principal_id),
                kind: kind_label(&p.principal_type),
                role: "Key Vault Secrets User".into(),
                shared_by: name_of(&p.sharer),
                until: dmy(p.until),
                via_pim: true,
                overdue: false,
                revoke_url: format!(
                    "{}/revoke?principal={}",
                    form_path(vault, name),
                    p.principal_id
                ),
            });
        }
    }
    out.rows = rows;
    out
}

// ---------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RevokeQuery {
    /// A plain assignment's name.
    #[serde(default)]
    assignment: String,
    /// The principal of a PIM share.
    #[serde(default)]
    principal: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RevokeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm_name: String,
    #[serde(default)]
    assignment: String,
    #[serde(default)]
    principal: String,
}

/// A share Keyring made on exactly this secret, found in Azure.
enum Found {
    Plain(share::Assignment),
    Pim(share::PimShare),
}

impl Found {
    fn principal(&self) -> &str {
        match self {
            Self::Plain(a) => &a.principal_id,
            Self::Pim(p) => &p.principal_id,
        }
    }
}

/// Look the share up in Azure: a plain assignment by its name with
/// Keyring's exact description, or a PIM share Keyring requested, for
/// Key Vault Secrets User at exactly the secret's scope.
async fn find_share(
    state: &AppState,
    session: &CurrentSession,
    scope: &str,
    assignment: &str,
    principal: &str,
) -> Result<Option<Found>, AzureError> {
    let url = &state.config.management_url;
    if is_guid(assignment) {
        let all = share::assignments(&state.azure, &session.0, url, scope, "atScope()").await?;
        return Ok(all
            .into_iter()
            .find(|a| {
                a.name.eq_ignore_ascii_case(assignment)
                    && a.scope.eq_ignore_ascii_case(scope)
                    && a.role == share::SECRETS_USER
                    && a.keyring.is_some()
            })
            .map(Found::Plain));
    }
    if is_guid(principal) {
        let all = share::pim_shares(&state.azure, &session.0, url, scope, "atScope()").await?;
        return Ok(all
            .into_iter()
            .find(|p| {
                p.principal_id.eq_ignore_ascii_case(principal)
                    && p.scope.eq_ignore_ascii_case(scope)
                    // Ended shares aren't revoked: what is there now was
                    // made by someone else.
                    && p.until >= today()
            })
            .map(Found::Pim));
    }
    Ok(None)
}

#[derive(Template)]
#[template(path = "secrets/share_revoke.html")]
struct RevokePage {
    shell: Shell,
    vault: String,
    name: String,
    who: String,
    assignment: String,
    principal: String,
    error: Option<String>,
}

async fn revoke_target(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
    assignment: &str,
    principal: &str,
) -> Result<(Shell, String, Found), Halt> {
    let back = secret_path(vault, name);
    let (shell, vault_id) = rbac_vault(state, session, shell, vault, name).await?;
    let Some(scope) = share::secret_scope(&vault_id, name) else {
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    match find_share(state, session, &scope, assignment.trim(), principal.trim()).await {
        Ok(Some(f)) => Ok((shell, scope, f)),
        Ok(None) => Err(refused(shell, Refusal::InvalidRequest, StatusCode::NOT_FOUND, "No such share", "Keyring couldn't find a share it made on this secret for that. It may already be gone. Nothing was changed.".into(), &back)),
        Err(e) => Err(vault_ctx::azure_problem(shell, &e, Need::ListVaults, &back)),
    }
}

pub(crate) async fn revoke_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Query(q): Query<RevokeQuery>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Secrets, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, _, found) = revoke_target(
        &state,
        &session,
        shell,
        &vault,
        &name,
        &q.assignment,
        &q.principal,
    )
    .await?;
    let pid = found.principal().to_owned();
    let names = graph::names(
        &state.azure,
        &session.0,
        &state.config.graph_url,
        std::slice::from_ref(&pid),
    )
    .await;
    let who = names
        .into_iter()
        .next()
        .map(|p| p.display_name)
        .filter(|n| !n.is_empty())
        .unwrap_or(pid);
    let (assignment, principal) = match &found {
        Found::Plain(a) => (a.name.clone(), String::new()),
        Found::Pim(p) => (String::new(), p.principal_id.clone()),
    };
    Ok(no_store(
        render(&RevokePage {
            shell,
            vault,
            name,
            who,
            assignment,
            principal,
            error: None,
        })
        .into_response(),
    ))
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<RevokeForm>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Secrets, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    // As a grant, in the same order: the reason gate ran before this.
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let shell = crate::routes::audit_gate::require_audit(&state, shell)?;
    let back = secret_path(&vault, &name);
    let shell = crate::routes::step_up::require(&state, &session.0, shell, &back, &back)?;
    if f.confirm_name.trim() != name {
        crate::audit::refuse(Refusal::TypedNameMismatch);
        let page = RevokePage {
            shell,
            vault,
            who: String::new(),
            assignment: f
                .assignment
                .trim()
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == '-')
                .take(36)
                .collect(),
            principal: f
                .principal
                .trim()
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == '-')
                .take(36)
                .collect(),
            error: Some(crate::routes::confirm::ConfirmError::mismatch(
                &name, "revoked",
            )),
            name,
        };
        return Ok(no_store(
            (StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response(),
        ));
    }
    let (shell, scope, found) = revoke_target(
        &state,
        &session,
        shell,
        &vault,
        &name,
        &f.assignment,
        &f.principal,
    )
    .await?;
    let Some(me) = session.0.user.subject.oid.clone().filter(|o| is_guid(o)) else {
        return Err(refused(
            shell,
            Refusal::InvalidRequest,
            StatusCode::FORBIDDEN,
            "Not revoked",
            "Keyring couldn't tell your object ID from your sign-in. Sign out and in again.".into(),
            &back,
        ));
    };
    let path = match &found {
        Found::Plain(_) => SharePath::Plain,
        Found::Pim(_) => SharePath::Pim,
    };
    crate::audit::note_share(&scope, found.principal(), None, None, Some(path.as_str()));
    let (vault_id, url) = (
        scope
            .rsplit_once("/secrets/")
            .map(|(v, _)| v.to_owned())
            .unwrap_or_default(),
        state.config.management_url.clone(),
    );
    let lead = format!("The share of {name} wasn't revoked. Nothing changed in Azure.");
    let done = match &found {
        Found::Plain(a) => tokio::time::timeout(
            REQUEST_TIMEOUT,
            share::revoke_plain(&state.azure, &session.0, &url, &vault_id, &name, &a.name),
        )
        .await
        .map(|r| r.map(|_| Outcome::Done)),
        Found::Pim(p) => {
            tokio::time::timeout(
                REQUEST_TIMEOUT,
                share::revoke_pim(
                    &state.azure,
                    &session.0,
                    &url,
                    &vault_id,
                    &name,
                    &p.principal_id,
                    &me,
                ),
            )
            .await
        }
    };
    match done {
        Ok(Ok(Outcome::Refused)) => {
            crate::audit::end(crate::audit::Outcome::Failed, "pim_refused");
            Err(no_store(
                PageError::new(
                    shell,
                    Problem::new(StatusCode::BAD_GATEWAY, "Not revoked", lead).returning_to(&back),
                )
                .into_response(),
            )
            .into())
        }
        Ok(Ok(_)) => {
            let mut res = Redirect::to(&back).into_response();
            flash::set(
                &state,
                &mut res,
                &Flash::success(format!(
                    "Revoked the share of {name}. Azure can take a few minutes to apply it."
                )),
            );
            Ok(res)
        }
        Ok(Err(e)) => Err(azure_refused(shell, &e, lead, &back)),
        Err(_) => Err(timed_out(shell, &back)),
    }
}

// ---------------------------------------------------------------------
// My shares
// ---------------------------------------------------------------------

pub(crate) struct MineRow {
    pub secret: String,
    pub secret_url: String,
    /// The other person: who shared it with me, or who I shared it with.
    pub other: String,
    pub until: String,
    pub via_pim: bool,
    pub overdue: bool,
}

#[derive(Template)]
#[template(path = "pim/my_shares.html")]
struct MySharesPage {
    shell: Shell,
    vault: String,
    with_me: Vec<MineRow>,
    by_me: Vec<MineRow>,
    notes: Vec<String>,
}

pub(crate) async fn my_shares(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    let (s, sess, v) = (state.clone(), session.clone(), vault.clone());
    let task = tokio::spawn(async move { read_mine(&s, &sess, &v).await });
    let (with_me, by_me, notes) = match tokio::time::timeout(READ_TIMEOUT * 2, task).await {
        Ok(Ok(Some(m))) => m,
        Ok(Ok(None)) => return Err(PageError::new(shell, Problem::not_found()).into()),
        _ => (
            Vec::new(),
            Vec::new(),
            vec!["Azure took too long to answer, so nothing is listed. Try again.".to_owned()],
        ),
    };
    Ok(render(&MySharesPage {
        shell,
        vault,
        with_me,
        by_me,
        notes,
    })
    .into_response())
}

type Mine = (Vec<MineRow>, Vec<MineRow>, Vec<String>);

async fn read_mine(state: &AppState, session: &CurrentSession, vault: &str) -> Option<Mine> {
    let Some(me) = session
        .0
        .user
        .subject
        .oid
        .clone()
        .filter(|o| is_guid(o))
        .map(|o| o.to_ascii_lowercase())
    else {
        return Some((
            Vec::new(),
            Vec::new(),
            vec![
                "Keyring couldn't tell your object ID from your sign-in. Sign out and in again."
                    .into(),
            ],
        ));
    };
    let vault_id = crate::routes::audit::vault_id(state, session, vault)
        .await
        .ok()??;
    let url = &state.config.management_url;
    let s = &session.0;
    let mine_filter = format!("principalId%20eq%20'{me}'");
    let (assigned_to_me, all_here, active, requested) = tokio::join!(
        share::assignments(&state.azure, s, url, &vault_id, &mine_filter),
        share::assignments(&state.azure, s, url, &vault_id, ""),
        crate::azure::pim::my_active(&state.azure, s, url, &vault_id),
        share::pim_shares(&state.azure, s, url, &vault_id, "asRequestor()"),
    );
    let mut notes = Vec::new();
    let today = today();
    let mut with_me: Vec<(String, Option<String>, Option<i64>, bool)> = Vec::new();
    match assigned_to_me {
        Ok(list) => {
            for a in list
                .into_iter()
                .filter(|a| a.principal_id == me && a.role == share::SECRETS_USER)
            {
                if let Some(secret) = share::secret_in(&a.scope, &vault_id) {
                    let (by, until) = a
                        .keyring
                        .map(|(b, u)| (Some(b), Some(u)))
                        .unwrap_or((None, None));
                    with_me.push((secret, by, until, false));
                }
            }
        }
        Err(_) => notes
            .push("Role assignments to you aren't listed: Keyring couldn't read them.".to_owned()),
    }
    match active {
        Ok(list) => {
            for a in list.into_iter().filter(|a| a.role == share::SECRETS_USER) {
                if let Some(secret) = share::secret_in(&a.scope, &vault_id) {
                    if a.span.when(now_ts()) == crate::azure::pim::When::Over {
                        continue;
                    }
                    match with_me.iter_mut().find(|(s, ..)| s.eq_ignore_ascii_case(&secret)) {
                        Some(row) => row.3 = true,
                        None => with_me.push((secret, None, a.span.ends.map(|e| e.div_euclid(86_400) * 86_400), true)),
                    }
                }
            }
        }
        Err(_) => notes.push("PIM assignments to you aren't listed: PIM isn't available here, or Keyring couldn't read them.".to_owned()),
    }
    let mut by_me: Vec<(String, String, i64, bool)> = Vec::new();
    match all_here {
        Ok(list) => {
            for a in list {
                let Some((by, until)) = a.keyring.clone() else { continue };
                if by != me || a.role != share::SECRETS_USER {
                    continue;
                }
                if let Some(secret) = share::secret_in(&a.scope, &vault_id) {
                    by_me.push((secret, a.principal_id, until, false));
                }
            }
        }
        Err(_) => notes.push("Shares you made without PIM aren't listed: Keyring couldn't read the role assignments here.".to_owned()),
    }
    match requested {
        Ok(list) => {
            for p in list.into_iter().filter(|p| p.sharer == me && p.until >= today) {
                if let Some(secret) = share::secret_in(&p.scope, &vault_id) {
                    by_me.push((secret, p.principal_id, p.until, true));
                }
            }
        }
        Err(_) => notes.push("Shares you made through PIM aren't listed: PIM isn't available here, or Keyring couldn't read them.".to_owned()),
    }
    let mut ids: Vec<String> = with_me.iter().filter_map(|r| r.1.clone()).collect();
    ids.extend(by_me.iter().map(|r| r.1.clone()));
    ids.sort();
    ids.dedup();
    let names = graph::names(&state.azure, s, &state.config.graph_url, &ids).await;
    let name_of = |id: &str| {
        names
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.display_name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.to_owned())
    };
    let row = |secret: String, other: String, until: Option<i64>, via_pim: bool| MineRow {
        secret_url: secret_path(vault, &secret),
        secret,
        other,
        until: until.map(dmy).unwrap_or_else(|| "No end date".into()),
        via_pim,
        overdue: !via_pim && until.is_some_and(|u| u < today),
    };
    let with_me = with_me
        .into_iter()
        .map(|(secret, by, until, via_pim)| {
            row(
                secret,
                by.as_deref()
                    .map(name_of)
                    .unwrap_or_else(|| "Not known".into()),
                until,
                via_pim,
            )
        })
        .collect();
    let by_me = by_me
        .into_iter()
        .map(|(secret, to, until, via_pim)| row(secret, name_of(&to), Some(until), via_pim))
        .collect();
    Some((with_me, by_me, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_checked_on_the_server() {
        let t = today();
        let iso = |d: i64| crate::dates::iso_date(t + d * 86_400);
        assert_eq!(checked_until(&iso(0), 30), Ok(t));
        assert_eq!(checked_until(&iso(30), 30), Ok(t + 30 * 86_400));
        assert!(checked_until(&iso(31), 30).is_err());
        assert!(checked_until(&iso(-1), 30).is_err());
        assert!(checked_until("tomorrow", 30).is_err());
        assert!(checked_until("2026-02-31", 30).is_err());
    }

    #[test]
    fn reveal_limits_of_any_spelling_refuse() {
        let tags = |k: &str, v: &str| [(k.to_owned(), v.to_owned())].into_iter().collect();
        assert!(has_reveal_limit(&tags("keyring-reveal", "copy-only")));
        assert!(has_reveal_limit(&tags(" Keyring-Reveal ", "")));
        assert!(has_reveal_limit(&tags("keyring-reveal", "anything")));
        assert!(!has_reveal_limit(&tags("env", "prod")));
    }

    #[test]
    fn the_picker_is_rate_limited_per_session() {
        let me = format!("test-{}", crate::audit::new_uuid());
        for _ in 0..PICKER_PER_WINDOW {
            assert!(picker_allowed(&me));
        }
        assert!(!picker_allowed(&me));
        assert!(picker_allowed(&format!("other-{me}")));
    }
}
