//! PIM role activation for a vault (#203): the "Activate" offer on a 403
//! page, the activation form, and the vault's My access page with
//! Deactivate.
//!
//! Everything goes through ARM as the signed-in person, with their
//! on-behalf-of Management token (`crate::azure::pim`). Keyring keeps no
//! request state: what is on, eligible or waiting for approval is read
//! back from ARM on every page.
//!
//! The offer never changes a 403 page unless it finds something to offer.
//! It looks only when the 403 is a Key Vault RBAC refusal that names a
//! role (`Problem::pim_need`), runs in its own task so its ARM calls don't
//! touch the request's audit event, and gives up after [`LOOKUP_TIMEOUT`].
//! Any failure leaves the page exactly as it was.

use std::collections::HashMap;
use std::time::Duration;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::audit::{Outcome as AuditOutcome, Refusal};
use crate::auth::CurrentSession;
use crate::auth::return_to;
use crate::auth::session::Session;
use crate::azure::authz::{RoleDefinition, applies_at, is_guid};
use crate::azure::pim::{
    self, Active, BrokenRule, DEFAULT_MAX_MINUTES, Eligibility, HARD_MAX_MINUTES, Outcome, Pending,
    Policy, When,
};
use crate::azure::{AzureError, TokenError};
use crate::routes::access::Origin;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, NextStep, Offer, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::FieldErrors;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, check_csrf, vault_path};

/// Longest the 403 page waits to find an eligible role, and longest the
/// activation form and My access wait for their reads. The same as the
/// Access section on item pages.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Time for the activation or deactivation request itself.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Shortest and longest justification, in characters, as for the reveal
/// reason (#205).
pub(crate) const MIN_JUSTIFICATION: usize = 5;
pub(crate) const MAX_JUSTIFICATION: usize = 200;
/// Longest ticket system and ticket number.
pub(crate) const MAX_TICKET: usize = 64;

/// Where people manage their PIM requests in the portal.
pub(crate) const PIM_PORTAL: &str =
    "https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/azurerbac";

/// The built-in Key Vault role each 403 page names, by its GUID. Microsoft
/// lists them in "Azure built-in roles for Security".
pub(crate) fn role_for(need: Need) -> Option<&'static str> {
    Some(match need {
        Need::ReadSecrets => "4633458b-17de-408a-b874-0445c86b69e6",
        Need::ManageSecrets => "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
        Need::ReadCertificates | Need::ReadKeys => "21090545-7ca7-4776-b22c-e363652d74d2",
        Need::ExportCertificate => "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba",
        Need::ManageCertificates => "a4417e6f-fecd-4de8-b567-7b0420556985",
        Need::ManageKeys => "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
        Need::ListVaults | Need::ReadAuditLogs => return None,
    })
}

/// A 403 page that a PIM role might lift, carried on the response from
/// [`PageError`]'s `into_response` to [`offer_layer`].
#[derive(Clone)]
pub(crate) struct OfferPending(pub(crate) Box<PageError>);

/// Run inside the session check. If the response is a 403 page that could
/// be lifted by an eligible PIM role, look for one, and if found show the
/// same page with "Activate" added. Otherwise the response is returned
/// untouched.
pub(super) async fn offer_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let session = req.extensions().get::<CurrentSession>().cloned();
    let mut res = next.run(req).await;
    let Some(OfferPending(pending)) = res.extensions_mut().remove::<OfferPending>() else {
        return res;
    };
    let (Some(session), Some(need)) = (session, pending.problem.pim_need) else {
        return res;
    };
    let Some(vault) = pending.shell.vault.as_ref().map(|v| v.name.clone()) else {
        return res;
    };
    let Some(role) = role_for(need) else {
        return res;
    };
    // Its own task: the request's audit draft is task-local, so these ARM
    // calls can't change the event the request writes.
    let task = {
        let (state, vault) = (state.clone(), vault.clone());
        tokio::spawn(async move { eligible_here(&state, &session, &vault, role).await })
    };
    let abort = task.abort_handle();
    let found = match tokio::time::timeout(LOOKUP_TIMEOUT, task).await {
        Ok(Ok(Some(e))) => Some(e),
        Ok(_) => None,
        Err(_) => {
            abort.abort();
            tracing::info!("PIM eligibility lookup timed out; no Activate offered");
            None
        }
    };
    let back = match &pending.problem.next {
        NextStep::Retry(p) => p.clone(),
        _ => vault_path(&vault, "/secrets"),
    };
    let Some(found) = found else {
        // No PIM offer: "Request access", when access requests are on.
        // Otherwise the page is exactly as it was.
        if !crate::routes::access_request::is_on(&state) {
            return res;
        }
        let mut page = *pending;
        page.problem.request = Some(Offer {
            role: need.role(),
            url: crate::routes::access_request::request_url(
                &vault,
                role,
                &safe_back(&vault, Some(&back)),
            ),
        });
        return page.into_response();
    };
    let mut page = *pending;
    page.problem.offer = Some(Offer {
        role: need.role(),
        url: activate_url(&vault, &found.role, Some(&Shown::of(&found)), &back),
    });
    page.into_response()
}

/// The person's eligibility for `role` at or above `vault`, if any. Any
/// failure is `None`.
async fn eligible_here(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    role: &str,
) -> Option<Eligibility> {
    let vault_id = super::audit::vault_id(state, session, vault).await.ok()??;
    let all = pim::my_eligibilities(
        &state.azure,
        &session.0,
        &state.config.management_url,
        &vault_id,
    )
    .await
    .map_err(|e| tracing::info!(error = %e, "PIM eligibility lookup failed"))
    .ok()?;
    pick(all, &vault_id, role)
}

/// The eligibility for `role` that reaches `vault_id`: the one nearest
/// the vault, so the role is turned on for as little as possible.
///
/// Nearness is by kind of scope, never by the length of its ID. A
/// management group's ID says nothing about what it holds, and Keyring
/// can't cheaply check that one contains the vault's subscription, so a
/// management group (and the tenant root, and anything Keyring can't name)
/// is used only when nothing nearer is on offer. ARM returned it for a
/// query at the vault, and ARM refuses the request if it doesn't apply.
fn pick(all: Vec<Eligibility>, vault_id: &str, role: &str) -> Option<Eligibility> {
    let now = crate::azure::secrets::now_ts();
    all.into_iter()
        .filter(|e| started(e, now))
        .filter(|e| e.role.eq_ignore_ascii_case(role) && applies_at(&e.scope, vault_id))
        .min_by_key(|e| nearness(Origin::of(&e.scope, vault_id)))
}

/// An eligibility that applies now. ARM also lists ones that start later,
/// and one whose times can't be read is not offered.
fn started(e: &Eligibility, now: i64) -> bool {
    e.span.when(now) == When::Now
}

/// Smaller is nearer the vault. Item-scoped eligibility comes after the
/// vault's own: turning a role on for one item wouldn't lift a refusal on
/// another, and the form doesn't know which item the person was on.
fn nearness(origin: Origin) -> u8 {
    match origin {
        Origin::Vault => 0,
        Origin::ResourceGroup => 1,
        Origin::Subscription => 2,
        Origin::Item => 3,
        Origin::ManagementGroup => 4,
        Origin::Root => 5,
        Origin::Above => 6,
    }
}

/// True for a role Keyring will turn on or off: only the built-in Key
/// Vault roles its own 403 pages name. Owner, Contributor and every other
/// role are left to PIM in the portal, whatever the address or form says.
pub(crate) fn is_offered_role(role: &str) -> bool {
    OFFERED_NEEDS
        .iter()
        .filter_map(|n| role_for(*n))
        .any(|g| g.eq_ignore_ascii_case(role))
}

/// The name of an offered role, as its 403 page writes it.
pub(crate) fn offered_name(role: &str) -> Option<&'static str> {
    OFFERED_NEEDS
        .iter()
        .find(|n| role_for(**n).is_some_and(|g| g.eq_ignore_ascii_case(role)))
        .map(|n| n.role())
}

/// Every need a 403 page can name a role for.
pub(crate) const OFFERED_NEEDS: [Need; 7] = [
    Need::ReadSecrets,
    Need::ManageSecrets,
    Need::ReadCertificates,
    Need::ReadKeys,
    Need::ExportCertificate,
    Need::ManageCertificates,
    Need::ManageKeys,
];

/// Which eligibility a form or link is for: its scope and its schedule
/// ID. Only ever a key to find that same eligibility in a fresh read from
/// ARM. The scope a request is sent to always comes from ARM's answer,
/// never from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shown {
    scope: String,
    schedule: String,
}

impl Shown {
    fn of(e: &Eligibility) -> Self {
        Self {
            scope: e.scope.clone(),
            schedule: e.schedule_id.clone(),
        }
    }

    /// From an address or a form. `None` unless both are plain ARM values.
    fn parse(scope: &str, schedule: &str) -> Option<Self> {
        let (scope, schedule) = (scope.trim(), schedule.trim());
        (pim::is_safe_scope(scope) && pim::is_safe_id(schedule)).then(|| Self {
            scope: scope.to_owned(),
            schedule: schedule.to_owned(),
        })
    }

    fn is(&self, e: &Eligibility) -> bool {
        e.scope.eq_ignore_ascii_case(&self.scope)
            && e.schedule_id.eq_ignore_ascii_case(&self.schedule)
    }
}

/// The activation form's address. `back` must already be a local path.
/// `role` goes in only when it is one of the roles Keyring offers (so a
/// GUID and nothing else); anything else gives the form with no role,
/// which says there is nothing to activate. `shown` names the eligibility
/// the link is for, so the form opens on that one and not another.
pub(crate) fn activate_url(vault: &str, role: &str, shown: Option<&Shown>, back: &str) -> String {
    let role = if is_offered_role(role) { role } else { "" };
    let which = shown
        .filter(|_| !role.is_empty())
        .map(|s| {
            format!(
                "&scope={}&schedule={}",
                return_to::encode(&s.scope),
                return_to::encode(&s.schedule)
            )
        })
        .unwrap_or_default();
    format!(
        "{}?role={role}{which}&back={}",
        vault_path(vault, "/my-access/activate"),
        return_to::encode(back)
    )
}

/// `back` if it is a local path under this vault, else the vault's My
/// access page.
pub(crate) fn safe_back(vault: &str, back: Option<&str>) -> String {
    let b = return_to::sanitise(back);
    if b.starts_with(&vault_path(vault, "/")) {
        b
    } else {
        vault_path(vault, "/my-access")
    }
}

// ---------------------------------------------------------------------
// The activation form
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ActivateQuery {
    #[serde(default)]
    role: String,
    /// The eligibility a link is for. See [`Shown`].
    #[serde(default)]
    scope: String,
    #[serde(default)]
    schedule: String,
    #[serde(default)]
    back: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct ActivateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
    /// The eligibility the form showed. See [`Shown`].
    #[serde(default)]
    scope: String,
    #[serde(default)]
    schedule: String,
    #[serde(default)]
    back: String,
    #[serde(default)]
    minutes: String,
    #[serde(default)]
    justification: String,
    #[serde(default)]
    ticket_system: String,
    #[serde(default)]
    ticket_number: String,
}

/// What the form shows and checks against, read from ARM each time.
struct Ready {
    eligibility: Eligibility,
    role_name: String,
    /// `None` when PIM's settings for the role couldn't be read.
    policy: Option<Policy>,
    origin: Origin,
    /// The eligibility asked for (`Shown`) is no longer there or has
    /// changed, so this is the nearest one now. Nothing may be sent for
    /// it until the person has seen it and asked again.
    changed: bool,
}

impl Ready {
    fn max_minutes(&self) -> u32 {
        self.policy
            .as_ref()
            .and_then(|p| p.max_minutes)
            .unwrap_or(DEFAULT_MAX_MINUTES)
            .clamp(1, HARD_MAX_MINUTES)
    }

    /// Asked for unless PIM's settings were read and don't ask for it.
    fn wants_justification(&self) -> bool {
        self.policy.as_ref().is_none_or(|p| p.justification)
    }

    fn wants_ticket(&self) -> bool {
        self.policy.as_ref().is_some_and(|p| p.ticket)
    }
}

#[derive(Template)]
#[template(path = "pim/activate.html")]
struct ActivatePage<'a> {
    shell: Shell,
    vault: String,
    ready: &'a Ready,
    back: String,
    form: ActivateForm,
    errors: FieldErrors,
    durations: Vec<(u32, String)>,
}

impl ActivatePage<'_> {
    fn scope_words(&self) -> String {
        scope_words(self.ready.origin, &self.vault)
    }

    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }

    fn is_selected(&self, minutes: &u32) -> bool {
        self.form.minutes == minutes.to_string()
    }
}

/// "the vault kv-prod", "its resource group", ...
fn scope_words(origin: Origin, vault: &str) -> String {
    match origin {
        Origin::Vault => format!("the vault {vault}"),
        Origin::Item => "one item in this vault".into(),
        Origin::ResourceGroup => "the vault's whole resource group".into(),
        Origin::Subscription => "the vault's whole subscription".into(),
        Origin::ManagementGroup => "a whole management group".into(),
        Origin::Root => "the whole tenant".into(),
        Origin::Above => "a scope above the vault".into(),
    }
}

/// Choices up to `max` minutes: 30 minutes, then whole hours, and `max`
/// itself.
fn durations(max: u32) -> Vec<(u32, String)> {
    let mut out: Vec<u32> = [30, 60, 120, 240, 480, 720, 1440]
        .into_iter()
        .filter(|m| *m <= max)
        .collect();
    if !out.contains(&max) {
        out.push(max);
    }
    out.into_iter().map(|m| (m, minutes_words(m))).collect()
}

/// "30 minutes", "1 hour", "2 hours 30 minutes".
pub(crate) fn minutes_words(m: u32) -> String {
    let (h, rest) = (m / 60, m % 60);
    let hours = match h {
        0 => String::new(),
        1 => "1 hour".into(),
        n => format!("{n} hours"),
    };
    let mins = match rest {
        0 => String::new(),
        1 => "1 minute".into(),
        n => format!("{n} minutes"),
    };
    [hours, mins]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read the eligibility and PIM's settings for `role`, within the time
/// limit. `Err` is a page to show.
async fn ready(
    state: &AppState,
    session: &CurrentSession,
    shell: &Shell,
    vault: &str,
    role: &str,
    shown: Option<&Shown>,
    back: &str,
) -> Result<Ready, Halt> {
    let not_eligible = || -> Halt {
        PageError::new(
            shell.clone(),
            Problem::new(
                StatusCode::NOT_FOUND,
                "Nothing to activate",
                "You don't have an eligible PIM assignment of this role that reaches this vault, or Keyring couldn't read it. Nothing was changed.",
            )
            .with_hint("Eligible roles are set up in Privileged Identity Management. Ask your admin for an eligible assignment, or for the role itself.")
            .with_next(NextStep::Go { url: back.to_owned(), label: "Back" }),
        )
        .into()
    };
    // Only the Key Vault roles Keyring names, checked before any call.
    if !is_guid(role) || !is_offered_role(role) {
        crate::audit::refuse(Refusal::InvalidRequest);
        return Err(not_eligible());
    }
    let read = async {
        let vault_id = super::audit::vault_id(state, session, vault).await?;
        let Some(vault_id) = vault_id else {
            return Ok(None);
        };
        let url = &state.config.management_url;
        let all = pim::my_eligibilities(&state.azure, &session.0, url, &vault_id).await?;
        // The one the form or link was for, if it is still there for this
        // role and still reaches the vault. Otherwise the nearest one now,
        // marked as changed so the caller shows it instead of using it.
        let same = shown.and_then(|s| {
            all.iter()
                .find(|e| {
                    s.is(e)
                        && e.role.eq_ignore_ascii_case(role)
                        && applies_at(&e.scope, &vault_id)
                        && started(e, crate::azure::secrets::now_ts())
                })
                .cloned()
        });
        let changed = shown.is_some() && same.is_none();
        let Some(e) = same.or_else(|| pick(all, &vault_id, role)) else {
            return Ok(None);
        };
        let (policy, def) = tokio::join!(
            pim::policy(&state.azure, &session.0, url, &e.scope, &e.role),
            crate::azure::authz::role_definition(&state.azure, &session.0, url, &vault_id, &e.role),
        );
        let policy = policy
            .map_err(|err| tracing::info!(error = %err, "PIM settings not read"))
            .ok()
            .flatten();
        let role_name = def
            .ok()
            .map(|d| d.role_name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| e.role.clone());
        Ok::<_, AzureError>(Some(Ready {
            origin: Origin::of(&e.scope, &vault_id),
            eligibility: e,
            role_name,
            policy,
            changed,
        }))
    };
    match tokio::time::timeout(LOOKUP_TIMEOUT, read).await {
        Ok(Ok(Some(r))) => Ok(r),
        Ok(Ok(None)) => Err(not_eligible()),
        Ok(Err(e @ AzureError::Token(_))) => Err(PageError::new(
            shell.clone(),
            Problem::from_azure(&e, Need::ReadSecrets).returning_to(back),
        )
        .into()),
        Ok(Err(e)) => {
            tracing::info!(error = %e, "PIM eligibility read failed");
            Err(not_eligible())
        }
        Err(_) => {
            crate::audit::end(AuditOutcome::Failed, "timeout");
            Err(PageError::new(
                shell.clone(),
                Problem::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Azure took too long",
                    "Keyring couldn't read your eligible roles in time. Nothing was changed. Try again.",
                ),
            )
            .into())
        }
    }
}

/// Shown when the eligibility a form or link was for has gone or changed.
const CHANGED: &str = "Your eligible roles changed since this page was opened. This is what you can turn on now. Check where it applies, then select Activate again. Nothing was turned on.";

fn activate_page(
    shell: Shell,
    vault: String,
    ready: &Ready,
    back: String,
    form: ActivateForm,
    errors: FieldErrors,
) -> Response {
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = ActivatePage {
        durations: durations(ready.max_minutes()),
        shell,
        vault,
        ready,
        back,
        form,
        errors,
    };
    (status, render(&page)).into_response()
}

pub(super) async fn activate_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(q): Query<ActivateQuery>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    let back = safe_back(&vault, q.back.as_deref());
    let shown = Shown::parse(&q.scope, &q.schedule);
    let here = activate_url(&vault, q.role.trim(), shown.as_ref(), &back);
    let shell = crate::routes::step_up::require(&state, &session.0, shell, &here, &back)?;
    let ready = ready(
        &state,
        &session,
        &shell,
        &vault,
        q.role.trim(),
        shown.as_ref(),
        &back,
    )
    .await?;
    let form = ActivateForm {
        role: ready.eligibility.role.clone(),
        back: back.clone(),
        minutes: ready.max_minutes().min(60).to_string(),
        ..ActivateForm::default()
    };
    let mut errors = FieldErrors::new();
    if ready.changed {
        errors.push("", CHANGED);
    }
    Ok(activate_page(shell, vault, &ready, back, form, errors))
}

/// What the person typed, checked. Never trusted from the form: the
/// maximum comes from PIM's settings read again here.
struct Checked {
    minutes: u32,
    justification: Option<String>,
    ticket_system: Option<String>,
    ticket_number: Option<String>,
}

fn check(form: &ActivateForm, ready: &Ready) -> Result<Checked, FieldErrors> {
    let mut errors = FieldErrors::new();
    let max = ready.max_minutes();
    let minutes = match form.minutes.trim().parse::<u32>() {
        Ok(m) if (1..=max).contains(&m) => m,
        Ok(m) if m > max => {
            errors.push(
                "minutes",
                format!(
                    "PIM allows this role for up to {}. Pick a shorter time.",
                    minutes_words(max)
                ),
            );
            0
        }
        _ => {
            errors.push("minutes", "Pick how long you need the role for.");
            0
        }
    };
    let text = |raw: &str, max: usize| -> Result<Option<String>, ()> {
        if raw.trim().is_empty() {
            return Ok(None);
        }
        pim::clean_line(raw, max).map(Some).ok_or(())
    };
    let justification = match text(&form.justification, MAX_JUSTIFICATION) {
        Ok(Some(j)) if j.chars().count() >= MIN_JUSTIFICATION => Some(j),
        Ok(None) if !ready.wants_justification() => None,
        Ok(None) => {
            errors.push(
                "justification",
                "Say why you need the role. PIM asks for it.",
            );
            None
        }
        _ => {
            errors.push(
                "justification",
                format!("Use {MIN_JUSTIFICATION} to {MAX_JUSTIFICATION} characters of plain text."),
            );
            None
        }
    };
    let ticket_system = text(&form.ticket_system, MAX_TICKET).unwrap_or_else(|()| {
        errors.push(
            "ticket_system",
            format!("Use up to {MAX_TICKET} characters of plain text."),
        );
        None
    });
    let ticket_number = match text(&form.ticket_number, MAX_TICKET) {
        Ok(Some(n)) => Some(n),
        Ok(None) if ready.wants_ticket() => {
            errors.push("ticket_number", "Give the ticket number. PIM asks for one.");
            None
        }
        Ok(None) => None,
        Err(()) => {
            errors.push(
                "ticket_number",
                format!("Use up to {MAX_TICKET} characters of plain text."),
            );
            None
        }
    };
    if ticket_system.is_some()
        && ticket_number.is_none()
        && !errors.error_for("ticket_number").is_some()
    {
        errors.push(
            "ticket_number",
            "Give the ticket number as well as the system.",
        );
    }
    if errors.is_empty() {
        Ok(Checked {
            minutes,
            justification,
            ticket_system,
            ticket_number,
        })
    } else {
        Err(errors)
    }
}

#[derive(Template)]
#[template(path = "pim/result.html")]
struct ResultPage {
    shell: Shell,
    heading: &'static str,
    role_name: String,
    scope: String,
    outcome: Outcome,
    /// ARM's status or error code, for a refusal. Never its message.
    code: String,
    minutes: String,
    /// The role was already on: this request changed nothing.
    already_on: bool,
    approvers: Vec<(String, String)>,
    back: String,
    portal: &'static str,
}

impl ResultPage {
    fn is_done(&self) -> bool {
        self.outcome == Outcome::Done
    }

    fn is_waiting(&self) -> bool {
        self.outcome == Outcome::Waiting
    }
}

pub(super) async fn activate(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(form): Form<ActivateForm>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    let shell = check_csrf(&session, &vault, &form.csrf, shell)?;
    let back = safe_back(&vault, Some(&form.back));
    // Which eligibility the form showed. A post without one (or with one
    // that isn't a plain ARM value) can't say what the person agreed to,
    // so it is treated as changed: the form is shown again, nothing sent.
    let shown = Shown::parse(&form.scope, &form.schedule);
    let here = activate_url(&vault, form.role.trim(), shown.as_ref(), &back);
    let shell = crate::routes::step_up::require(&state, &session.0, shell, &here, &back)?;
    let Some(principal) = session.0.user.subject.oid.clone().filter(|o| is_guid(o)) else {
        crate::audit::refuse(Refusal::InvalidRequest);
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::FORBIDDEN,
                "Keyring can't tell who you are in Entra",
                "Your sign-in didn't include your Entra object ID, which PIM needs. Nothing was changed. Sign out and in again.",
            ),
        )
        .into());
    };
    let ready = ready(
        &state,
        &session,
        &shell,
        &vault,
        form.role.trim(),
        shown.as_ref(),
        &back,
    )
    .await?;
    let e = &ready.eligibility;
    // Never fall back to another scope: if what the form showed isn't
    // exactly what ARM lists now, show the current choice and stop.
    if ready.changed || shown.is_none() {
        crate::audit::note_role_request(&e.role, &e.scope, None, None, None);
        crate::audit::end(AuditOutcome::Refused, "eligibility_changed");
        let mut errors = FieldErrors::new();
        errors.push("", CHANGED);
        return Ok(activate_page(shell, vault, &ready, back, form, errors));
    }
    let checked = match check(&form, &ready) {
        Ok(c) => c,
        Err(errors) => {
            crate::audit::note_role_request(&e.role, &e.scope, None, None, None);
            crate::audit::refuse(Refusal::InvalidRequest);
            return Ok(activate_page(shell, vault, &ready, back, form, errors));
        }
    };
    let duration = pim::iso_duration(checked.minutes);
    let ticket = checked
        .ticket_number
        .as_ref()
        .map(|n| match &checked.ticket_system {
            Some(s) => format!("{s} {n}"),
            None => n.clone(),
        });
    crate::audit::note_role_request(
        &e.role,
        &e.scope,
        Some(&duration),
        checked.justification.as_deref(),
        ticket.as_deref(),
    );
    let request = pim::Activation {
        principal_id: &principal,
        eligibility: e,
        minutes: checked.minutes,
        justification: checked.justification.as_deref(),
        ticket_system: checked.ticket_system.as_deref(),
        ticket_number: checked.ticket_number.as_deref(),
    };
    let sent = tokio::time::timeout(
        REQUEST_TIMEOUT,
        pim::activate(
            &state.azure,
            &session.0,
            &state.config.management_url,
            &request,
        ),
    )
    .await;
    let result = |outcome: Outcome, heading: &'static str, code: String| ResultPage {
        shell: shell.clone(),
        heading,
        role_name: ready.role_name.clone(),
        scope: scope_words(ready.origin, &vault),
        outcome,
        code,
        minutes: minutes_words(checked.minutes),
        already_on: false,
        approvers: ready
            .policy
            .as_ref()
            .map(|p| p.approvers.clone())
            .unwrap_or_default(),
        back: back.clone(),
        portal: PIM_PORTAL,
    };
    match sent {
        Err(_) => {
            crate::audit::end(AuditOutcome::Failed, "timeout");
            Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Azure took too long",
                    "PIM didn't answer in time. The request may still have gone through: check My access before trying again.",
                )
                .with_next(NextStep::Go {
                    url: vault_path(&vault, "/my-access"),
                    label: "Open My access",
                }),
            )
            .into())
        }
        Ok(Ok(status)) => {
            session.0.forget_permissions();
            Ok(match Outcome::of(&status) {
                Outcome::Done => {
                    render(&result(Outcome::Done, "Role turned on", status)).into_response()
                }
                Outcome::Waiting => {
                    crate::audit::end(AuditOutcome::Success, &status);
                    render(&result(Outcome::Waiting, "Waiting for approval", status))
                        .into_response()
                }
                Outcome::Refused => {
                    crate::audit::end(AuditOutcome::Denied, &status);
                    (
                        StatusCode::FORBIDDEN,
                        render(&result(
                            Outcome::Refused,
                            "PIM didn't turn the role on",
                            status,
                        )),
                    )
                        .into_response()
                }
            })
        }
        Ok(Err(err)) => {
            // Every refusal and failure is recorded as what ARM said, so
            // none of the pages below can read as a success. "Already on"
            // is the one answer that isn't a failure.
            let already_on = matches!(
                &err,
                AzureError::Status { code, .. } if code.as_deref() == Some("RoleAssignmentExists")
            );
            if !already_on {
                end_with_azure(&err);
            }
            if let Some(claims) = pim::claims_challenge(&err) {
                return Err(confirm_page(&session.0, shell, &claims, &here, &back));
            }
            let broken = pim::broken_rules(&err);
            if !broken.is_empty() && !broken.contains(&BrokenRule::Eligibility) {
                let mut errors = FieldErrors::new();
                for b in broken {
                    match b {
                        BrokenRule::Expiration => errors.push("minutes", "PIM won't allow this role for that long. Pick a shorter time."),
                        BrokenRule::Justification => errors.push("justification", "PIM wants a reason for this role."),
                        BrokenRule::Ticketing => errors.push("ticket_number", "PIM wants a ticket number for this role."),
                        BrokenRule::Mfa => errors.push("minutes", "PIM wants you to have signed in with multifactor authentication. Sign out and in again with it, then try again."),
                        BrokenRule::Eligibility => {}
                    }
                }
                return Ok(activate_page(shell, vault, &ready, back, form, errors));
            }
            match &err {
                AzureError::Status { code, .. }
                    if code.as_deref() == Some("RoleAssignmentExists") =>
                {
                    // The request set no end time, so the page names none.
                    let mut page = result(Outcome::Done, "This role is already on", String::new());
                    page.minutes = String::new();
                    page.already_on = true;
                    Ok(render(&page).into_response())
                }
                AzureError::Status {
                    status: 400..=499,
                    code,
                    ..
                } => Ok((
                    StatusCode::FORBIDDEN,
                    render(&result(
                        Outcome::Refused,
                        "PIM didn't turn the role on",
                        code.clone()
                            .map(|c| crate::audit::safe_code(&c))
                            .unwrap_or_default(),
                    )),
                )
                    .into_response()),
                _ => Err(PageError::new(
                    shell,
                    Problem::from_azure(&err, Need::ReadSecrets).returning_to(&here),
                )
                .into()),
            }
        }
    }
}

/// Record how a refused or failed ARM call ended on the request's audit
/// event: `denied` for a 401 or 403, `failed` for anything else, with
/// ARM's error code (never its message). Without this a refusal answered
/// with a page or redirect that isn't an error status would be recorded
/// as a success.
fn end_with_azure(err: &AzureError) {
    let (outcome, code) = match err {
        AzureError::Status { status, code, .. } => (
            if matches!(status, 401 | 403) {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failed
            },
            code.clone().unwrap_or_else(|| format!("http_{status}")),
        ),
        AzureError::Token(_) => (AuditOutcome::Denied, "token".to_owned()),
        _ => (AuditOutcome::Failed, "network".to_owned()),
    };
    crate::audit::end(outcome, &crate::audit::safe_code(&code));
}

/// PIM wants a stronger sign-in. Keep the checked challenge in the
/// session, where `/auth/start` picks it up, and offer to sign in again
/// and come back to the form. Nothing typed goes in the address.
fn confirm_page(session: &Session, shell: Shell, claims: &str, here: &str, back: &str) -> Halt {
    session.set_claims_challenge(claims);
    let start = format!("/auth/start?return_to={}", return_to::encode(here));
    PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "PIM wants you to confirm it's you",
            "This role needs a stronger sign-in before it can be turned on, such as multifactor authentication. Sign in with Microsoft again and you'll come back to the form. Nothing was changed, and you'll need to fill the form in again.",
        )
        .with_hint("Your organisation set this in Privileged Identity Management. Keyring passes on what PIM asked for and nothing else.")
        .with_next(NextStep::Go {
            url: start,
            label: "Confirm it's you",
        })
        .with_also(NextStep::Go {
            url: return_to::sanitise(Some(back)),
            label: "Cancel",
        }),
    )
    .into()
}

// ---------------------------------------------------------------------
// My access
// ---------------------------------------------------------------------

/// One role on the My access page.
pub(crate) struct Row {
    pub role: String,
    pub role_name: String,
    pub scope: String,
    pub origin: &'static str,
    /// "Ends 17 Nov 2026, 14:05 UTC (2 hours 10 minutes left)", or for
    /// one that starts later "Starts 18 Nov 2026, 09:00 UTC".
    pub ends: String,
    /// Turned on through PIM, so it can be turned off.
    pub can_deactivate: bool,
    /// For an eligible row: the activation form.
    pub activate_url: String,
    /// For an eligible row: already on, waiting for approval, or when it
    /// starts. Empty offers Activate.
    pub state: String,
}

#[derive(Template)]
#[template(path = "pim/my_access.html")]
struct MyAccessPage {
    shell: Shell,
    vault: String,
    active: Vec<Row>,
    upcoming: Vec<Row>,
    eligible: Vec<Row>,
    waiting: Vec<Row>,
    notes: Vec<String>,
    portal: &'static str,
    /// "Request access" links for the Key Vault roles that are neither on
    /// nor eligible here, when access requests are on (#258).
    requests: Vec<(&'static str, String)>,
    /// `KEYRING_SHARING` is on: link to My shares.
    sharing: bool,
}

fn ends_words(ends: Option<i64>, now: i64) -> String {
    let Some(t) = ends else {
        return "No end date".into();
    };
    let left = (t - now).max(0) / 60;
    let left = u32::try_from(left).unwrap_or(u32::MAX);
    if left == 0 {
        format!("Ends {} (ending now)", crate::dates::format_datetime(t))
    } else if left < 48 * 60 {
        format!(
            "Ends {} ({} left)",
            crate::dates::format_datetime(t),
            minutes_words(left)
        )
    } else {
        format!("Ends {}", crate::dates::format_datetime(t))
    }
}

fn starts_words(starts: i64, ends: Option<i64>) -> String {
    let starts = crate::dates::format_datetime(starts);
    match ends {
        Some(t) => format!("Starts {starts}, ends {}", crate::dates::format_datetime(t)),
        None => format!("Starts {starts}, no end date"),
    }
}

fn arm_note(what: &str, e: &AzureError) -> String {
    match e {
        AzureError::Status { status: 403, .. } => {
            format!("{what} aren't listed: you can't read them here.")
        }
        AzureError::Status {
            status: 400 | 404, ..
        } => format!(
            "{what} aren't listed: PIM isn't available here, or isn't licensed in this tenant."
        ),
        AzureError::Token(TokenError::SignInAgain) => {
            format!("{what} aren't listed: sign in again.")
        }
        _ => format!("{what} aren't listed: Keyring couldn't read them from Azure."),
    }
}

pub(super) async fn my_access(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    let read = read_mine(&state, &session, &vault);
    let page = match tokio::time::timeout(LOOKUP_TIMEOUT * 2, read).await {
        Ok(Ok(Some(m))) => m,
        Ok(Ok(None)) => return Err(PageError::new(shell, Problem::not_found()).into()),
        Ok(Err(e)) => {
            return Err(vault_ctx::azure_problem(
                shell,
                &e,
                Need::ListVaults,
                &vault_path(&vault, "/my-access"),
            ));
        }
        Err(_) => Mine {
            notes: vec!["Azure took too long to answer, so nothing is listed. Try again.".into()],
            ..Mine::default()
        },
    };
    let requests = if crate::routes::access_request::is_on(&state) {
        let back = vault_path(&vault, "/my-access");
        crate::routes::access_request::roles()
            .into_iter()
            .filter(|(g, _)| {
                !page
                    .active
                    .iter()
                    .chain(&page.eligible)
                    .any(|r| r.role.eq_ignore_ascii_case(g))
            })
            .map(|(g, name)| {
                (
                    name,
                    crate::routes::access_request::request_url(&vault, g, &back),
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(render(&MyAccessPage {
        requests,
        shell,
        vault,
        active: page.active,
        upcoming: page.upcoming,
        eligible: page.eligible,
        waiting: page.waiting,
        notes: page.notes,
        portal: PIM_PORTAL,
        sharing: state.config.sharing,
    })
    .into_response())
}

#[derive(Default)]
struct Mine {
    active: Vec<Row>,
    /// Assignments ARM lists that haven't started yet.
    upcoming: Vec<Row>,
    eligible: Vec<Row>,
    /// Requests waiting for approval, from the requests themselves.
    waiting: Vec<Row>,
    notes: Vec<String>,
}

/// The person's own Key Vault roles at or above `vault`. `Ok(None)` when
/// the vault isn't one they can see.
async fn read_mine(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
) -> Result<Option<Mine>, AzureError> {
    let Some(vault_id) = super::audit::vault_id(state, session, vault).await? else {
        return Ok(None);
    };
    let url = &state.config.management_url;
    let s = &session.0;
    let (active, eligible, pending) = tokio::join!(
        pim::my_active(&state.azure, s, url, &vault_id),
        pim::my_eligibilities(&state.azure, s, url, &vault_id),
        pim::my_pending(&state.azure, s, url, &vault_id),
    );
    let mut mine = Mine::default();
    let reaches = |scope: &str| applies_at(scope, &vault_id);
    let active: Vec<Active> = match active {
        Ok(a) => a.into_iter().filter(|a| reaches(&a.scope)).collect(),
        Err(e) => {
            mine.notes.push(arm_note("Active roles", &e));
            Vec::new()
        }
    };
    let eligible: Vec<Eligibility> = match eligible {
        Ok(a) => a.into_iter().filter(|a| reaches(&a.scope)).collect(),
        Err(e) => {
            mine.notes.push(arm_note("Eligible roles", &e));
            Vec::new()
        }
    };
    let pending: Vec<Pending> = match pending {
        Ok(p) => p.into_iter().filter(|p| reaches(&p.scope)).collect(),
        Err(e) => {
            // Not known is not none: the page says so, so an eligible row
            // with Activate isn't read as "nothing is waiting".
            mine.notes
                .push(arm_note("Requests waiting for approval", &e));
            Vec::new()
        }
    };
    let mut guids: Vec<String> = active
        .iter()
        .map(|a| a.role.clone())
        .chain(eligible.iter().map(|e| e.role.clone()))
        .chain(pending.iter().map(|p| p.role.clone()))
        .collect();
    guids.sort();
    guids.dedup();
    // Every distinct role is checked for a missing definition below, so
    // one past the lookup limit still gets the "may be incomplete" note.
    // The offered Key Vault roles need no lookup, so they don't use up
    // the limit.
    let wanted = guids.clone();
    guids.retain(|g| !is_offered_role(g));
    guids.truncate(crate::routes::access::MAX_ROLES);
    let defs: HashMap<String, RoleDefinition> =
        crate::routes::access::definitions(&state.azure, s, url, &vault_id, guids).await;
    // The built-in Key Vault roles are known by their GUIDs, so they are
    // listed (and can be turned off) even when their definition couldn't
    // be read. Any other role needs its definition to tell.
    let is_kv = |g: &str| {
        is_offered_role(g)
            || defs
                .get(g)
                .is_some_and(RoleDefinition::has_key_vault_data_actions)
    };
    let name = |g: &str| {
        defs.get(g)
            .map(|d| d.role_name.clone())
            .filter(|n| !n.is_empty())
            .or_else(|| offered_name(g).map(str::to_owned))
            .unwrap_or_else(|| g.to_owned())
    };
    let unread = wanted
        .iter()
        .filter(|g| !defs.contains_key(*g) && !is_offered_role(g))
        .count();
    if unread > 0 {
        mine.notes.push(format!(
            "This list may be incomplete: Keyring couldn't read what {} can do, so it isn't shown.",
            if unread == 1 {
                "one of your roles".to_owned()
            } else {
                format!("{unread} of your roles")
            }
        ));
    }
    let now = crate::azure::secrets::now_ts();
    // A start or end time ARM gave that couldn't be read: never shown as
    // on, or offered, since Keyring can't tell whether it applies.
    let mut unclear = 0usize;
    let mut on_now: Vec<&Active> = Vec::new();
    for a in active.iter().filter(|a| is_kv(&a.role)) {
        let mut row = Row {
            role: a.role.clone(),
            role_name: name(&a.role),
            scope: a.scope.clone(),
            origin: Origin::of(&a.scope, &vault_id).label(),
            ends: String::new(),
            can_deactivate: false,
            activate_url: String::new(),
            state: String::new(),
        };
        match a.span.when(now) {
            When::Now => {
                on_now.push(a);
                row.ends = ends_words(a.span.ends, now);
                row.can_deactivate = a.activated && is_offered_role(&a.role);
                mine.active.push(row);
            }
            When::Later(t) => {
                row.ends = starts_words(t, a.span.ends);
                mine.upcoming.push(row);
            }
            When::Over => {}
            When::Unknown => unclear += 1,
        }
    }
    let back = vault_path(vault, "/my-access");
    for e in eligible.iter().filter(|e| is_kv(&e.role)) {
        let state = match e.span.when(now) {
            When::Now => {
                let on = on_now.iter().any(|a| {
                    a.activated && a.role == e.role && a.scope.eq_ignore_ascii_case(&e.scope)
                });
                let waiting = pending
                    .iter()
                    .any(|p| p.role == e.role && p.scope.eq_ignore_ascii_case(&e.scope));
                if on {
                    "On now".to_owned()
                } else if waiting {
                    "Waiting for approval".to_owned()
                } else if !is_offered_role(&e.role) {
                    "Activate in PIM".to_owned()
                } else {
                    String::new()
                }
            }
            When::Later(t) => format!("Eligible from {}", crate::dates::format_datetime(t)),
            When::Over => continue,
            When::Unknown => {
                unclear += 1;
                continue;
            }
        };
        mine.eligible.push(Row {
            role: e.role.clone(),
            role_name: name(&e.role),
            scope: e.scope.clone(),
            origin: Origin::of(&e.scope, &vault_id).label(),
            ends: ends_words(e.span.ends, now),
            can_deactivate: false,
            activate_url: activate_url(vault, &e.role, Some(&Shown::of(e)), &back),
            state,
        });
    }
    // Built from the requests themselves, so one is still shown when the
    // eligible roles couldn't be read.
    for p in pending.iter().filter(|p| is_kv(&p.role)) {
        let seen = mine
            .waiting
            .iter()
            .any(|r| r.role == p.role && r.scope.eq_ignore_ascii_case(&p.scope));
        if !seen {
            mine.waiting.push(Row {
                role: p.role.clone(),
                role_name: name(&p.role),
                scope: p.scope.clone(),
                origin: Origin::of(&p.scope, &vault_id).label(),
                ends: String::new(),
                can_deactivate: false,
                activate_url: String::new(),
                state: "Waiting for approval".to_owned(),
            });
        }
    }
    if unclear > 0 {
        mine.notes.push(format!(
            "{}: Azure gave a start or end time Keyring couldn't read, so it can't tell whether it applies now.",
            if unclear == 1 {
                "One of your roles isn't shown".to_owned()
            } else {
                format!("{unclear} of your roles aren't shown")
            }
        ));
    }
    Ok(Some(mine))
}

#[derive(Deserialize)]
pub(super) struct DeactivateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    scope: String,
}

/// Turn off a role the person turned on through PIM. The role and scope
/// from the form are only used to find it in ARM's own list of what is
/// on, read again here.
pub(super) async fn deactivate(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(form): Form<DeactivateForm>,
) -> PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::MyAccess, &vault)?;
    let shell = check_csrf(&session, &vault, &form.csrf, shell)?;
    let mine = vault_path(&vault, "/my-access");
    let role = form.role.trim().to_ascii_lowercase();
    let scope = form.scope.trim();
    let principal = session.0.user.subject.oid.clone().filter(|o| is_guid(o));
    let (Some(principal), true, true) = (
        principal,
        is_guid(&role) && is_offered_role(&role),
        pim::is_safe_scope(scope),
    ) else {
        crate::audit::refuse(Refusal::InvalidRequest);
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    crate::audit::note_role_request(&role, scope, None, None, None);
    let find = async {
        let Some(vault_id) = super::audit::vault_id(&state, &session, &vault).await? else {
            return Ok(None);
        };
        let all = pim::my_active(
            &state.azure,
            &session.0,
            &state.config.management_url,
            &vault_id,
        )
        .await?;
        let now = crate::azure::secrets::now_ts();
        Ok::<_, AzureError>(all.into_iter().find(|a| {
            a.activated
                && a.span.when(now) == When::Now
                && a.role == role
                && a.scope.eq_ignore_ascii_case(scope)
                && applies_at(&a.scope, &vault_id)
        }))
    };
    let active = match tokio::time::timeout(LOOKUP_TIMEOUT, find).await {
        Ok(Ok(Some(a))) => a,
        Ok(Ok(None)) => {
            crate::audit::refuse(Refusal::InvalidRequest);
            return Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::NOT_FOUND,
                    "That role isn't on",
                    "PIM doesn't list that role as turned on for you here, so there was nothing to turn off. It may already have ended.",
                )
                .with_next(NextStep::Go { url: mine, label: "Back to My access" }),
            )
            .into());
        }
        Ok(Err(e)) => {
            end_with_azure(&e);
            return Err(vault_ctx::azure_problem(shell, &e, Need::ListVaults, &mine));
        }
        Err(_) => {
            crate::audit::end(AuditOutcome::Failed, "timeout");
            return Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Azure took too long",
                    "Nothing was changed. Try again.",
                ),
            )
            .into());
        }
    };
    let sent = tokio::time::timeout(
        REQUEST_TIMEOUT,
        pim::deactivate(
            &state.azure,
            &session.0,
            &state.config.management_url,
            &principal,
            &active,
        ),
    )
    .await;
    match sent {
        Ok(Ok(status)) if Outcome::of(&status) != Outcome::Refused => {
            session.0.forget_permissions();
            let mut res = Redirect::to(&mine).into_response();
            flash::set(
                &state,
                &mut res,
                &Flash::success(
                    "Role turned off. Key Vault can take a few minutes to see the change.",
                ),
            );
            Ok(res)
        }
        Ok(Ok(status)) => {
            crate::audit::end(AuditOutcome::Denied, &status);
            let mut res = Redirect::to(&mine).into_response();
            flash::set(
                &state,
                &mut res,
                &Flash::error(format!(
                    "PIM didn't turn the role off. It answered {}.",
                    crate::audit::safe_code(&status)
                )),
            );
            Ok(res)
        }
        Ok(Err(
            ref err @ AzureError::Status {
                status: 400..=499,
                ref code,
                ..
            },
        )) => {
            // The answer is a redirect, which the audit event would read as
            // success: say how ARM really answered.
            end_with_azure(err);
            let mut res = Redirect::to(&mine).into_response();
            let code = code
                .as_deref()
                .map(crate::audit::safe_code)
                .unwrap_or_else(|| "no code".into());
            flash::set(
                &state,
                &mut res,
                &Flash::error(format!(
                    "PIM didn't turn the role off. Azure gave the code {code}."
                )),
            );
            Ok(res)
        }
        Ok(Err(e)) => {
            end_with_azure(&e);
            Err(vault_ctx::azure_problem(shell, &e, Need::ListVaults, &mine))
        }
        Err(_) => {
            crate::audit::end(AuditOutcome::Failed, "timeout");
            Err(PageError::new(shell, Problem::new(StatusCode::GATEWAY_TIMEOUT, "Azure took too long", "PIM didn't answer in time. The role may still have been turned off: check My access.")).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str =
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv";

    fn el(scope: &str, role: &str) -> Eligibility {
        Eligibility {
            scope: scope.into(),
            role: role.into(),
            role_definition_id: format!("/x/roleDefinitions/{role}"),
            schedule_id: "/s".into(),
            span: pim::Span::default(),
        }
    }

    #[test]
    fn picks_the_nearest_matching_eligibility() {
        let r = "4633458b-17de-408a-b874-0445c86b69e6";
        let all = vec![
            el("/subscriptions/s1", r),
            el("/subscriptions/s1/resourceGroups/rg", r),
            el("/subscriptions/s2", r),
            el(VAULT, "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"),
        ];
        assert_eq!(
            pick(all.clone(), VAULT, r).unwrap().scope,
            "/subscriptions/s1/resourceGroups/rg"
        );
        assert!(pick(all, VAULT, "21090545-7ca7-4776-b22c-e363652d74d2").is_none());
        // A management group with a long ID is never preferred to a
        // subscription, a resource group or the vault.
        let mg = "/providers/Microsoft.Management/managementGroups/a-very-long-management-group-id";
        let near = |scopes: &[&str]| {
            pick(scopes.iter().map(|s| el(s, r)).collect(), VAULT, r)
                .unwrap()
                .scope
        };
        assert_eq!(near(&[mg, "/subscriptions/s1"]), "/subscriptions/s1");
        assert_eq!(near(&["/subscriptions/s1", mg, VAULT]), VAULT);
        assert_eq!(near(&[mg]), mg);
    }

    #[test]
    fn only_key_vault_roles_are_offered() {
        for n in OFFERED_NEEDS {
            assert!(is_offered_role(role_for(n).unwrap()), "{n:?}");
        }
        assert!(is_offered_role("4633458B-17DE-408A-B874-0445C86B69E6"));
        for other in [
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
            "b24988ac-6180-42a0-ab88-20f7382dd24c", // Contributor
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", // User Access Administrator
            "acdd72a7-3385-48ef-bd42-f606fba81ae7", // Reader
            "",
            "not-a-guid",
        ] {
            assert!(!is_offered_role(other), "{other}");
        }
        // Never a role in an address unless it is one of them.
        assert!(activate_url("kv", "x&admin=1", None, "/v/kv/secrets").contains("?role=&back="));
        // The eligibility a link is for is only a key, and only plain ARM
        // values are accepted as one.
        let r = "4633458b-17de-408a-b874-0445c86b69e6";
        let shown = Shown::parse("/subscriptions/s1", "/subscriptions/s1/providers/x/y").unwrap();
        let url = activate_url("kv", r, Some(&shown), "/v/kv/secrets");
        assert!(
            url.contains("&scope=%2Fsubscriptions%2Fs1&schedule="),
            "{url}"
        );
        // Matched on both the scope and the schedule, without regard to
        // case (ARM changes the case of IDs between calls).
        let same = |scope: &str, schedule: &str| {
            let mut e = el(scope, r);
            e.schedule_id = schedule.to_owned();
            shown.is(&e)
        };
        assert!(same("/SUBSCRIPTIONS/S1", "/subscriptions/s1/providers/X/Y"));
        assert!(!same(
            "/subscriptions/s2",
            "/subscriptions/s1/providers/x/y"
        ));
        assert!(!same(
            "/subscriptions/s1",
            "/subscriptions/s1/providers/x/z"
        ));
        for (scope, schedule) in [
            ("/subscriptions/s1?x=1", "/a/b"),
            ("/subscriptions/s1/..", "/a/b"),
            ("https://evil.example", "/a/b"),
            ("/subscriptions/s1", "/a/../b"),
            ("/subscriptions/s1", "a b"),
            ("", ""),
        ] {
            assert!(
                Shown::parse(scope, schedule).is_none(),
                "{scope} {schedule}"
            );
        }
    }

    #[test]
    fn every_vault_need_names_a_role() {
        for n in [
            Need::ReadSecrets,
            Need::ManageSecrets,
            Need::ReadCertificates,
            Need::ExportCertificate,
            Need::ManageCertificates,
            Need::ReadKeys,
            Need::ManageKeys,
        ] {
            assert!(role_for(n).is_some_and(is_guid), "{n:?}");
        }
        assert_eq!(role_for(Need::ListVaults), None);
    }

    #[test]
    fn words() {
        assert_eq!(minutes_words(30), "30 minutes");
        assert_eq!(minutes_words(60), "1 hour");
        assert_eq!(minutes_words(150), "2 hours 30 minutes");
        assert_eq!(durations(420).last().unwrap().0, 420);
        assert_eq!(durations(30).len(), 1);
        assert_eq!(
            safe_back("kv", Some("https://evil.example")),
            "/v/kv/my-access"
        );
        assert_eq!(safe_back("kv", Some("/v/other/secrets")), "/v/kv/my-access");
        assert_eq!(
            safe_back("kv", Some("/v/kv/secrets/db")),
            "/v/kv/secrets/db"
        );
    }
}
