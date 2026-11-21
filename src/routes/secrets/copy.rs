//! Copy a secret to another vault without showing its value.
//!
//! Three steps, all under the source secret's address so the reason gate
//! places the request from the route's own `vault` and `name`:
//!
//! - `GET /copy`: pick the target vault (from the vaults the person can
//!   see), the target name and what to bring.
//! - `GET /copy/review`: the confirmation. Names both vaults, says the
//!   value isn't shown, and looks at the target name: new, a new version
//!   of an existing secret, or soft-deleted (stop, recover first). Reads
//!   names and properties only.
//! - `POST /copy`: as the person, read the value from the source with
//!   `getSecret` and write it to the target with `setSecret`. The value is
//!   held in [`crate::secret::Secret`] and never rendered, logged, put in
//!   an address, a flash message, an error page or an audit event.
//!
//! The post is guarded like a reveal, in the same order: form token (bound
//! to the source vault in the address), `KEYRING_AUDIT_REQUIRED`, step-up,
//! and the reason gate (in `audited(...)`). The request's own audit event
//! is the read (`secret.copy.read`, source vault and name). The write is a
//! second event (`secret.copy.write`, target vault and name), so a refusal
//! from either vault can be told apart.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::audit::{Action, ItemEvents, Refusal};
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::{Attributes, SecretItem, SetSecret, now_ts};
use crate::azure::vaults::{self, is_valid_vault_name};
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::reveal::{managed_problem, no_store};
use crate::routes::secrets::{api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{is_valid_object_name, vault_path};

/// What the person asked for, from the form or the review's query. Each
/// "bring" box is sent only when ticked.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CopyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    to_vault: String,
    #[serde(default)]
    to_name: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    dates: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
}

/// What to bring besides the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bring {
    content_type: bool,
    tags: bool,
    dates: bool,
    enabled: bool,
}

impl Bring {
    const ALL: Self = Self {
        content_type: true,
        tags: true,
        dates: true,
        enabled: true,
    };

    fn from_form(f: &CopyForm) -> Self {
        Self {
            content_type: f.content_type.is_some(),
            tags: f.tags.is_some(),
            dates: f.dates.is_some(),
            enabled: f.enabled.is_some(),
        }
    }
}

/// A target that passed every check: a vault the person can see (its
/// name as Azure lists it) and a valid item name, not the source itself.
struct Target {
    vault: String,
    name: String,
}

#[derive(Template)]
#[template(path = "secrets/copy.html")]
struct CopyPage {
    shell: Shell,
    vault: String,
    name: String,
    vaults: Vec<String>,
    to_vault: String,
    to_name: String,
    bring: Bring,
    errors: FieldErrors,
}

impl CopyPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

/// What the review found at the target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AtTarget {
    New,
    /// An existing secret, with its current version's tags: a reveal limit
    /// there is carried onto the new version.
    Exists(std::collections::BTreeMap<String, String>),
    Deleted,
    /// A certificate's backing secret: never written over.
    Managed,
    /// Couldn't look. The write decides.
    Unknown,
}

#[derive(Template)]
#[template(path = "secrets/copy_review.html")]
struct ReviewPage {
    shell: Shell,
    vault: String,
    name: String,
    to_vault: String,
    to_name: String,
    bring: Bring,
    at_target: AtTarget,
    content_type: String,
    tag_count: usize,
    has_dates: bool,
    /// The source's expiry has passed, so the copy won't have one.
    expiry_dropped: bool,
    /// `KEYRING_REQUIRE_OWNER` is on and the copy would have no owner.
    owner_missing: bool,
    /// The source's reveal limit. `none` refuses the copy.
    limit: crate::reveal_limit::Limit,
    /// The limit the copy will carry: the source's or the target's,
    /// whichever is stricter, whatever is ticked.
    carried: crate::reveal_limit::Limit,
}

impl ReviewPage {
    fn can_copy(&self) -> bool {
        !matches!(self.at_target, AtTarget::Deleted | AtTarget::Managed)
            && !self.owner_missing
            && !self.limit.refuses_reveal()
    }

    /// The copy's `keyring-reveal`, said on the review.
    fn limit_word(&self) -> &'static str {
        match self.carried {
            crate::reveal_limit::Limit::Open => "",
            crate::reveal_limit::Limit::CopyOnly => "copy only",
            crate::reveal_limit::Limit::NoReveal => "no reveal",
        }
    }
}

/// With `KEYRING_REQUIRE_OWNER` on, would the copy be written without an
/// owner? It brings the source's tags as they are, so that is a source
/// with no `owner` tag, or Tags left unticked.
fn owner_missing(item: &SecretItem, bring: Bring, require: bool) -> bool {
    require && !(bring.tags && crate::owner::owner_of(item.tags()).is_some())
}

/// Said when a copy would have no owner while the policy is on.
const OWNER_MISSING: &str = "Keyring is set to need an owner on every secret it writes, and this copy wouldn't have one. Give the source an owner with Edit details and bring its tags, then copy it. Nothing was copied.";

fn form_path(vault: &str, name: &str) -> String {
    vault_path(vault, &format!("/secrets/{name}/copy"))
}

/// Refuse before step-up when the source's reveal limit is `none`. From
/// the versions list, never a value.
async fn limit_first(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<Shell, Halt> {
    let path = vault_path(vault, &format!("/secrets/{name}"));
    match crate::routes::reveal_limit::of_secret(&api(state, session, vault), name, None).await {
        Ok((l, _)) if l.refuses_reveal() => Err(crate::routes::reveal_limit::refused(
            shell, vault, "secret", &path,
        )),
        Ok(_) => Ok(shell),
        Err(err) => Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    }
}

/// Step-up before the review and the copy. Comes back to the form, whose
/// address holds nothing from the request.
fn copy_step_up(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<Shell, Halt> {
    crate::routes::step_up::require(
        state,
        &session.0,
        shell,
        &form_path(vault, name),
        &vault_path(vault, &format!("/secrets/{name}")),
    )
}

/// The source's current version, refusing a certificate's backing secret
/// and a disabled secret (Key Vault won't read its value).
async fn source_item(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, SecretItem), Halt> {
    let path = vault_path(vault, &format!("/secrets/{name}"));
    match api(state, session, vault).properties(name).await {
        Ok(item) if item.managed.unwrap_or(false) => Err(managed_problem(shell, vault, name)),
        Ok(item) if !item.attributes.is_enabled() => Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::BAD_REQUEST,
                "This secret is disabled",
                "Key Vault won't read the value of a disabled secret, so Keyring can't copy it. Enable it first.",
            )
            .returning_to(&path),
        )
        .into()),
        Ok(item) => Ok((shell, item)),
        Err(err) => Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    }
}

/// The vaults the person can see, by name, read as them.
async fn visible_vaults(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    back: &str,
) -> Result<(Shell, Vec<String>), Halt> {
    match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
        Ok(all) => {
            let mut names: Vec<String> = all
                .into_iter()
                .map(|v| v.name)
                .filter(|n| is_valid_vault_name(n))
                .collect();
            names.sort_by_key(|n| n.to_ascii_lowercase());
            names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
            Ok((shell, names))
        }
        Err(err) => Err(azure_problem(shell, &err, Need::ListVaults, back)),
    }
}

/// Check the target from the form: a well-formed vault name that is in
/// `visible`, a well-formed item name, and not the source itself.
fn check_target(
    f: &CopyForm,
    visible: &[String],
    vault: &str,
    name: &str,
) -> Result<Target, FieldErrors> {
    let mut errors = FieldErrors::new();
    let to_vault = f.to_vault.trim();
    let to_name = f.to_name.trim();
    let listed = is_valid_vault_name(to_vault)
        .then(|| visible.iter().find(|v| v.eq_ignore_ascii_case(to_vault)))
        .flatten();
    match listed {
        Some(_) => {}
        None if to_vault.is_empty() => errors.push("to_vault", "Pick the vault to copy to."),
        None => errors.push(
            "to_vault",
            "That vault isn't one you can see. Pick a vault from the list.",
        ),
    }
    if let Some(msg) =
        crate::routes::forms::name_problem(crate::routes::lifecycle::Kind::Secret, to_name)
    {
        errors.push("to_name", msg);
    }
    if let Some(v) = listed
        && errors.is_empty()
        && v.eq_ignore_ascii_case(vault)
        && to_name.eq_ignore_ascii_case(name)
    {
        errors.push(
            "to_name",
            "That's this secret. Pick another vault, or give the copy another name.",
        );
    }
    match listed {
        Some(v) if errors.is_empty() && is_valid_object_name(to_name) => Ok(Target {
            vault: v.clone(),
            name: to_name.to_owned(),
        }),
        _ => Err(errors),
    }
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    #[serde(default)]
    to_vault: String,
    #[serde(default)]
    to_name: String,
}

async fn page_inner(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, _) = source_item(&state, &session, shell, &vault, &name).await?;
    let shell = limit_first(&state, &session, shell, &vault, &name).await?;
    let back = form_path(&vault, &name);
    let (shell, vaults) = visible_vaults(&state, &session, shell, &back).await?;
    let prefill_vault = vaults
        .iter()
        .find(|v| v.eq_ignore_ascii_case(q.to_vault.trim()))
        .cloned()
        .unwrap_or_default();
    let prefill_name = {
        let trimmed = q.to_name.trim();
        if !trimmed.is_empty() && is_valid_object_name(trimmed) {
            trimmed.to_owned()
        } else {
            name.clone()
        }
    };
    Ok(no_store(
        render(&CopyPage {
            shell,
            to_vault: prefill_vault,
            to_name: prefill_name,
            vault,
            name,
            vaults,
            bring: Bring::ALL,
            errors: FieldErrors::new(),
        })
        .into_response(),
    ))
}

/// The form again, with what was wrong.
fn form_again(
    shell: Shell,
    vault: String,
    name: String,
    vaults: Vec<String>,
    f: &CopyForm,
    errors: FieldErrors,
) -> Response {
    no_store(
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            render(&CopyPage {
                shell,
                vault,
                name,
                vaults,
                to_vault: f.to_vault.trim().to_owned(),
                to_name: f.to_name.trim().chars().take(127).collect(),
                bring: Bring::from_form(f),
                errors,
            }),
        )
            .into_response(),
    )
}

/// What's at the target name, from its versions list and, if it has none,
/// the deleted secrets. Names and properties only.
async fn look_at_target(state: &AppState, session: &CurrentSession, t: &Target) -> AtTarget {
    let target = api(state, session, &t.vault);
    match target.versions(&t.name).await {
        Ok(v) if v.first().is_some_and(|i| i.managed.unwrap_or(false)) => AtTarget::Managed,
        Ok(v) if !v.is_empty() => AtTarget::Exists(v[0].tags().clone()),
        Ok(_) => match target.get_deleted(&t.name).await {
            Ok(_) => AtTarget::Deleted,
            Err(AzureError::Status { status: 404, .. }) => AtTarget::New,
            Err(_) => AtTarget::Unknown,
        },
        Err(_) => AtTarget::Unknown,
    }
}

async fn review_inner(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Query(f): Query<CopyForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = limit_first(&state, &session, shell, &vault, &name).await?;
    let shell = copy_step_up(&state, &session, shell, &vault, &name)?;
    let (shell, item) = source_item(&state, &session, shell, &vault, &name).await?;
    let back = form_path(&vault, &name);
    let (shell, vaults) = visible_vaults(&state, &session, shell, &back).await?;
    let target = match check_target(&f, &vaults, &vault, &name) {
        Ok(t) => t,
        Err(errors) => return Ok(form_again(shell, vault, name, vaults, &f, errors)),
    };
    let at_target = look_at_target(&state, &session, &target).await;
    let a = &item.attributes;
    let limit = crate::reveal_limit::of(item.tags());
    let carried = match &at_target {
        AtTarget::Exists(t) => limit.max(crate::reveal_limit::of(t)),
        _ => limit,
    };
    let page = ReviewPage {
        limit,
        carried,
        bring: Bring::from_form(&f),
        content_type: item.content_type.clone().unwrap_or_default(),
        tag_count: item.tags().len(),
        has_dates: a.not_before.is_some() || a.expires.is_some(),
        expiry_dropped: a.expires.is_some_and(|e| e <= now_ts()),
        owner_missing: owner_missing(&item, Bring::from_form(&f), state.config.require_owner),
        at_target,
        to_vault: target.vault,
        to_name: target.name,
        shell,
        vault,
        name,
    };
    let status = if page.can_copy() {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    Ok(no_store((status, render(&page)).into_response()))
}

/// A refused post: a page, no Key Vault call.
fn refused(
    shell: Shell,
    status: StatusCode,
    heading: &'static str,
    msg: String,
    back: &str,
) -> Halt {
    crate::audit::refuse(Refusal::InvalidRequest);
    no_store(
        PageError::new(shell, Problem::new(status, heading, msg).returning_to(back))
            .into_response(),
    )
    .into()
}

/// The body for the target: the value always, the rest as asked. A passed
/// expiry isn't brought: a copy that had already expired couldn't be used.
/// The reveal limit always goes, ticked or not: the source's, or the
/// target's current one (`target_tags`) when that is stricter, so no
/// option makes a copy with a weaker `keyring-reveal` than either.
fn body_for(
    item: &SecretItem,
    value: crate::secret::Secret,
    bring: Bring,
    target_tags: &std::collections::BTreeMap<String, String>,
) -> SetSecret {
    let a = &item.attributes;
    let base = if bring.tags {
        item.tags().clone()
    } else {
        std::collections::BTreeMap::new()
    };
    let tags =
        crate::reveal_limit::carry(&crate::reveal_limit::carry(&base, item.tags()), target_tags);
    SetSecret {
        value,
        content_type: if bring.content_type {
            item.content_type.clone()
        } else {
            None
        },
        attributes: Attributes {
            // The source is enabled (Key Vault won't read a disabled
            // one), so unticked means "make the copy disabled".
            enabled: Some(bring.enabled && a.is_enabled()),
            not_before: if bring.dates { a.not_before } else { None },
            expires: if bring.dates {
                a.expires.filter(|e| *e > now_ts())
            } else {
                None
            },
            ..Default::default()
        },
        tags: (!tags.is_empty()).then_some(tags),
    }
}

/// "Not copied", with the role to ask for on a 403, or Key Vault's error
/// code. Never Key Vault's message.
fn not_copied(shell: Shell, err: &AzureError, name: &str, t: &Target, back: &str) -> Halt {
    let lead = format!(
        "{name} wasn't copied to {}. Nothing was written there, and nothing changed in this vault.",
        t.vault
    );
    let problem = match err {
        AzureError::Status {
            status: 403, code, ..
        } if !matches!(
            code.as_deref(),
            Some("ForbiddenByFirewall" | "ForbiddenByConnection")
        ) =>
        {
            Problem::new(
                StatusCode::FORBIDDEN,
                "Not copied",
                format!("{lead} Key Vault in {} refused the write.", t.vault),
            )
            .with_role_hint(format!(
                "Ask your admin for the {} role on {}, or on the secret {} in it.",
                crate::routes::hints::Action::SetSecret.need().role(),
                t.vault,
                t.name
            ))
        }
        AzureError::Status {
            status: 409, code, ..
        } if code.as_deref().is_some_and(|c| {
            c.eq_ignore_ascii_case("ObjectIsDeletedButRecoverable")
                || c.eq_ignore_ascii_case("Conflict")
        }) =>
        {
            Problem::new(
                StatusCode::CONFLICT,
                "Not copied",
                format!(
                    "{lead} {} in {} is deleted or changing. If it's deleted, recover it first, then copy again.",
                    t.name, t.vault
                ),
            )
        }
        AzureError::Status { status, code, .. } => {
            let code = code
                .as_deref()
                .map(crate::audit::safe_code)
                .unwrap_or_else(|| format!("http_{status}"));
            Problem::new(StatusCode::BAD_GATEWAY, "Not copied", lead).with_hint(format!(
                "Key Vault in {} answered {status} {code}.",
                t.vault
            ))
        }
        other => {
            let p = Problem::from_azure(other, Need::ManageSecrets);
            Problem::new(p.status, "Not copied", format!("{lead} {}", p.message))
        }
    };
    no_store(PageError::new(shell, problem.returning_to(back)).into_response()).into()
}

async fn apply_inner(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<CopyForm>,
) -> PageResult {
    // The same checks as a reveal, in the same order. The reason gate ran
    // before this handler.
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = crate::routes::vault_ctx::check_csrf(&session, &vault, &f.csrf, shell)?;
    let shell = crate::routes::audit_gate::require_audit(&state, shell)?;
    let shell = limit_first(&state, &session, shell, &vault, &name).await?;
    let shell = copy_step_up(&state, &session, shell, &vault, &name)?;
    let back = form_path(&vault, &name);

    // The target, from the form: well-formed, and a vault the person can
    // see, read as them. Checked before any Key Vault call.
    let to_vault = f.to_vault.trim();
    let to_name = f.to_name.trim();
    if !is_valid_vault_name(to_vault) || !is_valid_object_name(to_name) {
        return Err(refused(
            shell,
            StatusCode::BAD_REQUEST,
            "That isn't a vault and name Keyring can copy to",
            "Go back to the form and pick a vault from the list and a name of letters, numbers and hyphens. Nothing was copied.".into(),
            &back,
        ));
    }
    let (shell, visible) = visible_vaults(&state, &session, shell, &back).await?;
    let target = match check_target(&f, &visible, &vault, &name) {
        Ok(t) => t,
        Err(errors) => {
            let msg = errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            return Err(refused(
                shell,
                StatusCode::BAD_REQUEST,
                "Not copied",
                format!("{msg} Nothing was copied."),
                &back,
            ));
        }
    };

    // The source: not a certificate's backing secret, and enabled. With
    // KEYRING_REQUIRE_OWNER on, it must bring an owner: refused before the
    // value is read.
    let (shell, item) = source_item(&state, &session, shell, &vault, &name).await?;
    let source_path = vault_path(&vault, &format!("/secrets/{name}"));
    if crate::reveal_limit::of(item.tags()).refuses_reveal() {
        return Err(crate::routes::reveal_limit::refused(
            shell,
            &vault,
            "secret",
            &source_path,
        ));
    }
    if owner_missing(&item, Bring::from_form(&f), state.config.require_owner) {
        crate::audit::refuse(Refusal::OwnerRequired);
        return Err(no_store(
            PageError::new(
                shell,
                Problem::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Not copied",
                    OWNER_MISSING,
                )
                .returning_to(&back),
            )
            .into_response(),
        )
        .into());
    }

    // The target name: stop before reading anything if it's a deleted
    // secret or a certificate's. If Keyring can't look, the write decides.
    let at_target = look_at_target(&state, &session, &target).await;
    let target_tags = match &at_target {
        AtTarget::Exists(t) => t.clone(),
        _ => std::collections::BTreeMap::new(),
    };
    match at_target {
        AtTarget::Deleted => {
            return Err(refused(
                shell,
                StatusCode::CONFLICT,
                "A deleted secret has that name",
                format!(
                    "A deleted secret called {} is still kept in {}, so Key Vault won't take a new one with that name. Recover it first, or pick another name. Nothing was copied.",
                    target.name, target.vault
                ),
                &back,
            ));
        }
        AtTarget::Managed => {
            return Err(refused(
                shell,
                StatusCode::CONFLICT,
                "That name belongs to a certificate",
                format!(
                    "{} in {} holds a certificate's private key, so Keyring won't write over it. Pick another name. Nothing was copied.",
                    target.name, target.vault
                ),
                &back,
            ));
        }
        // Keyring can't see whether the target has a reveal limit of its
        // own, so a copy could write a version without it. Refused.
        AtTarget::Unknown => {
            return Err(refused(
                shell,
                StatusCode::CONFLICT,
                "Keyring couldn't check the target",
                format!(
                    "Keyring couldn't read {} in {}, so it can't tell whether a copy would keep that secret's reveal limit. Check you can read secrets there, then try again. Nothing was copied.",
                    target.name, target.vault
                ),
                &back,
            ));
        }
        AtTarget::New | AtTarget::Exists(_) => {}
    }

    // The read, as the person. On failure nothing is written.
    let bundle = match api(&state, &session, &vault).get_value(&name, None).await {
        Ok(b) => b,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &source_path)),
    };
    crate::audit::note_version(bundle.item.version());
    crate::notify::activity::note_read(bundle.item.tags.as_ref());
    // Checked again on what was read, in case it changed since the
    // properties were read. The value is dropped unused.
    if bundle.item.managed.unwrap_or(false) {
        drop(bundle);
        return Err(managed_problem(shell, &vault, &name));
    }
    if crate::reveal_limit::of(bundle.item.tags()).refuses_reveal() {
        drop(bundle);
        return Err(crate::routes::reveal_limit::refused_after_read(
            shell,
            &vault,
            "secret",
            &source_path,
        ));
    }
    if owner_missing(
        &bundle.item,
        Bring::from_form(&f),
        state.config.require_owner,
    ) {
        crate::audit::refuse(Refusal::OwnerRequired);
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Not copied",
                OWNER_MISSING,
            )
            .returning_to(&back),
        )
        .into());
    }
    // The limit carried is the stricter of what was just read and what the
    // properties said, so a tag removed in between doesn't loosen the copy.
    let source_tags = crate::reveal_limit::carry(bundle.item.tags(), item.tags());
    let mut source = bundle.item.clone();
    source.tags = Some(source_tags);
    let body = body_for(&source, bundle.value, Bring::from_form(&f), &target_tags);

    // The write, as the person, with its own audit event on the target.
    // The target's kept list is dropped, as `forget_on_change` does for
    // the vault in the address.
    session.0.forget_list(&target.vault);
    let events = ItemEvents::for_request(Action::SecretCopyWrite, state.audit_sink.clone())
        .in_vault(&target.vault);
    let target_api = api(&state, &session, &target.vault);
    let written = events
        .run(&target.name, async {
            let r = target_api.set(&target.name, &body).await;
            if let Ok(new) = &r {
                crate::audit::note_version(new.version());
            }
            r
        })
        .await;
    drop(body);
    session.0.forget_list(&target.vault);
    match written {
        Ok(new) => {
            let short: String = new.version().chars().take(8).collect();
            let mut res = Redirect::to(&source_path).into_response();
            flash::set(
                &state,
                &mut res,
                &Flash::success(format!(
                    "Copied {name} to {} as {}. Version {short} is now current there. The value wasn't shown.",
                    target.vault, target.name
                )),
            );
            Ok(res)
        }
        Err(err) => {
            // The read went through, so the request's own event (the
            // read) is a success. The write's event says how it failed.
            crate::audit::succeed();
            Err(not_copied(shell, &err, &name, &target, &back))
        }
    }
}

/// Every page in the flow, error pages included, is `no-store`.
pub(crate) async fn page(
    state: State<AppState>,
    session: CurrentSession,
    shell: Shell,
    path: Path<(String, String)>,
    query: Query<PageQuery>,
) -> Response {
    no_store(
        page_inner(state, session, shell, path, query)
            .await
            .into_response(),
    )
}

pub(crate) async fn review(
    state: State<AppState>,
    session: CurrentSession,
    shell: Shell,
    path: Path<(String, String)>,
    query: Query<CopyForm>,
) -> Response {
    no_store(
        review_inner(state, session, shell, path, query)
            .await
            .into_response(),
    )
}

pub(crate) async fn apply(
    state: State<AppState>,
    session: CurrentSession,
    shell: Shell,
    path: Path<(String, String)>,
    form: Form<CopyForm>,
) -> Response {
    no_store(
        apply_inner(state, session, shell, path, form)
            .await
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(vault: &str, name: &str) -> CopyForm {
        CopyForm {
            to_vault: vault.into(),
            to_name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn targets_are_checked() {
        let seen = vec!["kv-prod".to_owned(), "kv-test".to_owned()];
        let t = check_target(&form("KV-PROD", " db "), &seen, "kv-test", "db").unwrap();
        assert_eq!((t.vault.as_str(), t.name.as_str()), ("kv-prod", "db"));
        // Same vault, another name: fine.
        assert!(check_target(&form("kv-test", "db-2"), &seen, "kv-test", "db").is_ok());
        // The source itself, in any case.
        assert!(check_target(&form("kv-test", "DB"), &seen, "kv-test", "db").is_err());
        // Not in the list, or not a vault name at all.
        for v in [
            "kv-other",
            "",
            "evil.example.com",
            "kv-prod/../x",
            "%6bv-prod",
        ] {
            assert!(
                check_target(&form(v, "db"), &seen, "kv-test", "db").is_err(),
                "{v}"
            );
        }
        for n in ["", "-x", "a b", "a/b", "../x", &"a".repeat(128)] {
            assert!(
                check_target(&form("kv-prod", n), &seen, "kv-test", "db").is_err(),
                "{n}"
            );
        }
    }

    #[test]
    fn require_owner_needs_the_sources_owner_brought() {
        let mut item = SecretItem {
            id: "https://kv.vault.azure.net/secrets/s/0123456789abcdef0123456789abcdef".into(),
            attributes: Attributes::default(),
            tags: None,
            content_type: None,
            managed: None,
        };
        let all = Bring::ALL;
        let bare = Bring {
            tags: false,
            ..Bring::ALL
        };
        assert!(!owner_missing(&item, all, false), "off: never");
        assert!(owner_missing(&item, all, true));
        item.tags = Some([("owner".to_owned(), "a@example.com".to_owned())].into());
        assert!(!owner_missing(&item, all, true));
        assert!(owner_missing(&item, bare, true), "tags not brought");
        // An odd owner set elsewhere is brought as it is.
        item.tags = Some([("owner".to_owned(), "Payments Team".to_owned())].into());
        assert!(!owner_missing(&item, all, true));
    }

    #[test]
    fn what_is_brought() {
        let item = SecretItem {
            id: "https://kv/secrets/db/v1".into(),
            attributes: Attributes {
                enabled: Some(true),
                not_before: Some(100),
                expires: Some(i64::MAX),
                ..Default::default()
            },
            tags: Some([("env".to_owned(), "prod".to_owned())].into()),
            content_type: Some("text/plain".into()),
            managed: None,
        };
        let nt = std::collections::BTreeMap::new();
        let all = body_for(&item, crate::secret::Secret::new("v"), Bring::ALL, &nt);
        assert_eq!(all.content_type.as_deref(), Some("text/plain"));
        assert_eq!(all.attributes.enabled, Some(true));
        assert_eq!(all.attributes.not_before, Some(100));
        assert!(all.tags.is_some());
        let none = Bring {
            content_type: false,
            tags: false,
            dates: false,
            enabled: false,
        };
        let bare = body_for(&item, crate::secret::Secret::new("v"), none, &nt);
        assert_eq!(bare.content_type, None);
        assert_eq!(bare.attributes.enabled, Some(false));
        assert_eq!(bare.attributes.not_before, None);
        assert_eq!(bare.attributes.expires, None);
        assert!(bare.tags.is_none());
        // A passed expiry isn't brought.
        let mut old = item.clone();
        old.attributes.expires = Some(1);
        let b = body_for(&old, crate::secret::Secret::new("v"), Bring::ALL, &nt);
        assert_eq!(b.attributes.expires, None);
    }

    #[test]
    fn no_option_weakens_the_reveal_limit() {
        let lim = |v: &str| -> std::collections::BTreeMap<String, String> {
            [("keyring-reveal".to_owned(), v.to_owned())].into()
        };
        let mut item = SecretItem {
            id: "https://kv/secrets/db/v1".into(),
            attributes: Attributes::default(),
            tags: Some(lim("copy-only")),
            content_type: None,
            managed: None,
        };
        let nt = std::collections::BTreeMap::new();
        for tags in [false, true] {
            for ct in [false, true] {
                let bring = Bring {
                    content_type: ct,
                    tags,
                    dates: tags,
                    enabled: ct,
                };
                let b = body_for(&item, crate::secret::Secret::new("v"), bring, &nt);
                let t = b.tags.unwrap_or_default();
                assert_eq!(
                    crate::reveal_limit::of(&t),
                    crate::reveal_limit::Limit::CopyOnly
                );
                // A stricter target keeps its own.
                let b = body_for(&item, crate::secret::Secret::new("v"), bring, &lim("none"));
                let t = b.tags.unwrap_or_default();
                assert_eq!(
                    crate::reveal_limit::of(&t),
                    crate::reveal_limit::Limit::NoReveal
                );
            }
        }
        // An unknown value is carried exactly.
        item.tags = Some([("Keyring-Reveal".to_owned(), "maybe".to_owned())].into());
        let none = Bring {
            content_type: false,
            tags: false,
            dates: false,
            enabled: false,
        };
        let b = body_for(&item, crate::secret::Secret::new("v"), none, &nt);
        assert_eq!(b.tags.unwrap()["Keyring-Reveal"], "maybe");
    }
}
