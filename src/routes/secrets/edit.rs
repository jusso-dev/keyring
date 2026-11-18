//! Create a secret, set a new value, edit properties, enable and disable.

use std::collections::BTreeMap;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::{SecretItem, SecretsApi, UpdateSecret, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::{FieldErrors, ToggleForm};
use crate::routes::lifecycle::Kind;
use crate::routes::secrets::form::{self, SecretForm};
use crate::routes::secrets::reveal::no_store;
use crate::routes::secrets::{api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;
use crate::routes::tag_rows::{self, Suggestions, TagField};
use crate::routes::used_by::{self, UsedBy};
use crate::routes::vault_ctx::check_csrf;
use crate::routes::vault_ctx::vault_path;
use crate::secret_types::{ContentKind, Field, SecretType, classify};

/// Which form is being shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Create,
    NewValue,
    Properties,
}

/// Values to put back in the form. Never includes the secret value.
#[derive(Default)]
pub(crate) struct FormView {
    pub name: String,
    pub content_type: String,
    pub expires: String,
    pub not_before: String,
    /// The tag rows, the tags a row can't show, and the suggestions.
    pub tags: TagField,
    /// The note in the `description` tag, as typed or as it is.
    pub description: String,
    /// The `owner` and `notify` tags, as typed or as they are.
    pub owners: crate::owner::Fields,
    /// The reveal limit control (`keyring-reveal`).
    pub reveal: crate::reveal_limit::Field,
    pub enabled: bool,
    /// The version the edit form was opened on, and its `updated` time.
    pub version: String,
    pub updated: String,
    /// A typed secret: one input per field in place of the value box.
    /// Field values are never put back into the form.
    pub secret_type: Option<SecretType>,
}

impl FormView {
    /// The form as posted. `current` is the item's tags, for the ones a
    /// row can't show.
    fn from_form(f: &SecretForm, current: &BTreeMap<String, String>) -> Self {
        Self {
            name: f.name.trim().to_owned(),
            content_type: f.content_type.clone(),
            expires: f.expires.clone(),
            not_before: f.not_before.clone(),
            tags: TagField::posted(&f.tag_rows, current),
            description: f.description.clone(),
            owners: crate::owner::Fields::posted(f.owners(), current),
            reveal: crate::reveal_limit::Field::posted(f.reveal.as_deref(), current),
            enabled: f.enabled.is_some(),
            version: f.version.clone(),
            updated: f.updated.clone(),
            secret_type: f.chosen_type().ok().flatten(),
        }
    }

    /// The type the secret already has, for "Set a new value" and "Edit
    /// details", whatever the form posted.
    fn typed_as(mut self, item: &SecretItem) -> Self {
        self.secret_type = match classify(item.content_type.as_deref()) {
            ContentKind::Typed(t) => Some(t),
            _ => None,
        };
        if self.secret_type.is_some() {
            self.content_type = item.content_type.clone().unwrap_or_default();
        }
        self
    }

    fn from_item(item: &SecretItem) -> Self {
        let a = &item.attributes;
        Self {
            name: item.name().to_owned(),
            content_type: item.content_type.clone().unwrap_or_default(),
            expires: a.expires.map(dates::iso_date).unwrap_or_default(),
            not_before: a.not_before.map(dates::iso_date).unwrap_or_default(),
            tags: TagField::of(item.tags()),
            description: crate::description::of(item.tags())
                .unwrap_or_default()
                .to_owned(),
            owners: crate::owner::Fields::of(item.tags()),
            reveal: crate::reveal_limit::Field::of(item.tags()),
            enabled: a.is_enabled(),
            version: item.version().to_owned(),
            updated: updated_stamp(item),
            secret_type: None,
        }
        .typed_as(item)
    }

    fn suggesting(mut self, s: Suggestions) -> Self {
        self.tags.suggest = s;
        self
    }
}

/// A version's `updated` time as the edit form carries it.
fn updated_stamp(item: &SecretItem) -> String {
    item.attributes
        .updated
        .map(|t| t.to_string())
        .unwrap_or_default()
}

#[derive(Template)]
#[template(path = "secrets/form.html")]
struct FormPage {
    shell: Shell,
    vault: String,
    mode: Mode,
    form: FormView,
    errors: FieldErrors,
    /// Set when a create clashed with a soft-deleted secret of the same name.
    deleted_clash: Option<String>,
    /// Who read the secret lately, on Set a new value.
    used_by: Option<UsedBy>,
}

impl FormPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }

    fn is_create(&self) -> bool {
        self.mode == Mode::Create
    }

    fn has_value_field(&self) -> bool {
        self.mode != Mode::Properties
    }

    /// The typed secret's fields, when the form shows them.
    fn typed_fields(&self) -> &'static [Field] {
        match self.form.secret_type {
            Some(t) if self.has_value_field() => t.fields(),
            _ => &[],
        }
    }

    fn type_label(&self) -> &'static str {
        self.form.secret_type.map_or("Password", SecretType::label)
    }

    /// Is `field` checked against `KEYRING_PASSWORD_POLICY` on this form?
    /// `value` for a Password, Login's `password`, while a policy is on.
    fn has_policy(&self, field: &str) -> bool {
        let checked = match self.form.secret_type {
            None => field == "value",
            Some(t) => t.policy_field() == Some(field),
        };
        checked && self.has_value_field() && self.shell.password_policy.is_on()
    }

    /// What the policy asks for, said before the person types.
    fn policy_help(&self) -> String {
        format!(
            "Keyring's password policy: {}. Checked when you save. The Azure CLI and portal don't apply it.",
            self.shell.password_policy.describe()
        )
    }

    /// The plain Value box's policy line: every plain value counts as a
    /// password, so a key or connection string is checked too.
    fn value_policy_help(&self) -> String {
        format!(
            "{} Every plain value is checked as a password, so for a key, PEM block or connection string choose its type (SSH private key, API key, Database) or use the Azure CLI.",
            self.policy_help()
        )
    }

    /// The help a typed field's `aria-describedby` names, if any.
    fn field_help_ids(&self, f: &Field) -> String {
        let mut ids = Vec::new();
        if !f.help.is_empty() {
            ids.push(format!("{}-help", f.name));
        }
        if self.has_policy(f.name) {
            ids.push(format!("{}-policy", f.name));
        }
        ids.join(" ")
    }

    /// `minlength` for a field with a policy, as a hint only: the server
    /// check is the real one.
    fn policy_min(&self) -> usize {
        self.shell.password_policy.min.unwrap_or(0)
    }

    /// The create form's type picker: each type, its link, and whether it
    /// is the one shown.
    fn type_choices(&self) -> Vec<(&'static str, String, bool)> {
        let base = vault_path(&self.vault, "/secrets/-/new");
        std::iter::once(("Password", base.clone(), self.form.secret_type.is_none()))
            .chain(SecretType::ALL.into_iter().map(|t| {
                (
                    t.label(),
                    format!("{base}?type={}", t.slug()),
                    self.form.secret_type == Some(t),
                )
            }))
            .collect()
    }

    /// What a typed secret's content type is, or will be.
    fn typed_content_type(&self) -> String {
        match self.form.secret_type {
            Some(_) if !self.form.content_type.is_empty() => self.form.content_type.clone(),
            Some(t) => t.content_type(),
            None => String::new(),
        }
    }

    fn secret_type_slug(&self) -> &'static str {
        self.form.secret_type.map_or("", SecretType::slug)
    }

    fn action(&self) -> String {
        match self.mode {
            Mode::Create => vault_path(&self.vault, "/secrets/-/new"),
            Mode::NewValue => {
                vault_path(&self.vault, &format!("/secrets/{}/value", self.form.name))
            }
            Mode::Properties => {
                vault_path(&self.vault, &format!("/secrets/{}/edit", self.form.name))
            }
        }
    }

    fn heading(&self) -> String {
        match self.mode {
            Mode::Create => "Create a secret".into(),
            Mode::NewValue => format!("New value for {}", self.form.name),
            Mode::Properties => format!("Edit {}", self.form.name),
        }
    }

    fn cancel_url(&self) -> String {
        match self.mode {
            Mode::Create => vault_path(&self.vault, "/secrets"),
            _ => vault_path(&self.vault, &format!("/secrets/{}", self.form.name)),
        }
    }
}

fn form_page(
    shell: Shell,
    vault: String,
    mode: Mode,
    form: FormView,
    errors: FieldErrors,
    deleted_clash: Option<String>,
) -> Response {
    form_page_with(shell, vault, mode, form, errors, deleted_clash, None)
}

fn form_page_with(
    shell: Shell,
    vault: String,
    mode: Mode,
    form: FormView,
    errors: FieldErrors,
    deleted_clash: Option<String>,
    used_by: Option<UsedBy>,
) -> Response {
    let status = if errors.is_empty() && deleted_clash.is_none() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    // Forms can hold a value on the way back in, so never cache them.
    no_store(
        (
            status,
            render(&FormPage {
                shell,
                vault,
                mode,
                form,
                errors,
                deleted_clash,
                used_by,
            }),
        )
            .into_response(),
    )
}

fn saved(state: &AppState, to: &str, message: String) -> Response {
    let mut res = Redirect::to(to).into_response();
    flash::set(state, &mut res, &Flash::success(message));
    res
}

#[derive(serde::Deserialize)]
pub(crate) struct NewQuery {
    #[serde(default, rename = "type")]
    kind: String,
}

pub(crate) async fn new_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(q): Query<NewQuery>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    // An unknown type shows the plain form.
    let view = FormView {
        enabled: true,
        secret_type: SecretType::from_slug(&q.kind),
        ..FormView::default()
    }
    .suggesting(tag_rows::for_vault(&state, &session, &vault).await);
    Ok(form_page(
        shell,
        vault,
        Mode::Create,
        view,
        FieldErrors::new(),
        None,
    ))
}

/// Is there a soft-deleted secret with this name?
async fn is_soft_deleted(api: &SecretsApi<'_>, name: &str) -> bool {
    api.get_deleted(name).await.is_ok()
}

pub(crate) async fn create(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (name, body) = match form::for_create(
        &f,
        now_ts(),
        &state.config.password_policy,
        crate::owner::Rules::of(&state.config),
    ) {
        Ok(ok) => {
            crate::audit::note_item(&ok.0);
            ok
        }
        Err(errors) => {
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            return Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f, &BTreeMap::new()).suggesting(suggest),
                errors,
                None,
            ));
        }
    };
    let api = api(&state, &session, &vault);

    // Setting a value on an existing name would silently add a version.
    // Check first so "Add" never overwrites. A name is taken when it has at
    // least one version. Key Vault answers an unknown name with an empty
    // list, and Keyring also takes a 404 to mean the name is free.
    match api.versions(&name).await {
        Ok(v) if v.is_empty() => {}
        Ok(_) => {
            let errors = FieldErrors::one(
                "name",
                format!(
                    "There's already a secret called {name}. Pick another name, or open it and set a new value."
                ),
            );
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            return Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f, &BTreeMap::new()).suggesting(suggest),
                errors,
                None,
            ));
        }
        Err(AzureError::Status { status: 404, .. }) => {}
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                &vault_path(&vault, "/secrets/-/new"),
            ));
        }
    }

    match api.set(&name, &body).await {
        Ok(_) => Ok(saved(
            &state,
            &vault_path(&vault, &format!("/secrets/{name}")),
            format!("Created {name}."),
        )),
        Err(AzureError::Status { status: 409, .. }) if is_soft_deleted(&api, &name).await => {
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f, &BTreeMap::new()).suggesting(suggest),
                FieldErrors::new(),
                Some(name),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &vault_path(&vault, "/secrets/-/new"),
        )),
    }
}

/// The current version's properties, refusing a certificate's backing
/// secret. `vault` and `name` are already checked.
async fn fetch(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(Shell, SecretItem), Halt> {
    match api(state, session, vault).properties(name).await {
        // Key Vault refuses changes to a certificate's backing secret;
        // say why instead of showing a confusing 403.
        Ok(item) if item.managed.unwrap_or(false) => Err(
            crate::routes::secrets::reveal::managed_problem(shell, vault, name),
        ),
        Ok(item) => Ok((shell, item)),
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ReadSecrets,
            &vault_path(vault, &format!("/secrets/{name}")),
        )),
    }
}

pub(crate) async fn value_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    // Who used it loads beside the secret, within its own time limit.
    // So do the tag suggestions.
    let (fetched, used_by, suggest) = tokio::join!(
        fetch(&state, &session, shell, &vault, &name),
        used_by::for_item(&state, &session, &vault, Kind::Secret, &name),
        tag_rows::for_vault(&state, &session, &vault),
    );
    let (shell, item) = fetched?;
    Ok(form_page_with(
        shell,
        vault,
        Mode::NewValue,
        FormView::from_item(&item).suggesting(suggest),
        FieldErrors::new(),
        None,
        Some(used_by),
    ))
}

pub(crate) async fn set_value(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(mut f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    // Refuse a certificate's backing secret, and refuse if we can't tell.
    let item = match api(&state, &session, &vault).properties(&name).await {
        Ok(item) if item.managed.unwrap_or(false) => {
            return Err(crate::routes::secrets::reveal::managed_problem(
                shell, &vault, &name,
            ));
        }
        Ok(item) => item,
        Err(err) => {
            let path = vault_path(&vault, &format!("/secrets/{name}"));
            return Err(azure_problem(shell, &err, Need::ManageSecrets, &path));
        }
    };
    f.name = name.clone();
    let body = match form::for_new_value(
        &f,
        &item,
        now_ts(),
        &state.config.password_policy,
        crate::owner::Rules::of(&state.config),
    ) {
        Ok(b) => b,
        Err(errors) => {
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            return Ok(form_page(
                shell,
                vault,
                Mode::NewValue,
                FormView::from_form(&f, item.tags())
                    .typed_as(&item)
                    .suggesting(suggest),
                errors,
                None,
            ));
        }
    };
    let form_url = vault_path(&vault, &format!("/secrets/{name}/value"));
    let empty = BTreeMap::new();
    let (shell, errors) = crate::routes::reveal_limit::loosening(
        &state,
        &session,
        shell,
        crate::audit::Action::SecretSet,
        item.tags(),
        body.tags.as_ref().unwrap_or(&empty),
        &f.reason,
        &f.ticket,
        &form_url,
    )?;
    if !errors.is_empty() {
        let suggest = tag_rows::for_vault(&state, &session, &vault).await;
        return Ok(form_page(
            shell,
            vault,
            Mode::NewValue,
            FormView::from_form(&f, item.tags())
                .typed_as(&item)
                .suggesting(suggest),
            errors,
            None,
        ));
    }
    match api(&state, &session, &vault).set(&name, &body).await {
        Ok(_) => Ok(saved(
            &state,
            &vault_path(&vault, &format!("/secrets/{name}")),
            format!("Saved a new version of {name}. The old value is still in its versions."),
        )),
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &vault_path(&vault, &format!("/secrets/{name}/value")),
        )),
    }
}

pub(crate) async fn edit_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    // The tag suggestions load beside the secret, within their own limit.
    let (fetched, suggest) = tokio::join!(
        fetch(&state, &session, shell, &vault, &name),
        tag_rows::for_vault(&state, &session, &vault),
    );
    let (shell, item) = fetched?;
    Ok(form_page(
        shell,
        vault,
        Mode::Properties,
        FormView::from_item(&item).suggesting(suggest),
        FieldErrors::new(),
        None,
    ))
}

pub(crate) async fn update(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(mut f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (shell, item) = fetch(&state, &session, shell, &vault, &name).await?;
    // The whole form is written back, so refuse if someone else saved a
    // new version or changed this one since the form was opened.
    if f.version != item.version() || f.updated != updated_stamp(&item) {
        return Err(changed_problem(shell, &vault, &name));
    }
    f.name = item.name().to_owned();
    f.value = None;
    let body = match form::for_update(&f, &item, now_ts(), crate::owner::Rules::of(&state.config)) {
        Ok(b) => b,
        Err(errors) => {
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            return Ok(form_page(
                shell,
                vault,
                Mode::Properties,
                FormView::from_form(&f, item.tags())
                    .typed_as(&item)
                    .suggesting(suggest),
                errors,
                None,
            ));
        }
    };
    let form_url = vault_path(&vault, &format!("/secrets/{}/edit", item.name()));
    let (shell, errors) = crate::routes::reveal_limit::loosening(
        &state,
        &session,
        shell,
        crate::audit::Action::SecretUpdate,
        item.tags(),
        body.tags.as_ref().unwrap_or(item.tags()),
        &f.reason,
        &f.ticket,
        &form_url,
    )?;
    if !errors.is_empty() {
        let suggest = tag_rows::for_vault(&state, &session, &vault).await;
        return Ok(form_page(
            shell,
            vault,
            Mode::Properties,
            FormView::from_form(&f, item.tags())
                .typed_as(&item)
                .suggesting(suggest),
            errors,
            None,
        ));
    }
    update_current(&state, &session, shell, &vault, &item, &body).await?;
    let name = item.name();
    Ok(saved(
        &state,
        &vault_path(&vault, &format!("/secrets/{name}")),
        format!("Saved changes to {name}."),
    ))
}

/// The page for an edit form that is out of date.
fn changed_problem(shell: Shell, vault: &str, name: &str) -> Halt {
    PageError::new(
        shell,
        Problem::new(
            StatusCode::CONFLICT,
            "This secret changed since you opened it",
            format!(
                "Someone saved a change to {name} after you opened the form, so nothing was saved. Open the form again to see the latest details, then make your change."
            ),
        )
        .returning_to(&vault_path(vault, &format!("/secrets/{name}/edit"))),
    )
    .into()
}

/// Save `body` onto the current version. The caller logs and redirects.
async fn update_current(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    item: &SecretItem,
    body: &UpdateSecret,
) -> Result<(), Halt> {
    let name = item.name();
    api(state, session, vault)
        .update(name, item.version(), body)
        .await
        .map(|_| ())
        .map_err(|err| {
            azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                &vault_path(vault, &format!("/secrets/{name}")),
            )
        })
}

/// Ask before disabling. Reads the secret first, so a missing or managed
/// secret gets the same page as the detail view would give.
pub(crate) async fn disable_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (fetched, used_by) = tokio::join!(
        fetch(&state, &session, shell, &vault, &name),
        used_by::for_item(&state, &session, &vault, Kind::Secret, &name),
    );
    let (shell, item) = fetched?;
    Ok(crate::routes::lifecycle::disable_page(
        shell,
        &vault,
        Kind::Secret,
        item.name(),
        used_by,
    ))
}

pub(crate) async fn toggle(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<ToggleForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let Some(enable) = f.enable() else {
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    let (shell, item) = fetch(&state, &session, shell, &vault, &name).await?;
    // Only `enabled` is sent. Key Vault keeps everything else.
    let body = UpdateSecret {
        content_type: None,
        attributes: crate::azure::secrets::UpdateAttributes {
            enabled: Some(enable),
            ..Default::default()
        },
        tags: None,
    };
    update_current(&state, &session, shell, &vault, &item, &body).await?;
    let name = item.name();
    let done = if enable { "Enabled" } else { "Disabled" };
    Ok(saved(
        &state,
        &vault_path(&vault, &format!("/secrets/{name}")),
        format!("{done} {name}."),
    ))
}
