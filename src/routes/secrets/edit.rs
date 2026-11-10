//! Create a secret, set a new value, edit properties, enable and disable.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::secrets::{SecretItem, SecretsApi, UpdateSecret, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::secrets::form::{self, FieldError, SecretForm};
use crate::routes::secrets::reveal::no_store;
use crate::routes::secrets::{api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;

/// Which form is being shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    NewValue,
    Properties,
}

/// Values to put back in the form. Never includes the secret value.
#[derive(Default)]
pub struct FormView {
    pub name: String,
    pub content_type: String,
    pub expires: String,
    pub not_before: String,
    pub tags: String,
    pub enabled: bool,
    /// Tags the textarea can't show without changing them. When set, the
    /// form lists them and keeps them as they are.
    pub locked_tags: Option<Vec<(String, String)>>,
    /// The version the edit form was opened on, and its `updated` time.
    pub version: String,
    pub updated: String,
}

impl FormView {
    fn from_form(f: &SecretForm) -> Self {
        Self {
            name: f.name.trim().to_owned(),
            content_type: f.content_type.clone(),
            expires: f.expires.clone(),
            not_before: f.not_before.clone(),
            tags: f.tags.clone(),
            enabled: f.enabled.is_some(),
            locked_tags: None,
            version: f.version.clone(),
            updated: f.updated.clone(),
        }
    }

    fn from_item(item: &SecretItem) -> Self {
        let a = &item.attributes;
        Self {
            name: item.name().to_owned(),
            content_type: item.content_type.clone().unwrap_or_default(),
            expires: a.expires.map(dates::iso_date).unwrap_or_default(),
            not_before: a.not_before.map(dates::iso_date).unwrap_or_default(),
            tags: form::format_tags(item.tags()),
            enabled: a.is_enabled(),
            locked_tags: None,
            version: item.version().to_owned(),
            updated: updated_stamp(item),
        }
        .locking_tags_of(item)
    }

    /// Lock the tags when the item's can't round-trip through the form.
    fn locking_tags_of(mut self, item: &SecretItem) -> Self {
        if !form::tags_editable(item.tags()) {
            self.tags.clear();
            self.locked_tags = Some(
                item.tags()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            );
        }
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
    errors: Vec<FieldError>,
    /// Set when a create clashed with a soft-deleted secret of the same name.
    deleted_clash: Option<String>,
}

impl FormPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }

    fn is_create(&self) -> bool {
        self.mode == Mode::Create
    }

    fn has_value_field(&self) -> bool {
        self.mode != Mode::Properties
    }

    fn action(&self) -> String {
        match self.mode {
            Mode::Create => "/secrets/new".into(),
            Mode::NewValue => format!("/secrets/{}/value", self.form.name),
            Mode::Properties => format!("/secrets/{}/edit", self.form.name),
        }
    }

    fn heading(&self) -> String {
        match self.mode {
            Mode::Create => "Add a secret".into(),
            Mode::NewValue => format!("New value for {}", self.form.name),
            Mode::Properties => format!("Edit {}", self.form.name),
        }
    }

    fn cancel_url(&self) -> String {
        match self.mode {
            Mode::Create => "/secrets".into(),
            _ => format!("/secrets/{}", self.form.name),
        }
    }
}

fn form_page(
    shell: Shell,
    vault: String,
    mode: Mode,
    form: FormView,
    errors: Vec<FieldError>,
    deleted_clash: Option<String>,
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
            }),
        )
            .into_response(),
    )
}

fn check_csrf(session: &CurrentSession, csrf: &str, shell: Shell) -> Result<Shell, Halt> {
    if session.0.csrf_matches(csrf) {
        Ok(shell)
    } else {
        Err(PageError::new(shell, Problem::stale_form()).into())
    }
}

fn saved(state: &AppState, to: &str, message: String) -> Response {
    let mut res = Redirect::to(to).into_response();
    flash::set(state, &mut res, &Flash::success(message));
    res
}

pub async fn new_form(session: CurrentSession, shell: Shell) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let view = FormView {
        enabled: true,
        ..FormView::default()
    };
    Ok(form_page(
        shell,
        vault,
        Mode::Create,
        view,
        Vec::new(),
        None,
    ))
}

/// Is there a soft-deleted secret with this name?
async fn is_soft_deleted(api: &SecretsApi<'_>, name: &str) -> bool {
    api.get_deleted(name).await.is_ok()
}

pub async fn create(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let (name, body) = match form::for_create(&f, now_ts()) {
        Ok(ok) => ok,
        Err(errors) => {
            return Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f),
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
            let errors = vec![FieldError {
                field: "name",
                message: format!(
                    "There's already a secret called {name}. Pick another name, or open it and set a new value."
                ),
            }];
            return Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f),
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
                "/secrets/new",
            ));
        }
    }

    match api.set(&name, &body).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret created");
            Ok(saved(
                &state,
                &format!("/secrets/{name}"),
                format!("Added {name}."),
            ))
        }
        Err(AzureError::Status { status: 409, .. }) if is_soft_deleted(&api, &name).await => {
            Ok(form_page(
                shell,
                vault,
                Mode::Create,
                FormView::from_form(&f),
                Vec::new(),
                Some(name),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            "/secrets/new",
        )),
    }
}

async fn load(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    name: &str,
) -> Result<(String, Shell, SecretItem), Halt> {
    let (vault, shell) = current_vault(session, shell)?;
    let (name, shell) = checked_name(name, shell)?;
    let (shell, item) = fetch(state, session, shell, &vault, &name).await?;
    Ok((vault, shell, item))
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
        Ok(item) if item.managed.unwrap_or(false) => {
            Err(crate::routes::secrets::reveal::managed_problem(shell, name))
        }
        Ok(item) => Ok((shell, item)),
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ReadSecrets,
            &format!("/secrets/{name}"),
        )),
    }
}

pub async fn value_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell, item) = load(&state, &session, shell, &name).await?;
    Ok(form_page(
        shell,
        vault,
        Mode::NewValue,
        FormView::from_item(&item),
        Vec::new(),
        None,
    ))
}

pub async fn set_value(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(mut f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    // Refuse a certificate's backing secret, and refuse if we can't tell.
    let item = match api(&state, &session, &vault).properties(&name).await {
        Ok(item) if item.managed.unwrap_or(false) => {
            return Err(crate::routes::secrets::reveal::managed_problem(
                shell, &name,
            ));
        }
        Ok(item) => item,
        Err(err) => {
            let path = format!("/secrets/{name}");
            return Err(azure_problem(shell, &err, Need::ManageSecrets, &path));
        }
    };
    f.name = name.clone();
    let body = match form::for_new_value(&f, &item, now_ts()) {
        Ok(b) => b,
        Err(errors) => {
            return Ok(form_page(
                shell,
                vault,
                Mode::NewValue,
                FormView::from_form(&f).locking_tags_of(&item),
                errors,
                None,
            ));
        }
    };
    match api(&state, &session, &vault).set(&name, &body).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret value changed");
            Ok(saved(
                &state,
                &format!("/secrets/{name}"),
                format!("Saved a new version of {name}. The old value is still in its history."),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/{name}/value"),
        )),
    }
}

pub async fn edit_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell, item) = load(&state, &session, shell, &name).await?;
    Ok(form_page(
        shell,
        vault,
        Mode::Properties,
        FormView::from_item(&item),
        Vec::new(),
        None,
    ))
}

pub async fn update(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(mut f): Form<SecretForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let (shell, item) = fetch(&state, &session, shell, &vault, &name).await?;
    // The whole form is written back, so refuse if someone else saved a
    // new version or changed this one since the form was opened.
    if f.version != item.version() || f.updated != updated_stamp(&item) {
        return Err(changed_problem(shell, &name));
    }
    f.name = item.name().to_owned();
    f.value = None;
    let body = match form::for_update(&f, &item, now_ts()) {
        Ok(b) => b,
        Err(errors) => {
            return Ok(form_page(
                shell,
                vault,
                Mode::Properties,
                FormView::from_form(&f).locking_tags_of(&item),
                errors,
                None,
            ));
        }
    };
    update_current(
        &state,
        &session,
        shell,
        &vault,
        &item,
        &body,
        "Saved changes",
    )
    .await
}

/// The page for an edit form that is out of date.
fn changed_problem(shell: Shell, name: &str) -> Halt {
    PageError::new(
        shell,
        Problem::new(
            StatusCode::CONFLICT,
            "This secret changed since you opened it",
            format!(
                "Someone saved a change to {name} after you opened the form, so nothing was saved. Open the form again to see the latest details, then make your change."
            ),
        )
        .returning_to(&format!("/secrets/{name}/edit")),
    )
    .into()
}

async fn update_current(
    state: &AppState,
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    item: &SecretItem,
    body: &UpdateSecret,
    done: &str,
) -> PageResult {
    let name = item.name();
    match api(state, session, vault)
        .update(name, item.version(), body)
        .await
    {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret properties changed");
            Ok(saved(
                state,
                &format!("/secrets/{name}"),
                format!("{done} to {name}."),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/{name}"),
        )),
    }
}

#[derive(Deserialize)]
pub struct ToggleForm {
    #[serde(default)]
    csrf: String,
    /// `on` or `off`.
    #[serde(default)]
    state: String,
}

pub async fn toggle(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<ToggleForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let enable = match f.state.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(PageError::new(shell, Problem::not_found()).into()),
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
    let done = if enable { "Enabled" } else { "Disabled" };
    let name = item.name().to_owned();
    match api(&state, &session, &vault)
        .update(&name, item.version(), &body)
        .await
    {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, enabled = enable, "secret enabled changed");
            Ok(saved(
                &state,
                &format!("/secrets/{name}"),
                format!("{done} {name}."),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/{name}"),
        )),
    }
}
