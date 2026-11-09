//! Delete (soft), the deleted secrets list, recover and purge.
//!
//! Delete needs the secret's name typed in, checked on the server. Purge is
//! off unless `KEYRING_ALLOW_PURGE=true`; with it off the purge routes
//! refuse every request, whatever the browser sends.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::{DeletedSecretItem, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::confirm::{self, ConfirmForm, ConfirmView};
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::secrets::{api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;

#[derive(Template)]
#[template(path = "secrets/confirm.html")]
struct ConfirmPage {
    shell: Shell,
    confirm: ConfirmView,
}

pub struct DeletedRow {
    pub name: String,
    pub deleted: String,
    pub purge: String,
    pub purge_note: String,
    pub content_type: String,
}

impl DeletedRow {
    fn from_item(d: &DeletedSecretItem, now: i64) -> Self {
        Self {
            name: d.name().to_owned(),
            deleted: d
                .deleted_date
                .map(dates::format_datetime)
                .unwrap_or_default(),
            purge: d
                .scheduled_purge_date
                .map(dates::format_date)
                .unwrap_or_default(),
            purge_note: d
                .scheduled_purge_date
                .map(|p| dates::relative_days(p, now))
                .unwrap_or_default(),
            content_type: d.content_type.clone().unwrap_or_default(),
        }
    }
}

#[derive(Template)]
#[template(path = "secrets/deleted.html")]
struct DeletedList {
    shell: Shell,
    vault: String,
    rows: Vec<DeletedRow>,
}

#[derive(Template)]
#[template(path = "secrets/deleted_detail.html")]
struct DeletedDetail {
    shell: Shell,
    vault: String,
    row: DeletedRow,
    allow_purge: bool,
}

fn redirect_with(state: &AppState, to: &str, flash: Flash) -> axum::response::Response {
    let mut res = Redirect::to(to).into_response();
    flash::set(state, &mut res, &flash);
    res
}

fn confirm_page(
    shell: Shell,
    confirm: ConfirmView,
    status: StatusCode,
) -> axum::response::Response {
    (status, render(&ConfirmPage { shell, confirm })).into_response()
}

fn delete_view(vault: &str, name: &str) -> ConfirmView {
    ConfirmView {
        heading: format!("Delete {name}?"),
        warning: format!(
            "{name} will move to deleted secrets in {vault}. Apps using it will stop being able to read it straight away. You can recover it until Key Vault purges it, usually 90 days."
        ),
        expected: name.to_owned(),
        action: format!("/secrets/{name}/delete"),
        button: "Delete secret".into(),
        cancel_url: format!("/secrets/{name}"),
        second_warning: None,
        error: None,
    }
}

pub async fn delete_form(
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    Ok(confirm_page(
        shell,
        delete_view(&vault, &name),
        StatusCode::OK,
    ))
}

/// Check the typed name. On a mismatch, show the form again with a message.
fn verify(
    session: &CurrentSession,
    form: &ConfirmForm,
    expected: &str,
    shell: Shell,
    view: ConfirmView,
) -> Result<Shell, Halt> {
    match confirm::verify(&session.0, form, expected) {
        Ok(()) => Ok(shell),
        Err(confirm::ConfirmError::StaleForm) => {
            Err(PageError::new(shell, Problem::stale_form()).into())
        }
        Err(e @ confirm::ConfirmError::NameMismatch) => {
            let mut view = view;
            view.error = Some(e.problem(expected).message);
            Err(confirm_page(shell, view, StatusCode::UNPROCESSABLE_ENTITY).into())
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = verify(&session, &form, &name, shell, delete_view(&vault, &name))?;
    // Refuse a certificate's backing secret, and refuse if we can't tell.
    match api(&state, &session, &vault).properties(&name).await {
        Ok(item) if item.managed.unwrap_or(false) => {
            return Err(crate::routes::secrets::reveal::managed_problem(
                shell, &name,
            ));
        }
        Ok(_) => {}
        Err(err) => {
            let path = format!("/secrets/{name}");
            return Err(azure_problem(shell, &err, Need::ManageSecrets, &path));
        }
    }
    match api(&state, &session, &vault).delete(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret deleted");
            Ok(redirect_with(
                &state,
                "/secrets",
                Flash::success(format!(
                    "Deleted {name}. You can recover it from deleted secrets."
                )),
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

pub async fn list_deleted(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let items = match api(&state, &session, &vault).list_deleted().await {
        Ok(i) => i,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                "/secrets/deleted",
            ));
        }
    };
    let now = now_ts();
    Ok(render(&DeletedList {
        rows: items
            .iter()
            .map(|d| DeletedRow::from_item(d, now))
            .collect(),
        shell,
        vault,
    })
    .into_response())
}

pub async fn deleted_detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let item = match api(&state, &session, &vault).get_deleted(&name).await {
        Ok(i) => i,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                "/secrets/deleted",
            ));
        }
    };
    Ok(render(&DeletedDetail {
        row: DeletedRow::from_item(&item, now_ts()),
        allow_purge: state.config.allow_purge,
        shell,
        vault,
    })
    .into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

pub async fn recover(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    if !session.0.csrf_matches(&form.csrf) {
        return Err(PageError::new(shell, Problem::stale_form()).into());
    }
    match api(&state, &session, &vault).recover(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret recovered");
            Ok(redirect_with(
                &state,
                &format!("/secrets/{name}"),
                Flash::success(format!(
                    "Recovered {name}, with its value and history. It can take a few seconds to show everywhere."
                )),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/deleted/{name}"),
        )),
    }
}

fn purge_view(vault: &str, name: &str) -> ConfirmView {
    ConfirmView {
        heading: format!("Permanently delete {name}?"),
        warning: format!(
            "This removes {name} and every version of it from {vault} for good. It can't be recovered by you, Keyring or Microsoft."
        ),
        expected: name.to_owned(),
        action: format!("/secrets/deleted/{name}/purge"),
        button: "Permanently delete".into(),
        cancel_url: format!("/secrets/deleted/{name}"),
        second_warning: Some(
            "Only do this if you're sure nothing needs this secret any more, or a policy requires it to be destroyed.".into(),
        ),
        error: None,
    }
}

/// With purge turned off, these routes refuse everything.
fn purge_allowed(state: &AppState, shell: Shell) -> Result<Shell, Halt> {
    if state.config.allow_purge {
        Ok(shell)
    } else {
        Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::FORBIDDEN,
                "Permanent delete is turned off",
                "This Keyring doesn't allow permanent deletes. Deleted secrets are kept until Key Vault purges them on schedule, and can be recovered until then.",
            )
            .with_hint("Whoever runs Keyring can turn this on with KEYRING_ALLOW_PURGE=true. You'd also need the Key Vault Secrets Officer role."),
        )
        .into())
    }
}

pub async fn purge_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let shell = purge_allowed(&state, shell)?;
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    Ok(confirm_page(
        shell,
        purge_view(&vault, &name),
        StatusCode::OK,
    ))
}

pub async fn purge(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let shell = purge_allowed(&state, shell)?;
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = verify(&session, &form, &name, shell, purge_view(&vault, &name))?;
    match api(&state, &session, &vault).purge(&name).await {
        Ok(()) => {
            tracing::warn!(subject = %session.0.user.subject, vault = %vault, secret = %name, "secret purged");
            Ok(redirect_with(
                &state,
                "/secrets/deleted",
                Flash::success(format!("Permanently deleted {name}.")),
            ))
        }
        Err(err) => Err(azure_problem(
            shell,
            &err,
            Need::ManageSecrets,
            &format!("/secrets/deleted/{name}"),
        )),
    }
}
