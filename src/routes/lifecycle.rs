//! Delete, recover and purge pieces shared by certificates and keys.
//!
//! Every delete needs the item's name typed and checked on the server.
//! Purge is refused on the server unless `KEYRING_ALLOW_PURGE=true`.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::auth::CurrentSession;
use crate::dates;
use crate::routes::assets::render;
use crate::routes::confirm::{self, ConfirmForm, ConfirmView};
use crate::routes::error::{Halt, PageError, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::shell::Shell;

/// What kind of item, for wording and URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Key,
}

impl Kind {
    pub fn noun(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Key => "key",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Self::Certificate => "certificates",
            Self::Key => "keys",
        }
    }

    /// URL prefix, `/certificates` or `/keys`.
    pub fn base(self) -> &'static str {
        match self {
            Self::Certificate => "/certificates",
            Self::Key => "/keys",
        }
    }

    fn delete_effect(self) -> &'static str {
        match self {
            Self::Certificate => {
                "Its key and backing secret go with it, and apps using it lose access straight away."
            }
            Self::Key => {
                "Anything that encrypts, decrypts or signs with it will stop working straight away. Data encrypted with it can't be read until it's recovered."
            }
        }
    }
}

#[derive(Template)]
#[template(path = "lifecycle/confirm.html")]
struct ConfirmPage {
    shell: Shell,
    confirm: ConfirmView,
}

pub fn confirm_page(shell: Shell, confirm: ConfirmView, status: StatusCode) -> Response {
    (status, render(&ConfirmPage { shell, confirm })).into_response()
}

pub fn delete_view(kind: Kind, vault: &str, name: &str) -> ConfirmView {
    ConfirmView {
        heading: format!("Delete {name}?"),
        warning: format!(
            "{name} will move to deleted {} in {vault}. {} You can recover it until Key Vault purges it, usually 90 days.",
            kind.plural(),
            kind.delete_effect()
        ),
        expected: name.to_owned(),
        action: format!("{}/{name}/delete", kind.base()),
        button: format!("Delete {}", kind.noun()),
        cancel_url: format!("{}/{name}", kind.base()),
        second_warning: None,
        error: None,
    }
}

pub fn purge_view(kind: Kind, vault: &str, name: &str) -> ConfirmView {
    ConfirmView {
        heading: format!("Permanently delete {name}?"),
        warning: format!(
            "This removes {name} and every version of it from {vault} for good. It can't be recovered by you, Keyring or Microsoft."
        ),
        expected: name.to_owned(),
        action: format!("{}/deleted/{name}/purge", kind.base()),
        button: "Permanently delete".into(),
        cancel_url: format!("{}/deleted/{name}", kind.base()),
        second_warning: Some(match kind {
            Kind::Key => "Anything encrypted with this key can never be decrypted again. Only do this if you're sure.".into(),
            Kind::Certificate => "Only do this if you're sure nothing needs this certificate any more, or a policy requires it to be destroyed.".into(),
        }),
        error: None,
    }
}

/// Check the form token and typed name. On a mismatch, show the confirm
/// page again saying nothing was done.
pub fn verify(
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
        Err(e) => {
            let mut view = view;
            view.error = Some(e.problem(expected).message);
            Err(confirm_page(shell, view, StatusCode::UNPROCESSABLE_ENTITY).into())
        }
    }
}

/// With purge turned off, purge routes refuse everything.
pub fn purge_allowed(state: &AppState, shell: Shell, kind: Kind) -> Result<Shell, Halt> {
    if state.config.allow_purge {
        return Ok(shell);
    }
    let role = match kind {
        Kind::Certificate => "Key Vault Certificates Officer",
        Kind::Key => "Key Vault Crypto Officer",
    };
    Err(PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "Permanent delete is turned off",
            format!(
                "This Keyring doesn't allow permanent deletes. Deleted {} are kept until Key Vault purges them on schedule, and can be recovered until then.",
                kind.plural()
            ),
        )
        .with_hint(format!(
            "Whoever runs Keyring can turn this on with KEYRING_ALLOW_PURGE=true. You'd also need the {role} role."
        )),
    )
    .into())
}

/// A deleted item, ready to show.
pub struct DeletedRow {
    pub name: String,
    pub deleted: String,
    pub purge: String,
    pub purge_note: String,
}

impl DeletedRow {
    pub fn new(name: &str, deleted: Option<i64>, purge: Option<i64>, now: i64) -> Self {
        Self {
            name: name.to_owned(),
            deleted: deleted.map(dates::format_datetime).unwrap_or_default(),
            purge: purge.map(dates::format_date).unwrap_or_default(),
            purge_note: purge
                .map(|p| dates::relative_days(p, now))
                .unwrap_or_default(),
        }
    }
}

#[derive(Template)]
#[template(path = "lifecycle/deleted.html")]
struct DeletedList<'a> {
    shell: Shell,
    vault: String,
    kind: Kind,
    rows: &'a [DeletedRow],
}

pub fn deleted_list(shell: Shell, vault: String, kind: Kind, rows: &[DeletedRow]) -> Response {
    render(&DeletedList {
        shell,
        vault,
        kind,
        rows,
    })
    .into_response()
}

#[derive(Template)]
#[template(path = "lifecycle/deleted_detail.html")]
struct DeletedDetail<'a> {
    shell: Shell,
    vault: String,
    kind: Kind,
    row: &'a DeletedRow,
    allow_purge: bool,
}

pub fn deleted_detail(
    state: &AppState,
    shell: Shell,
    vault: String,
    kind: Kind,
    row: &DeletedRow,
) -> Response {
    render(&DeletedDetail {
        shell,
        vault,
        kind,
        row,
        allow_purge: state.config.allow_purge,
    })
    .into_response()
}

pub fn redirect_with(state: &AppState, to: &str, message: String) -> Response {
    let mut res = Redirect::to(to).into_response();
    flash::set(state, &mut res, &Flash::success(message));
    res
}
