//! Reveal a secret's value on request.
//!
//! Reveal is a form post, so it works without JavaScript and can't be
//! triggered by a link or a prefetch. The value is only in that one
//! response, which is marked `no-store`. It is never logged.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::HeaderValue;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::secrets::{is_valid_version, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::secrets::{SecretRow, api, azure_problem, checked_name, current_vault};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::vault_path;
use crate::secret::Secret;
use crate::secret_types::{ContentKind, SecretType, TypedValue, classify};

/// One field on the reveal page. Every one is part of the value.
pub(crate) struct ShownField {
    /// Element id, `field-<name>`.
    pub id: String,
    pub label: &'static str,
    pub multiline: bool,
    pub value: Secret,
}

impl ShownField {
    /// The value for a textarea, with the line break the HTML parser drops.
    fn text(&self) -> String {
        format!("\n{}", self.value.expose())
    }
}

/// How the reveal page shows a value.
enum Shown {
    Plain,
    Typed {
        kind: SecretType,
        fields: Vec<ShownField>,
        /// Database only: connection strings built from the fields.
        connections: Vec<ShownField>,
    },
    /// A Keyring content type whose value isn't in the type's shape, or a
    /// type or version this build doesn't know.
    Malformed,
}

fn shown(content_type: Option<&str>, value: &Secret) -> Shown {
    let kind = match classify(content_type) {
        ContentKind::Plain => return Shown::Plain,
        ContentKind::Unknown => return Shown::Malformed,
        ContentKind::Typed(k) => k,
    };
    let Ok(typed) = TypedValue::decode(kind, value) else {
        return Shown::Malformed;
    };
    let fields = typed
        .fields()
        .map(|(f, v)| ShownField {
            id: format!("field-{}", f.name),
            label: f.label,
            multiline: f.multiline,
            value: v.clone(),
        })
        .collect();
    let connections = [
        (
            "conn-sqlserver",
            "SQL Server connection string",
            typed.sql_server(),
        ),
        (
            "conn-postgres",
            "PostgreSQL connection string",
            typed.postgres(),
        ),
    ]
    .into_iter()
    .filter_map(|(id, label, v)| {
        v.map(|value| ShownField {
            id: id.into(),
            label,
            multiline: false,
            value,
        })
    })
    .collect();
    Shown::Typed {
        kind,
        fields,
        connections,
    }
}

/// Seconds before the page hides a revealed value and the clipboard is
/// cleared. Only enforced by the browser script.
pub(crate) const CLEAR_AFTER_SECS: u32 = 30;

#[derive(Deserialize)]
pub(crate) struct RevealForm {
    #[serde(default)]
    csrf: String,
    /// A specific version, or empty for the current one.
    #[serde(default)]
    version: String,
}

#[derive(Template)]
#[template(path = "secrets/revealed.html")]
struct RevealedPage {
    shell: Shell,
    vault: String,
    row: SecretRow,
    version: String,
    is_current: bool,
    created: String,
    /// Rendered into the page once, HTML-escaped by Askama.
    value: Secret,
    shown: Shown,
    clear_after: u32,
}

impl RevealedPage {
    /// The value for the textarea. The HTML parser drops one line break
    /// straight after `<textarea>`, so start with one. Otherwise a value
    /// that begins with a line break would lose it on screen and on Copy.
    fn value(&self) -> String {
        format!("\n{}", self.value.expose())
    }

    fn type_label(&self) -> &'static str {
        match &self.shown {
            Shown::Typed { kind, .. } => kind.label(),
            _ => "",
        }
    }

    fn fields(&self) -> &[ShownField] {
        match &self.shown {
            Shown::Typed { fields, .. } => fields,
            _ => &[],
        }
    }

    fn connections(&self) -> &[ShownField] {
        match &self.shown {
            Shown::Typed { connections, .. } => connections,
            _ => &[],
        }
    }

    fn is_malformed(&self) -> bool {
        matches!(self.shown, Shown::Malformed)
    }
}

/// The page shown when someone tries to read or change a certificate's
/// backing secret directly.
pub(crate) fn managed_problem(shell: Shell, vault: &str, name: &str) -> crate::routes::error::Halt {
    crate::audit::refuse(crate::audit::Refusal::ManagedItem);
    PageError::new(
        shell,
        Problem::new(
            axum::http::StatusCode::FORBIDDEN,
            "This secret belongs to a certificate",
            format!("{name} holds the certificate of the same name, including its private key. Use the certificate's page to download it, so you see the warning first."),
        )
        .with_next(crate::routes::error::NextStep::Go {
            url: vault_path(vault, &format!("/certificates/{name}")),
            label: "Open the certificate",
        }),
    )
    .into()
}

/// Mark a response so browsers and proxies keep no copy.
pub(crate) fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    h.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

pub(crate) async fn reveal(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(form): Form<RevealForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = crate::routes::vault_ctx::check_csrf(&session, &vault, &form.csrf, shell)?;
    let shell = crate::routes::audit_gate::require_audit(&state, shell)?;
    let version = form.version.trim();
    if !version.is_empty() && !is_valid_version(version) {
        crate::audit::refuse(crate::audit::Refusal::InvalidRequest);
        return Err(PageError::new(shell, Problem::not_found()).into());
    }
    let path = vault_path(&vault, &format!("/secrets/{name}"));
    // Back to the page with the Reveal button: the versions list for an
    // older version, otherwise the secret's own page.
    let confirm = if version.is_empty() {
        path.clone()
    } else {
        format!("{path}/versions")
    };
    let shell = crate::routes::step_up::require(&state, &session.0, shell, &confirm, &confirm)?;
    // A certificate's backing secret holds its private key. That goes
    // through the certificate's own download, with its warning and typed
    // name, never through reveal. Checked from properties, so no value is
    // read.
    match api(&state, &session, &vault).properties(&name).await {
        Ok(item) if item.managed.unwrap_or(false) => {
            return Err(managed_problem(shell, &vault, &name));
        }
        // Who watches the item comes from its current version's tags,
        // whichever version is read: Key Vault keeps tags per version, and
        // Keyring writes them to the current one.
        Ok(item) => crate::notify::activity::note_read(item.tags.as_ref()),
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    }
    let bundle = match api(&state, &session, &vault)
        .get_value(&name, (!version.is_empty()).then_some(version))
        .await
    {
        Ok(b) => b,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    };
    // Which version was read goes on the audit event. The value never does.
    crate::audit::note_version(bundle.item.version());
    let now = now_ts();
    let page = RevealedPage {
        version: bundle.item.version().to_owned(),
        is_current: version.is_empty(),
        created: bundle
            .item
            .attributes
            .created
            .map(dates::format_datetime)
            .unwrap_or_default(),
        row: SecretRow::from_item(&bundle.item, now),
        shown: shown(bundle.item.content_type.as_deref(), &bundle.value),
        value: bundle.value,
        clear_after: CLEAR_AFTER_SECS,
        shell,
        vault,
    };
    Ok(no_store(render(&page).into_response()))
}
