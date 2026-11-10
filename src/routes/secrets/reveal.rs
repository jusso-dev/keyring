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
use crate::secret::Secret;

/// Seconds before the page hides a revealed value and the clipboard is
/// cleared. Only enforced by the browser script.
pub const CLEAR_AFTER_SECS: u32 = 30;

#[derive(Deserialize)]
pub struct RevealForm {
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
    clear_after: u32,
}

impl RevealedPage {
    /// The value for the textarea. The HTML parser drops one line break
    /// straight after `<textarea>`, so start with one. Otherwise a value
    /// that begins with a line break would lose it on screen and on Copy.
    fn value(&self) -> String {
        format!("\n{}", self.value.expose())
    }
}

/// The page shown when someone tries to read or change a certificate's
/// backing secret directly.
pub fn managed_problem(shell: Shell, name: &str) -> crate::routes::error::Halt {
    PageError::new(
        shell,
        Problem::new(
            axum::http::StatusCode::FORBIDDEN,
            "This secret belongs to a certificate",
            format!("{name} holds the certificate of the same name, including its private key. Use the certificate's page to download it, so you see the warning first."),
        )
        .with_next(crate::routes::error::NextStep::Go {
            url: format!("/certificates/{name}"),
            label: "Open the certificate",
        }),
    )
    .into()
}

/// Mark a response so browsers and proxies keep no copy.
pub fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    h.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

pub async fn reveal(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(form): Form<RevealForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    if !session.0.csrf_matches(&form.csrf) {
        return Err(PageError::new(shell, Problem::stale_form()).into());
    }
    let version = form.version.trim();
    if !version.is_empty() && !is_valid_version(version) {
        return Err(PageError::new(shell, Problem::not_found()).into());
    }
    let path = format!("/secrets/{name}");
    // A certificate's backing secret holds its private key. That goes
    // through the certificate's own download, with its warning and typed
    // name, never through reveal. Checked from properties, so no value is
    // read.
    match api(&state, &session, &vault).properties(&name).await {
        Ok(item) if item.managed.unwrap_or(false) => return Err(managed_problem(shell, &name)),
        Ok(_) => {}
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    }
    let bundle = match api(&state, &session, &vault)
        .get_value(&name, (!version.is_empty()).then_some(version))
        .await
    {
        Ok(b) => b,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadSecrets, &path)),
    };
    // Who read which secret is useful to the person running Keyring; the
    // value never is.
    tracing::info!(subject = %session.0.user.subject, vault = %vault, secret = %name, version = %bundle.item.version(), "secret value revealed");
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
        value: bundle.value,
        clear_after: CLEAR_AFTER_SECS,
        shell,
        vault,
    };
    Ok(no_store(render(&page).into_response()))
}
