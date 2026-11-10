//! Key pages. Public parts only: nothing here can request or return
//! private key material.

pub mod delete;
pub mod edit;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::keys::{KeyBundle, KeyItem, KeysApi, RotationPolicy};
use crate::azure::secrets::{ExpiryState, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, NextStep, PageError, PageResult, Problem};
use crate::routes::lifecycle::redirect_with;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name};

/// Rows per page on the keys list, the same as secrets and certificates.
pub const PER_PAGE: usize = 100;

/// Names Keyring uses for its own pages under `/keys`, so a key called one
/// of these couldn't be opened from the list.
pub const RESERVED_NAMES: [&str; 2] = ["new", "deleted"];

/// Explain why a new key can't have this name, or `None` if it can.
pub fn reserved_name_problem(name: &str) -> Option<String> {
    RESERVED_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name))
        .then(|| {
            format!(
                "Keyring uses {name} for one of its own pages, so a key called that couldn't be opened here. Pick another name."
            )
        })
}

/// The page for a key that belongs to a certificate. Key Vault makes and
/// changes these keys itself, so Keyring won't change them directly.
pub fn managed_problem(shell: Shell, name: &str) -> Halt {
    PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "This key belongs to a certificate",
            format!("This key belongs to the certificate {name}. Change it from the certificate."),
        )
        .with_next(NextStep::Retry(format!("/certificates/{name}"))),
    )
    .into()
}

/// Read the key and refuse if it belongs to a certificate. A missing key
/// gets the normal not-found page.
pub async fn unmanaged_key(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
    shell: Shell,
) -> Result<(KeyBundle, Shell), Halt> {
    match api(state, session, vault).get(name, None).await {
        Ok(b) if b.managed.unwrap_or(false) => Err(managed_problem(shell, name)),
        Ok(b) => Ok((b, shell)),
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ReadKeys,
            &format!("/keys/{name}"),
        )),
    }
}

/// A part of a page that loads separately: what to say when it couldn't.
pub fn section_note(err: &AzureError, what: &str, role: &str) -> String {
    match err {
        AzureError::Status { status: 403, .. } => {
            format!("You can't see {what}. That needs the {role} role.")
        }
        _ => format!("Couldn't load {what} just now. Refresh the page to try again."),
    }
}

pub fn current_vault(session: &CurrentSession, shell: Shell) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, Section::Keys)
}

pub fn api<'a>(state: &'a AppState, session: &'a CurrentSession, vault: &str) -> KeysApi<'a> {
    KeysApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

pub struct KeyRow {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub created: String,
    pub expires: String,
    pub expires_note: String,
    pub expiry: ExpiryState,
    pub tags: Vec<(String, String)>,
    pub managed: bool,
    pub filter_text: String,
}

impl KeyRow {
    pub fn from_item(k: &KeyItem, now: i64) -> Self {
        let a = &k.attributes;
        let tags: Vec<(String, String)> = k
            .tags()
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        let mut filter_text = k.name().to_lowercase();
        for (a, b) in &tags {
            filter_text.push_str(&format!(" {a}={b}").to_lowercase());
        }
        Self {
            name: k.name().to_owned(),
            version: k.version().to_owned(),
            enabled: a.is_enabled(),
            created: a.created.map(dates::format_datetime).unwrap_or_default(),
            expires: a.expires.map(dates::format_date).unwrap_or_default(),
            expires_note: a
                .expires
                .map(|e| dates::relative_days(e, now))
                .unwrap_or_default(),
            expiry: a.expiry_state(now),
            tags,
            managed: k.managed.unwrap_or(false),
            filter_text,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiry == ExpiryState::Expired
    }
    pub fn is_expiring(&self) -> bool {
        self.expiry == ExpiryState::Soon
    }
    pub fn short_version(&self) -> String {
        self.version.chars().take(8).collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct KeyFilter {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl KeyFilter {
    fn page_url(&self, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        format!("/keys?q={}&page={page}", enc(&self.q))
    }
}

#[derive(Template)]
#[template(path = "keys/list.html")]
struct ListPage {
    shell: Shell,
    vault: String,
    rows: Vec<KeyRow>,
    total: usize,
    filter: KeyFilter,
    page: usize,
    pages: usize,
    shown_from: usize,
    prev_url: Option<String>,
    next_url: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<KeyFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let items = match api(&state, &session, &vault).list().await {
        Ok(i) => i,
        Err(e) => return Err(azure_problem(shell, &e, Need::ReadKeys, "/keys")),
    };
    let now = now_ts();
    let all: Vec<KeyRow> = items.iter().map(|k| KeyRow::from_item(k, now)).collect();
    let total = all.len();
    let q = filter.q.trim().to_lowercase();
    let matching: Vec<KeyRow> = all
        .into_iter()
        .filter(|r| q.is_empty() || r.filter_text.contains(&q))
        .collect();
    let pages = matching.len().div_ceil(PER_PAGE).max(1);
    let page = filter.page.unwrap_or(1).clamp(1, pages);
    let shown_from = (page - 1) * PER_PAGE;
    let rows = matching
        .into_iter()
        .skip(shown_from)
        .take(PER_PAGE)
        .collect();
    Ok(render(&ListPage {
        prev_url: (page > 1).then(|| filter.page_url(page - 1)),
        next_url: (page < pages).then(|| filter.page_url(page + 1)),
        shell,
        vault,
        rows,
        total,
        filter,
        page,
        pages,
        shown_from,
    })
    .into_response())
}

pub struct RotationView {
    pub rotate_after: String,
    pub notify_before: String,
    pub expiry: String,
    pub any: bool,
}

impl RotationView {
    fn from_policy(p: &RotationPolicy) -> Self {
        let days = |d: Option<u32>| d.map(|d| format!("{d} days")).unwrap_or_default();
        let rotate_after = match (p.rotate_after_days(), p.rotate_before_expiry_days()) {
            (Some(d), _) => format!("{d} days after each version is made"),
            (_, Some(d)) => format!("{d} days before each version expires"),
            _ => String::new(),
        };
        Self {
            any: !p.is_key_vault_default()
                && (!p.lifetime_actions.is_empty() || p.expiry().is_some()),
            notify_before: days(p.notify_before_days()),
            expiry: days(p.expiry_days()),
            rotate_after,
        }
    }
}

#[derive(Template)]
#[template(path = "keys/detail.html")]
struct DetailPage {
    shell: Shell,
    vault: String,
    row: KeyRow,
    kind: String,
    operations: Vec<&'static str>,
    pem: Option<String>,
    jwk: String,
    versions: Vec<KeyRow>,
    /// Set when the versions couldn't be read.
    versions_note: Option<String>,
    rotation: Option<RotationView>,
    /// Set when the rotation policy couldn't be read.
    rotation_note: Option<String>,
    hsm: bool,
}

/// Plain names for permitted operations.
fn op_label(op: &str) -> &'static str {
    match op {
        "encrypt" => "Encrypt",
        "decrypt" => "Decrypt",
        "sign" => "Sign",
        "verify" => "Verify signatures",
        "wrapKey" => "Wrap other keys",
        "unwrapKey" => "Unwrap other keys",
        "import" => "Import",
        "export" => "Release to a trusted environment",
        _ => "Other",
    }
}

fn bundle_row(b: &KeyBundle, now: i64) -> KeyRow {
    KeyRow::from_item(
        &KeyItem {
            kid: b.kid().to_owned(),
            attributes: b.attributes.clone(),
            tags: b.tags.clone(),
            managed: b.managed,
        },
        now,
    )
}

pub async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let keys = api(&state, &session, &vault);
    let (bundle, versions, rotation) = tokio::join!(
        keys.get(&name, None),
        keys.versions(&name),
        keys.rotation_policy(&name)
    );
    let bundle = match bundle {
        Ok(b) => b,
        Err(e) => {
            return Err(azure_problem(
                shell,
                &e,
                Need::ReadKeys,
                &format!("/keys/{name}"),
            ));
        }
    };
    let now = now_ts();
    // Each section says why it's empty rather than pretending there's
    // nothing there.
    let (versions, versions_note) = match versions {
        Ok(v) => (v.iter().map(|v| KeyRow::from_item(v, now)).collect(), None),
        Err(e) => {
            tracing::warn!(vault = %vault, key = %name, error = %e, "couldn't read key versions");
            (
                Vec::new(),
                Some(section_note(
                    &e,
                    "this key's versions",
                    Need::ReadKeys.role(),
                )),
            )
        }
    };
    let (rotation, rotation_note) = match rotation {
        Ok(p) => (Some(RotationView::from_policy(&p)), None),
        Err(AzureError::Status { status: 404, .. }) => (None, None),
        Err(e) => {
            tracing::warn!(vault = %vault, key = %name, error = %e, "couldn't read key rotation policy");
            (
                None,
                Some(section_note(
                    &e,
                    "the rotation policy",
                    Need::ManageKeys.role(),
                )),
            )
        }
    };
    Ok(render(&DetailPage {
        row: bundle_row(&bundle, now),
        kind: bundle.key.describe(),
        hsm: bundle.key.kty.ends_with("-HSM"),
        operations: bundle.key.key_ops.iter().map(|o| op_label(o)).collect(),
        pem: bundle.key.to_pem(),
        jwk: bundle.key.to_json(),
        versions,
        versions_note,
        rotation,
        rotation_note,
        shell,
        vault,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct ToggleForm {
    #[serde(default)]
    csrf: String,
    /// `on` or `off`.
    #[serde(default)]
    state: String,
}

/// Enable or disable the current version, like the secrets page does.
pub async fn toggle(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<ToggleForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let enable = match f.state.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(PageError::new(shell, Problem::not_found()).into()),
    };
    let (bundle, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    let path = format!("/keys/{name}");
    match api(&state, &session, &vault)
        .set_enabled(&name, bundle.version(), enable)
        .await
    {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, enabled = enable, "key enabled changed");
            let done = if enable { "Enabled" } else { "Disabled" };
            Ok(redirect_with(&state, &path, format!("{done} {name}.")))
        }
        Err(e) => Err(azure_problem(shell, &e, Need::ManageKeys, &path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_are_refused() {
        for n in ["new", "deleted", "New"] {
            assert!(reserved_name_problem(n).is_some(), "{n}");
        }
        for n in ["news", "app-key", "upload"] {
            assert!(reserved_name_problem(n).is_none(), "{n}");
        }
    }
}
