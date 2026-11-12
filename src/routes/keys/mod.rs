//! Key pages. Public parts only: nothing here can request or return
//! private key material.

pub(super) mod delete;
pub(super) mod edit;

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
use crate::routes::forms::ToggleForm;
use crate::routes::lifecycle::{Kind, redirect_with};
use crate::routes::paging::{Pager, paginate};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name, vault_path};

/// The page for a key that belongs to a certificate. Key Vault makes and
/// changes these keys itself, so Keyring won't change them directly.
pub(super) fn managed_problem(shell: Shell, vault: &str, name: &str) -> Halt {
    PageError::new(
        shell,
        Problem::new(
            StatusCode::FORBIDDEN,
            "This key belongs to a certificate",
            format!("This key belongs to the certificate {name}. Change it from the certificate."),
        )
        .with_next(NextStep::Retry(vault_path(
            vault,
            &format!("/certificates/{name}"),
        ))),
    )
    .into()
}

/// Read the key and refuse if it belongs to a certificate. A missing key
/// gets the normal not-found page.
pub(super) async fn unmanaged_key(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
    shell: Shell,
) -> Result<(KeyBundle, Shell), Halt> {
    match api(state, session, vault).get(name, None).await {
        Ok(b) if b.managed.unwrap_or(false) => Err(managed_problem(shell, vault, name)),
        Ok(b) => Ok((b, shell)),
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ReadKeys,
            &vault_path(vault, &format!("/keys/{name}")),
        )),
    }
}

/// A part of a page that loads separately: what to say when it couldn't.
pub(super) fn section_note(err: &AzureError, what: &str, role: &str) -> String {
    match err {
        AzureError::Status { status: 403, .. } => {
            format!("You can't see {what}. That needs the {role} role.")
        }
        _ => format!("Couldn't load {what} just now. Refresh the page to try again."),
    }
}

pub(super) fn current_vault(
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
) -> Result<(String, Shell), Halt> {
    vault_ctx::path_vault(session, shell, Section::Keys, vault)
}

pub(super) fn api<'a>(
    state: &'a AppState,
    session: &'a CurrentSession,
    vault: &str,
) -> KeysApi<'a> {
    KeysApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

pub(super) struct KeyRow {
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
    pub(super) fn from_item(k: &KeyItem, now: i64) -> Self {
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

    pub(super) fn is_expired(&self) -> bool {
        self.expiry == ExpiryState::Expired
    }
    pub(super) fn is_expiring(&self) -> bool {
        self.expiry == ExpiryState::Soon
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct KeyFilter {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl KeyFilter {
    fn page_url(&self, vault: &str, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        vault_path(vault, &format!("/keys?q={}&page={page}", enc(&self.q)))
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
    pager: Pager,
}

pub(super) async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(filter): Query<KeyFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let items = match api(&state, &session, &vault).list().await {
        Ok(i) => i,
        Err(e) => {
            return Err(azure_problem(
                shell,
                &e,
                Need::ReadKeys,
                &vault_path(&vault, "/keys"),
            ));
        }
    };
    let now = now_ts();
    let all: Vec<KeyRow> = items.iter().map(|k| KeyRow::from_item(k, now)).collect();
    let total = all.len();
    let q = filter.q.trim().to_lowercase();
    let matching: Vec<KeyRow> = all
        .into_iter()
        .filter(|r| q.is_empty() || r.filter_text.contains(&q))
        .collect();
    let (rows, pager) = paginate(matching, filter.page, "keys", |p| {
        filter.page_url(&vault, p)
    });
    Ok(render(&ListPage {
        pager,
        shell,
        vault,
        rows,
        total,
        filter,
    })
    .into_response())
}

pub(super) struct RotationView {
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

pub(super) async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    uri: axum::http::Uri,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
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
            if let Some(res) =
                crate::routes::moved::missing_item(&vault, Kind::Key, &name, &e, &uri)
            {
                return Ok(res);
            }
            return Err(azure_problem(
                shell,
                &e,
                Need::ReadKeys,
                &vault_path(&vault, &format!("/keys/{name}")),
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

/// Ask before disabling. A key that belongs to a certificate is refused
/// here too.
pub(super) async fn disable_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    Ok(crate::routes::lifecycle::disable_page(
        shell,
        &vault,
        crate::routes::lifecycle::Kind::Key,
        &name,
    ))
}

/// Enable or disable the current version, like the secrets page does.
pub(super) async fn toggle(
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
    let (bundle, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    let path = vault_path(&vault, &format!("/keys/{name}"));
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
