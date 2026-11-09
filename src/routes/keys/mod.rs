//! Key pages. Public parts only: nothing here can request or return
//! private key material.

pub mod delete;
pub mod edit;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::keys::{KeyBundle, KeyItem, KeysApi, RotationPolicy};
use crate::azure::secrets::{ExpiryState, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageResult};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, azure_problem, checked_name};

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
}

#[derive(Template)]
#[template(path = "keys/list.html")]
struct ListPage {
    shell: Shell,
    vault: String,
    rows: Vec<KeyRow>,
    total: usize,
    filter: KeyFilter,
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
    let rows = all
        .into_iter()
        .filter(|r| q.is_empty() || r.filter_text.contains(&q))
        .collect();
    Ok(render(&ListPage {
        shell,
        vault,
        rows,
        total,
        filter,
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
            any: !p.lifetime_actions.is_empty() || p.expiry_days().is_some(),
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
    rotation: Option<RotationView>,
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
        "export" => "Export (release to a trusted environment)",
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
    // Reading the rotation policy needs a higher role; just leave it out
    // if the person can't.
    let rotation = match rotation {
        Ok(p) => Some(RotationView::from_policy(&p)),
        Err(AzureError::Status {
            status: 403 | 404, ..
        }) => None,
        Err(_) => None,
    };
    Ok(render(&DetailPage {
        row: bundle_row(&bundle, now),
        kind: bundle.key.describe(),
        hsm: bundle.key.kty.ends_with("-HSM"),
        operations: bundle.key.key_ops.iter().map(|o| op_label(o)).collect(),
        pem: bundle.key.to_pem(),
        jwk: bundle.key.to_json(),
        versions: versions
            .unwrap_or_default()
            .iter()
            .map(|v| KeyRow::from_item(v, now))
            .collect(),
        rotation,
        shell,
        vault,
    })
    .into_response())
}
