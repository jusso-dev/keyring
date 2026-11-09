//! Create keys, rotate now and edit the rotation policy.

use std::collections::BTreeMap;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::keys::{CreateKey, RotationPolicy};
use crate::azure::secrets::{Attributes, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageResult};
use crate::routes::lifecycle::redirect_with;
use crate::routes::secrets::form::{FieldError, name_problem, parse_tags};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name};

use super::{api, current_vault};

pub const KEY_TYPES: [(&str, &str); 7] = [
    ("RSA-3072", "RSA 3072 (recommended)"),
    ("RSA-2048", "RSA 2048"),
    ("RSA-4096", "RSA 4096"),
    ("EC-P-256", "EC P-256"),
    ("EC-P-384", "EC P-384"),
    ("EC-P-521", "EC P-521"),
    ("EC-P-256K", "EC P-256K (secp256k1)"),
];

pub const OPERATIONS: [(&str, &str); 6] = [
    ("encrypt", "Encrypt"),
    ("decrypt", "Decrypt"),
    ("sign", "Sign"),
    ("verify", "Verify signatures"),
    ("wrapKey", "Wrap other keys"),
    ("unwrapKey", "Unwrap other keys"),
];

/// HTML forms send repeated checkboxes as repeated fields, so read the
/// raw pairs.
pub struct CreateForm {
    pub csrf: String,
    pub name: String,
    pub key_type: String,
    pub hsm: bool,
    pub ops: Vec<String>,
    pub expires: String,
    pub tags: String,
}

impl CreateForm {
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let mut f = Self {
            csrf: String::new(),
            name: String::new(),
            key_type: String::new(),
            hsm: false,
            ops: Vec::new(),
            expires: String::new(),
            tags: String::new(),
        };
        for (k, v) in pairs {
            match k.as_str() {
                "csrf" => f.csrf = v,
                "name" => f.name = v.trim().to_owned(),
                "key_type" => f.key_type = v,
                "hsm" => f.hsm = true,
                "ops" => f.ops.push(v),
                "expires" => f.expires = v,
                "tags" => f.tags = v,
                _ => {}
            }
        }
        f
    }

    fn defaults() -> Self {
        Self {
            csrf: String::new(),
            name: String::new(),
            key_type: KEY_TYPES[0].0.into(),
            hsm: false,
            ops: Vec::new(),
            expires: String::new(),
            tags: String::new(),
        }
    }
}

fn err(field: &'static str, message: impl Into<String>) -> FieldError {
    FieldError {
        field,
        message: message.into(),
    }
}

/// Default operations for a key type: RSA can encrypt, sign and wrap; EC
/// can only sign.
pub fn default_ops(kty: &str) -> Vec<String> {
    if kty.starts_with("EC") {
        vec!["sign".into(), "verify".into()]
    } else {
        OPERATIONS.iter().map(|(o, _)| (*o).to_owned()).collect()
    }
}

pub fn build(f: &CreateForm, now: i64) -> Result<(String, CreateKey), Vec<FieldError>> {
    let mut errors = Vec::new();
    if let Some(m) = name_problem(&f.name) {
        errors.push(err("name", m.replace("the secret", "the key")));
    }
    let (mut kty, key_size, crv): (String, Option<u32>, Option<String>) = match f.key_type.as_str()
    {
        "" | "RSA-3072" => ("RSA".into(), Some(3072), None),
        "RSA-2048" => ("RSA".into(), Some(2048), None),
        "RSA-4096" => ("RSA".into(), Some(4096), None),
        "EC-P-256" => ("EC".into(), None, Some("P-256".into())),
        "EC-P-384" => ("EC".into(), None, Some("P-384".into())),
        "EC-P-521" => ("EC".into(), None, Some("P-521".into())),
        "EC-P-256K" => ("EC".into(), None, Some("P-256K".into())),
        _ => {
            errors.push(err("key_type", "Pick a key type from the list."));
            ("RSA".into(), Some(3072), None)
        }
    };
    if f.hsm {
        kty.push_str("-HSM");
    }
    let ops = if f.ops.is_empty() {
        default_ops(&kty)
    } else {
        f.ops.clone()
    };
    if ops.iter().any(|o| !OPERATIONS.iter().any(|(k, _)| k == o)) {
        errors.push(err("ops", "Pick operations from the list."));
    }
    if kty.starts_with("EC") && ops.iter().any(|o| !matches!(o.as_str(), "sign" | "verify")) {
        errors.push(err(
            "ops",
            "EC keys can only sign and verify. Pick an RSA key to encrypt or wrap keys.",
        ));
    }
    let expires = match f.expires.trim() {
        "" => None,
        s => match dates::parse_iso_date(s) {
            Some(d) if d + 86_399 > now => Some(d + 86_399),
            Some(_) => {
                errors.push(err(
                    "expires",
                    "The expiry date has already passed. Pick a later date, or leave it blank.",
                ));
                None
            }
            None => {
                errors.push(err(
                    "expires",
                    "Expiry date isn't a real date. Use the date picker or type YYYY-MM-DD.",
                ));
                None
            }
        },
    };
    let tags: BTreeMap<String, String> = parse_tags(&f.tags).unwrap_or_else(|m| {
        errors.push(err("tags", m));
        BTreeMap::new()
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok((
        f.name.clone(),
        CreateKey {
            kty,
            key_size,
            crv,
            key_ops: ops,
            attributes: Attributes {
                enabled: Some(true),
                expires,
                ..Attributes::default()
            },
            tags: Some(tags),
        },
    ))
}

#[derive(Template)]
#[template(path = "keys/create.html")]
struct CreatePage {
    shell: Shell,
    vault: String,
    form: CreateForm,
    errors: Vec<FieldError>,
}

impl CreatePage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }
    fn key_types(&self) -> &'static [(&'static str, &'static str)] {
        &KEY_TYPES
    }
    fn operations(&self) -> &'static [(&'static str, &'static str)] {
        &OPERATIONS
    }
    fn op_checked(&self, op: &str) -> bool {
        self.form.ops.iter().any(|o| o == op)
    }
}

fn create_page(
    shell: Shell,
    vault: String,
    form: CreateForm,
    errors: Vec<FieldError>,
) -> axum::response::Response {
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        render(&CreatePage {
            shell,
            vault,
            form,
            errors,
        }),
    )
        .into_response()
}

pub async fn create_form(session: CurrentSession, shell: Shell) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    Ok(create_page(
        shell,
        vault,
        CreateForm::defaults(),
        Vec::new(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(pairs): Form<Vec<(String, String)>>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let f = CreateForm::from_pairs(pairs);
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let (name, body) = match build(&f, now_ts()) {
        Ok(ok) => ok,
        Err(errors) => return Ok(create_page(shell, vault, f, errors)),
    };
    let keys = api(&state, &session, &vault);
    match keys.versions(&name).await {
        Ok(_) => {
            let errors = vec![err(
                "name",
                format!(
                    "There's already a key called {name}. Pick another name, or open it and rotate it."
                ),
            )];
            return Ok(create_page(shell, vault, f, errors));
        }
        Err(AzureError::Status { status: 404, .. }) => {}
        Err(e) => return Err(azure_problem(shell, &e, Need::ManageKeys, "/keys/new")),
    }
    match keys.create(&name, &body).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key created");
            Ok(redirect_with(
                &state,
                &format!("/keys/{name}"),
                format!("Created {name}."),
            ))
        }
        Err(AzureError::Status { status: 409, .. }) => {
            let errors = vec![err(
                "name",
                format!(
                    "A deleted key called {name} is still being kept. Recover it from deleted keys, or pick another name."
                ),
            )];
            Ok(create_page(shell, vault, f, errors))
        }
        Err(AzureError::Status {
            status: 400,
            code: Some(c),
            ..
        }) if c.contains("HSM") || f.hsm => {
            let errors = vec![err(
                "key_type",
                "This vault can't make HSM-protected keys. It needs the Premium tier. Untick HSM, or use a Premium vault.",
            )];
            Ok(create_page(shell, vault, f, errors))
        }
        Err(e) => Err(azure_problem(shell, &e, Need::ManageKeys, "/keys/new")),
    }
}

#[derive(Template)]
#[template(path = "keys/rotate.html")]
struct RotatePage {
    shell: Shell,
    vault: String,
    name: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

pub async fn rotate_form(
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    Ok(render(&RotatePage { shell, vault, name }).into_response())
}

pub async fn rotate(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<CsrfForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    match api(&state, &session, &vault).rotate(&name).await {
        Ok(b) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key rotated");
            let short: String = b.version().chars().take(8).collect();
            Ok(redirect_with(
                &state,
                &format!("/keys/{name}"),
                format!(
                    "Rotated {name}. Version {short} is now current; older versions still work for decrypting and verifying."
                ),
            ))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageKeys,
            &format!("/keys/{name}"),
        )),
    }
}

#[derive(Template)]
#[template(path = "keys/rotation.html")]
struct RotationPage {
    shell: Shell,
    vault: String,
    name: String,
    form: RotationForm,
    errors: Vec<FieldError>,
}

impl RotationPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }
}

#[derive(Deserialize, Default)]
pub struct RotationForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub rotate_after: String,
    #[serde(default)]
    pub notify_before: String,
    #[serde(default)]
    pub expiry: String,
}

fn days_field(
    field: &'static str,
    v: &str,
    label: &str,
    min: u32,
    errors: &mut Vec<FieldError>,
) -> Option<u32> {
    match v.trim() {
        "" => None,
        s => match s.parse::<u32>() {
            Ok(d) if (min..=36_500).contains(&d) => Some(d),
            _ => {
                errors.push(err(
                    field,
                    format!("{label} needs a whole number of days, at least {min}."),
                ));
                None
            }
        },
    }
}

/// Check the rotation form against Key Vault's rules.
pub fn build_rotation(f: &RotationForm) -> Result<RotationPolicy, Vec<FieldError>> {
    let mut errors = Vec::new();
    let rotate = days_field(
        "rotate_after",
        &f.rotate_after,
        "Rotate after",
        7,
        &mut errors,
    );
    let notify = days_field(
        "notify_before",
        &f.notify_before,
        "Notify before",
        7,
        &mut errors,
    );
    let expiry = days_field("expiry", &f.expiry, "Expiry", 28, &mut errors);
    if let (Some(r), Some(e)) = (rotate, expiry)
        && r >= e
    {
        errors.push(err(
            "rotate_after",
            "Rotate the key before it expires: pick fewer days than the expiry.",
        ));
    }
    if notify.is_some() && expiry.is_none() {
        errors.push(err(
            "notify_before",
            "Notifications count back from expiry, so set an expiry too.",
        ));
    }
    if let (Some(n), Some(e)) = (notify, expiry)
        && n >= e
    {
        errors.push(err("notify_before", "Pick fewer days than the expiry."));
    }
    if errors.is_empty() {
        Ok(RotationPolicy::from_days(rotate, notify, expiry))
    } else {
        Err(errors)
    }
}

pub async fn rotation_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let p = match api(&state, &session, &vault).rotation_policy(&name).await {
        Ok(p) => p,
        Err(e) => {
            return Err(azure_problem(
                shell,
                &e,
                Need::ManageKeys,
                &format!("/keys/{name}"),
            ));
        }
    };
    let show = |d: Option<u32>| d.map(|d| d.to_string()).unwrap_or_default();
    let form = RotationForm {
        csrf: String::new(),
        rotate_after: show(p.rotate_after_days()),
        notify_before: show(p.notify_before_days()),
        expiry: show(p.expiry_days()),
    };
    Ok(render(&RotationPage {
        shell,
        vault,
        name,
        form,
        errors: Vec::new(),
    })
    .into_response())
}

pub async fn save_rotation(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<RotationForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let policy = match build_rotation(&f) {
        Ok(p) => p,
        Err(errors) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                render(&RotationPage {
                    shell,
                    vault,
                    name,
                    form: f,
                    errors,
                }),
            )
                .into_response());
        }
    };
    match api(&state, &session, &vault)
        .set_rotation_policy(&name, &policy)
        .await
    {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key rotation policy changed");
            Ok(redirect_with(
                &state,
                &format!("/keys/{name}"),
                format!("Saved the rotation policy for {name}."),
            ))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageKeys,
            &format!("/keys/{name}/rotation"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> CreateForm {
        CreateForm::from_pairs(v.iter().map(|(a, b)| ((*a).into(), (*b).into())).collect())
    }

    #[test]
    fn defaults_in_one_step() {
        let (name, body) = build(&pairs(&[("name", "app-key")]), 0).unwrap();
        assert_eq!(name, "app-key");
        assert_eq!(body.kty, "RSA");
        assert_eq!(body.key_size, Some(3072));
        assert_eq!(body.key_ops.len(), 6);
        let (_, body) = build(&pairs(&[("name", "sig"), ("key_type", "EC-P-256")]), 0).unwrap();
        assert_eq!(body.crv.as_deref(), Some("P-256"));
        assert_eq!(body.key_ops, vec!["sign", "verify"]);
    }

    #[test]
    fn options_and_errors() {
        let (_, body) = build(
            &pairs(&[
                ("name", "k"),
                ("hsm", "on"),
                ("ops", "wrapKey"),
                ("ops", "unwrapKey"),
            ]),
            0,
        )
        .unwrap();
        assert_eq!(body.kty, "RSA-HSM");
        assert_eq!(body.key_ops, vec!["wrapKey", "unwrapKey"]);
        let e = build(
            &pairs(&[("name", "k"), ("key_type", "EC-P-256"), ("ops", "encrypt")]),
            0,
        )
        .err()
        .unwrap();
        assert!(e[0].message.contains("EC keys can only sign"));
        let e = build(
            &pairs(&[
                ("name", "bad name"),
                ("key_type", "DSA"),
                ("expires", "2000-01-01"),
            ]),
            1_790_000_000,
        )
        .err()
        .unwrap();
        let fields: Vec<_> = e.iter().map(|x| x.field).collect();
        assert_eq!(fields, vec!["name", "key_type", "expires"]);
    }

    #[test]
    fn rotation_rules() {
        let f = |r: &str, n: &str, e: &str| RotationForm {
            csrf: String::new(),
            rotate_after: r.into(),
            notify_before: n.into(),
            expiry: e.into(),
        };
        assert!(build_rotation(&f("90", "30", "365")).is_ok());
        assert!(
            build_rotation(&f("", "", ""))
                .unwrap()
                .lifetime_actions
                .is_empty()
        );
        assert_eq!(
            build_rotation(&f("400", "", "365")).err().unwrap()[0].field,
            "rotate_after"
        );
        assert_eq!(
            build_rotation(&f("", "30", "")).err().unwrap()[0].field,
            "notify_before"
        );
        assert_eq!(
            build_rotation(&f("3", "", "")).err().unwrap()[0].field,
            "rotate_after"
        );
        assert_eq!(
            build_rotation(&f("", "", "10")).err().unwrap()[0].field,
            "expiry"
        );
    }
}
