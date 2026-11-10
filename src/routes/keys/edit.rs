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
use crate::azure::keys::{CreateKey, RotateAt, RotationPolicy, iso_days};
use crate::azure::secrets::{Attributes, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageResult, rejection_message};
use crate::routes::lifecycle::redirect_with;
use crate::routes::secrets::form::{FieldError, name_problem, parse_tags};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name};

use super::{api, current_vault, reserved_name_problem, unmanaged_key};

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
    if let Some(m) = name_problem(&f.name)
        .map(|m| m.replace("the secret", "the key"))
        .or_else(|| reserved_name_problem(&f.name))
    {
        errors.push(err("name", m));
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
    /// Key Vault's own reason, after it refused the request.
    azure_message: Option<String>,
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
    create_page_with(shell, vault, form, errors, None)
}

fn create_page_with(
    shell: Shell,
    vault: String,
    form: CreateForm,
    errors: Vec<FieldError>,
    azure_message: Option<String>,
) -> axum::response::Response {
    let status = if errors.is_empty() && azure_message.is_none() {
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
            azure_message,
        }),
    )
        .into_response()
}

/// Key Vault's refusal of an HSM key on a Standard vault. The reviewer's
/// reading of the REST reference is `400 BadParameter` with a message that
/// names the vault's SKU, so match that narrowly rather than blaming every
/// 400 on HSM. Needs confirming on a real vault.
fn is_hsm_refusal(err: &AzureError) -> bool {
    match err {
        AzureError::Status {
            status: 400,
            code,
            message,
        } => {
            let code = code.as_deref().unwrap_or_default();
            let msg = message.as_deref().unwrap_or_default().to_ascii_lowercase();
            code.to_ascii_lowercase().contains("hsm")
                || msg.contains("sku")
                || msg.contains("premium")
        }
        _ => false,
    }
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
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (name, body) = match build(&f, now_ts()) {
        Ok(ok) => ok,
        Err(errors) => return Ok(create_page(shell, vault, f, errors)),
    };
    let keys = api(&state, &session, &vault);
    // Creating over an existing name adds a version, so refuse. Key Vault
    // may answer an unknown name with 404 or with an empty list.
    match keys.versions(&name).await {
        Ok(v) if !v.is_empty() => {
            let errors = vec![err(
                "name",
                format!(
                    "There's already a key called {name}. Pick another name, or open it and rotate it."
                ),
            )];
            return Ok(create_page(shell, vault, f, errors));
        }
        Ok(_) | Err(AzureError::Status { status: 404, .. }) => {}
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
        Err(e) if f.hsm && is_hsm_refusal(&e) => {
            let errors = vec![err(
                "key_type",
                "This vault can't make HSM-protected keys. It needs the Premium tier. Untick HSM, or use a Premium vault.",
            )];
            Ok(create_page(shell, vault, f, errors))
        }
        Err(e) => match rejection_message(&e) {
            Some(m) => Ok(create_page_with(shell, vault, f, Vec::new(), Some(m))),
            None => Err(azure_problem(shell, &e, Need::ManageKeys, "/keys/new")),
        },
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
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
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
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    match api(&state, &session, &vault).rotate(&name).await {
        Ok(b) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key rotated");
            let short: String = b.version().chars().take(8).collect();
            Ok(redirect_with(
                &state,
                &format!("/keys/{name}"),
                format!(
                    "Rotated {name}. Version {short} is now current. Older versions still work for decrypting and verifying."
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
    /// Parts of the current policy the form can't show.
    unsupported: Vec<String>,
    /// Key Vault's own reason, after it refused the policy.
    azure_message: Option<String>,
}

impl RotationPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }
    fn rotate_before_expiry(&self) -> bool {
        self.form.rotate_when == "expiry"
    }
}

#[derive(Deserialize, Default)]
pub struct RotationForm {
    #[serde(default)]
    pub csrf: String,
    /// `create` (count from when each version is made) or `expiry` (count
    /// back from when it expires).
    #[serde(default)]
    pub rotate_when: String,
    #[serde(default)]
    pub rotate_days: String,
    #[serde(default)]
    pub notify_before: String,
    #[serde(default)]
    pub expiry: String,
    /// Ticked to replace a policy that has parts the form can't show.
    #[serde(default)]
    pub replace: Option<String>,
}

impl RotationForm {
    /// The form as it would be filled in from `p`.
    pub fn from_policy(p: &RotationPolicy) -> Self {
        let show = |d: Option<u32>| d.map(|d| d.to_string()).unwrap_or_default();
        if p.is_key_vault_default() {
            return Self {
                rotate_when: "create".into(),
                ..Self::default()
            };
        }
        let (rotate_when, rotate_days) = match p.rotate_at() {
            Some(RotateAt::BeforeExpiry(d)) => ("expiry", show(iso_days(&d))),
            Some(RotateAt::AfterCreate(d)) => ("create", show(iso_days(&d))),
            None => ("create", String::new()),
        };
        Self {
            csrf: String::new(),
            rotate_when: rotate_when.into(),
            rotate_days,
            notify_before: show(p.notify_before_days()),
            expiry: show(p.expiry_days()),
            replace: None,
        }
    }
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

/// The duration to send for a field: Key Vault's original string if the
/// person left the number as it was shown, so `P18M` stays `P18M`, else
/// whole days.
fn keep_or_days(original: Option<&str>, typed: Option<u32>) -> Option<String> {
    let typed = typed?;
    match original {
        Some(o) if iso_days(o) == Some(typed) => Some(o.to_owned()),
        _ => Some(format!("P{typed}D")),
    }
}

/// Key Vault's rotation policy limits, from "Configure cryptographic key
/// auto-rotation in Azure Key Vault": expiry at least 28 days, triggers at
/// least 7 days, and a rotate trigger at least 7 days before expiry.
pub const MIN_EXPIRY_DAYS: u32 = 28;
pub const MIN_TRIGGER_DAYS: u32 = 7;
pub const MIN_GAP_DAYS: u32 = 7;

/// Check the rotation form against Key Vault's rules and build the policy
/// to save. `current` is the policy as Key Vault has it now: fields left
/// as they were keep its original durations, and a policy with parts the
/// form can't show is only replaced when the person ticks the box.
pub fn build_rotation(
    f: &RotationForm,
    current: &RotationPolicy,
) -> Result<RotationPolicy, Vec<FieldError>> {
    let mut errors = Vec::new();
    let before_expiry = match f.rotate_when.as_str() {
        "" | "create" => false,
        "expiry" => true,
        _ => {
            errors.push(err("rotate_days", "Pick when to rotate from the list."));
            false
        }
    };
    let rotate = days_field(
        "rotate_days",
        &f.rotate_days,
        "Rotate",
        MIN_TRIGGER_DAYS,
        &mut errors,
    );
    let notify = days_field(
        "notify_before",
        &f.notify_before,
        "Notify before",
        MIN_TRIGGER_DAYS,
        &mut errors,
    );
    let expiry = days_field("expiry", &f.expiry, "Expiry", MIN_EXPIRY_DAYS, &mut errors);
    match (rotate, expiry, before_expiry) {
        (Some(_), None, true) => errors.push(err(
            "rotate_days",
            "Rotating before expiry counts back from expiry, so set an expiry too.",
        )),
        (Some(r), Some(e), false) if r + MIN_GAP_DAYS > e => errors.push(err(
            "rotate_days",
            format!(
                "Rotate the key at least {MIN_GAP_DAYS} days before it expires: pick {} days or fewer, or a longer expiry.",
                e.saturating_sub(MIN_GAP_DAYS)
            ),
        )),
        (Some(r), Some(e), true) if r + MIN_GAP_DAYS > e => errors.push(err(
            "rotate_days",
            format!(
                "Key Vault needs each version to last at least {MIN_GAP_DAYS} days before it rotates: pick {} days or fewer, or a longer expiry.",
                e.saturating_sub(MIN_GAP_DAYS)
            ),
        )),
        _ => {}
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
    if !current.unsupported().is_empty() && f.replace.is_none() {
        errors.push(err(
            "replace",
            "This key's policy has parts the form can't show. Tick the box to replace the whole policy with what's on this page.",
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let original_rotate = current.rotate_at().and_then(|r| match (r, before_expiry) {
        (RotateAt::AfterCreate(d), false) | (RotateAt::BeforeExpiry(d), true) => Some(d),
        _ => None,
    });
    let rotate = keep_or_days(original_rotate.as_deref(), rotate).map(|d| {
        if before_expiry {
            RotateAt::BeforeExpiry(d)
        } else {
            RotateAt::AfterCreate(d)
        }
    });
    let original_notify = (!current.is_key_vault_default())
        .then(|| current.notify_before())
        .flatten();
    Ok(RotationPolicy::from_parts(
        rotate,
        keep_or_days(original_notify, notify),
        keep_or_days(current.expiry(), expiry),
    ))
}

fn rotation_page(
    shell: Shell,
    vault: String,
    name: String,
    form: RotationForm,
    errors: Vec<FieldError>,
    unsupported: Vec<String>,
    azure_message: Option<String>,
) -> axum::response::Response {
    let status = if errors.is_empty() && azure_message.is_none() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        render(&RotationPage {
            shell,
            vault,
            name,
            form,
            errors,
            unsupported,
            azure_message,
        }),
    )
        .into_response()
}

pub async fn rotation_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
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
    let form = RotationForm::from_policy(&p);
    Ok(rotation_page(
        shell,
        vault,
        name,
        form,
        Vec::new(),
        p.unsupported(),
        None,
    ))
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
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (_, shell) = unmanaged_key(&state, &session, &vault, &name, shell).await?;
    let keys = api(&state, &session, &vault);
    let path = format!("/keys/{name}/rotation");
    // Read the policy as it is now, so unchanged fields keep Key Vault's
    // own durations.
    let current = match keys.rotation_policy(&name).await {
        Ok(p) => p,
        Err(e) => return Err(azure_problem(shell, &e, Need::ManageKeys, &path)),
    };
    let unsupported = current.unsupported();
    let policy = match build_rotation(&f, &current) {
        Ok(p) => p,
        Err(errors) => {
            return Ok(rotation_page(
                shell,
                vault,
                name,
                f,
                errors,
                unsupported,
                None,
            ));
        }
    };
    match keys.set_rotation_policy(&name, &policy).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, key = %name, "key rotation policy changed");
            Ok(redirect_with(
                &state,
                &format!("/keys/{name}"),
                format!("Saved the rotation policy for {name}."),
            ))
        }
        Err(e) => match rejection_message(&e) {
            Some(m) => Ok(rotation_page(
                shell,
                vault,
                name,
                f,
                Vec::new(),
                unsupported,
                Some(m),
            )),
            None => Err(azure_problem(shell, &e, Need::ManageKeys, &path)),
        },
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

    fn rf(when: &str, r: &str, n: &str, e: &str) -> RotationForm {
        RotationForm {
            csrf: String::new(),
            rotate_when: when.into(),
            rotate_days: r.into(),
            notify_before: n.into(),
            expiry: e.into(),
            replace: None,
        }
    }

    fn policy(v: serde_json::Value) -> RotationPolicy {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn rotation_rules() {
        let none = RotationPolicy::default();
        let f = |r: &str, n: &str, e: &str| rf("create", r, n, e);
        assert!(build_rotation(&f("90", "30", "365"), &none).is_ok());
        assert!(
            build_rotation(&f("", "", ""), &none)
                .unwrap()
                .lifetime_actions
                .is_empty()
        );
        assert_eq!(
            build_rotation(&f("400", "", "365"), &none).err().unwrap()[0].field,
            "rotate_days"
        );
        assert_eq!(
            build_rotation(&f("", "30", ""), &none).err().unwrap()[0].field,
            "notify_before"
        );
        assert_eq!(
            build_rotation(&f("3", "", ""), &none).err().unwrap()[0].field,
            "rotate_days"
        );
        assert_eq!(
            build_rotation(&f("", "", "10"), &none).err().unwrap()[0].field,
            "expiry"
        );
    }

    #[test]
    fn rotate_needs_a_seven_day_gap_before_expiry() {
        let none = RotationPolicy::default();
        let e = build_rotation(&rf("create", "85", "", "90"), &none)
            .err()
            .unwrap();
        assert_eq!(e[0].field, "rotate_days");
        assert!(
            e[0].message.contains("83 days or fewer"),
            "{}",
            e[0].message
        );
        assert!(build_rotation(&rf("create", "83", "", "90"), &none).is_ok());
        assert!(build_rotation(&rf("expiry", "85", "", "90"), &none).is_err());
        assert!(build_rotation(&rf("expiry", "30", "", "90"), &none).is_ok());
        assert!(
            build_rotation(&rf("expiry", "30", "", ""), &none).is_err(),
            "before expiry needs an expiry"
        );
    }

    #[test]
    fn before_expiry_policies_round_trip() {
        let p = policy(serde_json::json!({
            "lifetimeActions": [
                {"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Rotate"}},
                {"trigger": {"timeBeforeExpiry": "P10D"}, "action": {"type": "Notify"}}
            ],
            "attributes": {"expiryTime": "P90D"}
        }));
        let f = RotationForm::from_policy(&p);
        assert_eq!(f.rotate_when, "expiry");
        assert_eq!(f.rotate_days, "30");
        // Changing only the notify period keeps the rotate trigger.
        let mut f = f;
        f.notify_before = "14".into();
        let saved = build_rotation(&f, &p).unwrap();
        assert_eq!(
            saved.rotate_at(),
            Some(RotateAt::BeforeExpiry("P30D".into()))
        );
        assert_eq!(saved.notify_before(), Some("P14D"));
    }

    #[test]
    fn unchanged_fields_keep_key_vault_durations() {
        let p = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeAfterCreate": "P1Y"}, "action": {"type": "Rotate"}}],
            "attributes": {"expiryTime": "P2Y"}
        }));
        let f = RotationForm::from_policy(&p);
        assert_eq!((f.rotate_days.as_str(), f.expiry.as_str()), ("365", "730"));
        let saved = build_rotation(&f, &p).unwrap();
        assert_eq!(saved, p, "open and save changes nothing");
        let mut changed = RotationForm::from_policy(&p);
        changed.expiry = "800".into();
        let saved = build_rotation(&changed, &p).unwrap();
        assert_eq!(saved.expiry(), Some("P800D"));
        assert_eq!(saved.rotate_at(), Some(RotateAt::AfterCreate("P1Y".into())));
    }

    #[test]
    fn policies_the_form_cant_show_need_replace() {
        let p = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeAfterCreate": "PT48H"}, "action": {"type": "Rotate"}}]
        }));
        let f = RotationForm::from_policy(&p);
        assert_eq!(f.rotate_days, "");
        let e = build_rotation(&f, &p).err().unwrap();
        assert_eq!(e[0].field, "replace");
        let mut f = f;
        f.replace = Some("on".into());
        assert!(build_rotation(&f, &p).is_ok());
    }

    #[test]
    fn key_vault_default_policy_saves_untouched() {
        let p = policy(serde_json::json!({
            "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}],
            "attributes": {}
        }));
        let f = RotationForm::from_policy(&p);
        assert_eq!(f.notify_before, "", "default shown as no policy");
        assert!(
            build_rotation(&f, &p).is_ok(),
            "Save on an untouched form works"
        );
    }

    #[test]
    fn hsm_refusal_is_matched_narrowly() {
        let e = |code: &str, msg: &str| AzureError::Status {
            status: 400,
            code: Some(code.into()),
            message: Some(msg.into()),
        };
        assert!(is_hsm_refusal(&e(
            "BadParameter",
            "The vault SKU does not support HSM keys."
        )));
        assert!(!is_hsm_refusal(&e("BadParameter", "Invalid curve name.")));
        assert!(!is_hsm_refusal(&e(
            "BadParameter",
            "Key size not supported for RSA-HSM."
        )));
    }

    #[test]
    fn reserved_names_refused_on_create() {
        let e = build(&pairs(&[("name", "new")]), 0).err().unwrap();
        assert_eq!(e[0].field, "name");
        assert!(e[0].message.contains("own pages"));
    }
}
