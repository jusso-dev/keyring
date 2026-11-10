//! Create a certificate from a policy: self-signed, or from an issuer the
//! vault already has set up.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::certs::{
    CreateCert, IssuerProps, KeyProps, LifetimeAction, LifetimeActionType, LifetimeTrigger, Policy,
    SecretProps, SubjectAltNames, X509Props,
};
use crate::azure::secrets::Attributes;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageResult, rejection_message};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::{CsrfForm, FieldErrors};
use crate::routes::lifecycle::redirect_with;
use crate::routes::secrets::form::parse_tags;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name};

use super::{api, current_vault, new_name_problem};

/// Key Vault's limit on `days_before_expiry`: from 1 to 27 times the
/// validity in months. From the REST reference for "Create Certificate",
/// `LifetimeAction.trigger.days_before_expiry`: "Value should be between 1
/// and validity_in_months multiplied by 27."
pub const DAYS_PER_MONTH_LIMIT: u32 = 27;

/// The default renewal point: 30 days before expiry, or less for a short
/// certificate.
pub fn default_renew_days(months: u32) -> u32 {
    30.min(months * DAYS_PER_MONTH_LIMIT)
}

/// The issuer choices for the form: always `Self`, then the vault's own.
pub struct Issuers {
    pub names: Vec<String>,
    /// Why only `Self` is offered, when the vault's list couldn't be read.
    pub note: Option<String>,
}

impl Issuers {
    pub fn self_only(note: Option<String>) -> Self {
        Self {
            names: Vec::new(),
            note,
        }
    }
}

async fn load_issuers(certs: &crate::azure::certs::CertsApi<'_>) -> Issuers {
    match certs.issuers().await {
        Ok(list) => Issuers {
            names: list
                .iter()
                .map(|i| i.name().to_owned())
                .filter(|n| !n.eq_ignore_ascii_case("Self") && !n.eq_ignore_ascii_case("Unknown"))
                .collect(),
            note: None,
        },
        Err(AzureError::Status { status: 403, .. }) => Issuers::self_only(Some(
            "You can't see this vault's issuers, so only self-signed is offered. Listing issuers needs the Key Vault Certificates Officer role.".into(),
        )),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't list certificate issuers");
            Issuers::self_only(Some(
                "Keyring couldn't load this vault's issuers just now, so only self-signed is offered. Refresh the page to try again.".into(),
            ))
        }
    }
}

/// Key choices offered. The first is the default.
pub const KEY_CHOICES: [(&str, &str); 5] = [
    ("RSA-2048", "RSA 2048 (works everywhere)"),
    ("RSA-3072", "RSA 3072"),
    ("RSA-4096", "RSA 4096"),
    (
        "EC-P-256",
        "EC P-256 (smaller and faster, newer systems only)",
    ),
    ("EC-P-384", "EC P-384"),
];

#[derive(Deserialize, Default, Clone)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
    /// Common name, for example `app.example.com`.
    #[serde(default)]
    pub common_name: String,
    /// More DNS names, one per line.
    #[serde(default)]
    pub dns_names: String,
    #[serde(default)]
    pub validity_months: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub exportable: Option<String>,
    /// `auto` (renew), `email` (remind) or `none`.
    #[serde(default)]
    pub renewal: String,
    #[serde(default)]
    pub renew_days: String,
    /// `Self` or the name of an issuer configured on the vault.
    #[serde(default)]
    pub issuer: String,
    /// `pfx` or `pem`.
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub tags: String,
}

fn is_dns_name(s: &str) -> bool {
    let s = s.strip_prefix("*.").unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Check the form and build the create request. `issuers` are the names
/// set up on the vault; `Self` is always allowed.
pub fn build(f: &CreateForm, issuers: &[String]) -> Result<(String, CreateCert), FieldErrors> {
    let mut errors = FieldErrors::new();
    let name = f.name.trim().to_owned();
    if let Some(m) = new_name_problem(&name) {
        errors.push("name", m);
    }
    let cn = f.common_name.trim();
    if cn.is_empty() {
        errors.push(
            "common_name",
            "Enter the main name, such as app.example.com.",
        );
    } else if cn.len() > 64 {
        errors.push(
            "common_name",
            "The main name can be up to 64 characters. Put longer names under other names.",
        );
    } else if cn.contains(['=', ',', '+', '"', '\\', '<', '>', ';']) {
        errors.push(
            "common_name",
            "Use just the name, such as app.example.com, without CN= or commas.",
        );
    }
    let mut dns: Vec<String> = Vec::new();
    for line in f.dns_names.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if is_dns_name(line) {
            if !dns.iter().any(|d| d.eq_ignore_ascii_case(line)) {
                dns.push(line.to_ascii_lowercase());
            }
        } else {
            errors.push("dns_names", format!("{line} isn't a valid DNS name. Use letters, numbers, hyphens and dots, like www.example.com."));
            break;
        }
    }
    // The common name usually needs to be a SAN too, or browsers reject it.
    if is_dns_name(cn) && !dns.iter().any(|d| d.eq_ignore_ascii_case(cn)) {
        dns.insert(0, cn.to_ascii_lowercase());
    }
    let months: u32 = match f.validity_months.trim().parse() {
        Ok(m) if (1..=120).contains(&m) => m,
        _ => {
            errors.push("validity_months", "Enter a number of months from 1 to 120.");
            12
        }
    };
    let key = match f.key.as_str() {
        "" | "RSA-2048" => KeyProps {
            kty: Some("RSA".into()),
            key_size: Some(2048),
            ..KeyProps::default()
        },
        "RSA-3072" => KeyProps {
            kty: Some("RSA".into()),
            key_size: Some(3072),
            ..KeyProps::default()
        },
        "RSA-4096" => KeyProps {
            kty: Some("RSA".into()),
            key_size: Some(4096),
            ..KeyProps::default()
        },
        "EC-P-256" => KeyProps {
            kty: Some("EC".into()),
            crv: Some("P-256".into()),
            ..KeyProps::default()
        },
        "EC-P-384" => KeyProps {
            kty: Some("EC".into()),
            crv: Some("P-384".into()),
            ..KeyProps::default()
        },
        _ => {
            errors.push("key", "Pick a key type from the list.");
            KeyProps::default()
        }
    };
    // `Unknown` means "I'll get it signed elsewhere", which Keyring can't
    // finish, so only Self and the vault's own issuers are allowed.
    let issuer = match f.issuer.trim() {
        "" | "Self" => "Self".to_owned(),
        other if issuers.iter().any(|i| i == other) => other.to_owned(),
        _ => {
            errors.push(
                "issuer",
                "Pick an issuer from the list. Self is for self-signed.",
            );
            "Self".into()
        }
    };
    let content_type = match f.format.as_str() {
        "pem" => "application/x-pem-file",
        _ => "application/x-pkcs12",
    };
    let max_days = months * DAYS_PER_MONTH_LIMIT;
    let renew_days: Option<u32> = match f.renewal.as_str() {
        "none" => None,
        _ => match f.renew_days.trim() {
            "" => Some(default_renew_days(months)),
            d => match d.parse::<u32>() {
                Ok(n) if (1..=max_days).contains(&n) => Some(n),
                _ => {
                    errors.push("renew_days", format!(
                            "Pick a number of days from 1 to {max_days}. Key Vault allows up to 27 days for each month the certificate is valid."
                        ));
                    None
                }
            },
        },
    };
    let lifetime_actions = match (f.renewal.as_str(), renew_days) {
        ("none", _) | (_, None) => Vec::new(),
        (kind, Some(days)) => vec![LifetimeAction {
            trigger: LifetimeTrigger {
                days_before_expiry: Some(days),
                lifetime_percentage: None,
            },
            action: LifetimeActionType {
                action_type: if kind == "email" {
                    "EmailContacts".into()
                } else {
                    "AutoRenew".into()
                },
            },
        }],
    };
    let tags = parse_tags(&f.tags).unwrap_or_else(|m| {
        errors.push("tags", m);
        Default::default()
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok((
        name,
        CreateCert {
            policy: Policy {
                key_props: Some(KeyProps {
                    exportable: Some(f.exportable.is_some()),
                    reuse_key: Some(false),
                    ..key
                }),
                secret_props: Some(SecretProps {
                    content_type: Some(content_type.into()),
                }),
                x509_props: Some(X509Props {
                    subject: Some(format!("CN={cn}")),
                    sans: (!dns.is_empty()).then_some(SubjectAltNames {
                        dns_names: dns,
                        ..Default::default()
                    }),
                    validity_months: Some(months),
                    ekus: Vec::new(),
                }),
                lifetime_actions,
                issuer: Some(IssuerProps { name: Some(issuer) }),
            },
            attributes: Attributes {
                enabled: Some(true),
                ..Attributes::default()
            },
            tags: Some(tags),
        },
    ))
}

#[derive(Template)]
#[template(path = "certs/create.html")]
struct CreatePage {
    shell: Shell,
    vault: String,
    form: CreateForm,
    errors: FieldErrors,
    issuers: Issuers,
    /// Key Vault's own reason, after it refused the request.
    azure_message: Option<String>,
}

impl CreatePage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
    fn key_choices(&self) -> &'static [(&'static str, &'static str)] {
        &KEY_CHOICES
    }
    fn key_selected(&self, v: &str) -> bool {
        self.form.key == v || (self.form.key.is_empty() && v == KEY_CHOICES[0].0)
    }
    fn issuer_selected(&self, v: &str) -> bool {
        self.form.issuer == v
    }
}

fn page(
    shell: Shell,
    vault: String,
    form: CreateForm,
    errors: FieldErrors,
    issuers: Issuers,
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
            issuers,
            azure_message,
        }),
    )
        .into_response()
}

pub async fn form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let issuers = load_issuers(&api(&state, &session, &vault)).await;
    let defaults = CreateForm {
        validity_months: "12".into(),
        exportable: Some("on".into()),
        renewal: "auto".into(),
        renew_days: "30".into(),
        issuer: "Self".into(),
        format: "pfx".into(),
        ..CreateForm::default()
    };
    Ok(page(
        shell,
        vault,
        defaults,
        FieldErrors::new(),
        issuers,
        None,
    ))
}

pub async fn create(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<CreateForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let certs = api(&state, &session, &vault);
    let issuers = load_issuers(&certs).await;
    let (name, body) = match build(&f, &issuers.names) {
        Ok(ok) => ok,
        Err(errors) => return Ok(page(shell, vault, f, errors, issuers, None)),
    };
    // Creating over an existing name adds a version. Refuse, like secrets.
    // Key Vault may answer an unknown name with 404 or with an empty list.
    match certs.versions(&name).await {
        Ok(v) if !v.is_empty() => {
            let errors = FieldErrors::one(
                "name",
                format!("There's already a certificate called {name}. Pick another name."),
            );
            return Ok(page(shell, vault, f, errors, issuers, None));
        }
        Ok(_) | Err(AzureError::Status { status: 404, .. }) => {}
        Err(e) => {
            return Err(azure_problem(
                shell,
                &e,
                Need::ManageCertificates,
                "/certificates/new",
            ));
        }
    }
    let self_signed = body.policy.issuer_name() == "Self";
    match certs.create(&name, &body).await {
        Ok(op) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate created");
            let done = op
                .status
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("completed"));
            // Key Vault answers 202 `inProgress` for every issuer, Self
            // included. A self-signed one is ready a few seconds later.
            let message = if done {
                format!("Created {name}.")
            } else if self_signed {
                format!("Creating {name}. This usually takes a few seconds.")
            } else {
                format!(
                    "Requested {name}. It appears once the issuer signs it. Its page shows progress."
                )
            };
            let mut res = Redirect::to(&format!("/certificates/{name}")).into_response();
            flash::set(&state, &mut res, &Flash::success(message));
            Ok(res)
        }
        Err(AzureError::Status { status: 409, .. }) => {
            let errors = FieldErrors::one(
                "name",
                format!(
                    "A deleted certificate called {name} is still being kept. Recover it from deleted certificates, or pick another name."
                ),
            );
            Ok(page(shell, vault, f, errors, issuers, None))
        }
        Err(e) => match rejection_message(&e) {
            Some(m) => Ok(page(shell, vault, f, FieldErrors::new(), issuers, Some(m))),
            None => Err(azure_problem(
                shell,
                &e,
                Need::ManageCertificates,
                "/certificates/new",
            )),
        },
    }
}

/// Stop a pending create or renewal: ask Key Vault to cancel it, then
/// delete the request.
pub async fn cancel_pending(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<CsrfForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let path = format!("/certificates/{name}");
    match api(&state, &session, &vault).cancel_pending(&name).await {
        Ok(()) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate request cancelled");
            Ok(redirect_with(
                &state,
                &path,
                format!("Cancelled the request for {name}."),
            ))
        }
        Err(e) => Err(azure_problem(shell, &e, Need::ManageCertificates, &path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> CreateForm {
        CreateForm {
            csrf: "t".into(),
            name: "web-tls".into(),
            common_name: "app.example.com".into(),
            validity_months: "12".into(),
            exportable: Some("on".into()),
            renewal: "auto".into(),
            ..CreateForm::default()
        }
    }

    #[test]
    fn defaults_make_a_sensible_self_signed_policy() {
        let (name, body) = build(&form(), &[]).unwrap();
        assert_eq!(name, "web-tls");
        let p = serde_json::to_value(&body.policy).unwrap();
        assert_eq!(p["issuer"]["name"], "Self");
        assert_eq!(p["key_props"]["kty"], "RSA");
        assert_eq!(p["key_props"]["key_size"], 2048);
        assert_eq!(p["key_props"]["exportable"], true);
        assert_eq!(p["x509_props"]["subject"], "CN=app.example.com");
        assert_eq!(
            p["x509_props"]["sans"]["dns_names"][0], "app.example.com",
            "CN added as a SAN"
        );
        assert_eq!(p["x509_props"]["validity_months"], 12);
        assert_eq!(
            p["lifetime_actions"][0]["action"]["action_type"],
            "AutoRenew"
        );
        assert_eq!(
            p["lifetime_actions"][0]["trigger"]["days_before_expiry"],
            30
        );
        assert_eq!(p["secret_props"]["contentType"], "application/x-pkcs12");
    }

    #[test]
    fn options() {
        let mut f = form();
        f.key = "EC-P-256".into();
        f.exportable = None;
        f.renewal = "email".into();
        f.renew_days = "14".into();
        f.issuer = "DigiCert-OV".into();
        f.format = "pem".into();
        f.dns_names = "www.example.com\n*.api.example.com\nWWW.example.com".into();
        let (_, body) = build(&f, &["DigiCert-OV".into()]).unwrap();
        let p = serde_json::to_value(&body.policy).unwrap();
        assert_eq!(p["key_props"]["crv"], "P-256");
        assert_eq!(p["key_props"]["exportable"], false);
        assert_eq!(
            p["lifetime_actions"][0]["action"]["action_type"],
            "EmailContacts"
        );
        assert_eq!(p["issuer"]["name"], "DigiCert-OV");
        assert_eq!(p["secret_props"]["contentType"], "application/x-pem-file");
        let sans = p["x509_props"]["sans"]["dns_names"].as_array().unwrap();
        assert_eq!(sans.len(), 3, "duplicates removed, CN added: {sans:?}");
        f.renewal = "none".into();
        let (_, body) = build(&f, &["DigiCert-OV".into()]).unwrap();
        assert!(body.policy.lifetime_actions.is_empty());
    }

    #[test]
    fn explains_problems() {
        let mut f = form();
        f.name = "web tls".into();
        f.common_name = "CN=x,O=y".into();
        f.dns_names = "bad name.com".into();
        f.validity_months = "0".into();
        f.key = "DSA".into();
        let fields: Vec<_> = build(&f, &[])
            .err()
            .unwrap()
            .iter()
            .map(|e| e.field)
            .collect();
        assert_eq!(
            fields,
            vec!["name", "common_name", "dns_names", "validity_months", "key"]
        );
        let mut f = form();
        f.renew_days = "500".into();
        assert_eq!(build(&f, &[]).err().unwrap()[0].field, "renew_days");
    }

    #[test]
    fn issuer_must_be_self_or_on_the_vault() {
        let mut f = form();
        for bad in ["Unknown", "DigiCert-OV", "bad name"] {
            f.issuer = bad.into();
            assert_eq!(
                build(&f, &["Other-CA".into()]).err().unwrap()[0].field,
                "issuer",
                "{bad}"
            );
        }
        f.issuer = "Other-CA".into();
        assert!(build(&f, &["Other-CA".into()]).is_ok());
    }

    #[test]
    fn renewal_days_follow_key_vaults_bound() {
        let days = |months: &str, renew: &str| {
            let mut f = form();
            f.validity_months = months.into();
            f.renew_days = renew.into();
            build(&f, &[]).map(|(_, b)| {
                b.policy.lifetime_actions[0]
                    .trigger
                    .days_before_expiry
                    .unwrap()
            })
        };
        // Blank uses 30, or less for a short certificate.
        assert_eq!(days("1", "").unwrap(), 27);
        assert_eq!(days("2", "").unwrap(), 30);
        assert_eq!(days("12", "").unwrap(), 30);
        // The bound is 27 days for each month.
        assert_eq!(days("1", "27").unwrap(), 27);
        assert!(days("1", "28").is_err());
        assert_eq!(days("2", "54").unwrap(), 54);
        assert!(days("2", "55").is_err());
        assert_eq!(days("12", "324").unwrap(), 324);
        assert!(days("12", "325").is_err());
        assert!(days("12", "0").is_err());
    }

    #[test]
    fn reserved_names_refused() {
        let mut f = form();
        f.name = "upload".into();
        assert_eq!(build(&f, &[]).err().unwrap()[0].field, "name");
    }

    #[test]
    fn dns_rules() {
        for ok in ["a.com", "*.example.com", "x-y.z", "localhost"] {
            assert!(is_dns_name(ok), "{ok}");
        }
        for bad in ["", "-a.com", "a..com", "a b.com", "*.*.com", "a_b.com"] {
            assert!(!is_dns_name(bad), "{bad}");
        }
    }
}
