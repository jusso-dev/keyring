//! Create a certificate from a policy: self-signed, or from an issuer the
//! vault already has set up.

use askama::Template;
use axum::Form;
use axum::extract::State;
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
use crate::routes::error::{Need, PageResult};
use crate::routes::flash::{self, Flash};
use crate::routes::secrets::form::{FieldError, name_problem, parse_tags};
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf};

use super::{api, current_vault};

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

fn err(field: &'static str, message: impl Into<String>) -> FieldError {
    FieldError {
        field,
        message: message.into(),
    }
}

/// Check the form and build the create request.
pub fn build(f: &CreateForm) -> Result<(String, CreateCert), Vec<FieldError>> {
    let mut errors = Vec::new();
    let name = f.name.trim().to_owned();
    if let Some(m) = name_problem(&name) {
        errors.push(err("name", m.replace("the secret", "the certificate")));
    }
    let cn = f.common_name.trim();
    if cn.is_empty() {
        errors.push(err(
            "common_name",
            "Enter the main name, such as app.example.com.",
        ));
    } else if cn.len() > 64 {
        errors.push(err(
            "common_name",
            "The main name can be up to 64 characters. Put longer names under other names.",
        ));
    } else if cn.contains(['=', ',', '+', '"', '\\', '<', '>', ';']) {
        errors.push(err(
            "common_name",
            "Use just the name, such as app.example.com, without CN= or commas.",
        ));
    }
    let mut dns: Vec<String> = Vec::new();
    for line in f.dns_names.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if is_dns_name(line) {
            if !dns.iter().any(|d| d.eq_ignore_ascii_case(line)) {
                dns.push(line.to_ascii_lowercase());
            }
        } else {
            errors.push(err("dns_names", format!("{line} isn't a valid DNS name. Use letters, numbers, hyphens and dots, like www.example.com.")));
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
            errors.push(err(
                "validity_months",
                "Enter a number of months from 1 to 120.",
            ));
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
            errors.push(err("key", "Pick a key type from the list."));
            KeyProps::default()
        }
    };
    let issuer = match f.issuer.trim() {
        "" | "Self" => "Self".to_owned(),
        other if crate::routes::vault_ctx::is_valid_object_name(other) => other.to_owned(),
        _ => {
            errors.push(err(
                "issuer",
                "Issuer names use letters, numbers and hyphens. Use Self for self-signed.",
            ));
            "Self".into()
        }
    };
    let content_type = match f.format.as_str() {
        "pem" => "application/x-pem-file",
        _ => "application/x-pkcs12",
    };
    let renew_days: Option<u32> = match f.renewal.as_str() {
        "none" => None,
        _ => match f.renew_days.trim() {
            "" => Some(30),
            d => match d.parse::<u32>() {
                Ok(n) if n >= 1 && n < months * 28 => Some(n),
                _ => {
                    errors.push(err(
                        "renew_days",
                        "Pick a number of days shorter than the certificate's life.",
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
        errors.push(err("tags", m));
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
    errors: Vec<FieldError>,
}

impl CreatePage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }
    fn key_choices(&self) -> &'static [(&'static str, &'static str)] {
        &KEY_CHOICES
    }
    fn key_selected(&self, v: &str) -> bool {
        self.form.key == v || (self.form.key.is_empty() && v == KEY_CHOICES[0].0)
    }
}

fn page(
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

pub async fn form(session: CurrentSession, shell: Shell) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let defaults = CreateForm {
        validity_months: "12".into(),
        exportable: Some("on".into()),
        renewal: "auto".into(),
        renew_days: "30".into(),
        issuer: "Self".into(),
        format: "pfx".into(),
        ..CreateForm::default()
    };
    Ok(page(shell, vault, defaults, Vec::new()))
}

pub async fn create(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<CreateForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let (name, body) = match build(&f) {
        Ok(ok) => ok,
        Err(errors) => return Ok(page(shell, vault, f, errors)),
    };
    let certs = api(&state, &session, &vault);
    // Creating over an existing name adds a version. Refuse, like secrets.
    match certs.versions(&name).await {
        Ok(_) => {
            let errors = vec![err(
                "name",
                format!("There's already a certificate called {name}. Pick another name."),
            )];
            return Ok(page(shell, vault, f, errors));
        }
        Err(AzureError::Status { status: 404, .. }) => {}
        Err(e) => {
            return Err(azure_problem(
                shell,
                &e,
                Need::ManageCertificates,
                "/certificates/new",
            ));
        }
    }
    match certs.create(&name, &body).await {
        Ok(op) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate created");
            let done = op
                .status
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("completed"));
            let message = if done {
                format!("Created {name}.")
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
            let errors = vec![err(
                "name",
                format!(
                    "A deleted certificate called {name} is still being kept. Recover it from deleted certificates, or pick another name."
                ),
            )];
            Ok(page(shell, vault, f, errors))
        }
        Err(e) => Err(azure_problem(
            shell,
            &e,
            Need::ManageCertificates,
            "/certificates/new",
        )),
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
        let (name, body) = build(&form()).unwrap();
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
        let (_, body) = build(&f).unwrap();
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
        let (_, body) = build(&f).unwrap();
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
        let fields: Vec<_> = build(&f).err().unwrap().iter().map(|e| e.field).collect();
        assert_eq!(
            fields,
            vec!["name", "common_name", "dns_names", "validity_months", "key"]
        );
        let mut f = form();
        f.renew_days = "500".into();
        assert_eq!(build(&f).err().unwrap()[0].field, "renew_days");
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
