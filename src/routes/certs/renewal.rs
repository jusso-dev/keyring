//! Change what Key Vault does near expiry: renew, or email the contacts.
//! Only the lifetime actions are sent, so the rest of the policy is left
//! alone.
//!
//! "Do nothing" can't be set here once a certificate has an action. Key
//! Vault answers 200 to `"lifetime_actions": []` (and to `null`, or the
//! field left out) but keeps the old action (real-vault run, 13-11-2026), so
//! the server refuses it before calling Key Vault.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::certs::{LifetimeAction, Policy};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageResult, rejection_message};
use crate::routes::forms::FieldErrors;
use crate::routes::lifecycle::redirect_with;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name, vault_path};

use super::create::{default_renew_days, lifetime_actions};
use super::{api, current_vault};

/// Used when the policy doesn't say, as the create form does.
const DEFAULT_MONTHS: u32 = 12;

#[derive(Deserialize, Default, Clone)]
pub(crate) struct RenewalForm {
    #[serde(default)]
    pub csrf: String,
    /// `auto`, `email` or `none`.
    #[serde(default)]
    pub renewal: String,
    #[serde(default)]
    pub renew_days: String,
}

/// What the policy says now, as far as this form is concerned.
struct Current {
    form: RenewalForm,
    months: u32,
    /// Signed outside Key Vault (an import), so Key Vault can't renew it.
    imported: bool,
    /// The policy has at least one action, which Key Vault won't remove.
    has_action: bool,
    /// Parts of the current setting the form can't show.
    unsupported: Vec<String>,
}

impl Current {
    fn from_policy(p: &Policy) -> Self {
        let months = p
            .x509_props
            .as_ref()
            .and_then(|x| x.validity_months)
            .filter(|m| *m > 0)
            .unwrap_or(DEFAULT_MONTHS);
        let imported = p.issuer_name() == "Unknown";
        let mut unsupported = Vec::new();
        if p.lifetime_actions.len() > 1 {
            unsupported.push(format!(
                "It has {} actions, and this form sets one.",
                p.lifetime_actions.len()
            ));
        }
        let first = p.lifetime_actions.first();
        let mut renewal = "none";
        let mut days = String::new();
        if let Some(a) = first {
            renewal = match a.action.action_type.as_str() {
                "AutoRenew" => "auto",
                "EmailContacts" => "email",
                other => {
                    unsupported.push(format!("Its action is {other}, which this form can't set."));
                    "none"
                }
            };
            match (a.trigger.days_before_expiry, a.trigger.lifetime_percentage) {
                (Some(d), _) => days = d.to_string(),
                (_, Some(pc)) => unsupported.push(format!(
                    "It acts at {pc}% of the certificate's lifetime, and this form sets a number of days."
                )),
                _ => {}
            }
        }
        // Key Vault can't renew what it didn't sign, so don't offer it as
        // the starting point.
        if imported && renewal == "auto" {
            renewal = "email";
        }
        Self {
            form: RenewalForm {
                csrf: String::new(),
                renewal: renewal.into(),
                renew_days: days,
            },
            months,
            imported,
            has_action: first.is_some(),
            unsupported,
        }
    }
}

#[derive(Template)]
#[template(path = "certs/renewal.html")]
struct RenewalPage {
    shell: Shell,
    vault: String,
    name: String,
    form: RenewalForm,
    errors: FieldErrors,
    months: u32,
    max_days: u32,
    default_days: u32,
    imported: bool,
    has_action: bool,
    unsupported: Vec<String>,
    /// Key Vault's own reason, after it refused the change.
    azure_message: Option<String>,
}

impl RenewalPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

fn renewal_page(
    shell: Shell,
    vault: String,
    name: String,
    form: RenewalForm,
    current: Current,
    errors: FieldErrors,
    azure_message: Option<String>,
) -> axum::response::Response {
    let status = if errors.is_empty() && azure_message.is_none() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        render(&RenewalPage {
            shell,
            vault,
            name,
            form,
            errors,
            months: current.months,
            max_days: current.months * super::create::DAYS_PER_MONTH_LIMIT,
            default_days: default_renew_days(current.months),
            imported: current.imported,
            has_action: current.has_action,
            unsupported: current.unsupported,
            azure_message,
        }),
    )
        .into_response()
}

pub(crate) async fn form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let path = vault_path(&vault, &format!("/certificates/{name}"));
    let bundle = match api(&state, &session, &vault).get_cert(&name, None).await {
        Ok(b) => b,
        Err(e) => return Err(azure_problem(shell, &e, Need::ReadCertificates, &path)),
    };
    let current = Current::from_policy(&bundle.policy.unwrap_or_default());
    let form = current.form.clone();
    Ok(renewal_page(
        shell,
        vault,
        name,
        form,
        current,
        FieldErrors::new(),
        None,
    ))
}

pub(crate) async fn save(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<RenewalForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let certs = api(&state, &session, &vault);
    let path = vault_path(&vault, &format!("/certificates/{name}/renewal"));
    // Read the policy as it is now: the validity sets the limit on days, and
    // the issuer decides whether Key Vault can renew it.
    let bundle = match certs.get_cert(&name, None).await {
        Ok(b) => b,
        Err(e) => return Err(azure_problem(shell, &e, Need::ReadCertificates, &path)),
    };
    let current = Current::from_policy(&bundle.policy.clone().unwrap_or_default());
    let mut errors = FieldErrors::new();
    let actions = if !matches!(f.renewal.as_str(), "auto" | "email" | "none") {
        errors.push("renewal", "Pick what should happen near expiry.");
        Vec::new()
    } else if f.renewal == "auto" && current.imported {
        errors.push(
            "renewal",
            "Key Vault can only remind for a certificate that was signed outside it. Pick the email choice.",
        );
        Vec::new()
    } else if f.renewal == "none" && current.has_action {
        errors.push(
            "renewal",
            "Key Vault won't remove the action this certificate already has. Pick renewing or emailing.",
        );
        Vec::new()
    } else {
        lifetime_actions(&f.renewal, &f.renew_days, current.months).unwrap_or_else(
            |(field, message)| {
                errors.push(field, message);
                Vec::new()
            },
        )
    };
    if !errors.is_empty() {
        let form = f.clone();
        return Ok(renewal_page(
            shell, vault, name, form, current, errors, None,
        ));
    }
    match certs.update_lifetime_actions(&name, &actions).await {
        // Key Vault answered, but its policy doesn't show what was sent. It
        // has kept values it was asked to change before (dates sent as null,
        // #187, and an empty action list), so say nothing changed rather than
        // report a change that didn't happen.
        Ok(policy) if !applied(&actions, &policy.lifetime_actions) => {
            let mut errors = FieldErrors::new();
            errors.push(
                "renewal",
                "Key Vault answered, but it kept the old setting, so nothing changed. Change it in the Azure portal.",
            );
            Ok(renewal_page(shell, vault, name, f, current, errors, None))
        }
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate renewal changed");
            Ok(redirect_with(
                &state,
                &vault_path(&vault, &format!("/certificates/{name}")),
                format!("Saved what happens near expiry for {name}."),
            ))
        }
        Err(e) => match rejection_message(&e) {
            Some(m) => Ok(renewal_page(
                shell,
                vault,
                name,
                f,
                current,
                FieldErrors::new(),
                Some(m),
            )),
            None => Err(azure_problem(shell, &e, Need::ManageCertificates, &path)),
        },
    }
}

/// True when Key Vault's policy shows the actions that were sent: the same
/// number, each with the same type and day count. Other fields Key Vault may
/// fill in are ignored.
fn applied(sent: &[LifetimeAction], got: &[LifetimeAction]) -> bool {
    let key = |a: &LifetimeAction| {
        (
            a.action.action_type.clone(),
            a.trigger.days_before_expiry,
            a.trigger.lifetime_percentage,
        )
    };
    sent.len() == got.len() && sent.iter().zip(got).all(|(s, g)| key(s) == key(g))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::certs::{IssuerProps, LifetimeActionType, LifetimeTrigger, X509Props};

    fn action(kind: &str, days: Option<u32>, pct: Option<u32>) -> LifetimeAction {
        LifetimeAction {
            trigger: LifetimeTrigger {
                days_before_expiry: days,
                lifetime_percentage: pct,
            },
            action: LifetimeActionType {
                action_type: kind.into(),
            },
        }
    }

    fn policy(issuer: &str, actions: Vec<LifetimeAction>) -> Policy {
        Policy {
            issuer: Some(IssuerProps {
                name: Some(issuer.into()),
            }),
            x509_props: Some(X509Props {
                validity_months: Some(6),
                ..X509Props::default()
            }),
            lifetime_actions: actions,
            ..Policy::default()
        }
    }

    #[test]
    fn prefills_from_the_first_action() {
        let c = Current::from_policy(&policy("Self", vec![action("AutoRenew", Some(30), None)]));
        assert_eq!(c.form.renewal, "auto");
        assert_eq!(c.form.renew_days, "30");
        assert_eq!(c.months, 6);
        assert!(!c.imported && c.unsupported.is_empty());
        let c = Current::from_policy(&policy("Self", Vec::new()));
        assert_eq!(c.form.renewal, "none");
        assert_eq!(c.months, 6);
        assert_eq!(Current::from_policy(&Policy::default()).months, 12);
    }

    #[test]
    fn warns_about_what_the_form_cannot_show() {
        let c = Current::from_policy(&policy("Self", vec![action("AutoRenew", None, Some(80))]));
        assert_eq!(c.unsupported.len(), 1);
        assert_eq!(c.form.renew_days, "");
        let c = Current::from_policy(&policy(
            "Self",
            vec![
                action("EmailContacts", Some(30), None),
                action("AutoRenew", Some(7), None),
            ],
        ));
        assert_eq!(c.unsupported.len(), 1);
    }

    #[test]
    fn a_change_counts_only_when_key_vault_shows_it() {
        let email = action("EmailContacts", Some(14), None);
        assert!(applied(&[], &[]));
        assert!(applied(
            std::slice::from_ref(&email),
            std::slice::from_ref(&email)
        ));
        // "Do nothing" sent, the old action kept.
        assert!(!applied(&[], &[action("AutoRenew", Some(30), None)]));
        // Same type, different day count.
        assert!(!applied(
            &[email],
            &[action("EmailContacts", Some(30), None)]
        ));
    }

    #[test]
    fn imported_certificates_do_not_start_on_auto() {
        let c = Current::from_policy(&policy(
            "Unknown",
            vec![action("AutoRenew", Some(30), None)],
        ));
        assert!(c.imported);
        assert_eq!(c.form.renewal, "email");
    }

    #[test]
    fn knows_whether_there_is_an_action_to_keep() {
        let some = Current::from_policy(&policy("Self", vec![action("AutoRenew", Some(30), None)]));
        assert!(some.has_action);
        assert!(!Current::from_policy(&policy("Self", Vec::new())).has_action);
    }
}
