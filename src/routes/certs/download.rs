//! Certificate downloads.
//!
//! `.cer` is the public certificate only. `.pfx` includes the private key,
//! read from the certificate's backing secret, so it's only offered when
//! the policy marks the key exportable, needs the name typed, and is never
//! cached or logged.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::Resource;
use crate::azure::secrets::is_valid_version;
use crate::routes::assets::render;
use crate::routes::confirm::{self, ConfirmForm, ConfirmView};
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, checked_name, vault_path};
use crate::x509;

use super::{api, current_vault};

#[derive(Deserialize)]
pub(crate) struct CerQuery {
    /// `der` (default) or `pem`.
    #[serde(default)]
    format: String,
    #[serde(default)]
    version: String,
}

fn checked_version(v: &str, shell: Shell) -> Result<(Option<String>, Shell), Halt> {
    let v = v.trim();
    if v.is_empty() {
        Ok((None, shell))
    } else if is_valid_version(v) {
        Ok((Some(v.to_owned()), shell))
    } else {
        Err(PageError::new(shell, Problem::not_found()).into())
    }
}

fn attachment(body: Vec<u8>, mime: &'static str, filename: &str) -> Response {
    let mut res = (StatusCode::OK, body).into_response();
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
    // `filename` is a checked Key Vault name, so it's safe in the header.
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        h.insert(CONTENT_DISPOSITION, v);
    }
    no_store(res)
}

pub(crate) async fn cer(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Query(q): Query<CerQuery>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (version, shell) = checked_version(&q.version, shell)?;
    let bundle = match api(&state, &session, &vault)
        .get_cert(&name, version.as_deref())
        .await
    {
        Ok(b) => b,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ReadCertificates,
                &vault_path(&vault, &format!("/certificates/{name}")),
            ));
        }
    };
    let Some(der) = bundle.der() else {
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::CONFLICT,
                "No certificate yet",
                "This certificate hasn't been issued yet, so there's nothing to download. Check the pending request on its page.",
            ),
        )
        .into());
    };
    Ok(if q.format == "pem" {
        attachment(
            x509::to_pem("CERTIFICATE", &der).into_bytes(),
            "application/x-pem-file",
            &format!("{name}.pem"),
        )
    } else {
        attachment(der, "application/pkix-cert", &format!("{name}.cer"))
    })
}

#[derive(Template)]
#[template(path = "confirm.html")]
struct ConfirmPage {
    shell: Shell,
    confirm: ConfirmView,
}

fn pfx_view(vault: &str, name: &str, pem: bool) -> ConfirmView {
    let what = if pem { "a PEM file" } else { "a .pfx file" };
    ConfirmView {
        heading: format!("Download {name} with its private key?"),
        warning: format!(
            "You'll get {what} holding the private key from {vault}. Anyone with the file can pretend to be this certificate's owner. Keep it somewhere safe and delete it when you're done."
        ),
        expected: name.to_owned(),
        action: vault_path(vault, &format!("/certificates/{name}/download-key")),
        button: "Download with private key".into(),
        cancel_url: vault_path(vault, &format!("/certificates/{name}")),
        second_warning: Some(
            "Only use this if you need the key outside Key Vault. Apps on Azure can usually read the certificate straight from the vault instead.".into(),
        ),
        error: None,
    }
}

async fn require_exportable(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    name: &str,
    shell: Shell,
) -> Result<(Shell, crate::azure::certs::CertBundle), Halt> {
    let bundle = match api(state, session, vault).get_cert(name, None).await {
        Ok(b) => b,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ReadCertificates,
                &vault_path(vault, &format!("/certificates/{name}")),
            ));
        }
    };
    if bundle.policy.as_ref().is_some_and(|p| p.exportable()) && bundle.sid.is_some() {
        Ok((shell, bundle))
    } else {
        Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::FORBIDDEN,
                "The private key can't be downloaded",
                "This certificate's policy keeps its private key inside Key Vault. You can still download the public certificate.",
            ),
        )
        .into())
    }
}

pub(crate) async fn pfx_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let (shell, bundle) = require_exportable(&state, &session, &vault, &name, shell).await?;
    let pem = bundle
        .policy
        .as_ref()
        .is_some_and(|p| p.content_type() == "application/x-pem-file");
    Ok(render(&ConfirmPage {
        shell,
        confirm: pfx_view(&vault, &name, pem),
    })
    .into_response())
}

/// True when `sid` is `{vault}/secrets/{name}/{version}` on this vault:
/// same origin (host in any case), the exact name, and a hex version.
pub(crate) fn is_backing_secret(vault_url: &str, name: &str, sid: &str) -> bool {
    if !crate::azure::paging::same_vault(vault_url, sid) {
        return false;
    }
    let Some((_, after)) = sid.split_once("://") else {
        return false;
    };
    let path = after.find('/').map(|i| &after[i..]).unwrap_or_default();
    if path.contains(['?', '#']) {
        return false;
    }
    let base = vault_url
        .split_once("://")
        .and_then(|(_, a)| a.find('/').map(|i| a[i..].trim_end_matches('/')))
        .unwrap_or_default();
    let Some(rest) = path.strip_prefix(base) else {
        return false;
    };
    match rest
        .strip_prefix("/secrets/")
        .map(|r| r.split('/').collect::<Vec<_>>())
    {
        Some(parts) => matches!(parts.as_slice(), [n, v] if *n == name && is_valid_version(v)),
        None => false,
    }
}

#[derive(Deserialize)]
struct SecretValue {
    value: String,
    #[serde(rename = "contentType", default)]
    content_type: Option<String>,
}

pub(crate) async fn pfx(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(form): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    // The form token first, so a forged post reaches nothing in Key Vault.
    let shell = check_csrf(&session, &vault, &form.csrf, shell)?;
    let (shell, bundle) = require_exportable(&state, &session, &vault, &name, shell).await?;
    let pem = bundle
        .policy
        .as_ref()
        .is_some_and(|p| p.content_type() == "application/x-pem-file");
    match confirm::verify(&session.0, &vault, &form, &name) {
        Ok(()) => {}
        Err(confirm::ConfirmError::StaleForm) => {
            return Err(PageError::new(shell, Problem::stale_form()).into());
        }
        Err(confirm::ConfirmError::NameMismatch) => {
            let mut view = pfx_view(&vault, &name, pem);
            view.error = Some(confirm::ConfirmError::mismatch(&name, "downloaded"));
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                render(&ConfirmPage {
                    shell,
                    confirm: view,
                }),
            )
                .into_response()
                .into());
        }
    }
    // The backing secret URL comes from Key Vault; only use it if it's
    // exactly this certificate's secret on this vault.
    let sid = bundle.sid.unwrap_or_default();
    let vault_url = state.config.vault_url(&vault);
    if !is_backing_secret(&vault_url, &name, &sid) {
        return Err(PageError::new(shell, Problem::not_found()).into());
    }
    let url = format!("{sid}?api-version={}", crate::azure::secrets::API_VERSION);
    let secret: SecretValue = match state
        .azure
        .get_json(&session.0, Resource::KeyVault, &url)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ExportCertificate,
                &vault_path(&vault, &format!("/certificates/{name}")),
            ));
        }
    };
    tracing::warn!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate private key downloaded");
    let is_pem = secret.content_type.as_deref() == Some("application/x-pem-file");
    if is_pem {
        Ok(attachment(
            secret.value.into_bytes(),
            "application/x-pem-file",
            &format!("{name}.pem"),
        ))
    } else {
        match STANDARD.decode(secret.value.trim()) {
            Ok(bytes) => Ok(attachment(bytes, "application/x-pkcs12", &format!("{name}.pfx"))),
            Err(_) => Err(PageError::new(
                shell,
                Problem::new(
                    StatusCode::BAD_GATEWAY,
                    "Key Vault sent an unreadable file",
                    "The certificate's stored file couldn't be read. Try again, or download it from the Azure portal.",
                ),
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn backing_secret_url_must_be_exact() {
        let vault = "https://kv-prod.vault.azure.net";
        assert!(is_backing_secret(
            vault,
            "api",
            &format!("https://kv-prod.vault.azure.net/secrets/api/{V}")
        ));
        // Key Vault may write the host in another case, or with :443.
        assert!(is_backing_secret(
            vault,
            "api",
            &format!("https://KV-Prod.vault.azure.net:443/secrets/api/{V}")
        ));
        for bad in [
            format!("https://kv-prod.vault.azure.net/secrets/api-internal/{V}"),
            format!("https://kv-prod.vault.azure.net/secrets/api/{V}/extra"),
            "https://kv-prod.vault.azure.net/secrets/api/not-hex".to_owned(),
            "https://kv-prod.vault.azure.net/secrets/api".to_owned(),
            format!("https://kv-other.vault.azure.net/secrets/api/{V}"),
            format!("https://kv-prod.vault.azure.net/secrets/api/{V}?x=1"),
            format!("https://kv-prod.vault.azure.net/keys/api/{V}"),
            String::new(),
        ] {
            assert!(!is_backing_secret(vault, "api", &bad), "{bad}");
        }
        // The test mock serves vaults under a path.
        let local = "http://127.0.0.1:5000/kv-test";
        assert!(is_backing_secret(
            local,
            "api",
            &format!("http://127.0.0.1:5000/kv-test/secrets/api/{V}")
        ));
        assert!(!is_backing_secret(
            local,
            "api",
            &format!("http://127.0.0.1:5000/kv-other/secrets/api/{V}")
        ));
    }
}
