//! Upload a `.pfx` or `.pem` certificate.
//!
//! The file is read into memory, checked, and shown as a preview. On
//! confirm it's imported into Key Vault and dropped. It's never written to
//! disk, logged or sent back to the browser.

use std::collections::BTreeMap;
use std::time::Instant;

use askama::Template;
use axum::Form;
use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::auth::crypto::random_token;
use crate::auth::session::PendingUpload;
use crate::azure::AzureError;
use crate::azure::certs::{ImportCert, KeyProps, Policy, SecretProps};
use crate::azure::secrets::{Attributes, now_ts};
use crate::dates;
use crate::pkcs12;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::secrets::form::{FieldError, name_problem, parse_tags};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf};
use crate::secret::Secret;
use crate::x509;

use super::{api, current_vault};

/// Largest file we accept. Real certificate files are a few KB; chains a
/// little more.
pub const MAX_FILE_BYTES: usize = 256 * 1024;
/// Request size limit for the upload route (file plus form fields).
pub const MAX_BODY_BYTES: usize = MAX_FILE_BYTES + 16 * 1024;

pub const PFX: &str = "application/x-pkcs12";
pub const PEM: &str = "application/x-pem-file";

/// Fields put back into the form after an error. Never the file or password.
#[derive(Default)]
pub struct UploadView {
    pub name: String,
    pub tags: String,
    pub enabled: bool,
    pub exportable: bool,
}

#[derive(Template)]
#[template(path = "certs/upload.html")]
struct UploadPage {
    shell: Shell,
    vault: String,
    form: UploadView,
    errors: Vec<FieldError>,
    max_kb: usize,
}

impl UploadPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }
}

pub struct PreviewCert {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub expired: bool,
}

#[derive(Template)]
#[template(path = "certs/upload_preview.html")]
struct PreviewPage {
    shell: Shell,
    vault: String,
    name: String,
    kind: &'static str,
    cert: Option<PreviewCert>,
    chain_len: usize,
    upload_id: String,
    tags: Vec<(String, String)>,
    enabled: bool,
    exportable: bool,
}

fn upload_page(
    shell: Shell,
    vault: String,
    form: UploadView,
    errors: Vec<FieldError>,
) -> axum::response::Response {
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    no_store(
        (
            status,
            render(&UploadPage {
                shell,
                vault,
                form,
                errors,
                max_kb: MAX_FILE_BYTES / 1024,
            }),
        )
            .into_response(),
    )
}

pub async fn form(session: CurrentSession, shell: Shell) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    Ok(upload_page(
        shell,
        vault,
        UploadView {
            enabled: true,
            exportable: true,
            ..UploadView::default()
        },
        Vec::new(),
    ))
}

/// The posted form, gathered from multipart fields.
#[derive(Default)]
struct Posted {
    csrf: String,
    name: String,
    tags: String,
    enabled: bool,
    exportable: bool,
    password: Option<Secret>,
    file: Option<Vec<u8>>,
    file_name: String,
    too_big: bool,
}

async fn read_multipart(mut mp: Multipart) -> Result<Posted, ()> {
    let mut p = Posted::default();
    while let Some(mut field) = mp.next_field().await.map_err(|_| ())? {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                p.file_name = field.file_name().unwrap_or_default().to_owned();
                let mut buf = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(|_| ())? {
                    if buf.len() + chunk.len() > MAX_FILE_BYTES {
                        p.too_big = true;
                        break;
                    }
                    buf.extend_from_slice(&chunk);
                }
                if !buf.is_empty() {
                    p.file = Some(buf);
                }
            }
            "password" => {
                let v = field.text().await.map_err(|_| ())?;
                if !v.is_empty() {
                    p.password = Some(Secret::new(v));
                }
            }
            "csrf" => p.csrf = field.text().await.map_err(|_| ())?,
            "name" => p.name = field.text().await.map_err(|_| ())?.trim().to_owned(),
            "tags" => p.tags = field.text().await.map_err(|_| ())?,
            "enabled" => p.enabled = true,
            "exportable" => p.exportable = true,
            _ => {}
        }
    }
    Ok(p)
}

/// What the file turned out to be.
pub enum Parsed {
    Pfx {
        /// Certificates readable without the password (often none).
        certs: Vec<Vec<u8>>,
    },
    Pem {
        certs: Vec<Vec<u8>>,
    },
}

/// Check a file is a usable PFX or PEM. Errors are written for people.
pub fn parse_file(bytes: &[u8], file_name: &str) -> Result<Parsed, String> {
    let lower = file_name.to_ascii_lowercase();
    let looks_pem = bytes.starts_with(b"-----")
        || std::str::from_utf8(bytes).is_ok_and(|s| s.contains("-----BEGIN"));
    if looks_pem {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "This PEM file has characters Keyring can't read.".to_owned())?;
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return Err("The private key in this PEM file is encrypted. Key Vault needs it unencrypted in a PEM upload. Use a .pfx with a password instead.".into());
        }
        let certs: Vec<Vec<u8>> = x509::pem_blocks(text, "CERTIFICATE")
            .into_iter()
            .filter(|c| x509::summarise(c).is_some())
            .collect();
        if certs.is_empty() {
            return Err("This PEM file has no certificate in it. It needs a -----BEGIN CERTIFICATE----- block.".into());
        }
        let has_key = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
            .iter()
            .any(|l| text.contains(&format!("-----BEGIN {l}-----")));
        if !has_key {
            return Err("This PEM file has a certificate but no private key. Add the key to the same file, or upload a .pfx.".into());
        }
        return Ok(Parsed::Pem { certs });
    }
    match pkcs12::inspect(bytes) {
        Some(info) if info.has_key || info.has_encrypted_part => Ok(Parsed::Pfx { certs: info.certs }),
        Some(_) => Err("This .pfx file has no private key in it.".into()),
        None if lower.ends_with(".cer") || lower.ends_with(".crt") || x509::summarise(bytes).is_some() => {
            Err("This is a public certificate only. Key Vault needs the private key too, in a .pfx or a PEM with the key.".into())
        }
        None => Err("Keyring can't read this file. Upload a .pfx (or .p12) file, or a .pem with the certificate and private key.".into()),
    }
}

pub async fn preview(
    State(_state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    multipart: Multipart,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let Ok(p) = read_multipart(multipart).await else {
        let errors = vec![FieldError {
            field: "file",
            message: "The upload didn't come through. Try again.".into(),
        }];
        return Ok(upload_page(shell, vault, UploadView::default(), errors));
    };
    let shell = check_csrf(&session, &p.csrf, shell)?;
    let view = UploadView {
        name: p.name.clone(),
        tags: p.tags.clone(),
        enabled: p.enabled,
        exportable: p.exportable,
    };
    let mut errors = Vec::new();
    if let Some(m) = name_problem(&p.name) {
        errors.push(FieldError {
            field: "name",
            message: m.replace("the secret", "the certificate"),
        });
    }
    let tags = parse_tags(&p.tags).unwrap_or_else(|m| {
        errors.push(FieldError {
            field: "tags",
            message: m,
        });
        BTreeMap::new()
    });
    let parsed = if p.too_big {
        errors.push(FieldError {
            field: "file",
            message: format!("That file is over {} KB. Certificate files are usually much smaller; check it's the right one.", MAX_FILE_BYTES / 1024),
        });
        None
    } else {
        match &p.file {
            None => {
                errors.push(FieldError {
                    field: "file",
                    message: "Choose a file to upload.".into(),
                });
                None
            }
            Some(bytes) => match parse_file(bytes, &p.file_name) {
                Ok(parsed) => Some(parsed),
                Err(m) => {
                    errors.push(FieldError {
                        field: "file",
                        message: m,
                    });
                    None
                }
            },
        }
    };
    let (Some(parsed), true) = (parsed, errors.is_empty()) else {
        return Ok(upload_page(shell, vault, view, errors));
    };
    let bytes = p.file.unwrap_or_default();
    let (kind, content_type, value, certs) = match parsed {
        Parsed::Pfx { certs } => (".pfx", PFX, STANDARD.encode(&bytes), certs),
        Parsed::Pem { certs } => (
            ".pem",
            PEM,
            String::from_utf8(bytes).unwrap_or_default(),
            certs,
        ),
    };
    let now = now_ts();
    let cert = certs
        .first()
        .and_then(|c| x509::summarise(c))
        .map(|s| PreviewCert {
            expired: s.not_after <= now,
            valid_from: dates::format_datetime(s.not_before),
            valid_to: dates::format_datetime(s.not_after),
            subject: s.subject,
            issuer: s.issuer,
            sans: s.sans,
        });
    let upload_id = random_token(16);
    session.0.set_pending_upload(PendingUpload {
        id: upload_id.clone(),
        vault: vault.clone(),
        name: p.name.clone(),
        content_type,
        value: Secret::new(value),
        password: p.password,
        tags: tags.clone(),
        enabled: p.enabled,
        exportable: p.exportable,
        created: Instant::now(),
    });
    Ok(no_store(
        render(&PreviewPage {
            shell,
            vault,
            name: p.name,
            kind,
            cert,
            chain_len: certs.len(),
            upload_id,
            tags: tags.into_iter().collect(),
            enabled: p.enabled,
            exportable: p.exportable,
        })
        .into_response(),
    ))
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    csrf: String,
    upload_id: String,
}

pub async fn confirm(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let shell = check_csrf(&session, &f.csrf, shell)?;
    let Some(up) = session
        .0
        .take_pending_upload(&f.upload_id)
        .filter(|u| u.vault == vault)
    else {
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::GONE,
                "That upload has expired",
                "Keyring only holds an uploaded file for 10 minutes, and only for one import. Upload it again.",
            )
            .returning_to("/certificates/upload"),
        )
        .into());
    };
    let body = ImportCert {
        value: up.value,
        pwd: up.password,
        policy: Policy {
            key_props: Some(KeyProps {
                exportable: Some(up.exportable),
                ..KeyProps::default()
            }),
            secret_props: Some(SecretProps {
                content_type: Some(up.content_type.into()),
            }),
            ..Policy::default()
        },
        attributes: Attributes {
            enabled: Some(up.enabled),
            ..Attributes::default()
        },
        tags: Some(up.tags),
    };
    let name = up.name;
    match api(&state, &session, &vault).import(&name, &body).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, "certificate uploaded");
            let mut res = Redirect::to(&format!("/certificates/{name}")).into_response();
            flash::set(&state, &mut res, &Flash::success(format!("Uploaded {name}.")));
            Ok(res)
        }
        // Key Vault answers 400 when the password is wrong or the file is
        // damaged. Say that plainly rather than "Azure turned it down".
        Err(AzureError::Status { status: 400, .. }) => Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Key Vault couldn't open the file",
                "The password is probably wrong, or the file is damaged. Nothing was uploaded. Upload it again with the right password.",
            )
            .returning_to("/certificates/upload"),
        )
        .into()),
        Err(AzureError::Status { status: 409, .. }) => Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::CONFLICT,
                "That name is taken",
                format!("There's a certificate called {name}, or one was deleted recently and can still be recovered. Pick another name, or recover the deleted one."),
            )
            .returning_to("/certificates/upload"),
        )
        .into()),
        Err(err) => Err(azure_problem(shell, &err, Need::ManageCertificates, "/certificates/upload")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &[u8] = include_bytes!("../../../tests/fixtures/test-plain.pfx");
    const ENCRYPTED: &[u8] = include_bytes!("../../../tests/fixtures/test-encrypted.pfx");
    const BUNDLE: &str = include_str!("../../../tests/fixtures/test-bundle.pem");
    const CERT: &str = include_str!("../../../tests/fixtures/test-cert.pem");

    #[test]
    fn accepts_pfx_and_pem_with_key() {
        assert!(
            matches!(parse_file(PLAIN, "a.pfx"), Ok(Parsed::Pfx { certs }) if certs.len() == 1)
        );
        assert!(
            matches!(parse_file(ENCRYPTED, "a.p12"), Ok(Parsed::Pfx { certs }) if certs.is_empty())
        );
        assert!(
            matches!(parse_file(BUNDLE.as_bytes(), "a.pem"), Ok(Parsed::Pem { certs }) if certs.len() == 1)
        );
    }

    #[test]
    fn explains_bad_files() {
        let e = parse_file(CERT.as_bytes(), "a.pem").err().unwrap();
        assert!(e.contains("no private key"));
        let der = &x509::pem_blocks(CERT, "CERTIFICATE")[0];
        assert!(
            parse_file(der, "a.cer")
                .err()
                .unwrap()
                .contains("public certificate only")
        );
        assert!(
            parse_file(b"hello", "a.txt")
                .err()
                .unwrap()
                .contains("can't read this file")
        );
        let enc = "-----BEGIN CERTIFICATE-----\n".to_owned()
            + CERT
            + "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(
            parse_file(enc.as_bytes(), "a.pem")
                .err()
                .unwrap()
                .contains("encrypted")
        );
        assert!(
            parse_file(
                b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
                "k.pem"
            )
            .err()
            .unwrap()
            .contains("no certificate")
        );
    }
}
