//! Upload a `.pfx` or `.pem` certificate.
//!
//! The file is read into memory, checked, and shown as a preview. On
//! confirm it's imported into Key Vault and dropped. It's never written to
//! disk, logged or sent back to the browser. Opening the upload page or
//! pressing "Start again" drops any file still waiting.

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
use crate::routes::error::{Need, PageError, PageResult, Problem, rejection_message};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::form::parse_tags;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf};
use crate::secret::Secret;
use crate::x509;

use super::{api, current_vault, new_name_problem};

/// Largest file we accept. Real certificate files are a few KB; chains a
/// little more.
pub(crate) const MAX_FILE_BYTES: usize = 256 * 1024;
/// Request size limit for the upload route (file plus form fields).
pub(crate) const MAX_BODY_BYTES: usize = MAX_FILE_BYTES + 16 * 1024;

pub(crate) const PFX: &str = "application/x-pkcs12";
pub(crate) const PEM: &str = "application/x-pem-file";

/// Fields put back into the form after an error. Never the file or password.
pub(crate) struct UploadView {
    pub name: String,
    pub tags: String,
    pub enabled: bool,
    pub exportable: bool,
}

impl Default for UploadView {
    /// What the form shows when first opened.
    fn default() -> Self {
        Self {
            name: String::new(),
            tags: String::new(),
            enabled: true,
            exportable: true,
        }
    }
}

#[derive(Template)]
#[template(path = "certs/upload.html")]
struct UploadPage {
    shell: Shell,
    vault: String,
    form: UploadView,
    errors: FieldErrors,
    max_kb: usize,
    /// Key Vault's own reason, after it refused the import.
    azure_message: Option<String>,
}

impl UploadPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

pub(crate) struct PreviewCert {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub expired: bool,
}

impl PreviewCert {
    fn from_summary(s: x509::Summary, now: i64) -> Self {
        Self {
            expired: s.not_after <= now,
            valid_from: dates::format_datetime(s.not_before),
            valid_to: dates::format_datetime(s.not_after),
            subject: s.subject,
            issuer: s.issuer,
            sans: s.sans,
        }
    }
}

/// The rest of the chain in the file, under the main certificate.
pub(crate) struct ChainCert {
    pub subject: String,
    pub valid_to: String,
}

/// The certificate already in Key Vault under the name being uploaded to.
pub(crate) struct ExistingCert {
    pub subject: String,
    pub thumbprint: String,
    pub expires: String,
}

#[derive(Template)]
#[template(path = "certs/upload_preview.html")]
struct PreviewPage {
    shell: Shell,
    vault: String,
    name: String,
    kind: &'static str,
    cert: Option<PreviewCert>,
    /// False when Keyring couldn't tell which certificate is the main one.
    leaf_sure: bool,
    chain: Vec<ChainCert>,
    /// Keyring couldn't read inside the file at all (BER encoding).
    unreadable: bool,
    has_password: bool,
    existing: Option<ExistingCert>,
    /// The name couldn't be looked up, so it may already be in use.
    existing_unknown: bool,
    upload_id: String,
    tags: Vec<(String, String)>,
    enabled: bool,
    exportable: bool,
}

fn upload_page(
    shell: Shell,
    vault: String,
    form: UploadView,
    errors: FieldErrors,
    azure_message: Option<String>,
) -> axum::response::Response {
    let status = if errors.is_empty() && azure_message.is_none() {
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
                azure_message,
            }),
        )
            .into_response(),
    )
}

/// Drop any file waiting in this session. `take_pending_upload` removes
/// the upload whatever ID it's given, and an upload ID is never empty, so
/// this always drops it and never returns it.
fn forget_pending_upload(session: &CurrentSession) {
    drop(session.0.take_pending_upload(""));
}

fn too_big_message() -> String {
    format!(
        "That file is over {} KB. Certificate files are usually much smaller; check it's the right one.",
        MAX_FILE_BYTES / 1024
    )
}

pub(crate) async fn form(session: CurrentSession, shell: Shell) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    // A fresh form means any file waiting from before isn't wanted.
    forget_pending_upload(&session);
    Ok(upload_page(
        shell,
        vault,
        UploadView::default(),
        FieldErrors::new(),
        None,
    ))
}

#[derive(Deserialize)]
pub(crate) struct CancelForm {
    #[serde(default)]
    csrf: String,
}

/// "Start again" on the preview: drop the waiting file and go back.
pub(crate) async fn cancel(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<CancelForm>,
) -> PageResult {
    // Dropping the waiting file is safe whichever vault the form was for.
    if !session.0.csrf_matches_any(&f.csrf) {
        return Err(PageError::new(shell, Problem::stale_form()).into());
    }
    forget_pending_upload(&session);
    let mut res = Redirect::to("/certificates/-/upload").into_response();
    flash::set(
        &state,
        &mut res,
        &Flash::success("Keyring has forgotten that file. Nothing was uploaded."),
    );
    Ok(res)
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

/// Why the multipart body couldn't be read.
enum ReadError {
    /// The request went over the route's body limit.
    TooBig,
    Broken,
}

impl From<axum::extract::multipart::MultipartError> for ReadError {
    fn from(e: axum::extract::multipart::MultipartError) -> Self {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::TooBig
        } else {
            Self::Broken
        }
    }
}

/// Read every field. A file over the limit is drained and dropped, so the
/// fields after it in the body are still read.
async fn read_multipart(mut mp: Multipart, p: &mut Posted) -> Result<(), ReadError> {
    while let Some(mut field) = mp.next_field().await? {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                p.file_name = field.file_name().unwrap_or_default().to_owned();
                let mut buf = Vec::new();
                while let Some(chunk) = field.chunk().await? {
                    if p.too_big || buf.len() + chunk.len() > MAX_FILE_BYTES {
                        p.too_big = true;
                        buf.clear();
                        continue;
                    }
                    buf.extend_from_slice(&chunk);
                }
                if !buf.is_empty() {
                    p.file = Some(buf);
                }
            }
            "password" => {
                let v = field.text().await?;
                if !v.is_empty() {
                    p.password = Some(Secret::new(v));
                }
            }
            "csrf" => p.csrf = field.text().await?,
            "name" => p.name = field.text().await?.trim().to_owned(),
            "tags" => p.tags = field.text().await?,
            "enabled" => p.enabled = true,
            "exportable" => p.exportable = true,
            _ => {}
        }
    }
    Ok(())
}

/// What the file turned out to be.
pub(crate) enum Parsed {
    Pfx {
        /// Certificates readable without the password (often none).
        certs: Vec<Vec<u8>>,
    },
    /// Starts like a PFX but in an encoding Keyring can't walk (BER, or
    /// indefinite lengths). Key Vault may still accept it.
    PfxUnreadable,
    Pem {
        certs: Vec<Vec<u8>>,
        /// The unencrypted PKCS #8 key, DER, for matching the certificate.
        key: Option<Vec<u8>>,
    },
}

const TOPK8: &str = "openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem";

/// Check a file is a usable PFX or PEM. Errors are written for people.
pub(crate) fn parse_file(bytes: &[u8], file_name: &str) -> Result<Parsed, String> {
    let lower = file_name.to_ascii_lowercase();
    let looks_pem = bytes.starts_with(b"-----")
        || std::str::from_utf8(bytes).is_ok_and(|s| s.contains("-----BEGIN"));
    if looks_pem {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "This PEM file has characters Keyring can't read.".to_owned())?;
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || text.contains("Proc-Type:") {
            return Err("The private key in this PEM file is encrypted. Key Vault needs it unencrypted in a PEM upload. Use a .pfx with a password instead.".into());
        }
        let certs: Vec<Vec<u8>> = x509::pem_blocks(text, "CERTIFICATE")
            .into_iter()
            .filter(|c| x509::summarise(c).is_some())
            .collect();
        if certs.is_empty() {
            return Err("This PEM file has no certificate in it. It needs a -----BEGIN CERTIFICATE----- block.".into());
        }
        // Key Vault's PEM import wants an unencrypted PKCS #8 key. PKCS #1
        // (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) pass a quick look
        // but fail at import.
        for (label, kind) in [("RSA PRIVATE KEY", "an RSA"), ("EC PRIVATE KEY", "an EC")] {
            if text.contains(&format!("-----BEGIN {label}-----")) {
                return Err(format!(
                    "The private key is in {kind} key format ({label}). Key Vault needs it as PKCS #8 (BEGIN PRIVATE KEY). Convert it with: {TOPK8}"
                ));
            }
        }
        let key = x509::pem_blocks(text, "PRIVATE KEY").into_iter().next();
        let Some(key) = key else {
            return Err("This PEM file has a certificate but no private key. Add the key to the same file, or upload a .pfx.".into());
        };
        // When Keyring can tell, the key must belong to one of the
        // certificates.
        let results: Vec<Option<bool>> = certs.iter().map(|c| x509::key_matches(c, &key)).collect();
        if results.iter().all(|r| *r == Some(false)) {
            return Err("The private key in this PEM file doesn't belong to its certificate. Check you've put the right key with it.".into());
        }
        return Ok(Parsed::Pem {
            certs,
            key: Some(key),
        });
    }
    match pkcs12::inspect(bytes) {
        Some(info) if info.has_key || info.has_encrypted_part => Ok(Parsed::Pfx { certs: info.certs }),
        Some(_) => Err("This .pfx file has no private key in it.".into()),
        None if pkcs12::looks_like_pfx(bytes) => Ok(Parsed::PfxUnreadable),
        None if lower.ends_with(".cer") || lower.ends_with(".crt") || x509::summarise(bytes).is_some() => {
            Err("This is a public certificate only. Key Vault needs the private key too, in a .pfx or a PEM with the key.".into())
        }
        None => Err("Keyring can't read this file. Upload a .pfx (or .p12) file, or a .pem with the certificate and private key.".into()),
    }
}

/// The certificate being uploaded and the rest of its chain. For PEM the
/// one matching the private key wins; otherwise the one that didn't issue
/// any of the others.
fn describe(
    certs: &[Vec<u8>],
    key: Option<&[u8]>,
    now: i64,
) -> (Option<PreviewCert>, bool, Vec<ChainCert>) {
    let summaries: Vec<x509::Summary> = certs.iter().filter_map(|c| x509::summarise(c)).collect();
    if summaries.is_empty() {
        return (None, true, Vec::new());
    }
    let by_key = key.and_then(|k| {
        certs
            .iter()
            .position(|c| x509::key_matches(c, k) == Some(true))
    });
    let (leaf, sure) = match by_key {
        Some(i) if i < summaries.len() => (i, true),
        _ => x509::pick_leaf(&summaries),
    };
    let chain = summaries
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != leaf)
        .map(|(_, s)| ChainCert {
            subject: s.subject.clone(),
            valid_to: dates::format_date(s.not_after),
        })
        .collect();
    let main = summaries
        .into_iter()
        .nth(leaf)
        .map(|s| PreviewCert::from_summary(s, now));
    (main, sure, chain)
}

pub(crate) async fn preview(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    multipart: Multipart,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let mut p = Posted::default();
    let read = read_multipart(multipart, &mut p).await;
    // A body cut off at the size limit may end before the form token
    // arrived. Then all Keyring can do is say the file is too big: nothing
    // goes to Key Vault and nothing is kept. Every other path checks the
    // token before anything else.
    if matches!(read, Err(ReadError::TooBig)) && p.csrf.is_empty() {
        let errors = FieldErrors::one("file", too_big_message());
        return Ok(upload_page(
            shell,
            vault,
            UploadView::default(),
            errors,
            None,
        ));
    }
    let shell = check_csrf(&session, &vault, &p.csrf, shell)?;
    let view = UploadView {
        name: p.name.clone(),
        tags: p.tags.clone(),
        enabled: p.enabled,
        exportable: p.exportable,
    };
    match read {
        Ok(()) => {}
        Err(ReadError::TooBig) => {
            // Fields after the file never arrived, so the tick boxes go back
            // to how the form first opened.
            let view = UploadView {
                name: p.name,
                tags: p.tags,
                ..UploadView::default()
            };
            let errors = FieldErrors::one("file", too_big_message());
            return Ok(upload_page(shell, vault, view, errors, None));
        }
        Err(ReadError::Broken) => {
            let errors = FieldErrors::one("file", "The upload didn't come through. Try again.");
            return Ok(upload_page(shell, vault, view, errors, None));
        }
    }
    let mut errors = FieldErrors::new();
    if let Some(m) = new_name_problem(&p.name) {
        errors.push("name", m);
    }
    let tags = parse_tags(&p.tags).unwrap_or_else(|m| {
        errors.push("tags", m);
        BTreeMap::new()
    });
    let parsed = if p.too_big {
        errors.push("file", too_big_message());
        None
    } else {
        match &p.file {
            None => {
                errors.push("file", "Choose a file to upload.");
                None
            }
            Some(bytes) => match parse_file(bytes, &p.file_name) {
                Ok(parsed) => Some(parsed),
                Err(m) => {
                    errors.push("file", m);
                    None
                }
            },
        }
    };
    let (Some(parsed), true) = (parsed, errors.is_empty()) else {
        return Ok(upload_page(shell, vault, view, errors, None));
    };
    // Importing onto an existing name adds a new current version, so show
    // what's there now next to the new file.
    let (existing, existing_unknown) = match api(&state, &session, &vault)
        .get_cert(&p.name, None)
        .await
    {
        Ok(b) => {
            let now = now_ts();
            (
                Some(ExistingCert {
                    subject: b
                        .der()
                        .and_then(|d| x509::summarise(&d))
                        .map(|s| s.subject)
                        .unwrap_or_default(),
                    thumbprint: crate::azure::certs::thumbprint_hex(b.x5t.as_deref()),
                    expires: b
                        .attributes
                        .expires
                        .map(|e| {
                            format!(
                                "{} ({})",
                                dates::format_date(e),
                                dates::relative_days(e, now)
                            )
                        })
                        .unwrap_or_default(),
                }),
                false,
            )
        }
        Err(AzureError::Status { status: 404, .. }) => (None, false),
        // Don't block the upload on a failed lookup; say so on the page.
        Err(e) => {
            tracing::warn!(vault = %vault, certificate = %p.name, error = %e, "couldn't check whether a certificate name is in use");
            (None, true)
        }
    };
    let bytes = p.file.unwrap_or_default();
    let now = now_ts();
    let (kind, content_type, value, described, unreadable) = match parsed {
        Parsed::Pfx { certs } => (
            ".pfx",
            PFX,
            STANDARD.encode(&bytes),
            describe(&certs, None, now),
            false,
        ),
        Parsed::PfxUnreadable => (
            ".pfx",
            PFX,
            STANDARD.encode(&bytes),
            (None, true, Vec::new()),
            true,
        ),
        Parsed::Pem { certs, key } => (
            ".pem",
            PEM,
            String::from_utf8(bytes).unwrap_or_default(),
            describe(&certs, key.as_deref(), now),
            false,
        ),
    };
    let (cert, leaf_sure, chain) = described;
    let has_password = p.password.is_some();
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
            leaf_sure,
            chain,
            unreadable,
            has_password,
            existing,
            existing_unknown,
            upload_id,
            tags: tags.into_iter().collect(),
            enabled: p.enabled,
            exportable: p.exportable,
        })
        .into_response(),
    ))
}

#[derive(Deserialize)]
pub(crate) struct ConfirmForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    upload_id: String,
}

pub(crate) async fn confirm(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(f): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    // The token is checked before the upload is taken, so a forged post
    // can't throw away someone's waiting file.
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
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
            .returning_to("/certificates/-/upload"),
        )
        .into());
    };
    let is_pfx = up.content_type == PFX;
    let view = UploadView {
        name: up.name.clone(),
        tags: up
            .tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n"),
        enabled: up.enabled,
        exportable: up.exportable,
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
        // Key Vault answers 400 when it can't open the file. Say what's
        // likely for this kind of file, keep the form, and show Key Vault's
        // own reason.
        Err(e @ AzureError::Status { status: 400, .. }) => {
            let message = if is_pfx {
                "Key Vault couldn't open the file. The password is probably wrong, or the file is damaged. Nothing was uploaded. Choose the file again and type the right password."
            } else {
                "Key Vault couldn't read this PEM file. It needs the certificate and an unencrypted PKCS #8 private key that belongs to it. Nothing was uploaded."
            };
            let errors = FieldErrors::one("file", message);
            Ok(upload_page(shell, vault, view, errors, rejection_message(&e)))
        }
        // An existing live certificate never gives 409 on import. Only a
        // deleted one that can still be recovered does.
        Err(AzureError::Status { status: 409, .. }) => Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::CONFLICT,
                "That name is taken",
                format!("A deleted certificate called {name} can still be recovered. Recover it from deleted certificates, or pick another name."),
            )
            .returning_to("/certificates/-/upload"),
        )
        .into()),
        Err(err) => Err(azure_problem(shell, &err, Need::ManageCertificates, "/certificates/-/upload")),
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
            matches!(parse_file(BUNDLE.as_bytes(), "a.pem"), Ok(Parsed::Pem { certs, key: Some(_) }) if certs.len() == 1)
        );
    }

    #[test]
    fn pem_key_formats_key_vault_refuses() {
        let cert = CERT;
        for (label, expect) in [
            ("RSA PRIVATE KEY", "openssl pkcs8 -topk8"),
            ("EC PRIVATE KEY", "openssl pkcs8 -topk8"),
        ] {
            let pem = format!("{cert}-----BEGIN {label}-----\nAA==\n-----END {label}-----\n");
            let e = parse_file(pem.as_bytes(), "a.pem").err().unwrap();
            assert!(e.contains(expect) && e.contains("PKCS #8"), "{label}: {e}");
        }
        let legacy = format!(
            "{cert}-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAA==\n-----END RSA PRIVATE KEY-----\n"
        );
        assert!(
            parse_file(legacy.as_bytes(), "a.pem")
                .err()
                .unwrap()
                .contains("encrypted")
        );
    }

    #[test]
    fn pem_key_must_match_the_certificate() {
        let key = x509::pem_blocks(BUNDLE, "PRIVATE KEY")[0].clone();
        let mut other = key.clone();
        // Change a byte inside the modulus: still parses, no longer matches.
        other[100] ^= 0x01;
        let pem = format!("{CERT}{}", x509::to_pem("PRIVATE KEY", &other));
        let e = parse_file(pem.as_bytes(), "a.pem").err().unwrap();
        assert!(e.contains("doesn't belong"), "{e}");
    }

    #[test]
    fn ber_pfx_is_allowed_without_a_preview() {
        let ber = crate::pkcs12::tests::ber_pfx();
        assert!(matches!(
            parse_file(&ber, "old.pfx"),
            Ok(Parsed::PfxUnreadable)
        ));
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
