//! Certificate pages: list, detail, versions and downloads.

pub mod create;
pub mod delete;
pub mod download;
pub mod upload;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::certs::{CertBundle, CertItem, CertsApi, Operation, Policy};
use crate::azure::secrets::now_ts;
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::forms::ToggleForm;
use crate::routes::keys::section_note;
use crate::routes::lifecycle::redirect_with;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name};
use crate::x509;

/// Names Keyring uses for its own pages under `/certificates`, so a
/// certificate called one of these couldn't be opened from the list.
pub const RESERVED_NAMES: [&str; 3] = ["new", "deleted", "upload"];

/// Explain why a new certificate can't have this name, or `None` if it can.
pub fn reserved_name_problem(name: &str) -> Option<String> {
    RESERVED_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name))
        .then(|| {
            format!(
                "Keyring uses {name} for one of its own pages, so a certificate called that couldn't be opened here. Pick another name."
            )
        })
}

/// Name checks for a new certificate: Key Vault's rules, then Keyring's
/// reserved names.
pub fn new_name_problem(name: &str) -> Option<String> {
    crate::routes::forms::name_problem(crate::routes::lifecycle::Kind::Certificate, name)
        .or_else(|| reserved_name_problem(name))
}

pub const PER_PAGE: usize = 100;
const DAY: i64 = 86_400;

/// How close a certificate is to expiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertExpiry {
    None,
    Ok,
    /// Under 90 days.
    Within90,
    /// Under 30 days.
    Within30,
    Expired,
}

pub fn cert_expiry(expires: Option<i64>, now: i64) -> CertExpiry {
    match expires {
        None => CertExpiry::None,
        Some(e) if e <= now => CertExpiry::Expired,
        Some(e) if e - now <= 30 * DAY => CertExpiry::Within30,
        Some(e) if e - now <= 90 * DAY => CertExpiry::Within90,
        Some(_) => CertExpiry::Ok,
    }
}

pub struct CertRow {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub thumbprint: String,
    pub expires: String,
    pub expires_note: String,
    pub expiry: CertExpiry,
    pub created: String,
    pub tags: Vec<(String, String)>,
    pub filter_text: String,
}

impl CertRow {
    pub fn from_item(item: &CertItem, now: i64) -> Self {
        let a = &item.attributes;
        let tags: Vec<(String, String)> = item
            .tags()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut filter_text = item.name().to_lowercase();
        for (k, v) in &tags {
            filter_text.push_str(&format!(" {k}={v}").to_lowercase());
        }
        Self {
            name: item.name().to_owned(),
            version: item.version().to_owned(),
            enabled: a.is_enabled(),
            thumbprint: item.thumbprint(),
            expires: a.expires.map(dates::format_date).unwrap_or_default(),
            expires_note: a
                .expires
                .map(|e| dates::relative_days(e, now))
                .unwrap_or_default(),
            expiry: cert_expiry(a.expires, now),
            created: a.created.map(dates::format_datetime).unwrap_or_default(),
            tags,
            filter_text,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiry == CertExpiry::Expired
    }
    pub fn within30(&self) -> bool {
        self.expiry == CertExpiry::Within30
    }
    pub fn within90(&self) -> bool {
        self.expiry == CertExpiry::Within90
    }
    pub fn short_version(&self) -> String {
        self.version.chars().take(8).collect()
    }
}

pub fn current_vault(session: &CurrentSession, shell: Shell) -> Result<(String, Shell), Halt> {
    vault_ctx::current_vault(session, shell, Section::Certificates)
}

pub fn api<'a>(state: &'a AppState, session: &'a CurrentSession, vault: &str) -> CertsApi<'a> {
    CertsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct CertFilter {
    #[serde(default)]
    pub q: String,
    /// `expired`, `30`, `90` or `disabled`.
    #[serde(default)]
    pub show: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl CertFilter {
    pub fn is_empty(&self) -> bool {
        self.q.trim().is_empty() && self.show.is_empty()
    }

    pub fn matches(&self, r: &CertRow) -> bool {
        let q = self.q.trim().to_lowercase();
        if !q.is_empty() && !r.filter_text.contains(&q) && !r.thumbprint.to_lowercase().contains(&q)
        {
            return false;
        }
        match self.show.as_str() {
            "expired" => r.is_expired(),
            "30" => r.is_expired() || r.within30(),
            "90" => r.is_expired() || r.within30() || r.within90(),
            "disabled" => !r.enabled,
            _ => true,
        }
    }

    fn page_url(&self, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "/certificates?q={}&show={}&page={page}",
            enc(&self.q),
            enc(&self.show)
        )
    }
}

pub struct ShowOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "certs/list.html")]
struct ListPage {
    shell: Shell,
    vault: String,
    rows: Vec<CertRow>,
    total: usize,
    expired: usize,
    within30: usize,
    within90: usize,
    filter: CertFilter,
    show_options: Vec<ShowOption>,
    page: usize,
    pages: usize,
    shown_from: usize,
    prev_url: Option<String>,
    next_url: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<CertFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let items = match api(&state, &session, &vault).list().await {
        Ok(i) => i,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ReadCertificates,
                "/certificates",
            ));
        }
    };
    let now = now_ts();
    let all: Vec<CertRow> = items.iter().map(|i| CertRow::from_item(i, now)).collect();
    let total = all.len();
    let expired = all.iter().filter(|r| r.is_expired()).count();
    let within30 = all.iter().filter(|r| r.within30()).count();
    let within90 = all.iter().filter(|r| r.within90()).count();
    let matching: Vec<CertRow> = all.into_iter().filter(|r| filter.matches(r)).collect();
    let pages = matching.len().div_ceil(PER_PAGE).max(1);
    let page = filter.page.unwrap_or(1).clamp(1, pages);
    let shown_from = (page - 1) * PER_PAGE;
    let rows = matching
        .into_iter()
        .skip(shown_from)
        .take(PER_PAGE)
        .collect();
    let show_options = [
        ("", "All certificates"),
        ("expired", "Expired"),
        ("30", "Expired or expiring within 30 days"),
        ("90", "Expired or expiring within 90 days"),
        ("disabled", "Disabled"),
    ]
    .into_iter()
    .map(|(value, label)| ShowOption {
        value,
        label,
        selected: filter.show == value,
    })
    .collect();
    Ok(render(&ListPage {
        prev_url: (page > 1).then(|| filter.page_url(page - 1)),
        next_url: (page < pages).then(|| filter.page_url(page + 1)),
        shell,
        vault,
        rows,
        total,
        expired,
        within30,
        within90,
        filter,
        show_options,
        page,
        pages,
        shown_from,
    })
    .into_response())
}

/// What the detail page shows about a certificate version.
pub struct CertView {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sans: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub self_signed: bool,
}

impl CertView {
    pub fn from_bundle(b: &CertBundle) -> Option<Self> {
        let s = x509::summarise(&b.der()?)?;
        Some(Self {
            valid_from: dates::format_datetime(s.not_before),
            valid_to: dates::format_datetime(s.not_after),
            subject: s.subject,
            issuer: s.issuer,
            serial: s.serial,
            sans: s.sans,
            self_signed: s.self_signed,
        })
    }
}

pub struct PolicyView {
    pub issuer: String,
    pub key: String,
    pub exportable: bool,
    pub renewal: String,
    pub content_type: String,
    pub validity: String,
}

impl PolicyView {
    pub fn from_policy(p: &Policy) -> Self {
        let key = p
            .key_props
            .as_ref()
            .map(|k| {
                let kty = k.kty.clone().unwrap_or_else(|| "RSA".into());
                match (k.key_size, &k.crv) {
                    (Some(size), _) => format!("{kty} {size}"),
                    (_, Some(crv)) => format!("{kty} {crv}"),
                    _ => kty,
                }
            })
            .unwrap_or_else(|| "Not set".into());
        Self {
            issuer: match p.issuer_name() {
                "Self" => "Self-signed".into(),
                "Unknown" => "Not managed by Key Vault (imported)".into(),
                other => other.into(),
            },
            key,
            exportable: p.exportable(),
            renewal: p.renewal(),
            content_type: if p.content_type() == "application/x-pem-file" {
                "PEM".into()
            } else {
                "PFX (PKCS #12)".into()
            },
            validity: p
                .x509_props
                .as_ref()
                .and_then(|x| x.validity_months)
                .map(|m| format!("{m} months"))
                .unwrap_or_default(),
        }
    }
}

pub struct PendingView {
    pub status: String,
    pub details: String,
    pub failed: bool,
    /// Self-signed and still being made: usually done in seconds.
    pub creating: bool,
}

impl PendingView {
    pub fn from_op(op: &Operation) -> Option<Self> {
        let status = op.status.clone().unwrap_or_default();
        if status.eq_ignore_ascii_case("completed") {
            return None;
        }
        let failed = op.error.is_some() || status.eq_ignore_ascii_case("failed");
        let self_signed = op
            .issuer
            .as_ref()
            .and_then(|i| i.name.as_deref())
            .is_some_and(|n| n.eq_ignore_ascii_case("Self"));
        let in_progress = status.eq_ignore_ascii_case("inProgress");
        Some(Self {
            creating: self_signed && in_progress && !failed,
            status: match status.to_ascii_lowercase().as_str() {
                "inprogress" if self_signed => "Being created".into(),
                "inprogress" => "Waiting for the issuer".into(),
                "failed" => "Failed".into(),
                "cancelled" => "Cancelled".into(),
                _ => status,
            },
            details: op
                .error
                .as_ref()
                .and_then(|e| e.code.clone())
                .map(|c| format!("The issuer returned {c}."))
                .or_else(|| op.status_details.clone())
                .unwrap_or_default(),
            failed,
        })
    }
}

#[derive(Template)]
#[template(path = "certs/detail.html")]
struct DetailPage {
    shell: Shell,
    vault: String,
    row: CertRow,
    cert: Option<CertView>,
    policy: Option<PolicyView>,
    pending: Option<PendingView>,
    /// Set when the pending request couldn't be checked.
    pending_note: Option<String>,
    versions: Vec<CertRow>,
    /// Set when the versions couldn't be read.
    versions_note: Option<String>,
}

pub async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let api = api(&state, &session, &vault);
    let path = format!("/certificates/{name}");
    let (bundle, versions, pending) = tokio::join!(
        api.get_cert(&name, None),
        api.versions(&name),
        api.pending(&name)
    );
    let bundle = match bundle {
        Ok(b) => b,
        Err(err) => return Err(azure_problem(shell, &err, Need::ReadCertificates, &path)),
    };
    let now = now_ts();
    // Each section says why it's empty rather than pretending there's
    // nothing there.
    let role = Need::ReadCertificates.role();
    let (versions, versions_note) = match versions {
        Ok(v) => (v.iter().map(|v| CertRow::from_item(v, now)).collect(), None),
        Err(e) => {
            tracing::warn!(vault = %vault, certificate = %name, error = %e, "couldn't read certificate versions");
            (
                Vec::new(),
                Some(section_note(&e, "this certificate's versions", role)),
            )
        }
    };
    let (pending, pending_note) = match pending {
        Ok(op) => (op.as_ref().and_then(PendingView::from_op), None),
        Err(e) => {
            tracing::warn!(vault = %vault, certificate = %name, error = %e, "couldn't read pending certificate request");
            (
                None,
                Some(section_note(&e, "whether a request is pending", role)),
            )
        }
    };
    let item = CertItem {
        id: bundle.id.clone(),
        attributes: bundle.attributes.clone(),
        tags: bundle.tags.clone(),
        x5t: bundle.x5t.clone(),
    };
    Ok(render(&DetailPage {
        row: CertRow::from_item(&item, now),
        cert: CertView::from_bundle(&bundle),
        policy: bundle.policy.as_ref().map(PolicyView::from_policy),
        pending,
        pending_note,
        versions,
        versions_note,
        shell,
        vault,
    })
    .into_response())
}

/// Enable or disable the current version, like the secrets page does.
pub async fn toggle(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(name): Path<String>,
    Form(f): Form<ToggleForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let Some(enable) = f.enable() else {
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    let certs = api(&state, &session, &vault);
    let path = format!("/certificates/{name}");
    let bundle = match certs.get_cert(&name, None).await {
        Ok(b) => b,
        Err(e) => return Err(azure_problem(shell, &e, Need::ReadCertificates, &path)),
    };
    match certs.set_enabled(&name, bundle.version(), enable).await {
        Ok(_) => {
            tracing::info!(subject = %session.0.user.subject, vault = %vault, certificate = %name, enabled = enable, "certificate enabled changed");
            let done = if enable { "Enabled" } else { "Disabled" };
            Ok(redirect_with(&state, &path, format!("{done} {name}.")))
        }
        Err(e) => Err(azure_problem(shell, &e, Need::ManageCertificates, &path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_bands() {
        let now = 1_000_000_000;
        assert_eq!(cert_expiry(None, now), CertExpiry::None);
        assert_eq!(cert_expiry(Some(now), now), CertExpiry::Expired);
        assert_eq!(cert_expiry(Some(now + 10 * DAY), now), CertExpiry::Within30);
        assert_eq!(cert_expiry(Some(now + 60 * DAY), now), CertExpiry::Within90);
        assert_eq!(cert_expiry(Some(now + 200 * DAY), now), CertExpiry::Ok);
    }

    #[test]
    fn reserved_names_are_refused() {
        for n in ["new", "deleted", "upload", "Upload"] {
            assert!(new_name_problem(n).is_some(), "{n}");
        }
        assert!(new_name_problem("web-tls").is_none());
        assert!(new_name_problem("web tls").is_some());
        assert!(new_name_problem("").unwrap().contains("certificate"));
    }

    #[test]
    fn pending_wording_depends_on_the_issuer() {
        let op = |status: &str, issuer: &str| Operation {
            status: Some(status.into()),
            issuer: Some(crate::azure::certs::IssuerProps {
                name: Some(issuer.into()),
            }),
            ..Operation::default()
        };
        let p = PendingView::from_op(&op("inProgress", "Self")).unwrap();
        assert_eq!(p.status, "Being created");
        assert!(p.creating);
        let p = PendingView::from_op(&op("inProgress", "DigiCert-OV")).unwrap();
        assert_eq!(p.status, "Waiting for the issuer");
        assert!(!p.creating);
        assert!(PendingView::from_op(&op("completed", "Self")).is_none());
    }
}
