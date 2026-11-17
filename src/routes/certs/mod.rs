//! Certificate pages: list, detail, versions and downloads.

pub(super) mod create;
pub(super) mod delete;
pub(super) mod download;
pub(super) mod renewal;
pub(super) mod upload;

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
use crate::routes::hints::Action;
use crate::routes::keys::section_note;
use crate::routes::lifecycle::{Kind, redirect_with};
use crate::routes::paging::{Pager, paginate};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name, vault_path};
use crate::x509;

/// Name checks for a new certificate.
pub(super) fn new_name_problem(name: &str) -> Option<String> {
    crate::routes::forms::name_problem(Kind::Certificate, name)
}

const DAY: i64 = 86_400;

/// How close a certificate is to expiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CertExpiry {
    None,
    Ok,
    /// Under 90 days.
    Within90,
    /// Under 30 days.
    Within30,
    Expired,
}

pub(super) fn cert_expiry(expires: Option<i64>, now: i64) -> CertExpiry {
    match expires {
        None => CertExpiry::None,
        Some(e) if e <= now => CertExpiry::Expired,
        Some(e) if e - now <= 30 * DAY => CertExpiry::Within30,
        Some(e) if e - now <= 90 * DAY => CertExpiry::Within90,
        Some(_) => CertExpiry::Ok,
    }
}

pub(super) struct CertRow {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub thumbprint: String,
    pub expires: String,
    pub expires_note: String,
    pub expiry: CertExpiry,
    pub created: String,
    pub created_at: Option<i64>,
    /// The "Not changed in over ..." badge, or empty. Set by `mark_stale`.
    pub stale: String,
    /// Tags, without the description, owner and notify.
    pub tags: Vec<(String, String)>,
    /// The note in the `description` tag, or empty.
    pub description: String,
    /// The `owner` and `notify` tags.
    pub owners: crate::owner::OfItem,
    /// The tags the tag filter and search box match: every tag but the
    /// description, `owner` and `notify` included.
    pub filter_tags: Vec<(String, String)>,
    pub filter_text: String,
}

impl CertRow {
    /// Set the badge for a value unchanged in more than `after_days`.
    pub(super) fn mark_stale(mut self, after_days: u32, now: i64) -> Self {
        self.stale = crate::age::stale_badge(self.created_at, false, after_days, now);
        self
    }

    pub(super) fn from_item(item: &CertItem, now: i64) -> Self {
        let a = &item.attributes;
        let tags: Vec<(String, String)> = crate::owner::without_fields(item.tags())
            .into_iter()
            .collect();
        let owners = crate::owner::OfItem::of(item.tags());
        let description = crate::description::of(item.tags())
            .unwrap_or_default()
            .to_owned();
        let filter_tags = crate::routes::tag_rows::filter_tags(item.tags());
        let filter_text =
            crate::routes::tag_rows::filter_text(item.name(), &filter_tags, &description);
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
            created_at: a.created,
            stale: String::new(),
            tags,
            description,
            owners,
            filter_tags,
            filter_text,
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        self.expiry == CertExpiry::Expired
    }
    pub(super) fn within30(&self) -> bool {
        self.expiry == CertExpiry::Within30
    }
    pub(super) fn within90(&self) -> bool {
        self.expiry == CertExpiry::Within90
    }
    pub(super) fn short_version(&self) -> String {
        self.version.chars().take(8).collect()
    }
}

pub(super) fn current_vault(
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
) -> Result<(String, Shell), Halt> {
    vault_ctx::path_vault(session, shell, Section::Certificates, vault)
}

pub(super) fn api<'a>(
    state: &'a AppState,
    session: &'a CurrentSession,
    vault: &str,
) -> CertsApi<'a> {
    CertsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct CertFilter {
    #[serde(default)]
    pub q: String,
    /// `name` or `name=value`.
    #[serde(default)]
    pub tag: String,
    /// `expired`, `30`, `90` or `disabled`.
    #[serde(default)]
    pub show: String,
    /// "Owned by me": any value turns it on.
    #[serde(default)]
    pub mine: String,
    #[serde(default)]
    pub page: Option<usize>,
}

impl CertFilter {
    pub(super) fn is_empty(&self) -> bool {
        self.q.trim().is_empty()
            && self.tag.trim().is_empty()
            && self.show.is_empty()
            && !self.mine()
    }

    pub(super) fn mine(&self) -> bool {
        crate::owner::mine_on(&self.mine)
    }

    pub(super) fn matches(&self, r: &CertRow, upn: Option<&str>) -> bool {
        if self.mine() && !r.owners.names(upn) {
            return false;
        }
        let q = self.q.trim().to_lowercase();
        if !q.is_empty() && !r.filter_text.contains(&q) && !r.thumbprint.to_lowercase().contains(&q)
        {
            return false;
        }
        if !crate::routes::tag_rows::matches_filter(&self.tag, &r.filter_tags) {
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

    fn page_url(&self, vault: &str, page: usize) -> String {
        let enc = crate::auth::return_to::encode;
        vault_path(
            vault,
            &format!(
                "/certificates?q={}&tag={}&show={}{}&page={page}",
                enc(&self.q),
                enc(&self.tag),
                enc(&self.show),
                if self.mine() { "&mine=1" } else { "" }
            ),
        )
    }
}

pub(super) struct ShowOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "certs/list.html")]
struct ListPage {
    hints: crate::routes::hints::Hints,
    shell: Shell,
    vault: String,
    rows: Vec<CertRow>,
    total: usize,
    expired: usize,
    within30: usize,
    within90: usize,
    filter: CertFilter,
    show_options: Vec<ShowOption>,
    pager: Pager,
    /// Suggestions for the tag filter, from this vault's certificates.
    tag_options: Vec<String>,
    /// The same, for the bulk change's tag name and value.
    tag_suggest: crate::routes::tag_rows::Suggestions,
}

pub(super) async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Query(filter): Query<CertFilter>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let list_api = api(&state, &session, &vault);
    let (items, hints) = tokio::join!(
        list_api.list(),
        crate::routes::hints::for_vault(&state, &session, &vault),
    );
    let items = match items {
        Ok(i) => i,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ReadCertificates,
                &vault_path(&vault, "/certificates"),
            ));
        }
    };
    let now = now_ts();
    let after = state.config.stale_after_days;
    let all: Vec<CertRow> = items
        .iter()
        .map(|i| CertRow::from_item(i, now).mark_stale(after, now))
        .collect();
    let total = all.len();
    let expired = all.iter().filter(|r| r.is_expired()).count();
    let within30 = all.iter().filter(|r| r.within30()).count();
    let within90 = all.iter().filter(|r| r.within90()).count();
    let tag_suggest = crate::routes::tag_rows::Suggestions::from_sets(
        // The owner is suggested in the bulk change's owner field.
        all.iter().map(|r| {
            r.tags
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .chain(std::iter::once((
                    crate::owner::OWNER_TAG,
                    r.owners.owner.as_str(),
                )))
        }),
    );
    let tag_options = tag_suggest.filter_options();
    let upn = session.0.user.username.clone();
    let matching: Vec<CertRow> = all
        .into_iter()
        .filter(|r| filter.matches(r, upn.as_deref()))
        .collect();
    let (rows, pager) = paginate(matching, filter.page, "certificates", |p| {
        filter.page_url(&vault, p)
    });
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
        hints,
        pager,
        shell,
        vault,
        rows,
        total,
        expired,
        within30,
        within90,
        filter,
        show_options,
        tag_options,
        tag_suggest,
    })
    .into_response())
}

/// What the detail page shows about a certificate version.
pub(super) struct CertView {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sans: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub self_signed: bool,
}

impl CertView {
    pub(super) fn from_bundle(b: &CertBundle) -> Option<Self> {
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

pub(super) struct PolicyView {
    pub issuer: String,
    pub key: String,
    pub exportable: bool,
    pub renewal: String,
    pub content_type: String,
    pub validity: String,
}

impl PolicyView {
    pub(super) fn from_policy(p: &Policy) -> Self {
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

pub(super) struct PendingView {
    pub status: String,
    pub details: String,
    pub failed: bool,
    /// Self-signed and still being made: usually done in seconds.
    pub creating: bool,
}

impl PendingView {
    pub(super) fn from_op(op: &Operation) -> Option<Self> {
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
    used_by: crate::routes::used_by::UsedBy,
    access: crate::routes::access::Access,
    hints: crate::routes::hints::Hints,
}

pub(super) async fn detail(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    uri: axum::http::Uri,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let api = api(&state, &session, &vault);
    let path = vault_path(&vault, &format!("/certificates/{name}"));
    let (bundle, versions, pending, used_by, access, hints) = tokio::join!(
        api.get_cert(&name, None),
        api.versions(&name),
        api.pending(&name),
        crate::routes::used_by::for_item(&state, &session, &vault, Kind::Certificate, &name),
        crate::routes::access::for_item(&state, &session, &vault, Kind::Certificate, &name),
        crate::routes::hints::for_item(&state, &session, &vault, Kind::Certificate, &name),
    );
    let bundle = match bundle {
        Ok(b) => b,
        Err(err) => {
            if let Some(res) =
                crate::routes::moved::missing_item(&vault, Kind::Certificate, &name, &err, &uri)
            {
                return Ok(res);
            }
            return Err(azure_problem(shell, &err, Need::ReadCertificates, &path));
        }
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
        row: CertRow::from_item(&item, now).mark_stale(state.config.stale_after_days, now),
        cert: CertView::from_bundle(&bundle),
        policy: bundle.policy.as_ref().map(PolicyView::from_policy),
        pending,
        pending_note,
        versions,
        versions_note,
        used_by,
        shell,
        vault,
        access,
        hints,
    })
    .into_response())
}

/// Enable or disable the current version, like the secrets page does.
/// Ask before disabling. Reads the certificate first, so a missing one
/// gets the not-found page rather than a confirmation.
pub(super) async fn disable_form(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let path = vault_path(&vault, &format!("/certificates/{name}"));
    let certs = api(&state, &session, &vault);
    let (got, used_by) = tokio::join!(
        certs.get_cert(&name, None),
        crate::routes::used_by::for_item(&state, &session, &vault, Kind::Certificate, &name),
    );
    if let Err(e) = got {
        return Err(azure_problem(shell, &e, Need::ReadCertificates, &path));
    }
    Ok(crate::routes::lifecycle::disable_page(
        shell,
        &vault,
        Kind::Certificate,
        &name,
        used_by,
    ))
}

pub(super) async fn toggle(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<ToggleForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    let (name, shell) = checked_name(&name, shell)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let Some(enable) = f.enable() else {
        return Err(PageError::new(shell, Problem::not_found()).into());
    };
    let certs = api(&state, &session, &vault);
    let path = vault_path(&vault, &format!("/certificates/{name}"));
    let bundle = match certs.get_cert(&name, None).await {
        Ok(b) => b,
        Err(e) => return Err(azure_problem(shell, &e, Need::ReadCertificates, &path)),
    };
    match certs.set_enabled(&name, bundle.version(), enable).await {
        Ok(_) => {
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
