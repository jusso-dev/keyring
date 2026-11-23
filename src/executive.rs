//! Organisation-wide security posture metrics, SVG chart geometry and
//! continuous white-label executive client reports.
//!
//! Pure functions over metadata already read from Resource Graph and Key Vault
//! list calls: no secret values, no private keys and no database state.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::azure::fanout::Skipped;
use crate::azure::vaults::Vault;
use crate::config::Thresholds;
use crate::dates;
use crate::defender::{self, Defender, PlanState, SeverityCounts};
use crate::environments::{self, EnvLabel};
use crate::expiry::{Item, ItemType, csv_field};
use crate::owner;

const DAY: i64 = 86_400;

/// Maximum characters for white-label report text fields.
const MAX_BRAND_TEXT: usize = 100;

/// Sanitise user-supplied report metadata (client name, title, prepared by,
/// period): strip control and bidirectional formatting characters, collapse
/// whitespace and enforce a hard character cap.
pub fn clean_brand_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut prev_space = true;
    for ch in raw.chars() {
        let forbidden = ch.is_control()
            || matches!(
                ch,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
            );
        if forbidden {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
        if out.chars().count() >= max_chars {
            break;
        }
    }
    out.trim().to_owned()
}

/// Safe lowercase ASCII filename slug for white-label export downloads.
pub fn safe_filename_slug(client: &str, white_label: bool) -> String {
    let mut slug = String::new();
    let mut prev_dash = true;
    for ch in client.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && slug.len() < 48 {
            slug.push('-');
            prev_dash = true;
        }
        if slug.len() >= 48 {
            break;
        }
    }
    let slug = slug.trim_matches('-');
    if !slug.is_empty() {
        slug.to_owned()
    } else if white_label {
        "client".to_owned()
    } else {
        "keyring".to_owned()
    }
}

/// Fixed palette presets for white-label executive reports. Using an enum
/// prevents any untrusted CSS value from reaching the exported report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportTheme {
    #[default]
    Cobalt,
    Navy,
    Emerald,
    Slate,
    Burgundy,
    Teal,
}

impl ReportTheme {
    pub const ALL: [ReportTheme; 6] = [
        ReportTheme::Cobalt,
        ReportTheme::Navy,
        ReportTheme::Emerald,
        ReportTheme::Slate,
        ReportTheme::Burgundy,
        ReportTheme::Teal,
    ];

    pub fn from_slug(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "navy" => Self::Navy,
            "emerald" => Self::Emerald,
            "slate" => Self::Slate,
            "burgundy" => Self::Burgundy,
            "teal" => Self::Teal,
            _ => Self::Cobalt,
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Cobalt => "cobalt",
            Self::Navy => "navy",
            Self::Emerald => "emerald",
            Self::Slate => "slate",
            Self::Burgundy => "burgundy",
            Self::Teal => "teal",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cobalt => "Enterprise Cobalt",
            Self::Navy => "Midnight Navy",
            Self::Emerald => "Security Emerald",
            Self::Slate => "Executive Slate",
            Self::Burgundy => "Advisory Burgundy",
            Self::Teal => "Platform Teal",
        }
    }

    pub fn primary_hex(self) -> &'static str {
        match self {
            Self::Cobalt => "#0e5ae5",
            Self::Navy => "#162d59",
            Self::Emerald => "#0f764a",
            Self::Slate => "#334155",
            Self::Burgundy => "#881337",
            Self::Teal => "#0f6e7d",
        }
    }

    pub fn dark_hex(self) -> &'static str {
        match self {
            Self::Cobalt => "#0b1a36",
            Self::Navy => "#0a1529",
            Self::Emerald => "#09261b",
            Self::Slate => "#141c29",
            Self::Burgundy => "#2c0a16",
            Self::Teal => "#0a242c",
        }
    }

    pub fn tint_hex(self) -> &'static str {
        match self {
            Self::Cobalt => "#eef4ff",
            Self::Navy => "#eef2fa",
            Self::Emerald => "#ecfdf3",
            Self::Slate => "#f1f5f9",
            Self::Burgundy => "#fdf2f4",
            Self::Teal => "#ecfeff",
        }
    }
}

/// Scope filter for continuous executive reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportScope {
    #[default]
    All,
    Production,
    NonProduction,
}

impl ReportScope {
    pub fn from_slug(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "prod" | "production" => Self::Production,
            "nonprod" | "non-prod" | "nonproduction" => Self::NonProduction,
            _ => Self::All,
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Production => "prod",
            Self::NonProduction => "nonprod",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All visible vaults",
            Self::Production => "Production vaults only",
            Self::NonProduction => "Non-production vaults only",
        }
    }

    pub fn matches_vault(self, v: &Vault) -> bool {
        let env = EnvLabel::of(v);
        match self {
            Self::All => true,
            Self::Production => env.is_production(),
            Self::NonProduction => !env.is_production(),
        }
    }
}

/// Customisable options for continuous white-label executive client reports.
#[derive(Debug, Clone, Serialize)]
pub struct ReportOptions {
    pub client_name: String,
    pub report_title: String,
    pub prepared_by: String,
    pub period: String,
    pub theme: ReportTheme,
    pub scope: ReportScope,
    pub white_label: bool,
    pub include_charts: bool,
    pub include_vaults: bool,
    pub include_environments: bool,
    pub include_actions: bool,
}

impl ReportOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn sanitized(
        client_name: &str,
        report_title: &str,
        prepared_by: &str,
        period: &str,
        theme: &str,
        scope: &str,
        white_label: bool,
        include_charts: bool,
        include_vaults: bool,
        include_environments: bool,
        include_actions: bool,
        default_period: &str,
    ) -> Self {
        let title = clean_brand_text(report_title, 120);
        let period_clean = clean_brand_text(period, 60);
        Self {
            client_name: clean_brand_text(client_name, MAX_BRAND_TEXT),
            report_title: if title.is_empty() {
                "Privileged Secrets & Key Vault Executive Report".to_owned()
            } else {
                title
            },
            prepared_by: clean_brand_text(prepared_by, MAX_BRAND_TEXT),
            period: if period_clean.is_empty() {
                default_period.to_owned()
            } else {
                period_clean
            },
            theme: ReportTheme::from_slug(theme),
            scope: ReportScope::from_slug(scope),
            white_label,
            include_charts,
            include_vaults,
            include_environments,
            include_actions,
        }
    }

    /// URL query string for bookmarkable continuous reporting links.
    pub fn query_string(&self, format: Option<&str>) -> String {
        let enc = crate::auth::return_to::encode;
        let mut qs = format!(
            "client={}&title={}&prepared_by={}&period={}&theme={}&scope={}&white_label={}&charts={}&vaults={}&envs={}&actions={}",
            enc(&self.client_name),
            enc(&self.report_title),
            enc(&self.prepared_by),
            enc(&self.period),
            self.theme.slug(),
            self.scope.slug(),
            if self.white_label { "1" } else { "0" },
            if self.include_charts { "1" } else { "0" },
            if self.include_vaults { "1" } else { "0" },
            if self.include_environments { "1" } else { "0" },
            if self.include_actions { "1" } else { "0" },
        );
        if let Some(fmt) = format {
            qs.push_str("&format=");
            qs.push_str(fmt);
        }
        qs
    }

    pub fn display_client(&self) -> &str {
        if self.client_name.is_empty() {
            "Organisation-Wide Key Vault Estate"
        } else {
            &self.client_name
        }
    }

    pub fn display_issuer(&self) -> &str {
        if !self.prepared_by.is_empty() {
            &self.prepared_by
        } else if self.white_label {
            "Privileged Access Governance"
        } else {
            "Keyring Privileged Access Management"
        }
    }
}

/// One segment of the credential health SVG donut chart.
#[derive(Debug, Clone, Serialize)]
pub struct DonutSlice {
    pub label: String,
    pub count: usize,
    pub pct: u32,
    pub dash_array: String,
    pub dash_offset: String,
    pub css_class: &'static str,
    pub hex: &'static str,
}

/// One bar in the security posture horizontal bar chart.
#[derive(Debug, Clone, Serialize)]
pub struct ControlBar {
    pub label: String,
    pub passed: usize,
    pub total: usize,
    pub pct: u32,
    pub bar_width: u32,
    pub css_class: &'static str,
    pub hex: &'static str,
}

/// One bucket in the expiry horizon vertical SVG bar chart.
#[derive(Debug, Clone, Serialize)]
pub struct HorizonBar {
    pub label: &'static str,
    pub short_label: &'static str,
    pub count: usize,
    pub x: u32,
    pub y: u32,
    pub height: u32,
    pub label_x: u32,
    pub count_y: u32,
    pub css_class: &'static str,
    pub hex: &'static str,
    pub href: &'static str,
}

/// Distribution across environments (dev, test, staging, prod, unlabelled).
#[derive(Debug, Clone, Serialize)]
pub struct EnvDistribution {
    pub label: String,
    pub is_prod: bool,
    pub vaults: usize,
    pub secrets: usize,
    pub certs: usize,
    pub keys: usize,
    pub total_items: usize,
    pub bar_width: u32,
}

/// Per-vault risk & posture summary row for the Home leaderboard & exec report.
#[derive(Debug, Clone, Serialize)]
pub struct VaultRiskRow {
    pub name: String,
    pub env_label: String,
    pub is_prod: bool,
    pub subscription: String,
    pub location: String,
    pub total_items: usize,
    pub expired: usize,
    pub expiring_30: usize,
    pub stale: usize,
    pub no_expiry: usize,
    pub rbac: bool,
    pub soft_delete: bool,
    pub purge_protection: bool,
    pub network_restricted: bool,
    pub private_endpoint: bool,
    pub has_owners: bool,
    /// Enabled items expiring within the warning window, not yet expired.
    pub expiring_warn: usize,
    /// Open Defender for Key Vault alerts on it, or `None` when they
    /// couldn't be read (see `defender_unread`). Never 0 for "not read".
    pub defender_open: Option<usize>,
    /// Why its Defender alerts couldn't be read, when they couldn't.
    pub defender_unread: Option<String>,
    pub read_error: Option<String>,
    pub risk_score: u32,
    pub risk_label: &'static str,
    pub risk_badge: &'static str,
    pub issues_summary: String,
}

/// Prioritised executive remediation item.
#[derive(Debug, Clone, Serialize)]
pub struct ActionItem {
    pub priority: &'static str,
    pub badge_class: &'static str,
    pub title: String,
    pub detail: String,
    pub href: &'static str,
}

/// Defender for Key Vault across the vaults in the snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct DefenderSummary {
    /// Open alerts on the snapshot's vaults, by severity.
    pub open: SeverityCounts,
    /// Vaults whose subscription has the plan on, off, or couldn't be told.
    pub vaults_on: usize,
    pub vaults_off: usize,
    pub vaults_unknown: usize,
    /// Why alerts couldn't be read, when they couldn't.
    pub alerts_error: Option<String>,
    /// The most urgent open alerts, for Home.
    pub top: Vec<AlertBrief>,
}

/// One alert, as Home and the report show it. Text is already cleaned.
#[derive(Debug, Clone, Serialize)]
pub struct AlertBrief {
    pub title: String,
    pub severity: &'static str,
    #[serde(skip)]
    pub severity_css: &'static str,
    pub vault: String,
    pub time: String,
    pub portal_url: Option<String>,
}

/// Summary of one discovered environment group (`dev -> test -> prod`).
#[derive(Debug, Clone, Serialize)]
pub struct EnvGroupSummary {
    pub name: String,
    pub vaults: Vec<String>,
    pub total_items: usize,
    pub expired_or_soon: usize,
}

/// Complete organisation-wide snapshot computed purely from Azure metadata.
#[derive(Debug, Clone, Serialize)]
pub struct OrgSnapshot {
    pub total_vaults: usize,
    pub read_vaults: usize,
    pub skipped_vaults: usize,
    pub capped: bool,
    pub subscriptions: usize,
    pub prod_vaults: usize,
    pub non_prod_vaults: usize,
    pub env_groups: Vec<EnvGroupSummary>,

    pub total_items: usize,
    pub secrets_count: usize,
    pub certs_count: usize,
    pub keys_count: usize,

    pub active_healthy: usize,
    pub expired: usize,
    pub expiring_30: usize,
    pub expiring_90: usize,
    pub expiring_180: usize,
    pub expiring_later: usize,
    pub no_expiry: usize,
    pub disabled: usize,
    pub stale: usize,
    pub unowned_items: usize,

    pub posture_score: u32,
    pub posture_label: &'static str,
    pub posture_badge: &'static str,
    pub posture_dash: String,

    pub health_donut: Vec<DonutSlice>,
    pub controls: Vec<ControlBar>,
    pub horizon: Vec<HorizonBar>,
    pub env_distribution: Vec<EnvDistribution>,
    pub vault_rows: Vec<VaultRiskRow>,
    pub top_risks: Vec<VaultRiskRow>,
    pub actions: Vec<ActionItem>,
    pub stale_after_days: u32,
    /// `KEYRING_EXPIRY_WARN_DAYS`.
    pub expiry_warn_days: u32,
    /// Enabled items expiring within `expiry_warn_days`, not yet expired.
    pub expiring_warn: usize,
    pub defender: DefenderSummary,
}

fn is_network_restricted(v: &Vault) -> bool {
    let public_off = v
        .health
        .public_access
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("Disabled"));
    let default_deny = v
        .health
        .default_action
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("Deny"));
    public_off || default_deny
}

fn has_private_endpoint(v: &Vault) -> bool {
    v.health
        .private_endpoints
        .iter()
        .any(|s| s.eq_ignore_ascii_case("Approved"))
}

fn pct(part: usize, total: usize) -> u32 {
    if total == 0 {
        return 0;
    }
    ((part as f64 / total as f64) * 100.0).round() as u32
}

fn control_bar(label: &str, passed: usize, total: usize) -> ControlBar {
    let p = pct(passed, total);
    let bar_width = ((p as f64 / 100.0) * 220.0).round() as u32;
    let (css_class, hex) = if total == 0 {
        ("bar-muted", "#94a3b8")
    } else if p >= 85 {
        ("bar-ok", "#117a49")
    } else if p >= 55 {
        ("bar-warn", "#b45309")
    } else {
        ("bar-danger", "#c81e32")
    };
    ControlBar {
        label: label.to_owned(),
        passed,
        total,
        pct: p,
        bar_width,
        css_class,
        hex,
    }
}

impl OrgSnapshot {
    pub(crate) fn build(
        vaults: &[Vault],
        items: &[Item],
        skipped: &[Skipped],
        capped: bool,
        thresholds: Thresholds,
        defender: &Defender,
        now: i64,
    ) -> Self {
        let stale_after_days = thresholds.stale_after_days;
        let expiry_warn_days = thresholds.expiry_warn_days;
        let warn_secs = i64::from(expiry_warn_days) * DAY;
        let in_snapshot: BTreeSet<String> =
            vaults.iter().map(|v| v.name.to_ascii_lowercase()).collect();
        let skipped_map: BTreeMap<&str, &str> = skipped
            .iter()
            .map(|s| (s.vault.as_str(), s.reason.as_str()))
            .collect();

        let total_vaults = vaults.len();
        let skipped_vaults = vaults
            .iter()
            .filter(|v| skipped_map.contains_key(v.name.as_str()))
            .count();
        let read_vaults = total_vaults.saturating_sub(skipped_vaults);

        let subs: BTreeSet<&str> = vaults.iter().map(|v| v.subscription_id.as_str()).collect();
        let subscriptions = subs.len();

        let mut prod_vaults = 0usize;
        let mut non_prod_vaults = 0usize;
        for v in vaults {
            if EnvLabel::of(v).is_production() {
                prod_vaults += 1;
            } else {
                non_prod_vaults += 1;
            }
        }

        // Index non-managed items by vault.
        let mut by_vault: BTreeMap<&str, Vec<&Item>> = BTreeMap::new();
        let mut secrets_count = 0usize;
        let mut certs_count = 0usize;
        let mut keys_count = 0usize;

        let mut active_healthy = 0usize;
        let mut expired = 0usize;
        let mut expiring_30 = 0usize;
        let mut expiring_90 = 0usize;
        let mut expiring_180 = 0usize;
        let mut expiring_later = 0usize;
        let mut no_expiry = 0usize;
        let mut disabled = 0usize;
        let mut stale = 0usize;
        let mut unowned_items = 0usize;
        let mut enabled_items = 0usize;
        let mut enabled_with_valid_expiry = 0usize;
        let mut enabled_fresh = 0usize;
        let mut expiring_warn = 0usize;

        let stale_secs = i64::from(stale_after_days) * DAY;

        for item in items.iter().filter(|i| !i.managed) {
            by_vault.entry(item.vault.as_str()).or_default().push(item);
            match item.kind {
                ItemType::Secret => secrets_count += 1,
                ItemType::Certificate => certs_count += 1,
                ItemType::Key => keys_count += 1,
            }
            let has_owner = item
                .tags
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("owner") && !v.trim().is_empty());
            if !has_owner {
                unowned_items += 1;
            }

            if !item.enabled {
                disabled += 1;
                continue;
            }
            enabled_items += 1;

            let is_stale = item.created.is_some_and(|c| now - c > stale_secs);
            if is_stale {
                stale += 1;
            } else {
                enabled_fresh += 1;
            }

            if item
                .expires
                .is_some_and(|e| e > now && e - now <= warn_secs)
            {
                expiring_warn += 1;
            }
            match item.expires {
                None => {
                    no_expiry += 1;
                }
                Some(exp) if exp <= now => {
                    expired += 1;
                }
                Some(exp) if exp - now <= 30 * DAY => {
                    expiring_30 += 1;
                    enabled_with_valid_expiry += 1;
                }
                Some(exp) if exp - now <= 90 * DAY => {
                    expiring_90 += 1;
                    enabled_with_valid_expiry += 1;
                }
                Some(exp) if exp - now <= 180 * DAY => {
                    expiring_180 += 1;
                    enabled_with_valid_expiry += 1;
                    active_healthy += 1;
                }
                Some(_) => {
                    expiring_later += 1;
                    enabled_with_valid_expiry += 1;
                    active_healthy += 1;
                }
            }
        }
        let total_items = secrets_count + certs_count + keys_count;

        // Vault control pass counts
        let mut pass_rbac = 0usize;
        let mut pass_soft_delete = 0usize;
        let mut pass_purge = 0usize;
        let mut pass_network = 0usize;
        let mut pass_pe = 0usize;
        let mut pass_owners = 0usize;
        let mut pass_defender = 0usize;
        let mut defender_known = 0usize;
        let (mut vaults_on, mut vaults_off, mut vaults_unknown) = (0usize, 0usize, 0usize);

        type EnvBucketKey = (u8, String, bool);
        type EnvBucketCounts = (usize, usize, usize, usize);
        let mut env_buckets: BTreeMap<EnvBucketKey, EnvBucketCounts> = BTreeMap::new();
        let mut vault_rows = Vec::with_capacity(vaults.len());

        for v in vaults {
            let env = EnvLabel::of(v);
            let env_name = if env.is_empty() {
                "unlabelled".to_owned()
            } else {
                env.name.clone()
            };
            let is_prod = env.is_production();

            let soft_del = v.health.soft_delete.unwrap_or(v.soft_delete);
            let net_ok = is_network_restricted(v);
            let pe_ok = has_private_endpoint(v);
            let owners_ok = !owner::vault_owners(&v.tags).is_empty();

            if v.rbac {
                pass_rbac += 1;
            }
            if soft_del {
                pass_soft_delete += 1;
            }
            if v.purge_protection {
                pass_purge += 1;
            }
            if net_ok {
                pass_network += 1;
            }
            if pe_ok {
                pass_pe += 1;
            }
            if owners_ok {
                pass_owners += 1;
            }
            let plan = defender.plan_for(&v.subscription_id);
            match plan {
                PlanState::On => {
                    vaults_on += 1;
                    pass_defender += 1;
                    defender_known += 1;
                }
                PlanState::Off => {
                    vaults_off += 1;
                    defender_known += 1;
                }
                PlanState::Unknown(_) => vaults_unknown += 1,
            }
            let v_open = defender.for_vault(&v.name, &v.subscription_id).open;
            let v_alerts = v_open.clone().unwrap_or_default();
            let defender_unread = v_open.err();

            let v_items = by_vault.get(v.name.as_str()).map_or(&[][..], Vec::as_slice);
            let mut v_sec = 0usize;
            let mut v_cert = 0usize;
            let mut v_key = 0usize;
            let mut v_expired = 0usize;
            let mut v_exp30 = 0usize;
            let mut v_stale = 0usize;
            let mut v_no_exp = 0usize;
            let mut v_warn = 0usize;

            for it in v_items {
                match it.kind {
                    ItemType::Secret => v_sec += 1,
                    ItemType::Certificate => v_cert += 1,
                    ItemType::Key => v_key += 1,
                }
                if !it.enabled {
                    continue;
                }
                if it.created.is_some_and(|c| now - c > stale_secs) {
                    v_stale += 1;
                }
                if it.expires.is_some_and(|e| e > now && e - now <= warn_secs) {
                    v_warn += 1;
                }
                match it.expires {
                    None => v_no_exp += 1,
                    Some(e) if e <= now => v_expired += 1,
                    Some(e) if e - now <= 30 * DAY => v_exp30 += 1,
                    _ => {}
                }
            }

            let entry = env_buckets
                .entry((env.rank(), env_name.clone(), is_prod))
                .or_insert((0, 0, 0, 0));
            entry.0 += 1;
            entry.1 += v_sec;
            entry.2 += v_cert;
            entry.3 += v_key;

            let mut issues = Vec::new();
            let mut risk: u32 = 0;
            if v_expired > 0 {
                risk += (v_expired as u32) * 5;
                issues.push(format!("{v_expired} expired"));
            }
            if v_exp30 > 0 {
                risk += (v_exp30 as u32) * 3;
                issues.push(format!("{v_exp30} expiring <=30d"));
            }
            if !v.purge_protection {
                risk += if is_prod { 6 } else { 3 };
                issues.push("No purge protection".into());
            }
            if !net_ok {
                risk += if is_prod { 5 } else { 2 };
                issues.push("Public network open".into());
            }
            if !v.rbac {
                risk += 3;
                issues.push("Legacy access policy".into());
            }
            if !owners_ok {
                risk += 2;
                issues.push("No vault owner".into());
            }
            if v_stale > 0 {
                risk += v_stale as u32;
                issues.push(format!("{v_stale} stale"));
            }
            if v_alerts.total() > 0 {
                risk += (v_alerts.high as u32) * 6
                    + (v_alerts.medium as u32) * 3
                    + (v_alerts.low + v_alerts.informational) as u32;
                issues.push(format!("{} Defender alert(s)", v_alerts.total()));
            }
            if defender_unread.is_some() {
                issues.push("Defender alerts not read".into());
            }
            if plan == PlanState::Off {
                risk += if is_prod { 3 } else { 1 };
                issues.push("Defender for Key Vault off".into());
            }
            let read_error = skipped_map.get(v.name.as_str()).map(|s| (*s).to_owned());
            if read_error.is_some() {
                issues.push("Vault not read".into());
            }

            // Something Keyring couldn't read is never shown as a green Low:
            // a higher risk found stays, and otherwise the row says Unknown.
            let unread = defender_unread.is_some() || read_error.is_some();
            let (risk_label, risk_badge) = if risk >= 12 {
                ("High", "badge-error")
            } else if risk >= 5 {
                ("Medium", "badge-warn")
            } else if unread {
                ("Unknown", "badge-muted")
            } else {
                ("Low", "badge-ok")
            };

            vault_rows.push(VaultRiskRow {
                name: v.name.clone(),
                env_label: env_name,
                is_prod,
                subscription: if v.subscription_name.is_empty() {
                    v.subscription_id.clone()
                } else {
                    v.subscription_name.clone()
                },
                location: v.location.clone(),
                total_items: v_items.len(),
                expired: v_expired,
                expiring_30: v_exp30,
                stale: v_stale,
                no_expiry: v_no_exp,
                rbac: v.rbac,
                soft_delete: soft_del,
                purge_protection: v.purge_protection,
                network_restricted: net_ok,
                private_endpoint: pe_ok,
                has_owners: owners_ok,
                expiring_warn: v_warn,
                defender_open: defender_unread.is_none().then(|| v_alerts.total()),
                defender_unread,
                read_error,
                risk_score: risk,
                risk_label,
                risk_badge,
                issues_summary: if issues.is_empty() {
                    "No gaps found".to_owned()
                } else {
                    issues.join(", ")
                },
            });
        }

        // Sort vault rows by highest risk first, then production first, then name.
        vault_rows.sort_by(|a, b| {
            b.risk_score
                .cmp(&a.risk_score)
                .then_with(|| b.is_prod.cmp(&a.is_prod))
                .then_with(|| a.name.cmp(&b.name))
        });

        let controls = vec![
            control_bar("Azure RBAC enabled", pass_rbac, total_vaults),
            control_bar("Soft delete enabled", pass_soft_delete, total_vaults),
            control_bar("Purge protection enabled", pass_purge, total_vaults),
            control_bar(
                "Network lockdown (deny / private)",
                pass_network,
                total_vaults,
            ),
            control_bar("Approved private endpoint", pass_pe, total_vaults),
            control_bar("Named vault owners", pass_owners, total_vaults),
            // Vaults whose plan couldn't be read aren't counted either way.
            control_bar("Defender for Key Vault on", pass_defender, defender_known),
            control_bar(
                "Credentials with valid expiry",
                enabled_with_valid_expiry,
                enabled_items,
            ),
            control_bar(
                &format!("Rotated within {stale_after_days} days"),
                enabled_fresh,
                enabled_items,
            ),
        ];

        // Posture score: average of applicable control percentages.
        let scored: Vec<u32> = controls
            .iter()
            .filter(|c| c.total > 0)
            .map(|c| c.pct)
            .collect();
        let posture_score = if scored.is_empty() {
            0
        } else {
            (scored.iter().map(|&p| u64::from(p)).sum::<u64>() as f64 / scored.len() as f64).round()
                as u32
        };
        let (posture_label, posture_badge) = if total_vaults == 0 {
            ("No vaults", "badge-muted")
        } else if posture_score >= 80 {
            ("Strong", "badge-ok")
        } else if posture_score >= 55 {
            ("Moderate", "badge-warn")
        } else {
            ("Needs attention", "badge-error")
        };
        let gauge_circ = 2.0 * std::f64::consts::PI * 44.0;
        let gauge_fill = (f64::from(posture_score) / 100.0) * gauge_circ;
        let posture_dash = format!("{gauge_fill:.2} {:.2}", (gauge_circ - gauge_fill).max(0.0));

        // Credential health SVG donut (radius 48 -> circumference 301.59)
        let donut_raw: [(&str, usize, &'static str, &'static str); 5] = [
            ("Healthy (> 90d)", active_healthy, "chart-ok", "#117a49"),
            (
                "Expiring <= 90d",
                expiring_30 + expiring_90,
                "chart-warn",
                "#d97706",
            ),
            ("Expired", expired, "chart-danger", "#c81e32"),
            ("No expiry set", no_expiry, "chart-accent", "#0e5ae5"),
            ("Disabled", disabled, "chart-muted", "#94a3b8"),
        ];
        let donut_circ = 2.0 * std::f64::consts::PI * 48.0;
        let mut offset = 0.0_f64;
        let mut health_donut = Vec::new();
        for (label, count, css_class, hex) in donut_raw {
            let p = pct(count, total_items);
            let seg = if total_items == 0 {
                0.0
            } else {
                (count as f64 / total_items as f64) * donut_circ
            };
            let gap = (donut_circ - seg).max(0.0);
            health_donut.push(DonutSlice {
                label: label.to_owned(),
                count,
                pct: p,
                dash_array: format!("{seg:.2} {gap:.2}"),
                dash_offset: format!("{:.2}", -offset),
                css_class,
                hex,
            });
            offset += seg;
        }

        // Expiry horizon vertical bar chart (6 columns in viewBox 0 0 420 176)
        let horizon_raw: [(&str, &str, usize, &'static str, &'static str, &'static str); 6] = [
            (
                "Expired",
                "Expired",
                expired,
                "bar-danger",
                "#c81e32",
                "/expiry?group=expired",
            ),
            (
                "Next 30d",
                "0-30d",
                expiring_30,
                "bar-danger",
                "#dc2626",
                "/expiry?group=30",
            ),
            (
                "31-90d",
                "31-90d",
                expiring_90,
                "bar-warn",
                "#d97706",
                "/expiry?group=90",
            ),
            (
                "91-180d",
                "91-180d",
                expiring_180,
                "bar-ok",
                "#117a49",
                "/expiry?group=later",
            ),
            (
                "180d+",
                "180d+",
                expiring_later,
                "bar-ok",
                "#0f766e",
                "/expiry?group=later",
            ),
            (
                "No expiry",
                "None",
                no_expiry,
                "bar-accent",
                "#0e5ae5",
                "/expiry?group=none",
            ),
        ];
        let max_h = horizon_raw.iter().map(|x| x.2).max().unwrap_or(1).max(1);
        let max_bar_px = 112.0_f64;
        let baseline_y = 144_u32;
        let horizon: Vec<HorizonBar> = horizon_raw
            .into_iter()
            .enumerate()
            .map(|(i, (label, short_label, count, css_class, hex, href))| {
                let h = if count == 0 {
                    3
                } else {
                    ((count as f64 / max_h as f64) * max_bar_px)
                        .round()
                        .max(8.0) as u32
                };
                let x = 18 + (i as u32) * 66;
                let y = baseline_y.saturating_sub(h);
                HorizonBar {
                    label,
                    short_label,
                    count,
                    x,
                    y,
                    height: h,
                    label_x: x + 21,
                    count_y: y.saturating_sub(6),
                    css_class,
                    hex,
                    href,
                }
            })
            .collect();

        // Environment distribution bars
        let max_env_items = env_buckets
            .values()
            .map(|x| x.1 + x.2 + x.3)
            .max()
            .unwrap_or(1)
            .max(1);
        let env_distribution: Vec<EnvDistribution> = env_buckets
            .into_iter()
            .map(|((_, label, is_prod), (vc, sc, cc, kc))| {
                let tot = sc + cc + kc;
                let bar_width = if tot == 0 {
                    4
                } else {
                    ((tot as f64 / max_env_items as f64) * 200.0)
                        .round()
                        .max(8.0) as u32
                };
                EnvDistribution {
                    label,
                    is_prod,
                    vaults: vc,
                    secrets: sc,
                    certs: cc,
                    keys: kc,
                    total_items: tot,
                    bar_width,
                }
            })
            .collect();

        // Discovered multi-environment workload groups
        let env_groups: Vec<EnvGroupSummary> = environments::discover_groups(vaults)
            .into_iter()
            .map(|g| {
                let mut g_items = 0usize;
                let mut g_urgent = 0usize;
                let names: Vec<String> = g.vaults.iter().map(|ev| ev.vault.name.clone()).collect();
                for vn in &names {
                    if let Some(list) = by_vault.get(vn.as_str()) {
                        g_items += list.len();
                        g_urgent += list
                            .iter()
                            .filter(|i| i.enabled && i.expires.is_some_and(|e| e - now <= 30 * DAY))
                            .count();
                    }
                }
                EnvGroupSummary {
                    name: g.name,
                    vaults: names,
                    total_items: g_items,
                    expired_or_soon: g_urgent,
                }
            })
            .collect();

        // Defender for Key Vault, only for the vaults in this snapshot.
        let mut open = SeverityCounts::default();
        let alerts_error = defender.alerts.as_ref().err().cloned();
        let mut top = Vec::new();
        if let Ok(list) = &defender.alerts {
            let mine: Vec<defender::Alert> = list
                .iter()
                .filter(|a| a.vault.as_ref().is_some_and(|v| in_snapshot.contains(v)))
                .cloned()
                .collect();
            for a in mine.iter().filter(|a| a.status.is_open()) {
                open.add(a.severity);
            }
            top = defender::most_urgent(&mine, 5)
                .into_iter()
                .map(|a| AlertBrief {
                    title: a.title,
                    severity: a.severity.label(),
                    severity_css: a.severity.css(),
                    vault: a.vault.unwrap_or_default(),
                    time: a.time.short,
                    portal_url: a.portal_url,
                })
                .collect();
        }
        let defender_summary = DefenderSummary {
            open,
            vaults_on,
            vaults_off,
            vaults_unknown,
            alerts_error,
            top,
        };

        // Executive remediation action items
        let mut actions = Vec::new();
        if open.high + open.medium > 0 {
            actions.push(ActionItem {
                priority: "Critical",
                badge_class: "badge-error",
                title: format!(
                    "Investigate {} open high or medium Defender for Key Vault alert(s)",
                    open.high + open.medium
                ),
                detail: "Defender saw unusual use of these vaults, such as secrets listed and read in bulk or access from a suspicious address. Confirm who it was and rotate anything exposed.".to_owned(),
                href: "/defender",
            });
        }
        if expired > 0 {
            actions.push(ActionItem {
                priority: "Critical",
                badge_class: "badge-error",
                title: format!("Rotate or disable {expired} expired credential(s)"),
                detail: "Expired secrets, certificates or keys indicate either active outage risk or orphaned credentials that should be cleaned up.".to_owned(),
                href: "/expiry?group=expired",
            });
        }
        if expiring_warn > 0 {
            actions.push(ActionItem {
                priority: "High",
                badge_class: "badge-error",
                title: format!("Schedule renewal for {expiring_warn} credential(s) expiring within {expiry_warn_days} days"),
                detail: "Confirm owners and notify lists on each expiring item and rotate before expiry to prevent service disruption.".to_owned(),
                // The dashboard's groups are fixed bands (7, 30, 90 days), so no one
                // group holds "within N days": link to all of it, soonest first.
                href: "/expiry",
            });
        }
        let no_purge = total_vaults.saturating_sub(pass_purge);
        if no_purge > 0 {
            actions.push(ActionItem {
                priority: "High",
                badge_class: "badge-warn",
                title: format!("Enable Purge Protection on {no_purge} Key Vault(s)"),
                detail: "Without purge protection, any privileged account or compromised principal can permanently destroy soft-deleted credentials before retention expires.".to_owned(),
                href: "/vault-health",
            });
        }
        let open_net = total_vaults.saturating_sub(pass_network);
        if open_net > 0 {
            actions.push(ActionItem {
                priority: "Medium",
                badge_class: "badge-warn",
                title: format!("Restrict public network access on {open_net} Key Vault(s)"),
                detail: "Set default firewall action to Deny or disable public access and route workloads and Keyring over Azure Private Endpoints.".to_owned(),
                href: "/vault-health",
            });
        }
        if vaults_off > 0 {
            actions.push(ActionItem {
                priority: "High",
                badge_class: "badge-warn",
                title: format!("Turn on Defender for Key Vault for {vaults_off} vault(s)"),
                detail: "Without the Key Vault plan in Defender for Cloud, nothing raises an alert when a vault is used in an unusual way.".to_owned(),
                href: "/defender",
            });
        }
        let unowned_vaults = total_vaults.saturating_sub(pass_owners);
        if unowned_vaults > 0 {
            actions.push(ActionItem {
                priority: "Medium",
                badge_class: "badge-warn",
                title: format!("Assign keyring-owners ARM tag to {unowned_vaults} vault(s)"),
                detail: "Named vault owners receive access requests, destructive-change alerts and access review accountability.".to_owned(),
                href: "/vault-health",
            });
        }
        if stale > 0 {
            actions.push(ActionItem {
                priority: "Medium",
                badge_class: "badge-warn",
                title: format!("Review {stale} stale credential(s) unchanged for over {stale_after_days} days"),
                detail: "Long-lived static credentials widen blast radius; rotate or migrate workloads to Managed Identities where possible.".to_owned(),
                href: "/expiry/age",
            });
        }
        if no_expiry > 0 {
            actions.push(ActionItem {
                priority: "Standard",
                badge_class: "badge-muted",
                title: format!("Set expiry dates on {no_expiry} enabled credential(s) without an expiry"),
                detail: "Credentials with no expiry date never appear in Event Grid expiry alerts or renewal queues.".to_owned(),
                href: "/expiry?group=none",
            });
        }

        let top_risks = vault_rows.iter().take(6).cloned().collect();

        Self {
            total_vaults,
            read_vaults,
            skipped_vaults,
            capped,
            subscriptions,
            prod_vaults,
            non_prod_vaults,
            env_groups,
            total_items,
            secrets_count,
            certs_count,
            keys_count,
            active_healthy,
            expired,
            expiring_30,
            expiring_90,
            expiring_180,
            expiring_later,
            no_expiry,
            disabled,
            stale,
            unowned_items,
            posture_score,
            posture_label,
            posture_badge,
            posture_dash,
            health_donut,
            controls,
            horizon,
            env_distribution,
            vault_rows,
            top_risks,
            actions,
            stale_after_days,
            expiry_warn_days,
            expiring_warn,
            defender: defender_summary,
        }
    }

    pub fn has_vaults(&self) -> bool {
        self.total_vaults > 0
    }
}

/// Format an RFC-3339 / UTC executive timestamp string (e.g. `21 Nov 2026, 18:45 UTC`).
pub fn format_generated_utc(now: i64) -> String {
    dates::format_datetime(now)
}

/// Default reporting period label (e.g. `Nov 2026`).
pub fn default_period(now: i64) -> String {
    let full = dates::format_date(now); // e.g. "21 Nov 2026"
    let parts: Vec<&str> = full.split_whitespace().collect();
    if parts.len() >= 3 {
        format!("{} {}", parts[1], parts[2])
    } else {
        full
    }
}

/// Export a formula-guarded CSV executive summary & per-vault posture matrix.
pub fn to_csv(snap: &OrgSnapshot, opts: &ReportOptions, generated_utc: &str) -> String {
    let mut out = String::new();
    let push_row = |out: &mut String, cols: &[&str]| {
        for (i, c) in cols.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&csv_field(c));
        }
        out.push_str("\r\n");
    };

    push_row(
        &mut out,
        &[
            "Section",
            "Entity",
            "Environment",
            "Subscription",
            "MetricOrRisk",
            "ValueOrItems",
            "Expired",
            "Expiring30d",
            "Stale",
            "NoExpiry",
            "RBAC",
            "SoftDelete",
            "PurgeProtection",
            "NetworkRestricted",
            "PrivateEndpoint",
            "NamedOwners",
            "Detail",
        ],
    );

    push_row(
        &mut out,
        &[
            "Report",
            opts.display_client(),
            opts.scope.label(),
            &opts.period,
            &opts.report_title,
            opts.display_issuer(),
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            &format!("Generated {generated_utc}"),
        ],
    );

    let score_str = format!("{}%", snap.posture_score);
    let total_v = snap.total_vaults.to_string();
    let total_i = snap.total_items.to_string();
    let exp_s = snap.expired.to_string();
    let exp30_s = snap.expiring_30.to_string();
    let stale_s = snap.stale.to_string();
    let noexp_s = snap.no_expiry.to_string();
    push_row(
        &mut out,
        &[
            "Summary",
            "Organisation Estate",
            opts.scope.label(),
            &format!("{} subscription(s)", snap.subscriptions),
            &format!("{} ({score_str})", snap.posture_label),
            &total_i,
            &exp_s,
            &exp30_s,
            &stale_s,
            &noexp_s,
            "",
            "",
            "",
            "",
            "",
            "",
            &format!(
                "{total_v} vault(s) ({} read, {} skipped); {} secrets, {} certs, {} keys",
                snap.read_vaults,
                snap.skipped_vaults,
                snap.secrets_count,
                snap.certs_count,
                snap.keys_count
            ),
        ],
    );

    let d = &snap.defender;
    let defender_detail = match &d.alerts_error {
        Some(why) => format!("NOT READ: {why}"),
        None => format!(
            "{} open alert(s): {}; plan on for {} vault(s), off for {}, unknown for {}",
            d.open.total(),
            if d.open.total() == 0 {
                "none".to_owned()
            } else {
                d.open.breakdown()
            },
            d.vaults_on,
            d.vaults_off,
            d.vaults_unknown
        ),
    };
    // Blank when alerts weren't read, so a spreadsheet can't count them as 0.
    let open_s = if d.alerts_error.is_some() {
        String::new()
    } else {
        d.open.total().to_string()
    };
    push_row(
        &mut out,
        &[
            "Defender",
            "Defender for Key Vault",
            opts.scope.label(),
            "",
            "OpenAlerts",
            &open_s,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            &defender_detail,
        ],
    );

    for c in &snap.controls {
        let passed = format!("{}/{} ({}%)", c.passed, c.total, c.pct);
        push_row(
            &mut out,
            &[
                "Control", &c.label, "", "", "PassRate", &passed, "", "", "", "", "", "", "", "",
                "", "", "",
            ],
        );
    }

    let yn = |b: bool| if b { "Pass" } else { "Warn" };
    for v in &snap.vault_rows {
        let ti = v.total_items.to_string();
        let ex = v.expired.to_string();
        let e30 = v.expiring_30.to_string();
        let st = v.stale.to_string();
        let ne = v.no_expiry.to_string();
        let mut detail = match &v.read_error {
            Some(err) => format!("NOT READ: {err}; {}", v.issues_summary),
            None => v.issues_summary.clone(),
        };
        if let Some(why) = &v.defender_unread {
            detail.push_str(&format!("; Defender alerts NOT READ: {why}"));
        }
        push_row(
            &mut out,
            &[
                "Vault",
                &v.name,
                &v.env_label,
                &v.subscription,
                v.risk_label,
                &ti,
                &ex,
                &e30,
                &st,
                &ne,
                yn(v.rbac),
                yn(v.soft_delete),
                yn(v.purge_protection),
                yn(v.network_restricted),
                yn(v.private_endpoint),
                yn(v.has_owners),
                &detail,
            ],
        );
    }

    out
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    branding: &'a ReportOptions,
    snapshot: &'a OrgSnapshot,
}

/// Export a structured JSON snapshot for continuous BI, Power BI or portal automation.
pub fn to_json(snap: &OrgSnapshot, opts: &ReportOptions, generated_utc: &str) -> String {
    serde_json::to_string_pretty(&JsonReport {
        schema_version: 1,
        generated_at_utc: generated_utc,
        branding: opts,
        snapshot: snap,
    })
    .unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::vaults::HealthProps;

    fn make_vault(name: &str, env: &str, purge: bool, net_deny: bool, owned: bool) -> Vault {
        let mut tags = BTreeMap::new();
        tags.insert("app".into(), "payments".into());
        tags.insert("env".into(), env.into());
        if owned {
            tags.insert("keyring-owners".into(), "ops@example.com".into());
        }
        Vault {
            id: format!(
                "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}"
            ),
            name: name.into(),
            resource_group: "rg".into(),
            subscription_id: "sub-1".into(),
            subscription_name: "Core Prod".into(),
            location: "australiaeast".into(),
            tags,
            rbac: true,
            soft_delete: true,
            purge_protection: purge,
            health: HealthProps {
                soft_delete: Some(true),
                public_access: Some(if net_deny { "Disabled" } else { "Enabled" }.into()),
                default_action: Some(if net_deny { "Deny" } else { "Allow" }.into()),
                private_endpoints: if net_deny {
                    vec!["Approved".into()]
                } else {
                    vec![]
                },
            },
        }
    }

    fn make_item(vault: &str, name: &str, kind: ItemType, exp: Option<i64>, created: i64) -> Item {
        Item {
            vault: vault.into(),
            kind,
            name: name.into(),
            enabled: true,
            expires: exp,
            not_before: None,
            created: Some(created),
            content_type: String::new(),
            managed: false,
            tags: vec![("owner".into(), "team@example.com".into())],
        }
    }

    #[test]
    fn builds_org_snapshot_charts_and_risk_ranking() {
        let now = 1_760_000_000_i64;
        let vaults = vec![
            make_vault("kv-payments-dev", "dev", false, false, false),
            make_vault("kv-payments-prod", "prod", true, true, true),
        ];
        let items = vec![
            make_item(
                "kv-payments-prod",
                "db-pass",
                ItemType::Secret,
                Some(now - DAY),
                now - 10 * DAY,
            ),
            make_item(
                "kv-payments-prod",
                "tls-cert",
                ItemType::Certificate,
                Some(now + 15 * DAY),
                now - 20 * DAY,
            ),
            make_item(
                "kv-payments-dev",
                "api-key",
                ItemType::Secret,
                Some(now + 200 * DAY),
                now - 400 * DAY,
            ),
            make_item(
                "kv-payments-dev",
                "signing-key",
                ItemType::Key,
                None,
                now - 5 * DAY,
            ),
        ];
        let snap = OrgSnapshot::build(
            &vaults,
            &items,
            &[],
            false,
            Thresholds::default(),
            &Defender::not_read("Not read"),
            now,
        );

        assert_eq!(snap.total_vaults, 2);
        assert_eq!(snap.prod_vaults, 1);
        assert_eq!(snap.non_prod_vaults, 1);
        assert_eq!(snap.total_items, 4);
        assert_eq!(snap.secrets_count, 2);
        assert_eq!(snap.certs_count, 1);
        assert_eq!(snap.keys_count, 1);
        assert_eq!(snap.expired, 1);
        assert_eq!(snap.expiring_30, 1);
        assert_eq!(snap.stale, 1);
        assert_eq!(snap.no_expiry, 1);
        assert_eq!(snap.env_groups.len(), 1);
        assert_eq!(snap.env_groups[0].name, "payments");
        assert!(snap.posture_score > 0 && snap.posture_score < 100);
        assert_eq!(snap.health_donut.len(), 5);
        assert_eq!(snap.horizon.len(), 6);
        assert!(!snap.actions.is_empty());
        assert_eq!(snap.expiring_warn, 1);
        let defender = snap
            .controls
            .iter()
            .find(|c| c.label.starts_with("Defender"))
            .unwrap();
        assert_eq!(defender.total, 0, "an unread plan counts neither way");
        assert_eq!(snap.defender.vaults_unknown, 2);
        // Alerts not read are never "no gaps", 0 or a green Low.
        assert!(snap.vault_rows.iter().all(|r| r.defender_unread.is_some()));
        assert!(snap.vault_rows.iter().all(|r| r.defender_open.is_none()));
        assert!(snap.vault_rows.iter().all(|r| r.risk_badge != "badge-ok"));
        assert!(
            snap.vault_rows
                .iter()
                .all(|r| r.issues_summary.contains("Defender alerts not read"))
        );
    }

    #[test]
    fn defender_alerts_and_plans_raise_risk_and_actions() {
        use crate::defender::RawAlert;
        let now = 1_760_000_000_i64;
        let vaults = vec![
            make_vault("kv-payments-dev", "dev", true, true, true),
            make_vault("kv-payments-prod", "prod", true, true, true),
        ];
        let alert = |vault: &str, sev: &str| RawAlert {
            subscription_id: "sub-1".into(),
            alert_type: "KV_SuspiciousIPAccess".into(),
            display_name: "Access from a suspicious IP address to a key vault".into(),
            severity: sev.into(),
            status: "Active".into(),
            time_generated: "2026-11-20T00:00:00Z".into(),
            compromised_entity: vault.into(),
            ..RawAlert::default()
        };
        let d = Defender::from_rows(
            Ok(vec![("sub-1".into(), "Free".into())]),
            Ok(vec![
                alert("kv-payments-prod", "High"),
                alert("kv-elsewhere", "High"),
            ]),
        );
        let t = Thresholds {
            expiry_warn_days: 60,
            stale_after_days: 365,
        };
        let items = vec![make_item(
            "kv-payments-dev",
            "soon",
            ItemType::Secret,
            Some(now + 45 * DAY),
            now,
        )];
        let snap = OrgSnapshot::build(&vaults, &items, &[], false, t, &d, now);
        // A plan row was read, so a vault with no alerts is a real 0.
        let dev = snap
            .vault_rows
            .iter()
            .find(|r| r.name == "kv-payments-dev")
            .unwrap();
        assert_eq!(dev.defender_open, Some(0));
        assert_eq!(dev.defender_unread, None);
        assert_eq!(
            snap.defender.open.high, 1,
            "only alerts on vaults in the snapshot"
        );
        assert_eq!(snap.defender.top.len(), 1);
        assert_eq!(snap.defender.vaults_off, 2);
        assert_eq!(snap.expiring_warn, 1, "45 days is inside a 60-day window");
        assert_eq!(
            snap.vault_rows[0].name, "kv-payments-prod",
            "the alert puts it first"
        );
        assert!(
            snap.vault_rows[0]
                .issues_summary
                .contains("1 Defender alert(s)")
        );
        assert!(snap.actions[0].title.starts_with("Investigate 1 open"));
        assert!(
            snap.actions
                .iter()
                .any(|a| a.title.contains("expiring within 60 days"))
        );
        assert!(
            snap.actions
                .iter()
                .any(|a| a.title.starts_with("Turn on Defender"))
        );
        let c = snap
            .controls
            .iter()
            .find(|c| c.label.starts_with("Defender"))
            .unwrap();
        assert_eq!((c.passed, c.total), (0, 2));
    }

    #[test]
    fn white_label_csv_and_json_guard_formulas_and_hide_keyring_brand() {
        let now = 1_760_000_000_i64;
        let vaults = vec![make_vault("kv-payments-prod", "prod", true, true, true)];
        let snap = OrgSnapshot::build(
            &vaults,
            &[],
            &[],
            false,
            Thresholds::default(),
            &Defender::not_read("Not read"),
            now,
        );
        let opts = ReportOptions::sanitized(
            "=HYPERLINK(\"http://evil\")",
            "Board Security Pack",
            "Acme Advisory",
            "Nov 2026",
            "emerald",
            "prod",
            true,
            true,
            true,
            true,
            true,
            "Nov 2026",
        );

        let csv = to_csv(&snap, &opts, "21 Nov 2026, 18:00 UTC");
        assert!(csv.contains("'=HYPERLINK"), "formula guarded: {csv}");
        assert!(!csv.contains("Keyring Privileged Access"), "white-labelled");
        assert!(csv.contains("Acme Advisory"));

        let json = to_json(&snap, &opts, "21 Nov 2026, 18:00 UTC");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["branding"]["white_label"], true);
        assert_eq!(parsed["branding"]["prepared_by"], "Acme Advisory");
        assert_eq!(parsed["snapshot"]["total_vaults"], 1);
    }

    #[test]
    fn clean_brand_text_strips_bidi_and_controls() {
        assert_eq!(
            clean_brand_text("Acme \u{202E}Corp\r\n  Ltd\t", 40),
            "Acme Corp Ltd"
        );
        assert_eq!(
            safe_filename_slug("Acme Financial Group!", true),
            "acme-financial-group"
        );
        assert_eq!(safe_filename_slug("", true), "client");
        assert_eq!(safe_filename_slug("", false), "keyring");
    }
}
