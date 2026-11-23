//! Microsoft Defender for Key Vault: each subscription's plan, and the
//! security alerts it raised on Key Vaults. Pure functions over what
//! [`crate::azure::defender`] read from Resource Graph, tested without Azure.
//!
//! Alerts are Microsoft's, but parts of them (the entity, and any address
//! or name in the title) describe whoever set them off, so every text
//! field is treated as untrusted: control and bidirectional characters are
//! dropped, whitespace is collapsed and the text is cut short. The page
//! escapes it, the CSV guards it against formulas, and none of it is
//! logged. The only link kept is the alert's own Azure portal address.

use std::collections::HashMap;

use serde::Serialize;

use crate::azure::vaults::is_valid_vault_name;
use crate::dates::{self, LogTime};
use crate::executive::clean_brand_text;
use crate::expiry::csv_field;

/// Alerts read at most, newest first. Resource Graph returns one page.
pub const MAX_ALERTS: usize = 1000;
/// How far back alerts are read, in days.
pub const ALERT_DAYS: u32 = 90;

const MAX_TITLE_CHARS: usize = 200;
const MAX_SHORT_CHARS: usize = 100;
const MAX_URL_CHARS: usize = 2048;

/// The Azure portals an alert's `alertUri` may point at. Anything else is
/// dropped, so an alert can't carry a link to another site.
const PORTALS: [&str; 3] = [
    "https://portal.azure.com/",
    "https://portal.azure.us/",
    "https://portal.azure.cn/",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Informational,
    Unknown,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Informational,
    ];

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "informational" => Self::Informational,
            _ => Self::Unknown,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Informational => "Informational",
            Self::Unknown => "Unknown",
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Informational => "informational",
            Self::Unknown => "unknown",
        }
    }
    pub fn css(self) -> &'static str {
        match self {
            Self::High => "badge-error",
            Self::Medium => "badge-warn",
            _ => "badge-muted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertStatus {
    Active,
    InProgress,
    Resolved,
    Dismissed,
    Unknown,
}

impl AlertStatus {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "inprogress" => Self::InProgress,
            "resolved" => Self::Resolved,
            "dismissed" => Self::Dismissed,
            _ => Self::Unknown,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::InProgress => "In progress",
            Self::Resolved => "Resolved",
            Self::Dismissed => "Dismissed",
            Self::Unknown => "Unknown",
        }
    }
    /// Still needs someone to look at it. An unknown status counts as
    /// open, so an alert is never hidden because Azure added a status.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Active | Self::InProgress | Self::Unknown)
    }
    pub fn css(self) -> &'static str {
        if self.is_open() {
            "badge-warn"
        } else {
            "badge-muted"
        }
    }
}

/// One Defender for Key Vault alert, cleaned and ready to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The vault it is about, when its resource ID (or compromised entity)
    /// names one. Lower-case, as vault names are case-insensitive.
    pub vault: Option<String>,
    pub subscription_id: String,
    /// `KV_ListGetAnomaly` and the like, or `unknown`.
    pub alert_type: String,
    pub title: String,
    pub severity: Severity,
    pub status: AlertStatus,
    pub time: LogTime,
    /// The MITRE ATT&CK tactic Defender gives, such as `CredentialAccess`.
    pub intent: String,
    pub entity: String,
    /// The alert in the Azure portal, only if it is a portal address.
    pub portal_url: Option<String>,
}

/// What Resource Graph sent for one alert, before cleaning.
#[derive(Debug, Clone, Default)]
pub struct RawAlert {
    pub subscription_id: String,
    pub alert_type: String,
    pub display_name: String,
    pub severity: String,
    pub status: String,
    pub time_generated: String,
    pub intent: String,
    pub compromised_entity: String,
    pub alert_uri: String,
    pub resource_identifiers: Option<serde_json::Value>,
}

impl Alert {
    pub fn from_raw(r: &RawAlert) -> Self {
        let alert_type = if (1..=MAX_SHORT_CHARS).contains(&r.alert_type.len())
            && r.alert_type
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            r.alert_type.clone()
        } else {
            "unknown".to_owned()
        };
        let title = clean_brand_text(&r.display_name, MAX_TITLE_CHARS);
        Self {
            vault: vault_of(r.resource_identifiers.as_ref())
                .or_else(|| vault_name(&r.compromised_entity)),
            subscription_id: clean_brand_text(&r.subscription_id, MAX_SHORT_CHARS)
                .to_ascii_lowercase(),
            title: if title.is_empty() {
                alert_type.clone()
            } else {
                title
            },
            alert_type,
            severity: Severity::parse(&r.severity),
            status: AlertStatus::parse(&r.status),
            time: dates::log_time(&clean_brand_text(&r.time_generated, MAX_SHORT_CHARS)),
            intent: clean_brand_text(&r.intent, MAX_SHORT_CHARS),
            entity: clean_brand_text(&r.compromised_entity, MAX_SHORT_CHARS),
            portal_url: portal_url(&r.alert_uri),
        }
    }
}

/// A vault name, lower-cased, if `s` is one.
fn vault_name(s: &str) -> Option<String> {
    let s = s.trim();
    is_valid_vault_name(s).then(|| s.to_ascii_lowercase())
}

/// The vault named by the first Key Vault resource ID in an alert's
/// `resourceIdentifiers`.
fn vault_of(ids: Option<&serde_json::Value>) -> Option<String> {
    const MARK: &str = "/providers/microsoft.keyvault/vaults/";
    ids?.as_array()?.iter().find_map(|entry| {
        let id = entry
            .get("azureResourceId")
            .or_else(|| entry.get("AzureResourceId"))?
            .as_str()?;
        let lower = id.to_ascii_lowercase();
        let at = lower.find(MARK)? + MARK.len();
        let name = lower[at..].split('/').next()?;
        vault_name(name)
    })
}

fn portal_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    (raw.len() <= MAX_URL_CHARS
        && PORTALS.iter().any(|p| raw.starts_with(p))
        && raw
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'<' && b != b'>'))
    .then(|| raw.to_owned())
}

/// A subscription's Defender for Key Vault plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanState {
    /// The Standard tier: Defender watches the subscription's vaults.
    On,
    /// The Free tier: no threat detection.
    Off,
    /// Couldn't tell, with the reason.
    Unknown(String),
}

impl PlanState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::On => "On",
            Self::Off => "Off",
            Self::Unknown(_) => "Unknown",
        }
    }
    pub fn css(&self) -> &'static str {
        match self {
            Self::On => "badge-ok",
            Self::Off => "badge-warn",
            Self::Unknown(_) => "badge-muted",
        }
    }
    pub fn reason(&self) -> &str {
        match self {
            Self::Unknown(why) => why,
            _ => "",
        }
    }
}

/// Why a subscription with no plan row is Unknown. Resource Graph leaves
/// out what the person can't read, and a subscription that has never
/// registered `Microsoft.Security` has no row either.
pub const NO_PLAN_ROW: &str = "Resource Graph returned no Defender plan for its subscription, which happens without Security Reader on it or before Defender for Cloud has been set up there";

/// Open alerts by severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

impl SeverityCounts {
    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Informational | Severity::Unknown => self.informational += 1,
        }
    }
    pub fn total(&self) -> usize {
        self.high + self.medium + self.low + self.informational
    }
    /// "2 high, 1 low": only the severities with alerts.
    pub fn breakdown(&self) -> String {
        [
            (self.high, "high"),
            (self.medium, "medium"),
            (self.low, "low"),
            (self.informational, "informational"),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, w)| format!("{n} {w}"))
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// What Defender says about one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultDefender {
    pub plan: PlanState,
    /// Open alerts on it, or why alerts couldn't be read.
    pub open: Result<SeverityCounts, String>,
}

impl Default for VaultDefender {
    fn default() -> Self {
        Self {
            plan: PlanState::Unknown("Not read".into()),
            open: Err("Not read".into()),
        }
    }
}

/// Everything read from Defender, or why each part couldn't be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defender {
    /// Each subscription (lower-case ID) with a plan row: `true` for On.
    pub plans: Result<HashMap<String, bool>, String>,
    /// Open alerts first, then newest first.
    pub alerts: Result<Vec<Alert>, String>,
}

impl Default for Defender {
    fn default() -> Self {
        Self::not_read("Not read")
    }
}

impl Defender {
    pub fn not_read(why: &str) -> Self {
        Self {
            plans: Err(why.to_owned()),
            alerts: Err(why.to_owned()),
        }
    }

    /// From Resource Graph rows: (subscription ID, pricing tier) and raw
    /// alerts. A tier other than `Standard` counts as off.
    pub fn from_rows(
        plans: Result<Vec<(String, String)>, String>,
        alerts: Result<Vec<RawAlert>, String>,
    ) -> Self {
        let plans = plans.map(|rows| {
            rows.into_iter()
                .map(|(sub, tier)| {
                    (
                        sub.trim().to_ascii_lowercase(),
                        tier.trim().eq_ignore_ascii_case("Standard"),
                    )
                })
                .collect()
        });
        let alerts = alerts.and_then(|rows| {
            // The query puts open alerts first, so a full page whose last
            // row is still open may have left open alerts out. Counting
            // them would understate the open alerts, so say it couldn't.
            let out: Vec<Alert> = rows.iter().take(MAX_ALERTS).map(Alert::from_raw).collect();
            if out.len() >= MAX_ALERTS && out.last().is_some_and(|a| a.status.is_open()) {
                return Err(format!(
                    "There are more than {MAX_ALERTS} open alerts, more than Keyring reads at once: see them in Defender for Cloud"
                ));
            }
            let mut out = out;
            sort_newest_first(&mut out);
            Ok(out)
        });
        Self { plans, alerts }
    }

    pub fn plan_for(&self, subscription_id: &str) -> PlanState {
        match &self.plans {
            Err(why) => PlanState::Unknown(why.clone()),
            Ok(map) => match map.get(&subscription_id.to_ascii_lowercase()) {
                Some(true) => PlanState::On,
                Some(false) => PlanState::Off,
                None => PlanState::Unknown(NO_PLAN_ROW.into()),
            },
        }
    }

    /// Open alerts about `vault`, by severity.
    pub fn open_for(&self, vault: &str) -> Result<SeverityCounts, String> {
        let alerts = self.alerts.as_ref().map_err(Clone::clone)?;
        let mut c = SeverityCounts::default();
        for a in alerts.iter().filter(|a| {
            a.status.is_open()
                && a.vault
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(vault))
        }) {
            c.add(a.severity);
        }
        Ok(c)
    }

    pub fn for_vault(&self, vault: &str, subscription_id: &str) -> VaultDefender {
        VaultDefender {
            plan: self.plan_for(subscription_id),
            open: self.open_for(vault),
        }
    }

    /// Every open alert, by severity.
    pub fn open_counts(&self) -> SeverityCounts {
        let mut c = SeverityCounts::default();
        if let Ok(list) = &self.alerts {
            for a in list.iter().filter(|a| a.status.is_open()) {
                c.add(a.severity);
            }
        }
        c
    }
}

/// Newest first; alerts with a time Keyring couldn't read go last.
pub fn sort_newest_first(alerts: &mut [Alert]) {
    alerts.sort_by(|a, b| {
        (b.time.iso.is_some(), &b.time.iso, a.severity).cmp(&(
            a.time.iso.is_some(),
            &a.time.iso,
            b.severity,
        ))
    });
}

/// Open alerts first by severity, then newest. For short lists such as Home.
pub fn most_urgent(alerts: &[Alert], n: usize) -> Vec<Alert> {
    let mut open: Vec<Alert> = alerts
        .iter()
        .filter(|a| a.status.is_open())
        .cloned()
        .collect();
    open.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| b.time.iso.cmp(&a.time.iso))
    });
    open.truncate(n);
    open
}

const CSV_HEADER: &str =
    "Time (UTC),Severity,Status,Alert,Alert type,Vault,Subscription,Tactic,Entity,Portal link\r\n";
const CSV_COLUMNS: usize = 10;

/// CSV of alerts. Every text field goes through [`csv_field`].
pub fn to_csv(alerts: &[Alert], subscription_names: &HashMap<String, String>) -> String {
    let mut out = String::from(CSV_HEADER);
    for a in alerts {
        let sub = subscription_names
            .get(&a.subscription_id)
            .cloned()
            .unwrap_or_else(|| a.subscription_id.clone());
        let row = [
            csv_field(a.time.iso.as_deref().unwrap_or(&a.time.short)),
            a.severity.label().to_owned(),
            a.status.label().to_owned(),
            csv_field(&a.title),
            csv_field(&a.alert_type),
            csv_field(a.vault.as_deref().unwrap_or_default()),
            csv_field(&sub),
            csv_field(&a.intent),
            csv_field(&a.entity),
            csv_field(a.portal_url.as_deref().unwrap_or_default()),
        ];
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// A line for something the export leaves out: `NOT READ` in the Status
/// column and the reason in the Alert column.
pub fn not_read_row(reason: &str) -> String {
    let mut row = vec![String::new(); CSV_COLUMNS];
    row[2] = "NOT READ".to_owned();
    row[3] = csv_field(reason);
    let mut out = row.join(",");
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(vault: &str, sev: &str, status: &str, time: &str) -> RawAlert {
        RawAlert {
            subscription_id: "SUB-A".into(),
            alert_type: "KV_ListGetAnomaly".into(),
            display_name: "Suspicious secret listing and query in a key vault".into(),
            severity: sev.into(),
            status: status.into(),
            time_generated: time.into(),
            intent: "CredentialAccess".into(),
            compromised_entity: vault.into(),
            alert_uri: "https://portal.azure.com/#blade/alert/1".into(),
            resource_identifiers: Some(json!([
                {"type": "LogAnalytics", "workspaceId": "w"},
                {"type": "AzureResource", "azureResourceId": format!("/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{vault}")}
            ])),
        }
    }

    #[test]
    fn parses_an_alert_and_finds_its_vault() {
        let a = Alert::from_raw(&raw(
            "KV-Prod",
            "High",
            "Active",
            "2026-11-20T03:04:05.123Z",
        ));
        assert_eq!(a.vault.as_deref(), Some("kv-prod"));
        assert_eq!(a.subscription_id, "sub-a");
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.status, AlertStatus::Active);
        assert_eq!(a.time.iso.as_deref(), Some("2026-11-20T03:04:05.123Z"));
        assert_eq!(a.time.short, "20 Nov 2026, 03:04");
        assert_eq!(
            a.portal_url.as_deref(),
            Some("https://portal.azure.com/#blade/alert/1")
        );
    }

    #[test]
    fn untrusted_text_is_cleaned_and_links_are_portal_only() {
        let mut r = raw("kv-a", "Medium", "Active", "nonsense");
        r.display_name = "Access from 1.2.3.4\u{202E}evil\n\t<script>".into();
        r.alert_type = "KV_<b>".into();
        r.alert_uri = "https://evil.example/portal.azure.com/".into();
        r.resource_identifiers = Some(
            json!([{"azureResourceId": "/subscriptions/s/providers/Microsoft.KeyVault/vaults/bad--name"}]),
        );
        r.compromised_entity = "=cmd|' /C calc'!A0".into();
        let a = Alert::from_raw(&r);
        assert_eq!(
            a.title, "Access from 1.2.3.4evil<script>",
            "controls dropped"
        );
        assert_eq!(a.alert_type, "unknown");
        assert_eq!(a.portal_url, None);
        assert_eq!(
            a.vault, None,
            "neither the ID nor the entity is a vault name"
        );
        assert_eq!(a.time.iso, None);
        let csv = to_csv(&[a], &HashMap::new());
        assert!(csv.contains(",'=cmd|' /C calc'!A0,"), "{csv}");
        let mut r = raw("kv-a", "Low", "Active", "");
        r.alert_uri = "https://portal.azure.com/\"onmouseover=x".into();
        assert_eq!(Alert::from_raw(&r).portal_url, None);
    }

    #[test]
    fn severity_and_status_words() {
        assert_eq!(Severity::parse(" medium "), Severity::Medium);
        assert_eq!(Severity::parse("Critical"), Severity::Unknown);
        assert_eq!(AlertStatus::parse("InProgress"), AlertStatus::InProgress);
        assert!(AlertStatus::parse("Something new").is_open());
        assert!(!AlertStatus::Dismissed.is_open());
        assert!(!AlertStatus::Resolved.is_open());
    }

    #[test]
    fn plans_and_counts_per_vault() {
        let d = Defender::from_rows(
            Ok(vec![
                ("SUB-A".into(), "Standard".into()),
                ("sub-b".into(), "Free".into()),
            ]),
            Ok(vec![
                raw("kv-a", "High", "Active", "2026-11-20T03:04:05Z"),
                raw("kv-a", "Low", "InProgress", "2026-11-21T03:04:05Z"),
                raw("kv-a", "High", "Dismissed", "2026-11-22T03:04:05Z"),
                raw("kv-b", "Medium", "Active", "2026-11-19T03:04:05Z"),
            ]),
        );
        assert_eq!(d.plan_for("sub-a"), PlanState::On);
        assert_eq!(d.plan_for("SUB-B"), PlanState::Off);
        assert_eq!(d.plan_for("sub-c"), PlanState::Unknown(NO_PLAN_ROW.into()));
        let a = d.open_for("KV-A").unwrap();
        assert_eq!((a.high, a.low, a.total()), (1, 1, 2));
        assert_eq!(a.breakdown(), "1 high, 1 low");
        assert_eq!(d.open_counts().total(), 3);
        let alerts = d.alerts.as_ref().unwrap();
        assert_eq!(alerts[0].time.short, "22 Nov 2026, 03:04", "newest first");
        let urgent = most_urgent(alerts, 2);
        assert_eq!(urgent[0].severity, Severity::High);
        assert_eq!(urgent[1].severity, Severity::Medium);

        let many: Vec<RawAlert> = (0..MAX_ALERTS)
            .map(|_| raw("kv-a", "Low", "Active", "2026-11-20T03:04:05Z"))
            .collect();
        let capped = Defender::from_rows(Ok(vec![]), Ok(many));
        assert!(
            capped
                .open_for("kv-a")
                .unwrap_err()
                .contains("more than 1000 open alerts")
        );
        let mut closed: Vec<RawAlert> = (0..MAX_ALERTS)
            .map(|_| raw("kv-a", "Low", "Resolved", "2026-11-20T03:04:05Z"))
            .collect();
        closed[0].status = "Active".into();
        let full_of_closed = Defender::from_rows(Ok(vec![]), Ok(closed));
        assert_eq!(full_of_closed.open_for("kv-a").unwrap().total(), 1);

        let failed = Defender::from_rows(Err("No access".into()), Err("No access".into()));
        assert_eq!(
            failed.plan_for("sub-a"),
            PlanState::Unknown("No access".into())
        );
        assert_eq!(failed.open_for("kv-a"), Err("No access".into()));
    }

    #[test]
    fn csv_has_a_row_per_alert_and_says_what_it_leaves_out() {
        let a = Alert::from_raw(&raw("kv-a", "High", "Active", "2026-11-20T03:04:05Z"));
        let names = HashMap::from([("sub-a".to_owned(), "Prod".to_owned())]);
        let mut csv = to_csv(&[a], &names);
        csv.push_str(&not_read_row("You don't have Security Reader"));
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], CSV_HEADER.trim_end());
        assert_eq!(
            lines[1],
            "2026-11-20T03:04:05Z,High,Active,Suspicious secret listing and query in a key vault,KV_ListGetAnomaly,kv-a,Prod,CredentialAccess,kv-a,https://portal.azure.com/#blade/alert/1"
        );
        assert_eq!(lines[2], ",,NOT READ,You don't have Security Reader,,,,,,");
        assert_eq!(lines[2].split(',').count(), CSV_COLUMNS);
    }
}
