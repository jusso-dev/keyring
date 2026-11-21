//! Multi-environment grouping, parity matrix and cross-environment helpers.
//!
//! Pure functions over Azure Resource Graph vault metadata and Key Vault item
//! lists (names and properties only, never values). Nothing is stored outside
//! Azure: environment labels and groups come from each vault's ARM tags, with
//! a fallback to common vault name suffixes such as `-dev`, `-test` and
//! `-prod`.

use std::collections::{BTreeMap, BTreeSet};

use crate::age;
use crate::azure::secrets::ExpiryState;
use crate::azure::vaults::Vault;
use crate::dates;
use crate::expiry::{Item, ItemType, csv_field};
use crate::owner::{self, Display as OwnerDisplay, OfItem};
use crate::reveal_limit::{self, Limit};
use crate::secret::Secret;

/// Most vaults compared side by side on the Environments page or written at
/// once on the multi-environment set form. Keeps the table readable and
/// Azure calls bounded.
pub const MAX_COMPARE_VAULTS: usize = 8;

/// Vault ARM tag names checked for an environment label, in priority order.
const ENV_TAGS: [&str; 4] = ["keyring-env", "env", "environment", "stage"];

/// Vault ARM tag names checked for a workload or application group, in
/// priority order.
const GROUP_TAGS: [&str; 6] = [
    "keyring-group",
    "app",
    "application",
    "service",
    "workload",
    "system",
];

/// Common vault name suffixes mapped to their normalised environment label.
const NAME_SUFFIXES: [(&str, &str); 15] = [
    ("-development", "dev"),
    ("-dev", "dev"),
    ("-testing", "test"),
    ("-test", "test"),
    ("-tst", "test"),
    ("-sit", "sit"),
    ("-qa", "qa"),
    ("-uat", "uat"),
    ("-staging", "staging"),
    ("-stage", "stage"),
    ("-preprod", "preprod"),
    ("-ppd", "preprod"),
    ("-production", "prod"),
    ("-prod", "prod"),
    ("-prd", "prod"),
];

/// A vault's environment label, from its ARM tags or inferred from its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvLabel {
    /// Display label, such as `dev`, `test`, `prod`, or empty when unknown.
    pub name: String,
    /// True when inferred from the vault name rather than an explicit ARM tag.
    pub inferred: bool,
}

impl EnvLabel {
    /// Read a vault's environment from its ARM tags, or infer it from a
    /// standard suffix on the vault name.
    pub fn of(vault: &Vault) -> Self {
        if let Some(val) = first_tag(&vault.tags, &ENV_TAGS) {
            return Self {
                name: val,
                inferred: false,
            };
        }
        if let Some((_, env)) = split_name_suffix(&vault.name) {
            return Self {
                name: env.to_owned(),
                inferred: true,
            };
        }
        Self {
            name: String::new(),
            inferred: false,
        }
    }

    /// True when the label names a production environment.
    pub fn is_production(&self) -> bool {
        matches!(
            self.name.to_ascii_lowercase().as_str(),
            "prod" | "prd" | "production" | "live"
        )
    }

    /// True when no environment tag or standard suffix was found.
    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
    }

    /// Ordering rank so columns read left-to-right from lowest to highest
    /// environment: dev -> test/sit/qa -> uat/staging/preprod -> prod -> dr.
    pub fn rank(&self) -> u8 {
        match self.name.to_ascii_lowercase().as_str() {
            "local" | "sandbox" | "sbx" => 5,
            "dev" | "development" => 10,
            "test" | "tst" | "testing" | "qa" | "sit" => 20,
            "uat" | "stage" | "staging" | "preprod" | "ppd" | "nonprod" => 30,
            "prod" | "prd" | "production" | "live" => 40,
            "dr" | "recovery" => 50,
            "" => 70,
            _ => 60,
        }
    }

    /// Short display text, or `"Unlabelled"` when none was found.
    pub fn display(&self) -> &str {
        if self.name.is_empty() {
            "Unlabelled"
        } else {
            &self.name
        }
    }
}

/// One vault with its resolved environment label and optional group key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVault {
    pub vault: Vault,
    pub env: EnvLabel,
    pub group: Option<String>,
}

impl EnvVault {
    pub fn from_vault(vault: Vault) -> Self {
        let env = EnvLabel::of(&vault);
        let group = group_of(&vault);
        Self { vault, env, group }
    }
}

/// A set of vaults belonging to the same workload across environments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvGroup {
    /// Group key (e.g. `payments` or `kv-payments`).
    pub name: String,
    /// True when grouped by an explicit ARM tag (`app`, `service`,
    /// `keyring-group`, etc.); false when grouped by vault name prefix.
    pub tagged: bool,
    /// Vaults in promotion order (dev -> test -> prod), capped to
    /// [`MAX_COMPARE_VAULTS`] only when selected for comparison.
    pub vaults: Vec<EnvVault>,
}

/// Find the first non-empty ARM tag matching any key in `candidates` (ignoring
/// case).
fn first_tag(tags: &BTreeMap<String, String>, candidates: &[&str]) -> Option<String> {
    for want in candidates {
        if let Some((_, v)) = tags.iter().find(|(k, _)| k.eq_ignore_ascii_case(want)) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

/// Split `<prefix>-<env>` on a known environment suffix, ignoring case.
fn split_name_suffix(name: &str) -> Option<(&str, &'static str)> {
    let lower = name.to_ascii_lowercase();
    for (suffix, env) in NAME_SUFFIXES {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            let prefix = &name[..name.len() - suffix.len()];
            if !prefix.is_empty() {
                return Some((prefix, env));
            }
        }
    }
    // Also recognise `-dr` when it follows a non-empty prefix.
    if lower.ends_with("-dr") && name.len() > 3 {
        return Some((&name[..name.len() - 3], "dr"));
    }
    None
}

/// Group key for a vault: explicit group tag first, otherwise the prefix
/// before a standard environment suffix.
fn group_of(vault: &Vault) -> Option<String> {
    if let Some(tag) = first_tag(&vault.tags, &GROUP_TAGS) {
        return Some(tag);
    }
    split_name_suffix(&vault.name).map(|(prefix, _)| prefix.to_owned())
}

/// Sort vaults in environment promotion order (`dev` -> `test` -> `prod`),
/// breaking ties by environment name then vault name.
pub fn sort_env_vaults(vaults: &mut [EnvVault]) {
    vaults.sort_by(|a, b| {
        a.env
            .rank()
            .cmp(&b.env.rank())
            .then_with(|| {
                a.env
                    .name
                    .to_ascii_lowercase()
                    .cmp(&b.env.name.to_ascii_lowercase())
            })
            .then_with(|| {
                a.vault
                    .name
                    .to_ascii_lowercase()
                    .cmp(&b.vault.name.to_ascii_lowercase())
            })
    });
}

/// Discover environment groups from the vaults the person can see. Only
/// groups with at least two vaults are returned, sorted by group name.
pub fn discover_groups(vaults: &[Vault]) -> Vec<EnvGroup> {
    let mut by_key: BTreeMap<String, (String, bool, Vec<EnvVault>)> = BTreeMap::new();
    for v in vaults {
        let tagged = first_tag(&v.tags, &GROUP_TAGS).is_some();
        let ev = EnvVault::from_vault(v.clone());
        let Some(group) = ev.group.clone() else {
            continue;
        };
        let key = group.to_ascii_lowercase();
        let entry = by_key
            .entry(key)
            .or_insert_with(|| (group, tagged, Vec::new()));
        if tagged {
            entry.1 = true;
        }
        entry.2.push(ev);
    }
    let mut groups: Vec<EnvGroup> = by_key
        .into_values()
        .filter(|(_, _, members)| members.len() >= 2)
        .map(|(name, tagged, mut members)| {
            sort_env_vaults(&mut members);
            EnvGroup {
                name,
                tagged,
                vaults: members,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    groups
}

/// Find the environment group a given vault belongs to, if any.
pub fn group_for_vault(vaults: &[Vault], vault_name: &str) -> Option<EnvGroup> {
    discover_groups(vaults).into_iter().find(|g| {
        g.vaults
            .iter()
            .any(|v| v.vault.name.eq_ignore_ascii_case(vault_name))
    })
}

/// Summary status of one secret across the selected environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// Present in every readable environment, active, and consistent metadata.
    Complete,
    /// Missing from at least one readable environment.
    Missing,
    /// Expired, expiring within 30 days, disabled, or stale in at least one
    /// environment.
    Attention,
    /// Present in every readable environment and active, but content type,
    /// owner or reveal limit differs between environments.
    Drift,
}

impl Parity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "In sync",
            Self::Missing => "Missing in an environment",
            Self::Attention => "Needs attention",
            Self::Drift => "Metadata differs",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Missing => "missing",
            Self::Attention => "attention",
            Self::Drift => "drift",
        }
    }

    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Complete => "badge-ok",
            Self::Missing => "badge-error",
            Self::Attention | Self::Drift => "badge-warn",
        }
    }
}

/// One cell in the cross-environment matrix (one secret in one vault).
#[derive(Debug, Clone)]
pub enum CellState {
    Present(Box<PresentCell>),
    Missing,
    /// The vault couldn't be read (e.g. missing Key Vault Reader or firewall).
    NotRead,
}

#[derive(Debug, Clone)]
pub struct PresentCell {
    pub vault: String,
    pub enabled: bool,
    pub expiry: ExpiryState,
    pub not_yet_valid: bool,
    pub changed: String,
    pub changed_note: String,
    pub stale: String,
    pub expires: String,
    pub expires_note: String,
    pub content_type: String,
    pub type_shown: String,
    pub owners: OfItem,
    pub limit: Limit,
    pub tags: Vec<(String, String)>,
    pub description: String,
}

impl PresentCell {
    pub fn is_expired(&self) -> bool {
        self.expiry == ExpiryState::Expired
    }

    pub fn is_expiring(&self) -> bool {
        self.expiry == ExpiryState::Soon
    }

    pub fn needs_attention(&self) -> bool {
        !self.enabled || self.is_expired() || self.is_expiring() || !self.stale.is_empty()
    }

    pub fn status_text(&self) -> &'static str {
        if !self.enabled {
            "Disabled"
        } else if self.is_expired() {
            "Expired"
        } else if self.is_expiring() {
            "Expires within 30 days"
        } else if self.not_yet_valid {
            "Not active yet"
        } else if !self.stale.is_empty() {
            "Stale"
        } else {
            "Active"
        }
    }
}

/// One row of the cross-environment matrix (one secret name across columns).
#[derive(Debug, Clone)]
pub struct MatrixRow {
    pub name: String,
    pub parity: Parity,
    /// Human-readable notes when metadata differs across environments.
    pub drift_notes: Vec<String>,
    /// One cell per selected column vault, in the same order as `columns`.
    pub cells: Vec<CellState>,
    /// First vault that holds an enabled, copyable copy of this secret (not
    /// `keyring-reveal=none`), for quick "Copy from" links on missing cells.
    pub copy_source: Option<String>,
    /// Slug of a Keyring typed secret if any environment has it typed, so
    /// "Create" links pre-select the same type.
    pub type_slug: String,
    /// Lower-case search text covering the secret name, descriptions and tags.
    pub filter_text: String,
}

impl MatrixRow {
    pub fn drift_summary(&self) -> String {
        self.drift_notes.join("; ")
    }

    pub fn owned_by(&self, upn: Option<&str>) -> bool {
        self.cells.iter().any(|c| match c {
            CellState::Present(p) => p.owners.names(upn),
            _ => false,
        })
    }

    pub fn has_tag(&self, filter: &str) -> bool {
        let filter = filter.trim();
        if filter.is_empty() {
            return true;
        }
        self.cells.iter().any(|c| match c {
            CellState::Present(p) => crate::routes::tag_rows::matches_filter(filter, &p.tags),
            _ => false,
        })
    }
}

/// Summary counts across every row in the matrix (before filtering).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MatrixCounts {
    pub total: usize,
    pub complete: usize,
    pub missing: usize,
    pub attention: usize,
    pub drift: usize,
}

/// One vault column in the matrix.
#[derive(Debug, Clone)]
pub struct MatrixColumn {
    pub vault: String,
    pub env: EnvLabel,
    /// Set when the vault couldn't be read.
    pub read_error: Option<String>,
}

/// The built matrix ready for display or CSV export.
#[derive(Debug, Clone)]
pub struct Matrix {
    pub columns: Vec<MatrixColumn>,
    pub rows: Vec<MatrixRow>,
    pub counts: MatrixCounts,
}

fn secret_type_slug(content_type: &str) -> &'static str {
    use crate::secret_types::{ContentKind, classify};
    match classify((!content_type.is_empty()).then_some(content_type)) {
        ContentKind::Typed(t) => t.slug(),
        _ => "",
    }
}

fn type_shown(content_type: &str) -> String {
    use crate::secret_types::{ContentKind, classify};
    match classify((!content_type.is_empty()).then_some(content_type)) {
        ContentKind::Typed(t) => t.label().to_owned(),
        _ => content_type.to_owned(),
    }
}

fn expiry_state(expires: Option<i64>, now: i64) -> ExpiryState {
    match expires {
        None => ExpiryState::None,
        Some(e) if e <= now => ExpiryState::Expired,
        Some(e) if e - now <= 30 * 86_400 => ExpiryState::Soon,
        Some(_) => ExpiryState::Ok,
    }
}

fn limit_label(l: Limit) -> &'static str {
    match l {
        Limit::Open => "none",
        Limit::CopyOnly => "copy-only",
        Limit::NoReveal => "no-reveal",
    }
}

impl Matrix {
    /// Build the cross-environment secret matrix from the selected vaults and
    /// their read item lists. Certificate-managed backing secrets are omitted.
    pub(crate) fn build(
        columns: Vec<MatrixColumn>,
        items_by_vault: &BTreeMap<String, Vec<Item>>,
        now: i64,
        stale_after_days: u32,
    ) -> Self {
        // Index secrets by canonical lowercase name while preserving the first
        // seen casing for display.
        let mut by_name: BTreeMap<String, (String, BTreeMap<usize, &Item>)> = BTreeMap::new();
        for (col_idx, col) in columns.iter().enumerate() {
            if col.read_error.is_some() {
                continue;
            }
            let Some(items) = items_by_vault.get(&col.vault) else {
                continue;
            };
            for item in items {
                if item.kind != ItemType::Secret || item.managed {
                    continue;
                }
                let key = item.name.to_ascii_lowercase();
                let entry = by_name
                    .entry(key)
                    .or_insert_with(|| (item.name.clone(), BTreeMap::new()));
                entry.1.insert(col_idx, item);
            }
        }

        let mut rows = Vec::with_capacity(by_name.len());
        let mut counts = MatrixCounts::default();

        for (_, (display_name, present_map)) in by_name {
            let mut cells = Vec::with_capacity(columns.len());
            let mut has_missing = false;
            let mut has_attention = false;
            let mut copy_source: Option<String> = None;
            let mut type_slug = String::new();
            let mut filter_parts = vec![display_name.to_ascii_lowercase()];

            let mut distinct_types: BTreeSet<String> = BTreeSet::new();
            let mut distinct_owners: BTreeSet<String> = BTreeSet::new();
            let mut distinct_limits: BTreeSet<&'static str> = BTreeSet::new();
            let mut distinct_enabled: BTreeSet<bool> = BTreeSet::new();
            let mut present_count = 0usize;

            for (col_idx, col) in columns.iter().enumerate() {
                if col.read_error.is_some() {
                    cells.push(CellState::NotRead);
                    continue;
                }
                match present_map.get(&col_idx) {
                    None => {
                        has_missing = true;
                        cells.push(CellState::Missing);
                    }
                    Some(item) => {
                        present_count += 1;
                        let tag_map: BTreeMap<String, String> = item.tags.iter().cloned().collect();
                        let owners = OfItem::of(&tag_map);
                        let limit = reveal_limit::of(&tag_map);
                        let exp = expiry_state(item.expires, now);
                        let stale = age::stale_badge(item.created, false, stale_after_days, now);
                        let description = item.description().to_owned();
                        let cell = PresentCell {
                            vault: col.vault.clone(),
                            enabled: item.enabled,
                            expiry: exp,
                            not_yet_valid: item.not_before.is_some_and(|n| n > now),
                            changed: item.created.map(dates::format_date).unwrap_or_default(),
                            changed_note: item
                                .created
                                .map(|c| dates::relative_days(c, now))
                                .unwrap_or_default(),
                            stale,
                            expires: item.expires.map(dates::format_date).unwrap_or_default(),
                            expires_note: item
                                .expires
                                .map(|e| dates::relative_days(e, now))
                                .unwrap_or_default(),
                            content_type: item.content_type.clone(),
                            type_shown: type_shown(&item.content_type),
                            owners: owners.clone(),
                            limit,
                            tags: item.tags.clone(),
                            description: description.clone(),
                        };
                        if cell.needs_attention() {
                            has_attention = true;
                        }
                        if copy_source.is_none() && cell.enabled && !cell.limit.refuses_reveal() {
                            copy_source = Some(col.vault.clone());
                        }
                        if type_slug.is_empty() {
                            let s = secret_type_slug(&item.content_type);
                            if !s.is_empty() {
                                type_slug = s.to_owned();
                            }
                        }
                        if !description.is_empty() {
                            filter_parts.push(description.to_ascii_lowercase());
                        }
                        for (k, v) in &item.tags {
                            filter_parts.push(format!("{k}={v}").to_ascii_lowercase());
                        }
                        distinct_types.insert(cell.type_shown.to_ascii_lowercase());
                        distinct_owners.insert(owners.owner.to_ascii_lowercase());
                        distinct_limits.insert(limit_label(limit));
                        distinct_enabled.insert(cell.enabled);
                        cells.push(CellState::Present(Box::new(cell)));
                    }
                }
            }

            let mut drift_notes = Vec::new();
            if present_count >= 2 {
                if distinct_types.len() > 1 {
                    drift_notes.push("Content type differs".to_owned());
                }
                if distinct_owners.len() > 1 {
                    drift_notes.push("Owner differs".to_owned());
                }
                if distinct_limits.len() > 1 {
                    drift_notes.push("Reveal limit differs".to_owned());
                }
                if distinct_enabled.len() > 1 {
                    drift_notes.push("Enabled state differs".to_owned());
                }
            }

            let parity = if has_missing {
                counts.missing += 1;
                Parity::Missing
            } else if has_attention {
                counts.attention += 1;
                Parity::Attention
            } else if !drift_notes.is_empty() {
                counts.drift += 1;
                Parity::Drift
            } else {
                counts.complete += 1;
                Parity::Complete
            };
            counts.total += 1;

            rows.push(MatrixRow {
                name: display_name,
                parity,
                drift_notes,
                cells,
                copy_source,
                type_slug,
                filter_text: filter_parts.join(" "),
            });
        }

        // Order: missing first, then attention, then drift, then complete;
        // alphabetical within each group so problems sit at the top.
        rows.sort_by(|a, b| {
            parity_order(a.parity)
                .cmp(&parity_order(b.parity))
                .then_with(|| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                })
        });

        Self {
            columns,
            rows,
            counts,
        }
    }

    /// Export the matrix to CSV (names and properties only, never values).
    pub fn to_csv(&self) -> String {
        let mut header = vec![
            "Secret".to_owned(),
            "Parity".to_owned(),
            "Drift notes".to_owned(),
        ];
        for col in &self.columns {
            let env = if col.env.is_empty() {
                col.vault.clone()
            } else {
                format!("{} ({})", col.vault, col.env.name)
            };
            header.push(csv_field(&format!("{env} status")));
            header.push(csv_field(&format!("{env} value changed (UTC)")));
            header.push(csv_field(&format!("{env} expires (UTC)")));
            header.push(csv_field(&format!("{env} owner")));
        }
        let mut out = header.join(",");
        out.push_str("\r\n");

        for row in &self.rows {
            let mut fields = vec![
                csv_field(&row.name),
                csv_field(row.parity.label()),
                csv_field(&row.drift_summary()),
            ];
            for cell in &row.cells {
                match cell {
                    CellState::Present(p) => {
                        fields.push(csv_field(p.status_text()));
                        fields.push(csv_field(&p.changed));
                        fields.push(csv_field(&p.expires));
                        fields.push(csv_field(&p.owners.owner));
                    }
                    CellState::Missing => {
                        fields.push("Missing".to_owned());
                        fields.push(String::new());
                        fields.push(String::new());
                        fields.push(String::new());
                    }
                    CellState::NotRead => {
                        fields.push("NOT READ".to_owned());
                        fields.push(String::new());
                        fields.push(String::new());
                        fields.push(String::new());
                    }
                }
            }
            out.push_str(&fields.join(","));
            out.push_str("\r\n");
        }

        // Append a NOT READ summary line for any vault that couldn't be read,
        // so the export is never mistaken for a complete report.
        for col in &self.columns {
            if let Some(why) = &col.read_error {
                let mut fields = vec![csv_field(&col.vault), "NOT READ".to_owned(), csv_field(why)];
                fields.resize(header.len(), String::new());
                out.push_str(&fields.join(","));
                out.push_str("\r\n");
            }
        }
        out
    }
}

fn parity_order(p: Parity) -> u8 {
    match p {
        Parity::Missing => 0,
        Parity::Attention => 1,
        Parity::Drift => 2,
        Parity::Complete => 3,
    }
}

/// One row of the "Across environments" card on a secret's detail page.
#[derive(Debug, Clone)]
pub struct SiblingEnv {
    pub vault: String,
    pub env: EnvLabel,
    pub is_current: bool,
    pub state: CellState,
}

impl SiblingEnv {
    pub fn owner_display(&self) -> OwnerDisplay {
        match &self.state {
            CellState::Present(p) => p.owners.owner_shown(),
            _ => owner::Display::default(),
        }
    }
}

/// Duplicate values detected across environment inputs (names of vaults only,
/// never the values themselves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateGroup {
    pub vaults: Vec<String>,
    pub includes_production: bool,
}

/// Check non-empty values entered across multiple environments for accidental
/// reuse (especially reusing a dev/test secret value in production). Operates
/// on [`Secret`] in memory and returns only the vault names, never any value.
pub fn find_duplicate_values<'a>(entries: &[(&'a str, bool, &'a Secret)]) -> Vec<DuplicateGroup> {
    let mut visited = vec![false; entries.len()];
    let mut groups = Vec::new();
    for i in 0..entries.len() {
        if visited[i] {
            continue;
        }
        let val_i = entries[i].2.expose();
        if val_i.is_empty() {
            continue;
        }
        let mut group = vec![entries[i].0.to_owned()];
        let mut prod = entries[i].1;
        for j in (i + 1)..entries.len() {
            if !visited[j] && entries[j].2.expose() == val_i {
                visited[j] = true;
                group.push(entries[j].0.to_owned());
                prod |= entries[j].1;
            }
        }
        if group.len() >= 2 {
            visited[i] = true;
            groups.push(DuplicateGroup {
                vaults: group,
                includes_production: prod,
            });
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::vaults::HealthProps;

    fn vault(name: &str, tags: &[(&str, &str)]) -> Vault {
        Vault {
            id: format!(
                "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}"
            ),
            name: name.into(),
            resource_group: "rg".into(),
            subscription_id: "s".into(),
            subscription_name: "Sub".into(),
            location: "australiaeast".into(),
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            rbac: true,
            soft_delete: true,
            purge_protection: true,
            health: HealthProps::default(),
        }
    }

    fn secret(
        vault: &str,
        name: &str,
        enabled: bool,
        exp: Option<i64>,
        tags: &[(&str, &str)],
    ) -> Item {
        Item {
            vault: vault.into(),
            kind: ItemType::Secret,
            name: name.into(),
            enabled,
            expires: exp,
            not_before: None,
            created: Some(1_790_000_000),
            content_type: "text/plain".into(),
            managed: false,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        }
    }

    #[test]
    fn env_label_prefers_tags_then_infers_from_name() {
        let tagged = vault("kv-alpha", &[("env", "staging")]);
        assert_eq!(
            EnvLabel::of(&tagged),
            EnvLabel {
                name: "staging".into(),
                inferred: false
            }
        );

        let keyring_env = vault("kv-alpha-dev", &[("keyring-env", "prod"), ("env", "dev")]);
        let l = EnvLabel::of(&keyring_env);
        assert_eq!(l.name, "prod");
        assert!(!l.inferred);
        assert!(l.is_production());

        let inferred = vault("kv-payments-prod", &[]);
        let l = EnvLabel::of(&inferred);
        assert_eq!(l.name, "prod");
        assert!(l.inferred);
        assert!(l.is_production());

        let unknown = vault("kv-shared", &[]);
        assert!(EnvLabel::of(&unknown).is_empty());
    }

    #[test]
    fn discovers_groups_in_promotion_order() {
        let vaults = vec![
            vault("kv-payments-prod", &[("app", "payments"), ("env", "prod")]),
            vault("kv-payments-dev", &[("app", "payments"), ("env", "dev")]),
            vault("kv-payments-test", &[("app", "payments"), ("env", "test")]),
            vault("kv-billing-prod", &[]),
            vault("kv-billing-dev", &[]),
            vault("kv-solo", &[]),
        ];
        let groups = discover_groups(&vaults);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "kv-billing");
        assert!(!groups[0].tagged);
        assert_eq!(
            groups[0]
                .vaults
                .iter()
                .map(|v| v.vault.name.as_str())
                .collect::<Vec<_>>(),
            vec!["kv-billing-dev", "kv-billing-prod"]
        );
        assert_eq!(groups[1].name, "payments");
        assert!(groups[1].tagged);
        assert_eq!(
            groups[1]
                .vaults
                .iter()
                .map(|v| v.vault.name.as_str())
                .collect::<Vec<_>>(),
            vec!["kv-payments-dev", "kv-payments-test", "kv-payments-prod"]
        );
    }

    #[test]
    fn matrix_detects_missing_attention_and_drift() {
        let now = 1_790_000_000 + 10 * 86_400;
        let cols = vec![
            MatrixColumn {
                vault: "kv-pay-dev".into(),
                env: EnvLabel {
                    name: "dev".into(),
                    inferred: false,
                },
                read_error: None,
            },
            MatrixColumn {
                vault: "kv-pay-prod".into(),
                env: EnvLabel {
                    name: "prod".into(),
                    inferred: false,
                },
                read_error: None,
            },
        ];
        let mut items = BTreeMap::new();
        items.insert(
            "kv-pay-dev".into(),
            vec![
                secret(
                    "kv-pay-dev",
                    "only-in-dev",
                    true,
                    None,
                    &[("owner", "a@e.com")],
                ),
                secret(
                    "kv-pay-dev",
                    "in-sync",
                    true,
                    Some(now + 100 * 86_400),
                    &[("owner", "a@e.com")],
                ),
                secret(
                    "kv-pay-dev",
                    "owner-drift",
                    true,
                    None,
                    &[("owner", "a@e.com")],
                ),
                secret(
                    "kv-pay-dev",
                    "expiring-prod",
                    true,
                    Some(now + 100 * 86_400),
                    &[],
                ),
            ],
        );
        items.insert(
            "kv-pay-prod".into(),
            vec![
                secret(
                    "kv-pay-prod",
                    "in-sync",
                    true,
                    Some(now + 100 * 86_400),
                    &[("owner", "a@e.com")],
                ),
                secret(
                    "kv-pay-prod",
                    "owner-drift",
                    true,
                    None,
                    &[("owner", "b@e.com")],
                ),
                secret(
                    "kv-pay-prod",
                    "expiring-prod",
                    true,
                    Some(now + 5 * 86_400),
                    &[],
                ),
            ],
        );

        let m = Matrix::build(cols, &items, now, 365);
        assert_eq!(m.counts.total, 4);
        assert_eq!(m.counts.missing, 1);
        assert_eq!(m.counts.attention, 1);
        assert_eq!(m.counts.drift, 1);
        assert_eq!(m.counts.complete, 1);
        // Sorted: missing, attention, drift, complete.
        assert_eq!(m.rows[0].name, "only-in-dev");
        assert_eq!(m.rows[0].parity, Parity::Missing);
        assert_eq!(m.rows[0].copy_source.as_deref(), Some("kv-pay-dev"));
        assert_eq!(m.rows[1].name, "expiring-prod");
        assert_eq!(m.rows[1].parity, Parity::Attention);
        assert_eq!(m.rows[2].name, "owner-drift");
        assert_eq!(m.rows[2].parity, Parity::Drift);
        assert!(m.rows[2].drift_summary().contains("Owner differs"));
        assert_eq!(m.rows[3].name, "in-sync");
        assert_eq!(m.rows[3].parity, Parity::Complete);

        let csv = m.to_csv();
        assert!(csv.contains("only-in-dev,Missing in an environment"));
        assert!(csv.contains("Missing"));
    }

    #[test]
    fn duplicate_value_check_flags_shared_secrets_without_leaking_values() {
        let s1 = Secret::new("same-secret-123");
        let s2 = Secret::new("same-secret-123");
        let s3 = Secret::new("unique-secret-456");
        let dupes = find_duplicate_values(&[
            ("kv-pay-dev", false, &s1),
            ("kv-pay-prod", true, &s2),
            ("kv-pay-test", false, &s3),
        ]);
        assert_eq!(dupes.len(), 1);
        assert_eq!(dupes[0].vaults, vec!["kv-pay-dev", "kv-pay-prod"]);
        assert!(dupes[0].includes_production);
    }
}
