//! Vault health: how each vault is set up, as pass, warn or unknown.
//!
//! The checks are plain functions over what was read, so they can be
//! tested without Azure. A check that couldn't be read is Unknown with the
//! reason, never a pass.

use crate::azure::audit::AuditSinks;
use crate::azure::vaults::Vault;
use crate::expiry::csv_field;

/// The result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Pass,
    Warn,
    Unknown,
}

impl Status {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Warn => "Warn",
            Self::Unknown => "Unknown",
        }
    }

    /// The badge class (design.md, Badges).
    pub(crate) fn css(self) -> &'static str {
        match self {
            Self::Pass => "badge-ok",
            Self::Warn => "badge-warn",
            Self::Unknown => "badge-muted",
        }
    }
}

/// The checks, in the order they're shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    AuditLogs,
    Rbac,
    SoftDelete,
    PurgeProtection,
    Network,
    PrivateEndpoint,
    SecretExpiry,
    CertRenewal,
    KeyRotation,
    Owners,
}

impl Kind {
    pub(crate) const ALL: [Kind; 10] = [
        Kind::AuditLogs,
        Kind::Rbac,
        Kind::SoftDelete,
        Kind::PurgeProtection,
        Kind::Network,
        Kind::PrivateEndpoint,
        Kind::SecretExpiry,
        Kind::CertRenewal,
        Kind::KeyRotation,
        Kind::Owners,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::AuditLogs => "Audit logs",
            Self::Rbac => "Azure RBAC",
            Self::SoftDelete => "Soft delete",
            Self::PurgeProtection => "Purge protection",
            Self::Network => "Network access",
            Self::PrivateEndpoint => "Private endpoint",
            Self::SecretExpiry => "Secret expiry",
            Self::CertRenewal => "Certificate renewal",
            Self::KeyRotation => "Key rotation",
            Self::Owners => "Owners",
        }
    }

    /// True for the checks read from the vault itself or its diagnostic
    /// settings, rather than from Resource Graph.
    pub(crate) fn needs_read(self) -> bool {
        matches!(
            self,
            Self::AuditLogs | Self::SecretExpiry | Self::CertRenewal | Self::KeyRotation
        )
    }

    /// Microsoft's guide for the setting.
    pub(crate) fn guide(self) -> &'static str {
        match self {
            Self::AuditLogs => "https://learn.microsoft.com/azure/key-vault/general/logging",
            Self::Rbac => "https://learn.microsoft.com/azure/key-vault/general/rbac-migration",
            Self::SoftDelete => {
                "https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview"
            }
            Self::PurgeProtection => {
                "https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview#purge-protection"
            }
            Self::Network => "https://learn.microsoft.com/azure/key-vault/general/network-security",
            Self::PrivateEndpoint => {
                "https://learn.microsoft.com/azure/key-vault/general/private-link-service"
            }
            Self::SecretExpiry => {
                "https://learn.microsoft.com/azure/key-vault/secrets/secrets-best-practices"
            }
            Self::CertRenewal => {
                "https://learn.microsoft.com/azure/key-vault/certificates/overview-renew-certificate"
            }
            Self::KeyRotation => {
                "https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation"
            }
            Self::Owners => {
                "https://learn.microsoft.com/azure/azure-resource-manager/management/tag-resources"
            }
        }
    }
}

/// One check on one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) kind: Kind,
    pub(crate) status: Status,
    /// For a warning: why it matters and what to do, in one sentence. For
    /// unknown: why it couldn't be checked. Empty for a pass.
    pub(crate) detail: String,
    /// A per-item check left for the one-vault view. Unknown, but not
    /// listed as something to look into.
    pub(crate) deferred: bool,
}

impl Finding {
    fn pass(kind: Kind) -> Self {
        Self {
            kind,
            status: Status::Pass,
            detail: String::new(),
            deferred: false,
        }
    }
    fn warn(kind: Kind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            status: Status::Warn,
            detail: detail.into(),
            deferred: false,
        }
    }
    fn unknown(kind: Kind, why: impl Into<String>) -> Self {
        Self {
            kind,
            status: Status::Unknown,
            detail: why.into(),
            deferred: false,
        }
    }
}

/// How many items in a vault fail a check, or why they couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Count {
    /// `failing` items fail the check. `unread` more couldn't be checked,
    /// for the reason given (a per-item call failed, ran out of time, or
    /// was past the cap).
    Read {
        failing: usize,
        unread: usize,
        unread_why: String,
    },
    /// Couldn't be read, with the reason in plain words.
    Failed(String),
    /// Left for the one-vault view.
    Deferred,
}

impl Count {
    pub(crate) fn all_read(failing: usize) -> Self {
        Self::Read {
            failing,
            unread: 0,
            unread_why: String::new(),
        }
    }
}

/// What was read from one vault, besides Resource Graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reads {
    /// Where audit logs go, or why the settings couldn't be read.
    pub(crate) audit: Result<AuditSinks, String>,
    pub(crate) secrets_without_expiry: Count,
    pub(crate) certs_not_renewing: Count,
    pub(crate) keys_without_rotation: Count,
    /// The vault wasn't read at all (too slow, out of time). The checks
    /// that need a read are Unknown with this reason as it stands.
    pub(crate) not_read: Option<String>,
}

impl Reads {
    /// Nothing beyond Resource Graph was read, for this reason.
    pub(crate) fn none(why: &str) -> Self {
        Self {
            audit: Err(why.to_owned()),
            secrets_without_expiry: Count::Failed(why.to_owned()),
            certs_not_renewing: Count::Failed(why.to_owned()),
            keys_without_rotation: Count::Failed(why.to_owned()),
            not_read: Some(why.to_owned()),
        }
    }
}

/// Words for a count check.
struct Words {
    /// "certificate", "certificates": what was listed.
    noun: (&'static str, &'static str),
    /// "1 key has no rotation policy", "3 keys have no rotation policy".
    failing: fn(usize) -> String,
    /// Why it matters and what to do, after a colon.
    fix: &'static str,
}

fn count_check(kind: Kind, c: &Count, w: &Words, deferred_why: &str) -> Finding {
    match c {
        Count::Deferred => Finding {
            deferred: true,
            ..Finding::unknown(kind, deferred_why)
        },
        Count::Failed(why) => Finding::unknown(
            kind,
            format!("Couldn't list its {}: {}", w.noun.1, lower_first(why)),
        ),
        Count::Read {
            failing,
            unread,
            unread_why,
        } => {
            let more = if *unread > 0 {
                format!(
                    " ({unread} more couldn't be checked: {})",
                    lower_first(unread_why)
                )
            } else {
                String::new()
            };
            if *failing > 0 {
                Finding::warn(kind, format!("{}{more}: {}", (w.failing)(*failing), w.fix))
            } else if *unread > 0 {
                let noun = if *unread == 1 { w.noun.0 } else { w.noun.1 };
                Finding::unknown(
                    kind,
                    format!(
                        "{unread} {noun} couldn't be checked: {}. The rest pass",
                        lower_first(unread_why)
                    ),
                )
            } else {
                Finding::pass(kind)
            }
        }
    }
}

/// "You don't have..." becomes "you don't have...", for a reason that
/// follows a colon. Names ("Azure", "Key Vault") keep their capital.
pub(crate) fn lower_first(s: &str) -> String {
    if s.starts_with("Azure") || s.starts_with("Key ") {
        return s.to_owned();
    }
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Every check for one vault.
pub(crate) fn assess(v: &Vault, r: &Reads) -> Vec<Finding> {
    let h = &v.health;
    let mut out = Vec::with_capacity(Kind::ALL.len());

    out.push(match &r.audit {
        Ok(s) if s.any == 0 => Finding::warn(
            Kind::AuditLogs,
            "No diagnostic setting sends its audit logs anywhere, so nobody can see who read or changed what: add one that sends the audit category to a Log Analytics workspace",
        ),
        Ok(_) => Finding::pass(Kind::AuditLogs),
        Err(why) => Finding::unknown(
            Kind::AuditLogs,
            format!("Couldn't read its diagnostic settings: {}", lower_first(why)),
        ),
    });

    out.push(if v.rbac {
        Finding::pass(Kind::Rbac)
    } else {
        Finding::warn(
            Kind::Rbac,
            "It uses access policies, which can't be scoped to one secret and are managed apart from your other Azure roles: move it to Azure RBAC",
        )
    });

    out.push(match h.soft_delete {
        Some(true) => Finding::pass(Kind::SoftDelete),
        Some(false) => Finding::warn(
            Kind::SoftDelete,
            "A deleted secret, certificate or key is gone at once and can't be recovered: turn soft delete on",
        ),
        None => Finding::unknown(
            Kind::SoftDelete,
            "Azure didn't say whether soft delete is on: check the vault's properties in the portal",
        ),
    });

    // Azure leaves enablePurgeProtection out until it's turned on, and it
    // can't be turned off, so missing means off.
    out.push(if v.purge_protection {
        Finding::pass(Kind::PurgeProtection)
    } else {
        Finding::warn(
            Kind::PurgeProtection,
            "Anyone allowed to purge can destroy a deleted item before its retention period ends: turn purge protection on (it can't be turned off again)",
        )
    });

    out.push(network(
        h.public_access.as_deref(),
        h.default_action.as_deref(),
    ));
    out.push(private_endpoint(&h.private_endpoints));

    out.push(count_check(
        Kind::SecretExpiry,
        &r.secrets_without_expiry,
        &Words {
            noun: ("secret", "secrets"),
            failing: |n| {
                if n == 1 {
                    "1 enabled secret has no expiry date".into()
                } else {
                    format!("{n} enabled secrets have no expiry date")
                }
            },
            fix: "nothing prompts anyone to change them, so set an expiry on each",
        },
        "",
    ));
    out.push(count_check(
        Kind::CertRenewal,
        &r.certs_not_renewing,
        &Words {
            noun: ("certificate", "certificates"),
            failing: |n| {
                if n == 1 {
                    "1 certificate doesn't renew automatically".into()
                } else {
                    format!("{n} certificates don't renew automatically")
                }
            },
            fix: "they lapse unless someone replaces them, so set them to renew or plan their replacement",
        },
        "Needs a call per certificate, so it's checked when you pick this vault on its own",
    ));
    out.push(count_check(
        Kind::KeyRotation,
        &r.keys_without_rotation,
        &Words {
            noun: ("key", "keys"),
            failing: |n| {
                if n == 1 {
                    "1 key has no rotation policy".into()
                } else {
                    format!("{n} keys have no rotation policy")
                }
            },
            fix: "they only change when someone rotates them by hand, so set a rotation policy on each",
        },
        "Needs a call per key, so it's checked when you pick this vault on its own",
    ));
    out.push(owners(&v.tags));
    if let Some(why) = &r.not_read {
        for f in out.iter_mut().filter(|f| f.kind.needs_read()) {
            *f = Finding::unknown(f.kind, why.clone());
        }
    }
    out
}

/// The vault's `keyring-owners` ARM tag names at least one address.
/// Keyring never sets it: it needs ARM write access Keyring doesn't ask for.
fn owners(tags: &std::collections::BTreeMap<String, String>) -> Finding {
    const WHERE: &str = "set the keyring-owners tag to their addresses, separated by commas, in the vault's Tags blade in the portal or with az tag update";
    match crate::owner::vault_tag(tags) {
        None => Finding::warn(
            Kind::Owners,
            format!(
                "It has no keyring-owners tag, so nobody is named to look after it or to ask for access: {WHERE}"
            ),
        ),
        Some(t) if t.trim().is_empty() => Finding::warn(
            Kind::Owners,
            format!(
                "Its keyring-owners tag is empty, so nobody is named to look after it or to ask for access: {WHERE}"
            ),
        ),
        Some(_) if crate::owner::vault_owners(tags).is_empty() => Finding::warn(
            Kind::Owners,
            format!(
                "Its keyring-owners tag holds no plain email address, so Keyring can't tell anyone about it: {WHERE}"
            ),
        ),
        Some(_) => Finding::pass(Kind::Owners),
    }
}

/// Public network access off, or the firewall denying by default, passes.
fn network(public_access: Option<&str>, default_action: Option<&str>) -> Finding {
    let eq = |a: Option<&str>, b: &str| a.is_some_and(|a| a.eq_ignore_ascii_case(b));
    if eq(public_access, "Disabled") || eq(default_action, "Deny") {
        return Finding::pass(Kind::Network);
    }
    // Azure's defaults: public access is Enabled and the firewall allows
    // everything when the vault doesn't say otherwise.
    let public_known = public_access.is_none() || eq(public_access, "Enabled");
    let action_known = default_action.is_none() || eq(default_action, "Allow");
    if public_known && action_known {
        return Finding::warn(
            Kind::Network,
            "Anyone on the internet can reach it, so only sign-in and roles stand in the way: turn public network access off or set the firewall to deny by default",
        );
    }
    let shown = [public_access, default_action]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
    Finding::unknown(
        Kind::Network,
        format!("Its network setting ({shown}) isn't one Keyring knows: check it in the portal"),
    )
}

fn private_endpoint(statuses: &[String]) -> Finding {
    if statuses.iter().any(|s| s.eq_ignore_ascii_case("Approved")) {
        return Finding::pass(Kind::PrivateEndpoint);
    }
    if statuses.is_empty() {
        return Finding::warn(
            Kind::PrivateEndpoint,
            "It has no private endpoint, so apps in your Azure networks reach it over its public address: add a private endpoint",
        );
    }
    let shown: Vec<&str> = statuses
        .iter()
        .map(|s| {
            if s.is_empty() {
                "no status"
            } else {
                s.as_str()
            }
        })
        .collect();
    Finding::warn(
        Kind::PrivateEndpoint,
        format!(
            "None of its private endpoints is approved ({}), so none carries traffic: approve one or remove them",
            shown.join(", ")
        ),
    )
}

/// One vault's row: its name and where it lives, then each check.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub(crate) vault: String,
    pub(crate) subscription: String,
    pub(crate) resource_group: String,
    /// The `keyring-owners` ARM tag, for the page.
    pub(crate) owners: crate::owner::Display,
    pub(crate) findings: Vec<Finding>,
}

impl Row {
    pub(crate) fn new(v: &Vault, r: &Reads) -> Self {
        Self {
            vault: v.name.clone(),
            subscription: v.subscription_name.clone(),
            resource_group: v.resource_group.clone(),
            owners: crate::owner::vault_display(&v.tags),
            findings: assess(v, r),
        }
    }
}

/// CSV, one line per vault and check. Every text field is formula-guarded.
pub(crate) fn to_csv(rows: &[Row]) -> String {
    let mut out =
        String::from("Vault,Subscription,Resource group,Owners,Check,Result,Detail,Guide\r\n");
    for r in rows {
        for f in &r.findings {
            let line = [
                csv_field(&r.vault),
                csv_field(&r.subscription),
                csv_field(&r.resource_group),
                csv_field(&owners_text(r)),
                f.kind.label().to_owned(),
                f.status.label().to_owned(),
                csv_field(&f.detail),
                if f.status == Status::Pass {
                    String::new()
                } else {
                    f.kind.guide().to_owned()
                },
            ];
            out.push_str(&line.join(","));
            out.push_str("\r\n");
        }
    }
    out
}

/// A vault's named owners for the CSV: every entry, separated by "; ".
fn owners_text(r: &Row) -> String {
    r.owners
        .entries
        .iter()
        .map(|e| e.text())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A line for something the export leaves out, so it can't pass for a
/// full report. `NOT READ` sits in the Result column.
pub(crate) fn not_read_row(vault: &str, reason: &str) -> String {
    format!(
        "{},,,,,NOT READ,{},\r\n",
        csv_field(vault),
        csv_field(reason)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::vaults::HealthProps;

    fn vault() -> Vault {
        Vault {
            id: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv".into(),
            name: "kv".into(),
            resource_group: "rg".into(),
            subscription_id: "s".into(),
            subscription_name: "Prod".into(),
            location: "australiaeast".into(),
            tags: [("keyring-owners".to_owned(), "ops@example.com".to_owned())].into(),
            rbac: true,
            soft_delete: true,
            purge_protection: true,
            health: HealthProps {
                soft_delete: Some(true),
                public_access: Some("Disabled".into()),
                default_action: Some("Deny".into()),
                private_endpoints: vec!["Approved".into()],
            },
        }
    }

    const SINKS: AuditSinks = AuditSinks {
        any: 1,
        workspaces: 0,
    };
    const NO_SINKS: AuditSinks = AuditSinks {
        any: 0,
        workspaces: 0,
    };

    fn reads() -> Reads {
        Reads {
            audit: Ok(SINKS),
            secrets_without_expiry: Count::all_read(0),
            certs_not_renewing: Count::all_read(0),
            keys_without_rotation: Count::all_read(0),
            not_read: None,
        }
    }

    fn get(v: &Vault, r: &Reads, k: Kind) -> Finding {
        assess(v, r).into_iter().find(|f| f.kind == k).unwrap()
    }

    #[test]
    fn a_well_set_vault_passes_everything() {
        let f = assess(&vault(), &reads());
        assert_eq!(f.len(), Kind::ALL.len());
        assert!(f.iter().all(|f| f.status == Status::Pass), "{f:?}");
    }

    #[test]
    fn audit_logs() {
        let mut r = reads();
        r.audit = Ok(NO_SINKS);
        let f = get(&vault(), &r, Kind::AuditLogs);
        assert_eq!(f.status, Status::Warn);
        assert!(f.detail.contains("audit category"));
        r.audit = Err("You need Reader on the vault".into());
        let f = get(&vault(), &r, Kind::AuditLogs);
        assert_eq!(f.status, Status::Unknown);
        assert_eq!(
            f.detail,
            "Couldn't read its diagnostic settings: you need Reader on the vault"
        );
    }

    #[test]
    fn access_model_soft_delete_and_purge_protection() {
        let mut v = vault();
        v.rbac = false;
        v.purge_protection = false;
        v.health.soft_delete = Some(false);
        assert_eq!(get(&v, &reads(), Kind::Rbac).status, Status::Warn);
        assert_eq!(
            get(&v, &reads(), Kind::PurgeProtection).status,
            Status::Warn
        );
        assert_eq!(get(&v, &reads(), Kind::SoftDelete).status, Status::Warn);
        v.health.soft_delete = None;
        assert_eq!(
            get(&v, &reads(), Kind::SoftDelete).status,
            Status::Unknown,
            "never a guessed pass"
        );
    }

    #[test]
    fn network_access() {
        let s = |p: Option<&str>, d: Option<&str>| network(p, d).status;
        assert_eq!(s(Some("Disabled"), None), Status::Pass);
        assert_eq!(s(Some("Enabled"), Some("Deny")), Status::Pass);
        assert_eq!(s(None, Some("deny")), Status::Pass);
        assert_eq!(s(Some("Enabled"), Some("Allow")), Status::Warn);
        assert_eq!(s(None, None), Status::Warn, "Azure's default is open");
        assert_eq!(s(Some("SecuredByPerimeter"), None), Status::Unknown);
        assert!(
            network(Some("SecuredByPerimeter"), None)
                .detail
                .contains("SecuredByPerimeter")
        );
    }

    #[test]
    fn private_endpoints() {
        let s = |v: &[&str]| {
            private_endpoint(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).status
        };
        assert_eq!(s(&["Pending", "Approved"]), Status::Pass);
        assert_eq!(s(&[]), Status::Warn);
        assert_eq!(s(&["Pending", ""]), Status::Warn);
        assert!(
            private_endpoint(&["Rejected".into()])
                .detail
                .contains("Rejected")
        );
    }

    #[test]
    fn content_counts() {
        let mut r = reads();
        r.secrets_without_expiry = Count::all_read(1);
        r.certs_not_renewing = Count::all_read(3);
        r.keys_without_rotation = Count::Failed("You don't have a Key Vault role on it".into());
        let f = assess(&vault(), &r);
        let by = |k: Kind| f.iter().find(|x| x.kind == k).unwrap();
        assert_eq!(by(Kind::SecretExpiry).status, Status::Warn);
        assert!(
            by(Kind::SecretExpiry)
                .detail
                .starts_with("1 enabled secret has")
        );
        assert!(
            by(Kind::CertRenewal)
                .detail
                .starts_with("3 certificates don't")
        );
        let k = by(Kind::KeyRotation);
        assert_eq!(k.status, Status::Unknown);
        assert_eq!(
            k.detail,
            "Couldn't list its keys: you don't have a Key Vault role on it"
        );
    }

    #[test]
    fn partly_read_counts_are_never_a_pass() {
        let mut r = reads();
        r.keys_without_rotation = Count::Read {
            failing: 0,
            unread: 2,
            unread_why: "Took too long to answer".into(),
        };
        let f = get(&vault(), &r, Kind::KeyRotation);
        assert_eq!(f.status, Status::Unknown);
        assert_eq!(
            f.detail,
            "2 keys couldn't be checked: took too long to answer. The rest pass"
        );
        r.keys_without_rotation = Count::Read {
            failing: 1,
            unread: 1,
            unread_why: "Took too long to answer".into(),
        };
        let f = get(&vault(), &r, Kind::KeyRotation);
        assert_eq!(f.status, Status::Warn);
        assert!(f.detail.contains("(1 more couldn't be checked"));
    }

    #[test]
    fn deferred_checks_are_unknown_and_marked() {
        let mut r = reads();
        r.certs_not_renewing = Count::Deferred;
        let f = get(&vault(), &r, Kind::CertRenewal);
        assert_eq!(f.status, Status::Unknown);
        assert!(f.deferred);
        assert!(f.detail.contains("pick this vault"));
    }

    #[test]
    fn nothing_read_leaves_the_resource_graph_checks() {
        let f = assess(&vault(), &Reads::none("Took too long to answer"));
        for x in &f {
            if x.kind.needs_read() {
                assert_eq!(x.status, Status::Unknown, "{:?}", x.kind);
                assert_eq!(x.detail, "Took too long to answer");
                assert!(!x.deferred);
            } else {
                assert_eq!(x.status, Status::Pass, "{:?}", x.kind);
            }
        }
    }

    #[test]
    fn csv_guards_formulas_and_links_guides() {
        let mut v = vault();
        v.name = "=cmd".into();
        v.resource_group = "+rg".into();
        v.rbac = false;
        let csv = to_csv(&[Row::new(&v, &reads())]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "Vault,Subscription,Resource group,Owners,Check,Result,Detail,Guide"
        );
        assert_eq!(lines.len(), 1 + Kind::ALL.len());
        assert!(lines[1].starts_with("'=cmd,Prod,'+rg,"), "{}", lines[1]);
        assert!(lines[1].contains(",Audit logs,Pass,,"), "{}", lines[1]);
        let rbac = lines.iter().find(|l| l.contains(",Azure RBAC,")).unwrap();
        assert!(rbac.contains(",Warn,"));
        assert!(rbac.ends_with(Kind::Rbac.guide()));
        assert_eq!(not_read_row("-x", "a, b"), "'-x,,,,,NOT READ,\"a, b\",\r\n");
    }

    #[test]
    fn vault_owners_tag() {
        let mut v = vault();
        let r = reads();
        v.tags.clear();
        let f = get(&v, &r, Kind::Owners);
        assert_eq!(f.status, Status::Warn);
        assert!(f.detail.contains("no keyring-owners tag") && f.detail.contains("az tag update"));
        v.tags.insert("keyring-owners".into(), "  ".into());
        assert!(get(&v, &r, Kind::Owners).detail.contains("is empty"));
        v.tags
            .insert("keyring-owners".into(), "Platform team".into());
        assert!(get(&v, &r, Kind::Owners).detail.contains("no plain email"));
        v.tags.insert(
            "keyring-owners".into(),
            "Platform team, ops@example.com".into(),
        );
        assert_eq!(get(&v, &r, Kind::Owners).status, Status::Pass);
        // ARM tag names ignore case.
        v.tags.clear();
        v.tags
            .insert("Keyring-Owners".into(), "ops@example.com".into());
        assert_eq!(get(&v, &r, Kind::Owners).status, Status::Pass);
        // Read from Resource Graph, so a vault not read still has it.
        assert_eq!(
            get(&v, &Reads::none("slow"), Kind::Owners).status,
            Status::Pass
        );
    }

    #[test]
    fn warnings_are_one_sentence_without_em_dashes() {
        let mut v = vault();
        v.rbac = false;
        v.purge_protection = false;
        v.tags.clear();
        v.health = HealthProps {
            soft_delete: Some(false),
            ..HealthProps::default()
        };
        let r = Reads {
            audit: Ok(NO_SINKS),
            secrets_without_expiry: Count::all_read(2),
            certs_not_renewing: Count::all_read(2),
            keys_without_rotation: Count::all_read(2),
            not_read: None,
        };
        let f = assess(&v, &r);
        assert!(f.iter().all(|x| x.status == Status::Warn), "{f:?}");
        for x in f {
            assert!(!x.detail.contains('\u{2014}'), "{}", x.detail);
            assert!(!x.detail.contains(". "), "one sentence: {}", x.detail);
            assert!(x.kind.guide().starts_with("https://learn.microsoft.com/"));
        }
    }
}
