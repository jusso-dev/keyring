//! Access: who can reach a vault or one of its items, from Azure role
//! assignments (active and PIM eligible) and, on older vaults, access
//! policies. Read through ARM as the signed-in person. Only reads, so it
//! writes no audit event.
//!
//! Principals are shown as object IDs and a type, with a link to the
//! portal. Keyring doesn't call Microsoft Graph, so it has no names.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::auth::session::Session;
use crate::azure::authz::{
    self, AccessPolicy, RoleAssignment, RoleDefinition, applies_at, distinct_roles, is_guid,
};
use crate::azure::{AzureClient, AzureError};
use crate::expiry::csv_field;
use crate::routes::assets::render;
use crate::routes::lifecycle::Kind;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx;

/// Time for the whole read on the vault's Access page.
pub(crate) const PAGE_TIMEOUT: Duration = Duration::from_secs(20);
/// Time for the read on an item's page. It runs beside the item's own
/// reads, so the page waits no longer than this for it.
pub(crate) const ITEM_TIMEOUT: Duration = Duration::from_secs(5);
/// Most distinct roles looked up for one page.
pub(crate) const MAX_ROLES: usize = 50;
/// Role definitions read at once.
const ROLE_CONCURRENCY: usize = 6;

/// Where an assignment was made, relative to the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Origin {
    Item,
    Vault,
    ResourceGroup,
    Subscription,
    ManagementGroup,
    Root,
    /// Above the vault, but not a shape Keyring names.
    Above,
}

impl Origin {
    pub(crate) fn of(scope: &str, vault_id: &str) -> Self {
        let s = scope.trim_end_matches('/').to_ascii_lowercase();
        let v = vault_id.trim_end_matches('/').to_ascii_lowercase();
        if s.is_empty() {
            return Self::Root;
        }
        if s == v {
            return Self::Vault;
        }
        if s.starts_with(&format!("{v}/")) {
            return Self::Item;
        }
        if s.starts_with("/providers/microsoft.management/managementgroups/") {
            return Self::ManagementGroup;
        }
        let parts: Vec<&str> = s.trim_start_matches('/').split('/').collect();
        match parts.as_slice() {
            ["subscriptions", _] => Self::Subscription,
            ["subscriptions", _, "resourcegroups", _] => Self::ResourceGroup,
            _ => Self::Above,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Item => "This item",
            Self::Vault => "The vault",
            Self::ResourceGroup => "Resource group",
            Self::Subscription => "Subscription",
            Self::ManagementGroup => "Management group",
            Self::Root => "Whole tenant",
            Self::Above => "Above the vault",
        }
    }
}

/// One person, group or app and one role they hold here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub principal_id: String,
    pub principal_type: &'static str,
    pub is_group: bool,
    /// Empty when Keyring has no portal page for this type.
    pub portal_url: String,
    pub role: String,
    pub origin: Origin,
    pub scope: String,
    /// A PIM eligible assignment: they can turn it on, but it isn't on.
    pub eligible: bool,
    /// Owner, Contributor or User Access Administrator.
    pub can_grant: bool,
    pub has_condition: bool,
}

/// One access policy, in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRow {
    pub object_id: String,
    /// Only through this app (a compound identity).
    pub application_id: String,
    /// (kind, what it allows), for each kind with any permission.
    pub lines: Vec<(&'static str, String)>,
    pub reads_secret_values: bool,
}

/// Why something couldn't be shown, and what to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unavailable {
    pub message: String,
    pub hint: String,
}

/// Everything the Access page or section shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Access {
    /// Set when nothing could be read: shown in place of everything else.
    pub unavailable: Option<Unavailable>,
    /// `true` for Azure RBAC, `false` for access policies.
    pub rbac: bool,
    /// On an item's page rather than the vault's.
    pub for_item: bool,
    pub entries: Vec<Entry>,
    /// Set when role assignments couldn't be read: shown in place of them.
    pub assignments_unavailable: Option<Unavailable>,
    pub policies: Vec<PolicyRow>,
    /// Smaller things left out, such as eligible assignments.
    pub notes: Vec<String>,
}

impl Access {
    fn unavailable(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            unavailable: Some(Unavailable {
                message: message.into(),
                hint: hint.into(),
            }),
            ..Self::default()
        }
    }

    pub(crate) fn groups(&self) -> usize {
        self.entries.iter().filter(|e| e.is_group).count()
    }
}

const READER_HINT: &str = "the Reader role on the vault, its resource group or its subscription. Reader lets you see who has access without giving any access to the vault's contents.";

/// Plain words for a failed ARM read. Never Azure's message.
fn arm_reason(e: &AzureError) -> String {
    match e {
        AzureError::Status { status: 429, .. } => {
            "Azure was throttling requests. Try again in a minute".into()
        }
        AzureError::Status { status: 404, .. } => "Azure couldn't find the vault".into(),
        AzureError::Network(_) => "Keyring couldn't reach Azure Resource Manager".into(),
        AzureError::Token(_) => "Sign-in needs refreshing. Sign out and in again".into(),
        AzureError::Unreadable => "Azure's answer wasn't one Keyring could read".into(),
        _ => "Azure returned an error".into(),
    }
}

fn principal(kind: &str, id: &str) -> (&'static str, bool, String) {
    let k = kind.to_ascii_lowercase();
    let (label, path) = match k.as_str() {
        "user" => (
            "User",
            "Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/",
        ),
        "group" => (
            "Group",
            "Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/",
        ),
        "serviceprincipal" => (
            "App or managed identity",
            "Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/",
        ),
        "foreigngroup" => ("Group in another tenant", ""),
        "device" => ("Device", ""),
        "" => ("Type not given", ""),
        _ => ("Other", ""),
    };
    let url = if !path.is_empty() && is_guid(id) {
        format!("https://portal.azure.com/#view/{path}{id}")
    } else {
        String::new()
    };
    (label, k == "group" || k == "foreigngroup", url)
}

/// Words for an access policy operation. Unknown ones are shown as Azure
/// names them.
fn op_words(kind: &str, op: &str) -> String {
    let o = op.to_ascii_lowercase();
    let w = match (kind, o.as_str()) {
        (_, "all") => "everything",
        ("secrets", "get") => "read values",
        ("keys", "get") => "read the public key",
        (_, "get") => "read",
        (_, "list") => "list",
        ("secrets", "set") => "set values",
        (_, "delete") => "delete",
        (_, "recover") => "recover",
        (_, "backup") => "back up",
        (_, "restore") => "restore",
        (_, "purge") => "purge",
        (_, "create") => "create",
        (_, "import") => "import",
        (_, "update") => "change details",
        (_, "rotate") => "rotate",
        (_, "getrotationpolicy") => "read the rotation policy",
        (_, "setrotationpolicy") => "change the rotation policy",
        (_, "decrypt") => "decrypt",
        (_, "encrypt") => "encrypt",
        (_, "unwrapkey") => "unwrap keys",
        (_, "wrapkey") => "wrap keys",
        (_, "sign") => "sign",
        (_, "verify") => "verify",
        (_, "release") => "release",
        (_, "managecontacts") => "manage contacts",
        (_, "getissuers") => "read issuers",
        (_, "listissuers") => "list issuers",
        (_, "setissuers") => "set issuers",
        (_, "deleteissuers") => "delete issuers",
        (_, "manageissuers") => "manage issuers",
        _ => return op.to_owned(),
    };
    w.to_owned()
}

fn policy_row(p: &AccessPolicy, only: Option<Kind>) -> PolicyRow {
    let perms = &p.permissions;
    let kinds: [(&'static str, &str, Kind, &Vec<String>); 3] = [
        ("Secrets", "secrets", Kind::Secret, &perms.secrets),
        ("Keys", "keys", Kind::Key, &perms.keys),
        (
            "Certificates",
            "certificates",
            Kind::Certificate,
            &perms.certificates,
        ),
    ];
    let lines = kinds
        .iter()
        .filter(|(_, _, k, ops)| !ops.is_empty() && only.is_none_or(|o| o == *k))
        .map(|(label, key, _, ops)| {
            let words: Vec<String> = ops.iter().map(|o| op_words(key, o)).collect();
            (*label, words.join(", "))
        })
        .collect();
    let reads_secret_values = perms
        .secrets
        .iter()
        .any(|o| o.eq_ignore_ascii_case("get") || o.eq_ignore_ascii_case("all"));
    PolicyRow {
        object_id: p.object_id.clone(),
        application_id: p.application_id.clone().unwrap_or_default(),
        lines,
        reads_secret_values,
    }
}

/// Read every role used, a few at a time. A role that can't be read is
/// left out of the map.
pub(crate) async fn definitions(
    azure: &AzureClient,
    session: &Arc<Session>,
    management_url: &str,
    vault_id: &str,
    guids: Vec<String>,
) -> HashMap<String, RoleDefinition> {
    let permits = Arc::new(Semaphore::new(ROLE_CONCURRENCY));
    let mut set = JoinSet::new();
    for g in guids {
        let (azure, session, url, scope, permits) = (
            azure.clone(),
            session.clone(),
            management_url.to_owned(),
            vault_id.to_owned(),
            permits.clone(),
        );
        set.spawn(async move {
            let _permit = permits.acquire_owned().await;
            let r = authz::role_definition(&azure, &session, &url, &scope, &g).await;
            (g, r)
        });
    }
    let mut out = HashMap::new();
    while let Some(done) = set.join_next().await {
        match done {
            Ok((g, Ok(d))) => {
                out.insert(g, d);
            }
            Ok((_, Err(e))) => tracing::info!(error = %e, "couldn't read a role definition"),
            Err(_) => tracing::warn!("role definition read failed inside Keyring"),
        }
    }
    out
}

/// The role assignments that reach `scope`, with role names, filtered to
/// the roles that matter for a vault.
async fn assignments(
    state: &AppState,
    session: &Arc<Session>,
    vault_id: &str,
    scope: &str,
    only_can_grant: bool,
    access: &mut Access,
) {
    let url = &state.config.management_url;
    let (active, eligible) = tokio::join!(
        authz::role_assignments(&state.azure, session, url, scope),
        authz::eligible_assignments(&state.azure, session, url, scope),
    );
    let active = match active {
        Ok(a) => a,
        Err(AzureError::Status { status: 403, .. }) => {
            access.assignments_unavailable = Some(Unavailable {
                message: "You can't read the role assignments here, so Keyring can't show who has access. That doesn't mean nobody has it.".into(),
                hint: READER_HINT.into(),
            });
            return;
        }
        Err(e) => {
            tracing::info!(error = %e, "couldn't read role assignments");
            access.assignments_unavailable = Some(Unavailable {
                message: format!(
                    "Keyring couldn't read the role assignments: {}.",
                    arm_reason(&e)
                ),
                hint: String::new(),
            });
            return;
        }
    };
    let eligible = match eligible {
        Ok(e) => e,
        Err(AzureError::Status { status: 403, .. }) => {
            access
                .notes
                .push("Eligible (PIM) assignments aren't listed: you can't read them here.".into());
            Vec::new()
        }
        Err(e) => {
            tracing::info!(error = %e, "couldn't read eligible role assignments");
            access.notes.push(format!(
                "Eligible (PIM) assignments aren't listed: {}.",
                arm_reason(&e)
            ));
            Vec::new()
        }
    };
    let keep = |a: &RoleAssignment| applies_at(&a.scope, scope);
    let active: Vec<RoleAssignment> = active.into_iter().filter(keep).collect();
    let eligible: Vec<RoleAssignment> = eligible.into_iter().filter(keep).collect();
    let mut guids = distinct_roles(active.iter().chain(eligible.iter()));
    if guids.len() > MAX_ROLES {
        access.notes.push(format!(
            "More than {MAX_ROLES} different roles are used here. Keyring looked up the first {MAX_ROLES}; assignments of the others are listed as \"Role not read\"."
        ));
        guids.truncate(MAX_ROLES);
    }
    let defs = definitions(&state.azure, session, url, vault_id, guids).await;
    let mut unread_roles = 0;
    let mut entries = Vec::new();
    for (a, is_eligible) in active
        .iter()
        .map(|a| (a, false))
        .chain(eligible.iter().map(|a| (a, true)))
    {
        let guid = authz::role_guid(&a.role_definition_id).map(str::to_ascii_lowercase);
        let def = guid.as_deref().and_then(|g| defs.get(g));
        let (role, can_grant) = match def {
            Some(d) if d.can_grant_itself_access() => (d.role_name.clone(), true),
            Some(d) if d.has_key_vault_data_actions() && !only_can_grant => {
                (d.role_name.clone(), false)
            }
            Some(_) => continue,
            None => {
                unread_roles += 1;
                ("Role not read".to_owned(), false)
            }
        };
        let (principal_type, is_group, portal_url) = principal(&a.principal_type, &a.principal_id);
        entries.push(Entry {
            principal_id: a.principal_id.clone(),
            principal_type,
            is_group,
            portal_url,
            role: if role.is_empty() {
                guid.unwrap_or_default()
            } else {
                role
            },
            origin: Origin::of(&a.scope, vault_id),
            scope: a.scope.clone(),
            eligible: is_eligible,
            can_grant,
            has_condition: a.has_condition,
        });
    }
    if unread_roles > 0 {
        access.notes.push(format!(
            "{unread_roles} assignment{} use a role Keyring couldn't look up, so it can't tell whether it reaches the vault's contents. {} listed as \"Role not read\".",
            if unread_roles == 1 { "" } else { "s" },
            if unread_roles == 1 { "It is" } else { "They are" },
        ));
    }
    entries.sort_by(|a, b| {
        (
            a.origin,
            a.eligible,
            a.role.to_ascii_lowercase(),
            &a.principal_id,
        )
            .cmp(&(
                b.origin,
                b.eligible,
                b.role.to_ascii_lowercase(),
                &b.principal_id,
            ))
    });
    access.entries = entries;
}

/// Read who has access to `vault`, or to one item in it when `item` is
/// set. Never fails: anything that couldn't be read is in the result with
/// a reason.
async fn read(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    item: Option<(Kind, &str)>,
) -> Access {
    let vault_id = match super::audit::vault_id(state, session, vault).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Access::unavailable(
                "Keyring couldn't find this vault in the list of vaults you can see in Azure, so it can't read who has access.",
                READER_HINT,
            );
        }
        Err(e) => {
            return Access::unavailable(
                format!("Keyring couldn't look up the vault: {}.", arm_reason(&e)),
                "",
            );
        }
    };
    let url = &state.config.management_url;
    let auth = match authz::vault_authorisation(&state.azure, &session.0, url, &vault_id).await {
        Ok(a) => a,
        Err(AzureError::Status { status: 403, .. }) => {
            return Access::unavailable(
                "You can't read this vault's settings in Azure, so Keyring can't show who has access. That doesn't mean nobody has it.",
                READER_HINT,
            );
        }
        Err(e) => {
            tracing::info!(error = %e, "couldn't read the vault's access settings");
            return Access::unavailable(
                format!(
                    "Keyring couldn't read the vault's settings: {}.",
                    arm_reason(&e)
                ),
                "",
            );
        }
    };
    let mut access = Access {
        rbac: auth.rbac,
        for_item: item.is_some(),
        ..Access::default()
    };
    let scope = match item {
        Some((kind, name)) => authz::item_scope(&vault_id, kind.plural(), name),
        None => vault_id.clone(),
    };
    if !auth.rbac {
        access.policies = auth
            .access_policies
            .iter()
            .map(|p| policy_row(p, item.map(|(k, _)| k)))
            .filter(|r| !r.lines.is_empty())
            .collect();
    }
    // On an access policy vault, data roles don't apply, but anyone who
    // can change the vault can add themselves a policy.
    assignments(
        state,
        &session.0,
        &vault_id,
        &scope,
        !auth.rbac,
        &mut access,
    )
    .await;
    access
}

/// [`read`] within `limit`. Past it, a reason in place of the list.
pub(crate) async fn read_within(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    item: Option<(Kind, &str)>,
    limit: Duration,
) -> Access {
    match tokio::time::timeout(limit, read(state, session, vault, item)).await {
        Ok(a) => a,
        Err(_) => Access {
            for_item: item.is_some(),
            ..Access::unavailable(
                format!(
                    "Azure didn't answer within {} seconds, so Keyring stopped waiting. Refresh the page to try again.",
                    limit.as_secs()
                ),
                "",
            )
        },
    }
}

/// For the secret, certificate and key pages.
pub(crate) async fn for_item(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
    kind: Kind,
    name: &str,
) -> Access {
    read_within(state, session, vault, Some((kind, name)), ITEM_TIMEOUT).await
}

#[derive(Template)]
#[template(path = "access.html")]
struct AccessPage {
    shell: Shell,
    vault: String,
    access: Access,
    csv_url: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> crate::routes::error::PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Access, &vault)?;
    let access = read_within(&state, &session, &vault, None, PAGE_TIMEOUT).await;
    Ok(render(&AccessPage {
        csv_url: vault_ctx::vault_path(&vault, "/access.csv"),
        shell,
        vault,
        access,
    })
    .into_response())
}

/// CSV of the vault's access list. Fields are formula-guarded.
pub(crate) fn to_csv(access: &Access) -> String {
    let mut out = String::from(
        "Principal object ID,Principal type,Role or permissions,Assignment,Comes from,Scope,Can grant itself access,Condition\r\n",
    );
    let mut line = |cols: [String; 8]| {
        out.push_str(&cols.join(","));
        out.push_str("\r\n");
    };
    for e in &access.entries {
        line([
            csv_field(&e.principal_id),
            csv_field(e.principal_type),
            csv_field(&e.role),
            (if e.eligible { "Eligible" } else { "Active" }).into(),
            csv_field(e.origin.label()),
            csv_field(&e.scope),
            (if e.can_grant { "Yes" } else { "No" }).into(),
            (if e.has_condition { "Yes" } else { "No" }).into(),
        ]);
    }
    for p in &access.policies {
        let perms: Vec<String> = p.lines.iter().map(|(k, w)| format!("{k}: {w}")).collect();
        let who = if p.application_id.is_empty() {
            "Type not given".to_owned()
        } else {
            format!("Only through app {}", p.application_id)
        };
        line([
            csv_field(&p.object_id),
            csv_field(&who),
            csv_field(&perms.join("; ")),
            "Access policy".into(),
            "The vault".into(),
            String::new(),
            "No".into(),
            "No".into(),
        ]);
    }
    let not_read = access
        .assignments_unavailable
        .iter()
        .map(|u| u.message.clone())
        .chain(access.notes.iter().cloned());
    for note in not_read {
        line([
            "NOT READ".into(),
            String::new(),
            csv_field(&note),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]);
    }
    out
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> crate::routes::error::PageResult {
    let (vault, shell) = vault_ctx::path_vault(&session, shell, Section::Access, &vault)?;
    let access = read_within(&state, &session, &vault, None, PAGE_TIMEOUT).await;
    // Nothing read at all: the page's explanation, never an empty file
    // that reads as "nobody has access".
    if access.unavailable.is_some()
        || (access.assignments_unavailable.is_some() && access.policies.is_empty())
    {
        let page = AccessPage {
            csv_url: vault_ctx::vault_path(&vault, "/access.csv"),
            shell,
            vault,
            access,
        };
        return Ok((StatusCode::FORBIDDEN, render(&page)).into_response());
    }
    let mut res: Response = (StatusCode::OK, to_csv(&access)).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"keyring-access-{vault}.csv\""
    )) {
        h.insert(CONTENT_DISPOSITION, v);
    }
    Ok(no_store(res))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::authz::PolicyPermissions;

    const VAULT: &str =
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv";

    #[test]
    fn origins() {
        assert_eq!(Origin::of(VAULT, VAULT), Origin::Vault);
        assert_eq!(
            Origin::of(&format!("{VAULT}/secrets/db"), VAULT),
            Origin::Item
        );
        assert_eq!(
            Origin::of("/subscriptions/S1/resourceGroups/RG", VAULT),
            Origin::ResourceGroup
        );
        assert_eq!(Origin::of("/subscriptions/s1", VAULT), Origin::Subscription);
        assert_eq!(Origin::of("/", VAULT), Origin::Root);
        assert_eq!(
            Origin::of("/providers/Microsoft.Management/managementGroups/mg", VAULT),
            Origin::ManagementGroup
        );
    }

    #[test]
    fn portal_links_only_for_known_types_and_guids() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let (label, group, url) = principal("Group", id);
        assert_eq!(label, "Group");
        assert!(group);
        assert!(url.starts_with("https://portal.azure.com/#view/") && url.ends_with(id));
        assert!(principal("User", "not-a-guid\"><x").2.is_empty());
        assert!(principal("", id).2.is_empty());
        assert_eq!(
            principal("ServicePrincipal", id).0,
            "App or managed identity"
        );
    }

    #[test]
    fn policies_in_plain_words() {
        let p = AccessPolicy {
            object_id: "o".into(),
            application_id: None,
            permissions: PolicyPermissions {
                secrets: vec!["Get".into(), "List".into()],
                keys: vec!["all".into()],
                certificates: vec![],
            },
        };
        let row = policy_row(&p, None);
        assert_eq!(
            row.lines,
            [
                ("Secrets", "read values, list".to_owned()),
                ("Keys", "everything".to_owned())
            ]
        );
        assert!(row.reads_secret_values);
        let keys_only = policy_row(&p, Some(Kind::Key));
        assert_eq!(keys_only.lines.len(), 1);
        assert!(policy_row(&p, Some(Kind::Certificate)).lines.is_empty());
    }

    #[test]
    fn csv_guards_formulas_and_says_what_it_left_out() {
        let access = Access {
            rbac: true,
            entries: vec![Entry {
                principal_id: "=cmd()".into(),
                principal_type: "User",
                is_group: false,
                portal_url: String::new(),
                role: "Key Vault Secrets User".into(),
                origin: Origin::Vault,
                scope: VAULT.into(),
                eligible: true,
                can_grant: false,
                has_condition: false,
            }],
            notes: vec!["Eligible (PIM) assignments aren't listed.".into()],
            ..Access::default()
        };
        let csv = to_csv(&access);
        assert!(csv.contains("'=cmd()"));
        assert!(csv.contains(",Eligible,The vault,"));
        assert!(csv.contains("NOT READ"));
    }
}
