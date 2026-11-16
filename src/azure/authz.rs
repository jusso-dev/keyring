//! Who has access: Azure role assignments, PIM eligible assignments, role
//! definitions and a vault's access policies, read through ARM as the
//! signed-in person.
//!
//! Every call uses the person's on-behalf-of Management token. Reader on
//! the vault (or above) is enough: it carries
//! `Microsoft.Authorization/*/read` and the vault's own read.
//!
//! Principals are object IDs and a type only. Keyring doesn't call
//! Microsoft Graph, so it has no names for them.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::auth::session::Session;
use crate::azure::audit::is_safe_resource_id;
use crate::azure::{AzureClient, AzureError, Resource};

/// Role assignments and role definitions.
pub const AUTHORIZATION_API: &str = "2022-04-01";
/// PIM schedule instances.
pub const PIM_API: &str = "2020-10-01";
/// The vault resource, for its access model and access policies.
pub const VAULT_API: &str = "2023-07-01";
/// Stop following `nextLink` after this many pages.
pub const MAX_PAGES: usize = 20;

/// Built-in roles that can give their holder access they don't have yet,
/// by changing role assignments or the vault's access policies.
const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";
const USER_ACCESS_ADMINISTRATOR: &str = "18d7d88d-d35e-4fb5-a5c3-7773c4a72e5c";

/// An active role assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    /// Where it was made: a management group, subscription, resource
    /// group, the vault or one item.
    pub scope: String,
    pub role_definition_id: String,
    pub principal_id: String,
    /// `User`, `Group`, `ServicePrincipal`, `ForeignGroup` or `Device`.
    pub principal_type: String,
    /// An ABAC condition narrows what it allows.
    pub has_condition: bool,
}

/// What an assignment, active or eligible, is made of. Both lists share it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentProps {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role_definition_id: String,
    #[serde(default)]
    principal_id: String,
    #[serde(default)]
    principal_type: Option<String>,
    #[serde(default)]
    condition: Option<String>,
}

#[derive(Deserialize)]
struct Wrapped<P> {
    properties: P,
}

impl From<AssignmentProps> for RoleAssignment {
    fn from(p: AssignmentProps) -> Self {
        Self {
            scope: p.scope,
            role_definition_id: p.role_definition_id,
            principal_id: p.principal_id,
            principal_type: p.principal_type.unwrap_or_default(),
            has_condition: p.condition.is_some_and(|c| !c.trim().is_empty()),
        }
    }
}

/// A role, as far as Keyring needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDefinition {
    /// The role's GUID, the last part of its ID.
    pub name: String,
    pub role_name: String,
    pub data_actions: Vec<String>,
}

impl RoleDefinition {
    /// True when the role allows something on a vault's contents: a data
    /// action under `Microsoft.KeyVault/`, or every data action.
    pub fn has_key_vault_data_actions(&self) -> bool {
        self.data_actions.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            a == "*" || a.starts_with("microsoft.keyvault/")
        })
    }

    /// Owner, Contributor and User Access Administrator: none of them reads
    /// a value on an RBAC vault, but each can give itself a role that does
    /// (or, on an access policy vault, a policy).
    pub fn can_grant_itself_access(&self) -> bool {
        let n = self.name.to_ascii_lowercase();
        [OWNER, CONTRIBUTOR, USER_ACCESS_ADMINISTRATOR].contains(&n.as_str())
    }
}

#[derive(Deserialize)]
struct DefinitionReply {
    #[serde(default)]
    name: String,
    properties: DefinitionProps,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DefinitionProps {
    #[serde(default)]
    role_name: String,
    #[serde(default)]
    permissions: Vec<PermissionSet>,
}

/// One entry in a vault's access policies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicy {
    #[serde(default)]
    pub object_id: String,
    /// Set for a "compound identity": this person, only through this app.
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub permissions: PolicyPermissions,
}

/// The operations an access policy allows, by kind of item, as Azure lists
/// them (`get`, `list`, `set`, `all` and so on).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PolicyPermissions {
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub certificates: Vec<String>,
}

/// How a vault decides who gets in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAuthorisation {
    /// `true` for Azure RBAC, `false` for access policies.
    pub rbac: bool,
    /// Only used when `rbac` is false, but Azure keeps them either way.
    pub access_policies: Vec<AccessPolicy>,
}

#[derive(Deserialize)]
struct VaultReply {
    #[serde(default)]
    properties: VaultProps,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultProps {
    #[serde(default)]
    enable_rbac_authorization: Option<bool>,
    #[serde(default)]
    access_policies: Option<Vec<AccessPolicy>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListPage<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    #[serde(default)]
    next_link: Option<String>,
}

/// True when `link` is on the same scheme, host and port as
/// `management_url`, so a `nextLink` can't send the person's token
/// anywhere else.
fn same_origin(management_url: &str, link: &str) -> bool {
    match (
        reqwest::Url::parse(management_url),
        reqwest::Url::parse(link),
    ) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
                && b.username().is_empty()
                && b.password().is_none()
        }
        _ => false,
    }
}

/// GET `first` and follow `nextLink` on the same origin, up to
/// [`MAX_PAGES`].
async fn list_all<T: DeserializeOwned>(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    first: String,
) -> Result<Vec<T>, AzureError> {
    let mut out = Vec::new();
    let mut url = first;
    for _ in 0..MAX_PAGES {
        let page: ListPage<T> = azure.get_json(session, Resource::Management, &url).await?;
        out.extend(page.value);
        match page.next_link {
            Some(next) if same_origin(management_url, &next) => url = next,
            Some(_) => {
                tracing::warn!("ARM nextLink on another host, not followed");
                return Ok(out);
            }
            None => return Ok(out),
        }
    }
    tracing::warn!(pages = MAX_PAGES, "ARM paging stopped at the limit");
    Ok(out)
}

/// Active role assignments at, above and below `scope`. Use [`applies_at`]
/// to keep the ones that reach it.
pub async fn role_assignments(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Vec<RoleAssignment>, AzureError> {
    if !is_safe_resource_id(scope) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignments?api-version={AUTHORIZATION_API}"
    );
    let rows: Vec<Wrapped<AssignmentProps>> = list_all(azure, session, management_url, url).await?;
    Ok(rows.into_iter().map(|w| w.properties.into()).collect())
}

/// PIM eligible assignments at or above `scope` (`atScope()`). A tenant
/// without PIM has none.
pub async fn eligible_assignments(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Vec<RoleAssignment>, AzureError> {
    if !is_safe_resource_id(scope) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={PIM_API}&$filter=atScope()"
    );
    let rows: Vec<Wrapped<AssignmentProps>> = list_all(azure, session, management_url, url).await?;
    Ok(rows.into_iter().map(|w| w.properties.into()).collect())
}

/// One role, read by its GUID at `scope`. Built-in roles and custom roles
/// assignable there can be read at any scope they apply to, so this works
/// for a role assigned on a management group too, whose ID doesn't start
/// with `/subscriptions/`.
pub async fn role_definition(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
    role_guid: &str,
) -> Result<RoleDefinition, AzureError> {
    if !is_safe_resource_id(scope) || !is_guid(role_guid) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleDefinitions/{role_guid}?api-version={AUTHORIZATION_API}"
    );
    let reply: DefinitionReply = azure.get_json(session, Resource::Management, &url).await?;
    Ok(RoleDefinition {
        name: if reply.name.is_empty() {
            role_guid.to_owned()
        } else {
            reply.name
        },
        role_name: reply.properties.role_name,
        data_actions: reply
            .properties
            .permissions
            .into_iter()
            .flat_map(|p| p.data_actions)
            .collect(),
    })
}

/// The vault's access model and its access policies, from the vault
/// resource itself.
pub async fn vault_authorisation(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
) -> Result<VaultAuthorisation, AzureError> {
    if !is_safe_resource_id(vault_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!("{management_url}{vault_id}?api-version={VAULT_API}");
    let reply: VaultReply = azure.get_json(session, Resource::Management, &url).await?;
    Ok(VaultAuthorisation {
        rbac: reply.properties.enable_rbac_authorization.unwrap_or(false),
        access_policies: reply.properties.access_policies.unwrap_or_default(),
    })
}

/// What the signed-in person may do at one scope, from
/// `{scope}/providers/Microsoft.Authorization/permissions`. One set per role
/// they hold there (directly, through a group, or inherited from above).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    pub sets: Vec<PermissionSet>,
}

/// One role's permissions, as ARM lists them. Patterns may hold `*`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSet {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub not_actions: Vec<String>,
    #[serde(default)]
    pub data_actions: Vec<String>,
    #[serde(default)]
    pub not_data_actions: Vec<String>,
}

impl PermissionSet {
    /// This set allows `action`: one of its `dataActions` matches and none
    /// of its `notDataActions` does.
    pub fn allows_data_action(&self, action: &str) -> bool {
        self.data_actions.iter().any(|p| action_matches(p, action))
            && !self
                .not_data_actions
                .iter()
                .any(|p| action_matches(p, action))
    }
}

impl Permissions {
    /// True when any one set allows `action`. Azure works the same way:
    /// `notDataActions` take away from the role they're in, not from the
    /// person's other roles, so they are not a deny.
    pub fn allows_data_action(&self, action: &str) -> bool {
        self.sets.iter().any(|s| s.allows_data_action(action))
    }
}

/// True when the action `pattern` from a role covers `action`. Both are
/// compared without regard to case, and `*` stands for any run of
/// characters, `/` included, wherever it appears
/// (`Microsoft.KeyVault/vaults/secrets/*`, `Microsoft.KeyVault/vaults/*/read`
/// or `*` on its own).
pub fn action_matches(pattern: &str, action: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let a = action.trim().to_ascii_lowercase();
    let mut parts = p.split('*');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(mut rest) = a.strip_prefix(first) else {
        return false;
    };
    let tail: Vec<&str> = parts.collect();
    let Some((last, middle)) = tail.split_last() else {
        // No `*`: the whole action must match.
        return rest.is_empty();
    };
    for piece in middle {
        match rest.find(piece) {
            Some(i) => rest = &rest[i + piece.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// The signed-in person's own permissions at `scope`: the vault's ARM ID,
/// or [`item_scope`] for one item. Follows `nextLink` like the lists.
pub async fn permissions(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Permissions, AzureError> {
    if !is_safe_resource_id(scope) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/permissions?api-version={AUTHORIZATION_API}"
    );
    let sets: Vec<PermissionSet> = list_all(azure, session, management_url, url).await?;
    Ok(Permissions { sets })
}

/// The ARM scope of one secret, certificate or key, for item-level role
/// assignments. `collection` is `secrets`, `certificates` or `keys`.
pub fn item_scope(vault_id: &str, collection: &str, name: &str) -> String {
    format!("{}/{collection}/{name}", vault_id.trim_end_matches('/'))
}

/// True when an assignment made at `assigned` reaches `target`: the same
/// scope or one above it. Management groups and the root (`/`) are above
/// every subscription the person can see.
pub fn applies_at(assigned: &str, target: &str) -> bool {
    let a = assigned.trim_end_matches('/').to_ascii_lowercase();
    let t = target.trim_end_matches('/').to_ascii_lowercase();
    a.is_empty()
        || a.starts_with("/providers/microsoft.management/managementgroups/")
        || a == t
        || t.starts_with(&format!("{a}/"))
}

/// The GUID at the end of a role definition ID, if it is one.
pub fn role_guid(role_definition_id: &str) -> Option<&str> {
    let last = role_definition_id
        .trim_end_matches('/')
        .rsplit('/')
        .next()?;
    is_guid(last).then_some(last)
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hex digits in any case.
pub fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Distinct role GUIDs across `lists`, in a stable order.
pub fn distinct_roles<'a>(lists: impl IntoIterator<Item = &'a RoleAssignment>) -> Vec<String> {
    let mut seen = BTreeMap::new();
    for a in lists {
        if let Some(g) = role_guid(&a.role_definition_id) {
            seen.entry(g.to_ascii_lowercase()).or_insert(());
        }
    }
    seen.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str =
        "/subscriptions/s1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv";

    #[test]
    fn scopes_at_or_above() {
        let item = item_scope(VAULT, "secrets", "db");
        assert!(item.ends_with("/vaults/kv/secrets/db"));
        assert!(applies_at(VAULT, VAULT));
        assert!(applies_at(VAULT, &item));
        assert!(
            applies_at("/subscriptions/S1", VAULT),
            "case doesn't matter"
        );
        assert!(applies_at("/subscriptions/s1/resourceGroups/rg-app", VAULT));
        assert!(applies_at("/", VAULT));
        assert!(applies_at(
            "/providers/Microsoft.Management/managementGroups/root",
            VAULT
        ));
        assert!(!applies_at(&item, VAULT), "below the vault");
        assert!(
            !applies_at("/subscriptions/s1/resourceGroups/rg", VAULT),
            "a prefix that isn't a parent"
        );
        assert!(!applies_at("/subscriptions/s2", VAULT));
        assert!(!applies_at(&item_scope(VAULT, "secrets", "db2"), &item));
    }

    #[test]
    fn role_guids() {
        assert_eq!(
            role_guid(
                "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
            ),
            Some("4633458b-17de-408a-b874-0445c86b69e6")
        );
        assert_eq!(role_guid("/providers/x/roleDefinitions/not-a-guid"), None);
        assert_eq!(role_guid(""), None);
        assert!(!is_guid("4633458b-17de-408a-b874-0445c86b69e/"));
        assert!(!is_guid("4633458b?17de-408a-b874-0445c86b69e6"));
    }

    #[test]
    fn which_roles_matter() {
        let def = |name: &str, actions: &[&str]| RoleDefinition {
            name: name.into(),
            role_name: String::new(),
            data_actions: actions.iter().map(|a| (*a).into()).collect(),
        };
        let secrets_user = def(
            "4633458b-17de-408a-b874-0445c86b69e6",
            &["Microsoft.KeyVault/vaults/secrets/getSecret/action"],
        );
        assert!(secrets_user.has_key_vault_data_actions());
        assert!(!secrets_user.can_grant_itself_access());
        assert!(def("x", &["*"]).has_key_vault_data_actions());
        assert!(
            !def(
                "x",
                &["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
            )
            .has_key_vault_data_actions()
        );
        let owner = def(&OWNER.to_ascii_uppercase(), &[]);
        assert!(owner.can_grant_itself_access());
        assert!(!owner.has_key_vault_data_actions());
    }

    #[test]
    fn wildcards_match_without_regard_to_case() {
        let get = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
        assert!(action_matches(get, get));
        assert!(action_matches(
            "microsoft.keyvault/VAULTS/secrets/getsecret/ACTION",
            get
        ));
        assert!(action_matches("Microsoft.KeyVault/vaults/secrets/*", get));
        assert!(action_matches("Microsoft.KeyVault/vaults/*", get));
        assert!(action_matches("*", get));
        assert!(action_matches("Microsoft.KeyVault/*/action", get));
        assert!(action_matches(
            "Microsoft.KeyVault/vaults/*/read",
            "Microsoft.KeyVault/vaults/keys/read"
        ));
        assert!(!action_matches(
            "Microsoft.KeyVault/vaults/*/read",
            "Microsoft.KeyVault/vaults/keys/delete"
        ));
        assert!(!action_matches("Microsoft.KeyVault/vaults/keys/*", get));
        assert!(
            !action_matches("Microsoft.KeyVault/vaults/secrets", get),
            "no star: the whole action"
        );
        assert!(
            !action_matches("Microsoft.KeyVault/vaults/secrets/getSecret", get),
            "a prefix isn't a match"
        );
        assert!(
            !action_matches("Microsoft.KeyVault/vaults/secretsX/*", get),
            "a near name isn't a match"
        );
        assert!(!action_matches("", get));
        assert!(action_matches("a*b*c", "aXbYc"));
        assert!(!action_matches("a*b*c", "aXcYb"));
    }

    #[test]
    fn not_data_actions_take_away_from_their_own_role() {
        let set = |data: &[&str], not: &[&str]| PermissionSet {
            data_actions: data.iter().map(|a| (*a).into()).collect(),
            not_data_actions: not.iter().map(|a| (*a).into()).collect(),
            ..PermissionSet::default()
        };
        let get = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
        let purge = "Microsoft.KeyVault/vaults/secrets/purge/action";
        let no_purge = set(
            &["Microsoft.KeyVault/vaults/secrets/*"],
            &["microsoft.keyvault/vaults/secrets/PURGE/*"],
        );
        assert!(no_purge.allows_data_action(get));
        assert!(!no_purge.allows_data_action(purge));
        let one = Permissions {
            sets: vec![no_purge.clone()],
        };
        assert!(!one.allows_data_action(purge));
        // Another role that allows it still does: notDataActions aren't a deny.
        let two = Permissions {
            sets: vec![no_purge, set(&["Microsoft.KeyVault/vaults/*"], &[])],
        };
        assert!(two.allows_data_action(purge));
        assert!(!set(&["*"], &["*"]).allows_data_action(get));
        assert!(!Permissions::default().allows_data_action(get));
    }

    #[test]
    fn parses_permissions() {
        let page: ListPage<PermissionSet> = serde_json::from_value(serde_json::json!({
            "value": [{
                "actions": ["Microsoft.KeyVault/vaults/*/read"],
                "notActions": [],
                "dataActions": ["Microsoft.KeyVault/vaults/secrets/readMetadata/action"],
                "notDataActions": []
            }, {"actions": ["*"]}]
        }))
        .unwrap();
        assert_eq!(page.value.len(), 2);
        assert_eq!(page.value[0].data_actions.len(), 1);
        assert!(page.value[1].data_actions.is_empty());
    }

    #[test]
    fn next_links_stay_on_arm() {
        let arm = "https://management.azure.com";
        assert!(same_origin(
            arm,
            "https://management.azure.com/subscriptions/x?skiptoken=1"
        ));
        assert!(same_origin(arm, "https://management.azure.com:443/x"));
        assert!(!same_origin(arm, "https://evil.example/x"));
        assert!(!same_origin(
            arm,
            "https://management.azure.com.evil.example/x"
        ));
        assert!(!same_origin(arm, "https://user@management.azure.com/x"));
        assert!(!same_origin(arm, "http://management.azure.com/x"));
        assert!(!same_origin(arm, "not a url"));
    }

    #[test]
    fn parses_assignments_and_policies() {
        let page: ListPage<Wrapped<AssignmentProps>> = serde_json::from_value(serde_json::json!({
            "value": [{"properties": {
                "scope": VAULT, "roleDefinitionId": "/x/roleDefinitions/g",
                "principalId": "p", "principalType": "Group", "condition": "@Resource[x] StringEquals 'y'"
            }}, {"properties": {"scope": "/", "roleDefinitionId": "", "principalId": "q", "condition": null}}],
            "nextLink": null
        }))
        .unwrap();
        let rows: Vec<RoleAssignment> = page
            .value
            .into_iter()
            .map(|w| w.properties.into())
            .collect();
        assert!(rows[0].has_condition && rows[0].principal_type == "Group");
        assert!(!rows[1].has_condition && rows[1].principal_type.is_empty());

        let v: VaultReply = serde_json::from_value(serde_json::json!({"properties": {
            "enableRbacAuthorization": false,
            "accessPolicies": [{"tenantId": "t", "objectId": "o", "permissions": {"secrets": ["get", "list"], "keys": [], "storage": ["get"]}}]
        }}))
        .unwrap();
        let p = v.properties.access_policies.unwrap();
        assert_eq!(p[0].permissions.secrets, ["get", "list"]);
        assert!(p[0].permissions.certificates.is_empty());
        let none: VaultReply = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(none.properties.enable_rbac_authorization.is_none());
    }
}
