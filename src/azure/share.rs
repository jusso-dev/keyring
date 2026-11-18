//! Sharing a secret (#286): a time-limited Key Vault Secrets User role
//! assignment on the one secret's scope, made with the sharer's own
//! on-behalf-of Management token. Keyring's managed identity makes no
//! assignment, and Keyring keeps nothing: what it knows about a share is
//! read back from Azure each time.
//!
//! - **With PIM:** `PUT {secret}/providers/Microsoft.Authorization/
//!   roleAssignmentScheduleRequests/{new GUID}` (api-version 2020-10-01),
//!   `requestType` `AdminAssign`, `scheduleInfo.expiration.type`
//!   `AfterDateTime` with `endDateTime`. Azure removes it at the end.
//! - **Without PIM** (the licence or a policy refused it):
//!   `PUT {secret}/providers/Microsoft.Authorization/roleAssignments/
//!   {new GUID}` (api-version 2022-04-01). Azure has no end date for
//!   these, so the `description` records it in a fixed form, and Keyring
//!   shows the share as overdue once the date has passed.
//!
//! Both carry the same fixed text, [`marker`]: as the PIM request's
//! `justification` and the plain assignment's `description`. That is how
//! Keyring tells its own shares from other assignments, and nothing else
//! is ever put in either.
//!
//! Shapes are from Microsoft's REST references for
//! `roleAssignmentScheduleRequests` (Create, List For Scope),
//! `roleAssignmentScheduleInstances` and `roleAssignments` (Create, Delete,
//! List For Scope), and "Grant permission to applications to access an
//! Azure key vault using Azure RBAC" for the per-secret scope.

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::audit::is_safe_resource_id;
use crate::azure::authz::{AUTHORIZATION_API, is_guid, list_all, role_guid};
use crate::azure::pim::{Outcome, PIM_API, parse_time};
use crate::azure::{AzureClient, AzureError, Resource};

/// Key Vault Secrets User: read a secret's value. The only role Keyring
/// shares, fixed here and never taken from a form.
pub const SECRETS_USER: &str = "4633458b-17de-408a-b874-0445c86b69e6";

/// What starts every share's description and justification.
pub const MARKER_PREFIX: &str = "Shared by Keyring by ";

/// ARM's code when PIM isn't licensed in the tenant (Entra ID P2).
pub const LICENCE_REQUIRED: &str = "AadPremiumLicenseRequired";

/// The ARM scope of one secret: `{vault ID}/secrets/{name}`, built only
/// from a checked vault resource ID and a checked secret name.
pub fn secret_scope(vault_id: &str, name: &str) -> Option<String> {
    let v = vault_id.trim_end_matches('/');
    let is_vault = is_safe_resource_id(v)
        && v.to_ascii_lowercase()
            .rsplit_once("/providers/microsoft.keyvault/vaults/")
            .is_some_and(|(_, n)| crate::azure::vaults::is_valid_vault_name(n));
    (is_vault && crate::routes::vault_ctx::is_valid_object_name(name))
        .then(|| format!("{v}/secrets/{name}"))
}

/// The secret's name, if `scope` is exactly one secret in `vault_id`.
pub fn secret_in(scope: &str, vault_id: &str) -> Option<String> {
    let v = vault_id.trim_end_matches('/').to_ascii_lowercase();
    let s = scope.trim_end_matches('/');
    let rest = s.to_ascii_lowercase();
    let name_at = rest.strip_prefix(&format!("{v}/secrets/"))?.len();
    let name = &s[s.len() - name_at..];
    crate::routes::vault_ctx::is_valid_object_name(name).then(|| name.to_owned())
}

/// The fixed text on a share: `Shared by Keyring by <oid> until
/// <DD-MM-YYYY>`. No free text.
pub fn marker(sharer_oid: &str, until: i64) -> String {
    let (y, m, d) = crate::dates::civil_from_days(until.div_euclid(86_400));
    format!(
        "{MARKER_PREFIX}{} until {d:02}-{m:02}-{y:04}",
        sharer_oid.to_ascii_lowercase()
    )
}

/// Read [`marker`] back: the sharer's object ID and the end date (Unix
/// seconds, midnight UTC). `None` for anything not exactly that form.
pub fn read_marker(text: &str) -> Option<(String, i64)> {
    let rest = text.strip_prefix(MARKER_PREFIX)?;
    let (oid, date) = rest.split_once(" until ")?;
    if !is_guid(oid) || date.len() != 10 {
        return None;
    }
    let (d, m, y) = (&date[0..2], &date[3..5], &date[6..10]);
    if &date[2..3] != "-" || &date[5..6] != "-" {
        return None;
    }
    let day = crate::dates::parse_iso_date(&format!("{y}-{m}-{d}"))?;
    // Exactly what [`marker`] writes, and nothing more.
    (marker(oid, day) == text).then(|| (oid.to_ascii_lowercase(), day))
}

/// How a share was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// A PIM schedule: Azure removes it at the end date.
    Pim,
    /// A plain role assignment: it stays until someone removes it.
    Plain,
}

impl Path {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pim => "pim",
            Self::Plain => "plain",
        }
    }
}

/// `2026-11-25T23:59:59Z`: the last second of the end date, UTC.
pub fn end_of_day(day: i64) -> String {
    let (y, m, d) = crate::dates::civil_from_days(day.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}T23:59:59Z")
}

fn role_definition_id(vault_id: &str) -> String {
    // Built-in roles can be named at any scope under the subscription.
    let sub = vault_id
        .trim_start_matches('/')
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");
    format!("/{sub}/providers/Microsoft.Authorization/roleDefinitions/{SECRETS_USER}")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScheduleBody<'a> {
    properties: ScheduleProps<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScheduleProps<'a> {
    principal_id: &'a str,
    role_definition_id: &'a str,
    request_type: &'static str,
    justification: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule_info: Option<Schedule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Schedule {
    start_date_time: String,
    expiration: Expiration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Expiration {
    #[serde(rename = "type")]
    kind: &'static str,
    end_date_time: String,
}

#[derive(Deserialize, Default)]
struct StatusReply {
    #[serde(default)]
    properties: StatusProps,
}

#[derive(Deserialize, Default)]
struct StatusProps {
    #[serde(default)]
    status: Option<String>,
}

/// What a share request is made of, already checked.
#[derive(Debug, Clone)]
pub struct Grant<'a> {
    pub vault_id: &'a str,
    pub secret: &'a str,
    /// The recipient's object ID, confirmed through Graph.
    pub principal_id: &'a str,
    /// ARM's `principalType`: `User` or `Group`.
    pub principal_type: &'static str,
    pub sharer_oid: &'a str,
    /// The end date, Unix seconds at midnight UTC.
    pub until: i64,
}

impl Grant<'_> {
    fn checked(&self) -> Result<String, AzureError> {
        let scope = secret_scope(self.vault_id, self.secret).ok_or(AzureError::Unreadable)?;
        if !is_guid(self.principal_id)
            || !is_guid(self.sharer_oid)
            || !matches!(self.principal_type, "User" | "Group")
        {
            return Err(AzureError::Unreadable);
        }
        Ok(scope)
    }
}

/// PIM `AdminAssign` with an end date, at the secret's scope. Returns
/// ARM's `status` as an [`Outcome`].
pub async fn grant_pim(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    g: &Grant<'_>,
) -> Result<Outcome, AzureError> {
    let scope = g.checked()?;
    let role = role_definition_id(g.vault_id);
    let text = marker(g.sharer_oid, g.until);
    let body = ScheduleBody {
        properties: ScheduleProps {
            principal_id: g.principal_id,
            role_definition_id: &role,
            request_type: "AdminAssign",
            justification: &text,
            schedule_info: Some(Schedule {
                start_date_time: crate::audit::rfc3339_millis(std::time::SystemTime::now()),
                expiration: Expiration {
                    kind: "AfterDateTime",
                    end_date_time: end_of_day(g.until),
                },
            }),
        },
    };
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/{}?api-version={PIM_API}",
        crate::audit::new_uuid()
    );
    let reply: StatusReply = azure
        .send_json(session, Resource::Management, Method::PUT, &url, &body)
        .await?;
    Ok(Outcome::of(
        reply.properties.status.as_deref().unwrap_or_default(),
    ))
}

/// PIM `AdminRemove` for a share Keyring made through PIM.
pub async fn revoke_pim(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
    secret: &str,
    principal_id: &str,
    sharer_oid: &str,
) -> Result<Outcome, AzureError> {
    let scope = secret_scope(vault_id, secret).ok_or(AzureError::Unreadable)?;
    if !is_guid(principal_id) || !is_guid(sharer_oid) {
        return Err(AzureError::Unreadable);
    }
    let role = role_definition_id(vault_id);
    let text = format!("Revoked by Keyring by {}", sharer_oid.to_ascii_lowercase());
    let body = ScheduleBody {
        properties: ScheduleProps {
            principal_id,
            role_definition_id: &role,
            request_type: "AdminRemove",
            justification: &text,
            schedule_info: None,
        },
    };
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/{}?api-version={PIM_API}",
        crate::audit::new_uuid()
    );
    let reply: StatusReply = azure
        .send_json(session, Resource::Management, Method::PUT, &url, &body)
        .await?;
    Ok(Outcome::of(
        reply.properties.status.as_deref().unwrap_or_default(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignBody<'a> {
    properties: AssignProps<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignProps<'a> {
    principal_id: &'a str,
    principal_type: &'a str,
    role_definition_id: &'a str,
    description: &'a str,
}

#[derive(Deserialize)]
struct Named {
    #[serde(default)]
    name: String,
}

/// A plain role assignment at the secret's scope, with the fixed
/// description. Returns the new assignment's name (a GUID).
pub async fn grant_plain(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    g: &Grant<'_>,
) -> Result<String, AzureError> {
    let scope = g.checked()?;
    let role = role_definition_id(g.vault_id);
    let text = marker(g.sharer_oid, g.until);
    let name = crate::audit::new_uuid();
    let body = AssignBody {
        properties: AssignProps {
            principal_id: g.principal_id,
            principal_type: g.principal_type,
            role_definition_id: &role,
            description: &text,
        },
    };
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignments/{name}?api-version={AUTHORIZATION_API}"
    );
    let reply: Named = azure
        .send_json(session, Resource::Management, Method::PUT, &url, &body)
        .await?;
    Ok(if is_guid(&reply.name) {
        reply.name.to_ascii_lowercase()
    } else {
        name
    })
}

/// Remove a plain assignment by its name, at exactly the secret's scope.
pub async fn revoke_plain(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    vault_id: &str,
    secret: &str,
    assignment: &str,
) -> Result<(), AzureError> {
    let scope = secret_scope(vault_id, secret).ok_or(AzureError::Unreadable)?;
    if !is_guid(assignment) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignments/{}?api-version={AUTHORIZATION_API}",
        assignment.to_ascii_lowercase()
    );
    azure
        .send(session, Resource::Management, Method::DELETE, &url, None)
        .await
        .map(|_| ())
}

/// A role assignment as a share needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The assignment's name, a GUID, lower case.
    pub name: String,
    pub scope: String,
    /// The role's GUID, lower case.
    pub role: String,
    pub principal_id: String,
    pub principal_type: String,
    /// Set when the description is exactly Keyring's: (sharer, end date).
    pub keyring: Option<(String, i64)>,
}

#[derive(Deserialize)]
struct Wrapped<P> {
    #[serde(default)]
    name: String,
    properties: P,
}

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
    description: Option<String>,
}

fn assignment(w: Wrapped<AssignmentProps>) -> Option<Assignment> {
    let p = w.properties;
    if !is_guid(&w.name) || !is_guid(&p.principal_id) || !is_safe_resource_id(&p.scope) {
        return None;
    }
    let role = role_guid(&p.role_definition_id)?.to_ascii_lowercase();
    Some(Assignment {
        name: w.name.to_ascii_lowercase(),
        scope: p.scope,
        role,
        principal_id: p.principal_id.to_ascii_lowercase(),
        principal_type: p
            .principal_type
            .filter(|t| t.bytes().all(|b| b.is_ascii_alphabetic()) && t.len() <= 32)
            .unwrap_or_default(),
        keyring: p.description.as_deref().and_then(read_marker),
    })
}

/// Role assignments ARM lists for `scope` with `filter` (empty for none).
/// Rows with anything but plain IDs are dropped.
pub async fn assignments(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
    filter: &str,
) -> Result<Vec<Assignment>, AzureError> {
    if !is_safe_resource_id(scope) {
        return Err(AzureError::Unreadable);
    }
    let filter = if filter.is_empty() {
        String::new()
    } else {
        format!("&$filter={filter}")
    };
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignments?api-version={AUTHORIZATION_API}{filter}"
    );
    let rows: Vec<Wrapped<AssignmentProps>> = list_all(azure, session, management_url, url).await?;
    Ok(rows.into_iter().filter_map(assignment).collect())
}

/// A share Keyring made through PIM, from its `AdminAssign` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimShare {
    pub scope: String,
    pub principal_id: String,
    pub principal_type: String,
    /// The sharer, from the request's fixed justification.
    pub sharer: String,
    /// The end date from the justification, midnight UTC.
    pub until: i64,
    /// When the request was made, for telling a later share from an
    /// earlier revoke.
    pub created: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestProps {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role_definition_id: String,
    #[serde(default)]
    principal_id: String,
    #[serde(default)]
    principal_type: Option<String>,
    #[serde(default)]
    request_type: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    created_on: Option<String>,
}

/// Keyring's PIM shares among the schedule requests at `scope` (`filter`
/// `atScope()` at a secret, or `asRequestor()` at a vault): `AdminAssign`
/// of Key Vault Secrets User with Keyring's fixed justification, that PIM
/// accepted. A later `AdminRemove` by Keyring for the same principal and
/// scope cancels an earlier one.
pub async fn pim_shares(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
    filter: &str,
) -> Result<Vec<PimShare>, AzureError> {
    if !is_safe_resource_id(scope) || !matches!(filter, "atScope()" | "asRequestor()") {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version={PIM_API}&$filter={filter}"
    );
    let rows: Vec<Wrapped<RequestProps>> = list_all(azure, session, management_url, url).await?;
    let mut shares: Vec<PimShare> = Vec::new();
    let mut removed: Vec<(String, String, Option<i64>)> = Vec::new();
    for w in rows {
        let p = w.properties;
        let is_su =
            role_guid(&p.role_definition_id).is_some_and(|g| g.eq_ignore_ascii_case(SECRETS_USER));
        if !is_su || !is_guid(&p.principal_id) || !is_safe_resource_id(&p.scope) {
            continue;
        }
        let done = p
            .status
            .as_deref()
            .is_some_and(|s| Outcome::of(s) == Outcome::Done);
        let created = p.created_on.as_deref().and_then(parse_time);
        match p.request_type.as_deref() {
            Some("AdminAssign") if done => {
                let Some((sharer, until)) = p.justification.as_deref().and_then(read_marker) else {
                    continue;
                };
                shares.push(PimShare {
                    scope: p.scope,
                    principal_id: p.principal_id.to_ascii_lowercase(),
                    principal_type: p
                        .principal_type
                        .filter(|t| t.bytes().all(|b| b.is_ascii_alphabetic()) && t.len() <= 32)
                        .unwrap_or_default(),
                    sharer,
                    until,
                    created,
                });
            }
            Some("AdminRemove")
                if done
                    && p.justification
                        .as_deref()
                        .is_some_and(|j| j.starts_with("Revoked by Keyring by ")) =>
            {
                removed.push((p.scope, p.principal_id.to_ascii_lowercase(), created));
            }
            _ => {}
        }
    }
    shares.retain(|s| {
        !removed.iter().any(|(scope, pid, at)| {
            scope.eq_ignore_ascii_case(&s.scope)
                && *pid == s.principal_id
                && match (at, s.created) {
                    (Some(r), Some(c)) => *r >= c,
                    _ => true,
                }
        })
    });
    Ok(shares)
}

/// The Azure codes that mean PIM can't be used for this share, so Keyring
/// makes a plain assignment instead: no licence, or a PIM setting refused.
pub fn falls_back(err: &AzureError) -> bool {
    matches!(
        err,
        AzureError::Status { code: Some(c), .. }
            if c == LICENCE_REQUIRED || c == crate::azure::pim::POLICY_FAILED
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str =
        "/subscriptions/sub-a/resourceGroups/rg-kv/providers/Microsoft.KeyVault/vaults/kv-test";
    const OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";

    #[test]
    fn scopes_come_only_from_checked_parts() {
        assert_eq!(
            secret_scope(VAULT, "db-password").as_deref(),
            Some(&*format!("{VAULT}/secrets/db-password"))
        );
        for bad in ["", "-x", "a/b", "../x", "a b", "a?b"] {
            assert!(secret_scope(VAULT, bad).is_none(), "{bad}");
        }
        for bad in [
            "/subscriptions/s/resourceGroups/rg",
            "https://evil.example/subscriptions/s/providers/Microsoft.KeyVault/vaults/kv",
            "/subscriptions/s/providers/Microsoft.KeyVault/vaults/kv/../x",
            "/subscriptions/s/providers/Microsoft.KeyVault/vaults/k_v",
        ] {
            assert!(secret_scope(bad, "db").is_none(), "{bad}");
        }
        let s = secret_scope(VAULT, "db").unwrap();
        assert_eq!(secret_in(&s, VAULT).as_deref(), Some("db"));
        assert_eq!(
            secret_in(&s.to_ascii_uppercase(), VAULT).as_deref(),
            Some("DB")
        );
        assert!(secret_in(VAULT, VAULT).is_none());
        assert!(secret_in(&format!("{VAULT}/secrets/db/x"), VAULT).is_none());
        assert!(secret_in(&format!("{VAULT}/keys/db"), VAULT).is_none());
        assert!(role_definition_id(VAULT).starts_with("/subscriptions/sub-a/providers/"));
    }

    #[test]
    fn markers_are_fixed_form() {
        let day = crate::dates::parse_iso_date("2026-11-25").unwrap();
        let m = marker(OID, day);
        assert_eq!(
            m,
            "Shared by Keyring by aaaaaaaa-0000-0000-0000-000000000001 until 25-11-2026"
        );
        assert_eq!(read_marker(&m), Some((OID.to_owned(), day)));
        for bad in [
            "",
            "Shared by Keyring by x until 25-11-2026",
            "Shared by Keyring by aaaaaaaa-0000-0000-0000-000000000001 until 31-02-2026",
            "Shared by Keyring by aaaaaaaa-0000-0000-0000-000000000001 until 2026-11-25",
            "Shared by Keyring by aaaaaaaa-0000-0000-0000-000000000001 until 25-11-2026 and more",
            "shared by someone",
        ] {
            assert_eq!(read_marker(bad), None, "{bad}");
        }
        assert_eq!(end_of_day(day), "2026-11-25T23:59:59Z");
    }

    #[test]
    fn only_licence_and_policy_fall_back() {
        let e = |status, code: &str| AzureError::Status {
            status,
            code: Some(code.into()),
            message: None,
        };
        assert!(falls_back(&e(400, LICENCE_REQUIRED)));
        assert!(falls_back(&e(400, crate::azure::pim::POLICY_FAILED)));
        assert!(!falls_back(&e(403, "AuthorizationFailed")));
        assert!(!falls_back(&AzureError::Unreadable));
    }

    #[test]
    fn requests_are_documented_shapes() {
        let day = crate::dates::parse_iso_date("2026-11-25").unwrap();
        let body = ScheduleBody {
            properties: ScheduleProps {
                principal_id: OID,
                role_definition_id: "/r",
                request_type: "AdminAssign",
                justification: "j",
                schedule_info: Some(Schedule {
                    start_date_time: "2026-11-18T00:00:00.000Z".into(),
                    expiration: Expiration {
                        kind: "AfterDateTime",
                        end_date_time: end_of_day(day),
                    },
                }),
            },
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["properties"]["requestType"], "AdminAssign");
        assert_eq!(
            v["properties"]["scheduleInfo"]["expiration"],
            serde_json::json!({"type": "AfterDateTime", "endDateTime": "2026-11-25T23:59:59Z"})
        );
    }
}
