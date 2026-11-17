//! PIM for Azure resources: the signed-in person's own eligible and active
//! role assignments, the PIM settings for a role, and requests to turn a
//! role on (`SelfActivate`) or off (`SelfDeactivate`). Read and sent
//! through ARM as the signed-in person, with their on-behalf-of Management
//! token, api-version 2020-10-01.
//!
//! Shapes are from Microsoft's REST reference for
//! `roleEligibilityScheduleInstances`, `roleAssignmentScheduleInstances`,
//! `roleAssignmentScheduleRequests` and `roleManagementPolicyAssignments`
//! (api-version 2020-10-01). Keyring keeps no request state: whether a
//! request is waiting for approval is read back from ARM each time.

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::audit::is_safe_resource_id;
use crate::azure::authz::{is_guid, list_all, role_guid};
use crate::azure::{AzureClient, AzureError, Resource};

/// Every PIM call.
pub const PIM_API: &str = "2020-10-01";

/// Longest activation offered when PIM's settings can't be read. Eight
/// hours is PIM's own default maximum for Azure resource roles.
pub const DEFAULT_MAX_MINUTES: u32 = 8 * 60;

/// The longest activation Keyring ever asks for, whatever the policy says.
pub const HARD_MAX_MINUTES: u32 = 24 * 60;

/// An eligible assignment the signed-in person can turn on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eligibility {
    pub scope: String,
    /// The role's GUID, lower case.
    pub role: String,
    pub role_definition_id: String,
    /// What `linkedRoleEligibilityScheduleId` is set to on activation.
    pub schedule_id: String,
    /// When the eligibility itself ends, Unix seconds.
    pub ends: Option<i64>,
}

/// A role the signed-in person holds now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    pub scope: String,
    pub role: String,
    pub role_definition_id: String,
    /// Turned on through PIM (`Activated`), so it can be turned off.
    pub activated: bool,
    /// Unix seconds. `None` for a permanent assignment.
    pub ends: Option<i64>,
}

/// A request the person made that is still waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub scope: String,
    pub role: String,
    /// ARM's status, such as `PendingApproval`. Checked to be a plain word.
    pub status: String,
}

/// What PIM asks for when this role is turned on. From the role's
/// `roleManagementPolicyAssignments` entry, `effectiveRules` with
/// `target.caller` `EndUser` and `target.level` `Assignment`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// `Expiration_EndUser_Assignment.maximumDuration`, in minutes.
    pub max_minutes: Option<u32>,
    pub justification: bool,
    pub ticket: bool,
    pub mfa: bool,
    pub approval: bool,
    /// Primary approvers' `description` and `userType`, as ARM gives them.
    /// Cleaned of control characters and cut to [`MAX_APPROVER_CHARS`].
    pub approvers: Vec<(String, String)>,
    /// `AuthenticationContext_EndUser_Assignment.claimValue` when enabled.
    pub auth_context: Option<String>,
}

/// Longest approver description shown.
pub const MAX_APPROVER_CHARS: usize = 80;
/// Most approvers shown.
pub const MAX_APPROVERS: usize = 10;

#[derive(Deserialize)]
struct Wrapped<P> {
    properties: P,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceProps {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role_definition_id: String,
    #[serde(default)]
    role_eligibility_schedule_id: Option<String>,
    #[serde(default)]
    assignment_type: Option<String>,
    #[serde(default)]
    end_date_time: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    request_type: Option<String>,
}

/// A scope PIM works at: a subscription or below, or a management group.
pub fn is_safe_scope(scope: &str) -> bool {
    if is_safe_resource_id(scope) {
        return true;
    }
    let lower = scope.to_ascii_lowercase();
    lower
        .strip_prefix("/providers/microsoft.management/managementgroups/")
        .is_some_and(|name| {
            (1..=90).contains(&name.len())
                && name.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'(' | b')')
                })
                && !name.contains("..")
        })
}

fn url(management_url: &str, scope: &str, what: &str, filter: &str) -> Result<String, AzureError> {
    if !is_safe_resource_id(scope) {
        return Err(AzureError::Unreadable);
    }
    Ok(format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/{what}?api-version={PIM_API}&$filter={filter}"
    ))
}

/// The signed-in person's eligible assignments (`$filter=asTarget()`),
/// including through groups. Callers keep the ones that reach their scope.
pub async fn my_eligibilities(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Vec<Eligibility>, AzureError> {
    let first = url(
        management_url,
        scope,
        "roleEligibilityScheduleInstances",
        "asTarget()",
    )?;
    let rows: Vec<Wrapped<InstanceProps>> = list_all(azure, session, management_url, first).await?;
    Ok(rows
        .into_iter()
        .filter_map(|w| {
            let p = w.properties;
            // What ARM returned goes into a request address and body, so
            // a row with anything but a plain scope and plain IDs is
            // dropped here, before it can be offered or used.
            if !is_safe_scope(&p.scope) || !is_safe_id(&p.role_definition_id) {
                return None;
            }
            let role = role_guid(&p.role_definition_id)?.to_ascii_lowercase();
            let schedule_id = p.role_eligibility_schedule_id.filter(|s| is_safe_id(s))?;
            Some(Eligibility {
                scope: p.scope,
                role,
                role_definition_id: p.role_definition_id,
                schedule_id,
                ends: p.end_date_time.as_deref().and_then(parse_time),
            })
        })
        .collect())
}

/// The signed-in person's active assignments
/// (`roleAssignmentScheduleInstances`, `$filter=asTarget()`).
pub async fn my_active(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Vec<Active>, AzureError> {
    let first = url(
        management_url,
        scope,
        "roleAssignmentScheduleInstances",
        "asTarget()",
    )?;
    let rows: Vec<Wrapped<InstanceProps>> = list_all(azure, session, management_url, first).await?;
    Ok(rows
        .into_iter()
        .filter_map(|w| {
            let p = w.properties;
            if !is_safe_scope(&p.scope) || !is_safe_id(&p.role_definition_id) {
                return None;
            }
            let role = role_guid(&p.role_definition_id)?.to_ascii_lowercase();
            Some(Active {
                scope: p.scope,
                role,
                role_definition_id: p.role_definition_id,
                activated: p
                    .assignment_type
                    .is_some_and(|t| t.eq_ignore_ascii_case("Activated")),
                ends: p.end_date_time.as_deref().and_then(parse_time),
            })
        })
        .collect())
}

/// Requests the signed-in person made (`$filter=asRequestor()`) that are
/// still waiting for approval or to be set up.
pub async fn my_pending(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
) -> Result<Vec<Pending>, AzureError> {
    let first = url(
        management_url,
        scope,
        "roleAssignmentScheduleRequests",
        "asRequestor()",
    )?;
    let rows: Vec<Wrapped<InstanceProps>> = list_all(azure, session, management_url, first).await?;
    Ok(rows
        .into_iter()
        .filter_map(|w| {
            let p = w.properties;
            let status = p.status.filter(|s| is_word(s))?;
            let activating = p
                .request_type
                .is_some_and(|t| t.eq_ignore_ascii_case("SelfActivate"));
            (activating && Outcome::of(&status) == Outcome::Waiting).then_some(())?;
            Some(Pending {
                scope: p.scope,
                role: role_guid(&p.role_definition_id)?.to_ascii_lowercase(),
                status,
            })
        })
        .collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyAssignmentProps {
    #[serde(default)]
    role_definition_id: String,
    #[serde(default)]
    effective_rules: Vec<serde_json::Value>,
}

/// PIM's settings for activating `role` at `scope`, from
/// `{scope}/providers/Microsoft.Authorization/roleManagementPolicyAssignments`.
/// `None` when no assignment there names the role.
pub async fn policy(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
    role: &str,
) -> Result<Option<Policy>, AzureError> {
    if !is_safe_scope(scope) || !is_guid(role) {
        return Err(AzureError::Unreadable);
    }
    let first = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version={PIM_API}"
    );
    let rows: Vec<Wrapped<PolicyAssignmentProps>> =
        list_all(azure, session, management_url, first).await?;
    Ok(rows
        .into_iter()
        .find(|w| {
            role_guid(&w.properties.role_definition_id)
                .is_some_and(|g| g.eq_ignore_ascii_case(role))
        })
        .map(|w| policy_from_rules(&w.properties.effective_rules)))
}

/// Read the end-user activation rules out of `effectiveRules`.
pub fn policy_from_rules(rules: &[serde_json::Value]) -> Policy {
    let mut p = Policy::default();
    for r in rules {
        let target = &r["target"];
        let end_user = target["caller"]
            .as_str()
            .is_some_and(|c| c.eq_ignore_ascii_case("EndUser"))
            && target["level"]
                .as_str()
                .is_some_and(|l| l.eq_ignore_ascii_case("Assignment"));
        if !end_user {
            continue;
        }
        match r["ruleType"].as_str().unwrap_or_default() {
            "RoleManagementPolicyExpirationRule" => {
                p.max_minutes = r["maximumDuration"].as_str().and_then(iso_minutes);
            }
            "RoleManagementPolicyEnablementRule" => {
                let on = |name: &str| {
                    r["enabledRules"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(name)))
                };
                p.justification = on("Justification");
                p.ticket = on("Ticketing");
                p.mfa = on("MultiFactorAuthentication");
            }
            "RoleManagementPolicyApprovalRule" => {
                let s = &r["setting"];
                p.approval = s["isApprovalRequired"].as_bool().unwrap_or(false);
                if p.approval {
                    p.approvers = s["approvalStages"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .flat_map(|st| st["primaryApprovers"].as_array().into_iter().flatten())
                        .filter_map(|a| {
                            let d = clean_line(a["description"].as_str()?, MAX_APPROVER_CHARS)?;
                            let t = a["userType"].as_str().filter(|t| is_word(t)).unwrap_or("");
                            Some((d, t.to_owned()))
                        })
                        .take(MAX_APPROVERS)
                        .collect();
                }
            }
            "RoleManagementPolicyAuthenticationContextRule"
                if r["isEnabled"].as_bool().unwrap_or(false) =>
            {
                p.auth_context = r["claimValue"]
                    .as_str()
                    .and_then(crate::auth::step_up::auth_context_id);
            }
            _ => {}
        }
    }
    p
}

/// What a request to turn a role on or off came back as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// On (or off) now, or being set up without anyone needing to approve.
    Done,
    /// Someone has to approve it first.
    Waiting,
    /// PIM said no.
    Refused,
}

impl Outcome {
    /// From ARM's `status`. Unknown values count as refused, so Keyring
    /// never says a role is on when it can't tell.
    pub fn of(status: &str) -> Self {
        match status {
            "Provisioned"
            | "Granted"
            | "ScheduleCreated"
            | "Accepted"
            | "AdminApproved"
            | "PendingProvisioning"
            | "ProvisioningStarted"
            | "PendingScheduleCreation"
            | "PendingExternalProvisioning"
            | "PendingEvaluation"
            | "PendingRevocation"
            | "Revoked" => Self::Done,
            "PendingApproval" | "PendingApprovalProvisioning" | "PendingAdminDecision" => {
                Self::Waiting
            }
            _ => Self::Refused,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestBody<'a> {
    properties: RequestProps<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestProps<'a> {
    principal_id: &'a str,
    role_definition_id: &'a str,
    request_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    linked_role_eligibility_schedule_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule_info: Option<ScheduleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket_info: Option<TicketInfo<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScheduleInfo {
    start_date_time: String,
    expiration: Expiration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Expiration {
    #[serde(rename = "type")]
    kind: &'static str,
    duration: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TicketInfo<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket_system: Option<&'a str>,
    ticket_number: &'a str,
}

#[derive(Deserialize)]
struct RequestReply {
    #[serde(default)]
    properties: RequestReplyProps,
}

#[derive(Deserialize, Default)]
struct RequestReplyProps {
    #[serde(default)]
    status: Option<String>,
}

/// What a person asked for, already checked.
#[derive(Debug, Clone)]
pub struct Activation<'a> {
    pub principal_id: &'a str,
    pub eligibility: &'a Eligibility,
    pub minutes: u32,
    pub justification: Option<&'a str>,
    pub ticket_system: Option<&'a str>,
    pub ticket_number: Option<&'a str>,
}

/// `PUT {scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/{new GUID}`
/// with `requestType` `SelfActivate`, at the eligibility's own scope.
/// Returns ARM's `status`, checked to be a plain word.
pub async fn activate(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    a: &Activation<'_>,
) -> Result<String, AzureError> {
    let e = a.eligibility;
    if !is_guid(a.principal_id) || !(1..=HARD_MAX_MINUTES).contains(&a.minutes) {
        return Err(AzureError::Unreadable);
    }
    let body = RequestBody {
        properties: RequestProps {
            principal_id: a.principal_id,
            role_definition_id: &e.role_definition_id,
            request_type: "SelfActivate",
            linked_role_eligibility_schedule_id: Some(&e.schedule_id),
            schedule_info: Some(ScheduleInfo {
                start_date_time: crate::audit::rfc3339_millis(std::time::SystemTime::now()),
                expiration: Expiration {
                    kind: "AfterDuration",
                    duration: iso_duration(a.minutes),
                },
            }),
            justification: a.justification,
            ticket_info: a.ticket_number.map(|n| TicketInfo {
                ticket_system: a.ticket_system,
                ticket_number: n,
            }),
        },
    };
    send(azure, session, management_url, &e.scope, &body).await
}

/// `SelfDeactivate` for an active role at its own scope.
pub async fn deactivate(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    principal_id: &str,
    active: &Active,
) -> Result<String, AzureError> {
    if !is_guid(principal_id) {
        return Err(AzureError::Unreadable);
    }
    let body = RequestBody {
        properties: RequestProps {
            principal_id,
            role_definition_id: &active.role_definition_id,
            request_type: "SelfDeactivate",
            linked_role_eligibility_schedule_id: None,
            schedule_info: None,
            justification: None,
            ticket_info: None,
        },
    };
    send(azure, session, management_url, &active.scope, &body).await
}

async fn send(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    scope: &str,
    body: &RequestBody<'_>,
) -> Result<String, AzureError> {
    if !is_safe_scope(scope) || !is_safe_id(body.properties.role_definition_id) {
        return Err(AzureError::Unreadable);
    }
    let url = format!(
        "{management_url}{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/{}?api-version={PIM_API}",
        crate::audit::new_uuid()
    );
    let reply: RequestReply = azure
        .send_json(session, Resource::Management, Method::PUT, &url, body)
        .await?;
    Ok(reply
        .properties
        .status
        .filter(|s| is_word(s))
        .unwrap_or_else(|| "Unknown".to_owned()))
}

/// The ARM error code PIM gives when the activation needs a stronger
/// sign-in: MFA or a Conditional Access authentication context.
pub const ACRS_FAILED: &str = "RoleAssignmentRequestAcrsValidationFailed";
/// The code for a request that breaks one of the role's PIM settings.
pub const POLICY_FAILED: &str = "RoleAssignmentRequestPolicyValidationFailed";

/// Which PIM setting a refused request broke, from the rule name in ARM's
/// message (`The following policy rules failed: ["ExpirationRule"]`). The
/// message is only searched for these names, never shown or logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokenRule {
    Expiration,
    Justification,
    Ticketing,
    Mfa,
    Eligibility,
}

pub fn broken_rules(err: &AzureError) -> Vec<BrokenRule> {
    let AzureError::Status {
        code: Some(code),
        message: Some(m),
        ..
    } = err
    else {
        return Vec::new();
    };
    if code != POLICY_FAILED {
        return Vec::new();
    }
    [
        ("ExpirationRule", BrokenRule::Expiration),
        ("JustificationRule", BrokenRule::Justification),
        ("TicketingRule", BrokenRule::Ticketing),
        ("MfaRule", BrokenRule::Mfa),
        ("EligibilityRule", BrokenRule::Eligibility),
    ]
    .into_iter()
    .filter(|(n, _)| m.contains(&format!("\"{n}\"")))
    .map(|(_, r)| r)
    .collect()
}

/// Largest claims challenge Keyring will pass on, in bytes, as for #235.
pub const MAX_CLAIMS_BYTES: usize = 4096;

/// The claims challenge in a refused activation, checked and rebuilt.
///
/// Microsoft doesn't document the shape for Azure resource roles. What is
/// seen in the field is ARM's code [`ACRS_FAILED`] with the challenge in
/// the message as `&claims=` and URL-encoded JSON, such as
/// `{"access_token":{"acrs":{"essential":true,"value":"c1"}}}`. Base64 JSON
/// is accepted too. Only a JSON object whose top-level keys are
/// `access_token` or `id_token` is kept, every `acrs` value must be an
/// authentication context ID (`c1` to `c99`), and the result is
/// re-serialised from the parsed value, so nothing from Azure is passed
/// on as it came.
pub fn claims_challenge(err: &AzureError) -> Option<String> {
    let AzureError::Status {
        code: Some(code),
        message: Some(m),
        ..
    } = err
    else {
        return None;
    };
    if code != ACRS_FAILED {
        return None;
    }
    let at = m.find("claims=")? + "claims=".len();
    let raw: String = m[at..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '&' | '"' | '\'' | ',' | ';'))
        .take(MAX_CLAIMS_BYTES * 3)
        .collect();
    let decoded = percent_decode(&raw).filter(|s| s.trim_start().starts_with('{'));
    let json = decoded.or_else(|| {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let t = raw.trim_end_matches('=');
        URL_SAFE_NO_PAD
            .decode(t)
            .or_else(|_| STANDARD.decode(&raw))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    })?;
    checked_claims(&json)
}

/// Rebuild a claims request from `json`, keeping only what Keyring
/// understands. See [`claims_challenge`].
pub fn checked_claims(json: &str) -> Option<String> {
    if json.len() > MAX_CLAIMS_BYTES {
        return None;
    }
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json).ok()?;
    if map.is_empty() || map.len() > 2 {
        return None;
    }
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        if k != "access_token" && k != "id_token" {
            return None;
        }
        let inner = v.as_object()?;
        let acrs = inner.get("acrs")?.as_object()?;
        let mut kept = serde_json::Map::new();
        if let Some(e) = acrs.get("essential") {
            kept.insert("essential".into(), serde_json::Value::Bool(e.as_bool()?));
        }
        if let Some(v) = acrs.get("value") {
            let id = crate::auth::step_up::auth_context_id(v.as_str()?)?;
            kept.insert("value".into(), id.into());
        }
        if let Some(vs) = acrs.get("values") {
            let ids: Option<Vec<serde_json::Value>> = vs
                .as_array()?
                .iter()
                .take(10)
                .map(|v| {
                    v.as_str()
                        .and_then(crate::auth::step_up::auth_context_id)
                        .map(Into::into)
                })
                .collect();
            kept.insert("values".into(), ids?.into());
        }
        if !kept.contains_key("value") && !kept.contains_key("values") {
            return None;
        }
        out.insert(k, serde_json::json!({ "acrs": kept }));
    }
    let s = serde_json::Value::Object(out).to_string();
    (s.len() <= MAX_CLAIMS_BYTES).then_some(s)
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// `PT8H`, `PT30M`, `P1D`, `P1DT2H`. `None` for anything else, or longer
/// than a year.
pub fn iso_minutes(s: &str) -> Option<u32> {
    let rest = s.trim().strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => (d, t),
        None => (rest, ""),
    };
    let mut total: u64 = 0;
    let mut take = |part: &str, units: &[(char, u64)]| -> Option<()> {
        let mut num = String::new();
        let mut last = 0usize;
        for c in part.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let idx = units.iter().position(|(u, _)| *u == c)?;
            if idx < last || num.is_empty() || num.len() > 6 {
                return None;
            }
            last = idx + 1;
            total += num.parse::<u64>().ok()? * units[idx].1;
            num.clear();
        }
        num.is_empty().then_some(())
    };
    take(date, &[('W', 7 * 24 * 60), ('D', 24 * 60)])?;
    take(time, &[('H', 60), ('M', 1)])?;
    if rest.is_empty() || rest.ends_with('T') || total == 0 || total > 366 * 24 * 60 {
        return None;
    }
    u32::try_from(total).ok()
}

/// `PT2H30M` for 150 minutes.
pub fn iso_duration(minutes: u32) -> String {
    match (minutes / 60, minutes % 60) {
        (h, 0) => format!("PT{h}H"),
        (0, m) => format!("PT{m}M"),
        (h, m) => format!("PT{h}H{m}M"),
    }
}

/// `2026-11-17T09:30:05.91Z` or with an offset, to Unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 || !s.is_ascii() {
        return None;
    }
    let date = crate::dates::parse_iso_date(&s[..10])?;
    if &s[10..11] != "T" && &s[10..11] != "t" {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<i64>().ok();
    let (h, m, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if &s[13..14] != ":" || &s[16..17] != ":" || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) && &o[3..4] == ":" => {
            let oh: i64 = o[1..3].parse().ok()?;
            let om: i64 = o[4..6].parse().ok()?;
            let v = oh * 3600 + om * 60;
            if o.starts_with('+') { v } else { -v }
        }
        _ => return None,
    };
    Some(date + h * 3600 + m * 60 + sec - offset)
}

/// Letters and digits only, up to 64: ARM's enum values.
fn is_word(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// An ARM ID or a bare GUID, as `linkedRoleEligibilityScheduleId` may be.
fn is_safe_id(s: &str) -> bool {
    is_guid(s)
        || (s.len() <= 1024
            && s.starts_with('/')
            && !s.contains("..")
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'(' | b')')
            }))
}

/// One line of text from a person or from Azure, made safe to show, send
/// and log: control, format and other invisible characters out (the same
/// check as the reveal reason, [`crate::reason::is_unsafe`]), runs of
/// white space made one space, trimmed. `None` if empty after that or
/// longer than `max` characters. Length is counted after cleaning, so
/// invisible characters can't pad a line up to a minimum.
pub fn clean_line(raw: &str, max: usize) -> Option<String> {
    if raw.len() > max * 16 {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    let mut gap = false;
    for c in raw.chars() {
        if c.is_whitespace() || crate::reason::is_unsafe(c) {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    let n = out.chars().count();
    (1..=max).contains(&n).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: &str, message: &str) -> AzureError {
        AzureError::Status {
            status: 400,
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }

    #[test]
    fn durations() {
        assert_eq!(iso_minutes("PT8H"), Some(480));
        assert_eq!(iso_minutes("PT30M"), Some(30));
        assert_eq!(iso_minutes("PT1H30M"), Some(90));
        assert_eq!(iso_minutes("P1D"), Some(1440));
        assert_eq!(iso_minutes("P1DT2H"), Some(1560));
        assert_eq!(iso_minutes("P1W"), Some(7 * 1440));
        for bad in [
            "", "P", "PT", "8H", "PT8", "PTH", "PT30M8H", "P1H", "PT-1H", "PT0H", "P999D", "PT1.5H",
        ] {
            assert_eq!(iso_minutes(bad), None, "{bad}");
        }
        assert_eq!(iso_duration(480), "PT8H");
        assert_eq!(iso_duration(30), "PT30M");
        assert_eq!(iso_duration(90), "PT1H30M");
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("1970-01-01T01:00:00.913Z"), Some(3600));
        assert_eq!(parse_time("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_time("2020-09-10T05:35:17.91Z"), Some(1_599_716_117));
        for bad in [
            "",
            "2020-09-10",
            "2020-09-10 05:35:17Z",
            "2020-13-10T05:35:17Z",
            "2020-09-10T25:00:00Z",
            "2020-09-10T05:35:17Q",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn outcomes() {
        assert_eq!(Outcome::of("Provisioned"), Outcome::Done);
        assert_eq!(Outcome::of("Granted"), Outcome::Done);
        assert_eq!(Outcome::of("PendingApproval"), Outcome::Waiting);
        assert_eq!(Outcome::of("PendingAdminDecision"), Outcome::Waiting);
        for s in [
            "Denied",
            "Failed",
            "AdminDenied",
            "TimedOut",
            "Invalid",
            "Canceled",
            "Whatever",
        ] {
            assert_eq!(Outcome::of(s), Outcome::Refused, "{s}");
        }
    }

    #[test]
    fn rules_from_the_documented_example() {
        let rules: Vec<serde_json::Value> = serde_json::from_value(serde_json::json!([
            {"enabledRules": ["MultiFactorAuthentication", "Justification"], "id": "Enablement_Admin_Assignment",
             "ruleType": "RoleManagementPolicyEnablementRule", "target": {"caller": "Admin", "level": "Assignment"}},
            {"isExpirationRequired": false, "maximumDuration": "P90D", "id": "Expiration_Admin_Assignment",
             "ruleType": "RoleManagementPolicyExpirationRule", "target": {"caller": "Admin", "level": "Assignment"}},
            {"setting": {"isApprovalRequired": true, "approvalStages": [{"primaryApprovers": [
                {"id": "2385b0f3-5fa9-43cf-8ca4-b01dc97298cd", "description": "kv\u{202E}-approvers\n", "isBackup": false, "userType": "Group"}]}]},
             "id": "Approval_EndUser_Assignment", "ruleType": "RoleManagementPolicyApprovalRule",
             "target": {"caller": "EndUser", "level": "Assignment"}},
            {"isEnabled": true, "claimValue": "c2", "id": "AuthenticationContext_EndUser_Assignment",
             "ruleType": "RoleManagementPolicyAuthenticationContextRule", "target": {"caller": "EndUser", "level": "Assignment"}},
            {"enabledRules": ["MultiFactorAuthentication", "Justification", "Ticketing"], "id": "Enablement_EndUser_Assignment",
             "ruleType": "RoleManagementPolicyEnablementRule", "target": {"caller": "EndUser", "level": "Assignment"}},
            {"isExpirationRequired": true, "maximumDuration": "PT7H", "id": "Expiration_EndUser_Assignment",
             "ruleType": "RoleManagementPolicyExpirationRule", "target": {"caller": "EndUser", "level": "Assignment"}}
        ]))
        .unwrap();
        let p = policy_from_rules(&rules);
        assert_eq!(
            p.max_minutes,
            Some(420),
            "the end-user rule, not the admin one"
        );
        assert!(p.justification && p.ticket && p.mfa && p.approval);
        assert_eq!(
            p.approvers,
            vec![("kv -approvers".to_owned(), "Group".to_owned())]
        );
        assert_eq!(p.auth_context.as_deref(), Some("c2"));
        assert_eq!(policy_from_rules(&[]), Policy::default());
    }

    #[test]
    fn claims_challenges_are_checked_and_rebuilt() {
        let field = "New-AzRoleAssignmentScheduleRequest : &claims=%7B%22access_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%20%22value%22%3A%22c1%22%7D%7D%7D";
        assert_eq!(
            claims_challenge(&refused(ACRS_FAILED, field)).as_deref(),
            Some(r#"{"access_token":{"acrs":{"essential":true,"value":"c1"}}}"#)
        );
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(r#"{"access_token":{"acrs":{"essential":true,"value":"c3"}}}"#);
        assert!(
            claims_challenge(&refused(ACRS_FAILED, &format!("x claims={b64} y")))
                .unwrap()
                .contains("\"c3\"")
        );
        // Wrong code, no challenge, junk, a bad context ID, other keys,
        // extra claims, and too long are all dropped.
        assert_eq!(claims_challenge(&refused("Other", field)), None);
        assert_eq!(
            claims_challenge(&refused(ACRS_FAILED, "no challenge here")),
            None
        );
        assert_eq!(claims_challenge(&refused(ACRS_FAILED, "claims=%ZZ")), None);
        for bad in [
            r#"{"access_token":{"acrs":{"value":"<script>"}}}"#,
            r#"{"access_token":{"acrs":{"value":"c1\n"}}}"#,
            r#"{"userinfo":{"acrs":{"value":"c1"}}}"#,
            r#"{"access_token":{"acrs":{"essential":"yes","value":"c1"}}}"#,
            r#"{"access_token":{"xms_cc":{"values":["cp1"]}}}"#,
            r#"[1]"#,
            r#"{}"#,
        ] {
            assert_eq!(checked_claims(bad), None, "{bad}");
        }
        // Extra fields beside acrs are dropped, not passed on.
        assert_eq!(
            checked_claims(r#"{"id_token":{"acrs":{"values":["c1","c2"]},"evil":"x"}}"#).as_deref(),
            Some(r#"{"id_token":{"acrs":{"values":["c1","c2"]}}}"#)
        );
        assert_eq!(checked_claims(&"x".repeat(MAX_CLAIMS_BYTES + 1)), None);
    }

    #[test]
    fn broken_rules_come_from_names_only() {
        let e = refused(
            POLICY_FAILED,
            r#"The following policy rules failed: ["ExpirationRule","TicketingRule"]"#,
        );
        assert_eq!(
            broken_rules(&e),
            vec![BrokenRule::Expiration, BrokenRule::Ticketing]
        );
        assert!(broken_rules(&refused("Other", r#"["ExpirationRule"]"#)).is_empty());
    }

    #[test]
    fn scopes() {
        assert!(is_safe_scope("/subscriptions/s/resourceGroups/rg"));
        assert!(is_safe_scope(
            "/providers/Microsoft.Management/managementGroups/mg-root"
        ));
        assert!(!is_safe_scope(
            "/providers/Microsoft.Management/managementGroups/"
        ));
        assert!(!is_safe_scope(
            "/providers/Microsoft.Management/managementGroups/a/../b"
        ));
        assert!(!is_safe_scope(
            "/providers/Microsoft.Management/managementGroups/a?x"
        ));
        assert!(!is_safe_scope("https://evil.example/subscriptions/s"));
    }

    #[test]
    fn lines_are_cleaned() {
        assert_eq!(clean_line("  a\tb\n\nc ", 10).as_deref(), Some("a b c"));
        assert_eq!(
            clean_line("a\u{202E}b\u{200B}c", 10).as_deref(),
            Some("a b c")
        );
        assert_eq!(clean_line("\u{0007}", 10), None);
        assert_eq!(clean_line("", 10), None);
        assert_eq!(clean_line(&"é".repeat(11), 10), None);
        assert_eq!(
            clean_line(&"é".repeat(10), 10).map(|s| s.chars().count()),
            Some(10)
        );
    }
}
