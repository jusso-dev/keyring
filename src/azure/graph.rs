//! Microsoft Graph, for sharing a secret (#286) only: find a person or a
//! security group by name, confirm one by object ID or email address, and
//! name the people a secret is shared with.
//!
//! Every call is delegated: the signed-in person's on-behalf-of token for
//! `https://graph.microsoft.com`, so Graph shows only what they could see
//! themselves, in their own tenant. The app registration needs
//! `User.ReadBasic.All` and `GroupMember.Read.All` (admin consent for the
//! second). This is the only place Keyring calls Graph for names.
//!
//! What comes back is outside text. Display names are cleaned
//! ([`crate::azure::pim::clean_line`]) and capped, addresses are parsed
//! strictly ([`crate::notify::Address`]), IDs must be GUIDs, and anything
//! else is dropped. Graph's error messages are never kept: only the status
//! and code reach the caller, and only fixed words reach a page.
//!
//! The query typed into the picker is never logged: the request log has
//! no query strings, and the Azure client logs a call's path only.

use serde::Deserialize;

use crate::auth::session::Session;
use crate::azure::authz::is_guid;
use crate::azure::{AzureClient, AzureError, Resource, TokenError};
use crate::notify::Address;

/// Shortest and longest picker query, in characters.
pub const MIN_QUERY_CHARS: usize = 2;
pub const MAX_QUERY_CHARS: usize = 64;
/// Most results of each kind (people, groups).
pub const MAX_RESULTS: usize = 10;
/// Longest display name kept, in characters.
pub const MAX_NAME_CHARS: usize = 120;
/// Most IDs named in one `$filter=id in (...)` lookup, as Graph allows.
pub const MAX_IDS_PER_LOOKUP: usize = 15;

/// Graph's `ConsistencyLevel` header, which `$search` on directory objects
/// needs.
const EVENTUAL: [(&str, &str); 1] = [("ConsistencyLevel", "eventual")];

/// A person or a security group, as Graph returned them, checked.
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    /// Object ID, lower case.
    pub id: String,
    pub kind: PrincipalKind,
    /// Cleaned and capped. Never part of a link.
    pub display_name: String,
    /// Graph's `mail`, parsed strictly. The only address an email is sent
    /// to. Groups get no email.
    pub mail: Option<Address>,
    /// The sign-in name, cleaned. Shown only, never mailed.
    pub upn: String,
}

/// Names and addresses are personal data: `Debug` prints the ID and kind
/// only.
impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What kind of principal a share goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A member of the tenant.
    User,
    /// A guest (B2B) account in the tenant: its sign-in name has `#EXT#`.
    Guest,
    /// A security group.
    Group,
}

impl PrincipalKind {
    /// As written on the audit event's `principal_type`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Guest => "guest",
            Self::Group => "group",
        }
    }

    /// ARM's `principalType` for a role assignment.
    pub fn arm_type(self) -> &'static str {
        match self {
            Self::User | Self::Guest => "User",
            Self::Group => "Group",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::User => "Person",
            Self::Guest => "Guest",
            Self::Group => "Group",
        }
    }

    pub fn is_group(self) -> bool {
        self == Self::Group
    }
}

/// Why Graph couldn't help. Fixed words only: Graph's message is never
/// kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphProblem {
    /// The app registration hasn't been granted the Graph permissions, or
    /// an admin hasn't consented to them.
    NoConsent,
    /// The person's sign-in needs refreshing.
    SignInAgain,
    /// Graph was throttling.
    Busy,
    /// Anything else.
    Unavailable,
}

impl GraphProblem {
    pub fn of(e: &AzureError) -> Self {
        match e {
            AzureError::Token(TokenError::ConsentNeeded) => Self::NoConsent,
            AzureError::Token(TokenError::SignInAgain) => Self::SignInAgain,
            // Graph answers 403 Authorization_RequestDenied when the token
            // lacks the permission.
            AzureError::Status { status: 403, .. } => Self::NoConsent,
            AzureError::Status { status: 429, .. } => Self::Busy,
            _ => Self::Unavailable,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NoConsent => {
                "Keyring can't search the directory: the app registration needs the delegated Microsoft Graph permissions User.ReadBasic.All and GroupMember.Read.All, with admin consent. Type the person's email address or object ID instead."
            }
            Self::SignInAgain => "Your sign-in needs refreshing. Sign out and in again.",
            Self::Busy => "Microsoft Graph is busy. Try again in a minute.",
            Self::Unavailable => {
                "Keyring couldn't search the directory just now. Type the person's email address or object ID instead."
            }
        }
    }

    /// A short code for the picker's answer.
    pub fn code(self) -> &'static str {
        match self {
            Self::NoConsent => "consent",
            Self::SignInAgain => "sign_in",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A picker query, checked: cleaned of control and invisible characters,
/// 2 to 64 characters. `None` otherwise.
pub fn checked_query(raw: &str) -> Option<String> {
    let q = crate::azure::pim::clean_line(raw, MAX_QUERY_CHARS)?;
    (q.chars().count() >= MIN_QUERY_CHARS).then_some(q)
}

/// The text inside one `$search` clause: `"` and `\` escaped with a
/// backslash, as Microsoft's `$search` reference asks. The whole value is
/// percent-encoded afterwards by [`encode`].
pub fn escape_search(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 4);
    for c in q.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Percent-encode everything but unreserved characters (RFC 3986), so no
/// `&`, `#`, `+` or space in a query value can change the request.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `/v1.0/users?$search=...`, for people whose name or address starts with
/// (or whose name has a word starting with) `q`.
pub fn users_search_url(graph_url: &str, q: &str) -> String {
    let e = escape_search(q);
    let search = format!("\"displayName:{e}\" OR \"mail:{e}\"");
    format!(
        "{graph_url}/v1.0/users?$search={}&$select=id,displayName,mail,userPrincipalName&$top={MAX_RESULTS}&$count=true",
        encode(&search)
    )
}

/// `/v1.0/groups?$search=...&$filter=securityEnabled eq true`.
pub fn groups_search_url(graph_url: &str, q: &str) -> String {
    let e = escape_search(q);
    let search = format!("\"displayName:{e}\"");
    format!(
        "{graph_url}/v1.0/groups?$search={}&$filter={}&$select=id,displayName,mail,securityEnabled&$top={MAX_RESULTS}&$count=true",
        encode(&search),
        encode("securityEnabled eq true")
    )
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    mail: Option<String>,
    #[serde(default)]
    user_principal_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    security_enabled: Option<bool>,
}

fn name_of(raw: Option<&str>) -> String {
    raw.and_then(|n| crate::azure::pim::clean_line(n, MAX_NAME_CHARS))
        .unwrap_or_default()
}

impl UserRow {
    fn checked(self) -> Option<Principal> {
        if !is_guid(&self.id) {
            return None;
        }
        let upn = name_of(self.user_principal_name.as_deref());
        // B2B guests' sign-in names carry `#EXT#`. `userType` would say so
        // too, but User.ReadBasic.All doesn't return it.
        let kind = if upn.to_ascii_uppercase().contains("#EXT#") {
            PrincipalKind::Guest
        } else {
            PrincipalKind::User
        };
        Some(Principal {
            id: self.id.to_ascii_lowercase(),
            kind,
            display_name: name_of(self.display_name.as_deref()),
            mail: self.mail.as_deref().and_then(|m| Address::parse(m).ok()),
            upn,
        })
    }
}

impl GroupRow {
    /// Security groups only: a Microsoft 365 or distribution group can't
    /// hold an Azure role.
    fn checked(self) -> Option<Principal> {
        if !is_guid(&self.id) || self.security_enabled != Some(true) {
            return None;
        }
        Some(Principal {
            id: self.id.to_ascii_lowercase(),
            kind: PrincipalKind::Group,
            display_name: name_of(self.display_name.as_deref()),
            mail: None,
            upn: String::new(),
        })
    }
}

/// What the picker found: people and groups, or why it couldn't look.
#[derive(Debug, Clone, Default)]
pub struct Found {
    pub people: Vec<Principal>,
    pub groups: Vec<Principal>,
    /// Set when people couldn't be searched.
    pub problem: Option<GraphProblem>,
    /// Set when groups couldn't be searched (often consent for
    /// `GroupMember.Read.All` alone).
    pub groups_problem: Option<GraphProblem>,
}

/// Search people and security groups by name or address, as the person.
/// `q` must come from [`checked_query`].
pub async fn search(azure: &AzureClient, session: &Session, graph_url: &str, q: &str) -> Found {
    let (users_url, groups_url) = (
        users_search_url(graph_url, q),
        groups_search_url(graph_url, q),
    );
    let (users, groups) = tokio::join!(
        azure.get_json_with::<Page<UserRow>>(session, Resource::Graph, &users_url, &EVENTUAL),
        azure.get_json_with::<Page<GroupRow>>(session, Resource::Graph, &groups_url, &EVENTUAL),
    );
    let mut found = Found::default();
    match users {
        Ok(p) => {
            found.people = p
                .value
                .into_iter()
                .filter_map(UserRow::checked)
                .take(MAX_RESULTS)
                .collect();
        }
        Err(e) => found.problem = Some(GraphProblem::of(&e)),
    }
    match groups {
        Ok(p) => {
            found.groups = p
                .value
                .into_iter()
                .filter_map(GroupRow::checked)
                .take(MAX_RESULTS)
                .collect();
        }
        Err(e) => found.groups_problem = Some(GraphProblem::of(&e)),
    }
    found
}

/// One user by object ID, or `None` if Graph has no such user.
pub async fn user_by_id(
    azure: &AzureClient,
    session: &Session,
    graph_url: &str,
    id: &str,
) -> Result<Option<Principal>, AzureError> {
    if !is_guid(id) {
        return Ok(None);
    }
    let url = format!(
        "{graph_url}/v1.0/users/{}?$select=id,displayName,mail,userPrincipalName",
        id.to_ascii_lowercase()
    );
    match azure
        .get_json::<UserRow>(session, Resource::Graph, &url)
        .await
    {
        Ok(u) => Ok(u.checked().filter(|p| p.id.eq_ignore_ascii_case(id))),
        Err(AzureError::Status { status: 404, .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// One security group by object ID, or `None` if Graph has no such
/// group, or it isn't a security group.
pub async fn group_by_id(
    azure: &AzureClient,
    session: &Session,
    graph_url: &str,
    id: &str,
) -> Result<Option<Principal>, AzureError> {
    if !is_guid(id) {
        return Ok(None);
    }
    let url = format!(
        "{graph_url}/v1.0/groups/{}?$select=id,displayName,mail,securityEnabled",
        id.to_ascii_lowercase()
    );
    match azure
        .get_json::<GroupRow>(session, Resource::Graph, &url)
        .await
    {
        Ok(g) => Ok(g.checked().filter(|p| p.id.eq_ignore_ascii_case(id))),
        Err(AzureError::Status { status: 404, .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The one user whose `mail` or sign-in name is exactly `addr`, or `None`
/// if there isn't exactly one. The address is already strictly parsed, so
/// it holds no quote; single quotes would be doubled for OData anyway.
pub async fn user_by_address(
    azure: &AzureClient,
    session: &Session,
    graph_url: &str,
    addr: &Address,
) -> Result<Option<Principal>, AzureError> {
    let a = addr.as_str().replace('\'', "''");
    let filter = format!("mail eq '{a}' or userPrincipalName eq '{a}'");
    let url = format!(
        "{graph_url}/v1.0/users?$filter={}&$select=id,displayName,mail,userPrincipalName&$top=2",
        encode(&filter)
    );
    let page: Page<UserRow> = azure.get_json(session, Resource::Graph, &url).await?;
    let mut found: Vec<Principal> = page
        .value
        .into_iter()
        .filter_map(UserRow::checked)
        .collect();
    Ok((found.len() == 1).then(|| found.remove(0)))
}

/// A user or a security group in the person's tenant, by object ID: the
/// user first, then the group.
pub async fn principal_by_id(
    azure: &AzureClient,
    session: &Session,
    graph_url: &str,
    id: &str,
) -> Result<Option<Principal>, AzureError> {
    if let Some(u) = user_by_id(azure, session, graph_url, id).await? {
        return Ok(Some(u));
    }
    group_by_id(azure, session, graph_url, id).await
}

/// Display names for up to [`MAX_IDS_PER_LOOKUP`] object IDs, people and
/// groups, in one call for each. IDs Graph doesn't return are left out.
/// Failures leave the names out: the panel shows object IDs instead.
pub async fn names(
    azure: &AzureClient,
    session: &Session,
    graph_url: &str,
    ids: &[String],
) -> Vec<Principal> {
    let ids: Vec<String> = ids
        .iter()
        .filter(|i| is_guid(i))
        .map(|i| i.to_ascii_lowercase())
        .take(MAX_IDS_PER_LOOKUP)
        .collect();
    if ids.is_empty() {
        return Vec::new();
    }
    let list = ids
        .iter()
        .map(|i| format!("'{i}'"))
        .collect::<Vec<_>>()
        .join(",");
    let filter = encode(&format!("id in ({list})"));
    let users = format!(
        "{graph_url}/v1.0/users?$filter={filter}&$select=id,displayName,mail,userPrincipalName"
    );
    let groups =
        format!("{graph_url}/v1.0/groups?$filter={filter}&$select=id,displayName,securityEnabled");
    let (u, g) = tokio::join!(
        azure.get_json::<Page<UserRow>>(session, Resource::Graph, &users),
        azure.get_json::<Page<GroupRow>>(session, Resource::Graph, &groups),
    );
    let mut out: Vec<Principal> = u
        .map(|p| p.value.into_iter().filter_map(UserRow::checked).collect())
        .unwrap_or_default();
    out.extend(
        g.map(|p| {
            p.value
                .into_iter()
                .filter_map(GroupRow::checked)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default(),
    );
    out.retain(|p| ids.contains(&p.id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_checked() {
        assert_eq!(checked_query("  al  "), Some("al".into()));
        assert_eq!(checked_query("a"), None);
        assert_eq!(checked_query("a\u{200B}"), None, "invisible padding");
        assert_eq!(checked_query(&"x".repeat(65)), None);
        assert!(checked_query(&"x".repeat(64)).is_some());
        assert_eq!(checked_query("a\nb").as_deref(), Some("a b"));
    }

    #[test]
    fn search_text_is_escaped_then_encoded() {
        assert_eq!(escape_search(r#"a"b\c"#), r#"a\"b\\c"#);
        let url = users_search_url("https://graph.microsoft.com", r#"x" OR "mail:a"#);
        let q = url
            .split("$search=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        // No raw quote, space, ampersand or hash survives.
        for bad in ['"', ' ', '&', '#', '+'] {
            assert!(!q.contains(bad), "{q}");
        }
        assert!(q.contains("%5C%22"), "the quote is escaped: {q}");
        let url = groups_search_url("https://graph.microsoft.com", "a&b=c");
        assert!(url.contains("a%26b%3Dc"), "{url}");
        assert!(url.contains("$filter=securityEnabled%20eq%20true"), "{url}");
    }

    #[test]
    fn rows_are_checked() {
        let u = UserRow {
            id: "AAAAAAAA-0000-0000-0000-000000000002".into(),
            display_name: Some("Blair\u{202E} \nExample".into()),
            mail: Some("blair@example.com".into()),
            user_principal_name: Some("blair@example.com".into()),
        }
        .checked()
        .unwrap();
        assert_eq!(u.id, "aaaaaaaa-0000-0000-0000-000000000002");
        assert_eq!(u.display_name, "Blair Example");
        assert_eq!(u.kind, PrincipalKind::User);
        assert!(!format!("{u:?}").contains("Blair"));
        let guest = UserRow {
            id: "aaaaaaaa-0000-0000-0000-000000000003".into(),
            display_name: None,
            mail: Some("Eve <eve@evil.example>".into()),
            user_principal_name: Some("eve_evil.example#EXT#@contoso.onmicrosoft.com".into()),
        }
        .checked()
        .unwrap();
        assert_eq!(guest.kind, PrincipalKind::Guest);
        assert!(guest.mail.is_none(), "a mail that isn't one plain address");
        assert!(
            UserRow {
                id: "not-a-guid".into(),
                display_name: None,
                mail: None,
                user_principal_name: None
            }
            .checked()
            .is_none()
        );
        let m365 = GroupRow {
            id: "aaaaaaaa-0000-0000-0000-000000000004".into(),
            display_name: Some("Team".into()),
            security_enabled: Some(false),
        };
        assert!(m365.checked().is_none());
    }

    #[test]
    fn problems_are_fixed_words() {
        let e = AzureError::Status {
            status: 403,
            code: Some("Authorization_RequestDenied".into()),
            message: Some("graph detail".into()),
        };
        assert_eq!(GraphProblem::of(&e), GraphProblem::NoConsent);
        assert!(!GraphProblem::of(&e).message().contains("graph detail"));
        assert_eq!(
            GraphProblem::of(&AzureError::Token(TokenError::ConsentNeeded)),
            GraphProblem::NoConsent
        );
    }
}
