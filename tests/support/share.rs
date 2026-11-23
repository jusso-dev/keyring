//! Mocks for sharing a secret (#286): Microsoft Graph, and the ARM calls a
//! share makes at one secret's scope (role assignments and PIM schedule
//! requests).
//!
//! Shapes follow Microsoft's references: Graph `GET /v1.0/users`,
//! `/v1.0/groups` (with `$search` and `ConsistencyLevel: eventual`, or
//! `$filter`), `GET /v1.0/users/{id}`, `/v1.0/groups/{id}`; ARM
//! `roleAssignments` (PUT, DELETE, GET with `atScope()` or
//! `principalId eq`, api-version 2022-04-01) and
//! `roleAssignmentScheduleRequests` (PUT and GET, api-version 2020-10-01).
//! Azure's and Graph's error messages carry `LEAKED-AZURE-MESSAGE` so tests
//! can check it never reaches a page, a log or an email.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{Method, StatusCode, Uri};
use axum::response::Response;
use serde_json::{Value, json};

use super::json_response;

pub(crate) const LEAK: &str = "LEAKED-AZURE-MESSAGE";

/// A person or group the Graph mock knows.
#[derive(Clone, Debug)]
pub(crate) struct Person {
    pub id: String,
    pub name: String,
    pub mail: Option<String>,
    pub upn: String,
    pub group: bool,
    /// For a group: a security group.
    pub security: bool,
}

impl Person {
    pub(crate) fn user(id: &str, name: &str, mail: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            mail: Some(mail.into()),
            upn: mail.into(),
            group: false,
            security: false,
        }
    }

    pub(crate) fn group(id: &str, name: &str, security: bool) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            mail: None,
            upn: String::new(),
            group: true,
            security,
        }
    }

    fn user_json(&self) -> Value {
        json!({"id": self.id, "displayName": self.name, "mail": self.mail, "userPrincipalName": self.upn})
    }

    fn group_json(&self) -> Value {
        json!({"id": self.id, "displayName": self.name, "securityEnabled": self.security})
    }
}

#[derive(Default)]
pub(crate) struct GraphState {
    pub people: Mutex<Vec<Person>>,
    /// Answer every call with this status and code (no consent: 403
    /// `Authorization_RequestDenied`).
    pub fail: Mutex<Option<(u16, &'static str)>>,
    /// Fail group calls only, as when `GroupMember.Read.All` isn't
    /// consented.
    pub groups_fail: Mutex<Option<(u16, &'static str)>>,
    /// Every request: method, path and decoded query, and its
    /// `ConsistencyLevel` header.
    pub requests: Mutex<Vec<(String, String, Option<String>)>>,
    pub bearers: Mutex<Vec<String>>,
}

pub(crate) struct MockGraph {
    pub addr: SocketAddr,
    pub state: Arc<GraphState>,
}

impl MockGraph {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn add(&self, p: Person) {
        self.state.people.lock().unwrap().push(p);
    }

    /// Every query string Graph was sent, decoded.
    pub(crate) fn queries(&self) -> Vec<String> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|(_, q, _)| q.clone())
            .collect()
    }
}

pub(crate) async fn start_graph() -> MockGraph {
    let state = Arc::new(GraphState::default());
    let app = Router::new().fallback(graph).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockGraph { addr, state }
}

fn decode(q: &str) -> String {
    url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn err(status: u16, code: &str) -> Response {
    json_response(
        StatusCode::from_u16(status).unwrap(),
        json!({"error": {"code": code, "message": LEAK}}),
    )
}

/// The text inside one `"field:text"` clause of a decoded `$search`.
fn clause(search: &str, field: &str) -> Option<String> {
    let at = search.find(&format!("\"{field}:"))? + field.len() + 2;
    let mut out = String::new();
    let mut chars = search[at..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

async fn graph(
    axum::extract::State(s): axum::extract::State<Arc<GraphState>>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    let path = uri.path().to_owned();
    let query = decode(uri.query().unwrap_or_default());
    let consistency = headers
        .get("consistencylevel")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    s.requests.lock().unwrap().push((
        format!("{method} {path}"),
        query.clone(),
        consistency.clone(),
    ));
    s.bearers.lock().unwrap().push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    );
    if let Some((status, code)) = *s.fail.lock().unwrap() {
        return err(status, code);
    }
    let groups = path.starts_with("/v1.0/groups");
    if groups && let Some((status, code)) = *s.groups_fail.lock().unwrap() {
        return err(status, code);
    }
    let people = s.people.lock().unwrap().clone();
    let of_kind: Vec<&Person> = people.iter().filter(|p| p.group == groups).collect();
    // One object by ID.
    if let Some(id) = path
        .strip_prefix("/v1.0/users/")
        .or_else(|| path.strip_prefix("/v1.0/groups/"))
    {
        return match of_kind.iter().find(|p| p.id.eq_ignore_ascii_case(id)) {
            Some(p) if groups => json_response(StatusCode::OK, p.group_json()),
            Some(p) => json_response(StatusCode::OK, p.user_json()),
            None => err(404, "Request_ResourceNotFound"),
        };
    }
    let search = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("$search="))
        .map(str::to_owned);
    let filter = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("$filter="))
        .unwrap_or_default()
        .to_owned();
    let hits: Vec<&Person> = if let Some(search) = search {
        assert_eq!(
            consistency.as_deref(),
            Some("eventual"),
            "$search needs ConsistencyLevel"
        );
        let name = clause(&search, "displayName")
            .unwrap_or_default()
            .to_lowercase();
        let mail = clause(&search, "mail").map(|m| m.to_lowercase());
        of_kind
            .into_iter()
            .filter(|p| {
                p.name
                    .to_lowercase()
                    .split(' ')
                    .any(|w| w.starts_with(&name))
                    || mail.as_ref().is_some_and(|m| {
                        p.mail
                            .as_deref()
                            .unwrap_or_default()
                            .to_lowercase()
                            .starts_with(m)
                    })
            })
            .collect()
    } else if let Some(list) = filter.strip_prefix("id in (") {
        of_kind
            .into_iter()
            .filter(|p| list.contains(&format!("'{}'", p.id)))
            .collect()
    } else if filter.starts_with("mail eq '") {
        let addr = filter
            .trim_start_matches("mail eq '")
            .split('\'')
            .next()
            .unwrap_or_default()
            .to_lowercase();
        of_kind
            .into_iter()
            .filter(|p| {
                p.mail.as_deref().unwrap_or_default().to_lowercase() == addr
                    || p.upn.to_lowercase() == addr
            })
            .collect()
    } else {
        Vec::new()
    };
    let value: Vec<Value> = hits
        .iter()
        .map(|p| {
            if groups {
                p.group_json()
            } else {
                p.user_json()
            }
        })
        .collect();
    json_response(StatusCode::OK, json!({"value": value}))
}

// ---------------------------------------------------------------------
// ARM: assignments and schedule requests at a secret's scope
// ---------------------------------------------------------------------

/// A role assignment the share mock holds, at any scope.
#[derive(Clone, Debug)]
pub(crate) struct Assigned {
    pub name: String,
    pub scope: String,
    pub role: String,
    pub principal_id: String,
    pub principal_type: String,
    pub description: Option<String>,
}

/// A schedule request the share mock holds.
#[derive(Clone, Debug)]
pub(crate) struct Requested {
    pub scope: String,
    pub body: Value,
    pub status: String,
    pub created: String,
}

#[derive(Default)]
pub(crate) struct ShareArm {
    pub assignments: Vec<Assigned>,
    pub requests: Vec<Requested>,
    /// Answer the next schedule request PUT with this status and code.
    pub pim_fail: Option<(u16, &'static str)>,
    /// Status PIM gives an accepted request. `Provisioned` when unset.
    pub pim_status: Option<&'static str>,
    /// Answer the next role assignment PUT with this status and code.
    pub assign_fail: Option<(u16, &'static str)>,
    /// Answer DELETE with this status and code.
    pub delete_fail: Option<(u16, &'static str)>,
    /// Every write: method and path.
    pub writes: Vec<(String, String)>,
    /// Every PUT body, by path.
    pub bodies: Vec<(String, Value)>,
}

const ASSIGN: &str = "/providers/Microsoft.Authorization/roleAssignments";
const REQUESTS: &str = "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests";

fn role_guid(id: &str) -> String {
    id.rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Answer an ARM call a share makes, or `None` if `path` isn't one. Only
/// calls at a secret's scope, and role assignment reads with a filter, are
/// the share mock's; the rest stays with the Access mock.
pub(crate) fn answer(
    m: &Mutex<ShareArm>,
    method: &Method,
    path: &str,
    query: &str,
    body: &str,
) -> Option<Response> {
    let at_secret = path.contains("/vaults/") && path.contains("/secrets/");
    let filtered = query.contains("$filter=atScope()") || query.contains("$filter=principalId");
    // `asRequestor()` at a vault is PIM's own read too (My access); the
    // share mock answers it only once it holds a share request.
    let mine_requests = path.ends_with(REQUESTS)
        && query.contains("asRequestor()")
        && !m.lock().unwrap().requests.is_empty();
    let is_assign = path.contains(ASSIGN);
    let is_request = path.contains(REQUESTS);
    if !((at_secret && (is_assign || is_request)) || (is_assign && filtered) || mine_requests) {
        return None;
    }
    let mut s = m.lock().unwrap();
    if *method == Method::PUT && is_request {
        assert!(query.contains("api-version=2020-10-01"), "{query}");
        let scope = path.split(REQUESTS).next().unwrap().to_owned();
        let v: Value = serde_json::from_str(body).unwrap();
        s.writes.push(("PUT".into(), path.to_owned()));
        s.bodies.push((path.to_owned(), v.clone()));
        if let Some((status, code)) = s.pim_fail.take() {
            return Some(err(status, code));
        }
        let status = s.pim_status.unwrap_or("Provisioned").to_owned();
        let p = &v["properties"];
        s.requests.push(Requested {
            scope: scope.clone(),
            body: v.clone(),
            status: status.clone(),
            created: super::rfc3339_utc(super::now_unix()),
        });
        if p["requestType"] == "AdminAssign" && status == "Provisioned" {
            let name = uuid_like(s.writes.len());
            s.assignments.push(Assigned {
                name,
                scope,
                role: role_guid(p["roleDefinitionId"].as_str().unwrap_or_default()),
                principal_id: p["principalId"].as_str().unwrap_or_default().into(),
                principal_type: "User".into(),
                description: None,
            });
        } else if p["requestType"] == "AdminRemove" {
            let pid = p["principalId"].as_str().unwrap_or_default().to_owned();
            s.assignments
                .retain(|a| !(a.scope.eq_ignore_ascii_case(&scope) && a.principal_id == pid));
        }
        return Some(json_response(
            StatusCode::CREATED,
            json!({"properties": {"status": status, "requestType": p["requestType"]}}),
        ));
    }
    if *method == Method::PUT && is_assign {
        assert!(query.contains("api-version=2022-04-01"), "{query}");
        let (scope, name) = path.split_once(&format!("{ASSIGN}/")).unwrap();
        let v: Value = serde_json::from_str(body).unwrap();
        s.writes.push(("PUT".into(), path.to_owned()));
        s.bodies.push((path.to_owned(), v.clone()));
        if let Some((status, code)) = s.assign_fail.take() {
            return Some(err(status, code));
        }
        let p = &v["properties"];
        s.assignments.push(Assigned {
            name: name.to_owned(),
            scope: scope.to_owned(),
            role: role_guid(p["roleDefinitionId"].as_str().unwrap_or_default()),
            principal_id: p["principalId"].as_str().unwrap_or_default().into(),
            principal_type: p["principalType"].as_str().unwrap_or_default().into(),
            description: p["description"].as_str().map(str::to_owned),
        });
        return Some(json_response(
            StatusCode::CREATED,
            json!({"name": name, "properties": {"scope": scope}}),
        ));
    }
    if *method == Method::DELETE && is_assign {
        assert!(query.contains("api-version=2022-04-01"), "{query}");
        s.writes.push(("DELETE".into(), path.to_owned()));
        if let Some((status, code)) = s.delete_fail.take() {
            return Some(err(status, code));
        }
        let (scope, name) = path.split_once(&format!("{ASSIGN}/")).unwrap();
        let before = s.assignments.len();
        s.assignments
            .retain(|a| !(a.name == name && a.scope.eq_ignore_ascii_case(scope)));
        return Some(if s.assignments.len() < before {
            json_response(StatusCode::OK, json!({}))
        } else {
            json_response(StatusCode::NO_CONTENT, json!({}))
        });
    }
    if *method != Method::GET {
        return None;
    }
    // An unfiltered list at a secret is the Access section's read: the
    // main mock answers it, with every assignment and the shares beside
    // them.
    if is_assign && !filtered {
        return None;
    }
    let scope = path
        .split("/providers/Microsoft.Authorization/")
        .next()
        .unwrap();
    if is_assign {
        let principal = query
            .split("principalId eq '")
            .nth(1)
            .and_then(|r| r.split('\'').next())
            .map(str::to_owned);
        let value: Vec<Value> = s
            .assignments
            .iter()
            .filter(|a| {
                let below = a.scope.to_ascii_lowercase().starts_with(&scope.to_ascii_lowercase());
                let above = scope.to_ascii_lowercase().starts_with(&a.scope.to_ascii_lowercase());
                match &principal {
                    Some(p) => a.principal_id == *p && (below || above),
                    None if query.contains("atScope()") => above,
                    None => below || above,
                }
            })
            .map(|a| json!({"name": a.name, "properties": {
                "scope": a.scope, "principalId": a.principal_id, "principalType": a.principal_type,
                "roleDefinitionId": format!("/subscriptions/sub-a/providers/Microsoft.Authorization/roleDefinitions/{}", a.role),
                "description": a.description}}))
            .collect();
        return Some(json_response(StatusCode::OK, json!({"value": value})));
    }
    let value: Vec<Value> = s
        .requests
        .iter()
        .filter(|r| {
            r.scope
                .to_ascii_lowercase()
                .starts_with(&scope.to_ascii_lowercase())
                || scope
                    .to_ascii_lowercase()
                    .starts_with(&r.scope.to_ascii_lowercase())
        })
        .map(|r| {
            let mut v = r.body.clone();
            v["properties"]["scope"] = json!(r.scope);
            v["properties"]["status"] = json!(r.status);
            v["properties"]["createdOn"] = json!(r.created);
            v["properties"]["principalType"] = json!("User");
            v
        })
        .collect();
    Some(json_response(StatusCode::OK, json!({"value": value})))
}

fn uuid_like(n: usize) -> String {
    format!("bbbbbbbb-0000-0000-0000-{n:012}")
}
