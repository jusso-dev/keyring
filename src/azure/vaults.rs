//! Find every Key Vault the signed-in user can see, across subscriptions,
//! with Azure Resource Graph.

use std::collections::{BTreeMap, HashMap};

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::auth::session::Session;
use crate::azure::{AzureClient, AzureError, Resource};

pub const RESOURCE_GRAPH_API: &str = "2022-10-01";
/// Rows per Resource Graph page. 1000 is the service maximum.
pub const PAGE_SIZE: u32 = 1000;
/// Stop after this many pages (100,000 rows) in case paging never ends.
pub const MAX_PAGES: usize = 100;

pub const VAULTS_QUERY: &str = "resources \
| where type =~ 'microsoft.keyvault/vaults' \
| project id, name, resourceGroup, subscriptionId, location, tags, \
enableRbacAuthorization = properties.enableRbacAuthorization, \
enableSoftDelete = properties.enableSoftDelete, \
enablePurgeProtection = properties.enablePurgeProtection \
| order by name asc";

pub const SUBSCRIPTIONS_QUERY: &str = "resourcecontainers \
| where type =~ 'microsoft.resources/subscriptions' \
| project id, subscriptionId, name \
| order by name asc";

/// A vault as shown in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub subscription_id: String,
    pub subscription_name: String,
    pub location: String,
    pub tags: BTreeMap<String, String>,
    /// `true` for Azure RBAC, `false` for the older access policies.
    pub rbac: bool,
    pub soft_delete: bool,
    pub purge_protection: bool,
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    query: &'a str,
    options: QueryOptions<'a>,
}

#[derive(Serialize)]
struct QueryOptions<'a> {
    #[serde(rename = "$top")]
    top: u32,
    #[serde(rename = "$skipToken", skip_serializing_if = "Option::is_none")]
    skip_token: Option<&'a str>,
    #[serde(rename = "resultFormat")]
    result_format: &'static str,
}

/// Build one Resource Graph request body.
pub fn query_body(query: &str, skip_token: Option<&str>) -> serde_json::Value {
    serde_json::to_value(QueryRequest {
        query,
        options: QueryOptions {
            top: PAGE_SIZE,
            skip_token,
            result_format: "objectArray",
        },
    })
    .expect("query body serialises")
}

#[derive(Deserialize)]
struct QueryResponse<T> {
    #[serde(default = "Vec::new")]
    data: Vec<T>,
    #[serde(rename = "$skipToken")]
    skip_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultRow {
    id: String,
    name: String,
    #[serde(default)]
    resource_group: String,
    #[serde(default)]
    subscription_id: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    tags: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    enable_rbac_authorization: Option<bool>,
    #[serde(default)]
    enable_soft_delete: Option<bool>,
    #[serde(default)]
    enable_purge_protection: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRow {
    subscription_id: String,
    name: String,
}

/// Turn raw rows into vaults, filling in subscription names. Missing flags
/// get Azure's defaults: soft delete is on for every vault created since
/// 2020, RBAC and purge protection are off.
fn map_vaults(rows: Vec<VaultRow>, subs: &HashMap<String, String>) -> Vec<Vault> {
    let mut vaults: Vec<Vault> = rows
        .into_iter()
        .map(|r| Vault {
            subscription_name: subs
                .get(&r.subscription_id.to_ascii_lowercase())
                .cloned()
                .unwrap_or_else(|| r.subscription_id.clone()),
            id: r.id,
            name: r.name,
            resource_group: r.resource_group,
            subscription_id: r.subscription_id,
            location: r.location,
            tags: r
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| {
                    let v = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, v)
                })
                .collect(),
            rbac: r.enable_rbac_authorization.unwrap_or(false),
            soft_delete: r.enable_soft_delete.unwrap_or(true),
            purge_protection: r.enable_purge_protection.unwrap_or(false),
        })
        .collect();
    vaults.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.subscription_name.cmp(&b.subscription_name))
    });
    vaults
}

async fn run_query<T: serde::de::DeserializeOwned>(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
    query: &str,
) -> Result<Vec<T>, AzureError> {
    let url = format!(
        "{management_url}/providers/Microsoft.ResourceGraph/resources?api-version={RESOURCE_GRAPH_API}"
    );
    let mut rows = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let page: QueryResponse<T> = azure
            .send_json(
                session,
                Resource::Management,
                Method::POST,
                &url,
                &query_body(query, token.as_deref()),
            )
            .await?;
        rows.extend(page.data);
        match page.skip_token {
            Some(t) if !t.is_empty() => token = Some(t),
            _ => return Ok(rows),
        }
    }
    tracing::warn!(
        pages = MAX_PAGES,
        "Resource Graph paging stopped at the limit"
    );
    Ok(rows)
}

/// Every vault the user can see, sorted by name.
pub async fn list_vaults(
    azure: &AzureClient,
    session: &Session,
    management_url: &str,
) -> Result<Vec<Vault>, AzureError> {
    let (rows, subs) = tokio::join!(
        run_query::<VaultRow>(azure, session, management_url, VAULTS_QUERY),
        run_query::<SubscriptionRow>(azure, session, management_url, SUBSCRIPTIONS_QUERY),
    );
    let rows = rows?;
    // Missing subscription names aren't worth failing over; show the ID.
    let subs: HashMap<String, String> = subs
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.subscription_id.to_ascii_lowercase(), s.name))
        .collect();
    Ok(map_vaults(rows, &subs))
}

/// Key Vault naming rules: 3 to 24 characters, letters, digits and
/// hyphens, starting with a letter, ending with a letter or digit, no two
/// hyphens in a row. Checked before a name is ever put into a URL.
pub fn is_valid_vault_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=24).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        && !name.contains("--")
}

/// Filters from the vault list's search form.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct VaultFilter {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub subscription: String,
    /// `key` or `key=value`.
    #[serde(default)]
    pub tag: String,
}

impl VaultFilter {
    pub fn is_empty(&self) -> bool {
        self.q.trim().is_empty() && self.subscription.is_empty() && self.tag.trim().is_empty()
    }

    pub fn matches(&self, v: &Vault) -> bool {
        let q = self.q.trim().to_lowercase();
        if !q.is_empty()
            && !v.name.to_lowercase().contains(&q)
            && !v.resource_group.to_lowercase().contains(&q)
        {
            return false;
        }
        if !self.subscription.is_empty()
            && !v.subscription_id.eq_ignore_ascii_case(&self.subscription)
        {
            return false;
        }
        let tag = self.tag.trim();
        if !tag.is_empty() {
            let (key, value) = match tag.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (tag, None),
            };
            let hit = v.tags.iter().any(|(k, val)| {
                k.eq_ignore_ascii_case(key)
                    && value.is_none_or(|want| val.eq_ignore_ascii_case(want))
            });
            if !hit {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_body_shape() {
        let first = query_body(VAULTS_QUERY, None);
        assert_eq!(first["query"], VAULTS_QUERY);
        assert_eq!(first["options"]["$top"], 1000);
        assert_eq!(first["options"]["resultFormat"], "objectArray");
        assert!(first["options"].get("$skipToken").is_none());
        let next = query_body(VAULTS_QUERY, Some("abc"));
        assert_eq!(next["options"]["$skipToken"], "abc");
    }

    #[test]
    fn queries_target_the_right_types() {
        assert!(VAULTS_QUERY.contains("microsoft.keyvault/vaults"));
        assert!(VAULTS_QUERY.contains("enableRbacAuthorization"));
        assert!(SUBSCRIPTIONS_QUERY.contains("microsoft.resources/subscriptions"));
    }

    #[test]
    fn maps_rows_with_subscription_names_and_defaults() {
        let rows: Vec<VaultRow> = serde_json::from_value(serde_json::json!([
            {
                "id": "/subscriptions/S2/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/zeta",
                "name": "zeta", "resourceGroup": "rg", "subscriptionId": "S2",
                "location": "australiaeast", "tags": {"env": "prod", "n": 3},
                "enableRbacAuthorization": true, "enableSoftDelete": true, "enablePurgeProtection": true
            },
            {
                "id": "/subscriptions/s1/.../alpha", "name": "Alpha", "resourceGroup": "rg1",
                "subscriptionId": "s1", "location": "australiasoutheast", "tags": null,
                "enableRbacAuthorization": null, "enableSoftDelete": null, "enablePurgeProtection": null
            }
        ]))
        .unwrap();
        let subs = HashMap::from([("s2".to_owned(), "Production".to_owned())]);
        let v = map_vaults(rows, &subs);
        assert_eq!(v[0].name, "Alpha");
        assert_eq!(v[0].subscription_name, "s1", "falls back to the ID");
        assert!(!v[0].rbac && v[0].soft_delete && !v[0].purge_protection);
        assert_eq!(v[1].subscription_name, "Production");
        assert!(v[1].rbac && v[1].purge_protection);
        assert_eq!(v[1].tags.get("n").map(String::as_str), Some("3"));
    }

    #[test]
    fn vault_name_rules() {
        for ok in ["abc", "kv-prod-01", "A1b", &"a".repeat(24)] {
            assert!(is_valid_vault_name(ok), "{ok}");
        }
        for bad in [
            "ab",
            "1abc",
            "abc-",
            "a--b",
            "kv.prod",
            "kv/../x",
            "kv@evil",
            &"a".repeat(25),
            "",
            "evil.com#",
        ] {
            assert!(!is_valid_vault_name(bad), "{bad}");
        }
    }

    fn vault(name: &str, sub: &str, tags: &[(&str, &str)]) -> Vault {
        Vault {
            id: format!("/x/{name}"),
            name: name.into(),
            resource_group: "rg-app".into(),
            subscription_id: sub.into(),
            subscription_name: sub.into(),
            location: "australiaeast".into(),
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            rbac: true,
            soft_delete: true,
            purge_protection: false,
        }
    }

    #[test]
    fn filter_by_name_subscription_and_tag() {
        let v = vault("kv-prod", "sub-a", &[("env", "Prod"), ("team", "data")]);
        let f = |q: &str, s: &str, t: &str| VaultFilter {
            q: q.into(),
            subscription: s.into(),
            tag: t.into(),
        };
        assert!(f("", "", "").is_empty());
        assert!(f("PROD", "", "").matches(&v));
        assert!(f("rg-app", "", "").matches(&v));
        assert!(!f("test", "", "").matches(&v));
        assert!(f("", "SUB-A", "").matches(&v));
        assert!(!f("", "sub-b", "").matches(&v));
        assert!(f("", "", "env").matches(&v));
        assert!(f("", "", "env=prod").matches(&v));
        assert!(!f("", "", "env=test").matches(&v));
        assert!(!f("", "", "owner").matches(&v));
    }
}
