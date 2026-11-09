//! Following Key Vault's `nextLink` paging, shared by secrets,
//! certificates and keys.

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::auth::session::Session;
use crate::azure::{AzureClient, AzureError, Resource};

/// Follow at most this many pages (25,000 items).
pub const MAX_PAGES: usize = 1000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    #[serde(default)]
    next_link: Option<String>,
}

/// Split `scheme://host[:port]/path...` into (scheme, host, port, rest).
fn parts(url: &str) -> Option<(String, String, u16, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, if scheme == "https" { 443 } else { 80 }),
    };
    Some((scheme, host.to_ascii_lowercase(), port, path))
}

/// True when `link` points at the same vault as `vault_url`: same scheme,
/// host (any case) and port (`:443` written or not), and a path under the
/// vault's. Key Vault writes `https://<vault>.vault.azure.net:443/...` in
/// its `nextLink`s, so a plain prefix check isn't enough.
pub fn same_vault(vault_url: &str, link: &str) -> bool {
    match (parts(vault_url), parts(link)) {
        (Some((s1, h1, p1, path1)), Some((s2, h2, p2, path2))) => {
            let base = path1.trim_end_matches('/');
            s1 == s2 && h1 == h2 && p1 == p2 && path2.starts_with(&format!("{base}/"))
        }
        _ => false,
    }
}

/// GET `first`, then follow `nextLink`s on the same vault.
pub async fn collect<T: DeserializeOwned>(
    azure: &AzureClient,
    session: &Session,
    vault_url: &str,
    first: String,
) -> Result<Vec<T>, AzureError> {
    let mut out = Vec::new();
    let mut next = Some(first);
    for page_no in 0.. {
        let Some(url) = next.take() else { break };
        if page_no >= MAX_PAGES {
            tracing::warn!(pages = MAX_PAGES, "Key Vault paging stopped at the limit");
            break;
        }
        let page: Page<T> = azure.get_json(session, Resource::KeyVault, &url).await?;
        out.extend(page.value);
        next = match page.next_link.filter(|l| !l.is_empty()) {
            Some(l) if same_vault(vault_url, &l) => Some(l),
            Some(_) => {
                tracing::warn!("ignored a nextLink that pointed somewhere other than this vault");
                None
            }
            None => None,
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_key_vault_next_links_are_followed() {
        let v = "https://kv-prod.vault.azure.net";
        assert!(same_vault(
            v,
            "https://kv-prod.vault.azure.net:443/secrets?api-version=7.5&$skiptoken=abc"
        ));
        assert!(same_vault(v, "https://kv-prod.vault.azure.net/secrets?x=1"));
        assert!(same_vault(
            "https://KV-Prod.vault.azure.net",
            "https://kv-prod.vault.azure.net:443/keys/a/versions?x"
        ));
        assert!(same_vault(
            "http://127.0.0.1:5000/kv-test",
            "http://127.0.0.1:5000/kv-test/secrets?x"
        ));
    }

    #[test]
    fn other_places_are_refused() {
        let v = "https://kv-prod.vault.azure.net";
        for bad in [
            "https://evil.example/secrets",
            "https://kv-prod.vault.azure.net.evil.example/secrets",
            "https://kv-prod.vault.azure.net:8443/secrets",
            "http://kv-prod.vault.azure.net/secrets",
            "https://kv-prod.vault.azure.net@evil.example/secrets",
            "https://kv-other.vault.azure.net/secrets",
            "/secrets",
            "",
        ] {
            assert!(!same_vault(v, bad), "{bad}");
        }
        assert!(!same_vault(
            "http://127.0.0.1:5000/kv-test",
            "http://127.0.0.1:5000/kv-other/secrets"
        ));
    }
}
