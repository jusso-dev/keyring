//! Configuration loaded from environment variables.

use std::fmt;
use std::net::SocketAddr;

use crate::secret::Secret;

/// Shortest `SESSION_SECRET` we accept, in bytes.
pub const MIN_SESSION_SECRET_LEN: usize = 32;

/// Typed app configuration. Built once at start-up.
#[derive(Debug, Clone)]
pub struct Config {
    pub tenant_id: String,
    pub client_id: String,
    /// Sign-in host, `https://login.microsoftonline.com` unless overridden.
    pub authority_host: String,
    /// Scope for Keyring's own API, requested at sign-in so the access token
    /// can be exchanged on behalf of the user.
    pub api_scope: String,
    pub client_secret: Secret,
    /// Public base URL with no trailing slash, for example `https://keyring.example.com`.
    pub base_url: String,
    pub session_secret: Secret,
    pub allow_purge: bool,
    pub listen: SocketAddr,
    pub log_level: String,
    /// Azure Resource Manager base URL. Only changed by tests.
    pub management_url: String,
    /// Log Analytics query API base URL. Only changed by tests.
    pub loganalytics_url: String,
    /// Replaces `https://<vault>.vault.azure.net` with `<base>/<vault>`.
    /// Only set by tests, to point at a mock Key Vault.
    pub keyvault_test_base: Option<String>,
}

/// Why the configuration couldn't be loaded. Messages are written for the
/// person running the app.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(Vec<&'static str>),
    Invalid { name: &'static str, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(names) => write!(
                f,
                "missing environment variables: {}. See .env.example.",
                names.join(", ")
            ),
            Self::Invalid { name, reason } => write!(f, "{name} is not valid: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Load using any lookup function. Used by tests.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let required = [
            "ENTRA_TENANT_ID",
            "ENTRA_CLIENT_ID",
            "ENTRA_CLIENT_SECRET",
            "APP_BASE_URL",
            "SESSION_SECRET",
        ];
        let missing: Vec<&'static str> = required
            .iter()
            .copied()
            .filter(|name| get(name).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(ConfigError::Missing(missing));
        }
        let take = |name: &str| get(name).unwrap_or_default();

        let tenant_id = take("ENTRA_TENANT_ID");
        if !is_guid(&tenant_id) {
            return Err(ConfigError::Invalid {
                name: "ENTRA_TENANT_ID",
                reason:
                    "expected the tenant's ID, a GUID like 00000000-0000-0000-0000-000000000000"
                        .into(),
            });
        }
        let client_id = take("ENTRA_CLIENT_ID");
        if !is_guid(&client_id) {
            return Err(ConfigError::Invalid {
                name: "ENTRA_CLIENT_ID",
                reason: "expected the app registration's client ID, a GUID".into(),
            });
        }

        let base_url = checked_url("APP_BASE_URL", &take("APP_BASE_URL"))?;
        let authority_host = checked_url(
            "ENTRA_AUTHORITY_HOST",
            &get("ENTRA_AUTHORITY_HOST").unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.into()),
        )?;
        let api_scope =
            get("ENTRA_API_SCOPE").unwrap_or_else(|| format!("api://{client_id}/access_as_user"));

        let session_secret = take("SESSION_SECRET");
        if session_secret.len() < MIN_SESSION_SECRET_LEN {
            return Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                reason: format!("must be at least {MIN_SESSION_SECRET_LEN} characters"),
            });
        }

        let allow_purge = match get("KEYRING_ALLOW_PURGE").as_deref() {
            None => false,
            Some(v) => parse_bool(v).ok_or_else(|| ConfigError::Invalid {
                name: "KEYRING_ALLOW_PURGE",
                reason: "use true or false".into(),
            })?,
        };

        let listen = get("KEYRING_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:3000".into())
            .parse()
            .map_err(|_| ConfigError::Invalid {
                name: "KEYRING_LISTEN",
                reason: "expected an address and port such as 127.0.0.1:3000".into(),
            })?;

        let management_url = checked_url(
            "KEYRING_TEST_MANAGEMENT_URL",
            &get("KEYRING_TEST_MANAGEMENT_URL").unwrap_or_else(|| DEFAULT_MANAGEMENT_URL.into()),
        )?;
        let loganalytics_url = checked_url(
            "KEYRING_TEST_LOGANALYTICS_URL",
            &get("KEYRING_TEST_LOGANALYTICS_URL")
                .unwrap_or_else(|| DEFAULT_LOGANALYTICS_URL.into()),
        )?;
        let keyvault_test_base = get("KEYRING_TEST_KEYVAULT_URL")
            .map(|v| checked_url("KEYRING_TEST_KEYVAULT_URL", &v))
            .transpose()?;

        Ok(Self {
            loganalytics_url,
            management_url,
            keyvault_test_base,
            tenant_id,
            client_id,
            authority_host,
            api_scope,
            client_secret: Secret::new(take("ENTRA_CLIENT_SECRET")),
            base_url,
            session_secret: Secret::new(session_secret),
            allow_purge,
            listen,
            log_level: get("KEYRING_LOG_LEVEL").unwrap_or_else(|| "info".into()),
        })
    }

    /// True when the app is served over HTTPS, so cookies get `Secure`.
    pub fn is_https(&self) -> bool {
        self.base_url.starts_with("https://")
    }

    /// True when every outbound endpoint is HTTPS, so the HTTP client can
    /// refuse plain HTTP. Only false in tests against local mocks.
    pub fn outbound_https_only(&self) -> bool {
        self.authority_host.starts_with("https://")
            && self.management_url.starts_with("https://")
            && self.loganalytics_url.starts_with("https://")
            && self
                .keyvault_test_base
                .as_deref()
                .is_none_or(|b| b.starts_with("https://"))
    }

    /// Data-plane URL for a vault. `name` must already be checked with
    /// [`crate::azure::vaults::is_valid_vault_name`].
    pub fn vault_url(&self, name: &str) -> String {
        match &self.keyvault_test_base {
            Some(base) => format!("{base}/{name}"),
            None => format!("https://{name}.vault.azure.net"),
        }
    }

    /// The Entra ID issuer for this tenant.
    pub fn issuer(&self) -> String {
        format!("{}/{}/v2.0", self.authority_host, self.tenant_id)
    }

    /// Where Entra sends the browser back to after sign-in.
    pub fn redirect_url(&self) -> String {
        format!("{}/auth/callback", self.base_url)
    }

    /// Where Entra sends the browser after sign-out.
    pub fn signed_out_url(&self) -> String {
        format!("{}/auth/signed-out", self.base_url)
    }
}

/// Default Log Analytics query endpoint.
pub const DEFAULT_LOGANALYTICS_URL: &str = "https://api.loganalytics.io";

/// Default Azure Resource Manager endpoint.
pub const DEFAULT_MANAGEMENT_URL: &str = "https://management.azure.com";

/// Default Entra ID sign-in host.
pub const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

/// True for `http://localhost` and `http://127.0.0.1`, with or without a port.
pub fn is_local_http(url: &str) -> bool {
    ["http://localhost", "http://127.0.0.1"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')
            })
        })
}

/// Trim a trailing slash and require `https://`, allowing plain `http://`
/// only for localhost.
fn checked_url(name: &'static str, raw: &str) -> Result<String, ConfigError> {
    let url = raw.trim_end_matches('/').to_owned();
    let has_host = url
        .split_once("://")
        .is_some_and(|(_, rest)| !rest.is_empty() && !rest.contains(char::is_whitespace));
    if has_host && (url.starts_with("https://") || is_local_http(&url)) {
        Ok(url)
    } else {
        Err(ConfigError::Invalid {
            name,
            reason: "must start with https:// (http:// is only allowed for localhost)".into(),
        })
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn is_guid(v: &str) -> bool {
    let groups: Vec<&str> = v.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use super::*;

    pub(crate) fn sample_env() -> HashMap<&'static str, String> {
        HashMap::from([
            (
                "ENTRA_TENANT_ID",
                "00000000-0000-0000-0000-000000000000".into(),
            ),
            (
                "ENTRA_CLIENT_ID",
                "11111111-1111-1111-1111-111111111111".into(),
            ),
            ("ENTRA_CLIENT_SECRET", "client-secret-value".into()),
            ("APP_BASE_URL", "http://localhost:3000/".into()),
            ("SESSION_SECRET", "x".repeat(64)),
        ])
    }

    fn load(env: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::from_lookup(|k| env.get(k).cloned())
    }

    #[test]
    fn loads_with_defaults() {
        let config = load(&sample_env()).unwrap();
        assert_eq!(config.base_url, "http://localhost:3000");
        assert!(!config.allow_purge);
        assert_eq!(config.listen.port(), 3000);
        assert!(!config.is_https());
    }

    #[test]
    fn reports_every_missing_variable() {
        let mut env = sample_env();
        env.remove("ENTRA_CLIENT_ID");
        env.insert("SESSION_SECRET", "   ".into());
        assert_eq!(
            load(&env).unwrap_err(),
            ConfigError::Missing(vec!["ENTRA_CLIENT_ID", "SESSION_SECRET"])
        );
    }

    #[test]
    fn rejects_short_session_secret() {
        let mut env = sample_env();
        env.insert("SESSION_SECRET", "short".into());
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                ..
            })
        ));
    }

    #[test]
    fn rejects_plain_http_outside_localhost() {
        let mut env = sample_env();
        env.insert("APP_BASE_URL", "http://keyring.example.com".into());
        assert!(load(&env).is_err());
        env.insert("APP_BASE_URL", "https://keyring.example.com".into());
        assert!(load(&env).unwrap().is_https());
    }

    #[test]
    fn rejects_non_guid_ids() {
        let mut env = sample_env();
        env.insert("ENTRA_TENANT_ID", "contoso.onmicrosoft.com".into());
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "ENTRA_TENANT_ID",
                ..
            })
        ));
    }

    #[test]
    fn derives_entra_urls() {
        let config = load(&sample_env()).unwrap();
        assert_eq!(
            config.issuer(),
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
        );
        assert_eq!(config.redirect_url(), "http://localhost:3000/auth/callback");
        assert_eq!(
            config.api_scope,
            "api://11111111-1111-1111-1111-111111111111/access_as_user"
        );
    }

    #[test]
    fn local_http_check_is_strict() {
        assert!(is_local_http("http://localhost:3000"));
        assert!(is_local_http("http://127.0.0.1"));
        assert!(!is_local_http("http://localhost.evil.com"));
        assert!(!is_local_http("http://127.0.0.1.evil.com"));
    }

    #[test]
    fn parses_purge_flag() {
        let mut env = sample_env();
        env.insert("KEYRING_ALLOW_PURGE", "TRUE".into());
        assert!(load(&env).unwrap().allow_purge);
        env.insert("KEYRING_ALLOW_PURGE", "maybe".into());
        assert!(load(&env).is_err());
    }

    #[test]
    fn debug_output_hides_secrets() {
        let config = load(&sample_env()).unwrap();
        let out = format!("{config:?}");
        assert!(!out.contains("client-secret-value"));
        assert!(!out.contains(&"x".repeat(64)));
    }
}
