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
    /// How Keyring proves to Entra that it is the app registration.
    pub credential: ClientCredential,
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

/// How Keyring proves it is the app registration.
#[derive(Debug, Clone)]
pub enum ClientCredential {
    /// A client secret from the app registration. For local use.
    Secret(Secret),
    /// A user-assigned managed identity that the app registration trusts as
    /// a federated credential. Keyring sends a short-lived token from the
    /// identity as `client_assertion`, so there is no secret to rotate.
    ManagedIdentity {
        /// The identity's client ID.
        identity_client_id: String,
        /// `IDENTITY_ENDPOINT`: the local token service, set by the platform.
        endpoint: String,
        /// `IDENTITY_HEADER`: sent with each request to that service.
        header: Secret,
    },
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

        // The client secret is only needed without a managed identity.
        let uses_identity = get("KEYRING_FEDERATED_IDENTITY_CLIENT_ID").is_some();
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
            .filter(|name| !(uses_identity && *name == "ENTRA_CLIENT_SECRET"))
            .collect();
        if !missing.is_empty() {
            return Err(ConfigError::Missing(missing));
        }
        let take = |name: &str| get(name).unwrap_or_default();

        // App Service passes a Key Vault reference through as plain text
        // when it can't resolve it. Starting with that as a secret would
        // mean a well-known session key, so refuse to start.
        for name in ["ENTRA_CLIENT_SECRET", "SESSION_SECRET"] {
            if get(name).is_some_and(|v| v.starts_with("@Microsoft.KeyVault(")) {
                return Err(ConfigError::Invalid {
                    name,
                    reason: "is still a Key Vault reference, so App Service couldn't read it. Check the secret exists in the config vault and the app's identity can read it".into(),
                });
            }
        }

        // Entra writes GUIDs in lower case, including in the issuer.
        let tenant_id = take("ENTRA_TENANT_ID").to_ascii_lowercase();
        if !is_guid(&tenant_id) {
            return Err(ConfigError::Invalid {
                name: "ENTRA_TENANT_ID",
                reason:
                    "expected the tenant's ID, a GUID like 00000000-0000-0000-0000-000000000000"
                        .into(),
            });
        }
        let client_id = take("ENTRA_CLIENT_ID").to_ascii_lowercase();
        if !is_guid(&client_id) {
            return Err(ConfigError::Invalid {
                name: "ENTRA_CLIENT_ID",
                reason: "expected the app registration's client ID, a GUID".into(),
            });
        }

        let credential = match get("KEYRING_FEDERATED_IDENTITY_CLIENT_ID") {
            None => ClientCredential::Secret(Secret::new(take("ENTRA_CLIENT_SECRET"))),
            Some(identity) => {
                if get("ENTRA_CLIENT_SECRET").is_some() {
                    return Err(ConfigError::Invalid {
                        name: "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
                        reason: "Set ENTRA_CLIENT_SECRET or KEYRING_FEDERATED_IDENTITY_CLIENT_ID, not both".into(),
                    });
                }
                let identity_client_id = identity.to_ascii_lowercase();
                if !is_guid(&identity_client_id) {
                    return Err(ConfigError::Invalid {
                        name: "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
                        reason: "expected the managed identity's client ID, a GUID".into(),
                    });
                }
                let (Some(endpoint), Some(header)) =
                    (get("IDENTITY_ENDPOINT"), get("IDENTITY_HEADER"))
                else {
                    return Err(ConfigError::Invalid {
                        name: "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
                        reason: "needs IDENTITY_ENDPOINT and IDENTITY_HEADER, which App Service and Container Apps set when a managed identity is assigned to the app".into(),
                    });
                };
                let endpoint =
                    crate::auth::assertion::checked_endpoint(&endpoint).map_err(|reason| {
                        ConfigError::Invalid {
                            name: "IDENTITY_ENDPOINT",
                            reason,
                        }
                    })?;
                ClientCredential::ManagedIdentity {
                    identity_client_id,
                    endpoint,
                    header: Secret::new(header),
                }
            }
        };

        let base_url = checked_origin("APP_BASE_URL", &take("APP_BASE_URL"))?;
        let authority_host = checked_origin(
            "ENTRA_AUTHORITY_HOST",
            &get("ENTRA_AUTHORITY_HOST").unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.into()),
        )?;
        let api_scope =
            get("ENTRA_API_SCOPE").unwrap_or_else(|| format!("api://{client_id}/access_as_user"));

        let session_secret = take("SESSION_SECRET");
        // The placeholder in .env.example is published, so it is no secret.
        if session_secret.starts_with("replace-me") {
            return Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                reason: "is still the placeholder from .env.example. Make a new one with: openssl rand -base64 48".into(),
            });
        }
        if session_secret.len() < MIN_SESSION_SECRET_LEN {
            return Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                reason: format!(
                    "must be at least {MIN_SESSION_SECRET_LEN} characters. Make one with: openssl rand -base64 48"
                ),
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

        let management_url = checked_origin(
            "KEYRING_TEST_MANAGEMENT_URL",
            &get("KEYRING_TEST_MANAGEMENT_URL").unwrap_or_else(|| DEFAULT_MANAGEMENT_URL.into()),
        )?;
        let loganalytics_url = checked_origin(
            "KEYRING_TEST_LOGANALYTICS_URL",
            &get("KEYRING_TEST_LOGANALYTICS_URL")
                .unwrap_or_else(|| DEFAULT_LOGANALYTICS_URL.into()),
        )?;
        let keyvault_test_base = get("KEYRING_TEST_KEYVAULT_URL")
            .map(|v| checked_origin("KEYRING_TEST_KEYVAULT_URL", &v))
            .transpose()?;

        let log_level = match get("KEYRING_LOG_LEVEL") {
            None => "info".to_owned(),
            Some(v) => {
                let v = v.to_ascii_lowercase();
                if !LOG_LEVELS.contains(&v.as_str()) {
                    return Err(ConfigError::Invalid {
                        name: "KEYRING_LOG_LEVEL",
                        reason: "use error, warn, info, debug or trace".into(),
                    });
                }
                v
            }
        };

        Ok(Self {
            loganalytics_url,
            management_url,
            keyvault_test_base,
            tenant_id,
            client_id,
            authority_host,
            api_scope,
            credential,
            base_url,
            session_secret: Secret::new(session_secret),
            allow_purge,
            listen,
            log_level,
        })
    }

    /// Names of the test-only overrides that are set. Each one sends user
    /// tokens (and for the authority host, the client secret) somewhere
    /// other than Microsoft, so start-up warns about them.
    pub fn test_overrides(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.authority_host != DEFAULT_AUTHORITY_HOST {
            out.push("ENTRA_AUTHORITY_HOST");
        }
        if self.management_url != DEFAULT_MANAGEMENT_URL {
            out.push("KEYRING_TEST_MANAGEMENT_URL");
        }
        if self.loganalytics_url != DEFAULT_LOGANALYTICS_URL {
            out.push("KEYRING_TEST_LOGANALYTICS_URL");
        }
        if self.keyvault_test_base.is_some() {
            out.push("KEYRING_TEST_KEYVAULT_URL");
        }
        out
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

/// Values `KEYRING_LOG_LEVEL` accepts. `off` is left out on purpose: it
/// would also drop the lines that record reveals and downloads.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Default Log Analytics query endpoint.
pub const DEFAULT_LOGANALYTICS_URL: &str = "https://api.loganalytics.io";

/// Default Azure Resource Manager endpoint.
pub const DEFAULT_MANAGEMENT_URL: &str = "https://management.azure.com";

/// Default Entra ID sign-in host.
pub const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

/// Check a base URL is a bare origin, `scheme://host[:port]`, and return it
/// in normal form. `https://` is required, except plain `http://` for
/// localhost. A path, query, fragment or user name is refused: cookies and
/// links are all rooted at `/`, so Keyring can't be hosted under a sub-path.
fn checked_origin(name: &'static str, raw: &str) -> Result<String, ConfigError> {
    let invalid = |reason: &str| ConfigError::Invalid {
        name,
        reason: reason.to_owned(),
    };
    let scheme_rule = "must start with https:// (http:// is only allowed for localhost)";
    let url = openidconnect::url::Url::parse(raw.trim()).map_err(|_| invalid(scheme_rule))?;
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "https" if !host.is_empty() => {}
        "http" if host == "localhost" || host == "127.0.0.1" => {}
        _ => return Err(invalid(scheme_rule)),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not include a user name or password"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "must be just the scheme and host, such as https://keyring.example.com. Hosting under a path isn't supported",
        ));
    }
    Ok(url.origin().ascii_serialization())
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

pub(crate) fn is_guid(v: &str) -> bool {
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
    fn refuses_unresolved_key_vault_references() {
        let mut env = sample_env();
        env.insert(
            "SESSION_SECRET",
            "@Microsoft.KeyVault(VaultName=kv-keyring-config;SecretName=session-secret)".into(),
        );
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                ..
            })
        ));
        let mut env = sample_env();
        env.insert(
            "ENTRA_CLIENT_SECRET",
            "@Microsoft.KeyVault(SecretUri=https://x/secrets/y)".into(),
        );
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "ENTRA_CLIENT_SECRET",
                ..
            })
        ));
    }

    #[test]
    fn refuses_the_example_session_secret() {
        let mut env = sample_env();
        env.insert(
            "SESSION_SECRET",
            "replace-me-with-at-least-32-random-characters".into(),
        );
        let err = load(&env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "SESSION_SECRET",
                ..
            }
        ));
        assert!(err.to_string().contains("openssl rand -base64 48"));
    }

    #[test]
    fn example_env_file_leaves_session_secret_empty() {
        let example = include_str!("../.env.example");
        let line = example
            .lines()
            .find(|l| l.starts_with("SESSION_SECRET="))
            .expect("SESSION_SECRET line");
        assert_eq!(line, "SESSION_SECRET=");
        // So copying the file as-is reports it as missing.
        let mut env = sample_env();
        env.insert("SESSION_SECRET", String::new());
        assert_eq!(
            load(&env).unwrap_err(),
            ConfigError::Missing(vec!["SESSION_SECRET"])
        );
    }

    #[test]
    fn base_url_must_be_a_bare_origin() {
        for bad in [
            "https://tools.example.com/keyring",
            "https://user@keyring.example.com",
            "https://user:pw@keyring.example.com",
            "https://keyring.example.com/?x=1",
            "https://keyring.example.com/#top",
            "https://",
            "keyring.example.com",
            "ftp://keyring.example.com",
            "http://localhost.evil.com",
        ] {
            let mut env = sample_env();
            env.insert("APP_BASE_URL", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "APP_BASE_URL",
                        ..
                    })
                ),
                "{bad} should be refused"
            );
        }
        let mut env = sample_env();
        env.insert("APP_BASE_URL", "HTTPS://Keyring.Example.com:443/".into());
        assert_eq!(load(&env).unwrap().base_url, "https://keyring.example.com");
        env.insert("APP_BASE_URL", "https://keyring.example.com:8443".into());
        assert_eq!(
            load(&env).unwrap().base_url,
            "https://keyring.example.com:8443"
        );
    }

    #[test]
    fn guids_are_lower_cased() {
        let mut env = sample_env();
        env.insert(
            "ENTRA_TENANT_ID",
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
        );
        env.insert(
            "ENTRA_CLIENT_ID",
            "FFFFFFFF-1111-2222-3333-444444444444".into(),
        );
        let config = load(&env).unwrap();
        assert_eq!(config.tenant_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(config.client_id, "ffffffff-1111-2222-3333-444444444444");
        assert!(config.issuer().contains("aaaaaaaa-bbbb"));
    }

    #[test]
    fn log_level_is_checked() {
        let mut env = sample_env();
        assert_eq!(load(&env).unwrap().log_level, "info");
        env.insert("KEYRING_LOG_LEVEL", "DEBUG".into());
        assert_eq!(load(&env).unwrap().log_level, "debug");
        for bad in ["verbose", "off", "info,keyring=trace"] {
            env.insert("KEYRING_LOG_LEVEL", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "KEYRING_LOG_LEVEL",
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn lists_test_overrides_in_use() {
        assert!(load(&sample_env()).unwrap().test_overrides().is_empty());
        let mut env = sample_env();
        env.insert("ENTRA_AUTHORITY_HOST", "http://127.0.0.1:9".into());
        env.insert("KEYRING_TEST_KEYVAULT_URL", "http://127.0.0.1:10".into());
        env.insert("KEYRING_TEST_LOGANALYTICS_URL", "https://la.example".into());
        env.insert("KEYRING_TEST_MANAGEMENT_URL", "https://arm.example".into());
        assert_eq!(
            load(&env).unwrap().test_overrides(),
            [
                "ENTRA_AUTHORITY_HOST",
                "KEYRING_TEST_MANAGEMENT_URL",
                "KEYRING_TEST_LOGANALYTICS_URL",
                "KEYRING_TEST_KEYVAULT_URL"
            ]
        );
    }

    #[test]
    fn parses_purge_flag() {
        let mut env = sample_env();
        env.insert("KEYRING_ALLOW_PURGE", "TRUE".into());
        assert!(load(&env).unwrap().allow_purge);
        env.insert("KEYRING_ALLOW_PURGE", "maybe".into());
        assert!(load(&env).is_err());
    }

    const IDENTITY: &str = "33333333-3333-3333-3333-333333333333";

    /// Settings for managed identity mode: no client secret, plus what App
    /// Service sets for an app with an identity.
    fn identity_env() -> HashMap<&'static str, String> {
        let mut env = sample_env();
        env.remove("ENTRA_CLIENT_SECRET");
        env.insert("KEYRING_FEDERATED_IDENTITY_CLIENT_ID", IDENTITY.into());
        env.insert(
            "IDENTITY_ENDPOINT",
            "http://169.254.129.1:8081/msi/token".into(),
        );
        env.insert("IDENTITY_HEADER", "header-value-from-platform".into());
        env
    }

    #[test]
    fn a_client_secret_alone_is_the_credential() {
        let config = load(&sample_env()).unwrap();
        assert!(matches!(config.credential, ClientCredential::Secret(_)));
    }

    #[test]
    fn a_managed_identity_alone_is_the_credential() {
        let mut env = identity_env();
        env.insert(
            "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
            IDENTITY.to_ascii_uppercase(),
        );
        let config = load(&env).unwrap();
        let ClientCredential::ManagedIdentity {
            identity_client_id,
            endpoint,
            ..
        } = &config.credential
        else {
            panic!("expected a managed identity: {:?}", config.credential);
        };
        assert_eq!(identity_client_id, IDENTITY);
        assert_eq!(endpoint, "http://169.254.129.1:8081/msi/token");
        let out = format!("{config:?}");
        assert!(!out.contains("header-value-from-platform"));
    }

    #[test]
    fn a_secret_and_an_identity_together_are_refused() {
        let mut env = identity_env();
        env.insert("ENTRA_CLIENT_SECRET", "client-secret-value".into());
        let err = load(&env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
                ..
            }
        ));
        assert!(
            err.to_string().contains(
                "Set ENTRA_CLIENT_SECRET or KEYRING_FEDERATED_IDENTITY_CLIENT_ID, not both"
            )
        );
    }

    #[test]
    fn neither_a_secret_nor_an_identity_reports_the_secret_missing() {
        let mut env = sample_env();
        env.remove("ENTRA_CLIENT_SECRET");
        assert_eq!(
            load(&env).unwrap_err(),
            ConfigError::Missing(vec!["ENTRA_CLIENT_SECRET"])
        );
    }

    #[test]
    fn the_identity_client_id_must_be_a_guid() {
        let mut env = identity_env();
        env.insert("KEYRING_FEDERATED_IDENTITY_CLIENT_ID", "my-identity".into());
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "KEYRING_FEDERATED_IDENTITY_CLIENT_ID",
                ..
            })
        ));
    }

    #[test]
    fn identity_mode_needs_the_platform_variables_and_a_local_endpoint() {
        for missing in ["IDENTITY_ENDPOINT", "IDENTITY_HEADER"] {
            let mut env = identity_env();
            env.remove(missing);
            let err = load(&env).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid { .. }), "{missing}");
            let text = err.to_string();
            assert!(
                text.contains("IDENTITY_ENDPOINT") && text.contains("IDENTITY_HEADER"),
                "{text}"
            );
        }
        let mut env = identity_env();
        env.insert("IDENTITY_ENDPOINT", "http://evil.example/msi/token".into());
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "IDENTITY_ENDPOINT",
                ..
            })
        ));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let config = load(&sample_env()).unwrap();
        let out = format!("{config:?}");
        assert!(!out.contains("client-secret-value"));
        assert!(!out.contains(&"x".repeat(64)));
    }
}
