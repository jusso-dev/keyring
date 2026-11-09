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
    pub client_secret: Secret,
    /// Public base URL with no trailing slash, for example `https://keyring.example.com`.
    pub base_url: String,
    pub session_secret: Secret,
    pub allow_purge: bool,
    pub listen: SocketAddr,
    pub log_level: String,
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
        if !is_tenant_id(&tenant_id) {
            return Err(ConfigError::Invalid {
                name: "ENTRA_TENANT_ID",
                reason: "expected a GUID or a domain such as contoso.onmicrosoft.com".into(),
            });
        }

        let base_url = take("APP_BASE_URL").trim_end_matches('/').to_owned();
        let local =
            base_url.starts_with("http://localhost") || base_url.starts_with("http://127.0.0.1");
        if !(base_url.starts_with("https://") || local) {
            return Err(ConfigError::Invalid {
                name: "APP_BASE_URL",
                reason: "must start with https:// (http:// is only allowed for localhost)".into(),
            });
        }

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

        Ok(Self {
            tenant_id,
            client_id: take("ENTRA_CLIENT_ID"),
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
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn is_tenant_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 253
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
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
