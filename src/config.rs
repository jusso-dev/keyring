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
    /// The one managed identity Keyring uses for its own Azure calls: the
    /// federated credential and the audit sink. Nothing else.
    pub managed_identity: Option<ManagedIdentity>,
    /// Where Keyring's own audit events are also sent, if anywhere.
    pub audit_sink: Option<AuditSinkSettings>,
    /// `KEYRING_AUDIT_REQUIRED`: refuse reveals and private key downloads
    /// while the audit sink is degraded.
    pub audit_required: bool,
    /// Set from `KEYRING_FEDERATED_IDENTITY_CLIENT_ID` alone.
    legacy_identity_setting: bool,
    /// Public base URL with no trailing slash, for example `https://keyring.example.com`.
    pub base_url: String,
    pub session_secret: Secret,
    pub allow_purge: bool,
    pub listen: SocketAddr,
    pub log_level: String,
    /// `KEYRING_LOG_FORMAT`: plain text lines (the default) or one JSON
    /// object per line.
    pub log_format: LogFormat,
    /// `KEYRING_TRUSTED_PROXY_HOPS`: how many proxies in front of Keyring
    /// add to `X-Forwarded-For`. 0 (the default) ignores the header and
    /// records the socket peer as the client's address.
    pub trusted_proxy_hops: u8,
    /// `KEYRING_STEP_UP_AUTH_CONTEXT` and `KEYRING_STEP_UP_MAX_AGE`: what a
    /// sensitive action needs beyond a live session. Off by default.
    pub step_up: crate::auth::step_up::StepUpPolicy,
    /// `KEYRING_STALE_AFTER_DAYS`: a value unchanged for more than this
    /// many days gets the "Not changed in over ..." badge.
    pub stale_after_days: u32,
    /// Azure Resource Manager base URL. Only changed by tests.
    pub management_url: String,
    /// Log Analytics query API base URL. Only changed by tests.
    pub loganalytics_url: String,
    /// Replaces the audit sink's ingestion endpoint. Only set by tests, to
    /// point at a mock.
    pub audit_ingestion_test_url: Option<String>,
    /// Replaces `https://<vault>.vault.azure.net` with `<base>/<vault>`.
    /// Only set by tests, to point at a mock Key Vault.
    pub keyvault_test_base: Option<String>,
}

/// How Keyring proves it is the app registration.
#[derive(Debug, Clone)]
pub enum ClientCredential {
    /// A client secret from the app registration. For local use.
    Secret(Secret),
    /// The configured managed identity ([`Config::managed_identity`]), which
    /// the app registration trusts as a federated credential. Keyring sends
    /// a short-lived token from the identity as `client_assertion`, so there
    /// is no secret to rotate.
    ManagedIdentity,
}

/// The user-assigned managed identity Keyring uses for its own calls.
#[derive(Debug, Clone)]
pub struct ManagedIdentity {
    /// The identity's client ID, lower case.
    pub client_id: String,
    /// `IDENTITY_ENDPOINT`: the local token service, set by the platform.
    pub endpoint: String,
    /// `IDENTITY_HEADER`: sent with each request to that service.
    pub header: Secret,
}

/// Where the audit sink sends Keyring's own audit events: a data collection
/// rule's stream in Log Analytics, through the Logs Ingestion API.
#[derive(Debug, Clone)]
pub struct AuditSinkSettings {
    /// `https://<rule>.<region>.ingest.monitor.azure.com`, no trailing slash.
    pub endpoint: String,
    /// The rule's immutable ID, `dcr-` and 32 hex digits.
    pub dcr_id: String,
    /// The stream, `Custom-KeyringAudit_CL` unless set.
    pub stream: String,
    /// Batching, retry and failure timings. Always the defaults outside
    /// tests.
    pub tuning: crate::audit::sink::Tuning,
}

/// The stream the templates create.
pub const DEFAULT_AUDIT_STREAM: &str = "Custom-KeyringAudit_CL";

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

        // One managed identity for everything Keyring does as itself. The
        // old name still works for now, and may not disagree with the new.
        let identity_name = identity_setting(&get)?;
        let identity_value = identity_name.and_then(get);
        // The client secret is only needed without a managed identity.
        let uses_identity = identity_value.is_some();
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

        let managed_identity = match (identity_name, identity_value) {
            (Some(name), Some(identity)) => {
                let client_id = identity.to_ascii_lowercase();
                if !is_guid(&client_id) {
                    return Err(ConfigError::Invalid {
                        name,
                        reason: "expected the managed identity's client ID, a GUID".into(),
                    });
                }
                let (Some(endpoint), Some(header)) =
                    (get("IDENTITY_ENDPOINT"), get("IDENTITY_HEADER"))
                else {
                    return Err(ConfigError::Invalid {
                        name,
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
                Some(ManagedIdentity {
                    client_id,
                    endpoint,
                    header: Secret::new(header),
                })
            }
            _ => None,
        };

        // Without a client secret, the managed identity is the credential.
        // The old name only ever meant that, so it can't sit beside a secret.
        let credential = match get("ENTRA_CLIENT_SECRET") {
            Some(_) if get(LEGACY_IDENTITY_VAR).is_some() => {
                return Err(ConfigError::Invalid {
                    name: LEGACY_IDENTITY_VAR,
                    reason: "Set ENTRA_CLIENT_SECRET or KEYRING_FEDERATED_IDENTITY_CLIENT_ID, not both. To keep the client secret and use the identity only for the audit sink, set KEYRING_MANAGED_IDENTITY_CLIENT_ID instead".into(),
                });
            }
            Some(secret) => ClientCredential::Secret(Secret::new(secret)),
            None => ClientCredential::ManagedIdentity,
        };

        let audit_sink = audit_sink(&get, managed_identity.is_some())?;
        let audit_required = match get("KEYRING_AUDIT_REQUIRED").as_deref() {
            None => false,
            Some(v) => parse_bool(v).ok_or_else(|| ConfigError::Invalid {
                name: "KEYRING_AUDIT_REQUIRED",
                reason: "use true or false".into(),
            })?,
        };
        if audit_required && audit_sink.is_none() {
            return Err(ConfigError::Invalid {
                name: "KEYRING_AUDIT_REQUIRED",
                reason: "needs the audit sink: set KEYRING_AUDIT_INGESTION_ENDPOINT and KEYRING_AUDIT_DCR_ID".into(),
            });
        }

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
        let audit_ingestion_test_url = get("KEYRING_TEST_AUDIT_INGESTION_URL")
            .map(|v| checked_origin("KEYRING_TEST_AUDIT_INGESTION_URL", &v))
            .transpose()?;
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

        let log_format = match get("KEYRING_LOG_FORMAT")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("text") => LogFormat::Text,
            Some("json") => LogFormat::Json,
            Some(_) => {
                return Err(ConfigError::Invalid {
                    name: "KEYRING_LOG_FORMAT",
                    reason: "use text or json".into(),
                });
            }
        };

        let trusted_proxy_hops = match get("KEYRING_TRUSTED_PROXY_HOPS") {
            None => 0,
            Some(v) => v
                .parse::<u8>()
                .ok()
                .filter(|n| *n <= MAX_PROXY_HOPS)
                .ok_or_else(|| ConfigError::Invalid {
                    name: "KEYRING_TRUSTED_PROXY_HOPS",
                    reason: format!(
                        "use a whole number from 0 to {MAX_PROXY_HOPS}: 1 on App Service or Container Apps, 0 with nothing in front"
                    ),
                })?,
        };

        let step_up = step_up_policy(&get)?;

        let stale_after_days = match get("KEYRING_STALE_AFTER_DAYS") {
            None => DEFAULT_STALE_AFTER_DAYS,
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|d| (1..=MAX_STALE_AFTER_DAYS).contains(d))
                .ok_or_else(|| ConfigError::Invalid {
                    name: "KEYRING_STALE_AFTER_DAYS",
                    reason: format!("use a whole number of days from 1 to {MAX_STALE_AFTER_DAYS}"),
                })?,
        };

        Ok(Self {
            stale_after_days,
            step_up,
            log_format,
            trusted_proxy_hops,
            loganalytics_url,
            management_url,
            keyvault_test_base,
            audit_ingestion_test_url,
            tenant_id,
            client_id,
            authority_host,
            api_scope,
            credential,
            managed_identity,
            audit_sink,
            audit_required,
            legacy_identity_setting: identity_name == Some(LEGACY_IDENTITY_VAR),
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
        if self.audit_ingestion_test_url.is_some() {
            out.push("KEYRING_TEST_AUDIT_INGESTION_URL");
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
            && self
                .audit_ingestion_test_url
                .as_deref()
                .is_none_or(|b| b.starts_with("https://"))
    }

    /// The URL the audit sink posts to, if the sink is set.
    pub fn audit_ingestion_url(&self) -> Option<String> {
        let sink = self.audit_sink.as_ref()?;
        let base = self
            .audit_ingestion_test_url
            .as_deref()
            .unwrap_or(&sink.endpoint);
        Some(format!(
            "{base}/dataCollectionRules/{}/streams/{}?api-version={}",
            sink.dcr_id,
            sink.stream,
            crate::audit::sink::API_VERSION
        ))
    }

    /// True when the old identity setting is the one in use, so start-up
    /// can warn that it is deprecated.
    pub fn uses_legacy_identity_setting(&self) -> bool {
        self.legacy_identity_setting
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

/// How log lines are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// `key=value` text lines, as before.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// The managed identity's client ID.
pub const IDENTITY_VAR: &str = "KEYRING_MANAGED_IDENTITY_CLIENT_ID";

/// The old name for [`IDENTITY_VAR`], from when the identity was only the
/// federated credential. Still read, with a warning at start.
pub const LEGACY_IDENTITY_VAR: &str = "KEYRING_FEDERATED_IDENTITY_CLIENT_ID";

/// Which identity setting is in use: the new name, the old one, or
/// neither. Both set to different values is refused, since Keyring has one
/// identity of its own.
fn identity_setting(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<&'static str>, ConfigError> {
    match (get(IDENTITY_VAR), get(LEGACY_IDENTITY_VAR)) {
        (Some(new), Some(old)) if !new.eq_ignore_ascii_case(&old) => Err(ConfigError::Invalid {
            name: IDENTITY_VAR,
            reason: "is set to a different identity from KEYRING_FEDERATED_IDENTITY_CLIENT_ID. Keyring has one managed identity. Set only KEYRING_MANAGED_IDENTITY_CLIENT_ID".into(),
        }),
        (Some(_), _) => Ok(Some(IDENTITY_VAR)),
        (None, Some(_)) => Ok(Some(LEGACY_IDENTITY_VAR)),
        (None, None) => Ok(None),
    }
}

/// The audit sink settings: the endpoint and rule ID together, or none of
/// the three. Needs the managed identity, which is the only thing it ever
/// writes with.
fn audit_sink(
    get: &impl Fn(&str) -> Option<String>,
    has_identity: bool,
) -> Result<Option<AuditSinkSettings>, ConfigError> {
    let endpoint = get("KEYRING_AUDIT_INGESTION_ENDPOINT");
    let dcr_id = get("KEYRING_AUDIT_DCR_ID");
    let stream = get("KEYRING_AUDIT_STREAM");
    let (endpoint, dcr_id) = match (endpoint, dcr_id) {
        (None, None) => {
            if stream.is_some() {
                return Err(ConfigError::Invalid {
                    name: "KEYRING_AUDIT_STREAM",
                    reason: "needs KEYRING_AUDIT_INGESTION_ENDPOINT and KEYRING_AUDIT_DCR_ID too"
                        .into(),
                });
            }
            return Ok(None);
        }
        (Some(e), Some(d)) => (e, d),
        (Some(_), None) | (None, Some(_)) => {
            return Err(ConfigError::Invalid {
                name: "KEYRING_AUDIT_INGESTION_ENDPOINT",
                reason: "set it and KEYRING_AUDIT_DCR_ID together, or neither".into(),
            });
        }
    };
    if !has_identity {
        return Err(ConfigError::Invalid {
            name: "KEYRING_AUDIT_INGESTION_ENDPOINT",
            reason: "needs KEYRING_MANAGED_IDENTITY_CLIENT_ID. The audit sink writes only with Keyring's managed identity, never with a client secret".into(),
        });
    }
    let endpoint =
        checked_ingestion_endpoint(&endpoint).map_err(|reason| ConfigError::Invalid {
            name: "KEYRING_AUDIT_INGESTION_ENDPOINT",
            reason,
        })?;
    if !is_dcr_id(&dcr_id) {
        return Err(ConfigError::Invalid {
            name: "KEYRING_AUDIT_DCR_ID",
            reason: "expected the rule's immutable ID, dcr- and 32 hexadecimal digits".into(),
        });
    }
    let stream = stream.unwrap_or_else(|| DEFAULT_AUDIT_STREAM.into());
    if !is_stream_name(&stream) {
        return Err(ConfigError::Invalid {
            name: "KEYRING_AUDIT_STREAM",
            reason:
                "expected Custom- and then letters, digits or _, such as Custom-KeyringAudit_CL"
                    .into(),
        });
    }
    Ok(Some(AuditSinkSettings {
        endpoint,
        dcr_id: dcr_id.to_ascii_lowercase(),
        stream,
        tuning: crate::audit::sink::Tuning::default(),
    }))
}

/// Check the logs ingestion endpoint is `https://` on a host under
/// `ingest.monitor.azure.com`, with nothing after the host, and return it
/// in normal form.
pub fn checked_ingestion_endpoint(raw: &str) -> Result<String, String> {
    let rule = "must be the rule's logs ingestion endpoint, https://<name>.<region>.ingest.monitor.azure.com";
    let url = openidconnect::url::Url::parse(raw.trim()).map_err(|_| rule.to_owned())?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let label = host.strip_suffix(".ingest.monitor.azure.com").unwrap_or("");
    let ok_host = !label.is_empty()
        && label
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if url.scheme() != "https"
        || !ok_host
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(rule.to_owned());
    }
    Ok(format!("https://{host}"))
}

fn is_dcr_id(v: &str) -> bool {
    v.strip_prefix("dcr-")
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_stream_name(v: &str) -> bool {
    v.strip_prefix("Custom-").is_some_and(|n| {
        (1..=100).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Most proxies `KEYRING_TRUSTED_PROXY_HOPS` can name.
pub const MAX_PROXY_HOPS: u8 = 8;

/// Values `KEYRING_LOG_LEVEL` accepts. `off` is left out on purpose.
/// Keyring's audit events are written at every level.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Default for `KEYRING_STALE_AFTER_DAYS`.
pub const DEFAULT_STALE_AFTER_DAYS: u32 = 365;
/// Largest `KEYRING_STALE_AFTER_DAYS` accepted: ten years.
pub const MAX_STALE_AFTER_DAYS: u32 = 3650;

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

/// `KEYRING_STEP_UP_AUTH_CONTEXT` and `KEYRING_STEP_UP_MAX_AGE`, checked
/// at start so a bad value stops Keyring instead of turning the check off.
fn step_up_policy(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<crate::auth::step_up::StepUpPolicy, ConfigError> {
    use crate::auth::step_up::{MAX_AGE_LIMIT_MINUTES, StepUpPolicy, auth_context_id};
    let auth_context = get("KEYRING_STEP_UP_AUTH_CONTEXT")
        .map(|v| {
            auth_context_id(&v).ok_or_else(|| ConfigError::Invalid {
                name: "KEYRING_STEP_UP_AUTH_CONTEXT",
                reason: "use an authentication context ID from c1 to c99, as shown in Entra ID under Conditional Access, Authentication contexts".into(),
            })
        })
        .transpose()?;
    let max_age = get("KEYRING_STEP_UP_MAX_AGE")
        .map(|v| {
            v.parse::<u64>()
                .ok()
                .filter(|m| (1..=MAX_AGE_LIMIT_MINUTES).contains(m))
                .map(|m| std::time::Duration::from_secs(m * 60))
                .ok_or_else(|| ConfigError::Invalid {
                    name: "KEYRING_STEP_UP_MAX_AGE",
                    reason: format!(
                        "use a whole number of minutes from 1 to {MAX_AGE_LIMIT_MINUTES}"
                    ),
                })
        })
        .transpose()?;
    Ok(StepUpPolicy {
        auth_context,
        max_age,
    })
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
    fn stale_after_days_is_checked() {
        let mut env = sample_env();
        assert_eq!(load(&env).unwrap().stale_after_days, 365);
        env.insert("KEYRING_STALE_AFTER_DAYS", "90".into());
        assert_eq!(load(&env).unwrap().stale_after_days, 90);
        env.insert("KEYRING_STALE_AFTER_DAYS", "3650".into());
        assert_eq!(load(&env).unwrap().stale_after_days, 3650);
        for bad in ["0", "-1", "3651", "1.5", "a year"] {
            env.insert("KEYRING_STALE_AFTER_DAYS", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "KEYRING_STALE_AFTER_DAYS",
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn log_format_and_proxy_hops() {
        let mut env = sample_env();
        let c = load(&env).unwrap();
        assert_eq!(c.log_format, LogFormat::Text);
        assert_eq!(c.trusted_proxy_hops, 0);
        env.insert("KEYRING_LOG_FORMAT", "JSON".into());
        env.insert("KEYRING_TRUSTED_PROXY_HOPS", "1".into());
        let c = load(&env).unwrap();
        assert_eq!(c.log_format, LogFormat::Json);
        assert_eq!(c.trusted_proxy_hops, 1);
        env.insert("KEYRING_LOG_FORMAT", "xml".into());
        assert!(matches!(
            load(&env),
            Err(ConfigError::Invalid {
                name: "KEYRING_LOG_FORMAT",
                ..
            })
        ));
        env.remove("KEYRING_LOG_FORMAT");
        for bad in ["-1", "9", "one", "1.5"] {
            env.insert("KEYRING_TRUSTED_PROXY_HOPS", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "KEYRING_TRUSTED_PROXY_HOPS",
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
        assert!(matches!(
            config.credential,
            ClientCredential::ManagedIdentity
        ));
        let identity = config.managed_identity.as_ref().unwrap();
        assert_eq!(identity.client_id, IDENTITY);
        assert_eq!(identity.endpoint, "http://169.254.129.1:8081/msi/token");
        assert!(config.uses_legacy_identity_setting());
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

    /// Identity mode under the new name.
    fn new_identity_env() -> HashMap<&'static str, String> {
        let mut env = identity_env();
        env.remove(LEGACY_IDENTITY_VAR);
        env.insert(IDENTITY_VAR, IDENTITY.into());
        env
    }

    const DCR: &str = "dcr-00112233445566778899aabbccddeeff";

    fn with_sink(mut env: HashMap<&'static str, String>) -> HashMap<&'static str, String> {
        env.insert(
            "KEYRING_AUDIT_INGESTION_ENDPOINT",
            "https://keyring-audit-abcd.australiaeast-1.ingest.monitor.azure.com".into(),
        );
        env.insert("KEYRING_AUDIT_DCR_ID", DCR.into());
        env
    }

    fn invalid(env: &HashMap<&'static str, String>) -> &'static str {
        match load(env) {
            Err(ConfigError::Invalid { name, .. }) => name,
            other => panic!("expected an invalid setting, got {other:?}"),
        }
    }

    #[test]
    fn the_new_identity_name_is_the_credential_without_a_secret() {
        let config = load(&new_identity_env()).unwrap();
        assert!(matches!(
            config.credential,
            ClientCredential::ManagedIdentity
        ));
        assert_eq!(config.managed_identity.unwrap().client_id, IDENTITY);
        assert!(
            !load(&new_identity_env())
                .unwrap()
                .uses_legacy_identity_setting()
        );
    }

    #[test]
    fn the_new_identity_name_can_sit_beside_a_client_secret() {
        // Then the secret proves the app to Entra, and the identity is only
        // for the audit sink.
        let mut env = new_identity_env();
        env.insert("ENTRA_CLIENT_SECRET", "client-secret-value".into());
        let config = load(&env).unwrap();
        assert!(matches!(config.credential, ClientCredential::Secret(_)));
        assert!(config.managed_identity.is_some());
    }

    #[test]
    fn both_identity_names_must_agree() {
        let mut env = new_identity_env();
        env.insert(LEGACY_IDENTITY_VAR, IDENTITY.to_ascii_uppercase());
        assert!(load(&env).is_ok(), "the same identity, in any case");
        env.insert(
            LEGACY_IDENTITY_VAR,
            "44444444-4444-4444-4444-444444444444".into(),
        );
        let err = load(&env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: IDENTITY_VAR,
                ..
            }
        ));
        assert!(err.to_string().contains("one managed identity"));
    }

    #[test]
    fn the_audit_sink_loads_with_its_default_stream() {
        let config = load(&with_sink(new_identity_env())).unwrap();
        let sink = config.audit_sink.as_ref().unwrap();
        assert_eq!(
            sink.endpoint,
            "https://keyring-audit-abcd.australiaeast-1.ingest.monitor.azure.com"
        );
        assert_eq!(sink.dcr_id, DCR);
        assert_eq!(sink.stream, "Custom-KeyringAudit_CL");
        assert_eq!(
            config.audit_ingestion_url().unwrap(),
            format!(
                "https://keyring-audit-abcd.australiaeast-1.ingest.monitor.azure.com/dataCollectionRules/{DCR}/streams/Custom-KeyringAudit_CL?api-version=2023-01-01"
            )
        );
        assert!(!config.audit_required);
        assert!(load(&new_identity_env()).unwrap().audit_sink.is_none());
    }

    #[test]
    fn the_audit_sink_needs_the_managed_identity() {
        // A client secret is never enough: the sink only writes as the
        // identity.
        let err = load(&with_sink(sample_env())).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "KEYRING_AUDIT_INGESTION_ENDPOINT",
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("KEYRING_MANAGED_IDENTITY_CLIENT_ID")
        );
        // The old name still counts as the identity.
        assert!(
            load(&with_sink(identity_env()))
                .unwrap()
                .audit_sink
                .is_some()
        );
    }

    #[test]
    fn the_audit_sink_settings_go_together() {
        let mut env = with_sink(new_identity_env());
        env.remove("KEYRING_AUDIT_DCR_ID");
        assert_eq!(invalid(&env), "KEYRING_AUDIT_INGESTION_ENDPOINT");
        let mut env = with_sink(new_identity_env());
        env.remove("KEYRING_AUDIT_INGESTION_ENDPOINT");
        assert_eq!(invalid(&env), "KEYRING_AUDIT_INGESTION_ENDPOINT");
        let mut env = new_identity_env();
        env.insert("KEYRING_AUDIT_STREAM", "Custom-KeyringAudit_CL".into());
        assert_eq!(invalid(&env), "KEYRING_AUDIT_STREAM");
    }

    #[test]
    fn the_ingestion_endpoint_is_https_on_azure_monitor() {
        for bad in [
            "http://x.australiaeast-1.ingest.monitor.azure.com",
            "https://ingest.monitor.azure.com",
            "https://x.ingest.monitor.azure.com.evil.com",
            "https://x.ingest.monitor.azure.com:8443",
            "https://x.ingest.monitor.azure.com/path",
            "https://x.ingest.monitor.azure.com/?q=1",
            "https://user@x.ingest.monitor.azure.com",
            "https://x.monitor.azure.com",
            "https://x..ingest.monitor.azure.com",
            "x.ingest.monitor.azure.com",
        ] {
            let mut env = with_sink(new_identity_env());
            env.insert("KEYRING_AUDIT_INGESTION_ENDPOINT", bad.into());
            assert_eq!(invalid(&env), "KEYRING_AUDIT_INGESTION_ENDPOINT", "{bad}");
        }
        let mut env = with_sink(new_identity_env());
        env.insert(
            "KEYRING_AUDIT_INGESTION_ENDPOINT",
            "HTTPS://My-DCE.EastUS-1.Ingest.Monitor.Azure.com/".into(),
        );
        assert_eq!(
            load(&env).unwrap().audit_sink.unwrap().endpoint,
            "https://my-dce.eastus-1.ingest.monitor.azure.com"
        );
    }

    #[test]
    fn the_rule_id_and_stream_are_checked() {
        for bad in [
            "dcr-123",
            "00112233445566778899aabbccddeeff",
            "dcr-00112233445566778899aabbccddeefg",
            "/subscriptions/x/resourceGroups/y/providers/Microsoft.Insights/dataCollectionRules/z",
        ] {
            let mut env = with_sink(new_identity_env());
            env.insert("KEYRING_AUDIT_DCR_ID", bad.into());
            assert_eq!(invalid(&env), "KEYRING_AUDIT_DCR_ID", "{bad}");
        }
        for bad in ["KeyringAudit_CL", "Custom-", "Custom-a/b", "Custom-a b"] {
            let mut env = with_sink(new_identity_env());
            env.insert("KEYRING_AUDIT_STREAM", bad.into());
            assert_eq!(invalid(&env), "KEYRING_AUDIT_STREAM", "{bad}");
        }
        let mut env = with_sink(new_identity_env());
        env.insert("KEYRING_AUDIT_STREAM", "Custom-Other_CL".into());
        assert_eq!(
            load(&env).unwrap().audit_sink.unwrap().stream,
            "Custom-Other_CL"
        );
    }

    #[test]
    fn audit_required_needs_the_sink() {
        let mut env = new_identity_env();
        env.insert("KEYRING_AUDIT_REQUIRED", "true".into());
        assert_eq!(invalid(&env), "KEYRING_AUDIT_REQUIRED");
        let mut env = with_sink(new_identity_env());
        env.insert("KEYRING_AUDIT_REQUIRED", "true".into());
        assert!(load(&env).unwrap().audit_required);
        env.insert("KEYRING_AUDIT_REQUIRED", "sometimes".into());
        assert_eq!(invalid(&env), "KEYRING_AUDIT_REQUIRED");
    }

    #[test]
    fn step_up_is_off_by_default_and_checked_when_set() {
        let config = load(&sample_env()).unwrap();
        assert!(!config.step_up.is_on());
        let mut env = sample_env();
        env.insert("KEYRING_STEP_UP_AUTH_CONTEXT", "C7".into());
        env.insert("KEYRING_STEP_UP_MAX_AGE", "15".into());
        let config = load(&env).unwrap();
        assert_eq!(config.step_up.auth_context.as_deref(), Some("c7"));
        assert_eq!(
            config.step_up.max_age,
            Some(std::time::Duration::from_secs(15 * 60))
        );
        for bad in ["c0", "c100", "acr1", "1"] {
            env.insert("KEYRING_STEP_UP_AUTH_CONTEXT", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "KEYRING_STEP_UP_AUTH_CONTEXT",
                        ..
                    })
                ),
                "{bad}"
            );
        }
        env.insert("KEYRING_STEP_UP_AUTH_CONTEXT", "c1".into());
        for bad in ["0", "-5", "721", "15m", "1.5"] {
            env.insert("KEYRING_STEP_UP_MAX_AGE", bad.into());
            assert!(
                matches!(
                    load(&env),
                    Err(ConfigError::Invalid {
                        name: "KEYRING_STEP_UP_MAX_AGE",
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_output_hides_secrets() {
        let config = load(&sample_env()).unwrap();
        let out = format!("{config:?}");
        assert!(!out.contains("client-secret-value"));
        assert!(!out.contains(&"x".repeat(64)));
    }
}
