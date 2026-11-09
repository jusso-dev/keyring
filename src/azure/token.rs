//! Access tokens for Azure, and the on-behalf-of exchange that gets them.
//!
//! Every token here belongs to the signed-in user. There is no
//! client-credentials grant, managed identity or app-only token anywhere in
//! the Azure data path.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::auth::session::{Session, UserTokens};
use crate::config::Config;
use crate::http::HttpError;
use crate::secret::Secret;

/// Treat tokens as expired this long before they really expire, so a request
/// never starts with a token that runs out halfway.
pub const EXPIRY_SKEW: Duration = Duration::from_secs(5 * 60);

/// Which Azure API a token is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// Key Vault data plane: secrets, keys and certificates.
    KeyVault,
    /// Azure Resource Manager and Resource Graph.
    Management,
    /// Log Analytics, for the audit view.
    LogAnalytics,
}

impl Resource {
    pub fn scope(self) -> &'static str {
        match self {
            Self::KeyVault => "https://vault.azure.net/.default",
            Self::Management => "https://management.azure.com/.default",
            Self::LogAnalytics => "https://api.loganalytics.io/.default",
        }
    }
}

/// A bearer token and when it stops working. Prints as `[redacted]`.
#[derive(Clone)]
pub struct AccessToken {
    secret: Secret,
    pub expires_at: SystemTime,
}

impl AccessToken {
    pub fn new(value: impl Into<String>, expires_at: SystemTime) -> Self {
        Self {
            secret: Secret::new(value),
            expires_at,
        }
    }

    /// True while the token has more than [`EXPIRY_SKEW`] left.
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        self.expires_at
            .duration_since(now)
            .is_ok_and(|left| left > EXPIRY_SKEW)
    }

    /// The raw token, for the `Authorization` header only.
    pub fn expose(&self) -> &str {
        self.secret.expose()
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("value", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Per-session cache of exchanged tokens. Memory only.
#[derive(Debug, Default)]
pub struct TokenCache {
    tokens: Mutex<HashMap<Resource, AccessToken>>,
}

impl TokenCache {
    fn get(&self, resource: Resource, now: SystemTime) -> Option<AccessToken> {
        let map = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&resource).filter(|t| t.is_fresh(now)).cloned()
    }

    fn put(&self, resource: Resource, token: AccessToken) {
        let mut map = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(resource, token);
    }

    /// Forget a token, for example after Azure rejected it.
    pub fn forget(&self, resource: Resource) {
        let mut map = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&resource);
    }
}

/// Why we couldn't get a token for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The user must sign in again: their session ran out, or Entra wants
    /// fresh sign-in (MFA or a conditional access policy).
    SignInAgain,
    /// An admin has to consent to Keyring calling this API for the user.
    ConsentNeeded,
    /// Entra refused for another reason. `code` is the OAuth error code.
    Refused { code: String },
    /// Couldn't reach Entra ID.
    Unreachable(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignInAgain => f.write_str("user needs to sign in again"),
            Self::ConsentNeeded => f.write_str("consent required"),
            Self::Refused { code } => write!(f, "token request refused: {code}"),
            Self::Unreachable(m) => write!(f, "token endpoint unreachable: {m}"),
        }
    }
}

impl std::error::Error for TokenError {}

impl From<HttpError> for TokenError {
    fn from(e: HttpError) -> Self {
        Self::Unreachable(e.to_string())
    }
}

#[derive(Deserialize)]
struct TokenSuccess {
    access_token: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenFailure {
    error: String,
    #[serde(default)]
    error_codes: Vec<u64>,
    #[serde(default)]
    suberror: Option<String>,
    /// A conditional access challenge (JSON) to pass to the next sign-in.
    #[serde(default)]
    claims: Option<String>,
}

/// Entra error codes that mean an admin must consent.
const CONSENT_CODES: [u64; 3] = [65001, 65004, 650057];

fn classify(failure: &TokenFailure) -> TokenError {
    if failure.error == "consent_required"
        || failure
            .error_codes
            .iter()
            .any(|c| CONSENT_CODES.contains(c))
    {
        return TokenError::ConsentNeeded;
    }
    match failure.error.as_str() {
        // MFA, conditional access, expired or revoked refresh token.
        "interaction_required" | "invalid_grant" | "login_required" => TokenError::SignInAgain,
        other => TokenError::Refused {
            code: other.to_owned(),
        },
    }
}

/// Talks to the Entra token endpoint for the on-behalf-of exchange and for
/// refreshing the user's own token.
pub struct TokenBroker {
    token_url: String,
    client_id: String,
    client_secret: Secret,
    api_scope: String,
    http: reqwest::Client,
}

impl TokenBroker {
    pub fn new(config: &Config, http: reqwest::Client) -> Self {
        Self {
            token_url: format!(
                "{}/{}/oauth2/v2.0/token",
                config.authority_host, config.tenant_id
            ),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            api_scope: config.api_scope.clone(),
            http,
        }
    }

    /// A token for `resource`, acting as the session's user. Uses the cache
    /// when it can, refreshes the user's own token if it's about to expire,
    /// then exchanges it on behalf of the user.
    pub async fn token_for(
        &self,
        session: &Session,
        resource: Resource,
    ) -> Result<AccessToken, TokenError> {
        let now = SystemTime::now();
        if let Some(t) = session.azure_tokens.get(resource, now) {
            return Ok(t);
        }
        let user = self.fresh_user_token(session, now).await?;
        let token = self.exchange(session, &user.access_token, resource).await?;
        session.azure_tokens.put(resource, token.clone());
        Ok(token)
    }

    async fn fresh_user_token(
        &self,
        session: &Session,
        now: SystemTime,
    ) -> Result<UserTokens, TokenError> {
        let tokens = session.tokens();
        let current = AccessToken {
            secret: tokens.access_token.clone(),
            expires_at: tokens.expires_at,
        };
        if current.is_fresh(now) {
            return Ok(tokens);
        }
        let Some(refresh) = tokens.refresh_token.as_ref() else {
            return Err(TokenError::SignInAgain);
        };
        let scope = format!("{} offline_access", self.api_scope);
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose()),
            ("refresh_token", refresh.expose()),
            ("scope", scope.as_str()),
        ];
        let ok = self.post(Some(session), &form).await?;
        let refreshed = UserTokens {
            access_token: Secret::new(ok.access_token),
            expires_at: SystemTime::now() + Duration::from_secs(ok.expires_in.unwrap_or(300)),
            // Entra rotates refresh tokens; keep the old one if it didn't.
            refresh_token: ok.refresh_token.map(Secret::new).or(tokens.refresh_token),
        };
        session.set_tokens(refreshed.clone());
        tracing::debug!("refreshed user token");
        Ok(refreshed)
    }

    async fn exchange(
        &self,
        session: &Session,
        user_token: &Secret,
        resource: Resource,
    ) -> Result<AccessToken, TokenError> {
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose()),
            ("assertion", user_token.expose()),
            ("scope", resource.scope()),
            ("requested_token_use", "on_behalf_of"),
        ];
        let ok = self.post(Some(session), &form).await?;
        tracing::debug!(resource = ?resource, "exchanged token on behalf of user");
        Ok(AccessToken::new(
            ok.access_token,
            SystemTime::now() + Duration::from_secs(ok.expires_in.unwrap_or(300)),
        ))
    }

    async fn post(
        &self,
        session: Option<&Session>,
        form: &[(&str, &str)],
    ) -> Result<TokenSuccess, TokenError> {
        let res = self
            .http
            .post(&self.token_url)
            .form(form)
            .send()
            .await
            .map_err(HttpError::from)?;
        let status = res.status();
        let body = res.bytes().await.map_err(HttpError::from)?;
        if status.is_success() {
            return serde_json::from_slice(&body)
                .map_err(|_| TokenError::Unreachable("unreadable token response".into()));
        }
        match serde_json::from_slice::<TokenFailure>(&body) {
            Ok(f) => {
                if let (Some(c), Some(session)) = (f.claims.as_deref(), session) {
                    session.set_claims_challenge(c);
                }
                // Only codes are logged. Descriptions can be long and aren't needed.
                tracing::warn!(
                    error = ?f.error,
                    codes = ?f.error_codes,
                    suberror = ?f.suberror,
                    "token request refused"
                );
                Err(classify(&f))
            }
            Err(_) => Err(TokenError::Unreachable(format!(
                "token endpoint returned {status}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_never_prints() {
        let t = AccessToken::new("eyJ.secret.value", SystemTime::now());
        assert!(!format!("{t:?}").contains("eyJ"));
        assert!(!format!("{t}").contains("eyJ"));
        assert_eq!(t.expose(), "eyJ.secret.value");
    }

    #[test]
    fn freshness_includes_skew() {
        let now = SystemTime::now();
        assert!(AccessToken::new("a", now + EXPIRY_SKEW * 2).is_fresh(now));
        assert!(!AccessToken::new("a", now + EXPIRY_SKEW).is_fresh(now));
        assert!(!AccessToken::new("a", now - Duration::from_secs(1)).is_fresh(now));
    }

    fn failure(error: &str, codes: &[u64]) -> TokenFailure {
        TokenFailure {
            error: error.into(),
            error_codes: codes.to_vec(),
            suberror: None,
            claims: None,
        }
    }

    #[test]
    fn classifies_entra_errors() {
        assert_eq!(
            classify(&failure("invalid_grant", &[65001])),
            TokenError::ConsentNeeded
        );
        assert_eq!(
            classify(&failure("consent_required", &[])),
            TokenError::ConsentNeeded
        );
        assert_eq!(
            classify(&failure("interaction_required", &[50076])),
            TokenError::SignInAgain
        );
        assert_eq!(
            classify(&failure("invalid_grant", &[70008])),
            TokenError::SignInAgain
        );
        assert_eq!(
            classify(&failure("invalid_client", &[7000215])),
            TokenError::Refused {
                code: "invalid_client".into()
            }
        );
    }

    #[test]
    fn scopes_are_dot_default() {
        for r in [
            Resource::KeyVault,
            Resource::Management,
            Resource::LogAnalytics,
        ] {
            assert!(r.scope().ends_with("/.default"));
        }
    }
}
