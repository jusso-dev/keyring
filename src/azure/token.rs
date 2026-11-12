//! Access tokens for Azure, and the on-behalf-of exchange that gets them.
//!
//! Every token here belongs to the signed-in user. There is no
//! client-credentials grant, managed identity or app-only token anywhere in
//! the Azure data path.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::Deserialize;

use crate::auth::assertion::Credential;
use crate::auth::entra::{EntraAdvice, classify};
use crate::auth::session::{Session, UserTokens};
use crate::config::Config;
use crate::http::HttpError;
use crate::secret::Secret;

/// Treat tokens as expired this long before they really expire, so a request
/// never starts with a token that runs out halfway.
pub const EXPIRY_SKEW: Duration = Duration::from_secs(5 * 60);

/// Lifetime assumed when a token response has no `expires_in`. Entra always
/// sends one; this only has to be longer than [`EXPIRY_SKEW`], or the token
/// would be stale on arrival and every call would fetch another.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Longest lifetime believed from a token response. Entra's are about an
/// hour; anything far beyond that is a bad value, not a real lifetime.
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// When a token from a response with this `expires_in` stops working.
/// Never panics, whatever the value.
pub fn expiry_from(expires_in: Option<Duration>, now: SystemTime) -> SystemTime {
    let lifetime = expires_in.unwrap_or(DEFAULT_LIFETIME).min(MAX_LIFETIME);
    now.checked_add(lifetime).unwrap_or(now)
}

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
    const ALL: [Resource; 3] = [Self::KeyVault, Self::Management, Self::LogAnalytics];

    fn index(self) -> usize {
        match self {
            Self::KeyVault => 0,
            Self::Management => 1,
            Self::LogAnalytics => 2,
        }
    }

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

/// Upper bound on how long a failed exchange is shared with callers that
/// were queued behind it.
pub(crate) const FAILURE_MEMORY: Duration = Duration::from_secs(5);

/// Per-session cache of exchanged tokens. Memory only.
///
/// Concurrent requests that miss the cache wait for one exchange per
/// resource, and one refresh of the user's own token, instead of each
/// making its own. The expiry dashboard reads several vaults at once.
#[derive(Debug, Default)]
pub struct TokenCache {
    tokens: Mutex<HashMap<Resource, AccessToken>>,
    /// Held while exchanging for a resource, one per [`Resource`].
    exchanging: [tokio::sync::Mutex<()>; Resource::ALL.len()],
    /// Held while refreshing the user's own token.
    refreshing: tokio::sync::Mutex<()>,
    /// The last failed exchange per resource, so callers that were waiting
    /// on it get the same answer instead of each trying again in turn.
    failed: Mutex<HashMap<Resource, (Instant, TokenError)>>,
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

    /// The failure of a call that finished after `since`, if there was one.
    fn failure_since(&self, resource: Resource, since: Instant) -> Option<TokenError> {
        let map = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&resource)
            .filter(|(at, _)| *at >= since && at.elapsed() < FAILURE_MEMORY)
            .map(|(_, e)| e.clone())
    }

    fn set_failure(&self, resource: Resource, err: Option<&TokenError>) {
        let mut map = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        match err {
            Some(e) => {
                map.insert(resource, (Instant::now(), e.clone()));
            }
            None => {
                map.remove(&resource);
            }
        }
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

/// Map a refused token request with the shared classifier.
fn token_error(failure: &TokenFailure) -> TokenError {
    let error = crate::auth::oidc::safe_code(&failure.error);
    match classify(&error, &failure.error_codes) {
        EntraAdvice::SignInAgain => TokenError::SignInAgain,
        EntraAdvice::ConsentNeeded => TokenError::ConsentNeeded,
        EntraAdvice::Configuration { code } => TokenError::Refused { code },
        // Not expected on a back-channel request.
        EntraAdvice::Cancelled => TokenError::Refused { code: error },
    }
}

/// Talks to the Entra token endpoint for the on-behalf-of exchange and for
/// refreshing the user's own token.
pub struct TokenBroker {
    token_url: String,
    client_id: String,
    credential: Credential,
    api_scope: String,
    http: reqwest::Client,
}

impl TokenBroker {
    pub fn new(config: &Config, http: reqwest::Client, credential: Credential) -> Self {
        Self {
            token_url: format!(
                "{}/{}/oauth2/v2.0/token",
                config.authority_host, config.tenant_id
            ),
            client_id: config.client_id.clone(),
            credential,
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
        let cache = &session.azure_tokens;
        if let Some(t) = cache.get(resource, SystemTime::now()) {
            return Ok(t);
        }
        // One exchange per resource at a time. Whoever waited checks the
        // cache again, since the one before may have filled it.
        let started = Instant::now();
        let _guard = cache.exchanging[resource.index()].lock().await;
        if let Some(t) = cache.get(resource, SystemTime::now()) {
            return Ok(t);
        }
        // If the call ahead of us failed while we waited, share its answer.
        // Otherwise each queued request would wait out its own timeout in
        // turn. A request that arrives later still tries again.
        if let Some(err) = cache.failure_since(resource, started) {
            return Err(err);
        }
        let result = match self.fresh_user_token(session).await {
            Ok(user) => self.exchange(session, &user.access_token, resource).await,
            Err(e) => Err(e),
        };
        cache.set_failure(resource, result.as_ref().err());
        let token = result?;
        cache.put(resource, token.clone());
        Ok(token)
    }

    async fn fresh_user_token(&self, session: &Session) -> Result<UserTokens, TokenError> {
        let is_fresh = |t: &UserTokens| {
            AccessToken {
                secret: t.access_token.clone(),
                expires_at: t.expires_at,
            }
            .is_fresh(SystemTime::now())
        };
        let tokens = session.tokens();
        if is_fresh(&tokens) {
            return Ok(tokens);
        }
        // One refresh at a time, so concurrent refreshes don't race on
        // which rotated refresh token is kept.
        let _guard = session.azure_tokens.refreshing.lock().await;
        let tokens = session.tokens();
        if is_fresh(&tokens) {
            return Ok(tokens);
        }
        let Some(refresh) = tokens.refresh_token.as_ref() else {
            return Err(TokenError::SignInAgain);
        };
        let scope = format!("{} offline_access", self.api_scope);
        let ok = self
            .post(
                session,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.expose()),
                    ("scope", scope.as_str()),
                ],
            )
            .await?;
        let refreshed = UserTokens {
            access_token: Secret::new(ok.access_token),
            expires_at: expiry_from(ok.expires_in.map(Duration::from_secs), SystemTime::now()),
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
        let ok = self
            .post(
                session,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", user_token.expose()),
                    ("scope", resource.scope()),
                    ("requested_token_use", "on_behalf_of"),
                ],
            )
            .await?;
        tracing::debug!(resource = ?resource, "exchanged token on behalf of user");
        Ok(AccessToken::new(
            ok.access_token,
            expiry_from(ok.expires_in.map(Duration::from_secs), SystemTime::now()),
        ))
    }

    /// Send a token request. The client ID and the credential (the client
    /// secret, or the managed identity's assertion) are added here, so every
    /// request authenticates the same way.
    async fn post(
        &self,
        session: &Session,
        fields: &[(&str, &str)],
    ) -> Result<TokenSuccess, TokenError> {
        let unreachable = |e: reqwest::Error| {
            let e = HttpError::from(e);
            tracing::warn!(error = %e, "token endpoint unreachable");
            TokenError::from(e)
        };
        let credential = self.credential.form_fields().await?;
        let mut form: Vec<(&str, &str)> = vec![("client_id", self.client_id.as_str())];
        form.extend(credential.iter().map(|(k, v)| (*k, v.expose())));
        form.extend_from_slice(fields);
        let res = self
            .http
            .post(&self.token_url)
            .form(&form)
            .send()
            .await
            .map_err(unreachable)?;
        let status = res.status();
        let body = res.bytes().await.map_err(unreachable)?;
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|_| {
                tracing::warn!(status = status.as_u16(), "unreadable token response");
                TokenError::Unreachable("unreadable token response".into())
            });
        }
        match serde_json::from_slice::<TokenFailure>(&body) {
            Ok(f) => {
                if let Some(c) = f.claims.as_deref() {
                    session.set_claims_challenge(c);
                }
                // Only codes are logged. Descriptions can be long and aren't needed.
                tracing::warn!(
                    error = ?f.error,
                    codes = ?f.error_codes,
                    suberror = ?f.suberror,
                    "token request refused"
                );
                Err(token_error(&f))
            }
            Err(_) => {
                tracing::warn!(
                    status = status.as_u16(),
                    "token endpoint returned an error with no OAuth body"
                );
                Err(TokenError::Unreachable(format!(
                    "token endpoint returned {status}"
                )))
            }
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
            token_error(&failure("invalid_grant", &[65001])),
            TokenError::ConsentNeeded
        );
        assert_eq!(
            token_error(&failure("consent_required", &[])),
            TokenError::ConsentNeeded
        );
        assert_eq!(
            token_error(&failure("interaction_required", &[50076])),
            TokenError::SignInAgain
        );
        assert_eq!(
            token_error(&failure("invalid_grant", &[70008])),
            TokenError::SignInAgain
        );
        // A wrong ENTRA_API_SCOPE: signing in again wouldn't help.
        assert_eq!(
            token_error(&failure("invalid_grant", &[50013])),
            TokenError::Refused {
                code: "invalid_grant (AADSTS50013)".into()
            }
        );
        assert_eq!(
            token_error(&failure("invalid_client", &[7000215])),
            TokenError::Refused {
                code: "invalid_client (AADSTS7000215)".into()
            }
        );
        // A crafted error name can't reach the page or the log as-is.
        assert_eq!(
            token_error(&failure("x\nFORGED", &[])),
            TokenError::Refused {
                code: "unrecognised".into()
            }
        );
    }

    #[test]
    fn lifetimes_never_panic_and_outlast_the_skew() {
        let now = SystemTime::now();
        let missing = expiry_from(None, now);
        assert!(AccessToken::new("a", missing).is_fresh(now));
        assert_eq!(
            expiry_from(Some(Duration::from_secs(u64::MAX)), now),
            now + MAX_LIFETIME
        );
        assert_eq!(
            expiry_from(Some(Duration::from_secs(3600)), now),
            now + Duration::from_secs(3600)
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
