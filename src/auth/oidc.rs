//! Entra ID sign-in: OpenID Connect authorisation code flow with PKCE.
//!
//! Token and ID token checks (issuer, audience, expiry, nonce, signature
//! against the tenant's published keys) are done by the `openidconnect`
//! crate, not by hand.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthType, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    ProviderMetadataWithLogout, RedirectUrl, Scope, SignatureVerificationError,
    StandardErrorResponse, StandardTokenResponse, TokenResponse,
};
use tokio::sync::{Mutex, RwLock};

use crate::auth::entra::{self, EntraAdvice};
use crate::auth::session::{User, UserId, UserTokens};
use crate::azure::token::expiry_from;
use crate::config::Config;
use crate::http::{HttpError, OidcHttp, error_chain};
use crate::secret::Secret;

/// Re-fetch the tenant's discovery document and signing keys this often.
pub const METADATA_TTL: Duration = Duration::from_secs(60 * 60);

/// After a failed fetch, wait this long before trying again. Meanwhile the
/// last good document is used if there is one.
pub const METADATA_RETRY_AFTER: Duration = Duration::from_secs(30);

/// What we remember between sending someone to Entra and them coming back.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    /// Set when the person was signed out before a form was saved, so the
    /// page they return to can say nothing changed.
    #[serde(default)]
    pub unsaved: bool,
}

/// Written by hand so state, nonce and the PKCE verifier never print.
impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("return_to", &self.return_to)
            .field("unsaved", &self.unsaved)
            .finish_non_exhaustive()
    }
}

/// Why sign-in failed. Each variant maps to a plain message for the user.
#[derive(Debug)]
pub enum SignInError {
    /// Couldn't reach Entra ID or read its answer.
    Unreachable(String),
    /// Entra sent back an error, for example the user cancelled or consent is needed.
    Provider { code: String, codes: Vec<u64> },
    /// The browser's side of the sign-in didn't match: no login cookie, an
    /// old one, or a `state` that isn't ours. Usually a sign-in that took
    /// too long or was started in another tab.
    Stale(String),
    /// Entra's ID token failed our checks (signature, issuer, audience,
    /// nonce). Usually a setting, not something the person can fix.
    Rejected(String),
}

impl std::fmt::Display for SignInError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "identity provider unreachable: {m}"),
            Self::Provider { code, codes } => {
                write!(f, "identity provider returned {code} {codes:?}")
            }
            Self::Stale(m) => write!(f, "sign-in state rejected: {m}"),
            Self::Rejected(m) => write!(f, "ID token rejected: {m}"),
        }
    }
}

impl SignInError {
    /// What the person or admin should do about an error Entra returned.
    pub fn advice(&self) -> Option<EntraAdvice> {
        match self {
            Self::Provider { code, codes } => Some(entra::classify(code, codes)),
            _ => None,
        }
    }
}

/// An OAuth error code from a query string or response, if it looks like
/// one (`access_denied`, `consent_required` and so on). Anything else is
/// replaced, so a crafted value can't be written into the logs.
pub fn safe_code(raw: &str) -> String {
    if (1..=64).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        raw.to_owned()
    } else {
        "unrecognised".to_owned()
    }
}

/// The Entra ID token claims Keyring reads beyond the standard ones.
/// `oid` and `tid` identify the person in Entra's own logs.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EntraClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
}

impl AdditionalClaims for EntraClaims {}

type EntraTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EntraClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

/// `CoreClient` with [`EntraClaims`] in place of no extra claims.
type EntraClient = openidconnect::Client<
    EntraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    EntraTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The discovery cache: the last good document, and when a fetch last
/// failed so a refetch isn't tried on every request.
#[derive(Default)]
struct MetadataCache {
    good: Option<(Instant, Arc<ProviderMetadataWithLogout>)>,
    failed_at: Option<Instant>,
    /// Set when the signing keys are known to be out of date.
    stale: bool,
}

pub struct Oidc {
    issuer: String,
    client_id: String,
    client_secret: Secret,
    redirect_url: String,
    signed_out_url: String,
    api_scope: String,
    http: OidcHttp,
    metadata: RwLock<MetadataCache>,
    /// Held while fetching, so only one fetch goes out at a time.
    fetching: Mutex<()>,
    ttl: Duration,
    retry_after: Duration,
}

impl Oidc {
    pub fn new(config: &Config, http: reqwest::Client) -> Self {
        Self {
            issuer: config.issuer(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_url: config.redirect_url(),
            signed_out_url: config.signed_out_url(),
            api_scope: config.api_scope.clone(),
            http: OidcHttp(http),
            metadata: RwLock::new(MetadataCache::default()),
            fetching: Mutex::new(()),
            ttl: METADATA_TTL,
            retry_after: METADATA_RETRY_AFTER,
        }
    }

    /// Change how long discovery is cached and how long to back off after
    /// a failure. Only tests need this.
    pub fn with_metadata_timings(mut self, ttl: Duration, retry_after: Duration) -> Self {
        self.ttl = ttl;
        self.retry_after = retry_after;
        self
    }

    /// The outbound HTTP client, shared with the token exchange.
    pub fn http(&self) -> &reqwest::Client {
        &self.http.0
    }

    /// The cached document if it's fresh enough, or if a fetch failed a
    /// moment ago (then the old one is better than none).
    async fn cached(&self) -> Option<Arc<ProviderMetadataWithLogout>> {
        let c = self.metadata.read().await;
        let (fetched, doc) = c.good.as_ref()?;
        let backing_off = c.failed_at.is_some_and(|t| t.elapsed() < self.retry_after);
        ((fetched.elapsed() < self.ttl && !c.stale) || backing_off).then(|| doc.clone())
    }

    async fn metadata(&self) -> Result<Arc<ProviderMetadataWithLogout>, SignInError> {
        if let Some(doc) = self.cached().await {
            return Ok(doc);
        }
        // One fetch at a time. Whoever waited checks again, since the one
        // before may have just fetched it.
        let _guard = self.fetching.lock().await;
        if let Some(doc) = self.cached().await {
            return Ok(doc);
        }
        if let Some(t) = self.metadata.read().await.failed_at
            && t.elapsed() < self.retry_after
        {
            return Err(SignInError::Unreachable(
                "discovery failed a moment ago".into(),
            ));
        }
        let issuer = IssuerUrl::new(self.issuer.clone())
            .map_err(|e| SignInError::Rejected(e.to_string()))?;
        match ProviderMetadataWithLogout::discover_async(issuer, &self.http).await {
            Ok(doc) => {
                let doc = Arc::new(doc);
                *self.metadata.write().await = MetadataCache {
                    good: Some((Instant::now(), doc.clone())),
                    failed_at: None,
                    stale: false,
                };
                Ok(doc)
            }
            Err(e) => {
                let detail = error_chain(&e);
                let mut c = self.metadata.write().await;
                c.failed_at = Some(Instant::now());
                match &c.good {
                    Some((_, doc)) => {
                        tracing::warn!(error = %detail, "could not refresh Entra discovery; using the last good copy");
                        Ok(doc.clone())
                    }
                    None => {
                        tracing::warn!(error = %detail, "could not fetch Entra discovery");
                        Err(SignInError::Unreachable(detail))
                    }
                }
            }
        }
    }

    /// Mark cached metadata as out of date so the next call fetches fresh
    /// signing keys. The last good copy is kept as a fallback in case that
    /// fetch fails, and any back-off is cleared so the fetch happens now.
    pub async fn forget_metadata(&self) {
        let mut c = self.metadata.write().await;
        c.stale = true;
        c.failed_at = None;
    }

    fn client(&self, metadata: &ProviderMetadataWithLogout) -> Result<EntraClient, SignInError> {
        let redirect = RedirectUrl::new(self.redirect_url.clone())
            .map_err(|e| SignInError::Rejected(e.to_string()))?;
        Ok(EntraClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.expose().to_owned())),
        )
        .set_redirect_uri(redirect)
        // Entra ID expects the client secret in the form body.
        .set_auth_type(AuthType::RequestBody))
    }

    /// Build the Entra sign-in URL and the state to keep until the callback.
    pub async fn begin(
        &self,
        return_to: String,
        unsaved: bool,
        claims: Option<String>,
    ) -> Result<(String, PendingLogin), SignInError> {
        let metadata = self.metadata().await?;
        let client = self.client(&metadata)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("offline_access".into()))
            .add_scope(Scope::new(self.api_scope.clone()))
            .set_pkce_challenge(challenge);
        // Entra wants more than a plain sign-in (MFA, a compliant device)
        // for a resource Keyring calls. Pass its challenge so it asks.
        if let Some(c) = claims {
            request = request.add_extra_param("claims", c);
        }
        let (url, state, nonce) = request.url();
        Ok((
            url.to_string(),
            PendingLogin {
                state: state.secret().clone(),
                nonce: nonce.secret().clone(),
                pkce_verifier: verifier.secret().clone(),
                return_to,
                unsaved,
            },
        ))
    }

    /// Swap the authorisation code for tokens and check the ID token.
    pub async fn finish(
        &self,
        pending: PendingLogin,
        code: String,
    ) -> Result<(User, UserTokens), SignInError> {
        let metadata = self.metadata().await?;
        let client = self.client(&metadata)?;
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| SignInError::Rejected(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|e| match e {
                openidconnect::RequestTokenError::ServerResponse(r) => SignInError::Provider {
                    code: safe_code(r.error().as_ref()),
                    codes: aadsts_code(r.error_description().map(String::as_str))
                        .into_iter()
                        .collect(),
                },
                other => SignInError::Unreachable(error_chain(&other)),
            })?;

        let id_token = token
            .id_token()
            .ok_or_else(|| SignInError::Rejected("no ID token in response".into()))?;
        let nonce = Nonce::new(pending.nonce);
        let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
            Ok(c) => c.clone(),
            Err(e) if is_key_miss(&e) => {
                // The signing keys may have rolled over since they were
                // cached. Fetch them again and check this token once more,
                // so this sign-in works and not just the next one.
                tracing::info!("ID token signed with an unknown key; refetching signing keys");
                self.forget_metadata().await;
                let fresh = self.client(&*self.metadata().await?)?;
                id_token
                    .claims(&fresh.id_token_verifier(), &nonce)
                    .map_err(|e| SignInError::Rejected(e.to_string()))?
                    .clone()
            }
            Err(e) => return Err(SignInError::Rejected(e.to_string())),
        };

        let username = claims.preferred_username().map(|u| u.as_str().to_owned());
        let name = claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str().to_owned())
            .or_else(|| username.clone())
            .unwrap_or_else(|| "Signed in".to_owned());
        let extra = claims.additional_claims();
        let user = User {
            name,
            username,
            subject: UserId {
                sub: claims.subject().as_str().to_owned(),
                oid: extra.oid.as_deref().and_then(guid_claim),
                tid: extra.tid.as_deref().and_then(guid_claim),
            },
        };
        let tokens = UserTokens {
            access_token: Secret::new(token.access_token().secret().clone()),
            expires_at: expiry_from(token.expires_in(), SystemTime::now()),
            refresh_token: token
                .refresh_token()
                .map(|t| Secret::new(t.secret().clone())),
        };
        Ok((user, tokens))
    }

    /// Entra's sign-out URL, which sends the browser back to us afterwards.
    pub async fn end_session_url(&self) -> Option<String> {
        let metadata = self.metadata().await.ok()?;
        let mut url = metadata
            .additional_metadata()
            .end_session_endpoint
            .as_ref()?
            .url()
            .clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("post_logout_redirect_uri", &self.signed_out_url);
        Some(url.to_string())
    }
}

/// Entra's error number from an `error_description` such as
/// `AADSTS54005: OAuth2 Authorization code was already redeemed...`. Only
/// the number is kept; the rest of the text is never stored or logged.
fn aadsts_code(description: Option<&str>) -> Option<u64> {
    let digits: String = description?
        .strip_prefix("AADSTS")?
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    digits.parse().ok()
}

/// True when an ID token failed because no cached key could check it.
fn is_key_miss(e: &ClaimsVerificationError) -> bool {
    matches!(
        e,
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey | SignatureVerificationError::CryptoError(_)
        )
    )
}

/// An `oid` or `tid` claim, lower-cased, if it is a GUID. Anything else is
/// dropped, so a strange value can't reach the logs.
fn guid_claim(v: &str) -> Option<String> {
    crate::config::is_guid(v).then(|| v.to_ascii_lowercase())
}

impl From<HttpError> for SignInError {
    fn from(e: HttpError) -> Self {
        Self::Unreachable(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aadsts_code_reads_only_the_number() {
        assert_eq!(
            aadsts_code(Some(
                "AADSTS54005: OAuth2 Authorization code was already redeemed."
            )),
            Some(54005)
        );
        assert_eq!(aadsts_code(Some("AADSTS70008")), Some(70008));
        assert_eq!(aadsts_code(Some("something else")), None);
        assert_eq!(aadsts_code(Some("AADSTS: no number")), None);
        assert_eq!(aadsts_code(None), None);
    }

    #[test]
    fn debug_hides_login_state() {
        let p = PendingLogin {
            state: "state-value".into(),
            nonce: "nonce-value".into(),
            pkce_verifier: "verifier-value".into(),
            return_to: "/secrets".into(),
            unsaved: false,
        };
        let out = format!("{p:?}");
        for hidden in ["state-value", "nonce-value", "verifier-value"] {
            assert!(!out.contains(hidden), "{out}");
        }
        assert!(out.contains("/secrets"));
    }

    #[test]
    fn only_guid_claims_are_kept() {
        assert_eq!(
            guid_claim("AAAAAAAA-0000-0000-0000-000000000001").as_deref(),
            Some("aaaaaaaa-0000-0000-0000-000000000001")
        );
        assert_eq!(guid_claim("x\nFORGED"), None);
    }

    #[test]
    fn key_misses_are_told_apart_from_other_failures() {
        assert!(is_key_miss(
            &ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey
            )
        ));
        assert!(!is_key_miss(&ClaimsVerificationError::InvalidNonce(
            "x".into()
        )));
        assert!(!is_key_miss(&ClaimsVerificationError::InvalidAudience(
            "x".into()
        )));
    }
}
