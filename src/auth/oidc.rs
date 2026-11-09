//! Entra ID sign-in: OpenID Connect authorisation code flow with PKCE.
//!
//! Token and ID token checks (issuer, audience, expiry, nonce, signature
//! against the tenant's published keys) are done by the `openidconnect`
//! crate, not by hand.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use openidconnect::core::{CoreAuthenticationFlow, CoreClient};
use openidconnect::{
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, ProviderMetadataWithLogout,
    RedirectUrl, Scope, TokenResponse,
};
use tokio::sync::RwLock;

use crate::auth::session::{User, UserTokens};
use crate::config::Config;
use crate::http::{HttpError, OidcHttp};
use crate::secret::Secret;

/// Re-fetch the tenant's discovery document and signing keys this often.
const METADATA_TTL: Duration = Duration::from_secs(60 * 60);

/// What we remember between sending someone to Entra and them coming back.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
}

/// Why sign-in failed. Each variant maps to a plain message for the user.
#[derive(Debug)]
pub enum SignInError {
    /// Couldn't reach Entra ID or read its answer.
    Unreachable(String),
    /// Entra sent back an error, for example the user cancelled or consent is needed.
    Provider { code: String },
    /// The response didn't pass our checks (state, nonce, signature and so on).
    Invalid(String),
}

impl std::fmt::Display for SignInError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "identity provider unreachable: {m}"),
            Self::Provider { code } => write!(f, "identity provider returned {code}"),
            Self::Invalid(m) => write!(f, "sign-in response rejected: {m}"),
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

struct Cached {
    fetched: Instant,
    metadata: Arc<ProviderMetadataWithLogout>,
}

pub struct Oidc {
    issuer: String,
    client_id: String,
    client_secret: Secret,
    redirect_url: String,
    signed_out_url: String,
    api_scope: String,
    http: OidcHttp,
    metadata: RwLock<Option<Cached>>,
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
            metadata: RwLock::new(None),
        }
    }

    /// The outbound HTTP client, shared with the token exchange.
    pub fn http(&self) -> &reqwest::Client {
        &self.http.0
    }

    async fn metadata(&self) -> Result<Arc<ProviderMetadataWithLogout>, SignInError> {
        if let Some(c) = self.metadata.read().await.as_ref()
            && c.fetched.elapsed() < METADATA_TTL
        {
            return Ok(c.metadata.clone());
        }
        let issuer =
            IssuerUrl::new(self.issuer.clone()).map_err(|e| SignInError::Invalid(e.to_string()))?;
        let metadata = ProviderMetadataWithLogout::discover_async(issuer, &self.http)
            .await
            .map_err(|e| SignInError::Unreachable(error_chain(&e)))?;
        let metadata = Arc::new(metadata);
        *self.metadata.write().await = Some(Cached {
            fetched: Instant::now(),
            metadata: metadata.clone(),
        });
        Ok(metadata)
    }

    /// Forget cached metadata so the next sign-in fetches fresh signing keys.
    async fn forget_metadata(&self) {
        *self.metadata.write().await = None;
    }

    fn client(
        &self,
        metadata: &ProviderMetadataWithLogout,
    ) -> Result<
        CoreClient<
            openidconnect::EndpointSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointMaybeSet,
            openidconnect::EndpointMaybeSet,
        >,
        SignInError,
    > {
        let redirect = RedirectUrl::new(self.redirect_url.clone())
            .map_err(|e| SignInError::Invalid(e.to_string()))?;
        Ok(CoreClient::from_provider_metadata(
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
            .map_err(|e| SignInError::Invalid(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|e| match e {
                openidconnect::RequestTokenError::ServerResponse(r) => SignInError::Provider {
                    code: safe_code(r.error().as_ref()),
                },
                other => SignInError::Unreachable(error_chain(&other)),
            })?;

        let id_token = token
            .id_token()
            .ok_or_else(|| SignInError::Invalid("no ID token in response".into()))?;
        let nonce = Nonce::new(pending.nonce);
        let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
            Ok(c) => c,
            Err(e) => {
                // Keys may have rolled over. Fetch them again next time.
                self.forget_metadata().await;
                return Err(SignInError::Invalid(e.to_string()));
            }
        };

        let username = claims.preferred_username().map(|u| u.as_str().to_owned());
        let name = claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str().to_owned())
            .or_else(|| username.clone())
            .unwrap_or_else(|| "Signed in".to_owned());
        let user = User {
            name,
            username,
            subject: claims.subject().as_str().to_owned(),
        };
        let expires_in = token.expires_in().unwrap_or(Duration::from_secs(300));
        let tokens = UserTokens {
            access_token: Secret::new(token.access_token().secret().clone()),
            expires_at: SystemTime::now() + expires_in,
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

/// Flatten an error and its sources into one line for logs. Errors from the
/// HTTP layer never include bodies, so this holds no tokens.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(e) = src {
        out.push_str(": ");
        out.push_str(&e.to_string());
        src = e.source();
    }
    out
}

impl From<HttpError> for SignInError {
    fn from(e: HttpError) -> Self {
        Self::Unreachable(e.to_string())
    }
}
