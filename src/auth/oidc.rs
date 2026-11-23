//! Entra ID sign-in: OpenID Connect authorisation code flow with PKCE.
//!
//! Discovery, the authorise URL, the code exchange and the ID token checks
//! are Keyring's own code on `reqwest` and `ring`. The token checks
//! (signature with RS256 only against the tenant's published keys, issuer,
//! audience, expiry, nonce) are in [`crate::auth::jwt`].

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::auth::assertion::Credential;
use crate::auth::crypto::random_token;
use crate::auth::entra::{self, EntraAdvice};
use crate::auth::jwt::{self, IdTokenCheck, Jwk, Jwks, JwtError};
use crate::auth::session::{User, UserId, UserTokens};
use crate::auth::step_up::{SignInFacts, auth_context_id};
use crate::azure::token::expiry_from;
use crate::config::Config;
use crate::http::HttpError;
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
    /// Started to meet `KEYRING_STEP_UP_*` before a sensitive action. The
    /// callback refuses a reply that still doesn't meet them, instead of
    /// sending the person back to try again (which would loop).
    #[serde(default)]
    pub step_up: bool,
    /// Started to ask Entra for MFA after an on-behalf-of exchange was
    /// refused for want of it. The session this sign-in creates remembers
    /// that, so a second refusal shows a page instead of looping.
    #[serde(default)]
    pub mfa: bool,
}

/// Written by hand so state, nonce and the PKCE verifier never print.
impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("return_to", &self.return_to)
            .field("unsaved", &self.unsaved)
            .field("step_up", &self.step_up)
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
    /// Authentication context IDs the sign-in met, when Keyring asked for
    /// one with the `claims` parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acrs: Option<Vec<String>>,
}

/// What Keyring keeps from the tenant's discovery document, with the
/// signing keys from its `jwks_uri`.
struct Metadata {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    end_session_endpoint: Option<Url>,
    jwks: Jwks,
}

/// The fields of the discovery document Keyring reads.
#[derive(serde::Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

/// A successful token response. No `Debug`, so tokens never print.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// An OAuth error response from the token endpoint.
#[derive(serde::Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Longest discovery document or key set read, in bytes.
const MAX_METADATA_BYTES: usize = 1024 * 1024;

/// A response body, read a chunk at a time and given up on as soon as it
/// passes `max` bytes, so a misbehaving endpoint can't make Keyring hold a
/// huge body in memory. `None` when it was too large.
async fn read_capped(
    mut res: reqwest::Response,
    max: usize,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    if res.content_length().is_some_and(|n| n > max as u64) {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if body.len() + chunk.len() > max {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// Why discovery failed. Holds no response bodies.
#[derive(Debug)]
struct DiscoveryError(String);

impl From<HttpError> for DiscoveryError {
    fn from(e: HttpError) -> Self {
        Self(e.to_string())
    }
}

impl From<reqwest::Error> for DiscoveryError {
    fn from(e: reqwest::Error) -> Self {
        HttpError::from(e).into()
    }
}

/// The discovery cache: the last good document, and when a fetch last
/// failed so a refetch isn't tried on every request.
#[derive(Default)]
struct MetadataCache {
    good: Option<(Instant, Arc<Metadata>)>,
    failed_at: Option<Instant>,
    /// Set when the signing keys are known to be out of date.
    stale: bool,
}

pub struct Oidc {
    issuer: String,
    client_id: String,
    credential: Credential,
    redirect_url: String,
    signed_out_url: String,
    api_scope: String,
    http: reqwest::Client,
    metadata: RwLock<MetadataCache>,
    /// Held while fetching, so only one fetch goes out at a time.
    fetching: Mutex<()>,
    ttl: Duration,
    retry_after: Duration,
}

impl Oidc {
    pub fn new(config: &Config, http: reqwest::Client, credential: Credential) -> Self {
        Self {
            issuer: config.issuer(),
            client_id: config.client_id.clone(),
            credential,
            redirect_url: config.redirect_url(),
            signed_out_url: config.signed_out_url(),
            api_scope: config.api_scope.clone(),
            http,
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

    /// The cached document if it's fresh enough, or if a fetch failed a
    /// moment ago (then the old one is better than none).
    async fn cached(&self) -> Option<Arc<Metadata>> {
        let c = self.metadata.read().await;
        let (fetched, doc) = c.good.as_ref()?;
        let backing_off = c.failed_at.is_some_and(|t| t.elapsed() < self.retry_after);
        ((fetched.elapsed() < self.ttl && !c.stale) || backing_off).then(|| doc.clone())
    }

    async fn metadata(&self) -> Result<Arc<Metadata>, SignInError> {
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
        match self.discover().await {
            Ok(doc) => {
                let doc = Arc::new(doc);
                *self.metadata.write().await = MetadataCache {
                    good: Some((Instant::now(), doc.clone())),
                    failed_at: None,
                    stale: false,
                };
                Ok(doc)
            }
            Err(DiscoveryError(detail)) => {
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

    /// GET a JSON document: discovery or the key set. Only the status, not
    /// the body, goes in an error.
    async fn get_json(&self, url: &str, what: &str) -> Result<Vec<u8>, DiscoveryError> {
        let res = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        let status = res.status();
        if status != reqwest::StatusCode::OK {
            return Err(DiscoveryError(format!("{what} returned HTTP {status}")));
        }
        read_capped(res, MAX_METADATA_BYTES)
            .await?
            .ok_or_else(|| DiscoveryError(format!("{what} is too large")))
    }

    /// Fetch the discovery document and the keys it points at. The
    /// document's `issuer` must be exactly the configured one.
    async fn discover(&self) -> Result<Metadata, DiscoveryError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let body = self.get_json(&url, "discovery").await?;
        let doc: Discovery = serde_json::from_slice(&body)
            .map_err(|_| DiscoveryError("discovery document unreadable".into()))?;
        if doc.issuer != self.issuer {
            return Err(DiscoveryError(
                "discovery document is for another issuer".into(),
            ));
        }
        let parse = |raw: &str, what: &str| {
            Url::parse(raw).map_err(|_| DiscoveryError(format!("discovery {what} unreadable")))
        };
        let authorization_endpoint = parse(&doc.authorization_endpoint, "authorization_endpoint")?;
        let token_endpoint = parse(&doc.token_endpoint, "token_endpoint")?;
        let jwks_uri = parse(&doc.jwks_uri, "jwks_uri")?;
        let end_session_endpoint = doc
            .end_session_endpoint
            .as_deref()
            .map(|u| parse(u, "end_session_endpoint"))
            .transpose()?;
        let body = self.get_json(jwks_uri.as_str(), "signing keys").await?;
        let jwks = Jwks::from_json(&body)
            .ok_or_else(|| DiscoveryError("signing keys unreadable".into()))?;
        Ok(Metadata {
            issuer: doc.issuer,
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
            jwks,
        })
    }

    /// Mark cached metadata as out of date so the next call fetches fresh
    /// signing keys. The last good copy is kept as a fallback in case that
    /// fetch fails, and any back-off is cleared so the fetch happens now.
    pub async fn forget_metadata(&self) {
        let mut c = self.metadata.write().await;
        c.stale = true;
        c.failed_at = None;
    }

    /// Build the Entra sign-in URL and the state to keep until the callback.
    pub async fn begin(
        &self,
        return_to: String,
        unsaved: bool,
        claims: Option<String>,
    ) -> Result<(String, PendingLogin), SignInError> {
        self.begin_with(return_to, unsaved, claims, None, false)
            .await
    }

    /// [`Self::begin`], for a step-up when `step_up` is set. With a maximum
    /// age in it, Entra is asked for a fresh sign-in (`prompt=login` and
    /// `max_age`). With `mfa` set, Entra is asked for a fresh sign-in
    /// (`prompt=login`) so it can't reuse a password-only session; the
    /// caller passes the MFA claims request in `claims`.
    pub async fn begin_with(
        &self,
        return_to: String,
        unsaved: bool,
        claims: Option<String>,
        step_up: Option<StepUpAsk>,
        mfa: bool,
    ) -> Result<(String, PendingLogin), SignInError> {
        let metadata = self.metadata().await?;
        let state = random_token(32);
        let nonce = random_token(32);
        let verifier = random_token(32);
        let challenge = pkce_challenge(&verifier);
        let scope = format!("openid profile offline_access {}", self.api_scope);
        let mut url = metadata.authorization_endpoint.clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("redirect_uri", &self.redirect_url)
                .append_pair("scope", &scope)
                .append_pair("nonce", &nonce);
            // Entra wants more than a plain sign-in (MFA, a compliant
            // device) for a resource Keyring calls. Pass its challenge so
            // it asks.
            if let Some(c) = claims.as_deref() {
                q.append_pair("claims", c);
            }
            let max_age = step_up.and_then(|s| s.max_age);
            if let Some(max_age) = max_age {
                q.append_pair("prompt", "login")
                    .append_pair("max_age", &max_age.as_secs().to_string());
            } else if mfa {
                q.append_pair("prompt", "login");
            }
        }
        Ok((
            url.to_string(),
            PendingLogin {
                state,
                nonce,
                pkce_verifier: verifier,
                return_to,
                unsaved,
                step_up: step_up.is_some(),
                mfa,
            },
        ))
    }

    /// Swap the authorisation code for tokens and check the ID token.
    pub async fn finish(
        &self,
        pending: PendingLogin,
        code: String,
    ) -> Result<(User, UserTokens, SignInFacts), SignInError> {
        let metadata = self.metadata().await?;
        let token = self
            .exchange_code(&metadata, &code, &pending.pkce_verifier)
            .await?;

        let id_token = token
            .id_token
            .as_deref()
            .ok_or_else(|| SignInError::Rejected("no ID token in response".into()))?;
        let verify = |m: &Metadata| {
            jwt::verify_id_token(
                id_token,
                &m.jwks,
                &IdTokenCheck {
                    issuer: &m.issuer,
                    client_id: &self.client_id,
                    nonce: &pending.nonce,
                    now: jwt::now_unix(),
                },
            )
        };
        let claims = match verify(&metadata) {
            Ok(c) => c,
            Err(e) if e.is_key_miss() => {
                // The signing keys may have rolled over since they were
                // cached. Fetch them again and check this token once more,
                // so this sign-in works and not just the next one.
                tracing::info!("ID token signed with an unknown key; refetching signing keys");
                self.forget_metadata().await;
                verify(&*self.metadata().await?).map_err(rejected)?
            }
            Err(e) => return Err(rejected(e)),
        };

        let str_claim = |name: &str| claims.get(name).and_then(Value::as_str);
        // Checked by `verify_id_token`, so always there.
        let sub = str_claim("sub").unwrap_or_default().to_owned();
        let username = str_claim("preferred_username").map(str::to_owned);
        let name = str_claim("name")
            .map(str::to_owned)
            .or_else(|| username.clone())
            .unwrap_or_else(|| "Signed in".to_owned());
        let extra: EntraClaims = serde_json::from_value(Value::Object(claims.clone()))
            .map_err(|_| SignInError::Rejected("ID token claims unreadable".into()))?;
        let user = User {
            name,
            username,
            subject: UserId {
                sub,
                oid: extra.oid.as_deref().and_then(guid_claim),
                tid: extra.tid.as_deref().and_then(guid_claim),
            },
        };
        let facts = SignInFacts {
            // Only well-formed context IDs are kept, so nothing odd is stored.
            acrs: extra
                .acrs
                .iter()
                .flatten()
                .filter_map(|a| auth_context_id(a))
                .collect(),
            auth_time: claims.get("auth_time").and_then(jwt::timestamp),
        };
        let tokens = UserTokens {
            access_token: Secret::new(token.access_token),
            expires_at: expiry_from(token.expires_in.map(Duration::from_secs), SystemTime::now()),
            refresh_token: token.refresh_token.map(Secret::new),
        };
        Ok((user, tokens, facts))
    }

    /// POST the code to the token endpoint. The client ID and credential
    /// (the client secret, or in managed identity mode the assertion in
    /// its place) go in the form body, as Entra ID expects.
    async fn exchange_code(
        &self,
        metadata: &Metadata,
        code: &str,
        verifier: &str,
    ) -> Result<TokenResponse, SignInError> {
        let credential = self
            .credential
            .form_fields()
            .await
            .map_err(|e| SignInError::Unreachable(e.to_string()))?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_url.as_str()),
            ("client_id", self.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        form.extend(credential.iter().map(|(k, v)| (*k, v.expose())));
        let unreachable =
            |e: reqwest::Error| SignInError::Unreachable(HttpError::from(e).to_string());
        let res = self
            .http
            .post(metadata.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(unreachable)?;
        let status = res.status();
        let body = read_capped(res, MAX_METADATA_BYTES)
            .await
            .map_err(unreachable)?
            .ok_or_else(|| SignInError::Unreachable("token response is too large".into()))?;
        if status.is_success() {
            let token: TokenResponse = serde_json::from_slice(&body)
                .map_err(|_| SignInError::Unreachable("unreadable token response".into()))?;
            if !token.token_type.eq_ignore_ascii_case("bearer") {
                return Err(SignInError::Unreachable(
                    "token response is not a bearer token".into(),
                ));
            }
            return Ok(token);
        }
        // Only the error code, and the AADSTS number from the description,
        // are kept. Never the rest of the body.
        match serde_json::from_slice::<TokenErrorResponse>(&body) {
            Ok(r) => Err(SignInError::Provider {
                code: safe_code(&r.error),
                codes: aadsts_code(r.error_description.as_deref())
                    .into_iter()
                    .collect(),
            }),
            Err(_) => Err(SignInError::Unreachable(format!(
                "token endpoint returned HTTP {status}"
            ))),
        }
    }

    /// The tenant's published signing key with this `kid`, from the same
    /// cached key set sign-in uses. With `refetch`, a key that isn't in
    /// the cache marks it out of date and fetches the keys once more, as
    /// sign-in does on a key rollover. `None` when there is no such key or
    /// the keys can't be fetched.
    pub async fn signing_key(&self, kid: &str, refetch: bool) -> Option<Jwk> {
        let doc = self.metadata().await.ok()?;
        if let Some(k) = doc.jwks.find(kid) {
            return Some(k.clone());
        }
        if !refetch {
            return None;
        }
        tracing::info!("webhook token signed with an unknown key; refetching signing keys");
        self.forget_metadata().await;
        let fresh = self.metadata().await.ok()?;
        fresh.jwks.find(kid).cloned()
    }

    /// Entra's sign-out URL, which sends the browser back to us afterwards.
    pub async fn end_session_url(&self) -> Option<String> {
        let metadata = self.metadata().await.ok()?;
        let mut url = metadata.end_session_endpoint.clone()?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("post_logout_redirect_uri", &self.signed_out_url);
        Some(url.to_string())
    }
}

/// The PKCE S256 challenge for a verifier: base64url of its SHA-256.
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

fn rejected(e: JwtError) -> SignInError {
    SignInError::Rejected(e.to_string())
}

/// What a step-up sign-in asks Entra for beyond the `claims` parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct StepUpAsk {
    /// Ask for a fresh sign-in, no older than this.
    pub max_age: Option<Duration>,
}

/// Entra's error number from an `error_description` such as
/// `AADSTS54005: OAuth2 Authorization code was already redeemed...`. Only
/// the number is kept; the rest of the text is never stored or logged.
pub fn aadsts_code(description: Option<&str>) -> Option<u64> {
    let digits: String = description?
        .strip_prefix("AADSTS")?
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    digits.parse().ok()
}

/// An `oid` or `tid` claim, lower-cased, if it is a GUID. Anything else is
/// dropped, so a strange value can't reach the logs.
fn guid_claim(v: &str) -> Option<String> {
    crate::config::is_guid(v).then(|| v.to_ascii_lowercase())
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
            step_up: false,
            mfa: false,
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
    fn pkce_challenge_is_s256() {
        // base64url, no padding, of the verifier's SHA-256, as worked out
        // separately with `openssl dgst -sha256 -binary | base64`.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mJ0kXlEyJc0eEx9xBbY3XWaFAsuSZ8"),
            "JA-ZKN9n2MQI7JGwtpFo5kyxEPO_a1SUlxjQqBYNXEQ"
        );
    }
}
