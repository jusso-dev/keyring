//! Checks the Entra bearer token Event Grid sends with each delivery to
//! `/hooks/eventgrid`.
//!
//! Event Grid, with Microsoft Entra authentication on the subscription,
//! gets an app-only token for Keyring's app registration (the
//! subscription's `azureActiveDirectoryApplicationIdOrUri`) as its own
//! first-party application and sends it as `Authorization: Bearer`. See
//! Microsoft's "Secure WebHook delivery with Microsoft Entra ID". A token
//! for the right audience isn't enough on its own, since any app in the
//! tenant may be able to get one, so every check below must pass:
//!
//! - **Signature** with RS256 only (never `none`, never HS*), against the
//!   tenant's published signing keys from the same cache sign-in uses. A
//!   `kid` not in the cache refetches the keys once, as sign-in does on a
//!   key rollover, at most once every [`REFETCH_EVERY`], and only for a
//!   token whose claims would otherwise pass.
//! - **`iss`**: the tenant's v1 issuer (`https://sts.windows.net/<tenant>/`)
//!   or its v2 issuer (`<authority>/<tenant>/v2.0`). Which one Event Grid's
//!   token has depends on the app registration's
//!   `requestedAccessTokenVersion`.
//! - **`aud`**: exactly the configured audience
//!   (`KEYRING_EVENTGRID_AUDIENCE`, or `api://<client ID>` when unset).
//! - **`tid`**: the configured tenant.
//! - **`exp`** and **`nbf`** with [`LEEWAY_SECS`] of leeway.
//! - **Caller**: `appid` (v1) or `azp` (v2), whichever are present, must
//!   be [`EVENT_GRID_APP_ID`], Event Grid's first-party application.
//! - **App role**: `roles` must hold [`EVENT_GRID_APP_ROLE`], the role the
//!   deployer assigns to the Event Grid service principal.
//! - **App-only**: no `scp` claim (that would be a person's delegated
//!   token), and `idtyp`, when present, is `app`.
//!
//! Failures carry only a fixed [`Reject`] code. The token and its claims'
//! values are never logged or kept.

use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::JsonWebKey;
use openidconnect::core::CoreJwsSigningAlgorithm;
use serde_json::Value;

use crate::auth::oidc::Oidc;

/// The application (client) ID of the `Microsoft.EventGrid` service
/// principal in Azure's public cloud. The same in every tenant. It is the
/// `appid` (v1) or `azp` (v2) of the token Event Grid sends.
pub const EVENT_GRID_APP_ID: &str = "4962773b-9cdb-44cf-a8bf-237846a00ab7";

/// The app role on Keyring's app registration that the deployer assigns to
/// the Event Grid service principal. Microsoft's scripts name it this, and
/// docs/alerts.md has the commands. A token without it is refused.
pub const EVENT_GRID_APP_ROLE: &str = "AzureEventGridSecureWebhookSubscriber";

/// Leeway on `exp` and `nbf`, in seconds.
pub const LEEWAY_SECS: i64 = 60;

/// Longest bearer token read, in bytes.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Fewest seconds between key refetches caused by an unknown `kid`.
pub const REFETCH_EVERY: Duration = Duration::from_secs(300);

/// Why a token was refused. Only this code is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No `Authorization: Bearer` header, or one that isn't readable.
    Missing,
    /// Not three base64url parts of JSON, or too long.
    Malformed,
    /// `alg` isn't RS256, or the header asks for something Keyring doesn't
    /// do (`crit`, a `typ` other than JWT, no `kid`).
    Algorithm,
    /// No published key with this `kid`, or the signature doesn't match.
    Signature,
    Issuer,
    Audience,
    Tenant,
    /// Past `exp`, before `nbf`, or no `exp`.
    Expired,
    /// `appid` or `azp` isn't Event Grid's application.
    Caller,
    /// `roles` lacks [`EVENT_GRID_APP_ROLE`].
    Role,
    /// A delegated (person's) token, not an app-only one.
    NotAppOnly,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "token_missing",
            Self::Malformed => "token_malformed",
            Self::Algorithm => "token_algorithm",
            Self::Signature => "token_signature",
            Self::Issuer => "token_issuer",
            Self::Audience => "token_audience",
            Self::Tenant => "token_tenant",
            Self::Expired => "token_expired",
            Self::Caller => "token_caller",
            Self::Role => "token_role",
            Self::NotAppOnly => "token_not_app_only",
        }
    }
}

/// What a token must say.
#[derive(Debug, Clone)]
pub struct Expect {
    pub tenant: String,
    /// `https://sts.windows.net/<tenant>/`.
    pub issuer_v1: String,
    /// `<authority>/<tenant>/v2.0`.
    pub issuer_v2: String,
    pub audience: String,
}

/// The token from an `Authorization` header value: `Bearer <token>`, the
/// scheme in any case.
pub fn bearer(header: Option<&str>) -> Result<&str, Reject> {
    let h = header.ok_or(Reject::Missing)?;
    let (scheme, token) = h.split_once(' ').ok_or(Reject::Missing)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Reject::Missing);
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(Reject::Missing);
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Reject::Malformed);
    }
    Ok(token)
}

/// A token split and decoded, nothing checked yet.
struct Parts<'a> {
    kid: String,
    signing_input: &'a str,
    signature: Vec<u8>,
    claims: serde_json::Map<String, Value>,
}

fn parts(token: &str) -> Result<Parts<'_>, Reject> {
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(Reject::Malformed);
    };
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| Reject::Malformed);
    let header: serde_json::Map<String, Value> =
        serde_json::from_slice(&decode(h)?).map_err(|_| Reject::Malformed)?;
    let claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&decode(p)?).map_err(|_| Reject::Malformed)?;
    let signature = decode(s)?;
    // RS256 only. `none`, HS*, ES*, PS* and anything else are refused
    // before a key is looked at.
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(Reject::Algorithm);
    }
    if header.contains_key("crit") {
        return Err(Reject::Algorithm);
    }
    if let Some(typ) = header.get("typ")
        && !typ.as_str().is_some_and(|t| t.eq_ignore_ascii_case("JWT"))
    {
        return Err(Reject::Algorithm);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| (1..=128).contains(&k.len()))
        .ok_or(Reject::Algorithm)?
        .to_owned();
    let signing_input = &token[..h.len() + 1 + p.len()];
    Ok(Parts {
        kid,
        signing_input,
        signature,
        claims,
    })
}

fn str_claim<'a>(c: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    c.get(name).and_then(Value::as_str)
}

fn num_claim(c: &serde_json::Map<String, Value>, name: &str) -> Option<i64> {
    c.get(name).and_then(Value::as_i64)
}

/// Every check that doesn't need the key.
fn check_claims(
    c: &serde_json::Map<String, Value>,
    expect: &Expect,
    now: i64,
) -> Result<(), Reject> {
    let iss = str_claim(c, "iss").ok_or(Reject::Issuer)?;
    if iss != expect.issuer_v1 && iss != expect.issuer_v2 {
        return Err(Reject::Issuer);
    }
    // One audience, as Entra writes it: a string.
    if str_claim(c, "aud") != Some(expect.audience.as_str()) {
        return Err(Reject::Audience);
    }
    if !str_claim(c, "tid").is_some_and(|t| t.eq_ignore_ascii_case(&expect.tenant)) {
        return Err(Reject::Tenant);
    }
    let exp = num_claim(c, "exp").ok_or(Reject::Expired)?;
    if now > exp.saturating_add(LEEWAY_SECS) {
        return Err(Reject::Expired);
    }
    if let Some(v) = c.get("nbf") {
        let nbf = v.as_i64().ok_or(Reject::Expired)?;
        if now < nbf.saturating_sub(LEEWAY_SECS) {
            return Err(Reject::Expired);
        }
    }
    // The caller: whichever of `appid` and `azp` are there, and at least
    // one, must be Event Grid.
    let appid = str_claim(c, "appid");
    let azp = str_claim(c, "azp");
    let is_eg = |v: &str| v.eq_ignore_ascii_case(EVENT_GRID_APP_ID);
    let caller_ok = match (appid, azp) {
        (None, None) => false,
        (a, z) => a.is_none_or(is_eg) && z.is_none_or(is_eg),
    };
    if !caller_ok
        || c.contains_key("appid") && appid.is_none()
        || c.contains_key("azp") && azp.is_none()
    {
        return Err(Reject::Caller);
    }
    if c.contains_key("scp") {
        return Err(Reject::NotAppOnly);
    }
    if let Some(idtyp) = c.get("idtyp")
        && idtyp.as_str() != Some("app")
    {
        return Err(Reject::NotAppOnly);
    }
    let has_role = c
        .get("roles")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().any(|v| v.as_str() == Some(EVENT_GRID_APP_ROLE)));
    if !has_role {
        return Err(Reject::Role);
    }
    Ok(())
}

/// Unix seconds now.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Check a bearer token end to end. `may_refetch` is asked once, only when
/// the `kid` isn't in the cache and every claim already passed, and says
/// whether a refetch of the signing keys is allowed now.
pub async fn verify(
    token: &str,
    expect: &Expect,
    oidc: &Oidc,
    now: i64,
    may_refetch: impl FnOnce() -> bool,
) -> Result<(), Reject> {
    let p = parts(token)?;
    check_claims(&p.claims, expect, now)?;
    let key = match oidc.signing_key(&p.kid, false).await {
        Some(k) => k,
        None if may_refetch() => oidc
            .signing_key(&p.kid, true)
            .await
            .ok_or(Reject::Signature)?,
        None => return Err(Reject::Signature),
    };
    key.verify_signature(
        &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        p.signing_input.as_bytes(),
        &p.signature,
    )
    .map_err(|_| Reject::Signature)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const T: &str = "00000000-0000-0000-0000-000000000000";

    fn expect() -> Expect {
        Expect {
            tenant: T.into(),
            issuer_v1: format!("https://sts.windows.net/{T}/"),
            issuer_v2: format!("https://login.microsoftonline.com/{T}/v2.0"),
            audience: "api://11111111-1111-1111-1111-111111111111".into(),
        }
    }

    fn good() -> serde_json::Map<String, Value> {
        json!({
            "iss": format!("https://sts.windows.net/{T}/"),
            "aud": "api://11111111-1111-1111-1111-111111111111",
            "tid": T,
            "exp": 2_000,
            "nbf": 1_000,
            "appid": EVENT_GRID_APP_ID,
            "roles": [EVENT_GRID_APP_ROLE],
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn with(f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Result<(), Reject> {
        let mut c = good();
        f(&mut c);
        check_claims(&c, &expect(), 1_500)
    }

    type Edit = Box<dyn FnOnce(&mut serde_json::Map<String, Value>)>;

    #[test]
    fn claims_are_checked() {
        assert_eq!(with(|_| {}), Ok(()));
        assert_eq!(
            with(|c| {
                c.insert(
                    "iss".into(),
                    json!(format!("https://login.microsoftonline.com/{T}/v2.0")),
                );
                c.remove("appid");
                c.insert("azp".into(), json!(EVENT_GRID_APP_ID));
            }),
            Ok(()),
            "a v2 token"
        );
        let cases: Vec<(Reject, Edit)> = vec![
            (
                Reject::Issuer,
                Box::new(|c| {
                    c.remove("iss");
                }),
            ),
            (
                Reject::Issuer,
                Box::new(|c| {
                    c.insert(
                        "iss".into(),
                        json!("https://sts.windows.net/99999999-0000-0000-0000-000000000000/"),
                    );
                }),
            ),
            (
                Reject::Issuer,
                Box::new(|c| {
                    c.insert("iss".into(), json!(format!("https://sts.windows.net/{T}")));
                }),
            ),
            (
                Reject::Audience,
                Box::new(|c| {
                    c.insert("aud".into(), json!("api://other"));
                }),
            ),
            (
                Reject::Audience,
                Box::new(|c| {
                    c.insert(
                        "aud".into(),
                        json!(["api://11111111-1111-1111-1111-111111111111"]),
                    );
                }),
            ),
            (
                Reject::Tenant,
                Box::new(|c| {
                    c.insert("tid".into(), json!("99999999-0000-0000-0000-000000000000"));
                }),
            ),
            (
                Reject::Tenant,
                Box::new(|c| {
                    c.remove("tid");
                }),
            ),
            (
                Reject::Expired,
                Box::new(|c| {
                    c.insert("exp".into(), json!(1_400));
                }),
            ),
            (
                Reject::Expired,
                Box::new(|c| {
                    c.remove("exp");
                }),
            ),
            (
                Reject::Expired,
                Box::new(|c| {
                    c.insert("nbf".into(), json!(1_600));
                }),
            ),
            (
                Reject::Expired,
                Box::new(|c| {
                    c.insert("exp".into(), json!("2000"));
                }),
            ),
            (
                Reject::Caller,
                Box::new(|c| {
                    c.insert(
                        "appid".into(),
                        json!("22222222-2222-2222-2222-222222222222"),
                    );
                }),
            ),
            (
                Reject::Caller,
                Box::new(|c| {
                    c.remove("appid");
                }),
            ),
            (
                Reject::Caller,
                Box::new(|c| {
                    c.insert("azp".into(), json!("22222222-2222-2222-2222-222222222222"));
                }),
            ),
            (
                Reject::Caller,
                Box::new(|c| {
                    c.insert("appid".into(), json!(null));
                    c.insert("azp".into(), json!(EVENT_GRID_APP_ID));
                }),
            ),
            (
                Reject::NotAppOnly,
                Box::new(|c| {
                    c.insert("scp".into(), json!("access_as_user"));
                }),
            ),
            (
                Reject::NotAppOnly,
                Box::new(|c| {
                    c.insert("idtyp".into(), json!("user"));
                }),
            ),
            (
                Reject::Role,
                Box::new(|c| {
                    c.remove("roles");
                }),
            ),
            (
                Reject::Role,
                Box::new(|c| {
                    c.insert("roles".into(), json!(["Other"]));
                }),
            ),
            (
                Reject::Role,
                Box::new(|c| {
                    c.insert("roles".into(), json!(EVENT_GRID_APP_ROLE));
                }),
            ),
        ];
        for (want, f) in cases {
            assert_eq!(with(f), Err(want));
        }
        // Leeway either side.
        assert_eq!(
            with(|c| {
                c.insert("exp".into(), json!(1_450));
            }),
            Ok(())
        );
        assert_eq!(
            with(|c| {
                c.insert("nbf".into(), json!(1_550));
            }),
            Ok(())
        );
    }

    fn token(header: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(header.to_string());
        let p = URL_SAFE_NO_PAD.encode(Value::Object(good()).to_string());
        format!("{h}.{p}.c2ln")
    }

    #[test]
    fn only_rs256_with_a_key_id() {
        assert!(parts(&token(json!({"alg": "RS256", "kid": "k1", "typ": "JWT"}))).is_ok());
        for bad in [
            json!({"alg": "none", "kid": "k1"}),
            json!({"alg": "HS256", "kid": "k1"}),
            json!({"alg": "RS384", "kid": "k1"}),
            json!({"alg": "PS256", "kid": "k1"}),
            json!({"alg": "ES256", "kid": "k1"}),
            json!({"alg": "rs256", "kid": "k1"}),
            json!({"kid": "k1"}),
            json!({"alg": "RS256"}),
            json!({"alg": "RS256", "kid": ""}),
            json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt+x"}),
            json!({"alg": "RS256", "kid": "k1", "crit": ["exp"]}),
        ] {
            assert_eq!(
                parts(&token(bad.clone())).err(),
                Some(Reject::Algorithm),
                "{bad}"
            );
        }
        for bad in ["", "a.b", "a.b.c.d", "!!.e30.c2ln", "e30.e30.!!"] {
            assert_eq!(parts(bad).err(), Some(Reject::Malformed), "{bad}");
        }
    }

    #[test]
    fn bearer_header() {
        assert_eq!(bearer(Some("Bearer abc")), Ok("abc"));
        assert_eq!(bearer(Some("bearer abc")), Ok("abc"));
        assert_eq!(bearer(None), Err(Reject::Missing));
        assert_eq!(bearer(Some("Basic abc")), Err(Reject::Missing));
        assert_eq!(bearer(Some("Bearer ")), Err(Reject::Missing));
        assert_eq!(bearer(Some("Bearer")), Err(Reject::Missing));
        let long = format!("Bearer {}", "a".repeat(MAX_TOKEN_BYTES + 1));
        assert_eq!(bearer(Some(&long)), Err(Reject::Malformed));
    }
}
