//! Step-up before a sensitive action: a Conditional Access authentication
//! context (`KEYRING_STEP_UP_AUTH_CONTEXT`), a recent sign-in
//! (`KEYRING_STEP_UP_MAX_AGE`), or both.
//!
//! This is a check Keyring makes, from the `acrs` and `auth_time` claims of
//! the verified ID token. Key Vault doesn't know about it, so a person can
//! still read the same values with the Azure CLI. It raises the bar for a
//! stolen session cookie.
//!
//! The guard that pages call is [`crate::routes::step_up::require`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Longest `KEYRING_STEP_UP_MAX_AGE`, in minutes: a session never lasts
/// longer than this anyway.
pub const MAX_AGE_LIMIT_MINUTES: u64 = 12 * 60;

/// What a sensitive action needs. Both parts are optional. With neither
/// set, nothing is checked and nothing changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepUpPolicy {
    /// An authentication context ID, `c1` to `c99`, that must be in `acrs`.
    pub auth_context: Option<String>,
    /// How long ago the person may have last signed in (`auth_time`).
    pub max_age: Option<Duration>,
}

/// What the verified ID token said about how the person signed in. Kept in
/// the session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignInFacts {
    /// Authentication context IDs met at sign-in (`acrs`), checked values only.
    pub acrs: Vec<String>,
    /// When the person last entered credentials (`auth_time`), Unix seconds.
    pub auth_time: Option<i64>,
}

/// Why the session doesn't meet the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shortfall {
    /// The authentication context isn't in `acrs`.
    Context,
    /// No `auth_time`, or it is older than the maximum age.
    Age,
}

impl StepUpPolicy {
    /// True when either rule is set.
    pub fn is_on(&self) -> bool {
        self.auth_context.is_some() || self.max_age.is_some()
    }

    /// Check a session's sign-in against the policy at `now`.
    pub fn check(&self, facts: &SignInFacts, now: SystemTime) -> Result<(), Shortfall> {
        if let Some(ctx) = &self.auth_context
            && !facts.acrs.iter().any(|a| a == ctx)
        {
            return Err(Shortfall::Context);
        }
        if let Some(max) = self.max_age {
            let now = unix(now);
            // Unknown counts as too old. A time a little in the future
            // (clock skew) counts as fresh.
            let fresh = facts
                .auth_time
                .is_some_and(|t| now.saturating_sub(t) <= max.as_secs() as i64);
            if !fresh {
                return Err(Shortfall::Age);
            }
        }
        Ok(())
    }

    /// The OIDC `claims` request that asks Entra for the authentication
    /// context, merged into a claims challenge Entra sent earlier, if any.
    /// `None` without an authentication context.
    pub fn claims(&self, challenge: Option<&str>) -> Option<String> {
        let Some(ctx) = &self.auth_context else {
            return challenge.map(str::to_owned);
        };
        let mut map = challenge
            .and_then(|c| {
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(c).ok()
            })
            .unwrap_or_default();
        let id_token = map
            .entry("id_token")
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
        if let Some(obj) = id_token.as_object_mut() {
            obj.insert(
                "acrs".into(),
                serde_json::json!({ "essential": true, "value": ctx }),
            );
        }
        Some(serde_json::Value::Object(map).to_string())
    }
}

/// An authentication context ID, `c1` to `c99`, in lower case, or `None`.
pub fn auth_context_id(raw: &str) -> Option<String> {
    // No trimming: config trims its own input, and a claim with spaces
    // or a line break in it isn't kept.
    let v = raw.to_ascii_lowercase();
    let n = v.strip_prefix('c')?;
    let ok =
        (1..=2).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0');
    ok.then_some(v)
}

/// Unix seconds.
pub fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(acrs: &[&str], auth_time: Option<i64>) -> SignInFacts {
        SignInFacts {
            acrs: acrs.iter().map(|s| (*s).to_owned()).collect(),
            auth_time,
        }
    }

    #[test]
    fn context_ids_are_c1_to_c99() {
        assert_eq!(auth_context_id("c1").as_deref(), Some("c1"));
        assert_eq!(auth_context_id("C25").as_deref(), Some("c25"));
        assert_eq!(auth_context_id("c99").as_deref(), Some("c99"));
        for bad in ["", "c", "c0", "c01", "c100", "1", "cx", "d1", "c1\n", " c1"] {
            assert_eq!(auth_context_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn off_lets_everything_through() {
        let p = StepUpPolicy::default();
        assert!(!p.is_on());
        assert_eq!(p.check(&SignInFacts::default(), SystemTime::now()), Ok(()));
        assert_eq!(p.claims(None), None);
    }

    #[test]
    fn context_must_be_in_acrs() {
        let p = StepUpPolicy {
            auth_context: Some("c1".into()),
            max_age: None,
        };
        let now = SystemTime::now();
        assert_eq!(p.check(&facts(&["c1"], None), now), Ok(()));
        assert_eq!(p.check(&facts(&["c2", "c1"], None), now), Ok(()));
        assert_eq!(p.check(&facts(&["c2"], None), now), Err(Shortfall::Context));
        assert_eq!(p.check(&facts(&[], None), now), Err(Shortfall::Context));
    }

    #[test]
    fn age_counts_from_auth_time() {
        let p = StepUpPolicy {
            auth_context: None,
            max_age: Some(Duration::from_secs(15 * 60)),
        };
        let now = SystemTime::now();
        let t = unix(now);
        assert_eq!(p.check(&facts(&[], Some(t - 60)), now), Ok(()));
        assert_eq!(p.check(&facts(&[], Some(t - 15 * 60)), now), Ok(()));
        assert_eq!(p.check(&facts(&[], Some(t + 30)), now), Ok(()));
        assert_eq!(
            p.check(&facts(&[], Some(t - 15 * 60 - 1)), now),
            Err(Shortfall::Age)
        );
        assert_eq!(p.check(&facts(&[], None), now), Err(Shortfall::Age));
    }

    #[test]
    fn claims_ask_for_the_context_in_the_id_token() {
        let p = StepUpPolicy {
            auth_context: Some("c1".into()),
            max_age: None,
        };
        assert_eq!(
            p.claims(None).as_deref(),
            Some(r#"{"id_token":{"acrs":{"essential":true,"value":"c1"}}}"#)
        );
        // A challenge from Entra is kept.
        let merged: serde_json::Value = serde_json::from_str(
            &p.claims(Some(r#"{"access_token":{"capolids":{"essential":true}}}"#))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(merged["access_token"]["capolids"]["essential"], true);
        assert_eq!(merged["id_token"]["acrs"]["value"], "c1");
        // Age only: no claims of its own, but a challenge still goes.
        let age = StepUpPolicy {
            auth_context: None,
            max_age: Some(Duration::from_secs(60)),
        };
        assert_eq!(age.claims(None), None);
        assert_eq!(age.claims(Some("{}")).as_deref(), Some("{}"));
    }
}
