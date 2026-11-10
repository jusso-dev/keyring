//! One place that decides what an Entra ID error means for the person.
//!
//! Used by the sign-in callback and by the token broker (refresh and
//! on-behalf-of), so the same code always gets the same advice.

/// What the person (or their admin) should do about an Entra error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntraAdvice {
    /// The person cancelled at Entra.
    Cancelled,
    /// Signing in again fixes it: the session ran out, or Entra wants a
    /// fresh sign-in (MFA, a conditional access policy).
    SignInAgain,
    /// An admin has to consent to Keyring.
    ConsentNeeded,
    /// Most likely a setting in Keyring or its app registration. `code` is
    /// the OAuth error with the first Entra error number, for the admin.
    Configuration { code: String },
}

/// Entra error numbers (AADSTS) that mean an admin must consent.
const CONSENT_CODES: [u64; 3] = [65001, 65004, 650057];

/// `invalid_grant` numbers that a fresh sign-in fixes. Any other
/// `invalid_grant`, for example a wrong `ENTRA_API_SCOPE`, is a setting:
/// signing in again would only land the person on the same page.
const SIGN_IN_AGAIN_CODES: [u64; 12] = [
    50076,  // MFA required
    50078,  // MFA registration or a fresh MFA required
    50079,  // MFA registration required
    50089,  // flow token expired
    50132,  // session revoked by a password change or expiry
    50133,  // session invalid because of a password change
    50158,  // an external security challenge wasn't satisfied
    50173,  // grant expired because the password was reset
    54005,  // authorisation code already redeemed
    70008,  // refresh token or authorisation code expired
    70043,  // refresh token expired under a sign-in frequency policy
    700082, // refresh token expired after 90 days without use
];

/// Classify an OAuth error code and Entra's error numbers.
pub fn classify(error: &str, codes: &[u64]) -> EntraAdvice {
    if error == "consent_required" || codes.iter().any(|c| CONSENT_CODES.contains(c)) {
        return EntraAdvice::ConsentNeeded;
    }
    match error {
        "access_denied" => EntraAdvice::Cancelled,
        // MFA, conditional access, or a sign-in Entra wants redone.
        "interaction_required" | "login_required" => EntraAdvice::SignInAgain,
        "invalid_grant" if codes.iter().any(|c| SIGN_IN_AGAIN_CODES.contains(c)) => {
            EntraAdvice::SignInAgain
        }
        other => EntraAdvice::Configuration {
            code: describe_code(other, codes),
        },
    }
}

/// `invalid_grant (AADSTS50013)`, or just the error when there's no number.
fn describe_code(error: &str, codes: &[u64]) -> String {
    match codes.first() {
        Some(n) => format!("{error} (AADSTS{n})"),
        None => error.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_wins_over_the_error_name() {
        assert_eq!(
            classify("invalid_grant", &[65001]),
            EntraAdvice::ConsentNeeded
        );
        assert_eq!(
            classify("consent_required", &[]),
            EntraAdvice::ConsentNeeded
        );
    }

    #[test]
    fn interaction_required_means_sign_in_again_everywhere() {
        assert_eq!(
            classify("interaction_required", &[50076]),
            EntraAdvice::SignInAgain
        );
        assert_eq!(
            classify("interaction_required", &[]),
            EntraAdvice::SignInAgain
        );
        assert_eq!(classify("login_required", &[]), EntraAdvice::SignInAgain);
    }

    #[test]
    fn only_known_invalid_grant_codes_mean_sign_in_again() {
        for n in [70008, 50173, 700082, 70043] {
            assert_eq!(
                classify("invalid_grant", &[n]),
                EntraAdvice::SignInAgain,
                "{n}"
            );
        }
        // For example an assertion for the wrong audience.
        assert_eq!(
            classify("invalid_grant", &[50013]),
            EntraAdvice::Configuration {
                code: "invalid_grant (AADSTS50013)".into()
            }
        );
        assert_eq!(
            classify("invalid_grant", &[]),
            EntraAdvice::Configuration {
                code: "invalid_grant".into()
            }
        );
    }

    #[test]
    fn cancel_and_other_errors() {
        assert_eq!(classify("access_denied", &[]), EntraAdvice::Cancelled);
        assert_eq!(
            classify("invalid_client", &[7000215]),
            EntraAdvice::Configuration {
                code: "invalid_client (AADSTS7000215)".into()
            }
        );
    }
}
