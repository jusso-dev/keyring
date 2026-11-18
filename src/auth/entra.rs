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
    /// A Conditional Access policy wasn't met and signing in again won't
    /// change that: a device that isn't compliant, a blocked location, or a
    /// sign-in method the person hasn't registered. `code` is as in
    /// [`EntraAdvice::Configuration`]. The numbers come from Microsoft's
    /// error reference and are not yet confirmed on a real tenant.
    PolicyNotMet { code: String },
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

/// Entra error numbers that mean the sign-in needs a stronger method,
/// usually MFA. A fresh sign-in that reuses Entra's single sign-on session
/// would only bring back the same token, so the next sign-in must ask for
/// MFA. All are also in [`SIGN_IN_AGAIN_CODES`].
pub const MFA_CODES: [u64; 4] = [50076, 50078, 50079, 50158];

/// True if Entra's error numbers say the sign-in needs MFA.
pub fn needs_mfa(codes: &[u64]) -> bool {
    mfa_code(codes).is_some()
}

/// The first of Entra's error numbers that says the sign-in needs MFA.
pub fn mfa_code(codes: &[u64]) -> Option<u64> {
    codes.iter().copied().find(|c| MFA_CODES.contains(c))
}

/// Entra error numbers for a Conditional Access policy the sign-in didn't
/// meet. From Microsoft's AADSTS reference; which of these Entra sends back
/// to Keyring, rather than showing on its own page, needs a real tenant.
const POLICY_CODES: [u64; 5] = [
    53000, // device not compliant
    53001, // device not domain joined
    53002, // app not approved for the policy
    53003, // blocked by Conditional Access
    53004, // the person must register a sign-in method first
];

/// Classify an OAuth error code and Entra's error numbers.
pub fn classify(error: &str, codes: &[u64]) -> EntraAdvice {
    if error == "consent_required" || codes.iter().any(|c| CONSENT_CODES.contains(c)) {
        return EntraAdvice::ConsentNeeded;
    }
    if codes.iter().any(|c| POLICY_CODES.contains(c)) {
        return EntraAdvice::PolicyNotMet {
            code: describe_code(error, codes),
        };
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
    fn conditional_access_blocks_are_told_apart() {
        for (error, n) in [
            ("access_denied", 53003),
            ("interaction_required", 53000),
            ("invalid_grant", 53004),
        ] {
            assert_eq!(
                classify(error, &[n]),
                EntraAdvice::PolicyNotMet {
                    code: format!("{error} (AADSTS{n})")
                },
                "{error} {n}"
            );
        }
        // Consent still wins.
        assert_eq!(
            classify("access_denied", &[65001, 53003]),
            EntraAdvice::ConsentNeeded
        );
    }

    #[test]
    fn mfa_codes_are_sign_in_again_codes() {
        for n in MFA_CODES {
            assert!(SIGN_IN_AGAIN_CODES.contains(&n), "{n}");
        }
        assert!(needs_mfa(&[50076]));
        assert!(!needs_mfa(&[70008]));
        assert!(!needs_mfa(&[]));
        assert_eq!(mfa_code(&[70008, 50076]), Some(50076));
        assert_eq!(mfa_code(&[70008]), None);
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
