//! `KEYRING_PASSWORD_POLICY`: rules for a password a person types into
//! Keyring.
//!
//! The setting is one line of comma-separated parts, for example
//! `min=14,upper,lower,digit,symbol,max-repeat=3,common`. Every part is off
//! unless it is listed, and unset means no policy at all. A part Keyring
//! doesn't know, a repeated part, or a number out of range stops Keyring
//! starting.
//!
//! The check runs in memory on submit. It never logs the value, any part of
//! it, its length or which common password it matched, and its messages
//! only repeat the rule's own wording.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::secret::Secret;

/// Largest `min=`. The generator makes up to this many characters, so a
/// policy can always be met by a generated value.
pub const MAX_MIN_LENGTH: usize = crate::generator::MAX_LENGTH;
/// Largest `max-repeat=`.
pub const MAX_REPEAT_LIMIT: usize = 64;

/// The built-in list, one lower-case password per line. Lines starting with
/// `#` are the source and licence.
const COMMON_LIST: &str = include_str!("common_passwords.txt");

static COMMON: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    COMMON_LIST
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

/// How many passwords are on the built-in list.
pub fn common_count() -> usize {
    COMMON.len()
}

/// What `KEYRING_PASSWORD_POLICY` asks for. The default asks for nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Fewest characters (Unicode scalar values, not bytes), not counting
    /// invisible characters or combining marks.
    pub min: Option<usize>,
    pub upper: bool,
    pub lower: bool,
    pub digit: bool,
    pub symbol: bool,
    /// Most times one character may appear in a row.
    pub max_repeat: Option<usize>,
    /// Refuse values on the built-in list of common passwords.
    pub common: bool,
}

/// An upper case letter, in any alphabet.
fn is_upper(c: char) -> bool {
    c.is_uppercase()
}
/// A lower case letter, in any alphabet.
fn is_lower(c: char) -> bool {
    c.is_lowercase()
}
/// 0 to 9.
fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}
/// Anything that isn't a letter, a number, a space or a character that
/// doesn't count (see [`counts`]).
fn is_symbol(c: char) -> bool {
    counts(c) && !c.is_alphanumeric() && !c.is_whitespace()
}

/// Unicode general category M (combining marks), such as the accent in a
/// decomposed `é`. The regex crate is already a dependency, with its
/// Unicode tables.
static MARK: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^\p{M}$").expect("a fixed pattern"));

/// Whether a character counts towards `min` and can be a symbol. Control,
/// format and other invisible characters ([`crate::reason::is_unsafe`]:
/// zero-width spaces and joiners, the soft hyphen, the byte order mark,
/// bidi marks, private use) and combining marks don't: they add nothing
/// anyone can see. A value may still hold them; they just don't meet a
/// rule.
fn counts(c: char) -> bool {
    if crate::reason::is_unsafe(c) {
        return false;
    }
    let mut buf = [0u8; 4];
    !MARK.is_match(c.encode_utf8(&mut buf))
}

impl PasswordPolicy {
    /// True when any rule is on.
    pub fn is_on(&self) -> bool {
        *self != Self::default()
    }

    /// Read the setting. The error says what to write instead, for the
    /// start-up message. It never repeats the part it couldn't read beyond
    /// its name, which is the deployer's own text.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut p = Self::default();
        let mut seen: Vec<&str> = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            let (name, number) = match part.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim())),
                None => (part, None),
            };
            let name_lc = name.to_ascii_lowercase();
            let key: &'static str = match name_lc.as_str() {
                "min" => "min",
                "upper" => "upper",
                "lower" => "lower",
                "digit" => "digit",
                "symbol" => "symbol",
                "max-repeat" => "max-repeat",
                "common" => "common",
                "" => return Err(format!("there's an empty part. {}", Self::SYNTAX)),
                _ => {
                    return Err(format!(
                        "{name} isn't a part Keyring knows. {}",
                        Self::SYNTAX
                    ));
                }
            };
            if seen.contains(&key) {
                return Err(format!("{key} is given more than once"));
            }
            seen.push(key);
            let n = |lo: usize, hi: usize| -> Result<usize, String> {
                number
                    // Digits only: Rust's parser would take `+14`.
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|n| (lo..=hi).contains(n))
                    .ok_or_else(|| {
                        format!("{key} takes a whole number from {lo} to {hi}, as {key}=N")
                    })
            };
            match (key, number) {
                ("min", _) => p.min = Some(n(1, MAX_MIN_LENGTH)?),
                ("max-repeat", _) => p.max_repeat = Some(n(1, MAX_REPEAT_LIMIT)?),
                (_, Some(_)) => return Err(format!("{key} doesn't take a value")),
                ("upper", None) => p.upper = true,
                ("lower", None) => p.lower = true,
                ("digit", None) => p.digit = true,
                ("symbol", None) => p.symbol = true,
                ("common", None) => p.common = true,
                _ => unreachable!("every key is matched above"),
            }
        }
        Ok(p)
    }

    const SYNTAX: &'static str = "Use comma-separated parts from min=N, upper, lower, digit, symbol, max-repeat=N and common, such as min=14,upper,lower,digit,symbol,max-repeat=3,common";

    /// What the policy asks for, for the form's help text, or empty when
    /// it is off. Starts lower case, to follow "A password needs".
    pub fn describe(&self) -> String {
        let mut needs: Vec<String> = Vec::new();
        if let Some(n) = self.min {
            needs.push(format!("at least {n} characters"));
        }
        needs.extend(self.classes().map(|(_, what, _)| what.to_owned()));
        let mut parts = Vec::new();
        if !needs.is_empty() {
            parts.push(join(&needs));
        }
        if let Some(n) = self.max_repeat {
            parts.push(format!("no character more than {n} {} in a row", times(n)));
        }
        if self.common {
            parts.push("not a common password".to_owned());
        }
        join(&parts)
    }

    fn classes(&self) -> impl Iterator<Item = (bool, &'static str, fn(char) -> bool)> {
        [
            (
                self.upper,
                "an upper case letter",
                is_upper as fn(char) -> bool,
            ),
            (self.lower, "a lower case letter", is_lower),
            (self.digit, "a digit (0 to 9)", is_digit),
            (self.symbol, "a symbol, such as ! # or %", is_symbol),
        ]
        .into_iter()
        .filter(|(on, _, _)| *on)
    }

    /// Check a value. `label` names the field in the message, such as
    /// "Password". `None` when it passes, or one message naming each rule
    /// it fails, in a fixed order. Every rule is checked every time, so the
    /// time taken doesn't depend on which rule fails first.
    pub fn check(&self, label: &str, value: &Secret) -> Option<String> {
        if !self.is_on() {
            return None;
        }
        let v = value.expose();
        let length = v.chars().filter(|&c| counts(c)).count();
        let mut needs: Vec<String> = Vec::new();
        if let Some(n) = self.min
            && length < n
        {
            needs.push(format!("at least {n} characters"));
        }
        for (_, what, has) in self.classes() {
            if !v.chars().any(has) {
                needs.push(what.to_owned());
            }
        }
        let longest_run = longest_run(v);
        // Lower-cased into a `Secret`, so the copy is zeroised when dropped.
        let lowered = Secret::new(v.to_lowercase());
        let on_list = COMMON.contains(lowered.expose());
        drop(lowered);

        let mut messages = Vec::new();
        if !needs.is_empty() {
            messages.push(format!("{label} needs {}.", join(&needs)));
        }
        if let Some(n) = self.max_repeat
            && longest_run > n
        {
            messages.push(format!(
                "{label} can't have the same character more than {n} {} in a row.",
                times(n)
            ));
        }
        if self.common && on_list {
            messages.push(format!(
                "{label} is a common password, on Keyring's built-in list. Choose another."
            ));
        }
        (!messages.is_empty()).then(|| messages.join(" "))
    }
}

/// The most times one character appears in a row.
fn longest_run(v: &str) -> usize {
    let mut longest = 0;
    let mut run = 0;
    let mut last = None;
    for c in v.chars() {
        run = if last == Some(c) { run + 1 } else { 1 };
        last = Some(c);
        longest = longest.max(run);
    }
    longest
}

fn times(n: usize) -> &'static str {
    if n == 1 { "time" } else { "times" }
}

/// "a", "a and b", "a, b and c".
fn join(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PasswordPolicy {
        PasswordPolicy::parse(s).unwrap()
    }

    fn check(policy: &str, value: &str) -> Option<String> {
        p(policy).check("Password", &Secret::new(value))
    }

    #[test]
    fn parses_every_part() {
        let all = p("min=14,upper,lower,digit,symbol,max-repeat=3,common");
        assert_eq!(
            all,
            PasswordPolicy {
                min: Some(14),
                upper: true,
                lower: true,
                digit: true,
                symbol: true,
                max_repeat: Some(3),
                common: true,
            }
        );
        assert_eq!(p(" MIN = 8 , Common "), p("min=8,common"));
        assert_eq!(p("common").min, None, "parts left out are off");
        assert!(!PasswordPolicy::default().is_on());
        assert!(p("upper").is_on());
    }

    #[test]
    fn refuses_anything_unknown_or_out_of_range() {
        for bad in [
            "",
            "min",
            "min=",
            "min=0",
            "min=257",
            "min=-1",
            "min=1.5",
            "min=ten",
            "max-repeat=0",
            "max-repeat=65",
            "upper=1",
            "common=yes",
            "min=8,min=9",
            "upper,UPPER",
            "min=8,,upper",
            "min=8,",
            "length=8",
            "maxrepeat=3",
            "digits",
            "min=8;upper",
            "min=+14",
            "max-repeat=+3",
            "min=1_4",
            "min=0x0E",
        ] {
            assert!(
                PasswordPolicy::parse(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
        assert!(PasswordPolicy::parse("min=256,max-repeat=64").is_ok());
        let e = PasswordPolicy::parse("length=8").unwrap_err();
        assert!(e.contains("length isn't a part"), "{e}");
    }

    #[test]
    fn describes_what_it_asks_for() {
        assert_eq!(
            p("min=14,upper,lower,digit,symbol,max-repeat=3,common").describe(),
            "at least 14 characters, an upper case letter, a lower case letter, a digit (0 to 9) and a symbol, such as ! # or %, no character more than 3 times in a row and not a common password"
        );
        assert_eq!(p("min=12").describe(), "at least 12 characters");
        assert_eq!(
            p("max-repeat=1").describe(),
            "no character more than 1 time in a row"
        );
        assert_eq!(PasswordPolicy::default().describe(), "");
    }

    #[test]
    fn length_is_counted_in_characters() {
        // Four characters, 13 bytes.
        assert_eq!(check("min=4", "ü日本🔑"), None);
        assert!(check("min=5", "ü日本🔑").is_some());
        assert_eq!(
            check("min=14", "short").as_deref(),
            Some("Password needs at least 14 characters.")
        );
    }

    #[test]
    fn classes() {
        let all = "upper,lower,digit,symbol";
        assert_eq!(check(all, "aB3!"), None);
        assert_eq!(
            check(all, "ÀéЖ٣¿"),
            Some("Password needs a digit (0 to 9).".into())
        );
        assert_eq!(
            check(all, "abc").as_deref(),
            Some(
                "Password needs an upper case letter, a digit (0 to 9) and a symbol, such as ! # or %."
            )
        );
        // A space is not a symbol.
        assert!(check("symbol", "a b").is_some());
        assert_eq!(check("symbol", "a_b"), None);
    }

    #[test]
    fn invisible_characters_and_marks_meet_no_rule() {
        let policy = "min=14,upper,lower,digit,symbol";
        // Looks like `Password1`: five zero-width characters don't make
        // it 14 long or give it a symbol.
        let padded = "Password1\u{200B}\u{200C}\u{200D}\u{2060}\u{FEFF}";
        assert_eq!(
            check(policy, padded).as_deref(),
            Some("Password needs at least 14 characters and a symbol, such as ! # or %.")
        );
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{00AD}',
        ] {
            assert!(!is_symbol(c), "{c:?}");
            assert!(check("symbol", &format!("ab{c}")).is_some(), "{c:?}");
            assert!(check("min=3", &format!("ab{c}")).is_some(), "{c:?}");
        }
        // Combining marks: not a symbol, and not counted. A decomposed
        // `é` (e and U+0301) is one character, as is the composed one.
        for c in ['\u{0301}', '\u{0308}', '\u{20DD}', '\u{0903}'] {
            assert!(!is_symbol(c), "{c:?}");
        }
        assert!(check("symbol", "abc\u{0301}\u{0301}").is_some());
        assert_eq!(check("min=3", "cafe\u{0301}"), None);
        assert!(check("min=5", "cafe\u{0301}").is_some());
        assert!(check("min=5", "caf\u{e9}\u{0301}\u{0301}\u{0301}").is_some());
        // Still allowed in a value: they just don't meet a rule.
        assert_eq!(check(policy, "Password1!-long\u{200B}"), None);
        // Visible symbols still count.
        for c in ['!', '_', '\u{00BF}', '\u{20AC}', '\u{1F511}'] {
            assert!(is_symbol(c), "{c:?}");
        }
    }

    #[test]
    fn repeats() {
        assert_eq!(check("max-repeat=3", "aaabbb"), None);
        assert_eq!(
            check("max-repeat=3", "xaaaax").as_deref(),
            Some("Password can't have the same character more than 3 times in a row.")
        );
        assert!(check("max-repeat=1", "abba").is_some());
        assert_eq!(check("max-repeat=1", "abab"), None);
        assert_eq!(longest_run(""), 0);
        assert_eq!(longest_run("🔑🔑🔑a"), 3);
    }

    #[test]
    fn common_passwords_get_one_message_whatever_the_entry() {
        let msg = "Password is a common password, on Keyring's built-in list. Choose another.";
        for v in ["password", "PassWord", "123456", "trustno1", "QWERTYUIOP"] {
            assert_eq!(check("common", v).as_deref(), Some(msg), "{v}");
        }
        assert_eq!(check("common", "password "), None, "compared whole");
        assert_eq!(check("common", "correct horse battery staple"), None);
        // Every rule is reported, the list last.
        assert_eq!(
            check("min=12,upper,common", "letmein").as_deref(),
            Some(
                "Password needs at least 12 characters and an upper case letter. Password is a common password, on Keyring's built-in list. Choose another."
            )
        );
    }

    #[test]
    fn the_list_is_small_lower_case_and_plain() {
        let n = common_count();
        assert!((300..=1000).contains(&n), "{n} entries");
        for w in COMMON.iter() {
            assert_eq!(*w, w.to_lowercase(), "{w} is lower case");
            assert!(!w.is_empty() && !w.contains(char::is_whitespace), "{w:?}");
        }
        assert!(COMMON_LIST.contains("MIT License"), "licence kept");
    }

    #[test]
    fn generated_defaults_pass_a_typical_policy() {
        let policy = p("min=14,upper,lower,digit,symbol,max-repeat=3,common");
        let mut passed = 0;
        for _ in 0..200 {
            let v =
                crate::generator::password(&crate::generator::PasswordOptions::default()).unwrap();
            if policy.check("Password", &v).is_none() {
                passed += 1;
            }
        }
        // A run of four of one character in 24 is possible but rare.
        assert!(passed >= 198, "{passed} of 200 passed");
    }

    #[test]
    fn off_passes_everything() {
        assert_eq!(
            PasswordPolicy::default().check("Password", &Secret::new("")),
            None
        );
    }

    #[test]
    fn messages_never_hold_the_value() {
        let policy = p("min=40,upper,lower,digit,symbol,max-repeat=1,common");
        // Lengths 13, 12 and 8: none appears in the rule wording.
        for v in ["MSGLEAKaabbcc", "msgleak!!xyz", "password"] {
            let m = policy.check("Password", &Secret::new(v)).unwrap();
            assert!(
                !m.to_lowercase().contains(&v.to_lowercase()) || v == "password",
                "{m}"
            );
            assert!(!m.contains("MSGLEAK") && !m.contains("msgleak"), "{m}");
            assert!(
                !m.contains(&v.chars().count().to_string()),
                "no length in {m}"
            );
        }
    }
}
