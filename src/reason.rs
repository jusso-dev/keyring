//! A reason, and optionally a ticket, before a value is shown or anything
//! is changed (`KEYRING_REQUIRE_REASON`, `KEYRING_REASON_TICKET_PATTERN`).
//!
//! The rules and the clean-up live here. The form gate that applies them
//! is `routes::reason`. The cleaned reason and ticket go on the action's
//! audit event as `reason` and `ticket`.
//!
//! This is for the Keyring path and for audit. It isn't a hard control:
//! anyone with access can read the same value with the Azure CLI and no
//! reason.

use crate::audit::Action;

/// Fewest characters a reason can have, after clean-up.
pub const MIN_REASON_CHARS: usize = 5;
/// Most characters a reason can have, after clean-up.
pub const MAX_REASON_CHARS: usize = 200;
/// Most characters a ticket can have.
pub const MAX_TICKET_CHARS: usize = 64;
/// Longest `KEYRING_REASON_TICKET_PATTERN` accepted, in characters.
pub const MAX_PATTERN_CHARS: usize = 200;
/// Longest raw reason looked at, in bytes. Anything longer is refused
/// without being read through.
const MAX_RAW_REASON_BYTES: usize = 4 * MAX_REASON_CHARS * 4;

/// `KEYRING_REQUIRE_REASON`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequireReason {
    /// Never ask. The default.
    #[default]
    Off,
    /// Before a secret value is shown or a private key downloaded.
    Reveal,
    /// Those, and every action that changes something.
    All,
}

impl RequireReason {
    /// The setting's value, as written in the environment.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "reveal" => Some(Self::Reveal),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// `KEYRING_REASON_TICKET_PATTERN`, compiled once at start. Always matched
/// against the whole ticket: the pattern is wrapped in `^(?:...)$`.
#[derive(Debug, Clone)]
pub struct TicketPattern {
    source: String,
    re: regex::Regex,
}

impl TicketPattern {
    /// Compile a pattern, or say why it can't be used.
    pub fn new(source: &str) -> Result<Self, String> {
        if source.chars().count() > MAX_PATTERN_CHARS {
            return Err(format!(
                "use a pattern of at most {MAX_PATTERN_CHARS} characters"
            ));
        }
        // Compiled alone first, so a pattern such as `a)|(b` can't close
        // the group below and slip out of the anchors.
        let build = |p: &str| {
            regex::RegexBuilder::new(p)
                // A small compiled size: a ticket pattern needs very little.
                .size_limit(256 * 1024)
                .dfa_size_limit(256 * 1024)
                .build()
                .map_err(|_| {
                    "it isn't a regular expression Keyring can use (check the syntax, and keep counted repeats small)"
                        .to_owned()
                })
        };
        build(source)?;
        let re = build(&format!("^(?:{source})$"))?;
        Ok(Self {
            source: source.to_owned(),
            re,
        })
    }

    /// The pattern as the admin wrote it, to show on the form.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// True when `ticket` matches the whole pattern.
    pub fn matches(&self, ticket: &str) -> bool {
        self.re.is_match(ticket)
    }
}

/// What Keyring asks for before an action.
#[derive(Debug, Clone, Default)]
pub struct ReasonPolicy {
    pub require: RequireReason,
    /// Set only when a ticket is asked for too.
    pub ticket: Option<TicketPattern>,
}

impl ReasonPolicy {
    /// True when `action` needs a reason under this policy.
    pub fn needs(&self, action: Action) -> bool {
        match self.require {
            RequireReason::Off => false,
            RequireReason::Reveal => is_reveal(action),
            RequireReason::All => action.item_kind().is_some(),
        }
    }

    /// Check a posted reason and ticket. On success, the cleaned reason and
    /// the ticket (if a pattern is set) to put on the audit event.
    pub fn check(&self, reason: &str, ticket: &str) -> Result<Given, Problems> {
        let mut problems = Problems::default();
        let reason = clean_reason(reason);
        if reason.is_none() {
            problems.reason = true;
        }
        let ticket = match &self.ticket {
            None => None,
            Some(p) => {
                let t = clean_ticket(ticket).filter(|t| p.matches(t));
                if t.is_none() {
                    problems.ticket = true;
                }
                t
            }
        };
        match reason {
            Some(reason) if !problems.ticket => Ok(Given { reason, ticket }),
            _ => Err(problems),
        }
    }
}

/// A reveal: a secret value shown, a private key downloaded, or a value
/// read to copy it to another vault.
pub fn is_reveal(action: Action) -> bool {
    matches!(
        action,
        Action::SecretReveal | Action::CertificateDownloadPrivateKey | Action::SecretCopyRead
    )
}

/// A reason and ticket that passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Given {
    pub reason: String,
    pub ticket: Option<String>,
}

/// Which of the two fields was refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Problems {
    pub reason: bool,
    pub ticket: bool,
}

/// Characters that never reach the log: controls (line breaks, tabs, the
/// ANSI escape, C1 controls), and invisible formatting that could disguise
/// what was written or stand in for text: every Unicode format character
/// (general category Cf, which holds the bidi marks and overrides, the
/// Arabic letter mark, zero-width spaces and joiners, the soft hyphen and
/// the tag characters), plus the line and paragraph separators, unassigned
/// "noncharacters" and private-use code points.
pub(crate) fn is_unsafe(c: char) -> bool {
    c.is_control() || is_format(c) || is_unprintable(c)
}

/// Unicode general category Cf (format), listed by range from the Unicode
/// Character Database, version 16. The standard library has no test for
/// it, and one more crate isn't worth it for a fixed list.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Other code points that show as nothing or as a box: the line and
/// paragraph separators, the reserved gap inside the format block,
/// variation selectors, the Hangul and braille blanks, noncharacters and
/// the private-use areas.
fn is_unprintable(c: char) -> bool {
    let n = c as u32;
    matches!(
        c,
        '\u{2028}'
            | '\u{2029}'
            | '\u{2065}'
            | '\u{034F}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180D}'
            | '\u{180F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFA0}'
            | '\u{FFFC}'
            | '\u{E0100}'..='\u{E01EF}'
            | '\u{E000}'..='\u{F8FF}'
            | '\u{F0000}'..='\u{10FFFF}'
            | '\u{FDD0}'..='\u{FDEF}'
    ) || (n & 0xFFFE) == 0xFFFE
}

/// The reason as written to the log: each run of spaces, line breaks and
/// unsafe characters becomes one space, ends trimmed. `None` unless that
/// leaves 5 to 200 characters (counted in characters, not bytes).
pub fn clean_reason(raw: &str) -> Option<String> {
    if raw.len() > MAX_RAW_REASON_BYTES {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    let mut gap = false;
    for c in raw.chars() {
        if c.is_whitespace() || is_unsafe(c) {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    let n = out.chars().count();
    (MIN_REASON_CHARS..=MAX_REASON_CHARS)
        .contains(&n)
        .then_some(out)
}

/// The ticket, trimmed. `None` when empty, too long, or holding anything
/// unsafe, before the pattern is tried.
fn clean_ticket(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty()
        || t.len() > MAX_TICKET_CHARS * 4
        || t.chars().count() > MAX_TICKET_CHARS
        || t.chars().any(|c| is_unsafe(c) || c.is_whitespace())
    {
        return None;
    }
    Some(t.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(require: RequireReason, pattern: Option<&str>) -> ReasonPolicy {
        ReasonPolicy {
            require,
            ticket: pattern.map(|p| TicketPattern::new(p).unwrap()),
        }
    }

    #[test]
    fn which_actions_need_a_reason() {
        let off = policy(RequireReason::Off, None);
        let reveal = policy(RequireReason::Reveal, None);
        let all = policy(RequireReason::All, None);
        for a in Action::ALL {
            assert!(!off.needs(a), "{a}");
            assert_eq!(reveal.needs(a), is_reveal(a), "{a}");
            assert_eq!(all.needs(a), a.item_kind().is_some(), "{a}");
        }
        assert!(reveal.needs(Action::CertificateDownloadPrivateKey));
        assert!(!reveal.needs(Action::SecretDelete));
        assert!(all.needs(Action::SecretRollback));
        assert!(all.needs(Action::KeyPurge));
        assert!(!all.needs(Action::SessionSignOut));
        assert!(!all.needs(Action::RequestRefused));
    }

    #[test]
    fn reasons_are_cleaned_and_limited() {
        assert_eq!(clean_reason("  INC fix  ").as_deref(), Some("INC fix"));
        // Line breaks, quotes and ANSI escapes can't start a line or
        // colour a terminal.
        assert_eq!(
            clean_reason("line one\r\nFORGED kind=audit \"q\" \u{1b}[31mred\u{1b}[0m").as_deref(),
            Some("line one FORGED kind=audit \"q\" [31mred [0m")
        );
        assert_eq!(
            clean_reason("a\u{202E}b\u{200B}c\u{2028}d\u{85}e\u{7f}f").as_deref(),
            Some("a b c d e f")
        );
        // Invisible characters don't count towards the five: a reason
        // made only of them is no reason.
        for invisible in [
            '\u{061C}',
            '\u{200B}',
            '\u{200D}',
            '\u{2060}',
            '\u{00AD}',
            '\u{180E}',
            '\u{FEFF}',
            '\u{202E}',
            '\u{2066}',
            '\u{E0041}',
            '\u{2800}',
            '\u{3164}',
            '\u{FE0F}',
            '\u{115F}',
            '\u{E000}',
            '\u{FFFE}',
            '\u{1D173}',
        ] {
            let only = invisible.to_string().repeat(8);
            assert_eq!(clean_reason(&only), None, "U+{:04X}", invisible as u32);
            // Between letters they become one space, and aren't counted.
            let mixed = format!("ab{invisible}{invisible}c");
            assert_eq!(clean_reason(&mixed), None, "U+{:04X}", invisible as u32);
        }
        assert_eq!(
            clean_reason("fix\u{061C}the\u{200D}login").as_deref(),
            Some("fix the login")
        );
        // Ordinary text in any script is kept as it is.
        for kept in [
            "مرحبا بالعالم",
            "日本語のテスト",
            "Größe prüfen",
            "naïve café",
        ] {
            assert_eq!(clean_reason(kept).as_deref(), Some(kept));
        }
        // 5 to 200 characters, counted in characters.
        assert_eq!(clean_reason("abcd"), None);
        assert_eq!(clean_reason(" \n\t ab \u{1b} "), None);
        assert!(clean_reason("abcde").is_some());
        assert!(clean_reason(&"é".repeat(200)).is_some());
        assert_eq!(clean_reason(&"é".repeat(201)), None);
        assert!(clean_reason("日本語です").is_some());
        assert_eq!(clean_reason(&"a".repeat(201)), None);
        assert_eq!(clean_reason(&"a".repeat(100_000)), None);
        // Runs of spaces count once.
        assert!(clean_reason(&format!("{}{}", "a ".repeat(100), "  ")).is_some());
    }

    #[test]
    fn ticket_pattern_is_whole_and_checked() {
        let p = policy(RequireReason::Reveal, Some("(INC|CHG)[0-9]{7}"));
        let ok = p
            .check("Rotating after an incident", " INC0012345 ")
            .unwrap();
        assert_eq!(ok.ticket.as_deref(), Some("INC0012345"));
        for bad in [
            "",
            "INC123",
            "xINC0012345",
            "INC0012345x",
            "INC0012345\nFORGED",
            "INC\u{1b}0012345",
        ] {
            assert_eq!(
                p.check("Rotating after an incident", bad),
                Err(Problems {
                    reason: false,
                    ticket: true
                }),
                "{bad:?}"
            );
        }
        assert_eq!(
            p.check("no", "INC0012345"),
            Err(Problems {
                reason: true,
                ticket: false
            })
        );
        // No pattern: any ticket is ignored.
        let p = policy(RequireReason::Reveal, None);
        let ok = p.check("Checking a value", "anything at all").unwrap();
        assert_eq!(ok.ticket, None);
        // An anchor in the pattern itself still works.
        let p = policy(RequireReason::All, Some("^CHG-[0-9]+$"));
        assert!(p.check("Changing things", "CHG-42").is_ok());
        assert!(p.check("Changing things", "CHG-42-x").is_err());
        // Too long, whatever the pattern.
        let p = policy(RequireReason::All, Some(".*"));
        assert!(p.check("Changing things", &"a".repeat(64)).is_ok());
        assert!(p.check("Changing things", &"a".repeat(65)).is_err());
    }

    #[test]
    fn bad_patterns_are_refused() {
        assert!(TicketPattern::new("(INC").is_err());
        assert!(TicketPattern::new("a)|(b").is_err());
        assert!(TicketPattern::new(&"a".repeat(201)).is_err());
        // Big counted repeats blow the compiled size limit.
        assert!(TicketPattern::new("(\\w{100}){100}").is_err());
        assert!(RequireReason::parse("REVEAL").is_some());
        assert!(RequireReason::parse("reveals").is_none());
    }
}
