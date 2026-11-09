//! Passwords, GUIDs and API keys from the operating system's secure random
//! source (`ring::rand::SystemRandom`, which reads `getrandom`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};

use crate::secret::Secret;

pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
/// Symbols that are safe in most config files and shells when quoted.
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters easy to mix up when read aloud or on screen.
pub const LOOK_ALIKES: &str = "0O1lI|";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 256;

fn fill(buf: &mut [u8]) {
    SystemRandom::new()
        .fill(buf)
        .expect("the operating system random number generator failed");
}

/// Uniform random index below `n`, by rejection sampling (no modulo bias).
fn below(n: usize) -> usize {
    assert!(n > 0 && n <= 256);
    let limit = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        fill(&mut b);
        if (b[0] as usize) < limit {
            return b[0] as usize % n;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub no_look_alikes: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            no_look_alikes: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GenError {
    NoCharacterSets,
    Length,
}

/// A password with at least one character from each chosen set.
pub fn password(o: &PasswordOptions) -> Result<Secret, GenError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&o.length) {
        return Err(GenError::Length);
    }
    let keep = |c: &char| !(o.no_look_alikes && LOOK_ALIKES.contains(*c));
    let sets: Vec<Vec<char>> = [
        (o.lower, LOWER),
        (o.upper, UPPER),
        (o.digits, DIGITS),
        (o.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, s)| s.chars().filter(keep).collect::<Vec<_>>())
    .filter(|s| !s.is_empty())
    .collect();
    if sets.is_empty() {
        return Err(GenError::NoCharacterSets);
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut out: Vec<char> = sets.iter().map(|s| s[below(s.len())]).collect();
    while out.len() < o.length {
        out.push(all[below(all.len())]);
    }
    // Shuffle so the guaranteed characters aren't always first.
    for i in (1..out.len()).rev() {
        out.swap(i, below(i + 1));
    }
    Ok(Secret::new(out.into_iter().collect::<String>()))
}

/// A random (version 4) GUID.
pub fn guid() -> String {
    let mut b = [0u8; 16];
    fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Base64Url,
    Hex,
}

pub const MIN_KEY_BYTES: usize = 16;
pub const MAX_KEY_BYTES: usize = 128;

/// An API key: `bytes` random bytes, optionally after a prefix.
pub fn api_key(bytes: usize, format: KeyFormat, prefix: &str) -> Result<Secret, GenError> {
    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&bytes) {
        return Err(GenError::Length);
    }
    let mut buf = vec![0u8; bytes];
    fill(&mut buf);
    let body = match format {
        KeyFormat::Base64Url => URL_SAFE_NO_PAD.encode(&buf),
        KeyFormat::Hex => buf.iter().map(|b| format!("{b:02x}")).collect(),
    };
    Ok(Secret::new(format!("{prefix}{body}")))
}

/// Prefixes may only use letters, digits, `_` and `-`, up to 16 characters.
pub fn is_valid_prefix(p: &str) -> bool {
    p.len() <= 16
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn password_length_and_sets() {
        for _ in 0..200 {
            let p = password(&PasswordOptions::default()).unwrap();
            let s = p.expose();
            assert_eq!(s.chars().count(), 24);
            assert!(s.chars().any(|c| c.is_ascii_lowercase()));
            assert!(s.chars().any(|c| c.is_ascii_uppercase()));
            assert!(s.chars().any(|c| c.is_ascii_digit()));
            assert!(s.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!s.chars().any(|c| LOOK_ALIKES.contains(c)));
        }
        let digits = PasswordOptions {
            lower: false,
            upper: false,
            symbols: false,
            length: 12,
            ..Default::default()
        };
        let s = password(&digits).unwrap();
        assert!(s.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn password_options_are_checked() {
        let none = PasswordOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(password(&none).err(), Some(GenError::NoCharacterSets));
        assert_eq!(
            password(&PasswordOptions {
                length: 4,
                ..Default::default()
            })
            .err(),
            Some(GenError::Length)
        );
        assert_eq!(
            password(&PasswordOptions {
                length: 300,
                ..Default::default()
            })
            .err(),
            Some(GenError::Length)
        );
    }

    #[test]
    fn values_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            assert!(
                seen.insert(
                    password(&PasswordOptions::default())
                        .unwrap()
                        .expose()
                        .to_owned()
                )
            );
            assert!(seen.insert(guid()));
            assert!(
                seen.insert(
                    api_key(32, KeyFormat::Base64Url, "")
                        .unwrap()
                        .expose()
                        .to_owned()
                )
            );
        }
    }

    #[test]
    fn guid_is_v4() {
        for _ in 0..100 {
            let g = guid();
            assert_eq!(g.len(), 36);
            assert_eq!(&g[14..15], "4");
            assert!(matches!(&g[19..20], "8" | "9" | "a" | "b"));
        }
    }

    #[test]
    fn api_keys() {
        let k = api_key(32, KeyFormat::Base64Url, "kr_").unwrap();
        assert!(k.expose().starts_with("kr_"));
        assert_eq!(k.expose().len(), 3 + 43);
        let k = api_key(16, KeyFormat::Hex, "").unwrap();
        assert_eq!(k.expose().len(), 32);
        assert!(k.expose().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(api_key(8, KeyFormat::Hex, "").err(), Some(GenError::Length));
        assert!(is_valid_prefix("sk_live-1"));
        assert!(!is_valid_prefix("bad prefix"));
        assert!(!is_valid_prefix(&"a".repeat(17)));
    }

    #[test]
    fn distribution_is_roughly_even() {
        // 6000 draws over 6 values: each should land near 1000.
        let mut counts = [0usize; 6];
        for _ in 0..6000 {
            counts[below(6)] += 1;
        }
        assert!(counts.iter().all(|c| (800..1200).contains(c)), "{counts:?}");
    }

    #[test]
    fn only_the_os_random_source_is_used() {
        let src = include_str!("generator.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        assert!(code.contains("SystemRandom::new()"));
        for weak in [
            "thread_rng",
            "SmallRng",
            "StdRng",
            "rand::random",
            "fastrand",
            "SystemTime",
        ] {
            assert!(!code.contains(weak), "generator must not use {weak}");
        }
    }
}
