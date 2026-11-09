//! Randomness and authenticated encryption for short-lived cookies.
//!
//! Uses `ring`, which is already in the tree as the rustls crypto provider.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

use crate::secret::Secret;

/// `n` random bytes from the operating system, base64url encoded.
pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut buf)
        .expect("the operating system random number generator failed");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Compare two byte strings without stopping at the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| acc | std::hint::black_box(x ^ y));
    diff == 0
}

/// Seals and opens values with AES-256-GCM. The key is derived from
/// `SESSION_SECRET` with HKDF-SHA256, and the cookie name is bound in as
/// associated data so one cookie can't be swapped for another.
pub struct Sealer {
    key: LessSafeKey,
}

struct KeyLen;
impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        32
    }
}

impl Sealer {
    pub fn new(secret: &Secret, purpose: &str) -> Self {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"keyring cookie v1");
        let prk = salt.extract(secret.expose().as_bytes());
        let info = [purpose.as_bytes()];
        let okm = prk.expand(&info, KeyLen).expect("valid HKDF length");
        let mut bytes = [0u8; 32];
        okm.fill(&mut bytes).expect("valid HKDF length");
        let key = UnboundKey::new(&AES_256_GCM, &bytes).expect("valid AES-256 key");
        Self {
            key: LessSafeKey::new(key),
        }
    }

    /// Encrypt `plain`, returning base64url `nonce || ciphertext || tag`.
    pub fn seal(&self, aad: &str, plain: &[u8]) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("the operating system random number generator failed");
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_bytes()),
                &mut buf,
            )
            .expect("AES-GCM sealing can't fail for small inputs");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Decrypt a value from [`Sealer::seal`]. `None` if it was tampered with,
    /// sealed with another key or for another purpose.
    pub fn open(&self, aad: &str, sealed: &str) -> Option<Vec<u8>> {
        let raw = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = rest.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
            .ok()?;
        Some(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer(secret: &str) -> Sealer {
        Sealer::new(&Secret::new(secret), "test")
    }

    #[test]
    fn round_trips() {
        let s = sealer("0123456789abcdef0123456789abcdef");
        let sealed = s.seal("name", b"hello");
        assert_eq!(s.open("name", &sealed).unwrap(), b"hello");
    }

    #[test]
    fn rejects_tampering_wrong_key_and_wrong_name() {
        let s = sealer("0123456789abcdef0123456789abcdef");
        let sealed = s.seal("name", b"hello");
        assert!(s.open("other", &sealed).is_none());
        assert!(
            sealer("ffffffffffffffffffffffffffffffff")
                .open("name", &sealed)
                .is_none()
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(s.open("name", &URL_SAFE_NO_PAD.encode(bytes)).is_none());
        assert!(s.open("name", "not base64!").is_none());
        assert!(s.open("name", "").is_none());
    }

    #[test]
    fn tokens_are_random_and_long_enough() {
        let a = random_token(32);
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_token(32));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
