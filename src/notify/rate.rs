//! The rate limit: at most N emails an hour to one recipient for one
//! notification type, so an alert storm or a misused tag can't mail-bomb
//! anyone.
//!
//! In memory, so a restart resets it. The map is bounded: when it is full,
//! entries whose window has passed are cleared first, and if it is still
//! full a new recipient is refused (counted as limited) rather than an old
//! one forgotten, so filling the map can't reset someone's limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{Address, NotifyType};

/// Default emails an hour to one recipient for one type.
pub const DEFAULT_PER_HOUR: u32 = 20;

/// Most recipient and type pairs tracked at once.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// A fixed one-hour window per recipient and type.
pub struct RateLimit {
    per_window: u32,
    window: Duration,
    max_entries: usize,
    seen: Mutex<HashMap<(NotifyType, Address), (Instant, u32)>>,
}

impl std::fmt::Debug for RateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimit")
            .field("per_window", &self.per_window)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl RateLimit {
    pub fn new(per_window: u32, window: Duration, max_entries: usize) -> Self {
        Self {
            per_window,
            window,
            max_entries: max_entries.max(1),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// The default: 20 an hour, 10,000 pairs.
    pub fn hourly(per_hour: u32) -> Self {
        Self::new(per_hour, Duration::from_secs(3600), DEFAULT_MAX_ENTRIES)
    }

    /// Take one send for `to` and `kind`. False when over the limit.
    pub fn allow(&self, kind: NotifyType, to: &Address) -> bool {
        self.allow_at(kind, to, Instant::now())
    }

    fn allow_at(&self, kind: NotifyType, to: &Address, now: Instant) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (kind, to.clone());
        if !seen.contains_key(&key) && seen.len() >= self.max_entries {
            let window = self.window;
            seen.retain(|_, (start, _)| now.duration_since(*start) < window);
            if seen.len() >= self.max_entries {
                return false;
            }
        }
        let entry = seen.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_window {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Pairs tracked now.
    pub fn tracked(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    #[test]
    fn limits_each_recipient_and_type_and_resets_after_the_window() {
        let r = RateLimit::new(2, Duration::from_secs(3600), 100);
        let t0 = Instant::now();
        let alex = a("alex@example.com");
        assert!(r.allow_at(NotifyType::Expiry, &alex, t0));
        assert!(r.allow_at(NotifyType::Expiry, &alex, t0));
        assert!(!r.allow_at(NotifyType::Expiry, &alex, t0));
        // Another type and another person have their own count.
        assert!(r.allow_at(NotifyType::Health, &alex, t0));
        assert!(r.allow_at(NotifyType::Expiry, &a("sam@example.com"), t0));
        let later = t0 + Duration::from_secs(3600);
        assert!(r.allow_at(NotifyType::Expiry, &alex, later));
    }

    #[test]
    fn the_map_is_bounded_and_full_refuses_new_pairs() {
        let r = RateLimit::new(5, Duration::from_secs(3600), 3);
        let t0 = Instant::now();
        for n in 0..3 {
            assert!(r.allow_at(NotifyType::Expiry, &a(&format!("u{n}@example.com")), t0));
        }
        assert!(!r.allow_at(NotifyType::Expiry, &a("new@example.com"), t0));
        assert_eq!(r.tracked(), 3);
        // A known pair still works.
        assert!(r.allow_at(NotifyType::Expiry, &a("u0@example.com"), t0));
        // Once the old windows pass, room is made.
        let later = t0 + Duration::from_secs(3601);
        assert!(r.allow_at(NotifyType::Expiry, &a("new@example.com"), later));
        assert_eq!(r.tracked(), 1);
    }
}
