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
    /// Keyed by [`Address::mailbox_key`], so a change of case or a `+tag`
    /// doesn't get a mailbox a second limit or a second place in the map.
    seen: Mutex<HashMap<(NotifyType, String), (Instant, u32)>>,
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
        let key = (kind, to.mailbox_key());
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

    /// Return a send taken by [`allow`](Self::allow) for an email that was
    /// then not queued, so it doesn't count against `to`. A window that has
    /// since started again is left alone.
    pub fn give_back(&self, kind: NotifyType, to: &Address) {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = seen.get_mut(&(kind, to.mailbox_key()))
            && Instant::now().duration_since(entry.0) < self.window
        {
            entry.1 = entry.1.saturating_sub(1);
        }
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
    fn case_and_plus_tags_share_one_limit_and_one_entry() {
        let r = RateLimit::new(2, Duration::from_secs(3600), 100);
        let t0 = Instant::now();
        assert!(r.allow_at(NotifyType::Expiry, &a("alex@example.com"), t0));
        assert!(r.allow_at(NotifyType::Expiry, &a("Alex@Example.com"), t0));
        for same in [
            "ALEX@example.com",
            "alex+1@example.com",
            "Alex+x+y@example.com",
        ] {
            assert!(!r.allow_at(NotifyType::Expiry, &a(same), t0), "{same}");
        }
        assert_eq!(r.tracked(), 1);
        // A different mailbox is still its own.
        assert!(r.allow_at(NotifyType::Expiry, &a("alexa@example.com"), t0));
    }

    #[test]
    fn a_send_given_back_can_be_taken_again() {
        let r = RateLimit::new(1, Duration::from_secs(3600), 100);
        let alex = a("alex@example.com");
        assert!(r.allow(NotifyType::Expiry, &alex));
        assert!(!r.allow(NotifyType::Expiry, &alex));
        r.give_back(NotifyType::Expiry, &a("Alex+x@example.com"));
        assert!(r.allow(NotifyType::Expiry, &alex));
        // Nothing to give back for a pair never taken, and never below zero.
        r.give_back(NotifyType::Health, &alex);
        r.give_back(NotifyType::Health, &alex);
        assert!(r.allow(NotifyType::Health, &alex));
        assert!(!r.allow(NotifyType::Health, &alex));
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
