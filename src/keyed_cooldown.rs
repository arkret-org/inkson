//! Small shared primitives for two patterns several inkson subsystems used to
//! hand-roll (arch-review D7):
//!
//! * [`KeyedCooldown`] — a `key → until_ms` table with expiry sweeping and an entry cap. Replaces
//!   the ad-hoc backoff tables in `key_backup/signing.rs` (key-backup unlock cooldown) and
//!   `app/mod.rs` (realm-key answer retry backoff).
//! * [`SeenSet`] — a `key → seen` single-flight set with an entry cap. Replaces the probe-guard set
//!   in `components/mls_backup_prompt.rs`.
//!
//! Both keep their bounds (expiry sweep + max entries) in one place so the four
//! call sites no longer each re-derive them.

use std::collections::{BTreeMap, BTreeSet};

/// A `key → until_ms` cooldown table.
///
/// `until_ms` is an absolute wall-clock instant (the same millisecond clock the
/// callers already use, e.g. `crate::clock::now_unix_ms()`). Lookups prune
/// elapsed entries; inserts enforce a max-entry cap so a churning key space
/// cannot grow the table without bound.
#[derive(Clone, Debug)]
pub struct KeyedCooldown {
    until_ms: BTreeMap<String, u64>,
    max_entries: usize,
}

impl KeyedCooldown {
    /// Create an empty cooldown table bounded to `max_entries`.
    pub const fn new(max_entries: usize) -> Self {
        Self {
            until_ms: BTreeMap::new(),
            max_entries,
        }
    }

    /// Record a cooldown for `key` lasting until the absolute `until_ms`.
    /// Replaces any existing entry for `key` and enforces the entry cap.
    pub fn note_until(&mut self, key: impl Into<String>, until_ms: u64) {
        self.until_ms.insert(key.into(), until_ms);
        self.enforce_cap();
    }

    /// Remaining cooldown for `key` at `now_ms`, or `None` when it is not
    /// cooling. Prunes elapsed entries as a side effect.
    pub fn remaining_ms(&mut self, key: &str, now_ms: u64) -> Option<u64> {
        self.prune(now_ms);
        self.until_ms
            .get(key)
            .map(|until| until.saturating_sub(now_ms))
    }

    /// Forget every cooldown.
    pub fn clear(&mut self) {
        self.until_ms.clear();
    }

    /// Remove every entry whose cooldown has elapsed at `now_ms`.
    pub fn prune(&mut self, now_ms: u64) {
        self.until_ms.retain(|_, until| *until > now_ms);
    }

    /// Number of live (possibly-elapsed-but-not-yet-pruned) entries.
    pub fn len(&self) -> usize {
        self.until_ms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until_ms.is_empty()
    }

    fn enforce_cap(&mut self) {
        while self.until_ms.len() > self.max_entries {
            // Evict the entry that expires soonest: it would free itself first
            // anyway, so dropping it early is the least-surprising bound.
            let Some(victim) = self
                .until_ms
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.until_ms.remove(&victim);
        }
    }
}

/// A `key → seen` single-flight set with an entry cap.
///
/// [`SeenSet::mark`] returns whether the key was newly inserted, so the caller
/// that observes `true` is the single-flight winner. The cap bounds a churning
/// key space; when it is exceeded the oldest-ordered key is evicted (a re-seen
/// key can at worst fire once more, so the eviction victim is not critical).
#[derive(Clone, Debug)]
pub struct SeenSet {
    seen: BTreeSet<String>,
    max_entries: usize,
}

impl SeenSet {
    /// Create an empty seen-set bounded to `max_entries`.
    pub const fn new(max_entries: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            max_entries,
        }
    }

    /// Mark `key` as seen. Returns `true` when it was newly inserted (the
    /// caller is the single-flight winner), `false` when already present.
    pub fn mark(&mut self, key: impl Into<String>) -> bool {
        let inserted = self.seen.insert(key.into());
        if inserted {
            self.enforce_cap();
        }
        inserted
    }

    /// Whether `key` has already been seen.
    pub fn contains(&self, key: &str) -> bool {
        self.seen.contains(key)
    }

    /// Forget `key`, allowing the next [`SeenSet::mark`] to win again.
    pub fn forget(&mut self, key: &str) -> bool {
        self.seen.remove(key)
    }

    /// Forget every key.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn enforce_cap(&mut self) {
        while self.seen.len() > self.max_entries {
            let Some(victim) = self.seen.iter().next().cloned() else {
                break;
            };
            self.seen.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_reports_and_prunes_by_expiry() {
        let mut cooldown = KeyedCooldown::new(8);
        cooldown.note_until("a", 1_000);
        assert_eq!(cooldown.remaining_ms("a", 400), Some(600));
        // At/after the deadline the entry is not cooling and gets pruned.
        assert_eq!(cooldown.remaining_ms("a", 1_000), None);
        assert!(cooldown.is_empty());
    }

    #[test]
    fn cooldown_enforces_cap_evicting_soonest_expiry() {
        let mut cooldown = KeyedCooldown::new(2);
        cooldown.note_until("soonest", 10);
        cooldown.note_until("mid", 20);
        cooldown.note_until("latest", 30);
        // "soonest" is evicted; the two later deadlines survive.
        assert_eq!(cooldown.len(), 2);
        assert_eq!(cooldown.remaining_ms("soonest", 0), None);
        assert_eq!(cooldown.remaining_ms("mid", 0), Some(20));
        assert_eq!(cooldown.remaining_ms("latest", 0), Some(30));
    }

    #[test]
    fn seen_set_marks_once_and_forgets() {
        let mut seen = SeenSet::new(8);
        assert!(seen.mark("k"));
        assert!(!seen.mark("k"));
        assert!(seen.contains("k"));
        assert!(seen.forget("k"));
        assert!(seen.mark("k"));
    }

    #[test]
    fn seen_set_enforces_cap() {
        let mut seen = SeenSet::new(2);
        seen.mark("a");
        seen.mark("b");
        seen.mark("c");
        assert_eq!(seen.len(), 2);
    }
}
