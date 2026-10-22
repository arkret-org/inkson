//! One pending revision behind one in-flight projection read.

pub(super) struct ProjectionReadQueue<K> {
    last_requested: Option<K>,
    pending: Option<K>,
    running: bool,
}

impl<K> Default for ProjectionReadQueue<K> {
    fn default() -> Self {
        Self {
            last_requested: None,
            pending: None,
            running: false,
        }
    }
}

impl<K: Clone + PartialEq> ProjectionReadQueue<K> {
    /// Returns true only to the caller that must start the worker.
    pub(super) fn request(&mut self, key: K) -> bool {
        if self.last_requested.as_ref() == Some(&key) {
            return false;
        }
        self.last_requested = Some(key.clone());
        self.pending = Some(key);
        if self.running {
            false
        } else {
            self.running = true;
            true
        }
    }

    pub(super) fn next(&mut self) -> Option<K> {
        let next = self.pending.take();
        if next.is_none() {
            self.running = false;
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_duplicate_hints_share_one_worker() {
        let mut reads = ProjectionReadQueue::default();
        assert!(reads.request(("alice", 0)));
        assert!(!reads.request(("alice", 0)));
        assert_eq!(reads.next(), Some(("alice", 0)));
        assert!(!reads.request(("alice", 0)));
        assert_eq!(reads.next(), None);
        assert!(!reads.request(("alice", 0)));
    }

    #[test]
    fn burst_keeps_only_the_latest_dirty_revision() {
        let mut reads = ProjectionReadQueue::default();
        assert!(reads.request(0));
        assert_eq!(reads.next(), Some(0));
        for revision in 1..=1_000 {
            assert!(!reads.request(revision));
        }
        assert_eq!(reads.next(), Some(1_000));
        assert_eq!(reads.next(), None);
        assert!(reads.request(1_001));
    }

    #[test]
    fn new_scope_supersedes_pending_old_scope() {
        let mut reads = ProjectionReadQueue::default();
        assert!(reads.request(("alice", 0)));
        assert_eq!(reads.next(), Some(("alice", 0)));
        assert!(!reads.request(("alice", 1)));
        assert!(!reads.request(("bob", 0)));
        assert_eq!(reads.next(), Some(("bob", 0)));
        assert_eq!(reads.next(), None);
    }
}
