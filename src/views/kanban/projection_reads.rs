//! One pending revision behind one in-flight projection read.

pub(super) struct ProjectionReadOwner<S, K> {
    scope: Option<S>,
    task: Option<dioxus::core::Task>,
    pub(super) queue: ProjectionReadQueue<K>,
    covered: ProjectionReadSet,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProjectionReadSet {
    pub spaces: bool,
    pub strands: bool,
}

impl ProjectionReadSet {
    pub(super) const fn all() -> Self {
        Self {
            spaces: true,
            strands: true,
        }
    }
    pub(super) fn any(self) -> bool {
        self.spaces || self.strands
    }
}

impl<S, K> Default for ProjectionReadOwner<S, K> {
    fn default() -> Self {
        Self {
            scope: None,
            task: None,
            queue: ProjectionReadQueue::default(),
            covered: ProjectionReadSet::default(),
        }
    }
}

impl<S: PartialEq, K> ProjectionReadOwner<S, K> {
    /// Retire the actual future before another account or target starts work.
    pub(super) fn set_scope(&mut self, scope: Option<S>) -> bool {
        if self.scope == scope {
            return false;
        }
        self.cancel_pending();
        self.covered = ProjectionReadSet::default();
        self.scope = scope;
        true
    }

    pub(super) fn attach(&mut self, task: dioxus::core::Task) {
        self.task = Some(task);
    }

    pub(super) fn finish(&mut self) {
        self.task = None;
    }

    pub(super) fn cancel_pending(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel();
        }
        self.queue = ProjectionReadQueue::default();
    }

    pub(super) fn missing(&self) -> ProjectionReadSet {
        ProjectionReadSet {
            spaces: !self.covered.spaces,
            strands: !self.covered.strands,
        }
    }

    pub(super) fn cover(&mut self, material: ProjectionReadSet) {
        self.covered.spaces |= material.spaces;
        self.covered.strands |= material.strands;
    }
}

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

    #[test]
    fn only_missing_material_is_requested_and_coverage_never_crosses_scopes() {
        let mut reads = ProjectionReadOwner::<&str, u64>::default();
        reads.set_scope(Some("alice"));
        assert_eq!(reads.missing(), ProjectionReadSet::all());
        reads.cover(ProjectionReadSet {
            spaces: false,
            strands: true,
        });
        assert_eq!(
            reads.missing(),
            ProjectionReadSet {
                spaces: true,
                strands: false
            }
        );
        reads.cancel_pending();
        assert!(reads.missing().spaces);
        assert!(!reads.missing().strands);
        reads.cover(ProjectionReadSet::all());
        for _ in 0..20 {
            assert!(!reads.missing().any());
        }
        reads.set_scope(Some("bob"));
        assert_eq!(reads.missing(), ProjectionReadSet::all());
    }

    #[test]
    fn replacing_scope_cancels_the_future_and_allows_immediate_new_work() {
        use std::cell::Cell;
        use std::rc::Rc;

        use dioxus::prelude::*;
        use futures_util::FutureExt;

        struct Dropped(Rc<Cell<bool>>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        let started = Rc::new(Cell::new(false));
        let dropped = Rc::new(Cell::new(false));
        let mut reads = ProjectionReadOwner::<&str, u64>::default();
        assert!(reads.set_scope(Some("alice/realm-a")));
        assert!(reads.queue.request(1));
        assert_eq!(reads.queue.next(), Some(1));
        let task = dom.in_scope(ScopeId::ROOT, || {
            spawn({
                let started = started.clone();
                let dropped = dropped.clone();
                async move {
                    let _guard = Dropped(dropped);
                    started.set(true);
                    futures_util::future::pending::<()>().await;
                }
            })
        });
        reads.attach(task);
        for _ in 0..4 {
            let _ = dom.wait_for_work().now_or_never();
            if started.get() {
                break;
            }
        }
        assert!(started.get());
        assert!(!reads.set_scope(Some("alice/realm-a")));
        assert!(!dropped.get(), "a same-scope update must keep its reader");
        assert!(!reads.queue.request(2));
        dom.in_scope(ScopeId::ROOT, || {
            assert!(reads.set_scope(Some("bob/realm-b")));
        });
        assert!(
            dropped.get(),
            "the pending response future must actually drop"
        );
        assert!(
            reads.queue.request(1),
            "the old worker cannot block a new scope"
        );
        assert_eq!(reads.queue.next(), Some(1));
        assert_eq!(reads.queue.next(), None, "old dirty work must not survive");
    }
}
