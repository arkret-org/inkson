use dioxus::prelude::*;

/// The caller keys this host by the complete authoring session and source target.
/// The latch retains only component lifetime, never a previous authority basis.
#[component]
pub(crate) fn RetainedDiscussionHost(ready: bool, children: Element) -> Element {
    let mut mounted = use_signal(|| ready);
    if ready && !*mounted.peek() {
        mounted.set(true);
    }
    if mounted() {
        children
    } else {
        rsx! {}
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[derive(Clone, PartialEq)]
    struct Probe {
        initial_ready: bool,
        ready: Rc<RefCell<Option<Signal<bool>>>>,
        target: Rc<RefCell<Option<Signal<String>>>>,
        draft: Rc<RefCell<Option<Signal<String>>>>,
        owners: Rc<Cell<usize>>,
        controls: Rc<Cell<usize>>,
        controls_dropped: Rc<Cell<usize>>,
        cancelled: Rc<Cell<usize>>,
        scopes: Rc<Cell<Option<(ScopeId, ScopeId)>>>,
    }

    impl Probe {
        fn new(initial_ready: bool) -> Self {
            Self {
                initial_ready,
                ready: Default::default(),
                target: Default::default(),
                draft: Default::default(),
                owners: Default::default(),
                controls: Default::default(),
                controls_dropped: Default::default(),
                cancelled: Default::default(),
                scopes: Default::default(),
            }
        }
    }

    struct PendingSend {
        pending: Signal<bool>,
        probe: Probe,
    }

    impl std::future::Future for PendingSend {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.probe.scopes.set(Some((
                dioxus::core::current_scope_id(),
                self.pending.origin_scope(),
            )));
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingSend {
        fn drop(&mut self) {
            self.probe.cancelled.set(self.probe.cancelled.get() + 1);
        }
    }

    #[component]
    fn Controls(probe: Probe, pending: Signal<bool>) -> Element {
        use_drop({
            let probe = probe.clone();
            move || probe.controls_dropped.set(probe.controls_dropped.get() + 1)
        });
        use_hook(move || {
            probe.controls.set(probe.controls.get() + 1);
            if !*pending.peek() {
                let mut pending = pending;
                pending.set(true);
                crate::runtime_helpers::spawn_owned(
                    pending.origin_scope(),
                    PendingSend { pending, probe },
                );
            }
        });
        rsx! { button { "Send" } }
    }

    #[component]
    fn TargetOwner(probe: Probe, suspended: bool) -> Element {
        let draft = use_signal(|| "unsent draft".to_owned());
        let pending = use_signal(|| false);
        *probe.draft.borrow_mut() = Some(draft);
        use_hook({
            let probe = probe.clone();
            move || probe.owners.set(probe.owners.get() + 1)
        });
        if suspended {
            return rsx! {};
        }
        rsx! { Controls { probe, pending } }
    }

    fn root(probe: Probe) -> Element {
        let ready = use_signal(|| probe.initial_ready);
        let target = use_signal(|| "session/account/device/realm/strand-a".to_owned());
        *probe.ready.borrow_mut() = Some(ready);
        *probe.target.borrow_mut() = Some(target);
        rsx! {
            for host_key in [target()] {
                RetainedDiscussionHost {
                    key: "{host_key}",
                    ready: ready(),
                    TargetOwner { probe: probe.clone(), suspended: !ready() }
                }
            }
        }
    }

    fn set_ready(dom: &mut VirtualDom, probe: &Probe, ready: bool) {
        dom.in_runtime(|| probe.ready.borrow().unwrap().set(ready));
        dom.render_immediate_to_vec();
    }

    #[test]
    fn missing_initial_current_never_mounts_the_discussion_owner() {
        let probe = Probe::new(false);
        let mut dom = VirtualDom::new_with_props(root, probe.clone());
        dom.rebuild_in_place();
        dom.render_immediate_to_vec();
        assert_eq!(probe.owners.get(), 0);
        assert_eq!(probe.controls.get(), 0);
        set_ready(&mut dom, &probe, true);
        assert_eq!(probe.owners.get(), 1);
        assert_eq!(probe.controls.get(), 1);
    }

    #[test]
    fn temporary_current_gap_hides_controls_but_keeps_draft_and_pending_send() {
        let probe = Probe::new(true);
        let mut dom = VirtualDom::new_with_props(root, probe.clone());
        dom.rebuild_in_place();
        dom.render_immediate_to_vec();
        let original_draft = probe.draft.borrow().unwrap();
        dom.in_runtime(|| {
            probe
                .draft
                .borrow()
                .unwrap()
                .set("captured private draft".into());
        });
        set_ready(&mut dom, &probe, false);
        assert_eq!(probe.owners.get(), 1);
        assert_eq!(probe.cancelled.get(), 0);
        assert_eq!(probe.controls_dropped.get(), 1);
        dom.in_runtime(|| assert_eq!(*original_draft.peek(), "captured private draft"));
        let (task, owner) = probe.scopes.get().expect("pending send was polled");
        assert_eq!(task, owner);
        assert_ne!(owner, ScopeId::ROOT);
        set_ready(&mut dom, &probe, true);
        assert_eq!(probe.owners.get(), 1);
        assert_eq!(probe.controls.get(), 2);
        assert_eq!(probe.cancelled.get(), 0);
        assert_eq!(probe.draft.borrow().unwrap(), original_draft);
        drop(dom);
        assert_eq!(probe.cancelled.get(), 1);
    }

    #[test]
    fn target_change_cancels_old_send_and_does_not_borrow_old_ready_state() {
        let probe = Probe::new(true);
        let mut dom = VirtualDom::new_with_props(root, probe.clone());
        dom.rebuild_in_place();
        dom.render_immediate_to_vec();
        dom.in_runtime(|| {
            probe.ready.borrow().unwrap().set(false);
            probe
                .target
                .borrow()
                .unwrap()
                .set("replacement-session-or-target".into());
        });
        dom.render_immediate_to_vec();
        assert_eq!(probe.cancelled.get(), 1);
        assert_eq!(probe.owners.get(), 1);
        set_ready(&mut dom, &probe, true);
        assert_eq!(probe.owners.get(), 2);
        dom.in_runtime(|| assert_eq!(*probe.draft.borrow().unwrap().peek(), "unsent draft"));
    }
}
