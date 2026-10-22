use std::time::Duration;

/// Register the task with the scope that owns its signals. Runtime::spawn
/// alone does not register scope cancellation and can outlive those signals.
pub(crate) fn spawn_owned(
    scope: dioxus::core::ScopeId,
    future: impl std::future::Future<Output = ()> + 'static,
) -> dioxus::core::Task {
    dioxus::core::Runtime::current().in_scope(scope, || dioxus::core::spawn(future))
}

// `tokio::time::sleep` reads `std::time::Instant::now()` and panics on
// wasm32-unknown-unknown ("time not implemented on this platform"). Route the
// wasm build through a cancellation-safe `setTimeout` future. The stock
// `gloo_timers::future::TimeoutFuture` calls `unwrap_throw()` when its callback
// races a dropped receiver. Dioxus routinely cancels effects during a route or
// session-state transition, so that otherwise-benign race can abort the whole
// wasm instance and leave the browser tab unresponsive.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep_for(delay: Duration) {
    let ms = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);
    BrowserTimeout::new(ms).await;
}

#[cfg(target_arch = "wasm32")]
struct BrowserTimeout {
    state: std::rc::Rc<std::cell::RefCell<BrowserTimeoutState>>,
    _timeout: gloo_timers::callback::Timeout,
}

#[cfg(target_arch = "wasm32")]
#[derive(Default)]
struct BrowserTimeoutState {
    fired: bool,
    waker: Option<std::task::Waker>,
}

#[cfg(target_arch = "wasm32")]
impl BrowserTimeout {
    fn new(milliseconds: u32) -> Self {
        let state = std::rc::Rc::new(std::cell::RefCell::new(BrowserTimeoutState::default()));
        let callback_state = std::rc::Rc::clone(&state);
        let timeout = gloo_timers::callback::Timeout::new(milliseconds, move || {
            let waker = {
                let mut state = callback_state.borrow_mut();
                state.fired = true;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        });
        Self {
            state,
            _timeout: timeout,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl std::future::Future for BrowserTimeout {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut state = self.state.borrow_mut();
        if state.fired {
            std::task::Poll::Ready(())
        } else {
            if state
                .waker
                .as_ref()
                .is_none_or(|waker| !waker.will_wake(context.waker()))
            {
                state.waker = Some(context.waker().clone());
            }
            std::task::Poll::Pending
        }
    }
}

/// Advance a reconnect ladder only while the generation-scoped engine is
/// still active. Keeping this decision shared prevents an ended HTTP body from
/// permanently killing a Signal or Realm rail, while profile/session/route
/// cancellation still terminates immediately.
pub(crate) fn next_reconnect_delay(
    active: bool,
    backoff: &mut garth::RetrySchedule,
) -> Option<Duration> {
    active.then(|| backoff.next_delay())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use dioxus::prelude::*;

    use super::*;

    #[derive(Clone, PartialEq)]
    struct Probe {
        mounted: Rc<RefCell<Option<Signal<bool>>>>,
        scopes: Rc<Cell<Option<(ScopeId, ScopeId)>>>,
        dropped: Rc<Cell<bool>>,
    }

    struct PendingWrite {
        value: Signal<u32>,
        probe: Probe,
    }

    impl std::future::Future for PendingWrite {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.probe.scopes.set(Some((
                dioxus::core::current_scope_id(),
                self.value.origin_scope(),
            )));
            self.value.set(1);
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingWrite {
        fn drop(&mut self) {
            self.probe.dropped.set(true);
        }
    }

    #[component]
    fn SignalOwner(probe: Probe) -> Element {
        let value = use_signal(|| 0);
        use_hook(move || {
            spawn_owned(value.origin_scope(), PendingWrite { value, probe });
        });
        rsx! { div { "{value}" } }
    }

    fn lifecycle_root(probe: Probe) -> Element {
        let mounted = use_signal(|| true);
        *probe.mounted.borrow_mut() = Some(mounted);
        rsx! { if mounted() { SignalOwner { probe } } }
    }

    #[test]
    fn owned_task_updates_live_signals_and_cancels_on_owner_unmount() {
        let probe = Probe {
            mounted: Rc::new(RefCell::new(None)),
            scopes: Rc::new(Cell::new(None)),
            dropped: Rc::new(Cell::new(false)),
        };
        let mut dom = VirtualDom::new_with_props(lifecycle_root, probe.clone());
        dom.rebuild_in_place();
        dom.render_immediate_to_vec();
        let (task_scope, signal_scope) = probe.scopes.get().expect("task writes while mounted");
        assert_eq!(task_scope, signal_scope);
        assert_ne!(task_scope, ScopeId::ROOT);
        assert!(!probe.dropped.get());
        dom.in_runtime(|| probe.mounted.borrow().unwrap().set(false));
        dom.render_immediate_to_vec();
        assert!(
            probe.dropped.get(),
            "owner unmount must cancel the pending write"
        );
    }

    #[test]
    fn reconnect_ladder_retries_active_engines_but_never_cancelled_ones() {
        let mut backoff = garth::RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(4));
        assert_eq!(
            next_reconnect_delay(true, &mut backoff),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            next_reconnect_delay(true, &mut backoff),
            Some(Duration::from_secs(2))
        );
        assert_eq!(next_reconnect_delay(false, &mut backoff), None);
        assert_eq!(
            next_reconnect_delay(true, &mut backoff),
            Some(Duration::from_secs(4)),
            "a cancelled check must not advance the retry ladder"
        );
    }
}
