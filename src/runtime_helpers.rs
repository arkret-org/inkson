use std::time::Duration;

/// Bind cancellation to the explicit owner of the state used by this task.
pub(crate) fn spawn_owned(
    scope: &glory::Scope,
    future: impl std::future::Future<Output = ()> + 'static,
) -> std::result::Result<glory::core::TaskToken, glory::core::AccessError> {
    scope.owner().spawn(future)
}

// `tokio::time::sleep` reads `std::time::Instant::now()` and panics on
// wasm32-unknown-unknown ("time not implemented on this platform"). Route the
// wasm build through a cancellation-safe `setTimeout` future. The stock
// `gloo_timers::future::TimeoutFuture` calls `unwrap_throw()` when its callback
// races a dropped receiver. The UI owner cancels effects during a route or
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

    use super::*;

    #[derive(Default)]
    struct Executor(RefCell<Vec<Rc<RefCell<Option<glory::core::LocalFuture>>>>>);
    impl glory::core::Host for Executor {
        fn spawn(
            &self,
            future: glory::core::LocalFuture,
        ) -> std::result::Result<Box<dyn FnOnce()>, glory::core::HostError> {
            let task = Rc::new(RefCell::new(Some(future)));
            self.0.borrow_mut().push(task.clone());
            Ok(Box::new(move || {
                task.borrow_mut().take();
            }))
        }
        fn wake(&self) {}
        fn now(&self) -> Duration {
            Duration::ZERO
        }
    }
    struct PendingWrite {
        value: glory::Cage<u32>,
        dropped: Rc<Cell<bool>>,
    }
    impl std::future::Future for PendingWrite {
        type Output = ();
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.value.revise(|value| *value = 1);
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingWrite {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }
    #[test]
    fn owned_task_updates_live_state_and_cancels_on_owner_unmount() {
        let executor = Rc::new(Executor::default());
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let child = app.scope().child().unwrap();
        let value = child.cage(0_u32);
        let dropped = Rc::new(Cell::new(false));
        spawn_owned(
            &child,
            PendingWrite {
                value,
                dropped: dropped.clone(),
            },
        )
        .unwrap();
        let task = executor.0.borrow()[0].clone();
        let _ = task
            .borrow_mut()
            .as_mut()
            .unwrap()
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert_eq!(value.get(), 1);
        assert!(!dropped.get());
        child.dispose();
        assert!(
            dropped.get(),
            "retiring the child must drop its pending state writer"
        );
        assert!(app.scope().is_alive());
        assert!(matches!(
            spawn_owned(&child, async {}),
            Err(glory::core::AccessError::Disposed)
        ));
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
