use std::time::Duration;

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
pub(crate) fn next_reconnect_delay(active: bool, backoff: &mut garth::Backoff) -> Option<Duration> {
    active.then(|| backoff.next_delay())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_ladder_retries_active_engines_but_never_cancelled_ones() {
        let mut backoff = garth::Backoff::new(Duration::from_secs(1), Duration::from_secs(4));
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
