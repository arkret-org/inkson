use std::time::Duration;

// `tokio::time::sleep` reads `std::time::Instant::now()` and panics on
// wasm32-unknown-unknown ("time not implemented on this platform"). Route the
// wasm build through `gloo_timers::future::TimeoutFuture`, which is backed by
// `setTimeout`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep_for(delay: Duration) {
    let ms = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);
    gloo_timers::future::TimeoutFuture::new(ms).await;
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
