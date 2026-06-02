//! Input-path perf helpers: debounce + typing throttle hooks.
//!
//! The composer hot paths (Timeline / Chat) used to do real work on *every*
//! keystroke — persist the whole local draft state to disk/localStorage and
//! POST a `cx.typing` ephemeral to the server. On normal typing that is one
//! synchronous serialize + one network request per character. These hooks
//! collapse that into:
//!
//! * **draft save** — a trailing debounce (`use_debouncer`): the local `draft`
//!   signal still updates instantly for responsiveness, but the persist only
//!   runs after the user pauses.
//! * **typing** — a leading-edge throttle + trailing stop (`use_typing_throttle`):
//!   emit `typing=true` at most once per `active` window, then emit
//!   `typing=false` once the user has been quiet for `stop`.
//!
//! Both are timer-driven with a monotonically increasing generation token, so
//! stale spawned tasks observe the bumped generation and exit instead of firing
//! — no timer handles to track, wasm- and desktop-safe via [`crate::api::sleep_for`].

use std::time::Duration;

use dioxus::prelude::*;

/// Trailing-edge debouncer. Each [`Debouncer::call`] cancels any pending run
/// and schedules `action` to run after `delay_ms` of quiet.
#[derive(Clone, Copy)]
pub struct Debouncer {
    generation: Signal<u64>,
    delay_ms: u32,
}

/// Create a [`Debouncer`] that fires `delay_ms` after the last `call`.
pub fn use_debouncer(delay_ms: u32) -> Debouncer {
    Debouncer {
        generation: use_signal(|| 0u64),
        delay_ms,
    }
}

impl Debouncer {
    /// Schedule `action` to run after `delay_ms` of no further calls.
    pub fn call<F>(&self, action: F)
    where
        F: FnOnce() + 'static,
    {
        let mut generation = self.generation;
        let my_gen = generation().wrapping_add(1);
        generation.set(my_gen);
        let delay = u64::from(self.delay_ms);
        spawn(async move {
            crate::api::sleep_for(Duration::from_millis(delay)).await;
            // A newer keystroke bumped the generation — this run is stale.
            if generation() == my_gen {
                action();
            }
        });
    }
}

/// Leading-edge throttle for "is typing" signals, with a trailing "stopped
/// typing" emit. `emit(true)` fires immediately on the first keystroke of a
/// burst and at most once per `active` window; `emit(false)` fires once the
/// user has been quiet for `stop`.
#[derive(Clone, Copy)]
pub struct TypingThrottle {
    cooldown: Signal<bool>,
    stop_generation: Signal<u64>,
    active_ms: u32,
    stop_ms: u32,
}

/// Create a [`TypingThrottle`]. `active_ms` is the minimum gap between
/// `typing=true` emits; `stop_ms` is the quiet period before `typing=false`.
pub fn use_typing_throttle(active_ms: u32, stop_ms: u32) -> TypingThrottle {
    TypingThrottle {
        cooldown: use_signal(|| false),
        stop_generation: use_signal(|| 0u64),
        active_ms,
        stop_ms,
    }
}

impl TypingThrottle {
    /// Call once per keystroke. `emit` performs the actual (async) send —
    /// typically by spawning a `send_typing` request; it is invoked with
    /// `true` on the throttled leading edge and `false` on the debounced stop.
    pub fn on_keystroke<E>(&self, emit: E)
    where
        E: Fn(bool) + Clone + 'static,
    {
        // Leading edge: only emit `true` when not already inside a cooldown
        // window, then hold the cooldown for `active_ms`.
        let mut cooldown = self.cooldown;
        if !cooldown() {
            cooldown.set(true);
            emit(true);
            let active = u64::from(self.active_ms);
            spawn(async move {
                crate::api::sleep_for(Duration::from_millis(active)).await;
                cooldown.set(false);
            });
        }

        // Trailing stop: debounce a `false` emit to fire after the burst ends.
        let mut stop_generation = self.stop_generation;
        let my_gen = stop_generation().wrapping_add(1);
        stop_generation.set(my_gen);
        let stop = u64::from(self.stop_ms);
        let emit_stop = emit.clone();
        spawn(async move {
            crate::api::sleep_for(Duration::from_millis(stop)).await;
            if stop_generation() == my_gen {
                emit_stop(false);
            }
        });
    }
}
