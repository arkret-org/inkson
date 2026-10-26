//! Input-path perf helpers: debounce + typing throttle hooks.
//!
//! The composer hot paths used to do real work on *every*
//! keystroke — persist the whole local draft state to disk/localStorage and
//! POST a `ak.typing` ephemeral to the server. On normal typing that is one
//! synchronous serialize + one network request per character. These hooks
//! collapse that into:
//!
//! * **draft save** — a trailing debounce (`use_debouncer`): the local `draft` signal still updates
//!   instantly for responsiveness, but the persist only runs after the user pauses.
//! * **typing** — a leading-edge throttle + trailing stop (`use_typing_throttle`): emit
//!   `typing=true` at most once per `active` window, then emit `typing=false` once the user has
//!   been quiet for `stop`.
//!
//! Both are timer-driven with a monotonically increasing generation token, so
//! stale spawned tasks observe the bumped generation and exit instead of firing
//! — no timer handles to track, wasm- and desktop-safe via [`crate::runtime_helpers::sleep_for`].

use std::time::Duration;

use glory::prelude::*;

/// Trailing-edge debouncer. Each [`Debouncer::call`] cancels any pending run
/// and schedules `action` to run after `delay_ms` of quiet.
#[derive(Clone, Copy)]
pub struct Debouncer {
    owner: Cage<glory::ui::WeakScope>,
    generation: Cage<u64>,
    delay_ms: u32,
}

impl Debouncer {
    pub fn new(scope: &Scope, delay_ms: u32) -> Self {
        Self {
            owner: scope.cage(scope.downgrade()),
            generation: scope.cage(0),
            delay_ms,
        }
    }
    /// Schedule `action` to run after `delay_ms` of no further calls.
    pub fn call<F>(&self, action: F)
    where
        F: FnOnce() + 'static,
    {
        let generation = self.generation;
        let my_gen = generation.get_untracked().wrapping_add(1);
        generation.revise(|value| *value = my_gen);
        let delay = u64::from(self.delay_ms);
        if let Some(scope) = self.owner.get_untracked().upgrade() {
            let _ = scope.spawn(async move {
                crate::runtime_helpers::sleep_for(Duration::from_millis(delay)).await;
                // A newer keystroke bumped the generation — this run is stale.
                if generation.get_untracked() == my_gen {
                    action();
                }
            });
        }
    }
}

/// Leading-edge throttle for "is typing" signals, with a trailing "stopped
/// typing" emit. `emit(true)` fires immediately on the first keystroke of a
/// burst and at most once per `active` window; `emit(false)` fires once the
/// user has been quiet for `stop`.
#[derive(Clone, Copy)]
pub struct TypingThrottle {
    owner: Cage<glory::ui::WeakScope>,
    cooldown: Cage<bool>,
    stop_generation: Cage<u64>,
    session_revision: Cage<u64>,
    active_ms: u32,
    stop_ms: u32,
}

/// Create a [`TypingThrottle`]. `active_ms` is the minimum gap between
/// `typing=true` emits; `stop_ms` is the quiet period before `typing=false`.
pub fn typing_throttle(scope: &Scope, active_ms: u32, stop_ms: u32) -> TypingThrottle {
    TypingThrottle {
        owner: scope.cage(scope.downgrade()),
        cooldown: scope.cage(false),
        stop_generation: scope.cage(0u64),
        session_revision: scope.cage(0u64),
        active_ms,
        stop_ms,
    }
}

impl TypingThrottle {
    pub(crate) fn retire_session(self) {
        self.session_revision
            .revise(|value| *value = value.wrapping_add(1));
        self.stop_generation
            .revise(|value| *value = value.wrapping_add(1));
        self.cooldown.revise(|value| *value = false);
    }

    /// Call once per keystroke. `emit` performs the actual (async) send —
    /// typically by spawning a `send_typing` request; it is invoked with
    /// `true` on the throttled leading edge and `false` on the debounced stop.
    pub fn on_keystroke<E>(&self, emit: E)
    where
        E: Fn(bool) + Clone + 'static,
    {
        // Leading edge: only emit `true` when not already inside a cooldown
        // window, then hold the cooldown for `active_ms`.
        let cooldown = self.cooldown;
        let session_revision = self.session_revision;
        let revision = session_revision.get_untracked();
        if !cooldown.get_untracked() {
            cooldown.revise(|value| *value = true);
            emit(true);
            let active = u64::from(self.active_ms);
            if let Some(scope) = self.owner.get_untracked().upgrade() {
                let _ = scope.spawn(async move {
                    crate::runtime_helpers::sleep_for(Duration::from_millis(active)).await;
                    if session_revision.get_untracked() == revision {
                        cooldown.revise(|value| *value = false);
                    }
                });
            }
        }

        // Trailing stop: debounce a `false` emit to fire after the burst ends.
        let stop_generation = self.stop_generation;
        let my_gen = stop_generation.get_untracked().wrapping_add(1);
        stop_generation.revise(|value| *value = my_gen);
        let stop = u64::from(self.stop_ms);
        let emit_stop = emit.clone();
        if let Some(scope) = self.owner.get_untracked().upgrade() {
            let _ = scope.spawn(async move {
                crate::runtime_helpers::sleep_for(Duration::from_millis(stop)).await;
                if session_revision.get_untracked() == revision
                    && stop_generation.get_untracked() == my_gen
                {
                    emit_stop(false);
                }
            });
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn retired_typing_timers_cannot_release_or_emit_for_the_next_session() {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let throttle = typing_throttle(app.scope(), 1, 1);
        let events = Rc::new(RefCell::new(Vec::new()));
        let observed = events.clone();
        let emit = move |active| observed.borrow_mut().push(active);
        throttle.on_keystroke(emit.clone());
        assert!(executor.poll_one());
        assert!(executor.poll_one());
        throttle.retire_session();
        assert!(!throttle.cooldown.get_untracked());
        throttle.on_keystroke(emit.clone());
        throttle.on_keystroke(emit);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // New timers are queued before the old timers' wakeups. Start the new
        // sleeps, then poll just the two old completions before new deadlines.
        for _ in 0..3 {
            assert!(executor.poll_one());
        }
        for _ in 0..2 {
            assert!(executor.poll_one());
        }
        assert!(throttle.cooldown.get_untracked());
        assert_eq!(*events.borrow(), vec![true, true]);
        tokio::time::sleep(Duration::from_millis(20)).await;
        for _ in 0..16 {
            executor.poll_one();
        }
        assert!(!throttle.cooldown.get_untracked());
        assert_eq!(*events.borrow(), vec![true, true, false]);
    }
}
