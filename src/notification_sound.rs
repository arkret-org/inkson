use crate::local_state::LocalStateStore;

pub const NOTIFICATION_SOUND_ENABLED_KEY: &str = "notification.sound.enabled.v1";

pub fn notification_sound_enabled(store: &LocalStateStore, account_key: &str) -> bool {
    private_bool_preference(
        store.load_private_data(account_key, NOTIFICATION_SOUND_ENABLED_KEY),
        true,
    )
}

pub fn set_notification_sound_enabled(
    store: &mut LocalStateStore,
    account_key: &str,
    enabled: bool,
) {
    store.save_private_data(
        account_key,
        NOTIFICATION_SOUND_ENABLED_KEY,
        enabled.to_string(),
    );
}

pub fn should_play_notification_sound(
    previous_unread: Option<usize>,
    current_unread: usize,
    enabled: bool,
) -> bool {
    enabled && previous_unread.is_some_and(|previous| current_unread > previous)
}

fn private_bool_preference(value: Option<String>, default_value: bool) -> bool {
    match value.as_deref().map(str::trim) {
        Some("true" | "1" | "yes" | "on") => true,
        Some("false" | "0" | "no" | "off") => false,
        Some(_) | None => default_value,
    }
}

pub fn initialize_notification_audio() {
    let _ = dioxus::document::eval(AUDIO_BOOTSTRAP_JS);
}

pub fn play_notification_sound() {
    let _ = dioxus::document::eval(PLAY_NOTIFICATION_SOUND_JS);
}

const AUDIO_BOOTSTRAP_JS: &str = r#"
(() => {
  try {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextCtor) {
      return;
    }
    const key = "__inksonNotificationAudio";
    const state = window[key] || {
      ctx: null,
      pending: false,
      listenersInstalled: false,
      play: null,
      unlock: null
    };
    window[key] = state;

    const context = () => {
      if (!state.ctx) {
        state.ctx = new AudioContextCtor();
      }
      return state.ctx;
    };

    state.play = () => {
      const ctx = context();
      if (ctx.state !== "running") {
        state.pending = true;
        return false;
      }
      const start = ctx.currentTime;
      const gain = ctx.createGain();
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.06, start + 0.014);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.22);
      gain.connect(ctx.destination);

      const tone = ctx.createOscillator();
      tone.type = "sine";
      tone.frequency.setValueAtTime(784, start);
      tone.frequency.setValueAtTime(1046.5, start + 0.09);
      tone.connect(gain);
      tone.start(start);
      tone.stop(start + 0.23);
      tone.addEventListener("ended", () => gain.disconnect(), { once: true });
      state.pending = false;
      return true;
    };

    state.unlock = () => {
      const ctx = context();
      const afterResume = () => {
        if (state.pending && state.play) {
          state.play();
        }
      };
      if (ctx.state === "suspended") {
        const resume = ctx.resume();
        if (resume && typeof resume.then === "function") {
          resume.then(afterResume).catch(() => {});
          return;
        }
      }
      afterResume();
    };

    if (!state.listenersInstalled) {
      window.addEventListener("pointerdown", state.unlock, { capture: true, passive: true });
      window.addEventListener("keydown", state.unlock, { capture: true });
      state.listenersInstalled = true;
    }
  } catch (_) {}
})()
"#;

const PLAY_NOTIFICATION_SOUND_JS: &str = r#"
(() => {
  try {
    const key = "__inksonNotificationAudio";
    if (!window[key]) {
      return;
    }
    const state = window[key];
    if (state.play && state.play()) {
      return;
    }
    state.pending = true;
    if (state.unlock) {
      state.unlock();
    }
  } catch (_) {}
})()
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_sound_pref_defaults_on_and_parses_false_values() {
        let mut store = crate::local_state::isolated_store_for_tests("notification-sound-pref");
        let account = "did:web:alice.example";

        assert!(notification_sound_enabled(&store, account));

        set_notification_sound_enabled(&mut store, account, false);
        assert!(!notification_sound_enabled(&store, account));

        set_notification_sound_enabled(&mut store, account, true);
        assert!(notification_sound_enabled(&store, account));
    }

    #[test]
    fn should_play_only_when_enabled_and_unread_count_increases() {
        assert!(!should_play_notification_sound(None, 1, true));
        assert!(!should_play_notification_sound(Some(1), 1, true));
        assert!(!should_play_notification_sound(Some(2), 1, true));
        assert!(!should_play_notification_sound(Some(1), 2, false));
        assert!(should_play_notification_sound(Some(1), 2, true));
    }
}
