// Window-owned notification oscillator. Unlock follows a trusted user gesture.
export function initializeNotificationAudio() {(() => {
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
})();}
export function playNotificationSound() {(() => {
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
})();}
