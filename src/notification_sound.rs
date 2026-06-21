pub fn play_notification_sound() {
    let _ = dioxus::document::eval(
        r#"
(() => {
  try {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextCtor) {
      return;
    }
    const key = "__yougenNotificationAudioContext";
    const ctx = window[key] || new AudioContextCtor();
    window[key] = ctx;

    const play = () => {
      const start = ctx.currentTime;
      const gain = ctx.createGain();
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.055, start + 0.014);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.21);
      gain.connect(ctx.destination);

      const tone = ctx.createOscillator();
      tone.type = "sine";
      tone.frequency.setValueAtTime(784, start);
      tone.frequency.setValueAtTime(1046.5, start + 0.09);
      tone.connect(gain);
      tone.start(start);
      tone.stop(start + 0.22);
      tone.addEventListener("ended", () => gain.disconnect(), { once: true });
    };

    if (ctx.state === "suspended") {
      const resume = ctx.resume();
      if (resume && typeof resume.then === "function") {
        resume.then(play).catch(() => {});
        return;
      }
    }
    play();
  } catch (_) {}
})()
"#,
    );
}
