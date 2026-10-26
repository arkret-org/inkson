// The dedicated native media process owns this offline SDK page and private IPC.
(async () => {
  const maximum = 64 * 1024;
  const queue = [];
  const waiting = [];
  let closed = false;
  const send = (event) => {
    const value = JSON.stringify(event);
    if (value.length <= maximum) window.ipc.postMessage(value);
  };
  const receive = () => queue.length
    ? Promise.resolve(queue.shift())
    : new Promise((resolve) => waiting.push(resolve));
  window.__inksonMediaReceive = (command) => {
    if (closed || !command || typeof command !== "object") return;
    if (waiting.length) waiting.shift()(command);
    else if (queue.length < 64) queue.push(command);
    else { send({ event: "failed", reason: "command_capacity" }); closed = true; }
  };
  send({ event: "ready" });
  const initial = await receive();
  if (initial.cmd !== "init") { send({ event: "failed", reason: "initialization" }); return; }
  const config = initial.config;
  const LK = window.LivekitClient;
  if (!LK || !LK.Room || !window.isSecureContext || !Array.isArray(config.frameKey) || config.frameKey.length !== 32) {
    send({ event: "failed", reason: "media_environment" }); return;
  }
  const fail = (reason) => send({ event: "failed", reason });
  const provider = new LK.ExternalE2EEKeyProvider();
  const room = new LK.Room({ adaptiveStream: true, dynacast: true,
    e2ee: { keyProvider: provider, worker: typeof Worker !== "undefined" && LK.E2EEWorker ? new LK.E2EEWorker() : undefined } });
  const admitted = new Set();
  const tracks = new Map();
  const attach = (track) => {
    const surface = document.getElementById("remote-media");
    if (!surface || typeof track.attach !== "function") return;
    const element = track.attach();
    element.autoplay = true;
    element.playsInline = true;
    surface.appendChild(element);
  };
  room.on(LK.RoomEvent.TrackSubscribed, (track, _, remote) => {
    if (!remote || typeof remote.identity !== "string") return;
    if (admitted.has(remote.identity)) attach(track);
    else if (tracks.size < 256) {
      const pending = tracks.get(remote.identity) || [];
      if (pending.length < 8) pending.push(track);
      tracks.set(remote.identity, pending);
    }
  });
  const participant = (value) => {
    if (typeof value.identity === "string") send({ event: "participant", identity: value.identity });
  };
  room.on(LK.RoomEvent.ParticipantConnected, participant);
  let leaving = false;
  const leave = async () => {
    if (leaving) return;
    leaving = true;
    await room.disconnect().catch(() => {});
    closed = true;
    config.frameKey.fill(0);
    config.backendToken = "";
    send({ event: "left" });
  };
  room.on(LK.RoomEvent.Disconnected, () => {
    if (!leaving) { closed = true; send({ event: "left" }); }
  });
  try {
    await room.connect(config.connectUrl, config.backendToken, { autoSubscribe: true });
    config.backendToken = "";
  } catch (_) { fail("connect"); return; }
  try {
    const owned = new Uint8Array(config.frameKey);
    await provider.setKey(owned, config.localIdentity, 0);
    owned.fill(0); config.frameKey.fill(0);
    await room.setE2EEEnabled(true);
  } catch (_) { fail("sender_key"); await leave(); return; }
  try {
    if (config.audio) await room.localParticipant.setMicrophoneEnabled(true);
    if (config.video) await room.localParticipant.setCameraEnabled(true);
  } catch (_) { fail("capture"); }
  for (const remote of room.remoteParticipants.values()) participant(remote);
  send({ event: "connected" });
  const share = document.getElementById("share-screen");
  if (share) share.addEventListener("click", async () => {
    try {
      const enabled = !room.localParticipant.isScreenShareEnabled;
      await room.localParticipant.setScreenShareEnabled(enabled);
      share.textContent = enabled ? "Stop screen sharing" : "Share screen";
    } catch (_) { fail("screen_permission"); }
  });
  const leaveButton = document.getElementById("leave-media");
  if (leaveButton) leaveButton.addEventListener("click", leave);
  while (!closed) {
    const command = await receive();
    try {
      const local = room.localParticipant;
      switch (command.cmd) {
        case "set_e2ee_key": {
          if (!Array.isArray(command.key) || command.key.length !== 32) throw new Error("key");
          const owned = new Uint8Array(command.key);
          await provider.setKey(owned, command.identity, command.keyIndex >>> 0);
          owned.fill(0); command.key.fill(0);
          await room.setE2EEEnabled(true);
          admitted.add(command.identity);
          for (const track of tracks.get(command.identity) || []) attach(track);
          tracks.delete(command.identity);
          break;
        }
        case "publish":
          if (typeof command.audio === "boolean") await local.setMicrophoneEnabled(command.audio);
          if (typeof command.video === "boolean") await local.setCameraEnabled(command.video);
          break;
        case "set_muted":
          if (command.kind === "audio") await local.setMicrophoneEnabled(!command.muted);
          else if (command.kind === "video") await local.setCameraEnabled(!command.muted);
          else if (command.kind === "screen") await local.setScreenShareEnabled(!command.muted);
          break;
        case "set_screen":
          try { await local.setScreenShareEnabled(command.enabled); }
          catch (_) {
            // Capture requires a real gesture on engines that do not transfer native activation.
            if (share && command.enabled) { share.hidden = false; share.focus(); }
            else fail("screen_permission");
          }
          break;
        case "leave": await leave(); break;
        default: break;
      }
    } catch (_) { fail("control"); }
  }
})().catch(() => {
  try { window.ipc.postMessage(JSON.stringify({ event: "failed", reason: "driver" })); } catch (_) {}
});
