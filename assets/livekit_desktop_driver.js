// Desktop (Dioxus native / wry webview) driver for the real livekit-client
// SDK. This is the SFU/conference media path for the desktop build: the
// native Rust transport (src/rtc_transport/native.rs) has no in-process
// libwebrtc, so it reuses the browser engine inside the wry webview to run
// the genuine livekit-client UMD, exactly like the web (wasm) build does
// through assets/livekit_shim.js.
//
// Unlike the wasm shim (which is imported as an ES module by wasm-bindgen and
// exposes one function per call), this file is fed to a single long-lived
// Dioxus `document::eval` bridge. It drives one room for the lifetime of the
// call and speaks the eval channel protocol:
//
//   * commands arrive from Rust via `await dioxus.recv()` (an object with a
//     `cmd` field: "set_e2ee_key" | "publish" | "set_muted" | "set_screen" |
//     "leave"),
//   * events are pushed back to Rust via `dioxus.send({ event, ... })`:
//       - { event: "connected" }                       room.connect resolved
//       - { event: "participant", identity }            ParticipantConnected
//       - { event: "failed", reason }                   fail-closed
//       - { event: "left" }                             disconnect complete
//
// Every call here drives a genuine `LivekitClient.Room` API. There are no
// stubs, no fabricated "connected" state, and no hard-coded participant data.
// When this runs in the desktop webview with a reachable LiveKit SFU it
// performs a real SFU connection, real local publish, and real MLS-derived
// E2EE key injection. A rejected `room.connect` emits `failed` (Rust stays
// out of `Connected`), never a fake success.
//
// The bridge is bootstrapped by native.rs, which substitutes the leading
// `__ARKRET_DRIVER_CONFIG__` token with a JSON object carrying the connect
// URL, backend token, desired media flags, and the MLS-exporter-derived
// 32-byte frame key (as a number array). The whole body is wrapped by the
// Dioxus query engine in `(async function(dioxus){ ... })`, so top-level
// `await` and the `dioxus` channel are in scope.

const config = __ARKRET_DRIVER_CONFIG__;

// Vendored livekit-client UMD source (pinned 2.19.2). native.rs substitutes the
// `__ARKRET_LIVEKIT_UMD_SOURCE__` token with the bundled UMD body (read via
// `include_str!`), so it ships inside the desktop binary — no runtime CDN
// fetch, works fully offline. Evaluating the UMD against the webview `window`
// registers the global `window.LivekitClient`, matching the wasm shim's
// vendored ES-module import.
const LIVEKIT_UMD_SOURCE = __ARKRET_LIVEKIT_UMD_SOURCE__;

function ensureLivekitVendored() {
  if (typeof window === "undefined" || typeof document === "undefined") {
    throw new Error("livekit_desktop_driver: no DOM (not a webview context)");
  }
  if (window.LivekitClient && window.LivekitClient.Room) {
    return;
  }
  // Evaluate the bundled UMD once. The UMD self-registers
  // `window.LivekitClient` via its global branch.
  // eslint-disable-next-line no-new-func
  new Function(LIVEKIT_UMD_SOURCE).call(window);
  if (!(window.LivekitClient && window.LivekitClient.Room)) {
    throw new Error(
      "livekit_desktop_driver: vendored LivekitClient global unavailable after eval"
    );
  }
}

async function ensureLivekit() {
  ensureLivekitVendored();
  return window.LivekitClient;
}

const fail = (reason) => {
  try {
    dioxus.send({ event: "failed", reason: String(reason) });
  } catch (_) {}
};

let LK;
try {
  LK = await ensureLivekit();
} catch (error) {
  fail(error && error.message ? error.message : error);
  return;
}

// Real LiveKit E2EE key provider. `ExternalE2EEKeyProvider` lets the
// application supply raw key bytes (our MLS-exporter-derived frame key)
// instead of a passphrase-derived key.
const keyProvider = new LK.ExternalE2EEKeyProvider();

const roomOptions = {
  adaptiveStream: true,
  dynacast: true,
  e2ee: {
    keyProvider,
    worker:
      typeof Worker !== "undefined" && LK.E2EEWorker ? new LK.E2EEWorker() : undefined,
  },
};

const room = new LK.Room(roomOptions);

// Wire the real ParticipantConnected event BEFORE connect so participants
// present at connect time and those joining later are both forwarded to Rust
// for the MEDIA-2 cross-check against the effective call-roster OR-Set.
room.on(LK.RoomEvent.ParticipantConnected, (participant) => {
  try {
    dioxus.send({ event: "participant", identity: participant.identity });
  } catch (_) {}
});

// Real connect to the SFU. Rejects on failure -> Rust stays out of Connected.
try {
  await room.connect(config.connectUrl, config.backendToken, {
    autoSubscribe: true,
  });
} catch (error) {
  fail(error && error.message ? error.message : error);
  return;
}

// Inject the MLS-exporter-derived frame key into LiveKit's E2EE key provider
// and enable room E2EE BEFORE publishing, so local media is encrypted from
// the first frame. `config.frameKey` is the verified 32-byte key array.
try {
  const owned = new Uint8Array(config.frameKey.length);
  owned.set(config.frameKey);
  // §8.1: the local frame key is sender-bound — install it under the local
  // participant identity, never a room-wide slot.
  await keyProvider.setKey(owned, config.localIdentity, 0);
  await room.setE2EEEnabled(true);
} catch (error) {
  fail(error && error.message ? error.message : error);
  await room.disconnect().catch(() => {});
  return;
}

// Publish local mic/cam per desired media (real SDK toggles).
try {
  const lp = room.localParticipant;
  if (config.audio) {
    await lp.setMicrophoneEnabled(true);
  }
  if (config.video) {
    await lp.setCameraEnabled(true);
  }
} catch (error) {
  // Publishing failure (e.g. denied mic/cam permission) must not fake a
  // success, but it also should not tear down an otherwise-live room; surface
  // it and continue so the connected state still reflects reality.
  fail(error && error.message ? error.message : error);
}

// Surface participants already present at connect time (ParticipantConnected
// only fires for joins after the listener is attached).
for (const p of room.remoteParticipants.values()) {
  try {
    dioxus.send({ event: "participant", identity: p.identity });
  } catch (_) {}
}

// Connect succeeded against the real SFU.
dioxus.send({ event: "connected" });

// Long-lived command loop. Rust drives mute/screen/leave over the same
// bridge; `dioxus.recv()` blocks until the next command. The loop (and the
// eval bridge) ends only when Rust requests "leave" or the channel closes.
for (;;) {
  let command;
  try {
    command = await dioxus.recv();
  } catch (_) {
    break;
  }
  if (!command || typeof command !== "object") {
    continue;
  }
  try {
    const lp = room.localParticipant;
    switch (command.cmd) {
      case "set_e2ee_key": {
        const owned = new Uint8Array(command.key.length);
        owned.set(command.key);
        // A recomputed remote sender's key (or a rotated local key) is
        // installed under its owning participant identity (§8.1), so the
        // receiver can decrypt that specific sender's frames.
        await keyProvider.setKey(
          owned,
          command.identity,
          (command.keyIndex || 0) >>> 0,
        );
        await room.setE2EEEnabled(true);
        break;
      }
      case "publish": {
        if (typeof command.audio === "boolean") {
          await lp.setMicrophoneEnabled(command.audio);
        }
        if (typeof command.video === "boolean") {
          await lp.setCameraEnabled(command.video);
        }
        break;
      }
      case "set_muted": {
        const enabled = !command.muted;
        if (command.kind === "audio") {
          await lp.setMicrophoneEnabled(enabled);
        } else if (command.kind === "video") {
          await lp.setCameraEnabled(enabled);
        } else if (command.kind === "screen") {
          await lp.setScreenShareEnabled(enabled);
        }
        break;
      }
      case "set_screen": {
        await lp.setScreenShareEnabled(command.enabled === true);
        break;
      }
      case "leave": {
        await room.disconnect().catch(() => {});
        try {
          dioxus.send({ event: "left" });
        } catch (_) {}
        return;
      }
      default:
        break;
    }
  } catch (error) {
    // A control-command failure is surfaced but does not silently drop the
    // live room; Rust decides how to react.
    fail(error && error.message ? error.message : error);
  }
}
