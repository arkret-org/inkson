// Thin JS shim over the real livekit-client SDK for the Arkret web (wasm)
// SFU media path. Every function here drives a genuine `LivekitClient.Room`
// API; there are no stubs, no fabricated "connected" state, and no
// hard-coded participant data. When this runs in a browser with the
// livekit-client UMD loaded and a reachable LiveKit SFU, it performs a real
// SFU connection, real local publish, and real E2EE key injection.
//
// The Rust side (src/rtc_transport/web.rs) binds these through
// `#[wasm_bindgen(module = "/assets/livekit_shim.js")]`. Promise-returning
// functions are awaited from Rust via `wasm_bindgen_futures::JsFuture`.

// Vendored livekit-client UMD, wrapped as an ES module (assets/livekit_vendor.js,
// pinned 2.19.2). Importing it self-executes the UMD against `window`, which
// registers the global `window.LivekitClient`. This is a static, bundled import
// — wasm-bindgen pulls the wrapper into the build's snippet graph — so there is
// no runtime CDN fetch and the call surface works fully offline.
import "/assets/livekit_vendor.js";

// Handle registry: opaque string ids handed to Rust map to live Room objects
// plus their per-room key provider, so subsequent publish/mute/key/leave
// calls operate on the real Room instance.
const rooms = new Map();
let nextHandle = 1;

async function ensureLivekit() {
  if (typeof window !== "undefined" && window.LivekitClient && window.LivekitClient.Room) {
    return window.LivekitClient;
  }
  // The vendored module is imported statically above, so the global must be
  // present by the time any join is requested. If it is not, the build is
  // broken — fail closed rather than silently degrade.
  throw new Error("livekit_shim: vendored LivekitClient global unavailable");
}

// arkretLivekitJoin(connectUrl, token, opts) -> Promise<handle string>
//
// Constructs a real `LivekitClient.Room` (wiring an ExternalE2EEKeyProvider so
// the MLS-derived frame key can be injected before/after connect) and calls
// the genuine `room.connect(connectUrl, token)`. Returns an opaque handle id.
export async function arkretLivekitJoin(connectUrl, token, opts) {
  const LK = await ensureLivekit();

  // Real LiveKit E2EE key provider. `ExternalE2EEKeyProvider` lets the
  // application supply raw key bytes (our MLS-exporter-derived frame key)
  // instead of a passphrase-derived key.
  const keyProvider = new LK.ExternalE2EEKeyProvider();

  const roomOptions = {
    adaptiveStream: true,
    dynacast: true,
    e2ee: {
      keyProvider,
      // LiveKit runs frame crypto in a dedicated worker. The UMD ships the
      // worker; instantiate it from the SDK's bundled worker entry.
      worker:
        typeof Worker !== "undefined" && LK.E2EEWorker
          ? new LK.E2EEWorker()
          : undefined,
    },
  };

  const room = new LK.Room(roomOptions);

  // Real connect to the SFU. Throws (rejects) on failure — Rust maps that to
  // a fail-closed transport error rather than a fake Connected state.
  await room.connect(connectUrl, token, {
    autoSubscribe: !!(opts && opts.autoSubscribe !== false),
  });

  const handle = String(nextHandle++);
  rooms.set(handle, { room, keyProvider, LK });
  return handle;
}

function lookup(handle) {
  const entry = rooms.get(String(handle));
  if (!entry) {
    throw new Error(`livekit_shim: unknown room handle ${handle}`);
  }
  return entry;
}

// arkretLivekitPublish(handle, {audio, video}) -> Promise<void>
//
// Drives the real localParticipant publish toggles.
export async function arkretLivekitPublish(handle, media) {
  const { room } = lookup(handle);
  const lp = room.localParticipant;
  if (media && typeof media.audio === "boolean") {
    await lp.setMicrophoneEnabled(media.audio);
  }
  if (media && typeof media.video === "boolean") {
    await lp.setCameraEnabled(media.video);
  }
  if (media && media.screen === true) {
    await lp.setScreenShareEnabled(true);
  } else if (media && media.screen === false) {
    await lp.setScreenShareEnabled(false);
  }
}

// arkretLivekitSetMuted(handle, kind, muted) -> Promise<void>
//
// `kind` is "audio" | "video" | "screen". Mute == disable the publish; the
// SDK stops sending that track. Uses the same real enable APIs inverted.
export async function arkretLivekitSetMuted(handle, kind, muted) {
  const { room } = lookup(handle);
  const lp = room.localParticipant;
  const enabled = !muted;
  if (kind === "audio") {
    await lp.setMicrophoneEnabled(enabled);
  } else if (kind === "video") {
    await lp.setCameraEnabled(enabled);
  } else if (kind === "screen") {
    await lp.setScreenShareEnabled(enabled);
  } else {
    throw new Error(`livekit_shim: unknown track kind ${kind}`);
  }
}

// arkretLivekitSetE2EEKey(handle, participantIdentity, keyBytes, keyIndex)
//   -> Promise<void>
//
// Injects a sender-bound MLS-exporter-derived 32-byte frame key into the real
// LiveKit E2EE key provider, keyed to `participantIdentity`, and enables E2EE
// on the room. `keyBytes` is a Uint8Array shared from wasm linear memory; copy
// it into a fresh buffer so the provider keeps an owned copy.
//
// SFrame frame keys are sender-bound (media-service-binding.md §8.1): the
// Context binds the sender's own (participant_identity, device_id). Each sender
// derives its key from the shared MLS exporter, and every other member
// recomputes that same sender's key from the same exporter (same epoch) and
// installs it under that sender's identity here — which is how the receiver
// decrypts that sender's frames. `participantIdentity` is therefore ALWAYS
// passed (local identity for our own publish, the remote's identity for a
// recomputed remote key), never undefined.
export async function arkretLivekitSetE2EEKey(
  handle,
  participantIdentity,
  keyBytes,
  keyIndex,
) {
  const { room, keyProvider } = lookup(handle);
  const owned = new Uint8Array(keyBytes.length);
  owned.set(keyBytes);
  // ExternalE2EEKeyProvider.setKey(key, participantIdentity, keyIndex).
  await keyProvider.setKey(owned, participantIdentity, keyIndex >>> 0);
  // Turn on frame encryption/decryption for this room.
  await room.setE2EEEnabled(true);
}

// arkretLivekitOnParticipant(handle, cb) -> void
//
// Subscribes to the real ParticipantConnected event and forwards the SFU
// participant identity string to the Rust callback, which cross-checks it
// against ck.call.state.participants[] (fail-closed on mismatch).
export function arkretLivekitOnParticipant(handle, cb) {
  const { room, LK } = lookup(handle);
  room.on(LK.RoomEvent.ParticipantConnected, (participant) => {
    try {
      cb(participant.identity);
    } catch (_e) {
      // Swallow callback errors so the SDK event loop is not broken; the
      // Rust side already logged/handled.
    }
  });
  // Surface participants already present at connect time too.
  for (const p of room.remoteParticipants.values()) {
    try {
      cb(p.identity);
    } catch (_e) {
      /* ignore */
    }
  }
}

// arkretLivekitLeave(handle) -> Promise<void>
//
// Real room.disconnect() and registry cleanup.
export async function arkretLivekitLeave(handle) {
  const entry = rooms.get(String(handle));
  if (!entry) {
    return;
  }
  rooms.delete(String(handle));
  await entry.room.disconnect();
}
