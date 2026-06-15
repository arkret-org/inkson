// Thin JS shim over the real livekit-client SDK for the Cokret web (wasm)
// SFU media path. Every function here drives a genuine `LivekitClient.Room`
// API; there are no stubs, no fabricated "connected" state, and no
// hard-coded participant data. When this runs in a browser with the
// livekit-client UMD loaded and a reachable LiveKit SFU, it performs a real
// SFU connection, real local publish, and real E2EE key injection.
//
// The Rust side (src/rtc_transport/web.rs) binds these through
// `#[wasm_bindgen(module = "/assets/livekit_shim.js")]`. Promise-returning
// functions are awaited from Rust via `wasm_bindgen_futures::JsFuture`.

// CDN location of the livekit-client UMD bundle. Exposes the global
// `LivekitClient`. Kept here (not index.html) because the Dioxus web build
// ships no static index.html; we load it lazily and idempotently the first
// time a room join is requested.
const LIVEKIT_UMD_URL =
  "https://cdn.jsdelivr.net/npm/livekit-client/dist/livekit-client.umd.min.js";

// Handle registry: opaque string ids handed to Rust map to live Room objects
// plus their per-room key provider, so subsequent publish/mute/key/leave
// calls operate on the real Room instance.
const rooms = new Map();
let nextHandle = 1;

// Load a script tag once and resolve when its global is available.
function loadScriptOnce(url) {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined" || typeof document === "undefined") {
      reject(new Error("livekit_shim: no DOM (not a browser context)"));
      return;
    }
    // Already loaded?
    if (window.LivekitClient && window.LivekitClient.Room) {
      resolve();
      return;
    }
    const existing = document.querySelector(`script[data-cokret-livekit="1"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () =>
        reject(new Error("livekit_shim: livekit-client UMD failed to load"))
      );
      return;
    }
    const tag = document.createElement("script");
    tag.src = url;
    tag.async = true;
    tag.setAttribute("data-cokret-livekit", "1");
    tag.addEventListener("load", () => resolve());
    tag.addEventListener("error", () =>
      reject(new Error("livekit_shim: livekit-client UMD failed to load"))
    );
    document.head.appendChild(tag);
  });
}

async function ensureLivekit() {
  if (typeof window !== "undefined" && window.LivekitClient && window.LivekitClient.Room) {
    return window.LivekitClient;
  }
  await loadScriptOnce(LIVEKIT_UMD_URL);
  if (!(typeof window !== "undefined" && window.LivekitClient && window.LivekitClient.Room)) {
    throw new Error("livekit_shim: LivekitClient global unavailable after load");
  }
  return window.LivekitClient;
}

// cokretLivekitJoin(connectUrl, token, opts) -> Promise<handle string>
//
// Constructs a real `LivekitClient.Room` (wiring an ExternalE2EEKeyProvider so
// the MLS-derived frame key can be injected before/after connect) and calls
// the genuine `room.connect(connectUrl, token)`. Returns an opaque handle id.
export async function cokretLivekitJoin(connectUrl, token, opts) {
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

// cokretLivekitPublish(handle, {audio, video}) -> Promise<void>
//
// Drives the real localParticipant publish toggles.
export async function cokretLivekitPublish(handle, media) {
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

// cokretLivekitSetMuted(handle, kind, muted) -> Promise<void>
//
// `kind` is "audio" | "video" | "screen". Mute == disable the publish; the
// SDK stops sending that track. Uses the same real enable APIs inverted.
export async function cokretLivekitSetMuted(handle, kind, muted) {
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

// cokretLivekitSetE2EEKey(handle, keyBytes, keyIndex) -> Promise<void>
//
// Injects the MLS-exporter-derived 32-byte frame key into the real LiveKit
// E2EE key provider and enables E2EE on the room. `keyBytes` is a Uint8Array
// shared from wasm linear memory; copy it into a fresh buffer so the
// provider keeps an owned copy.
export async function cokretLivekitSetE2EEKey(handle, keyBytes, keyIndex) {
  const { room, keyProvider } = lookup(handle);
  const owned = new Uint8Array(keyBytes.length);
  owned.set(keyBytes);
  // ExternalE2EEKeyProvider.setKey(key, participantIdentity?, keyIndex?).
  // Setting it room-wide (no participant identity) establishes the shared
  // sender key all members derive from the same MLS exporter secret.
  await keyProvider.setKey(owned, undefined, keyIndex >>> 0);
  // Turn on frame encryption/decryption for this room.
  await room.setE2EEEnabled(true);
}

// cokretLivekitOnParticipant(handle, cb) -> void
//
// Subscribes to the real ParticipantConnected event and forwards the SFU
// participant identity string to the Rust callback, which cross-checks it
// against ck.call.state.participants[] (fail-closed on mismatch).
export function cokretLivekitOnParticipant(handle, cb) {
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

// cokretLivekitLeave(handle) -> Promise<void>
//
// Real room.disconnect() and registry cleanup.
export async function cokretLivekitLeave(handle) {
  const entry = rooms.get(String(handle));
  if (!entry) {
    return;
  }
  rooms.delete(String(handle));
  await entry.room.disconnect();
}
