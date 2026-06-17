//! `wasm-bindgen` bindings to the real livekit-client JS SDK shim.
//!
//! These extern functions are backed by [`assets/livekit_shim.js`], which
//! drives genuine `LivekitClient.Room` APIs (connect / publish / E2EE key
//! provider / participant events / disconnect). Promise-returning functions
//! are awaited from Rust via [`wasm_bindgen_futures::JsFuture`].
//!
//! Nothing here fabricates a session: a failed `room.connect` rejects the
//! Promise, which surfaces to the transport as a fail-closed error rather
//! than a fake `Connected` state. Local-only verification (no browser, no
//! live LiveKit SFU) cannot exercise the runtime connection — but the
//! binding targets the real SDK and will connect for real in a browser.

// `manganis` is pulled in alongside the asset items because the `asset!` macro
// expands to `manganis::…` paths and must resolve that crate name in scope.
use dioxus::prelude::{Asset, AssetOptions, asset, manganis};
use wasm_bindgen::prelude::*;

/// Make dx copy the vendored livekit-client bundle into the served
/// `web/public/assets/` so the shim's hard-coded
/// `import "/assets/livekit_vendor.js"` (see [`assets/livekit_shim.js`]) resolves
/// to real JavaScript instead of falling through to the SPA `index.html` fallback
/// (which the browser rejects as a module, collapsing the whole `yougen.js` module
/// graph and leaving a blank white screen).
///
/// The shim imports the vendor by a fixed, unhashed path from *outside* Rust code,
/// so per the manganis contract this asset:
/// - sets `with_hash_suffix(false)` so dx serves it at exactly `/assets/livekit_vendor.js`;
/// - is a `#[used] static` (not a referenced value) so the linker keeps it even though nothing in
///   Rust reads the `Asset` — manganis requires `#[used]` for externally-referenced fixed-path
///   assets;
/// - sets `with_module(true)` because the file is an ES module (`export const …`) and
///   `with_minify(false)` to ship the already-minified UMD bundle verbatim.
///
/// Refresh the bundle with `scripts/vendor_livekit.sh`.
#[used]
static LIVEKIT_VENDOR: Asset = asset!(
    "/assets/livekit_vendor.js",
    AssetOptions::js()
        .with_hash_suffix(false)
        .with_module(true)
        .with_minify(false)
);

#[wasm_bindgen(module = "/assets/livekit_shim.js")]
extern "C" {
    /// `new Room(...)` + `room.connect(connectUrl, token)`. Resolves to an
    /// opaque room handle string. `opts` is a JS object (e.g.
    /// `{ autoSubscribe: true }`).
    #[wasm_bindgen(js_name = cokretLivekitJoin, catch)]
    pub fn join(connect_url: &str, token: &str, opts: &JsValue)
    -> Result<js_sys::Promise, JsValue>;

    /// `room.localParticipant.setMicrophoneEnabled / setCameraEnabled /
    /// setScreenShareEnabled`. `media` is `{ audio?, video?, screen? }`.
    #[wasm_bindgen(js_name = cokretLivekitPublish, catch)]
    pub fn publish(handle: &str, media: &JsValue) -> Result<js_sys::Promise, JsValue>;

    /// Mute/unmute a published track (`kind` = "audio" | "video" | "screen").
    #[wasm_bindgen(js_name = cokretLivekitSetMuted, catch)]
    pub fn set_muted(handle: &str, kind: &str, muted: bool) -> Result<js_sys::Promise, JsValue>;

    /// Inject a sender-bound MLS-exporter-derived frame key into the LiveKit
    /// `ExternalE2EEKeyProvider` under `participant_identity` and enable room
    /// E2EE. `participant_identity` is the sender the key belongs to (the local
    /// participant for our own publish, or a remote participant whose key we
    /// recomputed from the shared MLS exporter so we can decrypt its frames).
    #[wasm_bindgen(js_name = cokretLivekitSetE2EEKey, catch)]
    pub fn set_e2ee_key(
        handle: &str,
        participant_identity: &str,
        key_bytes: &[u8],
        key_index: u32,
    ) -> Result<js_sys::Promise, JsValue>;

    /// Subscribe to `RoomEvent.ParticipantConnected`; `cb` receives the
    /// participant identity string.
    #[wasm_bindgen(js_name = cokretLivekitOnParticipant, catch)]
    pub fn on_participant(handle: &str, cb: &JsValue) -> Result<(), JsValue>;

    /// `room.disconnect()`.
    #[wasm_bindgen(js_name = cokretLivekitLeave, catch)]
    pub fn leave(handle: &str) -> Result<js_sys::Promise, JsValue>;
}
