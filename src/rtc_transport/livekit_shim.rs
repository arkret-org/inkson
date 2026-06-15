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

use wasm_bindgen::prelude::*;

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

    /// Inject the MLS-exporter-derived frame key into the LiveKit
    /// `ExternalE2EEKeyProvider` and enable room E2EE.
    #[wasm_bindgen(js_name = cokretLivekitSetE2EEKey, catch)]
    pub fn set_e2ee_key(
        handle: &str,
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
