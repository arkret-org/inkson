// Browser behavior is covered by wasm integration tests. The inline unit-test
// tree is native-only and depends on native filesystem-backed test helpers.
#![cfg(not(all(test, target_arch = "wasm32")))]
// Many helpers and Dioxus components take more parameters than clippy's
// default `too_many_arguments` threshold of 7 — this is a UI crate where
// builders, API wrappers, and component prop bundles routinely cross
// that line. Allow at the crate level rather than peppering individual
// items with `#[allow(...)]`.
#![allow(clippy::too_many_arguments)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod account_data;
/// Single-source-of-truth resolver for the post-boot "account health" prompt
/// chain (device authorization → MLS unlock → MLS backup → recovery-missing →
/// recommended encryption floor → recovery reminder). Replaces the scattered
/// per-prompt suppression conditions that used to live inline in `app.rs`.
/// See `docs/user-flows-key-lifecycle.md` §3.
pub mod account_health;
pub mod api_error;
pub mod app;
pub mod avatar_crop;
pub mod blob;
pub(crate) mod browser_storage;
pub mod build_info;
pub mod calendar;
pub mod canonical;
/// P3B.2 — Circle UX types, scope picker, error-code mapping.
/// `Circle` is the intra-Realm cryptographic sub-boundary (strict
/// subset of Realm membership + independent MLS group). This module is
/// the client-side surface; the canonical struct lives in
/// `arkret_models_collaboration::governance::circle`.
pub mod circle;
pub mod circle_mls;
pub mod client_core;
pub(crate) mod clock;
pub mod components;
pub mod config;
pub mod conformance;
pub mod content;
pub(crate) mod current_projection;
pub(crate) mod directory_helpers;
pub(crate) mod ephemeral;
pub mod event_builders;
pub mod event_signer;
pub mod event_submit;
pub mod file_transfer;
pub mod fresh_device_recovery;
pub mod hpke_backup;
pub mod i18n;
pub(crate) mod identity;
pub mod key_backup;
pub mod keyed_cooldown;
pub(crate) mod keypackage_maintenance;
/// Late key recovery UX helpers.
pub mod late_recovery;
pub mod media;
/// Per arkret-spec @ 7157ee8 — Realm-scoped
/// `ak.member.identity.update` event store. Sync ingests inlined
/// `members[].identity_events[]` here; UI views resolve the current
/// effective [`arkret_sdk::MemberIdentity`] via the SDK's
/// replacement-edge filter helper. MID-4 (MLS decryption) is handled at
/// the carrier level — an encrypted carrier surfaces as
/// `decryption_pending` — and MID-5 (proof signature verification) is
/// implemented fail-closed in
/// `identity::member_identity_store::MemberIdentityStore::current_identity`.
/// G3.Y2 — messaging UI scaffolding (polls, mentions picker,
/// discussion-promote, sidecar-hash). The chat view consumes these
/// helpers; see `crate::messaging::mod` for the rationale.
pub mod messaging;
pub mod mls;
pub(crate) mod mls_api_helpers;
pub mod models;
pub mod move_builder;
pub mod notification_rules;
pub mod notification_sound;
pub mod object_address;
pub(crate) mod payload;
pub(crate) mod pcr_authority;
mod signing_stamp;
pub(crate) mod station_connection;
// The former `offline` / `offline_queue` modules (P3B.5
// offline write queue + drain worker) were removed — the entire chain
// (enqueue helpers, drain worker, pending badge) had zero production
// call sites, and the replay path posted raw bodies without auth /
// DPoP / event signing, so it could never have drained successfully
// against authenticated endpoints. Re-add only together with real
// wiring (enqueue on send failure, authed replay, app-shell drain).
// HYG-03: the former empty `oidc` placeholder module was removed — OIDC
// sign-in lives in `crate::identity::account_auth` + `crate::views::login`; the module
// carried only a doc comment and no code.
pub(crate) mod agent_identity;
pub mod operation;
pub mod organization;
mod outbound_store;
pub mod pending_logout;
/// Input-path perf helpers — draft-save debounce + typing throttle for the
/// composer hot paths. See [`perf`] for the rationale.
pub mod perf;
pub mod security_transaction;
// Presence/typing receive-side helpers formerly lived in `presence_rx`;
// after refactor a37e1b9 routed ephemeral signals through the soland sync
// projection the module was dead code. Its fail-closed `last_active_at`
// bucket validation moved into the shared SDK
// (`arkret_sdk::validate_last_active_at`), which soland now enforces at
// admission — the receive path here consumes the already-validated
// projection.
pub mod push;
pub(crate) mod random;
pub mod rank;
pub mod realm_defaults;
pub mod realm_events_engine;
/// R28-B — pure realm-tree / projection / field-extraction helpers
/// extracted out of the (formerly 12k-line) `app` module so the
/// hierarchy + projection-parsing logic is unit-testable in isolation.
pub(crate) mod realm_helpers;
pub(crate) mod realm_tree;
pub mod recovery_crypto;
pub mod recovery_flow;
pub mod routes;
pub mod rtc_transport;
pub(crate) mod runtime;
pub(crate) mod runtime_helpers;
pub(crate) mod secret_surface;
pub mod secure_key_store;

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub async fn run_browser_account_persist_fault_contract() -> anyhow::Result<()> {
    state::run_browser_account_persist_fault_contract().await
}

/// Durable-outbound-queue contract entry points for the browser test suite
/// (`tests/wasm_indexed_db_capacity.rs`). `outbound_store` is a private module,
/// so the contract reaches the real adoption / read-modify-write functions
/// through here rather than reimplementing them.
#[cfg(target_arch = "wasm32")]
pub use outbound_store::test_api as outbound_store_test_api;
pub mod realm_state_snapshot;
pub(crate) mod scheduled_send;
pub mod sidecar;
pub mod signal;
pub mod signal_receive_engine;
/// Sync projection layer (account/realm wire payloads -> local projection
/// models); moved out of `views/`.
pub(crate) mod state;
/// Browser regression harness for the durable current index. Not product
/// surface: the wasm test target cannot otherwise reach the crate-private
/// index, and the IndexedDB backend owes the same transaction, cancellation
/// and restart evidence the native SQLite backend already carries.
#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub use state::current_index::wasm_harness as current_index_harness;
pub mod sync_engine;
pub mod sync_parse;
pub mod telemetry;
/// Shared test fixtures. Compiled only under `cfg(test)`; every test
/// module builds authority/device/realm identifiers here instead of
/// re-deriving the same literals locally.
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod transport;
pub(crate) mod ui_signal;
pub use transport::realm_write::{
    relinquish_capability, reset_realm_authority, transfer_realm_owner,
};
/// `ak.profile.binding.websocket.v1` host wiring: the platform socket, the
/// holder-key signature and the transport-selection decision.
///
/// Public because the binding is exercised from outside this crate — the
/// conformance suite drives a real handshake against a live service — while the
/// rest of `transport` stays crate-internal.
pub use transport::websocket;
pub mod wire_helpers;
/// C3: shared UI component layer. The former local `src/ui/` moved unchanged
/// into the `yoface` crate (13 `#[css_module]` wrappers plus background utility
/// controls); this re-export keeps existing `crate::ui::button::Button`-style
/// paths working across the repo. Component colors use first-layer semantic
/// tokens (`--primary/--background/...`) provided by `yoface::TOKENS_CSS` (the
/// green palette injected in `app.rs`).
pub use yoface::ui;
pub mod views;
pub mod webrtc;
pub mod websocket_rail_engine;

pub use app::App;
