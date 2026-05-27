pub mod account_data;
pub mod anchor_witness;
pub mod api;
pub mod app;
pub mod audit;
/// G3.Y0 — per-device DPoP signing key management. Sits on top of
/// `crate::dpop` (the pure JWS builder) and persists the key + JKT via
/// `LocalStateStore::dpop_device_key`.
pub mod auth_dpop;
pub mod avatar_crop;
pub mod blob;
pub mod canonical;
pub mod capability;
pub mod card_comments;
/// CXP-0007 P3B.2 — Circle UX types, scope picker, error-code mapping.
/// `Circle` is the intra-Realm cryptographic sub-boundary (strict
/// subset of Realm membership + independent MLS group). This module is
/// the client-side surface; the canonical struct lives in
/// `contrix_sdk::contrix_core::model::circle`.
pub mod circle;
pub mod coauth;
pub mod components;
pub mod config;
pub mod conflict;
pub mod conformance;
pub mod content;
pub mod cross_signing;
pub mod crypto;
pub mod crypto_boundary;
pub mod cursor;
pub mod device_revoke;
pub mod did_resolver;
pub mod discovery;
pub mod dpop;
pub mod event_signer;
pub mod federation;
pub mod hlc;
pub mod i18n;
pub mod identity_handle;
/// Round 4 (spec a77b995) — invite-claim flow (subject_proof +
/// binding_proof transcript + 5 terminal states UI).
pub mod invite_claim;
pub mod key_backup;
pub mod key_store;
/// Round R2/R3 (T16) — late key recovery UX helpers.
pub mod late_recovery;
pub mod local_state;
pub mod media;
/// R3.1 (contrix-spec @ 7157ee8) — Realm-scoped
/// `cx.member.identity.update` event store. Sync ingests inlined
/// `members[].identity_events[]` here; UI views resolve the current
/// effective [`contrix_sdk::MemberIdentity`] via the SDK's
/// replacement-edge filter helper. MLS decryption (MID-4) + proof
/// signature verification (MID-5) are gated on `TODO(R4)`.
pub mod member_identity_store;
/// G3.Y2 — messaging UI scaffolding (polls, mentions picker,
/// discussion-promote, sidecar-hash). The chat view consumes these
/// helpers; see `crate::messaging::mod` for the rationale.
pub mod messaging;
pub mod mls;
pub mod models;
pub mod move_builder;
pub mod notification_rules;
pub mod objects;
pub mod offline;
pub mod offline_queue;
pub mod oidc;
pub mod operation;
pub mod presence_rx;
pub mod push;
pub mod rank;
pub mod recovery_crypto;
pub mod routes;
pub mod secure_key_store;
pub mod session_refresh;
pub mod snapshot;
pub mod sync_engine;
pub mod telemetry;
pub mod views;
pub mod webrtc;
pub mod workflows;

pub use app::App;
