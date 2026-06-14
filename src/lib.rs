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
/// See `docs/user-strands-key-lifecycle.md` §3.
pub mod account_health;
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
/// CKP-0007 P3B.2 — Circle UX types, scope picker, error-code mapping.
/// `Circle` is the intra-Realm cryptographic sub-boundary (strict
/// subset of Realm membership + independent MLS group). This module is
/// the client-side surface; the canonical struct lives in
/// `cokret_sdk::cokret_core::modelss::circle`.
pub mod circle;
pub(crate) mod clock;
pub mod coauth;
pub mod components;
pub mod config;
pub mod conformance;
pub mod content;
pub mod cross_signing;
pub mod crypto;
pub mod crypto_boundary;
pub mod cursor;
pub mod device_name;
pub mod device_revoke;
pub mod did_key;
pub mod did_resolver;
pub mod discovery;
pub mod dpop;
pub mod event_signer;
pub mod federation;
pub mod file_transfer;
pub mod hlc;
pub mod hpke_backup;
pub mod i18n;
pub mod identity_handle;
/// Round 4 (spec a77b995) — invite-claim strand (subject_proof +
/// binding_proof transcript + 5 terminal states UI).
pub mod invite_claim;
pub mod key_backup;
pub mod key_store;
/// Round R2/R3 (T16) — late key recovery UX helpers.
pub mod late_recovery;
pub mod local_state;
pub mod media;
/// R3.1 (cokret-spec @ 7157ee8) — Realm-scoped
/// `ck.member.identity.update` event store. Sync ingests inlined
/// `members[].identity_events[]` here; UI views resolve the current
/// effective [`cokret_sdk::MemberIdentity`] via the SDK's
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
pub mod object_address;
pub mod objects;
pub mod seal_witness;
// YOU-02-008: the former `offline` / `offline_queue` modules (P3B.5
// offline write queue + drain worker) were removed — the entire chain
// (enqueue helpers, drain worker, pending badge) had zero production
// call sites, and the replay path posted raw bodies without auth /
// DPoP / event signing, so it could never have drained successfully
// against authenticated endpoints. Re-add only together with real
// wiring (enqueue on send failure, authed replay, app-shell drain).
pub mod oidc;
pub mod operation;
pub mod passkey_prf;
/// Input-path perf helpers — draft-save debounce + typing throttle for the
/// composer hot paths. See [`perf`] for the rationale.
pub mod perf;
pub mod presence_rx;
pub mod push;
pub mod rank;
/// R28-B — pure realm-tree / projection / field-extraction helpers
/// extracted out of the (formerly 12k-line) `app` module so the
/// hierarchy + projection-parsing logic is unit-testable in isolation.
pub(crate) mod realm_tree;
pub mod recovery_crypto;
pub mod recovery_proof;
pub mod recovery_strand;
pub mod routes;
pub mod secure_key_store;
pub mod security_state;
pub mod session;
pub mod session_refresh;
pub mod snapshot;
pub mod sync_engine;
pub mod telemetry;
/// C3:共享 UI 组件层。原本地 `src/ui/` 已原样迁入 `yoface` crate(13 个
/// `#[css_module]` 封装 + 后台实用控件);此处 re-export 使全仓既有的
/// `crate::ui::button::Button` 等引用路径保持不变,组件颜色走第一层语义
/// 令牌(`--primary/--background/...`),由 `yoface::TOKENS_CSS` 提供(绿色
/// 调色板,注入见 `app.rs`)。
pub use yoface::ui;
pub mod views;
pub mod webrtc;
pub mod workflows;

pub use app::App;
