pub mod account_data;
pub mod agent_workspace_watcher;
pub mod anchor_witness;
pub mod api;
pub mod app;
pub mod audit;
pub mod blob;
pub mod canonical;
pub mod capability;
pub mod card_comments;
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
/// Round 4 (spec a77b995) — invite-claim flow (subject_proof +
/// binding_proof transcript + 5 terminal states UI).
pub mod invite_claim;
pub mod key_backup;
pub mod key_store;
/// Round R2/R3 (T16) — late key recovery UX helpers.
pub mod late_recovery;
pub mod local_state;
/// Round 4 (spec a77b995) — mention_redirect plaintext routing
/// consumer. Receivers consult
/// `mention_redirect_target_actor_ids` before decrypting the message
/// body; if the local actor is not in the list, the body MUST NOT be
/// decrypted at the push layer.
pub mod mention_redirect;
pub mod media;
pub mod mimi_client;
pub mod mls_governance;
pub mod mls_passphrase;
pub mod mls_persistence;
pub mod models;
pub mod move_builder;
pub mod native_notify;
pub mod notification_rules;
pub mod objects;
pub mod offline;
pub mod oidc_callback;
pub mod oidc_lifecycle;
pub mod operation;
pub mod presence_rx;
pub mod push;
pub mod push_registration;
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
