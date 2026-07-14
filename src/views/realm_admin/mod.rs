//! Realm administration surface.
//!
//! Split from the original single-file `realm_admin.rs` into focused
//! submodules: section navigation, metadata projection helpers, member
//! permission probing, the members panel, join/admission policy builders,
//! the main admin panel, and the headless MLS device-revoke handler. The
//! external module path (`crate::views::realm_admin::*`) and item
//! visibility are preserved via the re-exports below.

mod admin_panel;
mod capabilities;
mod durability;
mod durability_recovery;
mod members_panel;
mod metadata;
mod organization;
mod policy;
mod section;

pub use admin_panel::RealmAdminPanel;
pub use members_panel::RealmMembersPanel;
pub(crate) use members_panel::{
    mls_admission_candidate_realms_for_actor, parse_realm_key_request_envelope,
    pending_history_request_dedup_key, realm_key_request_answer_dedup_key,
    realm_key_source_ref_str, reconcile_mls_admissions_for_realm, request_history_keys_for_realm,
    share_history_to_requester, submit_mls_admission_for_invitees,
};
pub use organization::{RealmOrganizationPanel, ServerAdminSignal, is_server_admin};

// NOTE: All build_signed_*_move helpers and record_submit_outcome have
// been removed — every Move-based write path was migrated to
// ak.self.events.command.submit via the ak_ops::* event builders. The original
// helpers (and their tests) are preserved in git history.

// (Move-strand test module removed; the wire shapes are now covered by soland's events.submit tests
// and arkret-spec fixtures.)
