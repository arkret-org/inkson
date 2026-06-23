//! Realm administration surface.
//!
//! Split from the original single-file `realm_admin.rs` into focused
//! submodules: section navigation, metadata projection helpers, member
//! permission probing, the members panel, join/admission policy builders,
//! the main admin panel, and the headless MLS device-revoke handler. The
//! external module path (`crate::views::realm_admin::*`) and item
//! visibility are preserved via the re-exports below.

mod admin_panel;
mod device_revoke;
mod members_panel;
mod metadata;
mod permissions;
mod policy;
mod section;

pub use admin_panel::RealmAdminPanel;
pub use members_panel::RealmMembersPanel;
pub(crate) use members_panel::{
    submit_mls_admission_for_invitee, submit_mls_admission_for_invitees,
};

// NOTE: All build_signed_*_move helpers and record_submit_outcome have
// been removed — every Move-based write path was migrated to
// ck.self.events.command.submit via the ck_ops::* event builders. The original
// helpers (and their tests) are preserved in git history.

// (Move-strand test module removed; the wire shapes are now covered by soland's events.submit tests
// and cokret-spec fixtures.)
