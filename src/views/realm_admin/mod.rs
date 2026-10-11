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
mod members_panel;
mod metadata;
mod organization;
mod policy;
mod section;

pub use admin_panel::RealmAdminPanel;
pub use members_panel::RealmMembersPanel;
pub use organization::{RealmOrganizationPanel, ServerAdminSignal, is_server_admin};

// NOTE: All build_signed_*_move helpers and record_submit_outcome have
// been removed — every Move-based write path was migrated to
// ak.self.events.command.submit.v1 via the ak_ops::* event builders. The original
// helpers (and their tests) are preserved in git history.

// (Move-strand test module removed; the wire shapes are now covered by coland's events.submit tests
// and arkret-spec fixtures.)
