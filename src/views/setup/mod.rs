//! Setup surface: Realm bootstrap, Space create, and the overview map.
//!
//! `SetupPanel` is a thin router over three section components, split out by
//! responsibility:
//! - [`overview::OverviewSection`] — the setup surface map.
//! - [`realms::RealmsSection`] — the `ak.realm.create` wizard.
//! - [`new_space::NewSpaceSection`] — the `ak.space.create` form + lifecycle.
//!
//! Shared static option tables live in [`data`], the section / wizard-step
//! enums in [`model`], and pure helpers in [`helpers`].

use dioxus::prelude::*;

use crate::i18n::tr;
use crate::models::RealmTreeNode;

mod data;
mod helpers;
mod model;
mod new_space;
mod overview;
mod realms;

use model::{NewRealmStep, SetupSection};
use new_space::NewSpaceSection;
use overview::OverviewSection;
use realms::RealmsSection;

#[component]
pub fn SetupPanel(
    plaintext_service_id: String,
    secure_store_ready: bool,
    token: Signal<String>,
    account_recovery_configured: Signal<Option<bool>>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    selected_realm_id: Signal<String>,
    new_space_context_node: Signal<String>,
    section: Option<String>,
) -> Element {
    // A4 — base_url / state_store are read from the session context directly by
    // the child sections now; SetupPanel no longer threads them through.
    let active_section = SetupSection::from_slug(section.as_deref());

    // Wizard / form state lives on the parent so each section's in-progress
    // draft survives switching between conditionally-rendered sections.
    let create_step = use_signal(|| NewRealmStep::Basics);
    let realm_title = use_signal(String::new);
    let realm_summary = use_signal(String::new);
    let realm_alias = use_signal(String::new);
    let realm_discoverability = use_signal(|| "listed".to_owned());
    let realm_policy_join_rule = use_signal(|| "invite".to_owned());
    let realm_policy_history_access = use_signal(|| "all_history_for_current_members".to_owned());
    // Spec realm-and-space.md §2.3 — `encryption_profile` and `security_class`
    // are Realm create-locked fields; default to the safe `mls_rfc9420` +
    // `standard` case.
    let realm_encryption_profile = use_signal(|| "mls_rfc9420".to_owned());
    // §2.10 content-scheme capability axis: default to history-capable
    // (exporter-aead) so collaboration realms can share pre-join history.
    let realm_content_scheme = use_signal(|| "mls_exporter_aead_v1".to_owned());
    let realm_security_class = use_signal(|| "standard".to_owned());
    // Spec realm-and-space.md §2.3 advanced create-locked fields; safe defaults
    // `restricted` / `sha256`. The Realm notary signer is frozen from verified
    // Principal Server signer evidence during submission.
    let realm_federation_policy = use_signal(|| "restricted".to_owned());
    let realm_digest_algorithm = use_signal(|| "sha256".to_owned());
    let realm_state = use_signal(|| tr("setup.state.draft"));
    let realm_create_busy = use_signal(|| false);
    let created_realm_id = use_signal(String::new);
    // recovery_material_pending gate for encrypted-Realm creation.
    let pending_recovery_gate = use_signal(|| false);

    // Phase 3 — `ak.space.create` form state.
    let new_space_realm_id = use_signal(String::new);
    let new_space_title = use_signal(String::new);
    let new_space_summary = use_signal(String::new);
    let new_space_kind = use_signal(|| "space".to_owned());
    let new_space_parent_id = use_signal(String::new);
    let new_space_default_realm_id = use_signal(String::new);
    let new_space_context_seen = use_signal(String::new);
    let new_space_state = use_signal(|| tr("setup.state.draft"));
    let new_space_created_id = use_signal(String::new);

    rsx! {
        div { class: "timeline", "data-testid": "setup-panel",
            if active_section == SetupSection::Overview {
                OverviewSection { selected_realm_id }
            }

            if active_section == SetupSection::Realms {
                RealmsSection {
                    plaintext_service_id,
                    secure_store_ready,
                    token,
                    account_recovery_configured,
                    selected_realm_id,
                    create_step,
                    realm_title,
                    realm_summary,
                    realm_alias,
                    realm_discoverability,
                    realm_policy_join_rule,
                    realm_policy_history_access,
                    realm_encryption_profile,
                    realm_content_scheme,
                    realm_security_class,
                    realm_federation_policy,
                    realm_digest_algorithm,
                    realm_state,
                    realm_create_busy,
                    created_realm_id,
                    pending_recovery_gate,
                }
            }

            if active_section == SetupSection::NewSpace {
                NewSpaceSection {
                    token,
                    selected_realm_id,
                    realm_tree_nodes,
                    new_space_context_node,
                    new_space_realm_id,
                    new_space_title,
                    new_space_summary,
                    new_space_kind,
                    new_space_parent_id,
                    new_space_default_realm_id,
                    new_space_context_seen,
                    new_space_state,
                    new_space_created_id,
                }
            }
        }
    }
}
