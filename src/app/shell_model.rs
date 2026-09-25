//! Pure derivations behind the app shell.
//!
//! `AppBootstrap` used to compute the sidebar projection, the account identity
//! labels and the shell chrome inline, between its `use_signal` declarations
//! and its `rsx!`. None of that work touches a Signal beyond reading one, so it
//! was untestable for no reason: a regression in the Realm-security fallback or
//! in the pinned-contact ordering could only be caught by driving the whole
//! component.
//!
//! Everything here takes owned or borrowed plain data and returns plain data.
//! `AppBootstrap` reads its Signals once, calls these, and renders the result.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::sidebar::{RealmManageRow, sidebar_text_matches_query};
use crate::account_data::{ContactRemark, RealmRemark};
use crate::i18n::TextDirection;
use crate::models::{RealmTreeNode, RealmTreeNodeKind};
use crate::realm_tree::{
    RealmTreeItem, descendant_node_ids, realm_tree_items_with_pinned_realms,
    realm_tree_node_is_direct_conversation,
};
use crate::state::LocalStateStore;
use crate::views::helpers::actor_display_label;

/// Which Realm the shell treats as selected.
///
/// Kept separate from the write it implies: the route can name a Realm the
/// remembered selection does not, and the caller is the only place allowed to
/// push that back into a Signal.
pub(super) struct RealmSelection {
    pub effective_realm_id: Option<String>,
    /// Set when the routed Realm must replace the remembered selection.
    pub remember: Option<String>,
}

pub(super) fn resolve_realm_selection(
    routed_realm_id: Option<&str>,
    remembered_realm_id: &str,
    principal_control_realm_ids: &BTreeSet<String>,
) -> RealmSelection {
    // A principal-control Realm is never a product navigation target, so it can
    // neither become the effective selection nor overwrite the remembered one.
    let routed_product_realm_id =
        routed_realm_id.filter(|realm_id| !principal_control_realm_ids.contains(*realm_id));
    let effective_realm_id = routed_product_realm_id.map(ToOwned::to_owned).or_else(|| {
        (!remembered_realm_id.trim().is_empty()).then(|| remembered_realm_id.to_owned())
    });
    let remember = routed_product_realm_id
        .filter(|realm_id| remembered_realm_id != *realm_id)
        .map(ToOwned::to_owned);
    RealmSelection {
        effective_realm_id,
        remember,
    }
}

/// Account identity strings shown in the sidebar account row and its tooltip.
pub(super) struct AccountIdentityLabels {
    pub handles_label: String,
    pub handles_title: String,
    pub label: String,
    pub detail: String,
}

pub(super) struct AccountIdentityInput<'a> {
    pub has_session: bool,
    pub personal_handles: &'a [String],
    pub personal_handles_status: &'a str,
    pub account_display_name: &'a str,
    pub device_display_name: &'a str,
    pub device_id_label: &'a str,
    pub principal_id_value: &'a str,
    pub store: &'a LocalStateStore,
}

pub(super) fn account_identity_labels(input: AccountIdentityInput<'_>) -> AccountIdentityLabels {
    let handles_label = crate::views::helpers::account_handles_display(
        input.personal_handles,
        input.personal_handles_status,
    );
    let handles_title = if input.personal_handles.is_empty() {
        handles_label.clone()
    } else {
        input.personal_handles.join(", ")
    };
    let label = if input.has_session {
        if !input.account_display_name.trim().is_empty() {
            input.account_display_name.to_owned()
        } else {
            input
                .personal_handles
                .first()
                .map(|handle| format!("@{handle}"))
                .unwrap_or_else(|| actor_display_label(input.store, input.principal_id_value))
        }
    } else {
        crate::i18n::tr("account.not_signed_in")
    };
    let detail = if input.has_session {
        let device = if input.device_display_name.trim().is_empty() {
            input.device_id_label.to_owned()
        } else {
            input.device_display_name.to_owned()
        };
        input
            .personal_handles
            .first()
            .map(|handle| format!("@{handle} · {device}"))
            .unwrap_or(device)
    } else {
        crate::i18n::tr("account.refresh_then_sign_in")
    };
    AccountIdentityLabels {
        handles_label,
        handles_title,
        label,
        detail,
    }
}

/// The Realm-tree projection the sidebar, the topbar and the manage pages all
/// read. Produced once so the three surfaces cannot disagree.
pub(super) struct RealmNavigationModel {
    pub collaboration_nodes: Vec<RealmTreeNode>,
    pub selected_preview: Option<RealmTreeNode>,
    pub active_projection_realm_id: String,
    /// Unfiltered navigation rows; the mobile surface renders these.
    pub realm_tree: Vec<RealmTreeItem>,
    pub filtered_realm_tree: Vec<RealmTreeItem>,
    pub manage_realm_rows: Vec<RealmManageRow>,
    pub active_realm_security_encrypted: bool,
}

pub(super) struct RealmNavigationInput<'a> {
    /// Already gated by `session_boot::account_projections_visible`; empty when
    /// account projections must stay hidden.
    pub loaded_nodes: &'a [RealmTreeNode],
    pub principal_control_realm_ids: &'a BTreeSet<String>,
    pub context_realm_id: Option<&'a str>,
    pub active_realm_id: &'a str,
    pub pinned_realm_ids: &'a BTreeSet<String>,
    pub realm_tree_projections: &'a BTreeMap<String, Value>,
    pub current_product_view: Option<&'a crate::current_projection::RealmCurrentView>,
    pub realm_ids_with_local_mls: &'a BTreeSet<String>,
    pub realm_remarks: &'a BTreeMap<String, RealmRemark>,
    /// Already trimmed and lowercased by the caller.
    pub collaboration_query: &'a str,
}

pub(super) fn build_realm_navigation(input: RealmNavigationInput<'_>) -> RealmNavigationModel {
    // Control-plane and Direct Conversation Realms are never product
    // navigation nodes. PCR ids come only from accepted create projections or
    // the verified account-scoped recovery evidence; no DID-derived guess is
    // permitted because Realm ids are Event-derived.
    let hidden_node_ids: BTreeSet<String> = input
        .loaded_nodes
        .iter()
        .filter(|node| {
            node.kind == RealmTreeNodeKind::Realm
                && (realm_tree_node_is_direct_conversation(node)
                    || input.principal_control_realm_ids.contains(&node.id))
        })
        .flat_map(|node| descendant_node_ids(input.loaded_nodes, &node.id))
        .collect();
    let collaboration_nodes: Vec<RealmTreeNode> = input
        .loaded_nodes
        .iter()
        .filter(|node| !hidden_node_ids.contains(node.id.as_str()))
        .cloned()
        .collect();
    let selected_preview = input
        .loaded_nodes
        .iter()
        .find(|node| input.context_realm_id == Some(node.id.as_str()))
        .cloned();
    let active_projection_realm_id =
        super::projection_realm_id_for_known_node(input.loaded_nodes, input.active_realm_id)
            .unwrap_or_default();
    let realm_tree =
        realm_tree_items_with_pinned_realms(&collaboration_nodes, input.pinned_realm_ids);
    let filtered_realm_tree: Vec<RealmTreeItem> = realm_tree
        .iter()
        .filter(|item| {
            let display_name = remark_display_name(input.realm_remarks, &item.node);
            let kind_label = match item.node.kind {
                RealmTreeNodeKind::Realm => "realm",
                RealmTreeNodeKind::Space => "space",
            };
            sidebar_text_matches_query(
                input.collaboration_query,
                &[&item.node.id, &item.node.title, &display_name, kind_label],
            )
        })
        .cloned()
        .collect();
    let manage_realm_rows: Vec<RealmManageRow> = collaboration_nodes
        .iter()
        .filter(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| {
            let display_name = remark_display_name(input.realm_remarks, node);
            let encrypted =
                crate::views::helpers::realm_mls_activation(input.current_product_view, &node.id)
                    .unwrap_or_else(|| input.realm_ids_with_local_mls.contains(&node.id));
            let space_count = descendant_node_ids(&collaboration_nodes, &node.id)
                .len()
                .saturating_sub(1);
            RealmManageRow {
                realm_id: node.id.clone(),
                display_name,
                title: node.title.clone(),
                encrypted,
                space_count,
            }
        })
        .collect();
    let security_scope_id = if active_projection_realm_id.trim().is_empty() {
        input.active_realm_id
    } else {
        active_projection_realm_id.as_str()
    };
    // The Realm row and topbar must never disagree about the same Realm. Use
    // the row's already-resolved Realm projection first; only fall back to a
    // Space/Strand scope lookup while the Realm tree itself is still hydrating.
    // Scope-first lookup allowed a partial board projection to turn an
    // encrypted Realm into the topbar's `Unencrypted` false default.
    let active_realm_security_encrypted = manage_realm_rows
        .iter()
        .find(|row| row.realm_id == input.active_realm_id)
        .map(|row| row.encrypted)
        .or_else(|| {
            crate::views::helpers::scope_mls_activation(
                input.realm_tree_projections,
                input.current_product_view,
                security_scope_id,
            )
        })
        .unwrap_or(false);
    RealmNavigationModel {
        collaboration_nodes,
        selected_preview,
        active_projection_realm_id,
        realm_tree,
        filtered_realm_tree,
        manage_realm_rows,
        active_realm_security_encrypted,
    }
}

fn remark_display_name(remarks: &BTreeMap<String, RealmRemark>, node: &RealmTreeNode) -> String {
    remarks
        .get(&node.id)
        .map(|remark| remark.display_name(&node.title).to_owned())
        .unwrap_or_else(|| node.title.clone())
}

/// Direct-contact sidebar rows: query filter first, then pinned-before-others
/// ordering by display label with the peer id as the final tie-break.
///
/// `query` is already trimmed and lowercased by the caller.
pub(super) fn filter_and_sort_direct_contacts(
    rows: &[crate::models::ContactListRow],
    query: &str,
    store: &LocalStateStore,
    contact_remarks: &BTreeMap<String, ContactRemark>,
) -> Vec<crate::models::ContactListRow> {
    let mut filtered: Vec<crate::models::ContactListRow> = rows
        .iter()
        .filter(|contact| {
            let peer_id = crate::models::contact_peer_id(contact);
            let display_name = crate::views::helpers::contact_peer_label(store, contact);
            let scopes = contact
                .bidirectional_scopes
                .iter()
                .chain(contact.effective_scopes.iter().flatten())
                .chain(contact.granted_to_peer_scopes.iter())
                .chain(contact.granted_by_peer_scopes.iter())
                .map(|scope| crate::models::contact_scope_wire(*scope))
                .collect::<Vec<_>>()
                .join(" ");
            let agent_match = contact.contact_agent_projections.iter().any(|agent| {
                sidebar_text_matches_query(
                    query,
                    &[
                        agent.actor_id.signing_principal_id().as_str(),
                        agent.display_name.as_deref().unwrap_or_default(),
                        agent.agent_slug.as_deref().unwrap_or_default(),
                    ],
                )
            });
            agent_match
                || sidebar_text_matches_query(
                    query,
                    &[
                        peer_id.as_str(),
                        crate::models::contact_state_wire(contact.state),
                        &display_name,
                        &scopes,
                    ],
                )
        })
        .cloned()
        .collect();
    filtered.sort_by(|left, right| {
        let left_peer = crate::models::contact_peer_id(left);
        let right_peer = crate::models::contact_peer_id(right);
        let left_pinned = contact_remarks
            .get(left_peer.as_str())
            .is_some_and(|remark| remark.pinned);
        let right_pinned = contact_remarks
            .get(right_peer.as_str())
            .is_some_and(|remark| remark.pinned);
        let left_label =
            crate::views::helpers::contact_peer_label(store, left).to_ascii_lowercase();
        let right_label =
            crate::views::helpers::contact_peer_label(store, right).to_ascii_lowercase();
        right_pinned
            .cmp(&left_pinned)
            .then_with(|| left_label.cmp(&right_label))
            .then_with(|| left_peer.cmp(&right_peer))
    });
    filtered
}

/// Theme-derived and layout-derived shell attributes.
pub(super) struct ShellChrome {
    pub theme_toggle_icon: &'static str,
    pub theme_toggle_title: String,
    pub shell_class: String,
    pub auth_class: String,
}

pub(super) fn shell_chrome(
    theme: &str,
    system_theme_is_night: bool,
    direction: TextDirection,
    sidebar_collapsed: bool,
    sidebar_resizing: bool,
) -> ShellChrome {
    let theme_is_night = super::theme_renders_as_night(theme, system_theme_is_night);
    let rtl = if direction == TextDirection::Rtl {
        " rtl"
    } else {
        ""
    };
    ShellChrome {
        theme_toggle_icon: if theme_is_night { "sun" } else { "moon" },
        theme_toggle_title: crate::i18n::tr(if theme_is_night {
            "theme.switch_to_light"
        } else {
            "theme.switch_to_night"
        }),
        shell_class: format!(
            "shell app{rtl}{}{}",
            if sidebar_collapsed {
                " sidebar-collapsed"
            } else {
                ""
            },
            if sidebar_resizing {
                " sidebar-resizing"
            } else {
                ""
            }
        ),
        auth_class: format!("auth-shell{rtl}"),
    }
}

#[cfg(test)]
#[path = "shell_model_tests.rs"]
mod tests;
