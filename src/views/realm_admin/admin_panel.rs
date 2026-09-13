use arkret_wire::{CapabilityActionId, CellFamilyId, event_kind_str};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::Link;
use serde_json::{Value, json};

use super::metadata::{
    MetadataSubject, metadata_subject_for, projected_members_for_realm, reconcile_editor_value,
    resolve_realm_member_account,
};
use super::policy::build_principal_admission_join_policy;
use super::section::{REALM_ADMIN_NAV_GROUPS, RealmAdminSection};
use crate::components::encryption_floor_prompt::projection_has_recommended_encryption_floor;
use crate::models::RealmTreeNodeKind;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

mod controller;
mod model;

use controller::*;
use model::*;

fn metadata_causal_refs(
    state_store: &crate::state::LocalStateStore,
    home_realm_id: &str,
    kind: RealmTreeNodeKind,
    subject_id: &str,
) -> Result<Vec<arkret_sdk::Hash>, String> {
    let cell = match kind {
        RealmTreeNodeKind::Realm => arkret_wire::REALM_PROFILE_CELL.to_owned(),
        RealmTreeNodeKind::Space => {
            format!("ak:cell:ak.component.space.metadata.v1:{subject_id}")
        }
    };
    let current = state_store
        .realm_tree_projection(home_realm_id)
        .and_then(|projection| projection.get("current").cloned())
        .and_then(|value| serde_json::from_value::<arkret_sdk::CurrentEntries>(value).ok())
        .ok_or_else(|| "canonical metadata state is still loading".to_owned())?;
    let mut matching = current
        .entries
        .iter()
        .filter(|entry| entry.selector().cell_id.as_str() == cell);
    let entry = matching
        .next()
        .ok_or_else(|| "canonical metadata cell is still loading".to_owned())?;
    if matching.next().is_some() {
        return Err("canonical metadata selector is duplicated".to_owned());
    }
    match entry.result() {
        arkret_sdk::CurrentOutcome::Heads { heads } => {
            let mut refs = heads
                .iter()
                .map(|head| head.event_id.event_digest())
                .collect::<Vec<_>>();
            refs.sort();
            refs.dedup();
            Ok(refs)
        }
        arkret_sdk::CurrentOutcome::Removed => Ok(Vec::new()),
        arkret_sdk::CurrentOutcome::Unavailable { .. }
        | arkret_sdk::CurrentOutcome::Value { .. } => {
            Err("canonical metadata state is unavailable".to_owned())
        }
    }
}

#[component]
pub fn RealmAdminPanel(
    principal_id: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    active_section: Option<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut metadata_title = use_signal(String::new);
    let mut metadata_summary = use_signal(String::new);
    let mut metadata_avatar_blob_ref = use_signal(String::new);
    let mut metadata_alias = use_signal(String::new);
    let mut metadata_loaded_for = use_signal(String::new);
    let mut metadata_loaded_subject = use_signal(|| Option::<MetadataSubject>::None);
    let mut join_rule = use_signal(|| "public".to_owned());
    let mut principal_admission_enabled = use_signal(|| false);
    let mut principal_admission_methods = use_signal(|| "did:webvh".to_owned());
    let mut principal_admission_allowed_ids = use_signal(String::new);
    let mut principal_admission_denied_ids = use_signal(String::new);
    let mut tighten_history_access = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    // Capability grant/revoke Move-strand inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(String::new);
    let mut cap_tag = use_signal(|| CapabilityActionId::MESSAGE_CREATE.to_owned());
    let mut cap_subject = use_signal(String::new);
    let mut cap_revoke_reason = use_signal(|| "rotation policy".to_owned());
    let mut archive_confirm_open = use_signal(|| false);
    let mut destroy_confirm_open = use_signal(|| false);
    let mut danger_confirm_text = use_signal(String::new);
    let mut destroy_reason = use_signal(|| "operator_request".to_owned());
    // Leave Realm confirmation dialog (no ID re-typing: leaving is
    // recoverable-by-invite, unlike destroy, but still needs one explicit
    // confirmation step before the membership event is submitted).
    let mut leave_confirm_open = use_signal(|| false);
    // Realm governance (authority root) inputs — owner transfer target +
    // pasted successor acceptance proof, plus the two security_barrier
    // confirmation dialogs (transfer / authority reset).
    let mut gov_transfer_target = use_signal(String::new);
    let gov_transfer_target_selected = use_memo(move || Some(gov_transfer_target()));
    let mut gov_transfer_acceptance = use_signal(String::new);
    let mut gov_transfer_confirm_open = use_signal(|| false);
    let mut gov_reset_confirm_open = use_signal(|| false);
    // Keep protocol state and rare authority/access workflows out of the
    // everyday security view. Operators can still open each surface on demand.
    let mut security_diagnostics_open = use_signal(|| false);
    let mut governance_controls_open = use_signal(|| false);
    let mut advanced_access_open = use_signal(|| false);
    // `ak.realm.authority.reset` requires the payload to carry the literal
    // event-kind string as `destructive_confirmation`; the operator types it
    // here, and the typed text is what the payload ships.
    let mut gov_reset_confirm_text = use_signal(String::new);
    // Realm-admin grant inputs (see realm-admin-grant-card). The subject is
    // the stable principal id being made / removed as admin; the grant id is minted
    // client-side on grant and re-entered on revoke (the soland reducer
    // locates the cell by grant_id).
    let mut admin_subject_id = use_signal(String::new);
    let mut admin_grant_id = use_signal(String::new);
    // Structured constraint inputs for the capability grant.
    // `cap_constraint_kind` chooses the family (`temporal` / `quota` /
    // `scope_limitation` / `none`); the temporal MVP exposes `not_before`
    // / `expires_at` RFC 3339 timestamps (`not_after` is not a canonical
    // schema field name). Quota / scope_limitation are surfaced in the dropdown
    // but show a "coming soon" hint until matching widgets land.
    let mut cap_constraint_kind = use_signal(|| "none".to_owned());
    let cap_constraint_kind_selected = use_memo(move || Some(cap_constraint_kind()));
    let mut cap_temporal_not_before = use_signal(String::new);
    let mut cap_temporal_expires_at = use_signal(String::new);
    // Read-only notary cell value. The Arkret HTTP catalog does not expose
    // this as a spec endpoint yet, so surface that inline rather than
    // pretending a private path exists.
    // Selected Move for the failure detail inline panel. Clicking a row
    // that's in a failed state stores its move_id here; the detail block
    // below renders the reason / seal_ref.
    let mut move_detail_open = use_signal(|| Option::<String>::None);
    // Read the local seal view for this realm once per render. Surfaces:
    //  - the unique confirmation head used by safety commands
    //  - state_root       → admin can confirm divergence between local + server
    let SealDiagnostics {
        leaf_count: seal_leaf_count,
        frontier_label: seal_frontier_label,
        state_root_label: seal_state_root_label,
        mls_epoch_label,
    } = seal_diagnostics(&state_store.read().seal_view_for_realm(&selected_realm_id));
    // per-Realm Move submission tracker. Drives the state-pill list +
    // the Realm-wide notary_paused banner.
    let move_submissions = state_store
        .read()
        .move_submissions_for_realm(&selected_realm_id);
    let realm_paused = state_store
        .read()
        .realm_has_paused_notary(&selected_realm_id);
    let realm_pending_mls_binding = state_store
        .read()
        .realm_has_pending_mls_binding(&selected_realm_id);
    let RealmSecurityHealth {
        label: security_health_label,
        badge: security_health_badge,
        next_step: security_next_step,
        alert_count,
    } = realm_security_health(realm_paused, realm_pending_mls_binding);
    let active_section = RealmAdminSection::from_slug(active_section.as_deref());
    // The account-sync writer can update the shared store outside this
    // component's reactive scope. Subscribe to its canonical cursor so a
    // deep-linked editor reconciles again when that projection lands.
    let _projection_sync_cursor = sync_cursor();
    let metadata_subject = metadata_subject_for(&state_store.read(), &selected_realm_id);
    use_effect({
        let home_realm_id = metadata_subject.home_realm_id.clone();
        let subject_id = selected_realm_id.clone();
        let kind = metadata_subject.kind;
        move || {
            let Some(authority) = state_store.read().active_authority() else {
                return;
            };
            let cells = if kind == RealmTreeNodeKind::Space {
                arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.space.metadata.v1:{subject_id}"
                ))
                .ok()
                .into_iter()
                .collect()
            } else {
                Vec::new()
            };
            state_store.read().set_product_current_demand(
                &authority,
                &home_realm_id,
                Some(Vec::new()),
                cells,
            );
        }
    });
    use_drop({
        let home_realm_id = metadata_subject.home_realm_id.clone();
        move || {
            if let Some(authority) = state_store.read().active_authority() {
                state_store.read().set_product_current_demand(
                    &authority,
                    &home_realm_id,
                    None,
                    Vec::new(),
                );
            }
        }
    });
    {
        let loaded_for = metadata_loaded_for();
        let loaded_subject = metadata_loaded_subject();
        let editor_title = metadata_title();
        let editor_summary = metadata_summary();
        let editor_avatar = metadata_avatar_blob_ref();
        let patch = reconcile_metadata_editors(
            &selected_realm_id,
            &metadata_subject,
            MetadataEditorState {
                loaded_for: &loaded_for,
                loaded_subject: loaded_subject.as_ref(),
                title: &editor_title,
                summary: &editor_summary,
                avatar_blob_ref: &editor_avatar,
            },
        );
        if let Some(value) = patch.title {
            metadata_title.set(value);
        }
        if let Some(value) = patch.summary {
            metadata_summary.set(value);
        }
        if let Some(value) = patch.avatar_blob_ref {
            metadata_avatar_blob_ref.set(value);
        }
        if let Some(value) = patch.loaded_for {
            metadata_loaded_for.set(value);
        }
        if let Some(value) = patch.loaded_subject {
            metadata_loaded_subject.set(Some(value));
        }
    }
    let metadata_subject_label = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => "Realm",
        RealmTreeNodeKind::Space => "Space",
    };
    let metadata_event_kind = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => event_kind_str::REALM_PROFILE,
        RealmTreeNodeKind::Space => event_kind_str::SPACE_UPDATE,
    };
    let projected_members = projected_members_for_realm(&state_store.read(), &selected_realm_id);
    let projected_member_count = projected_members.len();
    // Resolve the authority root from the locally replayed projection. Every
    // governance authoring path below binds these exact coordinates; no UI
    // state or Realm identifier is treated as an authority assertion.
    let account_actor = crate::mls_api_helpers::local_account_actor_id(&principal_id).ok();
    let (authority_root, is_root_controller) = {
        let store = state_store.read();
        let state = store.load();
        let root = garth::realm_authority_root_value_for_realm(
            &state.realm_tree_projections,
            &selected_realm_id,
        );
        let controller = garth::realm_authority_root_controller_for_realm(
            &state.realm_tree_projections,
            &selected_realm_id,
        );
        let is_controller = controller
            .zip(account_actor.as_ref())
            .is_some_and(|(controller, actor)| &controller == actor);
        (root, is_controller)
    };
    let gov_transfer_candidates =
        governance_transfer_candidates(&projected_members, account_actor.as_ref());
    let issuer_root_basis =
        crate::operation::ak_ops::IssuerRootBasis::from_resolved_root(authority_root.as_ref());
    // Every write below is one named command on this bundle; the rsx keeps
    // only the synchronous half of each click.
    let controller = RealmAdminController {
        status_msg,
        sync_cursor,
        state_store,
        gov_transfer_target,
        gov_transfer_acceptance,
        metadata_alias,
        admin_grant_id,
    };
    rsx! {
        div { class: "settings realm-settings", "data-testid": "realm-admin-panel",
            div { class: "settings-shell realm-settings-shell",
                aside { class: "settings-sidebar-column", "data-testid": "realm-admin-sections",
                    for (group_index, (group_label, sections)) in REALM_ADMIN_NAV_GROUPS.iter().copied().enumerate() {
                        div { class: "settings-nav-cluster",
                            div { class: "settings-nav-group-label", "{group_label}" }
                            for section in sections.iter().copied() {
                                {
                                    let section_slug = section.slug().unwrap_or("overview");
                                    rsx! {
                                        Link {
                                            class: if active_section == section { "settings-nav-item active" } else { "settings-nav-item" },
                                            "data-testid": "realm-admin-nav-item-{section_slug}",
                                            "aria-current": if active_section == section { "page" } else { "false" },
                                            to: section.route(selected_realm_id.clone()),
                                            strong { "{section.label()}" }
                                        }
                                    }
                                }
                            }
                        }
                        if group_index + 1 < REALM_ADMIN_NAV_GROUPS.len() {
                            div { class: "settings-nav-divider", "aria-hidden": "true" }
                        }
                    }
                }
                section { class: "settings-content-column realm-settings-content",
                    div { class: "event settings-content-hero",
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "{active_section.label()}" }
                            span { class: "badge", "{metadata_subject_label}" }
                        }
                        Link {
                            class: "secondary",
                            to: Route::RealmMembers { realm_id: selected_realm_id.clone() },
                            {crate::i18n::tr("realm_admin.members")}
                        }
                    }
            if active_section == RealmAdminSection::Overview {
                div { class: "event", "data-testid": "realm-admin-overview",
                    div { class: "event-head",
                        span { "Realm settings" }
                        span { title: "{selected_realm_id}", "{short_protocol_id(&selected_realm_id)}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { {crate::i18n::tr("realm_admin.members")} }
                            span { "{projected_member_count} known" }
                            Link {
                                class: "secondary",
                                to: Route::RealmMembers {
                                    realm_id: selected_realm_id.clone(),
                                },
                                "Open Members"
                            }
                        }
                        div { class: "metric",
                            strong { "Profile" }
                            span { "{metadata_subject_label} title, summary, avatar" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "profile".to_owned(),
                                },
                                "Open Profile"
                            }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("realm_admin.access")} }
                            span { "{join_rule()}" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "access".to_owned(),
                                },
                                "Open Access"
                            }
                        }
                        div { class: "metric",
                            strong { "Security & repair" }
                            span { "{alert_count} alerts" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "security".to_owned(),
                                },
                                "Open Security"
                            }
                        }
                    }
                }
            }
            // Realm-wide notary-paused banner. Fires whenever any tracked
            // Move for this Realm has surfaced `NotaryPaused`. The Space
            // cannot advance until ops rotate the recovery notary.
            if realm_paused {
                div {
                    class: "event error-banner",
                    "data-testid": "notary-paused-banner",
                    div { class: "event-head",
                        span { "Realm changes are temporarily paused" }
                        span { class: "badge red", "Action needed" }
                    }
                    div { class: "muted",
                        "New changes cannot complete right now. Ask the deployment administrator to restore the security service, then try again."
                    }
                }
            }
            // Pending MLS binding toast — when a recent E2EE message Event
            // references a Security Frontier the local MLS view has not yet
            // acknowledged. Stays up until the
            // user clears the underlying Move record.
            if realm_pending_mls_binding {
                div {
                    class: "event",
                    "data-testid": "pending-mls-binding-toast",
                    div { class: "event-head",
                        span { "Encrypted updates are still syncing" }
                        span { class: "badge amber", "In progress" }
                    }
                    div { class: "muted",
                        "The latest encrypted update is waiting for confirmation. Messages remain protected and will deliver when it completes."
                    }
                }
            }
            // Move submission tracker - pill list of recent local writes
            // with state badges. Clicking a failed row reveals the reason
            // inline.
            if active_section == RealmAdminSection::Repair && !move_submissions.is_empty() {
                div { class: "event", "data-testid": "move-submission-tracker",
                    div { class: "event-head",
                        span { "Recent Move submissions" }
                        span { "{move_submissions.len()} tracked" }
                    }
                    div { class: "muted",
                        "Local Move/Seal pipeline state for writes you've submitted from this device. Pending → Effective once sealed; failures expand inline."
                    }
                    for record in move_submissions.clone() {
                        {
                            let move_id_label = short_protocol_id(&record.move_id);
                            rsx! {
                                div { class: "event", "data-testid": "move-submission-row",
                                    div { class: "event-head",
                                        span { "{record.kind}" }
                                        span {
                                            class: "{record.state.badge_class()}",
                                            "data-testid": "move-state-badge",
                                            "data-state-slug": "{record.state.slug()}",
                                            "{record.state.label_zh()}"
                                        }
                                    }
                                    div { class: "muted", "data-testid": "move-submission-id",
                                        title: "{record.move_id}",
                                        "move {move_id_label}"
                                    }
                                    if let Some(event_id) = &record.event_id {
                                        {
                                            let event_id_label = short_protocol_id(event_id);
                                            rsx! {
                                                div { class: "muted", "data-testid": "move-submission-event-id",
                                                    title: "{event_id}",
                                                    "event {event_id_label}"
                                                }
                                            }
                                        }
                                    }
                                    if record.state.is_failed() {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "move-failure-detail-toggle",
                                            onclick: {
                                                let mid = record.move_id.clone();
                                                move |_| {
                                                    let current = move_detail_open();
                                                    move_detail_open.set(if current.as_deref()
                                                        == Some(mid.as_str())
                                                    {
                                                        None
                                                    } else {
                                                        Some(mid.clone())
                                                    });
                                                }
                                            },
                                            "Failure detail"
                                        }
                                        if move_detail_open().as_deref() == Some(record.move_id.as_str()) {
                                            div {
                                                class: "muted",
                                                "data-testid": "move-failure-detail",
                                                if let Some(reason) = &record.reason {
                                                    div { "reason: {reason}" }
                                                } else {
                                                    div { "reason: (none reported)" }
                                                }
                                                if let Some(seal) = &record.seal_ref {
                                                    {
                                                        let seal_label = short_protocol_id(seal);
                                                        rsx! {
                                                            div { title: "{seal}", "bound seal: {seal_label}" }
                                                        }
                                                    }
                                                }
                                                div { "submitted_at: {record.submitted_at}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if active_section == RealmAdminSection::Security {
                div { class: "event admin-health-summary", "data-testid": "realm-security-summary",
                    div { class: "security-health-header",
                        div {
                            div { class: "event-head",
                                span { "Security health" }
                                span { class: security_health_badge, "{security_health_label}" }
                            }
                            p { class: "security-health-intro",
                                if security_health_label == "No active alerts" {
                                    "Everything looks ready from this device."
                                } else {
                                    "One or more security checks need attention."
                                }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: "security-diagnostics-button",
                            "data-testid": "security-diagnostics-toggle",
                            "aria-expanded": "{security_diagnostics_open()}",
                            onclick: move |_| security_diagnostics_open.toggle(),
                            if security_diagnostics_open() { "Hide diagnostics" } else { "Diagnostics" }
                        }
                    }
                    div { class: "security-health-list",
                        div { class: "security-health-row",
                            span {
                                class: if realm_paused { "security-status-dot is-alert" } else { "security-status-dot is-ok" },
                                "aria-hidden": "true"
                            }
                            div {
                                strong { "Realm activity" }
                                span { if realm_paused { "New changes are paused" } else { "New changes can be submitted" } }
                            }
                        }
                        div { class: "security-health-row",
                            span {
                                class: if realm_pending_mls_binding { "security-status-dot is-warning" } else { "security-status-dot is-ok" },
                                "aria-hidden": "true"
                            }
                            div {
                                strong { "Encrypted updates" }
                                span { if realm_pending_mls_binding { "Waiting for a security acknowledgement" } else { "Up to date" } }
                            }
                        }
                        if security_health_label != "No active alerts" {
                            div { class: "security-next-step",
                                span { class: "security-status-dot is-action", "aria-hidden": "true" }
                                div {
                                    strong { "Recommended next step" }
                                    span { "{security_next_step}" }
                                }
                            }
                        }
                    }
                }
                if security_diagnostics_open() {
                    div { class: "event security-diagnostics-panel", "data-testid": "security-diagnostics-panel",
                        div { class: "event-head",
                            span { "Diagnostics" }
                            span { "Local protocol state" }
                        }
                        p { class: "muted security-diagnostics-copy",
                            "Technical details for troubleshooting and support. These values do not normally require action."
                        }
                        div { class: "security-diagnostic-list",
                            div { class: "security-diagnostic-row", "data-testid": "mls-epoch-widget",
                                div {
                                    strong { "Encryption epoch" }
                                    span { class: "muted", "Latest locally published key generation" }
                                }
                                code { "data-testid": "mls-epoch-value", "{mls_epoch_label}" }
                            }
                            div { class: "security-diagnostic-row",
                                div {
                                    strong { "Epoch cell" }
                                    span { class: "muted", "Protocol family" }
                                }
                                code { {CellFamilyId::MLS_EPOCH_V1} }
                            }
                            div { class: "security-diagnostic-row", "data-testid": "seal-frontier-debug",
                                div {
                                    strong { "Seal frontier" }
                                    span { class: "muted", "{seal_leaf_count} accepted leaves" }
                                }
                                code { "data-testid": "seal-frontier-heads", title: "{seal_frontier_label}", "{short_protocol_id(&seal_frontier_label)}" }
                            }
                            div { class: "security-diagnostic-row",
                                div {
                                    strong { "State root" }
                                    span { class: "muted", "Current local projection" }
                                }
                                code { "data-testid": "seal-state-root", title: "{seal_state_root_label}", "{short_protocol_id(&seal_state_root_label)}" }
                            }
                            if let Some(root) = authority_root.clone() {
                                div { class: "security-diagnostic-row",
                                    div {
                                        strong { "Controller epoch" }
                                        span { class: "muted", "Ownership sequence" }
                                    }
                                    code { "data-testid": "governance-epoch", "{root.controller_epoch}" }
                                }
                                div { class: "security-diagnostic-row",
                                    div {
                                        strong { "Authority generation" }
                                        span { class: "muted", "Capability generation" }
                                    }
                                    code { "data-testid": "governance-generation", "{root.authority_generation}" }
                                }
                            }
                        }
                    }
                }
                // Realm governance — the two authority-root transitions
                // (`ak.realm.owner.transfer` / `ak.realm.authority.reset`). Both are sealed
                // control events whose registered execution is security:
                // the payload pins `expected_state_digest` to the replayed
                // root value, so a concurrent transition rejects with
                // `realm_authority_root_conflict` instead of merging.
                div { class: "event", "data-testid": "realm-governance-card",
                    div { class: "event-head",
                        span { "Ownership" }
                        span { class: if is_root_controller { "badge green" } else { "badge" },
                            if is_root_controller { "You are the owner" } else { "Member access" }
                        }
                    }
                    if let Some(root) = authority_root.clone() {
                        {
                            let controller_full = root.controller_actor_id.to_string();
                            let controller_label = short_protocol_id(&controller_full);
                            rsx! {
                                div { class: "security-owner-summary",
                                    div {
                                        span { class: "muted", "Current owner" }
                                        strong {
                                            class: "mono",
                                            title: "{controller_full}",
                                            "data-testid": "governance-controller",
                                            "{controller_label}"
                                        }
                                    }
                                    if is_root_controller {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "governance-controls-toggle",
                                            "aria-expanded": "{governance_controls_open()}",
                                            onclick: move |_| governance_controls_open.toggle(),
                                            if governance_controls_open() { "Close controls" } else { "Manage ownership" }
                                        }
                                    }
                                }
                            }
                        }
                        if is_root_controller && governance_controls_open() {
                            div { class: "workflow-form security-expanded-controls", "data-testid": "governance-owner-controls",
                                // Owner transfer — the root controller's only
                                // legitimate exit (capabilities.md §10.4).
                                div { class: "event-head",
                                    span { "Transfer ownership" }
                                }
                                div { class: "muted",
                                    "Choose a member to become the new owner. Your account will no longer control this Realm after the transfer completes."
                                }
                                label { "Successor (joined member)" }
                                Select::<String> {
                                    "data-testid": "owner-transfer-target-select",
                                    disabled: gov_transfer_candidates.is_empty(),
                                    value: Some(gov_transfer_target_selected.into()),
                                    on_value_change: move |v: Option<String>| {
                                        if let Some(v) = v {
                                            gov_transfer_target.set(v);
                                        }
                                    },
                                    SelectOption::<String> {
                                        index: 0usize,
                                        value: String::new(),
                                        text_value: if gov_transfer_candidates.is_empty() { "No other members projected yet" } else { "Select a member…" },
                                        if gov_transfer_candidates.is_empty() { "No other members projected yet" } else { "Select a member…" }
                                    }
                                    for (index, member) in gov_transfer_candidates.iter().enumerate() {
                                        SelectOption::<String> {
                                            key: "{member}",
                                            index: index + 1,
                                            value: member.clone(),
                                            text_value: "{member}",
                                            "{member}"
                                        }
                                    }
                                }
                                Label {
                                    html_for: "owner-transfer-acceptance-input",
                                    "Successor acceptance proof"
                                }
                                Textarea {
                                    id: "owner-transfer-acceptance-input",
                                    "data-testid": "owner-transfer-acceptance-input",
                                    value: "{gov_transfer_acceptance}",
                                    placeholder: "Paste the acceptance proof provided by the new owner.",
                                    oninput: move |event: FormEvent| gov_transfer_acceptance.set(event.value()),
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "owner-transfer-button",
                                        disabled: gov_transfer_target().trim().is_empty(),
                                        onclick: move |_| {
                                            gov_reset_confirm_open.set(false);
                                            gov_transfer_confirm_open.set(true);
                                        },
                                        "Transfer ownership…"
                                    }
                                }
                                // Authority reset — guarded destructive entry.
                                div { class: "security-danger-action",
                                    div {
                                        strong { "Revoke all existing permissions" }
                                        span { class: "muted",
                                            "Use only after a security incident. Members stay, but every granted permission must be issued again."
                                        }
                                    }
                                    Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "authority-reset-button",
                                            onclick: move |_| {
                                                gov_transfer_confirm_open.set(false);
                                                gov_reset_confirm_text.set(String::new());
                                                gov_reset_confirm_open.set(true);
                                            },
                                            "Revoke permissions…"
                                    }
                                }
                            }
                        } else if !is_root_controller {
                            div { class: "muted", "data-testid": "governance-not-controller",
                                "Only the current owner can transfer ownership or revoke Realm-wide permissions."
                            }
                        }
                    } else {
                        div { class: "muted", "data-testid": "governance-root-missing",
                            "Ownership information is not available yet. It may still be syncing."
                        }
                    }
                }

                // Owner-transfer confirmation (security_barrier second step).
                if gov_transfer_confirm_open() {
                    {
                        let transfer_target = gov_transfer_target().trim().to_owned();
                        let next_epoch = authority_root
                            .as_ref()
                            .map(|root| root.controller_epoch.saturating_add(1))
                            .unwrap_or_default();
                        let acceptance_present = !gov_transfer_acceptance().trim().is_empty();
                        rsx! {
                            crate::components::DismissiblePopup {
                                overlay_class: "modal-backdrop",
                                surface_class: "modal danger-confirm-modal",
                                overlay_test_id: Some("owner-transfer-confirm-modal".to_owned()),
                                surface_test_id: Some("owner-transfer-confirm-dialog".to_owned()),
                                aria_label: "Transfer Realm ownership".to_owned(),
                                on_dismiss: move |_| gov_transfer_confirm_open.set(false),
                                div { class: "modal-head",
                                    h3 { "Transfer Realm ownership" }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        class: "icon-button close",
                                        "aria-label": "Close",
                                        "data-testid": "owner-transfer-confirm-close",
                                        onclick: move |_| gov_transfer_confirm_open.set(false),
                                        "\u{2715}"
                                    }
                                }
                                div { class: "modal-body workflow-form",
                                    div { class: "callout danger", "data-testid": "owner-transfer-impact",
                                        strong { "This hands over root control" }
                                        p {
                                            "Once the transfer seals, the successor holds effective "
                                            "`ak.realm.owner` and this account keeps only whatever grants it "
                                            "was explicitly issued. The event is a security barrier: if the "
                                            "root changed concurrently it rejects instead of merging."
                                        }
                                    }
                                    div { class: "metric",
                                        strong { "Successor" }
                                        span { class: "mono", "data-testid": "owner-transfer-target-id", "{transfer_target}" }
                                    }
                                    div { class: "metric",
                                        strong { "Next controller epoch" }
                                        span { "data-testid": "owner-transfer-next-epoch", "{next_epoch}" }
                                    }
                                    if !acceptance_present {
                                        div { class: "muted", "data-testid": "owner-transfer-acceptance-missing",
                                            "The successor's acceptance proof is still empty — paste it in the "
                                            "governance card before confirming."
                                        }
                                    }
                                }
                                div { class: "modal-foot",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "owner-transfer-cancel-button",
                                        onclick: move |_| gov_transfer_confirm_open.set(false),
                                        "Cancel"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "owner-transfer-confirm-button",
                                        disabled: !acceptance_present,
                                        onclick: {
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor_principal_id = principal_id.clone();
                                            let root = authority_root.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let api_token = token();
                                                let actor_id = actor_principal_id.trim().to_owned();
                                                let target = gov_transfer_target().trim().to_owned();
                                                let acceptance = gov_transfer_acceptance().trim().to_owned();
                                                if actor_id.is_empty() {
                                                    status_msg.set("owner transfer failed: account is not connected".to_owned());
                                                    return;
                                                }
                                                let Some(root) = root.clone() else {
                                                    status_msg.set("owner transfer failed: authority root is not resolved locally".to_owned());
                                                    return;
                                                };
                                                let payload = match build_owner_transfer_payload(&realm, &root, &target, &acceptance) {
                                                    Ok(payload) => payload,
                                                    Err(err) => {
                                                        status_msg.set(format!("owner transfer build failed: {err}"));
                                                        return;
                                                    }
                                                };
                                                gov_transfer_confirm_open.set(false);
                                                let target_for_msg = target.clone();
                                                controller.transfer_owner(base, api_token, actor_id, payload, target_for_msg);
                                            }
                                        },
                                        "Transfer ownership"
                                    }
                                }
                            }
                        }
                    }
                }

                // Authority-reset confirmation: the operator must type the
                // literal spec token, which ships as
                // `destructive_confirmation` verbatim.
                if gov_reset_confirm_open() {
                    {
                        let confirm_token = event_kind_str::REALM_AUTHORITY_RESET;
                        let confirm_matches = gov_reset_confirm_text().trim() == confirm_token;
                        let next_generation = authority_root
                            .as_ref()
                            .map(|root| root.authority_generation.saturating_add(1))
                            .unwrap_or_default();
                        rsx! {
                            crate::components::DismissiblePopup {
                                overlay_class: "modal-backdrop",
                                surface_class: "modal danger-confirm-modal",
                                overlay_test_id: Some("authority-reset-confirm-modal".to_owned()),
                                surface_test_id: Some("authority-reset-confirm-dialog".to_owned()),
                                aria_label: "Reset authority generation".to_owned(),
                                on_dismiss: move |_| gov_reset_confirm_open.set(false),
                                div { class: "modal-head",
                                    h3 { "Reset authority generation" }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        class: "icon-button close",
                                        "aria-label": "Close",
                                        "data-testid": "authority-reset-confirm-close",
                                        onclick: move |_| gov_reset_confirm_open.set(false),
                                        "\u{2715}"
                                    }
                                }
                                div { class: "modal-body workflow-form",
                                    div { class: "callout danger", "data-testid": "authority-reset-impact",
                                        strong { "Every existing capability grant dies" }
                                        p {
                                            "Advancing the authority generation to {next_generation} invalidates "
                                            "every capability issued under the current generation — admins, "
                                            "delegations, applet grants, all of it. Members keep membership but "
                                            "lose granted authority until it is re-issued. This cannot be undone."
                                        }
                                    }
                                    Label {
                                        html_for: "authority-reset-confirm-input",
                                        "Type {confirm_token} to continue"
                                    }
                                    Input {
                                        id: "authority-reset-confirm-input",
                                        "data-testid": "authority-reset-confirm-input",
                                        value: "{gov_reset_confirm_text}",
                                        oninput: move |event: FormEvent| gov_reset_confirm_text.set(event.value()),
                                    }
                                }
                                div { class: "modal-foot",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "authority-reset-cancel-button",
                                        onclick: move |_| gov_reset_confirm_open.set(false),
                                        "Cancel"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "authority-reset-confirm-button",
                                        disabled: !confirm_matches,
                                        onclick: {
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor_principal_id = principal_id.clone();
                                            let root = authority_root.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let api_token = token();
                                                let actor_id = actor_principal_id.trim().to_owned();
                                                let typed_confirmation = gov_reset_confirm_text().trim().to_owned();
                                                if actor_id.is_empty() {
                                                    status_msg.set("authority reset failed: account is not connected".to_owned());
                                                    return;
                                                }
                                                let Some(root) = root.clone() else {
                                                    status_msg.set("authority reset failed: authority root is not resolved locally".to_owned());
                                                    return;
                                                };
                                                let payload = match build_authority_reset_payload(&realm, &root, &typed_confirmation) {
                                                    Ok(payload) => payload,
                                                    Err(err) => {
                                                        status_msg.set(format!("authority reset build failed: {err}"));
                                                        return;
                                                    }
                                                };
                                                gov_reset_confirm_open.set(false);
                                                gov_reset_confirm_text.set(String::new());
                                                controller.reset_authority(base, api_token, actor_id, payload);
                                            }
                                        },
                                        "Reset authority generation"
                                    }
                                }
                            }
                        }
                    }
                }

            }
            if active_section == RealmAdminSection::Profile {
                // Realm / Space profile editor. Spec fields are `title`,
                // optional `summary`, and optional `avatar_blob_ref`.
                // Access policy lives in the Access tab.
                div { class: "event", "data-testid": "realm-profile",
                    div { class: "event-head",
                        span { "{metadata_subject_label} Profile" }
                        span { "{metadata_event_kind}" }
                    }
                    div { class: "muted",
                        span { class: "mono", title: "{selected_realm_id}", "{short_protocol_id(&selected_realm_id)}" }
                        if metadata_subject.kind == RealmTreeNodeKind::Space {
                            span { " · home Realm " }
                            span {
                                class: "mono",
                                title: "{metadata_subject.home_realm_id}",
                                "{short_protocol_id(&metadata_subject.home_realm_id)}"
                            }
                        }
                    }
                    div { class: "workflow-form",
                        Label { html_for: "realm-name-input", "Title" }
                        Input {
                            id: "realm-name-input",
                            "data-testid": "realm-name-input",
                            value: "{metadata_title}",
                            placeholder: "{metadata_subject_label} title",
                            oninput: move |event: FormEvent| metadata_title.set(event.value()),
                        }
                        Label { html_for: "realm-summary-input", "Summary" }
                        Textarea {
                            id: "realm-summary-input",
                            "data-testid": "realm-summary-input",
                            value: "{metadata_summary}",
                            placeholder: "Optional summary",
                            oninput: move |event: FormEvent| metadata_summary.set(event.value()),
                        }
                        Label { html_for: "realm-alias-input", "Alias" }
                        Input {
                            id: "realm-alias-input",
                            "data-testid": "realm-alias-input",
                            value: "{metadata_alias}",
                            placeholder: "engineering (Realm only)",
                            oninput: move |event: FormEvent| metadata_alias.set(event.value()),
                        }
                        label { "Avatar" }
                        crate::components::AvatarUploader {
                            current_blob_ref: metadata_avatar_blob_ref(),
                            alt_text: format!("{metadata_subject_label} avatar"),
                            api_token: token(),
                            upload_realm_id: Some(metadata_subject.home_realm_id.clone()),
                            test_id_prefix: "realm-avatar".to_owned(),
                            on_uploaded: move |blob_ref: String| {
                                metadata_avatar_blob_ref.set(blob_ref);
                                status_msg.set("avatar uploaded; Save Profile publishes it".to_owned());
                            },
                            on_clear: move |_| {
                                metadata_avatar_blob_ref.set(String::new());
                                status_msg.set("avatar cleared; Save Profile publishes it".to_owned());
                            },
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "update-metadata-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let subject_id = selected_realm_id.clone();
                                    let subject_kind = metadata_subject.kind;
                                    let home_realm_id = metadata_subject.home_realm_id.clone();
                                    let stored_summary = metadata_subject.summary.trim().to_owned();
                                    let actor_principal_id = principal_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let subject_id = subject_id.clone();
                                        let home_realm_id = home_realm_id.clone();
                                        let api_token = token();
                                        let title = metadata_title().trim().to_owned();
                                        let summary = metadata_summary().trim().to_owned();
                                        let avatar_blob_ref = metadata_avatar_blob_ref().trim().to_owned();
                                        let alias = metadata_alias().trim().to_owned();
                                        let updates_alias =
                                            subject_kind == RealmTreeNodeKind::Realm && !alias.is_empty();
                                        if title.is_empty() {
                                            status_msg.set(
                                                "profile update failed: title is required by spec".to_owned(),
                                            );
                                            return;
                                        }
                                        // The SDK `BlobRef` newtype is the gate:
                                        // an `ak:blob:` prefix test admits values
                                        // `common-ids.schema.json` rejects, and the
                                        // publish path already re-validates through the
                                        // same type.
                                        if !avatar_blob_ref.is_empty()
                                            && arkret_sdk::BlobRef::new(avatar_blob_ref.clone())
                                                .is_err()
                                        {
                                            status_msg.set(
                                                "profile update failed: avatar_blob_ref must be a canonical blob reference".to_owned(),
                                            );
                                            return;
                                        }
                                        // Realm/Space metadata events are authored by the
                                        // account/principal DID, not the device DID, or the server
                                        // rejects them with `actor_session_mismatch`.
                                        let actor_id = actor_principal_id.trim().to_owned();
                                        if actor_id.is_empty() {
                                            status_msg.set(
                                                "profile update failed: account is not connected".to_owned(),
                                            );
                                            return;
                                        }
                                        let mut patch = serde_json::Map::new();
                                        patch.insert("title".to_owned(), json!(title));
                                        // `summary` is an ordinary optional member, not a
                                        // redactable content-carrier slot: only `content` /
                                        // `encrypted_content` are registered in
                                        // `redactable-field-registry.json`, so
                                        // `event-and-patch.md` §4.2.4 makes `$op: unset` the
                                        // non-terminal clear path here, exactly as for
                                        // `avatar_blob_ref` below. A Realm profile is a full
                                        // restatement of the singleton `ak.realm.profile` facet,
                                        // where the same op reads as "no summary".
                                        if !summary.is_empty() {
                                            patch.insert("summary".to_owned(), json!(summary));
                                        } else if !stored_summary.is_empty() {
                                            patch.insert(
                                                "summary".to_owned(),
                                                json!({ "$op": "unset" }),
                                            );
                                        }
                                        patch.insert(
                                            "avatar_blob_ref".to_owned(),
                                            if avatar_blob_ref.is_empty() {
                                                json!({ "$op": "unset" })
                                            } else {
                                                json!(avatar_blob_ref)
                                            },
                                        );
                                        let patch = Value::Object(patch);
                                        let accepted_title = title.clone();
                                        let accepted_summary = (!summary.is_empty()).then_some(summary.clone());
                                        let accepted_avatar = (!avatar_blob_ref.is_empty())
                                            .then_some(avatar_blob_ref.clone());
                                        let causal_refs = match metadata_causal_refs(
                                            &state_store.read(),
                                            &home_realm_id,
                                            subject_kind,
                                            &subject_id,
                                        ) {
                                            Ok(refs) => refs,
                                            Err(error) => {
                                                status_msg.set(format!("profile update blocked: {error}"));
                                                return;
                                            }
                                        };
                                        controller.save_metadata(
                                            base,
                                            api_token,
                                            actor_id,
                                            MetadataWriteSubject {
                                                home_realm_id,
                                                subject_id,
                                                kind: subject_kind,
                                                event_kind: metadata_event_kind,
                                                updates_alias,
                                                causal_refs,
                                            },
                                            patch,
                                            alias,
                                            AcceptedRealmProfile {
                                                title: accepted_title,
                                                summary: accepted_summary,
                                                avatar_blob_ref: accepted_avatar,
                                            },
                                        );
                                    }
                                },
                                {crate::i18n::tr("realm_admin.save_profile")}
                            }
                            if metadata_subject.kind == RealmTreeNodeKind::Realm {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "remove-realm-alias-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let home_realm_id = metadata_subject.home_realm_id.clone();
                                        let actor_principal_id = principal_id.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let home_realm_id = home_realm_id.clone();
                                            let actor_id = actor_principal_id.trim().to_owned();
                                            let api_token = token();
                                            if actor_id.is_empty() {
                                                status_msg.set(
                                                    "alias removal failed: account is not connected".to_owned(),
                                                );
                                                return;
                                            }
                                            controller.remove_alias(base, api_token, actor_id, home_realm_id);
                                        }
                                    },
                                    "Remove Alias"
                                }
                            }
                        }
                    }
                }
            }

            if active_section == RealmAdminSection::Access {
            // Join policy selector
            div { class: "event", "data-testid": "join-policy",
                div { class: "event-head", span { "Join Policy" } span { "access control" } }
                div { class: "actions",
                    Button {
                        variant: if join_rule() == "public" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("public".to_owned()),
                        "Public"
                    }
                    Button {
                        variant: if join_rule() == "invite" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("invite".to_owned()),
                        "Invite"
                    }
                    Button {
                        variant: if join_rule() == "knock" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("knock".to_owned()),
                        "Knock"
                    }
                    Button {
                        variant: if join_rule() == "restricted" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("restricted".to_owned()),
                        "Restricted"
                    }
                }
                div { class: "muted", "Current: {join_rule}" }
            }

            div { class: "event", "data-testid": "principal-admission-policy",
                div { class: "event-head", span { "Principal Admission" } span { "hard gate" } }
                label {
                    Checkbox {
                        checked: if principal_admission_enabled() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                        on_checked_change: move |state: CheckboxState| principal_admission_enabled.set(bool::from(state)),
                    }
                    " Enabled"
                }
                if principal_admission_enabled() {
                    Label { html_for: "principal-admission-methods-input", "Allowed DID methods" }
                    Input {
                        id: "principal-admission-methods-input",
                        "data-testid": "principal-admission-methods-input",
                        value: "{principal_admission_methods}",
                        placeholder: "did:webvh, did:web",
                        oninput: move |event: FormEvent| principal_admission_methods.set(event.value()),
                    }
                    Label { html_for: "principal-admission-allowed-ids-input", "Allowed principal ids" }
                    Textarea {
                        id: "principal-admission-allowed-ids-input",
                        "data-testid": "principal-admission-allowed-ids-input",
                        value: "{principal_admission_allowed_ids}",
                        placeholder: "ak:did_core:webvh:<scid>:alice.example",
                        oninput: move |event: FormEvent| principal_admission_allowed_ids.set(event.value()),
                    }
                    Label { html_for: "principal-admission-denied-ids-input", "Denied principal ids" }
                    Textarea {
                        id: "principal-admission-denied-ids-input",
                        "data-testid": "principal-admission-denied-ids-input",
                        value: "{principal_admission_denied_ids}",
                        placeholder: "ak:did_core:webvh:<scid>:blocked.example",
                        oninput: move |event: FormEvent| principal_admission_denied_ids.set(event.value()),
                    }
                } else {
                    div { class: "muted", "Disabled" }
                }
            }

            // History access can only tighten from all-history to since-join.
            div { class: "event", "data-testid": "history-access",
                div { class: "event-head", span { "History Access" } span { "One-way tightening" } }
                div { class: "actions",
                    Button {
                        variant: if tighten_history_access() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| tighten_history_access.set(!tighten_history_access()),
                        "Tighten to since joining"
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "apply-policy-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = principal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                let rule = join_rule();
                                let tighten_access = tighten_history_access();
                                let join_policy = match build_principal_admission_join_policy(
                                    principal_admission_enabled(),
                                    &principal_admission_methods(),
                                    &principal_admission_allowed_ids(),
                                    &principal_admission_denied_ids(),
                                ) {
                                    Ok(policy) => policy,
                                    Err(err) => {
                                        status_msg.set(format!("policy failed: {err}"));
                                        return;
                                    }
                                };
                                let preserve_recommended_encryption_floor = state_store
                                    .read()
                                    .load()
                                    .realm_tree_projections
                                    .get(&realm)
                                    .is_some_and(projection_has_recommended_encryption_floor);
                                controller.apply_policy(
                                    base,
                                    api_token,
                                    realm,
                                    actor,
                                    rule,
                                    tighten_access,
                                    join_policy,
                                    preserve_recommended_encryption_floor,
                                );
                            }
                        },
                        {crate::i18n::tr("realm_admin.apply_policy")}
                    }
                }
            }
            } // closes `if active_section == RealmAdminSection::Access`

            if active_section == RealmAdminSection::Security {
            // MLS epoch rotation: the spec has no
            // `POST /_arkret/self/mls/rotate` shim — epoch rotation is a
            // real local `self_update_commit` published as the canonical
            // `ak.mls.commit` event (persist-on-accept).
            div { class: "event", "data-testid": "mls-rotation",
                div { class: "security-action-row",
                    div {
                        strong { "Encryption keys" }
                        span { class: "muted", "Keys update automatically when membership changes. You can also refresh them now." }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "rotate-realm-epoch",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_principal_id = principal_id.clone();
                            let device = device_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor_id = actor_principal_id.trim().to_owned();
                                let device = device.clone();
                                let api_token = token();
                                if actor_id.is_empty() {
                                    status_msg.set("rotate failed: account is not connected".to_owned());
                                    return;
                                }
                                // Build the forced self-update commit + the
                                // canonical ak.mls.commit event locally.
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("inkson");
                                let Some(account) = crate::app::SessionContext::get().active_account() else {
                                    status_msg.set("rotate failed: active account context is unavailable".to_owned());
                                    return;
                                };
                                if account.principal_id().as_str() != actor_id
                                    || account.device_id.as_str() != device
                                {
                                    status_msg.set("rotate failed: active account authority changed".to_owned());
                                    return;
                                }
                                controller.rotate_mls_epoch(
                                    base,
                                    api_token,
                                    realm,
                                    actor_id,
                                    device,
                                    account,
                                    secure_store,
                                );
                            }
                        },
                        "Refresh keys"
                    }
                }
            }
            }

            if active_section == RealmAdminSection::Repair {
            // Leave Realm. The button only opens the confirmation dialog;
            // the membership event is submitted from the dialog's confirm
            // button below.
            div { class: "event", "data-testid": "leave-realm",
                div { class: "event-head", span { "Leave Realm" } span { "" } }
                // capabilities.md §10.4 L858: the root controller's only exit
                // is `ak.realm.owner.transfer` — a plain leave would strand
                // the authority root, so it is blocked here with directions
                // instead of failing opaquely downstream.
                if is_root_controller {
                    div { class: "callout danger", "data-testid": "leave-realm-owner-guard",
                        strong { "Transfer ownership first" }
                        p {
                            "You currently own this Realm. Transfer ownership from Security → Ownership before leaving."
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "leave-realm-button",
                        disabled: is_root_controller,
                        onclick: move |_| {
                            if is_root_controller {
                                status_msg.set(
                                    "leave blocked: transfer Realm ownership first (ak.realm.owner.transfer)"
                                        .to_owned(),
                                );
                                return;
                            }
                            leave_confirm_open.set(true)
                        },
                        {crate::i18n::tr("realm_admin.leave_realm")}
                    }
                }
            }

            if leave_confirm_open() {
                crate::components::DismissiblePopup {
                    overlay_class: "modal-backdrop",
                    surface_class: "modal danger-confirm-modal",
                    overlay_test_id: Some("leave-realm-confirm-modal".to_owned()),
                    surface_test_id: Some("leave-realm-confirm-dialog".to_owned()),
                    aria_label: crate::i18n::tr("realm_admin.leave_confirm_title"),
                    on_dismiss: move |_| leave_confirm_open.set(false),
                    div { class: "modal-head",
                        h3 { {crate::i18n::tr("realm_admin.leave_confirm_title")} }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: "icon-button close",
                            "aria-label": "Close",
                            "data-testid": "leave-realm-confirm-close",
                            onclick: move |_| leave_confirm_open.set(false),
                            "\u{2715}"
                        }
                    }
                    div { class: "modal-body workflow-form",
                        div { class: "callout danger", "data-testid": "leave-realm-impact",
                            p { {crate::i18n::tr("realm_admin.leave_confirm_body")} }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("realm_admin.leave_confirm_target")} }
                            span { class: "mono", "data-testid": "leave-realm-target-id", "{selected_realm_id}" }
                        }
                    }
                    div { class: "modal-foot",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "leave-realm-cancel-button",
                            onclick: move |_| leave_confirm_open.set(false),
                            {crate::i18n::tr("realm_admin.leave_confirm_cancel")}
                        }
                        Button {
                            variant: ButtonVariant::Destructive,
                            "data-testid": "leave-realm-confirm-button",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor_principal_id = principal_id.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let api_token = token();
                                    // Membership events are authored by the account/principal DID
                                    // (the authenticated session actor), not the device DID, or the server
                                    // rejects them with `actor_session_mismatch`.
                                    let actor_id = actor_principal_id.trim().to_owned();
                                    if actor_id.is_empty() {
                                        status_msg.set("Leave Realm failed: account is not connected".to_owned());
                                        return;
                                    }
                                    // Root-controller guard (see the card-level
                                    // callout): never author the dead-end leave.
                                    if is_root_controller {
                                        leave_confirm_open.set(false);
                                        status_msg.set(
                                            "leave blocked: transfer Realm ownership first (ak.realm.owner.transfer)"
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    leave_confirm_open.set(false);
                                    controller.leave_realm(base, api_token, realm, actor_id);
                                }
                            },
                            {crate::i18n::tr("realm_admin.leave_confirm_button")}
                        }
                    }
                }
            }
            }

            if active_section == RealmAdminSection::Security {
            div { class: "event security-advanced-card", "data-testid": "advanced-access-summary",
                div { class: "security-action-row",
                    div {
                        strong { "Advanced permissions" }
                        span { class: "muted", "Grant individual capabilities or Realm administrator access." }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "advanced-access-toggle",
                        "aria-expanded": "{advanced_access_open()}",
                        onclick: move |_| advanced_access_open.toggle(),
                        if advanced_access_open() { "Close" } else { "Manage permissions" }
                    }
                }
            }
            if advanced_access_open() {
            div { class: "settings-content-stack security-advanced-controls", "data-testid": "advanced-access-controls",
            div { class: "event", "data-testid": "capability-grant-card",
                div { class: "event-head",
                    span { "Capability grant / revoke" }
                    span { "Advanced" }
                }
                Label { html_for: "cap-grant-id-input", "Grant ID (required for revoke only)" }
                Input {
                    id: "cap-grant-id-input",
                    "data-testid": "cap-grant-id-input",
                    value: "{cap_grant_id}",
                    oninput: move |event: FormEvent| cap_grant_id.set(event.value()),
                }
                Label { html_for: "cap-grant-tag-input", "Capability tag (action / scope)" }
                Input {
                    id: "cap-grant-tag-input",
                    "data-testid": "cap-grant-tag-input",
                    value: "{cap_tag}",
                    oninput: move |event: FormEvent| cap_tag.set(event.value()),
                }
                Label { html_for: "cap-grant-subject-input", "Subject DID (grantee — required for grant)" }
                Input {
                    id: "cap-grant-subject-input",
                    "data-testid": "cap-grant-subject-input",
                    value: "{cap_subject}",
                    oninput: move |event: FormEvent| cap_subject.set(event.value()),
                }
                Label { html_for: "cap-revoke-reason-input", "Revoke reason (optional)" }
                Input {
                    id: "cap-revoke-reason-input",
                    "data-testid": "cap-revoke-reason-input",
                    value: "{cap_revoke_reason}",
                    oninput: move |event: FormEvent| cap_revoke_reason.set(event.value()),
                }
                // Capability constraint editor. Choose a family from the
                // dropdown (`temporal` / `quota` / `scope_limitation` /
                // `none`) and fill in the form for that family. Today only
                // `temporal` is fully wired - the other options surface
                // their hint copy but no inputs (matching the move_builder
                // constraint surface, which only provides a `temporal`
                // builder helper).
                div { class: "event-head", "data-testid": "cap-constraint-editor",
                    span { "Constraint" }
                    span { "temporal MVP · quota / scope_limitation soon" }
                }
                label { "Constraint family" }
                Select::<String> {
                    "data-testid": "cap-constraint-kind-select",
                    value: Some(cap_constraint_kind_selected.into()),
                    on_value_change: move |v: Option<String>| { if let Some(v) = v { cap_constraint_kind.set(v); } },
                    SelectOption::<String> { index: 0usize, value: "none".to_string(), text_value: "none", "none" }
                    SelectOption::<String> { index: 1usize, value: "temporal".to_string(), text_value: "temporal (not_before / expires_at)", "temporal (not_before / expires_at)" }
                    SelectOption::<String> { index: 2usize, value: "quota".to_string(), text_value: "quota (coming soon)", "quota (coming soon)" }
                    SelectOption::<String> { index: 3usize, value: "scope_limitation".to_string(), text_value: "scope_limitation (coming soon)", "scope_limitation (coming soon)" }
                }
                if cap_constraint_kind() == "temporal" {
                    div { "data-testid": "cap-constraint-temporal-fields",
                        Label { html_for: "cap-constraint-not-before-input", "not_before (RFC 3339, optional)" }
                        input {
                            id: "cap-constraint-not-before-input",
                            "data-testid": "cap-constraint-not-before-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_not_before}",
                            oninput: move |evt| {
                                cap_temporal_not_before.set(evt.value());
                            },
                        }
                        Label { html_for: "cap-constraint-expires-at-input", "expires_at (RFC 3339, optional)" }
                        input {
                            id: "cap-constraint-expires-at-input",
                            "data-testid": "cap-constraint-expires-at-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_expires_at}",
                            oninput: move |evt| {
                                cap_temporal_expires_at.set(evt.value());
                            },
                        }
                    }
                } else if cap_constraint_kind() == "quota"
                    || cap_constraint_kind() == "scope_limitation"
                {
                    div {
                        class: "muted",
                        "data-testid": "cap-constraint-coming-soon",
                        "{cap_constraint_kind()} editor not yet implemented; the constraint "
                        "is forwarded as a free-form JSON object on the grant once a UI lands."
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "cap-grant-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_principal_id = principal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let tag_val = cap_tag().trim().to_owned();
                                let subject_val = cap_subject().trim().to_owned();
                                if tag_val.is_empty() || subject_val.is_empty() {
                                    status_msg.set(
                                        "fill tag + subject DID before submitting capability grant".to_owned(),
                                    );
                                    return;
                                }
                                // Capability events are authored by the account/principal DID,
                                // not the device DID, or the server returns
                                // `actor_session_mismatch`.
                                let actor_id = actor_principal_id.trim().to_owned();
                                if actor_id.is_empty() {
                                    status_msg.set(
                                        "capability grant failed: account is not connected".to_owned(),
                                    );
                                    return;
                                }
                                // The subject is closed against the Realm roster (or pasted
                                // as the full selector); a bare principal is never completed
                                // with this client's Station.
                                let subject_account = match resolve_realm_member_account(
                                    &state_store.read(),
                                    &realm,
                                    &subject_val,
                                ) {
                                    Ok(subject) => subject,
                                    Err(err) => {
                                        status_msg.set(format!("capability grant failed: {err}"));
                                        return;
                                    }
                                };
                                // Pull the active constraint from the editor
                                // signals into the canonical `grant-constraint`
                                // shape (`{constraint_kind, effect, …}`). Empty
                                // input yields no constraint. `expires_at` is the
                                // grant's own validity bound, so it is threaded
                                // through the builder directly (not as a
                                // constraint) while the temporal constraint keeps
                                // only `not_before`.
                                let kind = cap_constraint_kind();
                                let expires_at_val = cap_temporal_expires_at().trim().to_owned();
                                let expires_at_opt = if kind == "temporal" && !expires_at_val.is_empty() {
                                    Some(expires_at_val.clone())
                                } else {
                                    None
                                };
                                let constraint_json: serde_json::Value =
                                    if kind == "temporal" {
                                        let nb = cap_temporal_not_before();
                                        let nb_trim = nb.trim();
                                        if nb_trim.is_empty() && expires_at_opt.is_none() {
                                            serde_json::Value::Null
                                        } else {
                                            let mut constraint = serde_json::Map::new();
                                            constraint.insert(
                                                "constraint_kind".into(),
                                                serde_json::Value::String("temporal".to_owned()),
                                            );
                                            constraint.insert(
                                                "effect".into(),
                                                serde_json::Value::String("allow".to_owned()),
                                            );
                                            if !nb_trim.is_empty() {
                                                constraint.insert(
                                                    "not_before".into(),
                                                    serde_json::Value::String(nb_trim.to_owned()),
                                                );
                                            }
                                            if let Some(ea) = expires_at_opt.as_deref() {
                                                constraint.insert(
                                                    "expires_at".into(),
                                                    serde_json::Value::String(ea.to_owned()),
                                                );
                                            }
                                            json!([serde_json::Value::Object(constraint)])
                                        }
                                    } else {
                                        serde_json::Value::Null
                                    };
                                let envelope = crate::operation::ak_ops::capability_grant_actions(
                                    &realm,
                                    &actor_id,
                                    &subject_account,
                                    &[tag_val.as_str()],
                                    expires_at_opt.as_deref(),
                                    constraint_json,
                                    issuer_root_basis,
                                )
                                .and_then(|builder| builder.build_sdk_event("inkson"));
                                let envelope = match envelope {
                                    Ok(envelope) => envelope,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "capability.grant build failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let op_id = envelope.local_operation_id().to_string();
                                controller.submit_capability_event(
                                    base,
                                    api_token,
                                    envelope,
                                    op_id,
                                    "ak.capability.grant",
                                    "capability.grant",
                                    true,
                                );
                            }
                        },
                        {crate::i18n::tr("realm_admin.grant_capability_move")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "cap-revoke-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_principal_id = principal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let grant_val = cap_grant_id().trim().to_owned();
                                let reason_val = cap_revoke_reason();
                                let reason_opt = if reason_val.trim().is_empty() {
                                    None
                                } else {
                                    Some(reason_val.clone())
                                };
                                if grant_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id before submitting capability revoke".to_owned(),
                                    );
                                    return;
                                }
                                // Capability events are authored by the account/principal DID,
                                // not the device DID, or the server returns
                                // `actor_session_mismatch`.
                                let actor_id = actor_principal_id.trim().to_owned();
                                if actor_id.is_empty() {
                                    status_msg.set(
                                        "capability revoke failed: account is not connected".to_owned(),
                                    );
                                    return;
                                }
                                let envelope = match crate::operation::ak_ops::capability_revoke(
                                    &realm,
                                    &actor_id,
                                    &grant_val,
                                    reason_opt.as_deref(),
                                ) {
                                    Ok(builder) => match builder.build_sdk_event("inkson") {
                                        Ok(envelope) => envelope,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "capability.revoke build failed: {err}"
                                            ));
                                            return;
                                        }
                                    },
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "capability.revoke build failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let op_id = envelope.local_operation_id().to_string();
                                controller.submit_capability_event(
                                    base,
                                    api_token,
                                    envelope,
                                    op_id,
                                    "ak.capability.revoke",
                                    "capability.revoke",
                                    false,
                                );
                            }
                        },
                        {crate::i18n::tr("realm_admin.revoke_capability_move")}
                    }
                }
            }
            div { class: "event", "data-testid": "realm-admin-grant-card",
                div { class: "event-head",
                    span { {crate::i18n::tr("realm_admin.admin_grant_title")} }
                    span { class: "badge", {CapabilityActionId::REALM_ADMIN} }
                }
                div { class: "muted",
                    {crate::i18n::tr("realm_admin.admin_grant_hint")}
                }
                Label { html_for: "realm-admin-subject-input", {crate::i18n::tr("realm_admin.admin_subject_label")} }
                Input {
                    id: "realm-admin-subject-input",
                    "data-testid": "realm-admin-subject-input",
                    value: "{admin_subject_id}",
                    placeholder: "ak:did_core:…",
                    oninput: move |event: FormEvent| admin_subject_id.set(event.value()),
                }
                Label { html_for: "realm-admin-grant-id-input", {crate::i18n::tr("realm_admin.admin_grant_id_label")} }
                Input {
                    id: "realm-admin-grant-id-input",
                    "data-testid": "realm-admin-grant-id-input",
                    value: "{admin_grant_id}",
                    placeholder: "ak:grant:… (auto on grant, paste on revoke)",
                    oninput: move |event: FormEvent| admin_grant_id.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "realm-admin-grant-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_principal_id = principal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let subject = admin_subject_id().trim().to_owned();
                                let actor_id = actor_principal_id.trim().to_owned();
                                if subject.is_empty() {
                                    status_msg.set(crate::i18n::tr("realm_admin.admin_subject_required"));
                                    return;
                                }
                                if actor_id.is_empty() {
                                    status_msg.set("set admin failed: account is not connected".to_owned());
                                    return;
                                }
                                let subject = match resolve_realm_member_account(
                                    &state_store.read(),
                                    &realm,
                                    &subject,
                                ) {
                                    Ok(subject) => subject,
                                    Err(err) => {
                                        status_msg.set(format!("set admin failed: {err}"));
                                        return;
                                    }
                                };
                                controller.grant_realm_admin(base, api_token, realm, actor_id, subject, issuer_root_basis);
                            }
                        },
                        {crate::i18n::tr("realm_admin.admin_grant_button")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "realm-admin-revoke-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_principal_id = principal_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let grant_id = admin_grant_id().trim().to_owned();
                                let actor_id = actor_principal_id.trim().to_owned();
                                if grant_id.is_empty() {
                                    status_msg.set(crate::i18n::tr("realm_admin.admin_grant_id_required"));
                                    return;
                                }
                                if actor_id.is_empty() {
                                    status_msg.set("revoke admin failed: account is not connected".to_owned());
                                    return;
                                }
                                controller.revoke_realm_admin(base, api_token, realm, actor_id, grant_id);
                            }
                        },
                        {crate::i18n::tr("realm_admin.admin_revoke_button")}
                    }
                }
            }
            }
            }
            }

            if active_section == RealmAdminSection::Federation {
                div { class: "event", "data-testid": "trust-bundle-panel",
                    div { class: "event-head",
                        span { "Federation trust" }
                        span { "Admin tooling" }
                    }
                    div { class: "muted",
                        "Trust bundle import, validation, and revocation are not wired in inkson. Use the deployment's admin tooling for federation trust changes."
                    }
                }
                // SOL-ORG-06 — read-only view of this Realm's verified
                // organization relationships (verified-active / revoked-expired)
                // and declared owning-organization hints. Binding and
                // organization-side signing live in the admin console (sodmin).
                super::RealmOrganizationPanel {
                    token,
                    realm_id: selected_realm_id.clone(),
                    principal_id: principal_id.clone(),
                }
            }

            // P3 — moderation reviewer workbench (decision/lift). Drives the
            // daily-governance moderation API; queues project from the local
            // raw-operation log.
            if active_section == RealmAdminSection::Moderation {
                crate::views::moderation::ModerationWorkbench {
                    principal_id: principal_id.clone(),
                    token,
                    selected_realm_id: selected_realm_id.clone(),
                }
            }

            // Danger zone
            if active_section == RealmAdminSection::Repair {
            div { class: "event", "data-testid": "danger-zone",
                div { class: "event-head", span { "Danger Zone" } span { "destructive actions" } }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "archive-realm-button",
                        onclick: move |_| {
                            danger_confirm_text.set(String::new());
                            destroy_confirm_open.set(false);
                            archive_confirm_open.set(true);
                        },
                        {crate::i18n::tr("realm_admin.archive_realm")}
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "destroy-realm-button",
                        onclick: move |_| {
                            danger_confirm_text.set(String::new());
                            archive_confirm_open.set(false);
                            destroy_confirm_open.set(true);
                        },
                        {crate::i18n::tr("realm_admin.destroy_realm")}
                    }
                }
            }

            }

            if active_section == RealmAdminSection::Repair
                && (archive_confirm_open() || destroy_confirm_open())
            {
                {
                    let is_destroy = destroy_confirm_open();
                    let title = if is_destroy { "Destroy Realm" } else { "Archive Realm" };
                    let confirm_label = if is_destroy { "Destroy Realm" } else { "Archive Realm" };
                    let body = if is_destroy {
                        "Destroying a Realm is destructive and may make its realm, members, policy, and encrypted history unavailable. This should only be used when the operator has verified the recovery and audit path."
                    } else {
                        "Archiving removes the Realm from active collaboration flows. Members may lose the normal working entry point until an operator restores or migrates it."
                    };
                    let confirm_matches = danger_confirm_text().trim() == selected_realm_id.trim();
                    rsx! {
                        crate::components::DismissiblePopup {
                            overlay_class: "modal-backdrop",
                            surface_class: "modal danger-confirm-modal",
                            overlay_test_id: Some("realm-danger-confirm-modal".to_owned()),
                            surface_test_id: Some("realm-danger-confirm-dialog".to_owned()),
                            aria_label: title.to_owned(),
                            on_dismiss: move |_| {
                                archive_confirm_open.set(false);
                                destroy_confirm_open.set(false);
                                danger_confirm_text.set(String::new());
                            },
                            div { class: "modal-head",
                                h3 { "{title}" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "icon-button close",
                                    "aria-label": "Close",
                                    "data-testid": "realm-danger-confirm-close",
                                    onclick: move |_| {
                                        archive_confirm_open.set(false);
                                        destroy_confirm_open.set(false);
                                        danger_confirm_text.set(String::new());
                                    },
                                    "\u{2715}"
                                }
                            }
                            div { class: "modal-body workflow-form",
                                div { class: "callout danger", "data-testid": "realm-danger-impact",
                                    strong { "Confirm operator intent" }
                                    p { "{body}" }
                                }
                                div { class: "metric",
                                    strong { "Target Realm ID" }
                                    span { class: "mono", "data-testid": "realm-danger-target-id", "{selected_realm_id}" }
                                }
                                Label {
                                    html_for: "realm-danger-confirm-input",
                                    "Type the full Realm ID to continue"
                                }
                                Input {
                                    id: "realm-danger-confirm-input",
                                    "data-testid": "realm-danger-confirm-input",
                                    value: "{danger_confirm_text}",
                                    oninput: move |event: FormEvent| danger_confirm_text.set(event.value()),
                                }
                                if is_destroy {
                                    Label {
                                        html_for: "realm-destroy-reason-input",
                                        "Audit reason"
                                    }
                                    Input {
                                        id: "realm-destroy-reason-input",
                                        "data-testid": "realm-destroy-reason-input",
                                        value: "{destroy_reason}",
                                        oninput: move |event: FormEvent| destroy_reason.set(event.value()),
                                    }
                                }
                            }
                            div { class: "modal-foot",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "realm-danger-confirm-cancel",
                                    onclick: move |_| {
                                        archive_confirm_open.set(false);
                                        destroy_confirm_open.set(false);
                                        danger_confirm_text.set(String::new());
                                    },
                                    "Cancel"
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "realm-danger-confirm-submit",
                                    disabled: !confirm_matches,
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor_principal_id = principal_id.clone();
                                        move |_| {
                                            if danger_confirm_text().trim() != realm.trim() {
                                                status_msg.set("confirmation did not match the Realm ID".to_owned());
                                                return;
                                            }
                                            let base = base.clone();
                                            let realm = realm.clone();
                                            let api_token = token();
                                            let actor_id = actor_principal_id.trim().to_owned();
                                            if actor_id.is_empty() {
                                                status_msg.set(format!("{} failed: account is not connected", if is_destroy { "destroy" } else { "archive" }));
                                                return;
                                            }
                                            archive_confirm_open.set(false);
                                            destroy_confirm_open.set(false);
                                            danger_confirm_text.set(String::new());
                                            let reason = destroy_reason().trim().to_owned();
                                            controller.archive_or_destroy_realm(base, api_token, realm, actor_id, reason, is_destroy);
                                        }
                                    },
                                    "{confirm_label}"
                                }
                            }
                        }
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "realm-admin-status", "{status_msg}" }
            }
                }
            }
        }
    }
}
