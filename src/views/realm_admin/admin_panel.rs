use arkret_wire::{CapabilityActionId, CellFamilyId, event_kind_str};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::Link;
use serde_json::{Value, json};

use super::metadata::{metadata_subject_for, projected_members_for_realm};
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

#[component]
pub fn RealmAdminPanel(
    account_did: String,
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
    let mut join_rule = use_signal(|| "public".to_owned());
    let mut principal_admission_enabled = use_signal(|| false);
    let mut principal_admission_methods = use_signal(|| "did:webvh".to_owned());
    let mut principal_admission_allowed_dids = use_signal(String::new);
    let mut principal_admission_denied_dids = use_signal(String::new);
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
    // pasted successor acceptance proof, plus the three security_barrier
    // confirmation dialogs (transfer / authority reset / basis update).
    let mut gov_transfer_target = use_signal(String::new);
    let gov_transfer_target_selected = use_memo(move || Some(gov_transfer_target()));
    let mut gov_transfer_acceptance = use_signal(String::new);
    let mut gov_transfer_confirm_open = use_signal(|| false);
    let mut gov_reset_confirm_open = use_signal(|| false);
    // `ak.realm.authority.reset` requires the payload to carry the literal
    // event-kind string as `destructive_confirmation`; the operator types it
    // here, and the typed text is what the payload ships.
    let mut gov_reset_confirm_text = use_signal(String::new);
    let mut gov_basis_confirm_open = use_signal(|| false);
    // Realm-admin grant inputs (see realm-admin-grant-card). The subject is
    // the DID being made / removed as admin; the grant id is minted
    // client-side on grant and re-entered on revoke (the soland reducer
    // locates the cell by grant_id).
    let mut admin_subject_did = use_signal(String::new);
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
    // YOU-01-011: the former conflict-repair submit dialog was removed —
    // `ak.conflict.repair` is not in the spec event-kind-registry (186
    // kinds, no conflict/repair entry), so the client must not mint that
    // wire kind. The bottom-cells banner below stays as read-only
    // diagnostics; repair tooling returns once a repair kind is
    // registered via AKP.
    // Read the local seal view for this realm once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let seal_view = state_store.read().seal_view_for_realm(&selected_realm_id);
    let bottom_cells: Vec<(String, crate::state::BottomCellInfo)> = seal_view
        .bottom_cells
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let seal_frontier_label = if seal_view.frontier.is_empty() {
        "(no Seal seen — using sha256(empty) sentinel)".to_owned()
    } else {
        seal_view.frontier.join(", ")
    };
    let seal_state_root_label = seal_view
        .state_root
        .clone()
        .unwrap_or_else(|| "(not published)".to_owned());
    // MLS epoch from the cas-register value of ak.component.mls.epoch.v1.
    let mls_epoch_label = seal_view
        .mls_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "(no MLS epoch published)".to_owned());
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
    let (security_health_label, security_health_badge, security_next_step) = if realm_paused {
        (
            "Writes paused",
            "badge red",
            "Rotate or recover the notary before asking members to retry writes.",
        )
    } else if realm_pending_mls_binding {
        (
            "Binding pending",
            "badge amber",
            "Wait for the MLS commit Move to bind the latest encrypted message.",
        )
    } else if !bottom_cells.is_empty() {
        (
            "Repair needed",
            "badge red",
            "Open Repair & Danger to inspect unresolved concurrent candidates.",
        )
    } else {
        (
            "No active alerts",
            "badge green",
            "No administrator action is required from the current local view.",
        )
    };
    let active_section = RealmAdminSection::from_slug(active_section.as_deref());
    let metadata_subject = metadata_subject_for(&state_store.read(), &selected_realm_id);
    if metadata_loaded_for() != selected_realm_id {
        metadata_title.set(metadata_subject.title.clone());
        metadata_summary.set(metadata_subject.summary.clone());
        metadata_avatar_blob_ref.set(metadata_subject.avatar_blob_ref.clone());
        metadata_loaded_for.set(selected_realm_id.clone());
    }
    let metadata_subject_label = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => "Realm",
        RealmTreeNodeKind::Space => "Space",
    };
    let metadata_event_kind = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => event_kind_str::REALM_PROFILE,
        RealmTreeNodeKind::Space => event_kind_str::SPACE_UPDATE,
    };
    let alert_count = usize::from(realm_paused)
        + usize::from(realm_pending_mls_binding)
        + usize::from(!bottom_cells.is_empty());
    let projected_member_count =
        projected_members_for_realm(&state_store.read(), &selected_realm_id).len();
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
                            span { "{alert_count} alerts · epoch {mls_epoch_label}" }
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
            // encryption-and-audit.md §2.10.8 disclosure obligation — RRK
            // durability banner. Renders only when this Realm's effective
            // durability_policy.mode != none AND content_scheme is
            // mls_exporter_aead_v1; otherwise it is a no-op. Until verified
            // coverage exists, it discloses policy configuration and the
            // client's pending capability without claiming key delivery.
            crate::components::DurabilityDisclosureBanner {
                realm_id: selected_realm_id.clone(),
            }
            // Realm-wide notary-paused banner. Fires whenever any tracked
            // Move for this Realm has surfaced `NotaryPaused`. The Space
            // cannot advance until ops rotate the recovery notary.
            if realm_paused {
                div {
                    class: "event error-banner",
                    "data-testid": "notary-paused-banner",
                    div { class: "event-head",
                        span { "Realm halted, waiting for the recovery notary" }
                        span { class: "badge red", "notary_paused" }
                    }
                    div { class: "muted",
                        "soland's notary signing pipeline is offline for this Realm — Moves remain in MoveStore but no Seal batch will close until ops rotate the recovery notary (sodmin H'8). All write attempts surface state=notary_paused."
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
                        span { "Security Frontier binding has not yet been acknowledged" }
                        span { class: "badge amber", "pending_mls_binding" }
                    }
                    div { class: "muted",
                        "The MLS commit Move that should bind your last encrypted message has not yet been acknowledged by the governance frontier. Outgoing messages stay encrypted but won't deliver until the binding lands."
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
            // Bottom/conflict banner — rendered when the projection
            // exposes unresolved concurrent candidates. P0 M5.
            if active_section == RealmAdminSection::Repair && !bottom_cells.is_empty() {
                div { class: "event", "data-testid": "bottom-cells-banner",
                    div { class: "event-head",
                        span { "Concurrent candidates unresolved" }
                        span { class: "badge red", "bottom/conflict" }
                    }
                    div { class: "muted",
                        "One or more cells in this Realm's projection have unresolved bottom/conflict diagnostics — soland received concurrent Events it cannot deterministically merge. Repair requires a registered recovery-repair event kind (pending AKP registration); until then this panel is read-only diagnostics for operators."
                    }
                    for (cell_ref, info) in &bottom_cells {
                        {
                            let cell_ref_label = short_protocol_id(cell_ref);
                            rsx! {
                                div { class: "muted", "data-testid": "bottom-cell-row",
                                    title: "{cell_ref}",
                                    "{cell_ref_label} · status={info.status}"
                                }
                                // Side-by-side render of the competing heads so the
                                // operator can see what they're picking between
                                // instead of pasting blind JSON.
                                if !info.heads.is_empty() {
                                    div { class: "metric-grid", "data-testid": "bottom-cell-heads",
                                        for head in &info.heads {
                                            {
                                                let head_move_id_label = short_protocol_id(&head.move_id);
                                                rsx! {
                                                    div { class: "metric", "data-testid": "bottom-cell-head",
                                                        strong { "data-testid": "bottom-cell-head-move-id", title: "{head.move_id}", "{head_move_id_label}" }
                                                        span { "data-testid": "bottom-cell-head-value",
                                                            "{serde_json::to_string(&head.value).unwrap_or_default()}"
                                                        }
                                                    }
                                                }
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
                    div { class: "event-head",
                        span { "Security health" }
                        span { class: security_health_badge, "{security_health_label}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Writes" }
                            span { if realm_paused { "Paused by notary state" } else { "Accepting local submissions" } }
                        }
                        div { class: "metric",
                            strong { "MLS binding" }
                            span { if realm_pending_mls_binding { "Pending governance acknowledgement" } else { "No pending binding alert" } }
                        }
                        div { class: "metric",
                            strong { "Next step" }
                            span { "{security_next_step}" }
                        }
                    }
                }
                // RRK durability policy editor (realm-and-space.md §2.3.1 /
                // encryption-and-audit.md §2.10.8). Writes durability_policy via
                // ak.realm.policy_bundle; prompts the operator that a
                // following ak.mls.commit activates sealing + re-disclosure.
                super::durability::DurabilityPolicyEditor {
                    token,
                    realm_id: selected_realm_id.clone(),
                    actor_id: account_did.clone(),
                }
                // Read-only MLS epoch widget from the current Seal view.
                div { class: "event", "data-testid": "mls-epoch-widget",
                    div { class: "event-head",
                        span { "MLS epoch" }
                        span { {CellFamilyId::MLS_EPOCH_V1} }
                    }
                    div { class: "muted",
                        "Read-only view of the most recent MLS epoch published in the cell map."
                    }
                    div { class: "muted", "data-testid": "mls-epoch-value",
                        "MLS epoch: {mls_epoch_label}"
                    }
                }
                // Seal frontier debug — shows whether sync has surfaced a
                // real Seal view yet. When empty this matches the sentinel
                // Move builders thread in.
                div { class: "event", "data-testid": "seal-frontier-debug",
                    div { class: "event-head",
                        span { "Seal frontier" }
                        span { "leaves={seal_view.leaves.len()}" }
                    }
                    div { class: "muted", "data-testid": "seal-frontier-heads",
                        "frontier: {seal_frontier_label}"
                    }
                    div { class: "muted", "data-testid": "seal-state-root",
                        "state_root: {seal_state_root_label}"
                    }
                }
                // Realm governance — the three authority-root transitions
                // (`ak.realm.owner.transfer` / `ak.realm.authority.reset` /
                // `ak.realm.authority.basis_update`). All three are sealed
                // control events with concurrency_class=security_barrier:
                // the payload pins `expected_state_digest` to the replayed
                // root value, so a concurrent transition rejects with
                // `realm_authority_root_conflict` instead of merging.
                div { class: "event", "data-testid": "realm-governance-card",
                    div { class: "event-head",
                        span { "Realm governance (authority root)" }
                        span { class: "badge", "security_barrier" }
                    }
                    if let Some(root) = authority_root.clone() {
                        {
                            let controller_full = root.controller_id.as_str().to_owned();
                            let controller_label = short_protocol_id(&controller_full);
                            let registry_full =
                                root.capability_action_registry_digest.as_str().to_owned();
                            let registry_label = short_protocol_id(&registry_full);
                            rsx! {
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "Controller (owner)" }
                                        span {
                                            class: "mono",
                                            title: "{controller_full}",
                                            "data-testid": "governance-controller",
                                            "{controller_label}"
                                        }
                                    }
                                    div { class: "metric",
                                        strong { "Controller epoch" }
                                        span { "data-testid": "governance-epoch", "{root.controller_epoch}" }
                                    }
                                    div { class: "metric",
                                        strong { "Authority generation" }
                                        span { "data-testid": "governance-generation", "{root.authority_generation}" }
                                    }
                                    div { class: "metric",
                                        strong { "Registry basis" }
                                        span {
                                            class: "mono",
                                            title: "{registry_full}",
                                            "data-testid": "governance-registry-basis",
                                            "{registry_label}"
                                        }
                                    }
                                }
                            }
                        }
                        if is_root_controller {
                            div { class: "workflow-form", "data-testid": "governance-owner-controls",
                                // Owner transfer — the root controller's only
                                // legitimate exit (capabilities.md §10.4).
                                div { class: "event-head",
                                    span { "Transfer ownership" }
                                    span { {event_kind_str::REALM_OWNER_TRANSFER} }
                                }
                                div { class: "muted",
                                    "Hands the authority root to a joined member. Existing grants stay valid "
                                    "(only an authority reset invalidates the generation); once sealed, this "
                                    "account is no longer the controller."
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
                                    placeholder: "Paste the acceptance proof the successor produced — the transfer embeds it verbatim; it is never synthesized here or by the service.",
                                    oninput: move |event: FormEvent| gov_transfer_acceptance.set(event.value()),
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "owner-transfer-button",
                                        disabled: gov_transfer_target().trim().is_empty(),
                                        onclick: move |_| {
                                            gov_reset_confirm_open.set(false);
                                            gov_basis_confirm_open.set(false);
                                            gov_transfer_confirm_open.set(true);
                                        },
                                        "Transfer ownership…"
                                    }
                                }
                                // Authority reset / basis update — guarded
                                // destructive entries.
                                div { class: "event-head",
                                    span { "Authority generation & registry basis" }
                                    span { "destructive / advanced" }
                                }
                                div { class: "muted",
                                    "Resetting the authority generation invalidates every capability issued "
                                    "under the current generation across the whole Realm. A basis update only "
                                    "adopts a new capability-action registry snapshot for future grants."
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "authority-reset-button",
                                        onclick: move |_| {
                                            gov_transfer_confirm_open.set(false);
                                            gov_basis_confirm_open.set(false);
                                            gov_reset_confirm_text.set(String::new());
                                            gov_reset_confirm_open.set(true);
                                        },
                                        "Reset authority generation…"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "authority-basis-update-button",
                                        onclick: move |_| {
                                            gov_transfer_confirm_open.set(false);
                                            gov_reset_confirm_open.set(false);
                                            gov_basis_confirm_open.set(true);
                                        },
                                        "Adopt current registry basis…"
                                    }
                                }
                            }
                        } else {
                            div { class: "muted", "data-testid": "governance-not-controller",
                                "Only the current authority-root controller (Realm owner) can transfer "
                                "ownership, reset the authority generation, or adopt a new registry basis."
                            }
                        }
                    } else {
                        div { class: "muted", "data-testid": "governance-root-missing",
                            "The authority root is not resolved in the local projection — either sync has "
                            "not surfaced the accepted `ak.realm.create` yet, or this Realm predates the "
                            "authority-root contract. Governance transitions stay unavailable until a root "
                            "value is projected."
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
                                            let actor_account_did = account_did.clone();
                                            let root = authority_root.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let api_token = token();
                                                let actor_id = actor_account_did.trim().to_owned();
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
                                                spawn(async move {
                                                    match crate::transport::auth::with_event_submitter(
                                                        &base,
                                                        api_token,
                                                        |sub| async move {
                                                            crate::transport::realm_write::transfer_realm_owner(&sub, &actor_id, payload).await
                                                        },
                                                    )
                                                    .await
                                                    {
                                                        Ok(resp) => {
                                                            gov_transfer_target.set(String::new());
                                                            gov_transfer_acceptance.set(String::new());
                                                            status_msg.set(format!(
                                                                "owner transfer submitted: event_id={} — once sealed, {} is the root controller and this account is demoted",
                                                                short_protocol_id(&resp.event_id),
                                                                short_protocol_id(&target_for_msg),
                                                            ));
                                                        }
                                                        Err(err) => {
                                                            let text = err.display();
                                                            let hint = governance_failure_hint(&text)
                                                                .map(|hint| format!(" — {hint}"))
                                                                .unwrap_or_default();
                                                            status_msg.set(format!("owner transfer failed: {text}{hint}"));
                                                        }
                                                    }
                                                });
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
                                            let actor_account_did = account_did.clone();
                                            let root = authority_root.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let api_token = token();
                                                let actor_id = actor_account_did.trim().to_owned();
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
                                                spawn(async move {
                                                    match crate::transport::auth::with_event_submitter(
                                                        &base,
                                                        api_token,
                                                        |sub| async move {
                                                            crate::transport::realm_write::reset_realm_authority(&sub, &actor_id, payload).await
                                                        },
                                                    )
                                                    .await
                                                    {
                                                        Ok(resp) => status_msg.set(format!(
                                                            "authority reset submitted: event_id={} — every grant issued under the previous generation is void once sealed",
                                                            short_protocol_id(&resp.event_id),
                                                        )),
                                                        Err(err) => {
                                                            let text = err.display();
                                                            let hint = governance_failure_hint(&text)
                                                                .map(|hint| format!(" — {hint}"))
                                                                .unwrap_or_default();
                                                            status_msg.set(format!("authority reset failed: {text}{hint}"));
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                        "Reset authority generation"
                                    }
                                }
                            }
                        }
                    }
                }

                // Basis-update confirmation — adopts this build's embedded
                // capability-action registry snapshot.
                if gov_basis_confirm_open() {
                    {
                        let current_basis = authority_root
                            .as_ref()
                            .map(|root| root.capability_action_registry_digest.as_str().to_owned())
                            .unwrap_or_default();
                        let embedded_basis = arkret_sdk::current_capability_action_registry_digest()
                            .map(|digest| digest.as_str().to_owned())
                            .unwrap_or_default();
                        let basis_unchanged = !embedded_basis.is_empty() && embedded_basis == current_basis;
                        rsx! {
                            crate::components::DismissiblePopup {
                                overlay_class: "modal-backdrop",
                                surface_class: "modal danger-confirm-modal",
                                overlay_test_id: Some("authority-basis-confirm-modal".to_owned()),
                                surface_test_id: Some("authority-basis-confirm-dialog".to_owned()),
                                aria_label: "Adopt registry basis".to_owned(),
                                on_dismiss: move |_| gov_basis_confirm_open.set(false),
                                div { class: "modal-head",
                                    h3 { "Adopt current registry basis" }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        class: "icon-button close",
                                        "aria-label": "Close",
                                        "data-testid": "authority-basis-confirm-close",
                                        onclick: move |_| gov_basis_confirm_open.set(false),
                                        "\u{2715}"
                                    }
                                }
                                div { class: "modal-body workflow-form",
                                    div { class: "callout danger", "data-testid": "authority-basis-impact",
                                        strong { "Changes the capability-action vocabulary" }
                                        p {
                                            "This binds the Realm's authority root to the capability-action "
                                            "registry snapshot embedded in this client build. Future grants are "
                                            "interpreted against the new snapshot; the receiving server must be "
                                            "able to resolve it or the event is rejected."
                                        }
                                    }
                                    div { class: "metric",
                                        strong { "Current basis" }
                                        span { class: "mono", "data-testid": "authority-basis-current", title: "{current_basis}", "{short_protocol_id(&current_basis)}" }
                                    }
                                    div { class: "metric",
                                        strong { "New basis (this build)" }
                                        span { class: "mono", "data-testid": "authority-basis-next", title: "{embedded_basis}", "{short_protocol_id(&embedded_basis)}" }
                                    }
                                    if basis_unchanged {
                                        div { class: "muted", "data-testid": "authority-basis-unchanged",
                                            "The Realm already uses this snapshot — submitting again is a no-op."
                                        }
                                    }
                                }
                                div { class: "modal-foot",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "authority-basis-cancel-button",
                                        onclick: move |_| gov_basis_confirm_open.set(false),
                                        "Cancel"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "authority-basis-confirm-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor_account_did = account_did.clone();
                                            let root = authority_root.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let realm = realm.clone();
                                                let api_token = token();
                                                let actor_id = actor_account_did.trim().to_owned();
                                                if actor_id.is_empty() {
                                                    status_msg.set("basis update failed: account is not connected".to_owned());
                                                    return;
                                                }
                                                let Some(root) = root.clone() else {
                                                    status_msg.set("basis update failed: authority root is not resolved locally".to_owned());
                                                    return;
                                                };
                                                let payload = match build_basis_update_payload(&realm, &root) {
                                                    Ok(payload) => payload,
                                                    Err(err) => {
                                                        status_msg.set(format!("basis update build failed: {err}"));
                                                        return;
                                                    }
                                                };
                                                gov_basis_confirm_open.set(false);
                                                spawn(async move {
                                                    match crate::transport::auth::with_event_submitter(
                                                        &base,
                                                        api_token,
                                                        |sub| async move {
                                                            crate::transport::realm_write::update_realm_authority_basis(&sub, &actor_id, payload).await
                                                        },
                                                    )
                                                    .await
                                                    {
                                                        Ok(resp) => status_msg.set(format!(
                                                            "registry basis update submitted: event_id={}",
                                                            short_protocol_id(&resp.event_id),
                                                        )),
                                                        Err(err) => {
                                                            let text = err.display();
                                                            let hint = governance_failure_hint(&text)
                                                                .map(|hint| format!(" — {hint}"))
                                                                .unwrap_or_default();
                                                            status_msg.set(format!("basis update failed: {text}{hint}"));
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                        "Adopt registry basis"
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
                                    let actor_account_did = account_did.clone();
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
                                        let actor_id = actor_account_did.trim().to_owned();
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
                                        let Some(digest_suite) = state_store
                                            .read()
                                            .trusted_mls_governance_checkpoint(&home_realm_id)
                                            .map(|checkpoint| checkpoint.live_digest_suite)
                                        else {
                                            status_msg.set(
                                                "profile update failed: Realm has no verified governance checkpoint"
                                                    .to_owned(),
                                            );
                                            return;
                                        };
                                        spawn(async move {
                                            match crate::transport::auth::with_event_submitter(
                                                &base,
                                                api_token,
                                                |sub| async move {
                                                    let profile_result = match subject_kind {
                                                        RealmTreeNodeKind::Realm => {
                                                            crate::transport::realm_write::update_realm_metadata(&sub, &home_realm_id, &actor_id, digest_suite, patch).await
                                                        }
                                                        RealmTreeNodeKind::Space => {
                                                            crate::transport::realm_write::update_space_metadata(&sub, &home_realm_id, &subject_id, &actor_id, patch).await
                                                        }
                                                    }?;
                                                    if subject_kind == RealmTreeNodeKind::Realm
                                                        && !alias.is_empty()
                                                    {
                                                        crate::transport::realm_write::set_realm_alias(
                                                            &sub,
                                                            &home_realm_id,
                                                            &actor_id,
                                                            Some(&alias),
                                                        )
                                                        .await?;
                                                    }
                                                    Ok::<_, anyhow::Error>(profile_result)
                                                },
                                            )
                                            .await
                                            {
                                                Ok(_) if updates_alias => status_msg.set(format!(
                                                    "{metadata_event_kind} profile and Realm alias updated"
                                                )),
                                                Ok(_) => status_msg.set(format!(
                                                    "{metadata_event_kind} profile updated"
                                                )),
                                                Err(err) => status_msg.set(format!(
                                                    "profile update failed: {}", err.display()
                                                )),
                                            }
                                        });
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
                                        let actor_account_did = account_did.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let home_realm_id = home_realm_id.clone();
                                            let actor_id = actor_account_did.trim().to_owned();
                                            let api_token = token();
                                            if actor_id.is_empty() {
                                                status_msg.set(
                                                    "alias removal failed: account is not connected".to_owned(),
                                                );
                                                return;
                                            }
                                            spawn(async move {
                                                match crate::transport::auth::with_event_submitter(
                                                    &base,
                                                    api_token,
                                                    |sub| async move {
                                                        crate::transport::realm_write::set_realm_alias(
                                                            &sub,
                                                            &home_realm_id,
                                                            &actor_id,
                                                            None,
                                                        )
                                                        .await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        metadata_alias.set(String::new());
                                                        status_msg.set("Realm alias removed".to_owned());
                                                    }
                                                    Err(error) => status_msg.set(format!(
                                                        "alias removal failed: {}",
                                                        error.display()
                                                    )),
                                                }
                                            });
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
                    Label { html_for: "principal-admission-allowed-dids-input", "Allowed principal DIDs" }
                    Textarea {
                        id: "principal-admission-allowed-dids-input",
                        "data-testid": "principal-admission-allowed-dids-input",
                        value: "{principal_admission_allowed_dids}",
                        placeholder: "did:web:alice.example",
                        oninput: move |event: FormEvent| principal_admission_allowed_dids.set(event.value()),
                    }
                    Label { html_for: "principal-admission-denied-dids-input", "Denied principal DIDs" }
                    Textarea {
                        id: "principal-admission-denied-dids-input",
                        "data-testid": "principal-admission-denied-dids-input",
                        value: "{principal_admission_denied_dids}",
                        placeholder: "did:web:blocked.example",
                        oninput: move |event: FormEvent| principal_admission_denied_dids.set(event.value()),
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
                            let actor = account_did.clone();
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
                                    &principal_admission_allowed_dids(),
                                    &principal_admission_denied_dids(),
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
                                let Some(digest_suite) = state_store
                                    .read()
                                    .trusted_mls_governance_checkpoint(&realm)
                                    .map(|checkpoint| checkpoint.live_digest_suite)
                                else {
                                    status_msg.set(
                                        "policy failed: Realm has no verified governance checkpoint"
                                            .to_owned(),
                                    );
                                    return;
                                };
                                spawn(async move {
                                    match crate::transport::auth::with_event_submitter(
                                        &base,
                                        api_token,
                                        |sub| async move {
                                            crate::transport::realm_write::set_realm_policy_events(
                                                &sub,
                                                &realm,
                                                &actor,
                                                digest_suite,
                                                &rule,
                                                tighten_access,
                                                join_policy,
                                                preserve_recommended_encryption_floor,
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "policy: join={}, history_access_tightened={}",
                                            resp.join_rule, resp.history_access_tightened
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "policy failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.apply_policy")}
                    }
                }
            }
            } // closes `if active_section == RealmAdminSection::Access`

            if active_section == RealmAdminSection::Security {
            // MLS epoch rotation. YOU-01-009: the spec has no
            // `POST /_arkret/self/mls/rotate` shim — epoch rotation is a
            // real local `self_update_commit` published as the canonical
            // `ak.mls.commit` event (persist-on-accept).
            div { class: "event", "data-testid": "mls-rotation",
                div { class: "event-head", span { "MLS Epoch" } span { "rotation" } }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "rotate-realm-epoch",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor_account_did = account_did.clone();
                            let device = device_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor_id = actor_account_did.trim().to_owned();
                                let device = device.clone();
                                let api_token = token();
                                let mut state_store = state_store;
                                if actor_id.is_empty() {
                                    status_msg.set("rotate failed: account is not connected".to_owned());
                                    return;
                                }
                                // Build the forced self-update commit + the
                                // canonical ak.mls.commit event locally.
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("inkson");
                                let built = {
                                    let store = state_store.read();
                                    crate::mls::runtime::force_epoch_rotation_commit(
                                        &store,
                                        secure_store.as_ref(),
                                        &realm,
                                        &actor_id,
                                        &device,
                                    )
                                    .map_err(|err| err.user_message())
                                    .and_then(|(commit_envelope, snapshot, previous_governance_binding)| {
                                        let schedule_hash = commit_envelope.commit_digest.clone();
                                        crate::mls::group_events::mls_commit_event_from_store(
                                            &store,
                                            &realm,
                                            &actor_id,
                                            &schedule_hash,
                                            &commit_envelope,
                                            &previous_governance_binding,
                                        )
                                        .map(|event| (event, commit_envelope.epoch, snapshot))
                                    })
                                };
                                let (commit_event, next_epoch, snapshot) = match built {
                                    Ok(parts) => parts,
                                    Err(err) => {
                                        status_msg.set(format!("rotate failed: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    match crate::transport::auth::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.event_submitter()?.submit_sdk_event(&commit_event).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(accepted) => {
                                            // Persist-on-accept: only advance the
                                            // local snapshot after the server
                                            // accepted the ak.mls.commit, and bind
                                            // it to the id the server accepted.
                                            let commit_event_id = match arkret_sdk::EventId::new(
                                                accepted.event_id.clone(),
                                            ) {
                                                Ok(event_id) => event_id,
                                                Err(error) => {
                                                    status_msg.set(format!(
                                                        "rotate accepted but its Event id is invalid: {error}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            if let Err(error) = state_store
                                                .write()
                                                .record_mls_group_state_ref_for_effective_scope(
                                                    realm.clone(),
                                                    None,
                                                    snapshot.group_id.as_str(),
                                                    snapshot.epoch,
                                                    commit_event_id,
                                                )
                                            {
                                                status_msg.set(format!(
                                                    "rotate accepted but MLS reference persistence failed: {error}"
                                                ));
                                                return;
                                            }
                                            if let Err(error) = state_store.write().save_mls_snapshot(
                                                realm.clone(),
                                                snapshot,
                                            ) {
                                                status_msg.set(format!(
                                                    "MLS snapshot persist failed: {error}"
                                                ));
                                                return;
                                            }
                                            // A self-update is also the spec-defined
                                            // recovery commit when a historical
                                            // membership transition changed the
                                            // frontier without changing the current
                                            // MLS roster.  Never clear the send gate
                                            // merely because the Event is effective:
                                            // require this accepted Commit and exact
                                            // complete-hint/MLS-roster agreement.
                                            let secure_store = crate::secure_key_store::
                                                default_secure_key_store("inkson");
                                            let roster_aligned = {
                                                let store = state_store.read();
                                                super::members_panel::
                                                    realm_mls_roster_matches_complete_membership_hint(
                                                        &store,
                                                        secure_store.as_ref(),
                                                        &realm,
                                                        &actor_id,
                                                        &device,
                                                    )
                                            };
                                            if roster_aligned {
                                                let mut store = state_store.write();
                                                store.resolve_member_add_mls_bindings(&realm);
                                                store.resolve_member_remove_mls_bindings(&realm);
                                            }
                                            status_msg.set(format!(
                                                "rotated to epoch {next_epoch}"
                                            ));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "rotate failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.rotate_epoch")}
                    }
                }
            }

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
                            "This account is the Realm authority-root controller, and the protocol's "
                            "only exit path for the root controller is `ak.realm.owner.transfer`. "
                            "Transfer ownership from Security → Realm governance, then leave."
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
                                let actor_account_did = account_did.clone();
                                let mut state_store = state_store;
                                let mut sync_cursor = sync_cursor;
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let api_token = token();
                                    // Membership events are authored by the account/principal DID
                                    // (the authenticated session actor), not the device DID, or the server
                                    // rejects them with `actor_session_mismatch`.
                                    let actor_id = actor_account_did.trim().to_owned();
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
                                    spawn(async move {
                                        let realm_for_msg = realm.clone();
                                        match crate::transport::auth::with_event_submitter(
                                            &base,
                                            api_token,
                                            |sub| async move {
                                                crate::transport::realm_write::leave_realm(&sub, &realm, &actor_id).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                state_store.write().forget_realm_tree_projection(&realm_for_msg);
                                                sync_cursor.set(String::new());
                                                status_msg.set(format!(
                                                    "left {realm_for_msg}; local cache cleared"
                                                ));
                                            }
                                            Err(err) => status_msg.set(format!(
                                                "leave failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("realm_admin.leave_confirm_button")}
                        }
                    }
                }
            }
            }

            if active_section == RealmAdminSection::Security {
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
                            let actor_account_did = account_did.clone();
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
                                let actor_id = actor_account_did.trim().to_owned();
                                if actor_id.is_empty() {
                                    status_msg.set(
                                        "capability grant failed: account is not connected".to_owned(),
                                    );
                                    return;
                                }
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
                                    &subject_val,
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
                                spawn(async move {
                                    match crate::transport::auth::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.event_submitter()?.submit_sdk_event(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ak.capability.grant event {}: event_id={}",
                                            short_protocol_id(&op_id),
                                            short_protocol_id(&resp.event_id)
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "capability.grant submit failed: {}", err.display()
                                        )),
                                    }
                                });
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
                            let actor_account_did = account_did.clone();
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
                                let actor_id = actor_account_did.trim().to_owned();
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
                                spawn(async move {
                                    match crate::transport::auth::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.event_submitter()?.submit_sdk_event(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ak.capability.revoke event {}: event_id={}",
                                            short_protocol_id(&op_id),
                                            short_protocol_id(&resp.event_id)
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "capability.revoke submit failed: {}", err.display()
                                        )),
                                    }
                                });
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
                    value: "{admin_subject_did}",
                    placeholder: "did:web:…",
                    oninput: move |event: FormEvent| admin_subject_did.set(event.value()),
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
                            let actor_account_did = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let subject = admin_subject_did().trim().to_owned();
                                let actor_id = actor_account_did.trim().to_owned();
                                if subject.is_empty() {
                                    status_msg.set(crate::i18n::tr("realm_admin.admin_subject_required"));
                                    return;
                                }
                                if actor_id.is_empty() {
                                    status_msg.set("set admin failed: account is not connected".to_owned());
                                    return;
                                }
                                let mut submitted_grant_id = admin_grant_id;
                                spawn(async move {
                                    match crate::transport::auth::with_event_submitter(
                                        &base,
                                        api_token,
                                        |sub| async move {
                                            crate::transport::realm_write::grant_realm_admin(&sub, &realm, &actor_id, &subject, issuer_root_basis).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => {
                                            if let Ok(event_id) = arkret_sdk::EventId::new(resp.event_id.clone()) {
                                                submitted_grant_id.set(
                                                    arkret_sdk::GrantId::from_event_id(&event_id).to_string(),
                                                );
                                            }
                                            status_msg.set(format!(
                                                "granted ak.realm.admin: event_id={}",
                                                short_protocol_id(&resp.event_id)
                                            ));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "set admin failed: {}", err.display()
                                        )),
                                    }
                                });
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
                            let actor_account_did = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let grant_id = admin_grant_id().trim().to_owned();
                                let actor_id = actor_account_did.trim().to_owned();
                                if grant_id.is_empty() {
                                    status_msg.set(crate::i18n::tr("realm_admin.admin_grant_id_required"));
                                    return;
                                }
                                if actor_id.is_empty() {
                                    status_msg.set("revoke admin failed: account is not connected".to_owned());
                                    return;
                                }
                                spawn(async move {
                                    match crate::transport::auth::with_event_submitter(
                                        &base,
                                        api_token,
                                        |sub| async move {
                                            crate::transport::realm_write::revoke_realm_admin(
                                                &sub,
                                                &realm,
                                                &actor_id,
                                                &grant_id,
                                                Some("admin_revoke"),
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "revoked ak.realm.admin: event_id={}",
                                            short_protocol_id(&resp.event_id)
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "revoke admin failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.admin_revoke_button")}
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
                    account_did: account_did.clone(),
                }
            }

            // P3 — moderation reviewer workbench (decision/lift + appeal
            // review/decide/close). Drives the daily-governance moderation_*
            // / appeal_* API; queues project from the local raw-operation log.
            if active_section == RealmAdminSection::Moderation {
                crate::views::moderation::ModerationWorkbench {
                    account_did: account_did.clone(),
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
                        "Destroying a Realm is destructive and may make its workspace, members, policy, and encrypted history unavailable. This should only be used when the operator has verified the recovery and audit path."
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
                                        let actor_account_did = account_did.clone();
                                        move |_| {
                                            if danger_confirm_text().trim() != realm.trim() {
                                                status_msg.set("confirmation did not match the Realm ID".to_owned());
                                                return;
                                            }
                                            let base = base.clone();
                                            let realm = realm.clone();
                                            let api_token = token();
                                            let actor_id = actor_account_did.trim().to_owned();
                                            if actor_id.is_empty() {
                                                status_msg.set(format!("{} failed: account is not connected", if is_destroy { "destroy" } else { "archive" }));
                                                return;
                                            }
                                            archive_confirm_open.set(false);
                                            destroy_confirm_open.set(false);
                                            danger_confirm_text.set(String::new());
                                            let reason = destroy_reason().trim().to_owned();
                                            spawn(async move {
                                                let realm_for_msg = realm.clone();
                                                let result = crate::transport::auth::with_event_submitter(
                                                    &base,
                                                    api_token,
                                                    |sub| async move {
                                                        if is_destroy {
                                                            let reason = if reason.is_empty() {
                                                                "operator_request".to_owned()
                                                            } else {
                                                                reason
                                                            };
                                                            crate::transport::realm_write::destroy_realm(&sub, &realm, &actor_id, &reason).await
                                                        } else {
                                                            crate::transport::realm_write::archive_realm(&sub, &realm, &actor_id).await
                                                        }
                                                    },
                                                )
                                                .await;
                                                match result {
                                                    Ok(_) if is_destroy => status_msg.set(format!(
                                                        "destroyed {}",
                                                        short_protocol_id(&realm_for_msg)
                                                    )),
                                                    Ok(_) => status_msg.set(format!(
                                                        "archive event submitted ({realm_for_msg})"
                                                    )),
                                                    Err(err) if is_destroy => status_msg.set(format!(
                                                        "destroy failed: {}", err.display()
                                                    )),
                                                    Err(err) => status_msg.set(format!(
                                                        "archive failed: {}", err.display()
                                                    )),
                                                }
                                            });
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

// ── Realm governance (authority root) helpers ─────────────────────────

/// `expected_state_digest` for the three authority-root transition payloads:
/// the canonical SHA-256 of the replayed root value, exactly what the soland
/// reducer recomputes before applying a `security_barrier` transition.
fn expected_authority_root_digest(
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
) -> anyhow::Result<arkret_sdk::Hash> {
    arkret_sdk::Hash::new(crate::canonical::canonical_sha256(root)?).map_err(anyhow::Error::msg)
}

/// Build the `ak.realm.owner.transfer` payload. `successor_acceptance` is the
/// successor's independent proof pasted by the operator — the client never
/// synthesizes it (the wire type only requires non-empty signature material;
/// binding semantics live with the successor's tooling).
fn build_owner_transfer_payload(
    realm_id: &str,
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
    successor: &str,
    successor_acceptance: &str,
) -> anyhow::Result<arkret_sdk::RealmOwnerTransferPayload> {
    Ok(arkret_sdk::RealmOwnerTransferPayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        expected_state_digest: expected_authority_root_digest(root)?,
        patch: arkret_sdk::RealmOwnerTransferPatch {
            controller_id: crate::mls_api_helpers::principal_core_id(successor)?,
            controller_epoch: root.controller_epoch.saturating_add(1),
        },
        successor_acceptance: arkret_sdk::SignatureMaterial::NonEmptyString(
            arkret_sdk::NonEmptyString::new(successor_acceptance.trim().to_owned())
                .map_err(|reason| anyhow::anyhow!("successor acceptance: {reason}"))?,
        ),
    })
}

/// Build the destructive `ak.realm.authority.reset` payload.
/// `destructive_confirmation` is the operator-typed token; the SDK builder
/// (and the reducer) only accept the literal event-kind string, so the typed
/// text ships verbatim instead of being auto-filled.
fn build_authority_reset_payload(
    realm_id: &str,
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
    destructive_confirmation: &str,
) -> anyhow::Result<arkret_sdk::RealmAuthorityResetPayload> {
    Ok(arkret_sdk::RealmAuthorityResetPayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        expected_state_digest: expected_authority_root_digest(root)?,
        patch: arkret_sdk::RealmAuthorityResetPatch {
            authority_generation: root.authority_generation.saturating_add(1),
        },
        destructive_confirmation: destructive_confirmation.trim().to_owned(),
    })
}

/// Build the `ak.realm.authority.basis_update` payload adopting this build's
/// embedded capability-action registry snapshot.
fn build_basis_update_payload(
    realm_id: &str,
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
) -> anyhow::Result<arkret_sdk::RealmAuthorityBasisUpdatePayload> {
    Ok(arkret_sdk::RealmAuthorityBasisUpdatePayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        expected_state_digest: expected_authority_root_digest(root)?,
        patch: arkret_sdk::RealmAuthorityBasisUpdatePatch {
            capability_action_registry_digest:
                arkret_sdk::current_capability_action_registry_digest()?,
        },
    })
}

/// Operator guidance for the known authority-root rejection reasons, appended
/// to the raw error in the status line. `None` for anything unrecognized.
fn governance_failure_hint(error_text: &str) -> Option<&'static str> {
    if error_text.contains("realm_authority_root_conflict") {
        Some(
            "the authority root changed concurrently (security barrier) — wait for sync to \
             surface the new root and retry from the refreshed state",
        )
    } else if error_text.contains("realm_authority_controller_mismatch") {
        Some(
            "only the current root controller may submit this transition, and an owner-transfer \
             successor must be a joined member with a non-empty acceptance proof",
        )
    } else if error_text.contains("realm_authority_root_missing") {
        Some(
            "this Realm has no projected authority-root cell (it predates the contract); \
             governance transitions are unavailable",
        )
    } else if error_text.contains("capability_registry_basis_unavailable") {
        Some(
            "the server cannot resolve the requested capability-action registry snapshot — the \
             deployment must ship that registry version before the basis can be adopted",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    fn root() -> arkret_policy::realm_bootstrap::RealmAuthorityRootValue {
        arkret_policy::realm_bootstrap::RealmAuthorityRootValue {
            controller_id: arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .unwrap(),
            controller_epoch: 3,
            authority_generation: 1,
            capability_action_registry_digest: arkret_sdk::Hash::new(format!(
                "sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
        }
    }

    const REALM: &str = "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";

    #[test]
    fn owner_transfer_payload_pins_digest_and_increments_epoch() {
        let payload =
            build_owner_transfer_payload(REALM, &root(), "did:web:bob.example", "detached-proof")
                .unwrap();
        assert_eq!(payload.patch.controller_epoch, 4);
        assert_eq!(
            payload.patch.controller_id.as_str(),
            "ak:did_core:web:bob.example"
        );
        assert_eq!(
            payload.expected_state_digest.as_str(),
            crate::canonical::canonical_sha256(&root()).unwrap()
        );
        // The full builder chain accepts this payload (root authorization ref
        // stamped by the SDK intent builder).
        let intent = crate::event_builders::build_realm_owner_transfer_control_intent(
            "did:web:alice.example",
            payload,
        )
        .unwrap();
        assert_eq!(
            intent.kind().as_str(),
            arkret_wire::event_kind_str::REALM_OWNER_TRANSFER
        );
    }

    #[test]
    fn owner_transfer_payload_rejects_an_empty_acceptance_proof() {
        assert!(build_owner_transfer_payload(REALM, &root(), "did:web:bob.example", "  ").is_err());
    }

    #[test]
    fn authority_reset_payload_ships_the_typed_confirmation_verbatim() {
        let payload = build_authority_reset_payload(
            REALM,
            &root(),
            arkret_wire::event_kind_str::REALM_AUTHORITY_RESET,
        )
        .unwrap();
        assert_eq!(payload.patch.authority_generation, 2);
        assert_eq!(payload.destructive_confirmation, "ak.realm.authority.reset");
        // A wrong token still builds a payload here, but the SDK intent
        // builder fails closed — the UI's disabled-until-match confirm is a
        // convenience, not the enforcement point.
        let wrong = build_authority_reset_payload(REALM, &root(), "yes really").unwrap();
        assert!(
            crate::event_builders::build_realm_authority_reset_control_intent(
                "did:web:alice.example",
                wrong,
            )
            .is_err()
        );
    }

    #[test]
    fn basis_update_payload_adopts_the_embedded_registry_snapshot() {
        let payload = build_basis_update_payload(REALM, &root()).unwrap();
        assert_eq!(
            payload.patch.capability_action_registry_digest,
            arkret_sdk::current_capability_action_registry_digest().unwrap()
        );
    }

    #[test]
    fn governance_failure_hints_cover_the_reducer_rejection_reasons() {
        assert!(governance_failure_hint("submit failed: realm_authority_root_conflict").is_some());
        assert!(governance_failure_hint("rejected: realm_authority_controller_mismatch").is_some());
        assert!(governance_failure_hint("realm_authority_root_missing").is_some());
        assert!(governance_failure_hint("capability_registry_basis_unavailable").is_some());
        assert_eq!(governance_failure_hint("network timeout"), None);
    }
}
