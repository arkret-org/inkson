use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::Link;
use serde_json::{Value, json};

use super::metadata::{metadata_subject_for, projected_members_for_realm};
use super::policy::build_principal_admission_join_policy;
use super::section::{
    DEFAULT_COVERED_SEALS_LAG_THRESHOLD, REALM_ADMIN_NAV_GROUPS, RealmAdminSection,
};
use crate::components::encryption_floor_prompt::projection_has_recommended_encryption_floor;
use crate::local_state::LocalStateStore;
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
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    active_section: Option<String>,
) -> Element {
    let mut metadata_title = use_signal(String::new);
    let mut metadata_summary = use_signal(String::new);
    let mut metadata_avatar_blob_ref = use_signal(String::new);
    let mut metadata_alias = use_signal(String::new);
    let mut metadata_loaded_for = use_signal(String::new);
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut principal_admission_enabled = use_signal(|| false);
    let mut principal_admission_methods = use_signal(|| "did:webvh".to_owned());
    let mut principal_admission_allowed_dids = use_signal(String::new);
    let mut principal_admission_denied_dids = use_signal(String::new);
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut status_msg = use_signal(String::new);
    // Capability grant/revoke Move-strand inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(|| "cap.demo-01".to_owned());
    let mut cap_tag = use_signal(|| "discussion.message.create".to_owned());
    let mut cap_revoke_reason = use_signal(|| "rotation policy".to_owned());
    let mut archive_confirm_open = use_signal(|| false);
    let mut destroy_confirm_open = use_signal(|| false);
    let mut danger_confirm_text = use_signal(String::new);
    let mut destroy_reason = use_signal(|| "operator_request".to_owned());
    // Leave Realm confirmation dialog (no ID re-typing: leaving is
    // recoverable-by-invite, unlike destroy, but still needs one explicit
    // confirmation step before the membership event is submitted).
    let mut leave_confirm_open = use_signal(|| false);
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
    // Covered_frontier alert threshold. Default 5 (mirrors sodmin's
    // `DEFAULT_LAG_WARN_THRESHOLD`); user can override via the numeric
    // input next to the banner.
    let mut covered_seals_threshold = use_signal(|| DEFAULT_COVERED_SEALS_LAG_THRESHOLD);
    // Read-only notary cell value. The Cokret HTTP catalog does not expose
    // this as a spec endpoint yet, so surface that inline rather than
    // pretending a private path exists.
    let mut notary_cell_status = use_signal(String::new);
    let mut notary_cell_value = use_signal(String::new);
    // Selected Move for the failure detail inline panel. Clicking a row
    // that's in a failed state stores its move_id here; the detail block
    // below renders the reason / seal_ref.
    let mut move_detail_open = use_signal(|| Option::<String>::None);
    // YOU-01-011: the former conflict-repair submit dialog was removed —
    // `ck.conflict.repair` is not in the spec event-kind-registry (186
    // kinds, no conflict/repair entry), so the client must not mint that
    // wire kind. The bottom-cells banner below stays as read-only
    // diagnostics; repair tooling returns once a repair kind is
    // registered via CKP.
    // Read the local seal view for this realm once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let seal_view = state_store.read().seal_view_for_realm(&selected_realm_id);
    let bottom_cells: Vec<(String, crate::local_state::BottomCellInfo)> = seal_view
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
    // MLS epoch + governance covered_seals for the read-only widget.
    // `mls_epoch` is the cas-register value of ck.component.mls.epoch.v1;
    // `covered_seals` is the
    // ck.component.governance.covered_seals.v1 cell value. Both come
    // from the same seal view the bottom-cells banner reads.
    let mls_epoch_label = seal_view
        .mls_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "(no MLS epoch published)".to_owned());
    let covered_seals_label = seal_view
        .covered_seals
        .clone()
        .unwrap_or_else(|| "(no governance covered_seals published)".to_owned());
    // Covered_frontier_lag value + threshold check for the alert banner.
    // We render only when a lag value has actually been surfaced AND it
    // exceeds the (user-configurable) warning threshold - matches the
    // sodmin admin page UX.
    let covered_seals_lag_value = seal_view.covered_seals_lag;
    let covered_seals_lag_threshold = covered_seals_threshold();
    let covered_seals_alert = seal_view.covered_seals_lag_above(covered_seals_lag_threshold);
    let covered_seals_lag_label = covered_seals_lag_value
        .map(|lag| lag.to_string())
        .unwrap_or_else(|| "-".to_owned());
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
    } else if covered_seals_alert {
        (
            "Needs attention",
            "badge amber",
            "Review covered_seals lag and wait for governance frontier catch-up.",
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
        RealmTreeNodeKind::Realm => "ck.realm.update",
        RealmTreeNodeKind::Space => "ck.space.update",
    };
    let alert_count = usize::from(realm_paused)
        + usize::from(realm_pending_mls_binding)
        + usize::from(!bottom_cells.is_empty())
        + usize::from(covered_seals_alert);
    let projected_member_count =
        projected_members_for_realm(&state_store.read(), &selected_realm_id).len();
    // RRK durability active (mode != none + mls-exporter-aead-v1) gates the
    // Realm-level recovery panel in the Security section.
    let durability_rrk_active = state_store
        .read()
        .realm_durability_is_rrk_active(&selected_realm_id);

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
                            span { "{join_rule()} / {history_visibility()}" }
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
            // mls-exporter-aead-v1; otherwise it is a no-op. Members MUST see
            // that history is continuously sealed to a verifiable recovery
            // holder who can decrypt all history (never "real-time listening").
            crate::components::DurabilityDisclosureBanner {
                realm_id: selected_realm_id.clone(),
                state_store,
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
            // asserts a covered_seals the local
            // MLS view has not yet acknowledged. Stays up until the
            // user clears the underlying Move record.
            if realm_pending_mls_binding {
                div {
                    class: "event",
                    "data-testid": "pending-mls-binding-toast",
                    div { class: "event-head",
                        span { "covered_seals has not yet caught up to the required governance frontier" }
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
                        "One or more cells in this Realm's projection have unresolved bottom/conflict diagnostics — soland received concurrent Events it cannot deterministically merge. Repair requires a registered recovery-repair event kind (pending CKP registration); until then this panel is read-only diagnostics for operators."
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
                            strong { "Covered seals" }
                            span { "lag {covered_seals_lag_label} / threshold {covered_seals_lag_threshold}" }
                        }
                        div { class: "metric",
                            strong { "Next step" }
                            span { "{security_next_step}" }
                        }
                    }
                }
                // RRK durability policy editor (realm-and-space.md §2.3.1 /
                // encryption-and-audit.md §2.10.8). Writes durability_policy via
                // ck.realm.policy_components; prompts the operator that a
                // following ck.mls.commit activates sealing + re-disclosure.
                super::durability::DurabilityPolicyEditor {
                    base_url: base_url.clone(),
                    token,
                    realm_id: selected_realm_id.clone(),
                    actor_id: account_did.clone(),
                    state_store,
                }
                // Realm-level RRK recovery panel — only when durability is active.
                if durability_rrk_active {
                    super::durability_recovery::DurabilityRecoveryPanel {
                        realm_id: selected_realm_id.clone(),
                        state_store,
                    }
                }
                // Covered_frontier_lag alert banner. Mirrors sodmin's admin
                // page banner but stays client-side - it reads the lag from
                // the LocalSealView populated on /sync, compares to a
                // user-configurable threshold (default 5, see
                // DEFAULT_COVERED_SEALS_LAG_THRESHOLD), and only renders
                // when soland has surfaced a lag AND it exceeds threshold.
                // Operators see the same urgency cue here that sodmin shows
                // on the dedicated covered_seals page.
                div { class: "event", "data-testid": "covered-frontier-threshold-row",
                    div { class: "event-head",
                        span { "covered_seals alert threshold" }
                        span { "client-side" }
                    }
                    div { class: "muted",
                        "Surface a banner when soland's published covered_seals_lag exceeds this value. Default 5 (mirrors sodmin)."
                    }
                    Label { html_for: "covered-frontier-threshold-input", "Threshold (Moves)" }
                    input {
                        id: "covered-frontier-threshold-input",
                        "data-testid": "covered-frontier-threshold-input",
                        r#type: "number",
                        min: "0",
                        value: "{covered_seals_lag_threshold}",
                        oninput: move |evt| {
                            if let Ok(parsed) = evt.value().parse::<u64>() {
                                covered_seals_threshold.set(parsed);
                            }
                        },
                    }
                    div { class: "muted", "data-testid": "covered-frontier-lag-value",
                        "current covered_seals_lag: {covered_seals_lag_label}"
                    }
                }
                if covered_seals_alert {
                    div { class: "event", "data-testid": "covered-frontier-alert-banner",
                        div { class: "event-head",
                            span { "covered_seals lag alert" }
                            span { class: "badge red", "above threshold" }
                        }
                        div { class: "muted", "data-testid": "covered-frontier-alert-message",
                            "Lag of {covered_seals_lag_label} Moves is above the warn threshold {covered_seals_lag_threshold}; investigate MLS group health (member offline, KeyPackage stale). Admin tools live on the sodmin covered_seals page."
                        }
                    }
                }
                // MLS epoch + governance frontier read-only widget. Reads
                // from the same LocalSealView the bottom-cells banner
                // uses, so it costs no extra fetch - just surfaces two
                // well-known cells (mls.epoch.v1,
                // governance.covered_seals.v1) for admin visibility into
                // E2EE rotation status and governance gating without leaving
                // the page.
                div { class: "event", "data-testid": "mls-epoch-widget",
                    div { class: "event-head",
                        span { "MLS epoch & governance frontier" }
                        span { "ck.component.mls.epoch.v1 · governance.covered_seals.v1" }
                    }
                    div { class: "muted",
                        "Read-only view of the most recent MLS epoch published in the cell map and the governance covered_seals value Move acceptance gates against. Updates as soon as sync surfaces a new seal view — no fetch button needed."
                    }
                    div { class: "muted", "data-testid": "mls-epoch-value",
                        "MLS epoch: {mls_epoch_label}"
                    }
                    div { class: "muted", "data-testid": "governance-covered-frontier",
                        "covered_seals: {covered_seals_label}"
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
                // Notary cell (read-only, P0 M4). This remains disabled until
                // the Cokret HTTP catalog exposes a spec endpoint for the
                // recovery-notary mode.
                div { class: "event", "data-testid": "notary-cell-card",
                    div { class: "event-head",
                        span { "Notary cell" }
                        span { "ck.component.notary.v1" }
                    }
                    div { class: "muted",
                        "Recovery notary mode for this Realm — controls who can re-seal a paused frontier. Read-only; modifications go through the dedicated notary-rotation strand."
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "notary-cell-refresh",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.admin_notary_describe(&realm).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(value) => {
                                                notary_cell_status.set("ok".to_owned());
                                                notary_cell_value.set(value.to_string());
                                            }
                                            Err(err) => {
                                                // 404 / not-implemented falls through here.
                                                // Keep the message clear so the operator
                                                // knows it's a missing endpoint, not bad
                                                // data.
                                                notary_cell_status.set(format!(
                                                    "notary endpoint unavailable ({}); no spec-defined Cokret HTTP endpoint",
                                                    err.display()
                                                ));
                                            }
                                        }
                                    });
                                }
                            },
                            "Fetch notary cell"
                        }
                    }
                    if !notary_cell_status().is_empty() {
                        div { class: "muted", "data-testid": "notary-cell-status",
                            "{notary_cell_status}"
                        }
                    }
                    if !notary_cell_value().is_empty() {
                        div { class: "muted", "data-testid": "notary-cell-value",
                            "{notary_cell_value}"
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
                            placeholder: "engineering (blank keeps current)",
                            oninput: move |event: FormEvent| metadata_alias.set(event.value()),
                        }
                        label { "Avatar" }
                        crate::components::AvatarUploader {
                            current_blob_ref: metadata_avatar_blob_ref(),
                            alt_text: format!("{metadata_subject_label} avatar"),
                            base_url: base_url.clone(),
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
                                        if title.is_empty() {
                                            status_msg.set(
                                                "profile update failed: title is required by spec".to_owned(),
                                            );
                                            return;
                                        }
                                        if !avatar_blob_ref.is_empty()
                                            && !avatar_blob_ref.starts_with("ck:blob:")
                                        {
                                            status_msg.set(
                                                "profile update failed: avatar_blob_ref must be a ck:blob:* reference".to_owned(),
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
                                        patch.insert(
                                            "summary".to_owned(),
                                            if summary.is_empty() {
                                                json!({ "$op": "unset" })
                                            } else {
                                                json!(summary)
                                            },
                                        );
                                        patch.insert(
                                            "avatar_blob_ref".to_owned(),
                                            if avatar_blob_ref.is_empty() {
                                                json!({ "$op": "unset" })
                                            } else {
                                                json!(avatar_blob_ref)
                                            },
                                        );
                                        // Realm alias rename (object-addressing.md §3.3): only patch
                                        // when the admin entered a value, so leaving it blank keeps
                                        // the current alias. soland re-normalizes + uniques it.
                                        if !alias.is_empty() {
                                            patch.insert("alias".to_owned(), json!(alias));
                                        }
                                        let patch = Value::Object(patch);
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    match subject_kind {
                                                        RealmTreeNodeKind::Realm => {
                                                            api.update_realm_metadata(&home_realm_id, &actor_id, patch).await
                                                        }
                                                        RealmTreeNodeKind::Space => {
                                                            api.update_space_metadata(&home_realm_id, &subject_id, &actor_id, patch).await
                                                        }
                                                    }
                                                },
                                            )
                                            .await
                                            {
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
                        variant: if join_rule() == "open" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("open".to_owned()),
                        "Open"
                    }
                    Button {
                        variant: if join_rule() == "invite" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("invite".to_owned()),
                        "Invite"
                    }
                    Button {
                        variant: if join_rule() == "request" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("request".to_owned()),
                        "Request"
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

            // History visibility selector
            div { class: "event", "data-testid": "history-visibility",
                div { class: "event-head", span { "History Visibility" } span { "" } }
                div { class: "actions",
                    Button {
                        variant: if history_visibility() == "shared" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("shared".to_owned()),
                        "Shared"
                    }
                    Button {
                        variant: if history_visibility() == "invited" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("invited".to_owned()),
                        "Invited"
                    }
                    Button {
                        variant: if history_visibility() == "joined" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("joined".to_owned()),
                        "Joined"
                    }
                    Button {
                        variant: if history_visibility() == "world_readable" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("world_readable".to_owned()),
                        "World Readable"
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
                                let vis = history_visibility();
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
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.set_realm_policy_events(
                                                &realm,
                                                &actor,
                                                &rule,
                                                &vis,
                                                join_policy,
                                                preserve_recommended_encryption_floor,
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "policy: join={}, history={}",
                                            resp.join_rule, resp.history_visibility
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
            // `POST /_cokret/self/mls/rotate` shim — epoch rotation is a
            // real local `self_update_commit` published as the canonical
            // `ck.mls.commit` event (persist-on-accept).
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
                            let state_store = state_store;
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
                                // canonical ck.mls.commit event locally.
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("yougen");
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
                                    .and_then(|(commit_envelope, snapshot)| {
                                        let schedule_hash = commit_envelope.commit_digest.clone();
                                        crate::views::kanban::kanban_mls_commit_event_from_store(
                                            &store,
                                            &realm,
                                            &actor_id,
                                            &schedule_hash,
                                            &commit_envelope,
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
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_sdk_event(&commit_event).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            // Persist-on-accept: only advance the
                                            // local snapshot after the server
                                            // accepted the ck.mls.commit.
                                            state_store
                                                .write()
                                                .save_mls_snapshot(realm.clone(), snapshot);
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
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "leave-realm-button",
                        onclick: move |_| leave_confirm_open.set(true),
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
                                    leave_confirm_open.set(false);
                                    spawn(async move {
                                        let realm_for_msg = realm.clone();
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.leave_realm(&realm, &actor_id).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                state_store.write().forget_realm_tree_projection(&realm_for_msg);
                                                sync_cursor.set("-".to_owned());
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
                Label { html_for: "cap-grant-id-input", "Grant ID (cell subject)" }
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
                                let grant_val = cap_grant_id().trim().to_owned();
                                let tag_val = cap_tag().trim().to_owned();
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability grant".to_owned(),
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
                                // signals into the wire shape. Empty input
                                // yields no constraint.
                                let kind = cap_constraint_kind();
                                let constraint_json: serde_json::Value =
                                    if kind == "temporal" {
                                        let nb = cap_temporal_not_before();
                                        let ea = cap_temporal_expires_at();
                                        let nb_trim = nb.trim();
                                        let ea_trim = ea.trim();
                                        if nb_trim.is_empty() && ea_trim.is_empty() {
                                            serde_json::Value::Null
                                        } else {
                                            let mut window = serde_json::Map::new();
                                            if !nb_trim.is_empty() {
                                                window.insert(
                                                    "not_before".into(),
                                                    serde_json::Value::String(nb_trim.to_owned()),
                                                );
                                            }
                                            if !ea_trim.is_empty() {
                                                // Validity upper bound is `expires_at`;
                                                // `not_after` is not canonical.
                                                window.insert(
                                                    "expires_at".into(),
                                                    serde_json::Value::String(ea_trim.to_owned()),
                                                );
                                            }
                                            json!([
                                                {
                                                    "kind": "temporal.window",
                                                    "value": serde_json::Value::Object(window),
                                                }
                                            ])
                                        }
                                    } else {
                                        serde_json::Value::Null
                                    };
                                let envelope = crate::operation::ck_ops::capability_grant(
                                    &realm,
                                    &actor_id,
                                    &grant_val,
                                    &tag_val,
                                    constraint_json,
                                )
                                .build_sdk_event("yougen");
                                let envelope = match envelope {
                                    Ok(envelope) => envelope,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "capability.grant build failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let op_id = envelope
                                    .unsigned
                                    .get("local_operation_idempotency_alias")
                                    .and_then(|value| value.as_str())
                                    .unwrap_or_else(|| envelope.event_id.as_str())
                                    .to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_sdk_event(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ck.capability.grant event {}: event_id={}",
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
                                let tag_val = cap_tag().trim().to_owned();
                                let reason_val = cap_revoke_reason();
                                let reason_opt = if reason_val.trim().is_empty() {
                                    None
                                } else {
                                    Some(reason_val.clone())
                                };
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability revoke".to_owned(),
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
                                let envelope = crate::operation::ck_ops::capability_revoke(
                                    &realm,
                                    &actor_id,
                                    &grant_val,
                                    &tag_val,
                                    reason_opt.as_deref(),
                                )
                                .build_sdk_event("yougen");
                                let envelope = match envelope {
                                    Ok(envelope) => envelope,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "capability.revoke build failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let op_id = envelope
                                    .unsigned
                                    .get("local_operation_idempotency_alias")
                                    .and_then(|value| value.as_str())
                                    .unwrap_or_else(|| envelope.event_id.as_str())
                                    .to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_sdk_event(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ck.capability.revoke event {}: event_id={}",
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
                    span { class: "badge", "ck.realm.admin" }
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
                    placeholder: "ck:grant:… (auto on grant, paste on revoke)",
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
                                let grant_id = format!("ck:grant:{}", crate::operation::uuid_v7());
                                admin_grant_id.set(grant_id.clone());
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.grant_realm_admin(&realm, &actor_id, &grant_id, &subject).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "granted ck.realm.admin: event_id={}",
                                            short_protocol_id(&resp.event_id)
                                        )),
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
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.revoke_realm_admin(
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
                                            "revoked ck.realm.admin: event_id={}",
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
                        "Trust bundle import, validation, and revocation are not wired in yougen. Use the deployment's admin tooling for federation trust changes."
                    }
                }
                // SOL-ORG-06 — read-only view of this Realm's verified
                // organization relationships (verified-active / revoked-expired)
                // and declared owning-organization hints. Binding and
                // organization-side signing live in the admin console (sodmin).
                super::RealmOrganizationPanel {
                    base_url: base_url.clone(),
                    token,
                    realm_id: selected_realm_id.clone(),
                    account_did: account_did.clone(),
                    state_store,
                }
            }

            // P3 — moderation reviewer workbench (decision/lift + appeal
            // review/decide/close). Drives the daily-governance moderation_*
            // / appeal_* API; queues project from the local raw-operation log.
            if active_section == RealmAdminSection::Moderation {
                crate::views::moderation::ModerationWorkbench {
                    base_url: base_url.clone(),
                    account_did: account_did.clone(),
                    token,
                    selected_realm_id: selected_realm_id.clone(),
                    state_store,
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
                                                let result = crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token,
                                                    |api| async move {
                                                        if is_destroy {
                                                            let reason = if reason.is_empty() {
                                                                "operator_request".to_owned()
                                                            } else {
                                                                reason
                                                            };
                                                            api.destroy_realm(&realm, &actor_id, &reason).await
                                                        } else {
                                                            api.archive_realm(&realm, &actor_id).await
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
