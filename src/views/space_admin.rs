use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::{Value, json};

use crate::device_revoke::{ChainMoveState, MlsRevokeMoveChain};
use crate::hlc::Hlc;
use crate::local_state::{LocalStateStore, MoveSubmissionState};
use crate::models::SpacePreviewKind;
use crate::operation::cx_ops;
use crate::routes::Route;
use crate::views::helpers::{active_sync_token, authed_api_with_sync, short_protocol_id};

/// Default `covered_frontier_lag` warning threshold used by the
/// space_admin alert banner. Mirrors sodmin's
/// `DEFAULT_LAG_WARN_THRESHOLD` so a member moving between the two
/// surfaces sees the same alert ceiling. Read from the user preference
/// signal in [`SpaceAdminPanel`].
pub(crate) const DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD: u64 = 5;

// NOTE: All build_signed_*_move helpers and record_submit_outcome have
// been removed — every Move-based write path was migrated to
// cx.events.submit via the cx_ops::* event builders. The original
// helpers (and their tests) are preserved in git history.

#[derive(Clone, Debug, PartialEq)]
struct InviteRecord {
    invite_id: String,
    target: String,
    role: Option<String>,
    state: String,
    operation_id: Option<String>,
    event_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpaceAdminSection {
    Overview,
    Members,
    Access,
    Security,
    Governance,
    Federation,
    Repair,
}

impl SpaceAdminSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "members" => Self::Members,
            "access" => Self::Access,
            "security" => Self::Security,
            "governance" => Self::Governance,
            "federation" => Self::Federation,
            "repair" => Self::Repair,
            _ => Self::Overview,
        }
    }

    fn slug(self) -> Option<&'static str> {
        match self {
            Self::Overview => None,
            Self::Members => Some("members"),
            Self::Access => Some("access"),
            Self::Security => Some("security"),
            Self::Governance => Some("governance"),
            Self::Federation => Some("federation"),
            Self::Repair => Some("repair"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Members => "Members",
            Self::Access => "Access",
            Self::Security => "Security & MLS",
            Self::Governance => "Governance",
            Self::Federation => "Federation",
            Self::Repair => "Repair & Danger",
        }
    }

    fn all() -> [Self; 7] {
        [
            Self::Overview,
            Self::Members,
            Self::Access,
            Self::Security,
            Self::Governance,
            Self::Federation,
            Self::Repair,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataSubject {
    kind: SpacePreviewKind,
    home_realm_id: String,
    title: String,
    summary: String,
}

fn projection_string(body: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        let mut current = body;
        let mut found = true;
        for segment in *path {
            if let Some(next) = current.get(*segment) {
                current = next;
            } else {
                found = false;
                break;
            }
        }
        if !found {
            continue;
        }
        if let Some(value) = current.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn projection_kind_for_admin(subject_id: &str, body: Option<&Value>) -> SpacePreviewKind {
    if subject_id.starts_with("cx:realm:") {
        return SpacePreviewKind::Realm;
    }
    let Some(body) = body else {
        return SpacePreviewKind::Realm;
    };
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some("cx.schema.space.v1") => SpacePreviewKind::Space,
        Some("realm") | Some("cx.schema.realm.v1") => SpacePreviewKind::Realm,
        _ => {
            let has_parent = projection_string(
                body,
                &[&["parent_space_id"], &["summary", "parent_space_id"]],
            )
            .is_some();
            if subject_id.starts_with("cx:space:") && has_parent {
                SpacePreviewKind::Space
            } else {
                SpacePreviewKind::Realm
            }
        }
    }
}

fn projection_home_realm_for_admin(
    subject_id: &str,
    kind: SpacePreviewKind,
    body: Option<&Value>,
) -> String {
    if kind == SpacePreviewKind::Realm {
        return crate::operation::scope_id_as_realm_id(subject_id);
    }
    body.and_then(|body| projection_string(body, &[&["realm_id"], &["summary", "realm_id"]]))
        .unwrap_or_else(|| crate::operation::scope_id_as_realm_id(subject_id))
}

fn metadata_subject_for(store: &LocalStateStore, subject_id: &str) -> MetadataSubject {
    let state = store.load();
    let body = state.space_projections.get(subject_id);
    let kind = projection_kind_for_admin(subject_id, body);
    let title = body
        .and_then(|body| {
            projection_string(
                body,
                &[&["summary", "title"], &["title"], &["object", "title"]],
            )
        })
        .unwrap_or_default();
    let summary = body
        .and_then(|body| {
            projection_string(
                body,
                &[
                    &["summary", "summary"],
                    &["summary"],
                    &["description"],
                    &["object", "summary"],
                    &["object", "description"],
                ],
            )
        })
        .unwrap_or_default();
    MetadataSubject {
        kind,
        home_realm_id: projection_home_realm_for_admin(subject_id, kind, body),
        title,
        summary,
    }
}

fn projected_members_for_space(store: &LocalStateStore, space_id: &str) -> Vec<String> {
    store
        .load()
        .space_projections
        .get(space_id)
        .and_then(|proj| {
            proj.get("members").or_else(|| {
                proj.get("summary")
                    .and_then(|summary| summary.get("members"))
            })
        })
        .and_then(|members| members.as_array())
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    member.as_str().map(ToOwned::to_owned).or_else(|| {
                        member
                            .get("did")
                            .and_then(|did| did.as_str())
                            .map(ToOwned::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[component]
pub fn SpaceAdminPanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    active_section: Option<String>,
) -> Element {
    let mut space_name = use_signal(String::new);
    let mut space_description = use_signal(String::new);
    let mut metadata_loaded_for = use_signal(String::new);
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<String>::new);
    // A5 — personal blocklist confirm state. `Some(did)` while a
    // block-this-user confirmation modal is open for that DID; resets
    // to `None` on cancel or confirm.
    let mut block_confirm_did = use_signal(|| Option::<String>::None);
    let mut space_invites = use_signal(Vec::<InviteRecord>::new);
    let mut discovery_enabled = use_signal(|| true);
    // Capability grant/revoke Move-flow inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(|| "cap.demo-01".to_owned());
    let mut cap_tag = use_signal(|| "discussion.message.create".to_owned());
    let mut cap_revoke_reason = use_signal(|| "rotation policy".to_owned());
    // Structured constraint inputs for the capability grant.
    // `cap_constraint_kind` chooses the family (`temporal` / `quota` /
    // `scope_limitation` / `none`); the temporal MVP exposes `not_before`
    // / `not_after` RFC 3339 timestamps. Quota / scope_limitation are
    // surfaced in the dropdown but show a "coming soon" hint until
    // matching widgets land.
    let mut cap_constraint_kind = use_signal(|| "none".to_owned());
    let mut cap_temporal_not_before = use_signal(String::new);
    let mut cap_temporal_not_after = use_signal(String::new);
    // Covered_frontier alert threshold. Default 5 (mirrors sodmin's
    // `DEFAULT_LAG_WARN_THRESHOLD`); user can override via the numeric
    // input next to the banner.
    let mut covered_frontier_threshold = use_signal(|| DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD);
    // Read-only anchorer cell value fetched from /api/admin/v1/spaces/{id}/anchorer.
    // The endpoint may 404 in dev — surface that inline rather than blocking the page.
    let mut anchorer_cell_status = use_signal(String::new);
    let mut anchorer_cell_value = use_signal(String::new);
    // Selected Move for the failure detail inline panel. Clicking a row
    // that's in a failed state stores its move_id here; the detail block
    // below renders the reason / anchor_ref.
    let mut move_detail_open = use_signal(|| Option::<String>::None);
    // Conflict-repair dialog state. Surfaces when the local projection
    // has bottom=expose cells; the operator picks two of the conflicting
    // heads + a recovery capability ref and submits a head_in repair
    // Move.
    let mut repair_target_cell = use_signal(String::new);
    let mut repair_head_a = use_signal(String::new);
    let mut repair_head_b = use_signal(String::new);
    let mut repair_capability_ref = use_signal(|| "cap.recovery-01".to_owned());
    let mut repair_state_witness_ref = use_signal(String::new);
    let mut repair_inclusion_proof_ref = use_signal(String::new);
    let mut repair_winner_json = use_signal(String::new);
    // Device-revoke MLS Remove builder. The full round-trip is: load
    // encrypted snapshot from `state_store`, decrypt with this device's
    // snapshot secret, run SDK `remove_member_by_principal`, sign the
    // canonical `mls_commit` Operation, submit via /api/v1/events, then
    // re-encrypt + persist the post-commit group state so a crash between
    // submit and persist doesn't leave the local cache an epoch behind.
    let mut device_revoke_target = use_signal(String::new);
    let device_revoke_status = use_signal(String::new);

    // Read the local anchor view for this space once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let anchor_view = state_store.read().anchor_view_for(&selected_space);
    let bottom_cells: Vec<(String, crate::local_state::BottomCellInfo)> = anchor_view
        .bottom_cells
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Per-cell safer-winner suggestion, cloned out of the anchor_view so
    // the rsx! event handlers don't have to borrow it. Tuple is
    // (cell_ref, head_a_move_id, head_b_move_id, safer_value_json).
    let safer_suggestions: Vec<(String, String, String, String)> = bottom_cells
        .iter()
        .filter_map(|(cell_ref, _)| {
            let (head_a, head_b, value) = anchor_view.safer_winner_for(cell_ref)?;
            let json = serde_json::to_string_pretty(&value).ok()?;
            Some((cell_ref.clone(), head_a, head_b, json))
        })
        .collect();
    let anchor_frontier_label = if anchor_view.frontier.is_empty() {
        "(no Anchor seen — using sha256(empty) sentinel)".to_owned()
    } else {
        anchor_view.frontier.join(", ")
    };
    let anchor_state_root_label = anchor_view
        .state_root
        .clone()
        .unwrap_or_else(|| "(not published)".to_owned());
    // MLS epoch + governance covered_frontier for the read-only widget.
    // `mls_epoch` is the cas-register value of cx.component.mls.epoch.v1;
    // `covered_frontier` is the
    // cx.component.governance.covered_frontier.v1 cell value. Both come
    // from the same anchor view the bottom-cells banner reads.
    let mls_epoch_label = anchor_view
        .mls_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "(no MLS epoch published)".to_owned());
    let covered_frontier_label = anchor_view
        .covered_frontier
        .clone()
        .unwrap_or_else(|| "(no governance covered_frontier published)".to_owned());
    // Covered_frontier_lag value + threshold check for the alert banner.
    // We render only when a lag value has actually been surfaced AND it
    // exceeds the (user-configurable) warning threshold - matches the
    // sodmin admin page UX.
    let covered_frontier_lag_value = anchor_view.covered_frontier_lag;
    let covered_frontier_lag_threshold = covered_frontier_threshold();
    let covered_frontier_alert =
        anchor_view.covered_frontier_lag_above(covered_frontier_lag_threshold);
    let covered_frontier_lag_label = covered_frontier_lag_value
        .map(|lag| lag.to_string())
        .unwrap_or_else(|| "-".to_owned());
    // Per-Space Move submission tracker. Drives the state-pill list +
    // the Space-wide anchorer_paused banner.
    let move_submissions = state_store
        .read()
        .move_submissions_for_space(&selected_space);
    let space_paused = state_store
        .read()
        .space_has_paused_anchorer(&selected_space);
    let space_pending_mls_binding = state_store
        .read()
        .space_has_pending_mls_binding(&selected_space);
    let active_section = SpaceAdminSection::from_slug(active_section.as_deref());
    {
        let selected_space_for_hydration = selected_space.clone();
        let should_hydrate_members = active_section == SpaceAdminSection::Members;
        use_effect(move || {
            if !should_hydrate_members {
                return;
            }
            let next =
                projected_members_for_space(&state_store.read(), &selected_space_for_hydration);
            if members() != next {
                members.set(next);
            }
        });
    }
    let metadata_subject = metadata_subject_for(&state_store.read(), &selected_space);
    if metadata_loaded_for() != selected_space {
        space_name.set(metadata_subject.title.clone());
        space_description.set(metadata_subject.summary.clone());
        metadata_loaded_for.set(selected_space.clone());
    }
    let metadata_subject_label = match metadata_subject.kind {
        SpacePreviewKind::Realm => "Realm",
        SpacePreviewKind::Space => "Space",
    };
    let metadata_event_kind = match metadata_subject.kind {
        SpacePreviewKind::Realm => "cx.realm.update",
        SpacePreviewKind::Space => "cx.space.update",
    };
    let alert_count = usize::from(space_paused)
        + usize::from(space_pending_mls_binding)
        + usize::from(!bottom_cells.is_empty())
        + usize::from(covered_frontier_alert);

    rsx! {
        div { class: "timeline", "data-testid": "space-admin-panel",
            // E2E debug: surface active_section value so tests can assert what
            // the component actually saw, not what the URL claims.
            div { class: "muted", "data-testid": "space-admin-active-section",
                "{active_section.label()}"
            }
            div { class: "actions", "data-testid": "space-admin-sections",
                for section in SpaceAdminSection::all() {
                    if let Some(slug) = section.slug() {
                        Link {
                            class: if active_section == section { "primary" } else { "secondary" },
                            to: Route::SpaceAdminSection {
                                space_id: selected_space.clone(),
                                section: slug.to_owned(),
                            },
                            "{section.label()}"
                        }
                    } else {
                        Link {
                            class: if active_section == section { "primary" } else { "secondary" },
                            to: Route::SpaceAdmin {
                                space_id: selected_space.clone(),
                            },
                            "{section.label()}"
                        }
                    }
                }
            }
            if active_section == SpaceAdminSection::Overview {
                div { class: "event", "data-testid": "space-admin-overview",
                    div { class: "event-head",
                        span { "Admin Map" }
                        span { "{selected_space}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { {crate::i18n::tr("space_admin.members")} }
                            span { "{members().len()} known" }
                            div { class: "muted", "Invites, membership state machine, and leave flow." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "members".to_owned(),
                                },
                                "Open Members"
                            }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("space_admin.access")} }
                            span { "{join_rule()} / {history_visibility()}" }
                            div { class: "muted", "Metadata, join rule, history visibility, and discovery live together." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "access".to_owned(),
                                },
                                "Open Access"
                            }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("space_admin.security_mls")} }
                            span { "epoch {mls_epoch_label}" }
                            div { class: "muted", "Capability grants, MLS health, anchor visibility, and audit-bound E2EE controls." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "security".to_owned(),
                                },
                                "Open Security"
                            }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("space_admin.governance")} }
                            span { "policy / moderation" }
                            div { class: "muted", "Organization-level governance and moderation policy stay out of the daily admin path." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "governance".to_owned(),
                                },
                                "Open Governance"
                            }
                        }
                        div { class: "metric",
                            strong { "Federation" }
                            span { "trust_bundle" }
                            div { class: "muted", "Partner trust and service DID boundaries are isolated from Space-local settings." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "federation".to_owned(),
                                },
                                "Open Federation"
                            }
                        }
                        div { class: "metric",
                            strong { "Repair & Danger" }
                            span { "{alert_count} active alerts" }
                            div { class: "muted", "Conflict repair, stalled Move diagnostics, and destructive actions are intentionally separated." }
                            Link {
                                class: "secondary",
                                to: Route::SpaceAdminSection {
                                    space_id: selected_space.clone(),
                                    section: "repair".to_owned(),
                                },
                                "Open Repair"
                            }
                        }
                    }
                }
            }
            // Space-wide anchorer-paused banner. Fires whenever any tracked
            // Move for this Space has surfaced `AnchorerPaused`. The Space
            // cannot advance until ops rotate the recovery anchorer.
            if space_paused {
                div {
                    class: "event error-banner",
                    "data-testid": "anchorer-paused-banner",
                    div { class: "event-head",
                        span { "Space halted, waiting for the recovery anchorer" }
                        span { class: "badge red", "anchorer_paused" }
                    }
                    div { class: "muted",
                        "soland's anchorer signing pipeline is offline for this Space — Moves remain in MoveStore but no Anchor batch will close until ops rotate the recovery anchorer (sodmin H'8). All write attempts surface state=anchorer_paused."
                    }
                }
            }
            // Pending MLS binding toast — when a recent E2EE message Event
            // asserts a covered_frontier the local
            // MLS view has not yet acknowledged. Stays up until the
            // user clears the underlying Move record.
            if space_pending_mls_binding {
                div {
                    class: "event",
                    "data-testid": "pending-mls-binding-toast",
                    div { class: "event-head",
                        span { "covered_frontier has not yet caught up to the required governance frontier" }
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
            if active_section == SpaceAdminSection::Repair && !move_submissions.is_empty() {
                div { class: "event", "data-testid": "move-submission-tracker",
                    div { class: "event-head",
                        span { "Recent Move submissions" }
                        span { "{move_submissions.len()} tracked" }
                    }
                    div { class: "muted",
                        "Local Move/Anchor pipeline state for writes you've submitted from this device. Pending → Effective once anchored; failures expand inline."
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
                                        button {
                                            class: "secondary",
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
                                                if let Some(anchor) = &record.anchor_ref {
                                                    {
                                                        let anchor_label = short_protocol_id(anchor);
                                                        rsx! {
                                                            div { title: "{anchor}", "bound anchor: {anchor_label}" }
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
            if active_section == SpaceAdminSection::Repair && !bottom_cells.is_empty() {
                div { class: "event", "data-testid": "bottom-cells-banner",
                    div { class: "event-head",
                        span { "Concurrent candidates unresolved" }
                        span { class: "badge red", "bottom/conflict" }
                    }
                    div { class: "muted",
                        "One or more cells in this Space's projection have unresolved bottom/conflict diagnostics — soland received concurrent Events it cannot deterministically merge. An admin / moderator must resolve each conflict by submitting a recovery repair Event before downstream queries return a definitive value."
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
                        // "Prefer safer side" prefill - only rendered for
                        // cell families where there's a semantic safety
                        // ordering (member.state, capability.grant). For
                        // everything else the operator picks manually below.
                        if let Some((_, head_a, head_b, winner_json)) = safer_suggestions
                            .iter()
                            .find(|(c, _, _, _)| c == cell_ref)
                            .cloned()
                        {
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "prefer-safer-side-button",
                                    "data-cell": "{cell_ref}",
                                    onclick: {
                                        let cell_ref_owned = cell_ref.clone();
                                        move |_| {
                                            repair_target_cell.set(cell_ref_owned.clone());
                                            repair_head_a.set(head_a.clone());
                                            repair_head_b.set(head_b.clone());
                                            repair_winner_json.set(winner_json.clone());
                                        }
                                    },
                                    "Prefer safer side"
                                }
                            }
                        }
                    }
                }
                // Conflict-repair Event dialog - only rendered when
                // bottom_cells is non-empty (i.e. there is something to
                // repair). Admin / moderator only; soland's authz reducer
                // rejects unsigned-by-recovery capability submissions.
                div { class: "event", "data-testid": "conflict-repair-dialog",
                    div { class: "event-head",
                        span { "Conflict repair" }
                        span { class: "badge amber", "admin / moderator" }
                    }
                    div { class: "muted",
                        "Build a repair Event with the competing heads and recovery capability ref to merge the two concurrent histories. Soland's authz reducer requires the repair to be signed by a holder of the named recovery capability."
                    }
                    label { "Target cell (id of unresolved bottom/conflict cell)" }
                    input {
                        "data-testid": "repair-target-cell-input",
                        value: "{repair_target_cell}",
                        placeholder: "cx:cell:cx.component.realm.organization.v1:...",
                        oninput: move |evt| repair_target_cell.set(evt.value()),
                    }
                    label { "conflict_head_A" }
                    input {
                        "data-testid": "repair-head-a-input",
                        value: "{repair_head_a}",
                        placeholder: "cx:anchor:sha256:headA...",
                        oninput: move |evt| repair_head_a.set(evt.value()),
                    }
                    label { "conflict_head_B" }
                    input {
                        "data-testid": "repair-head-b-input",
                        value: "{repair_head_b}",
                        placeholder: "cx:anchor:sha256:headB...",
                        oninput: move |evt| repair_head_b.set(evt.value()),
                    }
                    label { "recovery_capability ref" }
                    input {
                        "data-testid": "repair-capability-input",
                        value: "{repair_capability_ref}",
                        placeholder: "cap.recovery-01",
                        oninput: move |evt| repair_capability_ref.set(evt.value()),
                    }
                    label { "state_witness ref" }
                    input {
                        "data-testid": "repair-state-witness-input",
                        value: "{repair_state_witness_ref}",
                        placeholder: "cx:snapshot:sha256:...",
                        oninput: move |evt| repair_state_witness_ref.set(evt.value()),
                    }
                    label { "inclusion_proof ref" }
                    input {
                        "data-testid": "repair-inclusion-proof-input",
                        value: "{repair_inclusion_proof_ref}",
                        placeholder: "cx:proof:sha256:...",
                        oninput: move |evt| repair_inclusion_proof_ref.set(evt.value()),
                    }
                    label { "Winner value (JSON)" }
                    textarea {
                        "data-testid": "repair-winner-json-input",
                        value: "{repair_winner_json}",
                        placeholder: "{{\"title\": \"merged\"}}",
                        oninput: move |evt| repair_winner_json.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "repair-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                let actor_account_did = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let actor_did = actor_account_did.trim().to_owned();
                                    let api_token = token();
                                    let cell = repair_target_cell().trim().to_owned();
                                    let head_a = repair_head_a().trim().to_owned();
                                    let head_b = repair_head_b().trim().to_owned();
                                    let cap = repair_capability_ref().trim().to_owned();
                                    let witness = repair_state_witness_ref().trim().to_owned();
                                    let proof = repair_inclusion_proof_ref().trim().to_owned();
                                    let winner_str = repair_winner_json();
                                    if cell.is_empty() || head_a.is_empty() || head_b.is_empty()
                                        || cap.is_empty() || witness.is_empty() || proof.is_empty()
                                    {
                                        status_msg.set(
                                            "fill cell + both heads + recovery capability + state witness + inclusion proof before submitting repair"
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    let winner_value: serde_json::Value =
                                        match serde_json::from_str(&winner_str) {
                                            Ok(v) => v,
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "winner value is not valid JSON: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                    let _hlc = Hlc::now("yougen").to_string();
                                    if actor_did.is_empty() {
                                        status_msg.set("account actor unavailable".to_owned());
                                        return;
                                    }
                                    let heads = vec![head_a, head_b];
                                    let envelope = crate::operation::cx_ops::conflict_repair(
                                        &space,
                                        &actor_did,
                                        &cell,
                                        &heads,
                                        &cap,
                                        &witness,
                                        &proof,
                                        winner_value,
                                    )
                                    .build("yougen");
                                    let op_id = envelope.local_operation_id().to_owned();
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.submit_event_envelope(&envelope).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(resp) => status_msg.set(format!(
                                                "repair event {}: state=accepted event_id={}",
                                                short_protocol_id(&op_id),
                                                short_protocol_id(&resp.event_id)
                                            )),
                                            Err(err) => status_msg.set(format!(
                                                "repair submit failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Submit repair Move"
                        }
                    }
                }
            }
            if active_section == SpaceAdminSection::Security {
                // Covered_frontier_lag alert banner. Mirrors sodmin's admin
                // page banner but stays client-side - it reads the lag from
                // the LocalAnchorView populated on /sync, compares to a
                // user-configurable threshold (default 5, see
                // DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD), and only renders
                // when soland has surfaced a lag AND it exceeds threshold.
                // Operators see the same urgency cue here that sodmin shows
                // on the dedicated covered_frontier page.
                div { class: "event", "data-testid": "covered-frontier-threshold-row",
                    div { class: "event-head",
                        span { "covered_frontier alert threshold" }
                        span { "client-side" }
                    }
                    div { class: "muted",
                        "Surface a banner when soland's published covered_frontier_lag exceeds this value. Default 5 (mirrors sodmin)."
                    }
                    label { "Threshold (Moves)" }
                    input {
                        "data-testid": "covered-frontier-threshold-input",
                        r#type: "number",
                        min: "0",
                        value: "{covered_frontier_lag_threshold}",
                        oninput: move |evt| {
                            if let Ok(parsed) = evt.value().parse::<u64>() {
                                covered_frontier_threshold.set(parsed);
                            }
                        },
                    }
                    div { class: "muted", "data-testid": "covered-frontier-lag-value",
                        "current covered_frontier_lag: {covered_frontier_lag_label}"
                    }
                }
                if covered_frontier_alert {
                    div { class: "event", "data-testid": "covered-frontier-alert-banner",
                        div { class: "event-head",
                            span { "covered_frontier lag alert" }
                            span { class: "badge red", "above threshold" }
                        }
                        div { class: "muted", "data-testid": "covered-frontier-alert-message",
                            "Lag of {covered_frontier_lag_label} Moves is above the warn threshold {covered_frontier_lag_threshold}; investigate MLS group health (member offline, KeyPackage stale). Admin tools live on the sodmin covered_frontier page."
                        }
                    }
                }
                // MLS epoch + governance frontier read-only widget. Reads
                // from the same LocalAnchorView the bottom-cells banner
                // uses, so it costs no extra fetch - just surfaces two
                // well-known cells (mls.epoch.v1,
                // governance.covered_frontier.v1) for admin visibility into
                // E2EE rotation status and governance gating without leaving
                // the page.
                div { class: "event", "data-testid": "mls-epoch-widget",
                    div { class: "event-head",
                        span { "MLS epoch & governance frontier" }
                        span { "cx.component.mls.epoch.v1 · governance.covered_frontier.v1" }
                    }
                    div { class: "muted",
                        "Read-only view of the most recent MLS epoch published in the cell map and the governance covered_frontier value Move acceptance gates against. Updates as soon as sync surfaces a new anchor view — no fetch button needed."
                    }
                    div { class: "muted", "data-testid": "mls-epoch-value",
                        "MLS epoch: {mls_epoch_label}"
                    }
                    div { class: "muted", "data-testid": "governance-covered-frontier",
                        "covered_frontier: {covered_frontier_label}"
                    }
                }
                // Anchor frontier debug — shows whether sync has surfaced a
                // real Anchor view yet. When empty this matches the sentinel
                // Move builders thread in.
                div { class: "event", "data-testid": "anchor-frontier-debug",
                    div { class: "event-head",
                        span { "Anchor frontier" }
                        span { "leaves={anchor_view.leaves.len()}" }
                    }
                    div { class: "muted", "data-testid": "anchor-frontier-heads",
                        "frontier: {anchor_frontier_label}"
                    }
                    div { class: "muted", "data-testid": "anchor-state-root",
                        "state_root: {anchor_state_root_label}"
                    }
                }
                // Anchorer cell (read-only, P0 M4) — fetches from
                // /api/admin/v1/spaces/{id}/anchorer; surfaces the
                // recovery-anchorer mode (single_did / threshold / open_set /
                // mixed) on this admin page. A separate agent is implementing
                // the endpoint on soland; on 404 we fall back to a clear
                // inline message.
                div { class: "event", "data-testid": "anchorer-cell-card",
                    div { class: "event-head",
                        span { "Anchorer cell" }
                        span { "cx.component.anchorer.v1" }
                    }
                    div { class: "muted",
                        "Recovery anchorer mode for this Space — controls who can re-anchor a paused frontier. Read-only; modifications go through the dedicated anchorer-rotation flow."
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "anchorer-cell-refresh",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.admin_anchorer_describe(&space).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(value) => {
                                                anchorer_cell_status.set("ok".to_owned());
                                                anchorer_cell_value.set(value.to_string());
                                            }
                                            Err(err) => {
                                                // 404 / not-implemented falls through here.
                                                // Keep the message clear so the operator
                                                // knows it's a missing endpoint, not bad
                                                // data.
                                                anchorer_cell_status.set(format!(
                                                    "anchorer endpoint unavailable ({}); \
                                                     expected /api/admin/v1/spaces/{{id}}/anchorer \
                                                     (separate agent shipping)",
                                                    err.display()
                                                ));
                                            }
                                        }
                                    });
                                }
                            },
                            "Fetch anchorer cell"
                        }
                    }
                    if !anchorer_cell_status().is_empty() {
                        div { class: "muted", "data-testid": "anchorer-cell-status",
                            "{anchorer_cell_status}"
                        }
                    }
                    if !anchorer_cell_value().is_empty() {
                        div { class: "muted", "data-testid": "anchorer-cell-value",
                            "{anchorer_cell_value}"
                        }
                    }
                }
            }
            if active_section == SpaceAdminSection::Access {
            // Realm / Space metadata editor. Spec fields are `title` and
            // optional `summary`; access policy is handled by the facet
            // controls below rather than by generic metadata fields.
            div { class: "event", "data-testid": "space-metadata",
                div { class: "event-head",
                    span { "{metadata_subject_label} Metadata" }
                    span { "{metadata_event_kind}" }
                }
                div { class: "muted",
                    span { class: "mono", title: "{selected_space}", "{short_protocol_id(&selected_space)}" }
                    if metadata_subject.kind == SpacePreviewKind::Space {
                        span { " · home Realm " }
                        span {
                            class: "mono",
                            title: "{metadata_subject.home_realm_id}",
                            "{short_protocol_id(&metadata_subject.home_realm_id)}"
                        }
                    }
                }
                div { class: "workflow-form",
                    label { "Title" }
                    input {
                        "data-testid": "space-name-input",
                        value: "{space_name}",
                        placeholder: "{metadata_subject_label} title",
                        oninput: move |evt| space_name.set(evt.value()),
                    }
                    label { "Summary" }
                    textarea {
                        "data-testid": "space-description-input",
                        value: "{space_description}",
                        placeholder: "Optional summary",
                        oninput: move |evt| space_description.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "update-metadata-button",
                            onclick: {
                                let base = base_url.clone();
                                let subject_id = selected_space.clone();
                                let subject_kind = metadata_subject.kind;
                                let home_realm_id = metadata_subject.home_realm_id.clone();
                                move |_| {
                                    let base = base.clone();
                                    let subject_id = subject_id.clone();
                                    let home_realm_id = home_realm_id.clone();
                                    let api_token = token();
                                    let title = space_name().trim().to_owned();
                                    let summary = space_description().trim().to_owned();
                                    if title.is_empty() {
                                        status_msg.set("metadata update failed: title is required by spec".to_owned());
                                        return;
                                    }
                                    let actor_did = match state_store.write().ensure_local_identity() {
                                        Ok(id) => id.device_did.as_str().to_owned(),
                                        Err(err) => {
                                            status_msg.set(format!("identity unavailable: {err}"));
                                            return;
                                        }
                                    };
                                    let patch = if summary.is_empty() {
                                        json!({
                                            "title": title,
                                            "summary": { "$op": "unset" },
                                        })
                                    } else {
                                        json!({
                                            "title": title,
                                            "summary": summary,
                                        })
                                    };
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                match subject_kind {
                                                    SpacePreviewKind::Realm => {
                                                        api.update_realm_metadata(&home_realm_id, &actor_did, patch).await
                                                    }
                                                    SpacePreviewKind::Space => {
                                                        api.update_space_metadata(&home_realm_id, &subject_id, &actor_did, patch).await
                                                    }
                                                }
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => status_msg.set(format!(
                                                "{metadata_event_kind} metadata updated"
                                            )),
                                            Err(err) => status_msg.set(format!("update failed: {}", err.display())),
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("space_admin.save_metadata")}
                        }
                    }
                }
            }

            // Join policy selector
            div { class: "event", "data-testid": "join-policy",
                div { class: "event-head", span { "Join Policy" } span { "access control" } }
                div { class: "actions",
                    button {
                        class: if join_rule() == "open" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("open".to_owned()),
                        "Open"
                    }
                    button {
                        class: if join_rule() == "invite" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("invite".to_owned()),
                        "Invite"
                    }
                    button {
                        class: if join_rule() == "request" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("request".to_owned()),
                        "Request"
                    }
                    button {
                        class: if join_rule() == "restricted" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("restricted".to_owned()),
                        "Restricted"
                    }
                }
                div { class: "muted", "Current: {join_rule}" }
            }

            // History visibility selector
            div { class: "event", "data-testid": "history-visibility",
                div { class: "event-head", span { "History Visibility" } span { "" } }
                div { class: "actions",
                    button {
                        class: if history_visibility() == "shared" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("shared".to_owned()),
                        "Shared"
                    }
                    button {
                        class: if history_visibility() == "invited" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("invited".to_owned()),
                        "Invited"
                    }
                    button {
                        class: if history_visibility() == "joined" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("joined".to_owned()),
                        "Joined"
                    }
                    button {
                        class: if history_visibility() == "world_readable" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("world_readable".to_owned()),
                        "World Readable"
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "apply-policy-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                let rule = join_rule();
                                let vis = history_visibility();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.set_space_policy_events(&space, &actor, &rule, &vis).await
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
                        {crate::i18n::tr("space_admin.apply_policy")}
                    }
                }
            }
            } // closes `if active_section == SpaceAdminSection::Access`

            // Invite member
            div { class: "event", "data-testid": "admin-discussion-admission",
                div { class: "event-head", span { "Discussion-scoped external admission" } span { "policy proposal" } }
                div { class: "muted",
                    "External access is granted to a Discussion, not to the whole Space or linked Card. History visibility and capability grants remain separate."
                }
                div { class: "metric-grid",
                    div { class: "metric", strong { "Discussion" } span { "cx:flow:external-counsel" } div { class: "muted", "history: joined" } }
                    div { class: "metric", strong { "Capability" } span { "discussion.message.create" } div { class: "muted", "expires in 7 days" } }
                    div { class: "metric", strong { "Discussion Coupling" } span { "none" } div { class: "muted", "linked Discussion remains separately authorized" } }
                    div { class: "metric", strong { "Review" } span { "requires admin approval" } div { class: "muted", "danger actions require reason" } }
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                                "data-testid": "queue-discussion-admission",
                        onclick: move |_| status_msg.set("queued Discussion-scoped external admission proposal".to_owned()),
                        "Queue admission proposal"
                    }
                    button {
                        class: "secondary",
                                "data-testid": "deny-discussion-admission",
                        onclick: move |_| status_msg.set("denied without leaking locked Discussion membership".to_owned()),
                        "Deny"
                    }
                }
            }

            if active_section == SpaceAdminSection::Members {
            div { class: "muted", "data-testid": "dbg-members-block-entered", "members section entered" }
            // Invite member
            div { class: "event", "data-testid": "invite-member",
                div { class: "event-head", span { "Invite Member" } span { "" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "invite-target-input",
                        value: "{invite_target}",
                        placeholder: "DID or handle",
                        oninput: move |evt| invite_target.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "send-invite-button",
                            onclick: {
                                let base = base_url.clone();
                                let actor = account_did.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let target = invite_target().trim().to_owned();
                                    if target.is_empty() {
                                        status_msg.set("invite target is required".to_owned());
                                        return;
                                    }
                                    let wait_for = active_sync_token(sync_cursor());
                                    // Client-generated invite_id — spec-canonical (no
                                    // two-phase server lookup needed; cx.invite.create
                                    // event is the source of truth).
                                    let invite_id = format!(
                                        "cx:invite:{}",
                                        crate::operation::uuid_v7()
                                    );
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => {
                                                let op = cx_ops::invite_create_structured(
                                                    &space,
                                                    &actor,
                                                    &invite_id,
                                                    &target,
                                                    None,
                                                )
                                                .build("yougen");
                                                let op_id = op.local_operation_id().to_owned();
                                                match api.submit_event_envelope(&op).await {
                                                    Ok(submitted) => {
                                                        space_invites.write().push(InviteRecord {
                                                            invite_id: invite_id.clone(),
                                                            target: target.clone(),
                                                            role: None,
                                                            state: "pending".to_owned(),
                                                            operation_id: Some(op_id.clone()),
                                                            event_id: Some(submitted.event_id.clone()),
                                                        });
                                                        frontier_state.set(submitted.event_id.clone());
                                                        sync_cursor.set(submitted.sync_token.clone());
                                                        {
                                                            let mut store = state_store.write();
                                                            // POST /events returns a write barrier, not an
                                                            // account-subscribe resume cursor. Persisting it
                                                            // poisons the next /account/subscribe after= call.
                                                            store.append_raw_operation(
                                                                op_id.clone(),
                                                                Some(space.clone()),
                                                                json!({
                                                                    "kind": "cx.invite.create",
                                                                    "invite_id": invite_id,
                                                                    "invitee": target,
                                                                    "state": "pending",
                                                                    "event_id": submitted.event_id,
                                                                }),
                                                            );
                                                        }
                                                        invite_target.set(String::new());
                                                        status_msg.set(format!(
                                                            "invited {} (pending) fact {}",
                                                            target,
                                                            short_protocol_id(&op_id)
                                                        ));
                                                    }
                                                    Err(error) => status_msg.set(format!("invite failed: {error}")),
                                                }
                                            }
                                            Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Send Invite"
                        }
                    }
                }
            }

            // Member state — authz/event-auth-state-resolution.md §5
            // 5 MembershipState variants: Invited / Joined / Left / Banned / Knocked
            // Legal transitions form a state machine; reducer rejects illegal moves
            // with state_mismatch.
            div { class: "event", "data-testid": "member-state-banner",
                div { class: "event-head",
                    span { "Member state machine" }
                    span { "cx.member.state · 5 variants" }
                }
                div { class: "muted",
                    "Membership state is driven by cx.member.state events. In a `knock` Space, an uninvited actor can request access; an admin transitions them to invited, then to joined."
                }
                div { class: "actions",
                    span { class: "badge blue", "Invited" }
                    span { class: "badge green", "Joined" }
                    span { class: "badge", "Left" }
                    span { class: "badge red", "Banned" }
                    span { class: "badge amber", "Knocked" }
                }
                div { class: "muted",
                    "Allowed transitions: none → {{join, invite, knock}} | invite → {{join, leave}} | knock → {{invite, leave}} | join → {{leave, ban}} | leave → {{invite, knock}} | ban → leave (via unban)."
                }
            }

            // Member table
            div { class: "event", "data-testid": "member-table",
                div { class: "event-head", span { "Members" } span { "{members().len()}" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-members-button",
                        onclick: {
                            let space = selected_space.clone();
                            move |_| {
                                // Spec-canonical read path is the local sync
                                // projection (driven by cx.events.subscribe).
                                // Members appear as the local store applies
                                // cx.member.state events.
                                let store = state_store.read();
                                let next = projected_members_for_space(&store, &space);
                                let count = next.len();
                                members.set(next);
                                status_msg.set(format!(
                                    "members refreshed ({count}) from local sync state"
                                ));
                            }
                        },
                        {crate::i18n::tr("space_admin.refresh_members")}
                    }
                }
                for member in members() {
                    {
                        let member_label = short_protocol_id(&member);
                        rsx! {
                            div { class: "event", "data-testid": "member-row", "data-member-did": "{member}",
                        div { class: "event-head",
                            // A4b — member avatar slot. Avatars are
                            // public via `cx.account.update_profile`
                            // (mirrored on this row via the
                            // `member-avatar` testid). v1 renders an
                            // initials-only placeholder; a follow-up
                            // task wires a directory lookup cache so
                            // the slot can carry the actual `<img>`
                            // for actors that have published one.
                            {
                                let initial = member
                                    .trim_start_matches("did:web:")
                                    .chars()
                                    .next()
                                    .map(|c| c.to_ascii_uppercase().to_string())
                                    .unwrap_or_else(|| "?".to_owned());
                                rsx! {
                                    div {
                                        "data-testid": "member-avatar",
                                        "aria-hidden": "true",
                                        style: "display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: var(--bg-elevated, #2a2d33); color: var(--text-strong, #fff); font-size: 0.8rem; margin-right: 8px;",
                                        "{initial}"
                                    }
                                }
                            }
                            span { title: "{member}", "{member_label}" }
                            {
                                // Mark agent-endpoint DIDs (registered via
                                // `cx.agent.endpoint`) so admins can tell bots
                                // apart from real members at a glance. Sourced
                                // from the same local raw_operations cache the
                                // Agents panel uses.
                                let is_agent = state_store
                                    .read()
                                    .load()
                                    .raw_operations
                                    .iter()
                                    .any(|r| {
                                        r.payload
                                            .get("kind")
                                            .and_then(|k| k.as_str())
                                            == Some("cx.agent.endpoint")
                                            && r.space_id
                                                .as_deref()
                                                .map(|s| s == selected_space)
                                                .unwrap_or(true)
                                            && r.payload
                                                .get("body")
                                                .and_then(|b| b.get("agent_did"))
                                                .and_then(|d| d.as_str())
                                                == Some(member.as_str())
                                    });
                                rsx! {
                                    if is_agent {
                                        span {
                                            class: "badge member-badge member-badge-agent",
                                            "data-testid": "member-badge-agent",
                                            title: "Automated member (bot)",
                                            "\u{1f916} "
                                            {crate::i18n::tr("member.badge.agent")}
                                        }
                                    }
                                }
                            }
                            span { "member" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "kick-member-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let actor_account_did = account_did.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        let actor_did = actor_account_did.clone();
                                        spawn(async move {
                                            let m_for_msg = m.clone();
                                            let space_for_api = space.clone();
                                            // Spec-canonical "kick" = `join → leave` member-state
                                            // transition (no separate kick FSM verb).
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    api.transition_member_state(
                                                        &space_for_api,
                                                        &actor_did,
                                                        &m,
                                                        Some("join"),
                                                        "leave",
                                                        "admin_kick",
                                                    )
                                                    .await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(resp) => {
                                                    let mls_encrypted = state_store
                                                        .read()
                                                        .space_projection_is_mls_encrypted(&space);
                                                    if mls_encrypted {
                                                        state_store.write().record_move_submission_with_event_id(
                                                            resp.event_id.clone(),
                                                            Some(resp.event_id.clone()),
                                                            space.clone(),
                                                            "mls_member_remove",
                                                            MoveSubmissionState::PendingMlsBinding,
                                                            Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                            None,
                                                        );
                                                    }
                                                    let suffix = if mls_encrypted {
                                                        "; epoch_update_required"
                                                    } else {
                                                        ""
                                                    };
                                                    status_msg.set(format!(
                                                        "kicked {}{}",
                                                        short_protocol_id(&m_for_msg),
                                                        suffix
                                                    ));
                                                }
                                                Err(err) => status_msg.set(format!(
                                                    "kick failed: {}", err.display()
                                                )),
                                            }
                                        });
                                    }
                                },
                                {crate::i18n::tr("space_admin.kick_member")}
                            }
                            button {
                                class: "secondary",
                                "data-testid": "ban-member-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let actor_account_did = account_did.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        let actor_did = actor_account_did.clone();
                                        spawn(async move {
                                            let m_for_msg = m.clone();
                                            let space_for_api = space.clone();
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    api.ban_member(&space_for_api, &actor_did, &m).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(resp) => {
                                                    let mls_encrypted = state_store
                                                        .read()
                                                        .space_projection_is_mls_encrypted(&space);
                                                    if mls_encrypted {
                                                        state_store.write().record_move_submission_with_event_id(
                                                            resp.event_id.clone(),
                                                            Some(resp.event_id.clone()),
                                                            space.clone(),
                                                            "mls_member_remove",
                                                            MoveSubmissionState::PendingMlsBinding,
                                                            Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                            None,
                                                        );
                                                    }
                                                    let suffix = if mls_encrypted {
                                                        "; epoch_update_required"
                                                    } else {
                                                        ""
                                                    };
                                                    status_msg.set(format!(
                                                        "banned {}{}",
                                                        short_protocol_id(&m_for_msg),
                                                        suffix
                                                    ));
                                                }
                                                Err(err) => status_msg.set(format!(
                                                    "ban failed: {}", err.display()
                                                )),
                                            }
                                        });
                                    }
                                },
                                {crate::i18n::tr("space_admin.ban_member")}
                            }
                            // (Legacy Move-flow kick/ban buttons removed — the
                            // direct-event kick/ban above now submits the same
                            // cx.member.state event via cx.events.submit.)
                            // A5 — personal blocklist entry-point. Block is
                            // a purely actor-private action (writes
                            // `cx.account_data.set("cx.account.blocklist", …)`)
                            // and does NOT touch the Space's member-state
                            // FSM. Confirm modal renders below the row.
                            button {
                                class: "secondary",
                                "data-testid": "member-row-block-button",
                                onclick: {
                                    let m = member.clone();
                                    move |_| block_confirm_did.set(Some(m.clone()))
                                },
                                {crate::i18n::tr("member.block")}
                            }
                        }
                        if block_confirm_did().as_deref() == Some(member.as_str()) {
                            div {
                                class: "event",
                                "data-testid": "block-user-confirm-modal",
                                div { class: "space-title", {crate::i18n::tr("member.block_confirm.title")} }
                                div { class: "muted", title: "{member}", "{member_label}" }
                                div { class: "muted", {crate::i18n::tr("member.block_confirm.body")} }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "block-user-confirm-button",
                                        onclick: {
                                            let m = member.clone();
                                            let base = base_url.clone();
                                            move |_| {
                                                let changed = state_store
                                                    .write()
                                                    .block_user(&m, None);
                                                block_confirm_did.set(None);
                                                if changed {
                                                    status_msg.set(format!(
                                                        "Blocked {}",
                                                        short_protocol_id(&m)
                                                    ));
                                                    let entries = state_store
                                                        .read()
                                                        .client_blocklist();
                                                    crate::views::settings::push_blocklist_account_data(
                                                        base.clone(),
                                                        token(),
                                                        entries,
                                                    );
                                                } else {
                                                    status_msg.set(format!(
                                                        "{} is already blocked",
                                                        short_protocol_id(&m)
                                                    ));
                                                }
                                            }
                                        },
                                        {crate::i18n::tr("member.block_confirm.confirm")}
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "block-user-cancel-button",
                                        onclick: move |_| block_confirm_did.set(None),
                                        {crate::i18n::tr("timeline.cancel")}
                                    }
                                }
                            }
                        }
                            }
                        }
                    }
                }
                if members().is_empty() {
                    div { class: "muted", {crate::i18n::tr("space_admin.no_members_loaded")} }
                }
            }

            // Space invites — sync/third-party-invites.md + invite event family
            // 6 canonical events drive the invite lifecycle:
            //   cx.invite.create        — create an invite (proactively invite a known DID)
            //   cx.invite.third_party   — invite a 3PID (email / phone) when the DID is unknown
            //   cx.invite.claim         — invitee receives the invite proof (bound to their DID)
            //   cx.invite.accept        — invitee formally accepts (writes membership)
            //   cx.invite.cancel        — inviter cancels (before the receiver has claimed)
            //   cx.invite.revoke        — inviter revokes (receiver claimed but has not accepted)
            div { class: "event", "data-testid": "invite-lifecycle-banner",
                div { class: "event-head",
                    span { "Invite lifecycle" }
                    span { "6 canonical events" }
                }
                div { class: "muted",
                    "Invites do not grant capabilities directly — the recipient must accept first. MUST carry expires_at; default 7 days, 24 hours for high-security Spaces."
                }
                div { class: "actions",
                    span { class: "badge blue", title: "cx.invite.create", "Create" }
                    span { class: "badge blue", title: "cx.invite.third_party", "Third-party" }
                    span { class: "badge", title: "cx.invite.claim", "Claim" }
                    span { class: "badge green", title: "cx.invite.accept", "Accept" }
                    span { class: "badge amber", title: "cx.invite.cancel", "Cancel" }
                    span { class: "badge red", title: "cx.invite.revoke", "Revoke" }
                }
            }

            // Space invites
            div { class: "event", "data-testid": "space-invites",
                div { class: "event-head", span { "Invites" } span { "lifecycle" } }
                for invite in space_invites() {
                    {
                        let invite_target_label = short_protocol_id(&invite.target);
                        let invite_id_label = short_protocol_id(&invite.invite_id);
                        rsx! {
                            div { class: "event", "data-testid": "invite-row",
                                div { class: "event-head",
                                    span { title: "{invite.target}", "{invite_target_label}" }
                                    span { "{invite.state}" }
                                }
                                div { class: "muted", "data-testid": "invite-target", title: "{invite.target}", "{invite.target}" }
                                div { class: "muted", "data-testid": "invite-id", title: "{invite.invite_id}", "{invite_id_label}" }
                                if let Some(role) = &invite.role {
                                    div { class: "muted", "role {role}" }
                                }
                                if let Some(operation_id) = &invite.operation_id {
                                    {
                                        let operation_id_label = short_protocol_id(operation_id);
                                        rsx! {
                                            div { class: "muted", title: "{operation_id}", "fact {operation_id_label}" }
                                        }
                                    }
                                }
                                if let Some(event_id) = &invite.event_id {
                                    {
                                        let event_id_label = short_protocol_id(event_id);
                                        rsx! {
                                            div { class: "muted", title: "{event_id}", "event {event_id_label}" }
                                        }
                                    }
                                }
                                div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "accept-invite-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.invite_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => {
                                                    let op = cx_ops::invite_accept(&space, &actor, &invite_id).build("yougen");
                                                    let op_id = op.local_operation_id().to_owned();
                                                    match api.submit_event_envelope(&op).await {
                                                        Ok(submitted) => {
                                                            for row in space_invites.write().iter_mut() {
                                                                if row.invite_id == invite_id {
                                                                    row.state = "accepted".to_owned();
                                                                    row.operation_id = Some(op_id.clone());
                                                                    row.event_id = Some(submitted.event_id.clone());
                                                                }
                                                            }
                                                            frontier_state.set(submitted.event_id.clone());
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.append_raw_operation(
                                                                    op_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "kind": "cx.invite.accept",
                                                                        "invite_id": invite_id,
                                                                        "state": "accepted",
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set(format!(
                                                                "accepted invite fact {}",
                                                                short_protocol_id(&op_id)
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("accept failed: {error}")),
                                                    }
                                                }
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "cancel-invite-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.invite_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => {
                                                    let op = cx_ops::invite_cancel(
                                                        &space,
                                                        &actor,
                                                        &invite_id,
                                                        Some("declined"),
                                                    )
                                                    .build("yougen");
                                                    let op_id = op.local_operation_id().to_owned();
                                                    match api.submit_event_envelope(&op).await {
                                                        Ok(submitted) => {
                                                            for row in space_invites.write().iter_mut() {
                                                                if row.invite_id == invite_id {
                                                                    row.state = "canceled".to_owned();
                                                                    row.operation_id = Some(op_id.clone());
                                                                    row.event_id = Some(submitted.event_id.clone());
                                                                }
                                                            }
                                                            frontier_state.set(submitted.event_id.clone());
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.append_raw_operation(
                                                                    op_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "kind": "cx.invite.cancel",
                                                                        "invite_id": invite_id,
                                                                        "state": "canceled",
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set(format!(
                                                                "canceled invite fact {}",
                                                                short_protocol_id(&op_id)
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("cancel failed: {error}")),
                                                    }
                                                }
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Cancel"
                            }
                        }
                            }
                        }
                    }
                }
                if space_invites().is_empty() {
                    div { class: "muted", "No pending invites." }
                }
            }

            // Space discovery toggle
            div { class: "event", "data-testid": "discovery-toggle",
                div { class: "event-head", span { "Discovery" } span { "visibility" } }
                label {
                    input {
                        r#type: "checkbox",
                        checked: discovery_enabled(),
                        onchange: move |evt| discovery_enabled.set(evt.value() == "true"),
                    }
                    " Listed in directory"
                }
            }
            }

            if active_section == SpaceAdminSection::Security {
            // Audited E2EE assurance — crypto-media/audited-e2ee.md
            // Two profiles: cx.profile.attested_audit.e2ee.v1 (HW attestation forced)
            // and cx.profile.disclosed_audit.e2ee.v1 (procedural disclosure only).
            // UI MUST surface the policy choice + canonical join warning copy +
            // forbidden marketing terms (see audited-e2ee §3.1.1 / §3.5).
            div { class: "event", "data-testid": "audited-e2ee-assurance",
                div { class: "event-head",
                    span { "Audited E2EE assurance" }
                    span { "audit_disclosure policy" }
                }
                div { class: "muted",
                    "v1 core splits audited E2EE into two hardening profiles: attested and disclosed. Space policy is declared with an audit_disclosure object plus an audit_assurance enum; join warnings and external materials follow the normative classification and forbidden-marketing wording in audited-e2ee.md §3.1.1 and §3.5."
                }
                div { class: "metric-grid", "data-testid": "audited-e2ee-tiers",
                    div { class: "metric",
                        strong { "none" }
                        span { class: "badge", "default" }
                        div { class: "muted", "Standard MLS E2EE with no audit profile" }
                    }
                    div { class: "metric",
                        strong { "disclosed_audit" }
                        span { class: "badge amber", "disclosed_audit.e2ee.v1" }
                        div { class: "muted", "Audit agent receives procedural disclosure; cx.audit.accessed is mandatory; no cryptographic attestation" }
                    }
                    div { class: "metric",
                        strong { "attested_audit" }
                        span { class: "badge red", "attested_audit.e2ee.v1" }
                        div { class: "muted", "Hardware attestation required; the RYW receipt schema enforces cx.audit.ryw_receipt" }
                    }
                }
                div { class: "muted",
                    "Forbidden marketing wording: do not claim plain \"end-to-end encrypted\" — use \"E2EE with disclosed/attested audit\". See audited-e2ee.md §3.5."
                }
                div { class: "actions",
                    span { class: "muted", "Audit-bound key share events:" }
                    span { class: "badge blue", title: "cx.space_key.share", "Key share" }
                    span { class: "badge", title: "cx.space_key.share_audit", "Audit entry" }
                    span { class: "badge red", title: "cx.space_key.withheld", "Withheld" }
                }
                div { class: "actions",
                    button { class: "secondary", "data-testid": "audited-e2ee-set-none", "No audit profile" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-disclosed", "Enable disclosed_audit" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-attested", "Enable attested_audit" }
                }
            }

            // MLS epoch rotation
            div { class: "event", "data-testid": "mls-rotation",
                div { class: "event-head", span { "MLS Epoch" } span { "rotation" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "rotate-space-epoch",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.rotate_mls_epoch(&space).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "rotated to epoch {}", resp.epoch
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "rotate failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("space_admin.rotate_epoch")}
                    }
                }
            }

            // Leave space
            div { class: "event", "data-testid": "leave-space",
                div { class: "event-head", span { "Leave Space" } span { "" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "leave-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let mut state_store = state_store;
                            let mut sync_cursor = sync_cursor;
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    let space_for_msg = space.clone();
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.leave_space(&space, &actor_did).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            state_store.write().forget_space(&space_for_msg);
                                            sync_cursor.set("-".to_owned());
                                            status_msg.set(format!(
                                                "left {space_for_msg}; local cache cleared"
                                            ));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "leave failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("space_admin.leave_space")}
                    }
                }
            }
            }

            // Capability grant explanation — claude-design desktop/space-admin.html
            // authz/capabilities.md (delegation, revocation, claim conditions)
            //
            // Constraint type model: 8 family + subtype discriminator per
            // `authz/constraint-schema.md` §2.2:
            //   temporal (subtype: edit_window / redact_window / session_lifetime / ...)
            //   field_access (subtype: field_write_allow / field_write_deny)
            //   type_restriction (subtype: object_type / morph_type / facet)
            //   scope_limitation (subtype: container_move / view_kind / track / ...)
            //   delegation_control (subtype: max_depth / subset_only)
            //   quota (subtype: rate / resource)
            //   claim_based (subtype: approval / accountability / ...)
            //   confidentiality (subtype: encryption / visibility / sensitive_handling)
            // The grant-explanation rows below treat constraint as a description hint;
            // any future write UI MUST emit `(family, subtype)` pairs.
            div { class: "event", "data-testid": "grant-explanation",
                div { class: "event-head",
                    span { "Capability Grants" }
                    span { "approval_constraint trail" }
                }
                div { class: "muted",
                    "Grants are the input reducers use to accept or reject writes. Every decision is traceable to a signed grant; high-risk actions add an approval_constraint on top. Handles and email addresses are display-only — the permission subject is the DID."
                }
                div { class: "metric-grid", "data-testid": "grant-explanation-rows",
                    div { class: "metric",
                        strong { "Mei (admin)" }
                        span { "read · write · moderate · grant" }
                        div { class: "muted", "did:plc:8djrfj4… · permanent · auto-renew" }
                    }
                    div { class: "metric",
                        strong { "Build-bot (applet)" }
                        span { "write_message · reaction" }
                        div { class: "muted", "did:web:bot.acme.example · 30d · approval=auto" }
                    }
                    div { class: "metric",
                        strong { "Researcher Agent" }
                        span { "read_flow (pending)" }
                        div { class: "muted", "approval_constraint = 2 of 3 admin · 1/3 approved" }
                    }
                    div { class: "metric",
                        strong { "Compliance Auditor (partner)" }
                        span { "read_flow + write_morph(audit_report)" }
                        div { class: "muted", "did:web:partner.example · weekly job · revocable" }
                    }
                }
                div { class: "actions", "data-testid": "grant-decision-actions",
                    button { class: "primary", "data-testid": "grant-approve-button", "Approve Researcher Agent" }
                    button { class: "secondary", "data-testid": "grant-deny-button", "Deny and sign cx.capability.revoke" }
                    button { class: "secondary", "data-testid": "grant-explain-button", "View full grant trail (audit)" }
                }
                div { class: "muted",
                    "Reducer decision inputs: cx.capability.grant / cx.capability.revoke / resolved approval_constraint. Full trail in /audit."
                }
            }

            // Capability grant / revoke anchored-cell card (P0 M-capability).
            // Mirrors the consent grant/revoke PoC but targets
            // cx.component.capability.grant.v1 (OrSet add/remove). Signed
            // with the demo session key (TODO real-key-management) and
            // submitted through cx.events.submit. Anchor frontier is threaded
            // from the local sync view.
            div { class: "event", "data-testid": "capability-grant-card",
                div { class: "event-head",
                    span { "Capability grant / revoke (Move PoC)" }
                    span { "cx.component.capability.grant.v1 · OrSet" }
                }
                div { class: "muted",
                    "Submits a cx.capability.grant or cx.capability.revoke event via cx.events.submit; soland's reducer applies the OrSet add/remove to the capability cell."
                }
                label { "Grant ID (cell subject)" }
                input {
                    "data-testid": "cap-grant-id-input",
                    value: "{cap_grant_id}",
                    oninput: move |evt| cap_grant_id.set(evt.value()),
                }
                label { "Capability tag (action / scope)" }
                input {
                    "data-testid": "cap-grant-tag-input",
                    value: "{cap_tag}",
                    oninput: move |evt| cap_tag.set(evt.value()),
                }
                label { "Revoke reason (optional)" }
                input {
                    "data-testid": "cap-revoke-reason-input",
                    value: "{cap_revoke_reason}",
                    oninput: move |evt| cap_revoke_reason.set(evt.value()),
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
                select {
                    "data-testid": "cap-constraint-kind-select",
                    value: "{cap_constraint_kind}",
                    onchange: move |evt| cap_constraint_kind.set(evt.value()),
                    option { value: "none", "none" }
                    option { value: "temporal", "temporal (not_before / not_after)" }
                    option { value: "quota", "quota (coming soon)" }
                    option { value: "scope_limitation", "scope_limitation (coming soon)" }
                }
                if cap_constraint_kind() == "temporal" {
                    div { "data-testid": "cap-constraint-temporal-fields",
                        label { "not_before (RFC 3339, optional)" }
                        input {
                            "data-testid": "cap-constraint-not-before-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_not_before}",
                            oninput: move |evt| {
                                cap_temporal_not_before.set(evt.value());
                            },
                        }
                        label { "not_after (RFC 3339, optional)" }
                        input {
                            "data-testid": "cap-constraint-not-after-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_not_after}",
                            oninput: move |evt| {
                                cap_temporal_not_after.set(evt.value());
                            },
                        }
                    }
                } else if cap_constraint_kind() == "quota"
                    || cap_constraint_kind() == "scope_limitation"
                {
                    div {
                        class: "muted",
                        "data-testid": "cap-constraint-coming-soon",
                        "{cap_constraint_kind()} editor not yet implemented; the wire shape "
                        "passes through `move_builder::CapabilityConstraintInput::Other` once a UI lands."
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "cap-grant-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let grant_val = cap_grant_id().trim().to_owned();
                                let tag_val = cap_tag().trim().to_owned();
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability grant".to_owned(),
                                    );
                                    return;
                                }
                                let actor_did =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id.device_did.as_str().to_owned(),
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                // Pull the active constraint from the editor
                                // signals into the wire shape. Empty input
                                // yields no constraint.
                                let kind = cap_constraint_kind();
                                let constraint_json: serde_json::Value =
                                    if kind == "temporal" {
                                        let nb = cap_temporal_not_before();
                                        let na = cap_temporal_not_after();
                                        let nb_trim = nb.trim();
                                        let na_trim = na.trim();
                                        if nb_trim.is_empty() && na_trim.is_empty() {
                                            serde_json::Value::Null
                                        } else {
                                            let mut window = serde_json::Map::new();
                                            if !nb_trim.is_empty() {
                                                window.insert(
                                                    "not_before".into(),
                                                    serde_json::Value::String(nb_trim.to_owned()),
                                                );
                                            }
                                            if !na_trim.is_empty() {
                                                window.insert(
                                                    "not_after".into(),
                                                    serde_json::Value::String(na_trim.to_owned()),
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
                                let envelope = crate::operation::cx_ops::capability_grant(
                                    &space,
                                    &actor_did,
                                    &grant_val,
                                    &tag_val,
                                    constraint_json,
                                )
                                .build("yougen");
                                let op_id = envelope.local_operation_id().to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_event_envelope(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "cx.capability.grant event {}: event_id={}",
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
                        {crate::i18n::tr("space_admin.grant_capability_move")}
                    }
                    button {
                        class: "secondary",
                        "data-testid": "cap-revoke-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
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
                                let actor_did =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id.device_did.as_str().to_owned(),
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let envelope = crate::operation::cx_ops::capability_revoke(
                                    &space,
                                    &actor_did,
                                    &grant_val,
                                    &tag_val,
                                    reason_opt.as_deref(),
                                )
                                .build("yougen");
                                let op_id = envelope.local_operation_id().to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_event_envelope(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "cx.capability.revoke event {}: event_id={}",
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
                        {crate::i18n::tr("space_admin.revoke_capability_move")}
                    }
                }
            }

            if active_section == SpaceAdminSection::Governance {
            // Organization governance — identity/identity-did.md §6 + content-moderation
            // An Organization is a Principal (not a Realm). A single Realm can be
            // jointly governed by multiple organizations; the Realm's organization
            // relationships are maintained via the cx.realm.organization event.
            div { class: "event", "data-testid": "organization-governance",
                div { class: "event-head",
                    span { "Organization governance" }
                    span { "Realm ≠ Organization" }
                }
                div { class: "muted",
                    "An Organization is a Principal (a DID), not a Realm. Multi-org governance is expressed via cx.realm.organization relations; organization directory and moderation policy live independently of any single Realm."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Owning organizations" }
                        span { title: "cx.realm.organization", "Organization link" }
                        div { class: "muted", "Declares the organization(s) this Realm belongs to" }
                    }
                    div { class: "metric",
                        strong { "Org directory listing" }
                        span { title: "cx.organization.discovery", "Directory listing" }
                        div { class: "muted", "Organization-level discoverability, independent of any Space" }
                    }
                    div { class: "metric",
                        strong { "Org moderation policy" }
                        span { title: "cx.organization.moderation_policy", "Moderation policy" }
                        div { class: "muted", "Organization-level moderation; Spaces can inherit or override" }
                    }
                    div { class: "metric",
                        strong { "Sovereign DID policy" }
                        span { title: "cx.sovereign.did_policy", "Identity policy" }
                        div { class: "muted", "High-security deployments: restrict acceptable identity methods / resolver trust" }
                    }
                }
            }

            // Policy events — authz/policy-server.md
            // The three cx.policy.{rule,action,set} events feed the reducer's decision:
            //   cx.policy.rule    — a single rule (match condition + effect + scope)
            //   cx.policy.action  — a single action template (referenced by rules)
            //   cx.policy.set     — bundles rules + actions into one published policy version
            div { class: "event", "data-testid": "policy-event-family",
                div { class: "event-head",
                    span { "Policy authoring" }
                    span { "cx.policy.{{rule,action,set}}" }
                }
                div { class: "muted",
                    "Policy is the input the reducer and service node use to decide whether a request is acceptable. A policy is published as a set composed of rules + actions; one policy_version is written atomically."
                }
                div { class: "actions",
                    span { class: "badge blue", title: "cx.policy.rule", "Rule" }
                    span { class: "badge", title: "cx.policy.action", "Action" }
                    span { class: "badge green", title: "cx.policy.set", "Published set" }
                    span { class: "muted", "— three events combine to publish one policy version" }
                }
            }

            // Moderation events — governance/content-moderation.md
            // Two canonical events drive content-level moderation:
            //   cx.moderation.report — an actor files a report (against a message / flow / morph / actor)
            //   cx.moderation.franking_proof  — E2EE franking proof (so encrypted content remains reviewable)
            // Outcomes like quarantine / require_review are reducer decisions, not separate events.
            div { class: "event", "data-testid": "moderation-events",
                div { class: "event-head",
                    span { "Moderation events" }
                    span { "governance/content-moderation.md" }
                }
                div { class: "muted",
                    "Reports and moderation evidence are carried by two events; the reducer's decisions (deny / quarantine / require_review) materialize as cx.policy.action. Franking lets reviewers verify the sender of E2EE content without breaking the ciphertext."
                }
                div { class: "actions",
                    span { class: "badge blue", title: "cx.moderation.report", "Report" }
                    span { class: "badge accent", title: "cx.moderation.franking_proof", "Franking proof" }
                    span { class: "muted", "→ reducer decides deny / quarantine / require_review" }
                }
            }
            }

            if active_section == SpaceAdminSection::Federation {
            // Trust bundle import — claude-design desktop/space-admin.html
            // sync/federation.md + sync/sovereign-deployment.md
            div { class: "event", "data-testid": "trust-bundle-panel",
                div { class: "event-head",
                    span { "Trust Bundle (Federation)" }
                    span { "Trusted organization / service DIDs" }
                }
                div { class: "muted",
                    "Federation, cross-organization, and Controlled Collaboration Spaces must publish an explicit trust_bundle that enumerates eligible organization DIDs, service DIDs, and trusted issuers. Validate method evidence, the trust root, and service delegation before importing."
                }
                div { class: "metric-grid", "data-testid": "trust-bundle-rows",
                    div { class: "metric",
                        strong { "did:web:partner.example" }
                        span { "trust_bundle v3" }
                        div { class: "muted", "active · federation_in" }
                    }
                    div { class: "metric",
                        strong { "did:web:beta.example" }
                        span { "trust_bundle v2 · pending" }
                        div { class: "muted", "Missing attestation issuer; trust root not confirmed" }
                    }
                    div { class: "metric",
                        strong { "did:web:github-mirror.acme.example" }
                        span { "portal scope only" }
                        div { class: "muted", "applet · plaintext_visible(portal)" }
                    }
                    div { class: "metric",
                        strong { "did:web:hsm.contrix.social" }
                        span { "service · backup HSM" }
                        div { class: "muted", "1 use per year quota; recovery only" }
                    }
                }
                div { class: "actions", "data-testid": "trust-bundle-actions",
                    button { class: "primary", "data-testid": "trust-bundle-import-button", "Import trust_bundle" }
                    button { class: "secondary", "data-testid": "trust-bundle-validate-button", "Validate signature + method evidence" }
                    button { class: "secondary", "data-testid": "trust-bundle-revoke-button", "Revoke federation_in (partner)" }
                }
            }
            }

            // Danger zone
            if active_section == SpaceAdminSection::Repair {
            div { class: "event", "data-testid": "danger-zone",
                div { class: "event-head", span { "Danger Zone" } span { "destructive actions" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "archive-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                let space_for_msg = space.clone();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.archive_space(&space, &space, &actor_did).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => status_msg.set(format!(
                                            "archive event submitted ({space_for_msg})"
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "archive failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("space_admin.archive_space")}
                    }
                    button {
                        class: "secondary",
                        "data-testid": "delete-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    let space_for_msg = space.clone();
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.delete_space(&space, &space, &actor_did).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => status_msg.set(format!(
                                            "deleted {}",
                                            short_protocol_id(&space_for_msg)
                                        )),
                                        Err(err) => status_msg.set(format!("delete failed: {}", err.display())),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("space_admin.tombstone_delete")}
                    }
                }
            }

            // Device-revoke MLS Remove builder.
            // Lets an operator turn the persisted MLS snapshot for this
            // Space into a canonical `mls_commit` Operation that removes
            // a target device's leaf, submits it, and re-persists the
            // post-commit group state. On wasm builds (no OpenMLS
            // runtime) we surface a desktop-only notice instead — the
            // SDK group can't be hydrated from inside the browser yet.
            div { class: "event", "data-testid": "mls-remove-builder",
                div { class: "event-head",
                    span { {crate::i18n::tr("space_admin.mls_remove_header")} }
                    span { "B5c · cx.mls.commit" }
                }
                div { class: "muted",
                    {crate::i18n::tr("space_admin.mls_remove_hint")}
                }
                {
                    let has_snapshot = state_store
                        .read()
                        .mls_snapshot_for(&selected_space)
                        .is_some();
                    let cfg_native = cfg!(not(target_arch = "wasm32"));
                    let snapshot_banner = if !cfg_native {
                        "Web build cannot decrypt MLS snapshots — switch to the desktop client to revoke a device."
                    } else if !has_snapshot {
                        "No MLS snapshot persisted for this Space yet. Send at least one Secure message (chat.rs) to seed one before revoking a device."
                    } else {
                        "Snapshot found; enter the target device DID and click Build & submit."
                    };
                    let disable_button = !(cfg_native && has_snapshot);
                    rsx! {
                        div { class: "muted", "data-testid": "mls-remove-snapshot-status", "{snapshot_banner}" }
                        div { class: "workflow-form",
                            input {
                                "data-testid": "mls-remove-target-did",
                                value: "{device_revoke_target}",
                                placeholder: crate::i18n::tr("space_admin.mls_remove_target_placeholder"),
                                oninput: move |evt| device_revoke_target.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "danger",
                                    "data-testid": "mls-remove-submit-button",
                                    disabled: disable_button,
                                    title: crate::i18n::tr("space_admin.mls_remove_button"),
                                    onclick: {
                                        let base = base_url.clone();
                                        let space = selected_space.clone();
                                        let actor = account_did.clone();
                                        let device = device_id.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let space = space.clone();
                                            let actor = actor.clone();
                                            let device = device.clone();
                                            let api_token = token();
                                            let target = device_revoke_target().trim().to_owned();
                                            spawn(async move {
                                                run_device_revoke_from_snapshot(
                                                    base,
                                                    api_token,
                                                    state_store,
                                                    space,
                                                    actor,
                                                    device,
                                                    target,
                                                    device_revoke_status,
                                                )
                                                .await;
                                            });
                                        }
                                    },
                                    {crate::i18n::tr("space_admin.mls_remove_button")}
                                }
                            }
                            if !device_revoke_status().is_empty() {
                                div { class: "muted", "data-testid": "mls-remove-status", "{device_revoke_status}" }
                            }
                        }
                    }
                }
            }

            // Chained MLS Remove + epoch-advance Move tracker. Reads the
            // local move_submissions store, filters for `mls_commit` +
            // `mls_epoch_advance` kinds in the current Space, pairs them by
            // submission timestamp, and surfaces each pair as a chain
            // entry. Operators monitor here when a device-revocation chain
            // has stalled (e.g. anchorer paused before the epoch-advance
            // landed).
            div { class: "event", "data-testid": "mls-revoke-chain-tracker",
                div { class: "event-head",
                    span { "MLS revoke Move chains" }
                }
                div { class: "muted",
                    "Each row shows one chain of MLS Remove (commit) + epoch-advance Moves triggered by a device revocation. Both Moves must reach Effective before the device is fully unspooled from the group; failures are surfaced inline so operators can take corrective action."
                }
                {
                    let submissions = state_store
                        .read()
                        .move_submissions_for_space(&selected_space);
                    let commits: Vec<_> = submissions
                        .iter()
                        .filter(|r| r.kind == "mls_commit")
                        .cloned()
                        .collect();
                    let epoch_advances: Vec<_> = submissions
                        .iter()
                        .filter(|r| r.kind == "mls_epoch_advance")
                        .cloned()
                        .collect();
                    let chains: Vec<MlsRevokeMoveChain> = commits
                        .iter()
                        .enumerate()
                        .map(|(i, commit)| {
                            let epoch = epoch_advances.get(i);
                            let commit_state = match commit.state {
                                MoveSubmissionState::Effective => ChainMoveState::Effective,
                                MoveSubmissionState::PendingAnchor
                                | MoveSubmissionState::PendingMlsBinding => ChainMoveState::Pending,
                                _ => ChainMoveState::Failed {
                                    reason: commit
                                        .reason
                                        .clone()
                                        .unwrap_or_else(|| commit.state.label_zh().to_owned()),
                                },
                            };
                            let epoch_state = match epoch.map(|e| e.state) {
                                None => ChainMoveState::NotSubmitted,
                                Some(MoveSubmissionState::Effective) => ChainMoveState::Effective,
                                Some(MoveSubmissionState::PendingAnchor)
                                | Some(MoveSubmissionState::PendingMlsBinding) => {
                                    ChainMoveState::Pending
                                }
                                Some(_) => ChainMoveState::Failed {
                                    reason: epoch
                                        .and_then(|e| e.reason.clone())
                                        .unwrap_or_else(|| "epoch advance failed".to_owned()),
                                },
                            };
                            MlsRevokeMoveChain {
                                group_id: selected_space.clone(),
                                commit_move_id: Some(commit.move_id.clone()),
                                epoch_advance_move_id: epoch.map(|e| e.move_id.clone()),
                                commit_state,
                                epoch_advance_state: epoch_state,
                                pre_revoke_epoch: None,
                            }
                        })
                        .collect();
                    rsx! {
                        if chains.is_empty() {
                            div { class: "muted", "data-testid": "mls-revoke-chain-empty",
                                "No MLS revoke Move chains tracked for this Space yet. They appear here when a device-revoke handler enqueues an MLS commit + epoch-advance pair."
                            }
                        }
                        for chain in chains {
                            {
                                let group_id_label = short_protocol_id(&chain.group_id);
                                rsx! {
                                    div { class: "event", "data-testid": "mls-revoke-chain-row",
                                        div { class: "event-head",
                                            span { title: "{chain.group_id}", "{group_id_label}" }
                                            span { class: "badge", "{chain.status_summary()}" }
                                        }
                                        div { class: "metric-grid",
                                            div { class: "metric",
                                                strong { "MLS commit" }
                                                span {
                                                    class: "{chain.commit_state.badge_class()}",
                                                    "{chain.commit_state.label()}"
                                                }
                                                if let Some(ref id) = chain.commit_move_id {
                                                    {
                                                        let id_label = short_protocol_id(id);
                                                        rsx! {
                                                            div { class: "muted", title: "{id}", "{id_label}" }
                                                        }
                                                    }
                                                }
                                                if let ChainMoveState::Failed { reason } =
                                                    &chain.commit_state
                                                {
                                                    div { class: "muted", "reason: {reason}" }
                                                }
                                            }
                                            div { class: "metric",
                                                strong { "Epoch advance" }
                                                span {
                                                    class: "{chain.epoch_advance_state.badge_class()}",
                                                    "{chain.epoch_advance_state.label()}"
                                                }
                                                if let Some(ref id) = chain.epoch_advance_move_id {
                                                    {
                                                        let id_label = short_protocol_id(id);
                                                        rsx! {
                                                            div { class: "muted", title: "{id}", "{id_label}" }
                                                        }
                                                    }
                                                }
                                                if let ChainMoveState::Failed { reason } =
                                                    &chain.epoch_advance_state
                                                {
                                                    div { class: "muted", "reason: {reason}" }
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

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "space-admin-status", "{status_msg}" }
            }
        }
    }
}

/// wasm-fallback for the MLS Remove handler. The
/// browser build can't decrypt the snapshot or talk to OpenMLS, so this
/// branch surfaces a clear "use desktop" notice and returns without
/// touching `state_store` or the network.
#[cfg(target_arch = "wasm32")]
async fn run_device_revoke_from_snapshot(
    _base_url: String,
    _api_token: String,
    _state_store: Signal<LocalStateStore>,
    _space_id: String,
    _actor_did: String,
    _device_id: String,
    _target_did: String,
    mut status: Signal<String>,
) {
    status.set(
        "MLS Remove requires the desktop client (browser build has no OpenMLS runtime). Switch clients and try again."
            .to_owned(),
    );
}

/// Native handler that wraps
/// [`crate::device_revoke::execute_mls_remove_from_snapshot`]:
///
/// 1. read the encrypted MLS snapshot for the Space out of the local state store;
/// 2. validate inputs and load this device's snapshot secret;
/// 3. mint a UUIDv7 operation_id, parse typed `Did` / `SpaceId`;
/// 4. run the SDK Remove (group decrypt → commit → re-export);
/// 5. submit the `mls_commit` Operation via `with_authed_api`;
/// 6. on submit success, re-encrypt the post-commit group state and save it back so the next boot
///    doesn't try to rehydrate the pre-revoke epoch.
///
/// Any error along the way is surfaced verbatim in the `status` signal;
/// the operator can inspect it inline and retry without page reload.
#[cfg(not(target_arch = "wasm32"))]
async fn run_device_revoke_from_snapshot(
    base_url: String,
    api_token: String,
    mut state_store: Signal<LocalStateStore>,
    space_id: String,
    actor_did: String,
    device_id: String,
    target_did: String,
    mut status: Signal<String>,
) {
    if target_did.is_empty() {
        status.set("target device DID is required".to_owned());
        return;
    }
    let envelope = match state_store.read().mls_snapshot_for(&space_id) {
        Some(env) => env,
        None => {
            status.set(format!(
                "no persisted MLS snapshot for space {}; nothing to revoke against",
                short_protocol_id(&space_id)
            ));
            return;
        }
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let snapshot_secret = match crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        &actor_did,
        &device_id,
    ) {
        Ok(secret) => secret,
        Err(err) => {
            status.set(format!("device MLS snapshot secret unavailable: {err}"));
            return;
        }
    };
    let typed_target = match contrix_sdk::Did::new(target_did.clone()) {
        Ok(d) => d,
        Err(err) => {
            status.set(format!("invalid target DID: {err}"));
            return;
        }
    };
    let typed_realm = match contrix_sdk::RealmId::new(space_id.clone()) {
        Ok(s) => s,
        Err(err) => {
            status.set(format!("invalid realm id: {err}"));
            return;
        }
    };
    let op_id_str = format!("cx:operation:{}", crate::operation::uuid_v7());
    let typed_op_id = match contrix_sdk::OperationId::new(op_id_str) {
        Ok(o) => o,
        Err(err) => {
            status.set(format!("internal: operation id minting failed: {err}"));
            return;
        }
    };
    let full = match crate::device_revoke::execute_mls_remove_from_snapshot(
        &envelope,
        &snapshot_secret,
        &typed_target,
        typed_op_id,
        typed_realm,
    ) {
        Ok(full) => full,
        Err(err) => {
            status.set(format!("MLS Remove execution failed: {err}"));
            return;
        }
    };
    let removed_count = full.output.result.removed_leaves.len();
    let post_state = full.post_state.clone();
    // The SDK's `commit_operation` returns an SDK-typed Operation. We
    // wrap its payload into yougen's EventEnvelope shape so the
    // existing `submit_event_envelope` path (Event envelope wrapper +
    // /api/v1/events POST) accepts it without a separate wire route.
    let actor = full
        .output
        .commit_operation
        .payload
        .get("creator")
        .and_then(|v| v.as_str())
        .unwrap_or("yougen-operator")
        .to_owned();
    let target_ref = full.output.commit_operation.object_id.clone();
    let mut envelope_builder =
        crate::operation::OperationBuilder::new(space_id.clone(), actor, "mls_commit")
            .body(full.output.commit_operation.payload.clone());
    if let Some(tref) = target_ref {
        envelope_builder = envelope_builder.target_ref(tref);
    }
    let envelope = envelope_builder.build("yougen");
    let submit_result =
        crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.submit_event_envelope(&envelope).await
        })
        .await;
    match submit_result {
        Ok(_) => {
            // Re-encrypt and persist the post-commit group state so a
            // boot after the submit doesn't read the pre-revoke epoch.
            let mut salt = [0u8; 16];
            if let Err(err) = getrandom::fill(&mut salt) {
                status.set(format!(
                    "submit accepted but rng fill failed: {err}; re-encrypt deferred"
                ));
                return;
            }
            let new_envelope = crate::mls::persistence::encrypt_state(
                &space_id,
                &post_state.group_id,
                post_state.epoch,
                &post_state.serialized_state,
                &snapshot_secret,
                &salt,
            );
            state_store
                .write()
                .save_mls_snapshot(space_id.clone(), new_envelope);
            let snapshot = state_store.read().mls_snapshot_for(&space_id);
            let backup_result = if let Some(snapshot) = snapshot {
                crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| {
                    let actor_did = actor_did.clone();
                    let device_id = device_id.clone();
                    async move {
                        crate::mls::runtime::upload_mls_snapshot_backup(
                            &api, &snapshot, &actor_did, &device_id,
                        )
                        .await
                        .map_err(|err| anyhow::anyhow!(err.user_message()))
                    }
                })
                .await
                .map(Some)
            } else {
                Ok(None)
            };
            let backup_suffix = match backup_result {
                Ok(Some(backup_id)) => {
                    format!(
                        "; MLS history backup {} uploaded",
                        short_protocol_id(&backup_id)
                    )
                }
                Ok(None) => String::new(),
                Err(err) => format!("; MLS history backup failed: {}", err.display()),
            };
            status.set(format!(
                "MLS Remove submitted; {removed_count} leaf/leaves removed; post-state re-persisted (epoch {}){}",
                post_state.epoch,
                backup_suffix
            ));
        }
        Err(err) => {
            status.set(format!("MLS Remove submit failed: {}", err.display()));
        }
    }
}

// (Move-flow test module removed; the wire shapes are now covered by soland's events.submit tests
// and contrix-spec fixtures.)
