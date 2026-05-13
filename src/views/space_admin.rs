use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::json;

use crate::{
    device_revoke::{ChainMoveState, MlsRevokeMoveChain},
    hlc::Hlc,
    local_state::{LocalIdentity, LocalStateStore, MoveSubmissionState},
    models::SubmitMoveResponse,
    move_builder::{
        CapabilityConstraintInput, UnsignedMove, build_capability_grant_move_with_constraints,
        build_capability_revoke_move, build_conflict_repair_move,
        build_member_state_transition_move, build_space_organization_update_move,
        did_key_verification_method, sign_unsigned_move,
    },
    operation::cx_ops,
    routes::Route,
    views::{
        consent_demo::format_submit_response,
        helpers::{active_sync_token, authed_api, authed_api_with_sync},
    },
};
// `build_capability_grant_move` is only used by the test-only
// `build_signed_capability_grant` helper that pins the empty-constraint
// wire shape — gate the import to avoid a warning in non-test builds.
#[cfg(test)]
use crate::move_builder::build_capability_grant_move;

/// Default `covered_frontier_lag` warning threshold used by the
/// space_admin alert banner. Mirrors sodmin's
/// `DEFAULT_LAG_WARN_THRESHOLD` so a member moving between the two
/// surfaces sees the same alert ceiling. Round 22 — read from the user
/// preference signal in [`SpaceAdminPanel`].
pub(crate) const DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD: u64 = 5;

/// Placeholder anchor frontier used until sync.rs (P0 M3) surfaces the
/// effective Anchor head. Mirrors `consent_demo::PLACEHOLDER_ANCHOR_REF`.
/// Test-only — the production UI now reads the resolved frontier from
/// `LocalAnchorView` via `state_store.read().anchor_ref_for_move`.
#[cfg(test)]
const PLACEHOLDER_ANCHOR_REF: &str =
    "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Pure helper: build + sign a `cx.space.update` Move that writes the
/// space organization cas-register cell. Mirrors the consent-grant signing
/// flow so the Dioxus closure stays small. Round 21: takes the persisted
/// per-device [`LocalIdentity`] in place of the historical demo seed —
/// see `local_state::LocalStateStore::ensure_local_identity`.
pub(crate) fn build_signed_space_organization_update(
    identity: &LocalIdentity,
    space_id: &str,
    value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        build_space_organization_update_move(did, space_id, value, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Pure helper: build + sign a `cx.capability.grant` Move (OrSet add)
/// targeting `cx.component.capability.grant.v1`. Mirrors the consent
/// helpers — same signing path, just a different cell family. Round 22
/// retired the production caller (the UI now goes through
/// [`build_signed_capability_grant_with_constraints`] so a temporal
/// constraint can flow through); this remains for tests so the
/// no-constraint wire shape stays pinned to a stable test vector.
#[cfg(test)]
pub(crate) fn build_signed_capability_grant(
    identity: &LocalIdentity,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        build_capability_grant_move(did, space_id, grant_id, tag, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Round 22 — capability grant with structured constraints. Mirrors
/// [`build_signed_capability_grant`] but threads a constraint slice
/// through to the move_builder. The wire shape only differs when the
/// slice is non-empty (constraints land in the OrSet add op's `value`
/// field).
pub(crate) fn build_signed_capability_grant_with_constraints(
    identity: &LocalIdentity,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    constraints: &[CapabilityConstraintInput],
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove = build_capability_grant_move_with_constraints(
        did,
        space_id,
        grant_id,
        tag,
        constraints,
        anchor_ref,
        hlc,
    )?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Pure helper: build + sign a `cx.capability.revoke` Move (OrSet remove)
/// on the same cell family as the grant. `reason` shows up in the audit
/// trail and lets the UI explain why the capability was dropped.
pub(crate) fn build_signed_capability_revoke(
    identity: &LocalIdentity,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        build_capability_revoke_move(did, space_id, grant_id, tag, reason, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Round 23 (M8): pure helper — build + sign a conflict-repair Move
/// targeting a `bottom=expose` cell. Wraps
/// [`crate::move_builder::build_conflict_repair_move`] with the
/// per-device identity / DID URL fields the UI shouldn't have to
/// recompute. Admin / moderator only — soland's authz reducer rejects
/// unsigned-by-recovery-capability submissions.
pub(crate) fn build_signed_conflict_repair(
    identity: &LocalIdentity,
    space_id: &str,
    cell_id: &str,
    conflict_heads: &[String],
    recovery_capability_ref: &str,
    winner_value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove = build_conflict_repair_move(
        did,
        space_id,
        cell_id,
        conflict_heads,
        recovery_capability_ref,
        winner_value,
        anchor_ref,
        hlc,
    )?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Pure helper: format a `SubmitMoveResponse` AND record the outcome
/// in the local state's [`crate::local_state::MoveSubmissionState`]
/// tracker. Returns the formatted status string the caller can show
/// inline. Round 23 (M4).
pub(crate) fn record_submit_outcome(
    state_store: &mut LocalStateStore,
    space_id: &str,
    kind: &str,
    anchor_ref: Option<String>,
    response: &SubmitMoveResponse,
) -> String {
    let state =
        MoveSubmissionState::from_submit_state(response.state.as_str(), response.reason.as_deref());
    state_store.record_move_submission(
        response.move_id.clone(),
        space_id.to_owned(),
        kind.to_owned(),
        state,
        response.reason.clone(),
        anchor_ref,
    );
    format_submit_response(response)
}

/// Pure helper: build + sign a `cx.member.state` FSM transition Move.
/// Used by Kick / Ban / Unban Move-flow buttons in the member table.
pub(crate) fn build_signed_member_state_transition(
    identity: &LocalIdentity,
    space_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove = build_member_state_transition_move(
        did, space_id, actor_id, from_state, to_state, anchor_ref, hlc,
    )?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

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

    fn summary(self) -> &'static str {
        match self {
            Self::Overview => "sectioned admin map",
            Self::Members => "membership, invites, leave",
            Self::Access => "metadata, join, history, discovery",
            Self::Security => "MLS, capability grants, anchor visibility",
            Self::Governance => "org policy and moderation surfaces",
            Self::Federation => "trust bundles and partner boundaries",
            Self::Repair => "conflicts, stalled moves, destructive actions",
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

#[component]
pub fn SpaceAdminPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    active_section: Option<String>,
) -> Element {
    let mut space_name = use_signal(|| String::new());
    let mut space_topic = use_signal(|| String::new());
    let mut space_description = use_signal(|| String::new());
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());
    let members = use_signal(Vec::<String>::new);
    let mut space_invites = use_signal(Vec::<InviteRecord>::new);
    let mut discovery_enabled = use_signal(|| true);
    // Capability grant/revoke Move-flow inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(|| "cap.demo-01".to_owned());
    let mut cap_tag = use_signal(|| "discussion.message.create".to_owned());
    let mut cap_revoke_reason = use_signal(|| "rotation policy".to_owned());
    // Round 22: structured constraint inputs for the capability grant.
    // `cap_constraint_kind` chooses the family (`temporal` / `quota` /
    // `scope_limitation` / `none`); the temporal MVP exposes
    // `not_before` / `not_after` RFC 3339 timestamps. Quota /
    // scope_limitation are surfaced in the dropdown but show a
    // "coming soon" hint until matching widgets land.
    let mut cap_constraint_kind = use_signal(|| "none".to_owned());
    let mut cap_temporal_not_before = use_signal(String::new);
    let mut cap_temporal_not_after = use_signal(String::new);
    // Round 22: covered_frontier alert threshold. Default 5 (mirrors
    // sodmin's `DEFAULT_LAG_WARN_THRESHOLD`); user can override via the
    // numeric input next to the banner.
    let mut covered_frontier_threshold = use_signal(|| DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD);
    // Read-only anchorer cell value fetched from /api/admin/v1/spaces/{id}/anchorer.
    // The endpoint may 404 in dev — surface that inline rather than blocking the page.
    let mut anchorer_cell_status = use_signal(String::new);
    let mut anchorer_cell_value = use_signal(String::new);
    // Round 23 (M4): selected Move for the failure detail inline panel.
    // Clicking a row that's in a failed state stores its move_id here;
    // the detail block below renders the reason / anchor_ref.
    let mut move_detail_open = use_signal(|| Option::<String>::None);
    // Round 23 (M8): conflict-repair dialog state. Surfaces when the
    // local projection has bottom=expose cells; the operator picks
    // two of the conflicting heads + a recovery capability ref and
    // submits a head_in repair Move.
    let mut repair_target_cell = use_signal(String::new);
    let mut repair_head_a = use_signal(String::new);
    let mut repair_head_b = use_signal(String::new);
    let mut repair_capability_ref = use_signal(|| "cap.recovery-01".to_owned());
    let mut repair_winner_json = use_signal(String::new);

    // Read the local anchor view for this space once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let anchor_view = state_store.read().anchor_view_for(&selected_space);
    let bottom_cells: Vec<(String, String)> = anchor_view
        .bottom_cells
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
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
    // Round 21: MLS epoch + governance covered_frontier for the read-only
    // widget. `mls_epoch` is the cas-register value of
    // cx.component.mls.epoch.v1; `covered_frontier` is the
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
    // Round 22: covered_frontier_lag value + threshold check for the
    // alert banner. We render only when a lag value has actually been
    // surfaced AND it exceeds the (user-configurable) warning threshold
    // — matches the sodmin admin page UX.
    let covered_frontier_lag_value = anchor_view.covered_frontier_lag;
    let covered_frontier_lag_threshold = covered_frontier_threshold();
    let covered_frontier_alert =
        anchor_view.covered_frontier_lag_above(covered_frontier_lag_threshold);
    let covered_frontier_lag_label = covered_frontier_lag_value
        .map(|lag| lag.to_string())
        .unwrap_or_else(|| "-".to_owned());
    // Round 23 (M4): per-Space Move submission tracker. Drives the
    // state-pill list + the Space-wide anchorer_paused banner.
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
    let alert_count = usize::from(space_paused)
        + usize::from(space_pending_mls_binding)
        + usize::from(!bottom_cells.is_empty())
        + usize::from(covered_frontier_alert);

    rsx! {
        div { class: "timeline", "data-testid": "space-admin-panel",
            div { class: "event", "data-testid": "space-admin-sections",
                div { class: "event-head",
                    span { "Space Admin" }
                    span { "{active_section.label()} · {active_section.summary()}" }
                }
                div { class: "muted",
                    "This admin surface is now split by responsibility. Daily membership work, Space policy, security state, governance, federation trust, and destructive repair flows no longer share one undifferentiated scroll page."
                }
                div { class: "actions",
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
            }
            if active_section == SpaceAdminSection::Overview {
                div { class: "event", "data-testid": "space-admin-overview",
                    div { class: "event-head",
                        span { "Admin Map" }
                        span { "{selected_space}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Members" }
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
                            strong { "Access" }
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
                            strong { "Security & MLS" }
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
                            strong { "Governance" }
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
            // Round 23 (M4): Space-wide anchorer-paused banner. Fires
            // whenever any tracked Move for this Space has surfaced
            // `AnchorerPaused`. The Space cannot advance until ops
            // rotate the recovery anchorer.
            if space_paused {
                div {
                    class: "event error-banner",
                    "data-testid": "anchorer-paused-banner",
                    div { class: "event-head",
                        span { "Space 暂停推进，等待 recovery anchorer" }
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
                        span { "covered_frontier 暂未覆盖所需 governance frontier" }
                        span { class: "badge amber", "pending_mls_binding" }
                    }
                    div { class: "muted",
                        "The MLS commit Move that should bind your last encrypted message has not yet been acknowledged by the governance frontier. Outgoing messages stay encrypted but won't deliver until the binding lands."
                    }
                }
            }
            // Round 23 (M4): Move submission tracker — pill list of
            // recent local writes with state badges. Clicking a failed
            // row reveals the reason inline.
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
                                "move {record.move_id}"
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
                                            div { "bound anchor: {anchor}" }
                                        }
                                        div { "submitted_at: {record.submitted_at}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Bottom=expose conflict banner — only rendered when at least
            // one cell in the projection has unresolved concurrent
            // candidates. P0 M5.
            if active_section == SpaceAdminSection::Repair && !bottom_cells.is_empty() {
                div { class: "event", "data-testid": "bottom-cells-banner",
                    div { class: "event-head",
                        span { "Concurrent candidates unresolved" }
                        span { class: "badge red", "bottom=expose" }
                    }
                    div { class: "muted",
                        "One or more cells in this Space's projection are in the bottom-expose state — soland received concurrent Moves it cannot deterministically merge. An admin / moderator must resolve each conflict by submitting a head_in repair Move before downstream queries return a definitive value."
                    }
                    for (cell_ref, status) in &bottom_cells {
                        div { class: "muted", "data-testid": "bottom-cell-row",
                            "{cell_ref} · status={status}"
                        }
                    }
                }
                // Round 23 (M8): conflict-repair Move dialog — only
                // rendered when bottom_cells is non-empty (i.e. there
                // is something to repair). Admin / moderator only;
                // soland's authz reducer rejects unsigned-by-recovery
                // capability submissions.
                div { class: "event", "data-testid": "conflict-repair-dialog",
                    div { class: "event-head",
                        span { "Conflict repair (head_in Move)" }
                        span { class: "badge amber", "admin / moderator" }
                    }
                    div { class: "muted",
                        "Build a `head_in [conflict_head_A, conflict_head_B]` repair Move + recovery_capability ref to merge the two concurrent histories. Soland's authz reducer requires the repair Move be signed by a holder of the named recovery capability."
                    }
                    label { "Target cell (id of bottom=expose cell)" }
                    input {
                        "data-testid": "repair-target-cell-input",
                        value: "{repair_target_cell}",
                        placeholder: "cx:cell:cx.component.space.organization.v1:...",
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
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let cell = repair_target_cell().trim().to_owned();
                                    let head_a = repair_head_a().trim().to_owned();
                                    let head_b = repair_head_b().trim().to_owned();
                                    let cap = repair_capability_ref().trim().to_owned();
                                    let winner_str = repair_winner_json();
                                    if cell.is_empty() || head_a.is_empty() || head_b.is_empty()
                                        || cap.is_empty()
                                    {
                                        status_msg.set(
                                            "fill cell + both heads + recovery capability before submitting repair"
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
                                    let hlc = Hlc::now("yougen").to_string();
                                    let anchor_ref =
                                        state_store.read().anchor_ref_for_move(&space);
                                    let identity = match state_store
                                        .write()
                                        .ensure_local_identity()
                                    {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let heads = vec![head_a, head_b];
                                    let signed = match build_signed_conflict_repair(
                                        &identity,
                                        &space,
                                        &cell,
                                        &heads,
                                        &cap,
                                        winner_value,
                                        &anchor_ref,
                                        &hlc,
                                    ) {
                                        Ok(m) => m,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "build repair Move failed: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let space_for_record = space.clone();
                                    let anchor_for_record = anchor_ref.clone();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.submit_move(&signed).await {
                                                Ok(resp) => {
                                                    let line = record_submit_outcome(
                                                        &mut state_store.write(),
                                                        &space_for_record,
                                                        "conflict.repair",
                                                        Some(anchor_for_record),
                                                        &resp,
                                                    );
                                                    status_msg.set(format!(
                                                        "repair Move: {line}"
                                                    ));
                                                }
                                                Err(err) => status_msg.set(format!(
                                                    "repair submit failed: {err}"
                                                )),
                                            }
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
                // Round 22: covered_frontier_lag alert banner. Mirrors
                // sodmin's admin page banner but stays client-side — it
                // reads the lag from the LocalAnchorView populated on
                // /sync, compares to a user-configurable threshold (default
                // 5, see DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD), and only
                // renders when soland has surfaced a lag AND it exceeds
                // threshold. Operators see the same urgency cue here that
                // sodmin shows on the dedicated covered_frontier page.
                div { class: "event", "data-testid": "covered-frontier-threshold-row",
                    div { class: "event-head",
                        span { "covered_frontier alert threshold" }
                        span { "Round 22 (client-side)" }
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
                // Round 21: MLS epoch + governance frontier read-only widget.
                // Reads from the same LocalAnchorView the bottom-cells banner
                // uses, so it costs no extra fetch — just surfaces two
                // well-known cells (mls.epoch.v1, governance.covered_frontier.v1)
                // for admin visibility into E2EE rotation status and governance
                // gating without leaving the page.
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
                                        let api = match authed_api(&base, api_token) {
                                            Ok(api) => api,
                                            Err(error) => {
                                                anchorer_cell_status
                                                    .set(format!("API client unavailable: {error}"));
                                                return;
                                            }
                                        };
                                        match api.admin_anchorer_describe(&space).await {
                                            Ok(value) => {
                                                anchorer_cell_status.set("ok".to_owned());
                                                anchorer_cell_value.set(value.to_string());
                                            }
                                            Err(error) => {
                                                // 404 / not-implemented falls through here.
                                                // Keep the message clear so the operator
                                                // knows it's a missing endpoint, not bad
                                                // data.
                                                anchorer_cell_status.set(format!(
                                                    "anchorer endpoint unavailable ({error}); \
                                                     expected /api/admin/v1/spaces/{{id}}/anchorer \
                                                     (separate agent shipping)"
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
            // Space metadata editor
            div { class: "event", "data-testid": "space-metadata",
                div { class: "event-head", span { "Space Metadata" } span { "{selected_space}" } }
                div { class: "workflow-form",
                    label { "Name" }
                    input {
                        "data-testid": "space-name-input",
                        value: "{space_name}",
                        placeholder: "Space name",
                        oninput: move |evt| space_name.set(evt.value()),
                    }
                    label { "Topic" }
                    input {
                        "data-testid": "space-topic-input",
                        value: "{space_topic}",
                        placeholder: "Space topic",
                        oninput: move |evt| space_topic.set(evt.value()),
                    }
                    label { "Description" }
                    textarea {
                        "data-testid": "space-description-input",
                        value: "{space_description}",
                        placeholder: "Space description",
                        oninput: move |evt| space_description.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "update-metadata-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let name = space_name();
                                    let topic = space_topic();
                                    let desc = space_description();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.update_space(&space, json!({
                                                "name": name,
                                                "topic": topic,
                                                "description": desc,
                                            })).await {
                                                Ok(_) => status_msg.set("Metadata updated".to_owned()),
                                                Err(e) => status_msg.set(format!("update failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Save Metadata"
                        }
                        // Alternate Move-flow path: build a cx.space.update
                        // Move targeting cx.component.space.organization.v1
                        // (cas-register) and POST /api/v1/moves. Soland's
                        // LatticeRegistry routes this into the cell; the
                        // direct-event button above stays available until
                        // every deployment is on the new pipeline.
                        button {
                            class: "secondary",
                            "data-testid": "update-metadata-via-move-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let name = space_name();
                                    let topic = space_topic();
                                    let desc = space_description();
                                    let value = json!({
                                        "title": name,
                                        "topic": topic,
                                        "description": desc,
                                    });
                                    let hlc = Hlc::now("yougen").to_string();
                                    let anchor_ref =
                                        state_store.read().anchor_ref_for_move(&space);
                                    let identity = match state_store.write().ensure_local_identity() {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!("identity unavailable: {err}"));
                                            return;
                                        }
                                    };
                                    let signed = match build_signed_space_organization_update(
                                        &identity,
                                        &space,
                                        value,
                                        &anchor_ref,
                                        &hlc,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            status_msg.set(format!("build move failed: {e}"));
                                            return;
                                        }
                                    };
                                    let space_for_record = space.clone();
                                    let anchor_for_record = anchor_ref.clone();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.submit_move(&signed).await {
                                                Ok(resp) => {
                                                    let line = record_submit_outcome(
                                                        &mut state_store.write(),
                                                        &space_for_record,
                                                        "cx.space.update",
                                                        Some(anchor_for_record),
                                                        &resp,
                                                    );
                                                    status_msg.set(line);
                                                }
                                                Err(e) => status_msg.set(format!(
                                                    "submit_move failed: {e}"
                                                )),
                                            }
                                        }
                                    });
                                }
                            },
                            "Save Metadata (Move)"
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
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let rule = join_rule();
                                let vis = history_visibility();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.set_space_policy(&space, &rule, &vis).await {
                                            Ok(resp) => status_msg.set(format!("policy: join={}, history={}", resp.join_rule, resp.history_visibility)),
                                            Err(e) => status_msg.set(format!("policy failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Apply Policy"
                    }
                }
            }

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
                                    let wait_for = active_sync_token(&sync_cursor());
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => match api.invite_to_space(&space, &target, None).await {
                                                Ok(resp) => {
                                                    let op = cx_ops::invite_create_structured(
                                                        &space,
                                                        &actor,
                                                        &resp.invite_id,
                                                        &resp.target,
                                                        None,
                                                        &resp.state,
                                                    )
                                                    .build("yougen");
                                                    match api
                                                        .submit_operation_event(&op)
                                                        .await
                                                    {
                                                        Ok(submitted) => {
                                                            space_invites.write().push(InviteRecord {
                                                                invite_id: resp.invite_id.clone(),
                                                                target: resp.target.clone(),
                                                                role: None,
                                                                state: resp.state.clone(),
                                                                operation_id: Some(op.operation_id.clone()),
                                                                event_id: Some(submitted.event_id.clone()),
                                                            });
                                                            frontier_state.set(submitted.event_id.clone());
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.save_sync_cursor(submitted.sync_token.clone());
                                                                store.append_raw_operation(
                                                                    op.operation_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "kind": "cx.invite.create",
                                                                        "invite_id": resp.invite_id,
                                                                        "target": resp.target,
                                                                        "state": resp.state,
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            invite_target.set(String::new());
                                                            status_msg.set(format!(
                                                                "invited {} ({}) fact {}",
                                                                target, "pending", op.operation_id
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("invite fact failed: {error}")),
                                                    }
                                                }
                                                Err(e) => status_msg.set(format!("invite failed: {e}")),
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
                    "成员状态由 cx.member.state event 驱动。`knock` Space 允许未邀请的 actor 敲门，admin 同意后 transition 为 invited 再 join。"
                }
                div { class: "actions",
                    span { class: "badge blue", "Invited" }
                    span { class: "badge green", "Joined" }
                    span { class: "badge", "Left" }
                    span { class: "badge red", "Banned" }
                    span { class: "badge amber", "Knocked" }
                }
                div { class: "muted",
                    "合法转移：none → {{join, invite, knock}} | invite → {{join, leave}} | knock → {{invite, leave}} | join → {{leave, ban}} | leave → {{invite, knock}} | ban → leave (via unban)。"
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
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.resolve_space(&space).await {
                                            Ok(_) => status_msg.set("Space resolved".to_owned()),
                                            Err(e) => status_msg.set(format!("resolve failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
                for member in members() {
                    div { class: "event", "data-testid": "member-row",
                        div { class: "event-head",
                            span { "{member}" }
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
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.remove_space_member(&space, &m).await {
                                                    Ok(_) => status_msg.set(format!("kicked {m}")),
                                                    Err(e) => status_msg.set(format!("kick failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Kick"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "ban-member-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.ban_member(&space, &m).await {
                                                    Ok(_) => status_msg.set(format!("banned {m}")),
                                                    Err(e) => status_msg.set(format!("ban failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Ban"
                            }
                            // Move-flow alternates: build cx.member.state
                            // FSM transitions on cx.component.member.state.v1
                            // and POST /api/v1/moves. Kick = join→leave;
                            // Ban = join→ban. The direct-event buttons
                            // above remain wired until every deployment is
                            // on the new pipeline.
                            button {
                                class: "secondary",
                                "data-testid": "kick-member-via-move-button",
                                onclick: {
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let hlc = Hlc::now("yougen").to_string();
                                        let anchor_ref =
                                            state_store.read().anchor_ref_for_move(&space);
                                        let identity =
                                            match state_store.write().ensure_local_identity() {
                                                Ok(id) => id,
                                                Err(err) => {
                                                    status_msg.set(format!(
                                                        "identity unavailable: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                        let signed = match build_signed_member_state_transition(
                                            &identity,
                                            &space,
                                            &m,
                                            "join",
                                            "leave",
                                            &anchor_ref,
                                            &hlc,
                                        ) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                status_msg.set(format!("build move failed: {e}"));
                                                return;
                                            }
                                        };
                                        let actor_label = m.clone();
                                        let base = base.clone();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.submit_move(&signed).await {
                                                    Ok(resp) => status_msg.set(format!(
                                                        "kick(Move) {actor_label}: {}",
                                                        format_submit_response(&resp)
                                                    )),
                                                    Err(e) => status_msg.set(format!(
                                                        "kick(Move) failed: {e}"
                                                    )),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Kick (Move)"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "ban-member-via-move-button",
                                onclick: {
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let hlc = Hlc::now("yougen").to_string();
                                        let anchor_ref =
                                            state_store.read().anchor_ref_for_move(&space);
                                        let identity =
                                            match state_store.write().ensure_local_identity() {
                                                Ok(id) => id,
                                                Err(err) => {
                                                    status_msg.set(format!(
                                                        "identity unavailable: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                        let signed = match build_signed_member_state_transition(
                                            &identity,
                                            &space,
                                            &m,
                                            "join",
                                            "ban",
                                            &anchor_ref,
                                            &hlc,
                                        ) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                status_msg.set(format!("build move failed: {e}"));
                                                return;
                                            }
                                        };
                                        let actor_label = m.clone();
                                        let base = base.clone();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.submit_move(&signed).await {
                                                    Ok(resp) => status_msg.set(format!(
                                                        "ban(Move) {actor_label}: {}",
                                                        format_submit_response(&resp)
                                                    )),
                                                    Err(e) => status_msg.set(format!(
                                                        "ban(Move) failed: {e}"
                                                    )),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Ban (Move)"
                            }
                        }
                    }
                }
                if members().is_empty() {
                    div { class: "muted", "No members loaded." }
                }
            }

            // Space invites — sync/third-party-invites.md + invite event family
            // 6 canonical events drive the invite lifecycle:
            //   cx.invite.create        — 创建 invite（主动邀请已知 DID）
            //   cx.invite.third_party   — 邀请 3PID（邮箱 / 手机号），未知 DID 时使用
            //   cx.invite.claim         — 受邀人接收 invite proof（绑定到他们的 DID）
            //   cx.invite.accept        — 受邀人正式接受（写入 membership）
            //   cx.invite.cancel        — 邀请方撤销（receiver 未 claim 前）
            //   cx.invite.revoke        — 邀请方撤销（receiver 已 claim 但未 accept）
            div { class: "event", "data-testid": "invite-lifecycle-banner",
                div { class: "event-head",
                    span { "Invite lifecycle" }
                    span { "6 canonical events" }
                }
                div { class: "muted",
                    "Invite 不直接授予 capability — 接受后才进入有效集合。MUST 携带 expires_at；默认 7 天，高安全 Space 24 小时。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.invite.create" }
                    span { class: "badge blue", "cx.invite.third_party" }
                    span { class: "badge", "cx.invite.claim" }
                    span { class: "badge green", "cx.invite.accept" }
                    span { class: "badge amber", "cx.invite.cancel" }
                    span { class: "badge red", "cx.invite.revoke" }
                }
            }

            // Space invites
            div { class: "event", "data-testid": "space-invites",
                div { class: "event-head", span { "Invites" } span { "lifecycle" } }
                for invite in space_invites() {
                    div { class: "event", "data-testid": "invite-row",
                        div { class: "event-head",
                            span { "{invite.target}" }
                            span { "{invite.state}" }
                        }
                        div { class: "muted", "data-testid": "invite-id", "{invite.invite_id}" }
                        if let Some(role) = &invite.role {
                            div { class: "muted", "role {role}" }
                        }
                        if let Some(operation_id) = &invite.operation_id {
                            div { class: "muted", "fact {operation_id}" }
                        }
                        if let Some(event_id) = &invite.event_id {
                            div { class: "muted", "event {event_id}" }
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
                                        let wait_for = active_sync_token(&sync_cursor());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.accept_space_invite(&space, &invite_id).await {
                                                    Ok(resp) => {
                                                        let op = cx_ops::invite_accept(&space, &actor, &invite_id).build("yougen");
                                                        match api
                                                            .submit_operation_event(&op)
                                                            .await
                                                        {
                                                            Ok(submitted) => {
                                                                for row in space_invites.write().iter_mut() {
                                                                    if row.invite_id == invite_id {
                                                                        row.state = resp.state.clone();
                                                                        row.operation_id = Some(op.operation_id.clone());
                                                                        row.event_id = Some(submitted.event_id.clone());
                                                                    }
                                                                }
                                                                frontier_state.set(submitted.event_id.clone());
                                                                sync_cursor.set(submitted.sync_token.clone());
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.save_sync_cursor(submitted.sync_token.clone());
                                                                    store.append_raw_operation(
                                                                        op.operation_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "kind": "cx.invite.accept",
                                                                            "invite_id": invite_id,
                                                                            "state": resp.state,
                                                                            "event_id": submitted.event_id,
                                                                        }),
                                                                    );
                                                                }
                                                                status_msg.set(format!("accepted invite fact {}", op.operation_id));
                                                            }
                                                            Err(error) => status_msg.set(format!("accept fact failed: {error}")),
                                                        }
                                                    }
                                                    Err(error) => status_msg.set(format!("accept failed: {error}")),
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
                                        let wait_for = active_sync_token(&sync_cursor());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.reject_space_invite(&space, &invite_id).await {
                                                    Ok(resp) => {
                                                        let op = cx_ops::invite_cancel(
                                                            &space,
                                                            &actor,
                                                            &invite_id,
                                                            Some("declined"),
                                                        )
                                                        .build("yougen");
                                                        match api
                                                            .submit_operation_event(&op)
                                                            .await
                                                        {
                                                            Ok(submitted) => {
                                                                for row in space_invites.write().iter_mut() {
                                                                    if row.invite_id == invite_id {
                                                                        row.state = resp.state.clone();
                                                                        row.operation_id = Some(op.operation_id.clone());
                                                                        row.event_id = Some(submitted.event_id.clone());
                                                                    }
                                                                }
                                                                frontier_state.set(submitted.event_id.clone());
                                                                sync_cursor.set(submitted.sync_token.clone());
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.save_sync_cursor(submitted.sync_token.clone());
                                                                    store.append_raw_operation(
                                                                        op.operation_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "kind": "cx.invite.cancel",
                                                                            "invite_id": invite_id,
                                                                            "state": resp.state,
                                                                            "event_id": submitted.event_id,
                                                                        }),
                                                                    );
                                                                }
                                                                status_msg.set(format!("canceled invite fact {}", op.operation_id));
                                                            }
                                                            Err(error) => status_msg.set(format!("cancel fact failed: {error}")),
                                                        }
                                                    }
                                                    Err(error) => status_msg.set(format!("cancel failed: {error}")),
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
                    "v1 core 把 audited E2EE 拆成 attested / disclosed 两类 hardening profile。Space policy 通过 audit_disclosure 对象 + audit_assurance enum 声明；UI join warning 与对外材料按 audited-e2ee.md §3.1.1 / §3.5 normative 分类与禁用措辞执行。"
                }
                div { class: "metric-grid", "data-testid": "audited-e2ee-tiers",
                    div { class: "metric",
                        strong { "none" }
                        span { class: "badge", "default" }
                        div { class: "muted", "标准 MLS E2EE，无 audit profile" }
                    }
                    div { class: "metric",
                        strong { "disclosed_audit" }
                        span { class: "badge amber", "disclosed_audit.e2ee.v1" }
                        div { class: "muted", "审计 agent 流程性披露；强制留痕 cx.audit.accessed；无密码学 attestation" }
                    }
                    div { class: "metric",
                        strong { "attested_audit" }
                        span { class: "badge red", "attested_audit.e2ee.v1" }
                        div { class: "muted", "硬件 attestation 强制；RYW receipt schema 强制 cx.audit.ryw_receipt" }
                    }
                }
                div { class: "muted",
                    "禁用 marketing 措辞：不得宣称 \"end-to-end encrypted\" 不加修饰；必须使用 \"E2EE with disclosed/attested audit\"。详见 audited-e2ee.md §3.5。"
                }
                div { class: "actions",
                    span { class: "muted", "Audit-bound key share events:" }
                    span { class: "badge blue", "cx.space_key.share" }
                    span { class: "badge", "cx.space_key.share_audit" }
                    span { class: "badge red", "cx.space_key.withheld" }
                }
                div { class: "actions",
                    button { class: "secondary", "data-testid": "audited-e2ee-set-none", "无 audit profile" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-disclosed", "启用 disclosed_audit" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-attested", "启用 attested_audit" }
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
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.rotate_mls_epoch(&space).await {
                                            Ok(resp) => status_msg.set(format!("rotated to epoch {}", resp.epoch)),
                                            Err(e) => status_msg.set(format!("rotate failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Rotate Epoch"
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
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.leave_space(&space).await {
                                            Ok(_) => status_msg.set(format!("left {space}")),
                                            Err(e) => status_msg.set(format!("leave failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Leave"
                    }
                }
            }
            }

            // Capability grant explanation — claude-design desktop/space-admin.html
            // authz/capabilities.md (delegation, revocation, claim conditions)
            //
            // Constraint type model (Round 9, 2026-05-05): 14 types collapsed into
            // 8 family + subtype discriminator per `authz/constraint-schema.md` §2.2:
            //   temporal (subtype: edit_window / redact_window / session_lifetime / ...)
            //   field_access (subtype: field_write_allow / field_write_deny)
            //   type_restriction (subtype: object_type / morph_type / facet)
            //   scope_limitation (subtype: container_move / view_kind / branch / ...)
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
                    "Grant 是 reducer 接受/拒绝写入的依据。每次决策都可追溯到签名 grant；高风险动作叠加 approval_constraint。Handle / 邮箱仅作展示，权限主体以 DID 为准。"
                }
                div { class: "metric-grid", "data-testid": "grant-explanation-rows",
                    div { class: "metric",
                        strong { "Mei (admin)" }
                        span { "read · write · moderate · grant" }
                        div { class: "muted", "did:plc:8djrfj4… · 永久 · auto-renew" }
                    }
                    div { class: "metric",
                        strong { "Build-bot (applet)" }
                        span { "write_message · reaction" }
                        div { class: "muted", "did:web:bot.acme.example · 30d · approval=auto" }
                    }
                    div { class: "metric",
                        strong { "Researcher Agent" }
                        span { "read_flow (申请中)" }
                        div { class: "muted", "approval_constraint = 2 of 3 admin · 1/3 已批准" }
                    }
                    div { class: "metric",
                        strong { "Compliance Auditor (partner)" }
                        span { "read_flow + write_morph(audit_report)" }
                        div { class: "muted", "did:web:partner.example · weekly job · revocable" }
                    }
                }
                div { class: "actions", "data-testid": "grant-decision-actions",
                    button { class: "primary", "data-testid": "grant-approve-button", "批准 Researcher Agent" }
                    button { class: "secondary", "data-testid": "grant-deny-button", "拒绝并签名 cx.capability.revoke" }
                    button { class: "secondary", "data-testid": "grant-explain-button", "查看完整 grant trail (audit)" }
                }
                div { class: "muted",
                    "Reducer 决策入口：cx.capability.grant / cx.capability.revoke / approval_constraint resolved。详细 trail 在 /audit。"
                }
            }

            // Capability grant / revoke Move-flow card (P0 M-capability /
            // 第二十轮). Mirrors the consent grant/revoke PoC but targets
            // cx.component.capability.grant.v1 (OrSet add/remove). Signed
            // with the demo session key (TODO real-key-management) and
            // POST'd to /api/v1/moves. Anchor frontier is threaded from
            // the local sync view.
            div { class: "event", "data-testid": "capability-grant-card",
                div { class: "event-head",
                    span { "Capability grant / revoke (Move PoC)" }
                    span { "cx.component.capability.grant.v1 · OrSet" }
                }
                div { class: "muted",
                    "Build a cx.capability.grant or cx.capability.revoke Move on the capability OrSet cell, sign with the admin's session key, and POST /api/v1/moves. Anchor predecessor is taken from the local /sync Anchor view; falls back to sha256(empty) when sync hasn't surfaced one."
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
                // Round 22: capability constraint editor. Choose a
                // family from the dropdown (`temporal` / `quota` /
                // `scope_limitation` / `none`) and fill in the form
                // for that family. Today only `temporal` is fully
                // wired — the other options surface their hint copy
                // but no inputs (matching the move_builder constraint
                // surface, which only provides a `temporal` builder
                // helper).
                div { class: "event-head", "data-testid": "cap-constraint-editor",
                    span { "Constraint (Round 22)" }
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
                                let hlc = Hlc::now("yougen").to_string();
                                let anchor_ref =
                                    state_store.read().anchor_ref_for_move(&space);
                                let identity =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                // Round 22: pull the active constraint
                                // from the editor signals and thread it
                                // through the builder. Empty input
                                // yields no constraint.
                                let kind = cap_constraint_kind();
                                let constraints: Vec<CapabilityConstraintInput> =
                                    if kind == "temporal" {
                                        let nb = cap_temporal_not_before();
                                        let na = cap_temporal_not_after();
                                        let constraint =
                                            CapabilityConstraintInput::temporal(
                                                if nb.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(nb)
                                                },
                                                if na.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(na)
                                                },
                                            );
                                        if constraint.is_effective() {
                                            vec![constraint]
                                        } else {
                                            Vec::new()
                                        }
                                    } else {
                                        Vec::new()
                                    };
                                let signed =
                                    match build_signed_capability_grant_with_constraints(
                                        &identity,
                                        &space,
                                        &grant_val,
                                        &tag_val,
                                        &constraints,
                                        &anchor_ref,
                                        &hlc,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            status_msg.set(format!(
                                                "build capability grant failed: {e}"
                                            ));
                                            return;
                                        }
                                    };
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.submit_move(&signed).await {
                                            Ok(resp) => status_msg.set(format!(
                                                "capability.grant: {}",
                                                format_submit_response(&resp)
                                            )),
                                            Err(e) => status_msg.set(format!(
                                                "capability.grant submit failed: {e}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Grant capability (Move)"
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
                                let hlc = Hlc::now("yougen").to_string();
                                let anchor_ref =
                                    state_store.read().anchor_ref_for_move(&space);
                                let identity =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let signed = match build_signed_capability_revoke(
                                    &identity,
                                    &space,
                                    &grant_val,
                                    &tag_val,
                                    reason_opt.as_deref(),
                                    &anchor_ref,
                                    &hlc,
                                ) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        status_msg.set(format!(
                                            "build capability revoke failed: {e}"
                                        ));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.submit_move(&signed).await {
                                            Ok(resp) => status_msg.set(format!(
                                                "capability.revoke: {}",
                                                format_submit_response(&resp)
                                            )),
                                            Err(e) => status_msg.set(format!(
                                                "capability.revoke submit failed: {e}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Revoke capability (Move)"
                    }
                }
            }
            }

            if active_section == SpaceAdminSection::Governance {
            // Organization governance — identity/identity-did.md §6 + content-moderation
            // Organization 作为 Principal（不是 Space）。一个 Space 可以由多个 organization
            // 共同治理，Space 的 organization 关系通过 cx.space.organization event 维护。
            div { class: "event", "data-testid": "organization-governance",
                div { class: "event-head",
                    span { "Organization governance" }
                    span { "Space ≠ Organization" }
                }
                div { class: "muted",
                    "Organization 是 Principal（DID），不是 Space。多组织共治通过 cx.space.organization 关系表达；组织目录与审核策略独立维护，不绑定到任何单一 Space。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Owning organizations" }
                        span { "cx.space.organization" }
                        div { class: "muted", "声明 Space 的归属组织（可多个）" }
                    }
                    div { class: "metric",
                        strong { "Org directory listing" }
                        span { "cx.organization.discovery" }
                        div { class: "muted", "组织级 discoverability policy（独立于 Space）" }
                    }
                    div { class: "metric",
                        strong { "Org moderation policy" }
                        span { "cx.organization.moderation_policy" }
                        div { class: "muted", "组织级审核策略；Space 可继承 / 覆写" }
                    }
                    div { class: "metric",
                        strong { "Sovereign DID policy" }
                        span { "cx.sovereign.did_policy" }
                        div { class: "muted", "高安全部署：限制可接受的 DID method / resolver trust" }
                    }
                }
            }

            // Policy events — authz/policy-server.md
            // cx.policy.{rule,action,set} 三个 event 是 reducer 决策输入：
            //   cx.policy.rule    — 单条规则（match condition + effect + scope）
            //   cx.policy.action  — 单条 action 模板（被 rule 引用）
            //   cx.policy.set     — 把 rule + action 打包发布为 policy version
            div { class: "event", "data-testid": "policy-event-family",
                div { class: "event-head",
                    span { "Policy authoring" }
                    span { "cx.policy.{{rule,action,set}}" }
                }
                div { class: "muted",
                    "Policy 是 reducer / 服务节点判断请求是否可接受的输入。Policy 通过 rule + action 组合发布为 set；同一 policy_version 一次写入。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.policy.rule" }
                    span { class: "badge", "cx.policy.action" }
                    span { class: "badge green", "cx.policy.set" }
                    span { class: "muted", "—— 三 event 联合发布为 policy version" }
                    span { class: "muted", "policy_version_ref 由 cx.space.policy.set 选取" }
                }
            }

            // Moderation events — governance/content-moderation.md
            // Two canonical events drive content-level moderation:
            //   cx.moderation.report — actor 提交举报（针对 message / flow / morph / actor）
            //   cx.moderation.frank  — E2EE franking proof（让加密内容也可被审核）
            // Quarantine / require_review 等是 reducer 决策结果，不是独立 event。
            div { class: "event", "data-testid": "moderation-events",
                div { class: "event-head",
                    span { "Moderation events" }
                    span { "governance/content-moderation.md" }
                }
                div { class: "muted",
                    "举报和审核证据由两 event 驱动；reducer 输出 (deny / quarantine / require_review) 通过 cx.policy.action 落地。E2EE 内容通过 franking 让审核者可验证发送方又不破坏密文。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.moderation.report" }
                    span { class: "badge accent", "cx.moderation.frank" }
                    span { class: "muted", "→ reducer 输出 cx.policy.action（deny/quarantine/require_review）" }
                }
            }
            }

            if active_section == SpaceAdminSection::Federation {
            // Trust bundle import — claude-design desktop/space-admin.html
            // sync/federation.md + sync/sovereign-deployment.md
            div { class: "event", "data-testid": "trust-bundle-panel",
                div { class: "event-head",
                    span { "Trust Bundle (Federation)" }
                    span { "受信 organization / service DID" }
                }
                div { class: "muted",
                    "联邦 / 跨组织 / Controlled Collaboration Space 必须用显式 trust_bundle 列出可参与的 organization DID + service DID + trusted issuer。导入前请校验 method evidence、trust root 与 service delegation。"
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
                        div { class: "muted", "缺 attestation issuer; trust root 未确认" }
                    }
                    div { class: "metric",
                        strong { "did:web:github-mirror.acme.example" }
                        span { "portal scope only" }
                        div { class: "muted", "applet · plaintext_visible(portal)" }
                    }
                    div { class: "metric",
                        strong { "did:web:hsm.contrix.social" }
                        span { "service · backup HSM" }
                        div { class: "muted", "1 次/年配额; recovery only" }
                    }
                }
                div { class: "actions", "data-testid": "trust-bundle-actions",
                    button { class: "primary", "data-testid": "trust-bundle-import-button", "导入 trust_bundle" }
                    button { class: "secondary", "data-testid": "trust-bundle-validate-button", "校验签名 + method evidence" }
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
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.archive_space(&space).await {
                                            Ok(resp) => status_msg.set(format!("archived: {}", resp.archived)),
                                            Err(e) => status_msg.set(format!("archive failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Archive Space"
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
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.delete_space(&space).await {
                                            Ok(_) => status_msg.set(format!("deleted {space}")),
                                            Err(e) => status_msg.set(format!("delete failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Tombstone / Delete"
                    }
                }
            }

            // Round 25 (R4): chained MLS Remove + epoch-advance Move
            // tracker. Reads the local move_submissions store, filters
            // for `mls_commit` + `mls_epoch_advance` kinds in the
            // current Space, pairs them by submission timestamp, and
            // surfaces each pair as a chain entry. Operators monitor
            // here when a device-revocation chain has stalled (e.g.
            // anchorer paused before the epoch-advance landed).
            div { class: "event", "data-testid": "mls-revoke-chain-tracker",
                div { class: "event-head",
                    span { "MLS revoke Move chains" }
                    span { "round 25 R4" }
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
                            div { class: "event", "data-testid": "mls-revoke-chain-row",
                                div { class: "event-head",
                                    span { "{chain.group_id}" }
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
                                            div { class: "muted", "{id}" }
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
                                            div { class: "muted", "{id}" }
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

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "space-admin-status", "{status_msg}" }
            }
        }
    }
}

#[cfg(test)]
mod move_flow_tests {
    use super::*;
    use contrix_sdk::LatticeOpType;
    use ed25519_dalek::SigningKey;

    fn fixed_anchor_ref() -> &'static str {
        PLACEHOLDER_ANCHOR_REF
    }

    fn fixed_hlc() -> &'static str {
        "0189c4d2af00-00000000-aabbccdd"
    }

    /// Test-only stable identity. Mirrors the helper in
    /// `views::consent_demo::tests` so vector tests stay reproducible.
    fn fixed_identity() -> LocalIdentity {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let device_did =
            crate::move_builder::did_key_from_verifying_key(&signing_key.verifying_key());
        LocalIdentity {
            device_did,
            signing_key,
        }
    }

    /// "Save Metadata (Move)" wiring: produces a cx.space.update Move
    /// targeting the cx.component.space.organization.v1 cas-register cell
    /// with the form values folded into the cell's value object.
    #[test]
    fn build_signed_space_organization_update_targets_organization_cell() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let identity = fixed_identity();
        let signed = build_signed_space_organization_update(
            &identity,
            space,
            json!({"title": "Renamed", "topic": "new"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(signed.space_id.as_str(), space);
        assert_eq!(signed.effects.len(), 1);
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.space.organization.v1:"),
            "space organization update must target the organization cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set op carries value");
        assert_eq!(value.get("title").and_then(|v| v.as_str()), Some("Renamed"));
        assert_eq!(value.get("topic").and_then(|v| v.as_str()), Some("new"));
        // Detached JWS attached so soland's verifier can validate.
        assert!(!signed.sig.jws.is_empty());
        let parts: Vec<&str> = signed.sig.jws.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    /// "Kick (Move)" wiring: produces an FSM transition from join → leave
    /// on cx.component.member.state.v1 keyed by the actor id.
    #[test]
    fn build_signed_member_state_transition_kick_produces_join_leave_fsm() {
        let identity = fixed_identity();
        let signed = build_signed_member_state_transition(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "join",
            "leave",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.member.state.v1:"),
            "member state transition must target the member.state cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(
            effect.op.from.as_ref().and_then(|v| v.as_str()),
            Some("join")
        );
        assert_eq!(
            effect.op.to.as_ref().and_then(|v| v.as_str()),
            Some("leave")
        );
    }

    /// "Ban (Move)" wiring: produces an FSM transition from join → ban
    /// on the same cell family (different terminal state).
    #[test]
    fn build_signed_member_state_transition_ban_produces_join_ban_fsm() {
        let identity = fixed_identity();
        let signed = build_signed_member_state_transition(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "join",
            "ban",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(effect.op.to.as_ref().and_then(|v| v.as_str()), Some("ban"));
    }

    /// "Grant capability (Move)" wiring: produces a cx.capability.grant
    /// Move targeting cx.component.capability.grant.v1 with the form's
    /// tag added to the OrSet.
    #[test]
    fn build_signed_capability_grant_targets_capability_or_set_cell() {
        let identity = fixed_identity();
        let signed = build_signed_capability_grant(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:"),
            "capability grant must target the capability.grant.v1 cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
        // Detached JWS attached so soland's verifier can validate.
        assert!(!signed.sig.jws.is_empty());
    }

    /// "Revoke capability (Move)" wiring: produces a cx.capability.revoke
    /// Move on the SAME OrSet cell — soland's causal-remove semantics
    /// require it. Reason field flows through.
    #[test]
    fn build_signed_capability_revoke_attaches_reason_and_remove_op() {
        let identity = fixed_identity();
        let signed = build_signed_capability_revoke(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            Some("rotation policy"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:"),
            "capability revoke targets the same OrSet cell as the grant"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.reason.as_deref(), Some("rotation policy"));
    }

    /// Round 22: capability grant with a temporal constraint folds the
    /// `not_before` / `not_after` window into the OrSet add op's `value`
    /// field; revokes still hit the same cell family so soland's
    /// causal-remove semantics keep working.
    #[test]
    fn build_signed_capability_grant_with_temporal_constraint_attaches_window() {
        let identity = fixed_identity();
        let constraint = CapabilityConstraintInput::temporal(
            Some("2026-05-09T00:00:00Z".to_owned()),
            Some("2026-08-09T00:00:00Z".to_owned()),
        );
        let signed = build_signed_capability_grant_with_constraints(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            std::slice::from_ref(&constraint),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        let value = effect.op.value.as_ref().expect("value present");
        let constraints = value
            .get("constraints")
            .and_then(|v| v.as_array())
            .expect("constraints array");
        assert_eq!(constraints.len(), 1);
        assert_eq!(
            constraints[0].get("not_before").and_then(|v| v.as_str()),
            Some("2026-05-09T00:00:00Z")
        );
        assert_eq!(
            constraints[0].get("not_after").and_then(|v| v.as_str()),
            Some("2026-08-09T00:00:00Z")
        );
    }

    /// Round 22: when no constraints are passed, the wire shape (and
    /// content-addressed move id) match the direct no-constraint grant
    /// builder.
    #[test]
    fn build_signed_capability_grant_empty_constraints_matches_direct_id() {
        let identity = fixed_identity();
        let with_empty = build_signed_capability_grant_with_constraints(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            &[],
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let direct = build_signed_capability_grant(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(with_empty.id.as_str(), direct.id.as_str());
    }

    /// Different from-state values produce different content-addressed
    /// move ids — ensures soland can distinguish kick from ban even if
    /// every other input is identical (form, hlc, anchor_ref).
    #[test]
    fn member_state_kick_and_ban_have_distinct_content_addresses() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let actor = "did:web:alice.example";
        let identity = fixed_identity();
        let kick = build_signed_member_state_transition(
            &identity,
            space,
            actor,
            "join",
            "leave",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let ban = build_signed_member_state_transition(
            &identity,
            space,
            actor,
            "join",
            "ban",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_ne!(kick.id.as_str(), ban.id.as_str());
    }
}
