use super::*;

pub(super) const DEMO_BOARD_SPACE_ID: &str = "ck:space:0196419b-0000-7000-8000-00000000b0a0";

/// Maximum number of times a CAS-conflicted Move is automatically
/// rebased + re-submitted before the UI surfaces it as Quarantined and
/// requires manual review. Three is enough to absorb typical
/// two-actor races without spinning indefinitely if the cell is hot.
pub(super) const MAX_CONFLICT_REBASE_ATTEMPTS: u8 = 3;

pub(super) fn kanban_projection_refresh_key(
    realm_id: &str,
    view_id: &str,
    sync_cursor: &str,
) -> String {
    format!(
        "{}|{}|{}",
        realm_id.trim(),
        view_id.trim(),
        sync_cursor.trim()
    )
}

pub(super) fn next_kanban_projection_refresh_key(
    last_seen_key: &str,
    realm_id: &str,
    view_id: &str,
    sync_cursor: &str,
) -> Option<String> {
    let key = kanban_projection_refresh_key(realm_id, view_id, sync_cursor);
    if last_seen_key == key {
        return None;
    }
    let cursor = sync_cursor.trim();
    if cursor.is_empty()
        || cursor == "-"
        || (realm_id.trim().is_empty() && view_id.trim().is_empty())
    {
        return None;
    }
    Some(key)
}

pub(super) const LOCAL_PENDING_CARD_DESCRIPTION: &str =
    "New local card waiting for reducer receipt.";
pub(super) const DEMO_FLOW_LEGAL_REVIEW_ID: &str = "ck:flow:0196419b-0000-7000-8000-000000000101";
pub(super) const DEMO_FLOW_ONBOARDING_COPY_ID: &str =
    "ck:flow:0196419b-0000-7000-8000-000000000102";
pub(super) const DEMO_FLOW_SECURITY_SIGNOFF_ID: &str =
    "ck:flow:0196419b-0000-7000-8000-000000000103";
pub(super) const DEMO_FLOW_REVIEW_DISCUSSION_ID: &str =
    "ck:flow:0196419b-0000-7000-8000-000000000201";
pub(super) const DEMO_FLOW_SUPPORT_DISCUSSION_ID: &str =
    "ck:flow:0196419b-0000-7000-8000-000000000202";
pub(super) const DEMO_FLOW_SECURITY_REVIEW_ID: &str =
    "ck:flow:0196419b-0000-7000-8000-000000000203";
pub(super) const KANBAN_PRIVATE_FLOW_PATCH_PATHS: &[&str] = &[
    "body",
    "synthesis",
    "content",
    "attachments",
    "fields.body",
    "fields.synthesis",
    "tracks.synthesis.body",
    "tracks.discussion.body",
];
pub(super) const KANBAN_BODY_PRIVATE_FIELD_PATHS: &[&str] = &["body", "fields.body"];
pub(super) const KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS: &[&str] =
    &["synthesis", "fields.synthesis", "tracks.synthesis.body"];
pub(super) const KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE: &str =
    "application/vnd.cokret.flow.patch-value+json";

/// X10.2 — shown for an encrypted private field (body/synthesis) that this
/// device cannot read yet: no local plaintext sidecar AND the author can't
/// decrypt their own ciphertext (OpenMLS) / a fresh browser before MLS
/// unlock+restore. Distinguishes "encrypted, unlock to view" from genuinely
/// empty content so users don't read it as data loss.
pub(super) const MLS_LOCKED_FIELD_PLACEHOLDER: &str =
    "🔒 Encrypted — unlock MLS (enter your 24-word Recovery Key) to view";

/// Browser-`localStorage` keys for the card-detail panel display
/// preference. Dock mode + width are device-/browser-level UI state
/// (not tied to an account or Space), so they live in `localStorage`
/// on the web build and become no-ops on desktop where there is no
/// browser storage — the session-default applies there instead.
pub(super) const CARD_DETAIL_DOCKED_STORAGE_KEY: &str = "yougen.card-detail.docked";
pub(super) const CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY: &str = "yougen.card-detail.dock-width";
pub(super) const CARD_DETAIL_DOCK_WIDTH_DEFAULT: f64 = 720.0;
pub(super) const CARD_DETAIL_DOCK_WIDTH_MIN: f64 = 380.0;
pub(super) const CARD_DETAIL_DOCK_WIDTH_MAX: f64 = 1100.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kanban_projection_refresh_waits_for_cursor_advance() {
        let first_key = kanban_projection_refresh_key(" ck:realm:r1 ", "", " ck:cursor:1 ");

        assert_eq!(
            next_kanban_projection_refresh_key(&first_key, "ck:realm:r1", "", "ck:cursor:1"),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key(&first_key, "ck:realm:r1", "", "ck:cursor:2"),
            Some("ck:realm:r1||ck:cursor:2".to_owned())
        );
    }

    #[test]
    fn kanban_projection_refresh_ignores_empty_or_bootstrap_cursor() {
        assert_eq!(
            next_kanban_projection_refresh_key("", "ck:realm:r1", "", ""),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key("", "ck:realm:r1", "", "-"),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key("", "", "", "ck:cursor:1"),
            None
        );
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn local_storage_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()
        .flatten()?
        .get_item(key)
        .ok()
        .flatten()
}

#[cfg(target_arch = "wasm32")]
pub(super) fn local_storage_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn local_storage_get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn local_storage_set(_key: &str, _value: &str) {}

/// Hydrate the docked-vs-dialog choice from `localStorage`. Defaults to
/// the centered dialog when unset or on desktop.
pub(super) fn read_card_detail_docked() -> bool {
    local_storage_get(CARD_DETAIL_DOCKED_STORAGE_KEY)
        .map(|value| value == "true")
        .unwrap_or(false)
}

/// Hydrate the docked-panel width from `localStorage`, clamped to the
/// same bounds the drag handle enforces. Falls back to the default when
/// unset, unparseable, or on desktop.
pub(super) fn read_card_detail_dock_width() -> f64 {
    local_storage_get(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|width| width.is_finite())
        .map(|width| width.clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX))
        .unwrap_or(CARD_DETAIL_DOCK_WIDTH_DEFAULT)
}

pub(super) fn persist_card_detail_docked(docked: bool) {
    local_storage_set(
        CARD_DETAIL_DOCKED_STORAGE_KEY,
        if docked { "true" } else { "false" },
    );
}

pub(super) fn persist_card_detail_dock_width(width: f64) {
    local_storage_set(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY, &format!("{width:.0}"));
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct KanbanColumn {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) rank: String,
    pub(super) cards: Vec<KanbanCard>,
    /// Space-container lifecycle state. `Active` is the wire default; `Archived` is set
    /// optimistically after a successful `ck.space.archive` submit and reset
    /// after `ck.space.restore`. Spec: `models/realm-and-space.md §4.4`.
    /// `Tombstoned` is irreversible and modeled here for completeness but the
    /// UI currently has no tombstone affordance — server-only path.
    pub(super) state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SpaceContainerLifecycleState {
    #[default]
    Active,
    Archived,
    /// Server-only terminal state. UI never produces this; the variant
    /// exists so `dispatch_space_container_lifecycle` can exhaustively match.
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct KanbanCard {
    pub(super) id: String,
    /// The card's current rank inside its column. This is the local
    /// mirror of the `ck.component.flow.position.v1` cell's `rank`
    /// field and seeds the `expected_position` of any subsequent
    /// `ck.flow.move` / `ck.flow.reorder` Move. When the projection
    /// refreshes (server-side cell update), this must be re-synced.
    pub(super) rank: String,
    pub(super) title: String,
    /// Flow `summary` — short one-line/paragraph overview.
    pub(super) description: String,
    /// Flow `body` — rich long-form content shown in the Description tab.
    pub(super) body: String,
    /// Flow `synthesis` — rich content shown in the Synthesis tab. Stored
    /// on the Flow object alongside `body` so the kanban popup can edit
    /// it inline without round-tripping through the Document/Morph view.
    /// Canonical wire path: `object.synthesis` (with `object.tracks.synthesis.body`
    /// honored as a back-compat fallback in projection reads).
    pub(super) synthesis: String,
    /// X10.2 — `body`/`synthesis` are encrypted MLS envelopes this device
    /// cannot read yet (no local plaintext sidecar + can't decrypt: author's
    /// own ciphertext, or a fresh browser before MLS unlock). When true the
    /// display layer shows a locked placeholder; `body`/`synthesis` stay
    /// EMPTY so the editor never re-saves a placeholder over real ciphertext.
    pub(super) body_locked: bool,
    pub(super) synthesis_locked: bool,
    pub(super) created_by: String,
    pub(super) created_at: String,
    pub(super) updated_at: String,
    pub(super) labels: Vec<String>,
    pub(super) assignee: String,
    pub(super) assigned_to_relations: Vec<CardAssignedToRelation>,
    pub(super) due: String,
    pub(super) primary_flow_id: String,
    pub(super) locked_flow: Option<LockedFlow>,
    pub(super) external_visibility: String,
    pub(super) history_visibility: String,
    /// Explicit Flow security state from projection metadata. `None`
    /// means the Flow inherits the active Realm / Space posture.
    pub(super) security_encrypted: Option<bool>,
    pub(super) state: CardState,
    /// Flow lifecycle state (orthogonal to `state` above which is
    /// Move-lifecycle). Spec: `flow-and-message.md §3`,
    /// `common-fields.md §5.1`. Active cards render in the column;
    /// Archived cards move to the archived-cards drawer. Redacted is the
    /// irreversible terminal (content cleared, envelope/audit retained); UI
    /// never emits it but renders a "[消息已撤回]" placeholder for it.
    pub(super) lifecycle: FlowLifecycleState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CardAssignedToRelation {
    pub(super) relation_id: String,
    pub(super) actor_id: String,
}

pub(super) fn card_assigned_actor_ids(card: &KanbanCard) -> Vec<String> {
    let mut actor_ids = BTreeSet::new();
    for relation in &card.assigned_to_relations {
        let actor_id = relation.actor_id.trim();
        if !actor_id.is_empty() {
            actor_ids.insert(actor_id.to_owned());
        }
    }
    if actor_ids.is_empty() {
        for actor_id in card
            .assignee
            .split(',')
            .map(str::trim)
            .filter(|value| value.starts_with("did:"))
            .filter(|value| !value.is_empty())
        {
            actor_ids.insert(actor_id.to_owned());
        }
    }
    actor_ids.into_iter().collect()
}

pub(super) fn assignee_value_from_actor_ids(actor_ids: &BTreeSet<String>) -> String {
    if actor_ids.is_empty() {
        "—".to_owned()
    } else {
        actor_ids.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

pub(super) fn apply_card_assignment_projection(
    card: &mut KanbanCard,
    actor_ids: &BTreeSet<String>,
    relations: Vec<CardAssignedToRelation>,
    state: CardState,
) {
    card.assignee = assignee_value_from_actor_ids(actor_ids);
    card.assigned_to_relations = relations;
    card.state = state;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CardDetailDraft {
    pub(super) title: String,
    pub(super) description: String,
    /// Flow `body` — long-form content shown in the Description tab.
    pub(super) body: String,
    /// Flow `synthesis` — long-form content shown in the Synthesis tab.
    pub(super) synthesis: String,
    pub(super) labels: Vec<String>,
    pub(super) assignee: String,
    pub(super) due: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CardSynthesisRevision {
    pub(super) id: String,
    pub(super) body: String,
    pub(super) actor_id: String,
    pub(super) author_label: String,
    pub(super) timestamp_label: String,
    pub(super) sort_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CardSynthesisTrackEntry {
    pub(super) id: String,
    pub(super) body: String,
    pub(super) actor_id: String,
    pub(super) author_label: String,
    pub(super) timestamp_label: String,
    pub(super) sort_key: String,
    pub(super) edited: bool,
    pub(super) revisions: Vec<CardSynthesisRevision>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum FlowLifecycleState {
    #[default]
    Active,
    Archived,
    /// Irreversible terminal per the wire enum (`flow.schema.json` state =
    /// {`active`,`archived`,`redacted`}). `redacted` clears content but
    /// retains the envelope/audit trail, so the UI renders a
    /// "[消息已撤回]" placeholder rather than hiding the Flow. There is NO
    /// `deleted` terminal in the spec; `flow_lifecycle_from_wire` downgrades
    /// any stray `"deleted"` wire value (logging a warning) instead of
    /// treating it as terminal.
    Redacted,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct LockedFlow {
    pub(super) flow_id_hash: String,
    pub(super) reason: String,
}

/// Snapshot of the card-being-dragged's pre-move state. The cas-register
/// model in [`operations-sync.md` §9.1](../../cokret-spec/spec/v1/zh/sync/operations-sync.md)
/// requires the source `(list_space_id, rank)` to seed `head_eq` on the
/// resulting `ck.flow.move` / `ck.flow.reorder` Move. We capture it on
/// `ondragstart` so the drop handler doesn't have to re-derive it from
/// the column state (which may have been mutated optimistically in the
/// meantime).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct DraggedCard {
    pub(super) card_id: String,
    pub(super) from_column_id: String,
    pub(super) from_rank: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DraggedColumn {
    pub(super) column_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BoardSpaceOption {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum BoardToolbarPopover {
    #[default]
    None,
    SelectBoard,
    CreateBoard,
    Projection,
    Queue,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum CardDetailContentTab {
    #[default]
    Description,
    Synthesis,
    Discussion,
}

/// Which tab the right-hand card-detail sidebar is showing.
/// - `Details`: per-card metadata (Flow ID, Assignees, Due, Visibility) + Activity hints.
/// - `Members`: every actor in the surrounding Realm/Space — sourced from the cached space
///   projection (`members`/`participants`/`owners` keys). Each row is also marked when the actor
///   has authored an event against the current Flow (derived from local raw operations), so
///   participation is surfaced inline instead of in a separate tab.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum CardDetailSidebarTab {
    #[default]
    Details,
    Members,
}

/// Which slice of card fields the inline edit form is currently editing.
/// The Summary scope edits title + the short summary blurb; the
/// Description scope edits only the long-form body shown in the
/// Description tab. Each entry point seeds the matching scope so the
/// form only renders the relevant editor (avoids the "edit description"
/// CTA opening an unrelated Title + Summary editor as well).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum CardEditScope {
    #[default]
    Summary,
    Description,
    Synthesis,
}

pub(super) const TOAST_EDITOR_SCRIPT_URL: &str =
    "https://uicdn.toast.com/editor/latest/toastui-editor-all.min.js";
pub(super) const TOAST_EDITOR_CSS_URL: &str =
    "https://uicdn.toast.com/editor/latest/toastui-editor.min.css";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CardState {
    Synced,
    Optimistic,
    Queued,
    Submitted,
    Accepted,
    SoftFailed,
    Quarantined,
    Conflict,
}

impl CardState {
    pub(super) fn write_state(self) -> WriteState {
        match self {
            CardState::Synced => WriteState::Synced,
            CardState::Optimistic => WriteState::Optimistic,
            CardState::Queued => WriteState::Queued,
            CardState::Submitted => WriteState::Submitted,
            CardState::Accepted => WriteState::Accepted,
            CardState::SoftFailed => WriteState::SoftFailed,
            CardState::Quarantined => WriteState::Quarantined,
            CardState::Conflict => WriteState::CasConflict,
        }
    }

    pub(super) fn label(&self) -> &'static str {
        match self {
            CardState::Synced => "synced",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => "sending...",
            CardState::Accepted => "pending anchor",
            CardState::SoftFailed => "soft failed",
            CardState::Quarantined => "quarantined",
            CardState::Conflict => "CAS conflict",
        }
    }

    pub(super) fn class_name(&self) -> &'static str {
        match self {
            CardState::Synced => "badge green",
            CardState::Accepted => "badge amber",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => "badge blue",
            CardState::SoftFailed | CardState::Conflict => "badge red",
            CardState::Quarantined => "badge amber",
        }
    }

    pub(super) fn data_state(self) -> &'static str {
        match self {
            CardState::Synced => "synced",
            CardState::Optimistic => "optimistic",
            CardState::Queued => "queued",
            CardState::Submitted => "submitted",
            CardState::Accepted => "accepted",
            CardState::SoftFailed => "soft_failed",
            CardState::Quarantined => "quarantined",
            CardState::Conflict => "conflict",
        }
    }

    pub(super) fn status_title(self) -> &'static str {
        match self {
            CardState::Synced => "Server projection is current",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => {
                "Sending; waiting for server confirmation"
            }
            CardState::Accepted => "Server accepted the event; waiting for projection/anchor",
            CardState::SoftFailed => "Server did not accept this event",
            CardState::Quarantined => "Write failed; open the queue for details",
            CardState::Conflict => "Server reported a CAS conflict",
        }
    }
}

pub(super) fn card_state_from_write_state(write_state: &str) -> CardState {
    match WriteState::from_wire(write_state) {
        Some(WriteState::Synced) => CardState::Synced,
        Some(WriteState::Optimistic) => CardState::Optimistic,
        Some(WriteState::Queued) => CardState::Queued,
        Some(WriteState::Submitted) => CardState::Submitted,
        Some(WriteState::Accepted) => CardState::Accepted,
        Some(WriteState::SoftFailed) => CardState::SoftFailed,
        Some(WriteState::Quarantined) => CardState::Quarantined,
        Some(WriteState::CasConflict) => CardState::Conflict,
        None => CardState::Queued,
    }
}

/// Board write records track a Move pipeline submission. The Move's
/// canonical body lives in `cell_id` + `effect_summary` (string preview);
/// `move_id` is the content-addressed `sha256:...` id. `kind`
/// mirrors the MoveSubmissionState classifier (`ck.space.create` /
/// `ck.flow.create` /
/// `ck.flow.position`) so the tracker UI can decorate state pills.
///
/// `signed_move_json` is the typed [`cokret_sdk::Move`] serialised to
/// JSON. We persist it on the queued record so that Replay can re-POST
/// the exact same signed payload — server-side dedup is content-addressed
/// on `move_id`, making replay idempotent. None means the record cannot
/// be replayed idempotently.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct BoardWriteRecord {
    pub(super) state: CardState,
    pub(super) move_id: String,
    pub(super) kind: String,
    pub(super) cell_id: String,
    pub(super) effect_summary: String,
    pub(super) anchor_ref: String,
    pub(super) hlc: String,
    pub(super) note: String,
    pub(super) signed_move_json: Option<serde_json::Value>,
    /// Number of CAS-conflict rebase attempts so far. The submit path
    /// auto-retries up to [`MAX_CONFLICT_REBASE_ATTEMPTS`] before
    /// surfacing the record as Quarantined for manual review.
    pub(super) rebase_attempts: u8,
}

impl BoardWriteRecord {
    pub(super) fn needs_manual_conflict_review(&self) -> bool {
        match self.state {
            CardState::Conflict => true,
            CardState::Quarantined => {
                self.note.contains("cas_conflict")
                    || self.note.contains("manual conflict")
                    || self.note.contains("manual review")
            }
            _ => false,
        }
    }
}

/// T20 — Where the board projection data comes from.
///
/// The UI prefers API-derived board state from either the collection view
/// projection or the server's Space-container / Flow projection endpoints.
/// The local seed path is explicit demo-only so hard-coded cards are never
/// mistaken for persisted board data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoardProjectionSource {
    /// Sourced from the Principal Server's collection projection response.
    /// Conditions: the API exposes the view-projection endpoint AND the
    /// reducer has caught up to the current sync frontier.
    ApiDerived,
    /// Sourced from local `seed_columns()` demo data. Conditions: API
    /// unavailable, the view is not yet defined in the spec, or the client
    /// is offline.
    SeedFallback,
    /// No projection was available and demo seed fallback is disabled for
    /// this server profile.
    Unavailable,
}

pub(super) fn kanban_seed_fallback_allowed(_base_url: &str) -> bool {
    if truthy_env_value(option_env!("YOUGEN_ALLOW_KANBAN_SEED_FALLBACK"))
        || std::env::var("YOUGEN_ALLOW_KANBAN_SEED_FALLBACK")
            .ok()
            .as_deref()
            .is_some_and(|value| truthy_env_value(Some(value)))
    {
        return true;
    }
    false
}

#[cfg(test)]
pub(super) fn kanban_seed_fallback_allowed_for_url(_base_url: &str) -> bool {
    false
}

pub(super) fn truthy_env_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

/// T20 — Attempt to load the board projection from the API; return `None`
/// on failure or when the endpoint is unavailable.
///
/// The current `api.rs` does not expose a `collection_projection()` method,
/// so this probe always returns `None` and the caller falls back to
/// `seed_columns()`. Once the SDK exposes `client.collection_projection
/// (view_id)`, swap the probe's body to call the SDK; the surrounding UI
/// does not need to change.
///
/// The `_view_id` parameter is reserved so the future signature is stable:
/// the UI holds the saved View's `ck:view:` id and threads it in when calling
/// the probe.
pub(super) fn try_load_api_columns(_view_id: &str) -> Option<Vec<KanbanColumn>> {
    // Synchronous init context — always returns None. UI starts with
    // Unavailable unless explicit demo seed is enabled; async projection
    // hydrate promotes the board to ApiDerived once the server returns data.
    None
}

pub(super) fn initial_board_space_options(seed_fallback_allowed: bool) -> Vec<BoardSpaceOption> {
    if seed_fallback_allowed {
        vec![BoardSpaceOption {
            id: DEMO_BOARD_SPACE_ID.to_owned(),
            title: "Local demo board".to_owned(),
            state: SpaceContainerLifecycleState::Active,
        }]
    } else {
        Vec::new()
    }
}

pub(super) fn sort_board_space_options(options: &mut Vec<BoardSpaceOption>) {
    options.sort_by(|left, right| left.id.cmp(&right.id).then(left.title.cmp(&right.title)));
    options.dedup_by(|left, right| left.id == right.id);
    options.sort_by(|left, right| left.title.cmp(&right.title).then(left.id.cmp(&right.id)));
}

pub(super) fn generated_board_fallback_title(board_id: &str) -> String {
    format!("Board {}", short_protocol_id(board_id))
}

pub(super) fn should_replace_projected_container_title(
    existing_title: &str,
    container_id: &str,
) -> bool {
    let title = existing_title.trim();
    title.is_empty()
        || title == container_id
        || title == generated_board_fallback_title(container_id)
}

pub(super) fn board_space_options_from_projection(
    containers: &[crate::api::SpaceContainerProjectionView],
) -> Vec<BoardSpaceOption> {
    let mut options = containers
        .iter()
        .filter(|view| {
            view.kind == "board" || (view.kind.trim().is_empty() && view.parent_space_id.is_none())
        })
        .map(|view| BoardSpaceOption {
            id: view.space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.space_id.clone()
            } else {
                view.title.clone()
            },
            state: space_container_state_from_wire(&view.state),
        })
        .collect::<Vec<_>>();
    let mut seen = options
        .iter()
        .map(|option| option.id.clone())
        .collect::<BTreeSet<_>>();
    for parent_space_id in containers
        .iter()
        .filter(|view| view.kind == "list")
        .filter_map(|view| view.parent_space_id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        if !seen.insert(parent_space_id.to_owned()) {
            continue;
        }
        options.push(BoardSpaceOption {
            id: parent_space_id.to_owned(),
            title: generated_board_fallback_title(parent_space_id),
            state: SpaceContainerLifecycleState::Active,
        });
    }
    sort_board_space_options(&mut options);
    options
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocalSpaceCreate {
    pub(super) id: String,
    pub(super) realm_id: Option<String>,
    pub(super) kind: String,
    pub(super) title: String,
    pub(super) parent_space_id: Option<String>,
    pub(super) rank: Option<String>,
}

pub(super) fn local_projection_realm_id(
    selected_realm_id: &str,
    projection_realm_id: &str,
) -> String {
    let candidate = projection_realm_id.trim();
    if candidate.is_empty() {
        trim_realm_id(selected_realm_id)
    } else {
        trim_realm_id(candidate)
    }
}

pub(super) fn local_space_create_matches_realm(
    local_create: &LocalSpaceCreate,
    realm_id: &str,
) -> bool {
    let realm_id = realm_id.trim();
    realm_id.is_empty()
        || local_create
            .realm_id
            .as_deref()
            .is_none_or(|local_realm_id| trim_realm_id(local_realm_id) == trim_realm_id(realm_id))
}

pub(super) fn local_space_create_records(
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<LocalSpaceCreate> {
    raw_operations
        .iter()
        .filter_map(local_space_create_from_raw_operation)
        .filter(|local_create| local_space_create_matches_realm(local_create, realm_id))
        .collect()
}

pub(super) fn overlay_local_board_space_options(
    mut options: Vec<BoardSpaceOption>,
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<BoardSpaceOption> {
    for local_create in local_space_create_records(raw_operations, realm_id)
        .into_iter()
        .filter(|local_create| local_create.kind == "board")
    {
        if let Some(existing) = options
            .iter_mut()
            .find(|option| option.id == local_create.id)
        {
            if should_replace_projected_container_title(&existing.title, &existing.id) {
                existing.title = local_create.title;
            }
            if existing.state == SpaceContainerLifecycleState::Tombstoned {
                existing.state = SpaceContainerLifecycleState::Active;
            }
            continue;
        }
        options.push(BoardSpaceOption {
            id: local_create.id,
            title: local_create.title,
            state: SpaceContainerLifecycleState::Active,
        });
    }
    sort_board_space_options(&mut options);
    options
}

pub(super) fn containers_with_local_space_creates(
    containers: &[crate::api::SpaceContainerProjectionView],
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::api::SpaceContainerProjectionView> {
    let mut merged = containers.to_vec();
    for local_create in local_space_create_records(raw_operations, realm_id) {
        if let Some(existing) = merged
            .iter_mut()
            .find(|view| view.space_id == local_create.id)
        {
            if should_replace_projected_container_title(&existing.title, &existing.space_id) {
                existing.title = local_create.title;
            }
            continue;
        }
        merged.push(crate::api::SpaceContainerProjectionView {
            space_id: local_create.id,
            realm_id: local_create
                .realm_id
                .unwrap_or_else(|| trim_realm_id(realm_id)),
            kind: local_create.kind,
            title: local_create.title,
            state: "active".to_owned(),
            rank: local_create.rank,
            parent_space_id: local_create.parent_space_id,
        });
    }
    merged
}

/// T20 — Map a SDK [`CollectionProjectionResBody`] into the yougen
/// renderer's [`Vec<KanbanColumn>`] shape.
///
/// Pure adapter so it's unit-testable without a live HTTP client.
/// Position rank, when present, drives stable ordering inside a column.
pub(super) fn collection_projection_to_columns(
    projection: &cokret_sdk::CollectionProjectionResBody,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    projection
        .groups
        .iter()
        .map(|group| KanbanColumn {
            id: group.group_id.clone(),
            title: group.title.clone(),
            rank: group.rank.clone().unwrap_or_default(),
            cards: group
                .items
                .iter()
                .map(|item| card_from_projection_item(item, decrypt_ctx))
                .collect(),
            state: SpaceContainerLifecycleState::Active,
        })
        .collect()
}

/// Map a single projection item to a [`KanbanCard`]. Discussion metadata
/// is honoured: `visibility="locked"` produces a [`LockedFlow`] with an
/// opaque hash; `lazy_link=true` is surfaced via `history_visibility`
/// without leaking room contents.
pub(super) fn card_from_projection_item(
    item: &cokret_sdk::CollectionProjectionItem,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> KanbanCard {
    let id = item
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("ck:flow:unknown")
        .to_owned();
    let title = item
        .object
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("(untitled)")
        .to_owned();
    let primary_flow_id = id.clone();
    let (external_visibility, history_visibility) = item
        .discussion
        .as_ref()
        .map(|d| {
            let ext = match d.visibility.as_str() {
                "locked" => "Locked discussion (lazy_link)".to_owned(),
                "readable" => "Discussion readable to current member".to_owned(),
                other => format!("discussion: {other}"),
            };
            let hist = if d.lazy_link {
                "lazy_link (cross-Realm)".to_owned()
            } else if d.enabled {
                // Tracks do not carry independent access; a private
                // discussion uses a Circle-scoped Flow.
                "Circle-scoped discussion".to_owned()
            } else {
                "synthesis-only".to_owned()
            };
            (ext, hist)
        })
        .unwrap_or_else(|| {
            (
                "No external discussions linked".to_owned(),
                "synthesis-only".to_owned(),
            )
        });
    let locked_flow = item.discussion.as_ref().and_then(|d| {
        if d.visibility == "locked" {
            Some(LockedFlow {
                flow_id_hash: format!("sha256:{}", id),
                reason: "Locked discussion: title and members are not disclosed.".to_owned(),
            })
        } else {
            None
        }
    });
    // Per CollectionProjectionItem.position.rank: this is the
    // card's authoritative rank in the column from the API's view of
    // the cas-register cell. Falls back to "" so the seed-conversion
    // path still works when the projection omits position metadata
    // (e.g. group-level rank only).
    let rank = item
        .position
        .as_ref()
        .map(|p| p.rank.clone())
        .unwrap_or_default();
    let created_by = item
        .object
        .get("created_by")
        .or_else(|| item.object.get("actor_id"))
        .or_else(|| item.object.get("author"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let created_at = item
        .object
        .get("created_at")
        .or_else(|| item.object.get("timestamp"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let updated_at = item
        .object
        .get("updated_at")
        .or_else(|| item.object.get("edited_at"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    // X10.2: bind the private-field value exprs once so the text + locked
    // checks read the same source.
    let item_body_field =
        collection_item_private_field_value(&item.object, KANBAN_BODY_PRIVATE_FIELD_PATHS);
    let item_body_value = item_body_field.map(|(value, _)| value);
    let item_body_path = item_body_field.map(|(_, path)| path).unwrap_or("body");
    let item_synthesis_field =
        collection_item_private_field_value(&item.object, KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS);
    let item_synthesis_value = item_synthesis_field.map(|(value, _)| value);
    let item_synthesis_path = item_synthesis_field
        .map(|(_, path)| path)
        .unwrap_or("synthesis");
    KanbanCard {
        id,
        rank,
        title,
        description: item
            .object
            .get("summary")
            .or_else(|| item.object.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        body: private_flow_field_text(
            decrypt_ctx,
            &primary_flow_id,
            item_body_path,
            item_body_value,
        ),
        body_locked: private_flow_field_locked(
            decrypt_ctx,
            &primary_flow_id,
            item_body_path,
            item_body_value,
        ),
        synthesis: private_flow_field_text(
            decrypt_ctx,
            &primary_flow_id,
            item_synthesis_path,
            item_synthesis_value,
        ),
        synthesis_locked: private_flow_field_locked(
            decrypt_ctx,
            &primary_flow_id,
            item_synthesis_path,
            item_synthesis_value,
        ),
        created_by,
        created_at,
        updated_at,
        labels: item
            .object
            .get("fields")
            .and_then(|f| f.get("labels"))
            .and_then(|labels| labels.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        assignee: "—".to_owned(),
        assigned_to_relations: Vec::new(),
        due: item
            .object
            .get("fields")
            .and_then(|f| f.get("due_at").or_else(|| f.get("due")))
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .to_owned(),
        primary_flow_id,
        locked_flow,
        external_visibility,
        history_visibility,
        security_encrypted: crate::security_state::flow_projection_security_state(&item.object),
        state: CardState::Synced,
        lifecycle: FlowLifecycleState::Active,
    }
}

pub(super) fn columns_from_lifecycle_projection(
    containers: &[crate::api::SpaceContainerProjectionView],
    flows: &[crate::api::FlowProjectionView],
    preferred_board_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let board_options = board_space_options_from_projection(containers);
    let selected_board_id = if !preferred_board_id.trim().is_empty()
        && board_options
            .iter()
            .any(|option| option.id == preferred_board_id)
    {
        Some(preferred_board_id.to_owned())
    } else {
        board_options.first().map(|option| option.id.clone())
    };
    let Some(board_id) = selected_board_id else {
        return (Vec::new(), board_options, None);
    };

    let mut cols = containers
        .iter()
        .filter(|view| {
            view.kind == "list" && view.parent_space_id.as_deref() == Some(board_id.as_str())
        })
        .map(|view| KanbanColumn {
            id: view.space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.space_id.clone()
            } else {
                view.title.clone()
            },
            rank: view.rank.clone().unwrap_or_default(),
            cards: Vec::new(),
            state: space_container_state_from_wire(&view.state),
        })
        .collect::<Vec<_>>();
    cols.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });

    for flow in flows.iter().filter(|flow| {
        flow_projection_field_string(flow, flow.board_space_id.as_deref(), &["board_space_id"])
            .as_deref()
            == Some(board_id.as_str())
    }) {
        let Some(list_space_id) =
            flow_projection_field_string(flow, flow.list_space_id.as_deref(), &["list_space_id"])
        else {
            continue;
        };
        if let Some(column) = cols.iter_mut().find(|col| col.id == list_space_id) {
            column
                .cards
                .push(card_from_flow_projection(flow, decrypt_ctx));
        }
    }

    for column in &mut cols {
        sort_kanban_cards(&mut column.cards);
    }

    (cols, board_options, Some(board_id))
}

pub(super) fn columns_from_lifecycle_projection_with_local(
    containers: &[crate::api::SpaceContainerProjectionView],
    flows: &[crate::api::FlowProjectionView],
    preferred_board_id: &str,
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let merged_containers =
        containers_with_local_space_creates(containers, raw_operations, realm_id);
    columns_from_lifecycle_projection(&merged_containers, flows, preferred_board_id, decrypt_ctx)
}

pub(super) fn sort_kanban_cards(cards: &mut [KanbanCard]) {
    cards.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });
}

pub(super) fn reorder_column_before(
    columns: &mut Vec<KanbanColumn>,
    dragged_id: &str,
    target_id: &str,
) -> bool {
    if dragged_id == target_id {
        return false;
    }
    let Some(from_index) = columns.iter().position(|column| column.id == dragged_id) else {
        return false;
    };
    let Some(target_index) = columns.iter().position(|column| column.id == target_id) else {
        return false;
    };
    let dragged = columns.remove(from_index);
    let insert_index = if from_index < target_index {
        target_index.saturating_sub(1)
    } else {
        target_index
    };
    columns.insert(insert_index, dragged);
    for (index, column) in columns.iter_mut().enumerate() {
        column.rank = format!("r{:03}", index + 1);
    }
    true
}

pub(super) fn flow_projection_field_string(
    flow: &crate::api::FlowProjectionView,
    top_level: Option<&str>,
    field_names: &[&str],
) -> Option<String> {
    top_level
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            field_names.iter().find_map(|field_name| {
                flow.fields
                    .get(*field_name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            })
        })
}

pub(super) fn flow_projection_labels(flow: &crate::api::FlowProjectionView) -> Vec<String> {
    match flow.fields.get("labels") {
        Some(Value::Array(labels)) => labels
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::String(labels)) => parse_card_labels(labels),
        _ => Vec::new(),
    }
}

pub(super) fn flow_projection_assignee(flow: &crate::api::FlowProjectionView) -> Option<String> {
    if flow.assigned_actor_ids.is_empty() {
        return None;
    }
    Some(flow.assigned_actor_ids.join(", "))
}

pub(super) fn flow_projection_assigned_to_relations(
    flow: &crate::api::FlowProjectionView,
) -> Vec<CardAssignedToRelation> {
    flow.assigned_to_relations
        .iter()
        .filter_map(|relation| {
            let relation_id = relation.relation_id.trim();
            let actor_id = relation.actor_id.trim();
            (!relation_id.is_empty() && !actor_id.is_empty()).then(|| CardAssignedToRelation {
                relation_id: relation_id.to_owned(),
                actor_id: actor_id.to_owned(),
            })
        })
        .collect()
}

pub(super) fn flow_projection_security_state(
    flow: &crate::api::FlowProjectionView,
) -> Option<bool> {
    let mut value = Map::new();
    value.insert("fields".to_owned(), Value::Object(flow.fields.clone()));
    if let Some(body) = flow.body.as_ref() {
        value.insert("body".to_owned(), body.clone());
    }
    crate::security_state::flow_projection_security_state(&Value::Object(value))
}

pub(super) fn flow_body_display_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let mut lines = Vec::new();
    collect_content_text(value, &mut lines);
    lines
        .into_iter()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn collect_content_text(value: &Value, lines: &mut Vec<String>) {
    match value {
        Value::String(text) => lines.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_content_text(item, lines);
            }
        }
        Value::Object(object) => {
            for key in [
                "body",
                "text",
                "markdown",
                "plain_text",
                "content",
                "caption",
                "alt",
            ] {
                if let Some(child) = object.get(key) {
                    collect_content_text(child, lines);
                }
            }
            if let Some(blocks) = object.get("blocks") {
                collect_content_text(blocks, lines);
            }
        }
        _ => {}
    }
}

/// Borrowed decrypt context threaded into the pure card builders so an
/// encrypted realm's private patch values (`body` / `synthesis` /
/// `description`) can be decrypted on read. All fields are cheap borrows
/// captured from `KanbanPanel` (`state_store.read()`, `account_did`,
/// `device_id`, and the Realm id). `None` (the common, unencrypted
/// case, and every test) means "render plaintext values as-is".
#[derive(Clone, Copy)]
pub(super) struct MlsDecryptCtx<'a> {
    pub(super) state_store: &'a LocalStateStore,
    pub(super) realm_id: &'a str,
    pub(super) actor_id: &'a str,
    pub(super) device_id: &'a str,
}

/// Cheap key-only check for the raw MLS payload/envelope shape. Projection and
/// patch wrappers are handled by [`mls_envelope_value`].
pub(super) fn value_is_raw_mls_envelope(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("scheme").and_then(Value::as_str) == Some("mls-rfc9420") {
        return true;
    }
    object.contains_key("ciphertext") && object.contains_key("content_type")
}

/// Extract a canonical MLS envelope from the value shapes the reducer/projection
/// can hand back to the board UI:
///
/// - raw `EncryptedPayload` / `EncryptedEnvelopeV1`
/// - `{ "encrypted_content": <envelope> }`
/// - patch/set wrappers such as `{ "$op": "set", "value": <envelope> }`
///
/// This intentionally does not recurse through arbitrary object fields, so a
/// plaintext business object containing unrelated keys is not treated as E2EE.
pub(super) fn mls_envelope_value(value: &Value) -> Option<&Value> {
    if value_is_raw_mls_envelope(value) {
        return Some(value);
    }
    let object = value.as_object()?;
    for key in ["encrypted_content", "encrypted_payload", "value"] {
        if let Some(child) = object.get(key)
            && let Some(envelope) = mls_envelope_value(child)
        {
            return Some(envelope);
        }
    }
    None
}

/// Cheap key-only check: is `value` an MLS-encrypted envelope, possibly wrapped
/// by a projection or patch operation?
pub(super) fn value_is_mls_envelope(value: &Value) -> bool {
    mls_envelope_value(value).is_some()
}

/// Decrypt a single private flow patch value if (and only if) it is an MLS
/// envelope. Returns the decrypted plaintext patch value parsed as JSON
/// (e.g. a string `"…body text…"` or an object `{"body":"…"}`), or `None`
/// when `value` is not an envelope or the decrypt softly fails (no
/// snapshot / wrong device secret / payload that doesn't decrypt). On
/// `None` the caller keeps the original value (plaintext realms) or falls
/// back to a blank field (encrypted-but-locked).
pub(super) fn decrypt_private_flow_value(ctx: &MlsDecryptCtx<'_>, value: &Value) -> Option<Value> {
    let envelope = mls_envelope_value(value)?;
    let plaintext = crate::views::timeline::try_local_mls_decrypt_core(
        ctx.state_store,
        ctx.realm_id,
        ctx.actor_id,
        ctx.device_id,
        envelope,
    )?;
    serde_json::from_slice::<Value>(&plaintext).ok()
}

/// Render `value` as display text, transparently decrypting it first when
/// it is an MLS envelope and a decrypt context is available. When the
/// value is an envelope but decryption is not possible (no `ctx`, no
/// snapshot, wrong key), the field renders blank rather than leaking the
/// raw envelope JSON through `flow_body_display_text`.
pub(super) fn private_flow_display_text(
    ctx: Option<&MlsDecryptCtx<'_>>,
    value: Option<&Value>,
) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if value_is_mls_envelope(value) {
        return match ctx.and_then(|ctx| decrypt_private_flow_value(ctx, value)) {
            Some(plaintext) => flow_body_display_text(Some(&plaintext)),
            // Encrypted but un-decryptable: return BLANK (never the raw
            // envelope, never crash). The locked state is surfaced
            // separately via `private_flow_field_locked` so the placeholder
            // text never contaminates `card.body` / the editable draft
            // (which would let an edit overwrite the real ciphertext). See
            // X10.2.
            None => String::new(),
        };
    }
    flow_body_display_text(Some(value))
}

pub(super) fn private_plaintext_display_text(plaintext: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<Value>(plaintext) {
        return flow_body_display_text(Some(&parsed));
    }
    plaintext.to_owned()
}

/// X10.2 — true when a private field IS an MLS envelope that this device
/// cannot currently read: no local plaintext sidecar AND decryption is not
/// possible (author's own ciphertext / fresh browser before MLS unlock).
/// The display layer renders [`MLS_LOCKED_FIELD_PLACEHOLDER`] in this case so
/// the user can tell "encrypted, unlock to view" apart from "no content" —
/// WITHOUT putting the placeholder text into `card.body` (which the editor
/// copies and could re-save, corrupting the real encrypted content).
pub(super) fn private_flow_field_locked(
    ctx: Option<&MlsDecryptCtx<'_>>,
    flow_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> bool {
    let Some(value) = value else {
        return false;
    };
    if !value_is_mls_envelope(value) {
        return false;
    }
    // Non-empty sidecar hit → readable, not locked. Empty sidecars are not
    // useful for an encrypted `set` value; treat them as missing so the UI
    // does not confuse encrypted-but-unreadable content with "no content".
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, flow_id, field_path)
        && !private_plaintext_display_text(&plaintext).trim().is_empty()
    {
        return false;
    }
    // Decryptable non-empty content (another member's ciphertext) → not
    // locked. Empty decrypted text is treated like a missing plaintext for an
    // encrypted `set`, so the UI does not collapse unreadable private content
    // into a misleading empty state.
    if let Some(plaintext) = ctx.and_then(|ctx| decrypt_private_flow_value(ctx, value))
        && !flow_body_display_text(Some(&plaintext)).trim().is_empty()
    {
        return false;
    }
    // Envelope, no sidecar, can't decrypt → locked.
    true
}

/// X5.2 — resolve the display text for an author-private flow field
/// (`body` / `synthesis`) with a 3-tier precedence:
///
/// 1. **Local plaintext sidecar** (`save_private_plaintext`) — the author's own content, the ONLY
///    source the author can ever see for their own encrypted fields (OpenMLS refuses to decrypt the
///    author's own ciphertext). Stored as the JSON-serialized patch value, so we parse it back and
///    run it through `flow_body_display_text` exactly as the decrypt tier would, keeping write+read
///    symmetric.
/// 2. **Decrypt** (`private_flow_display_text`) — for ciphertext written by *other* members / other
///    leaves synced in, which we *can* decrypt.
/// 3. **Blank** — encrypted-but-unreadable; never leaks the raw envelope.
///
/// `field_path` MUST match the token the writer stored under (the patch
/// key from `collect_encryptable_private_patch_values`: `"body"` /
/// `"synthesis"`).
pub(super) fn private_flow_field_text(
    ctx: Option<&MlsDecryptCtx<'_>>,
    flow_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> String {
    // Tier 1: author's own plaintext sidecar (local-only).
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, flow_id, field_path)
    {
        let text = private_plaintext_display_text(&plaintext);
        if !text.trim().is_empty() {
            return text;
        }
    }
    // Tiers 2 + 3: decrypt another member's ciphertext, else blank.
    private_flow_display_text(ctx, value)
}

pub(super) fn card_from_flow_projection(
    flow: &crate::api::FlowProjectionView,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> KanbanCard {
    let title = if flow.title.trim().is_empty() {
        flow.flow_id.clone()
    } else {
        flow.title.clone()
    };
    let description =
        flow_projection_field_string(flow, flow.summary.as_deref(), &["summary", "description"])
            .unwrap_or_default();
    let discussion_visibility =
        flow_projection_field_string(flow, None, &["discussion_visibility", "visibility"]);
    let locked_flow = if discussion_visibility.as_deref() == Some("locked") {
        Some(LockedFlow {
            flow_id_hash: flow_projection_field_string(flow, None, &["discussion_ref_hash"])
                .unwrap_or_else(|| format!("sha256:{}", flow.flow_id)),
            reason: flow_projection_field_string(flow, None, &["locked_reason"]).unwrap_or_else(
                || "Locked discussion: title and members are not disclosed.".to_owned(),
            ),
        })
    } else {
        None
    };
    let external_visibility = if locked_flow.is_some() {
        "Locked discussion (lazy_link)".to_owned()
    } else {
        "No external discussions linked".to_owned()
    };
    let history_visibility = flow_projection_field_string(flow, None, &["history_visibility"])
        .unwrap_or_else(|| {
            if locked_flow.is_some() {
                "lazy_link (cross-Space)".to_owned()
            } else {
                "Managed by board".to_owned()
            }
        });
    // X10.2: bind the private-field value exprs once so text + locked agree.
    let flow_body_field =
        flow_projection_private_field_value(flow, KANBAN_BODY_PRIVATE_FIELD_PATHS);
    let flow_body_value = flow_body_field.map(|(value, _)| value);
    let flow_body_path = flow_body_field.map(|(_, path)| path).unwrap_or("body");
    let flow_synthesis_field =
        flow_projection_private_field_value(flow, KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS);
    let flow_synthesis_value = flow_synthesis_field.map(|(value, _)| value);
    let flow_synthesis_path = flow_synthesis_field
        .map(|(_, path)| path)
        .unwrap_or("synthesis");
    KanbanCard {
        id: flow.flow_id.clone(),
        rank: flow_projection_field_string(flow, flow.rank.as_deref(), &["rank"])
            .unwrap_or_default(),
        title: title.clone(),
        description,
        body: private_flow_field_text(decrypt_ctx, &flow.flow_id, flow_body_path, flow_body_value),
        body_locked: private_flow_field_locked(
            decrypt_ctx,
            &flow.flow_id,
            flow_body_path,
            flow_body_value,
        ),
        synthesis: private_flow_field_text(
            decrypt_ctx,
            &flow.flow_id,
            flow_synthesis_path,
            flow_synthesis_value,
        ),
        synthesis_locked: private_flow_field_locked(
            decrypt_ctx,
            &flow.flow_id,
            flow_synthesis_path,
            flow_synthesis_value,
        ),
        created_by: flow
            .created_by
            .clone()
            .or_else(|| flow_projection_field_string(flow, None, &["created_by", "actor_id"]))
            .unwrap_or_default(),
        created_at: flow
            .created_at
            .clone()
            .or_else(|| flow_projection_field_string(flow, None, &["created_at", "timestamp"]))
            .unwrap_or_default(),
        updated_at: flow
            .updated_at
            .clone()
            .or_else(|| flow_projection_field_string(flow, None, &["updated_at", "edited_at"]))
            .unwrap_or_default(),
        labels: flow_projection_labels(flow),
        assignee: flow_projection_assignee(flow).unwrap_or_else(|| "—".to_owned()),
        assigned_to_relations: flow_projection_assigned_to_relations(flow),
        due: flow_projection_field_string(flow, None, &["due_at", "due"])
            .unwrap_or_else(|| "—".to_owned()),
        primary_flow_id: flow.flow_id.clone(),
        locked_flow,
        external_visibility,
        history_visibility,
        security_encrypted: flow_projection_security_state(flow),
        state: CardState::Synced,
        lifecycle: flow_lifecycle_from_wire(&flow.state),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct LocalCardCreate {
    pub(super) board_space_id: String,
    pub(super) list_space_id: String,
    pub(super) card: KanbanCard,
}

pub(super) fn local_created_card(
    flow_id: String,
    title: String,
    rank: String,
    description: String,
    state: CardState,
) -> KanbanCard {
    KanbanCard {
        id: flow_id.clone(),
        rank,
        title,
        description,
        body: String::new(),
        synthesis: String::new(),
        body_locked: false,
        synthesis_locked: false,
        created_by: "yougen".to_owned(),
        created_at: String::new(),
        updated_at: String::new(),
        labels: vec!["draft".to_owned()],
        assignee: "yougen".to_owned(),
        assigned_to_relations: Vec::new(),
        due: "unscheduled".to_owned(),
        primary_flow_id: flow_id,
        locked_flow: None,
        external_visibility: "Not shared externally".to_owned(),
        history_visibility: "board default".to_owned(),
        security_encrypted: None,
        state,
        lifecycle: FlowLifecycleState::Active,
    }
}

pub(super) fn overlay_local_card_creates(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    overlay_local_card_creates_with_decrypt(columns, state_store, board_space_id, None)
}

pub(super) fn overlay_local_card_creates_with_decrypt(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        columns,
        state_store,
        board_space_id,
        &[],
        decrypt_ctx,
    )
}

pub(super) fn overlay_collection_projection_with_operations(
    projection: &cokret_sdk::CollectionProjectionResBody,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        collection_projection_to_columns(projection, decrypt_ctx),
        state_store,
        board_space_id,
        remote_operations,
        decrypt_ctx,
    )
}

#[cfg(test)]
pub(super) fn overlay_card_projection_with_operations(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        columns,
        state_store,
        board_space_id,
        remote_operations,
        None,
    )
}

pub(super) fn overlay_card_projection_with_operations_and_decrypt(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    let state = state_store.load();
    let columns = overlay_local_card_create_records(columns, &state.raw_operations, board_space_id);
    let columns = overlay_local_card_update_records(columns, remote_operations, decrypt_ctx);
    let columns = overlay_local_card_update_records(columns, &state.raw_operations, decrypt_ctx);
    overlay_local_card_assignment_records(columns, &state.raw_operations)
}

pub(super) fn flow_update_operations_from_events(events: &[Value]) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(flow_update_operation_from_event)
        .collect()
}

pub(super) fn space_create_operations_from_events(events: &[Value]) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(space_create_operation_from_event)
        .collect()
}

pub(super) fn flow_update_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    raw_operation_from_event(event, "ck.flow.update")
}

pub(super) fn space_create_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    raw_operation_from_event(event, "ck.space.create")
}

pub(super) fn raw_operation_from_event(
    event: &Value,
    expected_kind: &str,
) -> Option<RawOperationRecord> {
    let kind = json_path_string(Some(event), &["event_kind"])
        .or_else(|| json_path_string(Some(event), &["kind"]))?;
    if kind != expected_kind {
        return None;
    }
    let body = event.get("payload")?.clone();
    let operation_id = json_path_string(Some(event), &["operation_id"])
        .or_else(|| json_path_string(Some(event), &["event_id"]))
        .unwrap_or_else(|| format!("remote-{expected_kind}"));
    // canonical envelope 主体是 `actor_id`(spec forbidden-wire-fields.json:
    // sender → sender_actor_id)。优先 actor_id / sender_actor_id;`sender`
    // 已废弃,降到尾部仅作向后兼容容忍服务端旧值。
    let actor_id = json_path_string(Some(event), &["actor_id"])
        .or_else(|| json_path_string(Some(event), &["sender_actor_id"]))
        .or_else(|| json_path_string(Some(&body), &["actor_id"]))
        .or_else(|| json_path_string(Some(&body), &["sender_actor_id"]))
        .or_else(|| json_path_string(Some(event), &["sender"]))
        .or_else(|| json_path_string(Some(&body), &["sender"]))
        .unwrap_or_default();
    let created_at = json_path_string(Some(event), &["created_at"])
        .or_else(|| json_path_string(Some(&body), &["created_at"]))
        .unwrap_or_default();
    let received_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: json_path_string(Some(event), &["realm_id"])
            .or_else(|| json_path_string(Some(&body), &["object", "realm_id"])),
        received_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": created_at,
            "write_state": "synced",
            "body": body,
        }),
    })
}

pub(super) fn sync_selected_card_from_columns(
    mut selected_card: Signal<Option<KanbanCard>>,
    columns: &[KanbanColumn],
) {
    let Some(current) = selected_card.read().clone() else {
        return;
    };
    let Some(next) = find_card_by_flow_id(columns, &current.id) else {
        return;
    };
    if next != current {
        selected_card.set(Some(next));
    }
}

pub(super) fn raw_operation_allows_overlay(payload: &Value) -> bool {
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    !matches!(write_state.as_str(), "cancelled" | "canceled" | "dropped")
}

pub(super) fn raw_operation_card_state(payload: &Value) -> CardState {
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    card_state_from_write_state(&write_state)
}

pub(super) fn raw_operation_kind_matches(payload: &Value, expected: &str) -> bool {
    json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))
        .as_deref()
        == Some(expected)
}

pub(super) fn local_operation_state_for_target(
    raw_operations: &[RawOperationRecord],
    kind: &str,
    target_id: &str,
) -> Option<CardState> {
    raw_operations.iter().rev().find_map(|record| {
        if !raw_operation_kind_matches(&record.payload, kind) {
            return None;
        }
        let payload = &record.payload;
        let body = payload.get("body").or_else(|| payload.get("payload"));
        let effect = payload.get("effect");
        let matches_target = json_path_string(body, &["object", "id"])
            .or_else(|| json_path_string(body, &["flow_id"]))
            .or_else(|| json_path_string(body, &["target_ref"]))
            .or_else(|| json_path_string(effect, &["flow_id"]))
            .or_else(|| json_path_string(Some(payload), &["flow_id"]))
            .as_deref()
            == Some(target_id);
        matches_target.then(|| raw_operation_card_state(payload))
    })
}

pub(super) fn local_space_create_state_for_target(
    raw_operations: &[RawOperationRecord],
    projected_space_container_ids: &BTreeSet<String>,
    target_id: &str,
) -> Option<CardState> {
    let state = local_operation_state_for_target(raw_operations, "ck.space.create", target_id)?;
    if projected_space_container_ids.contains(target_id) {
        Some(CardState::Synced)
    } else {
        Some(state)
    }
}

pub(super) fn displayed_card_state(
    card: &KanbanCard,
    projected_flow_ids: &BTreeSet<String>,
) -> CardState {
    if projected_flow_ids.contains(&card.id) || projected_flow_ids.contains(&card.primary_flow_id) {
        CardState::Synced
    } else {
        card.state
    }
}

/// Re-apply locally-queued `ck.flow.update` patches on top of the
/// server projection. Without this overlay, optimistic edits to a
/// card's title / summary / body / fields would vanish on page reload
/// because the server projection is refetched but the local mutation
/// lived only in the in-memory `columns` signal. The reducer copy of
/// each Move is the source of truth once the server confirms, but in
/// the meantime we keep the user's edit visible by replaying the
/// queued payload here. Ops marked as terminally-failed are skipped
/// so a rejected edit doesn't keep clobbering the projection.
pub(super) fn overlay_local_card_update_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    for update in raw_operations
        .iter()
        .filter_map(|record| local_card_update_from_raw_operation(record, decrypt_ctx))
    {
        for column in columns.iter_mut() {
            if let Some(card) = column
                .cards
                .iter_mut()
                .find(|card| card.id == update.flow_id)
            {
                apply_card_update_overlay(card, &update);
            }
        }
    }
    columns
}

pub(super) fn overlay_local_card_assignment_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
) -> Vec<KanbanColumn> {
    for record in raw_operations
        .iter()
        .filter(|record| raw_operation_allows_overlay(&record.payload))
    {
        if raw_operation_kind_matches(&record.payload, "ck.relation.create") {
            overlay_local_assignment_create(&mut columns, &record.payload);
        } else if raw_operation_kind_matches(&record.payload, "ck.relation.tombstone") {
            overlay_local_assignment_tombstone(&mut columns, &record.payload);
        }
    }
    columns
}

fn overlay_local_assignment_create(columns: &mut [KanbanColumn], payload: &Value) {
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let relation_kind = json_path_string(body, &["relation_kind"])
        .or_else(|| json_path_string(body, &["kind"]))
        .unwrap_or_default();
    if relation_kind != "assigned_to" {
        return;
    }
    let Some(flow_id) = json_path_string(body, &["from_ref"]) else {
        return;
    };
    let Some(actor_id) = json_path_string(body, &["to_ref"])
        .or_else(|| json_path_string(Some(payload), &["assignment_actor_id"]))
    else {
        return;
    };
    let Some(relation_id) = json_path_string(Some(payload), &["assignment_relation_id"])
        .or_else(|| json_path_string(body, &["relation_id"]))
        .or_else(|| json_path_string(body, &["id"]))
    else {
        return;
    };
    for column in columns.iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| card.id == flow_id) {
            let mut actor_ids = card_assigned_actor_ids(card)
                .into_iter()
                .collect::<BTreeSet<_>>();
            actor_ids.insert(actor_id.clone());
            let mut relations = card.assigned_to_relations.clone();
            if !relations
                .iter()
                .any(|relation| relation.relation_id == relation_id)
            {
                relations.push(CardAssignedToRelation {
                    relation_id,
                    actor_id,
                });
            }
            apply_card_assignment_projection(
                card,
                &actor_ids,
                relations,
                raw_operation_card_state(payload),
            );
            break;
        }
    }
}

fn overlay_local_assignment_tombstone(columns: &mut [KanbanColumn], payload: &Value) {
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let Some(relation_id) = json_path_string(body, &["relation_id"])
        .or_else(|| json_path_string(Some(payload), &["assignment_relation_id"]))
    else {
        return;
    };
    for column in columns.iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| {
            card.assigned_to_relations
                .iter()
                .any(|relation| relation.relation_id == relation_id)
        }) {
            let removed_actor = card
                .assigned_to_relations
                .iter()
                .find(|relation| relation.relation_id == relation_id)
                .map(|relation| relation.actor_id.clone())
                .or_else(|| json_path_string(Some(payload), &["assignment_actor_id"]));
            let mut actor_ids = card_assigned_actor_ids(card)
                .into_iter()
                .collect::<BTreeSet<_>>();
            if let Some(actor_id) = removed_actor {
                actor_ids.remove(actor_id.trim());
            }
            let relations = card
                .assigned_to_relations
                .iter()
                .filter(|relation| relation.relation_id != relation_id)
                .cloned()
                .collect::<Vec<_>>();
            apply_card_assignment_projection(
                card,
                &actor_ids,
                relations,
                raw_operation_card_state(payload),
            );
            break;
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum PrivateFieldOverlay {
    Set(String),
    Unset,
    Locked,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct LocalCardUpdate {
    pub(super) flow_id: String,
    pub(super) title: Option<Option<String>>,
    pub(super) summary: Option<Option<String>>,
    pub(super) body: Option<PrivateFieldOverlay>,
    pub(super) synthesis: Option<PrivateFieldOverlay>,
    pub(super) fields: Option<Value>,
    pub(super) state: CardState,
}

pub(super) fn local_card_update_from_raw_operation(
    record: &RawOperationRecord,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Option<LocalCardUpdate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != "ck.flow.update" {
        return None;
    }
    if !raw_operation_allows_overlay(payload) {
        return None;
    }
    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    let flow_id = json_path_string(Some(body), &["flow_id"])
        .or_else(|| json_path_string(Some(body), &["target_ref"]))?;
    let patch = body.get("patch")?.as_object()?;

    fn extract_set_unset(op: &Value) -> Option<Option<String>> {
        let op_kind = op.get("$op").and_then(Value::as_str)?;
        match op_kind {
            "set" => op
                .get("value")
                .and_then(Value::as_str)
                .map(|s| Some(s.to_owned())),
            "unset" => Some(None),
            _ => None,
        }
    }

    fn extract_private_set_unset(
        op: &Value,
        decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
        flow_id: &str,
        field_path: &str,
    ) -> Option<PrivateFieldOverlay> {
        let op_kind = op.get("$op").and_then(Value::as_str)?;
        match op_kind {
            "unset" => Some(PrivateFieldOverlay::Unset),
            "set" => {
                let value = op.get("value")?;
                if value_is_mls_envelope(value) {
                    let text =
                        private_flow_field_text(decrypt_ctx, flow_id, field_path, Some(value));
                    if !text.trim().is_empty() {
                        Some(PrivateFieldOverlay::Set(text))
                    } else {
                        Some(PrivateFieldOverlay::Locked)
                    }
                } else {
                    Some(PrivateFieldOverlay::Set(flow_body_display_text(Some(
                        value,
                    ))))
                }
            }
            _ => None,
        }
    }

    fn extract_private_for_paths(
        patch: &Map<String, Value>,
        paths: &[&'static str],
        decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
        flow_id: &str,
    ) -> Option<PrivateFieldOverlay> {
        paths.iter().find_map(|path| {
            let op = patch_op_for_private_path(patch, path)?;
            extract_private_set_unset(op.as_ref(), decrypt_ctx, flow_id, path)
        })
    }

    let title = patch
        .get("metadata.title")
        .or_else(|| patch.get("title"))
        .and_then(extract_set_unset);
    let summary = patch
        .get("metadata.summary")
        .or_else(|| patch.get("summary"))
        .and_then(extract_set_unset);
    let body_op = extract_private_for_paths(
        patch,
        KANBAN_BODY_PRIVATE_FIELD_PATHS,
        decrypt_ctx,
        &flow_id,
    );
    let synthesis = extract_private_for_paths(
        patch,
        KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS,
        decrypt_ctx,
        &flow_id,
    );
    let fields = patch
        .get("metadata.fields")
        .or_else(|| patch.get("fields"))
        .and_then(|fields_op| {
            if fields_op.get("$op").and_then(Value::as_str) == Some("set") {
                fields_op.get("value").cloned()
            } else {
                None
            }
        });

    Some(LocalCardUpdate {
        flow_id,
        title,
        summary,
        body: body_op,
        synthesis,
        fields,
        state: raw_operation_card_state(payload),
    })
}

pub(super) fn apply_card_update_overlay(card: &mut KanbanCard, update: &LocalCardUpdate) {
    if let Some(slot) = &update.title {
        card.title = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.summary {
        card.description = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.body {
        match slot {
            PrivateFieldOverlay::Set(value) => {
                card.body = value.clone();
                card.body_locked = false;
            }
            PrivateFieldOverlay::Unset => {
                card.body.clear();
                card.body_locked = false;
            }
            PrivateFieldOverlay::Locked => {
                card.body.clear();
                card.body_locked = true;
            }
        }
    }
    if let Some(slot) = &update.synthesis {
        match slot {
            PrivateFieldOverlay::Set(value) => {
                card.synthesis = value.clone();
                card.synthesis_locked = false;
            }
            PrivateFieldOverlay::Unset => {
                card.synthesis.clear();
                card.synthesis_locked = false;
            }
            PrivateFieldOverlay::Locked => {
                card.synthesis.clear();
                card.synthesis_locked = true;
            }
        }
    }
    if let Some(fields) = &update.fields {
        if let Some(labels) = fields.get("labels").and_then(Value::as_array) {
            card.labels = labels
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
        }
        if let Some(due) = fields
            .get("due_at")
            .or_else(|| fields.get("due"))
            .and_then(Value::as_str)
        {
            card.due = display_optional_card_field(due);
        } else {
            card.due = display_optional_card_field("");
        }
    }
    card.state = update.state;
}

pub(super) fn overlay_local_card_create_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    let board_space_id = board_space_id.trim();
    if board_space_id.is_empty() {
        return columns;
    }

    let mut existing_card_ids = columns
        .iter()
        .flat_map(|column| column.cards.iter().map(|card| card.id.clone()))
        .collect::<BTreeSet<_>>();
    for local_create in raw_operations
        .iter()
        .filter_map(local_card_create_from_raw_operation)
    {
        if local_create.board_space_id != board_space_id {
            continue;
        }
        if existing_card_ids.contains(&local_create.card.id) {
            continue;
        }
        let Some(column) = columns
            .iter_mut()
            .find(|column| column.id == local_create.list_space_id)
        else {
            continue;
        };
        existing_card_ids.insert(local_create.card.id.clone());
        column.cards.push(local_create.card);
        sort_kanban_cards(&mut column.cards);
    }

    columns
}

pub(super) fn local_card_create_from_raw_operation(
    record: &RawOperationRecord,
) -> Option<LocalCardCreate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != "ck.flow.create" {
        return None;
    }
    if !raw_operation_allows_overlay(payload) {
        return None;
    }

    let effect = payload.get("effect");
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let position_component = flow_position_component(body);
    let flow_id = json_path_string(effect, &["flow_id"])
        .or_else(|| json_path_string(body, &["flow_id"]))
        .or_else(|| json_path_string(body, &["object", "id"]))?;
    let board_space_id = json_path_string(effect, &["board_space_id"])
        .or_else(|| json_path_string(position_component, &["board_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "board_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "board_space_id"]))?;
    let list_space_id = json_path_string(effect, &["list_space_id"])
        .or_else(|| json_path_string(position_component, &["list_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "list_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "list_space_id"]))?;
    let title = json_path_string(effect, &["title"])
        .or_else(|| json_path_string(body, &["object", "title"]))
        .or_else(|| json_path_string(body, &["title"]))
        .unwrap_or_else(|| flow_id.clone());
    let rank = json_path_string(effect, &["rank"])
        .or_else(|| json_path_string(position_component, &["rank"]))
        .or_else(|| json_path_string(body, &["object", "fields", "rank"]))
        .or_else(|| json_path_string(body, &["rank"]))
        .unwrap_or_else(|| "U".to_owned());
    let description = json_path_string(effect, &["description"])
        .or_else(|| json_path_string(effect, &["summary"]))
        .or_else(|| json_path_string(body, &["object", "summary"]))
        .or_else(|| json_path_string(body, &["summary"]))
        .unwrap_or_else(|| LOCAL_PENDING_CARD_DESCRIPTION.to_owned());

    Some(LocalCardCreate {
        board_space_id,
        list_space_id,
        card: local_created_card(
            flow_id,
            title,
            rank,
            description,
            raw_operation_card_state(payload),
        ),
    })
}

pub(super) fn local_space_create_from_raw_operation(
    record: &RawOperationRecord,
) -> Option<LocalSpaceCreate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != "ck.space.create" {
        return None;
    }
    if !raw_operation_allows_overlay(payload) {
        return None;
    }

    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    let object = body.get("object").unwrap_or(body);
    let id = json_path_string(Some(object), &["id"])
        .or_else(|| json_path_string(Some(body), &["space_id"]))
        .or_else(|| json_path_string(Some(body), &["space_id"]))?;
    let space_kind = json_path_string(Some(object), &["kind"])
        .or_else(|| json_path_string(Some(body), &["space_kind"]))?;
    if space_kind != "board" && space_kind != "list" {
        return None;
    }
    let realm_id = json_path_string(Some(object), &["realm_id"]).or_else(|| {
        record
            .realm_id
            .as_ref()
            .map(|record_realm_id| trim_realm_id(record_realm_id))
    });
    let title = json_path_string(Some(object), &["title"])
        .or_else(|| json_path_string(Some(body), &["title"]))
        .unwrap_or_else(|| id.clone());
    let parent_space_id = json_path_string(Some(object), &["parent_space_id"])
        .or_else(|| json_path_string(Some(body), &["parent_space_id"]));
    let rank = json_path_string(Some(object), &["rank"])
        .or_else(|| json_path_string(Some(body), &["rank"]));

    Some(LocalSpaceCreate {
        id,
        realm_id,
        kind: space_kind,
        title,
        parent_space_id,
        rank,
    })
}

pub(super) fn flow_position_component(body: Option<&Value>) -> Option<&Value> {
    body?
        .get("components")?
        .as_array()?
        .iter()
        .find(|component| {
            component.get("family").and_then(Value::as_str) == Some("ck.component.flow.position.v1")
        })
}

pub(super) fn json_path_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn map_dotted_value<'a>(map: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = map.get(first)?;
    for segment in segments {
        current = current.get(segment)?;
    }
    Some(current)
}

pub(super) fn value_dotted_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

pub(super) fn collection_item_private_field_value<'a>(
    object: &'a Value,
    paths: &[&'static str],
) -> Option<(&'a Value, &'static str)> {
    paths
        .iter()
        .find_map(|path| value_dotted_value(object, path).map(|value| (value, *path)))
}

pub(super) fn flow_projection_private_field_value<'a>(
    flow: &'a crate::api::FlowProjectionView,
    paths: &[&'static str],
) -> Option<(&'a Value, &'static str)> {
    paths.iter().find_map(|path| {
        let value = if *path == "body" {
            flow.body.as_ref()
        } else if let Some(field_path) = path.strip_prefix("fields.") {
            map_dotted_value(&flow.fields, field_path)
        } else {
            map_dotted_value(&flow.fields, path)
        }?;
        Some((value, *path))
    })
}

pub(super) fn patch_op_for_private_path<'a>(
    patch: &'a Map<String, Value>,
    path: &str,
) -> Option<Cow<'a, Value>> {
    if let Some(op) = patch.get(path) {
        return Some(Cow::Borrowed(op));
    }
    let mut segments = path.split('.');
    let first = segments.next()?;
    let parent_op = patch.get(first)?;
    if parent_op.get("$op").and_then(Value::as_str) != Some("set") {
        return None;
    }
    let mut current = parent_op.get("value")?;
    for segment in segments {
        current = current.get(segment)?;
    }
    if current.get("$op").and_then(Value::as_str).is_some() {
        Some(Cow::Owned(current.clone()))
    } else {
        Some(Cow::Owned(
            json!({ "$op": "set", "value": current.clone() }),
        ))
    }
}
