use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KanbanColumn {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) rank: String,
    pub(crate) cards: Vec<KanbanCard>,
    /// Space-container lifecycle state. `Active` is the wire default; `Archived` is set
    /// optimistically after a successful `ak.space.archive` submit and reset
    /// after `ak.space.restore`. Spec: `models/realm-and-space.md §4.4`.
    /// `Tombstoned` is irreversible and modeled here for completeness but the
    /// UI currently has no tombstone affordance — server-only path.
    pub(crate) state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SpaceContainerLifecycleState {
    #[default]
    Active,
    Archived,
    /// Server-only terminal state. UI never produces this; the variant
    /// exists so `dispatch_space_container_lifecycle` can exhaustively match.
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KanbanCard {
    pub(crate) id: String,
    /// The card's current rank inside its column. This is the local
    /// mirror of the `ak.component.strand.position.v1` cell's `rank`
    /// field and seeds the `expected_position` of any subsequent
    /// `ak.strand.move` / `ak.strand.reorder` Move. When the projection
    /// refreshes (server-side cell update), this must be re-synced.
    pub(crate) rank: String,
    pub(crate) title: String,
    /// Strand `metadata.summary` — the short one-line/paragraph overview. This
    /// is the ONLY short-text description the board persists; the long-form
    /// text lives in [`Self::synthesis`].
    pub(crate) description: String,
    /// The Strand's synthesis content, rendered as display text.
    ///
    /// Canonical wire home is top-level `content: ContentBlock`, or
    /// `encrypted_content: EncryptedEnvelope` in an E2EE scope
    /// (`strand.schema.json`). A Strand carries exactly one synthesis content
    /// slot, so this is the board's single long-form field.
    pub(crate) synthesis: String,
    /// X10.2 — the Strand's content is an encrypted envelope this device
    /// cannot read yet (no local plaintext sidecar + can't decrypt: author's
    /// own ciphertext, or a fresh browser before MLS unlock). When true the
    /// display layer shows a locked placeholder and [`Self::synthesis`] stays
    /// EMPTY so the editor never re-saves a placeholder over real ciphertext.
    pub(crate) synthesis_locked: bool,
    pub(crate) created_by: String,
    pub(crate) created_at: String,
    pub(crate) updated_by: String,
    pub(crate) updated_at: String,
    pub(crate) labels: Vec<String>,
    pub(crate) assignee: String,
    pub(crate) assigned_to_relations: Vec<CardAssignedToRelation>,
    pub(crate) due: String,
    /// Schedule revision frontier this client observed for the card's
    /// calendar, as `event_digest` values. Empty means the projection has not
    /// exposed `schedule_revision_heads` yet, and RSVP authoring fails closed
    /// rather than signing an unbacked basis.
    pub(crate) calendar_schedule_basis_refs: Vec<String>,
    /// Folded RSVP state for the card's calendar: the signed-in actor's own
    /// answer, the aggregate, and how many heads exist but do not count.
    pub(crate) calendar_rsvp: CalendarRsvpDisplay,
    pub(crate) calendar: CalendarCardFields,
    pub(crate) primary_strand_id: String,
    pub(crate) locked_strand: Option<LockedStrand>,
    pub(crate) external_visibility: String,
    pub(crate) history_visibility: String,
    /// Explicit Strand security state from projection metadata. `None`
    /// means the Strand inherits the active Realm / Space posture.
    pub(crate) security_encrypted: Option<bool>,
    pub(crate) state: CardState,
    /// Strand lifecycle state (orthogonal to `state` above which is
    /// Move-lifecycle). Spec: `strand-and-message.md §3`,
    /// `common-fields.md §5.1`. Active cards render in the column;
    /// Archived cards move to the archived-cards drawer. Redacted is the
    /// irreversible terminal (content cleared, envelope/audit retained); UI
    /// never emits it but renders a withdrawn-message placeholder for it.
    pub(crate) lifecycle: StrandLifecycleState,
}

impl KanbanCard {
    /// Parses the observed schedule revision frontier into SDK digests.
    ///
    /// Anything unparseable is dropped rather than guessed: an invalid digest
    /// can never be a legitimate causal edge, and signing it would produce an
    /// RSVP a receiver rejects with `rsvp_basis_not_causal`.
    pub(crate) fn calendar_schedule_basis_refs(&self) -> Vec<arkret_sdk::Hash> {
        self.calendar_schedule_basis_refs
            .iter()
            .filter_map(|value| arkret_sdk::Hash::new(value.clone()).ok())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CardAssignedToRelation {
    pub(crate) relation_id: String,
    pub(crate) actor_id: String,
}

pub(crate) fn card_assigned_actor_ids(card: &KanbanCard) -> Vec<String> {
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

pub(crate) fn assignee_value_from_actor_ids(actor_ids: &BTreeSet<String>) -> String {
    if actor_ids.is_empty() {
        "—".to_owned()
    } else {
        actor_ids.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

pub(crate) fn apply_card_assignment_projection(
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
pub(crate) struct CardDetailDraft {
    pub(crate) title: String,
    /// Strand `metadata.summary`.
    pub(crate) description: String,
    /// Strand synthesis content (`content` / `encrypted_content`).
    pub(crate) synthesis: String,
    pub(crate) labels: Vec<String>,
    pub(crate) assignee: String,
    pub(crate) due: String,
    pub(crate) calendar: CalendarCardFields,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CardSynthesisRevision {
    pub(crate) id: String,
    pub(crate) body: String,
    pub(crate) actor_id: String,
    pub(crate) author_label: String,
    pub(crate) timestamp_label: String,
    pub(crate) sort_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CardSynthesisTrackEntry {
    pub(crate) id: String,
    pub(crate) body: String,
    pub(crate) actor_id: String,
    pub(crate) author_label: String,
    pub(crate) timestamp_label: String,
    pub(crate) sort_key: String,
    pub(crate) edited: bool,
    pub(crate) revisions: Vec<CardSynthesisRevision>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum StrandLifecycleState {
    #[default]
    Active,
    Archived,
    /// Irreversible terminal per the projection enum. `redacted` clears
    /// content but retains the envelope and audit trail, so the UI renders a
    /// withdrawn-message placeholder rather than hiding the Strand.
    Redacted,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LockedStrand {
    pub(crate) strand_id_hash: String,
    pub(crate) reason: String,
}

/// Snapshot of the card-being-dragged's pre-move state. The cas-register
/// model in [`operations-sync.md` §9.1](../../arkret-spec/spec/v1/zh/sync/operations-sync.md)
/// requires the source `(list_space_id, rank)` to seed `head_eq` on the
/// resulting `ak.strand.move` / `ak.strand.reorder` Move. We capture it on
/// `ondragstart` so the drop handler doesn't have to re-derive it from
/// the column state (which may have been mutated optimistically in the
/// meantime).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DraggedCard {
    pub(crate) card_id: String,
    pub(crate) from_column_id: String,
    pub(crate) from_rank: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DraggedColumn {
    pub(crate) column_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoardSpaceOption {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BoardToolbarPopover {
    #[default]
    None,
    SelectBoard,
    CreateBoard,
    Projection,
    Queue,
}

/// Card-detail content tabs. There is no Description tab: `metadata.summary`
/// is rendered by the always-visible Summary section, and the Strand's single
/// synthesis `content` block is the Synthesis tab. A second persisted long-text
/// field has no canonical home on a Strand, so the board does not model one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CardDetailContentTab {
    #[default]
    Synthesis,
    Discussion,
}

/// Which tab the right-hand card-detail sidebar is showing.
/// - `Details`: per-card metadata (Strand ID, Assignees, Due, Visibility) + Activity hints.
/// - `Members`: every actor in the surrounding Realm/Space — sourced from the cached space
///   projection (`members`/`participants`/`owners` keys). Each row is also marked when the actor
///   has authored an event against the current Strand (derived from local raw operations), so
///   participation is surfaced inline instead of in a separate tab.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CardDetailSidebarTab {
    #[default]
    Details,
    Members,
}

/// Which slice of card fields the inline edit form is currently editing.
/// The Summary scope edits title + the short `metadata.summary` blurb; the
/// Synthesis scope edits the Strand's canonical `content` block. Each entry
/// point seeds the matching scope so the form only renders the relevant editor
/// (avoids the "edit synthesis" CTA opening an unrelated Title + Summary
/// editor as well).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CardEditScope {
    #[default]
    Summary,
    Synthesis,
    Calendar,
}

pub(crate) const TOAST_EDITOR_SCRIPT_URL: &str = "/assets/vendor/toastui-editor-all.min.js";
pub(crate) const TOAST_EDITOR_CSS_URL: &str = "/assets/vendor/toastui-editor.min.css";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CardState {
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
    pub(crate) fn write_state(self) -> WriteState {
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

    pub(crate) fn label(&self) -> &'static str {
        match self {
            CardState::Synced => "synced",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => "sending...",
            CardState::Accepted => "pending seal",
            CardState::SoftFailed => "soft failed",
            CardState::Quarantined => "quarantined",
            CardState::Conflict => "CAS conflict",
        }
    }

    pub(crate) fn class_name(&self) -> &'static str {
        match self {
            CardState::Synced => "badge green",
            CardState::Accepted => "badge amber",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => "badge blue",
            CardState::SoftFailed | CardState::Conflict => "badge red",
            CardState::Quarantined => "badge amber",
        }
    }

    pub(crate) fn data_state(self) -> &'static str {
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

    /// A card is "settled" once the server has accepted its create event
    /// (Synced or Accepted). Draft / in-flight / failed states are not
    /// settled: the archive-then-recreate promote pattern and the archive
    /// guard both wait for a card to settle before acting on it.
    pub(crate) fn is_settled(self) -> bool {
        matches!(self, CardState::Synced | CardState::Accepted)
    }

    pub(crate) fn status_title(self) -> &'static str {
        match self {
            CardState::Synced => "Server projection is current",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => {
                "Sending; waiting for server confirmation"
            }
            CardState::Accepted => "Server accepted the event; waiting for projection/seal",
            CardState::SoftFailed => "Server did not accept this event",
            CardState::Quarantined => "Write failed; open the queue for details",
            CardState::Conflict => "Server reported a CAS conflict",
        }
    }
}

pub(crate) fn card_state_from_write_state(write_state: &str) -> CardState {
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
/// mirrors the MoveSubmissionState classifier (`ak.space.create` /
/// `ak.strand.create` /
/// `ak.strand.position`) so the tracker UI can decorate state pills.
///
/// `signed_move_json` is the typed [`arkret_sdk::Move`] serialised to
/// JSON. We persist it on the queued record so that Replay can re-POST
/// the exact same signed payload — server-side dedup is content-addressed
/// on `move_id`, making replay idempotent. None means the record cannot
/// be replayed idempotently.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BoardWriteRecord {
    pub(crate) state: CardState,
    pub(crate) move_id: String,
    pub(crate) kind: String,
    pub(crate) cell_id: String,
    pub(crate) effect_summary: String,
    pub(crate) seal_ref: String,
    pub(crate) hlc: String,
    pub(crate) note: String,
    pub(crate) signed_move_json: Option<serde_json::Value>,
    /// Number of CAS-conflict rebase attempts so far. The submit path
    /// auto-retries up to [`MAX_CONFLICT_REBASE_ATTEMPTS`] before
    /// surfacing the record as Quarantined for manual review.
    pub(crate) rebase_attempts: u8,
}

impl BoardWriteRecord {
    pub(crate) fn needs_manual_conflict_review(&self) -> bool {
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
/// projection or the server's Space-container / Strand projection endpoints.
/// The local seed path is explicit demo-only so hard-coded cards are never
/// mistaken for persisted board data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoardProjectionSource {
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
