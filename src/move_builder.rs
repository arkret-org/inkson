//! Small client-side helpers retained from the former cell-driven
//! Move/Seal write pipeline.
//!
//! The full Move construction + signing surface (`build_*_move`,
//! `sign_unsigned_move`, `UnsignedMove`, …) has been removed: a Control Move
//! is just an Event carrying `seal_basis`, so all writes go through
//! `ak.self.events.command.submit.v1` via the Event Envelope path
//! (`operation.rs` / `api/events.rs`). The envelope carries no cell writes at
//! all — the receiver derives them from `kind + payload` through the registered
//! reducer contract. Only the few standalone helpers that other modules still
//! depend on survive here:
//!
//! - [`StrandPositionEffect`] / [`StrandPositionExpectation`] / [`strand_position_cell_id`] —
//!   strand-position cell helpers used by the kanban board (`views/kanban`).
//!
//! The did:key multibase encoding helpers previously defined here now live
//! in [`crate::identity::did_key`] (shared with `local_state`).

/// Identifies the causal-register cell that holds a Strand's position inside
/// a given Board. Per
/// [`spec/v1/zh/models/realm-and-space.md`
/// §3.6](../../arkret-spec/spec/v1/zh/models/realm-and-space.md) the cell key is
/// `ak:cell:ak.component.strand.position.v1:<board_space_id>:<strand_id>` — a Strand can appear on
/// multiple Boards with **independent** position cells, so the Board id is part of the subject.
pub fn strand_position_cell_id(board_space_id: &str, strand_id: &str) -> String {
    format!("ak:cell:ak.component.strand.position.v1:{board_space_id}:{strand_id}")
}

/// Causal position basis observed by the caller before authoring the Event.
/// The referenced heads are copied into the Event envelope's `causal_refs`;
/// they are not a compare-and-swap precondition.
///
/// - `Initial` has no predecessor head.
/// - `At` observes the one settled head and retains its value for the
///   holder-local optimistic projection.
/// - `Conflict` observes every concurrent head, so the new position causally
///   covers and resolves the complete frontier selected by the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrandPositionExpectation {
    /// Strand not yet present on the target Board.
    Initial,
    /// Strand currently at `(list_space_id, rank)` on the target Board.
    At {
        list_space_id: String,
        rank: String,
        head_ref: arkret_sdk::Hash,
    },
    /// Multiple concurrent position heads. A resolving Move has no unique
    /// value preimage, but it must causally observe every competing head.
    Conflict { head_refs: Vec<arkret_sdk::Hash> },
}

impl StrandPositionExpectation {
    /// Exact position frontier that the authored Event must causally cover.
    pub fn causal_refs(&self) -> Vec<arkret_sdk::Hash> {
        match self {
            Self::Initial => Vec::new(),
            Self::At { head_ref, .. } => vec![head_ref.clone()],
            Self::Conflict { head_refs } => head_refs.clone(),
        }
    }
}

/// Effect value for a `ak.strand.move` / `ak.strand.reorder` write. Compiles
/// to a causal-register `set` with `{"list_space_id", "rank"}` per
/// [`operations-sync.md` §9.1-9.2](../../arkret-spec/spec/v1/zh/sync/operations-sync.md).
///
/// `Remove` is the "Strand leaves the Board" effect — compiles to
/// `set null`. Reducer side this also retires the derived
/// `contains` Relation for that Board.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrandPositionEffect {
    /// Strand lands at `(list_space_id, rank)` on the target Board.
    SetPosition { list_space_id: String, rank: String },
    /// Strand is removed from the target Board.
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// spec/v1/zh/models/realm-and-space.md §3.6: the position cell key is
    /// `ak:cell:ak.component.strand.position.v1:<board_space_id>:<strand_id>`.
    /// This pins the composite subject so a future refactor that drops one
    /// segment fails loudly.
    #[test]
    fn strand_position_cell_id_is_composite_board_strand() {
        let cell = strand_position_cell_id(
            "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "ak:strand:AR0yYaLgfEhMOjzAp9eFpdYOf2dma-COBObvEGjj8NN0",
        );
        assert_eq!(
            cell,
            "ak:cell:ak.component.strand.position.v1:ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo:ak:strand:AR0yYaLgfEhMOjzAp9eFpdYOf2dma-COBObvEGjj8NN0"
        );
    }

    #[test]
    fn conflict_expectation_covers_every_observed_head() {
        let head_a = arkret_sdk::EventId::from_digest(
            arkret_sdk::canonical::DigestSuite::Sha256,
            [0x41; 32],
        )
        .event_digest();
        let head_b = arkret_sdk::EventId::from_digest(
            arkret_sdk::canonical::DigestSuite::Sha256,
            [0x42; 32],
        )
        .event_digest();
        let expectation = StrandPositionExpectation::Conflict {
            head_refs: vec![head_a.clone(), head_b.clone()],
        };
        assert_eq!(expectation.causal_refs(), vec![head_a, head_b]);
    }
}
