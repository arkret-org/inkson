//! Small client-side helpers retained from the former cell-driven
//! Move/Seal write pipeline.
//!
//! The full Move construction + signing surface (`build_*_move`,
//! `sign_unsigned_move`, `UnsignedMove`, …) has been removed: a Control Move
//! is just an Event carrying `seal_basis`, so all writes go through
//! `ak.self.events.command.submit` via the Event Envelope path
//! (`operation.rs` / `api/events.rs`). The envelope carries no cell writes at
//! all — the receiver derives them from `kind + payload` through the registered
//! reducer contract. Only the few standalone helpers that other modules still
//! depend on survive here:
//!
//! - [`StrandPositionEffect`] / [`StrandPositionExpectation`] / [`strand_position_cell_id`] —
//!   strand-position cell helpers used by the kanban board (`views/kanban`).
//!
//! The did:key multibase encoding helpers previously defined here now live
//! in [`crate::identity::did_key`] (shared with `local_state` / `cross_signing`).

/// Identifies the cas-register cell that holds a Strand's position inside
/// a given Board. Per
/// [`spec/v1/zh/models/realm-and-space.md`
/// §3.6](../../arkret-spec/spec/v1/zh/models/realm-and-space.md) the cell key is
/// `ak:cell:ak.component.strand.position.v1:<board_space_id>:<strand_id>` — a Strand can appear on
/// multiple Boards with **independent** position cells, so the Board id is part of the subject.
pub fn strand_position_cell_id(board_space_id: &str, strand_id: &str) -> String {
    format!("ak:cell:ak.component.strand.position.v1:{board_space_id}:{strand_id}")
}

/// CAS pre-state that the caller expects to find on the position cell
/// before the write applies. Compiled into a `head_eq` precondition per
/// [`spec/v1/zh/sync/operations-sync.md`
/// §9.1](../../arkret-spec/spec/v1/zh/sync/operations-sync.md).
///
/// - `Initial` ⇒ `head_eq null` — the Strand is not yet on this Board.
/// - `At { list_space_id, rank }` ⇒ `head_eq { list_space_id, rank }` — the write expects the
///   Strand to currently sit in `list_space_id` at `rank`; any drift triggers `failed_precondition`
///   and the caller must rebase against the latest projection.
///
/// Omitting `expected_position` (passing `None` when the cell is
/// non-initial) is a spec violation — soland's reducer rejects "blind
/// writes" outside the initial-state path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrandPositionExpectation {
    /// Strand not yet present on the target Board. Compiles to
    /// `head_eq null`.
    Initial,
    /// Strand currently at `(list_space_id, rank)` on the target Board.
    At { list_space_id: String, rank: String },
}

/// Effect value for a `ak.strand.move` / `ak.strand.reorder` write. Compiles
/// to a cas-register `set` with `{"list_space_id", "rank"}` per
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
            "ak:space:0196419b-0000-7000-8000-000000000010",
            "ak:strand:01abcd",
        );
        assert_eq!(
            cell,
            "ak:cell:ak.component.strand.position.v1:ak:space:0196419b-0000-7000-8000-000000000010:ak:strand:01abcd"
        );
    }
}
