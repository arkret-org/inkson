//! Small client-side helpers retained from the former cell-driven
//! Move/Anchor write pipeline.
//!
//! The full Move construction + signing surface (`build_*_move`,
//! `sign_unsigned_move`, `UnsignedMove`, …) has been removed: all writes
//! now go through `ck.events.submit` via the Event Envelope path
//! (`operation.rs` / `api/events.rs`), with `effects[]` inlined in the
//! envelope. Only the few standalone helpers that other modules still
//! depend on survive here:
//!
//! - [`encode_ed25519_did_key_multibase`] / [`did_key_from_verifying_key`] — did:key multibase
//!   encoding used by `cross_signing.rs`.
//! - [`FlowPositionEffect`] / [`FlowPositionExpectation`] / [`flow_position_cell_id`] —
//!   flow-position cell helpers used by the kanban board (`views/kanban`).

use ed25519_dalek::VerifyingKey;

/// Identifies the cas-register cell that holds a Flow's position inside
/// a given Board. Per
/// [`spec/v1/zh/models/realm-and-space.md`
/// §3.6](../../cokret-spec/spec/v1/zh/models/realm-and-space.md) the cell key is
/// `ck:cell:ck.component.flow.position.v1:<board_space_id>:<flow_id>` — a Flow can appear on
/// multiple Boards with **independent** position cells, so the Board id is part of the subject.
pub fn flow_position_cell_id(board_space_id: &str, flow_id: &str) -> String {
    format!("ck:cell:ck.component.flow.position.v1:{board_space_id}:{flow_id}")
}

/// CAS pre-state that the caller expects to find on the position cell
/// before the write applies. Compiled into a `head_eq` precondition per
/// [`spec/v1/zh/sync/operations-sync.md`
/// §9.1](../../cokret-spec/spec/v1/zh/sync/operations-sync.md).
///
/// - `Initial` ⇒ `head_eq null` — the Flow is not yet on this Board.
/// - `At { list_space_id, rank }` ⇒ `head_eq { list_space_id, rank }` — the write expects the Flow
///   to currently sit in `list_space_id` at `rank`; any drift triggers `failed_precondition` and
///   the caller must rebase against the latest projection.
///
/// Omitting `expected_position` (passing `None` when the cell is
/// non-initial) is a spec violation — soland's reducer rejects "blind
/// writes" outside the initial-state path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowPositionExpectation {
    /// Flow not yet present on the target Board. Compiles to
    /// `head_eq null`.
    Initial,
    /// Flow currently at `(list_space_id, rank)` on the target Board.
    At { list_space_id: String, rank: String },
}

/// Effect value for a `ck.flow.move` / `ck.flow.reorder` write. Compiles
/// to a cas-register `set` with `{"list_space_id", "rank"}` per
/// [`operations-sync.md` §9.1-9.2](../../cokret-spec/spec/v1/zh/sync/operations-sync.md).
///
/// `Remove` is the "Flow leaves the Board" effect — compiles to
/// `set null`. Reducer side this also retires the derived
/// `contains` Relation for that Board.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowPositionEffect {
    /// Flow lands at `(list_space_id, rank)` on the target Board.
    SetPosition { list_space_id: String, rank: String },
    /// Flow is removed from the target Board.
    Remove,
}

/// Encode an Ed25519 public key as the multibase form did:key DID URLs
/// and DID Document `verificationMethod` entries use:
/// `z<base58btc(0xed 0x01 || pubkey32)>`. Mirrors the SDK's internal
/// helper so yougen can build did:key DIDs locally.
pub fn encode_ed25519_did_key_multibase(verifying_key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(verifying_key.as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Compose a did:key DID URL from a verifying key (`did:key:z<...>`).
pub fn did_key_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    format!(
        "did:key:{}",
        encode_ed25519_did_key_multibase(verifying_key)
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    /// spec/v1/zh/models/realm-and-space.md §3.6: the position cell key is
    /// `ck:cell:ck.component.flow.position.v1:<board_space_id>:<flow_id>`.
    /// This pins the composite subject so a future refactor that drops one
    /// segment fails loudly.
    #[test]
    fn flow_position_cell_id_is_composite_board_flow() {
        let cell = flow_position_cell_id(
            "ck:space:0196419b-0000-7000-8000-000000000010",
            "ck:flow:01abcd",
        );
        assert_eq!(
            cell,
            "ck:cell:ck.component.flow.position.v1:ck:space:0196419b-0000-7000-8000-000000000010:ck:flow:01abcd"
        );
    }

    #[test]
    fn did_key_encoding_round_trips_multibase_prefix() {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let verifying = signing.verifying_key();
        let mb = encode_ed25519_did_key_multibase(&verifying);
        assert!(mb.starts_with('z'));
        assert_eq!(
            did_key_from_verifying_key(&verifying),
            format!("did:key:{mb}")
        );
    }
}
