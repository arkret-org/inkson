//! Client-side helpers to construct and sign `contrix_sdk::Move` values
//! for the cell-driven write paths.
//!
//! # When to use a Move (vs a direct event)
//!
//! Per spec event-kind-registry, only events that declare a `cell_family`
//! belong on the Move/Anchor pipeline. Examples:
//!
//! - **Yes**: `cx.consent.grant` / `revoke`, `cx.capability.*`,
//!   `cx.member.state`, `cx.realm.{create,update,destroy,...}`,
//!   `cx.space.{create,update,archive,restore,...}` (container Spaces),
//!   `cx.flow.position`, `cx.anchorer.*`, `cx.mls.epoch`
//! - **No**: `cx.message.*`, `cx.reaction.*`, `cx.read_cursor.advance`,
//!   `cx.relation.*`, `cx.redaction` — these stay on the durable Event
//!   Envelope endpoint (`/api/v1/events`) per spec.
//!
//! # Signing model
//!
//! Each Move's body is canonicalized (RFC 8785 JCS) and a SHA-256 digest
//! over those bytes serves as the content-addressed `id`. The `sig` field
//! carries an Ed25519 detached JWS (RFC 7515 §3.2) over the same
//! canonical bytes. Production yougen would resolve the issuer DID
//! (the local actor) to a private signing key via OS keychain / WebAuthn
//! / HSM; this module provides only the canonicalization + JWS shaping
//! helpers.
//!
//! # Builders provided
//!
//! - [`build_consent_grant_move`] — `cx.consent.grant` over the
//!   `cx.component.consent.grant.v1` OrSet cell
//! - [`build_member_state_transition_move`] — `cx.member.state` FSM
//!   transition (`invited` → `join`, etc.) over
//!   `cx.component.member.state.v1`
//! - [`build_space_organization_update_move`] — `cx.realm.update` over
//!   `cx.component.realm.organization.v1` (cas-register; post-R1.7)

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[cfg(test)]
use contrix_sdk::LatticeOpType;
use contrix_sdk::{
    AnchorId, CellRef, Did, Effect, Hash, Hlc, LatticeOp, Move, MoveId, MoveSignature, SpaceId,
    canonical,
};

/// Output of a builder: an unsigned [`Move`] body together with its
/// canonical bytes (so the signer can sign exactly the bytes the server
/// will rehash for `id` validation).
pub struct UnsignedMove {
    pub move_obj: Move,
    pub canonical_bytes: Vec<u8>,
}

/// Construct a `cx.consent.grant` Move that adds a tag to the consent
/// OrSet cell. The cell subject is the `consent_id` (one cell per
/// distinct consent grant). `tag` is what gets added to the OrSet —
/// typically a stable identifier the issuer wants to record (e.g.
/// the granted scope or capability id).
pub fn build_consent_grant_move(
    issuer: &str,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.consent.grant.v1:{consent_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "kind": "add", "tag": tag }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.consent.revoke` Move that removes a tag from the
/// consent OrSet cell. The cell subject is the same `consent_id` used by
/// [`build_consent_grant_move`]; soland's OrSet semantics enforce causal
/// remove (only tags previously added by an observed grant can be
/// removed). `reason` is optional but recommended — it surfaces in the
/// audit trail and can drive UI confirmation copy.
pub fn build_consent_revoke_move(
    issuer: &str,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    build_consent_revoke_move_v2(
        issuer,
        space_id,
        consent_id,
        tag,
        reason,
        &[],
        anchor_ref,
        hlc,
    )
}

/// Round 4 (spec a77b995) — `cx.consent.revoke` v2 with REQUIRED
/// `observed_dots` carried in the op payload. The receiver MUST NOT
/// silently cascade revoke to dots not explicitly observed; an empty
/// list is accepted only for non-causal revoke (which yougen's UI no
/// longer surfaces directly — every cascade flow MUST pass the dot
/// list).
///
/// `observed_dots` is the list of `(actor_id, actor_seq)` tuples per
/// [`contrix_sdk::Dot`] that the local view has observed and is
/// explicitly revoking. The wire field maps to
/// [`contrix_sdk::ConsentRevokePayload::observed_dots`].
pub fn build_consent_revoke_move_v2(
    issuer: &str,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    reason: Option<&str>,
    observed_dots: &[contrix_sdk::Dot],
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.consent.grant.v1:{consent_id}");
    let mut op = serde_json::json!({ "kind": "remove", "tag": tag });
    if let Some(reason) = reason {
        op["reason"] = serde_json::Value::String(reason.to_owned());
    }
    // Round 4 — emit the canonical observed_dots array even when empty
    // so the receiver-side schema_violation guard has the field to look
    // at. The SDK validator distinguishes "missing" from "empty"; the
    // op payload always sets the key.
    op["observed_dots"] = serde_json::to_value(observed_dots)
        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()));
    let effect = serde_json::json!({ "cell": cell_id, "op": op });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Structured constraint payloads attached to a capability grant. Mirrors
/// `contrix_sdk::authz::ProtocolGrantConstraint` but kept JSON-shaped
/// because soland's reducer round-trips constraints as opaque values
/// today - typing them up here would force every UI
/// surface to re-typing the SDK enum and future additions.
///
/// Use [`Self::temporal`] for the most common flavour (`not_before` /
/// `not_after` window). The wire shape lands in the OrSet `add` op as a
/// `constraints` array; soland's authz engine reads that into the typed
/// representation when evaluating future Moves.
#[derive(Clone, Debug, PartialEq)]
pub enum CapabilityConstraintInput {
    /// `temporal.window` constraint with optional `not_before` /
    /// `not_after` RFC 3339 timestamps. The UI's MVP form binds to this
    /// variant; quota / scope_limitation / etc. are scaffolded as
    /// [`Self::Other`] until matching form widgets land.
    Temporal {
        not_before: Option<String>,
        not_after: Option<String>,
    },
    /// Free-form constraint payload — the UI hands a JSON object to the
    /// builder and the wire shape forwards it as-is. Use for constraint
    /// kinds (quota, scope_limitation, claim_based) that don't have a
    /// dedicated builder yet.
    Other(serde_json::Value),
}

impl CapabilityConstraintInput {
    /// Convenience constructor for a temporal-window constraint.
    pub fn temporal(not_before: Option<String>, not_after: Option<String>) -> Self {
        Self::Temporal {
            not_before,
            not_after,
        }
    }

    /// Returns `true` when both bounds are missing — the UI uses this to
    /// avoid attaching an empty constraint.
    pub fn is_effective(&self) -> bool {
        match self {
            Self::Temporal {
                not_before,
                not_after,
            } => {
                not_before.as_deref().is_some_and(|s| !s.trim().is_empty())
                    || not_after.as_deref().is_some_and(|s| !s.trim().is_empty())
            }
            Self::Other(value) => {
                !value.is_null()
                    && (!value.is_object() || value.as_object().is_some_and(|map| !map.is_empty()))
            }
        }
    }

    /// Render to the canonical JSON shape soland accepts inside a
    /// capability OrSet `add` op's `constraints` array.
    pub fn to_constraint_value(&self) -> serde_json::Value {
        match self {
            Self::Temporal {
                not_before,
                not_after,
            } => {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "constraint_type".to_owned(),
                    serde_json::Value::String("temporal".to_owned()),
                );
                obj.insert(
                    "subtype".to_owned(),
                    serde_json::Value::String("temporal.window".to_owned()),
                );
                if let Some(value) = not_before
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    obj.insert(
                        "not_before".to_owned(),
                        serde_json::Value::String(value.to_owned()),
                    );
                }
                if let Some(value) = not_after
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    obj.insert(
                        "not_after".to_owned(),
                        serde_json::Value::String(value.to_owned()),
                    );
                }
                serde_json::Value::Object(obj)
            }
            Self::Other(value) => value.clone(),
        }
    }
}

/// Construct a `cx.capability.grant` Move that adds a capability tag to
/// the capability OrSet cell. Mirrors [`build_consent_grant_move`] —
/// the cell family (`cx.component.capability.grant.v1`) is OrSet too,
/// so the wire shape is identical save for the cell prefix. `grant_id`
/// is the cell subject (per-grant cell), `tag` is what the OrSet records
/// (typically the granted action / scope / capability identifier).
pub fn build_capability_grant_move(
    issuer: &str,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    build_capability_grant_move_with_constraints(
        issuer,
        space_id,
        grant_id,
        tag,
        &[],
        anchor_ref,
        hlc,
    )
}

/// Same as [`build_capability_grant_move`] but allows attaching structured
/// grant constraints (temporal / quota / scope_limitation / ...) to the
/// OrSet `add` op. An empty `constraints` slice yields exactly the
/// unconstrained wire shape, so this function is a strict superset.
pub fn build_capability_grant_move_with_constraints(
    issuer: &str,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    constraints: &[CapabilityConstraintInput],
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.capability.grant.v1:{grant_id}");
    let mut op = serde_json::json!({ "kind": "add", "tag": tag });
    let constraint_values: Vec<serde_json::Value> = constraints
        .iter()
        .filter(|c| c.is_effective())
        .map(|c| c.to_constraint_value())
        .collect();
    // Constraints land inside the OrSet add op's `value` field (typed
    // SDK shape: `LatticeOp { value: Option<Value> }`). Soland's
    // capability reducer reads `value.constraints` when deciding whether
    // a downstream Move's authz context satisfies the grant; the typed
    // field round-trips because it lives on `value`, not as a sibling
    // of `tag` (which the SDK's `LatticeOp` struct does not declare and
    // would silently drop on typed re-parse).
    if !constraint_values.is_empty() {
        op["value"] = serde_json::json!({
            "constraints": constraint_values,
        });
    }
    let effect = serde_json::json!({ "cell": cell_id, "op": op });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.capability.revoke` Move that removes a capability tag
/// from the capability OrSet cell. Mirrors [`build_consent_revoke_move`].
/// `reason` is optional but encouraged — it surfaces in the audit trail
/// and lets the UI explain why the capability was dropped.
pub fn build_capability_revoke_move(
    issuer: &str,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.capability.grant.v1:{grant_id}");
    let mut op = serde_json::json!({ "kind": "remove", "tag": tag });
    if let Some(reason) = reason {
        op["reason"] = serde_json::Value::String(reason.to_owned());
    }
    let effect = serde_json::json!({ "cell": cell_id, "op": op });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.member.state` Move that transitions an actor's
/// membership FSM. The cell subject is the `actor_id` (per-actor cell
/// across the whole protocol; soland's CellStore is space-scoped so
/// different Spaces have independent records of the same actor's state).
pub fn build_member_state_transition_move(
    issuer: &str,
    space_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.member.state.v1:{actor_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "kind": "transition", "from": from_state, "to": to_state }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.realm.update` Move that writes the
/// `cx.component.realm.organization.v1` cas-register cell with the
/// provided organization metadata. `value` should be a JSON object
/// (typically `{title, owner, ...}`); soland's reducer mirrors the
/// fields it knows about and ignores the rest.
pub fn build_space_organization_update_move(
    issuer: &str,
    space_id: &str,
    value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    // TODO(realm-rework): cell family renamed from cx.component.space.organization.v1
    // to cx.component.realm.organization.v1 in spec post-R1.7.
    let cell_id = format!("cx:cell:cx.component.realm.organization.v1:{space_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "kind": "set", "value": value }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct an MLS commit Move that updates the
/// `cx.component.mls.epoch.v1` cas-register cell to `new_epoch` and
/// records the local actor's understanding of `covered_frontier`. The
/// message Events can reference the observed frontier in their payload or
/// auth refs; messages themselves are not cell Moves in the active spec.
///
/// `epoch_cell_subject` is the cell subject — typically the Space id —
/// so the cas-register stays per-Space. `covered_frontier` is the
/// governance frontier ref the new MLS epoch claims to cover; soland's
/// projection compares this against
/// `cx.component.governance.covered_frontier.v1` and only treats the
/// epoch as binding once they match.
pub fn build_mls_commit_move(
    issuer: &str,
    space_id: &str,
    epoch_cell_subject: &str,
    new_epoch: u64,
    covered_frontier: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.mls.epoch.v1:{epoch_cell_subject}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": {
            "kind": "set",
            "value": {
                "epoch": new_epoch,
                "covered_frontier": covered_frontier,
            }
        }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Build an MLS commit Move that carries the canonical
/// [`mls_governance_binding.full.v1`] preconditions + effects from a
/// [`crate::mls_governance::GovernanceBindingPayload`].
///
/// Unlike [`build_mls_commit_move`] (which writes only the local epoch
/// cas-register and leaves preconditions empty), this builder threads
/// the SDK-derived precondition + effect tuples verbatim — the server
/// enforces `mls_governance_binding.full.v1` by checking that the Move's
/// `preconditions[]` and `effects[]` arrays match the SDK shape exactly,
/// so any drift here is server-rejected. The binding's canonical hash
/// is also added to the Move's `refs[]` so the proof chain is auditable.
///
/// Caller-supplied `prev_epoch` / `new_epoch` / `new_schedule` / etc.
/// live inside the binding — see
/// [`crate::mls_governance::GovernanceBindingPayload::from_anchor`] for
/// the constructor that validates those typed ids.
pub fn build_mls_commit_move_with_governance_binding(
    issuer: &str,
    space_id: &str,
    binding: &crate::mls_governance::GovernanceBindingPayload,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let preconditions: Vec<serde_json::Value> = binding
        .preconditions
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<_, _>>()
        .context("serialize governance binding preconditions")?;
    let effects: Vec<serde_json::Value> = binding
        .effects
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<_, _>>()
        .context("serialize governance binding effects")?;
    let binding_hash = binding
        .canonical_hash()
        .context("hash governance binding payload")?;
    // Carry the binding hash as a SemanticRef so the typed `Move.refs`
    // field round-trips it on the wire. `critical: true` tells the
    // reducer it MUST check this ref (the binding constitutes part of
    // the proof, not a hint).
    build_move_inner_with_preconditions_and_refs(
        issuer,
        space_id,
        preconditions,
        effects,
        anchor_ref,
        hlc,
        vec![serde_json::json!({
            "id": binding_hash,
            "role": "mls_governance_binding",
            "critical": true,
        })],
    )
}

/// Construct a `cx.component.flow.position.v1` Move that records a Flow's
/// position inside its containing Board Space. Used for the
/// canonical Move path of board-level entity create + move / position
/// update operations (kanban.rs add card / move card / add list).
///
/// `flow_id` is the cell subject (per-flow position cell). `value` is the
/// position record soland's reducer stores verbatim — typically:
///
///   `{"list_space_id": "cx:space:...", "rank": "r042", "title": "..."}`
///
/// Reducer treats the cell as a cas-register: concurrent writes from
/// two devices to the same flow_id surface as `bottom=expose` and the
/// admin operator can repair via [`build_conflict_repair_move`].
pub fn build_flow_position_move(
    issuer: &str,
    space_id: &str,
    flow_id: &str,
    value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.flow.position.v1:{flow_id}");
    // NOTE: the SDK's `LatticeOp` serializes the discriminator under
    // the wire-key `kind` (see `move_event.rs:LatticeOp.op_type`'s
    // `#[serde(rename = "kind")]`). Older revisions of this builder
    // used `"type"` which silently failed `parse_effects` deserialization
    // — the same issue is still present in the consent / capability /
    // member-state / space-organization / mls-commit builders below
    // and should be fixed in a follow-up sweep.
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "kind": "set", "value": value }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Identifies the cas-register cell that holds a Flow's position inside
/// a given Board. Per
/// [`spec/v1/zh/models/realm-and-space.md` §3.6](../../contrix-spec/spec/v1/zh/models/realm-and-space.md)
/// the cell key is `cx:cell:cx.component.flow.position.v1:<board_space_id>:<flow_id>`
/// — a Flow can appear on multiple Boards with **independent** position
/// cells, so the Board id is part of the subject.
pub fn flow_position_cell_id(board_space_id: &str, flow_id: &str) -> String {
    format!("cx:cell:cx.component.flow.position.v1:{board_space_id}:{flow_id}")
}

/// CAS pre-state that the caller expects to find on the position cell
/// before the Move applies. Compiled into a `head_eq` precondition per
/// [`spec/v1/zh/sync/operations-sync.md` §9.1](../../contrix-spec/spec/v1/zh/sync/operations-sync.md).
///
/// - `Initial` ⇒ `head_eq null` — the Flow is not yet on this Board.
/// - `At { list_space_id, rank }` ⇒ `head_eq { list_space_id, rank }` —
///   the Move expects the Flow to currently sit in `list_space_id` at
///   `rank`; any drift triggers `failed_precondition` and the caller
///   must rebase against the latest projection.
///
/// Omitting `expected_position` (passing `None` to the builder when the
/// cell is non-initial) is a spec violation — soland's reducer rejects
/// "blind writes" outside the initial-state path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowPositionExpectation {
    /// Flow not yet present on the target Board. Compiles to
    /// `head_eq null`.
    Initial,
    /// Flow currently at `(list_space_id, rank)` on the target Board.
    At { list_space_id: String, rank: String },
}

impl FlowPositionExpectation {
    /// Compile to the JSON value used as `predicate.value` in the
    /// canonical Move body. `Initial` becomes `null`; `At` becomes
    /// `{"list_space_id": ..., "rank": ...}`.
    fn to_predicate_value(&self) -> serde_json::Value {
        match self {
            Self::Initial => serde_json::Value::Null,
            Self::At {
                list_space_id,
                rank,
            } => serde_json::json!({
                "list_space_id": list_space_id,
                "rank": rank,
            }),
        }
    }
}

/// Effect value for a `cx.flow.move` / `cx.flow.reorder` Move. Compiles
/// to a cas-register `set` with `{"list_space_id", "rank"}` per
/// [`operations-sync.md` §9.1-9.2](../../contrix-spec/spec/v1/zh/sync/operations-sync.md).
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

impl FlowPositionEffect {
    fn to_op_value(&self) -> serde_json::Value {
        match self {
            Self::SetPosition {
                list_space_id,
                rank,
            } => serde_json::json!({
                "list_space_id": list_space_id,
                "rank": rank,
            }),
            Self::Remove => serde_json::Value::Null,
        }
    }
}

/// Construct a `cx.flow.move` / `cx.flow.reorder` Move that targets the
/// spec-canonical cell `cx:cell:cx.component.flow.position.v1:<board_space_id>:<flow_id>`
/// with a `head_eq` precondition expressing the caller's view of
/// pre-state. This is the spec-compliant replacement for the earlier
/// [`build_flow_position_move`] (which used a non-composite cell
/// subject and skipped CAS preconditions).
///
/// Per [`operations-sync.md` §9](../../contrix-spec/spec/v1/zh/sync/operations-sync.md):
///
/// - `expected_position == FlowPositionExpectation::Initial` is only
///   valid when the Flow has never been positioned on this Board;
///   reducer rejects with `failed_precondition` otherwise.
/// - Concurrent Moves that share a `head_eq` but emit different `set`
///   effects fold to `⊥` (kind=conflict) on the cas-register lattice;
///   dependent Moves `fail_bottom` and the caller MUST go through the
///   §8 conflict-recovery path (snapshot + state witness + retry with
///   refreshed `expected_position`).
///
/// Reorder vs move is encoded by the spec as a static schema rule: if
/// `effect.list_space_id == expected.list_space_id`, the Move is a
/// reorder; otherwise it's a cross-list move. Callers SHOULD set the
/// `kind` classifier on the wire envelope accordingly (`cx.flow.move`
/// vs `cx.flow.reorder`) so soland's audit + projection trail can
/// distinguish the two.
pub fn build_flow_position_cas_move(
    issuer: &str,
    space_id: &str,
    board_space_id: &str,
    flow_id: &str,
    expected_position: &FlowPositionExpectation,
    effect: &FlowPositionEffect,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = flow_position_cell_id(board_space_id, flow_id);
    let effect_value = serde_json::json!({
        "cell": cell_id,
        "op": { "kind": "set", "value": effect.to_op_value() }
    });
    let precondition = serde_json::json!({
        "cell": cell_id,
        "predicate": {
            "op": "head_eq",
            "value": expected_position.to_predicate_value(),
        }
    });
    build_move_inner_with_preconditions(
        issuer,
        space_id,
        vec![precondition],
        vec![effect_value],
        anchor_ref,
        hlc,
    )
}

/// Construct a conflict-repair Move that points at two (or more) competing
/// Anchor heads via `head_in` and references a `recovery_capability` so
/// soland's authz reducer accepts the merge. This is the admin-only /
/// moderator-only repair path for `bottom=expose` cells.
///
/// `cell_id` is the cell that has gone bottom (e.g. the
/// space.organization cell when two admins concurrently renamed a
/// Space). `conflict_heads` lists the competing Anchor ids — `head_in`
/// is set to that vector verbatim. `recovery_capability_ref` is the
/// id of the `cx.capability.grant` cell that authorises the repair.
/// `winner_value` is the merge result the operator chooses.
pub fn build_conflict_repair_move(
    issuer: &str,
    space_id: &str,
    cell_id: &str,
    conflict_heads: &[String],
    recovery_capability_ref: &str,
    winner_value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    if conflict_heads.len() < 2 {
        return Err(anyhow::anyhow!(
            "conflict repair requires at least 2 competing heads, got {}",
            conflict_heads.len()
        ));
    }
    // Splice `repair_of: [head_a, head_b, ...]` into the winner value so
    // the resulting cell value carries an audit trail of which conflict
    // it superseded. Spec: `authz/event-auth-state-resolution.md §8` and
    // conformance fixture `conflict_repair_fixture.json`. Scalar winner
    // values are wrapped under `{"value": <scalar>, "repair_of": [...]}`
    // so the audit field is always reachable.
    let repair_of: Vec<serde_json::Value> = conflict_heads
        .iter()
        .map(|h| serde_json::Value::String(h.clone()))
        .collect();
    let augmented_winner = match winner_value {
        serde_json::Value::Object(mut obj) => {
            obj.insert("repair_of".to_owned(), serde_json::Value::Array(repair_of));
            serde_json::Value::Object(obj)
        }
        other => {
            let mut obj = serde_json::Map::new();
            obj.insert("value".to_owned(), other);
            obj.insert("repair_of".to_owned(), serde_json::Value::Array(repair_of));
            serde_json::Value::Object(obj)
        }
    };
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": {
            "kind": "set",
            "value": augmented_winner,
        }
    });
    // Conflict repair body needs custom shape (head_in array +
    // recovery_capability ref) — go through a manual canonical body.
    let body = serde_json::json!({
        "issuer": issuer,
        "space_id": space_id,
        "preconditions": [
            {
                "kind": "head_in",
                "values": conflict_heads,
            },
            {
                "kind": "recovery_capability",
                "ref": recovery_capability_ref,
            }
        ],
        "effects": [effect.clone()],
        "anchor_ref": anchor_ref,
        "refs": conflict_heads,
        "hlc": hlc,
    });
    let canonical_bytes =
        canonical::canonical_json_bytes(&body).context("canonicalize repair move body")?;
    let payload_hash_str = canonical::sha256_digest(&canonical_bytes);
    let id_hex: String = Sha256::digest(&canonical_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let move_id = MoveId::new(format!("sha256:{id_hex}"))
        .map_err(|e| anyhow::anyhow!("derive move id: {e}"))?;
    // Build typed `refs` from conflict_heads — the SDK's `Move.refs`
    // is `Vec<MoveRef>` (or similar). For now we leave the typed list
    // empty and rely on the canonical body to carry the head_in
    // precondition; soland's wire-side reducer reads the body
    // directly. Once the SDK has a typed precondition struct, swap.
    let move_obj = Move {
        id: move_id,
        issuer: Did::new(issuer.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid issuer DID: {e}"))?,
        space_id: SpaceId::new(space_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid space id: {e}"))?,
        preconditions: vec![],
        effects: parse_effects(std::slice::from_ref(&effect))?,
        anchor_ref: AnchorId::new(anchor_ref.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid anchor_ref: {e}"))?,
        refs: vec![],
        hlc: Hlc::new(hlc.to_owned()).map_err(|e| anyhow::anyhow!("invalid hlc: {e}"))?,
        sig: MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#unsigned"),
            payload_hash: Hash::new(payload_hash_str)
                .map_err(|e| anyhow::anyhow!("payload hash: {e}"))?,
            created_at: chrono::Utc::now(),
            jws: String::new(),
        },
    };
    Ok(UnsignedMove {
        move_obj,
        canonical_bytes,
    })
}

/// Common Move-construction tail: take the typed pieces, build the
/// canonical body JSON, derive the Move id from `sha256(canonical_bytes)`,
/// stub the `sig` field with placeholder values, and return the unsigned
/// Move + the bytes that need signing. Callers run
/// [`sign_unsigned_move`] (or equivalent) before submitting.
fn build_move_inner(
    issuer: &str,
    space_id: &str,
    effects: Vec<serde_json::Value>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    build_move_inner_with_preconditions(issuer, space_id, vec![], effects, anchor_ref, hlc)
}

/// Variant of [`build_move_inner`] that accepts an explicit
/// `preconditions[]` array. Used by builders that emit CAS-style Moves
/// (`cx.flow.move` / `cx.flow.reorder` with `head_eq`); `build_move_inner`
/// keeps unconditional-write call sites compact.
fn build_move_inner_with_preconditions(
    issuer: &str,
    space_id: &str,
    preconditions: Vec<serde_json::Value>,
    effects: Vec<serde_json::Value>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    build_move_inner_with_preconditions_and_refs(
        issuer,
        space_id,
        preconditions,
        effects,
        anchor_ref,
        hlc,
        vec![],
    )
}

/// Variant of [`build_move_inner_with_preconditions`] that accepts an
/// explicit `refs[]` array. Used by builders that bind a Move to an
/// auxiliary canonical proof (e.g. a governance binding hash) the
/// reducer needs to validate alongside the preconditions/effects.
fn build_move_inner_with_preconditions_and_refs(
    issuer: &str,
    space_id: &str,
    preconditions: Vec<serde_json::Value>,
    effects: Vec<serde_json::Value>,
    anchor_ref: &str,
    hlc: &str,
    refs: Vec<serde_json::Value>,
) -> Result<UnsignedMove> {
    let body = serde_json::json!({
        "issuer": issuer,
        "space_id": space_id,
        "preconditions": preconditions,
        "effects": effects,
        "anchor_ref": anchor_ref,
        "refs": refs,
        "hlc": hlc,
    });
    let canonical_bytes =
        canonical::canonical_json_bytes(&body).context("canonicalize move body")?;
    let payload_hash_str = canonical::sha256_digest(&canonical_bytes);
    let id_hex: String = Sha256::digest(&canonical_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let move_id = MoveId::new(format!("sha256:{id_hex}"))
        .map_err(|e| anyhow::anyhow!("derive move id: {e}"))?;
    // Build typed Move with placeholder signature; the canonical_bytes
    // remain stable because `id` and `sig` are NOT part of the canonical
    // body (per `Move::canonical_bytes_for_id`).
    let move_obj = Move {
        id: move_id.clone(),
        issuer: Did::new(issuer.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid issuer DID: {e}"))?,
        space_id: SpaceId::new(space_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid space id: {e}"))?,
        preconditions: parse_preconditions(&preconditions)?,
        effects: parse_effects(&effects)?,
        anchor_ref: AnchorId::new(anchor_ref.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid anchor_ref: {e}"))?,
        refs: parse_refs(&refs)?,
        hlc: Hlc::new(hlc.to_owned()).map_err(|e| anyhow::anyhow!("invalid hlc: {e}"))?,
        sig: MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#unsigned"),
            payload_hash: Hash::new(payload_hash_str)
                .map_err(|e| anyhow::anyhow!("payload hash: {e}"))?,
            created_at: chrono::Utc::now(),
            jws: String::new(), // filled in by sign_unsigned_move
        },
    };
    Ok(UnsignedMove {
        move_obj,
        canonical_bytes,
    })
}

/// Re-parse the refs JSON array into typed [`contrix_sdk::SemanticRef`]
/// records. Refs carry auxiliary proof bindings (e.g. an MLS governance
/// binding hash) that the reducer validates alongside preconditions /
/// effects.
fn parse_refs(refs: &[serde_json::Value]) -> Result<Vec<contrix_sdk::SemanticRef>> {
    refs.iter()
        .map(|r| {
            serde_json::from_value::<contrix_sdk::SemanticRef>(r.clone())
                .map_err(|e| anyhow::anyhow!("invalid ref: {e}"))
        })
        .collect()
}

/// Re-parse the preconditions JSON array into typed
/// [`contrix_sdk::Precondition`] records. Mirrors [`parse_effects`].
fn parse_preconditions(
    preconditions: &[serde_json::Value],
) -> Result<Vec<contrix_sdk::Precondition>> {
    preconditions
        .iter()
        .map(|p| {
            serde_json::from_value::<contrix_sdk::Precondition>(p.clone())
                .map_err(|e| anyhow::anyhow!("invalid precondition: {e}"))
        })
        .collect()
}

/// Re-parse the effects JSON array into typed `Effect` records. The
/// builders construct effects as JSON for ergonomic shape composition;
/// this converts to the SDK type for the typed `Move.effects` field.
fn parse_effects(effects: &[serde_json::Value]) -> Result<Vec<Effect>> {
    effects
        .iter()
        .map(|e| {
            let cell_str = e
                .get("cell")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("effect missing `cell`"))?;
            let cell = CellRef::new(cell_str.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid cell ref: {e}"))?;
            let op_value = e
                .get("op")
                .ok_or_else(|| anyhow::anyhow!("effect missing `op`"))?
                .clone();
            let op: LatticeOp = serde_json::from_value(op_value)
                .map_err(|e| anyhow::anyhow!("invalid lattice op: {e}"))?;
            Ok(Effect { cell, op })
        })
        .collect()
}

/// Sign an [`UnsignedMove`] with an Ed25519 [`SigningKey`], producing a
/// detached JWS (RFC 7515 §3.2) over the canonical bytes. `verification_method`
/// is the DID URL fragment that resolves to the corresponding public key
/// (for `did:key:z<multibase>` the URL is `did:key:z<multibase>#z<multibase>`).
pub fn sign_unsigned_move(
    mut unsigned: UnsignedMove,
    signing_key: &SigningKey,
    verification_method: &str,
) -> Move {
    let header_json = br#"{"alg":"EdDSA"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&unsigned.canonical_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jws = format!("{header_b64}..{sig_b64}");
    unsigned.move_obj.sig.jws = jws;
    unsigned.move_obj.sig.verification_method = verification_method.to_owned();
    unsigned.move_obj
}

/// Encode an Ed25519 public key as the multibase form did:key DID URLs
/// + DID Document `verificationMethod` entries use:
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

/// Compose the verification_method DID URL for a did:key keypair
/// (`did:key:z<...>#z<...>`).
pub fn did_key_verification_method(verifying_key: &VerifyingKey) -> String {
    let mb = encode_ed25519_did_key_multibase(verifying_key);
    format!("did:key:{mb}#{mb}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_anchor_ref() -> &'static str {
        // SHA-256 of empty bytes — used as a "no predecessor" placeholder
        // for tests; production callers thread in the latest known
        // anchor frontier ref.
        "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    fn fixed_hlc() -> &'static str {
        // Some canonical HLC; tests don't enforce wall-clock here.
        "0189c4d2af00-0000-aabbccdd"
    }

    #[test]
    fn consent_grant_builder_produces_or_set_add_effect() {
        let did = "did:web:alice.example";
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let unsigned = build_consent_grant_move(
            did,
            space,
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(unsigned.move_obj.issuer.as_str(), did);
        assert_eq!(unsigned.move_obj.space_id.as_str(), space);
        assert_eq!(unsigned.move_obj.effects.len(), 1);
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.consent.grant.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
    }

    #[test]
    fn consent_revoke_builder_produces_or_set_remove_with_reason() {
        let unsigned = build_consent_revoke_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            Some("user revoked from settings UI"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.consent.grant.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
        assert_eq!(
            effect.op.reason.as_deref(),
            Some("user revoked from settings UI")
        );
    }

    #[test]
    fn consent_revoke_builder_omits_reason_when_none() {
        let unsigned = build_consent_revoke_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            None,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.reason, None);
    }

    #[test]
    fn capability_grant_builder_produces_or_set_add_effect() {
        let unsigned = build_capability_grant_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
    }

    #[test]
    fn capability_revoke_builder_produces_or_set_remove_with_reason() {
        let unsigned = build_capability_revoke_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            Some("rotation policy quarterly"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
        assert_eq!(
            effect.op.reason.as_deref(),
            Some("rotation policy quarterly")
        );
    }

    #[test]
    fn capability_constraint_input_temporal_renders_canonical_shape() {
        let c = CapabilityConstraintInput::temporal(
            Some("2026-05-09T00:00:00Z".to_owned()),
            Some("2026-08-09T00:00:00Z".to_owned()),
        );
        let v = c.to_constraint_value();
        assert_eq!(
            v.get("constraint_type").and_then(|x| x.as_str()),
            Some("temporal")
        );
        assert_eq!(
            v.get("subtype").and_then(|x| x.as_str()),
            Some("temporal.window")
        );
        assert_eq!(
            v.get("not_before").and_then(|x| x.as_str()),
            Some("2026-05-09T00:00:00Z")
        );
        assert_eq!(
            v.get("not_after").and_then(|x| x.as_str()),
            Some("2026-08-09T00:00:00Z")
        );
    }

    #[test]
    fn capability_constraint_input_temporal_skips_blank_bounds() {
        let c = CapabilityConstraintInput::temporal(None, Some("   ".to_owned()));
        assert!(!c.is_effective());
        let v = c.to_constraint_value();
        assert!(v.get("not_before").is_none());
        assert!(v.get("not_after").is_none());
    }

    #[test]
    fn capability_grant_with_temporal_constraint_attaches_value_constraints() {
        let constraint =
            CapabilityConstraintInput::temporal(Some("2026-05-09T00:00:00Z".to_owned()), None);
        let unsigned = build_capability_grant_move_with_constraints(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            std::slice::from_ref(&constraint),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
        let value = effect
            .op
            .value
            .as_ref()
            .expect("constraints embedded in value");
        let constraints = value
            .get("constraints")
            .and_then(|c| c.as_array())
            .expect("constraints array");
        assert_eq!(constraints.len(), 1);
        assert_eq!(
            constraints[0]
                .get("constraint_type")
                .and_then(|v| v.as_str()),
            Some("temporal")
        );
        assert_eq!(
            constraints[0].get("not_before").and_then(|v| v.as_str()),
            Some("2026-05-09T00:00:00Z")
        );
    }

    #[test]
    fn capability_grant_without_constraints_omits_empty_constraint_blob() {
        // Empty constraints are not serialized on the canonical wire.
        let with_empty = build_capability_grant_move_with_constraints(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            &[],
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let direct = build_capability_grant_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(with_empty.move_obj.id.as_str(), direct.move_obj.id.as_str());
        assert_eq!(with_empty.canonical_bytes, direct.canonical_bytes);
    }

    #[test]
    fn capability_grant_and_revoke_target_same_cell_family() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let granted = build_capability_grant_move(
            "did:web:admin.example",
            space,
            "cap.01abc",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let revoked = build_capability_revoke_move(
            "did:web:admin.example",
            space,
            "cap.01abc",
            "discussion.message.create",
            None,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        // Same cell subject — OrSet causal remove demands it.
        assert_eq!(
            granted.move_obj.effects[0].cell.as_str(),
            revoked.move_obj.effects[0].cell.as_str()
        );
        // Different op_type → different content-addressed move id.
        assert_ne!(granted.move_obj.id.as_str(), revoked.move_obj.id.as_str());
    }

    #[test]
    fn member_state_builder_produces_fsm_transition() {
        let unsigned = build_member_state_transition_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did.web.alice.example",
            "invited",
            "join",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.member.state.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(
            effect.op.from.as_ref().and_then(|v| v.as_str()),
            Some("invited")
        );
        assert_eq!(effect.op.to.as_ref().and_then(|v| v.as_str()), Some("join"));
    }

    #[test]
    fn space_organization_builder_produces_cas_register_set() {
        let unsigned = build_space_organization_update_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            serde_json::json!({"title": "Renamed", "owner": "did:web:admin.example"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.realm.organization.v1:")
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set op carries a value");
        assert_eq!(value.get("title").and_then(|v| v.as_str()), Some("Renamed"));
    }

    #[test]
    fn move_id_is_content_addressed_sha256_of_canonical_bytes() {
        let unsigned = build_consent_grant_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let recomputed: String = Sha256::digest(&unsigned.canonical_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            unsigned.move_obj.id.as_str(),
            format!("sha256:{recomputed}")
        );
    }

    #[test]
    fn signed_move_round_trip_verifies_with_dalek() {
        use ed25519_dalek::Verifier;
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let verifying = signing.verifying_key();
        let did = did_key_from_verifying_key(&verifying);
        let vm = did_key_verification_method(&verifying);

        let unsigned = build_consent_grant_move(
            &did,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let canonical_bytes = unsigned.canonical_bytes.clone();
        let signed = sign_unsigned_move(unsigned, &signing, &vm);
        // Reconstruct the JWS signing input the way a verifier would.
        let parts: Vec<&str> = signed.sig.jws.split('.').collect();
        assert_eq!(parts.len(), 3, "detached JWS has 3 segments");
        assert!(parts[1].is_empty(), "detached payload segment is empty");
        let header_b64 = parts[0];
        let signature_b64 = parts[2];
        let payload_b64 = URL_SAFE_NO_PAD.encode(&canonical_bytes);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        let signature_arr: [u8; 64] = signature_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
        // Real Ed25519 verify: must succeed for the matching public key.
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature should verify under matching pubkey");
    }

    #[test]
    fn mls_commit_move_targets_epoch_cell_and_carries_covered_frontier() {
        let unsigned = build_mls_commit_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            42,
            "cx:state:sha256:cffrontier01",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.mls.epoch.v1:"),
            "MLS commit must target mls.epoch.v1 cell"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set carries value");
        assert_eq!(value.get("epoch").and_then(|v| v.as_u64()), Some(42));
        assert_eq!(
            value.get("covered_frontier").and_then(|v| v.as_str()),
            Some("cx:state:sha256:cffrontier01")
        );
    }

    #[test]
    fn mls_commit_move_with_binding_attaches_sdk_preconditions_and_effects() {
        use crate::mls_governance::GovernanceBindingPayload;
        use contrix_sdk::{AnchorId, Hash, SpaceId};

        let space_id =
            SpaceId::new("cx:space:01964137-0000-7000-8000-000000000000".to_owned()).unwrap();
        let anchor = AnchorId::new(format!("cx:anchor:sha256:{}", "a".repeat(64))).unwrap();
        let schedule = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let binding = GovernanceBindingPayload::from_anchor(
            "mls-group-chat",
            &space_id,
            11,
            12,
            &schedule,
            &anchor,
        )
        .unwrap();

        let unsigned = build_mls_commit_move_with_governance_binding(
            "did:web:admin.example",
            space_id.as_str(),
            &binding,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();

        // Preconditions: SDK gives us two (epoch HeadEq + frontier
        // Contains). Effects: three (epoch set + schedule set + frontier
        // add). The reducer requires the wire shape match the SDK tuples
        // exactly; trimming or reordering would server-reject.
        assert_eq!(unsigned.move_obj.preconditions.len(), 2);
        assert_eq!(unsigned.move_obj.effects.len(), 3);

        // The binding's canonical hash MUST appear in the typed
        // Move.refs[] so the proof chain is auditable. `critical: true`
        // tells the reducer it MUST validate the binding ref (this is
        // proof material, not a hint).
        let binding_hash = binding.canonical_hash().unwrap();
        assert!(
            unsigned.move_obj.refs.iter().any(|r| {
                r.role == "mls_governance_binding" && r.id == binding_hash && r.critical
            }),
            "governance binding hash must be referenced in Move.refs"
        );
    }

    #[test]
    fn conflict_repair_move_requires_at_least_two_heads() {
        let result = build_conflict_repair_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            "cx:cell:cx.component.realm.organization.v1:cx:realm:0196419b-0000-7000-8000-000000000003",
            &["cx:anchor:sha256:only-one".to_owned()],
            "cap.recovery-01",
            serde_json::json!({"title": "merged"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        );
        match result {
            Err(err) => assert!(err.to_string().contains("at least 2")),
            Ok(_) => panic!("expected error for single-head repair Move"),
        }
    }

    #[test]
    fn conflict_repair_move_emits_head_in_and_recovery_preconditions() {
        let heads = vec![
            "cx:anchor:sha256:headA".to_owned(),
            "cx:anchor:sha256:headB".to_owned(),
        ];
        let unsigned = build_conflict_repair_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            "cx:cell:cx.component.realm.organization.v1:cx:realm:0196419b-0000-7000-8000-000000000003",
            &heads,
            "cap.recovery-01",
            serde_json::json!({"title": "merged"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&unsigned.canonical_bytes).unwrap();
        let preconditions = body
            .get("preconditions")
            .and_then(|v| v.as_array())
            .expect("preconditions array");
        assert_eq!(preconditions.len(), 2);
        let head_in = &preconditions[0];
        assert_eq!(
            head_in.get("kind").and_then(|v| v.as_str()),
            Some("head_in")
        );
        let head_values = head_in
            .get("values")
            .and_then(|v| v.as_array())
            .expect("head_in values array");
        assert_eq!(head_values.len(), 2);
        let recovery = &preconditions[1];
        assert_eq!(
            recovery.get("kind").and_then(|v| v.as_str()),
            Some("recovery_capability")
        );
        assert_eq!(
            recovery.get("ref").and_then(|v| v.as_str()),
            Some("cap.recovery-01")
        );
        // refs should round-trip the conflict heads on the wire body.
        let refs = body
            .get("refs")
            .and_then(|v| v.as_array())
            .expect("refs array");
        assert_eq!(refs.len(), 2);
        // Effect carries the chosen merge value AND the repair_of audit
        // trail listing the conflict heads it supersedes.
        let effect = &unsigned.move_obj.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().unwrap();
        assert_eq!(value.get("title").and_then(|v| v.as_str()), Some("merged"));
        let repair_of = value
            .get("repair_of")
            .and_then(|v| v.as_array())
            .expect("repair_of array on effect value");
        assert_eq!(repair_of.len(), 2);
        assert_eq!(repair_of[0].as_str(), Some("cx:anchor:sha256:headA"),);
        assert_eq!(repair_of[1].as_str(), Some("cx:anchor:sha256:headB"),);
    }

    #[test]
    fn conflict_repair_move_wraps_scalar_winner_under_value_field() {
        let heads = vec![
            "cx:anchor:sha256:headA".to_owned(),
            "cx:anchor:sha256:headB".to_owned(),
        ];
        let unsigned = build_conflict_repair_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            "cx:cell:cx.component.flow.position.v1:cx:flow:01abcd",
            &heads,
            "cap.recovery-01",
            // Scalar winner — must be wrapped so repair_of is reachable.
            serde_json::json!("merged-string-value"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        let value = effect.op.value.as_ref().unwrap();
        assert_eq!(
            value.get("value").and_then(|v| v.as_str()),
            Some("merged-string-value"),
        );
        assert_eq!(
            value
                .get("repair_of")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(2),
        );
    }

    #[test]
    fn flow_position_builder_targets_flow_position_cell_with_subject() {
        let unsigned = build_flow_position_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:flow:01abcd",
            serde_json::json!({
                "list_space_id": "cx:space:0196419b-0000-7000-8000-000000000001",
                "rank": "r042",
                "title": "Add tests",
            }),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert_eq!(
            effect.cell.as_str(),
            "cx:cell:cx.component.flow.position.v1:cx:flow:01abcd"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set carries value");
        assert_eq!(
            value.get("list_space_id").and_then(|v| v.as_str()),
            Some("cx:space:0196419b-0000-7000-8000-000000000001")
        );
        assert_eq!(value.get("rank").and_then(|v| v.as_str()), Some("r042"));
    }

    /// spec/v1/zh/models/realm-and-space.md §3.6: the position cell key is
    /// `cx:cell:cx.component.flow.position.v1:<board_space_id>:<flow_id>`.
    /// This pins the composite subject so a future refactor that drops one
    /// segment fails loudly.
    #[test]
    fn flow_position_cell_id_is_composite_board_flow() {
        let cell = flow_position_cell_id(
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:01abcd",
        );
        assert_eq!(
            cell,
            "cx:cell:cx.component.flow.position.v1:cx:space:0196419b-0000-7000-8000-000000000010:cx:flow:01abcd"
        );
    }

    /// Initial-entry CAS Move: `head_eq null` precondition and a
    /// `set { list_space_id, rank }` effect that carries the spec cell
    /// shape (spec field names only).
    ///
    /// We assert against the canonical body bytes — `Option<Value>` in
    /// the typed SDK structs loses the literal `null` on round-trip, but
    /// the body bytes (which seed the Move id and the JWS) are
    /// authoritative.
    #[test]
    fn flow_position_cas_move_initial_emits_head_eq_null_and_spec_effect() {
        let unsigned = build_flow_position_cas_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:01abcd",
            &FlowPositionExpectation::Initial,
            &FlowPositionEffect::SetPosition {
                list_space_id: "cx:space:0196419b-0000-7000-8000-000000000020".to_owned(),
                rank: "mV".to_owned(),
            },
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&unsigned.canonical_bytes).unwrap();
        let pre = &body["preconditions"][0];
        assert_eq!(
            pre["cell"].as_str(),
            Some(
                "cx:cell:cx.component.flow.position.v1:cx:space:0196419b-0000-7000-8000-000000000010:cx:flow:01abcd"
            )
        );
        assert_eq!(pre["predicate"]["op"].as_str(), Some("head_eq"));
        assert!(
            pre["predicate"]["value"].is_null(),
            "Initial expectation must serialize as head_eq null, got {}",
            pre["predicate"]["value"],
        );
        let effect = &body["effects"][0];
        assert_eq!(effect["op"]["kind"].as_str(), Some("set"));
        assert_eq!(
            effect["op"]["value"]["list_space_id"].as_str(),
            Some("cx:space:0196419b-0000-7000-8000-000000000020"),
            "spec cell shape uses list_space_id, not list_id",
        );
        assert_eq!(effect["op"]["value"]["rank"].as_str(), Some("mV"));
    }

    /// Cross-list move: `head_eq { list_space_id, rank }` precondition
    /// reflects the prior position; effect points at the new list. This
    /// is the wire shape soland's reducer expects per operations-sync.md
    /// §9.1.
    #[test]
    fn flow_position_cas_move_with_expected_position_emits_head_eq_value() {
        let unsigned = build_flow_position_cas_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:01abcd",
            &FlowPositionExpectation::At {
                list_space_id: "cx:space:0196419b-0000-7000-8000-000000000030".to_owned(),
                rank: "h0".to_owned(),
            },
            &FlowPositionEffect::SetPosition {
                list_space_id: "cx:space:0196419b-0000-7000-8000-000000000020".to_owned(),
                rank: "mV".to_owned(),
            },
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&unsigned.canonical_bytes).unwrap();
        let pre = &body["preconditions"][0]["predicate"];
        assert_eq!(pre["op"].as_str(), Some("head_eq"));
        assert_eq!(
            pre["value"]["list_space_id"].as_str(),
            Some("cx:space:0196419b-0000-7000-8000-000000000030")
        );
        assert_eq!(pre["value"]["rank"].as_str(), Some("h0"));
        let effect = &body["effects"][0];
        assert_eq!(
            effect["op"]["value"]["list_space_id"].as_str(),
            Some("cx:space:0196419b-0000-7000-8000-000000000020")
        );
        assert_eq!(effect["op"]["value"]["rank"].as_str(), Some("mV"));
    }

    /// Removing a Flow from a Board: `set null` effect retires the
    /// derived `contains` Relation on soland's reducer.
    #[test]
    fn flow_position_cas_move_remove_emits_set_null_effect() {
        let unsigned = build_flow_position_cas_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:01abcd",
            &FlowPositionExpectation::At {
                list_space_id: "cx:space:0196419b-0000-7000-8000-000000000040".to_owned(),
                rank: "zz".to_owned(),
            },
            &FlowPositionEffect::Remove,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&unsigned.canonical_bytes).unwrap();
        let effect_op = &body["effects"][0]["op"];
        assert_eq!(effect_op["kind"].as_str(), Some("set"));
        assert!(
            effect_op["value"].is_null(),
            "remove effect must serialize as set null, got {}",
            effect_op["value"],
        );
    }

    /// In-list reorder: `expected.list_space_id == effect.list_space_id`.
    /// Reducer-side schema rule distinguishes this from cross-list move.
    #[test]
    fn flow_position_cas_move_in_list_reorder_keeps_same_list() {
        let list = "cx:space:0196419b-0000-7000-8000-000000000050".to_owned();
        let unsigned = build_flow_position_cas_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:01abcd",
            &FlowPositionExpectation::At {
                list_space_id: list.clone(),
                rank: "h0".to_owned(),
            },
            &FlowPositionEffect::SetPosition {
                list_space_id: list.clone(),
                rank: "mV".to_owned(),
            },
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&unsigned.canonical_bytes).unwrap();
        let pre_list = body["preconditions"][0]["predicate"]["value"]["list_space_id"]
            .as_str()
            .unwrap();
        let post_list = body["effects"][0]["op"]["value"]["list_space_id"]
            .as_str()
            .unwrap();
        assert_eq!(
            pre_list, post_list,
            "reorder requires expected.list_space_id == effect.list_space_id",
        );
    }

    #[test]
    fn did_key_verification_method_round_trips() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let did = did_key_from_verifying_key(&verifying);
        let vm = did_key_verification_method(&verifying);
        // verification_method should be `<did>#<multibase>`; the `#`
        // suffix matches the DID itself per did:key §3.
        let (prefix, frag) = vm.split_once('#').unwrap();
        assert_eq!(prefix, did);
        assert!(frag.starts_with('z'));
        assert_eq!(format!("{prefix}#{frag}"), vm);
    }
}
