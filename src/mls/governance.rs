//! MLS Governance Binding helpers (`cx.profile.mls_governance_binding.full.v1`).
//!
//! Spec: `crypto-media/encryption-and-audit.md` §10. Every MLS commit MUST
//! carry preconditions binding it to:
//! 1. the previous MLS epoch (`mls_epoch_cell.head_eq(prev_epoch)`) — racing commits fail closed.
//! 2. the Space's `covered_frontier_cell.contains(required_governance_anchor)` — the commit MUST
//!    already cover the governance anchor it asserts.
//!
//! The commit's effects then:
//! 1. set `mls_epoch_cell` to the new epoch.
//! 2. set `key_schedule_cell` to the new schedule's content hash.
//! 3. add the attested governance anchor to `covered_frontier_cell`.
//!
//! This module wraps `cokret_sdk::mls_move::*` so yougen can produce the
//! canonical Move precondition / effect tuples used by the hardening profile.
//! It is not the `cx.mls.commit` event payload type; event payloads must use
//! `cokret_sdk::MlsCommitPayload` and `cokret_sdk::MlsGovernanceBindingPayload`.

use cokret_sdk::mls_move::{
    covered_frontier_cell_id, governance_frontier_tag, mls_commit_effects, mls_commit_preconditions,
};
use cokret_sdk::{AnchorId, Effect, Hash, Precondition, SpaceId};
use serde::{Deserialize, Serialize};

/// Serializable view of the MLS Governance Binding Move tuple set. Keeps
/// Move-builder call sites typed without forcing every module to depend on
/// `cokret_sdk::Precondition` / `Effect`.
///
/// Both the human-readable summary fields (epoch / schedule / anchor /
/// frontier cell) and the **full SDK Precondition + Effect tuples** are
/// carried. The summary fields make Audit / Conflict UIs cheap to render;
/// the tuples are what MLS governance Moves attach so the server can enforce
/// `mls_governance_binding.full.v1` (spec §10) without the client re-deriving
/// them. Both flow into `canonical_hash`, so changes to either fork yield a
/// distinct binding hash when threading the binding through Move proof refs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GovernanceBindingPayload {
    /// MLS group id (Space-scoped).
    pub group_id: String,
    /// `ck:space:` typed-id.
    pub space_id: String,
    /// Epoch the commit advances from.
    pub prev_epoch: u64,
    /// Epoch the commit advances to.
    pub new_epoch: u64,
    /// Content hash (`sha256:<hex>`) of the new MLS key schedule.
    pub new_schedule_hash: String,
    /// Governance Anchor id this commit asserts coverage of.
    pub attested_governance_anchor: String,
    /// Cell ref string of the Space's `covered_frontier_cell`.
    pub covered_frontier_cell: String,
    /// Tag string written into the `covered_frontier_cell` or-set entry.
    pub covered_frontier_tag: String,
    /// Canonical SDK preconditions the server MUST enforce.
    pub preconditions: Vec<Precondition>,
    /// Canonical SDK effects the commit applies on success.
    pub effects: Vec<Effect>,
}

impl GovernanceBindingPayload {
    /// Build a binding payload from the typed Anchor + schedule hash. Returns
    /// `Err` if the typed ids fail validation.
    pub fn from_anchor(
        group_id: impl Into<String>,
        space_id: &SpaceId,
        prev_epoch: u64,
        new_epoch: u64,
        new_schedule: &Hash,
        attested_governance_anchor: &AnchorId,
    ) -> anyhow::Result<Self> {
        let group_id = group_id.into();
        // Capture (do not discard) the SDK's canonical precondition + effect
        // tuples so the resulting Move body carries them verbatim. The
        // server enforces `mls_governance_binding.full.v1` by checking that
        // the submitted Move's preconditions/effects EXACTLY match these
        // SDK-derived shapes — yougen must not re-derive or shorten them.
        let preconditions =
            mls_commit_preconditions(&group_id, space_id, prev_epoch, attested_governance_anchor)
                .map_err(|e| anyhow::anyhow!("mls_commit_preconditions invalid: {e:?}"))?;
        let effects = mls_commit_effects(
            &group_id,
            space_id,
            new_epoch,
            new_schedule,
            attested_governance_anchor,
        )
        .map_err(|e| anyhow::anyhow!("mls_commit_effects invalid: {e:?}"))?;

        let frontier_cell = covered_frontier_cell_id(space_id)
            .map_err(|e| anyhow::anyhow!("covered_frontier_cell_id invalid: {e:?}"))?;

        Ok(Self {
            group_id,
            space_id: space_id.as_str().to_owned(),
            prev_epoch,
            new_epoch,
            new_schedule_hash: new_schedule.as_str().to_owned(),
            attested_governance_anchor: attested_governance_anchor.as_str().to_owned(),
            covered_frontier_cell: frontier_cell.as_str().to_owned(),
            covered_frontier_tag: governance_frontier_tag(attested_governance_anchor),
            preconditions,
            effects,
        })
    }

    /// Canonical hash of the binding payload, suitable for inclusion in the
    /// MLS governance Move's proof / refs.
    pub fn canonical_hash(&self) -> anyhow::Result<String> {
        crate::canonical::canonical_sha256(self)
    }

    /// Render the binding as the legacy/internal Move tuple JSON shape.
    ///
    /// Do not use this as a `cx.mls.commit` event payload. That wire surface
    /// is sealed by `cokret_sdk::MlsCommitPayload`.
    pub fn to_move_binding_body(&self) -> serde_json::Value {
        serde_json::json!({
            "group_id": &self.group_id,
            "space_id": &self.space_id,
            "prev_epoch": self.prev_epoch,
            "new_epoch": self.new_epoch,
            "new_schedule_hash": &self.new_schedule_hash,
            "attested_governance_anchor": &self.attested_governance_anchor,
            "covered_frontier_cell": &self.covered_frontier_cell,
            "covered_frontier_tag": &self.covered_frontier_tag,
            "preconditions": &self.preconditions,
            "effects": &self.effects,
        })
    }
}

/// The `cx.profile.mls_governance_binding.full.v1` profile id. Mirrors the
/// hardening profile registered in `spec/v1/artifacts/profiles/conformance-profiles.json`.
pub const PROFILE_MLS_GOVERNANCE_BINDING_FULL: &str = "cx.profile.mls_governance_binding.full.v1";

#[cfg(test)]
mod tests {
    use cokret_sdk::{AnchorId, Hash, SpaceId};

    use super::*;

    fn space_id() -> SpaceId {
        SpaceId::new("ck:space:01964137-0000-7000-8000-000000000000".to_owned()).unwrap()
    }

    fn anchor() -> AnchorId {
        AnchorId::new(format!("ck:anchor:sha256:{}", "a".repeat(64))).unwrap()
    }

    fn schedule_hash() -> Hash {
        Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap()
    }

    #[test]
    fn payload_carries_covered_frontier_cell() {
        let payload = GovernanceBindingPayload::from_anchor(
            "mls-group-1",
            &space_id(),
            7,
            8,
            &schedule_hash(),
            &anchor(),
        )
        .unwrap();
        assert_eq!(payload.prev_epoch, 7);
        assert_eq!(payload.new_epoch, 8);
        assert!(payload.covered_frontier_cell.contains("covered_frontier"));
        assert_eq!(payload.covered_frontier_tag, anchor().as_str());
    }

    #[test]
    fn payload_carries_sdk_preconditions_and_effects() {
        let payload = GovernanceBindingPayload::from_anchor(
            "mls-group-1",
            &space_id(),
            7,
            8,
            &schedule_hash(),
            &anchor(),
        )
        .unwrap();
        // Spec §10 requires exactly two preconditions (epoch + frontier)
        // and three effects (epoch set / schedule set / frontier add).
        // The server enforces this shape verbatim — if either side trims
        // a tuple the commit MUST fail validation.
        assert_eq!(payload.preconditions.len(), 2);
        assert_eq!(payload.effects.len(), 3);
        let body = payload.to_move_binding_body();
        assert_eq!(body["preconditions"].as_array().map(|a| a.len()), Some(2));
        assert_eq!(body["effects"].as_array().map(|a| a.len()), Some(3));
    }

    #[test]
    fn canonical_hash_changes_with_epoch() {
        let a = GovernanceBindingPayload::from_anchor(
            "g",
            &space_id(),
            1,
            2,
            &schedule_hash(),
            &anchor(),
        )
        .unwrap()
        .canonical_hash()
        .unwrap();
        let b = GovernanceBindingPayload::from_anchor(
            "g",
            &space_id(),
            1,
            3,
            &schedule_hash(),
            &anchor(),
        )
        .unwrap()
        .canonical_hash()
        .unwrap();
        assert_ne!(a, b);
    }
}
