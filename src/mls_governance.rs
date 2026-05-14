//! MLS Governance Binding helpers (`cx.profile.mls_governance_binding.full.v1`).
//!
//! Spec: `crypto-media/encryption-and-audit.md` §10. Every MLS commit MUST
//! carry preconditions binding it to:
//! 1. the previous MLS epoch (`mls_epoch_cell.head_eq(prev_epoch)`) — racing
//!    commits fail closed.
//! 2. the Space's `covered_frontier_cell.contains(required_governance_anchor)`
//!    — the commit MUST already cover the governance anchor it asserts.
//!
//! The commit's effects then:
//! 1. set `mls_epoch_cell` to the new epoch.
//! 2. set `key_schedule_cell` to the new schedule's content hash.
//! 3. add the attested governance anchor to `covered_frontier_cell`.
//!
//! This module wraps `contrix_sdk::mls_move::*` so yougen's MLS commit path
//! can produce the canonical precondition / effect tuples and serialize them
//! as a `governance_binding` payload alongside the commit Move.

use serde::{Deserialize, Serialize};

use contrix_sdk::mls_move::{
    covered_frontier_cell_id, governance_frontier_tag, mls_commit_effects,
    mls_commit_preconditions,
};
use contrix_sdk::{AnchorId, Hash, SpaceId};

/// Serializable view of the MLS Governance Binding payload that travels with
/// an `cx.mls.commit` event. Keeps yougen call sites typed without forcing
/// every UI module to depend on `contrix_sdk::Precondition` / `Effect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GovernanceBindingPayload {
    /// MLS group id (Space-scoped).
    pub group_id: String,
    /// `cx:space:` typed-id.
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
        // Force the SDK builders to validate inputs even though we don't
        // serialize the Precondition / Effect structures directly.
        let _ = mls_commit_preconditions(
            &group_id,
            space_id,
            prev_epoch,
            attested_governance_anchor,
        )
        .map_err(|e| anyhow::anyhow!("mls_commit_preconditions invalid: {e:?}"))?;
        let _ = mls_commit_effects(
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
        })
    }

    /// Canonical hash of the binding payload, suitable for inclusion in the
    /// MLS commit event's proof / refs.
    pub fn canonical_hash(&self) -> anyhow::Result<String> {
        crate::canonical::canonical_sha256(self)
    }
}

/// The `cx.profile.mls_governance_binding.full.v1` profile id. Mirrors the
/// hardening profile registered in `spec/v1/artifacts/profiles/conformance-profiles.json`.
pub const PROFILE_MLS_GOVERNANCE_BINDING_FULL: &str =
    "cx.profile.mls_governance_binding.full.v1";

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_sdk::{AnchorId, Hash, SpaceId};

    fn space_id() -> SpaceId {
        SpaceId::new("cx:space:01964137-0000-7000-8000-000000000000".to_owned()).unwrap()
    }

    fn anchor() -> AnchorId {
        AnchorId::new(format!("cx:anchor:sha256:{}", "a".repeat(64))).unwrap()
    }

    fn schedule_hash() -> Hash {
        Hash::new(format!(
            "sha256:{}",
            "0".repeat(64)
        ))
        .unwrap()
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
        assert_eq!(
            payload.covered_frontier_tag,
            anchor().as_str()
        );
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
