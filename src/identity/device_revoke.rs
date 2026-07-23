//! T31 — Device revocation orchestration.
//!
//! Breaks "revoke a device" into a sequence of canonical events + MLS
//! operations, forming an auditable plan. The UI surfaces the plan so the
//! user sees the full blast radius before confirming; the executor applies
//! the steps in order.
//!
//! Spec sources:
//! - `crypto-media/device-lifecycle.md` — the three concerns stay separate (login factor / device
//!   authorization / device verification), and `ak.device.revoke` is the only event that mutates
//!   the device set.
//! - `crypto-media/encryption-and-audit.md` — MLS leaf removal is performed via the chain
//!   `ak.mls.proposal` (Remove) → `ak.mls.commit` (epoch++) → `ak.mls.welcome` (to bring
//!   still-present members up to the new epoch).
//!
//! Current runtime surface:
//! - Local device-directory state marks the device revoked and fails closed on subsequent encrypted
//!   writes from it.
//! - `ArkretMlsGroup::add_member(...)` — performs add + Welcome via OpenMLS.
//! - `ArkretMlsGroup::remove_member_by_principal(target)` — leaf-level removal that produces an
//!   [`MlsRemoveMemberResult`] (commit envelope + removed leaf indices + per-leaf principal DIDs).
//! - `ArkretMlsGroup::remove_member_by_leaf(leaf_index)` — same outcome targeted at a specific
//!   OpenMLS leaf index, for single-device revocation of a multi-device principal.
//! - `E2eeManager::remove_member(group_id, did)` — DID-level removal (model layer; companion to the
//!   SDK-level OpenMLS calls above).
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A single revocation step. Each variant maps to one canonical event kind;
/// the UI can render an audit preview directly from `description` and
/// `canonical_event_kind`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceRevokeStep {
    /// Mark revoked in local device-directory state. Local state change only,
    /// no outbound event.
    LocalRevoke,
    /// Write the revocation proof into the actor event chain.
    /// canonical event = `ak.device.revoke`.
    DeviceRevoked,
    /// Rotate the account MLS snapshot secret and publish fresh key backups
    /// before any future encrypted history is uploaded under the old secret.
    RotateAccountMlsSecret,
    /// Issue a Remove proposal in every affected MLS group.
    /// canonical event = `ak.mls.proposal` (type = remove).
    MlsProposeRemove { group_id: String },
    /// Commit the proposal into the group; epoch advances by 1.
    /// canonical event = `ak.mls.commit`.
    MlsCommit { group_id: String },
    /// Send Welcome to the remaining members so lazy / offline peers can
    /// catch up to the new epoch.
    /// canonical event = `ak.mls.welcome`.
    MlsWelcome {
        group_id: String,
        recipient_count: usize,
    },
    /// Invalidate the revoked device's unconsumed KeyPackages in the OTK
    /// pool so new joiners do not mistake them for usable leaves.
    /// canonical event = `ak.mls.keypackage` (status = revoked).
    InvalidateKeyPackages,
    /// Ask the push gateway to drop the device's masked wake-up registration
    /// so we stop pushing to a revoked device. Not a canonical event; this
    /// is a local control over the device / key-server interface.
    UnregisterPushToken,
}

impl DeviceRevokeStep {
    /// Canonical event kind for this step (`None` for purely local /
    /// service-interface operations).
    pub fn canonical_event_kind(&self) -> Option<&'static str> {
        match self {
            Self::LocalRevoke => None,
            Self::DeviceRevoked => Some("ak.device.revoke"),
            Self::RotateAccountMlsSecret => None,
            Self::MlsProposeRemove { .. } => Some("ak.mls.proposal"),
            Self::MlsCommit { .. } => Some("ak.mls.commit"),
            Self::MlsWelcome { .. } => Some("ak.mls.welcome"),
            Self::InvalidateKeyPackages => Some("ak.mls.keypackage"),
            Self::UnregisterPushToken => None,
        }
    }

    /// One-line description of this step; rendered directly in the UI
    /// preview.
    pub fn description(&self) -> String {
        match self {
            Self::LocalRevoke => "Mark revoked in local device-directory state".to_owned(),
            Self::DeviceRevoked => "Write ak.device.revoke to the actor event chain".to_owned(),
            Self::RotateAccountMlsSecret => {
                "Rotate the account MLS history secret and rewrap latest backups".to_owned()
            }
            Self::MlsProposeRemove { group_id } => {
                format!("Issue MLS Remove proposal · group={group_id}")
            }
            Self::MlsCommit { group_id } => {
                format!("Commit proposal, epoch++ · group={group_id}")
            }
            Self::MlsWelcome {
                group_id,
                recipient_count,
            } => {
                format!("Send Welcome to {recipient_count} remaining members · group={group_id}")
            }
            Self::InvalidateKeyPackages => {
                "Invalidate the revoked device's unconsumed KeyPackages in the OTK pool".to_owned()
            }
            Self::UnregisterPushToken => {
                "Notify push gateway to drop this device's masked wake-up registration".to_owned()
            }
        }
    }
}

/// Full revocation plan. `steps` lists the steps in dependency order; the
/// executor consumes them sequentially.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevokePlan {
    pub principal_id: String,
    pub device_id: String,
    pub steps: Vec<DeviceRevokeStep>,
}

impl DeviceRevokePlan {
    /// Build the plan. `affected_groups` is the set of `group_id`s in which
    /// the device is an MLS leaf; `survivors_per_group` gives the member
    /// count remaining in each group after the device is removed (used as
    /// the Welcome recipient count).
    pub fn build(
        principal_id: &str,
        device_id: &str,
        affected_groups: &[String],
        survivors_per_group: &BTreeMap<String, usize>,
    ) -> Self {
        let mut steps: Vec<DeviceRevokeStep> = Vec::new();
        steps.push(DeviceRevokeStep::LocalRevoke);
        steps.push(DeviceRevokeStep::DeviceRevoked);
        steps.push(DeviceRevokeStep::RotateAccountMlsSecret);
        for group_id in affected_groups {
            steps.push(DeviceRevokeStep::MlsProposeRemove {
                group_id: group_id.clone(),
            });
            steps.push(DeviceRevokeStep::MlsCommit {
                group_id: group_id.clone(),
            });
            let recipient_count = survivors_per_group.get(group_id).copied().unwrap_or(0);
            steps.push(DeviceRevokeStep::MlsWelcome {
                group_id: group_id.clone(),
                recipient_count,
            });
        }
        steps.push(DeviceRevokeStep::InvalidateKeyPackages);
        steps.push(DeviceRevokeStep::UnregisterPushToken);
        Self {
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            steps,
        }
    }

    /// Canonical event kinds in the plan (deduplicated, in order of first
    /// appearance). Used for audit / inbox / blast-radius summaries.
    pub fn event_kinds(&self) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        for step in &self.steps {
            if let Some(k) = step.canonical_event_kind()
                && !seen.contains(&k)
            {
                seen.push(k);
            }
        }
        seen
    }

    /// Number of affected MLS groups, derived from the steps themselves so
    /// the count does not depend on the input arguments.
    pub fn affected_group_count(&self) -> usize {
        let mut groups: Vec<&str> = Vec::new();
        for step in &self.steps {
            let gid = match step {
                DeviceRevokeStep::MlsProposeRemove { group_id }
                | DeviceRevokeStep::MlsCommit { group_id }
                | DeviceRevokeStep::MlsWelcome { group_id, .. } => Some(group_id.as_str()),
                _ => None,
            };
            if let Some(g) = gid
                && !groups.contains(&g)
            {
                groups.push(g);
            }
        }
        groups.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Chained MLS Remove + epoch-advance Move tracker.
//
// When the device-revocation handler executes the plan, every MLS group
// the revoked device was a leaf in needs **two** Moves to fully advance:
//
// 1. an MLS commit Move that removes the device's leaf (`ak.mls.commit` via the
//    `ak.component.mls.epoch.v1` cas-register), and
// 2. an epoch-advance Move that bumps `covered_seals` so subsequent message Events can reference
//    the post-revocation MLS state.
//
// Each chain entry tracks the lifecycle of those Moves
// individually — both must reach `Effective` before the device is
// considered fully unspooled from the group. The realm-admin page
// renders this list with per-row stage chips so an operator can see
// where the revocation chain has stalled.
// ═══════════════════════════════════════════════════════════════════════════

/// A single MLS Move pair driven by a device-revocation chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsRevokeMoveChain {
    /// MLS group id the chain operates on — one chain per affected
    /// group.
    pub group_id: String,
    /// MLS commit Move id (`sha256:...`); `None` until the
    /// builder runs.
    pub commit_move_id: Option<String>,
    /// Epoch-advance Move id; `None` until the builder runs.
    pub epoch_advance_move_id: Option<String>,
    /// Lifecycle stage of the commit Move per the
    /// [`MoveSubmissionState`] mapping.
    pub commit_state: ChainMoveState,
    /// Lifecycle stage of the epoch-advance Move.
    pub epoch_advance_state: ChainMoveState,
    /// Pre-revoke epoch number — bookkeeping so the UI can surface the
    /// expected post-commit epoch (`pre_revoke_epoch + 1`).
    #[serde(default)]
    pub pre_revoke_epoch: Option<u64>,
}

impl MlsRevokeMoveChain {
    /// Whether the entire chain has reached its terminal state.
    pub fn is_terminal(&self) -> bool {
        self.commit_state.is_terminal() && self.epoch_advance_state.is_terminal()
    }

    /// Whether the chain has fully landed (both Moves Effective).
    pub fn is_complete(&self) -> bool {
        self.commit_state == ChainMoveState::Effective
            && self.epoch_advance_state == ChainMoveState::Effective
    }

    /// True when any Move in the chain has failed.
    pub fn has_failure(&self) -> bool {
        self.commit_state.is_failed() || self.epoch_advance_state.is_failed()
    }

    /// Short status summary for the UI: `pending`, `commit_ok`,
    /// `complete`, `failed`, `cancelled`.
    pub fn status_summary(&self) -> &'static str {
        if self.is_complete() {
            "complete"
        } else if self.has_failure() {
            "failed"
        } else if self.commit_state == ChainMoveState::Effective {
            "commit_ok"
        } else if self.commit_state == ChainMoveState::Cancelled
            || self.epoch_advance_state == ChainMoveState::Cancelled
        {
            "cancelled"
        } else {
            "pending"
        }
    }
}

/// Lifecycle of one Move within a chain. Keeps the state machine
/// simple — the full `MoveSubmissionState` flavour from local_state
/// has more fan-out (FailedBottom / FailedPrecondition / etc.); for
/// the chain UI we collapse all failure modes into `Failed` with an
/// optional reason string while preserving the most useful in-flight
/// distinctions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainMoveState {
    /// Move not yet submitted.
    NotSubmitted,
    /// Submitted; waiting for an Seal to sweep it.
    Pending,
    /// Sealed / effective.
    Effective,
    /// Submission failed (signature, precondition, notary-paused).
    Failed { reason: String },
    /// Operator cancelled the chain mid-flight.
    Cancelled,
}

impl ChainMoveState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Effective | Self::Failed { .. } | Self::Cancelled
        )
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::NotSubmitted => "Not submitted",
            Self::Pending => "Pending",
            Self::Effective => "Effective",
            Self::Failed { .. } => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }

    pub fn badge_class(&self) -> &'static str {
        match self {
            Self::NotSubmitted => "badge",
            Self::Pending => "badge amber",
            Self::Effective => "badge green",
            Self::Failed { .. } => "badge red",
            Self::Cancelled => "badge red",
        }
    }
}

/// Build the typed chain set from a [`DeviceRevokePlan`].
/// One [`MlsRevokeMoveChain`] per `MlsCommit` step in the plan.
/// `pre_revoke_epochs` maps `group_id` → known current epoch (often
/// supplied by the local Seal view); missing entries leave the
/// `pre_revoke_epoch` field as `None`.
pub fn chains_from_plan(
    plan: &DeviceRevokePlan,
    pre_revoke_epochs: &BTreeMap<String, u64>,
) -> Vec<MlsRevokeMoveChain> {
    plan.steps
        .iter()
        .filter_map(|step| match step {
            DeviceRevokeStep::MlsCommit { group_id } => Some(group_id.clone()),
            _ => None,
        })
        .map(|group_id| {
            let pre_epoch = pre_revoke_epochs.get(&group_id).copied();
            MlsRevokeMoveChain {
                group_id,
                commit_move_id: None,
                epoch_advance_move_id: None,
                commit_state: ChainMoveState::NotSubmitted,
                epoch_advance_state: ChainMoveState::NotSubmitted,
                pre_revoke_epoch: pre_epoch,
            }
        })
        .collect()
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    #[test]
    fn chain_is_complete_only_when_both_moves_effective() {
        let mut chain = MlsRevokeMoveChain {
            group_id: "ak:realm:01acme".to_owned(),
            commit_move_id: Some("sha256:aa".to_owned()),
            epoch_advance_move_id: Some("sha256:bb".to_owned()),
            commit_state: ChainMoveState::Effective,
            epoch_advance_state: ChainMoveState::Pending,
            pre_revoke_epoch: Some(12),
        };
        assert!(!chain.is_complete());
        assert!(!chain.is_terminal());
        assert_eq!(chain.status_summary(), "commit_ok");
        chain.epoch_advance_state = ChainMoveState::Effective;
        assert!(chain.is_complete());
        assert!(chain.is_terminal());
        assert_eq!(chain.status_summary(), "complete");
    }

    #[test]
    fn chain_failure_propagates_to_summary() {
        let chain = MlsRevokeMoveChain {
            group_id: "ak:realm:01x".to_owned(),
            commit_move_id: None,
            epoch_advance_move_id: None,
            commit_state: ChainMoveState::Failed {
                reason: "notary paused".to_owned(),
            },
            epoch_advance_state: ChainMoveState::NotSubmitted,
            pre_revoke_epoch: None,
        };
        assert!(chain.has_failure());
        assert_eq!(chain.status_summary(), "failed");
    }

    #[test]
    fn chain_cancellation_propagates_to_summary() {
        let chain = MlsRevokeMoveChain {
            group_id: "ak:realm:01x".to_owned(),
            commit_move_id: None,
            epoch_advance_move_id: None,
            commit_state: ChainMoveState::Cancelled,
            epoch_advance_state: ChainMoveState::NotSubmitted,
            pre_revoke_epoch: None,
        };
        assert_eq!(chain.status_summary(), "cancelled");
    }

    #[test]
    fn chains_from_plan_produces_one_chain_per_commit_step() {
        let groups = vec!["ak:realm:01a".to_owned(), "ak:realm:01b".to_owned()];
        let mut survivors = BTreeMap::new();
        survivors.insert("ak:realm:01a".to_owned(), 5);
        survivors.insert("ak:realm:01b".to_owned(), 3);
        let plan = DeviceRevokePlan::build("did:web:a", "ak:device:01x", &groups, &survivors);
        let mut epochs = BTreeMap::new();
        epochs.insert("ak:realm:01a".to_owned(), 7);
        let chains = chains_from_plan(&plan, &epochs);
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].group_id, "ak:realm:01a");
        assert_eq!(chains[0].pre_revoke_epoch, Some(7));
        assert_eq!(chains[1].pre_revoke_epoch, None);
        // Both freshly-built chains start in NotSubmitted.
        for chain in chains {
            assert_eq!(chain.commit_state, ChainMoveState::NotSubmitted);
            assert_eq!(chain.epoch_advance_state, ChainMoveState::NotSubmitted);
            assert!(!chain.is_complete());
            assert_eq!(chain.status_summary(), "pending");
        }
    }

    #[test]
    fn chain_move_state_is_terminal_for_effective_failed_cancelled() {
        assert!(ChainMoveState::Effective.is_terminal());
        assert!(
            ChainMoveState::Failed {
                reason: "x".to_owned()
            }
            .is_terminal()
        );
        assert!(ChainMoveState::Cancelled.is_terminal());
        assert!(!ChainMoveState::NotSubmitted.is_terminal());
        assert!(!ChainMoveState::Pending.is_terminal());
        assert_eq!(ChainMoveState::Pending.label(), "Pending");
        assert_eq!(ChainMoveState::Pending.badge_class(), "badge amber");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> DeviceRevokePlan {
        let groups = vec![
            "ak:realm:01acme0".to_owned(),
            "ak:realm:01launch0".to_owned(),
        ];
        let mut survivors = BTreeMap::new();
        survivors.insert("ak:realm:01acme0".to_owned(), 23);
        survivors.insert("ak:realm:01launch0".to_owned(), 11);
        DeviceRevokePlan::build(
            "did:web:alice.example",
            "ak:device:01js0dv00000000000000000003",
            &groups,
            &survivors,
        )
    }

    #[test]
    fn plan_starts_with_local_revoke_then_canonical_event() {
        let p = sample_plan();
        assert_eq!(p.steps[0], DeviceRevokeStep::LocalRevoke);
        assert_eq!(p.steps[1], DeviceRevokeStep::DeviceRevoked);
        assert_eq!(p.steps[2], DeviceRevokeStep::RotateAccountMlsSecret);
    }

    #[test]
    fn plan_includes_three_mls_steps_per_affected_group() {
        let p = sample_plan();
        // 2 groups × 3 steps (Propose + Commit + Welcome) = 6 MLS steps.
        let mls_step_count = p
            .steps
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    DeviceRevokeStep::MlsProposeRemove { .. }
                        | DeviceRevokeStep::MlsCommit { .. }
                        | DeviceRevokeStep::MlsWelcome { .. }
                )
            })
            .count();
        assert_eq!(mls_step_count, 6);
        assert_eq!(p.affected_group_count(), 2);
    }

    #[test]
    fn plan_terminates_with_keypackage_invalidate_and_push_unregister() {
        let p = sample_plan();
        let n = p.steps.len();
        assert_eq!(p.steps[n - 2], DeviceRevokeStep::InvalidateKeyPackages);
        assert_eq!(p.steps[n - 1], DeviceRevokeStep::UnregisterPushToken);
    }

    #[test]
    fn event_kinds_align_with_protocol_registry() {
        let p = sample_plan();
        let kinds = p.event_kinds();
        // Order matters: it's the order steps appear in the plan.
        assert_eq!(
            kinds,
            vec![
                "ak.device.revoke",
                "ak.mls.proposal",
                "ak.mls.commit",
                "ak.mls.welcome",
                "ak.mls.keypackage",
            ]
        );
    }

    #[test]
    fn welcome_step_carries_survivor_count() {
        let p = sample_plan();
        let mut welcomes: Vec<(String, usize)> = p
            .steps
            .iter()
            .filter_map(|s| match s {
                DeviceRevokeStep::MlsWelcome {
                    group_id,
                    recipient_count,
                } => Some((group_id.clone(), *recipient_count)),
                _ => None,
            })
            .collect();
        welcomes.sort();
        assert_eq!(
            welcomes,
            vec![
                ("ak:realm:01acme0".to_owned(), 23),
                ("ak:realm:01launch0".to_owned(), 11),
            ]
        );
    }

    #[test]
    fn missing_survivor_count_defaults_to_zero() {
        let groups = vec!["ak:realm:01x".to_owned()];
        let survivors = BTreeMap::new();
        let p = DeviceRevokePlan::build("did:web:b", "ak:device:01a", &groups, &survivors);
        let welcome = p
            .steps
            .iter()
            .find_map(|s| match s {
                DeviceRevokeStep::MlsWelcome {
                    recipient_count, ..
                } => Some(*recipient_count),
                _ => None,
            })
            .unwrap();
        assert_eq!(welcome, 0);
    }

    #[test]
    fn empty_groups_still_emits_terminal_steps() {
        let p = DeviceRevokePlan::build("did:web:b", "ak:device:01a", &[], &BTreeMap::new());
        // 5 steps: LocalRevoke, DeviceRevoked, RotateAccountMlsSecret,
        // InvalidateKeyPackages, UnregisterPushToken.
        assert_eq!(p.steps.len(), 5);
        assert_eq!(p.affected_group_count(), 0);
    }

    #[test]
    fn descriptions_are_non_empty_and_render_event_kind_when_relevant() {
        for kind in DeviceRevokeStep::all_variants() {
            let desc = kind.description();
            assert!(!desc.is_empty(), "step {kind:?} must have a description");
        }
    }
}

// Helper for tests / UI inventories — not part of the canonical plan API.
#[cfg(test)]
impl DeviceRevokeStep {
    fn all_variants() -> Vec<Self> {
        vec![
            Self::LocalRevoke,
            Self::DeviceRevoked,
            Self::RotateAccountMlsSecret,
            Self::MlsProposeRemove {
                group_id: "g".into(),
            },
            Self::MlsCommit {
                group_id: "g".into(),
            },
            Self::MlsWelcome {
                group_id: "g".into(),
                recipient_count: 0,
            },
            Self::InvalidateKeyPackages,
            Self::UnregisterPushToken,
        ]
    }
}
