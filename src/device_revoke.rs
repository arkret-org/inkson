//! T31 — Device 撤销编排
//!
//! 把 "撤销一台设备" 拆成一系列 canonical 事件 + MLS 操作，组成可审计的计划。
//! UI 展示该计划让用户在确认前看到完整影响范围；执行层按顺序逐步落地。
//!
//! 协议依据：
//! - `crypto-media/device-lifecycle.md` — 三件事分开（登录因子 / 设备授权 / 设备验证），
//!   `cx.device.revoked` 是改变 device set 的唯一 event。
//! - `crypto-media/encryption-and-audit.md` — MLS group 的 leaf removal 通过
//!   `cx.mls.proposal` (Remove) → `cx.mls.commit`（epoch++）→ `cx.mls.welcome`（给
//!   仍在 group 中的成员，让他们追上新 epoch）链式完成。
//!
//! 当前 SDK 暴露了：
//! - `DeviceManager::revoke_device(user_id, device_id)` — 标记 revoked。
//! - `E2eeManager::revoke_device(principal_id, device_id)` — 标记 revoked +
//!   后续从该 device 的加密写入 fail closed。
//! - `ContrixMlsGroup::add_member(...)` — 通过 OpenMLS 完成添加 + 派发 Welcome。
//! - `E2eeManager::remove_member(group_id, did)` — Did 级别移除（model layer）。
//!
//! 缺：基于 LeafNodeIndex 的真实 MLS Remove proposal/commit。该原子能力到位前，
//! 本编排层先把序列化的事件计划交给 UI 与离线队列，等 SDK 补齐后执行器自动接住。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 单个撤销步骤。每个变体对应一个 canonical event kind，UI 可按 `description`
/// 与 `canonical_event_kind` 直接渲染审计预览。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceRevokeStep {
    /// 在本地 DeviceManager / E2eeManager 中标记 revoked。
    /// 这一步是本地状态变化，没有对外 event。
    LocalRevoke,
    /// 写入 actor event chain 的撤销证明。
    /// canonical event = `cx.device.revoked`。
    CxDeviceRevoked,
    /// 对受影响的每个 MLS group 发起 Remove proposal。
    /// canonical event = `cx.mls.proposal`（type = remove）。
    MlsProposeRemove { group_id: String },
    /// 把 proposal commit 进 group，epoch 前进 1。
    /// canonical event = `cx.mls.commit`。
    MlsCommit { group_id: String },
    /// 给仍在 group 中的成员发送 Welcome 让他们追上新 epoch（针对错过 commit
    /// 的 lazy / offline 成员）。
    /// canonical event = `cx.mls.welcome`。
    MlsWelcome {
        group_id: String,
        recipient_count: usize,
    },
    /// 把被撤销设备未被消费的 KeyPackages 从 OTK pool 中作废（避免新成员
    /// 误把它当作可用 leaf）。
    /// canonical event = `cx.mls.keypackage`（status = revoked）。
    InvalidateKeyPackages,
    /// 让 push gateway 取消该设备的脱敏唤醒注册，避免继续向 revoked 设备发推送。
    /// 不是 canonical event；属于 device/key-server 接口的本地控制。
    UnregisterPushToken,
}

impl DeviceRevokeStep {
    /// 对应的 canonical event kind（`None` 表示纯本地 / 服务接口操作）。
    pub fn canonical_event_kind(&self) -> Option<&'static str> {
        match self {
            Self::LocalRevoke => None,
            Self::CxDeviceRevoked => Some("cx.device.revoked"),
            Self::MlsProposeRemove { .. } => Some("cx.mls.proposal"),
            Self::MlsCommit { .. } => Some("cx.mls.commit"),
            Self::MlsWelcome { .. } => Some("cx.mls.welcome"),
            Self::InvalidateKeyPackages => Some("cx.mls.keypackage"),
            Self::UnregisterPushToken => None,
        }
    }

    /// 一句话解释当前步骤，UI 可直接渲染给用户预览。
    pub fn description(&self) -> String {
        match self {
            Self::LocalRevoke => {
                "标记本地 DeviceManager + E2eeManager 中的 revoked 状态".to_owned()
            }
            Self::CxDeviceRevoked => "写入 cx.device.revoked 到 actor event chain".to_owned(),
            Self::MlsProposeRemove { group_id } => {
                format!("发起 MLS Remove proposal · group={group_id}")
            }
            Self::MlsCommit { group_id } => format!("提交 commit，epoch++ · group={group_id}"),
            Self::MlsWelcome {
                group_id,
                recipient_count,
            } => {
                format!("给 {recipient_count} 名仍在 group 中的成员发送 Welcome · group={group_id}")
            }
            Self::InvalidateKeyPackages => {
                "把被撤销设备未消费的 KeyPackages 从 OTK pool 作废".to_owned()
            }
            Self::UnregisterPushToken => "通知 push gateway 取消该设备的脱敏唤醒注册".to_owned(),
        }
    }
}

/// 完整的撤销计划。`steps` 是按依赖顺序排列的步骤集合；执行器顺序消费即可。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevokePlan {
    pub principal_id: String,
    pub device_id: String,
    pub steps: Vec<DeviceRevokeStep>,
}

impl DeviceRevokePlan {
    /// 生成计划。`affected_groups` 是该设备作为 MLS leaf 的 group_id 集合；
    /// `survivors_per_group` 给出每个 group 在移除该设备后剩余的成员数（用于
    /// Welcome 的接收方计数）。
    pub fn build(
        principal_id: &str,
        device_id: &str,
        affected_groups: &[String],
        survivors_per_group: &BTreeMap<String, usize>,
    ) -> Self {
        let mut steps: Vec<DeviceRevokeStep> = Vec::new();
        steps.push(DeviceRevokeStep::LocalRevoke);
        steps.push(DeviceRevokeStep::CxDeviceRevoked);
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

    /// 计划中包含的 canonical event kinds 列表（去重，按出现顺序）。
    /// 用于审计 / inbox / "影响范围" 摘要。
    pub fn event_kinds(&self) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        for step in &self.steps {
            if let Some(k) = step.canonical_event_kind() {
                if !seen.contains(&k) {
                    seen.push(k);
                }
            }
        }
        seen
    }

    /// 影响的 MLS group 数（从 step 中提取，不依赖输入参数）。
    pub fn affected_group_count(&self) -> usize {
        let mut groups: Vec<&str> = Vec::new();
        for step in &self.steps {
            let gid = match step {
                DeviceRevokeStep::MlsProposeRemove { group_id }
                | DeviceRevokeStep::MlsCommit { group_id }
                | DeviceRevokeStep::MlsWelcome { group_id, .. } => Some(group_id.as_str()),
                _ => None,
            };
            if let Some(g) = gid {
                if !groups.contains(&g) {
                    groups.push(g);
                }
            }
        }
        groups.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Round 25 (R4): chained MLS Remove + epoch-advance Move tracker.
//
// When the device-revocation handler executes the plan, every MLS group
// the revoked device was a leaf in needs **two** Moves to fully advance:
//
// 1. an MLS commit Move that removes the device's leaf (`cx.mls.commit`
//    via the `cx.component.mls.epoch.v1` cas-register), and
// 2. an epoch-advance Move that bumps `covered_frontier` so subsequent
//    message Events can reference the post-revocation MLS state.
//
// Each chain entry tracks the lifecycle of those Moves
// individually — both must reach `Effective` before the device is
// considered fully unspooled from the group. The space-admin page
// renders this list with per-row stage chips so an operator can see
// where the revocation chain has stalled.
// ═══════════════════════════════════════════════════════════════════════════

/// A single MLS Move pair driven by a device-revocation chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsRevokeMoveChain {
    /// MLS group id the chain operates on — one chain per affected
    /// group.
    pub group_id: String,
    /// MLS commit Move id (`cx:move:sha256:...`); `None` until the
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
    /// Submitted; waiting for an Anchor to sweep it.
    Pending,
    /// Anchored / effective.
    Effective,
    /// Submission failed (signature, precondition, anchorer-paused).
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

/// Round 25 (R4): build the typed chain set from a [`DeviceRevokePlan`].
/// One [`MlsRevokeMoveChain`] per `MlsCommit` step in the plan.
/// `pre_revoke_epochs` maps `group_id` → known current epoch (often
/// supplied by the local Anchor view); missing entries leave the
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
            group_id: "cx:space:01acme".to_owned(),
            commit_move_id: Some("cx:move:sha256:aa".to_owned()),
            epoch_advance_move_id: Some("cx:move:sha256:bb".to_owned()),
            commit_state: ChainMoveState::Effective,
            epoch_advance_state: ChainMoveState::Pending,
            pre_revoke_epoch: Some(12),
        };
        assert!(!chain.is_complete());
        assert_eq!(chain.status_summary(), "commit_ok");
        chain.epoch_advance_state = ChainMoveState::Effective;
        assert!(chain.is_complete());
        assert_eq!(chain.status_summary(), "complete");
    }

    #[test]
    fn chain_failure_propagates_to_summary() {
        let chain = MlsRevokeMoveChain {
            group_id: "cx:space:01x".to_owned(),
            commit_move_id: None,
            epoch_advance_move_id: None,
            commit_state: ChainMoveState::Failed {
                reason: "anchorer paused".to_owned(),
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
            group_id: "cx:space:01x".to_owned(),
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
        let groups = vec!["cx:space:01a".to_owned(), "cx:space:01b".to_owned()];
        let mut survivors = BTreeMap::new();
        survivors.insert("cx:space:01a".to_owned(), 5);
        survivors.insert("cx:space:01b".to_owned(), 3);
        let plan = DeviceRevokePlan::build("did:web:a", "cx:device:01x", &groups, &survivors);
        let mut epochs = BTreeMap::new();
        epochs.insert("cx:space:01a".to_owned(), 7);
        let chains = chains_from_plan(&plan, &epochs);
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].group_id, "cx:space:01a");
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> DeviceRevokePlan {
        let groups = vec![
            "cx:space:01acme0".to_owned(),
            "cx:space:01launch0".to_owned(),
        ];
        let mut survivors = BTreeMap::new();
        survivors.insert("cx:space:01acme0".to_owned(), 23);
        survivors.insert("cx:space:01launch0".to_owned(), 11);
        DeviceRevokePlan::build(
            "did:web:alice.example",
            "cx:device:01js0dv00000000000000000003",
            &groups,
            &survivors,
        )
    }

    #[test]
    fn plan_starts_with_local_revoke_then_canonical_event() {
        let p = sample_plan();
        assert_eq!(p.steps[0], DeviceRevokeStep::LocalRevoke);
        assert_eq!(p.steps[1], DeviceRevokeStep::CxDeviceRevoked);
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
                "cx.device.revoked",
                "cx.mls.proposal",
                "cx.mls.commit",
                "cx.mls.welcome",
                "cx.mls.keypackage",
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
                ("cx:space:01acme0".to_owned(), 23),
                ("cx:space:01launch0".to_owned(), 11),
            ]
        );
    }

    #[test]
    fn missing_survivor_count_defaults_to_zero() {
        let groups = vec!["cx:space:01x".to_owned()];
        let survivors = BTreeMap::new();
        let p = DeviceRevokePlan::build("did:web:b", "cx:device:01a", &groups, &survivors);
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
        let p = DeviceRevokePlan::build("did:web:b", "cx:device:01a", &[], &BTreeMap::new());
        // 4 steps: LocalRevoke, CxDeviceRevoked, InvalidateKeyPackages, UnregisterPushToken.
        assert_eq!(p.steps.len(), 4);
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
            Self::CxDeviceRevoked,
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
