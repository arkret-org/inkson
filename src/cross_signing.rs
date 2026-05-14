//! Cross-signing setup orchestration.
//!
//! Spec依据: [`crypto-media/device-lifecycle.md`](../../contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md)
//! §5 (Signing Hierarchy), §5.1 (Cross-Signing Publish Envelope), §5.2 (Device
//! Trust Chain), §14 (Cross-Signing Reset).
//!
//! 与 [`device_revoke`](super::device_revoke) 一样, 这一层只生成 **可审计的步骤
//! 计划**, 不直接落地——执行器顺序消费即可。SDK 提供的对应原语:
//!
//! - `CrossSigningPublishContent` / `SignedCrossSigningKey` /
//!   `CrossSigningBinding`: spec §5.1 wire envelope。
//! - `DeviceTrustBinding`: spec §5.2 `cx.device.authorized.cross_signing_binding`
//!   字段。
//! - `CrossSigningResetContent`: spec §14.1 reset envelope。
//! - `DeviceManager::record_cross_signing_publish` / `record_cross_signing_reset`
//!   / `evaluate_trust_chain`: 本地状态机。
//!
//! v1.1 之前 yougen UI 用 "Setup Cross-Signing (coming soon)" 占位; 现在 UI
//! 渲染 [`CrossSigningSetupPlan`] 并显示每个步骤对应的 canonical event kind,
//! 与 device-revoke 的设计保持一致。

use serde::{Deserialize, Serialize};

/// 一次完整的 cross-signing setup 步骤。每一步都对应 spec 中某个具体动作或
/// canonical event。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum CrossSigningSetupStep {
    /// 本地 KDF / 硬件 RNG 生成 principal_signing_key 公私钥对。
    /// 不是 canonical event; private key SHOULD 立刻进入加密 secret storage。
    GeneratePrincipalSigningKey,
    /// 本地生成 self_signing_key + user_signing_key 公私钥对。
    GenerateSelfAndUserSigningKeys,
    /// 用 PSK 对 SSK / USK 做绑定签名 (spec §5.1 `binding`)。
    /// canonical input = `cx-cross-signing-bind-v1\n` + canonical_json(...).
    SignSubordinateBindings,
    /// 把 SSK / USK 私钥写入加密 `cx.schema.key_backup.v1` envelope
    /// (`backup_class="secret_storage"`)。spec §11 + §7.1 域隔离。
    PublishSecretStorageBackup,
    /// 发布 `cx.cross_signing.publish.v1` 到 principal control space。
    EmitCrossSigningPublish,
    /// 用 SSK 对当前设备的 verify_key 签发 `cross_signing_binding`
    /// (spec §5.2), 并把它附在最新的 `cx.device.authorized` event 上。
    SignCurrentDeviceBinding,
    /// 触发对该 principal 已知设备的 trust chain 重评估;
    /// `NeedsReverification` 的设备 UI 上会标记。
    RecomputeDeviceTrustStates,
}

impl CrossSigningSetupStep {
    /// 对应的 canonical event kind。无对应 event 的步骤返回 `None`。
    pub fn canonical_event_kind(&self) -> Option<&'static str> {
        match self {
            Self::GeneratePrincipalSigningKey | Self::GenerateSelfAndUserSigningKeys => None,
            Self::SignSubordinateBindings => None,
            Self::PublishSecretStorageBackup => Some("cx.schema.key_backup.v1"),
            Self::EmitCrossSigningPublish => Some("cx.cross_signing.publish.v1"),
            Self::SignCurrentDeviceBinding => Some("cx.device.authorized"),
            Self::RecomputeDeviceTrustStates => None,
        }
    }

    /// 一句话用户描述, 直接渲染给 UI 预览。
    pub fn description(&self) -> &'static str {
        match self {
            Self::GeneratePrincipalSigningKey => "本地生成 principal_signing_key (DID 控制层根签名)",
            Self::GenerateSelfAndUserSigningKeys => {
                "本地生成 self_signing_key 与 user_signing_key"
            }
            Self::SignSubordinateBindings => "用 PSK 对 SSK / USK 签名 (spec §5.1)",
            Self::PublishSecretStorageBackup => {
                "把 SSK / USK 私钥写入加密 secret_storage backup"
            }
            Self::EmitCrossSigningPublish => "发布 cx.cross_signing.publish.v1 到 control stream",
            Self::SignCurrentDeviceBinding => {
                "用 SSK 对当前设备 verify_key 签发 cross_signing_binding"
            }
            Self::RecomputeDeviceTrustStates => "重新评估每台设备的 trust chain 状态",
        }
    }
}

/// First-time setup 与 cross-signing reset 共用同一个计划骨架; reset 多带一项
/// 前置步骤 (写 `cx.cross_signing.reset.v1`)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossSigningSetupMode {
    InitialSetup,
    Reset,
}

/// 完整 cross-signing setup / reset 计划。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningSetupPlan {
    pub principal_id: String,
    pub device_id: String,
    pub mode: CrossSigningSetupMode,
    pub previous_generation: Option<u64>,
    pub new_generation: u64,
    pub steps: Vec<CrossSigningSetupStep>,
}

impl CrossSigningSetupPlan {
    /// 构造初始 setup 计划 (`generation = 1`)。
    pub fn build_initial(principal_id: &str, device_id: &str) -> Self {
        Self {
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            mode: CrossSigningSetupMode::InitialSetup,
            previous_generation: None,
            new_generation: 1,
            steps: vec![
                CrossSigningSetupStep::GeneratePrincipalSigningKey,
                CrossSigningSetupStep::GenerateSelfAndUserSigningKeys,
                CrossSigningSetupStep::SignSubordinateBindings,
                CrossSigningSetupStep::PublishSecretStorageBackup,
                CrossSigningSetupStep::EmitCrossSigningPublish,
                CrossSigningSetupStep::SignCurrentDeviceBinding,
                CrossSigningSetupStep::RecomputeDeviceTrustStates,
            ],
        }
    }

    /// 构造 reset 计划; 多一步 `cx.cross_signing.reset.v1` 前置事件,
    /// 但不需要重新生成 PSK (PSK 来自 DID 控制链, 不在 reset 范围)。
    pub fn build_reset(principal_id: &str, device_id: &str, previous_generation: u64) -> Self {
        // Reset 写入由 prelude 表示; 后面紧接着 setup 主流程。
        let mut steps = vec![CrossSigningSetupStep::SignSubordinateBindings];
        // The reset event itself is modeled by SDK CrossSigningResetContent,
        // not as a step here — UI surfaces it separately so the reset proof
        // can be selected (DID control / recovery / quorum / trusted service).
        steps.extend([
            CrossSigningSetupStep::GenerateSelfAndUserSigningKeys,
            CrossSigningSetupStep::SignSubordinateBindings,
            CrossSigningSetupStep::PublishSecretStorageBackup,
            CrossSigningSetupStep::EmitCrossSigningPublish,
            CrossSigningSetupStep::SignCurrentDeviceBinding,
            CrossSigningSetupStep::RecomputeDeviceTrustStates,
        ]);
        // The first entry is from the leading bullet; dedupe to keep the
        // plan flat.
        steps.dedup();
        Self {
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            mode: CrossSigningSetupMode::Reset,
            previous_generation: Some(previous_generation),
            new_generation: previous_generation + 1,
            steps,
        }
    }

    /// 计划中出现的 canonical event kinds (按出现顺序去重)。
    pub fn event_kinds(&self) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        if matches!(self.mode, CrossSigningSetupMode::Reset) {
            seen.push("cx.cross_signing.reset.v1");
        }
        for step in &self.steps {
            if let Some(kind) = step.canonical_event_kind()
                && !seen.contains(&kind)
            {
                seen.push(kind);
            }
        }
        seen
    }
}

/// Trust-chain status the UI should surface per device. Mirrors the SDK
/// [`contrix::DeviceTrustChainOutcome`] but with a string discriminator that
/// fits yougen's JSON response shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossSigningTrustState {
    Unverified,
    Bootstrap,
    CrossSigned,
    NeedsReverification,
    AwaitingPublish,
    Invalid,
}

impl CrossSigningTrustState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unverified => "Unverified",
            Self::Bootstrap => "Bootstrap (inception)",
            Self::CrossSigned => "Cross-signed",
            Self::NeedsReverification => "Needs reverification",
            Self::AwaitingPublish => "Awaiting publish",
            Self::Invalid => "Invalid signature",
        }
    }

    pub fn badge_class(&self) -> &'static str {
        match self {
            Self::Unverified => "badge",
            Self::Bootstrap => "badge amber",
            Self::CrossSigned => "badge green",
            Self::NeedsReverification => "badge amber",
            Self::AwaitingPublish => "badge amber",
            Self::Invalid => "badge red",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_plan_has_seven_steps_and_emits_publish_event() {
        let plan = CrossSigningSetupPlan::build_initial("did:web:alice", "cx:device:01a");
        assert_eq!(plan.mode, CrossSigningSetupMode::InitialSetup);
        assert_eq!(plan.previous_generation, None);
        assert_eq!(plan.new_generation, 1);
        assert_eq!(plan.steps.len(), 7);
        let kinds = plan.event_kinds();
        assert!(kinds.contains(&"cx.cross_signing.publish.v1"));
        assert!(kinds.contains(&"cx.device.authorized"));
        assert!(kinds.contains(&"cx.schema.key_backup.v1"));
    }

    #[test]
    fn reset_plan_advances_generation_and_emits_reset_event_first() {
        let plan = CrossSigningSetupPlan::build_reset("did:web:alice", "cx:device:01a", 2);
        assert_eq!(plan.mode, CrossSigningSetupMode::Reset);
        assert_eq!(plan.previous_generation, Some(2));
        assert_eq!(plan.new_generation, 3);
        assert_eq!(plan.event_kinds()[0], "cx.cross_signing.reset.v1");
    }

    #[test]
    fn trust_state_label_and_badge_cover_all_variants() {
        for state in [
            CrossSigningTrustState::Unverified,
            CrossSigningTrustState::Bootstrap,
            CrossSigningTrustState::CrossSigned,
            CrossSigningTrustState::NeedsReverification,
            CrossSigningTrustState::AwaitingPublish,
            CrossSigningTrustState::Invalid,
        ] {
            assert!(!state.label().is_empty());
            assert!(state.badge_class().starts_with("badge"));
        }
    }

    #[test]
    fn step_descriptions_are_present_for_every_variant() {
        let variants = [
            CrossSigningSetupStep::GeneratePrincipalSigningKey,
            CrossSigningSetupStep::GenerateSelfAndUserSigningKeys,
            CrossSigningSetupStep::SignSubordinateBindings,
            CrossSigningSetupStep::PublishSecretStorageBackup,
            CrossSigningSetupStep::EmitCrossSigningPublish,
            CrossSigningSetupStep::SignCurrentDeviceBinding,
            CrossSigningSetupStep::RecomputeDeviceTrustStates,
        ];
        for v in variants {
            assert!(!v.description().is_empty());
        }
    }
}
