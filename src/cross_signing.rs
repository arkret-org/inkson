//! Cross-signing setup orchestration.
//!
//! Spec source: [`crypto-media/device-lifecycle.md`](../../contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md)
//! §5 (Signing Hierarchy), §5.1 (Cross-Signing Publish Envelope), §5.2 (Device
//! Trust Chain), §14 (Cross-Signing Reset).
//!
//! Like [`device_revoke`](super::device_revoke), this layer only produces an
//! **auditable step plan** — it does not perform side effects. The executor
//! consumes the steps in order. Corresponding SDK primitives:
//!
//! - `CrossSigningPublishContent` / `SignedCrossSigningKey` /
//!   `CrossSigningBinding`: spec §5.1 wire envelope.
//! - `DeviceTrustBinding`: spec §5.2 `cx.device.authorized.cross_signing_binding`
//!   field.
//! - `CrossSigningResetContent`: spec §14.1 reset envelope.
//! - `DeviceManager::record_cross_signing_publish` / `record_cross_signing_reset`
//!   / `evaluate_trust_chain`: local state machine.
//!
//! The UI renders [`CrossSigningSetupPlan`] and shows the canonical event kind
//! for each step, mirroring the device-revoke design.

use serde::{Deserialize, Serialize};

/// One step of a complete cross-signing setup. Each variant maps to a specific
/// action or canonical event in the spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum CrossSigningSetupStep {
    /// Generate the principal_signing_key keypair locally via KDF / hardware
    /// RNG. Not a canonical event; the private key SHOULD be moved into
    /// encrypted secret storage immediately.
    GeneratePrincipalSigningKey,
    /// Generate the self_signing_key + user_signing_key keypairs locally.
    GenerateSelfAndUserSigningKeys,
    /// Use the PSK to issue binding signatures over SSK / USK (spec §5.1
    /// `binding`). canonical input = `cx-cross-signing-bind-v1\n` +
    /// canonical_json(...).
    SignSubordinateBindings,
    /// Write the SSK / USK private keys into an encrypted
    /// `cx.schema.key_backup.v1` envelope (`backup_class="secret_storage"`).
    /// spec §11 + §7.1 domain separation.
    PublishSecretStorageBackup,
    /// Publish `cx.cross_signing.publish.v1` to the principal control space.
    EmitCrossSigningPublish,
    /// Use the SSK to issue a `cross_signing_binding` over the current
    /// device's verify_key (spec §5.2), and attach it to the latest
    /// `cx.device.authorized` event.
    SignCurrentDeviceBinding,
    /// Trigger trust-chain re-evaluation for every known device of this
    /// principal; devices ending up in `NeedsReverification` are flagged in
    /// the UI.
    RecomputeDeviceTrustStates,
}

impl CrossSigningSetupStep {
    /// Canonical event kind for this step; steps with no matching event
    /// return `None`.
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

    /// One-line user-facing description, rendered directly in the UI preview.
    pub fn description(&self) -> &'static str {
        match self {
            Self::GeneratePrincipalSigningKey => {
                "Generate principal_signing_key locally (root signature of the DID control layer)"
            }
            Self::GenerateSelfAndUserSigningKeys => {
                "Generate self_signing_key and user_signing_key locally"
            }
            Self::SignSubordinateBindings => "Sign SSK / USK with PSK (spec §5.1)",
            Self::PublishSecretStorageBackup => {
                "Write SSK / USK private keys into the encrypted secret_storage backup"
            }
            Self::EmitCrossSigningPublish => {
                "Publish cx.cross_signing.publish.v1 to the control stream"
            }
            Self::SignCurrentDeviceBinding => {
                "Use SSK to sign a cross_signing_binding over this device's verify_key"
            }
            Self::RecomputeDeviceTrustStates => {
                "Re-evaluate the trust-chain state for every device"
            }
        }
    }
}

/// Initial setup and cross-signing reset share the same plan skeleton; reset
/// carries an extra prelude step (writing `cx.cross_signing.reset.v1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossSigningSetupMode {
    InitialSetup,
    Reset,
}

/// Full cross-signing setup / reset plan.
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
    /// Build the initial setup plan (`generation = 1`).
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

    /// Build a reset plan; carries an extra `cx.cross_signing.reset.v1`
    /// prelude event but does not regenerate the PSK (PSK comes from the DID
    /// control chain and is out of scope for a cross-signing reset).
    pub fn build_reset(principal_id: &str, device_id: &str, previous_generation: u64) -> Self {
        // The reset write is represented by the prelude; the main setup
        // flow follows immediately after.
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

    /// Canonical event kinds that appear in the plan (deduplicated, in
    /// order of first appearance).
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
