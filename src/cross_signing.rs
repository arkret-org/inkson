//! Cross-signing setup orchestration.
//!
//! Spec source:
//! [`crypto-media/device-lifecycle.md`](../../cokret-spec/spec/v1/zh/crypto-media/
//! device-lifecycle.md) §5 (Signing Hierarchy), §5.1 (Cross-Signing Publish Envelope), §5.2 (Device
//! Trust Chain), §14 (Cross-Signing Reset).
//!
//! Like [`device_revoke`](super::device_revoke), this layer only produces an
//! **auditable step plan** — it does not perform side effects. The executor
//! consumes the steps in order. Corresponding SDK primitives:
//!
//! - `CrossSigningPublishContent` / `SignedCrossSigningKey` / `CrossSigningBinding`: spec §5.1 wire
//!   envelope.
//! - `DeviceTrustBinding`: spec §5.2 `ck.device.authorize.cross_signing_binding` field.
//! - `CrossSigningResetContent`: spec §14.1 reset envelope.
//! - `DeviceManager::record_cross_signing_publish` / `record_cross_signing_reset` /
//!   `evaluate_trust_chain`: local state machine.
//!
//! The UI renders [`CrossSigningSetupPlan`] and shows the canonical event kind
//! for each step, mirroring the device-revoke design.

use std::collections::BTreeSet;

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use chrono::Utc;
use cokret_sdk::{
    CrossSigningBinding, CrossSigningKeyRecord, CrossSigningPublishContent, Did,
    SignedCrossSigningKey, TypedTrustDomainId,
};
use ed25519_dalek::{SECRET_KEY_LENGTH, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::did_key::encode_ed25519_did_key_multibase;
use crate::operation::{EventEnvelope, OperationBuilder};
use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

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
    /// `binding`). canonical input = `ck-cross-signing-bind-v1\n` +
    /// canonical_json(...).
    SignSubordinateBindings,
    /// Write the SSK / USK private keys into an encrypted
    /// `ck.schema.key_backup.v1` envelope (`backup_class="secret_storage"`).
    /// spec §11 + §7.1 domain separation.
    PublishSecretStorageBackup,
    /// Publish `ck.cross_signing.publish` to the principal control Realm.
    EmitCrossSigningPublish,
    /// Use the SSK to issue a `cross_signing_binding` over the current
    /// device's verify_key (spec §5.2), and attach it to the latest
    /// `ck.device.authorize` event.
    SignCurrentDeviceBinding,
    /// Trigger trust-chain re-evaluation for every known device of this
    /// principal; devices ending up in `NeedsReverification` are flagged in
    /// the UI.
    RecomputeDeviceTrustStates,
}

impl CrossSigningSetupStep {
    /// Canonical wire-kind for this step; steps with no matching wire
    /// payload return `None`.
    ///
    /// F-CXSIGN-KIND-1 (2026-05-19): the spec `event-kind-registry.json`
    /// declares cross-signing events without a `.v1` suffix
    /// (`ck.cross_signing.publish`, `ck.cross_signing.reset`); the
    /// suffix is reserved for `schema-registry.json` entries. Yougen
    /// historically wrote the suffixed forms everywhere — this method,
    /// the OperationBuilder kind constant, the conformance test
    /// assertions, the workflows.rs dependency note, the verify_device
    /// test, and the e2e specs were all aligned in one pass.
    ///
    /// `PublishSecretStorageBackup` keeps `ck.schema.key_backup.v1`
    /// because key-backup is uploaded via PUT /_cokret/self/keys/backups/*
    /// rather than emitted as a wire event — the value here is the
    /// schema_id of the request body envelope, intentionally
    /// schema-namespaced. Renaming the function to
    /// `canonical_wire_kind` is left as the natural follow-up.
    pub fn canonical_event_kind(&self) -> Option<&'static str> {
        match self {
            Self::GeneratePrincipalSigningKey | Self::GenerateSelfAndUserSigningKeys => None,
            Self::SignSubordinateBindings => None,
            Self::PublishSecretStorageBackup => Some("ck.schema.key_backup.v1"),
            Self::EmitCrossSigningPublish => Some("ck.cross_signing.publish"),
            Self::SignCurrentDeviceBinding => Some("ck.device.authorize"),
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
                "Publish ck.cross_signing.publish to the control stream"
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
/// carries an extra prelude step (writing `ck.cross_signing.reset`).
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

    /// F-CXSIGN-RESET-1: policy-gated wrapper around [`build_reset`].
    ///
    /// Per spec `crypto-media/device-lifecycle.md §14`, the principal
    /// MUST be enrolled in the active reset audit policy before any
    /// `ck.cross_signing.reset` event is issued. Yougen mirrors the
    /// policy in [`ResetAuditPolicy`] (populated from incoming
    /// `ck.policy.set` events whose `policy_kind` is
    /// `ck.policy.cross_signing.reset`) and gates plan construction
    /// here so the UI never even surfaces the reset path when the
    /// caller would be rejected at submit time.
    pub fn try_build_reset(
        principal_id: &str,
        device_id: &str,
        previous_generation: u64,
        policy: &ResetAuditPolicy,
    ) -> Result<Self, ResetBlockedReason> {
        if !policy.permits_reset(principal_id) {
            return Err(ResetBlockedReason {
                principal_id: principal_id.to_owned(),
                hint: policy.enrollment_hint.clone(),
            });
        }
        Ok(Self::build_reset(
            principal_id,
            device_id,
            previous_generation,
        ))
    }

    /// Build a reset plan; carries an extra `ck.cross_signing.reset`
    /// prelude event but does not regenerate the PSK (PSK comes from the DID
    /// control chain and is out of scope for a cross-signing reset).
    ///
    /// F-CXSIGN-RESET-1: prefer [`try_build_reset`] in code paths that
    /// have the current [`ResetAuditPolicy`] — this raw constructor is
    /// kept so callers in pure-test contexts (and the existing
    /// fixture-based test in this module) can build a reset plan
    /// without threading the policy through.
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
            seen.push("ck.cross_signing.reset");
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

/// F-CXSIGN-RESET-1: snapshot of the deployment's cross-signing reset
/// audit policy, learned from a `ck.policy.set` event whose
/// `policy_kind == "ck.policy.cross_signing.reset"`.
///
/// Spec `crypto-media/device-lifecycle.md §14` requires the principal
/// to be enrolled in the reset audit policy *before* a reset event
/// can be issued — otherwise an attacker who compromises one device
/// could issue an unaudited reset that retires every other device's
/// trust without any audit row. Yougen mirrors the active policy
/// here and gates [`CrossSigningSetupPlan::try_build_reset`] on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetAuditPolicy {
    /// Whether the deployment requires reset enrollment at all. When
    /// `false`, every reset attempt is allowed (matches spec
    /// "PersonalNode" defaults).
    pub enrollment_required: bool,
    /// Principal DIDs that have currently completed enrollment. When
    /// `enrollment_required == true`, the principal MUST appear here.
    #[serde(default)]
    pub enrolled_principals: BTreeSet<String>,
    /// Optional human-readable hint surfaced in the UI when a reset is
    /// blocked — lets the operator explain how to enrol (e.g. "request
    /// access via /security/reset-policy").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_hint: Option<String>,
}

impl ResetAuditPolicy {
    /// Build a policy snapshot from a `ck.policy.set` event payload.
    /// Returns `None` when the payload isn't a reset-policy snapshot.
    ///
    /// Expected payload shape:
    /// ```json
    /// {
    ///   "policy_kind": "ck.policy.cross_signing.reset",
    ///   "enrollment_required": true,
    ///   "enrolled_principals": ["did:web:alice", "did:web:bob"],
    ///   "enrollment_hint": "Apply via /security/reset"
    /// }
    /// ```
    pub fn from_policy_set_payload(payload: &serde_json::Value) -> Option<Self> {
        let kind = payload.get("policy_kind")?.as_str()?;
        if kind != "ck.policy.cross_signing.reset" {
            return None;
        }
        let enrollment_required = payload
            .get("enrollment_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let enrolled_principals: BTreeSet<String> = payload
            .get("enrolled_principals")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let enrollment_hint = payload
            .get("enrollment_hint")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Some(Self {
            enrollment_required,
            enrolled_principals,
            enrollment_hint,
        })
    }

    /// Whether `principal_id` is permitted to issue a reset now.
    pub fn permits_reset(&self, principal_id: &str) -> bool {
        !self.enrollment_required || self.enrolled_principals.contains(principal_id)
    }
}

/// F-CXSIGN-RESET-1: why a reset attempt was blocked. Surfaces both
/// the failed principal and the policy's enrolment hint so the UI
/// can render an actionable message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetBlockedReason {
    pub principal_id: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for ResetBlockedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.hint {
            Some(h) => write!(
                f,
                "{} is not enrolled in the cross-signing reset audit policy: {h}",
                self.principal_id
            ),
            None => write!(
                f,
                "{} is not enrolled in the cross-signing reset audit policy",
                self.principal_id
            ),
        }
    }
}

impl std::error::Error for ResetBlockedReason {}

/// Trust-chain status the UI should surface per device. Mirrors the SDK
/// [`cokret::DeviceTrustChainOutcome`] but with a string discriminator that
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

/// Executor for [`CrossSigningSetupPlan`]. Generates the three keypairs
/// locally, computes the PSK-signed bindings for SSK / USK, and assembles
/// the [`CrossSigningPublishContent`] body the caller must submit as a
/// `ck.cross_signing.publish` operation.
///
/// What this executor **does** (per spec §5.1):
///   * Generates Ed25519 keypairs for PSK, SSK, USK via the platform RNG.
///   * Encodes each public key as multibase (`z` + base58btc with the `0xed 0x01` Ed25519
///     multicodec prefix), matching the `did:key:` / multikey wire format the SDK validates.
///   * Computes `canonical_cross_signing_binding_input` bytes for SSK and USK via the SDK's helper,
///     then signs them with the PSK private key. Signatures are emitted base64-encoded (the SDK's
///     declared encoding for the `binding.signature` field).
///   * Assembles a full `CrossSigningPublishContent`, runs the SDK's `validate_structure()` so the
///     publish event body MUST round-trip through SDK validation before the API call is even
///     constructed.
///
/// What this executor deliberately does **not** do:
///   * Persist the generated private keys to disk. The caller decides whether to push them through
///     `secure_key_store::SecureKeyStore` (preferred) or hand them to the recovery vault for
///     backup. Both paths are downstream consumers of [`CrossSigningSetupOutput`].
///   * Emit `ck.schema.key_backup.v1`, `ck.cross_signing.publish`, or `ck.device.authorize` to the
///     server. Those are API-bound side effects; the executor returns the canonical event bodies
///     and the caller (a view handler / orchestrator) drives the API.
///   * Recompute device trust states. That requires reading the device manager state and is a
///     separate concern; `recompute_trust_states` consumes this executor's output but lives in the
///     device manager.
pub struct CrossSigningExecutor {
    plan: CrossSigningSetupPlan,
    principal_did: Did,
    /// Round 4 (spec a77b995) — REQUIRED deployment-scope trust domain
    /// mixed into the canonical `ck-cross-signing-bind-v1` signing input
    /// so a publish from deployment A cannot be replayed into deployment
    /// B. Threaded from the caller's `/server/describe` response.
    trust_domain: TypedTrustDomainId,
}

/// Materials produced by [`CrossSigningExecutor::run`]. The PSK / SSK /
/// USK private signing keys MUST be moved into a secure store or the
/// recovery vault immediately; dropping them strands the publish event
/// (no subsequent device can be cross-signed without the PSK + SSK).
pub struct CrossSigningSetupOutput {
    pub principal_signing_key: SigningKey,
    pub self_signing_key: SigningKey,
    pub user_signing_key: SigningKey,
    /// The fully validated publish content the caller submits as
    /// `ck.cross_signing.publish`.
    pub publish_content: CrossSigningPublishContent,
}

/// One of the three cross-signing private keys; used as the namespace
/// suffix in [`secure_key_store_key`] so a single OS keychain can host
/// every role without collisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossSigningKeyRole {
    PrincipalSigning,
    SelfSigning,
    UserSigning,
}

impl CrossSigningKeyRole {
    fn suffix(self) -> &'static str {
        match self {
            Self::PrincipalSigning => "psk",
            Self::SelfSigning => "ssk",
            Self::UserSigning => "usk",
        }
    }
}

/// Stable [`SecureKeyStore`] key for a cross-signing private key.
///
/// Format: `cross_signing.{principal_did}.gen-{generation}.{role}`.
/// The generation is included so a reset (which mints fresh keys with
/// `generation = prev + 1`) does not clobber the previous keys until
/// the rollover is complete — both can coexist and a UI can revoke the
/// previous generation once the new publish is server-accepted.
pub fn secure_key_store_key(
    principal_did: &str,
    generation: u64,
    role: CrossSigningKeyRole,
) -> String {
    format!(
        "cross_signing.{principal_did}.gen-{generation}.{}",
        role.suffix()
    )
}

impl CrossSigningSetupOutput {
    /// Hand the three private keys to a [`SecureKeyStore`] under stable
    /// per-generation keys. Each value is the **hex** of the 32-byte
    /// Ed25519 seed (`SigningKey::to_bytes()`); callers reload via
    /// [`load_signing_key`].
    ///
    /// Hex is intentional: hex-encoded values are 7-bit-safe and round-
    /// trip through the OS keychain backends without padding nuance. The
    /// secret is still secret — the backend keeps it encrypted at rest;
    /// hex only fixes the wire shape between yougen and the backend.
    pub fn persist_private_keys(
        &self,
        store: &dyn SecureKeyStore,
        principal_did: &str,
    ) -> Result<(), SecureKeyStoreError> {
        let generation = self.publish_content.generation;
        store.store_secret(
            &secure_key_store_key(
                principal_did,
                generation,
                CrossSigningKeyRole::PrincipalSigning,
            ),
            &hex_encode(&self.principal_signing_key.to_bytes()),
        )?;
        store.store_secret(
            &secure_key_store_key(principal_did, generation, CrossSigningKeyRole::SelfSigning),
            &hex_encode(&self.self_signing_key.to_bytes()),
        )?;
        store.store_secret(
            &secure_key_store_key(principal_did, generation, CrossSigningKeyRole::UserSigning),
            &hex_encode(&self.user_signing_key.to_bytes()),
        )?;
        Ok(())
    }

    /// Construct the [`EventEnvelope`] yougen submits to write the
    /// `ck.cross_signing.publish` event. The caller supplies the
    /// `realm_id` of the principal's control Realm and the `actor` DID
    /// (typically the same as the principal). The envelope is unsigned;
    /// callers attach a `proof` via the standard signing pipeline before
    /// `submit_event_envelope`.
    pub fn build_publish_envelope(
        &self,
        realm_id: &str,
        actor: &str,
    ) -> anyhow::Result<EventEnvelope> {
        let body = serde_json::to_value(&self.publish_content)
            .context("serialize cross_signing publish content")?;
        Ok(
            OperationBuilder::new(realm_id, actor, "ck.cross_signing.publish")
                .target_ref(self.publish_content.principal_id.as_str())
                .body(body)
                .build("yougen"),
        )
    }
}

/// Reload a previously persisted Ed25519 signing key. Returns `Ok(None)`
/// when the store has no entry for this `(principal, generation, role)`
/// tuple (e.g. the user has not run setup yet on this device). `Err`
/// covers backend failures + corrupted hex.
pub fn load_signing_key(
    store: &dyn SecureKeyStore,
    principal_did: &str,
    generation: u64,
    role: CrossSigningKeyRole,
) -> anyhow::Result<Option<SigningKey>> {
    let key = secure_key_store_key(principal_did, generation, role);
    let Some(value) = store
        .get_secret(&key)
        .map_err(|err| anyhow::anyhow!("secure key store get: {err}"))?
    else {
        return Ok(None);
    };
    let bytes = hex_decode(&value)
        .ok_or_else(|| anyhow::anyhow!("cross_signing key hex decode failed for role {role:?}"))?;
    if bytes.len() != SECRET_KEY_LENGTH {
        anyhow::bail!(
            "cross_signing key for role {role:?} has wrong length: expected {SECRET_KEY_LENGTH}, got {}",
            bytes.len()
        );
    }
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    seed.copy_from_slice(&bytes);
    Ok(Some(SigningKey::from_bytes(&seed)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl CrossSigningExecutor {
    pub fn new(
        plan: CrossSigningSetupPlan,
        principal_did: Did,
        trust_domain: TypedTrustDomainId,
    ) -> Self {
        Self {
            plan,
            principal_did,
            trust_domain,
        }
    }

    /// Run the local generation + signing steps of the plan. Returns the
    /// generated keypairs + the validated publish content body.
    pub fn run(&self) -> anyhow::Result<CrossSigningSetupOutput> {
        let psk = generate_ed25519_signing_key().context("generate principal_signing_key")?;
        let ssk = generate_ed25519_signing_key().context("generate self_signing_key")?;
        let usk = generate_ed25519_signing_key().context("generate user_signing_key")?;

        // Spec §5: kid is a DID-URL pointing at a specific verification
        // method on the principal DID. Stable suffixes mirror the
        // `cx_principal_signing_v1` / `cx_self_signing_v1` / `cx_user_signing_v1`
        // names recommended by the v1 core registry.
        let psk_kid = format!(
            "{}#cx_principal_signing_v{}",
            self.principal_did.as_str(),
            self.plan.new_generation
        );
        let ssk_kid = format!(
            "{}#cx_self_signing_v{}",
            self.principal_did.as_str(),
            self.plan.new_generation
        );
        let usk_kid = format!(
            "{}#cx_user_signing_v{}",
            self.principal_did.as_str(),
            self.plan.new_generation
        );

        let psk_record = CrossSigningKeyRecord {
            kid: psk_kid.clone(),
            alg: "EdDSA".to_owned(),
            public_key: encode_ed25519_did_key_multibase(&psk.verifying_key()),
            key_format: "multibase".to_owned(),
        };
        let ssk_record = CrossSigningKeyRecord {
            kid: ssk_kid,
            alg: "EdDSA".to_owned(),
            public_key: encode_ed25519_did_key_multibase(&ssk.verifying_key()),
            key_format: "multibase".to_owned(),
        };
        let usk_record = CrossSigningKeyRecord {
            kid: usk_kid,
            alg: "EdDSA".to_owned(),
            public_key: encode_ed25519_did_key_multibase(&usk.verifying_key()),
            key_format: "multibase".to_owned(),
        };

        // Sign the SSK and USK bindings with PSK. We assemble a draft
        // publish so the SDK's canonical-binding helpers produce the exact
        // bytes the server will compare against.
        let draft = CrossSigningPublishContent {
            principal_id: self.principal_did.clone(),
            // Round 4 — REQUIRED trust domain mixed into the canonical
            // bind input; threaded from the caller's describe response.
            trust_domain: self.trust_domain.clone(),
            principal_signing_key: psk_record.clone(),
            self_signing_key: SignedCrossSigningKey {
                key: ssk_record.clone(),
                binding: CrossSigningBinding {
                    verification_method: psk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    signature: String::new(),
                },
            },
            user_signing_key: SignedCrossSigningKey {
                key: usk_record.clone(),
                binding: CrossSigningBinding {
                    verification_method: psk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    signature: String::new(),
                },
            },
            // Round 4 — CAS guard: prior accepted generation (0 on the
            // very first publish). `previous_generation` is `None` for
            // `InitialSetup` and `Some(prev)` for `Reset`.
            expected_previous_generation: self.plan.previous_generation.unwrap_or(0),
            generation: self.plan.new_generation,
            issued_at: Utc::now(),
        };
        let ssk_input = draft
            .self_signing_binding_input()
            .map_err(|e| anyhow::anyhow!("self_signing_binding_input: {e:?}"))?;
        let usk_input = draft
            .user_signing_binding_input()
            .map_err(|e| anyhow::anyhow!("user_signing_binding_input: {e:?}"))?;

        let ssk_sig = psk.sign(&ssk_input);
        let usk_sig = psk.sign(&usk_input);

        let publish_content = CrossSigningPublishContent {
            principal_id: draft.principal_id,
            trust_domain: draft.trust_domain,
            principal_signing_key: draft.principal_signing_key,
            self_signing_key: SignedCrossSigningKey {
                key: draft.self_signing_key.key,
                binding: CrossSigningBinding {
                    verification_method: psk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    signature: B64.encode(ssk_sig.to_bytes()),
                },
            },
            user_signing_key: SignedCrossSigningKey {
                key: draft.user_signing_key.key,
                binding: CrossSigningBinding {
                    verification_method: psk_kid,
                    alg: "EdDSA".to_owned(),
                    signature: B64.encode(usk_sig.to_bytes()),
                },
            },
            expected_previous_generation: draft.expected_previous_generation,
            generation: draft.generation,
            issued_at: draft.issued_at,
        };

        publish_content
            .validate_structure()
            .map_err(|e| anyhow::anyhow!("publish content failed SDK validation: {e:?}"))?;

        Ok(CrossSigningSetupOutput {
            principal_signing_key: psk,
            self_signing_key: ssk,
            user_signing_key: usk,
            publish_content,
        })
    }
}

/// Generate a fresh Ed25519 signing key via the platform-correct RNG.
fn generate_ed25519_signing_key() -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    getrandom::fill(&mut seed).map_err(|err| anyhow::anyhow!("rng fill: {err}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round 4 — every executor test thread needs a TypedTrustDomainId
    /// for the Round 4 `ck.cross_signing.publish` shape.
    fn test_trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap()
    }

    #[test]
    fn initial_plan_has_seven_steps_and_emits_publish_event() {
        let plan = CrossSigningSetupPlan::build_initial("did:web:alice", "ck:device:01a");
        assert_eq!(plan.mode, CrossSigningSetupMode::InitialSetup);
        assert_eq!(plan.previous_generation, None);
        assert_eq!(plan.new_generation, 1);
        assert_eq!(plan.steps.len(), 7);
        let kinds = plan.event_kinds();
        assert!(kinds.contains(&"ck.cross_signing.publish"));
        assert!(kinds.contains(&"ck.device.authorize"));
        assert!(kinds.contains(&"ck.schema.key_backup.v1"));
    }

    #[test]
    fn reset_plan_advances_generation_and_emits_reset_event_first() {
        let plan = CrossSigningSetupPlan::build_reset("did:web:alice", "ck:device:01a", 2);
        assert_eq!(plan.mode, CrossSigningSetupMode::Reset);
        assert_eq!(plan.previous_generation, Some(2));
        assert_eq!(plan.new_generation, 3);
        assert_eq!(plan.event_kinds()[0], "ck.cross_signing.reset");
    }

    // ── F-CXSIGN-RESET-1 ────────────────────────────────────────────

    #[test]
    fn reset_policy_parses_canonical_cx_policy_set_payload() {
        let payload = serde_json::json!({
            "policy_kind": "ck.policy.cross_signing.reset",
            "enrollment_required": true,
            "enrolled_principals": ["did:web:alice", "did:web:bob"],
            "enrollment_hint": "Apply via /security/reset"
        });
        let policy =
            ResetAuditPolicy::from_policy_set_payload(&payload).expect("recognised policy kind");
        assert!(policy.enrollment_required);
        assert!(policy.enrolled_principals.contains("did:web:alice"));
        assert!(policy.enrolled_principals.contains("did:web:bob"));
        assert_eq!(
            policy.enrollment_hint.as_deref(),
            Some("Apply via /security/reset")
        );
    }

    #[test]
    fn reset_policy_ignores_unrelated_policy_kinds() {
        let payload = serde_json::json!({
            "policy_kind": "ck.policy.space.moderation",
            "enrollment_required": true
        });
        assert!(ResetAuditPolicy::from_policy_set_payload(&payload).is_none());
    }

    #[test]
    fn try_build_reset_blocks_unenrolled_principal_when_enrollment_required() {
        let policy = ResetAuditPolicy {
            enrollment_required: true,
            enrolled_principals: ["did:web:bob".to_owned()].into_iter().collect(),
            enrollment_hint: Some("Apply via /security/reset".to_owned()),
        };
        let err =
            CrossSigningSetupPlan::try_build_reset("did:web:alice", "ck:device:01a", 2, &policy)
                .expect_err("alice is not enrolled");
        assert_eq!(err.principal_id, "did:web:alice");
        assert_eq!(err.hint.as_deref(), Some("Apply via /security/reset"));
        assert!(format!("{err}").contains("not enrolled"));
    }

    #[test]
    fn try_build_reset_passes_when_principal_is_enrolled() {
        let policy = ResetAuditPolicy {
            enrollment_required: true,
            enrolled_principals: ["did:web:alice".to_owned()].into_iter().collect(),
            enrollment_hint: None,
        };
        let plan =
            CrossSigningSetupPlan::try_build_reset("did:web:alice", "ck:device:01a", 2, &policy)
                .expect("alice is enrolled");
        assert_eq!(plan.mode, CrossSigningSetupMode::Reset);
        assert_eq!(plan.new_generation, 3);
    }

    #[test]
    fn try_build_reset_allows_everyone_when_enrollment_not_required() {
        // PersonalNode-style deployment: the policy exists but doesn't
        // gate reset. Every caller is admitted.
        let policy = ResetAuditPolicy::default(); // enrollment_required = false
        let plan =
            CrossSigningSetupPlan::try_build_reset("did:web:alice", "ck:device:01a", 5, &policy)
                .expect("permissive policy admits everyone");
        assert_eq!(plan.previous_generation, Some(5));
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
    fn executor_produces_validated_publish_content() {
        use ed25519_dalek::{Signature, Verifier};

        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ck:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().expect("local steps must succeed");

        // SDK validation runs inside `run()`; reaching here means the
        // publish content already passed the structural check (distinct
        // SSK / USK keys, non-empty kids, binding.verification_method matches PSK
        // kid, generation >= 1). Additionally verify the signatures
        // cryptographically using the PSK's verifying key — this is the
        // exact computation the server will run to accept the publish.
        let pub_content = &out.publish_content;
        assert_eq!(pub_content.generation, 1);
        assert_eq!(
            pub_content.principal_signing_key.public_key,
            encode_ed25519_did_key_multibase(&out.principal_signing_key.verifying_key())
        );

        let psk_verifying = out.principal_signing_key.verifying_key();
        let ssk_input = pub_content.self_signing_binding_input().unwrap();
        let ssk_sig_bytes = B64
            .decode(&pub_content.self_signing_key.binding.signature)
            .expect("ssk signature base64");
        let ssk_sig = Signature::from_slice(&ssk_sig_bytes).expect("ssk signature 64 bytes");
        psk_verifying
            .verify(&ssk_input, &ssk_sig)
            .expect("ssk binding signature must verify against PSK");

        let usk_input = pub_content.user_signing_binding_input().unwrap();
        let usk_sig_bytes = B64
            .decode(&pub_content.user_signing_key.binding.signature)
            .expect("usk signature base64");
        let usk_sig = Signature::from_slice(&usk_sig_bytes).expect("usk signature 64 bytes");
        psk_verifying
            .verify(&usk_input, &usk_sig)
            .expect("usk binding signature must verify against PSK");
    }

    #[test]
    fn executor_picks_distinct_keys_on_every_run() {
        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ck:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal, test_trust_domain());
        let a = executor.run().unwrap();
        let b = executor.run().unwrap();
        // Re-runs MUST mint fresh randomness for all three keys; reusing
        // any one of them across runs would be a critical entropy bug.
        assert_ne!(
            a.principal_signing_key.to_bytes(),
            b.principal_signing_key.to_bytes()
        );
        assert_ne!(a.self_signing_key.to_bytes(), b.self_signing_key.to_bytes());
        assert_ne!(a.user_signing_key.to_bytes(), b.user_signing_key.to_bytes());
    }

    #[test]
    fn persist_and_load_round_trip_three_keys() {
        use crate::secure_key_store::MemorySecureKeyStore;

        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ck:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().unwrap();

        let store = MemorySecureKeyStore::new();
        out.persist_private_keys(&store, principal.as_str())
            .unwrap();

        let generation = out.publish_content.generation;
        let psk = load_signing_key(
            &store,
            principal.as_str(),
            generation,
            CrossSigningKeyRole::PrincipalSigning,
        )
        .unwrap()
        .expect("PSK present after persist");
        assert_eq!(psk.to_bytes(), out.principal_signing_key.to_bytes());

        let ssk = load_signing_key(
            &store,
            principal.as_str(),
            generation,
            CrossSigningKeyRole::SelfSigning,
        )
        .unwrap()
        .expect("SSK present after persist");
        assert_eq!(ssk.to_bytes(), out.self_signing_key.to_bytes());

        let usk = load_signing_key(
            &store,
            principal.as_str(),
            generation,
            CrossSigningKeyRole::UserSigning,
        )
        .unwrap()
        .expect("USK present after persist");
        assert_eq!(usk.to_bytes(), out.user_signing_key.to_bytes());

        // A different generation MUST be absent — the keystore namespace
        // is per-generation so reset can mint fresh keys without
        // clobbering the pre-rollover set.
        assert!(
            load_signing_key(
                &store,
                principal.as_str(),
                generation + 1,
                CrossSigningKeyRole::PrincipalSigning,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn publish_envelope_carries_validated_publish_content() {
        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ck:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().unwrap();

        let envelope = out
            .build_publish_envelope(
                "ck:space:01964137-0000-7000-8000-000000000aaa",
                principal.as_str(),
            )
            .unwrap();
        assert_eq!(envelope.kind, "ck.cross_signing.publish");
        assert_eq!(
            envelope.local_target_ref(),
            Some(principal.as_str()),
            "target_ref must point at the principal whose keys these are"
        );
        // The full publish content body must round-trip — losing any
        // field here is the same as publishing a malformed event, which
        // the SDK validator would reject on the receiver side.
        let body_principal = envelope.payload["principal_id"]
            .as_str()
            .expect("body.principal_id is a string");
        assert_eq!(body_principal, principal.as_str());
        assert_eq!(envelope.payload["generation"].as_u64(), Some(1));
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
