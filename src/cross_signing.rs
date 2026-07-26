//! Cross-signing setup orchestration.
//!
//! Spec source:
//! [`crypto-media/device-lifecycle.md`](../../arkret-spec/spec/v1/zh/crypto-media/
//! device-lifecycle.md) §5 (Signing Hierarchy), §5.1 (Cross-Signing Publish Envelope), §5.2 (Device
//! Trust Chain), §14 (Cross-Signing Reset).
//!
//! This layer only produces an
//! **auditable step plan** — it does not perform side effects. The executor
//! consumes the steps in order. Corresponding SDK primitives:
//!
//! - `CrossSigningPublish` / `SubordinateSignedKey`: spec §5.1 wire envelope.
//! - `DeviceTrustBinding`: spec §5.2 `ak.device.authorize.cross_signing_binding` field.
//! - `CrossSigningResetPayload`: spec §14.1 reset envelope.
//! - Cross-signing publication and reset state is owned by the local device directory; trust-chain
//!   verification is owned by `arkret-crypto`.
//!
//! The UI renders [`CrossSigningSetupPlan`] and shows the canonical event kind
//! for each step, mirroring the device-revoke design.

use anyhow::Context;
use arkret_sdk::{
    CrossSigningPublish, Did, KeyFormat, NonEmptyString, PublishedKey, SubordinateSignedKey,
    SubordinateSignedKeyBinding, TypedTrustDomainId,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use chrono::Utc;
use ed25519_dalek::{SECRET_KEY_LENGTH, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identity::did_key::encode_ed25519_did_key_multibase;
use crate::operation::OperationBuilder;
use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

fn non_empty(value: impl Into<String>) -> anyhow::Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

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
    /// `binding`). canonical input = `ak-cross-signing-bind-v1\n` +
    /// canonical_json(...).
    SignSubordinateBindings,
    /// Write the SSK / USK private keys into an encrypted
    /// `ak.schema.key_backup.v1` envelope (`backup_kind="secret_storage"`).
    /// spec §11 + §7.1 domain separation.
    PublishSecretStorageBackup,
    /// Publish `ak.cross_signing.publish` to the principal control Realm.
    EmitCrossSigningPublish,
    /// Use the SSK to issue a `cross_signing_binding` over the current
    /// device's verify_key (spec §5.2), and attach it to the latest
    /// `ak.device.authorize` event.
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
    /// (`ak.cross_signing.publish`, `ak.cross_signing.reset`); the
    /// suffix is reserved for `schema-registry.json` entries. Inkson
    /// historically wrote the suffixed forms everywhere — this method,
    /// the OperationBuilder kind constant, the conformance test
    /// assertions, the workflows.rs dependency note, the verify_device
    /// test, and the e2e specs were all aligned in one pass.
    ///
    /// `PublishSecretStorageBackup` keeps `ak.schema.key_backup.v1`
    /// because key-backup is uploaded via PUT /_arkret/self/keys/backups/*
    /// rather than emitted as a wire event — the value here is the
    /// schema_id of the request body envelope, intentionally
    /// schema-namespaced. Renaming the function to
    /// `canonical_wire_kind` is left as the natural follow-up.
    pub fn canonical_event_kind(&self) -> Option<&'static str> {
        match self {
            Self::GeneratePrincipalSigningKey | Self::GenerateSelfAndUserSigningKeys => None,
            Self::SignSubordinateBindings => None,
            Self::PublishSecretStorageBackup => Some("ak.schema.key_backup.v1"),
            Self::EmitCrossSigningPublish => Some("ak.cross_signing.publish"),
            Self::SignCurrentDeviceBinding => Some("ak.device.authorize"),
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
                "Publish ak.cross_signing.publish to the control stream"
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
/// carries an extra prelude step (writing `ak.cross_signing.reset`).
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

    /// Build a reset plan; carries an extra `ak.cross_signing.reset`
    /// prelude event but does not regenerate the PSK (PSK comes from the DID
    /// control chain and is out of scope for a cross-signing reset).
    pub fn build_reset(principal_id: &str, device_id: &str, previous_generation: u64) -> Self {
        // The reset write is represented by the prelude; the main setup
        // strand follows immediately after.
        let mut steps = vec![CrossSigningSetupStep::SignSubordinateBindings];
        // The reset event itself is modeled by SDK CrossSigningResetPayload,
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
            seen.push("ak.cross_signing.reset");
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
/// [`arkret::DeviceTrustChainOutcome`] but with a string discriminator that
/// fits inkson's JSON response shape.
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
/// the [`CrossSigningPublish`] body the caller must submit as a
/// `ak.cross_signing.publish` operation.
///
/// What this executor **does** (per spec §5.1):
///   * Generates Ed25519 keypairs for PSK, SSK, USK via the platform RNG.
///   * Encodes each public key as multibase (`z` + base58btc with the `0xed 0x01` Ed25519
///     multicodec prefix), matching the `did:key:` / multikey wire format the SDK validates.
///   * Computes `canonical_cross_signing_binding_input` bytes for SSK and USK via the SDK's helper,
///     then signs them with the PSK private key. Signatures are emitted base64-encoded (the SDK's
///     declared encoding for the `binding.signature` field).
///   * Assembles a full `CrossSigningPublish`, runs the SDK's `validate_structure()` so the publish
///     event body MUST round-trip through SDK validation before the API call is even constructed.
///
/// What this executor deliberately does **not** do:
///   * Persist the generated private keys to disk. The caller decides whether to push them through
///     `secure_key_store::SecureKeyStore` (preferred) or hand them to the recovery vault for
///     backup. Both paths are downstream consumers of [`CrossSigningSetupOutput`].
///   * Emit `ak.schema.key_backup.v1`, `ak.cross_signing.publish`, or `ak.device.authorize` to the
///     server. Those are API-bound side effects; the executor returns the canonical event bodies
///     and the caller (a view handler / orchestrator) drives the API.
///   * Recompute device trust states. That requires reading the device manager state and is a
///     separate concern; `recompute_trust_states` consumes this executor's output but lives in the
///     device manager.
pub struct CrossSigningExecutor {
    plan: CrossSigningSetupPlan,
    principal_did: Did,
    /// Round 4 (spec a77b995) — REQUIRED deployment-scope trust domain
    /// mixed into the canonical `ak-cross-signing-bind-v1` signing input
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
    /// `ak.cross_signing.publish`.
    pub publish_content: CrossSigningPublish,
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
    /// hex only fixes the wire shape between inkson and the backend.
    pub fn persist_private_keys(
        &self,
        store: &dyn SecureKeyStore,
        principal_did: &str,
    ) -> Result<(), SecureKeyStoreError> {
        let generation = self.publish_content.generation.get();
        // Hold each hex-encoded private seed in a `Zeroizing<String>` so the
        // plaintext key material is wiped from the heap once it has been handed
        // to the secure store, rather than lingering in a freed `String`.
        let psk_hex = Zeroizing::new(hex_encode(&self.principal_signing_key.to_bytes()));
        store.store_secret(
            &secure_key_store_key(
                principal_did,
                generation,
                CrossSigningKeyRole::PrincipalSigning,
            ),
            &psk_hex,
        )?;
        let ssk_hex = Zeroizing::new(hex_encode(&self.self_signing_key.to_bytes()));
        store.store_secret(
            &secure_key_store_key(principal_did, generation, CrossSigningKeyRole::SelfSigning),
            &ssk_hex,
        )?;
        let usk_hex = Zeroizing::new(hex_encode(&self.user_signing_key.to_bytes()));
        store.store_secret(
            &secure_key_store_key(principal_did, generation, CrossSigningKeyRole::UserSigning),
            &usk_hex,
        )?;
        Ok(())
    }

    /// Construct the SDK Event inkson submits to write the
    /// `ak.cross_signing.publish` event. The caller supplies the
    /// `realm_id` of the principal's control Realm and the `actor` DID
    /// (typically the same as the principal). The envelope is unsigned;
    /// callers attach a `proof` via the standard SDK event signing pipeline.
    pub fn build_publish_envelope(
        &self,
        realm_id: &str,
        actor: &str,
    ) -> anyhow::Result<arkret_sdk::Event> {
        let body = serde_json::to_value(&self.publish_content)
            .context("serialize cross_signing publish content")?;
        OperationBuilder::new(
            realm_id,
            actor,
            arkret_sdk::events::kinds::EventKind::CrossSigningPublish,
        )
        .target_ref(self.publish_content.principal_id.as_str())
        .body(body)
        .build_sdk_event("inkson")
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
        .map(Zeroizing::new)
    else {
        return Ok(None);
    };
    // Hold the decoded private seed in zeroizing containers so the plaintext key
    // material is wiped from the heap once the `SigningKey` has been built.
    let bytes =
        Zeroizing::new(hex_decode(&value).ok_or_else(|| {
            anyhow::anyhow!("cross_signing key hex decode failed for role {role:?}")
        })?);
    if bytes.len() != SECRET_KEY_LENGTH {
        anyhow::bail!(
            "cross_signing key for role {role:?} has wrong length: expected {SECRET_KEY_LENGTH}, got {}",
            bytes.len()
        );
    }
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    seed.copy_from_slice(&bytes);
    Ok(Some(SigningKey::from_bytes(&seed)))
}

// YOU-05-007: shared lowercase-hex codec lives in `crate::canonical`.
use crate::canonical::{hex_decode, hex_encode};

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

        let psk_record = PublishedKey {
            kid: non_empty(psk_kid.clone())?,
            alg: non_empty("EdDSA")?,
            public_key: non_empty(encode_ed25519_did_key_multibase(&psk.verifying_key()))?,
            key_format: KeyFormat::Multibase,
        };

        // Sign the SSK and USK bindings with PSK. We assemble a draft
        // publish so the SDK's canonical-binding helpers produce the exact
        // bytes the server will compare against.
        let generation = std::num::NonZeroU64::new(self.plan.new_generation)
            .context("cross-signing generation must be non-zero")?;
        let mut publish_content = CrossSigningPublish {
            principal_id: self.principal_did.clone(),
            // Round 4 — REQUIRED trust domain mixed into the canonical
            // bind input; threaded from the caller's describe response.
            trust_domain: self.trust_domain.clone(),
            principal_signing_key: psk_record.clone(),
            self_signing_key: SubordinateSignedKey {
                kid: non_empty(ssk_kid)?,
                alg: non_empty("EdDSA")?,
                public_key: non_empty(encode_ed25519_did_key_multibase(&ssk.verifying_key()))?,
                key_format: KeyFormat::Multibase,
                binding: SubordinateSignedKeyBinding {
                    verification_method: non_empty(psk_kid.clone())?,
                    alg: non_empty("EdDSA")?,
                    signature: non_empty("pending")?,
                },
            },
            user_signing_key: SubordinateSignedKey {
                kid: non_empty(usk_kid)?,
                alg: non_empty("EdDSA")?,
                public_key: non_empty(encode_ed25519_did_key_multibase(&usk.verifying_key()))?,
                key_format: KeyFormat::Multibase,
                binding: SubordinateSignedKeyBinding {
                    verification_method: non_empty(psk_kid)?,
                    alg: non_empty("EdDSA")?,
                    signature: non_empty("pending")?,
                },
            },
            // Round 4 — CAS guard: prior accepted generation (0 on the
            // very first publish). `previous_generation` is `None` for
            // `InitialSetup` and `Some(prev)` for `Reset`.
            expected_previous_generation: self.plan.previous_generation.unwrap_or(0),
            generation,
            issued_at: arkret_sdk::canonical::normalize_timestamp_canonical(Utc::now()),
        };
        let ssk_input = publish_content
            .self_signing_binding_input()
            .map_err(|e| anyhow::anyhow!("self_signing_binding_input: {e:?}"))?;
        let usk_input = publish_content
            .user_signing_binding_input()
            .map_err(|e| anyhow::anyhow!("user_signing_binding_input: {e:?}"))?;

        let ssk_sig = psk.sign(&ssk_input);
        let usk_sig = psk.sign(&usk_input);

        publish_content.self_signing_key.binding.signature =
            non_empty(B64.encode(ssk_sig.to_bytes()))?;
        publish_content.user_signing_key.binding.signature =
            non_empty(B64.encode(usk_sig.to_bytes()))?;

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
    /// for the Round 4 `ak.cross_signing.publish` shape.
    fn test_trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap()
    }

    #[test]
    fn initial_plan_has_seven_steps_and_emits_publish_event() {
        let plan = CrossSigningSetupPlan::build_initial("did:web:alice", "ak:device:01a");
        assert_eq!(plan.mode, CrossSigningSetupMode::InitialSetup);
        assert_eq!(plan.previous_generation, None);
        assert_eq!(plan.new_generation, 1);
        assert_eq!(plan.steps.len(), 7);
        let kinds = plan.event_kinds();
        assert!(kinds.contains(&"ak.cross_signing.publish"));
        assert!(kinds.contains(&"ak.device.authorize"));
        assert!(kinds.contains(&"ak.schema.key_backup.v1"));
    }

    #[test]
    fn reset_plan_advances_generation_and_emits_reset_event_first() {
        let plan = CrossSigningSetupPlan::build_reset("did:web:alice", "ak:device:01a", 2);
        assert_eq!(plan.mode, CrossSigningSetupMode::Reset);
        assert_eq!(plan.previous_generation, Some(2));
        assert_eq!(plan.new_generation, 3);
        assert_eq!(plan.event_kinds()[0], "ak.cross_signing.reset");
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
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ak:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().expect("local steps must succeed");

        // SDK validation runs inside `run()`; reaching here means the
        // publish content already passed the structural check (distinct
        // SSK / USK keys, non-empty kids, binding.verification_method matches PSK
        // kid, generation >= 1). Additionally verify the signatures
        // cryptographically using the PSK's verifying key — this is the
        // exact computation the server will run to accept the publish.
        let pub_content = &out.publish_content;
        assert_eq!(pub_content.generation.get(), 1);
        assert_eq!(
            pub_content.principal_signing_key.public_key.as_str(),
            encode_ed25519_did_key_multibase(&out.principal_signing_key.verifying_key())
        );

        let psk_verifying = out.principal_signing_key.verifying_key();
        let ssk_input = pub_content.self_signing_binding_input().unwrap();
        let ssk_sig_bytes = B64
            .decode(pub_content.self_signing_key.binding.signature.as_str())
            .expect("ssk signature base64");
        let ssk_sig = Signature::from_slice(&ssk_sig_bytes).expect("ssk signature 64 bytes");
        psk_verifying
            .verify(&ssk_input, &ssk_sig)
            .expect("ssk binding signature must verify against PSK");

        let usk_input = pub_content.user_signing_binding_input().unwrap();
        let usk_sig_bytes = B64
            .decode(pub_content.user_signing_key.binding.signature.as_str())
            .expect("usk signature base64");
        let usk_sig = Signature::from_slice(&usk_sig_bytes).expect("usk signature 64 bytes");
        psk_verifying
            .verify(&usk_input, &usk_sig)
            .expect("usk binding signature must verify against PSK");
    }

    #[test]
    fn executor_serializes_issued_at_as_canonical_utc_milliseconds() {
        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ak:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal, test_trust_domain());
        let out = executor.run().expect("local steps must succeed");

        assert_eq!(
            out.publish_content.issued_at.timestamp_subsec_nanos() % 1_000_000,
            0
        );
        let serialized = serde_json::to_value(&out.publish_content).unwrap();
        let issued_at = serialized["issued_at"]
            .as_str()
            .expect("issued_at serializes as a string");
        arkret_sdk::canonical::validate_timestamp_canonical(issued_at).unwrap();
    }

    #[test]
    fn executor_picks_distinct_keys_on_every_run() {
        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ak:device:01a");
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
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ak:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().unwrap();

        let store = MemorySecureKeyStore::new();
        out.persist_private_keys(&store, principal.as_str())
            .unwrap();

        let generation = out.publish_content.generation.get();
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
        let plan = CrossSigningSetupPlan::build_initial(principal.as_str(), "ak:device:01a");
        let executor = CrossSigningExecutor::new(plan, principal.clone(), test_trust_domain());
        let out = executor.run().unwrap();

        let envelope = out
            .build_publish_envelope(
                "ak:realm:01964137-0000-7000-8000-000000000aaa",
                principal.as_str(),
            )
            .unwrap();
        assert_eq!(envelope.kind.as_str(), "ak.cross_signing.publish");
        assert_eq!(
            envelope
                .unsigned
                .get("local_target_ref")
                .and_then(serde_json::Value::as_str),
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
