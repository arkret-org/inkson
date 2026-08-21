use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_sdk::EncryptedPayload;
pub use arkret_sdk::{
    PresencePreference, PresenceVisibility, ReadCursorPosition, ReadCursorScope as ReadScope,
};
use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

// Sibling-module types (`LocalSealView`, the `move_tracking` / `mls_sidecar`
// helpers) and the parent constants (`RAW_OPERATIONS_MAX`, ...) are reached
// through the parent module glob.
use super::*;
use crate::notification_rules::{DndSettings, WatchLevel};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawOperationRecord {
    pub operation_id: String,
    pub realm_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMessageReceipt {
    pub canonical_digest: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmDestroyReceipt {
    #[serde(default)]
    pub destroyed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroyed_operation_id: Option<String>,
}

impl RealmDestroyReceipt {
    pub(crate) fn destroyed(operation_id: impl Into<String>) -> Self {
        Self {
            destroyed: true,
            destroyed_operation_id: Some(operation_id.into()),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationClientState {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub archived: bool,
}

/// Current local notification projection.
///
/// Account-subscribe `NotificationDelta` values are reducer inputs only. They
/// are folded into this closed current-state model before persistence or UI
/// consumption, so business code never has to rediscover the wire branch by
/// probing JSON discriminator strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "projection_kind", rename_all = "snake_case")]
pub enum StoredNotification {
    Event {
        notification: arkret_sdk::Notification,
    },
    AgentRuntimeApproval {
        id: arkret_sdk::NotificationId,
        data: arkret_sdk::AgentRuntimeApprovalNotificationData,
    },
    Invite {
        invite: StoredInviteNotification,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInviteNotification {
    pub invite_id: arkret_sdk::InviteId,
    pub realm_id: arkret_sdk::RealmId,
    pub created_at: DateTime<Utc>,
}

/// Private invite delivery credential received over the actor-private
/// account-data carrier (`ak.account.invite_delivery`).
///
/// This is the only legitimate source of an invite-accept token: the Invite
/// read model carries no token (`governance-objects.md` §5.3), so the accept
/// flow MUST read it from this holder-private state and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInviteCredential {
    pub realm_id: arkret_sdk::RealmId,
    pub invite_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub received_at: DateTime<Utc>,
}

impl StoredNotification {
    pub fn notification_id(&self) -> String {
        match self {
            Self::Event { notification } => notification.id.as_str().to_owned(),
            Self::AgentRuntimeApproval { id, .. } => id.as_str().to_owned(),
            Self::Invite { invite } => format!("invite:{}", invite.invite_id.as_str()),
        }
    }

    pub fn notification_kind(&self) -> arkret_sdk::NotificationKind {
        match self {
            Self::Event { notification } => notification.notification_kind.clone(),
            Self::AgentRuntimeApproval { .. } => arkret_sdk::NotificationKind::Agent,
            Self::Invite { .. } => arkret_sdk::NotificationKind::Invite,
        }
    }

    pub fn realm_id(&self) -> Option<&str> {
        match self {
            Self::Event { notification } => match &notification.source {
                arkret_sdk::NotificationSource::Event(source) => {
                    source.realm_id.as_ref().map(arkret_sdk::RealmId::as_str)
                }
                arkret_sdk::NotificationSource::AccountArtifact(_) => None,
            },
            Self::AgentRuntimeApproval { .. } => None,
            Self::Invite { invite } => Some(invite.realm_id.as_str()),
        }
    }

    pub fn source_event_id(&self) -> Option<&str> {
        match self {
            Self::Event { notification } => match &notification.source {
                arkret_sdk::NotificationSource::Event(source) => {
                    Some(source.source_event_id.as_str())
                }
                arkret_sdk::NotificationSource::AccountArtifact(_) => None,
            },
            Self::AgentRuntimeApproval { .. } | Self::Invite { .. } => None,
        }
    }

    pub fn strand_id(&self) -> Option<&str> {
        match self {
            Self::Event { notification } => match &notification.source {
                arkret_sdk::NotificationSource::Event(source) => {
                    source.strand_id.as_ref().map(arkret_sdk::StrandId::as_str)
                }
                arkret_sdk::NotificationSource::AccountArtifact(_) => None,
            },
            Self::AgentRuntimeApproval { .. } | Self::Invite { .. } => None,
        }
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        match self {
            Self::Event { notification } => notification.created_at,
            Self::AgentRuntimeApproval { data, .. } => data.requested_at,
            Self::Invite { invite } => invite.created_at,
        }
    }

    pub fn agent_runtime_approval(
        &self,
    ) -> Option<(
        &arkret_sdk::NotificationId,
        &arkret_sdk::AgentRuntimeApprovalNotificationData,
    )> {
        match self {
            Self::AgentRuntimeApproval { id, data } => Some((id, data)),
            Self::Event { .. } | Self::Invite { .. } => None,
        }
    }

    pub fn invite(&self) -> Option<&StoredInviteNotification> {
        match self {
            Self::Invite { invite } => Some(invite),
            Self::Event { .. } | Self::AgentRuntimeApproval { .. } => None,
        }
    }
}

/// Realm-scoped cache for `ak.find.directory.read.list_handles_for_subject`.
///
/// Handles are display evidence, not identity keys. Cache entries are
/// therefore bound to the visible subject DID, the Realm context, and the
/// roster `member_display_state_digest` when the server provided one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberHandleCacheEntry {
    pub subject_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle: Option<String>,
    #[serde(default)]
    pub claims_count: usize,
    pub fetched_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    pub cache_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_display_state_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerBody {
    #[serde(default = "new_read_cursor_id")]
    pub id: String,
    pub schema: String,
    pub realm_id: String,
    pub read_scope: ReadScope,
    pub position: ReadCursorPosition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerRecord {
    pub body: ReadMarkerBody,
    pub actor: String,
    pub device_id: String,
    pub updated_at: DateTime<Utc>,
}

/// Server-declared `ak.realm.read_receipt_policy` snapshot for a Realm, as
/// surfaced to clients via the Seal view (P0 M3) once sync.rs lands.
/// Locks the per-scope toggle in the settings UI when `disclosure` is
/// `required` (server forces send) or `disabled` (server forbids send).
///
/// Until the sync wires the policy from soland's `ak.component.realm.read_receipt_policy.v1`
/// cas-register cell, this is populated by tests / dev tooling only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPolicySnapshot {
    /// Disclosure mode — `optional` (default), `required`, or `disabled`.
    /// `required` and `disabled` lock the user's per-Realm override.
    pub disclosure: String,
    /// Visibility scope — `public`, `private`, `track_scoped`. Surfaced
    /// in the lock-reason text so the user knows why the toggle is locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

impl ReadReceiptPolicySnapshot {
    /// True when `disclosure` is one of the spec's lock-mandating values.
    pub fn locks_user_choice(&self) -> bool {
        matches!(self.disclosure.as_str(), "required" | "disabled")
    }

    /// Human-readable reason for showing the lock UI; empty when not locked.
    pub fn lock_reason(&self) -> String {
        match self.disclosure.as_str() {
            "required" => format!(
                "Realm policy: read receipts are REQUIRED ({}). User-level skip is disabled.",
                self.visibility.as_deref().unwrap_or("public")
            ),
            "disabled" => format!(
                "Realm policy: read receipts are DISABLED ({}). User-level send is disabled.",
                self.visibility.as_deref().unwrap_or("public")
            ),
            _ => String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

pub(crate) fn raw_operation_kind(payload: &Value) -> Option<&str> {
    payload
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| payload.get("type").and_then(Value::as_str))
}

/// Persisted shape of the device identity. Production callers store this
/// record in [`crate::secure_key_store::SecureKeyStore`]; plaintext
/// `state.json` storage is retained only for tests and explicitly enabled
/// development fallback.
///
/// This replaces the deterministic `[42; 32]` demo seed used by older Move
/// builder prototypes. Fresh installs generate via
/// `getrandom::fill` on first access; existing dev installs that still
/// hold a `[42; 32]` cache are simply broken - they regenerate the next
/// time the store is loaded with no record present (Arkret v1 protocol is
/// pre-release, with no migration path).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityRecord {
    /// Hex-encoded 32-byte ed25519 seed. Production callers persist this
    /// record in `SecureKeyStore`; the field remains serializable for
    /// test fixtures and the explicit plaintext development fallback.
    pub seed_hex: String,
    /// `did:key:z<multibase>` derived from the seed's verifying key.
    pub did_key: String,
}

impl Drop for LocalIdentityRecord {
    /// R16: the hex-encoded ed25519 seed is long-lived secret material; wipe
    /// it on drop so copies left over from hydrate / `to_record` round-trips
    /// don't linger in freed heap. `did_key` is public and left untouched.
    fn drop(&mut self) {
        self.seed_hex.zeroize();
    }
}

/// In-memory device identity: the per-device ed25519 signing key plus the
/// derived `did:key`. Construct via [`LocalStateStore::ensure_local_identity`]
/// (which generates+persists on first call) or [`LocalIdentity::from_record`]
/// (round-tripping a persisted record).
///
/// R16: `signing_key` is `ed25519_dalek::SigningKey`, which derives
/// `ZeroizeOnDrop` — its secret scalar is wiped automatically when this
/// struct (or any `Clone` of it) is dropped, so no manual `Drop` is needed
/// here and the `<redacted>` Debug formatting below is preserved.
#[derive(Clone)]
pub struct LocalIdentity {
    /// Local signing public key encoded as `did:key:z<multibase>`. This is a
    /// self-describing encoding of the device-local ed25519 signing key, not a
    /// device DID or actor identity; devices are not independent DID subjects.
    /// Event `actor_id` must use the account/principal DID (see spec
    /// models/actor.md §2). This field is only used for local signing / key
    /// store indexing.
    pub local_signing_did: String,
    pub signing_key: SigningKey,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private bytes.
        f.debug_struct("LocalIdentity")
            .field("local_signing_did", &self.local_signing_did)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl PartialEq for LocalIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.local_signing_did == other.local_signing_did
            && self.signing_key.to_bytes() == other.signing_key.to_bytes()
    }
}

impl Eq for LocalIdentity {}

impl LocalIdentity {
    /// Generate a fresh device identity. Uses `getrandom::fill` for the
    /// 32-byte seed — same RNG inkson uses for OIDC PKCE state/nonce/verifier.
    pub fn generate() -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|err| anyhow::anyhow!("rng fill: {err}"))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let local_signing_did = encode_did_key(&signing_key);
        Ok(Self {
            local_signing_did,
            signing_key,
        })
    }

    /// Recover an identity from a persisted record. Returns `Err` if the
    /// hex is malformed or the cached `did_key` mismatches what the seed
    /// derives — a tamper / corruption signal.
    pub fn from_record(record: &LocalIdentityRecord) -> anyhow::Result<Self> {
        let bytes = hex_to_bytes(&record.seed_hex)
            .ok_or_else(|| anyhow::anyhow!("identity seed_hex is not valid hex"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "identity seed must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let derived = encode_did_key(&signing_key);
        if derived != record.did_key {
            return Err(anyhow::anyhow!(
                "identity record tampered: stored did_key {} != derived {derived}",
                record.did_key
            ));
        }
        Ok(Self {
            local_signing_did: derived,
            signing_key,
        })
    }

    /// Serialize to the on-disk record shape.
    pub fn to_record(&self) -> LocalIdentityRecord {
        let seed_hex = crate::canonical::hex_encode(&self.signing_key.to_bytes());
        LocalIdentityRecord {
            seed_hex,
            did_key: self.local_signing_did.clone(),
        }
    }
}

/// Encode an ed25519 signing key's public half as a `did:key:z<multibase>`
/// DID. Thin wrapper over the shared [`crate::identity::did_key`] encoder.
fn encode_did_key(signing_key: &SigningKey) -> String {
    crate::identity::did_key::did_key_from_verifying_key(&signing_key.verifying_key())
}

/// Lifecycle state of a locally-submitted Move. Mirrors the states
/// soland's Move/Seal pipeline can report via the
/// `SubmitMoveOutcome.state` field plus the post-seal effects the
/// next `/sync` cycle exposes:
///
/// - `PendingSeal` — server accepted the Move into MoveStore, waiting for the next notary batch to
///   seal it. Initial state for any successful submit.
/// - `Effective` — notary included the Move in a signed Seal; the reducer ran and the resulting
///   cell state is now visible.
/// - `FailedPrecondition` — soland rejected the Move at submit time because a precondition
///   (`if_state` / `if_cell` / `parent_anchor`) no longer matches the server's view.
/// - `FailedBottom` — the reducer accepted the Move but produced a bottom (concurrent-candidate)
///   cell; downstream queries are undefined until an admin resolves the conflict via a `head_in`
///   repair Move (M8).
/// - `RejectedSeal` — the notary batch that swept the Move was rejected (signature / signer-set
///   policy / notary-cell mismatch); the Move never landed.
/// - `NotaryPaused` — the Space's notary is paused (recovery notary not yet rotated, or quorum
///   unmet); the Space cannot advance until ops bring it back online.
/// - `PendingMlsBinding` — the Move targets an E2EE message but its Security Frontier binding
///   references accepted control state the local MLS group has not yet acknowledged. Held
///   client-side until the binding is observed; the user sees a toast.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveSubmissionState {
    PendingSeal,
    Effective,
    FailedPrecondition,
    FailedBottom,
    RejectedSeal,
    NotaryPaused,
    PendingMlsBinding,
}

impl MoveSubmissionState {
    /// Map a soland `SubmitMoveOutcome.state` string into the typed
    /// enum. Unknown strings fall back to `PendingSeal` (the safe
    /// "we accepted it, server will tell us more later" default) so
    /// new server-side states surface as in-flight rather than as
    /// failures.
    pub fn from_submit_state(state: &str, reason: Option<&str>) -> Self {
        match state {
            "accepted" | "pending" | "pending_seal" => Self::PendingSeal,
            "effective" | "sealed" => Self::Effective,
            "rejected" => match reason.unwrap_or("") {
                r if r.contains("notary_paused") => Self::NotaryPaused,
                r if r.contains("rejected_seal") || r.contains("seal_signature") => {
                    Self::RejectedSeal
                }
                r if r.contains("bottom") => Self::FailedBottom,
                r if r.contains("security_frontier") || r.contains("mls_binding") => {
                    Self::PendingMlsBinding
                }
                _ => Self::FailedPrecondition,
            },
            "failed_precondition" => Self::FailedPrecondition,
            "failed_bottom" => Self::FailedBottom,
            "rejected_seal" => Self::RejectedSeal,
            "notary_paused" => Self::NotaryPaused,
            "pending_mls_binding" => Self::PendingMlsBinding,
            _ => Self::PendingSeal,
        }
    }

    /// Short tag used by the UI for state-specific styling (badge color
    /// / icon class). Mirrors the on-disk `serde(rename_all = "snake_case")`
    /// repr so log lines + CSS classes stay aligned.
    pub fn slug(self) -> &'static str {
        match self {
            Self::PendingSeal => "pending_seal",
            Self::Effective => "effective",
            Self::FailedPrecondition => "failed_precondition",
            Self::FailedBottom => "failed_bottom",
            Self::RejectedSeal => "rejected_seal",
            Self::NotaryPaused => "notary_paused",
            Self::PendingMlsBinding => "pending_mls_binding",
        }
    }

    /// Human-readable label (Chinese where the spec / sodmin already
    /// uses Chinese copy). Surfaces in message status pills / banners.
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::PendingSeal => "待 Seal",
            Self::Effective => "已生效",
            Self::FailedPrecondition => "前置条件失败",
            Self::FailedBottom => "Bottom 冲突",
            Self::RejectedSeal => "Seal 拒绝",
            Self::NotaryPaused => "Notary 暂停",
            Self::PendingMlsBinding => "MLS 绑定待覆盖",
        }
    }

    /// CSS-friendly badge class.
    pub fn badge_class(self) -> &'static str {
        match self {
            Self::PendingSeal => "badge amber",
            Self::Effective => "badge green",
            Self::FailedPrecondition => "badge red",
            Self::FailedBottom => "badge red",
            Self::RejectedSeal => "badge red",
            Self::NotaryPaused => "badge red",
            Self::PendingMlsBinding => "badge amber",
        }
    }

    /// True when the state represents a terminal failure — the UI
    /// allows the user to click for a detail dialog.
    pub fn is_failed(self) -> bool {
        matches!(
            self,
            Self::FailedPrecondition | Self::FailedBottom | Self::RejectedSeal | Self::NotaryPaused
        )
    }
}

/// Per-Move tracking record persisted in the local state store. `move_id`
/// is content-addressed (`sha256:...`); the reducer round-trips
/// `realm_id` so client UIs can scope filtering. `kind` is a free-form
/// classifier the UI uses for icons (e.g. `ak.consent.grant`,
/// `ak.message.create`, `mls_commit`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveSubmissionRecord {
    pub move_id: String,
    /// Server-assigned Event id returned by `ak.self.events.command.submit`. Older
    /// records may only have `move_id` (the local idempotency alias);
    /// sync `event_states[]` uses this id, so new records persist it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub realm_id: String,
    pub kind: String,
    pub state: MoveSubmissionState,
    pub submitted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional last-known seal frontier head the Move was bound to.
    /// Surfaces in the failure detail so an operator can correlate the
    /// rejected Move to the predecessor that conflicted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSyncStatus {
    pub manifest_id: String,
    pub trust_state: crate::snapshot::SnapshotTrustState,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
}

/// A near-current MLS governance frontier proof that was fully verified before
/// it entered local state. The original typed response is retained so a
/// Welcome receiver can re-run validation without trusting a derived digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedMlsGovernanceProof {
    pub request: arkret_sdk::MlsGovernanceProofRequestBody,
    pub governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    pub proof_base_basis: arkret_sdk::SealBasis,
    pub proof_target_basis: arkret_sdk::SealBasis,
    pub bundle: arkret_sdk::MlsGovernanceProofBundle,
    pub verified_at: DateTime<Utc>,
}

/// DID-P2-B — decode the persisted accepted-binding rows, **dropping** any row
/// that no longer validates instead of trusting it or failing the whole blob.
///
/// [`arkret_sdk::identity::AcceptedDidBinding`] has a hand-written
/// `Deserialize` that routes through its validating constructor: it recomputes
/// the pinned document's canonical digest, compares it to the digest the
/// binding recorded, and checks `document.id == binding.did()`. A row whose
/// document was edited on disk therefore fails to deserialize.
///
/// Decoding row-by-row (rather than letting the derived `Vec` deserializer
/// propagate the first failure) is deliberate and matters twice over:
///
/// - **one bad row must not destroy the account.** `read_account_state` treats *any*
///   `ClientLocalState` decode failure as a corrupt blob and starts from defaults, so a strict
///   vector would escalate "one tampered binding" into "lose every draft, cursor and MLS snapshot".
/// - **local state is not an authority.** A record that fails must degrade into a resolver miss,
///   not into an accepted binding — the same rule the in-memory store applies.
pub fn decode_accepted_did_bindings(
    rows: Vec<Value>,
) -> Vec<arkret_sdk::identity::AcceptedDidBinding> {
    rows.into_iter()
        .filter_map(|row| match serde_json::from_value(row) {
            Ok(accepted) => Some(accepted),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "dropping a persisted DID binding that no longer matches its pinned document"
                );
                None
            }
        })
        .collect()
}

fn deserialize_accepted_did_bindings<'de, D>(
    deserializer: D,
) -> Result<Vec<arkret_sdk::identity::AcceptedDidBinding>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(decode_accepted_did_bindings(Vec::<Value>::deserialize(
        deserializer,
    )?))
}

/// Public-only checkpoint for a client-authored principal registration.
/// Recovery words and every derived private seed are deliberately absent; a
/// resumed bootstrap must ask the user to re-enter the cold recovery secret.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingAccountHandoff {
    pub principal_server_url: String,
    pub gate_account_base: String,
    pub request_id: String,
    /// OIDC state whose authenticated callback created this handoff. This is
    /// used only to resume the exact same callback after response loss; a new
    /// Coauth interaction must always observe its newly selected account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_state: Option<String>,
    /// Account Authority handle used only for UI display and artifact naming.
    /// The protocol defines this as an unsigned UX hint, so it never proves
    /// handoff continuity or principal identity.
    #[serde(default)]
    pub account_handle: String,
    /// Stable Account Authority subject frozen from the authenticated handoff.
    /// A checkpoint that omits it must fail closed before cold-root signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_subject: Option<arkret_sdk::Hash>,
    pub holder_jkt: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_fence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// Coauth-authored durable saga state. This is the only identity-creation
    /// phase authority; local checkpoint presence must never replace it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_creation_state: Option<arkret_sdk::IdentityCreationLeaseState>,
    /// Server-persisted identity reservation, when challenge issuance already
    /// bound this account setup to one exact DID inception operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_identity: Option<arkret_sdk::ReservedIdentityCreation>,
    /// Durable explicit-abandonment challenge for a reserved identity whose
    /// registration control may no longer be available on this device.  It
    /// belongs to the account handoff rather than the registration checkpoint:
    /// the protocol deliberately authorizes abandonment with account handoff
    /// grants when no principal or recovery secret exists yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_abandonment: Option<PendingIdentityAbandonment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    pub device_id: String,
    pub trust_domain: String,
    /// Existing principal returned by a bound account handoff. Presence
    /// selects Recovery-Key re-anchor instead of identity creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_principal_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingPrincipalRegistration {
    pub principal_server_url: String,
    pub gate_account_base: String,
    pub handoff_request_id: String,
    /// Account Authority handle copied only for UI display and artifact naming.
    /// It is an unsigned UX hint; continuity is proven by an exact request id
    /// or the server's typed reserved identity, never by this string.
    #[serde(default)]
    pub account_handle: String,
    /// Account Authority subject frozen with this registration draft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_subject: Option<arkret_sdk::Hash>,
    pub lease_id: String,
    pub lease_fence: u64,
    pub device_id: String,
    pub trust_domain: String,
    pub did: String,
    pub version_id: String,
    /// Durable explicit-abandonment challenge projected by the Account
    /// Authority together with its authoritative reauthentication decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_abandonment: Option<PendingIdentityAbandonment>,
    pub root_public_key_multibase: String,
    pub root_verification_method: String,
    pub next_root_public_key_multibase: String,
    pub next_root_key_hash: String,
    pub recovery_proof_public_key_multibase: String,
    pub backup_hpke_public_key_multibase: String,
    pub recovery_key_fingerprint: String,
    /// Frozen method-native DID inception operation.
    pub did_operation: arkret_sdk::DidOperationSubmitRequestBody,
    /// Canonical bytes of the method-native did:webvh inception entry. The
    /// registration terminal re-reads did.jsonl and compares entry 0 against
    /// this frozen value before adopting the identity.
    pub did_entry0_canonical_base64url: String,
    /// Complete client-authored, root/device-signed PCR genesis unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_genesis_unit: Option<arkret_wire::PcrGenesisUnit>,
    /// First Standard grant request, bound to the durable DPoP key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_session: Option<arkret_sdk::InitialSessionGrantIntent>,
    /// Verified terminal PCR genesis receipt returned with the Standard grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_genesis_receipt: Option<arkret_sdk::EventBatchReceipt>,
    /// Exact device-signed bootstrap Seal, durably frozen before its first
    /// submission so recovery resumes the same bytes after response loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_bootstrap_seal: Option<arkret_sdk::Seal>,
    pub genesis_created_at: String,
    pub genesis_hlc: String,
    /// Random create-time salt committed by `ak.realm.create`. Realm identity
    /// is derived from that authored Event, never from the principal DID.
    pub genesis_salt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_receipt: Option<arkret_sdk::AccountBindingReceipt>,
    pub stage: PendingPrincipalRegistrationStage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingIdentityAbandonment {
    pub challenge: arkret_sdk::IdentityAbandonmentChallengeOutcome,
    /// Account Authority freshness decision for the current handoff. This is
    /// never inferred by comparing locally persisted bearer credentials.
    pub fresh_authentication_required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecoveryMaterialEvidence {
    pub principal_id: arkret_sdk::DidFullId,
    pub device_id: arkret_sdk::DeviceId,
    pub principal_control_realm_id: arkret_sdk::RealmId,
    pub pcr_genesis_unit: arkret_wire::PcrGenesisUnit,
    pub bootstrap_seal: arkret_sdk::Seal,
    /// Public account authority pair used for controller-authorized operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_authority: Option<arkret_sdk::PrincipalAuthorityKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingPrincipalRegistrationStage {
    /// The generated or supplied Recovery Key matched this public checkpoint
    /// during an earlier interaction. This does not assert that the user
    /// memorized/exported it, or that the current process still holds it.
    /// Current secret availability is tracked separately by
    /// `IdentityCreationRecoveryKeyState` and the platform SecureKeyStore.
    CustodyConfirmed,
    GenesisDraftPrepared,
    RegisterRequestPrepared,
    Accepted,
    RecoveryMaterialComplete,
}

impl PendingPrincipalRegistration {
    pub fn advance_registration_stage(
        &mut self,
        next: PendingPrincipalRegistrationStage,
    ) -> Result<(), &'static str> {
        use PendingPrincipalRegistrationStage as Stage;
        let allowed = matches!(
            (self.stage, next),
            (Stage::CustodyConfirmed, Stage::GenesisDraftPrepared)
                | (Stage::GenesisDraftPrepared, Stage::RegisterRequestPrepared)
                | (Stage::RegisterRequestPrepared, Stage::Accepted)
                | (Stage::Accepted, Stage::RecoveryMaterialComplete)
        );
        if !allowed {
            return Err("invalid principal registration checkpoint transition");
        }
        self.stage = next;
        Ok(())
    }
}

/// Canonical accepted Event that defines one locally persisted MLS epoch.
///
/// Encrypted content must cite this Event in `key_ref.group_state_ref`; a
/// Realm Seal, state root, or synthetic digest is not an MLS group-state
/// reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupStateRefRecord {
    pub group_id: String,
    pub epoch: u64,
    pub event_id: arkret_sdk::EventId,
}

/// One effective scope paused by `encryption-and-audit.md` §2.4.1
/// `epoch_update_required`.
///
/// The scope is carried in the record rather than only in the map key: the key
/// is the Circle id for a Circle-scoped group, so a Circle entry alone cannot
/// name the Realm whose MLS effect has to run the repair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCoverageStale {
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
    /// The receiver's own `mls_governance_binding_stale` message, so the repair
    /// pass and the UI name the governance Seals the epoch has not attested
    /// rather than a generic "send failed".
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CachedAgentSignerEvidenceContext {
    CurrentSignal {
        operation_id: arkret_sdk::ProtocolOperationId,
        request_digest: arkret_sdk::Hash,
        verifier_id: arkret_sdk::DidCoreId,
        audience: arkret_sdk::DidCoreId,
        challenge: arkret_sdk::NonEmptyString,
    },
    HistoricalEvent {
        realm_id: arkret_sdk::RealmId,
        event_id: arkret_sdk::EventId,
        event_digest: arkret_sdk::Hash,
        producer_accepted_at: chrono::DateTime<chrono::Utc>,
        producer_signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef,
        producer_signer_resolution_evidence_digest: arkret_sdk::Hash,
        receiver_service_id: arkret_sdk::DidCoreId,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CachedAgentSignerEvidence {
    pub evidence: arkret_sdk::AgentSignerEvidence,
    pub verification_context: CachedAgentSignerEvidenceContext,
    pub verification_method_public_keys:
        BTreeMap<String, arkret_sdk::signatures::PublicKeyMaterial>,
    pub cached_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredClientDelivery {
    pub id: u64,
    pub scope: garth::CursorScope,
    pub cursor: Option<garth::OpaqueCursor>,
    pub events: serde_json::Value,
    pub attempts: u32,
    pub next_attempt_at_ms: Option<i64>,
    pub error_class: Option<garth::DeliveryErrorClass>,
    pub last_error: Option<String>,
}

/// Private, MLS-authenticated IdentityLink material retained byte-exactly for
/// later history-response verification. The inner Principal proof is verified
/// from retained signer evidence when the response record is admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocallyAuthenticatedIdentityLink {
    pub(crate) identity_link: arkret_sdk::IdentityLink,
    pub(crate) identity_link_canonical_bytes_b64u: arkret_sdk::Base64UrlString,
    pub(crate) identity_link_digest: arkret_sdk::Hash,
    pub(crate) leaf_node_canonical_bytes_b64u: arkret_sdk::Base64UrlString,
    pub(crate) leaf_node_digest: arkret_sdk::Hash,
    pub(crate) winning_group_state_ref: arkret_sdk::EventId,
}

/// Persisted non-secret accounting for one resident external history-secret
/// candidate. The SDK material key is the protocol identity; secret bytes are
/// stored separately in `SecureKeyStore`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientLocalState {
    pub sync_cursor: Option<String>,
    /// Highest verified `ak.key_backup.active_series` pointer observed per
    /// `(actor_id, backup_kind)`. This is rollback protection, not a cache:
    /// a complete server response below this floor must fail closed.
    #[serde(default)]
    pub key_backup_active_series_highest_seen: BTreeMap<String, u64>,
    /// Per-realm `ak.self.events.stream.subscribe` resume cursors, keyed by
    /// realm id. Kept PHYSICALLY SEPARATE from the account-aggregate
    /// `sync_cursor`: the realm events stream and the account stream are
    /// bound to different `filter_digest`s (encoding.md §8.3.1), so their
    /// cursors are not interchangeable and MUST NOT be cross-used.
    #[serde(default)]
    pub realm_events_cursors: BTreeMap<String, String>,
    /// Realm scan cursors are filter-bound and cannot share the subscription
    /// cursor slot. Keys include service, realm, and order.
    #[serde(default)]
    pub realm_scan_cursors: BTreeMap<String, String>,
    /// Crash-safe client-core deliveries. A Realm cursor and the batch it
    /// admits are committed in one local-state write; the UI projector acks
    /// only after its own durable fold succeeds.
    #[serde(default)]
    pub(crate) client_core_pending_deliveries: VecDeque<StoredClientDelivery>,
    #[serde(default)]
    pub client_core_next_delivery_id: u64,
    #[serde(default)]
    pub device_message_cursors: BTreeMap<String, String>,
    #[serde(default)]
    pub client_core_seen_event_ids: VecDeque<String>,
    pub raw_operations: Vec<RawOperationRecord>,
    #[serde(default)]
    pub realm_destroy_receipts: BTreeMap<String, RealmDestroyReceipt>,
    pub realm_tree_projections: BTreeMap<String, Value>,
    #[serde(default)]
    pub realm_collaboration_roles: BTreeMap<String, arkret_sdk::CollaborationRealmRole>,
    #[serde(default)]
    pub snapshot_sync: BTreeMap<String, SnapshotSyncStatus>,
    /// Principal-private saved-item account-data values, keyed by
    /// `ak.saved.v1:<collection_key>:<target_key>`.
    #[serde(default)]
    pub saved_account_data: BTreeMap<String, Value>,
    /// Principal-private scheduled-send plan account-data entry contents,
    /// keyed by `ak.scheduled_send.v1:<scheduled_send_id>`; values are the
    /// encrypted envelopes exactly as the account-data projection carries
    /// them (spec `models/personal-productivity.md` §4).
    #[serde(default)]
    pub scheduled_send_account_data: BTreeMap<String, Value>,
    /// Local dispatch aid: `scheduled_send_id` -> home Realm of the plan's
    /// target Strand. The spec plan value carries no `realm_id`, so the
    /// dispatch driver resolves the authoring Realm from this index (or a
    /// projection scan fallback) when it builds the `ak.message.create`
    /// envelope at expiry.
    #[serde(default)]
    pub scheduled_send_target_realms: BTreeMap<String, String>,
    pub pending_encrypted_messages: BTreeMap<String, EncryptedPayload>,
    #[serde(default)]
    pub notification_projection: Vec<StoredNotification>,
    #[serde(default)]
    pub presence_projection: Vec<Value>,
    #[serde(default)]
    pub presence_visibility: PresenceVisibility,
    /// Manual presence preference (`ak.presence.preference`,
    /// profiles-presence.md §3.6). Local state is authoritative; the
    /// account-data push is best-effort and encrypted.
    #[serde(default)]
    pub presence_preference: PresencePreference,
    /// Persisted per-device to-device inbox. Both account.subscribe
    /// `delta.to_device.messages[]` and explicit `device_messages` pulls are
    /// funneled through this queue before protocol-specific handlers consume
    /// them. Entries stay local only and are deduplicated by envelope identity
    /// plus transaction/request ids where present.
    #[serde(default)]
    pub to_device_inbox: Vec<Value>,
    /// Durable canonical-envelope digest keyed by
    /// `(sender_principal_id, sender_device_id, message_id)`.
    /// The receipt is written in the same state snapshot as the inbox entry,
    /// before any protocol-specific handler runs.
    #[serde(default)]
    pub to_device_receipts: BTreeMap<String, DeviceMessageReceipt>,
    #[serde(default)]
    pub notification_client_state: BTreeMap<String, NotificationClientState>,
    /// Invite-accept credentials delivered over the actor-private
    /// account-data carrier, keyed by invite id. Entries carry their own
    /// `expires_at`; lookup drops expired credentials, and writes cap the map
    /// at `MAX_INVITE_CREDENTIALS` (expired first, then oldest).
    #[serde(default)]
    pub invite_credentials: BTreeMap<String, StoredInviteCredential>,
    /// Per-realm watch level overrides (spec
    /// `discovery/push-notifications.md` §4.3.2). Only non-default entries are
    /// stored; an absent realm resolves to `WatchLevel::MentionsOnly`.
    #[serde(default)]
    pub realm_watch_levels: BTreeMap<String, WatchLevel>,
    #[serde(default)]
    pub muted_notification_kinds: BTreeMap<String, bool>,
    /// Actor-private do-not-disturb preference for this local account view.
    /// The synced account_data value is encrypted/opaque to the server, so
    /// notification projection must evaluate DND from the locally held
    /// plaintext preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_dnd_settings: Option<DndSettings>,
    /// Read receipt preferences (spec
    /// `discovery/client-preferences.md` §3.6, account-data key
    /// `ak.read_receipt.preferences`).
    ///
    /// Send and display preferences resolve independently.
    /// Send and display override maps share the same scope order.
    /// Until the server wires `ak.account_data.set` for this key,
    /// preferences live only on this device.
    #[serde(default = "default_true")]
    pub read_receipt_default_send: bool,
    #[serde(default = "default_true")]
    pub read_receipt_default_display: bool,
    #[serde(default)]
    pub read_receipt_realm_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub read_receipt_realm_display_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub read_receipt_strand_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub read_receipt_strand_display_overrides: BTreeMap<String, bool>,
    /// Server-declared `ak.realm.read_receipt_policy` snapshots, keyed by
    /// realm id. Populated when sync (P0 M3) lands — surfaces the
    /// disclosure / visibility values from the
    /// `ak.component.realm.read_receipt_policy.v1` cas-register cell so
    /// the settings UI can lock per-Realm toggles when the server's
    /// policy is `required` or `disabled`.
    #[serde(default)]
    pub read_receipt_policy_snapshots: BTreeMap<String, ReadReceiptPolicySnapshot>,
    /// Latest Seal view per Space, threaded from `/sync`'s Seal
    /// projection (P0 M3). Move builders pull `frontier[0]` from here
    /// instead of using the empty-bytes sentinel. UIs use the
    /// `bottom_cells` map to surface conflict banners when a cell is
    /// `bottom=expose`.
    #[serde(default)]
    pub seal_views: BTreeMap<String, LocalSealView>,
    #[serde(default)]
    pub push_registration: Option<PushRegistrationState>,
    /// Per-device ed25519 identity. Generated + persisted on first access
    /// via `LocalStateStore::ensure_local_identity`. Move builders read
    /// this in place of the historical `[42; 32]` demo seed.
    #[serde(default)]
    pub local_identity: Option<LocalIdentityRecord>,
    /// Locally-submitted Move state tracker. Keyed by `move_id`; entries
    /// arrive when `submit_move` succeeds and get updated when the next
    /// sync surfaces an Seal that includes the id (or a rejection).
    /// Drives message / realm_admin state pill UI.
    #[serde(default)]
    pub move_submissions: BTreeMap<String, MoveSubmissionRecord>,
    /// Encrypted private account data (preferences, tags, custom emojis).
    /// Values are XOR-encrypted with account_key and hex-encoded.
    #[serde(default)]
    pub private_data: BTreeMap<String, String>,
    /// Private ak.read_cursor.advance cursors keyed by Realm + read_scope.
    #[serde(default)]
    pub read_cursors: BTreeMap<String, ReadMarkerRecord>,
    /// Persisted coauth `session_grant` payload. It is the client-visible
    /// session credential for `/_arkret/self/*` and is rotated through the
    /// Account Authority refresh endpoint when it nears expiry.
    #[serde(default)]
    pub session_grant: Option<PersistedSessionGrant>,
    /// Public account-handoff and lease metadata. The opaque handoff grant is
    /// stored separately as a session credential in the secure key store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_account_handoff: Option<PendingAccountHandoff>,
    /// Resumable public registration draft. This never contains the Recovery
    /// Key or derived private material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_principal_registration: Option<PendingPrincipalRegistration>,
    /// Durable facts used to revalidate the recovery-material gate after a
    /// restart. This is public control material only; no recovery secret is
    /// retained here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_material_evidence: Option<RecoveryMaterialEvidence>,
    /// Client-side telemetry log buffer. Mirrors sodmin's
    /// Persisted MLS group state snapshots, keyed by `realm_id`. Each
    /// entry is the encrypted envelope produced by
    /// [`crate::mls::persistence::encrypt_state`]; the boot path
    /// rehydrates each Realm's MLS group state from the latest envelope
    /// rather than rejoining via Welcome from scratch.
    #[serde(default)]
    pub mls_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Pre-decrypt MLS checkpoints retained until the combined secure entry
    /// (advanced snapshot + decrypted plaintext cache) is durably confirmed.
    /// These envelopes are already device-secret-encrypted; keeping the oldest
    /// in-flight checkpoint in account state lets startup roll back and decrypt
    /// again if the IndexedDB put was interrupted by page exit.
    #[serde(default)]
    pub mls_receive_recovery_snapshots:
        BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Realms whose `ak.mls.genesis` event has already been submitted to
    /// soland. Tracked per-Realm so genesis is emitted exactly once for a
    /// locally-created creator group (the server also rejects a duplicate
    /// genesis with `mls_genesis_already_exists`, but this avoids the
    /// needless round-trip on every encrypted write after the first).
    #[serde(default)]
    pub mls_genesis_emitted: BTreeSet<String>,
    /// Exact accepted `ak.mls.genesis` / winning `ak.mls.commit` Event for
    /// the current locally persisted epoch, keyed by effective scope.
    #[serde(default)]
    pub mls_group_state_refs: BTreeMap<String, MlsGroupStateRefRecord>,
    /// Bounded accepted historical epoch references, keyed by exact
    /// `(epoch, effective scope, group)` coordinates.
    #[serde(default)]
    pub mls_historical_group_state_refs: BTreeMap<String, MlsGroupStateRefRecord>,
    /// Device-secret-encrypted historical MLS snapshots used only to
    /// reconstruct authenticated author views for old messages.
    #[serde(default)]
    pub mls_historical_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Bounded, cryptographically verified portable Agent signer evidence.
    /// Keys bind agent, method, authorization Event, state root and frontier.
    #[serde(default)]
    pub agent_signer_evidence: BTreeMap<String, CachedAgentSignerEvidence>,
    /// `encryption-and-audit.md` §2.4.1 `epoch_update_required` — effective
    /// scopes whose last E2EE application DataEvent was refused with
    /// `mls_governance_binding_stale`, keyed by
    /// `mls_effective_scope_snapshot_key`.
    ///
    /// The flag is set only by a receiver's typed refusal — never guessed from
    /// a moving Seal head. Every accepted `ak.mls.commit` also seals itself
    /// into a new Seal, so "the head moved" is not evidence that coverage
    /// lags; treating it as such makes the client emit one commit per Seal
    /// forever.
    #[serde(default)]
    pub mls_coverage_stale: BTreeMap<String, MlsCoverageStale>,
    /// Bounded cache of complete, locally verified near-current MLS governance
    /// frontier outcomes. Keys are canonical query digests; values expire
    /// quickly and are invalidated when sync observes a different accepted
    /// Seal head.
    #[serde(default)]
    pub mls_governance_proofs: BTreeMap<String, CachedMlsGovernanceProof>,
    /// Complete locally verified replay checkpoint used as the next proof
    /// base. T1 installs the event-derived Realm genesis checkpoint.
    /// Successful full verification atomically advances it to the exact target
    /// checkpoint (T3); a bare Seal basis or service response never changes
    /// this pin.
    #[serde(default)]
    pub mls_governance_checkpoints:
        BTreeMap<String, arkret_sdk::MlsGovernanceVerificationCheckpoint>,
    /// DID-P2-B — accepted DID bindings that survive a restart.
    ///
    /// Scope: this vector lives inside the **per-account** `ClientLocalState`
    /// entry (`inkson.local_state.v1.account.<core_id>` on wasm, a sibling account
    /// file on native), so principal scoping is structural — account B's blob is
    /// a different key and can never be read while account A is active. The
    /// residual scoping dimension *inside* one account is the trust domain
    /// (which server / deployment the acceptance was made against); that is
    /// carried in each binding's own `trust_domain` and is cleared selectively
    /// by [`LocalStateStore::clear_accepted_did_bindings_outside_trust_domain`].
    ///
    /// Stored as a `Vec` rather than a map because the lookup key is the SDK's
    /// six-dimension [`arkret_sdk::identity::VerifiedDidBindingKey`], which is
    /// not a string; the in-memory SDK store owns keying and de-duplication and
    /// this is only its deterministic snapshot.
    ///
    /// The element type is the SDK's [`arkret_sdk::identity::AcceptedDidBinding`]
    /// verbatim (no parallel local binding model). It serializes as
    /// `{binding, document}` and re-validates the pairing on the way back in;
    /// [`decode_accepted_did_bindings`] turns a failed row into a dropped row.
    #[serde(default, deserialize_with = "deserialize_accepted_did_bindings")]
    pub accepted_did_bindings: Vec<arkret_sdk::identity::AcceptedDidBinding>,
    /// X5.1 — local-only plaintext sidecar for the author's own encrypted
    /// private strand fields. Keyed `realm_id -> strand_id -> field_path ->
    /// plaintext` where `field_path` is the dotted private patch path
    /// emitted by the kanban writer (e.g. `"body"`, `"synthesis"`) and
    /// `plaintext` is the JSON-serialized patch *value* (the same bytes
    /// `collect_encryptable_private_patch_values` produced before
    /// encryption, decoded to a UTF-8 string).
    ///
    /// Why this exists: OpenMLS refuses (RFC 9420 forward secrecy,
    /// `validation.rs:115`) to let the *author* decrypt their own
    /// application messages — the check is a pure leaf-index comparison
    /// that fires before any key lookup. Account-secret restore
    /// reconstructs the SAME leaf, so NO author device (original or
    /// restored) can ever decrypt the author's own ciphertext. The only
    /// way the author sees their own encrypted card body/synthesis after a
    /// re-projection (refresh / board switch / live poll) is this local
    /// plaintext sidecar.
    ///
    /// CRITICAL: this MUST NEVER leave the device or enter plaintext durable
    /// account-state storage. It is written by
    /// [`LocalStateStore::save_private_plaintext`], persisted only through the
    /// account-scoped hardened secure-store cache, and exported only through
    /// the dedicated encrypted sidecar-backup path. When hardened storage is
    /// unavailable it remains memory-only.
    #[serde(default, skip_serializing)]
    pub mls_private_plaintext: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    /// YOU-02-004 — local-only decrypted-plaintext cache for REMOTE members'
    /// MLS application messages, keyed `realm_id -> payload_digest ->
    /// base64url(plaintext)`. The receive chain is persisted forward on every
    /// successful decrypt (`encryption-and-audit.md` §5.6 first duty: persist the receive chain),
    /// which deliberately consumes the per-message ratchet key — re-rendering
    /// the same ciphertext (chat scroll, board re-projection, restart)
    /// MUST therefore be served from this cache instead of replaying the
    /// ratchet from an earlier snapshot. `payload_digest` is the envelope's
    /// canonical `sha256:` digest (bound over epoch/content_type/AAD/
    /// ciphertext), so the key is stable across re-fetches of the same event.
    ///
    /// Like [`Self::mls_private_plaintext`] (the author-side sidecar) this
    /// MUST NEVER leave the device; eviction is deliberate non-behavior —
    /// once the ratchet has advanced past a message, the cache entry is the
    /// only remaining way to render it after the ratchet advances. It is
    /// persisted only through the account-scoped hardened secure-store cache
    /// and is never serialized into plaintext account-state storage. When
    /// hardened storage is unavailable it remains memory-only.
    #[serde(default, skip_serializing)]
    pub mls_decrypted_plaintext: BTreeMap<String, BTreeMap<String, String>>,
    /// Exact IdentityLink and LeafNode bytes observed through an authenticated
    /// MLS decrypt. This pairwise-to-principal mapping is private and therefore
    /// persists only in the hardened E2EE cache.
    #[serde(default, skip_serializing)]
    pub(crate) authenticated_identity_links: BTreeMap<String, LocallyAuthenticatedIdentityLink>,
    /// Per-(effective scope, MLS group, epoch) locally authoritative MLS
    /// `history_secret`s derived from a verified and durably persisted local
    /// MLS post-state. Each value is a 32-byte exporter-derived secret for
    /// `mls_exporter_aead_v1` content.
    ///
    /// Keyed `canonical scope/group key -> epoch -> secret`. Durable persistence
    /// must go through the hardened secure store; this inline field is only a transient memory
    /// fallback and is never serialized into plaintext account-state storage.
    /// Like the other MLS sidecars this is device-local. External history-key,
    /// recovery-archive, and portable-backup material belongs in the separate
    /// bounded candidate ledger and never promotes this authoritative map.
    ///
    /// Nested string-keyed maps (not a `(String, u64)` tuple key) because
    /// `serde_json` rejects non-string map keys — the store flushes to JSON, so
    /// a tuple key would silently fail to persist. `u64` epoch keys serialize as
    /// strings, which round-trips cleanly.
    #[serde(default, skip_serializing)]
    pub history_secrets: BTreeMap<String, BTreeMap<u64, Vec<u8>>>,
    /// Replay-verified MLS ciphersuite for each retained history-secret epoch.
    /// The minimal encrypted envelope intentionally carries no algorithm
    /// selector, so group-free history decryption must use this exact frozen
    /// value rather than a current registry default or an identifier prefix.
    #[serde(default)]
    pub history_epoch_cipher_suites: BTreeMap<String, BTreeMap<u64, String>>,
    /// Garth-owned bounded external candidate ledger. Secret bytes remain in
    /// the hardened secure store and never enter this metadata snapshot.
    #[serde(default)]
    pub(crate) history_candidate_state: garth::HistoryCandidateStoreSnapshot,
    /// Crash-safe history request/response-stream/retry state owned by Garth. The
    /// revision participates in compare-and-swap updates across concurrent UI
    /// tasks so ACK high-water and exact retries cannot be rolled back.
    #[serde(default)]
    pub(crate) history_runtime_state: garth::VersionedHistoryRuntimeSnapshot,
    /// Actor-private Realm remarks per
    /// `discovery/client-preferences.md` §3.7. Hydrated from the soland
    /// `/sync` `account_data[]` projection (entries with
    /// `account_data_key == "ak.contacts.realm.<realm_id>"`) and from user edits
    /// in settings. Keyed by Realm id so the sidebar / dashboard can join
    /// it against the public `RealmTreeNode.name` at render time and prefer
    /// `local_name` when set.
    #[serde(default)]
    pub realm_remarks: BTreeMap<String, crate::account_data::RealmRemark>,
    /// Account-private global Contact petnames per
    /// `discovery/client-preferences.md` §3.6. Keyed by the decrypted human
    /// Contact `principal_id`; the opaque account-data slot is verified before
    /// an entry reaches this map.
    #[serde(default, skip)]
    pub contact_remarks: BTreeMap<String, crate::account_data::ContactRemark>,
    /// Principals from the latest accepted-human Contact projection. This is a
    /// transient eligibility index: retained remarks stay in `contact_remarks`
    /// after a Contact becomes inactive, but must not decorate live surfaces.
    /// Until the Contact projection is refreshed after startup, the safe
    /// behavior is therefore to show no petnames.
    #[serde(default, skip)]
    pub accepted_human_contact_principals: BTreeSet<String>,
    /// Actor-private personal blocklist per
    /// `discovery/client-preferences.md` (`ak.account.blocklist`). Each
    /// entry hides messages from the targeted DID in chat
    /// renderers and surfaces in the Settings → Privacy panel. The
    /// Entries use the SDK's closed wire contract directly; no client-local
    /// DTO is persisted alongside it.
    #[serde(default)]
    pub client_blocklist:
        Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry>,
    /// Account Data CAS revision that produced `client_blocklist`. The
    /// blocklist payload's `version` is the same counter, not a schema marker.
    #[serde(default)]
    pub client_blocklist_revision: u64,
    /// Durable actor-block side effects awaiting the independent standard
    /// Contact tombstone leg. Consent is deliberately unrelated to Personal
    /// DM authority and is not revoked as part of this saga.
    #[serde(default)]
    pub pending_personal_block_sagas: BTreeSet<String>,
    /// Round 4 (spec a77b995) — last `trust_domain` advertised by the
    /// connected principal server's Round 4 `ServiceDescribe` response.
    /// Threaded through to strands that need to canonicalise into
    /// transport / signing transcripts.
    /// `None` until the first successful `/server/describe` lands.
    #[serde(default)]
    pub server_trust_domain: Option<String>,
    /// G3.Y0 — per-device DPoP signing key metadata persisted across launches.
    /// Used to mint `DPoP:` proofs for session-grant issuance and private
    /// refresh strands that both require a key the server can bind to `cnf.jkt`.
    ///
    /// Production callers store the private seed in `SecureKeyStore`
    /// under `auth.dpop.device_key.v1`; this state record keeps the
    /// public `jkt` + creation timestamp for diagnostics. The wasm32
    /// boot path starts with the synchronous LocalStorage wrapper and
    /// upgrades the same secure-store entries into IndexedDB +
    /// SubtleCrypto during app initialization.
    #[serde(default)]
    pub dpop_device_key: Option<DpopDeviceKeyRecord>,
    /// R3.1 (MID-2) — raw inlined `ak.member.identity.update` event
    /// envelopes harvested from `account.subscribe` `members[]` entries.
    /// Keyed by `realm_id -> actor_id -> Vec<envelope>`. The runtime
    /// store ([`crate::identity::member_identity_store::MemberIdentityStore`]) is
    /// rebuilt from this list on boot; persisting the envelopes (not the
    /// typed payload) keeps the on-disk schema stable against future
    /// `MemberIdentityUpdatePayload` extensions and lets the renderer
    /// re-decrypt encrypted carriers once an MLS welcome arrives later.
    #[serde(default)]
    pub member_identity_events: BTreeMap<String, BTreeMap<String, Vec<Value>>>,
    /// Display-only cache for reverse handle lookup by subject DID. Entries
    /// come from validated `ak.find.directory.read.list_handles_for_subject` responses
    /// or equivalent roster evidence and are never used as authority for
    /// ACL, attribution, membership, or delivery.
    #[serde(default)]
    pub member_handle_cache: BTreeMap<String, MemberHandleCacheEntry>,
    /// This account's primary personal handle (e.g. `david`), resolved at login
    /// from the account viewer. Persisted per-account so the signed-out
    /// re-login screen's account selector can label each known account by its
    /// handle (never the raw DID) — read by DID via
    /// [`LocalStateStore::primary_handle_for_did`] without making the account
    /// active.
    pub primary_handle: String,
}

/// One row for the signed-out account selector (Google-style "choose an
/// account" list). Built from the [`RootIndex`] `known_dids` joined with each
/// account's own persisted entry. The `handle` is the display label (callers
/// MUST prefer it and never render the raw `did`); `device_id` / `server_url`
/// are the values that account last signed in with, so a reuse-login targets
/// that exact device + server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAccount {
    /// Canonical account DID. Used as the actor hint + per-account key; never
    /// shown raw in the UI.
    pub did: String,
    /// Resolved primary personal handle (e.g. `david`), or empty when unknown.
    pub handle: String,
    /// The `device_id` this account last signed in with on this browser.
    pub device_id: String,
    /// The principal-server URL this account last signed in against.
    pub server_url: String,
}

/// Cross-account UI device preferences — the ONLY part of local state shared
/// between accounts on the same browser/install. Lives in the [`RootIndex`],
/// never under a per-account entry, so toggling a theme on one account is
/// observed by every account but carries no identity/account/key material.
///
/// Kept deliberately minimal: today inkson still persists theme/locale through
/// the per-account `private_data` channel, so this map is reserved for prefs
/// that are explicitly routed here. Free-form string KV so adding a pref
/// doesn't churn the on-disk schema.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePrefs {
    /// Free-form UI preference KV (e.g. `theme`, `locale`). Cross-account.
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

/// The pre-DID device material minted at login kickoff, before the principal
/// DID is known (the authorize request needs a `device_id`). Adopted into the
/// resolved account's entry — or discarded in favour of a returning account's
/// own device — once `account_me` resolves the DID. Cleared after adoption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogin {
    /// Freshly-minted device id carried in the authorize request.
    pub device_id: String,
    /// RFC 7638 thumbprint of the freshly-minted grant-binding (DPoP) key. Diagnostic
    /// mirror of the key whose private seed lives under the
    /// `pending.<device_id>` secure-store namespace.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
}

/// Small, cold-written root index that replaces the former single global
/// `ClientLocalState` blob. Each account's full [`ClientLocalState`] lives in
/// its own sibling key (`inkson.local_state.v1.account.<core_id>`); this index only
/// records which account is active, the cross-account [`DevicePrefs`], any
/// in-flight [`PendingLogin`] device material, and the set of known account
/// DIDs (for enumeration / cleanup). Hot per-write flushes touch only the
/// active account's key, never this index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootIndex {
    /// The currently-foreground account DID, or `None` when signed out / before
    /// any account has been adopted on this browser.
    #[serde(default)]
    pub active_did: Option<String>,
    /// Cross-account UI device preferences (the only shared part).
    #[serde(default)]
    pub device_prefs: DevicePrefs,
    /// Pre-DID device material minted at login kickoff; `None` outside an
    /// in-flight interactive sign-in.
    #[serde(default)]
    pub pending_login: Option<PendingLogin>,
    /// Every account DID with a persisted `…account.<did>` entry, for
    /// enumeration and cleanup. The active account is always a member.
    #[serde(default)]
    pub known_dids: Vec<String>,
}

impl RootIndex {
    /// Record `did` as a known account (idempotent), keeping the vector sorted
    /// and deduplicated so enumeration order is stable across flushes.
    pub fn note_known_did(&mut self, did: &str) {
        let did = did.trim();
        if did.is_empty() || self.known_dids.iter().any(|known| known == did) {
            return;
        }
        self.known_dids.push(did.to_owned());
        self.known_dids.sort();
    }

    /// Forget a known account DID (used when an account's entry is purged).
    pub fn forget_known_did(&mut self, did: &str) {
        self.known_dids.retain(|known| known != did);
    }
}

/// G3.Y0 — persisted shape of the per-device DPoP signing key. The
/// private seed is stored as base64url-no-pad of 32 raw ed25519 bytes.
///
/// We intentionally use ed25519 (Ed25519) rather than ES256 because every
/// other signing path in inkson is already ed25519 (device authorization,
/// move-signing, session-grant introspection proofs) and coauth's
/// `DpopVerifier` accepts the `Ed25519`
/// algorithm out of the box. Sticking with ed25519 keeps a single
/// key-format story across the client.
///
/// Production code writes the full record into
/// [`crate::secure_key_store::SecureKeyStore`] and stores an empty
/// `seed_b64` in `state.json` so diagnostics can still show the `jkt`.
/// Unit tests use the plaintext record directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopDeviceKeyRecord {
    /// Base64url-no-pad of the 32-byte ed25519 seed.
    pub seed_b64: String,
    /// RFC 7638 thumbprint of the public JWK (what soland binds as
    /// `cnf.jkt` on issued grants). Cached so the UI / refresh path can
    /// surface it without re-deriving.
    pub jkt: String,
    /// Wall-clock the key was generated. Used by the settings panel to
    /// expose "this device's DPoP key was created at …" and by audit
    /// trails if a hard-logout later needs to wipe it.
    pub created_at: DateTime<Utc>,
}

pub(crate) const MEMBER_HANDLE_CACHE_TTL_SECONDS: i64 = 60 * 60;
pub(crate) const MEMBER_HANDLE_NEGATIVE_CACHE_TTL_SECONDS: i64 = 5 * 60;

/// Persisted `ak.session.grant` issued by the Account Authority during login.
///
/// ②(A+②) model (api-conventions.md §3.3): the grant itself is the live
/// credential for `/_arkret/self/*`; soland does not mint a second
/// client-visible local session credential. Each request presents `Authorization: DPoP
/// <grant_jwt>` + a matching per-request `DPoP` proof. Keeping
/// the grant on disk lets the client keep using it directly and rotate it (DPoP
/// grant-binding DPoP proof → fresh grant) before its own expiry — no user-visible re-login
/// as long as the grant chain is still rotatable.
///
/// `session_private_key_pem` is the ephemeral holder/DPoP key material. The
/// rotation request separately proves the durable accepted-device key; neither
/// key substitutes for the other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSessionGrant {
    /// The signed grant JWT (long-lived, signed by coauth).
    pub grant_jwt: String,
    /// PKCS8 PEM of the ephemeral session signing key. Decoded with
    /// [`crate::identity::account_auth::session_grant_signing_key_from_pem`] before
    /// signing a fresh introspection proof.
    pub session_private_key_pem: String,
    /// Grant id assigned by coauth. Embedded in introspection proof claims.
    pub grant_id: String,
    /// Audience the grant is bound to (typically the principal-server URL).
    pub audience: String,
    /// Stable core principal ID (`DidCoreId`) the grant authorizes. A record
    /// holding anything else is invalid and the session is unusable; it is
    /// never repaired by back-projecting a full DID.
    pub principal_id: String,
    /// Device id bound to the grant.
    pub device_id: String,
    /// Principal-server base URL whose `/_arkret/self/*` surface accepts this grant.
    pub principal_server_url: String,
    /// When the grant itself stops being usable. Once we pass this the
    /// next refresh attempt will fail and the user must re-login.
    #[serde(default)]
    pub grant_expires_at: Option<DateTime<Utc>>,
    /// RFC 3339 timestamp of when this record was last written.
    pub stored_at: DateTime<Utc>,
}

impl Default for ClientLocalState {
    fn default() -> Self {
        Self {
            sync_cursor: None,
            key_backup_active_series_highest_seen: BTreeMap::new(),
            realm_events_cursors: BTreeMap::new(),
            realm_scan_cursors: BTreeMap::new(),
            client_core_pending_deliveries: VecDeque::new(),
            client_core_next_delivery_id: 0,
            device_message_cursors: BTreeMap::new(),
            client_core_seen_event_ids: VecDeque::new(),
            raw_operations: Vec::new(),
            realm_destroy_receipts: BTreeMap::new(),
            realm_tree_projections: BTreeMap::new(),
            realm_collaboration_roles: BTreeMap::new(),
            snapshot_sync: BTreeMap::new(),
            saved_account_data: BTreeMap::new(),
            scheduled_send_account_data: BTreeMap::new(),
            scheduled_send_target_realms: BTreeMap::new(),
            pending_encrypted_messages: BTreeMap::new(),
            notification_projection: Vec::new(),
            presence_projection: Vec::new(),
            presence_visibility: PresenceVisibility::Public,
            presence_preference: PresencePreference::default(),
            to_device_inbox: Vec::new(),
            to_device_receipts: BTreeMap::new(),
            notification_client_state: BTreeMap::new(),
            invite_credentials: BTreeMap::new(),
            realm_watch_levels: BTreeMap::new(),
            muted_notification_kinds: BTreeMap::new(),
            notification_dnd_settings: None,
            read_receipt_default_send: true,
            read_receipt_default_display: true,
            read_receipt_realm_overrides: BTreeMap::new(),
            read_receipt_realm_display_overrides: BTreeMap::new(),
            read_receipt_strand_overrides: BTreeMap::new(),
            read_receipt_strand_display_overrides: BTreeMap::new(),
            read_receipt_policy_snapshots: BTreeMap::new(),
            seal_views: BTreeMap::new(),
            push_registration: None,
            local_identity: None,
            move_submissions: BTreeMap::new(),
            private_data: BTreeMap::new(),
            read_cursors: BTreeMap::new(),
            session_grant: None,
            pending_principal_registration: None,
            recovery_material_evidence: None,
            pending_account_handoff: None,
            mls_snapshots: BTreeMap::new(),
            mls_receive_recovery_snapshots: BTreeMap::new(),
            mls_genesis_emitted: BTreeSet::new(),
            mls_group_state_refs: BTreeMap::new(),
            mls_historical_group_state_refs: BTreeMap::new(),
            mls_historical_snapshots: BTreeMap::new(),
            agent_signer_evidence: BTreeMap::new(),
            mls_coverage_stale: BTreeMap::new(),
            mls_governance_proofs: BTreeMap::new(),
            mls_governance_checkpoints: BTreeMap::new(),
            accepted_did_bindings: Vec::new(),
            mls_private_plaintext: BTreeMap::new(),
            mls_decrypted_plaintext: BTreeMap::new(),
            authenticated_identity_links: BTreeMap::new(),
            history_secrets: BTreeMap::new(),
            history_epoch_cipher_suites: BTreeMap::new(),
            history_candidate_state: garth::HistoryCandidateStoreSnapshot::default(),
            history_runtime_state: garth::VersionedHistoryRuntimeSnapshot::default(),
            realm_remarks: BTreeMap::new(),
            contact_remarks: BTreeMap::new(),
            accepted_human_contact_principals: BTreeSet::new(),
            client_blocklist: Vec::new(),
            client_blocklist_revision: 0,
            pending_personal_block_sagas: BTreeSet::new(),
            server_trust_domain: None,
            dpop_device_key: None,
            member_identity_events: BTreeMap::new(),
            member_handle_cache: BTreeMap::new(),
            primary_handle: String::new(),
        }
    }
}

/// YOU-02-004 — interior-mutable receive-chain write-back overlay.
///
/// The MLS decrypt-on-read paths only hold `&LocalStateStore` (they run
/// inside Dioxus render passes where taking the `Signal` write lock would
/// re-enter the active read borrow), yet `encryption-and-audit.md` §5.6
/// makes persisting the advanced group state after every successful decrypt
/// a MUST. This overlay is the bridge: decrypts record the advanced
/// snapshot + decrypted plaintext here through a shared `Arc<Mutex<_>>`
/// (same sharing pattern as `persist_health`), every read path and
/// [`LocalStateStore::flush`] merge it over `cached`, and `&mut self`
/// mutation paths absorb it into `cached` before touching the same maps.
#[derive(Debug, Default)]
pub(crate) struct MlsReceiveOverlay {
    /// Advanced (post-decrypt) snapshot envelopes, keyed by realm_id.
    /// Invariant: an entry here is always derived from (and strictly newer
    /// than) the `cached` envelope for the same realm; `&mut` snapshot
    /// writers clear/absorb the entry so it can never shadow a newer
    /// send-path snapshot.
    pub(crate) snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Oldest pre-decrypt checkpoint for each realm touched by this overlay.
    pub(crate) recovery_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Decrypted-plaintext cache entries pending absorption into
    /// `ClientLocalState::mls_decrypted_plaintext`
    /// (`realm_id -> payload_digest -> base64url(plaintext)`).
    pub(crate) plaintexts: BTreeMap<String, BTreeMap<String, String>>,
    pub(crate) identity_links: BTreeMap<String, LocallyAuthenticatedIdentityLink>,
}

impl MlsReceiveOverlay {
    pub(crate) fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
            && self.recovery_snapshots.is_empty()
            && self.plaintexts.is_empty()
            && self.identity_links.is_empty()
    }

    /// Merge this overlay over a `ClientLocalState` (overlay wins — see the
    /// invariant on [`Self::snapshots`]).
    pub(crate) fn apply_to(&self, state: &mut ClientLocalState) {
        for (realm_id, envelope) in &self.snapshots {
            state
                .mls_snapshots
                .insert(realm_id.clone(), envelope.clone());
        }
        for (realm_id, envelope) in &self.recovery_snapshots {
            state
                .mls_receive_recovery_snapshots
                .entry(realm_id.clone())
                .or_insert_with(|| envelope.clone());
        }
        for (realm_id, entries) in &self.plaintexts {
            let slot = state
                .mls_decrypted_plaintext
                .entry(realm_id.clone())
                .or_default();
            for (digest, plaintext) in entries {
                slot.insert(digest.clone(), plaintext.clone());
            }
        }
        for (key, identity_link) in &self.identity_links {
            state
                .authenticated_identity_links
                .insert(key.clone(), identity_link.clone());
        }
    }
}
