use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use cokret_sdk::EncryptedPayload;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::hlc::Hlc;
use crate::notification_rules::WatchLevel;

#[cfg(target_arch = "wasm32")]
const LOCAL_STATE_STORAGE_KEY: &str = "yougen.local_state.v1";

/// YOU-02-003: hard cap on the persisted `raw_operations` audit log. Each
/// user write appends one record and the whole `ClientLocalState` blob is
/// re-serialized on every flush; left unbounded it grows without limit
/// (linear native write cost) and, on wasm, eventually blows the ~5 MB
/// localStorage quota — after which *all* persistence (MLS snapshots, sync
/// cursor, plaintext sidecar) silently fails. We retain the most recent
/// `RAW_OPERATIONS_MAX` records, dropping the oldest first.
const RAW_OPERATIONS_MAX: usize = 512;
const TO_DEVICE_INBOX_MAX: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawOperationRecord {
    pub operation_id: String,
    pub realm_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmLifecycleState {
    #[serde(default)]
    pub destroyed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroyed_operation_id: Option<String>,
}

impl RealmLifecycleState {
    fn destroyed(operation_id: impl Into<String>) -> Self {
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

/// Realm-scoped cache for `ck.find.directory.list_handles_for_subject`.
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

/// 同构,待合并(05-5):与 `discovery::ReadMarkerScope`、
/// `presence_rx::ReadScopeEvent`字段一致,后续应收敛为单一 read_scope 类型。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadScope {
    pub kind: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCursorPosition {
    pub event_id: String,
    pub hlc: String,
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
    #[serde(rename = "type")]
    pub marker_type: String,
    pub body: ReadMarkerBody,
    pub actor: String,
    pub device_id: String,
    pub updated_at: DateTime<Utc>,
}

impl ReadMarkerRecord {
    pub fn ck_read_cursor_payload(&self) -> Value {
        json!({
            "id": &self.body.id,
            "schema": &self.body.schema,
            "actor_id": &self.actor,
            "device_id": &self.device_id,
            "realm_id": &self.body.realm_id,
            "read_scope": &self.body.read_scope,
            "position": &self.body.position,
            "updated_at": self.updated_at,
        })
    }

    pub fn ck_read_cursor_operation(&self) -> Value {
        json!({
            "kind": &self.marker_type,
            "payload": self.ck_read_cursor_payload(),
        })
    }
}

/// Server-declared `ck.realm.read_receipt_policy` snapshot for a Realm, as
/// surfaced to clients via the Seal view (P0 M3) once sync.rs lands.
/// Locks the per-scope toggle in the settings UI when `disclosure` is
/// `required` (server forces send) or `disabled` (server forbids send).
///
/// Until the sync wires the policy from soland's `ck.component.realm.read_receipt_policy.v1`
/// cas-register cell, this is populated by tests / dev tooling only.
/// See `_todos.md` C10.D "Policy lock UI".
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

fn raw_operation_kind(payload: &Value) -> Option<&str> {
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
/// time the store is loaded with no record present (Cokret v1 protocol is
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
    /// `did:key:z<multibase>` 编码的本地签名公钥。这是设备本地 ed25519
    /// 签名密钥的自描述编码,**不是设备 DID、也不是 actor 身份**——
    /// 设备不是独立 DID 主体。事件 `actor_id` 必须用 account/principal
    /// DID(见 spec models/actor.md §2),本字段只用于本地签名 / key
    /// store 索引。
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
    /// 32-byte seed — same RNG yougen uses for OIDC PKCE state/nonce/verifier.
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
        let seed_hex = self
            .signing_key
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        LocalIdentityRecord {
            seed_hex,
            did_key: self.local_signing_did.clone(),
        }
    }
}

/// Encode an ed25519 signing key's public half as a `did:key:z<multibase>`
/// DID. Thin wrapper over the shared [`crate::did_key`] encoder.
fn encode_did_key(signing_key: &SigningKey) -> String {
    crate::did_key::did_key_from_verifying_key(&signing_key.verifying_key())
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
/// - `PendingMlsBinding` — the Move targets an E2EE message but its `covered_seals` precondition
///   references a governance frontier the local MLS group has not yet acknowledged. Held
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
                r if r.contains("covered_seals") || r.contains("mls_binding") => {
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
    /// uses Chinese copy). Surfaces in the timeline pill / banner.
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
/// classifier the UI uses for icons (e.g. `ck.consent.grant`,
/// `ck.message.create`, `mls_commit`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveSubmissionRecord {
    pub move_id: String,
    /// Server-assigned Event id returned by `ck.self.events.submit`. Older
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

/// One competing head for a `bottom=expose` cell. Surfaced from sync so the
/// UI can render side-by-side candidates and prefill the "safer side" of a
/// conflict-repair Move.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellHead {
    /// Move (or Seal head) id that produced this candidate.
    pub move_id: String,
    /// Candidate cell value carried by that Move. `Value::Null` when soland
    /// only published the move_id without an inline value.
    #[serde(default)]
    pub value: Value,
}

/// Per-cell bottom record. `status` is the lattice `bottom=` literal (typically
/// `"expose"`) and `heads` is the competing-candidate list. `heads` may be
/// empty when soland publishes only the bottom flag without per-head values;
/// the UI then falls back to manual JSON entry on the repair dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellInfo {
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<BottomCellHead>,
}

/// Snapshot of the latest Seal view observed for a Space. Surfaced from
/// the `/sync` Seal view (P0 M3) and threaded into Move submissions so
/// every cell-driven write references the right frontier instead of the
/// `sha256(empty)` placeholder used previously.
///
/// `frontier` lists the Seal head ids the local client currently treats
/// as the predecessor set (typically a single id but multiple while a
/// concurrent fork is unresolved). `state_root` is the post-state Merkle
/// root soland published in the most recent Seal — clients can use it
/// to detect divergence between their projection and the server view.
/// `leaves` lists the Move ids covered by the current Seal batch (the
/// "leaves of the lattice that the next Seal will close over"); UIs
/// surface this so an admin can see which pending Moves an Seal
/// rotation will sweep up.
///
/// The struct is intentionally `Default` so callers that haven't received
/// any Seal view yet (offline, fresh login) still have a clean empty
/// view to feed into builders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSealView {
    /// Seal head ids that the next Move treats as predecessors. Empty
    /// vec means "no Seal seen yet" — Move builders fall back to the
    /// `sha256(empty)` sentinel.
    #[serde(default)]
    pub frontier: Vec<String>,
    /// Move ids covered by the current Seal batch (or about to be
    /// closed by the next Seal rotation). Surfaced for admin UIs.
    #[serde(default)]
    pub leaves: Vec<String>,
    /// Post-state Merkle root from the most recent Seal. Optional —
    /// brand new spaces / offline clients may not have one yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    /// Cell map snapshot: cell ref → bottom record (status + competing
    /// heads). Populated when the projection contains a `bottom=expose`
    /// cell so the UI can surface a "concurrent candidates unresolved"
    /// banner with side-by-side head values. Other cells are omitted to
    /// keep this struct compact.
    #[serde(default)]
    pub bottom_cells: BTreeMap<String, BottomCellInfo>,
    /// The current MLS epoch as published in the
    /// `ck.component.mls.epoch.v1` cas-register cell, when sync surfaces
    /// it. `None` means the Space hasn't published an MLS epoch yet (no
    /// E2EE group or pre-genesis state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_epoch: Option<u64>,
    /// The current `governance.covered_seals` cell value - the lattice
    /// frontier cell that governance Moves require predecessor coverage of
    /// before they're accepted. Surfaced as a string so the UI can render
    /// whatever shape soland publishes (typically a `ck:state:sha256:...`
    /// ref). `None` means the governance cell hasn't been observed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals: Option<String>,
    /// The per-Realm MLS `covered_seals_lag` count - how many
    /// governance Moves the MLS group has yet to acknowledge. Soland
    /// publishes this as `seal_view.covered_seals_lag` (a bare
    /// integer) when it knows the lag; clients combine it with a
    /// configurable warn threshold (default 5) to render an alert banner
    /// in `realm_admin`. `None` means soland hasn't surfaced a lag value -
    /// UI treats that as "no alert".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals_lag: Option<u64>,
    /// MLS key-schedule content hash (`sha256:<hex>`) from the
    /// `ck.component.key_schedule.v1` cas-register cell. The MLS commit
    /// path uses this as `prev_schedule`; the new commit computes a
    /// fresh schedule on top of it. `None` means the Space has not
    /// published a key schedule yet (no prior MLS commit observed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule_hash: Option<String>,
}

impl LocalSealView {
    /// SHA-256 of empty bytes — used as the "no Seal seen yet" sentinel
    /// the Move builders historically defaulted to.
    pub const EMPTY_ANCHOR_REF: &'static str =
        "ck:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Pick the single Seal ref to feed into a Move builder. Returns the
    /// first frontier head if any, otherwise the empty-bytes sentinel.
    /// When the frontier holds multiple heads (concurrent fork) this picks
    /// the lex-min head so two clients building Moves against the same
    /// view will agree on which predecessor they reference.
    pub fn move_seal_ref(&self) -> String {
        self.frontier
            .iter()
            .min()
            .cloned()
            .unwrap_or_else(|| Self::EMPTY_ANCHOR_REF.to_owned())
    }

    /// True when the view contains at least one cell with `bottom=expose`
    /// status — the UI should surface a banner.
    pub fn has_bottom_cells(&self) -> bool {
        !self.bottom_cells.is_empty()
    }

    /// True when soland has surfaced a covered_seals_lag strictly
    /// greater than `threshold`. Used by the realm_admin covered_seals
    /// alert banner to decide whether to render. Returns `false` when no
    /// lag has been published yet (the field is `None`) - the UI treats
    /// that as "no signal, no alert".
    pub fn covered_seals_lag_above(&self, threshold: u64) -> bool {
        self.covered_seals_lag.is_some_and(|lag| lag > threshold)
    }

    /// For security-relevant cell families (member.state, capability.grant),
    /// return the safer winner candidate from the cell's competing heads —
    /// the more restrictive membership value or the revoked grant. Returns
    /// `None` when:
    /// - the cell isn't a known security-relevant family (operator must pick manually — there's no
    ///   semantic safety ordering to lean on),
    /// - sync hasn't published per-head values yet (`heads` is empty),
    /// - the heads aren't comparable in the safety order.
    ///
    /// The protocol layer never auto-picks a winner; this only powers a UX
    /// "Prefer safer side" prefill — the operator still signs and submits
    /// the resulting repair Move.
    pub fn safer_winner_for(&self, cell_ref: &str) -> Option<(String, String, Value)> {
        let info = self.bottom_cells.get(cell_ref)?;
        if info.heads.len() < 2 {
            return None;
        }
        let head_a = &info.heads[0];
        let head_b = &info.heads[1];
        let safer = if cell_ref.starts_with("ck:cell:ck.component.realm.organization.v1") {
            head_a.value.clone()
        } else {
            safer_value_for_cell(cell_ref, &head_a.value, &head_b.value)?
        };
        Some((head_a.move_id.clone(), head_b.move_id.clone(), safer))
    }
}

/// Rank `a` and `b` on the cell's safety order; return whichever ranks
/// higher (more restrictive). `None` means "no order I'll commit to" —
/// either the cell family is not in the table, or both heads tie. Tying
/// is intentional: ban-vs-ban or revoke-vs-revoke is a content conflict,
/// not a safety call, so we surface no preference and the operator picks.
fn safer_value_for_cell(cell_ref: &str, a: &Value, b: &Value) -> Option<Value> {
    let rank: fn(&Value) -> u8 = if cell_ref.starts_with("ck:cell:ck.component.member.state.v1") {
        member_state_safety_rank
    } else if cell_ref.starts_with("ck:cell:ck.component.capability.grant.v1") {
        capability_grant_safety_rank
    } else {
        return None;
    };
    let ra = rank(a);
    let rb = rank(b);
    match ra.cmp(&rb) {
        std::cmp::Ordering::Greater => Some(a.clone()),
        std::cmp::Ordering::Less => Some(b.clone()),
        std::cmp::Ordering::Equal => None,
    }
}

fn member_state_safety_rank(value: &Value) -> u8 {
    let label = value
        .get("membership")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    match label {
        "ban" => 4,
        "leave" => 3,
        "knock" => 2,
        "invite" => 1,
        "join" => 0,
        _ => 0,
    }
}

fn capability_grant_safety_rank(value: &Value) -> u8 {
    let label = value
        .get("status")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    match label {
        "revoked" => 2,
        "active" => 1,
        _ => 0,
    }
}

impl LocalSealView {
    /// Best-effort extraction of an Seal view from a per-Realm `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "seal_view": {
    ///     "frontier": ["ck:seal:sha256:..."],
    ///     "leaves":   ["sha256:..."],
    ///     "state_root": "ck:state:sha256:...",
    ///     "cells": {
    ///       "ck:cell:ck.component.member.state.v1:did:web:alice": {
    ///         "bottom": "expose"
    ///       }
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Until soland publishes the full payload, missing fields default to
    /// empty / `None`. The function is total and never errors — it just
    /// degrades to `LocalSealView::default()` when fields are missing
    /// or have unexpected shapes.
    pub fn from_sync_body(body: &Value) -> Self {
        let seal = body.get("seal_view");
        let mut view = Self::default();
        let Some(seal) = seal else {
            view.ingest_structured_bottoms(body);
            view.ingest_legacy_bottom_cells(body);
            return view;
        };
        if let Some(arr) = seal.get("frontier").and_then(|v| v.as_array()) {
            view.frontier = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(arr) = seal.get("leaves").and_then(|v| v.as_array()) {
            view.leaves = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(s) = seal.get("state_root").and_then(|v| v.as_str()) {
            view.state_root = Some(s.to_owned());
        }
        // Top-level `covered_seals_lag`: soland publishes this directly
        // on the seal view (sibling of `frontier` / `leaves`) so clients
        // don't have to compute it from cell maps.
        if let Some(lag) = seal.get("covered_seals_lag").and_then(|v| v.as_u64()) {
            view.covered_seals_lag = Some(lag);
        }
        if let Some(cells) = seal.get("cells").and_then(|v| v.as_object()) {
            for (cell_ref, status) in cells {
                let bottom = status.get("bottom").and_then(|v| v.as_str());
                if let Some(b) = bottom
                    && b == "expose"
                {
                    let mut heads = Vec::new();
                    if let Some(arr) = status.get("heads").and_then(|v| v.as_array()) {
                        for h in arr {
                            let move_id = h
                                .get("move_id")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                                .unwrap_or_default();
                            if move_id.is_empty() {
                                continue;
                            }
                            let value = h.get("value").cloned().unwrap_or(Value::Null);
                            heads.push(BottomCellHead { move_id, value });
                        }
                    }
                    view.bottom_cells.insert(
                        cell_ref.clone(),
                        BottomCellInfo {
                            status: b.to_owned(),
                            heads,
                        },
                    );
                }
                // Well-known named cells surfaced for the realm_admin MLS
                // epoch widget. We accept either a raw `value` or a typed
                // `register.value` field - soland's canonical projection
                // uses the latter; tests may emit the former.
                let value_for = |status: &Value| -> Option<Value> {
                    status
                        .get("value")
                        .cloned()
                        .or_else(|| status.get("register").and_then(|r| r.get("value")).cloned())
                };
                if cell_ref.starts_with("ck:cell:ck.component.mls.epoch.v1")
                    && let Some(value) = value_for(status)
                {
                    view.mls_epoch = value
                        .as_u64()
                        .or_else(|| value.get("epoch").and_then(|v| v.as_u64()));
                }
                if cell_ref.starts_with("ck:cell:ck.component.governance.covered_seals.v1")
                    && let Some(value) = value_for(status)
                {
                    view.covered_seals = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("frontier")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
                // B3c: surface the MLS key schedule hash so the next
                // commit's SDK MLS governance binding can carry the
                // SDK-canonical "advance schedule" effect on it.
                if cell_ref.starts_with("ck:cell:ck.component.key_schedule.v1")
                    && let Some(value) = value_for(status)
                {
                    view.key_schedule_hash = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
            }
        }
        view.ingest_structured_bottoms(body);
        view.ingest_legacy_bottom_cells(body);
        view
    }

    fn ingest_structured_bottoms(&mut self, body: &Value) {
        let Some(entries) = body.get("bottoms").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in entries {
            let Some(bottom) = entry.get("bottom") else {
                continue;
            };
            let cell_ref = entry.get("cell").and_then(|v| v.as_str()).or_else(|| {
                bottom
                    .get("cells")
                    .and_then(|v| v.as_array())
                    .and_then(|cells| cells.first())
                    .and_then(|v| v.as_str())
            });
            let Some(cell_ref) = cell_ref else {
                continue;
            };
            if self.bottom_cells.contains_key(cell_ref) {
                continue;
            }
            let status = entry
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("bottom");
            let kind = bottom.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if status != "conflict" && kind != "conflict" {
                continue;
            }
            let event_ids: Vec<String> = bottom
                .get("event_ids")
                .or_else(|| bottom.get("move_ids"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let mut heads = Vec::new();
            if let Some(arr) = bottom.get("heads").and_then(|v| v.as_array()) {
                for (idx, value) in arr.iter().enumerate() {
                    let move_id = value
                        .get("move_id")
                        .and_then(|v| v.as_str())
                        .or_else(|| value.get("event_id").and_then(|v| v.as_str()))
                        .map(str::to_owned)
                        .or_else(|| event_ids.get(idx).cloned())
                        .unwrap_or_default();
                    let candidate = value.get("value").cloned().unwrap_or_else(|| value.clone());
                    heads.push(BottomCellHead {
                        move_id,
                        value: candidate,
                    });
                }
            } else {
                heads.extend(event_ids.into_iter().map(|move_id| BottomCellHead {
                    move_id,
                    value: Value::Null,
                }));
            }
            self.bottom_cells.insert(
                cell_ref.to_owned(),
                BottomCellInfo {
                    status: status.to_owned(),
                    heads,
                },
            );
        }
    }

    fn ingest_legacy_bottom_cells(&mut self, body: &Value) {
        let Some(entries) = body.get("bottom_cells").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in entries {
            let Some(cell_ref) = entry.get("cell_id").and_then(|v| v.as_str()) else {
                continue;
            };
            if self.bottom_cells.contains_key(cell_ref) {
                continue;
            }
            let Some(bottom) = entry.get("bottom") else {
                continue;
            };
            let status = match bottom.get("kind").and_then(|v| v.as_str()) {
                Some("Conflict") | Some("conflict") => "expose",
                _ => "reject",
            };
            if status != "expose" {
                continue;
            }
            let mut heads = Vec::new();
            if let Some(arr) = bottom.get("heads").and_then(|v| v.as_array()) {
                for h in arr {
                    let move_id = h
                        .get("move_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .unwrap_or_default();
                    if move_id.is_empty() {
                        continue;
                    }
                    heads.push(BottomCellHead {
                        move_id,
                        value: h.get("value").cloned().unwrap_or(Value::Null),
                    });
                }
            }
            self.bottom_cells.insert(
                cell_ref.to_owned(),
                BottomCellInfo {
                    status: status.to_owned(),
                    heads,
                },
            );
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLocalState {
    pub sync_cursor: Option<String>,
    pub raw_operations: Vec<RawOperationRecord>,
    #[serde(default)]
    pub realm_lifecycle_state: BTreeMap<String, RealmLifecycleState>,
    pub realm_tree_projections: BTreeMap<String, Value>,
    #[serde(default)]
    pub snapshot_sync: BTreeMap<String, SnapshotSyncStatus>,
    pub drafts: BTreeMap<String, String>,
    pub pending_encrypted_messages: BTreeMap<String, EncryptedPayload>,
    #[serde(default)]
    pub notification_projection: Vec<Value>,
    #[serde(default)]
    pub presence_projection: Vec<Value>,
    /// Persisted per-device to-device inbox. Both account.subscribe
    /// `delta.to_device.messages[]` and explicit `device_messages` pulls are
    /// funneled through this queue before protocol-specific handlers consume
    /// them. Entries stay local only and are deduplicated by envelope identity
    /// plus transaction/request ids where present.
    #[serde(default)]
    pub to_device_inbox: Vec<Value>,
    #[serde(default)]
    pub notification_client_state: BTreeMap<String, NotificationClientState>,
    /// Legacy binary per-realm mute map (JSON key `muted_realms`). Superseded
    /// by `realm_watch_levels`; kept as deserialize-only so existing devices
    /// migrate (`true → WatchLevel::Muted`) on next load via
    /// `migrate_legacy_realm_mutes`. Never written back to storage.
    #[serde(default, rename = "muted_realms", skip_serializing)]
    pub legacy_muted_realms: BTreeMap<String, bool>,
    /// Per-realm watch level overrides (spec
    /// `discovery/push-notifications.md` §4.3.2). Only non-default entries are
    /// stored; an absent realm resolves to `WatchLevel::MentionsOnly`.
    #[serde(default)]
    pub realm_watch_levels: BTreeMap<String, WatchLevel>,
    #[serde(default)]
    pub muted_notification_kinds: BTreeMap<String, bool>,
    /// Read receipt send preferences (spec
    /// `discovery/client-preferences.md` §3.6, account-data key
    /// `ck.read_receipt.preferences`).
    ///
    /// `read_receipt_default_send` is the global fallback (default: send).
    /// `read_receipt_realm_overrides` and `read_receipt_flow_overrides`
    /// are per-scope overrides; resolution order is (flow → realm →
    /// default), matching the SDK's `ReadReceiptPreferences::effective_send`.
    /// Until the server wires `ck.account_data.set` for this key,
    /// preferences live only on this device.
    #[serde(default = "default_true")]
    pub read_receipt_default_send: bool,
    #[serde(default)]
    pub read_receipt_realm_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub read_receipt_flow_overrides: BTreeMap<String, bool>,
    /// Server-declared `ck.realm.read_receipt_policy` snapshots, keyed by
    /// realm id. Populated when sync (P0 M3) lands — surfaces the
    /// disclosure / visibility values from the
    /// `ck.component.realm.read_receipt_policy.v1` cas-register cell so
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
    /// Drives the timeline / realm_admin state pill UI.
    #[serde(default)]
    pub move_submissions: BTreeMap<String, MoveSubmissionRecord>,
    /// Encrypted private account data (preferences, tags, custom emojis).
    /// Values are XOR-encrypted with account_key and hex-encoded.
    #[serde(default)]
    pub private_data: BTreeMap<String, String>,
    /// Private ck.read_cursor.advance cursors keyed by Realm + read_scope.
    #[serde(default)]
    pub read_cursors: BTreeMap<String, ReadMarkerRecord>,
    /// Persisted OIDC token bundle - access_token, expiry, audience and
    /// optional id_token. `refresh_token` is always stripped before this
    /// state is flushed; callers with an actor DID must use the
    /// SecureKeyStore helper to retain the refresh credential.
    #[serde(default)]
    pub oidc_tokens: Option<OidcTokenBundle>,
    /// Persisted coauth `session_grant` payload. Lets the refresh
    /// poller re-mint a principal session without bouncing the user
    /// through OIDC again. Cleared on logout or when a re-exchange
    /// surfaces a definitive "grant is dead" error.
    #[serde(default)]
    pub session_grant: Option<PersistedSessionGrant>,
    /// Client-side telemetry log buffer. Mirrors sodmin's
    /// `utils/audit.rs` shape - each entry is a structured "user action"
    /// record (actor / action / outcome / timestamp). Written by
    /// [`crate::telemetry::emit_user_action_log`] when offline; the flush
    /// path reads + clears via [`LocalStateStore::drain_telemetry`] once a
    /// network channel is available.
    ///
    /// The buffer is bounded at [`TELEMETRY_BUFFER_CAP`] (oldest
    /// entries dropped first) so a long offline session can't grow
    /// `state.json` without bound.
    #[serde(default)]
    pub telemetry_log: Vec<UserActionLogEntry>,
    /// Persisted MLS group state snapshots, keyed by `realm_id`. Each
    /// entry is the encrypted envelope produced by
    /// [`crate::mls::persistence::encrypt_state`]; the boot path
    /// rehydrates each Realm's `LocalMlsDevice` from the latest envelope
    /// rather than rejoining via Welcome from scratch.
    #[serde(default)]
    pub mls_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Realms whose `ck.mls.genesis` event has already been submitted to
    /// soland. Tracked per-Realm so genesis is emitted exactly once for a
    /// locally-created creator group (the server also rejects a duplicate
    /// genesis with `mls_genesis_already_exists`, but this avoids the
    /// needless round-trip on every encrypted write after the first).
    #[serde(default)]
    pub mls_genesis_emitted: BTreeSet<String>,
    /// X5.1 — local-only plaintext sidecar for the author's own encrypted
    /// private flow fields. Keyed `realm_id -> flow_id -> field_path ->
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
    /// CRITICAL: this MUST NEVER leave the device. It is written only by
    /// [`LocalStateStore::save_private_plaintext`] and never enters any
    /// upstream op / `ck.flow.update` payload. (Cross-device backup of the
    /// sidecar is a separate later task — not implemented here.)
    #[serde(default)]
    pub mls_private_plaintext: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    /// YOU-02-004 — local-only decrypted-plaintext cache for REMOTE members'
    /// MLS application messages, keyed `realm_id -> payload_digest ->
    /// base64url(plaintext)`. The receive chain is persisted forward on every
    /// successful decrypt (`encryption-and-audit.md` §5.6 "第一义务是接收链持久化"),
    /// which deliberately consumes the per-message ratchet key — re-rendering
    /// the same ciphertext (timeline scroll, board re-projection, restart)
    /// MUST therefore be served from this cache instead of replaying the
    /// ratchet from an earlier snapshot. `payload_digest` is the envelope's
    /// canonical `sha256:` digest (bound over epoch/content_type/AAD/
    /// ciphertext), so the key is stable across re-fetches of the same event.
    ///
    /// Like [`Self::mls_private_plaintext`] (the author-side sidecar) this
    /// MUST NEVER leave the device; eviction is deliberate non-behavior —
    /// once the ratchet has advanced past a message, the cache entry is the
    /// only remaining way to render it.
    #[serde(default)]
    pub mls_decrypted_plaintext: BTreeMap<String, BTreeMap<String, String>>,
    /// Actor-private Realm remarks per
    /// `discovery/client-preferences.md` §3.7. Hydrated from the soland
    /// `/sync` `account_data[]` projection (entries with
    /// `data_type == "ck.contacts.realm.<realm_id>"`) and from user edits
    /// in settings. Keyed by Realm id so the sidebar / dashboard can join
    /// it against the public `RealmTreeNode.name` at render time and prefer
    /// `local_name` when set.
    #[serde(default)]
    pub realm_remarks: BTreeMap<String, crate::account_data::RealmRemark>,
    /// Actor-private contact remarks per
    /// `discovery/client-preferences.md` §3.6. Keyed by actor DID and
    /// hydrated from `ck.contacts.actor.<did>` account_data entries.
    #[serde(default)]
    pub contact_remarks: BTreeMap<String, crate::account_data::ContactRemark>,
    /// Actor-private personal blocklist per
    /// `discovery/client-preferences.md` (`ck.account.blocklist`). Each
    /// entry hides messages from the targeted DID in the timeline/chat
    /// renderers and surfaces in the Settings → Privacy panel. The
    /// shape mirrors the wire body so the future
    /// `ck.account_data.set("ck.account.blocklist", …)` push can serialise
    /// straight from this `Vec`.
    #[serde(default)]
    pub client_blocklist: Vec<crate::account_data::BlocklistEntry>,
    /// Round 4 (spec a77b995) — last `trust_domain` advertised by the
    /// connected principal server's Round 4 `ServiceDescribe` response.
    /// Threaded through to flows that need to canonicalise into
    /// transport / signing transcripts (e.g. `ck.cross_signing.publish`).
    /// `None` until the first successful `/server/describe` lands.
    #[serde(default)]
    pub server_trust_domain: Option<String>,
    /// G3.Y0 — per-device DPoP signing key metadata persisted across launches.
    /// Used to mint `DPoP:` proofs for session-grant issuance and private
    /// refresh flows that both require a key the server can bind to `cnf.jkt`.
    ///
    /// Production callers store the private seed in `SecureKeyStore`
    /// under `auth.dpop.device_key.v1`; this state record keeps the
    /// public `jkt` + creation timestamp for diagnostics. The wasm32
    /// boot path starts with the synchronous LocalStorage wrapper and
    /// upgrades the same secure-store entries into IndexedDB +
    /// SubtleCrypto during app initialization.
    #[serde(default)]
    pub dpop_device_key: Option<DpopDeviceKeyRecord>,
    /// R3.1 (MID-2) — raw inlined `ck.member.identity.update` event
    /// envelopes harvested from `account.subscribe` `members[]` entries.
    /// Keyed by `realm_id -> actor_id -> Vec<envelope>`. The runtime
    /// store ([`crate::member_identity_store::MemberIdentityStore`]) is
    /// rebuilt from this list on boot; persisting the envelopes (not the
    /// typed payload) keeps the on-disk schema stable against future
    /// `MemberIdentityUpdatePayload` extensions and lets the renderer
    /// re-decrypt encrypted carriers once an MLS welcome arrives later.
    #[serde(default)]
    pub member_identity_events: BTreeMap<String, BTreeMap<String, Vec<Value>>>,
    /// Display-only cache for reverse handle lookup by subject DID. Entries
    /// come from validated `ck.find.directory.list_handles_for_subject` responses
    /// or equivalent roster evidence and are never used as authority for
    /// ACL, attribution, membership, or delivery.
    #[serde(default)]
    pub member_handle_cache: BTreeMap<String, MemberHandleCacheEntry>,
    /// Actor DID that the currently-persisted account-scoped state
    /// (sync cursor, realm-tree projections, session grant, OIDC bundle, …)
    /// belongs to. Stamped by [`LocalStateStore::adopt_account_scope`]
    /// whenever a session is established. When a new session's actor
    /// disagrees with this owner, every account-scoped record is wiped
    /// before the new session adopts the scope — this is what stops a
    /// previous identity's revoked grant or foreign-principal sync
    /// cursor from leaking into the new session (`cursor_integrity_invalid`
    /// / `session grant is not active: revoked`). `None` until the first
    /// stamp.
    #[serde(default)]
    pub account_scope_owner: Option<String>,
}

/// G3.Y0 — persisted shape of the per-device DPoP signing key. The
/// private seed is stored as base64url-no-pad of 32 raw ed25519 bytes.
///
/// We intentionally use ed25519 (EdDSA) rather than ES256 because every
/// other signing path in yougen is already ed25519 (cross-signing,
/// move-signing, session-grant introspection proofs) and coauth's
/// `DpopVerifier` (`coauth::services::dpop`) accepts the `EdDSA`
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

/// Hard cap on the number of buffered telemetry entries kept in
/// `ClientLocalState::telemetry_log`. When the cap is reached the
/// oldest entry is dropped to make room for the new one. 256 is
/// roughly two minutes of aggressive interaction at 2 actions/sec —
/// enough to survive a network blip, well below the size at which
/// `state.json` becomes painful to round-trip.
pub const TELEMETRY_BUFFER_CAP: usize = 256;
const MEMBER_HANDLE_CACHE_TTL_SECONDS: i64 = 60 * 60;
const MEMBER_HANDLE_NEGATIVE_CACHE_TTL_SECONDS: i64 = 5 * 60;

/// Structured client-side telemetry record produced by
/// [`crate::telemetry::emit_user_action_log`]. Mirrors sodmin's
/// `utils/audit.rs` line shape but keeps the fields typed so the
/// flush path can serialise straight to JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserActionLogEntry {
    /// Who took the action. For yougen this is typically the local
    /// device DID (or `did:anon` when the user hasn't logged in yet).
    pub actor: String,
    /// Verb-style action name (e.g. `message.create`,
    /// `oidc.refresh`, `device.revoke.confirm`).
    pub action: String,
    /// Result of the action; mirrors sodmin's `AdminAuditOutcome`.
    pub outcome: String,
    /// Optional free-form context (operator note, error short text).
    /// Stripped of newlines + clamped to 120 chars before persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// RFC 3339 timestamp at which the action was recorded. Set by
    /// the helper, not by the caller.
    pub recorded_at: DateTime<Utc>,
}

/// Persisted coauth `session_grant` returned by the auth-server during
/// login. Keeping this on disk lets the client re-run
/// `exchange_session_grant_at_with_proof` to mint a fresh principal
/// `access_token` after the previous one expires — no user-visible
/// re-login as long as the grant itself is still valid.
///
/// The fields mirror the inputs needed by
/// [`crate::api::CokretApi::exchange_session_grant_at_with_proof`] plus
/// the `session_private_key_pem` the introspection proof is signed with.
/// The private key here is the ephemeral session-grant key (coauth's
/// `session_public_key` registration), not the long-lived device
/// identity — losing it only invalidates the current grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSessionGrant {
    /// The signed grant JWT (long-lived, signed by coauth).
    pub grant_jwt: String,
    /// PKCS8 PEM of the ephemeral session signing key. Decoded with
    /// [`crate::coauth::session_grant_signing_key_from_pem`] before
    /// signing a fresh introspection proof.
    pub session_private_key_pem: String,
    /// Grant id assigned by coauth. Embedded in introspection proof claims.
    pub grant_id: String,
    /// Audience the grant is bound to (typically the principal-server URL).
    pub audience: String,
    /// Principal ID the grant authorizes.
    pub principal_id: String,
    /// Device id bound to the grant.
    pub device_id: String,
    /// Principal-server base URL where the grant is exchanged.
    pub principal_server_url: String,
    /// `session_grant_exchange_path` for the canonical
    /// `/_cokret/gate/account/session-grants` operation.
    pub session_grant_exchange_path: String,
    /// When the grant itself stops being usable. Once we pass this the
    /// next refresh attempt will fail and the user must re-login.
    #[serde(default)]
    pub grant_expires_at: Option<DateTime<Utc>>,
    /// When the *current* minted principal session token expires (per
    /// the most recent exchange response). Used by the refresh poller
    /// to decide whether a re-exchange is due.
    #[serde(default)]
    pub session_expires_at: Option<DateTime<Utc>>,
    /// RFC 3339 timestamp of when this record was last written.
    pub stored_at: DateTime<Utc>,
}

/// Persisted OIDC token bundle. Stored next to the device identity so a
/// single boot sequence can rehydrate both. Fields mirror the `oauth2`
/// token endpoint response shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcTokenBundle {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// `Bearer` per RFC 6750; recorded verbatim for future use.
    pub token_type: String,
    /// Unix epoch seconds at which `access_token` expires. `None` when
    /// the token endpoint did not return `expires_in`.
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
    /// `id_token` JWT — present when the OIDC scope was granted.
    #[serde(default)]
    pub id_token: Option<String>,
    /// `scope` claim from the token response (whitespace-separated).
    #[serde(default)]
    pub scope: Option<String>,
    /// `audience` claim — typically the principal-server URL the token
    /// is bound to; recorded so the client knows where it can present.
    #[serde(default)]
    pub audience: Option<String>,
    /// RFC 3339 timestamp of when the bundle was persisted (debug aid).
    pub stored_at: DateTime<Utc>,
}

impl ClientLocalState {
    /// One-way migration of the legacy binary `muted_realms` map into
    /// `realm_watch_levels`. A muted realm becomes `WatchLevel::Muted`; the
    /// legacy map is drained so it is never serialized again. Existing
    /// `realm_watch_levels` entries win (already migrated / explicitly set).
    fn migrate_legacy_realm_mutes(&mut self) {
        if self.legacy_muted_realms.is_empty() {
            return;
        }
        for (realm_id, muted) in std::mem::take(&mut self.legacy_muted_realms) {
            if muted {
                self.realm_watch_levels
                    .entry(realm_id)
                    .or_insert(WatchLevel::Muted);
            }
        }
    }
}

impl Default for ClientLocalState {
    fn default() -> Self {
        Self {
            sync_cursor: None,
            raw_operations: Vec::new(),
            realm_lifecycle_state: BTreeMap::new(),
            realm_tree_projections: BTreeMap::new(),
            snapshot_sync: BTreeMap::new(),
            drafts: BTreeMap::new(),
            pending_encrypted_messages: BTreeMap::new(),
            notification_projection: Vec::new(),
            presence_projection: Vec::new(),
            to_device_inbox: Vec::new(),
            notification_client_state: BTreeMap::new(),
            legacy_muted_realms: BTreeMap::new(),
            realm_watch_levels: BTreeMap::new(),
            muted_notification_kinds: BTreeMap::new(),
            read_receipt_default_send: true,
            read_receipt_realm_overrides: BTreeMap::new(),
            read_receipt_flow_overrides: BTreeMap::new(),
            read_receipt_policy_snapshots: BTreeMap::new(),
            seal_views: BTreeMap::new(),
            push_registration: None,
            local_identity: None,
            move_submissions: BTreeMap::new(),
            private_data: BTreeMap::new(),
            read_cursors: BTreeMap::new(),
            oidc_tokens: None,
            session_grant: None,
            telemetry_log: Vec::new(),
            mls_snapshots: BTreeMap::new(),
            mls_genesis_emitted: BTreeSet::new(),
            mls_private_plaintext: BTreeMap::new(),
            mls_decrypted_plaintext: BTreeMap::new(),
            realm_remarks: BTreeMap::new(),
            contact_remarks: BTreeMap::new(),
            client_blocklist: Vec::new(),
            server_trust_domain: None,
            dpop_device_key: None,
            member_identity_events: BTreeMap::new(),
            member_handle_cache: BTreeMap::new(),
            account_scope_owner: None,
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
struct MlsReceiveOverlay {
    /// Advanced (post-decrypt) snapshot envelopes, keyed by realm_id.
    /// Invariant: an entry here is always derived from (and strictly newer
    /// than) the `cached` envelope for the same realm; `&mut` snapshot
    /// writers clear/absorb the entry so it can never shadow a newer
    /// send-path snapshot.
    snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Decrypted-plaintext cache entries pending absorption into
    /// `ClientLocalState::mls_decrypted_plaintext`
    /// (`realm_id -> payload_digest -> base64url(plaintext)`).
    plaintexts: BTreeMap<String, BTreeMap<String, String>>,
}

impl MlsReceiveOverlay {
    fn is_empty(&self) -> bool {
        self.snapshots.is_empty() && self.plaintexts.is_empty()
    }

    /// Merge this overlay over a `ClientLocalState` (overlay wins — see the
    /// invariant on [`Self::snapshots`]).
    fn apply_to(&self, state: &mut ClientLocalState) {
        for (realm_id, envelope) in &self.snapshots {
            state
                .mls_snapshots
                .insert(realm_id.clone(), envelope.clone());
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
    }
}

#[derive(Clone, Debug)]
pub struct LocalStateStore {
    cached: ClientLocalState,
    /// Perf: whether `cached` has been reconciled with the persistence layer at
    /// least once. Before this flag existed, an empty/default account (where
    /// `cached == ClientLocalState::default()`) re-read the backing store (disk
    /// on native, localStorage on wasm) AND did a full-state `!= default`
    /// comparison on EVERY `load()` / mutation. Once loaded, `cached` is the
    /// authoritative single-process source of truth, so we skip both.
    loaded: Cell<bool>,
    /// Perf (P0 sync-apply / notifications bulk): when `> 0`, [`Self::flush`]
    /// defers the (potentially synchronous, blocking) persist and only records
    /// that a write is pending. A batch guard performs exactly one flush when
    /// the outermost batch closes. This collapses the dozens of full-state
    /// serializations a single sync/bulk mutation used to trigger into one.
    flush_suspended: u32,
    /// Set by [`Self::flush`] while suspended; consumed by the batch guard so
    /// it only persists when at least one mutation actually requested a flush.
    flush_pending: Cell<bool>,
    /// YOU-02-002/003: shared persistence-health latch. `None` = healthy;
    /// `Some(message)` records the last persist/read failure (atomic write
    /// failed, localStorage quota exceeded, or a corrupt backing store was
    /// found on boot). Shared via `Arc<Mutex<_>>` so every `Clone` of the store
    /// (the Dioxus `Signal<LocalStateStore>` is cloned widely) observes the same
    /// latch, letting the UI surface "your changes aren't being saved"
    /// instead of silently diverging from disk. Must be thread-safe because the
    /// store is held behind `Arc<Mutex<_>>` in `InMemoryKeyStore` (`KeyStore:
    /// Send + Sync`).
    persist_health: Arc<Mutex<Option<String>>>,
    /// YOU-02-004 — shared receive-chain write-back overlay (see
    /// [`MlsReceiveOverlay`]). Shared across clones like `persist_health` so
    /// a decrypt recorded through any handle is visible to every reader.
    mls_receive_overlay: Arc<Mutex<MlsReceiveOverlay>>,
    /// YOU-02-004 — serialization lock for the MLS "decrypt → state
    /// write-back" critical section. Multiple views (timeline / chat /
    /// kanban) can trigger decrypt-on-read for the same realm; holding this
    /// for the whole restore→decrypt→export→persist sequence guarantees the
    /// receive chain only ever advances from the latest persisted snapshot
    /// (never replays the ratchet from a stale clone of it). Distinct from
    /// the overlay data mutex so the short data-access sections never nest
    /// inside it in both orders (no deadlock).
    mls_decrypt_serial: Arc<Mutex<()>>,
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

fn realm_tree_projection_value_is_mls_encrypted(body: &Value) -> bool {
    fn normalized_profile(value: &str) -> String {
        value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
    }

    // YOU-05-008: shared "first non-empty string under candidate keys"
    // helper lives in `crate::realm_tree`.
    use crate::realm_tree::string_field;

    let null = Value::Null;
    let summary = body.get("summary").unwrap_or(&null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if container
            .get("encrypted")
            .or_else(|| container.get("is_encrypted"))
            .or_else(|| container.get("e2ee"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return true;
        }
        if let Some(profile) = string_field(container, &["encryption_profile"]) {
            let profile = normalized_profile(&profile);
            if matches!(profile.as_str(), "mls" | "mls_rfc9420" | "e2ee") {
                return true;
            }
        }
    }

    false
}

/// SEC-08 (`encryption-and-audit.md` §2.9) — does a cached realm-tree
/// projection declare the `ck.profile.mls.minimal_metadata_realm.v1` profile?
///
/// Mirrors soland's server-side `payload_declares_minimal_metadata_realm`
/// (`profiles[]` / `active_profiles[]` arrays) but scans the same nested
/// containers ([summary]/[object]/[realm]/[metadata]) the encryption-state
/// reader walks, since the local projection nests the realm body. The profile
/// id is the SDK constant so the client and server agree on the exact string.
fn realm_tree_projection_value_is_minimal_metadata(body: &Value) -> bool {
    fn declares_in(container: &Value) -> bool {
        ["profiles", "active_profiles"].iter().any(|field| {
            container
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|profiles| {
                    profiles.iter().any(|profile| {
                        profile.as_str() == Some(cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE)
                    })
                })
        })
    }

    let null = Value::Null;
    let summary = body.get("summary").unwrap_or(&null);
    [
        body,
        summary,
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ]
    .into_iter()
    .any(declares_in)
}

impl Default for LocalStateStore {
    fn default() -> Self {
        Self {
            cached: ClientLocalState::default(),
            loaded: Cell::new(false),
            flush_suspended: 0,
            flush_pending: Cell::new(false),
            persist_health: Arc::new(Mutex::new(None)),
            mls_receive_overlay: Arc::new(Mutex::new(MlsReceiveOverlay::default())),
            mls_decrypt_serial: Arc::new(Mutex::new(())),
            #[cfg(not(target_arch = "wasm32"))]
            path: default_state_path(),
        }
    }
}

fn member_handle_cache_key(subject_id: &str, realm_id: Option<&str>) -> String {
    let realm = realm_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("*");
    format!("{realm}\u{1f}{subject_id}")
}

impl LocalStateStore {
    const SECURE_IDENTITY_KEY: &'static str = "identity.local.primary.v1";
    const SECURE_DPOP_DEVICE_KEY: &'static str = "auth.dpop.device_key.v1";

    pub fn load(&self) -> ClientLocalState {
        // Once reconciled with persistence, `cached` is authoritative (single
        // process) — skip the full-state `!= default` compare and the repeated
        // backing-store read that an empty account used to pay on every call.
        let mut state = if self.loaded.get() || self.cached != ClientLocalState::default() {
            self.cached.clone()
        } else {
            self.read_persisted_state().unwrap_or_default()
        };
        // YOU-02-004: readers must observe receive-chain write-backs that the
        // decrypt paths recorded through the interior-mutable overlay.
        {
            let overlay = self.mls_receive_overlay.lock().unwrap();
            if !overlay.is_empty() {
                overlay.apply_to(&mut state);
            }
        }
        state
    }

    pub fn save(&mut self, state: ClientLocalState) {
        // Wholesale replacement: the incoming state is authoritative, so any
        // pending receive-chain overlay entries derived from the OLD state
        // must not survive to shadow it.
        *self.mls_receive_overlay.lock().unwrap() = MlsReceiveOverlay::default();
        self.cached = state;
        self.loaded.set(true);
        let _ = self.flush();
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        if self.flush_suspended > 0 {
            // Inside a batch — defer the persist and remember a write happened.
            self.flush_pending.set(true);
            return Ok(());
        }
        let result = self.write_persisted_state(&self.effective_state_for_persist());
        self.record_persist_result(&result);
        result
    }

    /// YOU-02-004 — the state every persist must write: `cached` with the
    /// receive-chain overlay merged over it. Without this, any unrelated
    /// setter's flush would clobber the on-disk receive-chain advancement
    /// that a decrypt recorded via the overlay (a §5.6 violation: the next
    /// boot would replay the ratchet from the stale snapshot).
    fn effective_state_for_persist(&self) -> ClientLocalState {
        let overlay = self.mls_receive_overlay.lock().unwrap();
        let mut state = self.cached.clone();
        if !overlay.is_empty() {
            overlay.apply_to(&mut state);
        }
        state
    }

    /// YOU-02-004 — drain the receive-chain overlay into `cached`. `&mut`
    /// writers that touch `mls_snapshots` / `mls_decrypted_plaintext` call
    /// this FIRST so their own write is ordered after (and therefore
    /// supersedes) any decrypt write-backs recorded so far. Safe to call
    /// from any `&mut self` context; no flush of its own (the caller's
    /// flush persists the merged result).
    fn absorb_mls_receive_overlay(&mut self) {
        self.ensure_cached_loaded();
        let mut overlay = self.mls_receive_overlay.lock().unwrap();
        if overlay.is_empty() {
            return;
        }
        let drained = std::mem::take(&mut *overlay);
        drop(overlay);
        drained.apply_to(&mut self.cached);
    }

    /// YOU-02-002: latch the outcome of a persist attempt so callers that
    /// (legitimately) drop the `Result` — the fire-and-forget setters — still
    /// leave a durable signal the UI can read via [`Self::persist_error`].
    fn record_persist_result(&self, result: &anyhow::Result<()>) {
        match result {
            Ok(()) => {
                self.persist_health.lock().unwrap().take();
            }
            Err(error) => {
                let message = error.to_string();
                tracing::error!(%error, "local state persist failed (latched for UI)");
                *self.persist_health.lock().unwrap() = Some(message);
            }
        }
    }

    /// Current persistence-health message, if the last persist/boot-read
    /// failed (atomic write error, localStorage quota exceeded, or a corrupt
    /// backing store detected on load). `None` once a subsequent persist
    /// succeeds. UI surfaces this as a "changes are not being saved" banner.
    pub fn persist_error(&self) -> Option<String> {
        self.persist_health.lock().unwrap().clone()
    }

    /// Perf: run `body` with flushing suspended, then persist at most once.
    ///
    /// Every flush-on-write setter (`save_realm_tree_projection`, `set_seal_view`,
    /// `set_notification_read`, …) becomes a no-op persist while the batch is
    /// open; the single trailing flush coalesces them. Batches nest safely —
    /// only the outermost one persists. Use this on hot paths that touch the
    /// store many times in a row (sync apply, "mark all read").
    pub fn batch<R>(&mut self, body: impl FnOnce(&mut Self) -> R) -> R {
        self.flush_suspended = self.flush_suspended.saturating_add(1);
        let result = body(self);
        self.flush_suspended = self.flush_suspended.saturating_sub(1);
        if self.flush_suspended == 0 && self.flush_pending.replace(false) {
            let persisted = self.write_persisted_state(&self.effective_state_for_persist());
            self.record_persist_result(&persisted);
        }
        result
    }

    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.ensure_cached_loaded();
        let cursor = cursor.into();
        if self.cached.sync_cursor.as_deref() == Some(cursor.as_str()) {
            return; // cursor unchanged — skip flush
        }
        self.cached.sync_cursor = Some(cursor);
        let _ = self.flush();
    }

    pub fn save_presence_projection(&mut self, events: Vec<Value>) {
        self.ensure_cached_loaded();
        if self.cached.presence_projection == events {
            return;
        }
        self.cached.presence_projection = events;
        let _ = self.flush();
    }

    pub fn ingest_to_device_messages(&mut self, messages: &[Value]) -> usize {
        if messages.is_empty() {
            return 0;
        }
        self.ensure_cached_loaded();
        let now = Utc::now();
        let before_retain = self.cached.to_device_inbox.len();
        self.cached
            .to_device_inbox
            .retain(|message| !to_device_message_expired(message, now));
        let pruned_expired = before_retain != self.cached.to_device_inbox.len();
        let mut seen: BTreeSet<String> = self
            .cached
            .to_device_inbox
            .iter()
            .map(to_device_message_dedup_key)
            .collect();
        let mut inserted = 0;
        for message in messages {
            if to_device_message_expired(message, now) {
                continue;
            }
            let key = to_device_message_dedup_key(message);
            if !seen.insert(key) {
                continue;
            }
            self.cached.to_device_inbox.push(message.clone());
            inserted += 1;
        }
        let overflow = self
            .cached
            .to_device_inbox
            .len()
            .saturating_sub(TO_DEVICE_INBOX_MAX);
        if overflow > 0 {
            self.cached.to_device_inbox.drain(0..overflow);
        }
        if inserted > 0 || pruned_expired || overflow > 0 {
            let _ = self.flush();
        }
        inserted
    }

    pub fn to_device_inbox(&self) -> Vec<Value> {
        self.load().to_device_inbox
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        realm_id: Option<String>,
        payload: Value,
    ) {
        self.ensure_cached_loaded();
        let operation_id = operation_id.into();
        if raw_operation_kind(&payload) == Some("ck.realm.destroy")
            && let Some(realm_id) = realm_id.as_deref().filter(|id| !id.trim().is_empty())
        {
            self.cached.realm_lifecycle_state.insert(
                realm_id.to_owned(),
                RealmLifecycleState::destroyed(operation_id.clone()),
            );
        }
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id,
            realm_id,
            received_at: Utc::now(),
            payload,
        });
        // YOU-02-003: roll the audit log so it can't grow without bound (and,
        // on wasm, eventually exhaust the localStorage quota and make all
        // persistence fail silently). Drop the oldest records past the cap.
        let len = self.cached.raw_operations.len();
        if len > RAW_OPERATIONS_MAX {
            self.cached
                .raw_operations
                .drain(0..len - RAW_OPERATIONS_MAX);
        }
        let _ = self.flush();
    }

    pub fn update_raw_operation_write_state(
        &mut self,
        operation_id: &str,
        write_state: &str,
        event_id: Option<String>,
        error: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let Some(record) = self
            .cached
            .raw_operations
            .iter_mut()
            .find(|record| record.operation_id == operation_id)
        else {
            return false;
        };
        let Some(payload) = record.payload.as_object_mut() else {
            return false;
        };
        payload.insert(
            "write_state".to_owned(),
            Value::String(write_state.to_owned()),
        );
        match event_id {
            Some(event_id) => {
                payload.insert("event_id".to_owned(), Value::String(event_id));
            }
            None => {
                payload.remove("event_id");
            }
        }
        match error {
            Some(error) => {
                payload.insert("error".to_owned(), Value::String(error));
            }
            None => {
                payload.remove("error");
            }
        }
        let _ = self.flush();
        true
    }

    /// Round R2/R3 (T07) — has the Realm (security boundary, formerly Space)
    /// emitted a `ck.realm.destroy` event we've already received? The
    /// timeline / chat UI MUST gray out the send box and surface the
    /// "permanently retired" banner once this returns true.
    ///
    /// Backed by `realm_lifecycle_state`, which is updated as local raw
    /// operations are appended. This keeps the timeline send-box guard at
    /// a constant-time lookup instead of scanning the raw operation log on
    /// every render.
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        if realm_id.is_empty() {
            return false;
        }
        self.load()
            .realm_lifecycle_state
            .get(realm_id)
            .is_some_and(|state| state.destroyed)
    }

    pub fn save_realm_tree_projection(
        &mut self,
        projection_id: impl Into<String>,
        projection: Value,
    ) {
        self.ensure_cached_loaded();
        let projection_id = projection_id.into();
        if self.cached.realm_tree_projections.get(&projection_id) == Some(&projection) {
            return; // projection identical — skip flush + dirtying renders
        }
        self.cached
            .realm_tree_projections
            .insert(projection_id, projection);
        let _ = self.flush();
    }

    pub fn apply_snapshot_chunks(
        &mut self,
        manifest: &cokret_sdk::SnapshotManifest,
        chunks: &[cokret_sdk::SnapshotChunkPayload],
        trust_state: crate::snapshot::SnapshotTrustState,
    ) -> anyhow::Result<()> {
        let report = cokret_sdk::verify_snapshot_manifest(
            manifest,
            chunks,
            &cokret_sdk::SnapshotVerifyOptions::standard(
                Utc::now(),
                cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
            ),
        )
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code.as_str(), error.message))?;

        let mut projections = Vec::new();
        let mut encrypted_messages = Vec::new();
        for chunk in chunks {
            for item in &chunk.items {
                if item.id.trim().is_empty() {
                    anyhow::bail!("snapshot item id must not be empty");
                }
                projections.push((item.id.clone(), item.object.clone()));
                if let Some(payload) = snapshot_item_encrypted_payload(item) {
                    encrypted_messages.push((item.id.clone(), payload));
                }
            }
        }

        let status = SnapshotSyncStatus {
            manifest_id: manifest.id.to_string(),
            trust_state,
            updated_at: Utc::now(),
            source_event_ids: report
                .source_event_ids
                .into_iter()
                .map(|event_id| event_id.to_string())
                .collect(),
            degraded_reason: None,
        };
        let realm_id = manifest.realm_id.to_string();

        self.batch(|store| {
            for (projection_id, projection) in projections {
                store.save_realm_tree_projection(projection_id, projection);
            }
            for (message_id, payload) in encrypted_messages {
                store.preserve_encrypted_message(message_id, payload);
            }
            store.ensure_cached_loaded();
            store.cached.snapshot_sync.insert(realm_id, status);
            store.flush_pending.set(true);
        });
        Ok(())
    }

    pub fn mark_snapshot_degraded(
        &mut self,
        realm_id: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let status = SnapshotSyncStatus {
            manifest_id: String::new(),
            trust_state: crate::snapshot::SnapshotTrustState::Degraded,
            updated_at: Utc::now(),
            source_event_ids: Vec::new(),
            degraded_reason: Some(reason.into()),
        };
        self.cached.snapshot_sync.insert(realm_id, status);
        let _ = self.flush();
    }

    pub fn snapshot_sync_status(&self, realm_id: &str) -> Option<SnapshotSyncStatus> {
        self.load().snapshot_sync.get(realm_id).cloned()
    }

    /// R3.1 MID-2 — record inlined `ck.member.identity.update` event
    /// envelopes harvested off a `members[]` roster entry. Idempotent
    /// on event id; events that already exist for this `(realm, actor)`
    /// pair are skipped. The runtime
    /// [`crate::member_identity_store::MemberIdentityStore`] is rebuilt
    /// from these envelopes on demand.
    pub fn ingest_member_identity_events(
        &mut self,
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        events: &[Value],
    ) {
        if events.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let actor_id = actor_id.into();
        let bucket = self
            .cached
            .member_identity_events
            .entry(realm_id)
            .or_default()
            .entry(actor_id)
            .or_default();
        for event in events {
            let Some(event_id) = event.get("event_id").and_then(Value::as_str) else {
                continue;
            };
            let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
            if kind != "ck.member.identity.update" {
                continue;
            }
            let already = bucket.iter().any(|existing| {
                existing
                    .get("event_id")
                    .and_then(Value::as_str)
                    .is_some_and(|existing_id| existing_id == event_id)
            });
            if !already {
                bucket.push(event.clone());
            }
        }
        let _ = self.flush();
    }

    /// R3.1 MID-3 — return the resolved [`cokret_sdk::MemberIdentity`]
    /// for `(realm_id, actor_id)`, or `None` when no plaintext identity
    /// has been observed (decryption pending or no events ingested
    /// yet). UI surfaces SHOULD fall back to a muted placeholder when
    /// [`is_member_decryption_pending`] returns `true`, and to the
    /// compact DID otherwise.
    pub fn resolved_member_identity(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<cokret_sdk::MemberIdentity> {
        let envelopes = self.member_identity_envelopes(realm_id, actor_id);
        if envelopes.is_empty() {
            return None;
        }
        let mut store = crate::member_identity_store::MemberIdentityStore::new();
        store.ingest_inline(realm_id, actor_id, &envelopes);
        store.current_identity(realm_id, actor_id)
    }

    /// R3.1 MID-6 — `true` when the actor has at least one identity
    /// event but every effective event is `decryption_pending` (the
    /// MLS group state needed to decrypt the carrier has not yet
    /// arrived). UI surfaces a muted placeholder rather than the raw
    /// DID in this state.
    pub fn is_member_decryption_pending(&self, realm_id: &str, actor_id: &str) -> bool {
        let envelopes = self.member_identity_envelopes(realm_id, actor_id);
        if envelopes.is_empty() {
            return false;
        }
        let mut store = crate::member_identity_store::MemberIdentityStore::new();
        store.ingest_inline(realm_id, actor_id, &envelopes);
        store.is_decryption_pending(realm_id, actor_id)
    }

    /// Return a fresh cached primary handle lookup for a subject in a Realm
    /// display context. `Some(entry)` with `entry.primary_handle == None` is
    /// a fresh negative cache entry; callers should not immediately re-query.
    pub fn cached_member_handle_lookup(
        &self,
        subject_id: &str,
        realm_id: Option<&str>,
        member_display_state_digest: Option<&str>,
    ) -> Option<MemberHandleCacheEntry> {
        let subject_id = subject_id.trim();
        if subject_id.is_empty() {
            return None;
        }
        let state = self.load();
        let key = member_handle_cache_key(subject_id, realm_id);
        let entry = state.member_handle_cache.get(&key)?;
        if entry.cache_expires_at <= Utc::now() {
            return None;
        }
        if let Some(expected) = member_display_state_digest
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match entry.member_display_state_digest.as_deref() {
                Some(cached) if cached == expected => {}
                _ => return None,
            }
        }
        Some(entry.clone())
    }

    /// Save a display-only `list_handles_for_subject` result. The cache TTL
    /// is capped at one hour, and additionally capped by the earliest visible
    /// claim expiry when the response supplies one. Empty results use a short
    /// negative-cache TTL so a render loop does not hammer the Directory.
    pub fn save_member_handle_lookup(
        &mut self,
        subject_id: impl Into<String>,
        realm_id: Option<String>,
        member_display_state_digest: Option<String>,
        primary_handle: Option<String>,
        claims_count: usize,
        as_of: Option<DateTime<Utc>>,
        earliest_claim_expires_at: Option<DateTime<Utc>>,
    ) {
        self.ensure_cached_loaded();
        let subject_id = subject_id.into();
        let subject_id = subject_id.trim();
        if subject_id.is_empty() {
            return;
        }
        let realm_id = realm_id
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let primary_handle = primary_handle
            .and_then(|value| crate::identity_handle::parse_user_handle(&value).map(|h| h.display));
        let now = Utc::now();
        let ttl = if primary_handle.is_some() || claims_count > 0 {
            MEMBER_HANDLE_CACHE_TTL_SECONDS
        } else {
            MEMBER_HANDLE_NEGATIVE_CACHE_TTL_SECONDS
        };
        let mut cache_expires_at = now + chrono::Duration::seconds(ttl);
        if let Some(claim_expiry) = earliest_claim_expires_at
            && claim_expiry > now
            && claim_expiry < cache_expires_at
        {
            cache_expires_at = claim_expiry;
        }
        let entry = MemberHandleCacheEntry {
            subject_id: subject_id.to_owned(),
            realm_id: realm_id.clone(),
            primary_handle,
            claims_count,
            fetched_at: now,
            as_of,
            cache_expires_at,
            member_display_state_digest: member_display_state_digest
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
        };
        let key = member_handle_cache_key(subject_id, realm_id.as_deref());
        self.cached.member_handle_cache.insert(key, entry);
        let _ = self.flush();
    }

    fn member_identity_envelopes(&self, realm_id: &str, actor_id: &str) -> Vec<Value> {
        self.cached
            .member_identity_events
            .get(realm_id)
            .and_then(|by_actor| by_actor.get(actor_id))
            .cloned()
            .unwrap_or_default()
    }

    /// Drop every `realm_tree_projections` entry whose key isn't in `keep`.
    /// Used by the sync reconcile path when `after=None` so Realm/Space
    /// projection nodes the server no longer reports get pruned from the
    /// local cache instead of lingering as ghost entries in the sidebar.
    ///
    /// Also prunes the auxiliary per-Realm caches (`drafts`,
    /// `seal_views`, `read_cursors`, `realm_remarks`,
    /// `mls_snapshots`, `move_submissions` keyed by Realm, the
    /// `read_receipt_*_overrides`, `read_receipt_policy_snapshots`,
    /// `realm_watch_levels`, and any leftover encrypted-message draft) so a
    /// pruned Realm/Space node doesn't leave private remnants behind.
    pub fn retain_realm_tree_projections<F>(&mut self, keep: F) -> Vec<String>
    where
        F: Fn(&str) -> bool,
    {
        self.ensure_cached_loaded();
        let removed: Vec<String> = self
            .cached
            .realm_tree_projections
            .keys()
            .filter(|id| !keep(id))
            .cloned()
            .collect();
        if removed.is_empty() {
            return removed;
        }
        for id in &removed {
            self.forget_realm_tree_projection_inner(id);
        }
        let _ = self.flush();
        removed
    }

    /// Remove a single Realm Tree projection node and every derived record
    /// keyed by the same id. Public entry point for `left_realms`-style sync
    /// deltas. Flushes once.
    pub fn forget_realm_tree_projection(&mut self, projection_id: &str) {
        self.ensure_cached_loaded();
        let trimmed = projection_id.trim();
        if trimmed.is_empty() {
            return;
        }
        self.forget_realm_tree_projection_inner(trimmed);
        let _ = self.flush();
    }

    fn forget_realm_tree_projection_inner(&mut self, projection_id: &str) {
        self.cached.realm_tree_projections.remove(projection_id);
        self.cached.realm_lifecycle_state.remove(projection_id);
        self.cached.drafts.remove(projection_id);
        self.cached.seal_views.remove(projection_id);
        self.cached.realm_remarks.remove(projection_id);
        self.cached.mls_snapshots.remove(projection_id);
        self.cached.realm_watch_levels.remove(projection_id);
        self.cached
            .read_receipt_realm_overrides
            .remove(projection_id);
        self.cached
            .read_receipt_policy_snapshots
            .remove(projection_id);
        // `read_cursors` are keyed by `"{realm}\n{kind}\n{ref}\n{track}"` —
        // strip every marker whose Realm prefix matches.
        let prefix = format!("{projection_id}\n");
        self.cached
            .read_cursors
            .retain(|key, _| !key.starts_with(&prefix));
        // `move_submissions` carry a `realm_id` field; drop matching entries.
        self.cached
            .move_submissions
            .retain(|_, record| record.realm_id != projection_id);
        // `pending_encrypted_messages` are keyed by message id, not space id,
        // so we leave them alone — the per-message flush path will reject
        // them if the target Space is gone.
    }

    /// Wipe every account-scoped projection field while keeping
    /// device-level state (`local_identity`, `push_registration`,
    /// `telemetry_log`) and the auth-token state (`oidc_tokens`,
    /// `session_grant`). Called on logout, when the principal DID
    /// changes between logins, or when the user switches servers —
    /// anything that means the cached *projection* no longer
    /// represents the current viewer.
    ///
    /// The auth tokens are deliberately preserved here because the
    /// caller usually has its own opinion: a fresh-login flow has just
    /// written the new account's tokens via `set_oidc_tokens` and would
    /// be sad to see them disappear, while a `logout` flow follows up
    /// with explicit `set_oidc_tokens(None)` + `set_session_grant(None)`
    /// of its own. Bundling the token clear into this helper would have
    /// made the account-change-during-connect path racy.
    ///
    /// Pairs with [`Self::retain_realm_tree_projections`] which only handles
    /// the steady-state sync reconcile case.
    pub fn clear_account_scoped(&mut self) {
        self.ensure_cached_loaded();
        let preserved_identity = self.cached.local_identity.clone();
        let preserved_push = self.cached.push_registration.clone();
        let preserved_telemetry = std::mem::take(&mut self.cached.telemetry_log);
        let preserved_oidc = self.cached.oidc_tokens.clone();
        let preserved_grant = self.cached.session_grant.clone();
        // G3.Y0 — the DPoP device key is device-level state, same
        // semantics as `local_identity`. Preserved across the
        // soft-logout / account-change paths so a re-authentication on
        // this device keeps `cnf.jkt` stable; only the hard-logout flow
        // (`clear_device_scoped`) wipes it.
        let preserved_dpop = self.cached.dpop_device_key.clone();
        // YOU-02-004: the MLS receive-chain overlay is account-scoped state —
        // wipe it with the rest so a stale decrypt write-back can't resurrect
        // the previous account's MLS snapshots through a later flush merge.
        *self.mls_receive_overlay.lock().unwrap() = MlsReceiveOverlay::default();
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            telemetry_log: preserved_telemetry,
            oidc_tokens: preserved_oidc,
            session_grant: preserved_grant,
            dpop_device_key: preserved_dpop,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
    }

    /// Stamp the current account-scope owner without wiping anything.
    /// Used by paths that have already validated the actor (e.g. the
    /// connect bootstrap's account viewer probe) and just need to record
    /// who the account-scoped state now belongs to so a later
    /// [`adopt_account_scope`](Self::adopt_account_scope) recognises it.
    pub fn stamp_account_scope_owner(&mut self, actor: &str) {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        let next = (!actor.is_empty()).then(|| actor.to_owned());
        if self.cached.account_scope_owner == next {
            return;
        }
        self.cached.account_scope_owner = next;
        let _ = self.flush();
    }

    /// Adopt the account-scope for `actor`. When the persisted scope
    /// belongs to a *different* — or unknown — actor, every account-scoped
    /// record is wiped first: sync cursor, projections, drafts, **and the
    /// session grant + OIDC bundle** (which `clear_account_scoped` alone
    /// preserves — wrong across an identity change). Device-level state
    /// (local identity, push registration, DPoP key) is preserved.
    ///
    /// This is the single guard that stops a previous identity's *revoked*
    /// session grant or *foreign-principal* sync cursor from bleeding into
    /// a freshly established session — the root of the `cursor_integrity_invalid`
    /// / `session grant is not active: revoked` cascade. Call it whenever a
    /// session is (re-)established for `actor` (login, and the connect
    /// bootstrap once the canonical actor is known).
    ///
    /// Returns `true` when a wipe happened.
    pub fn adopt_account_scope(&mut self, actor: &str) -> bool {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        let owner_matches = self
            .cached
            .account_scope_owner
            .as_deref()
            .map(str::trim)
            .is_some_and(|owner| !owner.is_empty() && owner == actor);
        if owner_matches {
            return false;
        }
        self.clear_account_scoped();
        self.cached.session_grant = None;
        self.cached.oidc_tokens = None;
        self.cached.account_scope_owner = (!actor.is_empty()).then(|| actor.to_owned());
        let _ = self.flush();
        true
    }

    /// G3.Y0 — hard logout: wipe everything `clear_account_scoped`
    /// would wipe, PLUS the device DPoP key, push registration, and
    /// local identity. The next sign-in starts from a clean slate
    /// (new `cnf.jkt`, new `did:key`).
    ///
    /// Distinct from `clear_account_scoped` (which is the soft path —
    /// session expired, server-switch, account-change). The split is
    /// the public surface for the G3.Y0 soft-vs-hard logout contract:
    /// soft keeps device material so the user can re-authenticate on
    /// the same `cnf.jkt`; hard rotates the device key.
    pub fn clear_device_scoped(&mut self) {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            let _ = secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY);
        }
        self.ensure_cached_loaded();
        *self.mls_receive_overlay.lock().unwrap() = MlsReceiveOverlay::default();
        self.cached = ClientLocalState::default();
        let _ = self.flush();
    }

    /// G3.Y0 — read the persisted device DPoP key, if any.
    pub fn dpop_device_key(&self) -> Option<DpopDeviceKeyRecord> {
        self.load().dpop_device_key
    }

    /// G3.Y0 — persist (or clear via `None`) the device DPoP key.
    pub fn set_dpop_device_key(&mut self, record: Option<DpopDeviceKeyRecord>) {
        #[cfg(not(test))]
        if record.is_none() {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            if let Err(error) = secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY) {
                tracing::debug!(
                    ?error,
                    "secure_key_store DPoP key delete on clear failed (likely already missing)",
                );
            }
        }
        self.ensure_cached_loaded();
        self.cached.dpop_device_key = record;
        let _ = self.flush();
    }

    /// Persist the DPoP key through `SecureKeyStore`. The private seed
    /// is written to the secure backend; `state.json` keeps only the
    /// public diagnostics (`jkt`, `created_at`) with an empty seed.
    pub fn set_dpop_device_key_with_secure_store(
        &mut self,
        record: Option<DpopDeviceKeyRecord>,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        let public_record = match record {
            Some(record) => {
                store_dpop_device_key_in_secure_store(secure_store, &record)?;
                let mut public_record = record;
                public_record.seed_b64.clear();
                Some(public_record)
            }
            None => {
                secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY)?;
                None
            }
        };
        self.ensure_cached_loaded();
        self.cached.dpop_device_key = public_record.clone();
        let _ = self.flush();
        Ok(public_record)
    }

    /// Load the DPoP key from `SecureKeyStore`, migrating a legacy
    /// plaintext seed from `state.json` when one is present.
    pub fn load_dpop_device_key_with_secure_store(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        if let Some(record) = load_dpop_device_key_from_secure_store(secure_store)? {
            return Ok(Some(record));
        }

        let Some(record) = self.dpop_device_key() else {
            return Ok(None);
        };
        if record.seed_b64.trim().is_empty() {
            return Ok(None);
        }
        store_dpop_device_key_in_secure_store(secure_store, &record)?;
        Ok(Some(record))
    }

    pub fn save_draft(&mut self, draft_scope_id: impl Into<String>, draft: impl Into<String>) {
        self.ensure_cached_loaded();
        let draft_scope_id = draft_scope_id.into();
        let draft = draft.into();
        if draft.trim().is_empty() {
            if self.cached.drafts.remove(&draft_scope_id).is_none() {
                return; // nothing to clear — skip flush
            }
        } else {
            if self.cached.drafts.get(&draft_scope_id) == Some(&draft) {
                return; // draft unchanged — skip flush
            }
            self.cached.drafts.insert(draft_scope_id, draft);
        }
        let _ = self.flush();
    }

    pub fn draft_for(&self, draft_scope_id: &str) -> String {
        self.cached
            .drafts
            .get(draft_scope_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn preserve_encrypted_message(
        &mut self,
        message_id: impl Into<String>,
        payload: EncryptedPayload,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .pending_encrypted_messages
            .insert(message_id.into(), payload);
        let _ = self.flush();
    }

    pub fn pending_encrypted_count(&self) -> usize {
        self.cached.pending_encrypted_messages.len()
    }

    pub fn save_notification_projection(&mut self, notifications: Vec<Value>) {
        self.ensure_cached_loaded();
        self.cached.notification_projection = notifications;
        let _ = self.flush();
    }

    pub fn notification_projection(&self) -> Vec<Value> {
        self.load().notification_projection
    }

    pub fn set_notification_read(&mut self, notification_id: impl Into<String>, read: bool) {
        self.ensure_cached_loaded();
        let entry = self
            .cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default();
        if entry.read == read {
            return; // no change — don't dirty the store
        }
        entry.read = read;
        let _ = self.flush();
    }

    pub fn set_notification_archived(
        &mut self,
        notification_id: impl Into<String>,
        archived: bool,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default()
            .archived = archived;
        let _ = self.flush();
    }

    pub fn notification_state_for(&self, notification_id: &str) -> NotificationClientState {
        self.load()
            .notification_client_state
            .get(notification_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn save_read_cursor(
        &mut self,
        actor: impl Into<String>,
        device_id: impl Into<String>,
        realm_id: impl Into<String>,
        topic_id: Option<String>,
        event_id: impl Into<String>,
    ) -> ReadMarkerRecord {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let device_id = device_id.into();
        let event_id = event_id.into();
        let topic_id = topic_id.filter(|topic| !topic.trim().is_empty());
        let read_scope = read_scope_for_cursor(&realm_id, topic_id.as_deref());
        let position = ReadCursorPosition {
            event_id,
            hlc: Hlc::now(&device_id).to_string(),
        };
        let marker = ReadMarkerRecord {
            marker_type: "ck.read_cursor.advance".to_owned(),
            body: ReadMarkerBody {
                id: new_read_cursor_id(),
                schema: "ck.schema.read_cursor.v1".to_owned(),
                realm_id: realm_id.clone(),
                read_scope: read_scope.clone(),
                position,
            },
            actor: actor.into(),
            device_id,
            updated_at: Utc::now(),
        };
        self.cached
            .read_cursors
            .insert(read_cursor_key(&realm_id, &read_scope), marker.clone());
        let _ = self.flush();
        marker
    }

    pub fn read_cursor_for(
        &self,
        realm_id: &str,
        topic_id: Option<&str>,
    ) -> Option<ReadMarkerRecord> {
        self.load()
            .read_cursors
            .get(&read_cursor_key(
                realm_id,
                &read_scope_for_cursor(realm_id, topic_id),
            ))
            .cloned()
    }

    pub fn latest_read_cursor(&self, realm_id: &str) -> Option<ReadMarkerRecord> {
        self.load()
            .read_cursors
            .into_values()
            .filter(|marker| marker.body.realm_id == realm_id)
            .max_by(|left, right| left.updated_at.cmp(&right.updated_at))
    }

    // ── Per-realm watch level (spec push-notifications.md §4.3.2) ──
    //
    // Replaces the legacy binary mute map. A realm with no stored entry
    // resolves to the protocol default `WatchLevel::MentionsOnly`; only
    // non-default levels are persisted. Binary "mute" is just the `Muted`
    // end of this scale, so the `*_muted` helpers below stay as thin
    // wrappers for the notification drawer / chat sidebar toggles.

    /// Set (or clear) the per-realm watch level. Storing the default
    /// (`MentionsOnly`) removes the override so the realm follows global
    /// defaults again.
    pub fn set_realm_watch_level(&mut self, realm_id: impl Into<String>, level: WatchLevel) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if level == WatchLevel::default() {
            self.cached.realm_watch_levels.remove(&realm_id);
        } else {
            self.cached.realm_watch_levels.insert(realm_id, level);
        }
        let _ = self.flush();
    }

    /// Effective per-realm watch level (default `MentionsOnly` when unset).
    pub fn realm_watch_level(&self, realm_id: &str) -> WatchLevel {
        self.load()
            .realm_watch_levels
            .get(realm_id)
            .copied()
            .unwrap_or_default()
    }

    /// All non-default per-realm watch level overrides.
    pub fn realm_watch_levels(&self) -> BTreeMap<String, WatchLevel> {
        self.load().realm_watch_levels
    }

    pub fn set_realm_muted(&mut self, realm_id: impl Into<String>, muted: bool) {
        let level = if muted {
            WatchLevel::Muted
        } else {
            WatchLevel::default()
        };
        self.set_realm_watch_level(realm_id, level);
    }

    pub fn clear_muted_realms(&mut self) {
        self.ensure_cached_loaded();
        self.cached
            .realm_watch_levels
            .retain(|_, level| *level != WatchLevel::Muted);
        let _ = self.flush();
    }

    pub fn is_realm_muted(&self, realm_id: &str) -> bool {
        self.realm_watch_level(realm_id) == WatchLevel::Muted
    }

    pub fn muted_realms(&self) -> Vec<String> {
        self.load()
            .realm_watch_levels
            .into_iter()
            .filter_map(|(realm_id, level)| (level == WatchLevel::Muted).then_some(realm_id))
            .collect()
    }

    // ── Read receipt preferences (spec client-preferences.md §3.6) ─

    pub fn read_receipt_default_send(&self) -> bool {
        self.load().read_receipt_default_send
    }

    pub fn set_read_receipt_default_send(&mut self, send: bool) {
        self.ensure_cached_loaded();
        self.cached.read_receipt_default_send = send;
        let _ = self.flush();
    }

    pub fn read_receipt_realm_override(&self, realm_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_realm_overrides
            .get(realm_id)
            .copied()
    }

    pub fn set_read_receipt_realm_override(
        &mut self,
        realm_id: impl Into<String>,
        send: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        match send {
            Some(value) => {
                self.cached
                    .read_receipt_realm_overrides
                    .insert(realm_id, value);
            }
            None => {
                self.cached.read_receipt_realm_overrides.remove(&realm_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_realm_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_realm_overrides
    }

    pub fn read_receipt_flow_override(&self, flow_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_flow_overrides
            .get(flow_id)
            .copied()
    }

    pub fn set_read_receipt_flow_override(
        &mut self,
        flow_id: impl Into<String>,
        send: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let flow_id = flow_id.into();
        match send {
            Some(value) => {
                self.cached
                    .read_receipt_flow_overrides
                    .insert(flow_id, value);
            }
            None => {
                self.cached.read_receipt_flow_overrides.remove(&flow_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_flow_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_flow_overrides
    }

    // ── Realm remarks (spec client-preferences.md §3.7) ─

    /// Return the stored remark for `realm_id`, if any. `None` means the
    /// user has not set a local override and the public Realm title
    /// should be rendered.
    pub fn realm_remark(&self, realm_id: &str) -> Option<crate::account_data::RealmRemark> {
        self.load().realm_remarks.get(realm_id).cloned()
    }

    /// All known Realm remarks. The settings UI uses this to render the
    /// edit list; callers MUST NOT publish this map to other Realm
    /// members — it is actor-private per §3.7.
    pub fn realm_remarks(&self) -> BTreeMap<String, crate::account_data::RealmRemark> {
        self.load().realm_remarks
    }

    /// Upsert a remark for `realm_id`. Passing a remark whose
    /// [`RealmRemark::is_empty`] returns true tombstones the entry
    /// (equivalent to `remove_realm_remark`). Persists synchronously to
    /// disk; the caller is responsible for pushing the same payload to
    /// soland via `ck.account_data.set`.
    pub fn set_realm_remark(
        &mut self,
        realm_id: impl Into<String>,
        remark: crate::account_data::RealmRemark,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if remark.is_empty() {
            self.cached.realm_remarks.remove(&realm_id);
        } else {
            self.cached.realm_remarks.insert(realm_id, remark);
        }
        let _ = self.flush();
    }

    /// Delete the remark for `realm_id`. No-op if none is stored.
    pub fn remove_realm_remark(&mut self, realm_id: &str) {
        self.ensure_cached_loaded();
        self.cached.realm_remarks.remove(realm_id);
        let _ = self.flush();
    }

    // ── Contact remarks (spec client-preferences.md §3.6) ─

    pub fn contact_remark(&self, actor_id: &str) -> Option<crate::account_data::ContactRemark> {
        self.load().contact_remarks.get(actor_id).cloned()
    }

    pub fn contact_remarks(&self) -> BTreeMap<String, crate::account_data::ContactRemark> {
        self.load().contact_remarks
    }

    pub fn set_contact_remark(
        &mut self,
        actor_id: impl Into<String>,
        remark: crate::account_data::ContactRemark,
    ) {
        self.ensure_cached_loaded();
        let actor_id = actor_id.into();
        if remark.is_empty() {
            self.cached.contact_remarks.remove(&actor_id);
        } else {
            self.cached.contact_remarks.insert(actor_id, remark);
        }
        let _ = self.flush();
    }

    pub fn remove_contact_remark(&mut self, actor_id: &str) {
        self.ensure_cached_loaded();
        self.cached.contact_remarks.remove(actor_id);
        let _ = self.flush();
    }

    pub fn display_name_for_actor(&self, actor_id: &str, public_name: &str) -> String {
        match self
            .load()
            .contact_remarks
            .get(actor_id)
            .map(|r| r.display_name(public_name).to_owned())
        {
            Some(name) => name,
            None => public_name.to_owned(),
        }
    }

    // ── Personal blocklist (spec client-preferences.md "ck.account.blocklist") ─

    /// Current personal blocklist. Cheap clone — the underlying `Vec`
    /// is short by design (curated by the user).
    pub fn client_blocklist(&self) -> Vec<crate::account_data::BlocklistEntry> {
        self.load().client_blocklist
    }

    /// True when `did` appears in the local blocklist. Used by the
    /// timeline + chat renderers to gate message bodies behind a
    /// "Show anyway" affordance.
    pub fn is_user_blocked(&self, did: &str) -> bool {
        crate::account_data::is_blocked(&self.load().client_blocklist, did)
    }

    /// Append `did` to the personal blocklist. Idempotent — duplicate
    /// DIDs are not inserted twice. `reason` is shown back to the user
    /// in Settings → Privacy; pass `None` to skip.
    ///
    /// Persists synchronously to disk; the caller is responsible for
    /// pushing the new list to soland via
    /// `ck.account_data.set("ck.account.blocklist", …)`.
    pub fn block_user(&mut self, did: impl AsRef<str>, reason: Option<String>) -> bool {
        self.ensure_cached_loaded();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = crate::account_data::block_user_in(
            &mut self.cached.client_blocklist,
            did.as_ref(),
            reason,
            Some(now),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Remove every entry for `did` from the personal blocklist.
    /// Returns `true` when at least one entry was removed.
    pub fn unblock_user(&mut self, did: impl AsRef<str>) -> bool {
        self.ensure_cached_loaded();
        let changed =
            crate::account_data::unblock_user_in(&mut self.cached.client_blocklist, did.as_ref());
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Append a typed block (`kind` ∈ actor / service / domain / organization)
    /// to the personal blocklist. Idempotent per `(kind, value)` pair.
    /// `applies_to` lists the surfaces the block covers (empty = all default
    /// surfaces); `expires_at` is an optional RFC 3339 expiry. Same
    /// persistence + push contract as [`block_user`].
    pub fn block_target(
        &mut self,
        kind: impl AsRef<str>,
        value: impl AsRef<str>,
        reason: Option<String>,
        applies_to: Vec<String>,
        expires_at: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let now = chrono::Utc::now().to_rfc3339();
        let changed = crate::account_data::block_target_in(
            &mut self.cached.client_blocklist,
            kind.as_ref(),
            value.as_ref(),
            reason,
            applies_to,
            expires_at,
            Some(now),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Remove the `(kind, value)` block from the personal blocklist. Returns
    /// `true` when an entry was removed. Prefer this over [`unblock_user`] on
    /// surfaces that track the target kind.
    pub fn unblock_target(&mut self, kind: impl AsRef<str>, value: impl AsRef<str>) -> bool {
        self.ensure_cached_loaded();
        let changed = crate::account_data::unblock_target_in(
            &mut self.cached.client_blocklist,
            kind.as_ref(),
            value.as_ref(),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Replace the whole personal blocklist from `/sync account_data`.
    /// User edits still go through [`block_user`] / [`unblock_user`];
    /// this method is only for remote state hydration.
    pub fn set_client_blocklist(&mut self, entries: Vec<crate::account_data::BlocklistEntry>) {
        self.ensure_cached_loaded();
        self.cached.client_blocklist = entries;
        let _ = self.flush();
    }

    /// Best-effort name for `realm_id`: trimmed `local_name` from the
    /// stored remark if set, otherwise `public_title`. Mirrors the §3.7
    /// "UI MUST prefer local_name" rule so the sidebar / dashboard /
    /// dashboard cards all agree.
    pub fn display_name_for_realm(&self, realm_id: &str, public_title: &str) -> String {
        match self
            .load()
            .realm_remarks
            .get(realm_id)
            .map(|r| r.display_name(public_title).to_owned())
        {
            Some(name) => name,
            None => public_title.to_owned(),
        }
    }

    /// Get the server-declared read-receipt policy for a Realm (when known).
    /// `None` means the client hasn't synced a policy snapshot yet and the
    /// user's override is still authoritative.
    pub fn read_receipt_policy_for_realm(
        &self,
        realm_id: &str,
    ) -> Option<ReadReceiptPolicySnapshot> {
        self.load()
            .read_receipt_policy_snapshots
            .get(realm_id)
            .cloned()
    }

    /// Replace the server-declared policy snapshot for a Realm. Called from
    /// the sync path once the Seal view (P0 M3) surfaces
    /// `ck.component.realm.read_receipt_policy.v1` cell value; tests use
    /// this to seed lock-state UI behavior.
    pub fn set_read_receipt_policy_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        snapshot: Option<ReadReceiptPolicySnapshot>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        match snapshot {
            Some(value) => {
                self.cached
                    .read_receipt_policy_snapshots
                    .insert(realm_id, value);
            }
            None => {
                self.cached.read_receipt_policy_snapshots.remove(&realm_id);
            }
        }
        let _ = self.flush();
    }

    /// All known server-declared read-receipt policy snapshots.
    pub fn read_receipt_policy_snapshots(&self) -> BTreeMap<String, ReadReceiptPolicySnapshot> {
        self.load().read_receipt_policy_snapshots
    }

    /// Get the latest Seal view for a Realm. Returns the Default view
    /// (empty frontier / empty leaves / no state_root) when none has been
    /// observed yet — Move builders treat that as "use sha256(empty)
    /// sentinel".
    pub fn seal_view_for_realm(&self, realm_id: &str) -> LocalSealView {
        self.load()
            .seal_views
            .get(realm_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the Seal view snapshot for a Realm. Called from the sync
    /// path once the `/sync` response surfaces the projection's Seal
    /// view. Tests use this to seed Move-frontier behavior.
    pub fn set_realm_seal_view(&mut self, realm_id: impl Into<String>, view: LocalSealView) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if self.cached.seal_views.get(&realm_id) == Some(&view) {
            return; // seal view unchanged — skip flush
        }
        self.cached.seal_views.insert(realm_id, view);
        let _ = self.flush();
    }

    /// All known Seal views — handy for app-wide UI banners.
    pub fn seal_views(&self) -> BTreeMap<String, LocalSealView> {
        self.load().seal_views
    }

    /// Convenience: pick the right `seal_ref` to thread into a Move
    /// builder for a given Realm. Returns the lex-min frontier head when
    /// available, otherwise the `sha256(empty)` sentinel. Mirrors
    /// [`LocalSealView::move_seal_ref`].
    pub fn seal_ref_for_realm_move(&self, realm_id: &str) -> String {
        self.seal_view_for_realm(realm_id).move_seal_ref()
    }

    /// Resolve effective send preference per spec (server policy → flow →
    /// realm → default). Mirror of
    /// `cokret_sdk::ReadReceiptPreferences::effective_send` extended with
    /// server-declared policy lock: when the Realm publishes a
    /// `ck.realm.read_receipt_policy` with `disclosure="required"` the
    /// answer is forced `true`; with `disclosure="disabled"` it's forced
    /// `false`. User-level overrides are ignored in those cases (matching
    /// the lock UI in settings).
    pub fn read_receipt_should_send(&self, flow_id: Option<&str>, realm_id: Option<&str>) -> bool {
        let snapshot = self.load();
        if let Some(rid) = realm_id
            && let Some(policy) = snapshot.read_receipt_policy_snapshots.get(rid)
        {
            match policy.disclosure.as_str() {
                "required" => return true,
                "disabled" => return false,
                _ => {}
            }
        }
        if let Some(fid) = flow_id
            && let Some(value) = snapshot.read_receipt_flow_overrides.get(fid)
        {
            return *value;
        }
        if let Some(rid) = realm_id
            && let Some(value) = snapshot.read_receipt_realm_overrides.get(rid)
        {
            return *value;
        }
        snapshot.read_receipt_default_send
    }

    pub fn set_notification_kind_enabled(&mut self, kind: impl Into<String>, enabled: bool) {
        self.ensure_cached_loaded();
        self.cached
            .muted_notification_kinds
            .insert(kind.into(), enabled);
        let _ = self.flush();
    }

    pub fn notification_kind_enabled(&self, kind: &str) -> bool {
        self.load()
            .muted_notification_kinds
            .get(kind)
            .copied()
            .unwrap_or(true)
    }

    pub fn notification_kind_preferences(&self) -> BTreeMap<String, bool> {
        self.load().muted_notification_kinds
    }

    // ── Move submission tracking ─────────────────────────────────────────

    /// Record a freshly-submitted Move and its initial state. The
    /// caller has just received soland's `SubmitMoveOutcome`; the
    /// state is mapped in via [`MoveSubmissionState::from_submit_state`].
    /// `kind` is a free-form classifier (e.g. `ck.consent.grant`,
    /// `ck.message.create`, `mls_commit`) the UI uses to decorate
    /// pills + icons.
    pub fn record_move_submission(
        &mut self,
        move_id: impl Into<String>,
        realm_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        seal_ref: Option<String>,
    ) -> MoveSubmissionRecord {
        self.record_move_submission_with_event_id(
            move_id, None, realm_id, kind, state, reason, seal_ref,
        )
    }

    /// Record a freshly-submitted Move/Event and remember the server Event id
    /// when available. Sync `event_states[]` is keyed by server `event_id`,
    /// while older local queues used `move_id` / idempotency aliases.
    pub fn record_move_submission_with_event_id(
        &mut self,
        move_id: impl Into<String>,
        event_id: Option<String>,
        realm_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        seal_ref: Option<String>,
    ) -> MoveSubmissionRecord {
        self.ensure_cached_loaded();
        let move_id = move_id.into();
        let record = MoveSubmissionRecord {
            move_id: move_id.clone(),
            event_id,
            realm_id: realm_id.into(),
            kind: kind.into(),
            state,
            submitted_at: Utc::now(),
            reason,
            seal_ref,
        };
        self.cached.move_submissions.insert(move_id, record.clone());
        let _ = self.flush();
        record
    }

    /// Update the lifecycle state of a tracked Move. Called when the
    /// next `/sync` cycle surfaces an Seal inclusion / rejection.
    /// Returns `false` when the move id isn't tracked (no-op).
    pub fn update_move_submission_state(
        &mut self,
        move_id: &str,
        state: MoveSubmissionState,
        reason: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let Some(record) = self.move_submission_record_mut(move_id) else {
            return false;
        };
        record.state = state;
        if reason.is_some() {
            record.reason = reason;
        }
        let _ = self.flush();
        true
    }

    fn move_submission_record_mut(&mut self, id: &str) -> Option<&mut MoveSubmissionRecord> {
        if self.cached.move_submissions.contains_key(id) {
            return self.cached.move_submissions.get_mut(id);
        }
        self.cached
            .move_submissions
            .values_mut()
            .find(|record| record.event_id.as_deref() == Some(id))
    }

    fn move_submission_lookup_key(
        &self,
        event_id: Option<&str>,
        move_id: Option<&str>,
    ) -> Option<String> {
        for id in [move_id, event_id].into_iter().flatten() {
            if self.cached.move_submissions.contains_key(id) {
                return Some(id.to_owned());
            }
        }
        self.cached
            .move_submissions
            .iter()
            .find(|(_, record)| {
                event_id.is_some_and(|id| record.event_id.as_deref() == Some(id))
                    || move_id.is_some_and(|id| record.move_id == id)
            })
            .map(|(key, _)| key.clone())
    }

    /// Apply per-event protocol states from a per-Realm sync projection.
    /// Spec source: `service-surface.md §5.3`, where each reducer-input
    /// Event may carry `event_id`, `event_state`, and an optional reason code.
    pub fn ingest_move_event_states(&mut self, realm_id: &str, body: &Value) -> usize {
        let Some(entries) = body.get("event_states").and_then(|v| v.as_array()) else {
            return 0;
        };
        self.ensure_cached_loaded();
        let mut updated = 0usize;
        for entry in entries {
            let event_id = entry.get("event_id").and_then(|v| v.as_str());
            let move_id = entry.get("move_id").and_then(|v| v.as_str());
            if event_id.is_none() && move_id.is_none() {
                continue;
            }
            let Some(state_label) = entry
                .get("event_state")
                .or_else(|| entry.get("state"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let reason = entry
                .get("event_state_reason_code")
                .or_else(|| entry.get("reason_code"))
                .or_else(|| entry.get("reason"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let state = MoveSubmissionState::from_submit_state(state_label, reason.as_deref());
            let Some(record_key) = self.move_submission_lookup_key(event_id, move_id) else {
                continue;
            };
            let Some(record) = self.cached.move_submissions.get_mut(&record_key) else {
                continue;
            };
            if record.realm_id != realm_id {
                continue;
            }
            if let Some(event_id) = event_id {
                record.event_id.get_or_insert_with(|| event_id.to_owned());
            }
            record.state = state;
            if reason.is_some() {
                record.reason = reason;
            }
            updated += 1;
        }
        if updated > 0 {
            let _ = self.flush();
        }
        updated
    }

    /// Read all tracked Moves for a specific Realm, sorted by submit
    /// time (newest first). Used by the timeline / realm_admin pills.
    pub fn move_submissions_for_realm(&self, realm_id: &str) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> = self
            .load()
            .move_submissions
            .into_values()
            .filter(|record| record.realm_id == realm_id)
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
        out
    }

    /// Read all tracked Moves regardless of Space — used by the
    /// dashboard "everything failing" banner and the recovery flow.
    pub fn all_move_submissions(&self) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> =
            self.load().move_submissions.into_values().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
        out
    }

    /// True when at least one tracked Move in `realm_id` is in
    /// `NotaryPaused`. Drives the Realm-wide "waiting for recovery notary"
    /// banner described in the M4 ticket.
    pub fn realm_has_paused_notary(&self, realm_id: &str) -> bool {
        self.move_submissions_for_realm(realm_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::NotaryPaused)
    }

    /// True when at least one tracked Move targeting `realm_id` is
    /// stuck on `PendingMlsBinding`. Drives the M7 toast.
    pub fn realm_has_pending_mls_binding(&self, realm_id: &str) -> bool {
        self.move_submissions_for_realm(realm_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::PendingMlsBinding)
    }

    /// True when the latest cached realm-tree projection declares an
    /// MLS-backed encryption profile. Used by membership/admin surfaces
    /// to decide whether a membership frontier change must pause sends
    /// until an MLS commit covers it.
    pub fn realm_projection_is_mls_encrypted(&self, realm_id: &str) -> bool {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .is_some_and(realm_tree_projection_value_is_mls_encrypted)
    }

    /// SEC-08 (`encryption-and-audit.md` §2.9) — does the latest cached
    /// realm-tree projection declare the
    /// `ck.profile.mls.minimal_metadata_realm.v1` profile? The committer uses
    /// this to decide whether the ≤1h epoch-lifetime cap and the
    /// `aad_visibility=hidden` MUST apply to a given Realm. Unknown / absent
    /// projection ⇒ `false` (the realm is treated as a normal realm).
    pub fn realm_projection_is_minimal_metadata(&self, realm_id: &str) -> bool {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .is_some_and(realm_tree_projection_value_is_minimal_metadata)
    }

    /// Drop a tracked Move (after it terminates and the user
    /// dismisses the row). Idempotent.
    pub fn drop_move_submission(&mut self, move_id: &str) {
        self.ensure_cached_loaded();
        if self.cached.move_submissions.remove(move_id).is_some() {
            let _ = self.flush();
        }
    }

    /// Look up the persisted device identity record without generating
    /// a fresh one. Returns `None` when the device hasn't been initialised
    /// yet (e.g. fresh install before `ensure_local_identity` has been
    /// called).
    pub fn local_identity_record(&self) -> Option<LocalIdentityRecord> {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            if let Some(record) = load_identity_record_from_secure_store(secure_store.as_ref()) {
                return Some(record);
            }
            if !plaintext_identity_seed_fallback_allowed() {
                return None;
            }
        }
        self.load().local_identity
    }

    /// Replace (or clear) the persisted device identity record. Used by
    /// the [`crate::key_store::KeyStore`] trait's `save_identity` impl so
    /// a future Keychain / Secret-Service backend can hand a different
    /// record back to the in-memory cache without going through
    /// `ensure_local_identity` (which would generate a fresh seed if the
    /// record was missing).
    pub fn set_local_identity_record(&mut self, record: Option<LocalIdentityRecord>) {
        self.ensure_cached_loaded();
        #[cfg(target_arch = "wasm32")]
        if record.is_some() && !plaintext_identity_seed_fallback_allowed() {
            tracing::warn!("refusing to persist wasm local identity seed in plaintext local state");
            self.cached.local_identity = None;
            let _ = self.flush();
            return;
        }
        self.cached.local_identity = record;
        let _ = self.flush();
    }

    /// Read the in-memory device identity. Returns `None` when no record
    /// is persisted; callers that need a key should call
    /// [`Self::ensure_local_identity`] which generates + persists on first
    /// access. Distinct from `ensure_*` so callers that only want to
    /// **observe** an existing identity (e.g. status UI) don't trigger a
    /// write.
    pub fn local_identity(&self) -> Option<LocalIdentity> {
        self.local_identity_record()
            .as_ref()
            .and_then(|record| LocalIdentity::from_record(record).ok())
    }

    /// Load — or generate + persist — the device identity. First call on
    /// a fresh install fills `getrandom::fill` 32-byte seed, derives the
    /// `did:key`, and writes the record to disk. Subsequent calls return
    /// the persisted identity. If the persisted record is malformed (e.g.
    /// hand-edited or truncated) this regenerates and overwrites — the
    /// alternative is bricking the client, and Cokret v1 is pre-release
    /// so there is no user-facing key recovery story to preserve.
    pub fn ensure_local_identity(&mut self) -> anyhow::Result<LocalIdentity> {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            self.ensure_local_identity_with_secure_store(secure_store.as_ref())
        }
        #[cfg(test)]
        {
            self.ensure_local_identity_in_plaintext_state()
        }
    }

    pub fn ensure_local_identity_with_secure_store(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<LocalIdentity> {
        self.ensure_cached_loaded();
        if let Some(record) = load_identity_record_from_secure_store(secure_store) {
            return LocalIdentity::from_record(&record);
        }

        #[cfg(target_arch = "wasm32")]
        if self.cached.local_identity.is_some() {
            tracing::warn!("discarding wasm plaintext local identity seed instead of migrating it");
            self.cached.local_identity = None;
            let _ = self.flush();
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(record) = self.cached.local_identity.clone() {
            let identity = LocalIdentity::from_record(&record)?;
            match store_identity_record_in_secure_store(secure_store, &record) {
                Ok(()) => {
                    self.cached.local_identity = None;
                    let _ = self.flush();
                    return Ok(identity);
                }
                Err(error) if plaintext_identity_seed_fallback_allowed() => {
                    tracing::warn!(
                        ?error,
                        "secure identity handoff failed; using explicit plaintext identity fallback",
                    );
                    return Ok(identity);
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "secure identity handoff failed and plaintext identity fallback is disabled: {error}"
                    ));
                }
            }
        }

        let identity = LocalIdentity::generate()?;
        let record = identity.to_record();
        match store_identity_record_in_secure_store(secure_store, &record) {
            Ok(()) => {
                self.cached.local_identity = None;
                let _ = self.flush();
                Ok(identity)
            }
            Err(error) if plaintext_identity_seed_fallback_allowed() => {
                tracing::warn!(
                    ?error,
                    "secure identity store unavailable; using explicit plaintext identity fallback",
                );
                self.cached.local_identity = Some(record);
                let _ = self.flush();
                Ok(identity)
            }
            Err(error) => Err(anyhow::anyhow!(
                "secure identity store unavailable and plaintext identity fallback is disabled: {error}"
            )),
        }
    }

    #[cfg(test)]
    fn ensure_local_identity_in_plaintext_state(&mut self) -> anyhow::Result<LocalIdentity> {
        self.ensure_cached_loaded();
        if let Some(record) = self.cached.local_identity.as_ref() {
            match LocalIdentity::from_record(record) {
                Ok(id) => return Ok(id),
                Err(err) => {
                    tracing::warn!("local_identity record corrupted ({err}); regenerating");
                }
            }
        }
        let identity = LocalIdentity::generate()?;
        self.cached.local_identity = Some(identity.to_record());
        let _ = self.flush();
        Ok(identity)
    }

    /// Persisted OIDC token bundle. Returns `None` when no successful PKCE
    /// exchange has happened yet.
    pub fn oidc_tokens(&self) -> Option<OidcTokenBundle> {
        self.load().oidc_tokens
    }

    /// Persist a fresh OIDC token bundle (or clear via `None`). Neither
    /// the refresh credential nor the access token is serialised to
    /// `state.json` — both are bearer secrets and MUST NOT land in the
    /// plaintext persistence layer. Callers that know the actor DID
    /// MUST use [`Self::set_oidc_tokens_with_secure_store`] so the
    /// tokens land in SecureKeyStore instead; this plain variant only
    /// keeps the non-secret bundle metadata (expiry, audience, ...).
    pub fn set_oidc_tokens(&mut self, bundle: Option<OidcTokenBundle>) {
        self.ensure_cached_loaded();
        self.cached.oidc_tokens = bundle.map(|mut bundle| {
            bundle.refresh_token = None;
            bundle.access_token = String::new();
            bundle
        });
        let _ = self.flush();
    }

    /// Persist a fresh OIDC token bundle and
    /// **migrate the refresh_token and access_token fields into the
    /// supplied `SecureKeyStore`** so the disk-backed `state.json` does
    /// not hold either bearer credential in plaintext. Returns the
    /// bundle that ended up serialised (the `refresh_token` field is
    /// wiped to `None` and `access_token` to the empty string
    /// post-secure-store-write so a corrupt-restore can't leak).
    ///
    /// The secure-store keys are `coauth.refresh_token.<actor_id>` and
    /// `coauth.access_token.<actor_id>` so a device that has signed in
    /// as multiple actors keeps them isolated. Callers SHOULD use
    /// [`load_oidc_tokens_with_secure_store`] to reattach the tokens at
    /// boot before passing the bundle into the OIDC refresh poller.
    pub fn set_oidc_tokens_with_secure_store(
        &mut self,
        bundle: Option<OidcTokenBundle>,
        actor_id: &str,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Option<OidcTokenBundle> {
        let refresh_key = format!("coauth.refresh_token.{actor_id}");
        let access_key = format!("coauth.access_token.{actor_id}");
        let stripped = match bundle {
            Some(mut bundle) => {
                if let Some(refresh) = bundle.refresh_token.take()
                    && let Err(error) = secure_store.store_secret(&refresh_key, &refresh)
                {
                    tracing::warn!(
                        ?error,
                        actor = actor_id,
                        "secure_key_store refresh_token write failed; bundle persisted without refresh_token (next refresh poll will fall back to re-login)",
                    );
                }
                if !bundle.access_token.is_empty() {
                    let access = std::mem::take(&mut bundle.access_token);
                    if let Err(error) = secure_store.store_secret(&access_key, &access) {
                        tracing::warn!(
                            ?error,
                            actor = actor_id,
                            "secure_key_store access_token write failed; bundle persisted without access_token (next use will re-mint via refresh)",
                        );
                    }
                }
                Some(bundle)
            }
            None => {
                if let Err(error) = secure_store.delete_secret(&refresh_key) {
                    tracing::debug!(
                        ?error,
                        actor = actor_id,
                        "secure_key_store refresh_token delete on bundle-clear failed (likely already missing)",
                    );
                }
                if let Err(error) = secure_store.delete_secret(&access_key) {
                    tracing::debug!(
                        ?error,
                        actor = actor_id,
                        "secure_key_store access_token delete on bundle-clear failed (likely already missing)",
                    );
                }
                None
            }
        };
        self.ensure_cached_loaded();
        self.cached.oidc_tokens = stripped.clone();
        let _ = self.flush();
        stripped
    }

    /// Companion to
    /// [`set_oidc_tokens_with_secure_store`]. Reads the bundle from
    /// state.json and reattaches the `refresh_token` and
    /// `access_token` from the secure store under the per-actor keys.
    /// Returns `None` when no bundle has been persisted yet (same
    /// shape as [`Self::oidc_tokens`]).
    pub fn load_oidc_tokens_with_secure_store(
        &self,
        actor_id: &str,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Option<OidcTokenBundle> {
        let mut bundle = self.oidc_tokens()?;
        if bundle.refresh_token.is_none() {
            let key = format!("coauth.refresh_token.{actor_id}");
            match secure_store.get_secret(&key) {
                Ok(Some(value)) => bundle.refresh_token = Some(value),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        actor = actor_id,
                        "secure_key_store refresh_token read failed; bundle returned without refresh_token",
                    );
                }
            }
        }
        if bundle.access_token.is_empty() {
            let key = format!("coauth.access_token.{actor_id}");
            match secure_store.get_secret(&key) {
                Ok(Some(value)) => bundle.access_token = value,
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        actor = actor_id,
                        "secure_key_store access_token read failed; bundle returned without access_token",
                    );
                }
            }
        }
        Some(bundle)
    }

    /// Read the persisted coauth `session_grant` if any.
    pub fn session_grant(&self) -> Option<PersistedSessionGrant> {
        self.load().session_grant
    }

    /// Persist (or clear via `None`) the coauth `session_grant`.
    pub fn set_session_grant(&mut self, grant: Option<PersistedSessionGrant>) {
        self.ensure_cached_loaded();
        self.cached.session_grant = grant;
        let _ = self.flush();
    }

    /// Update only the `session_expires_at` timestamp on the persisted
    /// grant — used after a successful re-exchange when the grant body
    /// itself didn't change but the minted access token's expiry did.
    pub fn update_session_expires_at(&mut self, session_expires_at: Option<DateTime<Utc>>) {
        self.ensure_cached_loaded();
        if let Some(grant) = self.cached.session_grant.as_mut() {
            grant.session_expires_at = session_expires_at;
            grant.stored_at = Utc::now();
            let _ = self.flush();
        }
    }

    /// Append a structured user-action log entry to the buffered telemetry
    /// log. Bounded by [`TELEMETRY_BUFFER_CAP`] - excess entries are
    /// dropped from the front (oldest-first).
    pub fn append_telemetry(&mut self, entry: UserActionLogEntry) {
        self.ensure_cached_loaded();
        self.cached.telemetry_log.push(entry);
        let overflow = self
            .cached
            .telemetry_log
            .len()
            .saturating_sub(TELEMETRY_BUFFER_CAP);
        if overflow > 0 {
            self.cached.telemetry_log.drain(0..overflow);
        }
        let _ = self.flush();
    }

    /// Read-only snapshot of the buffered telemetry entries.
    pub fn telemetry_log(&self) -> Vec<UserActionLogEntry> {
        self.load().telemetry_log
    }

    /// Drain the buffered telemetry entries — returns the existing
    /// entries and clears the on-disk buffer atomically. Called by the
    /// flush path once a network channel is available.
    pub fn drain_telemetry(&mut self) -> Vec<UserActionLogEntry> {
        self.ensure_cached_loaded();
        let drained = std::mem::take(&mut self.cached.telemetry_log);
        let _ = self.flush();
        drained
    }

    // ── MLS group state persistence ─────────────────────────────────

    /// Persist (or replace) the MLS snapshot envelope for a Realm.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// device-secret-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) {
        // YOU-02-004: order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_snapshot_for`).
        self.absorb_mls_receive_overlay();
        self.cached.mls_snapshots.insert(realm_id.into(), envelope);
        let _ = self.flush();
    }

    /// Look up the latest MLS snapshot envelope for a Realm, if any.
    /// Returns `None` when the Realm has not yet been snapshotted (a
    /// fresh group on this device, or a group that has not committed
    /// yet so there is no state to persist).
    pub fn mls_snapshot_for(
        &self,
        realm_id: &str,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots.get(realm_id).cloned()
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery flows to enumerate the encrypted snapshots that
    /// can be restored for this device.
    pub fn mls_snapshots(&self) -> BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots
    }

    /// Drop the MLS snapshot for a Realm — used after a successful
    /// "rotate group" / "leave group" Move so the next boot doesn't
    /// try to rehydrate a stale leaf.
    pub fn drop_mls_snapshot(&mut self, realm_id: &str) {
        self.absorb_mls_receive_overlay();
        let dropped_snapshot = self.cached.mls_snapshots.remove(realm_id).is_some();
        // The decrypted-plaintext cache is keyed to ciphertext minted under
        // the dropped group state; it stays readable history (same lifetime
        // policy as the author sidecar) and is NOT wiped here.
        if dropped_snapshot {
            let _ = self.flush();
        }
    }

    // ── YOU-02-004: MLS receive-chain persistence + plaintext cache ──
    //
    // `encryption-and-audit.md` §5.6 (normative): after every successful
    // decrypt of an application message the advanced MLS group state MUST
    // be persisted — the ratchet must never be replayed from an earlier
    // snapshot on the next decrypt. These entry points are deliberately
    // `&self` (interior mutability through [`MlsReceiveOverlay`]) because
    // the decrypt-on-read callers run inside render passes that only hold
    // a read borrow of the `Signal<LocalStateStore>`.

    /// Acquire the receive-chain serialization guard. The caller holds it
    /// across the whole restore→decrypt→export→[`Self::advance_mls_receive_chain`]
    /// sequence so concurrent views can't both advance the same group from
    /// the same base snapshot.
    pub fn mls_decrypt_serial_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mls_decrypt_serial.lock().unwrap()
    }

    /// Look up a previously decrypted plaintext by the envelope's canonical
    /// `payload_digest`. Render paths consult this BEFORE attempting an MLS
    /// decrypt — after the receive chain advanced past a message, this cache
    /// is the only way to re-render it.
    pub fn mls_decrypted_plaintext_for(
        &self,
        realm_id: &str,
        payload_digest: &str,
    ) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let encoded = {
            let overlay = self.mls_receive_overlay.lock().unwrap();
            overlay
                .plaintexts
                .get(realm_id)
                .and_then(|entries| entries.get(payload_digest))
                .cloned()
        };
        let encoded = match encoded {
            Some(encoded) => encoded,
            None => self
                .load()
                .mls_decrypted_plaintext
                .get(realm_id)?
                .get(payload_digest)?
                .clone(),
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .ok()
    }

    /// Persist a successful decrypt: the advanced (post-decrypt) snapshot
    /// envelope AND the decrypted plaintext (cached under `payload_digest`).
    /// Both are recorded through the shared overlay and immediately flushed
    /// to the backing store, so a restart never replays the ratchet from
    /// the pre-decrypt snapshot (§5.6 MUST) and the message stays readable.
    pub fn advance_mls_receive_chain(
        &self,
        realm_id: &str,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        {
            let mut overlay = self.mls_receive_overlay.lock().unwrap();
            overlay.snapshots.insert(realm_id.to_owned(), envelope);
            overlay
                .plaintexts
                .entry(realm_id.to_owned())
                .or_default()
                .insert(payload_digest.to_owned(), encoded);
        }
        // Persist NOW (merged via `effective_state_for_persist`). Failures
        // are latched into `persist_health` like every other persist; the
        // overlay still holds the advancement in memory so the session
        // itself never regresses.
        let _ = self.flush();
    }

    /// True once a `ck.mls.genesis` event has been submitted for this Realm.
    pub fn mls_genesis_emitted_for(&self, realm_id: &str) -> bool {
        self.load().mls_genesis_emitted.contains(realm_id)
    }

    /// Record that a `ck.mls.genesis` event has been submitted for this
    /// Realm so it is never re-emitted (idempotent).
    pub fn mark_mls_genesis_emitted(&mut self, realm_id: impl Into<String>) {
        self.ensure_cached_loaded();
        if self.cached.mls_genesis_emitted.insert(realm_id.into()) {
            let _ = self.flush();
        }
    }

    /// X5.1 — persist the author's own plaintext for an encrypted private
    /// flow field into the local-only sidecar. `field_path` is the dotted
    /// private patch path (e.g. `"body"`, `"synthesis"`); `plaintext` is
    /// the JSON-serialized patch value the writer encrypted. Empty values
    /// are removed rather than stored so a cleared field doesn't keep a
    /// stale plaintext around (consistent with the `unset` write path).
    ///
    /// This data NEVER leaves the device — it is the only place the
    /// author's own encrypted content survives a re-projection, since the
    /// author can never decrypt their own MLS ciphertext.
    pub fn save_private_plaintext(
        &mut self,
        realm_id: &str,
        flow_id: &str,
        field_path: &str,
        plaintext: &str,
    ) {
        let realm_id = realm_id.trim();
        let flow_id = flow_id.trim();
        let field_path = field_path.trim();
        if realm_id.is_empty() || flow_id.is_empty() || field_path.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        if plaintext.is_empty() {
            // Cleared field: drop the sidecar entry (and prune empty maps).
            if let Some(flows) = self.cached.mls_private_plaintext.get_mut(realm_id)
                && let Some(fields) = flows.get_mut(flow_id)
            {
                if fields.remove(field_path).is_some() {
                    changed = true;
                }
                if fields.is_empty() {
                    flows.remove(flow_id);
                }
            }
            if let Some(flows) = self.cached.mls_private_plaintext.get(realm_id)
                && flows.is_empty()
            {
                self.cached.mls_private_plaintext.remove(realm_id);
            }
        } else {
            let slot = self
                .cached
                .mls_private_plaintext
                .entry(realm_id.to_owned())
                .or_default()
                .entry(flow_id.to_owned())
                .or_default()
                .entry(field_path.to_owned())
                .or_default();
            if *slot != plaintext {
                *slot = plaintext.to_owned();
                changed = true;
            }
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// X5.1 — read back a single author-owned plaintext field from the
    /// local sidecar, if present. Returns `None` when no plaintext was
    /// ever stored for this (Realm, flow, field) — the read path then
    /// falls back to decrypting another member's ciphertext.
    pub fn private_plaintext_for(
        &self,
        realm_id: &str,
        flow_id: &str,
        field_path: &str,
    ) -> Option<String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|flows| flows.get(flow_id.trim()))
            .and_then(|fields| fields.get(field_path.trim()))
            .filter(|plaintext| !plaintext.is_empty())
            .cloned()
    }

    /// X5.1 — all sidecar plaintext fields for a single flow (`field_path
    /// -> plaintext`). Convenience for callers that want to enumerate
    /// every stored field at once.
    pub fn private_plaintext_fields(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> BTreeMap<String, String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|flows| flows.get(flow_id.trim()))
            .cloned()
            .unwrap_or_default()
    }

    /// X5.3 — serialize the ENTIRE local-plaintext sidecar map
    /// (`realm -> flow -> field -> plaintext`) to JSON bytes for the encrypted
    /// cross-device backup. Returns the serialization of an empty map (`{}`)
    /// when no sidecar entries exist, so callers can cheaply detect "nothing to
    /// back up" via [`Self::private_plaintext_is_empty`] first.
    pub fn private_plaintext_snapshot_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.load().mls_private_plaintext).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// X5.3 — true when the sidecar holds no plaintext for any Realm/flow/field.
    /// Used to skip the cross-device backup upload when there is nothing to
    /// protect.
    pub fn private_plaintext_is_empty(&self) -> bool {
        self.load().mls_private_plaintext.is_empty()
    }

    /// X5.3 — merge an incoming sidecar map (decrypted from a cross-device
    /// backup) into the local cache, then flush.
    ///
    /// Merge semantics: incoming entries only FILL fields that are missing
    /// locally; on a (Realm, flow, field) conflict the EXISTING LOCAL value is
    /// kept. Rationale: the local sidecar is written synchronously on every
    /// encrypted write by the author on THIS device, so a locally-present value
    /// is at least as fresh as the backup (which is only re-uploaded
    /// periodically). On a brand-new browser the local cache is empty, so the
    /// backup populates everything — the common restore case.
    pub fn merge_private_plaintext_map(
        &mut self,
        incoming: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    ) {
        if incoming.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        for (realm_id, flows) in incoming {
            let local_flows = self
                .cached
                .mls_private_plaintext
                .entry(realm_id)
                .or_default();
            for (flow_id, fields) in flows {
                let local_fields = local_flows.entry(flow_id).or_default();
                for (field_path, plaintext) in fields {
                    if plaintext.is_empty() {
                        continue;
                    }
                    // Keep existing local value on conflict; only fill gaps.
                    local_fields.entry(field_path).or_insert_with(|| {
                        changed = true;
                        plaintext
                    });
                }
            }
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// Drain the buffered telemetry log and POST each entry to soland's
    /// audit feed. The endpoint is 404-tolerant: until soland wires
    /// `ck.audit.user_action.ingest`, the server returns 404 and we
    /// simply restore the buffer (so the entries survive for the next
    /// flush attempt). Any other error class drops the affected entry
    /// — they're best-effort telemetry, not durable audit.
    ///
    /// The endpoint shape mirrors sodmin's audit feed: `actor`,
    /// `action`, `outcome`, optional `note`, `recorded_at`. soland's
    /// telemetry sink can ingest yougen + sodmin streams without a
    /// translation layer because both lines share the same wire
    /// shape.
    ///
    /// Returns the number of successfully POSTed entries; the buffer
    /// is fully drained on success and partially restored on 404.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn flush_telemetry_to_server(&mut self, api: &crate::api::CokretApi) -> usize {
        let entries = self.drain_telemetry();
        if entries.is_empty() {
            return 0;
        }
        let mut sent = 0usize;
        let mut deferred: Vec<UserActionLogEntry> = Vec::new();
        for entry in entries {
            let payload = json!({
                "actor": entry.actor,
                "action": entry.action,
                "outcome": entry.outcome,
                "note": entry.note,
                "recorded_at": entry.recorded_at,
            });
            match api.post_audit_user_action(payload).await {
                Ok(()) => sent += 1,
                Err(crate::api::AuditPostError::NotWired) => {
                    deferred.push(entry);
                }
                Err(crate::api::AuditPostError::Other(_)) => {
                    // Best-effort — drop the entry rather than
                    // ballooning the buffer when the server is
                    // misbehaving.
                }
            }
        }
        // 404-tolerant: re-insert the deferred entries so a later
        // flush attempt picks them up once the endpoint is wired.
        if !deferred.is_empty() {
            self.ensure_cached_loaded();
            for entry in deferred.into_iter().rev() {
                self.cached.telemetry_log.insert(0, entry);
            }
            // Respect the bounded cap — if the server has been 404
            // for a long time the cap kicks in and the oldest
            // entries get dropped.
            let overflow = self
                .cached
                .telemetry_log
                .len()
                .saturating_sub(TELEMETRY_BUFFER_CAP);
            if overflow > 0 {
                self.cached.telemetry_log.drain(0..overflow);
            }
            let _ = self.flush();
        }
        sent
    }

    pub fn push_registration(&self) -> Option<PushRegistrationState> {
        self.load().push_registration
    }

    pub fn save_push_registration(&mut self, state: PushRegistrationState) {
        self.ensure_cached_loaded();
        self.cached.push_registration = Some(state);
        let _ = self.flush();
    }

    pub fn clear_push_registration(&mut self) {
        self.ensure_cached_loaded();
        self.cached.push_registration = None;
        let _ = self.flush();
    }

    /// Save a private preference encrypted with the account key.
    /// The account_key is typically the account DID or a derived secret.
    pub fn save_private_data(
        &mut self,
        account_key: &str,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.ensure_cached_loaded();
        let plaintext = value.into();
        let encrypted = xor_encrypt(account_key, &plaintext);
        self.cached.private_data.insert(key.into(), encrypted);
        let _ = self.flush();
    }

    /// Load and decrypt a private preference.
    pub fn load_private_data(&self, account_key: &str, key: &str) -> Option<String> {
        let encrypted = self.load().private_data.get(key)?.clone();
        xor_decrypt(account_key, &encrypted)
    }

    /// Remove a private preference.
    pub fn remove_private_data(&mut self, key: &str) {
        self.ensure_cached_loaded();
        self.cached.private_data.remove(key);
        let _ = self.flush();
    }

    /// List all private data keys.
    pub fn private_data_keys(&self) -> Vec<String> {
        self.load().private_data.keys().cloned().collect()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cached: ClientLocalState::default(),
            loaded: Cell::new(false),
            flush_suspended: 0,
            flush_pending: Cell::new(false),
            persist_health: Arc::new(Mutex::new(None)),
            mls_receive_overlay: Arc::new(Mutex::new(MlsReceiveOverlay::default())),
            mls_decrypt_serial: Arc::new(Mutex::new(())),
            path: path.into(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let bytes = fs::read(&self.path).ok()?;
        match serde_json::from_slice::<ClientLocalState>(&bytes) {
            Ok(mut state) => {
                state.migrate_legacy_realm_mutes();
                Some(state)
            }
            Err(error) => {
                // YOU-02-002: a corrupt / truncated state.json (e.g. a crash
                // mid-write before atomic rename landed) MUST NOT be silently
                // reset to a blank account — that loses every MLS snapshot and
                // the plaintext sidecar. Preserve the bad file for forensics
                // and latch a health error so the UI can warn before the user
                // overwrites it.
                let corrupt_path = self.path.with_extension("corrupt");
                let _ = fs::rename(&self.path, &corrupt_path);
                let message = format!(
                    "local state at {} was unreadable ({error}); preserved a copy at {} and started from defaults",
                    self.path.display(),
                    corrupt_path.display()
                );
                tracing::error!(%error, "corrupt local state preserved, not silently reset");
                *self.persist_health.lock().unwrap() = Some(message);
                None
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let json = browser_storage()
            .and_then(|storage| storage.get_item(LOCAL_STATE_STORAGE_KEY).ok().flatten())?;
        match serde_json::from_str::<ClientLocalState>(&json) {
            Ok(mut state) => {
                state.migrate_legacy_realm_mutes();
                Some(state)
            }
            Err(error) => {
                // YOU-02-002: preserve the corrupt blob under a sibling key
                // rather than silently dropping it back to defaults.
                if let Some(storage) = browser_storage() {
                    let _ = storage.set_item(&format!("{LOCAL_STATE_STORAGE_KEY}.corrupt"), &json);
                }
                let message = format!(
                    "local state in localStorage was unreadable ({error}); preserved a copy and started from defaults"
                );
                tracing::error!(%error, "corrupt local state preserved, not silently reset");
                *self.persist_health.lock().unwrap() = Some(message);
                None
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        use std::io::Write;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(state)?;
        // YOU-02-002: atomic write — serialize to a sibling temp file, fsync,
        // then rename over the target. A crash mid-write leaves either the old
        // complete file or the temp file, never a truncated state.json.
        let tmp_path = self.path.with_extension("json.tmp");
        {
            let mut tmp = fs::File::create(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
        }
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(LOCAL_STATE_STORAGE_KEY, &serde_json::to_string(state)?)
            .map_err(|error| {
                // YOU-02-003: most commonly a QuotaExceededError once the
                // single-key blob outgrows ~5 MB. Surfaced via the health
                // latch by the caller (`flush`/`batch`) so the UI can warn
                // instead of failing forever in silence.
                anyhow::anyhow!("localStorage write failed: {error:?}")
            })?;
        Ok(())
    }

    fn ensure_cached_loaded(&mut self) {
        // Read the backing store at most once; afterwards `cached` is the
        // authoritative source so empty/default accounts stop re-reading disk /
        // localStorage on every mutation.
        if self.loaded.get() {
            return;
        }
        if self.cached == ClientLocalState::default()
            && let Some(state) = self.read_persisted_state()
        {
            self.cached = state;
        }
        self.loaded.set(true);
    }
}

fn to_device_message_dedup_key(message: &Value) -> String {
    let kind = message
        .get("kind")
        .or_else(|| message.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let sender = message
        .get("sender_principal_id")
        .or_else(|| message.get("sender"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let sender_device = message
        .get("sender_device_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let recipient = message
        .get("recipient_principal_id")
        .or_else(|| message.get("recipient"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let recipient_device = message
        .get("recipient_device_id")
        .or_else(|| message.get("device_id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let content = message.get("content").unwrap_or(&Value::Null);
    let transaction = content
        .get("transaction_id")
        .or_else(|| content.get("request_id"))
        .or_else(|| content.get("pairing_code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !transaction.is_empty() {
        return format!(
            "{kind}|{sender}|{sender_device}|{recipient}|{recipient_device}|{transaction}"
        );
    }
    serde_json::to_string(message).unwrap_or_else(|_| format!("{kind}|{sender}|{recipient}"))
}

fn to_device_message_expired(message: &Value, now: DateTime<Utc>) -> bool {
    message
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|expires_at| expires_at.with_timezone(&Utc) <= now)
        .unwrap_or(false)
}

fn read_scope_for_cursor(realm_id: &str, topic_id: Option<&str>) -> ReadScope {
    match topic_id.map(str::trim).filter(|topic| !topic.is_empty()) {
        Some(topic) if topic.starts_with("ck:thread:") => ReadScope {
            kind: "thread".to_owned(),
            object_ref: Some(topic.to_owned()),
            track_name: None,
            track_scope: None,
        },
        Some(topic) if topic.starts_with("ck:flow:") => ReadScope {
            kind: "flow".to_owned(),
            object_ref: Some(topic.to_owned()),
            track_name: Some("discussion".to_owned()),
            track_scope: None,
        },
        _ => ReadScope {
            kind: "flow".to_owned(),
            object_ref: Some(default_flow_id_for_realm(realm_id)),
            track_name: Some("discussion".to_owned()),
            track_scope: None,
        },
    }
}

/// YOU-05-009: the `ck:realm:<suffix>` → `ck:flow:<suffix>` main-flow id
/// derivation is a protocol mapping rule that affects event addressing.
/// This is the crate's single authoritative copy — do NOT re-derive it
/// locally; a divergent copy writes events to the wrong flow.
pub(crate) fn default_flow_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:flow:{suffix}"))
        .unwrap_or_else(|| realm_id.to_owned())
}

/// YOU-05-010: shared test fixture — build a `LocalStateStore` rooted at a
/// unique temp file so tests never read or pollute the developer's real
/// `state.json` (or the `YOUGEN_STATE_PATH` override). On wasm32 the
/// default store is memory-only and therefore already hermetic. The `tag`
/// keeps any leftover temp file attributable to the test that created it;
/// uniqueness comes from the uuid_v7 suffix.
#[cfg(test)]
pub(crate) fn isolated_store_for_tests(tag: &str) -> LocalStateStore {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = std::env::temp_dir().join(format!(
            "yougen-test-{tag}-{}.json",
            crate::operation::uuid_v7()
        ));
        LocalStateStore::with_path(path)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = tag;
        LocalStateStore::default()
    }
}

fn new_read_cursor_id() -> String {
    format!("ck:read_cursor:{}", crate::operation::uuid_v7())
}

fn read_cursor_key(realm_id: &str, read_scope: &ReadScope) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        realm_id,
        read_scope.kind.as_str(),
        read_scope.object_ref.as_deref().unwrap_or(""),
        read_scope
            .track_name
            .as_deref()
            .or(read_scope.track_scope.as_deref())
            .unwrap_or("")
    )
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_state_path() -> PathBuf {
    std::env::var_os("YOUGEN_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_dir().join("state.json"))
}

#[cfg(not(target_arch = "wasm32"))]
fn app_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config").into()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("yougen")
}

/// XOR-based symmetric encryption for client-side private data.
/// This is a simple obfuscation, not production-grade crypto.
/// The same function encrypts and decrypts since XOR is its own inverse.
fn xor_encrypt(key: &str, data: &str) -> String {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return data.to_owned();
    }
    let encrypted: Vec<u8> = data
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    // Encode as hex for safe storage
    encrypted.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex-encoded XOR-encrypted data back to plaintext.
fn xor_decrypt(key: &str, hex_data: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return Some(hex_data.to_owned());
    }
    let bytes = hex_to_bytes(hex_data)?;
    let decrypted: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decrypted).ok()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn load_identity_record_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<LocalIdentityRecord> {
    #[cfg(target_arch = "wasm32")]
    if let Err(error) =
        crate::secure_key_store::require_wasm_indexeddb_ed25519_seed_store(secure_store)
    {
        tracing::warn!(?error, "secure identity read refused on wasm");
        return None;
    }
    match secure_store.get_secret(LocalStateStore::SECURE_IDENTITY_KEY) {
        Ok(Some(json)) => serde_json::from_str(&json).ok(),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(?error, "secure identity read failed");
            None
        }
    }
}

fn store_identity_record_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: &LocalIdentityRecord,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    crate::secure_key_store::require_wasm_indexeddb_ed25519_seed_store(secure_store)?;
    let json = serde_json::to_string(record).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize identity record: {error}"
        ))
    })?;
    secure_store.store_secret(LocalStateStore::SECURE_IDENTITY_KEY, &json)
}

fn load_dpop_device_key_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
    let Some(json) = secure_store.get_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY)? else {
        return Ok(None);
    };
    let record = serde_json::from_str(&json).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "parse DPoP device key record: {error}"
        ))
    })?;
    Ok(Some(record))
}

fn store_dpop_device_key_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: &DpopDeviceKeyRecord,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    let json = serde_json::to_string(record).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize DPoP device key record: {error}"
        ))
    })?;
    secure_store.store_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY, &json)
}

fn plaintext_identity_seed_fallback_allowed() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        cfg!(test)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        cfg!(test)
            || std::env::var("YOUGEN_ALLOW_PLAINTEXT_IDENTITY_SEED")
                .ok()
                .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    }
}

fn snapshot_item_encrypted_payload(
    item: &cokret_sdk::SnapshotMaterializedItem,
) -> Option<EncryptedPayload> {
    let schema = item
        .object
        .get("schema")
        .or_else(|| item.object.get("type"))
        .and_then(Value::as_str);
    let is_envelope = item.kind == "ck.schema.encrypted_envelope.v1"
        || schema == Some("ck.schema.encrypted_envelope.v1");
    if !is_envelope {
        return None;
    }
    serde_json::from_value(item.object.clone()).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::secure_key_store::SecureKeyStore;

    #[test]
    fn move_submission_state_maps_pending_seal_and_effective() {
        assert_eq!(
            MoveSubmissionState::from_submit_state("pending", None),
            MoveSubmissionState::PendingSeal
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("pending_seal", None),
            MoveSubmissionState::PendingSeal
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("accepted", None),
            MoveSubmissionState::PendingSeal
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("effective", None),
            MoveSubmissionState::Effective
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("sealed", None),
            MoveSubmissionState::Effective
        );
    }

    #[test]
    fn move_submission_state_maps_failure_reasons() {
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("notary_paused: recovery notary not signed")
            ),
            MoveSubmissionState::NotaryPaused
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("seal_signature_invalid for batch")
            ),
            MoveSubmissionState::RejectedSeal
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("bottom: cell has concurrent candidates")
            ),
            MoveSubmissionState::FailedBottom
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("rejected", Some("covered_seals mismatch")),
            MoveSubmissionState::PendingMlsBinding
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("rejected", Some("if_state did not match")),
            MoveSubmissionState::FailedPrecondition
        );
    }

    #[test]
    fn private_plaintext_snapshot_json_round_trips_through_merge() {
        // X5.3 — write sidecar entries, snapshot to JSON, then merge that JSON
        // into a FRESH store (the new-browser restore case) and read them back.
        let path = temp_state_path("private-plaintext-snapshot");
        let mut store = LocalStateStore::with_path(path);
        assert!(store.private_plaintext_is_empty());
        store.save_private_plaintext("ck:realm:s1", "ck:flow:f1", "body", "\"hello body\"");
        store.save_private_plaintext(
            "ck:realm:s1",
            "ck:flow:f1",
            "synthesis",
            "\"hello synthesis\"",
        );
        store.save_private_plaintext("ck:realm:s2", "ck:flow:f2", "body", "\"other body\"");
        assert!(!store.private_plaintext_is_empty());

        let json = store.private_plaintext_snapshot_json();
        let map: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>> =
            serde_json::from_slice(&json).unwrap();

        // Fresh store (empty) merges the snapshot -> every field reappears.
        let fresh_path = temp_state_path("private-plaintext-merged");
        let mut fresh = LocalStateStore::with_path(fresh_path);
        assert!(fresh.private_plaintext_is_empty());
        fresh.merge_private_plaintext_map(map);
        assert_eq!(
            fresh.private_plaintext_for("ck:realm:s1", "ck:flow:f1", "body"),
            Some("\"hello body\"".to_owned())
        );
        assert_eq!(
            fresh.private_plaintext_for("ck:realm:s1", "ck:flow:f1", "synthesis"),
            Some("\"hello synthesis\"".to_owned())
        );
        assert_eq!(
            fresh.private_plaintext_for("ck:realm:s2", "ck:flow:f2", "body"),
            Some("\"other body\"".to_owned())
        );
    }

    #[test]
    fn merge_private_plaintext_map_keeps_local_value_on_conflict() {
        // X5.3 merge semantics: incoming only FILLS missing fields; an existing
        // local value wins on conflict.
        let path = temp_state_path("private-plaintext-conflict");
        let mut store = LocalStateStore::with_path(path);
        store.save_private_plaintext("ck:realm:s1", "ck:flow:f1", "body", "\"local newer\"");

        let mut fields = BTreeMap::new();
        fields.insert("body".to_owned(), "\"backup older\"".to_owned()); // conflict
        fields.insert("synthesis".to_owned(), "\"backup synthesis\"".to_owned()); // gap
        let mut flows = BTreeMap::new();
        flows.insert("ck:flow:f1".to_owned(), fields);
        let mut incoming = BTreeMap::new();
        incoming.insert("ck:realm:s1".to_owned(), flows);
        store.merge_private_plaintext_map(incoming);

        // Conflict: local value kept.
        assert_eq!(
            store.private_plaintext_for("ck:realm:s1", "ck:flow:f1", "body"),
            Some("\"local newer\"".to_owned())
        );
        // Gap: backup fills it.
        assert_eq!(
            store.private_plaintext_for("ck:realm:s1", "ck:flow:f1", "synthesis"),
            Some("\"backup synthesis\"".to_owned())
        );
    }

    #[test]
    fn move_submission_record_round_trips_through_store() {
        let path = temp_state_path("move-submission");
        let mut store = LocalStateStore::with_path(path.clone());
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let mid = "sha256:111";
        store.record_move_submission(
            mid,
            realm,
            "ck.consent.grant",
            MoveSubmissionState::PendingSeal,
            None,
            Some("ck:seal:sha256:abc".to_owned()),
        );
        let listed = store.move_submissions_for_realm(realm);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].move_id, mid);
        assert_eq!(listed[0].state, MoveSubmissionState::PendingSeal);
        assert!(!store.realm_has_paused_notary(realm));

        // Update to NotaryPaused — Space should now flag the banner.
        assert!(store.update_move_submission_state(
            mid,
            MoveSubmissionState::NotaryPaused,
            Some("recovery notary not signed".to_owned()),
        ));
        assert!(store.realm_has_paused_notary(realm));
        let listed = store.move_submissions_for_realm(realm);
        assert_eq!(listed[0].state, MoveSubmissionState::NotaryPaused);
        assert_eq!(
            listed[0].reason.as_deref(),
            Some("recovery notary not signed")
        );

        // Persistence: a fresh reader sees the same state.
        let reader = LocalStateStore::with_path(path);
        assert!(reader.realm_has_paused_notary(realm));

        // Drop it and the banner clears.
        let mut store = LocalStateStore::with_path(reader.path.clone());
        store.drop_move_submission(mid);
        assert!(!store.realm_has_paused_notary(realm));
    }

    #[test]
    fn private_plaintext_sidecar_round_trips_through_store() {
        // X5.1 — save → reload via a fresh reader → read back. The local
        // plaintext sidecar must survive a reload (serde-persisted), since
        // it is the only place the author's own encrypted content lives.
        let path = temp_state_path("private-plaintext-sidecar");
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let flow = "ck:flow:0196419b-0000-7000-8000-0000000000aa";
        {
            let mut store = LocalStateStore::with_path(path.clone());
            store.save_private_plaintext(realm, flow, "body", "\"author body\"");
            store.save_private_plaintext(realm, flow, "synthesis", "\"author synthesis\"");
        }
        // Fresh reader (simulating a process restart / reload).
        let reader = LocalStateStore::with_path(path.clone());
        assert_eq!(
            reader.private_plaintext_for(realm, flow, "body").as_deref(),
            Some("\"author body\"")
        );
        assert_eq!(
            reader
                .private_plaintext_for(realm, flow, "synthesis")
                .as_deref(),
            Some("\"author synthesis\"")
        );
        let fields = reader.private_plaintext_fields(realm, flow);
        assert_eq!(fields.len(), 2);
        // Missing keys return None.
        assert!(
            reader
                .private_plaintext_for(realm, flow, "content")
                .is_none()
        );
        assert!(
            reader
                .private_plaintext_for("ck:realm:other", flow, "body")
                .is_none()
        );

        // Clearing a field (empty plaintext) removes it and persists.
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.save_private_plaintext(realm, flow, "body", "");
        let reader = LocalStateStore::with_path(path);
        assert!(reader.private_plaintext_for(realm, flow, "body").is_none());
        assert_eq!(
            reader
                .private_plaintext_for(realm, flow, "synthesis")
                .as_deref(),
            Some("\"author synthesis\"")
        );
    }

    #[test]
    fn sync_event_states_update_submission_by_event_id() {
        let path = temp_state_path("move-event-state");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let local_id = "sha256:local-submit";
        let event_id = "ck:event:0196419b-0000-7000-8000-0000000000aa";
        store.record_move_submission_with_event_id(
            local_id,
            Some(event_id.to_owned()),
            realm,
            "ck.flow.move",
            MoveSubmissionState::PendingSeal,
            None,
            Some("ck:seal:sha256:abc".to_owned()),
        );

        let updated = store.ingest_move_event_states(
            realm,
            &serde_json::json!({
                "event_states": [{
                    "event_id": event_id,
                    "event_state": "effective"
                }]
            }),
        );

        assert_eq!(updated, 1);
        let listed = store.move_submissions_for_realm(realm);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].move_id, local_id);
        assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
        assert_eq!(listed[0].state, MoveSubmissionState::Effective);
    }

    #[test]
    fn sync_event_states_update_legacy_submission_keyed_by_event_id() {
        let path = temp_state_path("legacy-move-event-state");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let event_id = "ck:event:0196419b-0000-7000-8000-0000000000bb";
        store.record_move_submission(
            event_id,
            realm,
            "mls_member_remove",
            MoveSubmissionState::PendingMlsBinding,
            None,
            None,
        );

        let updated = store.ingest_move_event_states(
            realm,
            &serde_json::json!({
                "event_states": [{
                    "event_id": event_id,
                    "event_state": "failed_bottom",
                    "event_state_reason_code": "cell_in_bottom_state"
                }]
            }),
        );

        assert_eq!(updated, 1);
        let listed = store.move_submissions_for_realm(realm);
        assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
        assert_eq!(listed[0].state, MoveSubmissionState::FailedBottom);
        assert_eq!(listed[0].reason.as_deref(), Some("cell_in_bottom_state"));
    }

    #[test]
    fn sync_event_states_update_submission_when_event_and_move_ids_are_present() {
        let path = temp_state_path("move-event-and-move-id-state");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let move_id = "sha256:local-submit-with-server-event";
        let event_id = "ck:event:0196419b-0000-7000-8000-0000000000cc";
        store.record_move_submission(
            move_id,
            realm,
            "ck.flow.move",
            MoveSubmissionState::PendingSeal,
            None,
            None,
        );

        let updated = store.ingest_move_event_states(
            realm,
            &serde_json::json!({
                "event_states": [{
                    "event_id": event_id,
                    "move_id": move_id,
                    "event_state": "effective"
                }]
            }),
        );

        assert_eq!(updated, 1);
        let listed = store.move_submissions_for_realm(realm);
        assert_eq!(listed[0].move_id, move_id);
        assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
        assert_eq!(listed[0].state, MoveSubmissionState::Effective);
    }

    #[test]
    fn move_submission_pending_mls_binding_drives_toast() {
        let path = temp_state_path("move-mls-binding");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000002";
        store.record_move_submission(
            "sha256:222",
            realm,
            "ck.message.create",
            MoveSubmissionState::PendingMlsBinding,
            Some("covered_seals missing".to_owned()),
            None,
        );
        assert!(store.realm_has_pending_mls_binding(realm));
        assert!(!store.realm_has_paused_notary(realm));
    }

    #[test]
    fn mls_encrypted_projection_detects_epoch_pause_scope() {
        let path = temp_state_path("mls-encrypted-projection");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:0196419b-0000-7000-8000-0000000000ee";
        store.save_realm_tree_projection(
            realm.to_owned(),
            json!({
                "schema": "ck.schema.realm.v1",
                "summary": {
                    "title": "Encrypted",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        );
        assert!(store.realm_projection_is_mls_encrypted(realm));

        let plain = "ck:realm:0196419b-0000-7000-8000-0000000000ef";
        store.save_realm_tree_projection(
            plain.to_owned(),
            json!({
                "schema": "ck.schema.realm.v1",
                "summary": {
                    "title": "Plain",
                    "encryption_profile": "none"
                }
            }),
        );
        assert!(!store.realm_projection_is_mls_encrypted(plain));
    }

    #[test]
    fn minimal_metadata_projection_detected_from_profiles_arrays() {
        // SEC-08 — the committer reads minimal-metadata status off the cached
        // projection. Recognised under `profiles[]` / `active_profiles[]` at the
        // top level and inside the nested realm body; absent / unknown ⇒ false.
        let path = temp_state_path("minimal-metadata-projection");
        let mut store = LocalStateStore::with_path(path);

        let top = "ck:realm:0196419b-0000-7000-8000-0000000000a1";
        store.save_realm_tree_projection(
            top.to_owned(),
            json!({ "profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
        );
        assert!(store.realm_projection_is_minimal_metadata(top));

        let nested = "ck:realm:0196419b-0000-7000-8000-0000000000a2";
        store.save_realm_tree_projection(
            nested.to_owned(),
            json!({
                "summary": {
                    "active_profiles": [
                        "ck.profile.core.v1",
                        cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE
                    ]
                }
            }),
        );
        assert!(store.realm_projection_is_minimal_metadata(nested));

        let plain = "ck:realm:0196419b-0000-7000-8000-0000000000a3";
        store.save_realm_tree_projection(
            plain.to_owned(),
            json!({ "profiles": ["ck.profile.core.v1"] }),
        );
        assert!(!store.realm_projection_is_minimal_metadata(plain));

        // Unknown Realm (no projection) ⇒ treated as non-minimal.
        assert!(
            !store.realm_projection_is_minimal_metadata(
                "ck:realm:0196419b-0000-7000-8000-0000000000a9"
            )
        );
    }

    #[test]
    fn member_handle_cache_is_realm_and_digest_scoped() {
        let path = temp_state_path("member-handle-cache");
        let mut store = LocalStateStore::with_path(path);
        let subject = "did:webvh:zQmMember";
        let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
        store.save_member_handle_lookup(
            subject,
            Some(realm.to_owned()),
            Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            ),
            Some("Alice:Example.COM".to_owned()),
            1,
            Some(Utc::now()),
            Some(Utc::now() + chrono::Duration::hours(2)),
        );

        let entry = store
            .cached_member_handle_lookup(
                subject,
                Some(realm),
                Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )
            .expect("fresh cache entry");
        assert_eq!(entry.primary_handle.as_deref(), Some("alice:example.com"));
        assert!(
            store
                .cached_member_handle_lookup(
                    subject,
                    Some(realm),
                    Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                )
                .is_none()
        );
        assert!(
            store
                .cached_member_handle_lookup(
                    subject,
                    Some("ck:realm:0196419b-0000-7000-8000-000000000002"),
                    Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                )
                .is_none()
        );
    }

    #[test]
    fn member_handle_cache_records_fresh_negative_lookup() {
        let path = temp_state_path("member-handle-negative-cache");
        let mut store = LocalStateStore::with_path(path);
        let subject = "did:webvh:zQmNoVisibleHandle";
        store.save_member_handle_lookup(
            subject,
            Some("ck:realm:0196419b-0000-7000-8000-000000000001".to_owned()),
            None,
            None,
            0,
            None,
            None,
        );

        let entry = store
            .cached_member_handle_lookup(
                subject,
                Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
                None,
            )
            .expect("fresh negative entry");
        assert!(entry.primary_handle.is_none());
    }

    #[test]
    fn move_submission_state_label_and_badge_class_distinct_per_state() {
        for state in [
            MoveSubmissionState::PendingSeal,
            MoveSubmissionState::Effective,
            MoveSubmissionState::FailedPrecondition,
            MoveSubmissionState::FailedBottom,
            MoveSubmissionState::RejectedSeal,
            MoveSubmissionState::NotaryPaused,
            MoveSubmissionState::PendingMlsBinding,
        ] {
            assert!(!state.slug().is_empty());
            assert!(!state.label_zh().is_empty());
            assert!(state.badge_class().starts_with("badge"));
        }
        assert!(MoveSubmissionState::NotaryPaused.is_failed());
        assert!(!MoveSubmissionState::PendingSeal.is_failed());
        assert!(!MoveSubmissionState::Effective.is_failed());
    }

    #[test]
    fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
        let path = temp_state_path("tracks");
        let mut store = LocalStateStore::with_path(path);
        store.save_sync_cursor("sx:next");
        store.append_raw_operation(
            "ck:operation:local-01",
            Some("ck:realm:demo".to_owned()),
            serde_json::json!({"type": "ck.message.create"}),
        );
        store.save_realm_tree_projection("ck:realm:demo", serde_json::json!({"name": "Demo"}));
        store.save_draft("ck:realm:demo", "hello");

        let state = store.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
        assert_eq!(
            state.raw_operations[0].operation_id,
            "ck:operation:local-01"
        );
        assert_eq!(
            state.realm_tree_projections["ck:realm:demo"]["name"],
            "Demo"
        );
        assert_eq!(store.draft_for("ck:realm:demo"), "hello");

        store.save_draft("ck:realm:demo", " ");
        assert!(store.draft_for("ck:realm:demo").is_empty());
    }

    #[test]
    fn realm_lifecycle_state_tracks_destroy_without_raw_operation_scan() {
        let path = temp_state_path("realm-lifecycle");
        let mut store = LocalStateStore::with_path(path.clone());
        let realm_id = "ck:realm:destroyed";

        assert!(!store.realm_is_destroyed(realm_id));
        store.append_raw_operation(
            "ck:operation:destroy",
            Some(realm_id.to_owned()),
            serde_json::json!({"kind": "ck.realm.destroy"}),
        );

        assert!(store.realm_is_destroyed(realm_id));
        let lifecycle = store.load().realm_lifecycle_state;
        assert!(lifecycle[realm_id].destroyed);
        assert_eq!(
            lifecycle[realm_id].destroyed_operation_id.as_deref(),
            Some("ck:operation:destroy")
        );

        let reader = LocalStateStore::with_path(path);
        assert!(reader.realm_is_destroyed(realm_id));

        store.forget_realm_tree_projection(realm_id);
        assert!(!store.realm_is_destroyed(realm_id));
    }

    #[test]
    fn local_state_store_persists_to_disk_between_instances() {
        let path = temp_state_path("persisted");
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.save_sync_cursor("sx:persisted");
        writer.save_draft("ck:realm:persisted", "draft survives restart");

        let reader = LocalStateStore::with_path(path);
        let state = reader.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:persisted"));
        assert_eq!(state.drafts["ck:realm:persisted"], "draft survives restart");
    }

    #[test]
    fn local_state_store_persists_notifications_and_mute_preferences() {
        let path = temp_state_path("notifications");
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_notification_projection(vec![serde_json::json!({
            "notification_id": "notif-1",
            "realm_id": "ck:realm:demo",
            "kind": "message",
            "body": "Hello"
        })]);
        store.set_notification_read("notif-1", true);
        store.set_notification_archived("notif-1", true);
        store.set_realm_muted("ck:realm:demo", true);
        store.set_notification_kind_enabled("message", false);

        let reader = LocalStateStore::with_path(path);
        assert_eq!(reader.notification_projection().len(), 1);
        assert!(reader.notification_state_for("notif-1").read);
        assert!(reader.notification_state_for("notif-1").archived);
        assert!(reader.is_realm_muted("ck:realm:demo"));
        assert!(!reader.notification_kind_enabled("message"));
    }

    #[test]
    fn realm_watch_level_set_get_roundtrip() {
        let path = temp_state_path("watch-level-roundtrip");
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_watch_level("ck:realm:a", WatchLevel::All);
        store.set_realm_watch_level("ck:realm:b", WatchLevel::Muted);
        // Setting the protocol default clears the override.
        store.set_realm_watch_level("ck:realm:c", WatchLevel::Participating);
        store.set_realm_watch_level("ck:realm:c", WatchLevel::MentionsOnly);

        let reader = LocalStateStore::with_path(path);
        assert_eq!(reader.realm_watch_level("ck:realm:a"), WatchLevel::All);
        assert_eq!(reader.realm_watch_level("ck:realm:b"), WatchLevel::Muted);
        assert_eq!(
            reader.realm_watch_level("ck:realm:c"),
            WatchLevel::MentionsOnly
        );
        assert!(!reader.realm_watch_levels().contains_key("ck:realm:c"));
        // The binary-mute compatibility view only reports `Muted` realms.
        assert_eq!(reader.muted_realms(), vec!["ck:realm:b".to_owned()]);
        assert!(reader.is_realm_muted("ck:realm:b"));
        assert!(!reader.is_realm_muted("ck:realm:a"));
    }

    #[test]
    fn legacy_muted_realms_migrate_to_watch_level() {
        let path = temp_state_path("legacy-mute-migration");
        // Persist a snapshot in the legacy shape (binary `muted_realms` map).
        let mut value = serde_json::to_value(ClientLocalState::default()).unwrap();
        value["muted_realms"] = serde_json::json!({
            "ck:realm:legacy": true,
            "ck:realm:already-unmuted": false,
        });
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let store = LocalStateStore::with_path(path);
        assert_eq!(
            store.realm_watch_level("ck:realm:legacy"),
            WatchLevel::Muted
        );
        assert_eq!(
            store.realm_watch_level("ck:realm:already-unmuted"),
            WatchLevel::MentionsOnly
        );
        // The legacy key must not survive a round-trip back to storage.
        let reserialized = serde_json::to_value(store.load()).unwrap();
        assert!(reserialized.get("muted_realms").is_none());
    }

    #[test]
    fn local_state_store_persists_private_read_cursors() {
        let path = temp_state_path("read-cursor");
        let mut store = LocalStateStore::with_path(path.clone());
        let marker = store.save_read_cursor(
            "did:web:alice.example",
            "device-1",
            "ck:realm:demo",
            None,
            "ck:event:read-1",
        );

        assert_eq!(marker.marker_type, "ck.read_cursor.advance");
        assert_eq!(marker.body.realm_id, "ck:realm:demo");
        assert_eq!(marker.body.position.event_id, "ck:event:read-1");
        assert_eq!(marker.body.read_scope.kind, "flow");
        assert_eq!(
            marker.body.read_scope.track_name.as_deref(),
            Some("discussion")
        );
        assert_eq!(
            marker.ck_read_cursor_operation(),
            serde_json::json!({
                "kind": "ck.read_cursor.advance",
                "payload": {
                    "id": &marker.body.id,
                    "schema": "ck.schema.read_cursor.v1",
                    "actor_id": "did:web:alice.example",
                    "device_id": "device-1",
                    "realm_id": "ck:realm:demo",
                    "read_scope": {
                        "kind": "flow",
                        "ref": "ck:flow:demo",
                        "track_name": "discussion"
                    },
                    "position": {
                        "event_id": "ck:event:read-1",
                        "hlc": &marker.body.position.hlc
                    },
                    "updated_at": &marker.updated_at,
                },
            })
        );

        let reader = LocalStateStore::with_path(path);
        let persisted = reader
            .read_cursor_for("ck:realm:demo", None)
            .expect("read marker persisted");
        assert_eq!(persisted.body.id, marker.body.id);
        assert_eq!(persisted.actor, "did:web:alice.example");
        assert_eq!(persisted.device_id, "device-1");
        assert_eq!(persisted.body.position.event_id, "ck:event:read-1");
    }

    #[test]
    fn local_state_store_keeps_thread_read_cursors_separate() {
        let path = temp_state_path("thread-read-cursor");
        let mut store = LocalStateStore::with_path(path);
        store.save_read_cursor(
            "did:web:alice.example",
            "desktop",
            "ck:realm:demo",
            None,
            "ck:event:topic",
        );
        store.save_read_cursor(
            "did:web:alice.example",
            "desktop",
            "ck:realm:demo",
            Some("ck:thread:reply-1".to_owned()),
            "ck:event:thread",
        );

        assert_eq!(
            store
                .read_cursor_for("ck:realm:demo", None)
                .expect("topic marker")
                .body
                .position
                .event_id,
            "ck:event:topic"
        );
        assert_eq!(
            store
                .read_cursor_for("ck:realm:demo", Some("ck:thread:reply-1"))
                .expect("thread marker")
                .body
                .position
                .event_id,
            "ck:event:thread"
        );
    }

    #[test]
    fn local_state_store_persists_push_registration_state() {
        let path = temp_state_path("push-registration");
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_push_registration(PushRegistrationState {
            schema_version: chime::PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
            principal_id: None,
            registration_id: Some("ck:push:local".to_owned()),
            device_id: "dev_yougen".to_owned(),
            platform: Some("desktop".to_owned()),
            app_id: Some("yougen".to_owned()),
            push_gateway: "https://push.example/_cokret/edge/push/notify".to_owned(),
            push_key_hash: "sha256:abc".to_owned(),
            push_key_preview: "desktop:<redacted,len=5>".to_owned(),
            registered_at: Some("2026-04-29T00:00:00Z".to_owned()),
            expires_at: None,
            refresh_hint: None,
            last_success_at: Some("2026-04-29T00:00:00Z".to_owned()),
            last_error: None,
        });

        let mut reader = LocalStateStore::with_path(path);
        let state = reader.push_registration().expect("push registration");
        assert_eq!(state.registration_id.as_deref(), Some("ck:push:local"));
        assert_eq!(state.device_id, "dev_yougen");

        reader.clear_push_registration();
        assert!(reader.push_registration().is_none());
    }

    /// `set_oidc_tokens_with_secure_store`
    /// MUST move the `refresh_token` AND the `access_token` out of the
    /// disk-backed `state.json` into the supplied `SecureKeyStore`
    /// keyed by `coauth.refresh_token.<actor_id>` /
    /// `coauth.access_token.<actor_id>`. The companion `load_*`
    /// helper reads them back. The on-disk JSON MUST NOT contain
    /// either bearer credential after the migration.
    #[test]
    fn oidc_tokens_migrate_into_secure_key_store_and_round_trip() {
        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
        let path = temp_state_path("h3-refresh-token");
        let mut store = LocalStateStore::with_path(path.clone());
        let secure = MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";

        let bundle = OidcTokenBundle {
            access_token: "atok".to_owned(),
            refresh_token: Some("rtok-secret".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix: Some(2_000_000_000),
            id_token: None,
            scope: None,
            audience: None,
            stored_at: Utc::now(),
        };
        let stripped = store
            .set_oidc_tokens_with_secure_store(Some(bundle), actor, &secure)
            .expect("bundle persisted");
        // Post-migration: in-state bundle MUST NOT carry either bearer
        // credential any more (the secure store is the new authority).
        assert!(stripped.refresh_token.is_none());
        assert!(stripped.access_token.is_empty());

        // The disk-backed bundle agrees.
        let on_disk = store.oidc_tokens().expect("bundle still on disk");
        assert!(on_disk.refresh_token.is_none());
        assert!(on_disk.access_token.is_empty());

        // Secure store holds the secrets under the per-actor keys.
        let secret = secure
            .get_secret(&format!("coauth.refresh_token.{actor}"))
            .expect("read ok")
            .expect("secret present");
        assert_eq!(secret, "rtok-secret");
        let access = secure
            .get_secret(&format!("coauth.access_token.{actor}"))
            .expect("read ok")
            .expect("access secret present");
        assert_eq!(access, "atok");

        // Load helper reattaches both tokens from the store.
        let reattached = store
            .load_oidc_tokens_with_secure_store(actor, &secure)
            .expect("bundle visible");
        assert_eq!(reattached.refresh_token.as_deref(), Some("rtok-secret"));
        assert_eq!(reattached.access_token, "atok");

        // Clearing the bundle deletes the secure-store entries too.
        store.set_oidc_tokens_with_secure_store(None, actor, &secure);
        assert!(
            secure
                .get_secret(&format!("coauth.refresh_token.{actor}"))
                .expect("read ok after clear")
                .is_none()
        );
        assert!(
            secure
                .get_secret(&format!("coauth.access_token.{actor}"))
                .expect("read ok after clear")
                .is_none()
        );
    }

    #[test]
    fn dpop_device_key_migrates_into_secure_key_store() {
        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
        let path = temp_state_path("dpop-secure-store");
        let mut store = LocalStateStore::with_path(path);
        let secure = MemorySecureKeyStore::default();
        let record = DpopDeviceKeyRecord {
            seed_b64: "seed-material".to_owned(),
            jkt: "jkt-1".to_owned(),
            created_at: Utc::now(),
        };

        let public_record = store
            .set_dpop_device_key_with_secure_store(Some(record.clone()), &secure)
            .expect("store dpop key")
            .expect("public record");
        assert_eq!(public_record.jkt, "jkt-1");
        assert!(public_record.seed_b64.is_empty());
        assert!(store.dpop_device_key().unwrap().seed_b64.is_empty());

        let secure_json = secure
            .get_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY)
            .expect("read secure dpop")
            .expect("secure dpop present");
        assert!(secure_json.contains("seed-material"));

        let loaded = store
            .load_dpop_device_key_with_secure_store(&secure)
            .expect("load dpop key")
            .expect("dpop key present");
        assert_eq!(loaded, record);

        store
            .set_dpop_device_key_with_secure_store(None, &secure)
            .expect("clear dpop key");
        assert!(store.dpop_device_key().is_none());
        assert!(
            secure
                .get_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY)
                .expect("read secure dpop after clear")
                .is_none()
        );
    }

    fn temp_state_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("yougen-state-{name}-{stamp}.json"))
    }

    fn snapshot_event_id(suffix: &str) -> cokret_sdk::EventId {
        cokret_sdk::EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn snapshot_hash(seed: u8) -> cokret_sdk::Hash {
        cokret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
    }

    fn snapshot_manifest_for_items(
        items: Vec<cokret_sdk::SnapshotMaterializedItem>,
    ) -> (
        cokret_sdk::SnapshotManifest,
        Vec<cokret_sdk::SnapshotChunkPayload>,
    ) {
        let snapshot_id =
            cokret_sdk::SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-0000000000aa")
                .unwrap();
        let realm_id =
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000aa").unwrap();
        let service_did = cokret_sdk::Did::new("did:web:server.example").unwrap();
        let state_digest = cokret_sdk::state_digest_from_items(&items).unwrap();
        let built = cokret_sdk::build_snapshot_chunks(
            &snapshot_id,
            cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
            items,
            4096,
        )
        .unwrap();
        let chunk_payloads = built
            .iter()
            .map(|chunk| chunk.payload.clone())
            .collect::<Vec<_>>();
        let chunks = built
            .into_iter()
            .map(|chunk| chunk.descriptor)
            .collect::<Vec<_>>();
        let created_at = Utc::now();
        let mut manifest = cokret_sdk::SnapshotManifest {
            id: snapshot_id,
            realm_id,
            reducer_profile: cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
            schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
            state_digest,
            frontier: cokret_sdk::SnapshotFrontier {
                event_ids: vec![snapshot_event_id("0000000000a2")],
                timeline_hlc: cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            },
            event_set_commitment: cokret_sdk::EventSetCommitment {
                algorithm: cokret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
                root: snapshot_hash(9),
                covered_event_count: 2,
                covered_seals: vec![snapshot_event_id("0000000000a2")],
                actor_seq_ranges: Vec::new(),
            },
            chunks,
            security_class: cokret_sdk::SnapshotSecurityClass::Standard,
            verification_hints: None,
            created_by: service_did.clone(),
            created_at,
            authority_binding: cokret_sdk::AuthorityBinding {
                issuer: service_did,
                authority_kind: cokret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
                auth_state_digest: snapshot_hash(1),
                auth_frontier: vec![snapshot_event_id("0000000000a2")],
                checked_at: created_at,
                witness_attestations: Vec::new(),
            },
            signature: cokret_sdk::DetachedJwsProof::eddsa(
                "did:web:server.example#snapshot".to_owned(),
                snapshot_hash(2),
                created_at,
                "header..signature".to_owned(),
            ),
        };
        manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
        (manifest, chunk_payloads)
    }

    #[test]
    fn apply_snapshot_chunks_imports_projection_status_and_encrypted_payload() {
        let path = temp_state_path("snapshot-apply");
        let mut store = LocalStateStore::with_path(path.clone());
        let message_id = "ck:message:01904100-0000-7000-8000-0000000000a1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-0000000000aa";
        let encrypted_message = json!({
            "schema": "ck.schema.encrypted_envelope.v1",
            "scheme": "mls-rfc9420",
            "group_id": realm_id,
            "epoch": 1,
            "content_type": "application/vnd.cokret.message+json",
            "ciphertext": "AA",
            "payload_digest": format!("sha256:{}", "ab".repeat(32)),
            "key_ref": {
                "algorithm": "mls-rfc9420",
                "group_state_ref": format!("{realm_id}:1")
            }
        });
        let items = vec![
            cokret_sdk::SnapshotMaterializedItem {
                kind: "ck.schema.encrypted_envelope.v1".to_owned(),
                id: message_id.to_owned(),
                object: encrypted_message.clone(),
                source_event_id: snapshot_event_id("0000000000a1"),
            },
            cokret_sdk::SnapshotMaterializedItem {
                kind: "realm".to_owned(),
                id: realm_id.to_owned(),
                object: json!({
                    "id": realm_id,
                    "title": "Snapshot Realm"
                }),
                source_event_id: snapshot_event_id("0000000000a2"),
            },
        ];
        let (manifest, chunks) = snapshot_manifest_for_items(items);

        store
            .apply_snapshot_chunks(
                &manifest,
                &chunks,
                crate::snapshot::SnapshotTrustState::LowerTrust,
            )
            .unwrap();

        let loaded = store.load();
        assert_eq!(
            loaded.realm_tree_projections.get(message_id),
            Some(&encrypted_message)
        );
        let status = loaded.snapshot_sync.get(realm_id).unwrap();
        assert_eq!(status.manifest_id, manifest.id.to_string());
        assert_eq!(
            status.trust_state,
            crate::snapshot::SnapshotTrustState::LowerTrust
        );
        assert_eq!(status.source_event_ids.len(), 2);
        assert_eq!(store.pending_encrypted_count(), 1);

        let reader = LocalStateStore::with_path(path);
        assert_eq!(reader.pending_encrypted_count(), 1);
        assert_eq!(
            reader.snapshot_sync_status(realm_id).unwrap().trust_state,
            crate::snapshot::SnapshotTrustState::LowerTrust
        );
    }

    #[test]
    fn retain_realm_tree_projections_prunes_per_realm_caches() {
        let path = temp_state_path("retain-prunes");
        let mut store = LocalStateStore::with_path(path);
        // Seed three realms with overlapping per-realm caches.
        for id in ["ck:realm:keep", "ck:realm:drop-a", "ck:realm:drop-b"] {
            store.save_realm_tree_projection(id, serde_json::json!({"name": id}));
            store.save_draft(id, "draft");
            store.set_realm_seal_view(id, LocalSealView::default());
            store.set_realm_muted(id, true);
        }
        // Independently keyed records that should follow the prune.
        store.save_read_cursor(
            "did:web:tester.example",
            "device-1",
            "ck:realm:drop-a",
            None,
            "ck:event:42",
        );
        store.save_read_cursor(
            "did:web:tester.example",
            "device-1",
            "ck:realm:keep",
            None,
            "ck:event:99",
        );

        let pruned = store.retain_realm_tree_projections(|id| id == "ck:realm:keep");
        assert_eq!(pruned.len(), 2);
        assert!(pruned.contains(&"ck:realm:drop-a".to_owned()));
        assert!(pruned.contains(&"ck:realm:drop-b".to_owned()));

        let state = store.load();
        assert_eq!(state.realm_tree_projections.len(), 1);
        assert!(state.realm_tree_projections.contains_key("ck:realm:keep"));
        assert!(!state.drafts.contains_key("ck:realm:drop-a"));
        assert!(state.drafts.contains_key("ck:realm:keep"));
        assert!(!state.seal_views.contains_key("ck:realm:drop-a"));
        assert!(state.seal_views.contains_key("ck:realm:keep"));
        assert!(!state.realm_watch_levels.contains_key("ck:realm:drop-b"));
        assert!(state.realm_watch_levels.contains_key("ck:realm:keep"));
        let kept_marker_keys: Vec<&str> = state.read_cursors.keys().map(String::as_str).collect();
        assert!(
            kept_marker_keys
                .iter()
                .any(|k| k.starts_with("ck:realm:keep\n")),
            "kept realm marker should survive prune: {kept_marker_keys:?}",
        );
        assert!(
            kept_marker_keys
                .iter()
                .all(|k| !k.starts_with("ck:realm:drop-a\n")),
            "pruned realm marker should be gone: {kept_marker_keys:?}",
        );
    }

    #[test]
    fn retain_realm_tree_projections_keeps_everything_when_all_match() {
        let path = temp_state_path("retain-all");
        let mut store = LocalStateStore::with_path(path);
        store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
        store.save_realm_tree_projection("ck:space:b", serde_json::json!({}));
        let pruned = store.retain_realm_tree_projections(|_| true);
        assert!(pruned.is_empty());
        assert_eq!(store.load().realm_tree_projections.len(), 2);
    }

    #[test]
    fn forget_realm_tree_projection_clears_a_single_space() {
        let path = temp_state_path("forget-one");
        let mut store = LocalStateStore::with_path(path);
        for id in ["ck:space:gone", "ck:space:stay"] {
            store.save_realm_tree_projection(id, serde_json::json!({}));
            store.save_draft(id, "draft");
            store.set_realm_seal_view(id, LocalSealView::default());
        }

        store.forget_realm_tree_projection("ck:space:gone");

        let state = store.load();
        assert!(!state.realm_tree_projections.contains_key("ck:space:gone"));
        assert!(state.realm_tree_projections.contains_key("ck:space:stay"));
        assert!(!state.drafts.contains_key("ck:space:gone"));
        assert!(state.drafts.contains_key("ck:space:stay"));
    }

    #[test]
    fn clear_account_scoped_preserves_device_level_and_token_state() {
        let path = temp_state_path("clear-account");
        let mut store = LocalStateStore::with_path(path);
        // Account-scoped projections.
        store.save_sync_cursor("sx:before");
        store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
        store.save_draft("ck:space:a", "draft");
        store.save_private_data("did:web:tester.example", "theme", "night");
        // Device-level state that MUST survive. ensure_local_identity
        // generates a fresh seed + DID and persists the record under
        // local_identity — the canonical device-level field this helper
        // is responsible for not nuking.
        let identity = store
            .ensure_local_identity()
            .expect("ensure_local_identity should succeed in plaintext mode");
        // Auth-token state that clear_account_scoped MUST preserve too.
        let bundle = OidcTokenBundle {
            access_token: "at".to_owned(),
            refresh_token: Some("rt".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix: None,
            id_token: None,
            scope: None,
            audience: None,
            stored_at: chrono::Utc::now(),
        };
        store.set_oidc_tokens(Some(bundle.clone()));

        store.clear_account_scoped();

        let state = store.load();
        assert!(state.sync_cursor.is_none(), "sync cursor should be wiped");
        assert!(
            state.realm_tree_projections.is_empty(),
            "projections should be wiped"
        );
        assert!(state.drafts.is_empty(), "drafts should be wiped");
        assert!(
            state.private_data.is_empty(),
            "private_data is account-scoped and should be wiped"
        );
        assert!(
            state.local_identity.is_some(),
            "device identity must survive an account-level wipe"
        );
        assert_eq!(
            state.local_identity.as_ref().unwrap().did_key,
            identity.local_signing_did,
        );
        assert!(
            state.oidc_tokens.is_some(),
            "OIDC tokens must survive — login flow owns them",
        );
        assert!(
            state.oidc_tokens.as_ref().unwrap().access_token.is_empty(),
            "access_token must not be serialised to state.json",
        );
        assert!(
            state.oidc_tokens.as_ref().unwrap().refresh_token.is_none(),
            "refresh_token must not be serialised to state.json",
        );
    }

    #[test]
    fn adopt_account_scope_resets_grant_cursor_and_oidc_on_identity_change() {
        let path = temp_state_path("adopt-account-scope");
        let mut store = LocalStateStore::with_path(path);

        // Establish alice's scope with a grant + OIDC + cursor + projection.
        assert!(
            store.adopt_account_scope("did:web:alice.example"),
            "first adopt (owner None) stamps and reports a reset"
        );
        let identity = store
            .ensure_local_identity()
            .expect("ensure_local_identity should succeed in plaintext mode");
        store.save_sync_cursor("sx:alice");
        store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
        store.set_oidc_tokens(Some(OidcTokenBundle {
            access_token: "alice-at".to_owned(),
            refresh_token: Some("alice-rt".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix: None,
            id_token: None,
            scope: None,
            audience: None,
            stored_at: chrono::Utc::now(),
        }));
        store.set_session_grant(Some(PersistedSessionGrant {
            grant_jwt: "alice.grant".to_owned(),
            session_private_key_pem: "pem".to_owned(),
            grant_id: "g-alice".to_owned(),
            audience: "https://principal.example/api".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
            grant_expires_at: None,
            session_expires_at: None,
            stored_at: chrono::Utc::now(),
        }));

        // Re-adopting the same actor is a no-op and keeps state.
        assert!(!store.adopt_account_scope("did:web:alice.example"));
        assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
        assert!(store.load().session_grant.is_some());

        // A different identity wipes the previous scope — including the
        // (possibly revoked) grant and the foreign-principal cursor — so
        // they can't leak into bob's session.
        assert!(store.adopt_account_scope("did:web:bob.example"));
        let state = store.load();
        assert!(state.sync_cursor.is_none(), "stale cursor must be wiped");
        assert!(
            state.realm_tree_projections.is_empty(),
            "projections must be wiped"
        );
        assert!(
            state.session_grant.is_none(),
            "previous identity's grant must be wiped, not preserved"
        );
        assert!(
            state.oidc_tokens.is_none(),
            "previous OIDC bundle must be wiped"
        );
        assert_eq!(
            state.account_scope_owner.as_deref(),
            Some("did:web:bob.example"),
            "owner is stamped to the new identity"
        );
        // Device-level identity survives the account-scope swap.
        assert_eq!(
            state.local_identity.as_ref().unwrap().did_key,
            identity.local_signing_did,
        );
    }

    #[test]
    fn xor_encrypt_decrypt_roundtrip() {
        let key = "did:web:alice.example";
        let plaintext = "my secret preference";
        let encrypted = xor_encrypt(key, plaintext);
        assert_ne!(encrypted, plaintext);
        let decrypted = xor_decrypt(key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xor_encrypt_empty_key_returns_original() {
        assert_eq!(xor_encrypt("", "hello"), "hello");
    }

    #[test]
    fn private_data_store_encrypts_and_persists() {
        let path = temp_state_path("private");
        let mut store = LocalStateStore::with_path(path.clone());
        let account_key = "did:web:alice.example";
        store.save_private_data(account_key, "theme", "dark");
        store.save_private_data(account_key, "custom_emoji", "party_parrot");

        assert_eq!(
            store.load_private_data(account_key, "theme"),
            Some("dark".to_owned())
        );
        assert_eq!(
            store.load_private_data(account_key, "custom_emoji"),
            Some("party_parrot".to_owned())
        );
        assert!(store.load_private_data(account_key, "missing").is_none());
        assert_eq!(store.private_data_keys().len(), 2);

        // Verify data is encrypted on disk
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("dark"));
        assert!(!raw.contains("party_parrot"));

        // Verify wrong key cannot decrypt
        assert_ne!(
            store.load_private_data("wrong-key", "theme"),
            Some("dark".to_owned())
        );
    }

    #[test]
    fn private_data_remove_works() {
        let path = temp_state_path("private-remove");
        let mut store = LocalStateStore::with_path(path);
        store.save_private_data("key", "temp", "value");
        assert!(store.load_private_data("key", "temp").is_some());
        store.remove_private_data("temp");
        assert!(store.load_private_data("key", "temp").is_none());
    }

    #[test]
    fn read_receipt_default_is_send_until_user_opts_out() {
        let path = temp_state_path("read-receipt-default");
        let mut store = LocalStateStore::with_path(path.clone());
        assert!(store.read_receipt_default_send());
        assert!(store.read_receipt_should_send(None, Some("ck:realm:any")));

        store.set_read_receipt_default_send(false);
        let reader = LocalStateStore::with_path(path);
        assert!(!reader.read_receipt_default_send());
        assert!(!reader.read_receipt_should_send(None, Some("ck:realm:any")));
    }

    #[test]
    fn read_receipt_resolution_flow_overrides_realm_overrides_default() {
        let path = temp_state_path("read-receipt-resolve");
        let mut store = LocalStateStore::with_path(path.clone());
        // default = true (send)
        store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
        store.set_read_receipt_flow_override("ck:flow:demo", Some(true));

        let reader = LocalStateStore::with_path(path);
        // Flow override wins.
        assert!(reader.read_receipt_should_send(Some("ck:flow:demo"), Some("ck:realm:demo")));
        // Space override wins over default when no flow override.
        assert!(!reader.read_receipt_should_send(None, Some("ck:realm:demo")));
        // Default applies when nothing matches.
        assert!(reader.read_receipt_should_send(None, Some("ck:realm:other")));
    }

    #[test]
    fn read_receipt_clearing_override_falls_back_to_default() {
        let path = temp_state_path("read-receipt-clear");
        let mut store = LocalStateStore::with_path(path);
        store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
        assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));

        store.set_read_receipt_realm_override("ck:realm:demo", None);
        assert!(store.read_receipt_should_send(None, Some("ck:realm:demo")));
        assert!(store.read_receipt_realm_override("ck:realm:demo").is_none());
    }

    #[test]
    fn server_policy_required_locks_user_choice_to_send() {
        let path = temp_state_path("read-receipt-policy-required");
        let mut store = LocalStateStore::with_path(path);
        // User opted out of the Space.
        store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
        // But server publishes disclosure=required → must override to true.
        store.set_read_receipt_policy_snapshot(
            "ck:realm:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "required".to_owned(),
                visibility: Some("public".to_owned()),
            }),
        );
        assert!(store.read_receipt_should_send(None, Some("ck:realm:demo")));
        let snap = store
            .read_receipt_policy_for_realm("ck:realm:demo")
            .unwrap();
        assert!(snap.locks_user_choice());
        assert!(!snap.lock_reason().is_empty());
    }

    #[test]
    fn server_policy_disabled_locks_user_choice_to_skip() {
        let path = temp_state_path("read-receipt-policy-disabled");
        let mut store = LocalStateStore::with_path(path);
        // User opts in.
        store.set_read_receipt_default_send(true);
        // Server publishes disclosure=disabled → must override to false.
        store.set_read_receipt_policy_snapshot(
            "ck:realm:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "disabled".to_owned(),
                visibility: Some("private".to_owned()),
            }),
        );
        assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));
    }

    #[test]
    fn server_policy_optional_does_not_lock() {
        let path = temp_state_path("read-receipt-policy-optional");
        let mut store = LocalStateStore::with_path(path);
        store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
        store.set_read_receipt_policy_snapshot(
            "ck:realm:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "optional".to_owned(),
                visibility: None,
            }),
        );
        // optional → user override wins.
        assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));
        let snap = store
            .read_receipt_policy_for_realm("ck:realm:demo")
            .unwrap();
        assert!(!snap.locks_user_choice());
        assert_eq!(snap.lock_reason(), "");
    }

    #[test]
    fn seal_view_default_returns_empty_bytes_sentinel() {
        let path = temp_state_path("seal-default");
        let store = LocalStateStore::with_path(path);
        let view = store.seal_view_for_realm("ck:realm:demo");
        assert!(view.frontier.is_empty());
        assert!(view.leaves.is_empty());
        assert!(view.state_root.is_none());
        assert_eq!(view.move_seal_ref(), LocalSealView::EMPTY_ANCHOR_REF);
        assert_eq!(
            store.seal_ref_for_realm_move("ck:realm:demo"),
            LocalSealView::EMPTY_ANCHOR_REF
        );
    }

    #[test]
    fn seal_view_set_persists_and_picks_lex_min_frontier() {
        let path = temp_state_path("seal-set");
        {
            let mut store = LocalStateStore::with_path(path.clone());
            store.set_realm_seal_view(
                "ck:realm:demo",
                LocalSealView {
                    frontier: vec![
                        "ck:seal:sha256:bbb".to_owned(),
                        "ck:seal:sha256:aaa".to_owned(),
                    ],
                    leaves: vec!["sha256:lf1".to_owned()],
                    state_root: Some("ck:state:sha256:abc".to_owned()),
                    bottom_cells: BTreeMap::new(),
                    mls_epoch: None,
                    covered_seals: None,
                    covered_seals_lag: None,
                    key_schedule_hash: None,
                },
            );
        }
        let reader = LocalStateStore::with_path(path);
        let view = reader.seal_view_for_realm("ck:realm:demo");
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves.len(), 1);
        assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
        assert_eq!(view.move_seal_ref(), "ck:seal:sha256:aaa");
        assert_eq!(
            reader.seal_ref_for_realm_move("ck:realm:demo"),
            "ck:seal:sha256:aaa"
        );
    }

    #[test]
    fn seal_view_bottom_cells_signal_conflict() {
        let mut view = LocalSealView::default();
        assert!(!view.has_bottom_cells());
        view.bottom_cells.insert(
            "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![],
            },
        );
        assert!(view.has_bottom_cells());
    }

    #[test]
    fn safer_winner_for_member_state_prefers_ban_over_join() {
        let mut view = LocalSealView::default();
        let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "ck:event:joined".to_owned(),
                        value: serde_json::json!({"membership": "join"}),
                    },
                    BottomCellHead {
                        move_id: "ck:event:banned".to_owned(),
                        value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                    },
                ],
            },
        );
        let (head_a, head_b, winner) = view.safer_winner_for(&cell).expect("ban beats join");
        assert_eq!(head_a, "ck:event:joined");
        assert_eq!(head_b, "ck:event:banned");
        assert_eq!(
            winner.get("membership").and_then(|v| v.as_str()),
            Some("ban")
        );
    }

    #[test]
    fn safer_winner_for_capability_grant_prefers_revoked_over_active() {
        let mut view = LocalSealView::default();
        let cell = "ck:cell:ck.component.capability.grant.v1:ck.grant.01".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "ck:event:granted".to_owned(),
                        value: serde_json::json!({"status": "active"}),
                    },
                    BottomCellHead {
                        move_id: "ck:event:revoked".to_owned(),
                        value: serde_json::json!({"status": "revoked"}),
                    },
                ],
            },
        );
        let (_, _, winner) = view.safer_winner_for(&cell).expect("revoked beats active");
        assert_eq!(
            winner.get("status").and_then(|v| v.as_str()),
            Some("revoked")
        );
    }

    #[test]
    fn safer_winner_for_unknown_cell_family_returns_none() {
        let mut view = LocalSealView::default();
        let cell = "ck:cell:ck.component.test.unknown.v1:ck:realm:demo".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "ck:event:a".to_owned(),
                        value: serde_json::json!({"title": "alpha"}),
                    },
                    BottomCellHead {
                        move_id: "ck:event:b".to_owned(),
                        value: serde_json::json!({"title": "beta"}),
                    },
                ],
            },
        );
        // No semantic safety ordering for this test-only cell family — operator
        // must pick manually.
        assert!(view.safer_winner_for(&cell).is_none());
    }

    #[test]
    fn safer_winner_for_tied_heads_returns_none() {
        let mut view = LocalSealView::default();
        let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "ck:event:ban-a".to_owned(),
                        value: serde_json::json!({"membership": "ban", "reason": "spam"}),
                    },
                    BottomCellHead {
                        move_id: "ck:event:ban-b".to_owned(),
                        value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                    },
                ],
            },
        );
        // Both heads tie on safety rank → no preference; operator picks.
        assert!(view.safer_winner_for(&cell).is_none());
    }

    #[test]
    fn safer_winner_for_missing_heads_returns_none() {
        let mut view = LocalSealView::default();
        let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![],
            },
        );
        assert!(view.safer_winner_for(&cell).is_none());
    }

    #[test]
    fn seal_view_from_sync_body_parses_full_payload() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ck:seal:sha256:aaa", "ck:seal:sha256:bbb"],
                "leaves":   ["sha256:lf1"],
                "state_root": "ck:state:sha256:abc",
                "cells": {
                    "ck:cell:ck.component.member.state.v1:did:web:alice": {
                        "bottom": "expose",
                        "heads": [
                            {
                                "move_id": "ck:event:joined",
                                "value": {"membership": "join"}
                            },
                            {
                                "move_id": "ck:event:banned",
                                "value": {"membership": "ban", "reason": "abuse"}
                            }
                        ]
                    },
                    "ck:cell:ck.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
        assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
        // Only `bottom=expose` cells are surfaced — `reject` cells stay
        // out of the conflict map.
        assert_eq!(view.bottom_cells.len(), 1);
        let info = view
            .bottom_cells
            .get("ck:cell:ck.component.member.state.v1:did:web:alice")
            .expect("expose cell present");
        assert_eq!(info.status, "expose");
        assert_eq!(info.heads.len(), 2);
        assert_eq!(info.heads[0].move_id, "ck:event:joined");
        assert_eq!(
            info.heads[1]
                .value
                .get("membership")
                .and_then(|v| v.as_str()),
            Some("ban")
        );
    }

    #[test]
    fn seal_view_from_sync_body_parses_structured_bottoms() {
        let body = serde_json::json!({
            "bottoms": [{
                "cell": "ck:cell:ck.component.flow.position.v1:ck:space:board:ck:flow:card",
                "status": "conflict",
                "bottom": {
                    "kind": "conflict",
                    "cells": [
                        "ck:cell:ck.component.flow.position.v1:ck:space:board:ck:flow:card"
                    ],
                    "event_ids": [
                        "ck:event:0196419b-0000-7000-8000-000000000001",
                        "ck:event:0196419b-0000-7000-8000-000000000002"
                    ],
                    "heads": [
                        {"list_space_id": "ck:space:list-a", "rank": "U"},
                        {"list_space_id": "ck:space:list-b", "rank": "U"}
                    ]
                }
            }]
        });

        let view = LocalSealView::from_sync_body(&body);
        let info = view
            .bottom_cells
            .get("ck:cell:ck.component.flow.position.v1:ck:space:board:ck:flow:card")
            .expect("structured bottom conflict surfaced");
        assert_eq!(info.status, "conflict");
        assert_eq!(info.heads.len(), 2);
        assert_eq!(
            info.heads[0].move_id,
            "ck:event:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(
            info.heads[1]
                .value
                .get("list_space_id")
                .and_then(|v| v.as_str()),
            Some("ck:space:list-b")
        );
    }

    #[test]
    fn seal_view_from_sync_body_extracts_mls_epoch_and_covered_seals() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ck:seal:sha256:aaa"],
                "leaves": [],
                "cells": {
                    "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                        "value": 7
                    },
                    "ck:cell:ck.component.governance.covered_seals.v1:ck:realm:demo": {
                        "register": { "value": "ck:state:sha256:abcd" }
                    }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(7));
        assert_eq!(view.covered_seals.as_deref(), Some("ck:state:sha256:abcd"));
    }

    #[test]
    fn seal_view_mls_epoch_supports_object_value_with_epoch_field() {
        // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
        // (typed view) instead of a bare integer. Both shapes need to round-trip.
        let body = serde_json::json!({
            "seal_view": {
                "frontier": [],
                "cells": {
                    "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                        "value": { "epoch": 42, "members": 3 }
                    }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(42));
    }

    #[test]
    fn seal_view_from_sync_body_extracts_covered_seals_lag() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ck:seal:sha256:aaa"],
                "leaves": [],
                "covered_seals_lag": 12,
                "cells": {}
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.covered_seals_lag, Some(12));
        // default threshold is 5 -> 12 > 5
        assert!(view.covered_seals_lag_above(5));
        assert!(!view.covered_seals_lag_above(20));
    }

    #[test]
    fn seal_view_lag_above_returns_false_when_lag_unknown() {
        let view = LocalSealView::default();
        assert!(!view.covered_seals_lag_above(5));
        assert!(!view.covered_seals_lag_above(0));
    }

    #[test]
    fn seal_view_from_sync_body_missing_returns_default() {
        let body = serde_json::json!({"summary": {"summary": "hi"}});
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view, LocalSealView::default());
    }

    #[test]
    fn seal_views_aggregates_across_realms() {
        let path = temp_state_path("seal-aggregate");
        let mut store = LocalStateStore::with_path(path);
        store.set_realm_seal_view(
            "ck:realm:one",
            LocalSealView {
                frontier: vec!["ck:seal:sha256:one".to_owned()],
                ..LocalSealView::default()
            },
        );
        store.set_realm_seal_view(
            "ck:realm:two",
            LocalSealView {
                frontier: vec!["ck:seal:sha256:two".to_owned()],
                ..LocalSealView::default()
            },
        );
        let all = store.seal_views();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("ck:realm:one"));
        assert!(all.contains_key("ck:realm:two"));
    }

    #[test]
    fn ensure_local_identity_generates_persists_and_round_trips() {
        let path = temp_state_path("local-identity");
        let id = {
            let mut store = LocalStateStore::with_path(path.clone());
            assert!(store.local_identity_record().is_none());
            assert!(store.local_identity().is_none());
            let id = store.ensure_local_identity().expect("first generate");
            assert!(id.local_signing_did.starts_with("did:key:z"));
            // Idempotent on the same store instance.
            let again = store.ensure_local_identity().expect("idempotent");
            assert_eq!(id, again);
            id
        };
        // Round-trip across store instances.
        let reader = LocalStateStore::with_path(path);
        let loaded = reader.local_identity().expect("persisted identity loads");
        assert_eq!(loaded.local_signing_did, id.local_signing_did);
        assert_eq!(loaded.signing_key.to_bytes(), id.signing_key.to_bytes());
    }

    #[test]
    fn secure_identity_handoff_moves_seed_out_of_state_record() {
        let path = temp_state_path("local-identity-secure");
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let id = {
            let mut store = LocalStateStore::with_path(path.clone());
            store
                .ensure_local_identity_with_secure_store(&secure)
                .expect("secure identity")
        };
        assert!(
            LocalStateStore::with_path(path)
                .load()
                .local_identity
                .is_none(),
            "state.json must not keep the identity seed after secure-store handoff",
        );
        let stored = secure
            .get_secret(LocalStateStore::SECURE_IDENTITY_KEY)
            .expect("secure read")
            .expect("identity secret");
        let record: LocalIdentityRecord = serde_json::from_str(&stored).unwrap();
        assert_eq!(record.did_key, id.local_signing_did);
        assert_eq!(
            LocalIdentity::from_record(&record)
                .unwrap()
                .signing_key
                .to_bytes(),
            id.signing_key.to_bytes(),
        );
    }

    #[test]
    fn secure_identity_handoff_migrates_existing_plaintext_seed() {
        let path = temp_state_path("local-identity-migrate");
        let existing = {
            let mut store = LocalStateStore::with_path(path.clone());
            store
                .ensure_local_identity_in_plaintext_state()
                .expect("plaintext test identity")
        };
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let migrated = {
            let mut store = LocalStateStore::with_path(path.clone());
            store
                .ensure_local_identity_with_secure_store(&secure)
                .expect("secure migration")
        };
        assert_eq!(migrated.local_signing_did, existing.local_signing_did);
        assert!(
            LocalStateStore::with_path(path)
                .load()
                .local_identity
                .is_none()
        );
        assert!(
            secure
                .get_secret(LocalStateStore::SECURE_IDENTITY_KEY)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn local_identity_two_calls_to_generate_diverge() {
        // Sanity: two `generate()` calls produce distinct keys (otherwise
        // the rng plumbing is broken). This guards against an accidental
        // regression to the deterministic [42; 32] seed.
        let one = LocalIdentity::generate().unwrap();
        let two = LocalIdentity::generate().unwrap();
        assert_ne!(one.local_signing_did, two.local_signing_did);
        assert_ne!(one.signing_key.to_bytes(), two.signing_key.to_bytes());
        assert_ne!(one.signing_key.to_bytes(), [42u8; 32]);
        assert_ne!(two.signing_key.to_bytes(), [42u8; 32]);
    }

    #[test]
    fn local_identity_record_tamper_detection_regenerates() {
        let path = temp_state_path("local-identity-tamper");
        let mut store = LocalStateStore::with_path(path.clone());
        let original = store.ensure_local_identity().unwrap();
        // Tamper: scramble the cached did_key while keeping the seed valid.
        // The next `ensure_local_identity` must reject + regenerate.
        store.cached.local_identity = Some(LocalIdentityRecord {
            seed_hex: original.to_record().seed_hex.clone(),
            did_key: "did:key:zTAMPERED".to_owned(),
        });
        let _ = store.flush();
        let regenerated = store.ensure_local_identity().unwrap();
        assert_ne!(regenerated.local_signing_did, "did:key:zTAMPERED");
        assert_ne!(
            regenerated.signing_key.to_bytes(),
            original.signing_key.to_bytes(),
            "regenerated identity is fresh, not the tampered original"
        );
    }

    #[test]
    fn read_receipt_policy_snapshot_persists_across_store_instances() {
        let path = temp_state_path("read-receipt-policy-persists");
        {
            let mut store = LocalStateStore::with_path(path.clone());
            store.set_read_receipt_policy_snapshot(
                "ck:realm:demo",
                Some(ReadReceiptPolicySnapshot {
                    disclosure: "required".to_owned(),
                    visibility: Some("track_scoped".to_owned()),
                }),
            );
        }
        let reader = LocalStateStore::with_path(path);
        let snap = reader
            .read_receipt_policy_for_realm("ck:realm:demo")
            .unwrap();
        assert_eq!(snap.disclosure, "required");
        assert_eq!(snap.visibility.as_deref(), Some("track_scoped"));
    }

    #[test]
    fn mls_snapshot_persists_and_round_trips_through_store() {
        // MLS snapshot envelope is durable across store instances and the
        // boot path can rehydrate every realm's group from the persisted
        // record.
        use crate::mls::persistence::encrypt_state;
        let path = temp_state_path("mls-snapshot-persist");
        let realm = "ck:realm:round28-mls";
        let envelope = encrypt_state(
            realm,
            "deadbeef",
            5,
            b"placeholder-state-bytes",
            "round28-pass",
            b"deterministic-salt",
        );
        {
            let mut writer = LocalStateStore::with_path(path.clone());
            assert!(writer.mls_snapshot_for(realm).is_none());
            writer.save_mls_snapshot(realm, envelope.clone());
        }
        let reader = LocalStateStore::with_path(path);
        let restored = reader.mls_snapshot_for(realm).expect("envelope persists");
        assert_eq!(restored.realm_id, envelope.realm_id);
        assert_eq!(restored.epoch, 5);
        assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
        assert_eq!(reader.mls_snapshots().len(), 1);
    }

    #[test]
    fn mls_snapshot_drop_clears_persisted_record() {
        use crate::mls::persistence::encrypt_state;
        let path = temp_state_path("mls-snapshot-drop");
        let mut store = LocalStateStore::with_path(path);
        let realm = "ck:realm:drop-me";
        store.save_mls_snapshot(realm, encrypt_state(realm, "abcd", 1, b"x", "p", b"salt"));
        assert!(store.mls_snapshot_for(realm).is_some());
        store.drop_mls_snapshot(realm);
        assert!(store.mls_snapshot_for(realm).is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_telemetry_404_re_buffers_entries() {
        // When the audit endpoint isn't wired (404), the flush
        // re-buffers each entry so a later flush attempt picks it up. We
        // simulate the 404 by pointing the API at a localhost port that
        // nothing's listening on - reqwest emits a connection error which
        // maps to `AuditPostError::Other`. To exercise the 404 path
        // specifically we spawn a minimal hyper-free TCP listener that
        // blanket-replies with 404.
        use std::net::SocketAddr;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use crate::telemetry::{UserActionOutcome, build_user_action_entry};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Reply 404 to a single request — enough for one
            // telemetry entry.
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                // Drain the request body opportunistically so the
                // client sees the response.
                let _ = socket.read(&mut buf).await;
                let resp =
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp).await;
                let _ = socket.shutdown().await;
            }
        });

        let mut store = LocalStateStore::with_path(temp_state_path("flush-404"));
        store.append_telemetry(build_user_action_entry(
            "did:key:zAlice",
            "settings.theme.set",
            UserActionOutcome::Success,
            None,
        ));
        assert_eq!(store.telemetry_log().len(), 1);

        let base = format!("http://{}/", addr);
        let api = crate::api::CokretApi::new(&base).unwrap();
        let sent = store.flush_telemetry_to_server(&api).await;
        assert_eq!(sent, 0, "404 must not count as sent");
        // 404-tolerant: entry survives for next attempt.
        assert_eq!(
            store.telemetry_log().len(),
            1,
            "404 must re-buffer the entry"
        );
        server.abort();
    }

    #[test]
    fn audit_post_error_display_and_classification() {
        // The typed error variants are how callers branch between
        // "re-buffer" and "drop" - the strings here drive operator-facing
        // copy and are part of the contract.
        let not_wired = crate::api::AuditPostError::NotWired;
        assert!(not_wired.to_string().contains("404"));
        let other = crate::api::AuditPostError::Other("conn refused".to_owned());
        assert!(other.to_string().contains("conn refused"));
    }

    // ── Realm remarks (spec client-preferences.md §3.7) ─

    #[test]
    fn realm_remark_set_and_display_name_prefers_local_name() {
        let path = temp_state_path("realm-remark-set");
        let mut store = LocalStateStore::with_path(path);
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        assert!(store.realm_remark(realm_id).is_none());
        assert_eq!(
            store.display_name_for_realm(realm_id, "Engineering"),
            "Engineering",
            "no remark → public title"
        );

        let remark = crate::account_data::RealmRemark::new(realm_id, "Acme · Eng");
        store.set_realm_remark(realm_id, remark);
        assert_eq!(
            store.display_name_for_realm(realm_id, "Engineering"),
            "Acme · Eng",
            "remark → local_name"
        );
        assert!(store.realm_remarks().contains_key(realm_id));
    }

    #[test]
    fn realm_remark_empty_value_tombstones_entry() {
        let path = temp_state_path("realm-remark-tombstone");
        let mut store = LocalStateStore::with_path(path);
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        store.set_realm_remark(
            realm_id,
            crate::account_data::RealmRemark::new(realm_id, "x"),
        );
        assert!(store.realm_remark(realm_id).is_some());

        // Whitespace-only local_name is treated as tombstone — see
        // RealmRemark::is_empty.
        store.set_realm_remark(
            realm_id,
            crate::account_data::RealmRemark {
                local_name: "   ".into(),
                ..crate::account_data::RealmRemark::default()
            },
        );
        assert!(
            store.realm_remark(realm_id).is_none(),
            "empty remark must remove the entry"
        );
    }

    #[test]
    fn realm_remark_remove_clears_only_target_realm() {
        let path = temp_state_path("realm-remark-remove");
        let mut store = LocalStateStore::with_path(path);
        let a = "ck:realm:00000000-0000-7000-8000-000000000001";
        let b = "ck:realm:00000000-0000-7000-8000-000000000002";
        store.set_realm_remark(a, crate::account_data::RealmRemark::new(a, "A"));
        store.set_realm_remark(b, crate::account_data::RealmRemark::new(b, "B"));

        store.remove_realm_remark(a);
        assert!(store.realm_remark(a).is_none());
        assert_eq!(
            store.realm_remark(b).map(|r| r.local_name),
            Some("B".to_owned()),
            "removing one Realm remark must not touch the other"
        );
    }

    #[test]
    fn realm_remark_persists_to_disk_between_instances() {
        let path = temp_state_path("realm-remark-persist");
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        {
            let mut writer = LocalStateStore::with_path(path.clone());
            writer.set_realm_remark(
                realm_id,
                crate::account_data::RealmRemark::new(realm_id, "Acme · Eng"),
            );
        }
        let reader = LocalStateStore::with_path(path);
        assert_eq!(
            reader.display_name_for_realm(realm_id, "Engineering"),
            "Acme · Eng"
        );
    }

    #[test]
    fn contact_remark_set_tombstone_and_display_name() {
        let path = temp_state_path("contact-remark-set");
        let mut store = LocalStateStore::with_path(path);
        let did = "did:web:alice.example";
        assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice");

        store.set_contact_remark(
            did,
            crate::account_data::ContactRemark::new(did, "Alice from Ops"),
        );
        assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice from Ops");
        assert!(store.contact_remarks().contains_key(did));

        store.set_contact_remark(
            did,
            crate::account_data::ContactRemark {
                actor_id: did.to_owned(),
                ..crate::account_data::ContactRemark::default()
            },
        );
        assert!(store.contact_remark(did).is_none());
    }
}
