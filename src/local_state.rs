use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use contrix_sdk::EncryptedPayload;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[cfg(target_arch = "wasm32")]
const LOCAL_STATE_STORAGE_KEY: &str = "yougen.local_state.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawOperationRecord {
    pub operation_id: String,
    pub space_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationClientState {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerBody {
    pub space_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_id: Option<String>,
    pub event_id: String,
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
    pub fn cx_marker_read_operation(&self) -> Value {
        json!({
            "type": self.marker_type,
            "body": &self.body,
        })
    }
}

/// Server-declared `cx.space.read_receipt_policy` snapshot for a Space, as
/// surfaced to clients via the Anchor view (P0 M3) once sync.rs lands.
/// Locks the per-scope toggle in the settings UI when `disclosure` is
/// `required` (server forces send) or `disabled` (server forbids send).
///
/// Until the sync wires the policy from soland's `cx.component.space.read_receipt_policy.v1`
/// cas-register cell, this is populated by tests / dev tooling only.
/// See `_todos.md` C10.D "Policy lock UI".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPolicySnapshot {
    /// Disclosure mode — `optional` (default), `required`, or `disabled`.
    /// `required` and `disabled` lock the user's per-Space override.
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
                "Space policy: read receipts are REQUIRED ({}). User-level skip is disabled.",
                self.visibility.as_deref().unwrap_or("public")
            ),
            "disabled" => format!(
                "Space policy: read receipts are DISABLED ({}). User-level send is disabled.",
                self.visibility.as_deref().unwrap_or("public")
            ),
            _ => String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Persisted shape of the device identity. Production callers store this
/// record in [`crate::secure_key_store::SecureKeyStore`]; plaintext
/// `state.json` storage is retained only for tests and explicitly enabled
/// development fallback.
///
/// This replaces the deterministic `[42; 32]` demo seed used by every Move
/// builder caller (`consent_demo::demo_signing_key`,
/// `space_admin::build_signed_*`, etc.). Fresh installs generate via
/// `getrandom::fill` on first access; existing dev installs that still
/// hold a `[42; 32]` cache are simply broken - they regenerate the next
/// time the store is loaded with no record present (Contrix v1 protocol is
/// pre-release, with no migration path).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityRecord {
    /// Hex-encoded 32-byte ed25519 seed. Production deploys MUST move this
    /// to OS keychain / WebAuthn / HSM and only keep a `did:key` reference
    /// here (TODO `secure-key-store-handoff`).
    pub seed_hex: String,
    /// `did:key:z<multibase>` derived from the seed's verifying key.
    pub did_key: String,
}

/// In-memory device identity: the per-device ed25519 signing key plus the
/// derived `did:key`. Construct via [`LocalStateStore::ensure_local_identity`]
/// (which generates+persists on first call) or [`LocalIdentity::from_record`]
/// (round-tripping a persisted record).
#[derive(Clone)]
pub struct LocalIdentity {
    pub device_did: String,
    pub signing_key: SigningKey,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private bytes.
        f.debug_struct("LocalIdentity")
            .field("device_did", &self.device_did)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl PartialEq for LocalIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.device_did == other.device_did
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
        let device_did = encode_did_key(&signing_key);
        Ok(Self {
            device_did,
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
            device_did: derived,
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
            did_key: self.device_did.clone(),
        }
    }
}

/// Encode an ed25519 verifying key as a `did:key:z<multibase>` DID. Mirror
/// of `move_builder::did_key_from_verifying_key` — duplicated here to keep
/// `local_state` independent of `move_builder` (which depends on this
/// module via the new identity accessor).
fn encode_did_key(signing_key: &SigningKey) -> String {
    let verifying = signing_key.verifying_key();
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(verifying.as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// Lifecycle state of a locally-submitted Move. Mirrors the states
/// soland's Move/Anchor pipeline can report via the
/// `SubmitMoveResponse.state` field plus the post-anchor effects the
/// next `/sync` cycle exposes:
///
/// - `PendingAnchor` — server accepted the Move into MoveStore, waiting
///   for the next anchorer batch to seal it. Initial state for any
///   successful submit.
/// - `Effective` — anchorer included the Move in a signed Anchor; the
///   reducer ran and the resulting cell state is now visible.
/// - `FailedPrecondition` — soland rejected the Move at submit time
///   because a precondition (`if_state` / `if_cell` / `parent_anchor`)
///   no longer matches the server's view.
/// - `FailedBottom` — the reducer accepted the Move but produced a
///   bottom (concurrent-candidate) cell; downstream queries are
///   undefined until an admin resolves the conflict via a `head_in`
///   repair Move (M8).
/// - `RejectedAnchor` — the anchorer batch that swept the Move was
///   rejected (signature / signer-set policy / anchorer-cell
///   mismatch); the Move never landed.
/// - `AnchorerPaused` — the Space's anchorer is paused (recovery
///   anchorer not yet rotated, or quorum unmet); the Space cannot
///   advance until ops bring it back online.
/// - `PendingMlsBinding` — the Move targets an E2EE
///   message but its `covered_frontier` precondition references a
///   governance frontier the local MLS group has not yet acknowledged.
///   Held client-side until the binding is observed; the user sees a
///   toast.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveSubmissionState {
    PendingAnchor,
    Effective,
    FailedPrecondition,
    FailedBottom,
    RejectedAnchor,
    AnchorerPaused,
    PendingMlsBinding,
}

impl MoveSubmissionState {
    /// Map a soland `SubmitMoveResponse.state` string into the typed
    /// enum. Unknown strings fall back to `PendingAnchor` (the safe
    /// "we accepted it, server will tell us more later" default) so
    /// new server-side states surface as in-flight rather than as
    /// failures.
    pub fn from_submit_state(state: &str, reason: Option<&str>) -> Self {
        match state {
            "pending" | "pending_anchor" => Self::PendingAnchor,
            "effective" | "anchored" => Self::Effective,
            "rejected" => match reason.unwrap_or("") {
                r if r.contains("anchorer_paused") => Self::AnchorerPaused,
                r if r.contains("rejected_anchor") || r.contains("anchor_signature") => {
                    Self::RejectedAnchor
                }
                r if r.contains("bottom") => Self::FailedBottom,
                r if r.contains("covered_frontier") || r.contains("mls_binding") => {
                    Self::PendingMlsBinding
                }
                _ => Self::FailedPrecondition,
            },
            "failed_precondition" => Self::FailedPrecondition,
            "failed_bottom" => Self::FailedBottom,
            "rejected_anchor" => Self::RejectedAnchor,
            "anchorer_paused" => Self::AnchorerPaused,
            "pending_mls_binding" => Self::PendingMlsBinding,
            _ => Self::PendingAnchor,
        }
    }

    /// Short tag used by the UI for state-specific styling (badge color
    /// / icon class). Mirrors the on-disk `serde(rename_all = "snake_case")`
    /// repr so log lines + CSS classes stay aligned.
    pub fn slug(self) -> &'static str {
        match self {
            Self::PendingAnchor => "pending_anchor",
            Self::Effective => "effective",
            Self::FailedPrecondition => "failed_precondition",
            Self::FailedBottom => "failed_bottom",
            Self::RejectedAnchor => "rejected_anchor",
            Self::AnchorerPaused => "anchorer_paused",
            Self::PendingMlsBinding => "pending_mls_binding",
        }
    }

    /// Human-readable label (Chinese where the spec / sodmin already
    /// uses Chinese copy). Surfaces in the timeline pill / banner.
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::PendingAnchor => "待 Anchor",
            Self::Effective => "已生效",
            Self::FailedPrecondition => "前置条件失败",
            Self::FailedBottom => "Bottom 冲突",
            Self::RejectedAnchor => "Anchor 拒绝",
            Self::AnchorerPaused => "Anchorer 暂停",
            Self::PendingMlsBinding => "MLS 绑定待覆盖",
        }
    }

    /// CSS-friendly badge class.
    pub fn badge_class(self) -> &'static str {
        match self {
            Self::PendingAnchor => "badge amber",
            Self::Effective => "badge green",
            Self::FailedPrecondition => "badge red",
            Self::FailedBottom => "badge red",
            Self::RejectedAnchor => "badge red",
            Self::AnchorerPaused => "badge red",
            Self::PendingMlsBinding => "badge amber",
        }
    }

    /// True when the state represents a terminal failure — the UI
    /// allows the user to click for a detail dialog.
    pub fn is_failed(self) -> bool {
        matches!(
            self,
            Self::FailedPrecondition
                | Self::FailedBottom
                | Self::RejectedAnchor
                | Self::AnchorerPaused
        )
    }
}

/// Per-Move tracking record persisted in the local state store. `move_id`
/// is content-addressed (`sha256:...`); the reducer round-trips
/// `space_id` so client UIs can scope filtering. `kind` is a free-form
/// classifier the UI uses for icons (e.g. `cx.consent.grant`,
/// `cx.message.create`, `mls_commit`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveSubmissionRecord {
    pub move_id: String,
    pub space_id: String,
    pub kind: String,
    pub state: MoveSubmissionState,
    pub submitted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional last-known anchor frontier head the Move was bound to.
    /// Surfaces in the failure detail so an operator can correlate the
    /// rejected Move to the predecessor that conflicted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
}

/// One competing head for a `bottom=expose` cell. Surfaced from sync so the
/// UI can render side-by-side candidates and prefill the "safer side" of a
/// conflict-repair Move.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellHead {
    /// Move (or Anchor head) id that produced this candidate.
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

/// Snapshot of the latest Anchor view observed for a Space. Surfaced from
/// the `/sync` Anchor view (P0 M3) and threaded into Move submissions so
/// every cell-driven write references the right frontier instead of the
/// `sha256(empty)` placeholder used previously.
///
/// `frontier` lists the Anchor head ids the local client currently treats
/// as the predecessor set (typically a single id but multiple while a
/// concurrent fork is unresolved). `state_root` is the post-state Merkle
/// root soland published in the most recent Anchor — clients can use it
/// to detect divergence between their projection and the server view.
/// `leaves` lists the Move ids covered by the current Anchor batch (the
/// "leaves of the lattice that the next Anchor will close over"); UIs
/// surface this so an admin can see which pending Moves an Anchor
/// rotation will sweep up.
///
/// The struct is intentionally `Default` so callers that haven't received
/// any Anchor view yet (offline, fresh login) still have a clean empty
/// view to feed into builders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAnchorView {
    /// Anchor head ids that the next Move treats as predecessors. Empty
    /// vec means "no Anchor seen yet" — Move builders fall back to the
    /// `sha256(empty)` sentinel.
    #[serde(default)]
    pub frontier: Vec<String>,
    /// Move ids covered by the current Anchor batch (or about to be
    /// closed by the next Anchor rotation). Surfaced for admin UIs.
    #[serde(default)]
    pub leaves: Vec<String>,
    /// Post-state Merkle root from the most recent Anchor. Optional —
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
    /// `cx.component.mls.epoch.v1` cas-register cell, when sync surfaces
    /// it. `None` means the Space hasn't published an MLS epoch yet (no
    /// E2EE group or pre-genesis state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_epoch: Option<u64>,
    /// The current `governance.covered_frontier` cell value - the lattice
    /// frontier cell that governance Moves require predecessor coverage of
    /// before they're accepted. Surfaced as a string so the UI can render
    /// whatever shape soland publishes (typically a `cx:state:sha256:...`
    /// ref). `None` means the governance cell hasn't been observed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_frontier: Option<String>,
    /// The per-Space MLS `covered_frontier_lag` count - how many
    /// governance Moves the MLS group has yet to acknowledge. Soland
    /// publishes this as `anchor_view.covered_frontier_lag` (a bare
    /// integer) when it knows the lag; clients combine it with a
    /// configurable warn threshold (default 5) to render an alert banner
    /// in `space_admin`. `None` means soland hasn't surfaced a lag value -
    /// UI treats that as "no alert".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_frontier_lag: Option<u64>,
    /// MLS key-schedule content hash (`sha256:<hex>`) from the
    /// `cx.component.key_schedule.v1` cas-register cell. The MLS commit
    /// path uses this as `prev_schedule`; the new commit computes a
    /// fresh schedule on top of it. `None` means the Space has not
    /// published a key schedule yet (no prior MLS commit observed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule_hash: Option<String>,
}

impl LocalAnchorView {
    /// SHA-256 of empty bytes — used as the "no Anchor seen yet" sentinel
    /// the Move builders historically defaulted to.
    pub const EMPTY_ANCHOR_REF: &'static str =
        "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Pick the single Anchor ref to feed into a Move builder. Returns the
    /// first frontier head if any, otherwise the empty-bytes sentinel.
    /// When the frontier holds multiple heads (concurrent fork) this picks
    /// the lex-min head so two clients building Moves against the same
    /// view will agree on which predecessor they reference.
    pub fn move_anchor_ref(&self) -> String {
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

    /// True when soland has surfaced a covered_frontier_lag strictly
    /// greater than `threshold`. Used by the space_admin covered_frontier
    /// alert banner to decide whether to render. Returns `false` when no
    /// lag has been published yet (the field is `None`) - the UI treats
    /// that as "no signal, no alert".
    pub fn covered_frontier_lag_above(&self, threshold: u64) -> bool {
        self.covered_frontier_lag.is_some_and(|lag| lag > threshold)
    }

    /// For security-relevant cell families (member.state, capability.grant),
    /// return the safer winner candidate from the cell's competing heads —
    /// the more restrictive membership value or the revoked grant. Returns
    /// `None` when:
    /// - the cell isn't a known security-relevant family (operator must
    ///   pick manually — there's no semantic safety ordering to lean on),
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
        let safer = safer_value_for_cell(cell_ref, &head_a.value, &head_b.value)?;
        Some((head_a.move_id.clone(), head_b.move_id.clone(), safer))
    }
}

/// Rank `a` and `b` on the cell's safety order; return whichever ranks
/// higher (more restrictive). `None` means "no order I'll commit to" —
/// either the cell family is not in the table, or both heads tie. Tying
/// is intentional: ban-vs-ban or revoke-vs-revoke is a content conflict,
/// not a safety call, so we surface no preference and the operator picks.
fn safer_value_for_cell(cell_ref: &str, a: &Value, b: &Value) -> Option<Value> {
    let rank: fn(&Value) -> u8 = if cell_ref.starts_with("cx:cell:cx.component.member.state.v1") {
        member_state_safety_rank
    } else if cell_ref.starts_with("cx:cell:cx.component.capability.grant.v1") {
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

impl LocalAnchorView {
    /// Best-effort extraction of an Anchor view from a per-Space `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "anchor_view": {
    ///     "frontier": ["cx:anchor:sha256:..."],
    ///     "leaves":   ["sha256:..."],
    ///     "state_root": "cx:state:sha256:...",
    ///     "cells": {
    ///       "cx:cell:cx.component.member.state.v1:did:web:alice": {
    ///         "bottom": "expose"
    ///       }
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Until soland publishes the full payload, missing fields default to
    /// empty / `None`. The function is total and never errors — it just
    /// degrades to `LocalAnchorView::default()` when fields are missing
    /// or have unexpected shapes.
    pub fn from_sync_body(body: &Value) -> Self {
        let anchor = body.get("anchor_view");
        let mut view = Self::default();
        let Some(anchor) = anchor else {
            return view;
        };
        if let Some(arr) = anchor.get("frontier").and_then(|v| v.as_array()) {
            view.frontier = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(arr) = anchor.get("leaves").and_then(|v| v.as_array()) {
            view.leaves = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(s) = anchor.get("state_root").and_then(|v| v.as_str()) {
            view.state_root = Some(s.to_owned());
        }
        // Top-level `covered_frontier_lag`: soland publishes this directly
        // on the anchor view (sibling of `frontier` / `leaves`) so clients
        // don't have to compute it from cell maps.
        if let Some(lag) = anchor.get("covered_frontier_lag").and_then(|v| v.as_u64()) {
            view.covered_frontier_lag = Some(lag);
        }
        if let Some(cells) = anchor.get("cells").and_then(|v| v.as_object()) {
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
                // Well-known named cells surfaced for the space_admin MLS
                // epoch widget. We accept either a raw `value` or a typed
                // `register.value` field - soland's canonical projection
                // uses the latter; tests may emit the former.
                let value_for = |status: &Value| -> Option<Value> {
                    status
                        .get("value")
                        .cloned()
                        .or_else(|| status.get("register").and_then(|r| r.get("value")).cloned())
                };
                if cell_ref.starts_with("cx:cell:cx.component.mls.epoch.v1")
                    && let Some(value) = value_for(status)
                {
                    view.mls_epoch = value
                        .as_u64()
                        .or_else(|| value.get("epoch").and_then(|v| v.as_u64()));
                }
                if cell_ref.starts_with("cx:cell:cx.component.governance.covered_frontier.v1")
                    && let Some(value) = value_for(status)
                {
                    view.covered_frontier = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("frontier")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
                // B3c: surface the MLS key schedule hash so the next
                // commit's `GovernanceBindingPayload` can carry the
                // SDK-canonical "advance schedule" effect on it.
                if cell_ref.starts_with("cx:cell:cx.component.key_schedule.v1")
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
        view
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLocalState {
    pub sync_cursor: Option<String>,
    pub raw_operations: Vec<RawOperationRecord>,
    pub space_projections: BTreeMap<String, Value>,
    pub drafts: BTreeMap<String, String>,
    pub pending_encrypted_messages: BTreeMap<String, EncryptedPayload>,
    #[serde(default)]
    pub notification_projection: Vec<Value>,
    #[serde(default)]
    pub notification_client_state: BTreeMap<String, NotificationClientState>,
    #[serde(default)]
    pub muted_spaces: BTreeMap<String, bool>,
    #[serde(default)]
    pub muted_notification_kinds: BTreeMap<String, bool>,
    /// Read receipt send preferences (spec
    /// `discovery/client-preferences.md` §3.6, account-data key
    /// `cx.read_receipt.preferences`).
    ///
    /// `read_receipt_default_send` is the global fallback (default: send).
    /// `read_receipt_space_overrides` and `read_receipt_flow_overrides`
    /// are per-scope overrides; resolution order is (flow → space →
    /// default), matching the SDK's `ReadReceiptPreferences::effective_send`.
    /// Until the server wires `cx.account_data.set` for this key,
    /// preferences live only on this device.
    #[serde(default = "default_true")]
    pub read_receipt_default_send: bool,
    #[serde(default)]
    pub read_receipt_space_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub read_receipt_flow_overrides: BTreeMap<String, bool>,
    /// Server-declared `cx.space.read_receipt_policy` snapshots, keyed by
    /// space id. Populated when sync (P0 M3) lands — surfaces the
    /// disclosure / visibility values from the
    /// `cx.component.space.read_receipt_policy.v1` cas-register cell so
    /// the settings UI can lock per-Space toggles when the server's
    /// policy is `required` or `disabled`.
    #[serde(default)]
    pub read_receipt_policy_snapshots: BTreeMap<String, ReadReceiptPolicySnapshot>,
    /// Latest Anchor view per Space, threaded from `/sync`'s Anchor
    /// projection (P0 M3). Move builders pull `frontier[0]` from here
    /// instead of using the empty-bytes sentinel. UIs use the
    /// `bottom_cells` map to surface conflict banners when a cell is
    /// `bottom=expose`.
    #[serde(default)]
    pub anchor_views: BTreeMap<String, LocalAnchorView>,
    #[serde(default)]
    pub push_registration: Option<PushRegistrationState>,
    /// Per-device ed25519 identity. Generated + persisted on first access
    /// via `LocalStateStore::ensure_local_identity`. Move builders read
    /// this in place of the historical `[42; 32]` demo seed.
    #[serde(default)]
    pub local_identity: Option<LocalIdentityRecord>,
    /// Locally-submitted Move state tracker. Keyed by `move_id`; entries
    /// arrive when `submit_move` succeeds and get updated when the next
    /// sync surfaces an Anchor that includes the id (or a rejection).
    /// Drives the timeline / space_admin state pill UI.
    #[serde(default)]
    pub move_submissions: BTreeMap<String, MoveSubmissionRecord>,
    /// Encrypted private account data (preferences, tags, custom emojis).
    /// Values are XOR-encrypted with account_key and hex-encoded.
    #[serde(default)]
    pub private_data: BTreeMap<String, String>,
    /// Private cx.marker.read cursors keyed by space + topic/thread scope.
    #[serde(default)]
    pub read_markers: BTreeMap<String, ReadMarkerRecord>,
    /// Persisted OIDC token bundle - access_token, refresh_token, expiry,
    /// audience. Written when the PKCE token endpoint exchange succeeds;
    /// read at boot to seed the API client. The KeyStore abstraction
    /// provides the signing key for session-grant proofs; this field
    /// carries the short-lived bearer + the longer-lived refresh handle.
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
    /// Persisted MLS group state snapshots, keyed by `space_id`. Each
    /// entry is the encrypted envelope produced by
    /// [`crate::mls_persistence::encrypt_state`]; the boot path
    /// rehydrates each space's `LocalMlsDevice` from the latest envelope
    /// rather than rejoining via Welcome from scratch.
    #[serde(default)]
    pub mls_snapshots: BTreeMap<String, crate::mls_persistence::MlsSnapshotEnvelope>,
    /// Actor-private Space remarks per
    /// `discovery/client-preferences.md` §3.7. Hydrated from the soland
    /// `/sync` `account_data[]` projection (entries with
    /// `data_type == "cx.contacts.space.<space_id>"`) and from user edits
    /// in settings. Keyed by Space id so the sidebar / dashboard can join
    /// it against the public `SpacePreview.name` at render time and prefer
    /// `local_name` when set.
    #[serde(default)]
    pub space_remarks: BTreeMap<String, crate::account_data::SpaceRemark>,
    /// Actor-private contact remarks per
    /// `discovery/client-preferences.md` §3.6. Keyed by actor DID and
    /// hydrated from `cx.contacts.actor.<did>` account_data entries.
    #[serde(default)]
    pub contact_remarks: BTreeMap<String, crate::account_data::ContactRemark>,
    /// Actor-private personal blocklist per
    /// `discovery/client-preferences.md` (`cx.account.blocklist`). Each
    /// entry hides messages from the targeted DID in the timeline/chat
    /// renderers and surfaces in the Settings → Privacy panel. The
    /// shape mirrors the wire body so the future
    /// `cx.account_data.set("cx.account.blocklist", …)` push can serialise
    /// straight from this `Vec`.
    #[serde(default)]
    pub client_blocklist: Vec<crate::account_data::BlocklistEntry>,
}

/// Hard cap on the number of buffered telemetry entries kept in
/// `ClientLocalState::telemetry_log`. When the cap is reached the
/// oldest entry is dropped to make room for the new one. 256 is
/// roughly two minutes of aggressive interaction at 2 actions/sec —
/// enough to survive a network blip, well below the size at which
/// `state.json` becomes painful to round-trip.
pub const TELEMETRY_BUFFER_CAP: usize = 256;

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
/// [`crate::api::ContrixApi::exchange_session_grant_at_with_proof`] plus
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
    /// Principal DID the grant authorizes.
    pub principal_did: String,
    /// Device id bound to the grant.
    pub device_id: String,
    /// Principal-server base URL where the grant is exchanged.
    pub principal_server_url: String,
    /// `session_grant_exchange_path` discovered from the principal
    /// auth-bridge `/api/v1/auth/bridge/describe`.
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

impl Default for ClientLocalState {
    fn default() -> Self {
        Self {
            sync_cursor: None,
            raw_operations: Vec::new(),
            space_projections: BTreeMap::new(),
            drafts: BTreeMap::new(),
            pending_encrypted_messages: BTreeMap::new(),
            notification_projection: Vec::new(),
            notification_client_state: BTreeMap::new(),
            muted_spaces: BTreeMap::new(),
            muted_notification_kinds: BTreeMap::new(),
            read_receipt_default_send: true,
            read_receipt_space_overrides: BTreeMap::new(),
            read_receipt_flow_overrides: BTreeMap::new(),
            read_receipt_policy_snapshots: BTreeMap::new(),
            anchor_views: BTreeMap::new(),
            push_registration: None,
            local_identity: None,
            move_submissions: BTreeMap::new(),
            private_data: BTreeMap::new(),
            read_markers: BTreeMap::new(),
            oidc_tokens: None,
            session_grant: None,
            telemetry_log: Vec::new(),
            mls_snapshots: BTreeMap::new(),
            space_remarks: BTreeMap::new(),
            contact_remarks: BTreeMap::new(),
            client_blocklist: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalStateStore {
    cached: ClientLocalState,
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

impl Default for LocalStateStore {
    fn default() -> Self {
        Self {
            cached: ClientLocalState::default(),
            #[cfg(not(target_arch = "wasm32"))]
            path: default_state_path(),
        }
    }
}

impl LocalStateStore {
    const SECURE_IDENTITY_KEY: &'static str = "identity.local.primary.v1";

    pub fn load(&self) -> ClientLocalState {
        if self.cached != ClientLocalState::default() {
            return self.cached.clone();
        }
        self.read_persisted_state().unwrap_or_default()
    }

    pub fn save(&mut self, state: ClientLocalState) {
        self.cached = state;
        let _ = self.flush();
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        self.write_persisted_state(&self.cached)
    }

    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.ensure_cached_loaded();
        self.cached.sync_cursor = Some(cursor.into());
        let _ = self.flush();
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        space_id: Option<String>,
        payload: Value,
    ) {
        self.ensure_cached_loaded();
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id: operation_id.into(),
            space_id,
            received_at: Utc::now(),
            payload,
        });
        let _ = self.flush();
    }

    pub fn save_space_projection(&mut self, space_id: impl Into<String>, projection: Value) {
        self.ensure_cached_loaded();
        self.cached
            .space_projections
            .insert(space_id.into(), projection);
        let _ = self.flush();
    }

    /// Drop every `space_projections` entry whose key isn't in `keep`. Used
    /// by the sync reconcile path when `since=None` so spaces the server
    /// no longer reports get pruned from the local cache instead of
    /// lingering as ghost entries in the sidebar.
    ///
    /// Also prunes the auxiliary per-space caches (`drafts`,
    /// `anchor_views`, `read_markers`, `space_remarks`,
    /// `mls_snapshots`, `move_submissions` keyed by space, the
    /// `read_receipt_*_overrides`, `read_receipt_policy_snapshots`,
    /// `muted_spaces`, and any leftover encrypted-message draft) so a
    /// pruned Space doesn't leave private remnants behind.
    pub fn retain_space_projections<F>(&mut self, keep: F) -> Vec<String>
    where
        F: Fn(&str) -> bool,
    {
        self.ensure_cached_loaded();
        let removed: Vec<String> = self
            .cached
            .space_projections
            .keys()
            .filter(|id| !keep(id))
            .cloned()
            .collect();
        if removed.is_empty() {
            return removed;
        }
        for id in &removed {
            self.forget_space_inner(id);
        }
        let _ = self.flush();
        removed
    }

    /// Remove a single Space and every per-space derived record. Public
    /// entry point for `left_spaces`-style sync deltas. Flushes once.
    pub fn forget_space(&mut self, space_id: &str) {
        self.ensure_cached_loaded();
        let trimmed = space_id.trim();
        if trimmed.is_empty() {
            return;
        }
        self.forget_space_inner(trimmed);
        let _ = self.flush();
    }

    fn forget_space_inner(&mut self, space_id: &str) {
        self.cached.space_projections.remove(space_id);
        self.cached.drafts.remove(space_id);
        self.cached.anchor_views.remove(space_id);
        self.cached.space_remarks.remove(space_id);
        self.cached.mls_snapshots.remove(space_id);
        self.cached.muted_spaces.remove(space_id);
        self.cached.read_receipt_space_overrides.remove(space_id);
        self.cached.read_receipt_policy_snapshots.remove(space_id);
        // `read_markers` are keyed by `"{space}\n{topic}"` — strip every
        // marker whose space prefix matches.
        let prefix = format!("{space_id}\n");
        self.cached
            .read_markers
            .retain(|key, _| !key.starts_with(&prefix));
        // `move_submissions` carry a `space_id` field; drop matching entries.
        self.cached
            .move_submissions
            .retain(|_, record| record.space_id != space_id);
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
    /// Pairs with [`Self::retain_space_projections`] which only handles
    /// the steady-state sync reconcile case.
    pub fn clear_account_scoped(&mut self) {
        self.ensure_cached_loaded();
        let preserved_identity = self.cached.local_identity.clone();
        let preserved_push = self.cached.push_registration.clone();
        let preserved_telemetry = std::mem::take(&mut self.cached.telemetry_log);
        let preserved_oidc = self.cached.oidc_tokens.clone();
        let preserved_grant = self.cached.session_grant.clone();
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            telemetry_log: preserved_telemetry,
            oidc_tokens: preserved_oidc,
            session_grant: preserved_grant,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
    }

    pub fn save_draft(&mut self, space_id: impl Into<String>, draft: impl Into<String>) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        let draft = draft.into();
        if draft.trim().is_empty() {
            self.cached.drafts.remove(&space_id);
        } else {
            self.cached.drafts.insert(space_id, draft);
        }
        let _ = self.flush();
    }

    pub fn draft_for(&self, space_id: &str) -> String {
        self.cached
            .drafts
            .get(space_id)
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
        self.cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default()
            .read = read;
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

    pub fn save_read_marker(
        &mut self,
        actor: impl Into<String>,
        device_id: impl Into<String>,
        space_id: impl Into<String>,
        topic_id: Option<String>,
        event_id: impl Into<String>,
    ) -> ReadMarkerRecord {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        let topic_id = topic_id.filter(|topic| !topic.trim().is_empty());
        let marker = ReadMarkerRecord {
            marker_type: "cx.marker.read".to_owned(),
            body: ReadMarkerBody {
                space_id: space_id.clone(),
                topic_id: topic_id.clone(),
                event_id: event_id.into(),
            },
            actor: actor.into(),
            device_id: device_id.into(),
            updated_at: Utc::now(),
        };
        self.cached.read_markers.insert(
            read_marker_key(&space_id, topic_id.as_deref()),
            marker.clone(),
        );
        let _ = self.flush();
        marker
    }

    pub fn read_marker_for(
        &self,
        space_id: &str,
        topic_id: Option<&str>,
    ) -> Option<ReadMarkerRecord> {
        self.load()
            .read_markers
            .get(&read_marker_key(space_id, topic_id))
            .cloned()
    }

    pub fn latest_read_marker(&self, space_id: &str) -> Option<ReadMarkerRecord> {
        self.load()
            .read_markers
            .into_values()
            .filter(|marker| marker.body.space_id == space_id)
            .max_by(|left, right| left.updated_at.cmp(&right.updated_at))
    }

    pub fn set_space_muted(&mut self, space_id: impl Into<String>, muted: bool) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        if muted {
            self.cached.muted_spaces.insert(space_id, true);
        } else {
            self.cached.muted_spaces.remove(&space_id);
        }
        let _ = self.flush();
    }

    pub fn clear_muted_spaces(&mut self) {
        self.ensure_cached_loaded();
        self.cached.muted_spaces.clear();
        let _ = self.flush();
    }

    pub fn is_space_muted(&self, space_id: &str) -> bool {
        self.load()
            .muted_spaces
            .get(space_id)
            .copied()
            .unwrap_or(false)
    }

    pub fn muted_spaces(&self) -> Vec<String> {
        self.load()
            .muted_spaces
            .into_iter()
            .filter_map(|(space_id, muted)| muted.then_some(space_id))
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

    pub fn read_receipt_space_override(&self, space_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_space_overrides
            .get(space_id)
            .copied()
    }

    pub fn set_read_receipt_space_override(
        &mut self,
        space_id: impl Into<String>,
        send: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        match send {
            Some(value) => {
                self.cached
                    .read_receipt_space_overrides
                    .insert(space_id, value);
            }
            None => {
                self.cached.read_receipt_space_overrides.remove(&space_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_space_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_space_overrides
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

    // ── Space remarks (spec client-preferences.md §3.7) ─

    /// Return the stored remark for `space_id`, if any. `None` means the
    /// user has not set a local override and the public `Space.title`
    /// should be rendered.
    pub fn space_remark(&self, space_id: &str) -> Option<crate::account_data::SpaceRemark> {
        self.load().space_remarks.get(space_id).cloned()
    }

    /// All known Space remarks. The settings UI uses this to render the
    /// edit list; callers MUST NOT publish this map to other Space
    /// members — it is actor-private per §3.7.
    pub fn space_remarks(&self) -> BTreeMap<String, crate::account_data::SpaceRemark> {
        self.load().space_remarks
    }

    /// Upsert a remark for `space_id`. Passing a remark whose
    /// [`SpaceRemark::is_empty`] returns true tombstones the entry
    /// (equivalent to `remove_space_remark`). Persists synchronously to
    /// disk; the caller is responsible for pushing the same payload to
    /// soland via `PUT /api/v1/account_data/{key}`.
    pub fn set_space_remark(
        &mut self,
        space_id: impl Into<String>,
        remark: crate::account_data::SpaceRemark,
    ) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        if remark.is_empty() {
            self.cached.space_remarks.remove(&space_id);
        } else {
            self.cached.space_remarks.insert(space_id, remark);
        }
        let _ = self.flush();
    }

    /// Delete the remark for `space_id`. No-op if none is stored.
    pub fn remove_space_remark(&mut self, space_id: &str) {
        self.ensure_cached_loaded();
        self.cached.space_remarks.remove(space_id);
        let _ = self.flush();
    }

    // ── Contact remarks (spec client-preferences.md §3.6) ─

    pub fn contact_remark(&self, actor_did: &str) -> Option<crate::account_data::ContactRemark> {
        self.load().contact_remarks.get(actor_did).cloned()
    }

    pub fn contact_remarks(&self) -> BTreeMap<String, crate::account_data::ContactRemark> {
        self.load().contact_remarks
    }

    pub fn set_contact_remark(
        &mut self,
        actor_did: impl Into<String>,
        remark: crate::account_data::ContactRemark,
    ) {
        self.ensure_cached_loaded();
        let actor_did = actor_did.into();
        if remark.is_empty() {
            self.cached.contact_remarks.remove(&actor_did);
        } else {
            self.cached.contact_remarks.insert(actor_did, remark);
        }
        let _ = self.flush();
    }

    pub fn remove_contact_remark(&mut self, actor_did: &str) {
        self.ensure_cached_loaded();
        self.cached.contact_remarks.remove(actor_did);
        let _ = self.flush();
    }

    pub fn display_name_for_actor(&self, actor_did: &str, public_name: &str) -> String {
        match self
            .load()
            .contact_remarks
            .get(actor_did)
            .map(|r| r.display_name(public_name).to_owned())
        {
            Some(name) => name,
            None => public_name.to_owned(),
        }
    }

    // ── Personal blocklist (spec client-preferences.md "cx.account.blocklist") ─

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
    /// `cx.account_data.set("cx.account.blocklist", …)`.
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

    /// Replace the whole personal blocklist from `/sync account_data`.
    /// User edits still go through [`block_user`] / [`unblock_user`];
    /// this method is only for remote state hydration.
    pub fn set_client_blocklist(&mut self, entries: Vec<crate::account_data::BlocklistEntry>) {
        self.ensure_cached_loaded();
        self.cached.client_blocklist = entries;
        let _ = self.flush();
    }

    /// Best-effort name for `space_id`: trimmed `local_name` from the
    /// stored remark if set, otherwise `public_title`. Mirrors the §3.7
    /// "UI MUST prefer local_name" rule so the sidebar / dashboard /
    /// dashboard cards all agree.
    pub fn display_name_for_space(&self, space_id: &str, public_title: &str) -> String {
        match self
            .load()
            .space_remarks
            .get(space_id)
            .map(|r| r.display_name(public_title).to_owned())
        {
            Some(name) => name,
            None => public_title.to_owned(),
        }
    }

    /// Get the server-declared read-receipt policy for a Space (when known).
    /// `None` means the client hasn't synced a policy snapshot yet and the
    /// user's override is still authoritative.
    pub fn read_receipt_policy_for_space(
        &self,
        space_id: &str,
    ) -> Option<ReadReceiptPolicySnapshot> {
        self.load()
            .read_receipt_policy_snapshots
            .get(space_id)
            .cloned()
    }

    /// Replace the server-declared policy snapshot for a Space. Called from
    /// the sync path once the Anchor view (P0 M3) surfaces
    /// `cx.component.space.read_receipt_policy.v1` cell value; tests use
    /// this to seed lock-state UI behavior.
    pub fn set_read_receipt_policy_snapshot(
        &mut self,
        space_id: impl Into<String>,
        snapshot: Option<ReadReceiptPolicySnapshot>,
    ) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        match snapshot {
            Some(value) => {
                self.cached
                    .read_receipt_policy_snapshots
                    .insert(space_id, value);
            }
            None => {
                self.cached.read_receipt_policy_snapshots.remove(&space_id);
            }
        }
        let _ = self.flush();
    }

    /// All known server-declared read-receipt policy snapshots.
    pub fn read_receipt_policy_snapshots(&self) -> BTreeMap<String, ReadReceiptPolicySnapshot> {
        self.load().read_receipt_policy_snapshots
    }

    /// Get the latest Anchor view for a Space. Returns the Default view
    /// (empty frontier / empty leaves / no state_root) when none has been
    /// observed yet — Move builders treat that as "use sha256(empty)
    /// sentinel".
    pub fn anchor_view_for(&self, space_id: &str) -> LocalAnchorView {
        self.load()
            .anchor_views
            .get(space_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the Anchor view snapshot for a Space. Called from the sync
    /// path once the `/sync` response surfaces the projection's Anchor
    /// view. Tests use this to seed Move-frontier behavior.
    pub fn set_anchor_view(&mut self, space_id: impl Into<String>, view: LocalAnchorView) {
        self.ensure_cached_loaded();
        self.cached.anchor_views.insert(space_id.into(), view);
        let _ = self.flush();
    }

    /// All known Anchor views — handy for app-wide UI banners.
    pub fn anchor_views(&self) -> BTreeMap<String, LocalAnchorView> {
        self.load().anchor_views
    }

    /// Convenience: pick the right `anchor_ref` to thread into a Move
    /// builder for a given Space. Returns the lex-min frontier head when
    /// available, otherwise the `sha256(empty)` sentinel. Mirrors
    /// [`LocalAnchorView::move_anchor_ref`].
    pub fn anchor_ref_for_move(&self, space_id: &str) -> String {
        self.anchor_view_for(space_id).move_anchor_ref()
    }

    /// Resolve effective send preference per spec (server policy → flow →
    /// space → default). Mirror of
    /// `contrix_sdk::ReadReceiptPreferences::effective_send` extended with
    /// server-declared policy lock: when the Space publishes a
    /// `cx.space.read_receipt_policy` with `disclosure="required"` the
    /// answer is forced `true`; with `disclosure="disabled"` it's forced
    /// `false`. User-level overrides are ignored in those cases (matching
    /// the lock UI in settings).
    pub fn read_receipt_should_send(&self, flow_id: Option<&str>, space_id: Option<&str>) -> bool {
        let snapshot = self.load();
        if let Some(sid) = space_id
            && let Some(policy) = snapshot.read_receipt_policy_snapshots.get(sid)
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
        if let Some(sid) = space_id
            && let Some(value) = snapshot.read_receipt_space_overrides.get(sid)
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
    /// caller has just received soland's `SubmitMoveResponse`; the
    /// state is mapped in via [`MoveSubmissionState::from_submit_state`].
    /// `kind` is a free-form classifier (e.g. `cx.consent.grant`,
    /// `cx.message.create`, `mls_commit`) the UI uses to decorate
    /// pills + icons.
    pub fn record_move_submission(
        &mut self,
        move_id: impl Into<String>,
        space_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        anchor_ref: Option<String>,
    ) -> MoveSubmissionRecord {
        self.ensure_cached_loaded();
        let move_id = move_id.into();
        let record = MoveSubmissionRecord {
            move_id: move_id.clone(),
            space_id: space_id.into(),
            kind: kind.into(),
            state,
            submitted_at: Utc::now(),
            reason,
            anchor_ref,
        };
        self.cached.move_submissions.insert(move_id, record.clone());
        let _ = self.flush();
        record
    }

    /// Update the lifecycle state of a tracked Move. Called when the
    /// next `/sync` cycle surfaces an Anchor inclusion / rejection.
    /// Returns `false` when the move id isn't tracked (no-op).
    pub fn update_move_submission_state(
        &mut self,
        move_id: &str,
        state: MoveSubmissionState,
        reason: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let Some(record) = self.cached.move_submissions.get_mut(move_id) else {
            return false;
        };
        record.state = state;
        if reason.is_some() {
            record.reason = reason;
        }
        let _ = self.flush();
        true
    }

    /// Read all tracked Moves for a specific Space, sorted by submit
    /// time (newest first). Used by the timeline / space_admin pills.
    pub fn move_submissions_for_space(&self, space_id: &str) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> = self
            .load()
            .move_submissions
            .into_values()
            .filter(|record| record.space_id == space_id)
            .collect();
        out.sort_by(|a, b| b.submitted_at.cmp(&a.submitted_at));
        out
    }

    /// Read all tracked Moves regardless of Space — used by the
    /// dashboard "everything failing" banner and the recovery flow.
    pub fn all_move_submissions(&self) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> =
            self.load().move_submissions.into_values().collect();
        out.sort_by(|a, b| b.submitted_at.cmp(&a.submitted_at));
        out
    }

    /// True when at least one tracked Move in `space_id` is in
    /// `AnchorerPaused`. Drives the Space-wide "waiting for recovery anchorer"
    /// banner described in the M4 ticket.
    pub fn space_has_paused_anchorer(&self, space_id: &str) -> bool {
        self.move_submissions_for_space(space_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::AnchorerPaused)
    }

    /// True when at least one tracked Move targeting `space_id` is
    /// stuck on `PendingMlsBinding`. Drives the M7 toast.
    pub fn space_has_pending_mls_binding(&self, space_id: &str) -> bool {
        self.move_submissions_for_space(space_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::PendingMlsBinding)
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
    /// alternative is bricking the client, and Contrix v1 is pre-release
    /// so there is no user-facing key recovery story to preserve.
    pub fn ensure_local_identity(&mut self) -> anyhow::Result<LocalIdentity> {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            return self.ensure_local_identity_with_secure_store(secure_store.as_ref());
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

    /// Persist a fresh OIDC token bundle (or clear via `None`). Stores
    /// access + refresh + id_token verbatim - the KeyStore abstraction is
    /// responsible for the at-rest secrecy of the underlying state.json
    /// file.
    pub fn set_oidc_tokens(&mut self, bundle: Option<OidcTokenBundle>) {
        self.ensure_cached_loaded();
        self.cached.oidc_tokens = bundle;
        let _ = self.flush();
    }

    /// Persist a fresh OIDC token bundle and
    /// **migrate the refresh_token field into the supplied
    /// `SecureKeyStore`** so the disk-backed `state.json` does not
    /// hold the refresh credential in plaintext. Returns the bundle
    /// that ended up serialised (the `refresh_token` field is wiped to
    /// `None` post-secure-store-write so a corrupt-restore can't leak).
    ///
    /// The secure-store key is `coauth.refresh_token.<actor_did>` so a
    /// device that has signed in as multiple actors keeps them
    /// isolated. Callers SHOULD use [`load_oidc_tokens_with_secure_store`]
    /// to reattach the refresh_token at boot before passing the bundle
    /// into the OIDC refresh poller.
    pub fn set_oidc_tokens_with_secure_store(
        &mut self,
        bundle: Option<OidcTokenBundle>,
        actor_did: &str,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Option<OidcTokenBundle> {
        let key = format!("coauth.refresh_token.{actor_did}");
        let stripped = match bundle {
            Some(mut bundle) => {
                if let Some(refresh) = bundle.refresh_token.take() {
                    if let Err(error) = secure_store.store_secret(&key, &refresh) {
                        tracing::warn!(
                            ?error,
                            actor = actor_did,
                            "secure_key_store refresh_token write failed; bundle persisted without refresh_token (next refresh poll will fall back to re-login)",
                        );
                    }
                }
                Some(bundle)
            }
            None => {
                if let Err(error) = secure_store.delete_secret(&key) {
                    tracing::debug!(
                        ?error,
                        actor = actor_did,
                        "secure_key_store refresh_token delete on bundle-clear failed (likely already missing)",
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
    /// state.json and reattaches the `refresh_token` from the secure
    /// store under the per-actor key. Returns `None` when no bundle
    /// has been persisted yet (same shape as
    /// [`Self::oidc_tokens`]).
    pub fn load_oidc_tokens_with_secure_store(
        &self,
        actor_did: &str,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Option<OidcTokenBundle> {
        let mut bundle = self.oidc_tokens()?;
        if bundle.refresh_token.is_none() {
            let key = format!("coauth.refresh_token.{actor_did}");
            match secure_store.get_secret(&key) {
                Ok(Some(value)) => bundle.refresh_token = Some(value),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        actor = actor_did,
                        "secure_key_store refresh_token read failed; bundle returned without refresh_token",
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

    /// True when a persisted access_token exists AND has not yet expired
    /// (per `expires_at_unix`). Used by the API client boot path to decide
    /// whether to refresh before issuing requests.
    pub fn oidc_access_token_valid(&self) -> bool {
        let Some(bundle) = self.oidc_tokens() else {
            return false;
        };
        if bundle.access_token.is_empty() {
            return false;
        }
        match bundle.expires_at_unix {
            // 30s skew window so a token that's about to expire is
            // refreshed proactively rather than dying mid-request.
            Some(expires) => Utc::now().timestamp() + 30 < expires,
            None => true,
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

    /// Persist (or replace) the MLS snapshot envelope for a space.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// passphrase-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_snapshot(
        &mut self,
        space_id: impl Into<String>,
        envelope: crate::mls_persistence::MlsSnapshotEnvelope,
    ) {
        self.ensure_cached_loaded();
        self.cached.mls_snapshots.insert(space_id.into(), envelope);
        let _ = self.flush();
    }

    /// Look up the latest MLS snapshot envelope for a space, if any.
    /// Returns `None` when the space has not yet been snapshotted (a
    /// fresh group on this device, or a group that has not committed
    /// yet so there is no state to persist).
    pub fn mls_snapshot_for(
        &self,
        space_id: &str,
    ) -> Option<crate::mls_persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots.get(space_id).cloned()
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known space's group in one pass and by
    /// the cross-device sync UI to enumerate what's available before
    /// asking the user for a passphrase.
    pub fn mls_snapshots(&self) -> BTreeMap<String, crate::mls_persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots
    }

    /// Drop the MLS snapshot for a space — used after a successful
    /// "rotate group" / "leave group" Move so the next boot doesn't
    /// try to rehydrate a stale leaf.
    pub fn drop_mls_snapshot(&mut self, space_id: &str) {
        self.ensure_cached_loaded();
        if self.cached.mls_snapshots.remove(space_id).is_some() {
            let _ = self.flush();
        }
    }

    /// Drain the buffered telemetry log and POST each entry to soland's
    /// audit feed. The endpoint is 404-tolerant: until soland wires
    /// `cx.audit.user_action.ingest`, the server returns 404 and we
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
    pub async fn flush_telemetry_to_server(&mut self, api: &crate::api::ContrixApi) -> usize {
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
            path: path.into(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let bytes = fs::read(&self.path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        browser_storage()
            .and_then(|storage| storage.get_item(LOCAL_STATE_STORAGE_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(state)?)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(LOCAL_STATE_STORAGE_KEY, &serde_json::to_string(state)?)
            .map_err(|error| anyhow::anyhow!("localStorage write failed: {error:?}"))?;
        Ok(())
    }

    fn ensure_cached_loaded(&mut self) {
        if self.cached == ClientLocalState::default() {
            if let Some(state) = self.read_persisted_state() {
                self.cached = state;
            }
        }
    }
}

fn read_marker_key(space_id: &str, topic_id: Option<&str>) -> String {
    let topic = topic_id
        .map(str::trim)
        .filter(|topic| !topic.is_empty())
        .unwrap_or("-");
    format!("{space_id}\n{topic}")
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_state_path() -> PathBuf {
    std::env::var_os("CLIENTX_STATE_PATH")
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
    if hex.len() % 2 != 0 {
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
    let json = serde_json::to_string(record).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize identity record: {error}"
        ))
    })?;
    secure_store.store_secret(LocalStateStore::SECURE_IDENTITY_KEY, &json)
}

fn plaintext_identity_seed_fallback_allowed() -> bool {
    cfg!(test)
        || std::env::var("YOUGEN_ALLOW_PLAINTEXT_IDENTITY_SEED")
            .ok()
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key_store::SecureKeyStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn move_submission_state_maps_pending_anchor_and_effective() {
        assert_eq!(
            MoveSubmissionState::from_submit_state("pending", None),
            MoveSubmissionState::PendingAnchor
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("pending_anchor", None),
            MoveSubmissionState::PendingAnchor
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("effective", None),
            MoveSubmissionState::Effective
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("anchored", None),
            MoveSubmissionState::Effective
        );
    }

    #[test]
    fn move_submission_state_maps_failure_reasons() {
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("anchorer_paused: recovery anchorer not signed")
            ),
            MoveSubmissionState::AnchorerPaused
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("anchor_signature_invalid for batch")
            ),
            MoveSubmissionState::RejectedAnchor
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state(
                "rejected",
                Some("bottom: cell has concurrent candidates")
            ),
            MoveSubmissionState::FailedBottom
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("rejected", Some("covered_frontier mismatch")),
            MoveSubmissionState::PendingMlsBinding
        );
        assert_eq!(
            MoveSubmissionState::from_submit_state("rejected", Some("if_state did not match")),
            MoveSubmissionState::FailedPrecondition
        );
    }

    #[test]
    fn move_submission_record_round_trips_through_store() {
        let path = temp_state_path("move-submission");
        let mut store = LocalStateStore::with_path(path.clone());
        let space = "cx:space:0196419b-0000-7000-8000-000000000001";
        let mid = "sha256:111";
        store.record_move_submission(
            mid,
            space,
            "cx.consent.grant",
            MoveSubmissionState::PendingAnchor,
            None,
            Some("cx:anchor:sha256:abc".to_owned()),
        );
        let listed = store.move_submissions_for_space(space);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].move_id, mid);
        assert_eq!(listed[0].state, MoveSubmissionState::PendingAnchor);
        assert!(!store.space_has_paused_anchorer(space));

        // Update to AnchorerPaused — Space should now flag the banner.
        assert!(store.update_move_submission_state(
            mid,
            MoveSubmissionState::AnchorerPaused,
            Some("recovery anchorer not signed".to_owned()),
        ));
        assert!(store.space_has_paused_anchorer(space));
        let listed = store.move_submissions_for_space(space);
        assert_eq!(listed[0].state, MoveSubmissionState::AnchorerPaused);
        assert_eq!(
            listed[0].reason.as_deref(),
            Some("recovery anchorer not signed")
        );

        // Persistence: a fresh reader sees the same state.
        let reader = LocalStateStore::with_path(path);
        assert!(reader.space_has_paused_anchorer(space));

        // Drop it and the banner clears.
        let mut store = LocalStateStore::with_path(reader.path.clone());
        store.drop_move_submission(mid);
        assert!(!store.space_has_paused_anchorer(space));
    }

    #[test]
    fn move_submission_pending_mls_binding_drives_toast() {
        let path = temp_state_path("move-mls-binding");
        let mut store = LocalStateStore::with_path(path);
        let space = "cx:space:0196419b-0000-7000-8000-000000000002";
        store.record_move_submission(
            "sha256:222",
            space,
            "cx.message.create",
            MoveSubmissionState::PendingMlsBinding,
            Some("covered_frontier missing".to_owned()),
            None,
        );
        assert!(store.space_has_pending_mls_binding(space));
        assert!(!store.space_has_paused_anchorer(space));
    }

    #[test]
    fn move_submission_state_label_and_badge_class_distinct_per_state() {
        for state in [
            MoveSubmissionState::PendingAnchor,
            MoveSubmissionState::Effective,
            MoveSubmissionState::FailedPrecondition,
            MoveSubmissionState::FailedBottom,
            MoveSubmissionState::RejectedAnchor,
            MoveSubmissionState::AnchorerPaused,
            MoveSubmissionState::PendingMlsBinding,
        ] {
            assert!(!state.slug().is_empty());
            assert!(!state.label_zh().is_empty());
            assert!(state.badge_class().starts_with("badge"));
        }
        assert!(MoveSubmissionState::AnchorerPaused.is_failed());
        assert!(!MoveSubmissionState::PendingAnchor.is_failed());
        assert!(!MoveSubmissionState::Effective.is_failed());
    }

    #[test]
    fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
        let path = temp_state_path("tracks");
        let mut store = LocalStateStore::with_path(path);
        store.save_sync_cursor("sx:next");
        store.append_raw_operation(
            "cx:operation:local-01",
            Some("cx:space:demo".to_owned()),
            serde_json::json!({"type": "cx.message.create"}),
        );
        store.save_space_projection("cx:space:demo", serde_json::json!({"name": "Demo"}));
        store.save_draft("cx:space:demo", "hello");

        let state = store.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
        assert_eq!(
            state.raw_operations[0].operation_id,
            "cx:operation:local-01"
        );
        assert_eq!(state.space_projections["cx:space:demo"]["name"], "Demo");
        assert_eq!(store.draft_for("cx:space:demo"), "hello");

        store.save_draft("cx:space:demo", " ");
        assert!(store.draft_for("cx:space:demo").is_empty());
    }

    #[test]
    fn local_state_store_persists_to_disk_between_instances() {
        let path = temp_state_path("persisted");
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.save_sync_cursor("sx:persisted");
        writer.save_draft("cx:space:persisted", "draft survives restart");

        let reader = LocalStateStore::with_path(path);
        let state = reader.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:persisted"));
        assert_eq!(state.drafts["cx:space:persisted"], "draft survives restart");
    }

    #[test]
    fn local_state_store_persists_notifications_and_mute_preferences() {
        let path = temp_state_path("notifications");
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_notification_projection(vec![serde_json::json!({
            "notification_id": "notif-1",
            "space_id": "cx:space:demo",
            "kind": "message",
            "body": "Hello"
        })]);
        store.set_notification_read("notif-1", true);
        store.set_notification_archived("notif-1", true);
        store.set_space_muted("cx:space:demo", true);
        store.set_notification_kind_enabled("message", false);

        let reader = LocalStateStore::with_path(path);
        assert_eq!(reader.notification_projection().len(), 1);
        assert!(reader.notification_state_for("notif-1").read);
        assert!(reader.notification_state_for("notif-1").archived);
        assert!(reader.is_space_muted("cx:space:demo"));
        assert!(!reader.notification_kind_enabled("message"));
    }

    #[test]
    fn local_state_store_persists_private_read_markers() {
        let path = temp_state_path("read-marker");
        let mut store = LocalStateStore::with_path(path.clone());
        let marker = store.save_read_marker(
            "did:web:alice.example",
            "device-1",
            "cx:space:demo",
            None,
            "cx:event:read-1",
        );

        assert_eq!(marker.marker_type, "cx.marker.read");
        assert_eq!(marker.body.space_id, "cx:space:demo");
        assert_eq!(marker.body.event_id, "cx:event:read-1");
        assert_eq!(
            marker.cx_marker_read_operation(),
            serde_json::json!({
                "type": "cx.marker.read",
                "body": {
                    "space_id": "cx:space:demo",
                    "event_id": "cx:event:read-1",
                },
            })
        );

        let reader = LocalStateStore::with_path(path);
        let persisted = reader
            .read_marker_for("cx:space:demo", None)
            .expect("read marker persisted");
        assert_eq!(persisted.actor, "did:web:alice.example");
        assert_eq!(persisted.device_id, "device-1");
        assert_eq!(persisted.body.event_id, "cx:event:read-1");
    }

    #[test]
    fn local_state_store_keeps_thread_read_markers_separate() {
        let path = temp_state_path("thread-read-marker");
        let mut store = LocalStateStore::with_path(path);
        store.save_read_marker(
            "did:web:alice.example",
            "desktop",
            "cx:space:demo",
            None,
            "cx:event:topic",
        );
        store.save_read_marker(
            "did:web:alice.example",
            "desktop",
            "cx:space:demo",
            Some("cx:thread:reply-1".to_owned()),
            "cx:event:thread",
        );

        assert_eq!(
            store
                .read_marker_for("cx:space:demo", None)
                .expect("topic marker")
                .body
                .event_id,
            "cx:event:topic"
        );
        assert_eq!(
            store
                .read_marker_for("cx:space:demo", Some("cx:thread:reply-1"))
                .expect("thread marker")
                .body
                .event_id,
            "cx:event:thread"
        );
    }

    #[test]
    fn local_state_store_persists_push_registration_state() {
        let path = temp_state_path("push-registration");
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_push_registration(PushRegistrationState {
            schema_version: chime::PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
            principal_did: None,
            registration_id: Some("cx:push:local".to_owned()),
            device_id: "dev_yougen".to_owned(),
            platform: Some("desktop".to_owned()),
            app_id: Some("yougen".to_owned()),
            push_gateway: "https://push.example/api/v1/push/notify".to_owned(),
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
        assert_eq!(state.registration_id.as_deref(), Some("cx:push:local"));
        assert_eq!(state.device_id, "dev_yougen");

        reader.clear_push_registration();
        assert!(reader.push_registration().is_none());
    }

    /// `set_oidc_tokens_with_secure_store`
    /// MUST move the `refresh_token` out of the disk-backed
    /// `state.json` into the supplied `SecureKeyStore` keyed by
    /// `coauth.refresh_token.<actor_did>`. The companion `load_*`
    /// helper reads it back. The on-disk JSON MUST NOT contain the
    /// refresh_token after the migration.
    #[test]
    fn refresh_token_migrates_into_secure_key_store_and_round_trips() {
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
        // Post-migration: in-state bundle MUST NOT carry the refresh
        // token any more (the secure store is the new authority).
        assert!(stripped.refresh_token.is_none());

        // The disk-backed bundle agrees.
        let on_disk = store.oidc_tokens().expect("bundle still on disk");
        assert!(on_disk.refresh_token.is_none());
        assert_eq!(on_disk.access_token, "atok");

        // Secure store holds the secret under the per-actor key.
        let secret = secure
            .get_secret(&format!("coauth.refresh_token.{actor}"))
            .expect("read ok")
            .expect("secret present");
        assert_eq!(secret, "rtok-secret");

        // Load helper reattaches the refresh_token from the store.
        let reattached = store
            .load_oidc_tokens_with_secure_store(actor, &secure)
            .expect("bundle visible");
        assert_eq!(reattached.refresh_token.as_deref(), Some("rtok-secret"));
        assert_eq!(reattached.access_token, "atok");

        // Clearing the bundle deletes the secure-store entry too.
        store.set_oidc_tokens_with_secure_store(None, actor, &secure);
        assert!(
            secure
                .get_secret(&format!("coauth.refresh_token.{actor}"))
                .expect("read ok after clear")
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

    #[test]
    fn retain_space_projections_prunes_per_space_caches() {
        let path = temp_state_path("retain-prunes");
        let mut store = LocalStateStore::with_path(path);
        // Seed three spaces with overlapping per-space caches.
        for id in ["cx:space:keep", "cx:space:drop-a", "cx:space:drop-b"] {
            store.save_space_projection(id, serde_json::json!({"name": id}));
            store.save_draft(id, "draft");
            store.set_anchor_view(id, LocalAnchorView::default());
            store.set_space_muted(id, true);
        }
        // Independently keyed records that should follow the prune.
        store.save_read_marker(
            "did:web:tester.example",
            "device-1",
            "cx:space:drop-a",
            None,
            "cx:event:42",
        );
        store.save_read_marker(
            "did:web:tester.example",
            "device-1",
            "cx:space:keep",
            None,
            "cx:event:99",
        );

        let pruned = store.retain_space_projections(|id| id == "cx:space:keep");
        assert_eq!(pruned.len(), 2);
        assert!(pruned.contains(&"cx:space:drop-a".to_owned()));
        assert!(pruned.contains(&"cx:space:drop-b".to_owned()));

        let state = store.load();
        assert_eq!(state.space_projections.len(), 1);
        assert!(state.space_projections.contains_key("cx:space:keep"));
        assert!(!state.drafts.contains_key("cx:space:drop-a"));
        assert!(state.drafts.contains_key("cx:space:keep"));
        assert!(!state.anchor_views.contains_key("cx:space:drop-a"));
        assert!(state.anchor_views.contains_key("cx:space:keep"));
        assert!(!state.muted_spaces.contains_key("cx:space:drop-b"));
        assert!(state.muted_spaces.contains_key("cx:space:keep"));
        let kept_marker_keys: Vec<&str> = state.read_markers.keys().map(String::as_str).collect();
        assert!(
            kept_marker_keys
                .iter()
                .any(|k| k.starts_with("cx:space:keep\n")),
            "kept space marker should survive prune: {kept_marker_keys:?}",
        );
        assert!(
            kept_marker_keys
                .iter()
                .all(|k| !k.starts_with("cx:space:drop-a\n")),
            "pruned space marker should be gone: {kept_marker_keys:?}",
        );
    }

    #[test]
    fn retain_space_projections_keeps_everything_when_all_match() {
        let path = temp_state_path("retain-all");
        let mut store = LocalStateStore::with_path(path);
        store.save_space_projection("cx:space:a", serde_json::json!({}));
        store.save_space_projection("cx:space:b", serde_json::json!({}));
        let pruned = store.retain_space_projections(|_| true);
        assert!(pruned.is_empty());
        assert_eq!(store.load().space_projections.len(), 2);
    }

    #[test]
    fn forget_space_clears_a_single_space() {
        let path = temp_state_path("forget-one");
        let mut store = LocalStateStore::with_path(path);
        for id in ["cx:space:gone", "cx:space:stay"] {
            store.save_space_projection(id, serde_json::json!({}));
            store.save_draft(id, "draft");
            store.set_anchor_view(id, LocalAnchorView::default());
        }

        store.forget_space("cx:space:gone");

        let state = store.load();
        assert!(!state.space_projections.contains_key("cx:space:gone"));
        assert!(state.space_projections.contains_key("cx:space:stay"));
        assert!(!state.drafts.contains_key("cx:space:gone"));
        assert!(state.drafts.contains_key("cx:space:stay"));
    }

    #[test]
    fn clear_account_scoped_preserves_device_level_and_token_state() {
        let path = temp_state_path("clear-account");
        let mut store = LocalStateStore::with_path(path);
        // Account-scoped projections.
        store.save_sync_cursor("sx:before");
        store.save_space_projection("cx:space:a", serde_json::json!({}));
        store.save_draft("cx:space:a", "draft");
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
            state.space_projections.is_empty(),
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
            identity.device_did,
        );
        assert!(
            state.oidc_tokens.is_some(),
            "OIDC tokens must survive — login flow owns them",
        );
        assert_eq!(
            state.oidc_tokens.as_ref().unwrap().access_token,
            bundle.access_token,
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
        assert!(store.read_receipt_should_send(None, Some("cx:space:any")));

        store.set_read_receipt_default_send(false);
        let reader = LocalStateStore::with_path(path);
        assert!(!reader.read_receipt_default_send());
        assert!(!reader.read_receipt_should_send(None, Some("cx:space:any")));
    }

    #[test]
    fn read_receipt_resolution_flow_overrides_space_overrides_default() {
        let path = temp_state_path("read-receipt-resolve");
        let mut store = LocalStateStore::with_path(path.clone());
        // default = true (send)
        store.set_read_receipt_space_override("cx:space:demo", Some(false));
        store.set_read_receipt_flow_override("cx:flow:demo", Some(true));

        let reader = LocalStateStore::with_path(path);
        // Flow override wins.
        assert!(reader.read_receipt_should_send(Some("cx:flow:demo"), Some("cx:space:demo")));
        // Space override wins over default when no flow override.
        assert!(!reader.read_receipt_should_send(None, Some("cx:space:demo")));
        // Default applies when nothing matches.
        assert!(reader.read_receipt_should_send(None, Some("cx:space:other")));
    }

    #[test]
    fn read_receipt_clearing_override_falls_back_to_default() {
        let path = temp_state_path("read-receipt-clear");
        let mut store = LocalStateStore::with_path(path);
        store.set_read_receipt_space_override("cx:space:demo", Some(false));
        assert!(!store.read_receipt_should_send(None, Some("cx:space:demo")));

        store.set_read_receipt_space_override("cx:space:demo", None);
        assert!(store.read_receipt_should_send(None, Some("cx:space:demo")));
        assert!(store.read_receipt_space_override("cx:space:demo").is_none());
    }

    #[test]
    fn server_policy_required_locks_user_choice_to_send() {
        let path = temp_state_path("read-receipt-policy-required");
        let mut store = LocalStateStore::with_path(path);
        // User opted out of the Space.
        store.set_read_receipt_space_override("cx:space:demo", Some(false));
        // But server publishes disclosure=required → must override to true.
        store.set_read_receipt_policy_snapshot(
            "cx:space:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "required".to_owned(),
                visibility: Some("public".to_owned()),
            }),
        );
        assert!(store.read_receipt_should_send(None, Some("cx:space:demo")));
        let snap = store
            .read_receipt_policy_for_space("cx:space:demo")
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
            "cx:space:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "disabled".to_owned(),
                visibility: Some("private".to_owned()),
            }),
        );
        assert!(!store.read_receipt_should_send(None, Some("cx:space:demo")));
    }

    #[test]
    fn server_policy_optional_does_not_lock() {
        let path = temp_state_path("read-receipt-policy-optional");
        let mut store = LocalStateStore::with_path(path);
        store.set_read_receipt_space_override("cx:space:demo", Some(false));
        store.set_read_receipt_policy_snapshot(
            "cx:space:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "optional".to_owned(),
                visibility: None,
            }),
        );
        // optional → user override wins.
        assert!(!store.read_receipt_should_send(None, Some("cx:space:demo")));
        let snap = store
            .read_receipt_policy_for_space("cx:space:demo")
            .unwrap();
        assert!(!snap.locks_user_choice());
        assert_eq!(snap.lock_reason(), "");
    }

    #[test]
    fn anchor_view_default_returns_empty_bytes_sentinel() {
        let path = temp_state_path("anchor-default");
        let store = LocalStateStore::with_path(path);
        let view = store.anchor_view_for("cx:space:demo");
        assert!(view.frontier.is_empty());
        assert!(view.leaves.is_empty());
        assert!(view.state_root.is_none());
        assert_eq!(view.move_anchor_ref(), LocalAnchorView::EMPTY_ANCHOR_REF);
        assert_eq!(
            store.anchor_ref_for_move("cx:space:demo"),
            LocalAnchorView::EMPTY_ANCHOR_REF
        );
    }

    #[test]
    fn anchor_view_set_persists_and_picks_lex_min_frontier() {
        let path = temp_state_path("anchor-set");
        {
            let mut store = LocalStateStore::with_path(path.clone());
            store.set_anchor_view(
                "cx:space:demo",
                LocalAnchorView {
                    frontier: vec![
                        "cx:anchor:sha256:bbb".to_owned(),
                        "cx:anchor:sha256:aaa".to_owned(),
                    ],
                    leaves: vec!["sha256:lf1".to_owned()],
                    state_root: Some("cx:state:sha256:abc".to_owned()),
                    bottom_cells: BTreeMap::new(),
                    mls_epoch: None,
                    covered_frontier: None,
                    covered_frontier_lag: None,
                    key_schedule_hash: None,
                },
            );
        }
        let reader = LocalStateStore::with_path(path);
        let view = reader.anchor_view_for("cx:space:demo");
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves.len(), 1);
        assert_eq!(view.state_root.as_deref(), Some("cx:state:sha256:abc"));
        assert_eq!(view.move_anchor_ref(), "cx:anchor:sha256:aaa");
        assert_eq!(
            reader.anchor_ref_for_move("cx:space:demo"),
            "cx:anchor:sha256:aaa"
        );
    }

    #[test]
    fn anchor_view_bottom_cells_signal_conflict() {
        let mut view = LocalAnchorView::default();
        assert!(!view.has_bottom_cells());
        view.bottom_cells.insert(
            "cx:cell:cx.component.member.state.v1:did:web:alice".to_owned(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![],
            },
        );
        assert!(view.has_bottom_cells());
    }

    #[test]
    fn safer_winner_for_member_state_prefers_ban_over_join() {
        let mut view = LocalAnchorView::default();
        let cell = "cx:cell:cx.component.member.state.v1:did:web:alice".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "cx:event:joined".to_owned(),
                        value: serde_json::json!({"membership": "join"}),
                    },
                    BottomCellHead {
                        move_id: "cx:event:banned".to_owned(),
                        value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                    },
                ],
            },
        );
        let (head_a, head_b, winner) = view.safer_winner_for(&cell).expect("ban beats join");
        assert_eq!(head_a, "cx:event:joined");
        assert_eq!(head_b, "cx:event:banned");
        assert_eq!(
            winner.get("membership").and_then(|v| v.as_str()),
            Some("ban")
        );
    }

    #[test]
    fn safer_winner_for_capability_grant_prefers_revoked_over_active() {
        let mut view = LocalAnchorView::default();
        let cell = "cx:cell:cx.component.capability.grant.v1:cx.grant.01".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "cx:event:granted".to_owned(),
                        value: serde_json::json!({"status": "active"}),
                    },
                    BottomCellHead {
                        move_id: "cx:event:revoked".to_owned(),
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
        let mut view = LocalAnchorView::default();
        let cell = "cx:cell:cx.component.space.organization.v1:cx:space:demo".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "cx:event:a".to_owned(),
                        value: serde_json::json!({"title": "alpha"}),
                    },
                    BottomCellHead {
                        move_id: "cx:event:b".to_owned(),
                        value: serde_json::json!({"title": "beta"}),
                    },
                ],
            },
        );
        // No semantic safety ordering for space.organization — operator
        // must pick manually.
        assert!(view.safer_winner_for(&cell).is_none());
    }

    #[test]
    fn safer_winner_for_tied_heads_returns_none() {
        let mut view = LocalAnchorView::default();
        let cell = "cx:cell:cx.component.member.state.v1:did:web:alice".to_owned();
        view.bottom_cells.insert(
            cell.clone(),
            BottomCellInfo {
                status: "expose".to_owned(),
                heads: vec![
                    BottomCellHead {
                        move_id: "cx:event:ban-a".to_owned(),
                        value: serde_json::json!({"membership": "ban", "reason": "spam"}),
                    },
                    BottomCellHead {
                        move_id: "cx:event:ban-b".to_owned(),
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
        let mut view = LocalAnchorView::default();
        let cell = "cx:cell:cx.component.member.state.v1:did:web:alice".to_owned();
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
    fn anchor_view_from_sync_body_parses_full_payload() {
        let body = serde_json::json!({
            "anchor_view": {
                "frontier": ["cx:anchor:sha256:aaa", "cx:anchor:sha256:bbb"],
                "leaves":   ["sha256:lf1"],
                "state_root": "cx:state:sha256:abc",
                "cells": {
                    "cx:cell:cx.component.member.state.v1:did:web:alice": {
                        "bottom": "expose",
                        "heads": [
                            {
                                "move_id": "cx:event:joined",
                                "value": {"membership": "join"}
                            },
                            {
                                "move_id": "cx:event:banned",
                                "value": {"membership": "ban", "reason": "abuse"}
                            }
                        ]
                    },
                    "cx:cell:cx.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
                }
            }
        });
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
        assert_eq!(view.state_root.as_deref(), Some("cx:state:sha256:abc"));
        // Only `bottom=expose` cells are surfaced — `reject` cells stay
        // out of the conflict map.
        assert_eq!(view.bottom_cells.len(), 1);
        let info = view
            .bottom_cells
            .get("cx:cell:cx.component.member.state.v1:did:web:alice")
            .expect("expose cell present");
        assert_eq!(info.status, "expose");
        assert_eq!(info.heads.len(), 2);
        assert_eq!(info.heads[0].move_id, "cx:event:joined");
        assert_eq!(
            info.heads[1]
                .value
                .get("membership")
                .and_then(|v| v.as_str()),
            Some("ban")
        );
    }

    #[test]
    fn anchor_view_from_sync_body_extracts_mls_epoch_and_covered_frontier() {
        let body = serde_json::json!({
            "anchor_view": {
                "frontier": ["cx:anchor:sha256:aaa"],
                "leaves": [],
                "cells": {
                    "cx:cell:cx.component.mls.epoch.v1:cx:space:demo": {
                        "value": 7
                    },
                    "cx:cell:cx.component.governance.covered_frontier.v1:cx:space:demo": {
                        "register": { "value": "cx:state:sha256:abcd" }
                    }
                }
            }
        });
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(7));
        assert_eq!(
            view.covered_frontier.as_deref(),
            Some("cx:state:sha256:abcd")
        );
    }

    #[test]
    fn anchor_view_mls_epoch_supports_object_value_with_epoch_field() {
        // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
        // (typed view) instead of a bare integer. Both shapes need to round-trip.
        let body = serde_json::json!({
            "anchor_view": {
                "frontier": [],
                "cells": {
                    "cx:cell:cx.component.mls.epoch.v1:cx:space:demo": {
                        "value": { "epoch": 42, "members": 3 }
                    }
                }
            }
        });
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(42));
    }

    #[test]
    fn anchor_view_from_sync_body_extracts_covered_frontier_lag() {
        let body = serde_json::json!({
            "anchor_view": {
                "frontier": ["cx:anchor:sha256:aaa"],
                "leaves": [],
                "covered_frontier_lag": 12,
                "cells": {}
            }
        });
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view.covered_frontier_lag, Some(12));
        // default threshold is 5 -> 12 > 5
        assert!(view.covered_frontier_lag_above(5));
        assert!(!view.covered_frontier_lag_above(20));
    }

    #[test]
    fn anchor_view_lag_above_returns_false_when_lag_unknown() {
        let view = LocalAnchorView::default();
        assert!(!view.covered_frontier_lag_above(5));
        assert!(!view.covered_frontier_lag_above(0));
    }

    #[test]
    fn anchor_view_from_sync_body_missing_returns_default() {
        let body = serde_json::json!({"summary": {"summary": "hi"}});
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view, LocalAnchorView::default());
    }

    #[test]
    fn anchor_views_aggregates_across_spaces() {
        let path = temp_state_path("anchor-aggregate");
        let mut store = LocalStateStore::with_path(path);
        store.set_anchor_view(
            "cx:space:one",
            LocalAnchorView {
                frontier: vec!["cx:anchor:sha256:one".to_owned()],
                ..LocalAnchorView::default()
            },
        );
        store.set_anchor_view(
            "cx:space:two",
            LocalAnchorView {
                frontier: vec!["cx:anchor:sha256:two".to_owned()],
                ..LocalAnchorView::default()
            },
        );
        let all = store.anchor_views();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("cx:space:one"));
        assert!(all.contains_key("cx:space:two"));
    }

    #[test]
    fn ensure_local_identity_generates_persists_and_round_trips() {
        let path = temp_state_path("local-identity");
        let id = {
            let mut store = LocalStateStore::with_path(path.clone());
            assert!(store.local_identity_record().is_none());
            assert!(store.local_identity().is_none());
            let id = store.ensure_local_identity().expect("first generate");
            assert!(id.device_did.starts_with("did:key:z"));
            // Idempotent on the same store instance.
            let again = store.ensure_local_identity().expect("idempotent");
            assert_eq!(id, again);
            id
        };
        // Round-trip across store instances.
        let reader = LocalStateStore::with_path(path);
        let loaded = reader.local_identity().expect("persisted identity loads");
        assert_eq!(loaded.device_did, id.device_did);
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
        assert_eq!(record.did_key, id.device_did);
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
        assert_eq!(migrated.device_did, existing.device_did);
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
        assert_ne!(one.device_did, two.device_did);
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
        assert_ne!(regenerated.device_did, "did:key:zTAMPERED");
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
                "cx:space:demo",
                Some(ReadReceiptPolicySnapshot {
                    disclosure: "required".to_owned(),
                    visibility: Some("track_scoped".to_owned()),
                }),
            );
        }
        let reader = LocalStateStore::with_path(path);
        let snap = reader
            .read_receipt_policy_for_space("cx:space:demo")
            .unwrap();
        assert_eq!(snap.disclosure, "required");
        assert_eq!(snap.visibility.as_deref(), Some("track_scoped"));
    }

    #[test]
    fn mls_snapshot_persists_and_round_trips_through_store() {
        // MLS snapshot envelope is durable across store instances and the
        // boot path can rehydrate every space's group from the persisted
        // record.
        use crate::mls_persistence::encrypt_state;
        let path = temp_state_path("mls-snapshot-persist");
        let space = "cx:space:round28-mls";
        let envelope = encrypt_state(
            space,
            "deadbeef",
            5,
            b"placeholder-state-bytes",
            "round28-pass",
            b"deterministic-salt",
        );
        {
            let mut writer = LocalStateStore::with_path(path.clone());
            assert!(writer.mls_snapshot_for(space).is_none());
            writer.save_mls_snapshot(space, envelope.clone());
        }
        let reader = LocalStateStore::with_path(path);
        let restored = reader.mls_snapshot_for(space).expect("envelope persists");
        assert_eq!(restored.space_id, envelope.space_id);
        assert_eq!(restored.epoch, 5);
        assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
        assert_eq!(reader.mls_snapshots().len(), 1);
    }

    #[test]
    fn mls_snapshot_drop_clears_persisted_record() {
        use crate::mls_persistence::encrypt_state;
        let path = temp_state_path("mls-snapshot-drop");
        let mut store = LocalStateStore::with_path(path);
        let space = "cx:space:drop-me";
        store.save_mls_snapshot(space, encrypt_state(space, "abcd", 1, b"x", "p", b"salt"));
        assert!(store.mls_snapshot_for(space).is_some());
        store.drop_mls_snapshot(space);
        assert!(store.mls_snapshot_for(space).is_none());
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
        use crate::telemetry::{UserActionOutcome, build_user_action_entry};
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

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
        let api = crate::api::ContrixApi::new(&base).unwrap();
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

    // ── Space remarks (spec client-preferences.md §3.7) ─

    #[test]
    fn space_remark_set_and_display_name_prefers_local_name() {
        let path = temp_state_path("space-remark-set");
        let mut store = LocalStateStore::with_path(path);
        let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
        assert!(store.space_remark(space_id).is_none());
        assert_eq!(
            store.display_name_for_space(space_id, "Engineering"),
            "Engineering",
            "no remark → public title"
        );

        let remark = crate::account_data::SpaceRemark::new(space_id, "Acme · Eng");
        store.set_space_remark(space_id, remark);
        assert_eq!(
            store.display_name_for_space(space_id, "Engineering"),
            "Acme · Eng",
            "remark → local_name"
        );
        assert!(store.space_remarks().contains_key(space_id));
    }

    #[test]
    fn space_remark_empty_value_tombstones_entry() {
        let path = temp_state_path("space-remark-tombstone");
        let mut store = LocalStateStore::with_path(path);
        let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
        store.set_space_remark(
            space_id,
            crate::account_data::SpaceRemark::new(space_id, "x"),
        );
        assert!(store.space_remark(space_id).is_some());

        // Whitespace-only local_name is treated as tombstone — see
        // SpaceRemark::is_empty.
        store.set_space_remark(
            space_id,
            crate::account_data::SpaceRemark {
                local_name: "   ".into(),
                ..crate::account_data::SpaceRemark::default()
            },
        );
        assert!(
            store.space_remark(space_id).is_none(),
            "empty remark must remove the entry"
        );
    }

    #[test]
    fn space_remark_remove_clears_only_target_space() {
        let path = temp_state_path("space-remark-remove");
        let mut store = LocalStateStore::with_path(path);
        let a = "cx:space:00000000-0000-7000-8000-000000000001";
        let b = "cx:space:00000000-0000-7000-8000-000000000002";
        store.set_space_remark(a, crate::account_data::SpaceRemark::new(a, "A"));
        store.set_space_remark(b, crate::account_data::SpaceRemark::new(b, "B"));

        store.remove_space_remark(a);
        assert!(store.space_remark(a).is_none());
        assert_eq!(
            store.space_remark(b).map(|r| r.local_name),
            Some("B".to_owned()),
            "removing one Space remark must not touch the other"
        );
    }

    #[test]
    fn space_remark_persists_to_disk_between_instances() {
        let path = temp_state_path("space-remark-persist");
        let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
        {
            let mut writer = LocalStateStore::with_path(path.clone());
            writer.set_space_remark(
                space_id,
                crate::account_data::SpaceRemark::new(space_id, "Acme · Eng"),
            );
        }
        let reader = LocalStateStore::with_path(path);
        assert_eq!(
            reader.display_name_for_space(space_id, "Engineering"),
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
                actor_did: did.to_owned(),
                ..crate::account_data::ContactRemark::default()
            },
        );
        assert!(store.contact_remark(did).is_none());
    }
}
