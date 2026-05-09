use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use contrix_sdk::EncryptedPayload;
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

/// Snapshot of the latest Anchor view observed for a Space. Surfaced from
/// the `/sync` Anchor view (P0 M3) and threaded into Move submissions so
/// every cell-driven write references the right frontier instead of the
/// `sha256(empty)` placeholder used during Round 18.
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
    /// Cell map snapshot: cell ref → bottom status string. Populated when
    /// the projection contains a `bottom=expose` cell so the UI can
    /// surface a "concurrent candidates unresolved" banner. Other cells
    /// are omitted to keep this struct compact.
    #[serde(default)]
    pub bottom_cells: BTreeMap<String, String>,
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

    /// Best-effort extraction of an Anchor view from a per-Space `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "anchor_view": {
    ///     "frontier": ["cx:anchor:sha256:..."],
    ///     "leaves":   ["cx:move:sha256:..."],
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
        if let Some(cells) = anchor.get("cells").and_then(|v| v.as_object()) {
            for (cell_ref, status) in cells {
                let bottom = status.get("bottom").and_then(|v| v.as_str());
                if let Some(b) = bottom
                    && b == "expose"
                {
                    view.bottom_cells.insert(cell_ref.clone(), b.to_owned());
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
    /// Encrypted private account data (preferences, tags, custom emojis).
    /// Values are XOR-encrypted with account_key and hex-encoded.
    #[serde(default)]
    pub private_data: BTreeMap<String, String>,
    /// Private cx.marker.read cursors keyed by space + topic/thread scope.
    #[serde(default)]
    pub read_markers: BTreeMap<String, ReadMarkerRecord>,
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
            private_data: BTreeMap::new(),
            read_markers: BTreeMap::new(),
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
        self.load().read_receipt_space_overrides.get(space_id).copied()
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
                self.cached.read_receipt_space_overrides.insert(space_id, value);
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
        self.load().read_receipt_flow_overrides.get(flow_id).copied()
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
                self.cached.read_receipt_flow_overrides.insert(flow_id, value);
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
                self.cached
                    .read_receipt_policy_snapshots
                    .remove(&space_id);
            }
        }
        let _ = self.flush();
    }

    /// All known server-declared read-receipt policy snapshots.
    pub fn read_receipt_policy_snapshots(
        &self,
    ) -> BTreeMap<String, ReadReceiptPolicySnapshot> {
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
    pub fn set_anchor_view(
        &mut self,
        space_id: impl Into<String>,
        view: LocalAnchorView,
    ) {
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
    pub fn read_receipt_should_send(
        &self,
        flow_id: Option<&str>,
        space_id: Option<&str>,
    ) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
        let path = temp_state_path("tracks");
        let mut store = LocalStateStore::with_path(path);
        store.save_sync_cursor("sx:next");
        store.append_raw_operation(
            "cx:operation:local-01",
            Some("cx:space:demo".to_owned()),
            serde_json::json!({"type": "cx.message.send"}),
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

    fn temp_state_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("yougen-state-{name}-{stamp}.json"))
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
        let snap = store.read_receipt_policy_for_space("cx:space:demo").unwrap();
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
        let snap = store.read_receipt_policy_for_space("cx:space:demo").unwrap();
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
        assert_eq!(
            view.move_anchor_ref(),
            LocalAnchorView::EMPTY_ANCHOR_REF
        );
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
                    leaves: vec!["cx:move:sha256:lf1".to_owned()],
                    state_root: Some("cx:state:sha256:abc".to_owned()),
                    bottom_cells: BTreeMap::new(),
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
            "expose".to_owned(),
        );
        assert!(view.has_bottom_cells());
    }

    #[test]
    fn anchor_view_from_sync_body_parses_full_payload() {
        let body = serde_json::json!({
            "anchor_view": {
                "frontier": ["cx:anchor:sha256:aaa", "cx:anchor:sha256:bbb"],
                "leaves":   ["cx:move:sha256:lf1"],
                "state_root": "cx:state:sha256:abc",
                "cells": {
                    "cx:cell:cx.component.member.state.v1:did:web:alice": { "bottom": "expose" },
                    "cx:cell:cx.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
                }
            }
        });
        let view = LocalAnchorView::from_sync_body(&body);
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves, vec!["cx:move:sha256:lf1".to_owned()]);
        assert_eq!(view.state_root.as_deref(), Some("cx:state:sha256:abc"));
        // Only `bottom=expose` cells are surfaced — `reject` cells stay
        // out of the conflict map.
        assert_eq!(view.bottom_cells.len(), 1);
        assert!(
            view.bottom_cells
                .contains_key("cx:cell:cx.component.member.state.v1:did:web:alice")
        );
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
        let snap = reader.read_receipt_policy_for_space("cx:space:demo").unwrap();
        assert_eq!(snap.disclosure, "required");
        assert_eq!(snap.visibility.as_deref(), Some("track_scoped"));
    }
}
