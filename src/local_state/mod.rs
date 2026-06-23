use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use cokret_sdk::EncryptedPayload;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

// Structural split: client-state data types (RawOperationRecord,
// ClientLocalState, MlsReceiveOverlay, the persisted-record structs, ...)
// moved out of this file into `types` (move only). The glob re-export keeps
// the `crate::local_state::*` public paths and the `impl LocalStateStore` /
// tests `use super::*` resolution unchanged.
mod types;
pub use types::*;

mod seal_view;
pub use seal_view::*;

mod mls_sidecar;

mod move_tracking;

// YOU-07-001: storage / path / at-rest-crypto utility free functions moved out
// of this file into `storage_util` (move only). The glob re-export keeps the
// parent `impl LocalStateStore` call sites and `local_state_tests.rs`
// `use super::*` resolution unchanged.
mod storage_util;
pub(crate) use storage_util::*;

// Structural split: the giant `impl LocalStateStore` was carved by theme
// into sibling child modules. Each holds one `impl LocalStateStore` block
// (an inherent impl may span files) and opens with `use super::*;` so it
// sees this module's items (private parent items are visible to child
// modules, so no visibility widening is needed).
mod identity_session;
mod member_identity;
mod notifications_cursors;
mod realm_tree_snapshot;
mod remarks_blocklist;
mod scope;
mod to_device_raw;

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
    /// write-back" critical section. Multiple views (chat / kanban) can
    /// trigger decrypt-on-read for the same realm; holding this
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

    fn lock_persist_health(&self) -> MutexGuard<'_, Option<String>> {
        self.persist_health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_mls_receive_overlay(&self) -> MutexGuard<'_, MlsReceiveOverlay> {
        self.mls_receive_overlay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_mls_decrypt_serial(&self) -> MutexGuard<'_, ()> {
        self.mls_decrypt_serial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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
            let overlay = self.lock_mls_receive_overlay();
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
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
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
        let overlay = self.lock_mls_receive_overlay();
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
        let mut overlay = self.lock_mls_receive_overlay();
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
                self.lock_persist_health().take();
            }
            Err(error) => {
                let message = error.to_string();
                tracing::error!(%error, "local state persist failed (latched for UI)");
                *self.lock_persist_health() = Some(message);
            }
        }
    }

    /// Current persistence-health message, if the last persist/boot-read
    /// failed (atomic write error, localStorage quota exceeded, or a corrupt
    /// backing store detected on load). `None` once a subsequent persist
    /// succeeds. UI surfaces this as a "changes are not being saved" banner.
    pub fn persist_error(&self) -> Option<String> {
        self.lock_persist_health().clone()
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
            Ok(state) => Some(state),
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
                *self.lock_persist_health() = Some(message);
                None
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let json = browser_storage()
            .and_then(|storage| storage.get_item(LOCAL_STATE_STORAGE_KEY).ok().flatten())?;
        match serde_json::from_str::<ClientLocalState>(&json) {
            Ok(state) => Some(state),
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
                *self.lock_persist_health() = Some(message);
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

#[cfg(test)]
#[path = "../local_state_tests/mod.rs"]
mod tests;
