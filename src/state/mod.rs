use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use arkret_sdk::EncryptedPayload;
use chime::PushRegistrationState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::notification_rules::WatchLevel;

/// Root-index storage key. Per-account `ClientLocalState` entries live under
/// the sibling key `account_state_key(did)`.
#[cfg(target_arch = "wasm32")]
const LOCAL_STATE_STORAGE_KEY: &str = "inkson.local_state.v1";

/// Reserved namespace for the pre-login (signed-out) account entry. Local state
/// exists before any DID is known — drafts, UI scratch, the boot-time device
/// material the secure store mirrors — and must survive a reload. The root
/// index retains the last-selected account independently from `pending_login`;
/// while a transaction is pending this namespace takes precedence without
/// erasing that account pointer. It is not a real account and never appears in
/// `known_profiles`.
const ANONYMOUS_ACCOUNT_NAMESPACE: &str = "anonymous";

/// Canonical physical namespace for an accepted account authority pair.
fn account_storage_scope(authority: &arkret_sdk::PrincipalAuthorityKey) -> anyhow::Result<String> {
    crate::identity::active_account::authority_namespace(authority)
}

/// Per-account `ClientLocalState` storage key, always authority-pair scoped.
#[cfg(target_arch = "wasm32")]
fn account_state_key(namespace: &str) -> String {
    format!("{LOCAL_STATE_STORAGE_KEY}.account.{namespace}")
}

/// YOU-02-003: hard cap on the persisted `raw_operations` audit log. Each
/// user write appends one record and the whole `ClientLocalState` blob is
/// re-serialized on every flush; left unbounded it grows without limit
/// (linear native write cost) and, on wasm, eventually blows the ~5 MB
/// localStorage quota — after which *all* persistence (MLS snapshots, sync
/// cursor, plaintext sidecar) silently fails. We retain the most recent
/// `RAW_OPERATIONS_MAX` records, dropping the oldest first.
const RAW_OPERATIONS_MAX: usize = 512;
const TO_DEVICE_INBOX_MAX: usize = 512;
const TO_DEVICE_RECEIPTS_MAX: usize = 4096;

// Structural split: client-state data types (RawOperationRecord,
// ClientLocalState, MlsReceiveOverlay, the persisted-record structs, ...)
// moved out of this file into `types` (move only). The glob re-export keeps
// the `crate::state::*` public paths and the `impl LocalStateStore` /
// tests `use super::*` resolution unchanged.
mod types;
pub use types::*;

mod seal_view;
pub use seal_view::*;

mod mls_sidecar;
pub(crate) use mls_sidecar::{
    PendingHistorySecrets, mls_scope_snapshot_key, mls_scope_snapshot_key_for_group,
};

mod history_candidates;
mod history_runtime;
mod identity_links;
pub(crate) use history_runtime::{InksonHistoryRuntimeStore, history_runtime};

mod agent_evidence;
mod did_bindings;
mod mls_governance;

mod e2ee_secure_cache;
pub(crate) use e2ee_secure_cache::{
    BrowserStorageEstimate, E2eePlaintextCacheClearScope, E2eePlaintextCacheUsage,
    browser_storage_estimate,
};

mod account_persist;
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) use account_persist::run_browser_account_persist_fault_contract;

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
pub(crate) mod invite_credentials;
mod member_identity;
mod notifications_cursors;
mod realm_tree_snapshot;
mod remarks_blocklist;
mod scope;
mod to_device_raw;

#[derive(Clone, Debug, PartialEq)]
enum LocalProjectionCommand {
    AppendRawOperation {
        operation_id: String,
        realm_id: Option<String>,
        payload: Value,
    },
}

#[derive(Debug)]
pub struct LocalStateStore {
    /// The ACTIVE account's full state. Every existing read/write method
    /// operates on `cached` unchanged — they simply act on whichever account
    /// the persisted root index's `active_profile_id` selects. Loaded from
    /// `account_state_key(active_profile_id)` (or default when signed out) by
    /// [`Self::ensure_cached_loaded`].
    ///
    /// NOTE: the root index is deliberately NOT a struct field. `LocalStateStore`
    /// is `#[derive(Clone)]` and held in a widely-cloned `Signal<_>`; a cached
    /// `root` field would diverge per clone (one clone adopting an account while
    /// a stale clone's later flush rewrites the index back), which is exactly the
    /// "login leaves active_profile_id = null / pending_login uncleared" race. Instead
    /// the root index is the small localStorage/root-file blob itself — read
    /// through [`Self::read_root`] and updated atomically through
    /// [`Self::mutate_root`] so every clone observes one shared source of truth.
    cached: ClientLocalState,
    /// Principal storage scope bound to `cached`. The root index is shared by every
    /// store instance, while `cached` is instance-local; without this fence a
    /// store loaded for Alice can observe Bob becoming active and flush Alice's
    /// snapshot into Bob's entry. `None` means this instance has not hydrated a
    /// namespace yet.
    cached_account_key: Option<String>,
    /// Perf: whether `cached` has been reconciled with the persistence layer at
    /// least once. Before this flag existed, an empty/default account (where
    /// `cached == ClientLocalState::default()`) re-read the backing store (disk
    /// on native, localStorage on wasm) AND did a full-state `!= default`
    /// comparison on EVERY `load()` / mutation. Once loaded, `cached` is the
    /// authoritative single-process source of truth, so we skip both.
    loaded: AtomicBool,
    /// Perf (P0 sync-apply / notifications bulk): when `> 0`, [`Self::flush`]
    /// defers the (potentially synchronous, blocking) persist and only records
    /// that a write is pending. A batch guard performs exactly one flush when
    /// the outermost batch closes. This collapses the dozens of full-state
    /// serializations a single sync/bulk mutation used to trigger into one.
    flush_suspended: u32,
    /// Set by [`Self::flush`] while suspended; consumed by the batch guard so
    /// it only persists when at least one mutation actually requested a flush.
    flush_pending: AtomicBool,
    /// YOU-02-002/003: shared persistence-health latch. `None` = healthy;
    /// `Some(message)` records the last persist/read failure (atomic write
    /// failed, localStorage quota exceeded, or a corrupt backing store was
    /// found on boot). Shared via `Arc<Mutex<_>>` so every `Clone` of the store
    /// (the Dioxus `SyncSignal<LocalStateStore>` is cloned widely) observes the same
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
    /// Runtime-only unified Sidecar projection. Its inputs come exclusively
    /// from decrypted Account Data and deterministic accepted private-history
    /// folds; persisted caches remain rebuildable accelerators.
    sidecar_projection_fold: garth::projection::SidecarProjectionFold,
    pending_projection_commands: std::collections::VecDeque<LocalProjectionCommand>,
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

pub(crate) struct LocalStatePersistBarrier {
    inner: account_persist::AccountPersistBarrier,
    persist_health: Arc<Mutex<Option<String>>>,
}

impl LocalStatePersistBarrier {
    pub(crate) async fn wait(self) -> anyhow::Result<()> {
        let result = self.inner.wait().await;
        let mut health = self
            .persist_health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &result {
            Ok(()) => {
                health.take();
            }
            Err(error) => {
                *health = Some(error.to_string());
            }
        }
        result
    }
}

/// Extract the effective `durability_policy` (RRK, realm-and-space.md §2.3.1)
/// from a cached realm-tree projection body, if present. Scans the same nested
/// containers as the encryption-state reader since the local projection nests
/// the realm body. Returns the SDK-typed closed union
/// [`arkret_wire::DurabilityPolicy`] so the client never re-defines the spec
/// shape; `None` when absent or outside the registered value set.
fn realm_tree_projection_value_durability_policy(
    body: &Value,
) -> Option<arkret_wire::DurabilityPolicy> {
    let null = Value::Null;
    for container in [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if let Some(policy) = container.get("durability_policy")
            && !policy.is_null()
            && let Ok(parsed) =
                serde_json::from_value::<arkret_wire::DurabilityPolicy>(policy.clone())
        {
            return Some(parsed);
        }
    }
    None
}

/// SEC-08 (`encryption-and-audit.md` §2.9) — does a cached realm-tree
/// projection declare the `ak.profile.mls.minimal_metadata_realm.v1` profile?
///
/// Mirrors soland's server-side `payload_declares_minimal_metadata_realm`
/// (`profiles[]` / `active_profiles[]` arrays) but scans the same nested
/// containers ([summary]/[object]/[realm]/[metadata]) the encryption-state
/// reader walks, since the local projection nests the realm body. The profile
/// id is the SDK constant so the client and server agree on the exact string.
/// The containers a realm-tree projection may nest its Realm object under.
/// Callers scan all of them because the projection shape differs by source.
fn realm_tree_projection_containers(body: &Value) -> Vec<&Value> {
    const NULL: &Value = &Value::Null;
    vec![
        body,
        body.get("summary").unwrap_or(NULL),
        body.get("object").unwrap_or(NULL),
        body.get("realm").unwrap_or(NULL),
        body.get("metadata").unwrap_or(NULL),
    ]
}

/// Every profile the projection declares, from whichever container carries them.
fn realm_tree_projection_profiles(body: &Value) -> Vec<String> {
    let mut profiles = Vec::new();
    for container in realm_tree_projection_containers(body) {
        for field in ["profiles", "active_profiles"] {
            let Some(declared) = container.get(field).and_then(Value::as_array) else {
                continue;
            };
            for profile in declared.iter().filter_map(Value::as_str) {
                if !profiles.iter().any(|seen: &String| seen == profile) {
                    profiles.push(profile.to_owned());
                }
            }
        }
    }
    profiles
}

fn realm_tree_projection_value_is_minimal_metadata(body: &Value) -> bool {
    realm_tree_projection_profiles(body)
        .iter()
        .any(|profile| profile == arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1)
}

impl Default for LocalStateStore {
    fn default() -> Self {
        Self {
            cached: ClientLocalState::default(),
            cached_account_key: None,
            loaded: AtomicBool::new(false),
            flush_suspended: 0,
            flush_pending: AtomicBool::new(false),
            persist_health: Arc::new(Mutex::new(None)),
            mls_receive_overlay: Arc::new(Mutex::new(MlsReceiveOverlay::default())),
            mls_decrypt_serial: Arc::new(Mutex::new(())),
            sidecar_projection_fold: garth::projection::SidecarProjectionFold::default(),
            pending_projection_commands: std::collections::VecDeque::new(),
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
    pub(crate) fn apply_sidecar_view_state(
        &mut self,
        view_state: arkret_sdk::AgentSidecarViewState,
    ) -> bool {
        self.sidecar_projection_fold.apply_view_state(view_state)
    }

    pub(crate) fn sidecar_view_state(
        &self,
        controller_id: &str,
        realm_id: &arkret_sdk::RealmId,
        strand_id: &arkret_sdk::StrandId,
    ) -> Option<arkret_sdk::AgentSidecarViewState> {
        self.sidecar_projection_fold
            .view_state(controller_id, realm_id, strand_id)
            .cloned()
    }

    pub(crate) fn apply_sidecar_exchange_projection(
        &mut self,
        projection: arkret_sdk::AgentSidecarExchangeProjection,
    ) -> arkret_sdk::Result<()> {
        self.sidecar_projection_fold
            .apply_folded_exchange(projection)
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
    }

    pub(crate) fn sidecar_projection_fold_snapshot(
        &self,
    ) -> garth::projection::SidecarProjectionFold {
        self.sidecar_projection_fold.clone()
    }

    const SECURE_IDENTITY_KEY: &'static str = "identity.local.primary.v1";

    pub(crate) const SECURE_DPOP_DEVICE_KEY: &'static str = "auth.dpop.device_key.v1";

    pub(crate) const SECURE_SESSION_GRANT_KEY: &'static str = "auth.session_grant.v1";

    fn active_series_highest_seen_key(actor_id: &str, backup_kind: &str) -> String {
        format!("{actor_id}\u{1f}{backup_kind}")
    }

    pub(crate) fn observe_key_backup_active_series_version(
        &mut self,
        actor_id: &str,
        backup_kind: &str,
        version: u64,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        let key = Self::active_series_highest_seen_key(actor_id, backup_kind);
        if self
            .cached
            .key_backup_active_series_highest_seen
            .get(&key)
            .is_some_and(|highest| version < *highest)
        {
            anyhow::bail!("backup_frontier_stale");
        }
        if self.cached.key_backup_active_series_highest_seen.get(&key) == Some(&version) {
            return Ok(());
        }
        self.cached
            .key_backup_active_series_highest_seen
            .insert(key, version);
        self.flush()
    }

    pub(crate) fn enqueue_local_projection_command(
        &mut self,
        operation_id: impl Into<String>,
        realm_id: Option<String>,
        payload: Value,
    ) {
        self.pending_projection_commands
            .push_back(LocalProjectionCommand::AppendRawOperation {
                operation_id: operation_id.into(),
                realm_id,
                payload,
            });
    }

    fn drain_local_projection_commands(&mut self) -> Vec<LocalProjectionCommand> {
        self.pending_projection_commands.drain(..).collect()
    }

    pub(crate) fn project_pending_local_commands(&mut self) {
        for command in self.drain_local_projection_commands() {
            match command {
                LocalProjectionCommand::AppendRawOperation {
                    operation_id,
                    realm_id,
                    payload,
                } => self.append_raw_operation(operation_id, realm_id, payload),
            }
        }
    }

    pub(crate) fn has_pending_local_projection_commands(&self) -> bool {
        !self.pending_projection_commands.is_empty()
    }

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
        let effective_account_key = self.effective_account_key();
        let mut state = if self.loaded.load(Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(effective_account_key.as_str())
        {
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
        self.ensure_cached_loaded();
        // Wholesale replacement: the incoming state is authoritative, so any
        // pending receive-chain overlay entries derived from the OLD state
        // must not survive to shadow it.
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        self.cached = state;
        self.loaded.store(true, Ordering::Relaxed);
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        if self.flush_suspended > 0 {
            // Inside a batch — defer the persist and remember a write happened.
            self.flush_pending.store(true, Ordering::Relaxed);
            return Ok(());
        }
        let account_key = self.cached_account_key_for_persist()?;
        let result = self.write_account_state(&account_key, &self.effective_state_for_persist());
        self.record_persist_result(&result);
        result
    }

    /// Freeze the active account's current state into the single-writer queue
    /// and return a barrier that resolves only after that sequence (or a newer
    /// coalesced snapshot) is durably committed. Remote acknowledgements and
    /// post-accept actions must await this instead of treating a wasm enqueue
    /// as a completed IndexedDB write.
    pub(crate) fn begin_durable_flush(&self) -> anyhow::Result<LocalStatePersistBarrier> {
        if self.flush_suspended > 0 {
            anyhow::bail!("cannot begin a durable state barrier inside a state batch");
        }

        #[cfg(not(target_arch = "wasm32"))]
        let inner = {
            self.flush()?;
            account_persist::AccountPersistBarrier::ready()
        };

        #[cfg(target_arch = "wasm32")]
        let inner = {
            let account_key = self.cached_account_key_for_persist()?;
            let state = e2ee_safe_persist_state(&self.effective_state_for_persist());
            let json = serde_json::to_string(&state)?;
            match account_persist::enqueue_account_state_persist_barrier(
                account_state_key(&account_key),
                json,
            ) {
                Ok(barrier) => barrier,
                Err(error) => {
                    tracing::error!(%error, "local state durable barrier enqueue failed");
                    *self.lock_persist_health() = Some(error.to_string());
                    return Err(error);
                }
            }
        };

        Ok(LocalStatePersistBarrier {
            inner,
            persist_health: Arc::clone(&self.persist_health),
        })
    }

    /// YOU-02-004 — the state every persist must write: `cached` with the
    /// receive-chain overlay merged over it. Without this, any unrelated
    /// setter's flush would clobber the on-disk receive-chain advancement
    /// that a decrypt recorded via the overlay (a §5.6 violation: the next
    /// boot would replay the ratchet from the stale snapshot).
    fn effective_state_for_persist(&self) -> ClientLocalState {
        let mut state = self.cached.clone();
        {
            let overlay = self.lock_mls_receive_overlay();
            if !overlay.is_empty() {
                overlay.apply_to(&mut state);
            }
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
        if self.flush_suspended == 0 && self.flush_pending.swap(false, Ordering::Relaxed) {
            let persisted = self
                .cached_account_key_for_persist()
                .and_then(|account_key| {
                    self.write_account_state(&account_key, &self.effective_state_for_persist())
                });
            self.record_persist_result(&persisted);
        }
        result
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cached: ClientLocalState::default(),
            cached_account_key: None,
            loaded: AtomicBool::new(false),
            flush_suspended: 0,
            flush_pending: AtomicBool::new(false),
            persist_health: Arc::new(Mutex::new(None)),
            mls_receive_overlay: Arc::new(Mutex::new(MlsReceiveOverlay::default())),
            mls_decrypt_serial: Arc::new(Mutex::new(())),
            sidecar_projection_fold: garth::projection::SidecarProjectionFold::default(),
            pending_projection_commands: std::collections::VecDeque::new(),
            path: path.into(),
        }
    }

    // ── Account-aware persistence (per-account isolation) ────────────────
    //
    // The storage layout is a small root index at [`LOCAL_STATE_STORAGE_KEY`]
    // plus one full `ClientLocalState` per authority at its digest-derived key
    // (native: sibling files via `account_state_path`). The only persistence
    // functions that touch a storage key are the three below; the ~hundreds of
    // `cached`-based read/write methods are untouched — they act on whichever
    // account `root.active_profile_id` selects.
    //
    // `read_persisted_state` returns the ACTIVE account's state (its callers
    // only want the state); `load_persisted_root` reads the index;
    // `write_persisted_state` writes the active account's entry and the index.

    #[cfg(not(target_arch = "wasm32"))]
    fn account_state_path(&self, namespace: &str) -> PathBuf {
        let sanitized = sanitize_did_for_filename(namespace);
        let stem = self
            .path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("state");
        let ext = self
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json");
        let file_name = format!("{stem}.account.{sanitized}.{ext}");
        match self.path.parent() {
            Some(parent) => parent.join(file_name),
            None => PathBuf::from(file_name),
        }
    }

    /// Dedicated atomic store for durable Signal sequence block reservations.
    /// It is intentionally separate from the large account-state snapshot: a
    /// second process can lock and advance this high-water without rewriting
    /// or racing unrelated projections.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn signal_sequence_store_path(&self) -> PathBuf {
        let account = self.account_state_path(&self.effective_account_key());
        let file_name = format!(
            "{}.signal-sequences.jsonl",
            account
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("account")
        );
        account
            .parent()
            .map(|parent| parent.join(&file_name))
            .unwrap_or_else(|| PathBuf::from(file_name))
    }

    /// Stable namespace for the active account's Signal sequence allocator.
    /// Process-local block caches and browser storage include it so an account
    /// switch cannot consume a block persisted for a different account.
    pub(crate) fn signal_sequence_store_namespace(&self) -> String {
        self.effective_account_key()
    }

    /// The single source of truth for the root index: ALWAYS read through from
    /// the backing store (it is small — a sync localStorage read on wasm, a tiny
    /// file on native — so this is cheap). There is no per-clone cache to go
    /// stale, so every `LocalStateStore` clone in the `Signal<_>` observes the
    /// same `active_profile_id` / `pending_login` / `known_profiles`.
    fn read_root(&self) -> RootIndex {
        self.load_persisted_root()
    }

    /// Atomic read-modify-write of the root index. Reads the current persisted
    /// index, applies `f`, and writes the result straight back — no intermediate
    /// in-memory `self.root` to diverge across clones. Must NOT trigger anything
    /// that re-reads/re-writes the root (no `flush`) to avoid re-entrancy.
    fn mutate_root<T>(&self, f: impl FnOnce(&mut RootIndex) -> T) -> T {
        let mut root = self.load_persisted_root();
        let result = f(&mut root);
        if let Err(error) = self.write_root(&root) {
            tracing::error!(%error, "persist root index failed");
            self.record_persist_result(&Err(error));
        }
        result
    }

    /// Read the root index, preserving malformed data before resetting.
    fn load_persisted_root(&self) -> RootIndex {
        let Some(raw) = self.read_root_raw() else {
            return RootIndex::default();
        };
        match serde_json::from_str::<RootIndex>(&raw) {
            Ok(root) => root,
            Err(error) => {
                self.preserve_corrupt_root(&raw, &error.to_string());
                RootIndex::default()
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_root_raw(&self) -> Option<String> {
        let bytes = fs::read(&self.path).ok()?;
        String::from_utf8(bytes).ok()
    }

    #[cfg(target_arch = "wasm32")]
    fn read_root_raw(&self) -> Option<String> {
        browser_storage()
            .and_then(|storage| storage.get_item(LOCAL_STATE_STORAGE_KEY).ok().flatten())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn preserve_corrupt_root(&self, _raw: &str, error: &str) {
        // YOU-02-002: a corrupt / truncated root file MUST NOT be silently reset.
        let corrupt_path = self.path.with_extension("corrupt");
        let _ = fs::rename(&self.path, &corrupt_path);
        let message = format!(
            "local state at {} was unreadable ({error}); preserved a copy at {} and started from defaults",
            self.path.display(),
            corrupt_path.display()
        );
        tracing::error!(error, "corrupt local state preserved, not silently reset");
        *self.lock_persist_health() = Some(message);
    }

    #[cfg(target_arch = "wasm32")]
    fn preserve_corrupt_root(&self, raw: &str, error: &str) {
        if let Some(storage) = browser_storage() {
            let _ = storage.set_item(&format!("{LOCAL_STATE_STORAGE_KEY}.corrupt"), raw);
        }
        let message = format!(
            "local state in localStorage was unreadable ({error}); preserved a copy and started from defaults"
        );
        tracing::error!(error, "corrupt local state preserved, not silently reset");
        *self.lock_persist_health() = Some(message);
    }

    /// The namespace the cached blob persists under. A pending transaction
    /// always selects the anonymous namespace; otherwise the last committed
    /// account is selected. Reads the shared root on every call so no clone can
    /// route pending writes into the retained account.
    fn effective_account_key(&self) -> String {
        let root = self.read_root();
        if root.pending_login.is_some() {
            ANONYMOUS_ACCOUNT_NAMESPACE.to_owned()
        } else {
            root.active_entry()
                .and_then(|entry| account_storage_scope(&entry.authority).ok())
                .unwrap_or_else(|| ANONYMOUS_ACCOUNT_NAMESPACE.to_owned())
        }
    }

    /// Read the ACTIVE account's `ClientLocalState`. Resolves the namespace
    /// (active authority, or the anonymous sentinel when signed out) from the
    /// root index, then reads that entry. `None` when the entry is
    /// absent.
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let root = self.read_root();
        let active_namespace = root
            .pending_login
            .is_none()
            .then(|| root.active_entry())
            .flatten()
            .and_then(|entry| account_storage_scope(&entry.authority).ok());
        let account_key = active_namespace
            .as_deref()
            .unwrap_or(ANONYMOUS_ACCOUNT_NAMESPACE);
        let state = self.read_account_state(account_key).unwrap_or_default();
        #[cfg(not(test))]
        {
            let mut state = state;
            // On wasm the grant lives in the IndexedDB tier; before its async
            // init completes the localStorage fallback refuses grant reads
            // (fail closed). Skip the restore quietly in that window instead
            // of warning on every persist-path read and overwriting the grant
            // with None; identity_session's deferred persist repopulates the
            // store once it is ready.
            #[cfg(target_arch = "wasm32")]
            let secure_store_ready = crate::secure_key_store::wasm_secure_store_ready();
            #[cfg(not(target_arch = "wasm32"))]
            let secure_store_ready = true;
            if secure_store_ready {
                // Restoring an account-local session requires the accepted
                // PrincipalAuthorityKey. The legacy root retains only a DID,
                // so fail closed instead of guessing a secure-store scope from
                // a core/full string. Authority-scoped restore is wired only
                // after the root/profile context can be reconstructed.
                state.session_grant = None;
            }
            Some(state)
        }
        #[cfg(test)]
        Some(state)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_account_state(&self, storage_scope: &str) -> Option<ClientLocalState> {
        let path = self.account_state_path(storage_scope);
        let bytes = fs::read(&path).ok()?;
        match serde_json::from_slice::<ClientLocalState>(&bytes) {
            Ok(state) => Some(state),
            Err(error) => {
                let corrupt_path = path.with_extension("corrupt");
                let _ = fs::rename(&path, &corrupt_path);
                let message = format!(
                    "account state at {} was unreadable ({error}); preserved a copy at {} and started from defaults",
                    path.display(),
                    corrupt_path.display()
                );
                tracing::error!(%error, "corrupt account state preserved, not silently reset");
                *self.lock_persist_health() = Some(message);
                None
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn read_account_state(&self, did: &str) -> Option<ClientLocalState> {
        let key = account_state_key(did);
        // Read-your-writes: a durable write still in the single-writer queue is
        // the newest snapshot for this key; observe it before the backend cache
        // so a flush-then-read in the same tick never reads a stale value.
        let json = if let Some(pending) = account_persist::pending_account_state_json(&key) {
            pending
        } else {
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            // Before the IndexedDB tier is ready the localStorage secure tier
            // refuses this IndexedDB-only key (`Unsupported`), treated as absent —
            // fail closed rather than reading a weaker copy. After boot the
            // decrypted entry is served synchronously from the in-memory cache.
            match store.get_secret(&key) {
                Ok(Some(json)) => json,
                Ok(None) | Err(_) => return None,
            }
        };
        match serde_json::from_str::<ClientLocalState>(&json) {
            Ok(state) => Some(state),
            Err(error) => {
                // Preserve the undecodable blob under a sibling secure entry
                // (still IndexedDB-only) before returning defaults, so a later
                // flush cannot silently overwrite the only copy.
                let store = crate::secure_key_store::default_secure_key_store("inkson");
                let _ = store.store_secret(&format!("{key}.corrupt"), &json);
                let message = format!(
                    "account state entry was unreadable ({error}); preserved a copy and started from defaults"
                );
                tracing::error!(%error, "corrupt account state preserved, not silently reset");
                *self.lock_persist_health() = Some(message);
                None
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_account_state(&self, did: &str, state: &ClientLocalState) -> anyhow::Result<()> {
        use std::io::Write;

        let path = self.account_state_path(did);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let persisted = e2ee_safe_persist_state(state);
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        let tmp_path = path.with_extension("json.tmp");
        {
            let mut tmp = fs::File::create(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
        }
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_account_state(&self, did: &str, state: &ClientLocalState) -> anyhow::Result<()> {
        // E2EE-at-rest: never persist raw history key material or decrypted MLS
        // plaintext in the account-state blob — those live in their own hardened
        // secure entries (`e2ee_plaintext_cache` / `mls_history_secret`).
        let to_persist = e2ee_safe_persist_state(state);
        let json = serde_json::to_string(&to_persist)?;
        // Route the blob through the durable single-writer queue into the
        // IndexedDB encrypted entries store. Before the IndexedDB tier is ready
        // this is a no-op (fail closed): the value stays in `cached` and the boot
        // hydration flushes it once the tier initialises. The account key is
        // frozen here so a later account switch cannot misroute this write.
        account_persist::enqueue_account_state_persist(account_state_key(did), json);
        Ok(())
    }

    /// Delete a single account's persisted entry. Best-effort (a missing entry
    /// is fine). Native: removes the sibling file. wasm: removes the
    /// secure-store key and its corrupt sidecar.
    fn delete_account_state(&self, did: &str) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self.account_state_path(did);
            let _ = fs::remove_file(&path);
        }
        #[cfg(target_arch = "wasm32")]
        {
            let key = account_state_key(did);
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            let _ = store.delete_secret(&key);
            let _ = store.delete_secret(&format!("{key}.corrupt"));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_root(&self, root: &RootIndex) -> anyhow::Result<()> {
        use std::io::Write;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(root)?;
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
    fn write_root(&self, root: &RootIndex) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(LOCAL_STATE_STORAGE_KEY, &serde_json::to_string(root)?)
            .map_err(|error| anyhow::anyhow!("localStorage write failed: {error:?}"))?;
        Ok(())
    }

    /// Return the namespace that may receive this instance's cached snapshot.
    /// The shared root can change through another store instance while this
    /// instance is alive; fail closed instead of routing a stale snapshot to the
    /// newly-active account.
    fn cached_account_key_for_persist(&self) -> anyhow::Result<String> {
        let active = self.effective_account_key();
        match self.cached_account_key.as_deref() {
            Some(cached_scope) if cached_scope == active => Ok(active),
            Some(cached_scope) => anyhow::bail!(
                "refusing cross-account local-state persist: cached principal scope {cached_scope} is not active account scope {active}"
            ),
            None => anyhow::bail!(
                "refusing local-state persist before the active account namespace is hydrated"
            ),
        }
    }

    fn ensure_cached_loaded(&mut self) {
        // Read the backing store at most once; afterwards `cached` is the
        // authoritative source so empty/default accounts stop re-reading disk /
        // localStorage on every mutation.
        let effective_account_key = self.effective_account_key();
        if self.loaded.load(Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(effective_account_key.as_str())
        {
            return;
        }
        // The root index is read through storage on demand (no `self.root`
        // field), so `effective_account_key` already reflects the persisted
        // active account; just hydrate `cached` from that account's entry.
        self.cached = self
            .read_account_state(&effective_account_key)
            .unwrap_or_default();
        self.cached_account_key = Some(effective_account_key);
        self.loaded.store(true, Ordering::Relaxed);
    }
}

/// Sanitise a DID into a filesystem-safe filename segment for the native
/// per-account state file. URL-safe-base64 of the DID bytes keeps it stable,
/// reversible-free (we never need to decode it), and free of `:`/`/` which are
/// hostile on Windows. Matches the per-account secure-store scoping convention.
#[cfg(not(target_arch = "wasm32"))]
fn sanitize_storage_scope_for_filename(storage_scope: &str) -> String {
    storage_scope.to_owned()
}

fn e2ee_safe_persist_state(state: &ClientLocalState) -> ClientLocalState {
    e2ee_safe_persist_state_with_policy(state, !cfg!(test))
}

fn e2ee_safe_persist_state_with_policy(
    state: &ClientLocalState,
    strip_credentials: bool,
) -> ClientLocalState {
    let mut stripped = state.clone();
    // Credentials and private signing material are secure-store-only. Keep
    // them in the live cache, never in cursor/projection/account JSON.
    if strip_credentials {
        stripped.session_grant = None;
    }
    stripped.history_secrets.clear();
    stripped.mls_private_plaintext.clear();
    stripped.mls_decrypted_plaintext.clear();
    stripped.authenticated_identity_links.clear();
    stripped
}

pub mod projection;
pub mod projection_views;
#[cfg(test)]
#[path = "../local_state_tests/mod.rs"]
mod tests;
