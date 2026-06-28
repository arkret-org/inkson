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

/// Root-index storage key. Per-account `ClientLocalState` entries live under
/// the sibling key `account_state_key(did)`. The `.v1` suffix is preserved
/// across the per-account refactor — only the *shape* stored under this key
/// changed (old: a single global `ClientLocalState`; new: a small [`RootIndex`]
/// that points at per-account entries). Read-time migration upgrades any blob
/// still in the old shape.
#[cfg(target_arch = "wasm32")]
const LOCAL_STATE_STORAGE_KEY: &str = "yougen.local_state.v1";

/// Reserved namespace for the pre-login (signed-out) account entry. Local state
/// exists before any DID is known — drafts, UI scratch, the boot-time device
/// material the secure store mirrors — and must survive a reload. The root
/// index keeps `active_did = None` while signed out (per the spec), but the
/// blob still has a home under this stable sentinel entry instead of being held
/// only in memory. The first real login switches the active account to the
/// resolved DID; this anonymous entry is left untouched (it is not a real
/// account and never appears in `known_dids`).
const ANONYMOUS_ACCOUNT_NAMESPACE: &str = "anonymous";

/// Per-account `ClientLocalState` storage key. The DID is appended verbatim;
/// on wasm (localStorage) any DID character is a valid key, so no sanitisation
/// is needed. The native backend derives sibling *files* instead (see
/// [`LocalStateStore::account_state_path`]) and sanitises filesystem-hostile
/// characters there.
#[cfg(target_arch = "wasm32")]
fn account_state_key(did: &str) -> String {
    format!("{LOCAL_STATE_STORAGE_KEY}.account.{did}")
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
    /// The ACTIVE account's full state. Every existing read/write method
    /// operates on `cached` unchanged — they simply act on whichever account
    /// the persisted root index's `active_did` selects. Loaded from
    /// `account_state_key(active_did)` (or default when signed out) by
    /// [`Self::ensure_cached_loaded`].
    ///
    /// NOTE: the root index is deliberately NOT a struct field. `LocalStateStore`
    /// is `#[derive(Clone)]` and held in a widely-cloned `Signal<_>`; a cached
    /// `root` field would diverge per clone (one clone adopting an account while
    /// a stale clone's later flush rewrites the index back), which is exactly the
    /// "login leaves active_did = null / pending_login uncleared" race. Instead
    /// the root index is the small localStorage/root-file blob itself — read
    /// through [`Self::read_root`] and updated atomically through
    /// [`Self::mutate_root`] so every clone observes one shared source of truth.
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

/// Extract the effective `durability_policy` (RRK, realm-and-space.md §2.3.1)
/// from a cached realm-tree projection body, if present. Scans the same nested
/// containers as the encryption-state reader since the local projection nests
/// the realm body. Returns the SDK-typed [`cokret_sdk::models::DurabilityPolicy`]
/// so the client never re-defines the spec shape; `None` when absent or malformed.
fn realm_tree_projection_value_durability_policy(
    body: &Value,
) -> Option<cokret_sdk::models::DurabilityPolicy> {
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
                serde_json::from_value::<cokret_sdk::models::DurabilityPolicy>(policy.clone())
        {
            return Some(parsed);
        }
    }
    None
}

/// Extract the effective `content_scheme` selector from a cached realm-tree
/// projection body. RRK durability is only effective when this is
/// `mls-exporter-aead-v1` (encryption-and-audit.md §2.10.8 scheme constraint).
fn realm_tree_projection_value_content_scheme(body: &Value) -> Option<String> {
    use crate::realm_tree::string_field;
    let null = Value::Null;
    for container in [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if let Some(scheme) = string_field(container, &["content_scheme"]) {
            return Some(scheme);
        }
    }
    None
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

    // ── Account-aware persistence (per-account isolation) ────────────────
    //
    // The storage layout is a small root index at [`LOCAL_STATE_STORAGE_KEY`]
    // plus one full `ClientLocalState` per account at `account_state_key(did)`
    // (native: sibling files via `account_state_path`). The only persistence
    // functions that touch a storage key are the three below; the ~hundreds of
    // `cached`-based read/write methods are untouched — they act on whichever
    // account `root.active_did` selects.
    //
    // `read_persisted_state` returns the ACTIVE account's state (its callers
    // only want the state); `load_persisted_root` reads + migrates the index;
    // `write_persisted_state` writes the active account's entry and the index.

    #[cfg(not(target_arch = "wasm32"))]
    fn account_state_path(&self, did: &str) -> PathBuf {
        // Sibling file with the stem suffixed by `.account.<sanitized_did>`.
        // DID syntax (`did:webvh:…`) contains `:` which is filesystem-hostile
        // on Windows, so sanitise to a stable token.
        let sanitized = sanitize_did_for_filename(did);
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

    /// The single source of truth for the root index: ALWAYS read through from
    /// the backing store (it is small — a sync localStorage read on wasm, a tiny
    /// file on native — so this is cheap). There is no per-clone cache to go
    /// stale, so every `LocalStateStore` clone in the `Signal<_>` observes the
    /// same `active_did` / `pending_login` / `known_dids`.
    fn read_root(&self) -> RootIndex {
        self.load_persisted_root()
    }

    /// Atomic read-modify-write of the root index. Reads the current persisted
    /// index, applies `f`, and writes the result straight back — no intermediate
    /// in-memory `self.root` to diverge across clones. Must NOT trigger anything
    /// that re-reads/re-writes the root (no `flush`) to avoid re-entrancy.
    fn mutate_root(&self, f: impl FnOnce(&mut RootIndex)) {
        let mut root = self.load_persisted_root();
        f(&mut root);
        if let Err(error) = self.write_root(&root) {
            tracing::error!(%error, "persist root index failed");
            self.record_persist_result(&Err(error));
        }
    }

    /// Read + migrate the root index. On the old single-blob shape (a
    /// `ClientLocalState` parked at the root key with no `known_dids`) this
    /// rewrites the root key into a [`RootIndex`] and moves the blob into the
    /// owner's `account.<did>` entry (read-time, one-time, key name unchanged).
    /// Returns the resolved index (default when nothing is persisted yet).
    fn load_persisted_root(&self) -> RootIndex {
        let Some(raw) = self.read_root_raw() else {
            return RootIndex::default();
        };
        // Discriminator: the new index always serializes a `known_dids` array;
        // the old `ClientLocalState` never had that field.
        let is_new_shape = serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .map(|object| object.contains_key("known_dids"))
            })
            .unwrap_or(false);
        if is_new_shape {
            match serde_json::from_str::<RootIndex>(&raw) {
                Ok(root) => return root,
                Err(error) => {
                    tracing::error!(%error, "root index unreadable; starting from default");
                    *self.lock_persist_health() = Some(format!(
                        "local state root index was unreadable ({error}); started from defaults"
                    ));
                    return RootIndex::default();
                }
            }
        }
        // Old shape (or corrupt): try to migrate a single global blob.
        self.migrate_old_blob_to_root(&raw)
    }

    /// One-time migration of the legacy single-blob `ClientLocalState`.
    /// `account_scope_owner` (if present) becomes the active/known account and
    /// the whole blob is written to its `account.<did>` entry; the root key is
    /// rewritten as a [`RootIndex`]. A blob that doesn't parse as the old shape
    /// is treated as corrupt: preserved and reset to a default index.
    fn migrate_old_blob_to_root(&self, raw: &str) -> RootIndex {
        let old = match serde_json::from_str::<ClientLocalState>(raw) {
            Ok(old) => old,
            Err(error) => {
                self.preserve_corrupt_root(raw, &error.to_string());
                return RootIndex::default();
            }
        };
        // The legacy blob no longer carries `account_scope_owner` as a typed
        // field (it was removed with this refactor), so recover the owner from
        // the raw JSON to decide where the blob lands.
        let owner = serde_json::from_str::<Value>(raw).ok().and_then(|value| {
            value
                .get("account_scope_owner")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|owner| !owner.is_empty())
                .map(ToOwned::to_owned)
        });
        let mut root = RootIndex::default();
        if let Some(owner) = owner {
            // Move the blob into the owner's account entry, then rewrite root.
            if let Err(error) = self.write_account_state(&owner, &old) {
                tracing::error!(%error, "migrate: writing owner account entry failed");
            }
            root.active_did = Some(owner.clone());
            root.note_known_did(&owner);
            // The wrap_seed stays GLOBAL (service namespace), so the owner's
            // previously-stored secrets remain under the same wrapping key and
            // need no migration. (Per-account isolation is at the entry-key
            // level, not the wrap_seed.)
        }
        let _ = self.write_root(&root);
        root
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

    /// The account namespace the active blob persists under: the active DID
    /// when signed in, else the reserved anonymous sentinel so pre-login local
    /// state still has a durable home. This is a *storage* detail only — the
    /// root index `active_did` stays `None` while signed out. Reads the root
    /// through storage (no per-clone cache) so the flush hot path always writes
    /// the `…account.<did>` key the most recently adopted account selected.
    fn effective_account_key(&self) -> String {
        self.read_root()
            .active_did
            .unwrap_or_else(|| ANONYMOUS_ACCOUNT_NAMESPACE.to_owned())
    }

    /// Read the ACTIVE account's `ClientLocalState`. Resolves the namespace
    /// (active DID, or the anonymous sentinel when signed out) from the
    /// (migrated) root index, then reads that entry. `None` when the entry is
    /// absent.
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        self.read_account_state(&self.effective_account_key())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_account_state(&self, did: &str) -> Option<ClientLocalState> {
        let path = self.account_state_path(did);
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
        let json = browser_storage().and_then(|storage| storage.get_item(&key).ok().flatten())?;
        match serde_json::from_str::<ClientLocalState>(&json) {
            Ok(state) => Some(state),
            Err(error) => {
                if let Some(storage) = browser_storage() {
                    let _ = storage.set_item(&format!("{key}.corrupt"), &json);
                }
                let message = format!(
                    "account state in localStorage was unreadable ({error}); preserved a copy and started from defaults"
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
        let bytes = serde_json::to_vec_pretty(state)?;
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
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(&account_state_key(did), &serde_json::to_string(state)?)
            .map_err(|error| anyhow::anyhow!("localStorage write failed: {error:?}"))?;
        Ok(())
    }

    /// Delete a single account's persisted entry. Best-effort (a missing entry
    /// is fine). Native: removes the sibling file. wasm: removes the
    /// localStorage key and its corrupt sidecar.
    fn delete_account_state(&self, did: &str) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self.account_state_path(did);
            let _ = fs::remove_file(&path);
        }
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(storage) = browser_storage() {
                let key = account_state_key(did);
                let _ = storage.remove_item(&key);
                let _ = storage.remove_item(&format!("{key}.corrupt"));
            }
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

    /// Persist the active account's `state` to its own entry. The hot path
    /// (every flush) ONLY touches the active account's `…account.<did>` key and
    /// deliberately does NOT rewrite the root index: the index is the shared
    /// source of truth owned by [`Self::mutate_root`], and co-writing a
    /// per-clone copy of it here is exactly what let a stale clone clobber a
    /// freshly-adopted `active_did` back to null. The active DID is resolved by
    /// reading the index through ([`Self::effective_account_key`]), so a flush
    /// always lands in whatever account the latest adoption selected.
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        // Active DID when signed in, else the anonymous sentinel so pre-login
        // local state (drafts, scratch) is durable rather than memory-only.
        // YOU-02-003 note: the per-account split keeps each account's blob well
        // under the localStorage quota the single global blob used to risk.
        self.write_account_state(&self.effective_account_key(), state)
    }

    fn ensure_cached_loaded(&mut self) {
        // Read the backing store at most once; afterwards `cached` is the
        // authoritative source so empty/default accounts stop re-reading disk /
        // localStorage on every mutation.
        if self.loaded.get() {
            return;
        }
        // The root index is read through storage on demand (no `self.root`
        // field), so `effective_account_key` already reflects the persisted
        // active account; just hydrate `cached` from that account's entry.
        if self.cached == ClientLocalState::default()
            && let Some(state) = self.read_account_state(&self.effective_account_key())
        {
            self.cached = state;
        }
        self.loaded.set(true);
    }
}

/// Sanitise a DID into a filesystem-safe filename segment for the native
/// per-account state file. URL-safe-base64 of the DID bytes keeps it stable,
/// reversible-free (we never need to decode it), and free of `:`/`/` which are
/// hostile on Windows. Matches the per-account secure-store scoping convention.
#[cfg(not(target_arch = "wasm32"))]
fn sanitize_did_for_filename(did: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(did.as_bytes())
}

#[cfg(test)]
#[path = "../local_state_tests/mod.rs"]
mod tests;
