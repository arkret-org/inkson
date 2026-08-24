//! Durable account-main-state persistence engine (E2EE-local-state phase 2).
//!
//! On wasm the per-account `ClientLocalState` blob is stored in the
//! IndexedDB + non-extractable SubtleCrypto encrypted entries store
//! (the same `inkson.secret.inkson`/`entries` store the seed-grade secrets
//! use). The semantic key is `inkson.local_state.v1.account.<authority_digest>`, and the physical
//! backend is the hardened secure store, so the account
//! blob is ciphertext at rest instead of near-plaintext localStorage JSON.
//!
//! Two target-agnostic pieces live here so they can be unit-tested natively:
//!
//!   * [`merge_persisted_into_live`] — the boot-time reconciliation between the previous session's
//!     stored blob and any live in-memory writes made before the IndexedDB tier finished
//!     initialising. Live values win; stored values fill gaps ("现场优先、已存补缺").
//!   * [`AccountPersistQueueState`] — the per-account single-writer commit-queue state machine.
//!     Each enqueue freezes the target account key and takes a monotonic sequence number; a single
//!     drain per account coalesces to the latest not-yet-started snapshot so an older async write
//!     can never land on top of a newer one.
//!
//! The wasm driver ([`enqueue_account_state_persist`]) wires the state machine
//! to `spawn_local` + `SecureKeyStore::store_secret_durable`. Native builds keep
//! the synchronous atomic-file backend in `state/mod.rs` unchanged.

// The merge + queue logic is a target-agnostic core: it drives persistence on
// wasm and is exercised by the native unit tests below. On a native non-test
// build it is compiled but unused, so silence dead-code there instead of
// scattering per-item gates.
#![cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]

use serde_json::Value;

use super::ClientLocalState;

/// Restore secure-store-only session material without replacing a grant that
/// was minted in the live session while the durable wasm tier was opening.
fn merge_secure_session_grant_into_live(
    live: &mut ClientLocalState,
    secure_grant: Option<super::PersistedSessionGrant>,
) {
    if live.session_grant.is_none() {
        live.session_grant = secure_grant;
    }
}

/// Recursively merge `stored` UNDER `live`: object keys are unioned (recursing
/// into shared keys), a `null`/absent live value adopts the stored value, and a
/// present live scalar or array wins outright.
///
/// This is deliberately map-oriented: `ClientLocalState` is overwhelmingly a bag
/// of `BTreeMap`/`Vec` projections, so unioning object keys recovers every
/// stored-only realm/cursor/snapshot entry the live blob has not re-observed
/// yet, while the live session's own writes stay authoritative. The only lossy
/// case is a scalar both sessions set to *different non-null* values inside the
/// narrow pre-init window; there live wins (this session's intent) and the
/// stored value re-materialises on the next sync. That window is only reachable
/// when a real main-state write happened before the IndexedDB tier initialised,
/// which the bootstrap ordering makes vanishingly rare.
fn json_merge_live_priority(live: Value, stored: Value) -> Value {
    match (live, stored) {
        (Value::Object(mut live_map), Value::Object(stored_map)) => {
            for (key, stored_value) in stored_map {
                match live_map.remove(&key) {
                    Some(live_value) => {
                        live_map.insert(key, json_merge_live_priority(live_value, stored_value));
                    }
                    None => {
                        live_map.insert(key, stored_value);
                    }
                }
            }
            Value::Object(live_map)
        }
        // A live `null` means "the live session never set this"; adopt stored.
        (Value::Null, stored) => stored,
        // Any other present live value (scalar or array) is authoritative.
        (live, _) => live,
    }
}

/// Reconcile a freshly-loaded `stored` blob (previous session, from the durable
/// backend) with the `live` in-memory state accumulated before the durable tier
/// was ready.
///
/// Fast paths keep the common cases exact:
///   * `live` is structurally default → adopt `stored` wholesale (the ordinary reload: nothing
///     wrote main state before hydration).
///   * `stored` is default → keep `live` (an empty durable tier catches the writes made before it
///     initialised — "空安全库也会接住现场值").
///
/// Otherwise both are non-default (a real live write raced hydration) and the
/// field-wise [`json_merge_live_priority`] union runs.
///
/// The four memory-only sidecars (`mls_private_plaintext`,
/// `mls_decrypted_plaintext`, `history_secrets`, `authenticated_identity_links`)
/// are `#[serde(skip_serializing)]`
/// and never appear in a stored blob, so they are lifted out of `live` before
/// the JSON round-trip and restored afterwards — the JSON merge would otherwise
/// deserialize them back to empty and drop the live plaintext caches.
pub(super) fn merge_persisted_into_live(
    live: ClientLocalState,
    stored: ClientLocalState,
) -> ClientLocalState {
    let default_state = ClientLocalState::default();
    if live == default_state {
        return stored;
    }
    if stored == default_state {
        return live;
    }
    // Preserve the memory-only sidecars from the live state; a JSON round-trip
    // drops them (they are skip_serializing) and stored never carries them.
    let live_private_plaintext = live.mls_private_plaintext.clone();
    let live_decrypted_plaintext = live.mls_decrypted_plaintext.clone();
    let live_history_secrets = live.history_secrets.clone();
    let live_authenticated_identity_links = live.authenticated_identity_links.clone();

    let merged_value = match (serde_json::to_value(&live), serde_json::to_value(&stored)) {
        (Ok(live_value), Ok(stored_value)) => json_merge_live_priority(live_value, stored_value),
        _ => {
            // Serialization cannot realistically fail for these types; if it
            // somehow did, keep the live session's state rather than risk
            // adopting a partial merge.
            return live;
        }
    };
    let mut merged: ClientLocalState = match serde_json::from_value(merged_value) {
        Ok(merged) => merged,
        Err(_) => return live,
    };
    merged.mls_private_plaintext = live_private_plaintext;
    merged.mls_decrypted_plaintext = live_decrypted_plaintext;
    merged.history_secrets = live_history_secrets;
    merged.authenticated_identity_links = live_authenticated_identity_links;
    merged
}

/// One queued account-state write: the JSON payload to persist and the
/// monotonic sequence number stamped when it was enqueued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PendingAccountWrite {
    pub(super) seq: u64,
    pub(super) json: String,
}

/// Result of [`AccountPersistQueueState::enqueue`]: whether the caller must
/// launch a fresh drain task for this account key, or an existing drain is
/// already running and will pick the write up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EnqueueOutcome {
    StartDrain,
    AlreadyDraining,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EnqueuedAccountWrite {
    pub(super) seq: u64,
    pub(super) outcome: EnqueueOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AccountPersistBarrierStatus {
    Pending,
    Committed,
    Failed(String),
}

#[derive(Clone, Debug)]
pub(crate) struct AccountPersistBarrier {
    #[cfg(target_arch = "wasm32")]
    account_key: String,
    #[cfg(target_arch = "wasm32")]
    seq: u64,
}

impl AccountPersistBarrier {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn ready() -> Self {
        Self {}
    }

    pub(crate) async fn wait(self) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return wasm_driver::wait_for_account_state_persist(&self.account_key, self.seq).await;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(())
        }
    }
}

/// Per-account single-writer commit-queue state machine.
///
/// Invariants:
///   * At most one entry is pending per account key — a newer enqueue replaces an older
///     not-yet-started snapshot (coalescing to the latest tail).
///   * At most one drain runs per account key (`draining` set membership).
///   * `enqueue` and `take_next` are the only mutators of `draining`, and both run under the same
///     external lock in the wasm driver, so there is no lost-wakeup window: a write enqueued while
///     a drain is finishing is either seen by that drain's next `take_next` (pending inserted
///     before the drain's lock) or starts a new drain (drain cleared `draining` first).
#[derive(Debug, Default)]
pub(super) struct AccountPersistQueueState {
    pending: std::collections::HashMap<String, PendingAccountWrite>,
    committed_seq: std::collections::HashMap<String, u64>,
    failed: std::collections::HashMap<String, (u64, String)>,
    draining: std::collections::HashSet<String>,
    next_seq: u64,
}

impl AccountPersistQueueState {
    /// Stamp `json` with the next sequence number as the latest pending write
    /// for `account_key`, superseding any earlier not-yet-started snapshot.
    pub(super) fn enqueue(&mut self, account_key: String, json: String) -> EnqueuedAccountWrite {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        self.pending
            .insert(account_key.clone(), PendingAccountWrite { seq, json });
        let outcome = if self.draining.contains(&account_key) {
            EnqueueOutcome::AlreadyDraining
        } else {
            self.draining.insert(account_key);
            EnqueueOutcome::StartDrain
        };
        EnqueuedAccountWrite { seq, outcome }
    }

    /// Pull the latest pending write for `account_key`. Returns `None` and
    /// atomically clears the drain flag when nothing is pending, ending the
    /// drain loop.
    pub(super) fn take_next(&mut self, account_key: &str) -> Option<PendingAccountWrite> {
        match self.pending.remove(account_key) {
            Some(write) => Some(write),
            None => {
                self.draining.remove(account_key);
                None
            }
        }
    }

    /// Record that `seq` durably committed for `account_key` (monotonic; a
    /// late-completing lower sequence never lowers the high-water mark).
    pub(super) fn record_committed(&mut self, account_key: &str, seq: u64) {
        let entry = self
            .committed_seq
            .entry(account_key.to_owned())
            .or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
        if self
            .failed
            .get(account_key)
            .is_some_and(|(failed_seq, _)| *failed_seq <= seq)
        {
            self.failed.remove(account_key);
        }
    }

    pub(super) fn record_failed(&mut self, account_key: &str, seq: u64, error: String) {
        let entry = self
            .failed
            .entry(account_key.to_owned())
            .or_insert_with(|| (seq, error.clone()));
        if seq >= entry.0 {
            *entry = (seq, error);
        }
    }

    /// The latest not-yet-drained snapshot JSON for `account_key`, if any.
    /// Read-your-writes: a synchronous read must see the newest enqueued blob
    /// even before the async drain has committed it to the durable backend's
    /// in-memory cache. `pending` holds at most the coalesced latest per key, so
    /// this is exactly the value a subsequent read should observe.
    pub(super) fn peek(&self, account_key: &str) -> Option<String> {
        self.pending
            .get(account_key)
            .map(|write| write.json.clone())
    }

    /// Highest durably-committed sequence for `account_key` (0 when none).
    /// The waitable durable barrier reads this to know when a remote-dependency
    /// snapshot has truly landed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn committed_seq(&self, account_key: &str) -> u64 {
        self.committed_seq.get(account_key).copied().unwrap_or(0)
    }

    pub(super) fn barrier_status(
        &self,
        account_key: &str,
        seq: u64,
    ) -> AccountPersistBarrierStatus {
        if self.committed_seq(account_key) >= seq {
            return AccountPersistBarrierStatus::Committed;
        }
        if !self.draining.contains(account_key)
            && !self.pending.contains_key(account_key)
            && let Some((failed_seq, error)) = self.failed.get(account_key)
            && *failed_seq >= seq
        {
            return AccountPersistBarrierStatus::Failed(error.clone());
        }
        AccountPersistBarrierStatus::Pending
    }
}

// ── wasm driver ──────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod wasm_driver {
    use std::sync::{Mutex, OnceLock};

    use super::{
        AccountPersistBarrier, AccountPersistBarrierStatus, AccountPersistQueueState,
        EnqueueOutcome, PendingAccountWrite,
    };

    fn queue() -> &'static Mutex<AccountPersistQueueState> {
        static QUEUE: OnceLock<Mutex<AccountPersistQueueState>> = OnceLock::new();
        QUEUE.get_or_init(|| Mutex::new(AccountPersistQueueState::default()))
    }

    fn lock() -> std::sync::MutexGuard<'static, AccountPersistQueueState> {
        queue()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn changes() -> &'static tokio::sync::watch::Sender<u64> {
        static CHANGES: OnceLock<tokio::sync::watch::Sender<u64>> = OnceLock::new();
        CHANGES.get_or_init(|| tokio::sync::watch::channel(0).0)
    }

    fn notify_change() {
        changes().send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    /// Enqueue a durable persist of the account-state `json` under the frozen
    /// `account_key`. No-op before the IndexedDB tier is ready (fail closed:
    /// the value stays in the live `cached` state and is flushed by the boot
    /// hydration once the tier initialises). Coalesces to the latest snapshot
    /// per account and runs exactly one drain per account key.
    pub(crate) fn enqueue_account_state_persist(account_key: String, json: String) {
        if !crate::secure_key_store::wasm_secure_store_ready() {
            return;
        }
        let enqueued = lock().enqueue(account_key.clone(), json);
        if matches!(enqueued.outcome, EnqueueOutcome::StartDrain) {
            wasm_bindgen_futures::spawn_local(drain_account(account_key));
        }
    }

    pub(crate) fn enqueue_account_state_persist_barrier(
        account_key: String,
        json: String,
    ) -> anyhow::Result<AccountPersistBarrier> {
        if !crate::secure_key_store::wasm_secure_store_ready() {
            anyhow::bail!("secure account-state store is not ready");
        }
        let enqueued = lock().enqueue(account_key.clone(), json);
        if matches!(enqueued.outcome, EnqueueOutcome::StartDrain) {
            wasm_bindgen_futures::spawn_local(drain_account(account_key.clone()));
        }
        Ok(AccountPersistBarrier {
            account_key,
            seq: enqueued.seq,
        })
    }

    /// The latest enqueued-but-not-yet-committed account-state JSON for
    /// `account_key`, if a durable write is still in the queue. `read_account_state`
    /// consults this before the durable backend cache so a synchronous read
    /// observes this session's most recent flush (read-your-writes) even while
    /// the async drain is still in flight.
    pub(crate) fn pending_account_state_json(account_key: &str) -> Option<String> {
        lock().peek(account_key)
    }

    async fn drain_account(account_key: String) {
        loop {
            let next = { lock().take_next(&account_key) };
            let Some(PendingAccountWrite { seq, json }) = next else {
                notify_change();
                break;
            };
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            match store.store_secret_durable(&account_key, &json).await {
                Ok(()) => {
                    lock().record_committed(&account_key, seq);
                    notify_change();
                }
                Err(error) => {
                    // The snapshot was removed from the queue but `cached` still
                    // holds it, so the next flush re-enqueues the latest state.
                    // Mirrors the fire-and-forget failure mode of the secure
                    // store's own sync writes.
                    let error = error.to_string();
                    lock().record_failed(&account_key, seq, error.clone());
                    notify_change();
                    tracing::warn!(
                        error = %error,
                        account_key = %account_key,
                        "account state durable IndexedDB persist failed (will retry on next flush)"
                    );
                }
            }
        }
    }

    pub(super) async fn wait_for_account_state_persist(
        account_key: &str,
        seq: u64,
    ) -> anyhow::Result<()> {
        let mut changes = changes().subscribe();
        loop {
            // Do not retain the synchronous queue lock while awaiting the
            // notifier. The drain must acquire the same lock to publish the
            // terminal status that wakes this waiter.
            let status = { lock().barrier_status(account_key, seq) };
            match status {
                AccountPersistBarrierStatus::Committed => return Ok(()),
                AccountPersistBarrierStatus::Failed(error) => {
                    anyhow::bail!("account state durable persist failed: {error}");
                }
                AccountPersistBarrierStatus::Pending => {
                    changes.changed().await.map_err(|_| {
                        anyhow::anyhow!("account state durable persist notifier closed")
                    })?;
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use wasm_driver::{
    enqueue_account_state_persist, enqueue_account_state_persist_barrier,
    pending_account_state_json,
};

// ── wasm boot-time hydration ──────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod wasm_bootstrap {
    use std::sync::atomic::Ordering;

    use super::super::LocalStateStore;
    use super::{
        ClientLocalState, merge_persisted_into_live, merge_secure_session_grant_into_live,
    };

    impl LocalStateStore {
        /// Hydrate the active account's main state from the IndexedDB entry
        /// into `cached`, reconciling with any live writes made
        /// before the durable tier was ready (live wins, stored fills gaps). Must
        /// run before `secure_store_bootstrap_ready` is published so the account
        /// state is authoritative before session/connect starts. Persists the
        /// merged result so IndexedDB reflects any pre-init live writes.
        pub(crate) fn hydrate_active_account_state_from_secure_store(
            &mut self,
            _secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        ) {
            self.ensure_cached_loaded();
            let effective_did = self.effective_account_key();
            // The root key cannot prove a PrincipalAuthorityKey, so it is not
            // an acceptable source for restoring an account-local session
            // secret. Session credentials are committed explicitly before
            // publication and are never repaired by account-state hydration.
            let secure_grant = None;
            let Some(stored) = self.read_account_state(&effective_did) else {
                // No durable entry yet; keep the live state and mark loaded so the
                // first flush persists it under the active account key.
                merge_secure_session_grant_into_live(&mut self.cached, secure_grant);
                self.loaded.store(true, Ordering::Relaxed);
                let _ = self.flush();
                return;
            };
            let live = std::mem::replace(&mut self.cached, ClientLocalState::default());
            self.cached = merge_persisted_into_live(live, stored);
            merge_secure_session_grant_into_live(&mut self.cached, secure_grant);
            self.loaded.store(true, Ordering::Relaxed);
            let _ = self.flush();
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) async fn run_browser_account_persist_fault_contract() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::secure_key_store::{IndexedDbSecureKeyStore, SecureKeyStore};

    fn state_json(cursor: &str, seen: &[&str]) -> anyhow::Result<String> {
        let mut state = ClientLocalState {
            sync_cursor: Some(cursor.to_owned()),
            ..ClientLocalState::default()
        };
        state.client_core_seen_event_ids = seen.iter().map(|value| (*value).to_owned()).collect();
        serde_json::to_string(&state).context("encode browser account state")
    }

    let service = format!("account-persist-contract-{}", js_sys::Date::now());
    let store = IndexedDbSecureKeyStore::new_async(&service)
        .await
        .context("open browser account store")?;
    let key_a = "inkson.local_state.v1.account.ak:did_core:example:contract-a";
    let key_b = "inkson.local_state.v1.account.ak:did_core:example:contract-b";
    let mut queue = AccountPersistQueueState::default();

    queue.enqueue(key_a.to_owned(), state_json("sx:a1", &["a1"])?);
    queue.enqueue(key_a.to_owned(), state_json("sx:a2", &["a1", "a2"])?);
    let latest_a = queue.enqueue(key_a.to_owned(), state_json("sx:a3", &["a1", "a2", "a3"])?);
    let b = queue.enqueue(key_b.to_owned(), state_json("sx:b1", &["b1"])?);
    let write_a = queue.take_next(key_a).context("take coalesced account a")?;
    let write_b = queue.take_next(key_b).context("take account b")?;
    anyhow::ensure!(write_a.seq == latest_a.seq, "rapid writes did not coalesce");

    store
        .store_secret_durable(key_b, &write_b.json)
        .await
        .context("commit account b first")?;
    queue.record_committed(key_b, write_b.seq);
    store
        .store_secret_durable(key_a, &write_a.json)
        .await
        .context("commit account a second")?;
    queue.record_committed(key_a, write_a.seq);
    anyhow::ensure!(
        queue.barrier_status(key_a, latest_a.seq) == AccountPersistBarrierStatus::Committed
            && queue.barrier_status(key_b, b.seq) == AccountPersistBarrierStatus::Committed,
        "out-of-order account commits did not satisfy their own barriers"
    );
    drop(store);

    let reopened = IndexedDbSecureKeyStore::new_async(&service)
        .await
        .context("reload browser account store")?;
    let state_a: ClientLocalState = serde_json::from_str(
        &reopened
            .get_secret(key_a)?
            .context("reloaded account a is missing")?,
    )
    .context("decode reloaded account a")?;
    let state_b: ClientLocalState = serde_json::from_str(
        &reopened
            .get_secret(key_b)?
            .context("reloaded account b is missing")?,
    )
    .context("decode reloaded account b")?;
    anyhow::ensure!(
        state_a.sync_cursor.as_deref() == Some("sx:a3")
            && state_a.client_core_seen_event_ids.len() == 3,
        "reload lost the newest cursor or dedupe window"
    );
    anyhow::ensure!(
        state_b.sync_cursor.as_deref() == Some("sx:b1"),
        "account switch/isolation mixed account state"
    );

    let failure_service = format!("account-persist-failure-{}", js_sys::Date::now());
    let failed_store = IndexedDbSecureKeyStore::new_async(&failure_service)
        .await
        .context("open failure-injection store")?;
    failed_store
        .store_secret_durable(key_a, &state_json("sx:stable", &["stable"])?)
        .await
        .context("seed stable account state")?;
    failed_store.close_database_for_test();
    let failed = queue.enqueue(key_a.to_owned(), state_json("sx:failed", &["failed"])?);
    let failed_write = queue
        .take_next(key_a)
        .context("take injected failure write")?;
    let error = match failed_store
        .store_secret_durable(key_a, &failed_write.json)
        .await
    {
        Ok(()) => anyhow::bail!("closed IndexedDB unexpectedly accepted a write"),
        Err(error) => error,
    };
    queue.record_failed(key_a, failed_write.seq, error.to_string());
    anyhow::ensure!(
        queue.take_next(key_a).is_none(),
        "failed drain did not stop"
    );
    anyhow::ensure!(
        matches!(
            queue.barrier_status(key_a, failed.seq),
            AccountPersistBarrierStatus::Failed(_)
        ),
        "failed write did not publish terminal failure"
    );
    let retry_store = IndexedDbSecureKeyStore::new_async(&failure_service)
        .await
        .context("reopen failure-injection store")?;
    let retry = queue.enqueue(key_a.to_owned(), state_json("sx:retry", &["retry"])?);
    let retry_write = queue.take_next(key_a).context("take retry write")?;
    retry_store
        .store_secret_durable(key_a, &retry_write.json)
        .await
        .context("commit retry")?;
    queue.record_committed(key_a, retry_write.seq);
    anyhow::ensure!(
        queue.barrier_status(key_a, retry.seq) == AccountPersistBarrierStatus::Committed,
        "retry did not clear the older failure"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_grant(jwt: &str) -> crate::state::PersistedSessionGrant {
        crate::state::PersistedSessionGrant {
            grant_jwt: jwt.to_owned(),
            session_private_key_pem: String::new(),
            grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".to_owned(),
            audience: "ak:did_core:webvh:z6mkfixture:soland.example".to_owned(),
            principal_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
            )
            .unwrap(),
            device_id: arkret_sdk::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            principal_server_url: url::Url::parse("https://soland.example").unwrap(),
            grant_expires_at: None,
            stored_at: chrono::Utc::now(),
        }
    }

    fn state_with_cursor(cursor: &str) -> ClientLocalState {
        ClientLocalState {
            sync_cursor: Some(cursor.to_owned()),
            ..ClientLocalState::default()
        }
    }

    #[test]
    fn merge_adopts_stored_when_live_is_default() {
        let stored = state_with_cursor("sx:stored");
        let merged = merge_persisted_into_live(ClientLocalState::default(), stored.clone());
        assert_eq!(merged, stored);
    }

    #[test]
    fn merge_keeps_live_when_stored_is_default() {
        let live = state_with_cursor("sx:live");
        let merged = merge_persisted_into_live(live.clone(), ClientLocalState::default());
        assert_eq!(merged, live);
    }

    #[test]
    fn secure_session_grant_fills_hydrated_state_but_never_replaces_live_grant() {
        let mut hydrated = ClientLocalState::default();
        merge_secure_session_grant_into_live(&mut hydrated, Some(session_grant("stored")));
        assert_eq!(
            hydrated
                .session_grant
                .as_ref()
                .map(|grant| grant.grant_jwt.as_str()),
            Some("stored")
        );

        merge_secure_session_grant_into_live(&mut hydrated, Some(session_grant("stale")));
        assert_eq!(
            hydrated
                .session_grant
                .as_ref()
                .map(|grant| grant.grant_jwt.as_str()),
            Some("stored")
        );
    }

    #[test]
    fn merge_prefers_live_scalar_but_unions_stored_only_map_entries() {
        let mut live = state_with_cursor("sx:live");
        live.realm_tree_projections.insert(
            "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned(),
            serde_json::json!({"name": "A-live"}),
        );

        let mut stored = state_with_cursor("sx:stored");
        // Same-key projection: live must win.
        stored.realm_tree_projections.insert(
            "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned(),
            serde_json::json!({"name": "A-stored"}),
        );
        // Stored-only projection: must be recovered into the merge.
        stored.realm_tree_projections.insert(
            "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned(),
            serde_json::json!({"name": "B-stored"}),
        );
        // Stored-only cursor entry: must be recovered.
        stored.realm_events_cursors.insert(
            "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned(),
            "cursor-b".to_owned(),
        );

        let merged = merge_persisted_into_live(live, stored);

        // Live wins the scalar and the shared projection key.
        assert_eq!(merged.sync_cursor.as_deref(), Some("sx:live"));
        assert_eq!(
            merged.realm_tree_projections["ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"]
                ["name"],
            "A-live"
        );
        // Stored-only entries are recovered.
        assert_eq!(
            merged.realm_tree_projections["ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo"]
                ["name"],
            "B-stored"
        );
        assert_eq!(
            merged
                .realm_events_cursors
                .get("ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo")
                .map(String::as_str),
            Some("cursor-b")
        );
    }

    #[test]
    fn merge_preserves_live_memory_only_plaintext_sidecars() {
        let mut live = state_with_cursor("sx:live");
        live.mls_decrypted_plaintext
            .entry("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned())
            .or_default()
            .insert("digest-1".to_owned(), "plaintext-1".to_owned());

        let stored = state_with_cursor("sx:stored");
        let merged = merge_persisted_into_live(live, stored);

        // The skip_serializing sidecar survived the JSON round-trip merge.
        assert_eq!(
            merged.mls_decrypted_plaintext["ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"]
                ["digest-1"],
            "plaintext-1"
        );
    }

    #[test]
    fn queue_coalesces_to_latest_pending_snapshot() {
        let mut queue = AccountPersistQueueState::default();
        let key = "acct".to_owned();

        let first = queue.enqueue(key.clone(), "v1".to_owned());
        assert_eq!(first.outcome, EnqueueOutcome::StartDrain);
        assert_eq!(first.seq, 1);
        // Two more writes arrive before the drain starts consuming.
        let second = queue.enqueue(key.clone(), "v2".to_owned());
        assert_eq!(second.outcome, EnqueueOutcome::AlreadyDraining);
        let third = queue.enqueue(key.clone(), "v3".to_owned());
        assert_eq!(third.outcome, EnqueueOutcome::AlreadyDraining);

        // Read-your-writes: peek observes the latest pending snapshot before it
        // is drained to the durable backend.
        assert_eq!(queue.peek(&key).as_deref(), Some("v3"));

        // The drain sees only the latest snapshot, with the latest sequence.
        let taken = queue.take_next(&key).expect("pending write");
        assert_eq!(taken.json, "v3");
        assert_eq!(taken.seq, third.seq);
        assert!(first.seq < second.seq && second.seq < third.seq);
        // Once drained, nothing is pending to observe.
        assert!(queue.peek(&key).is_none());
        // Nothing else pending → drain ends and clears its flag.
        assert!(queue.take_next(&key).is_none());
    }

    #[test]
    fn queue_reports_start_drain_again_after_drain_drains_dry() {
        let mut queue = AccountPersistQueueState::default();
        let key = "acct".to_owned();

        let first = queue.enqueue(key.clone(), "v1".to_owned());
        assert_eq!(first.outcome, EnqueueOutcome::StartDrain);
        assert_eq!(queue.take_next(&key).map(|w| w.json), Some("v1".to_owned()));
        assert!(queue.take_next(&key).is_none());

        // A write after the drain drained dry must start a fresh drain.
        let second = queue.enqueue(key.clone(), "v2".to_owned());
        assert_eq!(second.outcome, EnqueueOutcome::StartDrain);
        assert!(second.seq > first.seq);
    }

    #[test]
    fn queue_isolates_accounts_and_tracks_committed_high_water_mark() {
        let mut queue = AccountPersistQueueState::default();
        let a = "acct-a".to_owned();
        let b = "acct-b".to_owned();

        let a_enqueued = queue.enqueue(a.clone(), "a1".to_owned());
        assert_eq!(a_enqueued.outcome, EnqueueOutcome::StartDrain);
        // A different account starts its own independent drain.
        let b_enqueued = queue.enqueue(b.clone(), "b1".to_owned());
        assert_eq!(b_enqueued.outcome, EnqueueOutcome::StartDrain);

        let a_write = queue.take_next(&a).expect("a pending");
        queue.record_committed(&a, a_write.seq);
        assert_eq!(queue.committed_seq(&a), a_write.seq);
        // Account b's commit is independent of a's.
        assert_eq!(queue.committed_seq(&b), 0);

        // A late lower sequence never lowers the high-water mark.
        queue.record_committed(&a, 0);
        assert_eq!(queue.committed_seq(&a), a_write.seq);
    }

    #[test]
    fn barrier_is_satisfied_by_a_superseding_commit() {
        let mut queue = AccountPersistQueueState::default();
        let key = "acct".to_owned();
        let first = queue.enqueue(key.clone(), "v1".to_owned());
        let second = queue.enqueue(key.clone(), "v2".to_owned());

        assert_eq!(
            queue.barrier_status(&key, first.seq),
            AccountPersistBarrierStatus::Pending
        );
        let write = queue.take_next(&key).expect("coalesced write");
        assert_eq!(write.seq, second.seq);
        queue.record_committed(&key, write.seq);

        assert_eq!(
            queue.barrier_status(&key, first.seq),
            AccountPersistBarrierStatus::Committed
        );
        assert_eq!(
            queue.barrier_status(&key, second.seq),
            AccountPersistBarrierStatus::Committed
        );
    }

    #[test]
    fn barrier_reports_terminal_write_failure_after_drain_stops() {
        let mut queue = AccountPersistQueueState::default();
        let key = "acct".to_owned();
        let enqueued = queue.enqueue(key.clone(), "v1".to_owned());
        let write = queue.take_next(&key).expect("pending write");
        queue.record_failed(&key, write.seq, "disk full".to_owned());

        assert_eq!(
            queue.barrier_status(&key, enqueued.seq),
            AccountPersistBarrierStatus::Pending
        );
        assert!(queue.take_next(&key).is_none());
        assert_eq!(
            queue.barrier_status(&key, enqueued.seq),
            AccountPersistBarrierStatus::Failed("disk full".to_owned())
        );
    }

    #[test]
    fn newer_commit_clears_an_older_terminal_failure() {
        let mut queue = AccountPersistQueueState::default();
        let key = "acct".to_owned();
        let failed = queue.enqueue(key.clone(), "v1".to_owned());
        let write = queue.take_next(&key).expect("first write");
        queue.record_failed(&key, write.seq, "disk full".to_owned());
        assert!(queue.take_next(&key).is_none());

        let retry = queue.enqueue(key.clone(), "v2".to_owned());
        let write = queue.take_next(&key).expect("retry write");
        queue.record_committed(&key, write.seq);

        assert!(retry.seq > failed.seq);
        assert_eq!(
            queue.barrier_status(&key, retry.seq),
            AccountPersistBarrierStatus::Committed
        );
    }
}
