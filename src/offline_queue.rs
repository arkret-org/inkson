//! Persistent operation queue with exponential-backoff retry.
//!
//! Sits next to [`crate::offline`] (which is an HTTP-replay queue keyed
//! by `OfflineQueue::QueuedOperation`) but solves a different problem:
//! a typed, file-backed FIFO of opaque payloads that survives process
//! restarts, tracks per-entry attempt counts, and exposes a retry
//! schedule the caller can poll. Designed to back chime's
//! `BackgroundFetchDriver` so wakeups that arrive while the network is
//! down still leave a durable record on disk.
//!
//! ## Storage
//!
//! The queue persists to a single JSON file under
//! `OfflineOpQueue::new(root, …)`'s `root` directory. Writes are
//! atomic (`write-temp + rename`) so an interrupted persist does not
//! corrupt the prior state. The file format is intentionally readable
//! (`serde_json::to_string_pretty`) so developers can inspect what's
//! pending without a custom tool.
//!
//! No external database / sled dependency — the queue is small
//! (1.0-milestone usage is bounded by interactive-user scale) and a
//! single JSON file is sufficient. If the queue grows beyond a few
//! thousand entries we'd revisit, but that's not the local 1.0
//! requirement.
//!
//! ## Retry policy
//!
//! Each entry tracks an `attempts: u32` counter. The next-retry timer
//! is `base_delay * 2.pow(attempts)` capped at `max_delay`, with
//! ±10% jitter applied multiplicatively so a fleet of clients does
//! not synchronise their retry storms.
//!
//! Defaults: `base = 1s`, `max = 5min`. Override via
//! [`OfflineOpQueue::with_backoff`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Opaque payload kind. The queue itself does not interpret the
/// payload; the kind is purely a hint the driver can use to route
/// the bytes to the right handler when it pops the entry.
///
/// Variants cover the 1.0 yougen surfaces that need durable retry:
///
/// * [`OpKind::BackgroundFetch`] — chime blind-wakeup → background sync. The payload is the wakeup
///   hint as JSON.
/// * [`OpKind::PushTokenRotate`] — register-device retry after a token rotation while the gateway
///   was unreachable.
/// * [`OpKind::EventSubmit`] — durable event submission (the higher-level
///   [`crate::offline::QueuedOperation`] replay also covers this; we keep the kind here so a single
///   driver can route events from both paths).
/// * [`OpKind::Generic`] — escape hatch for callers that haven't yet minted a typed variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    BackgroundFetch,
    PushTokenRotate,
    EventSubmit,
    Generic,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackgroundFetch => "background_fetch",
            Self::PushTokenRotate => "push_token_rotate",
            Self::EventSubmit => "event_submit",
            Self::Generic => "generic",
        }
    }
}

/// A single persisted operation. The `id` is monotonic per-queue —
/// the queue assigns it on `enqueue` so callers cannot duplicate it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineOp {
    pub id: u64,
    pub kind: OpKind,
    pub payload: Vec<u8>,
    /// Unix epoch milliseconds at the moment of enqueue. Stored as
    /// millis (`u64`) rather than `SystemTime` so the JSON file is
    /// portable across hosts with different `SystemTime`
    /// representations.
    pub created_at_unix_ms: u64,
    pub attempts: u32,
    /// Unix epoch milliseconds before which this entry should not be
    /// retried. Set on `mark_failure` per the backoff policy; defaults
    /// to `0` (immediately retryable).
    pub next_attempt_after_unix_ms: u64,
}

impl OfflineOp {
    /// Pseudo-`SystemTime` accessor for callers that prefer
    /// the time type. Returns `UNIX_EPOCH + created_at`.
    pub fn created_at(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(self.created_at_unix_ms)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute the next-attempt delay given the attempt count, base
/// delay, and max delay. Public for unit testability — the queue
/// uses it internally on `mark_failure`.
pub fn backoff_delay(attempts: u32, base: Duration, max: Duration) -> Duration {
    // `2.pow(attempts)` saturates at u32::MAX which * base nanos
    // would overflow long before then. Cap at 32 to keep the math
    // small.
    let shift = attempts.min(31);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base_nanos = base.as_nanos() as u64;
    let raw_nanos = base_nanos.saturating_mul(multiplier);
    let raw = Duration::from_nanos(raw_nanos);
    if raw > max { max } else { raw }
}

/// Apply ±10% jitter to `delay`. The jitter is multiplicative and
/// uniformly distributed across the [-10%, +10%] window. Returns
/// `delay` unchanged when the random draw fails (which on `getrandom`
/// is essentially impossible outside no_std contexts).
pub fn jittered(delay: Duration) -> Duration {
    let mut buf = [0u8; 2];
    if getrandom::fill(&mut buf).is_err() {
        return delay;
    }
    // [0, 65535] → [-10%, +10%] of the delay.
    let raw = u16::from_le_bytes(buf) as f64 / u16::MAX as f64;
    let factor = 0.9 + 0.2 * raw; // [0.9, 1.1]
    let nanos = (delay.as_nanos() as f64 * factor) as u64;
    Duration::from_nanos(nanos)
}

#[derive(Debug)]
pub enum OfflineQueueError {
    /// Underlying filesystem error during read/write.
    Io(std::io::Error),
    /// JSON serialisation / parsing error on the persisted file.
    Json(serde_json::Error),
    /// Lock poisoned because another thread panicked while holding it.
    LockPoisoned,
    /// `pop` was called with no eligible entries (all entries are
    /// either still in their backoff window or the queue is empty).
    Empty,
    /// `mark_success` / `mark_failure` referenced an id that no
    /// longer exists (already popped, or never enqueued).
    UnknownId(u64),
}

impl std::fmt::Display for OfflineQueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "offline queue io: {err}"),
            Self::Json(err) => write!(f, "offline queue json: {err}"),
            Self::LockPoisoned => write!(f, "offline queue lock poisoned"),
            Self::Empty => write!(f, "offline queue has no eligible entry"),
            Self::UnknownId(id) => write!(f, "offline queue unknown id {id}"),
        }
    }
}

impl std::error::Error for OfflineQueueError {}

impl From<std::io::Error> for OfflineQueueError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for OfflineQueueError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// On-disk representation of the queue. Versioned so a future schema
/// change can bump `version` and ignore older files instead of
/// silently mis-deserialising.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDiskQueue {
    version: u32,
    next_id: u64,
    entries: Vec<OfflineOp>,
}

impl OnDiskQueue {
    const CURRENT_VERSION: u32 = 1;

    fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            next_id: 1,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OfflineQueueBackoff {
    pub base: Duration,
    pub max: Duration,
}

impl Default for OfflineQueueBackoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(5 * 60),
        }
    }
}

/// Trait the chime `BackgroundFetchDriver` (or any other consumer)
/// can target instead of holding a concrete [`OfflineOpQueue`].
///
/// Keeping the trait narrow (no async, no error type) lets the chime
/// adapter wire one of these in without pulling tokio into its
/// dependency closure. The driver typically:
///
///   1. Calls [`enqueue`](OfflineQueueDriver::enqueue) on the wakeup path to record the hint.
///   2. Calls [`pop`](OfflineQueueDriver::pop) on a worker loop to drain eligible entries.
///   3. Calls [`mark_success`](OfflineQueueDriver::mark_success) or
///      [`mark_failure`](OfflineQueueDriver::mark_failure) once the handler resolves.
pub trait OfflineQueueDriver: Send + Sync {
    /// Append a new entry. Returns the assigned id.
    fn enqueue(&self, kind: OpKind, payload: Vec<u8>) -> Result<u64, OfflineQueueError>;

    /// Return the oldest eligible entry (whose
    /// `next_attempt_after_unix_ms` is in the past). Entry stays in
    /// the queue — the caller must follow up with
    /// `mark_success` or `mark_failure`.
    fn pop(&self) -> Result<Option<OfflineOp>, OfflineQueueError>;

    /// Remove the entry with the given id. Returns
    /// `Err(UnknownId)` if the entry is absent.
    fn mark_success(&self, id: u64) -> Result<(), OfflineQueueError>;

    /// Bump the entry's attempt counter, recompute its
    /// `next_attempt_after_unix_ms` via the backoff policy, and
    /// leave it in the queue.
    fn mark_failure(&self, id: u64) -> Result<(), OfflineQueueError>;

    /// Total entries currently in the queue (including ones that are
    /// still in their backoff window).
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// File-backed implementation of [`OfflineQueueDriver`].
#[derive(Clone)]
pub struct OfflineOpQueue {
    inner: Arc<Mutex<OnDiskQueue>>,
    path: PathBuf,
    backoff: OfflineQueueBackoff,
    /// When `true`, writes go to disk; when `false` (the default for
    /// in-memory test instances), the file is never touched. The
    /// constructor [`OfflineOpQueue::new`] sets this to true; the
    /// tests use [`OfflineOpQueue::new_in_memory`] for the false case.
    persistent: bool,
}

impl OfflineOpQueue {
    /// Open / create a queue persisting under
    /// `<root>/offline_queue.json`. The `root` directory must already
    /// exist. Reads the prior queue state if the file exists; starts
    /// from empty otherwise.
    pub fn new(root: &Path) -> Result<Self, OfflineQueueError> {
        let path = root.join("offline_queue.json");
        let inner = if path.exists() {
            let raw = std::fs::read(&path)?;
            let on_disk: OnDiskQueue = serde_json::from_slice(&raw).unwrap_or_else(|_| {
                tracing::warn!(?path, "offline_queue.json failed to parse; starting fresh");
                OnDiskQueue::new()
            });
            on_disk
        } else {
            OnDiskQueue::new()
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            path,
            backoff: OfflineQueueBackoff::default(),
            persistent: true,
        })
    }

    /// In-memory queue with no disk persistence. Used by tests and by
    /// callers that want the API surface without the file overhead.
    pub fn new_in_memory() -> Self {
        Self {
            inner: Arc::new(Mutex::new(OnDiskQueue::new())),
            path: PathBuf::new(),
            backoff: OfflineQueueBackoff::default(),
            persistent: false,
        }
    }

    /// Override the default backoff policy (`base=1s`, `max=5min`).
    pub fn with_backoff(mut self, backoff: OfflineQueueBackoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Path the queue persists to. Empty `PathBuf` when the queue is
    /// in-memory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self, guard: &OnDiskQueue) -> Result<(), OfflineQueueError> {
        if !self.persistent {
            return Ok(());
        }
        let serialised = serde_json::to_vec_pretty(guard)?;
        // Atomic write: temp file + rename. The temp filename
        // includes the queue's own filename so concurrent rename
        // collisions across processes are extremely unlikely.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &serialised)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, OnDiskQueue>, OfflineQueueError> {
        self.inner
            .lock()
            .map_err(|_| OfflineQueueError::LockPoisoned)
    }

    /// Snapshot of every entry currently in the queue (eligible or
    /// not). Returned by value so the caller doesn't hold the lock.
    pub fn snapshot(&self) -> Result<Vec<OfflineOp>, OfflineQueueError> {
        let guard = self.lock()?;
        Ok(guard.entries.clone())
    }
}

impl std::fmt::Debug for OfflineOpQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.inner.lock().map(|g| g.entries.len()).unwrap_or(0);
        f.debug_struct("OfflineOpQueue")
            .field("path", &self.path)
            .field("persistent", &self.persistent)
            .field("entries", &len)
            .finish()
    }
}

impl OfflineQueueDriver for OfflineOpQueue {
    fn enqueue(&self, kind: OpKind, payload: Vec<u8>) -> Result<u64, OfflineQueueError> {
        let mut guard = self.lock()?;
        let id = guard.next_id;
        guard.next_id = guard.next_id.saturating_add(1);
        guard.entries.push(OfflineOp {
            id,
            kind,
            payload,
            created_at_unix_ms: now_unix_ms(),
            attempts: 0,
            next_attempt_after_unix_ms: 0,
        });
        self.persist(&guard)?;
        Ok(id)
    }

    fn pop(&self) -> Result<Option<OfflineOp>, OfflineQueueError> {
        let guard = self.lock()?;
        let now = now_unix_ms();
        // Find the oldest entry whose backoff window has passed.
        // Sort by id ascending (id is monotonic, so FIFO).
        let mut eligible: BTreeMap<u64, &OfflineOp> = BTreeMap::new();
        for entry in &guard.entries {
            if entry.next_attempt_after_unix_ms <= now {
                eligible.insert(entry.id, entry);
            }
        }
        Ok(eligible.into_iter().next().map(|(_, op)| op.clone()))
    }

    fn mark_success(&self, id: u64) -> Result<(), OfflineQueueError> {
        let mut guard = self.lock()?;
        let before = guard.entries.len();
        guard.entries.retain(|op| op.id != id);
        if guard.entries.len() == before {
            return Err(OfflineQueueError::UnknownId(id));
        }
        self.persist(&guard)?;
        Ok(())
    }

    fn mark_failure(&self, id: u64) -> Result<(), OfflineQueueError> {
        let mut guard = self.lock()?;
        let backoff = self.backoff.clone();
        let Some(entry) = guard.entries.iter_mut().find(|op| op.id == id) else {
            return Err(OfflineQueueError::UnknownId(id));
        };
        entry.attempts = entry.attempts.saturating_add(1);
        let delay = jittered(backoff_delay(entry.attempts, backoff.base, backoff.max));
        let now = now_unix_ms();
        entry.next_attempt_after_unix_ms = now.saturating_add(delay.as_millis() as u64);
        self.persist(&guard)?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.entries.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backoff is `base * 2^attempts` capped at `max`. attempts=0
    /// yields `base`, attempts=1 yields `2*base`, attempts=20 saturates
    /// at `max`.
    #[test]
    fn backoff_delay_caps_at_max() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(backoff_delay(0, base, max), Duration::from_secs(1));
        assert_eq!(backoff_delay(1, base, max), Duration::from_secs(2));
        assert_eq!(backoff_delay(2, base, max), Duration::from_secs(4));
        // 2^20 seconds is way past the 60s cap.
        assert_eq!(backoff_delay(20, base, max), max);
    }

    /// Jitter stays within ±10% of the input — sanity check that the
    /// random factor is bounded, not unbounded.
    #[test]
    fn jittered_delay_stays_within_ten_percent() {
        let base = Duration::from_secs(10);
        for _ in 0..32 {
            let j = jittered(base);
            let nanos = j.as_nanos() as f64;
            let base_nanos = base.as_nanos() as f64;
            let ratio = nanos / base_nanos;
            assert!(
                (0.9..=1.1).contains(&ratio),
                "jitter ratio out of bounds: {ratio}"
            );
        }
    }

    #[test]
    fn enqueue_assigns_monotonic_ids() {
        let queue = OfflineOpQueue::new_in_memory();
        let id_a = queue.enqueue(OpKind::Generic, b"a".to_vec()).unwrap();
        let id_b = queue.enqueue(OpKind::Generic, b"b".to_vec()).unwrap();
        let id_c = queue.enqueue(OpKind::Generic, b"c".to_vec()).unwrap();
        assert!(id_a < id_b && id_b < id_c);
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn pop_returns_oldest_eligible_entry() {
        let queue = OfflineOpQueue::new_in_memory();
        let id_a = queue
            .enqueue(OpKind::BackgroundFetch, b"first".to_vec())
            .unwrap();
        let _id_b = queue
            .enqueue(OpKind::PushTokenRotate, b"second".to_vec())
            .unwrap();
        let popped = queue.pop().unwrap().expect("eligible");
        assert_eq!(popped.id, id_a);
        // Still in queue until mark_success.
        assert_eq!(queue.len(), 2);
        queue.mark_success(id_a).unwrap();
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn mark_failure_pushes_backoff_window_into_future() {
        let queue = OfflineOpQueue::new_in_memory().with_backoff(OfflineQueueBackoff {
            base: Duration::from_secs(60),
            max: Duration::from_secs(300),
        });
        let id = queue
            .enqueue(OpKind::EventSubmit, b"payload".to_vec())
            .unwrap();
        queue.mark_failure(id).unwrap();
        let entry = queue
            .snapshot()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert_eq!(entry.attempts, 1);
        // Next attempt should be in the future by at least
        // 0.9 * 60s = 54s (allowing for ±10% jitter).
        let now = now_unix_ms();
        let delta_ms = entry.next_attempt_after_unix_ms.saturating_sub(now);
        assert!(
            delta_ms >= 54_000,
            "expected ≥54s backoff window, got {delta_ms}ms"
        );
        // pop now returns None because the only entry is in its
        // backoff window.
        assert!(queue.pop().unwrap().is_none());
    }

    #[test]
    fn mark_success_unknown_id_returns_error() {
        let queue = OfflineOpQueue::new_in_memory();
        let err = queue.mark_success(999).unwrap_err();
        assert!(matches!(err, OfflineQueueError::UnknownId(999)));
    }

    #[test]
    fn mark_failure_unknown_id_returns_error() {
        let queue = OfflineOpQueue::new_in_memory();
        let err = queue.mark_failure(999).unwrap_err();
        assert!(matches!(err, OfflineQueueError::UnknownId(999)));
    }

    /// Persistence round-trip: enqueue → drop → reopen → snapshot
    /// returns the same entries with the same ids and attempt counts.
    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("yougen-offline-queue-test-{}", now_unix_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let id;
        {
            let queue = OfflineOpQueue::new(&dir).unwrap();
            id = queue
                .enqueue(OpKind::BackgroundFetch, b"hello".to_vec())
                .unwrap();
            queue.mark_failure(id).unwrap();
        }
        // Reopen from disk.
        let queue = OfflineOpQueue::new(&dir).unwrap();
        let entries = queue.snapshot().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].kind, OpKind::BackgroundFetch);
        assert_eq!(entries[0].attempts, 1);
        assert_eq!(entries[0].payload, b"hello");
        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The trait object surface compiles + dispatches the same way
    /// the concrete type does — the chime BackgroundFetchDriver
    /// adapter targets `dyn OfflineQueueDriver`.
    #[test]
    fn trait_object_dispatch_works() {
        let queue = OfflineOpQueue::new_in_memory();
        let driver: Arc<dyn OfflineQueueDriver> = Arc::new(queue);
        let id = driver.enqueue(OpKind::Generic, b"x".to_vec()).unwrap();
        assert_eq!(driver.len(), 1);
        driver.mark_success(id).unwrap();
        assert!(driver.is_empty());
    }
}
