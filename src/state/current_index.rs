//! Demand-loaded current selectors, staged independently of the account blob.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use arkret_sdk::AccountId;
use arkret_sdk::sync::AccountSubscribeFrame;
use arkret_sdk::sync::RealmDetailBaseline;
use arkret_wire::{CurrentRevision, CurrentSelector, TypedCurrentResult};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[cfg(not(target_arch = "wasm32"))]
#[path = "current_index/native.rs"]
mod platform;
#[cfg(target_arch = "wasm32")]
#[path = "current_index/wasm.rs"]
mod platform;

// The browser regressions of this index are an integration test target, which
// cannot reach a crate-private type; this is their only entry point.
#[cfg(target_arch = "wasm32")]
#[path = "current_index/wasm_harness.rs"]
pub mod wasm_harness;

pub(crate) const CURRENT_PREFIX: &str = "inkson.current.v1/";
const PAGE_LIMIT: usize = 100;

/// Index grouping of one typed current selector.
///
/// The wire selector union is closed and already names its domain coordinate;
/// this is only the paging bucket the local index stores rows under, so a
/// product view can read "every member row of this Realm" without scanning
/// every selector. It is host state and never reaches the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CurrentTarget {
    Realm,
    Strand { strand_id: arkret_sdk::StrandId },
    Member { actor_id: arkret_sdk::ActorId },
    Event { event_id: arkret_sdk::EventId },
    MlsGroup { scope_ref: arkret_sdk::ScopeRef },
}

fn target_of(selector: &CurrentSelector) -> CurrentTarget {
    match selector {
        CurrentSelector::RealmProfile | CurrentSelector::RealmPolicy => CurrentTarget::Realm,
        CurrentSelector::MemberState { actor_id } => CurrentTarget::Member {
            actor_id: actor_id.clone(),
        },
        CurrentSelector::Strand { strand_id } => CurrentTarget::Strand {
            strand_id: strand_id.clone(),
        },
        CurrentSelector::MessageReactions { event_id } => CurrentTarget::Event {
            event_id: event_id.clone(),
        },
        CurrentSelector::MlsGroup { scope_ref } => CurrentTarget::MlsGroup {
            scope_ref: scope_ref.clone(),
        },
    }
}

fn selector_of(entry: &TypedCurrentResult) -> &CurrentSelector {
    match entry {
        TypedCurrentResult::Value { selector, .. }
        | TypedCurrentResult::MessageReactions { selector, .. } => selector,
    }
}

fn revision_of(entry: &TypedCurrentResult) -> &CurrentRevision {
    match entry {
        TypedCurrentResult::Value { revision, .. }
        | TypedCurrentResult::MessageReactions { revision, .. } => revision,
    }
}

fn selector_key(selector: &CurrentSelector) -> anyhow::Result<String> {
    Ok(String::from_utf8(
        arkret_sdk::canonical::canonical_json_bytes(selector)?,
    )?)
}

/// Small durable per-Realm metadata, independent of the number of selectors.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct CurrentRealmProgress {
    #[serde(default)]
    pub governance_generation: Option<u64>,
    pub baseline: Option<RealmDetailBaseline>,
    pub invalidated_snapshot: Option<String>,
    pub invalidation_revision: u64,
    pub has_invalidation: bool,
    pub needs_refresh: bool,
}

impl CurrentRealmProgress {
    fn invalidate(&mut self, revision: u64) {
        if self.has_invalidation && revision <= self.invalidation_revision {
            return;
        }
        self.has_invalidation = true;
        self.invalidation_revision = revision;
        self.needs_refresh = true;
        self.invalidated_snapshot = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.clone());
    }

    fn reset(&mut self) {
        self.needs_refresh = true;
        self.invalidated_snapshot = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.clone());
    }

    fn begin_governance_generation(&mut self, generation: u64) {
        self.invalidated_snapshot = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.clone());
        self.baseline = None;
        self.needs_refresh = true;
        self.governance_generation = Some(generation);
    }
}

/// A sweep predicate, never a list of every covered selector.
#[derive(Clone, Debug)]
struct CurrentCoverageCleanup {
    snapshot_cursor: String,
}

#[derive(Clone, Debug)]
struct CurrentInstallPlan {
    progress: CurrentRealmProgress,
    writes: Vec<TypedCurrentResult>,
    seen_selectors: Vec<String>,
    cleanup: Option<CurrentCoverageCleanup>,
    /// An invalidated snapshot must not reach secondary product projections.
    discard_frame: bool,
}

/// Validate one replacement while the caller holds only this selector's old
/// row. Returns `(write, seen)`.
fn plan_current_entry(
    previous: &CurrentRealmProgress,
    baseline: Option<&RealmDetailBaseline>,
    entry: &TypedCurrentResult,
    old: Option<&TypedCurrentResult>,
) -> anyhow::Result<(bool, bool)> {
    let complete = baseline.is_some_and(|segment| {
        previous
            .baseline
            .as_ref()
            .is_some_and(|old| old.snapshot_cursor == segment.snapshot_cursor && old.complete)
    });
    let seen = baseline.is_some() && !complete;
    if let Some(old) = old {
        anyhow::ensure!(
            selector_of(old) == selector_of(entry),
            "current row changed its selector"
        );
        let old_revision = revision_of(old);
        let new_revision = revision_of(entry);
        if old_revision.stream_position == new_revision.stream_position {
            anyhow::ensure!(
                old_revision == new_revision,
                "current result forked at the same stream position"
            );
            anyhow::ensure!(
                arkret_sdk::canonical::canonical_json_bytes(old)?
                    == arkret_sdk::canonical::canonical_json_bytes(entry)?,
                "current result changed at the same revision"
            );
            return Ok((false, seen));
        }
        if old_revision.stream_position > new_revision.stream_position {
            return Ok((false, seen));
        }
    }
    Ok((!complete, seen))
}

/// Preflight one Realm entry's baseline transition without changing host state.
fn plan_current_install(
    previous: &CurrentRealmProgress,
    incoming: &arkret_sdk::sync::RealmSyncEntry,
) -> anyhow::Result<CurrentInstallPlan> {
    let mut plan = CurrentInstallPlan {
        progress: previous.clone(),
        writes: Vec::new(),
        seen_selectors: Vec::new(),
        cleanup: None,
        discard_frame: false,
    };
    if incoming.unavailable.is_some() {
        plan.progress.reset();
        return Ok(plan);
    }
    let mut already_complete = false;
    if let Some(segment) = &incoming.baseline {
        segment
            .coverage
            .validate()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        if previous.invalidated_snapshot.as_deref() == Some(segment.snapshot_cursor.as_str())
            || segment.cut_revision < previous.invalidation_revision
        {
            plan.discard_frame = true;
            return Ok(plan);
        }
        if let Some(old) = &previous.baseline
            && old.snapshot_cursor == segment.snapshot_cursor
        {
            anyhow::ensure!(
                old.cut_revision == segment.cut_revision && old.coverage == segment.coverage,
                "current baseline changed its cut or coverage"
            );
            already_complete = old.complete;
        }
        if !already_complete {
            plan.progress.baseline = Some(segment.clone());
            plan.progress.needs_refresh = !segment.complete;
        }
        if segment.complete && segment.coverage.complete_for_authorized_streams && !already_complete
        {
            plan.cleanup = Some(CurrentCoverageCleanup {
                snapshot_cursor: segment.snapshot_cursor.clone(),
            });
        }
    }
    Ok(plan)
}

// Dropping the caller must not release a lease while a platform transaction
// continues running. The independent job owns its lease until all IO completes.
#[cfg(not(target_arch = "wasm32"))]
async fn complete_independently<T: Send + 'static>(
    job: impl std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
) -> anyhow::Result<T> {
    tokio::spawn(job).await?
}

#[cfg(target_arch = "wasm32")]
async fn complete_independently<T: 'static>(
    job: impl std::future::Future<Output = anyhow::Result<T>> + 'static,
) -> anyhow::Result<T> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = sender.send(job.await);
    });
    receiver
        .await
        .map_err(|_| anyhow::anyhow!("current index task ended before completion"))?
}

#[derive(Clone)]
pub(crate) struct CurrentIndex {
    backend: platform::Backend,
    prefix: String,
    generation: Arc<AtomicU64>,
    lease: Arc<Mutex<()>>,
    _shared: Arc<SharedGeneration>,
}

struct SharedGeneration {
    generation: Arc<AtomicU64>,
    lease: Arc<Mutex<()>>,
    poisoned: AtomicBool,
    pending: AtomicU64,
}
static SHARED_INDICES: OnceLock<std::sync::Mutex<BTreeMap<String, Arc<SharedGeneration>>>> =
    OnceLock::new();

pub(crate) struct CurrentStage {
    index: CurrentIndex,
    generation: u64,
    filtered: AccountSubscribeFrame,
    _lease: OwnedMutexGuard<()>,
}

impl CurrentStage {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn filtered_frame(&self) -> &AccountSubscribeFrame {
        &self.filtered
    }
    pub(crate) fn arm_account_commit(&mut self) {
        self.index
            ._shared
            .pending
            .store(self.generation, Ordering::Release);
    }
    /// The caller must first durably commit this generation and account cursor together.
    pub(crate) fn finish(self) {
        self.index
            .generation
            .store(self.generation, Ordering::Release);
        self.index._shared.pending.store(0, Ordering::Release);
    }
}

impl Drop for CurrentStage {
    fn drop(&mut self) {
        if self.index._shared.pending.load(Ordering::Acquire) == self.generation {
            self.index.poison();
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoverageMark {
    snapshot: String,
    /// Rows installed no later than this generation were part of the frozen
    /// baseline cut. Later live rows must not be compared across streams.
    generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RetiredEntry {
    revision: CurrentRevision,
    target: CurrentTarget,
    digest: String,
    generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CleanupTask {
    realm: String,
    after: Option<String>,
    generation: u64,
}

/// One queued per-selector version-compaction task. It carries the Realm
/// because the selector alone does not name one.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PruneTask {
    realm: String,
    selector: CurrentSelector,
}

/// Phases of one reachability cycle over snapshot-scoped `seen` evidence.
/// `Purge` drops the marks of the previous cycle, `Mark` republishes the marks
/// of every live root, and only then may `Sweep` delete.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GcPhase {
    #[default]
    Purge,
    Mark,
    Sweep,
}

/// Durable position of the reachability cycle. The epoch keeps the marks of the
/// running cycle apart from the previous root set, so a stale mark can never be
/// mistaken for current evidence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GcState {
    epoch: u64,
    phase: GcPhase,
    stream: usize,
    cursor: Option<String>,
    reclaimed: bool,
    /// A root was published or retired since this cycle began. The cycle that
    /// observes the change usually only stops marking the orphan; the delete
    /// belongs to the next one, so this keeps that next cycle scheduled.
    dirty: bool,
    idle: bool,
}

/// Rotating position of per-logical-key version compaction over metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct MetaPosition {
    stream: usize,
    cursor: Option<String>,
}

/// Metadata whose historical versions answer no read once a newer committed
/// version exists. Rotation gives each one a share of every maintenance pass.
const META_STREAMS: [&str; 5] = ["progress/", "coverage/", "retired/", "refresh/", "reset/"];
/// Root streams of the mark phase: a realm's installed baseline and every
/// coverage mark a reader can still reach through `strongest_mark`.
const MARK_STREAMS: [&str; 2] = ["progress/", "coverage/"];

#[derive(Clone, Debug)]
pub(crate) struct CurrentTargetPage {
    pub entries: Vec<TypedCurrentResult>,
    // Pagination is owned by the 0540 durable-index follow-up. Keep the cursor
    // in the internal result shape until that reader is wired.
    #[allow(dead_code)]
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub(crate) struct CurrentIndexLocation {
    #[cfg(not(target_arch = "wasm32"))]
    path: std::path::PathBuf,
}

impl super::LocalStateStore {
    pub(crate) fn current_reset_required(&self) -> bool {
        self.cached.current_reset_required
    }
    pub(crate) fn set_current_reset_required(&mut self, required: bool) {
        self.cached.current_reset_required = required;
    }
    pub(crate) fn current_generation(&self) -> u64 {
        self.cached.current_generation
    }
    pub(crate) fn set_current_generation(&mut self, generation: u64) {
        self.cached.current_generation = generation;
    }
    pub(crate) fn current_index_location(&self) -> CurrentIndexLocation {
        CurrentIndexLocation {
            #[cfg(not(target_arch = "wasm32"))]
            path: self.path.with_extension("current.sqlite"),
        }
    }
}

fn hash(value: &impl Serialize) -> anyhow::Result<String> {
    Ok(arkret_sdk::canonical::canonical_sha256(value)?.replace(':', "-"))
}
fn version(generation: u64) -> String {
    format!("{:020}", u64::MAX - generation)
}
fn target_key(target: &CurrentTarget) -> anyhow::Result<String> {
    hash(target)
}
fn member_all_key() -> &'static str {
    "member-all"
}
/// Snapshot cursors reach storage only as this digest, so marks and `seen`
/// keys address the same snapshot without keeping the cursor itself around.
fn snapshot_key(snapshot: &str) -> anyhow::Result<String> {
    hash(&snapshot)
}
/// Split a versioned key into its logical prefix and the generation that wrote
/// it. Versions sort descending, so a page lists each logical key newest first.
fn split_version(key: &str) -> anyhow::Result<(&str, u64)> {
    let cut = key
        .rfind('/')
        .ok_or_else(|| anyhow::anyhow!("current version key has no logical prefix"))?
        + 1;
    Ok((&key[..cut], u64::MAX - key[cut..].parse::<u64>()?))
}

impl CurrentIndex {
    pub(crate) async fn open(
        authority: &AccountId,
        committed_generation: u64,
        location: CurrentIndexLocation,
    ) -> anyhow::Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let location =
            tokio::task::spawn_blocking(move || -> anyhow::Result<CurrentIndexLocation> {
                let path = std::path::absolute(location.path)?;
                let parent = path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("current location lacks parent"))?;
                std::fs::create_dir_all(parent)?;
                let path = if path.exists() {
                    std::fs::canonicalize(path)?
                } else {
                    std::fs::canonicalize(parent)?.join(
                        path.file_name()
                            .ok_or_else(|| anyhow::anyhow!("current location lacks filename"))?,
                    )
                };
                Ok(CurrentIndexLocation { path })
            })
            .await??;
        let prefix = format!("{}{}/", CURRENT_PREFIX, hash(authority)?);
        #[cfg(not(target_arch = "wasm32"))]
        let storage_id = location.path.to_string_lossy().to_string();
        #[cfg(target_arch = "wasm32")]
        let storage_id = "inkson.secret.inkson/entries".to_owned();
        let registry_key = format!("{storage_id}/{prefix}");
        let shared = {
            let mut registry = SHARED_INDICES
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| anyhow::anyhow!("current registry poisoned"))?;
            registry.retain(|_, value| {
                Arc::strong_count(value) > 1 || value.poisoned.load(Ordering::Acquire)
            });
            match registry.get(&registry_key).cloned() {
                Some(shared) => shared,
                None => {
                    let shared = Arc::new(SharedGeneration {
                        generation: Arc::new(AtomicU64::new(committed_generation)),
                        lease: Arc::new(Mutex::new(())),
                        poisoned: AtomicBool::new(false),
                        pending: AtomicU64::new(0),
                    });
                    registry.insert(registry_key, shared.clone());
                    shared
                }
            }
        };
        let _lease = shared.lease.lock().await;
        anyhow::ensure!(
            shared.generation.load(Ordering::Acquire) == committed_generation
                || (shared.poisoned.load(Ordering::Acquire)
                    && shared.pending.load(Ordering::Acquire) == committed_generation),
            "account current pointer differs from active durable generation"
        );
        let backend = platform::Backend::open(location).await?;
        if committed_generation > 0
            && backend
                .get(&format!("{prefix}stage/{}", version(committed_generation)))
                .await?
                .is_none()
        {
            anyhow::bail!("committed current generation is missing its durable manifest");
        }
        Ok(Self {
            backend,
            prefix,
            generation: shared.generation.clone(),
            lease: shared.lease.clone(),
            _shared: shared.clone(),
        })
    }

    pub(crate) fn poison(&self) {
        self._shared.poisoned.store(true, Ordering::Release);
    }
    pub(crate) fn is_poisoned(&self) -> bool {
        self._shared.poisoned.load(Ordering::Acquire)
    }
    /// Call only after the account pointer has been confirmed durable.
    pub(crate) fn confirm_durable_pointer(&self, generation: u64) -> anyhow::Result<()> {
        let current = self.generation.load(Ordering::Acquire);
        let pending = self._shared.pending.load(Ordering::Acquire);
        anyhow::ensure!(
            current == generation
                || (pending == generation && current.checked_add(1) == Some(generation)),
            "durable current pointer differs"
        );
        self.generation.store(generation, Ordering::Release);
        self._shared.pending.store(0, Ordering::Release);
        self._shared.poisoned.store(false, Ordering::Release);
        Ok(())
    }
    async fn latest<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        generation: u64,
    ) -> anyhow::Result<Option<T>> {
        let rows = self
            .backend
            .scan(
                prefix,
                Some(&format!("{prefix}{}", version(generation))),
                None,
                1,
            )
            .await?;
        rows.into_iter()
            .next()
            .map(|(_, bytes)| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }
    async fn latest_generation(&self, prefix: &str, generation: u64) -> anyhow::Result<u64> {
        let rows = self
            .backend
            .keys(
                prefix,
                Some(&format!("{prefix}{}", version(generation))),
                None,
                1,
            )
            .await?;
        rows.first()
            .map(|key| {
                key.strip_prefix(prefix)
                    .ok_or_else(|| anyhow::anyhow!("invalid version key"))
                    .and_then(|suffix| Ok(u64::MAX - suffix.parse::<u64>()?))
            })
            .transpose()
            .map(|value| value.unwrap_or(0))
    }
    /// Row key. The selector union is Realm-relative — `RealmProfile` names a
    /// different row in every Realm — so the Realm is part of the key and never
    /// re-derived from the selector.
    fn row_prefix(&self, realm: &str, selector: &CurrentSelector) -> anyhow::Result<String> {
        Ok(format!(
            "{}row/{}/{}/",
            self.prefix,
            hash(&realm)?,
            hash(selector)?
        ))
    }
    fn progress_prefix(&self, realm: &str) -> anyhow::Result<String> {
        Ok(format!("{}progress/{}/", self.prefix, hash(&realm)?))
    }
    /// Coverage marks are per Realm. Baseline coverage is a set of independent
    /// commit-stream heads, not a per-target enumeration, so one mark answers
    /// for every selector of the Realm.
    fn mark_prefix(&self, realm: &str) -> anyhow::Result<String> {
        Ok(format!("{}coverage/{}/", self.prefix, hash(&realm)?))
    }
    fn seen_prefix(
        &self,
        snapshot: &str,
        realm: &str,
        selector: &CurrentSelector,
    ) -> anyhow::Result<String> {
        Ok(format!(
            "{}seen/{}/{}/{}/",
            self.prefix,
            snapshot_key(snapshot)?,
            hash(&realm)?,
            hash(selector)?
        ))
    }
    fn gc_state_key(&self) -> String {
        format!("{}gc-state", self.prefix)
    }
    fn gc_mark_prefix(&self) -> String {
        format!("{}gc-mark/", self.prefix)
    }
    fn gc_mark_key(&self, epoch: u64, snapshot: &str) -> String {
        format!("{}{epoch:020}/{snapshot}", self.gc_mark_prefix())
    }
    async fn load_state<T: serde::de::DeserializeOwned + Default>(
        &self,
        key: &str,
    ) -> anyhow::Result<T> {
        Ok(self
            .backend
            .get(key)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default())
    }
    async fn progress_at(
        &self,
        realm: &str,
        generation: u64,
    ) -> anyhow::Result<CurrentRealmProgress> {
        let prefix = self.progress_prefix(realm)?;
        let mut progress: CurrentRealmProgress =
            self.latest(&prefix, generation).await?.unwrap_or_default();
        let reset = self
            .latest::<u64>(&format!("{}reset/", self.prefix), generation)
            .await?
            .unwrap_or(0);
        if self.latest_generation(&prefix, generation).await? < reset {
            progress.reset();
        }
        Ok(progress)
    }
    async fn strongest_mark(
        &self,
        realm: &str,
        generation: u64,
    ) -> anyhow::Result<Option<CoverageMark>> {
        self.latest::<CoverageMark>(&self.mark_prefix(realm)?, generation)
            .await
    }
    async fn raw_selector(
        &self,
        realm: &str,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<TypedCurrentResult>> {
        let prefix = self.row_prefix(realm, selector)?;
        let row_generation = self.latest_generation(&prefix, generation).await?;
        if let Some(retired) = self.retired(realm, selector, generation).await? {
            if retired.generation >= row_generation {
                return Ok(None);
            }
        }
        self.latest(&prefix, generation).await
    }
    fn retired_prefix(&self, realm: &str, selector: &CurrentSelector) -> anyhow::Result<String> {
        Ok(format!(
            "{}retired/{}/{}/",
            self.prefix,
            hash(&realm)?,
            hash(selector)?
        ))
    }
    async fn retired(
        &self,
        realm: &str,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<RetiredEntry>> {
        self.latest(&self.retired_prefix(realm, selector)?, generation)
            .await
    }
    async fn visible_selector(
        &self,
        realm: &str,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<TypedCurrentResult>> {
        let Some(entry) = self.raw_selector(realm, selector, generation).await? else {
            return Ok(None);
        };
        if let Some(mark) = self.strongest_mark(realm, generation).await? {
            let row_generation = self
                .latest_generation(&self.row_prefix(realm, selector)?, generation)
                .await?;
            if row_generation <= mark.generation
                && self
                    .latest::<bool>(
                        &self.seen_prefix(&mark.snapshot, realm, selector)?,
                        generation,
                    )
                    .await?
                    .is_none()
            {
                return Ok(None);
            }
        }
        Ok(Some(entry))
    }
    #[cfg(test)]
    pub(crate) async fn read_selector(
        &self,
        realm: &str,
        selector: &CurrentSelector,
    ) -> anyhow::Result<Option<TypedCurrentResult>> {
        let _lease = self.lease.lock().await;
        self.visible_selector(realm, selector, self.generation.load(Ordering::Acquire))
            .await
    }
    pub(crate) async fn read_selector_ready(
        &self,
        realm: &str,
        selector: &CurrentSelector,
    ) -> anyhow::Result<Option<TypedCurrentResult>> {
        let _lease = self.lease.lock().await;
        let generation = self.generation.load(Ordering::Acquire);
        self.ready_selector(realm, selector, generation).await
    }
    async fn ready_selector(
        &self,
        realm: &str,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<TypedCurrentResult>> {
        let Some(entry) = self.visible_selector(realm, selector, generation).await? else {
            return Ok(None);
        };
        let progress = self.progress_at(realm, generation).await?;
        let floor = self
            .latest::<u64>(
                &format!("{}refresh/{}/", self.prefix, hash(&realm)?),
                generation,
            )
            .await?
            .unwrap_or(0)
            .max(
                self.latest::<u64>(&format!("{}reset/", self.prefix), generation)
                    .await?
                    .unwrap_or(0),
            );
        let row_generation = self
            .latest_generation(&self.row_prefix(realm, selector)?, generation)
            .await?;
        if progress.needs_refresh
            || row_generation < floor
            || revision_of(&entry).stream_position < progress.invalidation_revision
        {
            let seen = match &progress.baseline {
                Some(baseline)
                    if progress.invalidated_snapshot.as_deref()
                        != Some(baseline.snapshot_cursor.as_str()) =>
                {
                    let seen = self
                        .latest_generation(
                            &self.seen_prefix(
                                baseline.snapshot_cursor.as_str(),
                                realm,
                                selector,
                            )?,
                            generation,
                        )
                        .await?;
                    seen > 0 && seen >= floor
                }
                _ => false,
            };
            if !seen {
                return Ok(None);
            }
        }
        Ok(Some(entry))
    }
    // These bounded readers are the explicit 0540 hand-off surface.
    #[allow(dead_code)]
    pub(crate) async fn read_progress(&self, realm: &str) -> anyhow::Result<CurrentRealmProgress> {
        let _lease = self.lease.lock().await;
        self.progress_at(realm, self.generation.load(Ordering::Acquire))
            .await
    }
    pub(crate) async fn read_target_page(
        &self,
        realm: &str,
        target: &CurrentTarget,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<CurrentTargetPage> {
        self.read_region_page(realm, &target_key(target)?, after, limit)
            .await
    }
    #[allow(dead_code)]
    pub(crate) async fn read_members_page(
        &self,
        realm: &str,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<CurrentTargetPage> {
        self.read_region_page(realm, member_all_key(), after, limit)
            .await
    }
    async fn read_region_page(
        &self,
        realm: &str,
        target: &str,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<CurrentTargetPage> {
        anyhow::ensure!(
            (1..=PAGE_LIMIT).contains(&limit),
            "invalid current page limit"
        );
        let _lease = self.lease.lock().await;
        let generation = self.generation.load(Ordering::Acquire);
        let prefix = format!("{}target/{}/{target}/", self.prefix, hash(&realm)?);
        if let Some(after) = after {
            anyhow::ensure!(
                after.starts_with(&prefix),
                "current page cursor has another target"
            );
        }
        let rows = self.backend.scan(&prefix, None, after, limit).await?;
        let has_more = rows.len() == limit;
        let mut next_cursor = None;
        let mut consumed = after.map(str::to_owned);
        let mut entries = Vec::new();
        let mut bytes_used = 0usize;
        for (key, bytes) in rows {
            let selector: CurrentSelector = serde_json::from_slice(&bytes)?;
            if let Some(entry) = self.ready_selector(realm, &selector, generation).await? {
                let size = arkret_sdk::canonical::canonical_json_bytes(&entry)?.len();
                anyhow::ensure!(size <= 8 * 1024 * 1024, "current entry exceeds byte limit");
                if bytes_used + size > 8 * 1024 * 1024 {
                    next_cursor = consumed.clone();
                    break;
                }
                bytes_used += size;
                entries.push(entry);
            }
            consumed = Some(key);
        }
        if next_cursor.is_none() && has_more {
            next_cursor = consumed;
        }
        Ok(CurrentTargetPage {
            entries,
            next_cursor,
        })
    }

    pub(crate) async fn stage_frame(
        &self,
        expected_generation: u64,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<CurrentStage> {
        let lease = self.lease.clone().lock_owned().await;
        anyhow::ensure!(
            !self.is_poisoned(),
            "current pointer durability is unresolved"
        );
        anyhow::ensure!(
            self.generation.load(Ordering::Acquire) == expected_generation,
            "current generation changed"
        );
        let generation = expected_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("current generation exhausted"))?;
        let suffix = version(generation);
        let manifest_key = format!("{}stage/{suffix}", self.prefix);
        let deletes: Vec<String> = self
            .backend
            .get(&manifest_key)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        let mut writes = BTreeMap::<String, Vec<u8>>::new();
        let mut unversioned = BTreeMap::<String, Vec<u8>>::new();
        // Publish write barrier. Maintenance and staging share one lease, so the
        // epoch read here is the epoch the running mark phase collects under.
        // Marking every snapshot this frame roots, in the same apply as the
        // rows that root it, means a mark cursor that already passed a Realm
        // cannot lose the evidence and never has to restart its scan.
        let gc: GcState = self.load_state(&self.gc_state_key()).await?;
        let mut filtered = frame.clone();
        let mut progress_updates = BTreeMap::<String, CurrentRealmProgress>::new();
        if frame.kind == arkret_sdk::sync::AccountSubscribeFrameKind::ResyncRequired {
            writes.insert(
                format!("{}reset/{suffix}", self.prefix),
                serde_json::to_vec(&generation)?,
            );
        }
        if let Some(invalidations) = &frame.realm_invalidations {
            for invalidation in invalidations {
                let realm = invalidation.realm_id.as_str();
                let mut progress = self.progress_at(realm, expected_generation).await?;
                if progress.has_invalidation
                    && invalidation.revision <= progress.invalidation_revision
                {
                    continue;
                }
                progress.invalidate(invalidation.revision);
                progress_updates.insert(realm.to_owned(), progress);
                writes.insert(
                    format!("{}refresh/{}/{suffix}", self.prefix, hash(&realm)?),
                    serde_json::to_vec(&generation)?,
                );
            }
        }
        if let Some(realms) = &mut filtered.realms {
            for (realm, incoming) in &mut realms.entries {
                let mut previous = match progress_updates.remove(realm) {
                    Some(progress) => progress,
                    None => self.progress_at(realm, expected_generation).await?,
                };
                if let Some(baseline) = &incoming.baseline {
                    anyhow::ensure!(
                        baseline.coverage.realm_id.as_str() == realm,
                        "current coverage belongs to another Realm"
                    );
                    anyhow::ensure!(
                        !baseline.complete || baseline.coverage.complete_for_authorized_streams,
                        "complete current baseline has incomplete stream coverage"
                    );
                }
                if let Some(current) = &incoming.current {
                    current
                        .validate()
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    anyhow::ensure!(
                        current.realm_id.as_str() == realm,
                        "current result belongs to another Realm"
                    );
                    if let Some(baseline) = &incoming.baseline {
                        anyhow::ensure!(
                            current.stream_heads == baseline.coverage.stream_heads,
                            "current result and baseline have different stream heads"
                        );
                    }
                    if let Some(installed) = previous.governance_generation {
                        anyhow::ensure!(
                            current.governance_generation >= installed,
                            "older governance generation cannot replace current results"
                        );
                        if current.governance_generation > installed {
                            anyhow::ensure!(
                                incoming.baseline.is_some(),
                                "governance generation changed without a fresh baseline"
                            );
                            previous.begin_governance_generation(current.governance_generation);
                        }
                    } else {
                        previous.governance_generation = Some(current.governance_generation);
                    }
                }
                let mut plan = plan_current_install(&previous, incoming)?;
                let baseline = incoming.baseline.clone();
                let mut accepted = Vec::new();
                let mut delivered = std::collections::BTreeSet::new();
                // `RealmSyncEntry::current` is the Station's typed
                // `AccountCurrentResult`; its entries are already selected and
                // signed, so nothing is re-decoded out of opaque JSON here.
                let entries = incoming
                    .current
                    .as_ref()
                    .map(|current| current.entries.clone())
                    .unwrap_or_default();
                anyhow::ensure!(entries.len() <= 100, "current selector limit exceeded");
                for entry in &entries {
                    if plan.discard_frame {
                        break;
                    }
                    let selector = selector_of(entry);
                    let key = selector_key(selector)?;
                    anyhow::ensure!(delivered.insert(key.clone()), "duplicate current selector");
                    let old = self
                        .raw_selector(realm, selector, expected_generation)
                        .await?;
                    let (write, seen) =
                        plan_current_entry(&previous, baseline.as_ref(), entry, old.as_ref())?;
                    if seen {
                        plan.seen_selectors.push(key);
                    }
                    if let Some(retired) =
                        self.retired(realm, selector, expected_generation).await?
                    {
                        anyhow::ensure!(
                            retired.target == target_of(selector),
                            "retired selector changed its target"
                        );
                        if retired.revision == *revision_of(entry) {
                            anyhow::ensure!(
                                retired.digest == hash(entry)?,
                                "retired current changed at same revision"
                            );
                        }
                        if retired.revision.stream_position > revision_of(entry).stream_position {
                            continue;
                        }
                    }
                    if !write {
                        continue;
                    }
                    accepted.push(entry.clone());
                }
                plan.writes = accepted;
                if incoming.unavailable.is_some() {
                    writes.insert(
                        format!("{}refresh/{}/{suffix}", self.prefix, hash(realm)?),
                        serde_json::to_vec(&generation)?,
                    );
                }
                if plan.discard_frame {
                    incoming.current = None;
                    incoming.baseline = None;
                } else {
                    if let Some(current) = incoming.current.as_mut() {
                        // Keep the frame's authority coordinates; only the
                        // entry set is narrowed to what this install accepted.
                        current.entries = plan.writes.clone();
                    }
                    if let Some(baseline) = &plan.progress.baseline {
                        for selector in &plan.seen_selectors {
                            let selector: CurrentSelector = serde_json::from_str(selector)?;
                            writes.insert(
                                format!(
                                    "{}{suffix}",
                                    self.seen_prefix(
                                        baseline.snapshot_cursor.as_str(),
                                        realm,
                                        &selector
                                    )?
                                ),
                                serde_json::to_vec(&true)?,
                            );
                        }
                    }
                    for entry in &plan.writes {
                        let selector = selector_of(entry);
                        let target = target_of(selector);
                        writes.insert(
                            format!("{}{suffix}", self.row_prefix(realm, selector)?),
                            serde_json::to_vec(entry)?,
                        );
                        unversioned.insert(
                            format!("{}prune/{}/{}", self.prefix, hash(realm)?, hash(selector)?),
                            serde_json::to_vec(&PruneTask {
                                realm: realm.clone(),
                                selector: selector.clone(),
                            })?,
                        );
                        unversioned.insert(
                            format!(
                                "{}target/{}/{}/{}",
                                self.prefix,
                                hash(realm)?,
                                target_key(&target)?,
                                hash(selector)?
                            ),
                            serde_json::to_vec(selector)?,
                        );
                        if matches!(target, CurrentTarget::Member { .. }) {
                            unversioned.insert(
                                format!(
                                    "{}target/{}/{}/{}",
                                    self.prefix,
                                    hash(realm)?,
                                    member_all_key(),
                                    hash(selector)?
                                ),
                                serde_json::to_vec(selector)?,
                            );
                        }
                    }
                    if let Some(cleanup) = &plan.cleanup {
                        let prefix = self.mark_prefix(realm)?;
                        let old = self
                            .latest::<CoverageMark>(&prefix, expected_generation)
                            .await?;
                        if old.as_ref().is_none_or(|old| old.generation <= generation) {
                            unversioned.insert(
                                self.gc_mark_key(
                                    gc.epoch,
                                    &snapshot_key(cleanup.snapshot_cursor.as_str())?,
                                ),
                                serde_json::to_vec(&true)?,
                            );
                            writes.insert(
                                format!("{prefix}{suffix}"),
                                serde_json::to_vec(&CoverageMark {
                                    snapshot: cleanup.snapshot_cursor.clone(),
                                    generation,
                                })?,
                            );
                            writes.insert(
                                format!("{}cleanup/{suffix}/{}", self.prefix, hash(realm)?),
                                serde_json::to_vec(&CleanupTask {
                                    realm: realm.clone(),
                                    after: None,
                                    generation,
                                })?,
                            );
                        }
                    }
                }
                progress_updates.insert(realm.clone(), plan.progress.clone());
            }
        }
        for (realm, progress) in progress_updates {
            if let Some(baseline) = &progress.baseline {
                unversioned.insert(
                    self.gc_mark_key(gc.epoch, &snapshot_key(baseline.snapshot_cursor.as_str())?),
                    serde_json::to_vec(&true)?,
                );
            }
            writes.insert(
                format!("{}{suffix}", self.progress_prefix(&realm)?),
                serde_json::to_vec(&progress)?,
            );
        }
        if gc.idle || !gc.dirty {
            let mut woken = gc.clone();
            woken.idle = false;
            woken.dirty = true;
            unversioned.insert(self.gc_state_key(), serde_json::to_vec(&woken)?);
        }
        let mut manifest = writes.keys().cloned().collect::<Vec<_>>();
        for key in unversioned.keys() {
            if deletes.contains(key) || self.backend.get(key).await?.is_none() {
                manifest.push(key.clone());
            }
        }
        writes.insert(manifest_key, serde_json::to_vec(&manifest)?);
        writes.extend(unversioned);
        let backend = self.backend.clone();
        let stage = CurrentStage {
            index: self.clone(),
            generation,
            filtered,
            _lease: lease,
        };
        complete_independently(async move {
            backend.apply(deletes, writes.into_iter().collect()).await?;
            Ok(stage)
        })
        .await
    }

    /// Deduplicate live-update cleanup by selector and rotate its scan position.
    /// The queue carries no authority: only versions at the committed pointer
    /// may be reclaimed, including when an uncommitted stage created the task.
    async fn prune_live_versions(&self, generation: u64) -> anyhow::Result<bool> {
        let prefix = format!("{}prune/", self.prefix);
        let cursor_key = format!("{}prune-position", self.prefix);
        let after: Option<String> = self
            .backend
            .get(&cursor_key)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        let mut rows = self
            .backend
            .scan(&prefix, None, after.as_deref(), 1)
            .await?;
        if rows.is_empty() && after.is_some() {
            rows = self.backend.scan(&prefix, None, None, 1).await?;
        }
        let Some((task_key, bytes)) = rows.into_iter().next() else {
            return Ok(false);
        };
        let task: PruneTask = serde_json::from_slice(&bytes)?;
        let row_prefix = self.row_prefix(&task.realm, &task.selector)?;
        let versions = self
            .backend
            .keys(
                &row_prefix,
                Some(&format!("{row_prefix}{}", version(generation))),
                None,
                100,
            )
            .await?;
        let mut deletes: Vec<String> = versions.iter().skip(1).cloned().collect();
        if versions.len() < 100 {
            deletes.push(task_key.clone());
        }
        self.backend
            .apply(deletes, vec![(cursor_key, serde_json::to_vec(&task_key)?)])
            .await?;
        Ok(true)
    }

    /// One bounded page of per-logical-key version compaction.
    ///
    /// Versions above the committed pointer belong to an unfinished stage and
    /// are never touched. At or below it only the newest can still answer
    /// `latest` or `latest_generation`, so the rest are bytes. Nothing is
    /// rewritten: a retained key keeps the generation the reader compares
    /// against the refresh and reset floors.
    async fn compact_versions(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        generation: u64,
    ) -> anyhow::Result<(Vec<String>, Option<String>)> {
        let keys = self.backend.keys(prefix, None, cursor, PAGE_LIMIT).await?;
        let Some(next) = keys.last().cloned() else {
            return Ok((Vec::new(), None));
        };
        let mut deletes = Vec::new();
        let mut logical = String::new();
        let mut retained = false;
        for (position, key) in keys.iter().enumerate() {
            let (key_logical, key_generation) = split_version(key)?;
            if key_logical != logical {
                logical = key_logical.to_owned();
                // A page can open inside a logical key whose survivor an
                // earlier pass already passed, so ask instead of assuming.
                retained = position == 0
                    && self
                        .backend
                        .keys(
                            key_logical,
                            Some(&format!("{key_logical}{}", version(generation))),
                            None,
                            1,
                        )
                        .await?
                        .first()
                        .is_some_and(|survivor| survivor.as_str() < key.as_str());
            }
            if key_generation > generation {
                continue;
            }
            if retained {
                deletes.push(key.clone());
            } else {
                retained = true;
            }
        }
        Ok((deletes, Some(next)))
    }

    /// Rotate the compaction quota across the metadata prefixes so a Realm that
    /// keeps rewriting one of them cannot starve the others.
    async fn compact_metadata(&self, generation: u64) -> anyhow::Result<bool> {
        let cursor_key = format!("{}meta-position", self.prefix);
        let mut position: MetaPosition = self.load_state(&cursor_key).await?;
        position.stream %= META_STREAMS.len();
        let prefix = format!("{}{}", self.prefix, META_STREAMS[position.stream]);
        let (deletes, next) = self
            .compact_versions(&prefix, position.cursor.as_deref(), generation)
            .await?;
        match next {
            Some(next) => position.cursor = Some(next),
            None => {
                position.stream = (position.stream + 1) % META_STREAMS.len();
                position.cursor = None;
            }
        }
        let reclaimed = !deletes.is_empty();
        self.backend
            .apply(deletes, vec![(cursor_key, serde_json::to_vec(&position)?)])
            .await?;
        Ok(reclaimed)
    }

    /// One bounded page of roots. Every stored version is treated as a root,
    /// including the ones an unfinished stage wrote: over-retaining costs a
    /// cycle, while under-marking would delete evidence a reader still needs.
    /// Compaction removes the superseded versions, so the root set converges.
    async fn mark_roots(
        &self,
        stream: usize,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<String>, Option<String>)> {
        let prefix = format!("{}{}", self.prefix, MARK_STREAMS[stream]);
        let rows = self.backend.scan(&prefix, None, cursor, PAGE_LIMIT).await?;
        let mut snapshots = Vec::new();
        let mut next = None;
        for (key, bytes) in rows {
            if MARK_STREAMS[stream] == "progress/" {
                let progress: CurrentRealmProgress = serde_json::from_slice(&bytes)?;
                if let Some(baseline) = &progress.baseline {
                    snapshots.push(snapshot_key(baseline.snapshot_cursor.as_str())?);
                }
            } else {
                let mark: CoverageMark = serde_json::from_slice(&bytes)?;
                snapshots.push(snapshot_key(&mark.snapshot)?);
            }
            next = Some(key);
        }
        Ok((snapshots, next))
    }

    /// One bounded page of `seen` evidence. A snapshot no root reaches is gone
    /// from both readers, so its evidence at or below the committed pointer is
    /// deleted outright; a snapshot still rooted only loses superseded
    /// versions. Future generations stay untouched in either case.
    async fn sweep_seen(
        &self,
        epoch: u64,
        cursor: Option<&str>,
        generation: u64,
    ) -> anyhow::Result<(Vec<String>, Option<String>)> {
        let prefix = format!("{}seen/", self.prefix);
        let keys = self.backend.keys(&prefix, None, cursor, PAGE_LIMIT).await?;
        let Some(next) = keys.last().cloned() else {
            return Ok((Vec::new(), None));
        };
        let mut marks = BTreeMap::<String, bool>::new();
        let mut deletes = Vec::new();
        let mut logical = String::new();
        let mut retained = false;
        for (position, key) in keys.iter().enumerate() {
            let (key_logical, key_generation) = split_version(key)?;
            if key_logical != logical {
                logical = key_logical.to_owned();
                retained = position == 0
                    && self
                        .backend
                        .keys(
                            key_logical,
                            Some(&format!("{key_logical}{}", version(generation))),
                            None,
                            1,
                        )
                        .await?
                        .first()
                        .is_some_and(|survivor| survivor.as_str() < key.as_str());
            }
            if key_generation > generation {
                continue;
            }
            let snapshot = key_logical
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split('/').next())
                .ok_or_else(|| anyhow::anyhow!("current seen key carries no snapshot"))?
                .to_owned();
            let marked = match marks.get(&snapshot) {
                Some(marked) => *marked,
                None => {
                    let marked = self
                        .backend
                        .get(&self.gc_mark_key(epoch, &snapshot))
                        .await?
                        .is_some();
                    marks.insert(snapshot, marked);
                    marked
                }
            };
            if !marked || retained {
                deletes.push(key.clone());
            } else {
                retained = true;
            }
        }
        Ok((deletes, Some(next)))
    }

    /// One bounded step of the reachability cycle. The batch of deletes and the
    /// phase, epoch and cursor advance reach the backend in a single apply, so
    /// a crash keeps the whole step or none of it and a replay resumes at the
    /// same position rather than skipping the unfinished batch.
    async fn collect_garbage(&self, generation: u64, wake: bool) -> anyhow::Result<bool> {
        let state_key = self.gc_state_key();
        let mut state: GcState = self.load_state(&state_key).await?;
        if state.idle && !wake {
            return Ok(false);
        }
        state.idle = false;
        state.dirty |= wake;
        let mut deletes = Vec::new();
        let mut writes = Vec::new();
        match state.phase {
            GcPhase::Purge => {
                let prefix = self.gc_mark_prefix();
                let current = format!("{prefix}{:020}/", state.epoch);
                for key in self.backend.keys(&prefix, None, None, PAGE_LIMIT).await? {
                    if key.as_str() < current.as_str() {
                        deletes.push(key);
                    }
                }
                if deletes.is_empty() {
                    state.phase = GcPhase::Mark;
                    state.stream = 0;
                    state.cursor = None;
                }
            }
            GcPhase::Mark => {
                state.stream %= MARK_STREAMS.len();
                let (snapshots, next) = self
                    .mark_roots(state.stream, state.cursor.as_deref())
                    .await?;
                for snapshot in snapshots {
                    writes.push((
                        self.gc_mark_key(state.epoch, &snapshot),
                        serde_json::to_vec(&true)?,
                    ));
                }
                match next {
                    Some(next) => state.cursor = Some(next),
                    None => {
                        state.cursor = None;
                        if state.stream + 1 < MARK_STREAMS.len() {
                            state.stream += 1;
                        } else {
                            state.phase = GcPhase::Sweep;
                        }
                    }
                }
            }
            GcPhase::Sweep => {
                let (batch, next) = self
                    .sweep_seen(state.epoch, state.cursor.as_deref(), generation)
                    .await?;
                state.reclaimed |= !batch.is_empty();
                deletes = batch;
                match next {
                    Some(next) => state.cursor = Some(next),
                    None => {
                        // A cycle that reclaimed nothing and saw no root change
                        // has no work left until a frame publishes another root
                        // or compaction retires one.
                        state.idle = !state.reclaimed && !state.dirty;
                        state.reclaimed = false;
                        state.dirty = false;
                        state.epoch += 1;
                        state.phase = GcPhase::Purge;
                        state.stream = 0;
                        state.cursor = None;
                    }
                }
            }
        }
        let reclaimed = !deletes.is_empty();
        writes.push((state_key, serde_json::to_vec(&state)?));
        self.backend.apply(deletes, writes).await?;
        Ok(reclaimed)
    }

    /// At most two selectors and 200 historical row keys per pass. Logical
    /// coverage removal was already atomic with the frame; this reclaims bytes.
    pub(crate) async fn maintain(&self) -> anyhow::Result<bool> {
        let index = self.clone();
        complete_independently(async move { index.maintain_locked().await }).await
    }

    async fn maintain_locked(&self) -> anyhow::Result<bool> {
        let _lease = self.lease.lock().await;
        anyhow::ensure!(
            !self.is_poisoned(),
            "current pointer durability is unresolved"
        );
        let generation = self.generation.load(Ordering::Acquire);
        let mut maintained = self.prune_live_versions(generation).await?;
        // Each reclaimer takes its own fixed share of the pass before the queue
        // that produces the most work runs, so none of them can be starved by a
        // Realm that keeps writing. Retiring a metadata version can orphan a
        // snapshot, so it wakes an idle reachability cycle.
        let retired_metadata = self.compact_metadata(generation).await?;
        maintained |= retired_metadata;
        maintained |= self.collect_garbage(generation, retired_metadata).await?;
        let manifests = format!("{}stage/", self.prefix);
        let older = self
            .backend
            .keys(
                &manifests,
                None,
                Some(&format!("{manifests}{}", version(generation))),
                100,
            )
            .await?;
        if !older.is_empty() {
            self.backend.apply(older, Vec::new()).await?;
            maintained = true;
        }
        let tasks = format!("{}cleanup/", self.prefix);
        let cursor_key = format!("{}cleanup-position", self.prefix);
        let after: Option<String> = self
            .backend
            .get(&cursor_key)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        let lower = format!("{tasks}{}", version(generation));
        let mut rows = self
            .backend
            .scan(&tasks, Some(&lower), after.as_deref(), 1)
            .await?;
        if rows.is_empty() && after.is_some() {
            rows = self.backend.scan(&tasks, Some(&lower), None, 1).await?;
        }
        let Some((task_key, bytes)) = rows.into_iter().next() else {
            return Ok(maintained);
        };
        let mut task: CleanupTask = serde_json::from_slice(&bytes)?;
        let prefix = format!("{}target/{}/", self.prefix, hash(&task.realm)?);
        let Some((index_key, bytes)) = self
            .backend
            .scan(&prefix, None, task.after.as_deref(), 1)
            .await?
            .into_iter()
            .next()
        else {
            self.backend
                .apply(
                    vec![task_key.clone()],
                    vec![(cursor_key, serde_json::to_vec(&task_key)?)],
                )
                .await?;
            return Ok(true);
        };
        let selector: CurrentSelector = serde_json::from_slice(&bytes)?;
        let row_prefix = self.row_prefix(&task.realm, &selector)?;
        let versions = self
            .backend
            .keys(
                &row_prefix,
                Some(&format!("{row_prefix}{}", version(generation))),
                None,
                100,
            )
            .await?;
        let visible = self
            .visible_selector(&task.realm, &selector, generation)
            .await?;
        let mut deletes = Vec::new();
        let mut writes = Vec::new();
        if visible.is_none() {
            if let Some(key) = versions.first() {
                let bytes = self
                    .backend
                    .get(key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("current version disappeared"))?;
                let entry: TypedCurrentResult = serde_json::from_slice(&bytes)?;
                let row_generation = self.latest_generation(&row_prefix, generation).await?;
                if self
                    .retired(&task.realm, &selector, generation)
                    .await?
                    .is_none_or(|retired| retired.generation < row_generation)
                {
                    writes.push((
                        format!(
                            "{}{}",
                            self.retired_prefix(&task.realm, &selector)?,
                            version(generation)
                        ),
                        serde_json::to_vec(&RetiredEntry {
                            revision: revision_of(&entry).clone(),
                            target: target_of(&selector),
                            digest: hash(&entry)?,
                            generation,
                        })?,
                    ));
                }
            }
            deletes.extend(versions.iter().cloned());
            if versions.len() < 100 {
                // The selector may have more than one target index (member
                // rows also have `member-all`). This scan reaches and deletes
                // each concrete index key independently.
                deletes.push(index_key.clone());
                task.after = Some(index_key);
            }
        } else {
            // Retain the latest live row and prune older versions in bounded chunks.
            deletes.extend(versions.iter().skip(1).cloned());
            if versions.len() < 100 {
                task.after = Some(index_key);
            }
        }
        writes.push((cursor_key, serde_json::to_vec(&task_key)?));
        writes.push((task_key, serde_json::to_vec(&task)?));
        self.backend.apply(deletes, writes).await?;
        Ok(true)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde_json::json;

    use super::*;
    const REALM: &str = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
    fn row(revision: u64, removed: bool) -> TypedCurrentResult {
        serde_json::from_value(json!({
            "selector":{"kind":"realm_profile"},
            "revision":{"commit_id":COMMIT,"stream_position":revision},
            "value":if removed{json!({"status":"removed"})}else{json!({"status":"value","value":null})}
        })).unwrap()
    }
    fn frame(
        entries: Vec<TypedCurrentResult>,
        baseline: Option<serde_json::Value>,
    ) -> AccountSubscribeFrame {
        realm_frame(REALM, entries, baseline)
    }
    fn at_generation(mut frame: AccountSubscribeFrame, generation: u64) -> AccountSubscribeFrame {
        frame
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM)
            .unwrap()
            .current
            .as_mut()
            .unwrap()
            .governance_generation = generation;
        frame
    }
    fn baseline(snapshot: &str, cut: u64, complete: bool) -> serde_json::Value {
        json!({
            "snapshot_cursor":snapshot,
            "cut_revision":cut,
            "coverage":{
                "realm_id":REALM,
                "stream_heads":[{
                    "stream_ref":{"kind":"realm","realm_id":REALM},
                    "stream_position":cut,
                    "commit_id":COMMIT
                }],
                "complete_for_authorized_streams":true
            },
            "complete":complete
        })
    }
    async fn index(path: &std::path::Path, generation: u64) -> CurrentIndex {
        let shared = Arc::new(SharedGeneration {
            generation: Arc::new(AtomicU64::new(generation)),
            lease: Arc::new(Mutex::new(())),
            poisoned: AtomicBool::new(false),
            pending: AtomicU64::new(0),
        });
        CurrentIndex {
            backend: platform::Backend::open_test(path.to_owned()).await.unwrap(),
            prefix: "inkson.current.v1/test/".into(),
            generation: shared.generation.clone(),
            lease: shared.lease.clone(),
            _shared: shared,
        }
    }
    const OTHER_REALM: &str = "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    const CURSORS: [&str; 12] = [
        "ak:cursor:YQ",
        "ak:cursor:Yg",
        "ak:cursor:Yw",
        "ak:cursor:ZA",
        "ak:cursor:ZQ",
        "ak:cursor:Zg",
        "ak:cursor:Zw",
        "ak:cursor:aA",
        "ak:cursor:aQ",
        "ak:cursor:ag",
        "ak:cursor:aw",
        "ak:cursor:bA",
    ];
    fn realm_row(_realm: &str, revision: u64) -> TypedCurrentResult {
        row(revision, false)
    }
    fn member_row(_realm: &str, actor: &str, revision: u64) -> TypedCurrentResult {
        serde_json::from_value(json!({
            "selector":{"kind":"member_state","actor_id":{"kind":"service","service_id":actor}},
            "revision":{"commit_id":COMMIT,"stream_position":revision},
            "value":{"membership":"join"}
        }))
        .unwrap()
    }
    fn realm_frame(
        realm: &str,
        entries: Vec<TypedCurrentResult>,
        baseline: Option<serde_json::Value>,
    ) -> AccountSubscribeFrame {
        let mut baseline = baseline;
        if let Some(value) = baseline.as_mut() {
            value["coverage"]["realm_id"] = json!(realm);
            value["coverage"]["stream_heads"][0]["stream_ref"]["realm_id"] = json!(realm);
        }
        let stream_heads = baseline
            .as_ref()
            .map(|value| value["coverage"]["stream_heads"].clone())
            .unwrap_or_else(|| json!([]));
        let mut entry = json!({"current":{
            "realm_id":realm,
            "governance_generation":1,
            "stream_heads":stream_heads,
            "entries":entries
        }});
        if let Some(baseline) = baseline {
            entry["baseline"] = baseline;
        }
        serde_json::from_value(
            json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{realm:entry}}),
        )
        .unwrap()
    }
    fn members_baseline(snapshot: &str, cut: u64, complete: bool) -> serde_json::Value {
        baseline(snapshot, cut, complete)
    }
    async fn seen_versions_in_realm(
        index: &CurrentIndex,
        snapshot: &str,
        realm: &str,
        selector: &CurrentSelector,
    ) -> usize {
        let prefix = index.seen_prefix(snapshot, realm, selector).unwrap();
        index
            .backend
            .keys(&prefix, None, None, PAGE_LIMIT)
            .await
            .unwrap()
            .len()
    }
    async fn seen_versions(
        index: &CurrentIndex,
        snapshot: &str,
        selector: &CurrentSelector,
    ) -> usize {
        seen_versions_in_realm(index, snapshot, REALM, selector).await
    }
    async fn seen_generation(
        index: &CurrentIndex,
        snapshot: &str,
        selector: &CurrentSelector,
    ) -> u64 {
        let prefix = index.seen_prefix(snapshot, REALM, selector).unwrap();
        index.latest_generation(&prefix, u64::MAX).await.unwrap()
    }
    async fn count_keys(index: &CurrentIndex, prefix: &str) -> usize {
        let mut after: Option<String> = None;
        let mut total = 0;
        loop {
            let keys = index
                .backend
                .keys(prefix, None, after.as_deref(), PAGE_LIMIT)
                .await
                .unwrap();
            let Some(last) = keys.last().cloned() else {
                return total;
            };
            total += keys.len();
            after = Some(last);
        }
    }
    async fn gc(index: &CurrentIndex) -> GcState {
        index.load_state(&index.gc_state_key()).await.unwrap()
    }
    async fn drive(index: &CurrentIndex, passes: usize) {
        for _ in 0..passes {
            index.maintain().await.unwrap();
        }
    }
    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "inkson-current-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[tokio::test]
    async fn cancelled_caller_cannot_release_an_inflight_transaction_lease() {
        let lease = Arc::new(Mutex::new(()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(tokio::sync::Notify::new());
        let guard = lease.clone().lock_owned().await;
        let job_entered = entered.clone();
        let job_resume = resume.clone();
        let job_finished = finished.clone();
        let caller = tokio::spawn(async move {
            complete_independently(async move {
                job_entered.notify_one();
                job_resume.notified().await;
                drop(guard);
                job_finished.notify_one();
                Ok(())
            })
            .await
        });
        entered.notified().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(lease.try_lock().is_err());
        resume.notify_one();
        finished.notified().await;
        assert!(lease.try_lock().is_ok());
    }

    #[tokio::test]
    async fn live_updates_reclaim_old_versions_without_a_new_baseline() {
        let path = path();
        let index = index(&path, 0).await;
        for revision in 1..=110 {
            index
                .stage_frame(revision - 1, &frame(vec![row(revision, false)], None))
                .await
                .unwrap()
                .finish();
        }
        let selector = selector_of(&row(110, false));
        let row_prefix = index.row_prefix(REALM, &selector).unwrap();
        assert_eq!(
            index
                .backend
                .keys(&row_prefix, None, None, 100)
                .await
                .unwrap()
                .len(),
            100
        );
        // A failed later stage must not cause maintenance to promote its row.
        drop(
            index
                .stage_frame(110, &frame(vec![row(999, true)], None))
                .await
                .unwrap(),
        );
        for _ in 0..4 {
            index.maintain().await.unwrap();
        }
        assert_eq!(
            index.read_selector(REALM, &selector).await.unwrap(),
            Some(row(110, false))
        );
        assert_eq!(
            index
                .backend
                .keys(
                    &row_prefix,
                    Some(&format!("{row_prefix}{}", version(110))),
                    None,
                    100,
                )
                .await
                .unwrap()
                .len(),
            1
        );
        index
            .stage_frame(110, &frame(vec![row(111, false)], None))
            .await
            .unwrap()
            .finish();
        // Frequent new manifests cannot starve reclamation of live row versions.
        for revision in 112..=120 {
            index
                .stage_frame(revision - 1, &frame(vec![row(revision, false)], None))
                .await
                .unwrap()
                .finish();
            index.maintain().await.unwrap();
        }
        assert_eq!(
            index
                .backend
                .keys(&row_prefix, None, None, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            index.read_selector(REALM, &selector).await.unwrap(),
            Some(row(120, false))
        );
    }

    #[tokio::test]
    async fn failed_stage_is_invisible_after_restart_and_exact_generation_retry() {
        let path = path();
        let first = index(&path, 0).await;
        drop(
            first
                .stage_frame(0, &frame(vec![row(1, false)], None))
                .await
                .unwrap(),
        );
        assert!(
            first
                .read_selector(REALM, &selector_of(&row(1, false)))
                .await
                .unwrap()
                .is_none()
        );
        drop(first);
        let restored = index(&path, 0).await;
        restored
            .stage_frame(0, &frame(vec![row(2, true)], None))
            .await
            .unwrap()
            .finish();
        assert_eq!(
            restored
                .read_selector(REALM, &selector_of(&row(2, true)))
                .await
                .unwrap(),
            Some(row(2, true))
        );
        drop(restored);
        let committed = index(&path, 1).await;
        assert_eq!(
            committed
                .read_selector(REALM, &selector_of(&row(2, true)))
                .await
                .unwrap(),
            Some(row(2, true))
        );
        assert!(
            committed
                .stage_frame(1, &frame(vec![row(2, false)], None))
                .await
                .is_err()
        );
    }

    #[test]
    fn same_position_with_another_commit_is_a_fork() {
        let old = row(7, false);
        let mut value = serde_json::to_value(row(7, false)).unwrap();
        value["revision"]["commit_id"] =
            json!("ak:realm_commit:Aaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur");
        let fork: TypedCurrentResult = serde_json::from_value(value).unwrap();
        assert!(
            plan_current_entry(&CurrentRealmProgress::default(), None, &fork, Some(&old))
                .unwrap_err()
                .to_string()
                .contains("forked at the same stream position")
        );
    }

    #[tokio::test]
    async fn governance_generation_requires_a_fresh_baseline_and_never_rolls_back() {
        let path = path();
        let index = index(&path, 0).await;
        index
            .stage_frame(
                0,
                &at_generation(
                    frame(vec![row(1, false)], Some(baseline(CURSORS[0], 1, true))),
                    2,
                ),
            )
            .await
            .unwrap()
            .finish();
        assert!(
            index
                .stage_frame(1, &at_generation(frame(vec![row(2, false)], None), 1))
                .await
                .is_err()
        );
        assert!(
            index
                .stage_frame(1, &at_generation(frame(vec![row(2, false)], None), 3))
                .await
                .is_err()
        );
        index
            .stage_frame(
                1,
                &at_generation(
                    frame(vec![row(2, false)], Some(baseline(CURSORS[1], 2, true))),
                    3,
                ),
            )
            .await
            .unwrap()
            .finish();
        assert_eq!(
            index
                .read_progress(REALM)
                .await
                .unwrap()
                .governance_generation,
            Some(3)
        );
    }
    #[tokio::test]
    async fn reset_and_invalidation_require_fresh_seen_without_waiting_for_completion() {
        let path = path();
        let index = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        index
            .stage_frame(
                0,
                &frame(vec![row(1, false)], Some(baseline("ak:cursor:YQ", 1, true))),
            )
            .await
            .unwrap()
            .finish();
        let reset = serde_json::from_value(json!({"kind":"resync_required"})).unwrap();
        index.stage_frame(1, &reset).await.unwrap().finish();
        assert!(
            index
                .read_selector(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            index
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_none()
        );
        let stale = index
            .stage_frame(
                2,
                &frame(vec![row(1, false)], Some(baseline("ak:cursor:YQ", 1, true))),
            )
            .await
            .unwrap();
        let discarded = &stale.filtered_frame().realms.as_ref().unwrap().entries[REALM];
        assert!(discarded.current.is_none());
        assert!(discarded.baseline.is_none());
        stale.finish();
        index
            .stage_frame(
                3,
                &frame(
                    vec![row(1, false)],
                    Some(baseline("ak:cursor:Yg", 1, false)),
                ),
            )
            .await
            .unwrap()
            .finish();
        assert!(
            index
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        let invalidation=serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ","realm_invalidations":[{"realm_id":REALM,"revision":0}]})).unwrap();
        index.stage_frame(4, &invalidation).await.unwrap().finish();
        assert!(
            index
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_none()
        );
        index
            .stage_frame(
                5,
                &frame(
                    vec![row(1, false)],
                    Some(baseline("ak:cursor:Yw", 1, false)),
                ),
            )
            .await
            .unwrap()
            .finish();
        index.stage_frame(6, &invalidation).await.unwrap().finish();
        assert!(
            index
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn coverage_cleanup_keeps_post_cut_live_and_rejects_retired_conflicts() {
        let path = path();
        let index = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        index
            .stage_frame(0, &frame(vec![], Some(baseline("ak:cursor:YQ", 5, true))))
            .await
            .unwrap()
            .finish();
        index
            .stage_frame(1, &frame(vec![row(7, false)], None))
            .await
            .unwrap()
            .finish();
        for _ in 0..4 {
            index.maintain().await.unwrap();
        }
        assert_eq!(
            index.read_selector(REALM, &selector).await.unwrap(),
            Some(row(7, false))
        );
        index
            .stage_frame(2, &frame(vec![], Some(baseline("ak:cursor:Yg", 8, true))))
            .await
            .unwrap()
            .finish();
        for _ in 0..4 {
            index.maintain().await.unwrap();
        }
        assert!(
            index
                .read_selector(REALM, &selector)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            index
                .read_target_page(REALM, &CurrentTarget::Realm, None, 100)
                .await
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            index
                .stage_frame(
                    3,
                    &frame(vec![row(7, true)], Some(baseline("ak:cursor:Yw", 8, false)))
                )
                .await
                .is_err()
        );
        assert!(
            index
                .stage_frame(3, &frame(vec![row(7, true)], None))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn unresolved_pointer_poison_prevents_failed_generation_reuse() {
        let path = path();
        let index = index(&path, 0).await;
        drop(
            index
                .stage_frame(0, &frame(vec![row(1, false)], None))
                .await
                .unwrap(),
        );
        let other = index.clone();
        index.poison();
        assert!(
            other
                .stage_frame(0, &frame(vec![row(2, false)], None))
                .await
                .is_err()
        );
        assert!(other.confirm_durable_pointer(1).is_err());
        assert!(other.is_poisoned());
        other.confirm_durable_pointer(0).unwrap();
        other
            .stage_frame(0, &frame(vec![row(2, false)], None))
            .await
            .unwrap()
            .finish();
    }

    #[tokio::test]
    async fn cancelled_account_commit_recovers_only_the_confirmed_pointer() {
        let path = path();
        let index = index(&path, 0).await;
        let mut stage = index
            .stage_frame(0, &frame(vec![row(1, false)], None))
            .await
            .unwrap();
        stage.arm_account_commit();
        drop(stage);
        assert!(index.is_poisoned());
        assert!(
            index
                .stage_frame(0, &frame(vec![row(2, false)], None))
                .await
                .is_err()
        );
        index.confirm_durable_pointer(1).unwrap();
        assert_eq!(
            index
                .read_selector(REALM, &selector_of(&row(1, false)))
                .await
                .unwrap(),
            Some(row(1, false))
        );
        let mut stage = index
            .stage_frame(1, &frame(vec![row(2, false)], None))
            .await
            .unwrap();
        stage.arm_account_commit();
        index.poison();
        index.confirm_durable_pointer(1).unwrap();
        drop(stage);
        assert!(!index.is_poisoned());
        assert_eq!(
            index
                .read_selector(REALM, &selector_of(&row(1, false)))
                .await
                .unwrap(),
            Some(row(1, false))
        );
    }

    #[tokio::test]
    async fn repeated_baselines_reclaim_zero_reference_snapshot_seen() {
        let path = path();
        let store = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        for (generation, snapshot) in CURSORS[..3].iter().enumerate() {
            store
                .stage_frame(
                    generation as u64,
                    &frame(vec![row(1, false)], Some(baseline(snapshot, 5, true))),
                )
                .await
                .unwrap()
                .finish();
        }
        for snapshot in &CURSORS[..3] {
            assert_eq!(seen_versions(&store, snapshot, &selector).await, 1);
        }
        assert_eq!(
            store.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        drive(&store, 80).await;
        assert_eq!(seen_versions(&store, CURSORS[0], &selector).await, 0);
        assert_eq!(seen_versions(&store, CURSORS[1], &selector).await, 0);
        assert_eq!(seen_versions(&store, CURSORS[2], &selector).await, 1);
        assert_eq!(
            store.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn another_target_reference_keeps_a_shared_snapshot_alive() {
        let path = path();
        let store = index(&path, 0).await;
        let realm_selector = selector_of(&row(1, false));
        let member = member_row(REALM, "ak:did_core:webvh:z6mkfixture", 1);
        let member_selector = selector_of(&member);
        store
            .stage_frame(
                0,
                &frame(
                    vec![row(1, false), member.clone()],
                    Some(members_baseline(CURSORS[0], 5, true)),
                ),
            )
            .await
            .unwrap()
            .finish();
        // Selected members with an empty set retires only the Realm region, so
        // the member-all coverage mark still reaches the first snapshot.
        store
            .stage_frame(
                1,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[1], 5, true))),
            )
            .await
            .unwrap()
            .finish();
        drive(&store, 80).await;
        assert_eq!(seen_versions(&store, CURSORS[0], &member_selector).await, 1);
        assert_eq!(seen_versions(&store, CURSORS[0], &realm_selector).await, 1);
        assert_eq!(
            store.read_selector(REALM, &member_selector).await.unwrap(),
            Some(member.clone())
        );
        assert_eq!(
            store.read_selector(REALM, &realm_selector).await.unwrap(),
            Some(row(1, false))
        );
        // Only another member-all baseline detaches the first snapshot.
        store
            .stage_frame(
                2,
                &frame(
                    vec![row(1, false), member.clone()],
                    Some(members_baseline(CURSORS[2], 5, true)),
                ),
            )
            .await
            .unwrap()
            .finish();
        drive(&store, 120).await;
        assert_eq!(seen_versions(&store, CURSORS[0], &member_selector).await, 0);
        assert_eq!(seen_versions(&store, CURSORS[0], &realm_selector).await, 0);
        assert_eq!(seen_versions(&store, CURSORS[2], &member_selector).await, 1);
        assert_eq!(
            store.read_selector(REALM, &member_selector).await.unwrap(),
            Some(member)
        );
        assert_eq!(
            store.read_selector(REALM, &realm_selector).await.unwrap(),
            Some(row(1, false))
        );
    }

    #[tokio::test]
    async fn an_unfinished_baseline_keeps_its_seen_at_the_original_generation() {
        let path = path();
        let store = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        store
            .stage_frame(
                0,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[0], 1, false))),
            )
            .await
            .unwrap()
            .finish();
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        let reset = serde_json::from_value(json!({"kind":"resync_required"})).unwrap();
        store.stage_frame(1, &reset).await.unwrap().finish();
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_none()
        );
        drive(&store, 80).await;
        // The pending baseline still references this evidence, and maintenance
        // must not rewrite it into its own generation to look fresh.
        assert_eq!(seen_versions(&store, CURSORS[0], &selector).await, 1);
        assert_eq!(seen_generation(&store, CURSORS[0], &selector).await, 1);
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .read_selector(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        store
            .stage_frame(
                2,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[1], 1, false))),
            )
            .await
            .unwrap()
            .finish();
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        drive(&store, 80).await;
        assert_eq!(seen_generation(&store, CURSORS[1], &selector).await, 3);
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_root_published_after_the_mark_cursor_survives_the_same_sweep() {
        let path = path();
        let store = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        store
            .stage_frame(
                0,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[0], 5, true))),
            )
            .await
            .unwrap()
            .finish();
        let mut generation = 1;
        let mut passes = 0;
        while gc(&store).await.phase != GcPhase::Sweep {
            store.maintain().await.unwrap();
            passes += 1;
            assert!(passes < 40, "the mark phase did not terminate");
        }
        // The mark scan is already past this Realm; only the publish write
        // barrier can protect the snapshot this frame roots.
        store
            .stage_frame(
                generation,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[1], 5, false))),
            )
            .await
            .unwrap()
            .finish();
        generation += 1;
        let epoch = gc(&store).await.epoch;
        passes = 0;
        while gc(&store).await.epoch == epoch {
            store.maintain().await.unwrap();
            passes += 1;
            assert!(passes < 40, "the sweep did not terminate");
        }
        assert_eq!(seen_versions(&store, CURSORS[1], &selector).await, 1);
        assert_eq!(
            store.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        assert!(
            store
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
        // Publishing on every pass still lets whole cycles finish.
        let epoch = gc(&store).await.epoch;
        passes = 0;
        while gc(&store).await.epoch < epoch + 2 {
            store
                .stage_frame(generation, &frame(vec![row(generation + 10, false)], None))
                .await
                .unwrap()
                .finish();
            generation += 1;
            store.maintain().await.unwrap();
            passes += 1;
            assert!(passes < 120, "continuous writes restarted the cycle");
        }
    }

    #[tokio::test]
    async fn maintenance_never_deletes_future_data_or_skips_an_unfinished_batch() {
        let path = path();
        let store = index(&path, 0).await;
        let selector = selector_of(&row(1, false));
        for (generation, snapshot) in CURSORS[..2].iter().enumerate() {
            store
                .stage_frame(
                    generation as u64,
                    &frame(vec![row(1, false)], Some(baseline(snapshot, 5, true))),
                )
                .await
                .unwrap()
                .finish();
        }
        drop(
            store
                .stage_frame(
                    2,
                    &frame(vec![row(1, false)], Some(baseline(CURSORS[2], 5, true))),
                )
                .await
                .unwrap(),
        );
        let future = store.seen_prefix(CURSORS[2], REALM, &selector).unwrap();
        let staged = store
            .backend
            .keys(&future, None, None, PAGE_LIMIT)
            .await
            .unwrap();
        assert_eq!(staged.len(), 1);
        for _ in 0..40 {
            let job = tokio::spawn({
                let store = store.clone();
                async move { store.maintain().await }
            });
            job.abort();
            let _ = job.await;
            store.maintain().await.unwrap();
        }
        assert_eq!(
            store
                .backend
                .keys(&future, None, None, PAGE_LIMIT)
                .await
                .unwrap(),
            staged
        );
        assert_eq!(seen_versions(&store, CURSORS[0], &selector).await, 0);
        assert_eq!(seen_versions(&store, CURSORS[1], &selector).await, 1);
        assert_eq!(
            store.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        store.poison();
        assert!(store.maintain().await.is_err());
        store.confirm_durable_pointer(2).unwrap();
        drop(store);
        let restored = index(&path, 2).await;
        assert_eq!(
            restored.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        assert_eq!(
            restored
                .backend
                .keys(&future, None, None, PAGE_LIMIT)
                .await
                .unwrap(),
            staged
        );
        // The exact-generation retry replaces the abandoned stage byte for byte.
        restored
            .stage_frame(
                2,
                &frame(vec![row(1, false)], Some(baseline(CURSORS[3], 5, true))),
            )
            .await
            .unwrap()
            .finish();
        assert!(
            restored
                .backend
                .keys(&future, None, None, PAGE_LIMIT)
                .await
                .unwrap()
                .is_empty()
        );
        drive(&restored, 80).await;
        assert_eq!(seen_versions(&restored, CURSORS[3], &selector).await, 1);
        assert_eq!(
            restored.read_selector(REALM, &selector).await.unwrap(),
            Some(row(1, false))
        );
        assert!(
            restored
                .read_selector_ready(REALM, &selector)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn continuous_writes_reclaim_both_realms_without_starving_either() {
        let path = path();
        let store = index(&path, 0).await;
        let mut generation = 0;
        for round in 0..6usize {
            for (offset, realm) in [REALM, OTHER_REALM].into_iter().enumerate() {
                let snapshot = CURSORS[round * 2 + offset];
                store
                    .stage_frame(
                        generation,
                        &realm_frame(
                            realm,
                            vec![realm_row(realm, 1)],
                            Some(baseline(snapshot, 5, true)),
                        ),
                    )
                    .await
                    .unwrap()
                    .finish();
                generation += 1;
                store
                    .stage_frame(
                        generation,
                        &realm_frame(realm, vec![realm_row(realm, round as u64 + 10)], None),
                    )
                    .await
                    .unwrap()
                    .finish();
                generation += 1;
                store.maintain().await.unwrap();
            }
        }
        drive(&store, 240).await;
        for (offset, realm) in [REALM, OTHER_REALM].into_iter().enumerate() {
            let selector = selector_of(&realm_row(realm, 1));
            for round in 0..5usize {
                assert_eq!(
                    seen_versions_in_realm(&store, CURSORS[round * 2 + offset], realm, &selector,)
                        .await,
                    0,
                    "stale snapshot survived for realm {realm}"
                );
            }
            assert_eq!(
                seen_versions_in_realm(&store, CURSORS[10 + offset], realm, &selector).await,
                1
            );
            let row_prefix = store.row_prefix(realm, &selector).unwrap();
            assert_eq!(count_keys(&store, &row_prefix).await, 1);
            assert_eq!(
                store.read_selector(realm, &selector).await.unwrap(),
                Some(realm_row(realm, 15))
            );
        }
    }

    #[tokio::test]
    async fn one_maintenance_pass_reclaims_at_most_one_bounded_page() {
        let path = path();
        let store = index(&path, 0).await;
        let members: Vec<TypedCurrentResult> = (0..120)
            .map(|index| {
                member_row(
                    REALM,
                    &format!("ak:did_core:webvh:z6mkfixture{index:03}"),
                    1,
                )
            })
            .collect();
        store
            .stage_frame(
                0,
                &frame(
                    members[..100].to_vec(),
                    Some(members_baseline(CURSORS[0], 5, false)),
                ),
            )
            .await
            .unwrap()
            .finish();
        store
            .stage_frame(
                1,
                &frame(
                    members[100..].to_vec(),
                    Some(members_baseline(CURSORS[0], 5, true)),
                ),
            )
            .await
            .unwrap()
            .finish();
        let seen = format!("{}seen/", store.prefix);
        let total = count_keys(&store, &seen).await;
        assert_eq!(total, 120);
        // A later member-all baseline delivers none of them, so every one of
        // those snapshot references becomes unreachable at once.
        store
            .stage_frame(
                2,
                &frame(
                    vec![row(1, false)],
                    Some(members_baseline(CURSORS[1], 5, true)),
                ),
            )
            .await
            .unwrap()
            .finish();
        let total = count_keys(&store, &seen).await;
        assert_eq!(total, 121);
        let mut intermediate = None;
        for _ in 0..200 {
            store.maintain().await.unwrap();
            let remaining = count_keys(&store, &seen).await;
            if remaining < total {
                intermediate = Some(remaining);
                break;
            }
        }
        let intermediate = intermediate.expect("no unreachable evidence was reclaimed");
        assert!(intermediate > 0, "one pass cleared the whole account");
        assert!(total - intermediate <= PAGE_LIMIT);
        drive(&store, 200).await;
        assert_eq!(count_keys(&store, &seen).await, 1);
        assert_eq!(
            store
                .read_selector(REALM, &selector_of(&members[0]))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .read_selector(REALM, &selector_of(&row(1, false)))
                .await
                .unwrap(),
            Some(row(1, false))
        );
    }

    fn selector_of(entry: &TypedCurrentResult) -> CurrentSelector {
        super::selector_of(entry).clone()
    }
}
