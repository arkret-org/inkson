//! Demand-loaded current selectors, staged independently of the account blob.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use arkret_sdk::{
    AccountId, AccountSubscribeFrame, CurrentMemberCoverage, CurrentResultEntry, CurrentSelector,
    CurrentTarget,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[cfg(not(target_arch = "wasm32"))]
#[path = "current_index/native.rs"]
mod platform;
#[cfg(target_arch = "wasm32")]
#[path = "current_index/wasm.rs"]
mod platform;

pub(crate) const CURRENT_PREFIX: &str = "inkson.current.v1/";
const PAGE_LIMIT: usize = 100;

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
    cut_revision: u64,
    generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RetiredEntry {
    revision: u64,
    target: CurrentTarget,
    digest: String,
    generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CleanupTask {
    realm: String,
    target: String,
    after: Option<String>,
    generation: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CurrentTargetPage {
    pub entries: Vec<CurrentResultEntry>,
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
    fn row_prefix(&self, selector: &CurrentSelector) -> anyhow::Result<String> {
        Ok(format!("{}row/{}/", self.prefix, hash(selector)?))
    }
    fn progress_prefix(&self, realm: &str) -> anyhow::Result<String> {
        Ok(format!("{}progress/{}/", self.prefix, hash(&realm)?))
    }
    fn mark_prefix(&self, realm: &str, target: &str) -> anyhow::Result<String> {
        Ok(format!(
            "{}coverage/{}/{target}/",
            self.prefix,
            hash(&realm)?
        ))
    }
    fn seen_prefix(&self, snapshot: &str, selector: &CurrentSelector) -> anyhow::Result<String> {
        Ok(format!(
            "{}seen/{}/{}/",
            self.prefix,
            hash(&snapshot)?,
            hash(selector)?
        ))
    }
    async fn progress_at(
        &self,
        realm: &str,
        generation: u64,
    ) -> anyhow::Result<garth::CurrentRealmProgress> {
        let prefix = self.progress_prefix(realm)?;
        let mut progress: garth::CurrentRealmProgress =
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
        target: &CurrentTarget,
        generation: u64,
    ) -> anyhow::Result<Option<CoverageMark>> {
        let mut regions = vec![target_key(target)?];
        if matches!(target, CurrentTarget::Member { .. }) {
            regions.push(member_all_key().into());
        }
        let mut strongest: Option<CoverageMark> = None;
        for region in regions {
            if let Some(mark) = self
                .latest::<CoverageMark>(&self.mark_prefix(realm, &region)?, generation)
                .await?
            {
                if strongest.as_ref().is_none_or(|old| {
                    (old.cut_revision, old.generation) <= (mark.cut_revision, mark.generation)
                }) {
                    strongest = Some(mark);
                }
            }
        }
        Ok(strongest)
    }
    async fn raw_selector(
        &self,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<CurrentResultEntry>> {
        let prefix = self.row_prefix(selector)?;
        let row_generation = self.latest_generation(&prefix, generation).await?;
        if let Some(retired) = self.retired(selector, generation).await? {
            if retired.generation >= row_generation {
                return Ok(None);
            }
        }
        self.latest(&prefix, generation).await
    }
    async fn retired(
        &self,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<RetiredEntry>> {
        self.latest(
            &format!("{}retired/{}/", self.prefix, hash(selector)?),
            generation,
        )
        .await
    }
    async fn visible_selector(
        &self,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<CurrentResultEntry>> {
        let Some(entry) = self.raw_selector(selector, generation).await? else {
            return Ok(None);
        };
        let realm = selector
            .scope_ref
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("current selector has no Realm"))?
            .as_str();
        if let Some(mark) = self
            .strongest_mark(realm, entry.target(), generation)
            .await?
        {
            if entry.revision() <= mark.cut_revision
                && self
                    .latest::<bool>(&self.seen_prefix(&mark.snapshot, selector)?, generation)
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
        selector: &CurrentSelector,
    ) -> anyhow::Result<Option<CurrentResultEntry>> {
        let _lease = self.lease.lock().await;
        self.visible_selector(selector, self.generation.load(Ordering::Acquire))
            .await
    }
    pub(crate) async fn read_selector_ready(
        &self,
        selector: &CurrentSelector,
    ) -> anyhow::Result<Option<CurrentResultEntry>> {
        let _lease = self.lease.lock().await;
        let generation = self.generation.load(Ordering::Acquire);
        self.ready_selector(selector, generation).await
    }
    async fn ready_selector(
        &self,
        selector: &CurrentSelector,
        generation: u64,
    ) -> anyhow::Result<Option<CurrentResultEntry>> {
        let Some(entry) = self.visible_selector(selector, generation).await? else {
            return Ok(None);
        };
        let realm = selector
            .scope_ref
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("current selector has no Realm"))?
            .as_str();
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
            .latest_generation(&self.row_prefix(selector)?, generation)
            .await?;
        let pending_covered = progress.needs_refresh
            && progress.baseline.as_ref().is_some_and(|baseline| {
                baseline.coverage.covers(selector, entry.target())
                    && entry.revision() <= baseline.cut_revision
            });
        if pending_covered
            || row_generation < floor
            || entry.revision() < progress.invalidation_revision
        {
            let seen = match &progress.baseline {
                Some(baseline)
                    if progress.invalidated_snapshot.as_ref()
                        != Some(&baseline.snapshot_cursor) =>
                {
                    let seen = self
                        .latest_generation(
                            &self.seen_prefix(baseline.snapshot_cursor.as_str(), selector)?,
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
    pub(crate) async fn read_progress(
        &self,
        realm: &str,
    ) -> anyhow::Result<garth::CurrentRealmProgress> {
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
            if let Some(entry) = self.ready_selector(&selector, generation).await? {
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
        let mut filtered = frame.clone();
        let mut progress_updates = BTreeMap::<String, garth::CurrentRealmProgress>::new();
        if frame.kind == arkret_sdk::AccountSubscribeFrameKind::ResyncRequired {
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
                incoming.validate_demand()?;
                let previous = match progress_updates.remove(realm) {
                    Some(progress) => progress,
                    None => self.progress_at(realm, expected_generation).await?,
                };
                let mut metadata = incoming.clone();
                metadata.current = None;
                let mut plan = garth::plan_current_install(&previous, &metadata, &BTreeMap::new())?;
                let mut accepted = Vec::new();
                let mut delivered = std::collections::BTreeSet::new();
                let entries = incoming
                    .current
                    .as_ref()
                    .map(|current| current.entries.as_slice())
                    .unwrap_or(&[]);
                anyhow::ensure!(entries.len() <= 100, "current selector limit exceeded");
                for entry in entries {
                    if plan.discard_frame {
                        break;
                    }
                    let key = entry.selector().canonical_key()?;
                    anyhow::ensure!(delivered.insert(key.clone()), "duplicate current selector");
                    let old = self
                        .raw_selector(entry.selector(), expected_generation)
                        .await?;
                    let (write, seen) =
                        garth::plan_current_entry(&previous, incoming, entry, old.as_ref())?;
                    if seen {
                        plan.seen_selectors.push(key);
                    }
                    if let Some(retired) =
                        self.retired(entry.selector(), expected_generation).await?
                    {
                        anyhow::ensure!(
                            retired.target == *entry.target(),
                            "retired selector changed its target"
                        );
                        if retired.revision == entry.revision() {
                            anyhow::ensure!(
                                retired.digest == hash(entry)?,
                                "retired current changed at same revision"
                            );
                        }
                        if retired.revision > entry.revision() {
                            continue;
                        }
                    }
                    if !write {
                        continue;
                    }
                    if incoming.baseline.is_none() {
                        if let Some(mark) = self
                            .strongest_mark(realm, entry.target(), expected_generation)
                            .await?
                        {
                            if entry.revision() <= mark.cut_revision
                                && self
                                    .latest_generation(
                                        &self.seen_prefix(&mark.snapshot, entry.selector())?,
                                        expected_generation,
                                    )
                                    .await?
                                    == 0
                            {
                                continue;
                            }
                        }
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
                    if let Some(current) = &mut incoming.current {
                        current.entries = plan.writes.clone();
                    }
                    if let Some(baseline) = &plan.progress.baseline {
                        for selector in &plan.seen_selectors {
                            let selector: CurrentSelector = serde_json::from_str(selector)?;
                            writes.insert(
                                format!(
                                    "{}{suffix}",
                                    self.seen_prefix(baseline.snapshot_cursor.as_str(), &selector)?
                                ),
                                serde_json::to_vec(&true)?,
                            );
                        }
                    }
                    for entry in &plan.writes {
                        writes.insert(
                            format!("{}{suffix}", self.row_prefix(entry.selector())?),
                            serde_json::to_vec(entry)?,
                        );
                        unversioned.insert(
                            format!("{}prune/{}", self.prefix, hash(entry.selector())?),
                            serde_json::to_vec(entry.selector())?,
                        );
                        unversioned.insert(
                            format!(
                                "{}target/{}/{}/{}",
                                self.prefix,
                                hash(realm)?,
                                target_key(entry.target())?,
                                hash(entry.selector())?
                            ),
                            serde_json::to_vec(entry.selector())?,
                        );
                        if matches!(entry.target(), CurrentTarget::Member { .. }) {
                            unversioned.insert(
                                format!(
                                    "{}target/{}/{}/{}",
                                    self.prefix,
                                    hash(realm)?,
                                    member_all_key(),
                                    hash(entry.selector())?
                                ),
                                serde_json::to_vec(entry.selector())?,
                            );
                        }
                    }
                    if let Some(cleanup) = &plan.cleanup {
                        let mut targets = Vec::new();
                        if cleanup.coverage.realm {
                            targets.push(target_key(&CurrentTarget::Realm)?);
                        }
                        for id in &cleanup.coverage.strand_ids {
                            targets.push(target_key(&CurrentTarget::Strand {
                                strand_id: id.clone(),
                            })?);
                        }
                        for id in &cleanup.coverage.event_ids {
                            targets.push(target_key(&CurrentTarget::Event {
                                event_id: id.clone(),
                            })?);
                        }
                        match &cleanup.coverage.members {
                            CurrentMemberCoverage::All => targets.push(member_all_key().into()),
                            CurrentMemberCoverage::Selected { actor_ids } => {
                                for id in actor_ids {
                                    targets.push(target_key(&CurrentTarget::Member {
                                        actor_id: id.clone(),
                                    })?);
                                }
                            }
                        }
                        for target in targets {
                            let prefix = self.mark_prefix(realm, &target)?;
                            let old = self
                                .latest::<CoverageMark>(&prefix, expected_generation)
                                .await?;
                            if old
                                .as_ref()
                                .is_none_or(|old| old.cut_revision <= cleanup.cut_revision)
                            {
                                writes.insert(
                                    format!("{prefix}{suffix}"),
                                    serde_json::to_vec(&CoverageMark {
                                        snapshot: cleanup.snapshot_cursor.to_string(),
                                        cut_revision: cleanup.cut_revision,
                                        generation,
                                    })?,
                                );
                                writes.insert(
                                    format!(
                                        "{}cleanup/{suffix}/{}",
                                        self.prefix,
                                        hash(&(realm, &target))?
                                    ),
                                    serde_json::to_vec(&CleanupTask {
                                        realm: realm.clone(),
                                        target: target.clone(),
                                        after: None,
                                        generation,
                                    })?,
                                );
                            }
                        }
                    }
                }
                progress_updates.insert(realm.clone(), plan.progress.clone());
            }
        }
        for (realm, progress) in progress_updates {
            writes.insert(
                format!("{}{suffix}", self.progress_prefix(&realm)?),
                serde_json::to_vec(&progress)?,
            );
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
        let selector: CurrentSelector = serde_json::from_slice(&bytes)?;
        let row_prefix = self.row_prefix(&selector)?;
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
        let prefix = format!(
            "{}target/{}/{}/",
            self.prefix,
            hash(&task.realm)?,
            task.target
        );
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
        let row_prefix = self.row_prefix(&selector)?;
        let versions = self
            .backend
            .keys(
                &row_prefix,
                Some(&format!("{row_prefix}{}", version(generation))),
                None,
                100,
            )
            .await?;
        let visible = self.visible_selector(&selector, generation).await?;
        let mut deletes = Vec::new();
        let mut writes = Vec::new();
        if visible.is_none() {
            if let Some(key) = versions.first() {
                let bytes = self
                    .backend
                    .get(key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("current version disappeared"))?;
                let entry: CurrentResultEntry = serde_json::from_slice(&bytes)?;
                let row_generation = self.latest_generation(&row_prefix, generation).await?;
                if self
                    .retired(&selector, generation)
                    .await?
                    .is_none_or(|retired| retired.generation < row_generation)
                {
                    writes.push((
                        format!(
                            "{}retired/{}/{}",
                            self.prefix,
                            hash(&selector)?,
                            version(generation)
                        ),
                        serde_json::to_vec(&RetiredEntry {
                            revision: entry.revision(),
                            target: entry.target().clone(),
                            digest: hash(&entry)?,
                            generation,
                        })?,
                    ));
                }
            }
            deletes.extend(versions.iter().cloned());
            if versions.len() < 100 {
                let retired = self.retired(&selector, generation).await?;
                let target = if let Some(key) = versions.first() {
                    let bytes = self
                        .backend
                        .get(key)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("current row disappeared"))?;
                    Some(
                        serde_json::from_slice::<CurrentResultEntry>(&bytes)?
                            .target()
                            .clone(),
                    )
                } else {
                    retired.map(|entry| entry.target)
                };
                if let Some(target) = target {
                    deletes.push(format!(
                        "{}target/{}/{}/{}",
                        self.prefix,
                        hash(&task.realm)?,
                        target_key(&target)?,
                        hash(&selector)?
                    ));
                    if matches!(target, CurrentTarget::Member { .. }) {
                        deletes.push(format!(
                            "{}target/{}/{}/{}",
                            self.prefix,
                            hash(&task.realm)?,
                            member_all_key(),
                            hash(&selector)?
                        ));
                    }
                }
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
    fn row(revision: u64, removed: bool) -> CurrentResultEntry {
        serde_json::from_value(json!({"selector":{"scope_ref":{"kind":"realm","realm_id":REALM},"cell_id":"ak:cell:ak.component.realm.freeze.v1:null"},"target":{"kind":"realm"},"revision":revision,"result":if removed{json!({"status":"removed"})}else{json!({"status":"value","value":null})}})).unwrap()
    }
    fn frame(
        entries: Vec<CurrentResultEntry>,
        baseline: Option<serde_json::Value>,
    ) -> AccountSubscribeFrame {
        let mut realm = json!({"current":{"entries":entries}});
        if let Some(baseline) = baseline {
            realm["baseline"] = baseline;
        }
        serde_json::from_value(
            json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{REALM:realm}}),
        )
        .unwrap()
    }
    fn baseline(snapshot: &str, cut: u64, complete: bool) -> serde_json::Value {
        json!({"snapshot_cursor":snapshot,"cut_revision":cut,"coverage":{"realm":true,"strand_ids":[],"members":{"mode":"selected","actor_ids":[]},"event_ids":[]},"complete":complete})
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
        let selector = row(110, false).selector().clone();
        let row_prefix = index.row_prefix(&selector).unwrap();
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
            index.read_selector(&selector).await.unwrap(),
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
            index.read_selector(&selector).await.unwrap(),
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
                .read_selector(row(1, false).selector())
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
                .read_selector(row(2, true).selector())
                .await
                .unwrap(),
            Some(row(2, true))
        );
        drop(restored);
        let committed = index(&path, 1).await;
        assert_eq!(
            committed
                .read_selector(row(2, true).selector())
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
    #[tokio::test]
    async fn reset_and_invalidation_require_fresh_seen_without_waiting_for_completion() {
        let path = path();
        let index = index(&path, 0).await;
        let selector = row(1, false).selector().clone();
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
        assert!(index.read_selector(&selector).await.unwrap().is_some());
        assert!(
            index
                .read_selector_ready(&selector)
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
                .read_selector_ready(&selector)
                .await
                .unwrap()
                .is_some()
        );
        let invalidation=serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ","realm_invalidations":[{"realm_id":REALM,"revision":0}]})).unwrap();
        index.stage_frame(4, &invalidation).await.unwrap().finish();
        assert!(
            index
                .read_selector_ready(&selector)
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
                .read_selector_ready(&selector)
                .await
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn coverage_cleanup_keeps_post_cut_live_and_rejects_retired_conflicts() {
        let path = path();
        let index = index(&path, 0).await;
        let selector = row(1, false).selector().clone();
        index
            .stage_frame(0, &frame(vec![row(7, false)], None))
            .await
            .unwrap()
            .finish();
        index
            .stage_frame(1, &frame(vec![], Some(baseline("ak:cursor:YQ", 5, true))))
            .await
            .unwrap()
            .finish();
        for _ in 0..4 {
            index.maintain().await.unwrap();
        }
        assert_eq!(
            index.read_selector(&selector).await.unwrap(),
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
        assert!(index.read_selector(&selector).await.unwrap().is_none());
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
            index.read_selector(row(1, false).selector()).await.unwrap(),
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
            index.read_selector(row(1, false).selector()).await.unwrap(),
            Some(row(1, false))
        );
    }
}
