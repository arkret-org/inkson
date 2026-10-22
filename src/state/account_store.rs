//! Account records and current publications share one encrypted KV transaction.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ClientLocalState;
use super::current_index::CurrentIndexLocation;
use super::current_index::platform::Backend;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
mod browser_contract;
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) async fn run_browser_account_persist_fault_contract() -> anyhow::Result<()> {
    browser_contract::run().await
}
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) async fn run_browser_account_record_corruption_contract() -> anyhow::Result<()> {
    browser_contract::corruption().await
}

mod committed_read;
mod record_tree;
pub(crate) use committed_read::CommittedAccountRead;

const CHUNK_BYTES: usize = 48 * 1024;
const GC_BUDGET: u32 = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    revision: u64,
    incarnation: String,
    current_generation: u64,
    sync_cursor_digest: String,
    record_count: u64,
    record_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: Vec<String>,
    blob: String,
    bytes: usize,
    chunks: u32,
    digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Garbage {
    incarnation: String,
    blob: String,
    chunks: u32,
    next: u32,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Checkpoint {
    pub incarnation: String,
    root: Option<Vec<u8>>,
    pub state: ClientLocalState,
    // Persistent tree mutations move complete leaf nodes. Share immutable
    // metadata across checkpoints without placing each Record in those frames.
    records: imbl::OrdMap<Vec<String>, Arc<Record>>,
    physical: imbl::OrdMap<String, Arc<Record>>,
    tree: record_tree::Tree,
}

#[derive(Clone, Debug)]
pub(super) struct Plan {
    pub check: (String, Option<Vec<u8>>),
    pub deletes: Vec<String>,
    pub writes: Vec<(String, Vec<u8>)>,
    pub checkpoint: Checkpoint,
}

fn prefix(scope: &str) -> String {
    format!("{}accounts/{scope}/", super::current_index::CURRENT_PREFIX)
}
pub(super) fn root_key(scope: &str) -> String {
    format!("{}{scope}", roots_prefix())
}
fn roots_prefix() -> String {
    format!("{}accounts/roots/", super::current_index::CURRENT_PREFIX)
}
fn validate_incarnation(incarnation: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        incarnation.len() == 36
            && incarnation
                .bytes()
                .enumerate()
                .all(|(i, c)| if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }),
        "invalid account storage incarnation"
    );
    Ok(())
}
fn item_scope(scope: &str, incarnation: &str) -> anyhow::Result<String> {
    validate_incarnation(incarnation)?;
    Ok(format!("{scope}/incarnations/{incarnation}"))
}
fn active_item_scope(scope: &str, root: Option<&[u8]>) -> anyhow::Result<Option<String>> {
    root.map(|root| {
        let root: Root = serde_json::from_slice(root)?;
        item_scope(scope, &root.incarnation)
    })
    .transpose()
}

fn record_field_prefix(scope: &str, field: &str) -> String {
    format!("{}records/{field}/", prefix(scope))
}
fn scope_bucket(key: &str) -> anyhow::Result<String> {
    Ok(format!(
        "{}/",
        arkret_sdk::canonical::canonical_sha256(&key.split('\u{1f}').next().unwrap_or(key))?
            .replace(':', "-")
    ))
}
fn record_key(scope: &str, path: &[String]) -> anyhow::Result<String> {
    let field = path
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty account record path"))?;
    let bucket = if field == "mls_snapshots" && path.len() == 2 {
        scope_bucket(&path[1])?
    } else {
        String::new()
    };
    Ok(format!(
        "{}{bucket}{}",
        record_field_prefix(scope, field),
        arkret_sdk::canonical::canonical_sha256(&path)?.replace(':', "-")
    ))
}

fn chunk_key(scope: &str, blob: &str, index: u32) -> String {
    format!("{}chunks/{blob}/{index:010}", prefix(scope))
}

fn record_path_hash(path: &[String]) -> anyhow::Result<[u8; 32]> {
    Ok(arkret_sdk::canonical::sha256_bytes(
        arkret_sdk::canonical::canonical_json_bytes(&path)?,
    ))
}
fn record_hash(record: &Record) -> anyhow::Result<[u8; 32]> {
    Ok(arkret_sdk::canonical::sha256_bytes(
        arkret_sdk::canonical::canonical_json_bytes(record)?,
    ))
}

pub(super) fn plan(scope: &str, old: &Checkpoint, state: ClientLocalState) -> anyhow::Result<Plan> {
    let state = super::e2ee_safe_persist_state_owned(state);
    let changes = state.durable_changes(&old.state)?;
    if changes.0.is_empty() && old.root.is_some() {
        return Ok(Plan {
            check: (root_key(scope), old.root.clone()),
            deletes: Vec::new(),
            writes: Vec::new(),
            checkpoint: old.clone(),
        });
    }

    let revision = old
        .root
        .as_ref()
        .map(|root| serde_json::from_slice::<Root>(root))
        .transpose()?
        .map_or(Ok(1), |root| {
            root.revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("account checkpoint exhausted"))
        })?;
    let mut checkpoint = old.clone();
    if checkpoint.incarnation.is_empty() {
        checkpoint.incarnation = crate::operation::uuid_v7();
    }
    let data_scope = item_scope(scope, &checkpoint.incarnation)?;
    let mut deletes = Vec::new();
    let mut writes = Vec::new();
    for change in changes.0 {
        let key = record_key(&data_scope, &change.path)?;
        if let Some(previous) = checkpoint.records.remove(&change.path) {
            checkpoint.physical.remove(&key);
            checkpoint.tree.set(record_path_hash(&change.path)?, None);
            let task = Garbage {
                incarnation: checkpoint.incarnation.clone(),
                blob: previous.blob.clone(),
                chunks: previous.chunks,
                next: 0,
            };
            writes.push((
                format!("{}gc/{}", prefix(scope), previous.blob),
                serde_json::to_vec(&task)?,
            ));
        }
        match change.value {
            None => deletes.push(key),
            Some(bytes) => {
                let blob = crate::operation::uuid_v7();
                let chunks = u32::try_from(bytes.len().div_ceil(CHUNK_BYTES))?;
                let record = Record {
                    path: change.path.clone(),
                    blob: blob.clone(),
                    bytes: bytes.len(),
                    chunks,
                    digest: arkret_sdk::canonical::sha256_digest(&bytes),
                };
                for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
                    // The shared KV authenticates UTF-8 payloads. Hex bounds expansion
                    // and avoids splitting a multi-byte JSON character at a chunk cut.
                    writes.push((
                        chunk_key(&data_scope, &blob, index as u32),
                        hex::encode(chunk).into_bytes(),
                    ));
                }
                let metadata = serde_json::to_vec(&record)?;
                anyhow::ensure!(
                    metadata.len() <= CHUNK_BYTES,
                    "account record metadata exceeds its physical bound"
                );
                let record = Arc::new(record);
                checkpoint.physical.insert(key.clone(), record.clone());
                checkpoint
                    .tree
                    .set(record_path_hash(&change.path)?, Some(record_hash(&record)?));
                writes.push((key, metadata));
                checkpoint.records.insert(change.path, record);
            }
        }
    }
    checkpoint.root = Some(serde_json::to_vec(&Root {
        revision,
        incarnation: checkpoint.incarnation.clone(),
        current_generation: state.current_generation,
        sync_cursor_digest: arkret_sdk::canonical::canonical_sha256(&state.sync_cursor)?,
        record_count: checkpoint.records.len() as u64,
        record_digest: checkpoint.tree.digest(),
    })?);
    checkpoint.state = state;
    writes.push((
        root_key(scope),
        checkpoint
            .root
            .clone()
            .ok_or_else(|| anyhow::anyhow!("new account root is missing"))?,
    ));
    Ok(Plan {
        check: (root_key(scope), old.root.clone()),
        deletes,
        writes,
        checkpoint,
    })
}

fn install_json(root: &mut Value, path: &[String], value: Value) -> anyhow::Result<()> {
    anyhow::ensure!(!path.is_empty(), "empty account record path");
    let mut target = root;
    for (index, key) in path.iter().enumerate() {
        let last = index + 1 == path.len();
        if let Value::Array(array) = target {
            if (index == 1 && super::account_items::SET_FIELDS.contains(&path[0].as_str()))
                || (path[0] == "station_cas_projection"
                    && index == 3
                    && path[2] == "live_overrides")
                || (path[0] == "demand_sync"
                    && index == 2
                    && ["list_seen", "device_ids"].contains(&path[1].as_str()))
                || (path[0] == "demand_sync"
                    && index == 4
                    && path[1] == "channels"
                    && ["seen", "mutated"].contains(&path[3].as_str()))
            {
                anyhow::ensure!(last, "nested account set record");
                array.push(value);
                return Ok(());
            }
            let offset: usize = key.parse()?;
            anyhow::ensure!(offset <= 1_000_000, "invalid account sequence offset");
            array.resize(array.len().max(offset + 1), Value::Null);
            if last {
                array[offset] = value;
                return Ok(());
            }
            target = &mut array[offset];
        } else {
            if target.is_null() {
                *target = Value::Object(Default::default());
            }
            let object = target
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("account path container differs"))?;
            if last {
                object.insert(key.clone(), value);
                return Ok(());
            }
            target = object
                .entry(key.clone())
                .or_insert_with(|| Value::Object(Default::default()));
        }
    }
    unreachable!()
}

fn decode_records(
    root: Option<Vec<u8>>,
    mut records: Vec<(String, Record, Vec<u8>)>,
    scope: &str,
) -> anyhow::Result<Checkpoint> {
    records.sort_by_key(|(_, record, _)| record.path.len());
    let mut value = serde_json::to_value(ClientLocalState::default())?;
    let mut entries = imbl::OrdMap::new();
    let mut physical = imbl::OrdMap::new();
    let mut tree = record_tree::Tree::default();
    for (key, record, bytes) in records {
        anyhow::ensure!(
            key == record_key(scope, &record.path)?,
            "account record path binding differs"
        );
        anyhow::ensure!(
            bytes.len() == record.bytes
                && arkret_sdk::canonical::sha256_digest(&bytes) == record.digest,
            "account record is incomplete or corrupt"
        );
        tree.set(record_path_hash(&record.path)?, Some(record_hash(&record)?));
        let record = Arc::new(record);
        physical.insert(key.clone(), record.clone());
        install_json(&mut value, &record.path, serde_json::from_slice(&bytes)?)?;
        anyhow::ensure!(
            entries.insert(record.path.clone(), record).is_none(),
            "duplicate account record"
        );
    }
    let state: ClientLocalState = serde_json::from_value(value)?;
    if let Some(root) = &root {
        let root: Root = serde_json::from_slice(root)?;
        anyhow::ensure!(
            root.record_count == entries.len() as u64 && root.record_digest == tree.digest(),
            "account record set is incomplete or replayed"
        );
        anyhow::ensure!(
            root.current_generation == state.current_generation
                && root.sync_cursor_digest
                    == arkret_sdk::canonical::canonical_sha256(&state.sync_cursor)?,
            "account cursor and publication root differ"
        );
    } else {
        anyhow::ensure!(entries.is_empty(), "account records have no committed root");
    }
    let incarnation = root
        .as_ref()
        .map(|root| serde_json::from_slice::<Root>(root).map(|root| root.incarnation))
        .transpose()?
        .unwrap_or_default();
    Ok(Checkpoint {
        incarnation,
        root,
        state,
        records: entries,
        physical,
        tree,
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn load(backend: &Backend, scope: &str) -> anyhow::Result<Checkpoint> {
    backend.snapshot(|snapshot| load_snapshot(snapshot, scope))
}
#[cfg(not(target_arch = "wasm32"))]
fn load_snapshot(
    backend: &super::current_index::platform::Snapshot<'_>,
    scope: &str,
) -> anyhow::Result<Checkpoint> {
    // Validate the root again after the paged read. Concurrent publishers cannot
    // turn a mixed read into a usable checkpoint, even through another connection.
    let account_root = root_key(scope);
    let root = backend.get_sync(&account_root)?;
    let Some(data_scope) = active_item_scope(scope, root.as_deref())? else {
        anyhow::ensure!(
            backend
                .scan_sync(&format!("{}incarnations/", prefix(scope)), None, 1)?
                .is_empty(),
            "account records lost their committed root"
        );
        return Ok(Checkpoint::default());
    };
    let scope = data_scope.as_str();
    let rows_prefix = format!("{}records/", prefix(scope));
    let mut after = None;
    let mut records = Vec::new();
    loop {
        let rows = backend.scan_sync(&rows_prefix, after.as_deref(), 100)?;
        if rows.is_empty() {
            break;
        }
        after = rows.last().map(|(key, _)| key.clone());
        for (key, bytes) in rows {
            anyhow::ensure!(
                bytes.len() <= CHUNK_BYTES,
                "oversized account record metadata"
            );
            let record: Record = serde_json::from_slice(&bytes)?;
            let mut data = Vec::new();
            anyhow::ensure!(
                record.chunks == u32::try_from(record.bytes.div_ceil(CHUNK_BYTES))?,
                "invalid account chunk count"
            );
            for index in 0..record.chunks {
                let chunk = backend
                    .get_sync(&chunk_key(scope, &record.blob, index))?
                    .ok_or_else(|| anyhow::anyhow!("account record chunk missing"))?;
                anyhow::ensure!(chunk.len() <= CHUNK_BYTES * 2, "oversized account chunk");
                data.extend(hex::decode(chunk)?);
            }
            records.push((key, record, data));
        }
    }
    anyhow::ensure!(
        root == backend.get_sync(&account_root)?,
        "account changed during hydration"
    );
    decode_records(root, records, scope)
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn gc(backend: &Backend, scope: &str) -> anyhow::Result<bool> {
    let Some((key, bytes)) = backend
        .scan_sync(&format!("{}gc/", prefix(scope)), None, 1)?
        .pop()
    else {
        return Ok(false);
    };
    let task: Garbage = serde_json::from_slice(&bytes)?;
    let (deletes, writes) = gc_step(scope, &key, task)?;
    backend.apply_checked_sync(Some((key, Some(bytes))), deletes, writes)?;
    Ok(true)
}

type RecordBatch = (Vec<String>, Vec<(String, Vec<u8>)>);

fn gc_step(scope: &str, key: &str, mut task: Garbage) -> anyhow::Result<RecordBatch> {
    anyhow::ensure!(
        task.next <= task.chunks && key == format!("{}gc/{}", prefix(scope), task.blob),
        "invalid account GC task"
    );
    let data_scope = item_scope(scope, &task.incarnation)?;
    let end = task.next.saturating_add(GC_BUDGET).min(task.chunks);
    let mut deletes = (task.next..end)
        .map(|i| chunk_key(&data_scope, &task.blob, i))
        .collect::<Vec<_>>();
    task.next = end;
    let writes = if end == task.chunks {
        deletes.push(key.to_owned());
        Vec::new()
    } else {
        vec![(key.to_owned(), serde_json::to_vec(&task)?)]
    };
    Ok((deletes, writes))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn load_async(backend: &Backend, scope: &str) -> anyhow::Result<Checkpoint> {
    for _ in 0..3 {
        let before = backend.get(&root_key(scope)).await?;
        match load_async_attempt(backend, scope).await {
            Ok(checkpoint) => return Ok(checkpoint),
            Err(error) => {
                if before == backend.get(&root_key(scope)).await? {
                    return Err(error);
                }
            }
        }
    }
    anyhow::bail!("account changed repeatedly during hydration")
}

#[cfg(target_arch = "wasm32")]
async fn load_async_attempt(backend: &Backend, scope: &str) -> anyhow::Result<Checkpoint> {
    let account_root = root_key(scope);
    let root = backend.get(&account_root).await?;
    let Some(data_scope) = active_item_scope(scope, root.as_deref())? else {
        anyhow::ensure!(
            backend
                .keys(&format!("{}incarnations/", prefix(scope)), None, None, 1)
                .await?
                .is_empty(),
            "account records lost their committed root"
        );
        return Ok(Checkpoint::default());
    };
    let scope = data_scope.as_str();
    let rows_prefix = format!("{}records/", prefix(scope));
    let mut after = None;
    let mut records = Vec::new();
    loop {
        let rows = backend
            .scan(&rows_prefix, None, after.as_deref(), 100)
            .await?;
        if rows.is_empty() {
            break;
        }
        after = rows.last().map(|(key, _)| key.clone());
        for (key, bytes) in rows {
            anyhow::ensure!(
                bytes.len() <= CHUNK_BYTES,
                "oversized account record metadata"
            );
            let record: Record = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                record.chunks == u32::try_from(record.bytes.div_ceil(CHUNK_BYTES))?,
                "invalid account chunk count"
            );
            let mut data = Vec::new();
            for index in 0..record.chunks {
                let chunk = backend
                    .get(&chunk_key(scope, &record.blob, index))
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("account record chunk missing"))?;
                anyhow::ensure!(chunk.len() <= CHUNK_BYTES * 2, "oversized account chunk");
                data.extend(hex::decode(chunk)?);
            }
            records.push((key, record, data));
        }
    }
    anyhow::ensure!(
        root == backend.get(&account_root).await?,
        "account changed during hydration"
    );
    decode_records(root, records, scope)
}

#[cfg(target_arch = "wasm32")]
async fn gc_async(backend: &Backend, scope: &str) -> anyhow::Result<bool> {
    let Some((key, bytes)) = backend
        .scan(&format!("{}gc/", prefix(scope)), None, None, 1)
        .await?
        .pop()
    else {
        return Ok(false);
    };
    let (deletes, writes) = gc_step(scope, &key, serde_json::from_slice(&bytes)?)?;
    backend
        .apply_checked(Some((key, Some(bytes))), deletes, writes)
        .await?;
    Ok(true)
}

#[derive(Debug)]
pub(super) struct Barrier {
    #[cfg(target_arch = "wasm32")]
    result: tokio::sync::watch::Receiver<Option<Result<(), String>>>,
}
impl Barrier {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn ready() -> Self {
        Self {}
    }
    pub async fn wait(self) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        let mut result = self.result;
        #[cfg(target_arch = "wasm32")]
        loop {
            if let Some(result) = result.borrow().clone() {
                return result.map_err(anyhow::Error::msg);
            }
            result
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("account writer stopped before durable completion"))?;
        }
        #[cfg(not(target_arch = "wasm32"))]
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CachedCheckpoint {
    pub checkpoint: Checkpoint,
    #[cfg(target_arch = "wasm32")]
    pub last_committed: Arc<Mutex<Checkpoint>>,
    #[cfg(target_arch = "wasm32")]
    pub failed: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    pub recovering: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    pub conflicted: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    pub queued: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(target_arch = "wasm32")]
    pub pending_result: Option<tokio::sync::watch::Receiver<Option<Result<(), String>>>>,
}

#[cfg(target_arch = "wasm32")]
pub(super) mod browser {
    use std::sync::OnceLock;
    use std::sync::atomic::Ordering;

    use super::*;
    static CACHE: OnceLock<Mutex<BTreeMap<String, Arc<CachedCheckpoint>>>> = OnceLock::new();
    static ERRORS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    fn errors() -> &'static Mutex<BTreeMap<String, String>> {
        ERRORS.get_or_init(Default::default)
    }
    pub(in crate::state) fn cached_result(scope: &str) -> anyhow::Result<Option<CachedCheckpoint>> {
        let cached = cached(scope);
        if cached
            .as_ref()
            .is_some_and(|cached| cached.recovering.load(Ordering::Acquire))
        {
            return Ok(cached);
        }
        if let Some(error) = errors().lock().unwrap().get(scope) {
            anyhow::bail!("account records unavailable: {error}");
        }
        Ok(cached)
    }
    pub(in crate::state) async fn persisted_scopes() -> anyhow::Result<Vec<String>> {
        let backend = Backend::open(CurrentIndexLocation {}).await?;
        let prefix = roots_prefix();
        let mut after = None;
        let mut scopes = Vec::new();
        loop {
            let keys = backend.keys(&prefix, None, after.as_deref(), 100).await?;
            if keys.is_empty() {
                break;
            }
            after = keys.last().cloned();
            scopes.extend(keys.into_iter().map(|key| key[prefix.len()..].to_owned()));
        }
        Ok(scopes)
    }
    fn cache() -> &'static Mutex<BTreeMap<String, Arc<CachedCheckpoint>>> {
        CACHE.get_or_init(Default::default)
    }
    static WRITERS: OnceLock<Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    pub fn cached(scope: &str) -> Option<CachedCheckpoint> {
        cache()
            .lock()
            .unwrap()
            .get(scope)
            .map(|value| value.as_ref().clone())
    }
    pub async fn hydrate(scope: &str) -> anyhow::Result<()> {
        let backend = Backend::open(CurrentIndexLocation {}).await?;
        let checkpoint = match load_async(&backend, scope).await {
            Ok(checkpoint) => {
                errors().lock().unwrap().remove(scope);
                checkpoint
            }
            Err(error) => {
                errors()
                    .lock()
                    .unwrap()
                    .insert(scope.to_owned(), error.to_string());
                return Err(error);
            }
        };
        let cached = CachedCheckpoint {
            last_committed: Arc::new(Mutex::new(checkpoint.clone())),
            checkpoint,
            ..Default::default()
        };
        cache()
            .lock()
            .unwrap()
            .insert(scope.to_owned(), Arc::new(cached));
        // A restart resumes the persisted queue without scanning account data.
        schedule_gc(backend, scope.to_owned());
        Ok(())
    }
    fn schedule_gc(backend: Backend, scope: String) {
        static WORKERS: OnceLock<Mutex<BTreeMap<String, Arc<std::sync::atomic::AtomicBool>>>> =
            OnceLock::new();
        let workers = WORKERS.get_or_init(Default::default);
        let dirty = {
            let Ok(mut registry) = workers.lock() else {
                tracing::warn!("account GC registry lock poisoned; durable task retained");
                return;
            };
            if let Some(dirty) = registry.get(&scope) {
                dirty.store(true, Ordering::Release);
                return;
            }
            let dirty = Arc::new(std::sync::atomic::AtomicBool::new(false));
            registry.insert(scope.clone(), dirty.clone());
            dirty
        };
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                match gc_async(&backend, &scope).await {
                    Ok(true) => {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1))
                            .await;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error,"account GC retained durable task for retry");
                    }
                }
                let Ok(mut registry) = workers.lock() else {
                    tracing::warn!("account GC registry lock poisoned; durable task retained");
                    return;
                };
                if dirty.swap(false, Ordering::AcqRel) {
                    continue;
                }
                registry.remove(&scope);
                break;
            }
        });
    }
    fn reset_current(incarnation: &str) -> bool {
        super::super::LocalStateStore::default()
            .read_root()
            .pending_login
            .as_ref()
            .and_then(|pending| pending.anonymous_storage_incarnation.as_deref())
            == Some(incarnation)
    }
    pub(in crate::state) async fn resume_reset(incarnation: &str) -> anyhow::Result<Checkpoint> {
        validate_incarnation(incarnation)?;
        let scope = super::super::ANONYMOUS_ACCOUNT_NAMESPACE;
        let backend = Backend::open(CurrentIndexLocation {}).await?;
        for _ in 0..3 {
            anyhow::ensure!(
                reset_current(incarnation),
                "anonymous reset belongs to a replaced login"
            );
            if let Ok(Some(root)) = backend.get(&root_key(scope)).await
                && let Ok(root) = serde_json::from_slice::<Root>(&root)
                && root.incarnation == incarnation
            {
                return load_async(&backend, scope).await;
            }
            anyhow::ensure!(
                backend
                    .keys(
                        &format!(
                            "{}/",
                            prefix(&item_scope(scope, incarnation)?).trim_end_matches('/')
                        ),
                        None,
                        None,
                        1
                    )
                    .await?
                    .is_empty(),
                "anonymous reset target already has unverified records"
            );
            let raw = backend.raw(&root_key(scope)).await?;
            let mut plan = fresh_anonymous_plan(incarnation)?;
            preserve_anonymous_root(&mut plan, incarnation, raw.as_deref())?;
            anyhow::ensure!(
                reset_current(incarnation),
                "anonymous reset belongs to a replaced login"
            );
            match backend
                .apply_raw_checked((root_key(scope), raw), plan.deletes, plan.writes)
                .await
            {
                Ok(()) => return Ok(plan.checkpoint),
                Err(error) if error.to_string().starts_with("account checkpoint changed") => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        anyhow::bail!("anonymous reset repeatedly conflicted")
    }
    pub(in crate::state) fn enqueue_reset(
        incarnation: String,
        corrupt: Arc<Mutex<std::collections::BTreeSet<String>>>,
        health: Arc<Mutex<Option<String>>>,
    ) -> anyhow::Result<CachedCheckpoint> {
        let scope = super::super::ANONYMOUS_ACCOUNT_NAMESPACE.to_owned();
        let plan = fresh_anonymous_plan(&incarnation)?;
        let (sender, result) = tokio::sync::watch::channel(None);
        let cached = CachedCheckpoint {
            checkpoint: plan.checkpoint,
            last_committed: Default::default(),
            pending_result: Some(result),
            ..Default::default()
        };
        cached.recovering.store(true, Ordering::Release);
        cached.queued.store(1, Ordering::Release);
        let writer = WRITERS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(scope.clone())
            .or_default()
            .clone();
        cache()
            .lock()
            .unwrap()
            .insert(scope.clone(), Arc::new(cached.clone()));
        let pending = cached.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _guard = writer.lock().await;
            let outcome = resume_reset(&incarnation).await;
            pending.recovering.store(false, Ordering::Release);
            let result = match outcome {
                Ok(checkpoint) => {
                    *pending.last_committed.lock().unwrap() = checkpoint;
                    errors().lock().unwrap().remove(&scope);
                    corrupt.lock().unwrap().remove(&scope);
                    health.lock().unwrap().take();
                    Ok(())
                }
                Err(error) => {
                    pending.failed.store(true, Ordering::Release);
                    *health.lock().unwrap() = Some(error.to_string());
                    Err(error.to_string())
                }
            };
            pending.queued.fetch_sub(1, Ordering::AcqRel);
            sender.send_replace(Some(result));
        });
        Ok(cached)
    }
    pub fn enqueue(
        scope: String,
        cached: &mut CachedCheckpoint,
        state: ClientLocalState,
        current: Option<super::super::current_index::AccountPublication>,
        health: Arc<Mutex<Option<String>>>,
    ) -> anyhow::Result<Barrier> {
        anyhow::ensure!(
            crate::secure_key_store::wasm_secure_store_ready(),
            "secure account store is not ready"
        );
        anyhow::ensure!(
            !cached.conflicted.load(Ordering::Acquire),
            "account checkpoint conflicted; reload committed state before retry"
        );
        if cached.failed.swap(false, Ordering::AcqRel) {
            cached.checkpoint = cached.last_committed.lock().unwrap().clone();
            cached.pending_result = None;
        }
        cached
            .queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 32).then_some(count + 1)
            })
            .map_err(|_| anyhow::anyhow!("account transaction queue reached its physical bound"))?;
        struct Permit(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Permit {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let permit = Permit(cached.queued.clone());
        let needs_current = state.current_generation > cached.checkpoint.state.current_generation;
        anyhow::ensure!(
            !needs_current || current.is_some(),
            "account generation has no bound current publication"
        );
        let mut plan = plan(&scope, &cached.checkpoint, state)?;
        if needs_current && let Some(current) = &current {
            plan.deletes.extend(current.deletes.iter().cloned());
            plan.writes.extend(current.writes.iter().cloned());
        }
        let publication_lease = if needs_current {
            current
                .as_ref()
                .map(|publication| publication._lease.clone())
        } else {
            None
        };
        let predecessor = cached.pending_result.clone();
        let writer = WRITERS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(scope.clone())
            .or_default()
            .clone();
        let (sender, result) = tokio::sync::watch::channel(None);
        cached.checkpoint = plan.checkpoint.clone();
        cached.pending_result = Some(result.clone());
        let committed = cached.last_committed.clone();
        let failed = cached.failed.clone();
        let conflicted = cached.conflicted.clone();
        let optimistic = cached.clone();
        cache()
            .lock()
            .unwrap()
            .insert(scope.clone(), Arc::new(optimistic));
        // The job, not its waiter or the mounted UI, owns the commit.
        wasm_bindgen_futures::spawn_local(async move {
            let _permit = permit;
            let _publication_lease = publication_lease;
            let _guard = writer.lock().await;
            let result: anyhow::Result<()> = async {
                if let Some(predecessor) = predecessor {
                    match predecessor.borrow().as_ref() {
                        Some(Ok(())) => {}
                        Some(Err(error)) => {
                            anyhow::bail!("earlier account transaction failed: {error}")
                        }
                        None => anyhow::bail!("earlier account transaction has no terminal result"),
                    }
                }
                let backend = Backend::open(CurrentIndexLocation {}).await?;
                if plan.check.1.is_none() {
                    anyhow::ensure!(
                        backend
                            .keys(&format!("{}incarnations/", prefix(&scope)), None, None, 1)
                            .await?
                            .is_empty(),
                        "account records lost their committed root"
                    );
                }
                backend
                    .apply_checked(Some(plan.check), plan.deletes, plan.writes)
                    .await?;
                *committed.lock().unwrap() = plan.checkpoint;
                // Maintenance failure cannot turn an already committed cursor
                // into a false failed acknowledgement. The durable task survives.
                schedule_gc(backend, scope.clone());
                Ok(())
            }
            .await;
            if let Err(error) = &result {
                failed.store(true, Ordering::Release);
                if error.to_string().starts_with("account checkpoint changed") {
                    conflicted.store(true, Ordering::Release);
                }
            } else {
                failed.store(false, Ordering::Release);
            }
            if super::super::LocalStateStore::default().effective_account_key() == scope {
                *health.lock().unwrap() = result.as_ref().err().map(|error| error.to_string());
            }
            sender.send_replace(Some(result.map_err(|error| error.to_string())));
        });
        Ok(Barrier { result })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn schedule_gc(backend: Backend, scope: String, storage: String) {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    static WORKERS: OnceLock<Mutex<BTreeMap<String, Arc<AtomicBool>>>> = OnceLock::new();
    if matches!(backend.scan_sync(&format!("{}gc/", prefix(&scope)), None, 1), Ok(rows) if rows.is_empty())
    {
        return;
    }
    let workers = WORKERS.get_or_init(Default::default);
    let identity = format!("{storage}/{scope}");
    let dirty = {
        let Ok(mut registry) = workers.lock() else {
            tracing::warn!("account GC registry lock poisoned; durable task retained");
            return;
        };
        if let Some(dirty) = registry.get(&identity) {
            dirty.store(true, Ordering::Release);
            return;
        }
        let dirty = Arc::new(AtomicBool::new(false));
        registry.insert(identity.clone(), dirty.clone());
        dirty
    };
    std::thread::spawn(move || {
        loop {
            match gc(&backend, &scope) {
                Ok(true) => {
                    std::thread::yield_now();
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error,"account GC retained durable task for retry");
                }
            }
            let Ok(mut registry) = workers.lock() else {
                tracing::warn!("account GC registry lock poisoned; durable task retained");
                return;
            };
            if dirty.swap(false, Ordering::AcqRel) {
                continue;
            }
            registry.remove(&identity);
            break;
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn record_value(
    snapshot: &super::current_index::platform::Snapshot<'_>,
    scope: &str,
    key: &str,
    record: &Record,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        key == record_key(scope, &record.path)?,
        "account record key differs"
    );
    anyhow::ensure!(
        record.chunks == u32::try_from(record.bytes.div_ceil(CHUNK_BYTES))?,
        "invalid account chunk count"
    );
    let mut bytes = Vec::new();
    for index in 0..record.chunks {
        let chunk = snapshot
            .get_sync(&chunk_key(scope, &record.blob, index))?
            .ok_or_else(|| anyhow::anyhow!("account record chunk missing"))?;
        anyhow::ensure!(chunk.len() <= CHUNK_BYTES * 2, "oversized account chunk");
        bytes.extend(hex::decode(chunk)?);
    }
    anyhow::ensure!(
        bytes.len() == record.bytes
            && arkret_sdk::canonical::sha256_digest(&bytes) == record.digest,
        "account record is incomplete or corrupt"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn committed_map<T: serde::de::DeserializeOwned + Clone>(
    backend: &Backend,
    scope: &str,
    field: &str,
    scope_key: Option<&str>,
    expected: &Checkpoint,
) -> anyhow::Result<imbl::OrdMap<String, T>> {
    backend.snapshot(|snapshot| {
        anyhow::ensure!(
            snapshot.get_sync(&root_key(scope))? == expected.root,
            committed_read::CommittedReadChanged::Before
        );
        if expected.incarnation.is_empty() {
            return Ok(imbl::OrdMap::new());
        }
        let data_scope = item_scope(scope, &expected.incarnation)?;
        let mut prefix = record_field_prefix(&data_scope, field);
        if let Some(key) = scope_key {
            prefix.push_str(&scope_bucket(key)?);
        }
        let mut result = imbl::OrdMap::new();
        for (key, physical_record) in expected
            .physical
            .range(prefix.clone()..format!("{prefix}~"))
        {
            let path = &physical_record.path;
            let bytes = snapshot
                .get_sync(key)?
                .ok_or_else(|| anyhow::anyhow!("committed account record missing"))?;
            anyhow::ensure!(
                bytes.len() <= CHUNK_BYTES,
                "oversized account record metadata"
            );
            let record: Record = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                Some(&record) == expected.records.get(path).map(Arc::as_ref),
                "committed account record was replayed"
            );
            anyhow::ensure!(
                record.path.len() == 2 && record.path[0] == field,
                "unexpected account map record"
            );
            result.insert(
                record.path[1].clone(),
                serde_json::from_value(record_value(snapshot, &data_scope, key, &record)?)?,
            );
        }
        Ok(result)
    })
}

pub(super) fn published_generation(root: &[u8]) -> anyhow::Result<u64> {
    Ok(serde_json::from_slice::<Root>(root)?.current_generation)
}

fn fresh_anonymous_plan(incarnation: &str) -> anyhow::Result<Plan> {
    validate_incarnation(incarnation)?;
    let base = Checkpoint {
        incarnation: incarnation.to_owned(),
        ..Default::default()
    };
    plan(
        super::ANONYMOUS_ACCOUNT_NAMESPACE,
        &base,
        ClientLocalState::default(),
    )
}
fn preserve_anonymous_root(
    plan: &mut Plan,
    incarnation: &str,
    raw: Option<&[u8]>,
) -> anyhow::Result<()> {
    if let Some(raw) = raw {
        anyhow::ensure!(
            raw.len() <= CHUNK_BYTES,
            "unreadable anonymous root exceeds its preservation bound"
        );
        plan.writes.push((format!("{}quarantine/{incarnation}/root",prefix(super::ANONYMOUS_ACCOUNT_NAMESPACE)),serde_json::to_vec(&serde_json::json!({
            "original_key":root_key(super::ANONYMOUS_ACCOUNT_NAMESPACE),"ciphertext":hex::encode(raw)
        }))?));
    }
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn reset_anonymous(
    backend: &Backend,
    incarnation: &str,
    guard: impl Fn() -> bool,
) -> anyhow::Result<Checkpoint> {
    anyhow::ensure!(guard(), "anonymous reset belongs to a replaced login");
    let scope = super::ANONYMOUS_ACCOUNT_NAMESPACE;
    if let Ok(Some(root)) = backend.get_sync(&root_key(scope))
        && let Ok(root) = serde_json::from_slice::<Root>(&root)
        && root.incarnation == incarnation
    {
        return load(backend, scope);
    }
    anyhow::ensure!(
        backend
            .scan_sync(&prefix(&item_scope(scope, incarnation)?), None, 1)?
            .is_empty(),
        "anonymous reset target already has unverified records"
    );
    let raw = backend.get_raw_sync(&root_key(scope))?;
    let mut plan = fresh_anonymous_plan(incarnation)?;
    preserve_anonymous_root(&mut plan, incarnation, raw.as_deref())?;
    anyhow::ensure!(guard(), "anonymous reset belongs to a replaced login");
    backend.apply_raw_checked_sync((root_key(scope), raw), plan.deletes, plan.writes)?;
    Ok(plan.checkpoint)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) fn decoded_records_for_test(backend: &Backend, scope: &str) -> anyhow::Result<String> {
    let checkpoint = load(backend, scope)?;
    if checkpoint.incarnation.is_empty() {
        return Ok(String::new());
    }
    let data_scope = item_scope(scope, &checkpoint.incarnation)?;
    backend.snapshot(|snapshot| {
        let mut text = String::new();
        for (key, physical_record) in &checkpoint.physical {
            let path = &physical_record.path;
            let record = &checkpoint.records[path];
            text.push_str(&serde_json::to_string(path)?);
            text.push_str(&serde_json::to_string(&record_value(
                snapshot,
                &data_scope,
                key,
                record,
            )?)?);
        }
        Ok(text)
    })
}
