//! Exact committed reads never consult the optimistic account queue.
use super::*;

pub(crate) struct CommittedAccountRead {
    pub(in crate::state) scope: String,
    pub(in crate::state) expected: Checkpoint,
    pub(in crate::state) location: CurrentIndexLocation,
    pub(in crate::state) account: Option<arkret_sdk::AccountId>,
    pub(in crate::state) generation: u64,
    pub(in crate::state) epoch: u64,
    pub(in crate::state) device: Option<(arkret_sdk::AccountId, arkret_sdk::DeviceId)>,
    pub(in crate::state) grant: Option<String>,
    pub(in crate::state) pending: Option<(arkret_sdk::DeviceId, Option<String>)>,
}
impl CommittedAccountRead {
    pub(crate) fn matches(&self, store: &super::super::LocalStateStore) -> bool {
        self.scope == store.effective_account_key()
            && self.account == store.active_authority()
            && self.generation == store.current_generation()
            && self.epoch == crate::identity::device_directory::cache_epoch()
            && self.device
                == crate::secure_key_store::active_device_seed_scope()
                    .map(|scope| (scope.authority, scope.device_id))
            && self.grant == store.session_grant().map(|grant| grant.grant_id)
            && self.pending
                == store
                    .pending_login()
                    .map(|pending| (pending.device_id, pending.anonymous_storage_incarnation))
            && store
                .committed_account_checkpoint(&self.scope)
                .ok()
                .is_some_and(|checkpoint| checkpoint.root == self.expected.root)
    }
    pub(crate) async fn checkpoint_for_scope(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<Option<garth::mls::checkpoint::MlsLocalCheckpointEnvelope>> {
        let key =
            garth::mls::checkpoint_port::scope_checkpoint_key(scope).map_err(anyhow::Error::msg)?;
        let rows: imbl::OrdMap<String, garth::mls::checkpoint::MlsLocalCheckpointEnvelope> =
            self.map("mls_snapshots", Some(&key)).await?;
        Ok(if matches!(scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
            rows.into_iter()
                .map(|(_, checkpoint)| checkpoint)
                .max_by_key(|checkpoint| checkpoint.epoch)
        } else {
            rows.get(&key).cloned()
        })
    }
    pub(crate) async fn pending_consumes(
        &self,
    ) -> anyhow::Result<Vec<(String, arkret_sdk::KeyPackagesConsumeRequestBody)>> {
        let rows: imbl::OrdMap<String, String> =
            self.map("mls_pending_keypackage_consumes", None).await?;
        rows.into_iter()
            .map(|(key, value)| Ok((key, serde_json::from_str(&value)?)))
            .collect()
    }
    async fn map<T: serde::de::DeserializeOwned + Clone + Send + Sync + 'static>(
        &self,
        field: &str,
        key: Option<&str>,
    ) -> anyhow::Result<imbl::OrdMap<String, T>> {
        let backend = Backend::open(self.location.clone()).await?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let scope = self.scope.clone();
            let field = field.to_owned();
            let key = key.map(str::to_owned);
            let expected = self.expected.clone();
            tokio::task::spawn_blocking(move || {
                committed_map(&backend, &scope, &field, key.as_deref(), &expected)
            })
            .await?
        }
        #[cfg(target_arch = "wasm32")]
        committed_map_async(&backend, &self.scope, field, key, &self.expected).await
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn committed_map_async<T: serde::de::DeserializeOwned + Clone>(
    backend: &Backend,
    scope: &str,
    field: &str,
    scope_key: Option<&str>,
    expected: &Checkpoint,
) -> anyhow::Result<imbl::OrdMap<String, T>> {
    anyhow::ensure!(
        backend.get(&root_key(scope)).await? == expected.root,
        "account checkpoint changed before committed read"
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
        let bytes = backend
            .get(key)
            .await?
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
            record.path.len() == 2
                && record.path[0] == field
                && key == &record_key(&data_scope, &record.path)?,
            "committed account map binding differs"
        );
        let mut bytes = Vec::new();
        for index in 0..record.chunks {
            let chunk = backend
                .get(&chunk_key(&data_scope, &record.blob, index))
                .await?
                .ok_or_else(|| anyhow::anyhow!("committed account chunk missing"))?;
            anyhow::ensure!(chunk.len() <= CHUNK_BYTES * 2, "oversized account chunk");
            bytes.extend(hex::decode(chunk)?);
        }
        anyhow::ensure!(
            bytes.len() == record.bytes
                && arkret_sdk::canonical::sha256_digest(&bytes) == record.digest,
            "committed account value is incomplete or corrupt"
        );
        result.insert(record.path[1].clone(), serde_json::from_slice(&bytes)?);
    }
    anyhow::ensure!(
        backend.get(&root_key(scope)).await? == expected.root,
        "account checkpoint changed during committed read"
    );
    Ok(result)
}
