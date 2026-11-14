//! Exact public historical epochs, consumed through a live own Station.
//! These process-local proofs contain no member-held MLS private state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{ContentRootContext, EventContentMaterial};
use arkret_sdk::http_client::own_station_results::OwnStationStateClient;
use arkret_sdk::{AccountId, EncryptedEnvelope, Event, Hash};

struct PublicEpoch {
    source: OwnStationStateClient,
    roster: arkret_sdk::VerifiedMlsHistoricalContentRoster,
}

#[cfg(not(target_arch = "wasm32"))]
type SharedEpoch = Arc<PublicEpoch>;
#[cfg(target_arch = "wasm32")]
type SharedEpoch = std::rc::Rc<PublicEpoch>;
type EpochMap = BTreeMap<Hash, SharedEpoch>;

#[derive(Clone, Default)]
pub(crate) struct HistoricalContentRosters {
    pub(crate) idle_history_exchanges: super::history_exchange::IdleReconciliations,
    #[cfg(not(target_arch = "wasm32"))]
    epochs: Arc<Mutex<EpochMap>>,
    revision: Arc<AtomicU64>,
    content_key_revision: Arc<AtomicU64>,
}

#[cfg(target_arch = "wasm32")]
struct BrowserEpochs {
    owner: std::sync::Weak<AtomicU64>,
    epochs: EpochMap,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static BROWSER_EPOCHS: std::cell::RefCell<BTreeMap<usize, BrowserEpochs>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

impl std::fmt::Debug for HistoricalContentRosters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricalContentRosters")
            .finish_non_exhaustive()
    }
}

impl HistoricalContentRosters {
    pub(crate) fn note_keys_changed(&self) {
        self.idle_history_exchanges.clear();
        self.content_key_revision.fetch_add(1, Ordering::Release);
        self.note_install();
    }

    pub(crate) fn content_key_revision(&self) -> u64 {
        self.content_key_revision.load(Ordering::Acquire)
    }
    /// A process-local presentation input, independent of durable Account and
    /// current-state revisions. Public attribution can arrive after either.
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn note_install(&self) {
        self.revision.fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn advance_projection_revision_for_test(&self) {
        self.note_install();
    }

    pub(crate) fn install(
        &self,
        root: Hash,
        source: &OwnStationStateClient,
        roster: arkret_sdk::VerifiedMlsHistoricalContentRoster,
    ) -> anyhow::Result<()> {
        source.check_session()?;
        self.with_epochs(|entries| {
            entries.retain(|_, entry| entry.source.check_session().is_ok());
            entries.insert(
                root,
                SharedEpoch::new(PublicEpoch {
                    source: source.clone(),
                    roster,
                }),
            );
            self.note_install();
        })
        .ok_or_else(|| anyhow::anyhow!("historical roster cache unavailable"))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn with_epochs<T>(&self, action: impl FnOnce(&mut EpochMap) -> T) -> Option<T> {
        let mut epochs = self.epochs.lock().ok()?;
        Some(action(&mut epochs))
    }

    #[cfg(target_arch = "wasm32")]
    fn with_epochs<T>(&self, action: impl FnOnce(&mut EpochMap) -> T) -> Option<T> {
        BROWSER_EPOCHS.with(|all| {
            let mut all = all.try_borrow_mut().ok()?;
            all.retain(|_, cache| cache.owner.strong_count() > 0);
            // Browser sources stay on their owning thread. The shared store
            // carries only the revision/lifetime, never a !Send source.
            let key = Arc::as_ptr(&self.revision) as usize;
            let cache = all.entry(key).or_insert_with(|| BrowserEpochs {
                owner: Arc::downgrade(&self.revision),
                epochs: BTreeMap::new(),
            });
            // The Weak lifetime prevents pointer reuse from reviving an old
            // owner's proofs, including after an account's cache is dropped.
            let owner = cache.owner.upgrade()?;
            if !Arc::ptr_eq(&owner, &self.revision) {
                return None;
            }
            Some(action(&mut cache.epochs))
        })
    }

    fn epoch(&self, root: &Hash, account: &AccountId) -> Option<SharedEpoch> {
        let epoch = self.with_epochs(|epochs| epochs.get(root).cloned())??;
        (epoch.source.session().ok()?.account_id() == account).then_some(epoch)
    }

    pub(crate) fn material_for_original(
        &self,
        account: &AccountId,
        original: &Event,
        envelope: &EncryptedEnvelope,
    ) -> Option<EventContentMaterial> {
        let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
            root_ref, ..
        } = &envelope.encryption_context;
        let epoch = self.epoch(root_ref, account)?;
        let material = epoch
            .roster
            .content_material_for_verified_original(original, envelope)
            .ok()?;
        epoch.source.check_session().ok()?;
        Some(material)
    }

    /// Callers supply an exact original from the sealed accepted-page path.
    /// The roster authenticates its leaf attribution, independently of its
    /// native Event signature, which was verified when the page was consumed.
    pub(crate) fn material(
        &self,
        account: &AccountId,
        original: &Event,
        envelope: &EncryptedEnvelope,
        context: &ContentRootContext,
    ) -> Option<EventContentMaterial> {
        let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
            root_ref, ..
        } = &envelope.encryption_context;
        let epoch = self.epoch(root_ref, account)?;
        if epoch.roster.root_context() != context {
            return None;
        }
        let material = epoch
            .roster
            .content_material_for_verified_original(original, envelope)
            .ok()?;
        epoch.source.check_session().ok()?;
        Some(material)
    }
}

/// Prepare public attribution only for roots already held by this exact local
/// reader. Missing roots remain pending; reading a roster grants no history.
/// Network work happens outside StateStoreHandle read/write closures.
pub(crate) async fn prepare_accepted_page(
    source: &OwnStationStateClient,
    state: &crate::runtime::input::StateStoreHandle,
    page: &impl crate::transport::own_station_results::AcceptedPageRows,
) -> anyhow::Result<()> {
    let Some(active) = crate::secure_key_store::active_device_seed_scope() else {
        return Ok(());
    };
    anyhow::ensure!(
        source.session()?.account_id() == &active.authority
            && page
                .accepted_account()
                .is_none_or(|account| account == &active.authority),
        "historical page belongs to another reader"
    );
    let account = active.authority;
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id,
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let vault =
        garth::mls::content_roots::ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    let cache = state.read(|store| store.historical_content_rosters.clone());
    let mut roots = BTreeMap::new();
    for row in page.accepted_rows().map_err(anyhow::Error::msg)? {
        let arkret_sdk::CommittedEventView::Full(full) = row else {
            continue;
        };
        for slot in full.event.event_content_envelopes()? {
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                root_ref,
                ..
            } = &slot.envelope.encryption_context;
            if cache.epoch(root_ref, &account).is_some() {
                continue;
            }
            if let Some(root) = vault.cached_root(root_ref)? {
                roots.insert(root_ref.clone(), root.root_context);
            }
        }
    }
    for (root_ref, context) in roots {
        let roster = read_public_epoch(source, state, &context).await?;
        // Re-check both the sealed page and the live account after all I/O.
        page.accepted_rows().map_err(anyhow::Error::msg)?;
        source.check_session()?;
        anyhow::ensure!(
            state.read(|store| store.active_authority().as_ref() == Some(&account)
                && !store.current_reset_required()),
            "historical reader changed"
        );
        cache.install(root_ref, source, roster)?;
    }
    Ok(())
}

/// A held root may arrive after the page that carried its metadata. Retry the
/// retained accepted originals even when a new current cut has no content rows.
/// This prepares public provenance only; it neither admits Events nor grants
/// history, and never restores an old private checkpoint as current.
pub(crate) async fn prepare_retained_realm(
    source: &OwnStationStateClient,
    state: &crate::runtime::input::StateStoreHandle,
    realm: &arkret_sdk::RealmId,
) -> anyhow::Result<()> {
    let Some(active) = crate::secure_key_store::active_device_seed_scope() else {
        return Ok(());
    };
    anyhow::ensure!(
        source.session()?.account_id() == &active.authority,
        "retained content belongs to another reader"
    );
    let account = active.authority;
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id,
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let vault =
        garth::mls::content_roots::ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    let (cache, originals) = state.read(|store| {
        (
            store.historical_content_rosters.clone(),
            store.encrypted_originals_for(realm.as_str()),
        )
    });
    let mut roots = BTreeMap::new();
    for original in originals {
        if original.realm_id != *realm || original.scope_ref.realm_id_opt() != Some(realm) {
            continue;
        }
        for slot in original.event_content_envelopes()? {
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                root_ref,
                ..
            } = &slot.envelope.encryption_context;
            if cache.epoch(root_ref, &account).is_none()
                && let Some(root) = vault.cached_root(root_ref)?
            {
                roots.insert(root_ref.clone(), root.root_context);
            }
        }
    }
    for (root, context) in roots {
        let roster = match read_public_epoch(source, state, &context).await {
            Ok(roster) => roster,
            Err(error) => {
                tracing::warn!(%error, "retained public historical attribution remains pending");
                continue;
            }
        };
        source.check_session()?;
        anyhow::ensure!(
            state.read(|store| store.active_authority().as_ref() == Some(&account)
                && !store.current_reset_required()),
            "retained historical reader changed"
        );
        cache.install(root, source, roster)?;
    }
    Ok(())
}

pub(crate) async fn prepare_accepted_page_for_http(
    http: &arkret_sdk::http_client::Client,
    state: &crate::runtime::input::StateStoreHandle,
    page: &impl crate::transport::own_station_results::AcceptedPageRows,
) {
    let result = async {
        let source = crate::transport::own_station_results::client_for_http(http).await?;
        prepare_accepted_page(&source, state, page).await
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(%error, "public historical attribution remains pending");
    }
}

pub(crate) async fn read_public_epoch(
    source: &OwnStationStateClient,
    state: &crate::runtime::input::StateStoreHandle,
    context: &ContentRootContext,
) -> anyhow::Result<arkret_sdk::VerifiedMlsHistoricalContentRoster> {
    // The read target must be a cut where this reader is authorized. It is
    // independent of the old content epoch and needs no private checkpoint.
    let input = crate::mls::send_gate::MlsSendGateInput::capture(state, &context.effective_scope);
    let current = crate::mls::send_gate::read_durable_mls_current(&input, &context.effective_scope)
        .await?
        .ok_or_else(|| anyhow::anyhow!("historical scope has no accepted MLS current"))?;
    anyhow::ensure!(
        current.effective_scope == context.effective_scope
            && current.genesis_event_ref == context.genesis_event_ref
            && current.cipher_suite.as_str() == context.cipher_suite
            && current.epoch >= context.epoch,
        "historical content differs from the authorized current group"
    );
    let request = arkret_sdk::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: context.effective_scope.realm_id().clone(),
        effective_scope: context.effective_scope.clone(),
        mls_group_id: context.effective_scope.canonical_mls_group_id()?,
        target_commit_event_ref: current.current_mls_commit_event_ref,
        target_epoch: current.epoch,
        caller_actor_id: arkret_sdk::ActorId::account(source.session()?.account_id().clone()),
        cursor: None,
    };
    let mut next = request.clone();
    let mut cursors = BTreeSet::new();
    let mut pages = Vec::new();
    loop {
        let page = source
            .self_mls_roster_authority(&next)
            .await?
            .into_value()?;
        let count = page.roster.manifest.page_count;
        anyhow::ensure!(
            page.roster.page_index == u64::try_from(pages.len())? && page.roster.page_index < count,
            "historical roster page order differs"
        );
        let cursor = page.roster.next_cursor.clone();
        pages.push(page);
        match cursor {
            Some(cursor)
                if u64::try_from(pages.len())? < count && cursors.insert(cursor.clone()) =>
            {
                next.cursor = Some(cursor);
            }
            None if u64::try_from(pages.len())? == count => break,
            _ => anyhow::bail!("historical roster pagination is incomplete"),
        }
    }
    let peer = arkret_sdk::verify_mls_member_roster_authority_pages(&pages, &request)?;
    let genesis_request =
        arkret_sdk::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let genesis_material = source
        .self_mls_group_state_material(&genesis_request)
        .await?;
    let content_original = if context.epoch == 0 {
        // The signed manifest binds the original Genesis public refs. Do not
        // attempt a forbidden pre-join business Event read.
        None
    } else {
        Some(
            garth::own_station_results::read_window_dependency_by_event_id(
                source,
                &context.group_state_ref,
            )
            .await?,
        )
    };
    let content_material = if let Some(original) = &content_original {
        let original = &original.full()?.event;
        anyhow::ensure!(
            original.kind == arkret_sdk::EventKind::MlsCommit,
            "historical content epoch is not an MLS Commit"
        );
        let payload: arkret_models_crypto::MlsCommitPayload =
            serde_json::from_value(serde_json::to_value(&original.payload)?)?;
        let material_request = arkret_sdk::MlsMemberGroupStateMaterialReadRequestBody {
            realm_id: request.realm_id.clone(),
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            epoch: context.epoch,
            group_state_event_id: context.group_state_ref.clone(),
            caller_actor_id: request.caller_actor_id.clone(),
            target_commit_event_ref: request.target_commit_event_ref.clone(),
            target_epoch: request.target_epoch,
            group_info_ref: payload.group_info_ref().clone(),
            ratchet_tree_ref: payload.ratchet_tree_ref().clone(),
            max_response_bytes: None,
        };
        source
            .self_mls_group_state_material(&material_request)
            .await?
            .into_value()?
    } else {
        genesis_material.value()?.clone()
    };
    let mut recovery_material = BTreeMap::new();
    for record in pages.iter().flat_map(|page| &page.roster.records) {
        if let arkret_sdk::MlsRosterRecord::Recovery { commit_event, .. } = record {
            let payload: arkret_models_crypto::MlsCommitPayload =
                serde_json::from_value(serde_json::to_value(&commit_event.payload)?)?;
            if payload.next_epoch() > context.epoch {
                continue;
            }
            let request = arkret_sdk::mls_roster_recovery_material_request(record, &peer)
                .map_err(anyhow::Error::msg)?;
            let material = source
                .self_mls_group_state_material(&request)
                .await?
                .into_value()?;
            anyhow::ensure!(
                recovery_material
                    .insert(commit_event.event_id.clone(), material)
                    .is_none(),
                "historical recovery base repeats"
            );
        }
    }
    let roster = arkret_sdk::verify_mls_self_historical_content_roster(
        arkret_sdk::MlsHistoricalContentRosterMaterials {
            request: &request,
            pages: &pages,
            genesis_original: None,
            genesis_material: genesis_material.value()?,
            content_original: content_original
                .as_ref()
                .map(|original| original.full())
                .transpose()?,
            content_material: &content_material,
            recovery_material: &recovery_material,
            root_context: context,
        },
    )
    .map_err(anyhow::Error::msg)?;
    source.check_session()?;
    Ok(roster)
}
