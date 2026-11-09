//! Exact public historical epochs, consumed through a live own Station.
//! These process-local proofs contain no member-held MLS private state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;

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

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub(crate) struct HistoricalContentRosters(Arc<Mutex<EpochMap>>);

/// Browser session providers stay on their owning thread. The shared store
/// carries only this lifetime identity; it never makes a !Send source Send.
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Default)]
pub(crate) struct HistoricalContentRosters(Arc<()>);

#[cfg(target_arch = "wasm32")]
struct BrowserEpochs {
    owner: std::sync::Weak<()>,
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
    #[cfg(not(target_arch = "wasm32"))]
    fn with_epochs<T>(&self, action: impl FnOnce(&mut EpochMap) -> T) -> Option<T> {
        let mut epochs = self.0.lock().ok()?;
        Some(action(&mut epochs))
    }

    #[cfg(target_arch = "wasm32")]
    fn with_epochs<T>(&self, action: impl FnOnce(&mut EpochMap) -> T) -> Option<T> {
        BROWSER_EPOCHS.with(|all| {
            let mut all = all.try_borrow_mut().ok()?;
            all.retain(|_, cache| cache.owner.strong_count() > 0);
            let key = Arc::as_ptr(&self.0) as usize;
            let cache = all.entry(key).or_insert_with(|| BrowserEpochs {
                owner: Arc::downgrade(&self.0),
                epochs: BTreeMap::new(),
            });
            // The Weak lifetime prevents pointer reuse from reviving an old
            // owner's proofs, including after an account's cache is dropped.
            let owner = cache.owner.upgrade()?;
            if !Arc::ptr_eq(&owner, &self.0) {
                return None;
            }
            Some(action(&mut cache.epochs))
        })
    }

    fn epoch(&self, root: &Hash, account: &AccountId) -> Option<SharedEpoch> {
        let epoch = self.with_epochs(|epochs| epochs.get(root).cloned())??;
        (epoch.source.session().ok()?.account_id() == account).then_some(epoch)
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
        let roster = read_public_epoch(source, &context).await?;
        // Re-check both the sealed page and the live account after all I/O.
        page.accepted_rows().map_err(anyhow::Error::msg)?;
        source.check_session()?;
        anyhow::ensure!(
            state.read(|store| store.active_authority().as_ref() == Some(&account)
                && !store.current_reset_required()),
            "historical reader changed"
        );
        cache
            .with_epochs(|entries| {
                entries.retain(|_, entry| entry.source.check_session().is_ok());
                entries.insert(
                    root_ref,
                    SharedEpoch::new(PublicEpoch {
                        source: source.clone(),
                        roster,
                    }),
                );
            })
            .ok_or_else(|| anyhow::anyhow!("historical roster cache unavailable"))?;
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

async fn read_public_epoch(
    source: &OwnStationStateClient,
    context: &ContentRootContext,
) -> anyhow::Result<arkret_sdk::VerifiedMlsHistoricalContentRoster> {
    let request = arkret_sdk::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: context.effective_scope.realm_id().clone(),
        effective_scope: context.effective_scope.clone(),
        mls_group_id: context.effective_scope.canonical_mls_group_id()?,
        target_commit_event_ref: context.group_state_ref.clone(),
        target_epoch: context.epoch,
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
    let genesis = garth::own_station_results::read_window_dependency_by_event_id(
        source,
        &context.genesis_event_ref,
    )
    .await?;
    let target = garth::own_station_results::read_window_dependency_by_event_id(
        source,
        &context.group_state_ref,
    )
    .await?;
    let genesis_request =
        arkret_sdk::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let genesis_material = source
        .self_mls_group_state_material(&genesis_request)
        .await?;
    let original = &target.full()?.event;
    let payload = serde_json::to_value(&original.payload)?;
    let (info, tree) = match original.kind {
        arkret_sdk::EventKind::MlsGenesis => {
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(payload)?;
            (payload.group_info_ref, payload.ratchet_tree_ref)
        }
        arkret_sdk::EventKind::MlsCommit => {
            let payload: arkret_models_crypto::MlsCommitPayload = serde_json::from_value(payload)?;
            (
                payload.group_info_ref().clone(),
                payload.ratchet_tree_ref().clone(),
            )
        }
        _ => anyhow::bail!("historical target is not an MLS group original"),
    };
    let material_request = arkret_sdk::MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        epoch: context.epoch,
        group_state_event_id: context.group_state_ref.clone(),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: context.group_state_ref.clone(),
        target_epoch: context.epoch,
        group_info_ref: info,
        ratchet_tree_ref: tree,
        max_response_bytes: None,
    };
    let target_material = source
        .self_mls_group_state_material(&material_request)
        .await?;
    let mut recovery_material = BTreeMap::new();
    for record in pages.iter().flat_map(|page| &page.roster.records) {
        if let arkret_sdk::MlsRosterRecord::Recovery { commit_event, .. } = record {
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
            genesis_original: genesis.full()?,
            genesis_material: genesis_material.value()?,
            target_original: target.full()?,
            target_material: target_material.value()?,
            recovery_material: &recovery_material,
            root_context: context,
        },
    )
    .map_err(anyhow::Error::msg)?;
    source.check_session()?;
    Ok(roster)
}
