//! Resumable creator-side MLS bootstrap using Account Station acceptance.
//! The creator persists actual MLS epoch-0 state and publishes its Genesis.
//! Readiness follows the exact Station-accepted artifact and atomic crypto commit.

use crate::runtime::input::StateStoreHandle;
use crate::state::LocalStateStore;

fn creator_bootstrap_lock(key: String) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    type Locks = std::collections::BTreeMap<String, Weak<tokio::sync::Mutex<()>>>;
    static LOCKS: OnceLock<Mutex<Locks>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreatorGenesisResumeAction {
    Author,
    ConvergeAccepted,
}

fn creator_genesis_resume_action(
    accepted_event_id: Option<&arkret_sdk::EventId>,
    emitted: bool,
) -> Result<CreatorGenesisResumeAction, String> {
    if accepted_event_id.is_some() {
        return Ok(CreatorGenesisResumeAction::ConvergeAccepted);
    }
    if emitted {
        return Err(
            "MLS genesis is marked emitted but its accepted Event is unavailable".to_owned(),
        );
    }
    Ok(CreatorGenesisResumeAction::Author)
}

/// Whether local epoch-zero work for a Realm is still incomplete.
///
/// Cheap and synchronous so UI effects can gate on it without spawning. The
/// creator check is only a cheap scheduling hint. The asynchronous entry point
/// revalidates the creator against the accepted authority-root/founding Event
/// before it authors Genesis; this local predicate never grants authority.
pub(crate) fn creator_mls_bootstrap_pending(
    store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
) -> bool {
    // The only creator-side evidence a synchronous caller can rely on is that
    // this device holds the scope's epoch-zero group material: a non-creator
    // never has it, because it joins through a Welcome delivery at a later
    // epoch. The asynchronous entry point still resolves the accepted creator
    // with the current authority before it authors anything.
    let _ = actor_id;
    creator_mls_bootstrap_incomplete(store, realm_id)
}

/// The local completion half of the creator-bootstrap gate. Kept separate
/// from creator identification because a freshly accepted Realm can have an
/// optimistic security projection before account current-sync installs the
/// authority-root cell. In that gap the asynchronous entry point verifies the
/// exact accepted founding Event directly with the Station.
fn creator_mls_bootstrap_incomplete(store: &LocalStateStore, realm_id: &str) -> bool {
    if store.persist_error().is_some() {
        return true;
    }
    let Some(snapshot) = store.mls_checkpoint_for(realm_id) else {
        return true;
    };
    // This recovery entry point owns the creator's epoch-0 transaction. Once
    // the group has advanced, commit convergence owns later epochs.
    if snapshot.epoch != 0 {
        return false;
    }
    if !store.mls_genesis_emitted_for(realm_id) {
        return true;
    }
    // `emitted` plus a local marker is not a completion boundary: the create
    // flow can be unmounted right after the submit succeeds. Bootstrap is
    // complete only once the epoch-zero checkpoint names the accepted Genesis
    // Event that materialized it.
    let accepted = store
        .mls_group_state_ref_for_effective_scope(realm_id, None, &snapshot.group_id, 0)
        .ok();
    let scope =
        arkret_sdk::RealmId::new(realm_id).map(|realm_id| arkret_sdk::ScopeRef::Realm { realm_id });
    let durable = scope.ok().and_then(|scope| {
        store
            .durable_mls_checkpoint_for_scope(&scope)
            .ok()
            .flatten()
    });
    accepted.is_none()
        || durable.is_none_or(|durable| {
            durable.epoch != 0
                || durable.group_id != snapshot.group_id
                || durable.group_state_event_id.as_ref() != accepted.as_ref()
        })
}

async fn publish_accepted_creator_genesis(
    state: &StateStoreHandle,
    realm_id: &str,
    accepted_event_id: &arkret_sdk::EventId,
) -> Result<(), String> {
    let barrier = state.write(|store| {
        store.mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            None,
            accepted_event_id,
        )
    })?;
    let result = barrier.wait().await.map_err(|error| error.to_string());
    // Re-evaluate durable readiness after the commit or its failure is visible.
    state.write(|_| {});
    result
}

fn has_staged_creator_genesis(store: &LocalStateStore, realm_id: &str) -> bool {
    store.mls_checkpoint_for(realm_id).is_some()
}

fn creator_genesis_has_resume_evidence(
    accepted: bool,
    staged_checkpoint: bool,
    durable_queued_genesis: bool,
) -> bool {
    if accepted {
        staged_checkpoint
    } else {
        staged_checkpoint || durable_queued_genesis
    }
}

/// Compare the complete account identity with exact accepted founding authority.
pub(crate) async fn authenticated_account_is_realm_creator(
    api: &crate::transport::TransportClient,
    _state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
) -> Result<bool, String> {
    api.event_submitter()
        .map_err(|error| format!("MLS creator classification client: {error}"))?
        .accepted_scope_genesis_author(realm_id, authority)
        .await
        .map(|(genesis_author, _)| genesis_author)
        .map_err(|error| format!("resolve accepted Realm creator: {error}"))
}

/// Background recovery gate for an already accepted or staged creator Genesis.
/// Absence of accepted/staged work is a plaintext Realm, not an implicit MLS
/// activation request. A candidate is still checked against accepted creator
/// authority before any resume work proceeds.
pub(crate) async fn should_resume_creator_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
) -> Result<bool, String> {
    let submitter = api.event_submitter().map_err(|e| e.to_string())?;
    let accepted = submitter
        .find_mls_genesis_event_id(realm_id)
        .await
        .map_err(|e| e.to_string())?;
    let staged_checkpoint = state_store.read(|store| has_staged_creator_genesis(store, realm_id));
    if accepted.is_some() {
        return Ok(creator_genesis_has_resume_evidence(
            true,
            staged_checkpoint,
            false,
        ));
    }
    // A plaintext Realm with no accepted Genesis is not an implicit request
    // to activate MLS. Only an already-staged checkpoint or a byte-identical
    // durable queue item may be resumed by background effects.
    let durable_queued_genesis = if staged_checkpoint {
        false
    } else {
        submitter
            .has_durable_mls_genesis_for_realm(realm_id)
            .await
            .map_err(|e| e.to_string())?
    };
    // A Direct Conversation is MLS-backed from its founding: its founder
    // authors the one scope-derived Genesis the bootstrap phases require
    // (`identity/contact-and-direct-conversation.md` 7.2 / 7.3). Unlike an
    // ordinary plaintext Realm, the absence of an accepted Genesis there is
    // outstanding founder work, not a declined MLS activation.
    let (genesis_author, direct_conversation) = submitter
        .accepted_scope_genesis_author(realm_id, authority)
        .await
        .map_err(|error| format!("resolve accepted Realm creator: {error}"))?;
    if !direct_conversation
        && !creator_genesis_has_resume_evidence(false, staged_checkpoint, durable_queued_genesis)
    {
        return Ok(false);
    }
    Ok(genesis_author)
}

async fn converge_accepted_creator_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    accepted_event_id: &arkret_sdk::EventId,
) -> Result<(), String> {
    if state_store.read(|store| store.mls_checkpoint_for(realm_id).is_none()) {
        return Err(format!(
            "accepted MLS genesis exists for {realm_id}, but the local snapshot is missing; restore this device before retrying creator bootstrap"
        ));
    }
    publish_accepted_creator_genesis(state_store, realm_id, accepted_event_id).await?;
    // Genesis carries no MLS message, so nothing has to be merged: the accepted
    // Event id recorded above is what makes the epoch-zero group usable.
    let _ = (api, authority, device_id);
    Ok(())
}

/// Explicitly start MLS after Realm creation. This does not change the
/// `ak.realm.create` payload; only an accepted Genesis activates the scope.
pub(crate) async fn start_creator_realm_mls_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<(), String> {
    bootstrap_creator_realm_mls_genesis(api, state_store, realm_id, authority, device_id, true)
        .await
}

/// Resume only a previously staged epoch-zero checkpoint or durable Genesis
/// queue item. A plaintext Realm with neither is not an activation request.
/// The common implementation is idempotent and converges exact accepted
/// Genesis evidence before reporting success.
pub(crate) async fn ensure_creator_realm_mls_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<(), String> {
    let founder_genesis = api
        .event_submitter()
        .map_err(|error| format!("MLS genesis Event submitter: {error}"))?
        .accepted_scope_genesis_author(realm_id, authority)
        .await
        .map_err(|error| format!("resolve accepted Realm creator: {error}"))?
        .1;
    bootstrap_creator_realm_mls_genesis(
        api,
        state_store,
        realm_id,
        authority,
        device_id,
        founder_genesis,
    )
    .await
}

async fn bootstrap_creator_realm_mls_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    explicit_start: bool,
) -> Result<(), String> {
    let actor_id = authority.principal_id.as_str();
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err("realm_id is required for creator MLS bootstrap".to_owned());
    }
    // Effects and the create flow can overlap. Recheck accepted/local state
    // only after the preceding attempt finishes, so a second proposal cannot
    // replace the staged group while its Genesis is being accepted.
    let lock = creator_bootstrap_lock(format!(
        "{}|{}|{}|{}",
        authority.station_id, authority.principal_id, device_id, realm_id
    ));
    let _guard = lock.lock().await;
    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS genesis Event submitter: {error}"))?;
    // Resolve exact accepted authority; a local presentation row is not evidence.
    if !authenticated_account_is_realm_creator(api, state_store, realm_id, authority).await? {
        return Err("the authenticated actor is not the accepted Realm creator".to_owned());
    }
    // An accepted Genesis is the authoritative completion record. Resolve it,
    // or drain its byte-identical durable queue item, before reading or
    // rebuilding any pre-Genesis proposal, proof, or epoch-0 authoring state.
    // This ordering is required by encryption-and-audit.md §5.1.3: refreshing
    // the proof first can invalidate a perfectly valid staged snapshot after
    // the Event has already been accepted.
    let mut accepted_before_authoring = submitter
        .find_mls_genesis_event_id(realm_id)
        .await
        .map_err(|error| format!("resolve accepted ak.mls.genesis Event: {error}"))?;
    if accepted_before_authoring.is_none()
        && submitter
            .has_durable_mls_genesis_for_realm(realm_id)
            .await
            .map_err(|error| format!("inspect queued ak.mls.genesis Event: {error}"))?
    {
        submitter
            .drain_outbound()
            .await
            .map_err(|error| format!("resume queued ak.mls.genesis Event: {error}"))?;
        accepted_before_authoring = submitter
            .find_mls_genesis_event_id(realm_id)
            .await
            .map_err(|error| format!("resolve retried ak.mls.genesis Event: {error}"))?;
        if accepted_before_authoring.is_none() {
            return Err(
                "the byte-identical ak.mls.genesis transaction remains durably queued".to_owned(),
            );
        }
    }
    if let Some(accepted_event_id) = accepted_before_authoring.as_ref() {
        return converge_accepted_creator_genesis(
            api,
            state_store,
            realm_id,
            authority,
            device_id,
            accepted_event_id,
        )
        .await;
    }
    if !explicit_start && !state_store.read(|store| has_staged_creator_genesis(store, realm_id)) {
        return Err(
            "creator MLS resume has no accepted Genesis or staged local checkpoint".to_owned(),
        );
    }
    if state_store.read(|store| store.mls_genesis_emitted_for(realm_id)) {
        // A local marker cannot overrule the Station's complete accepted Event
        // history. Repair only unaccepted epoch-0 authoring state.
        state_store.write(|store| store.clear_unaccepted_creator_mls_genesis(realm_id))?;
    }

    if state_store.read(|store| {
        store.mls_genesis_emitted_for(realm_id) && store.mls_checkpoint_for(realm_id).is_none()
    }) {
        return Err(format!(
            "accepted MLS genesis exists for {realm_id}, but the local snapshot is missing; restore this device before retrying creator bootstrap"
        ));
    }

    // Resolve server acceptance before touching the pre-Genesis authoring
    // proof. A cancelled create task can leave an accepted Genesis plus its
    // epoch-0 snapshot while the pinned checkpoint still predates Genesis.
    // Re-fetching a current 0->0 proof first changes the cached binding and
    // then makes the perfectly valid staged snapshot look corrupt. Once the
    // Event is accepted, its verified checkpoint + artifact convergence is the
    // only remaining work; Genesis authoring material must not be rebuilt.
    let mut accepted_event_id = submitter
        .find_mls_genesis_event_id(realm_id)
        .await
        .map_err(|error| format!("resolve accepted ak.mls.genesis Event: {error}"))?;
    if accepted_event_id.is_none()
        && submitter
            .has_durable_mls_genesis_for_realm(realm_id)
            .await
            .map_err(|error| format!("inspect queued ak.mls.genesis Event: {error}"))?
    {
        // encryption-and-audit.md §5.1.3 requires byte-identical retry of the
        // persisted epoch-0 transaction. A retryable foreground result means
        // Garth already owns those signed bytes; drain that lane and never
        // build another Genesis merely because this UI effect was re-entered.
        submitter
            .drain_outbound()
            .await
            .map_err(|error| format!("resume queued ak.mls.genesis Event: {error}"))?;
        accepted_event_id = submitter
            .find_mls_genesis_event_id(realm_id)
            .await
            .map_err(|error| format!("resolve retried ak.mls.genesis Event: {error}"))?;
        if accepted_event_id.is_none() {
            return Err(
                "the byte-identical ak.mls.genesis transaction remains durably queued".to_owned(),
            );
        }
    }
    let mut genesis_emitted = state_store.read(|store| store.mls_genesis_emitted_for(realm_id));
    if accepted_event_id.is_none() && genesis_emitted {
        // The Station's complete accepted-event history is the authority for
        // protocol completion. A browser can retain a stale local marker after
        // an interrupted/rolled-back development run; treating it as success
        // violates encryption-and-audit.md §5.1 and permanently suppresses
        // the required Genesis retry. Repair only epoch-0 authoring state with
        // no durably accepted local artifact, then author a fresh queue item.
        state_store.write(|store| store.clear_unaccepted_creator_mls_genesis(realm_id))?;
        genesis_emitted = false;
    }
    match creator_genesis_resume_action(accepted_event_id.as_ref(), genesis_emitted)? {
        CreatorGenesisResumeAction::ConvergeAccepted => {
            let accepted_event_id = accepted_event_id.as_ref().ok_or_else(|| {
                "creator MLS convergence is missing its accepted Event id".to_owned()
            })?;
            if state_store.read(|store| store.mls_checkpoint_for(realm_id).is_none()) {
                return Err(format!(
                    "accepted MLS genesis exists for {realm_id}, but the local snapshot is missing; restore this device before retrying creator bootstrap"
                ));
            }
            publish_accepted_creator_genesis(state_store, realm_id, accepted_event_id).await?;
        }
        CreatorGenesisResumeAction::Author => {
            // encryption-and-audit.md \u00a75.1 requires creator bootstrap to
            // converge even while account current-sync has not installed the
            // authority-root projection yet. The exact creator was resolved
            // above and the accepted governance frontier was refreshed before
            // this branch, so bypass only the redundant local-detail gate for
            // this one Realm; normal authoring and server admission still run.
            let founding_realm = arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid creator bootstrap Realm id: {error}"))?;
            let submitter = submitter.for_founding_realm(founding_realm);

            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            // The verified first-enrollment flow creates the account MLS root. Realm
            // creation may only re-commit that existing root before writing the first
            // dependent snapshot; it must never mint a replacement from a feature API.
            crate::mls::runtime::ensure_existing_account_mls_secret_durable(
                secure_store.as_ref(),
                authority,
            )
            .await
            .map_err(|error| {
                format!("durably persisting the account MLS secret failed: {error}")
            })?;
            let fresh_summary = state_store
                .write(|store| {
                    crate::mls::runtime::ensure_creator_mls_checkpoint(
                        store,
                        secure_store.as_ref(),
                        realm_id,
                        authority,
                        device_id,
                    )
                })
                .map_err(|error| {
                    format!("MLS initial group setup failed: {}", error.user_message())
                })?;
            // The interesting recovery case is "snapshot persisted, genesis never
            // accepted": `ensure_creator_mls_checkpoint` short-circuits to `None` there,
            // and the genesis builder refuses to emit without epoch-0 material. Restore
            // that material from the stored epoch-0 snapshot — the same fallback the
            // direct-conversation and Agent PCR bootstraps use — so the submit is
            // actually retried instead of silently skipped.
            let summary = match fresh_summary {
                Some(summary) => Some(summary),
                None => {
                    let restored_summary = state_store.read(|store| {
                        crate::mls::runtime::initial_mls_checkpoint_summary_from_existing(
                            store,
                            secure_store.as_ref(),
                            realm_id,
                            authority,
                            device_id,
                        )
                    });
                    match restored_summary {
                        Ok(summary) => summary,
                        Err(crate::mls::runtime::MlsRuntimeError::Genesis(reason))
                            if reason
                                == crate::mls::runtime::EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH =>
                        {
                            // The server has just confirmed that no Genesis is
                            // accepted. The persisted epoch-0 group is therefore
                            // staged authoring state, not history. Recreate it
                            // under the now-current verified proof; the runtime
                            // additionally refuses this replacement if any local
                            // accepted/emitted marker exists.
                            Some(
                                state_store
                                    .write(|store| {
                                        crate::mls::runtime::recreate_unaccepted_creator_mls_checkpoint(
                                            store,
                                            secure_store.as_ref(),
                                            realm_id,
                                            authority,
                                            device_id,
                                        )
                                    })
                                    .map_err(|error| {
                                        format!(
                                            "rebasing the unaccepted epoch-0 MLS snapshot failed: {}",
                                            error.user_message()
                                        )
                                    })?,
                            )
                        }
                        Err(error) => {
                            return Err(format!(
                                "restoring the epoch-0 MLS summary failed: {}",
                                error.user_message()
                            ));
                        }
                    }
                }
            };
            let genesis_event = state_store
                .write(|store| {
                    crate::mls::group_events::build_creator_mls_genesis_event(
                        store,
                        realm_id,
                        actor_id,
                        summary.as_ref(),
                    )
                })
                .map_err(|error| format!("building ak.mls.genesis event failed: {error}"))?
                .ok_or_else(|| "creator MLS Genesis authoring returned no Event".to_owned())?;
            let genesis_material = summary.as_ref().ok_or_else(|| {
                "ak.mls.genesis was built without recoverable epoch-0 public material".to_owned()
            })?;
            crate::mls::runtime::upload_mls_genesis_public_material(api, genesis_material)
                .await
                .map_err(|error| {
                    format!(
                        "publishing ak.mls.genesis public group-state material failed: {}",
                        error.user_message()
                    )
                })?;
            let accepted = match submitter.submit_sdk_event(&genesis_event).await {
                Ok(accepted) => {
                    arkret_sdk::EventId::new(accepted.event_id.clone()).map_err(|error| {
                        anyhow::anyhow!(
                            "accepted ak.mls.genesis carries an invalid Event id: {error}"
                        )
                    })
                }
                // `mls_genesis_already_exists` is reserved, not an active
                // Station response. An ambiguous failure is not proof of
                // acceptance; the next run recovers only an exact committed
                // genesis Event through the lookup above.
                Err(error) => Err(error),
            };
            match accepted {
                Ok(event_id) => {
                    publish_accepted_creator_genesis(state_store, realm_id, &event_id).await?;
                    accepted_event_id = Some(event_id);
                }
                Err(error) => {
                    // The local snapshot and pinned checkpoint stay persisted, but the
                    // bootstrap is not complete until genesis is accepted and its
                    // exact Event id is recorded. Propagate the failure so the
                    // background effect clears its dedup key and retries; returning
                    // success here used to strand first-Realm writes permanently.
                    tracing::warn!(
                        error = %error,
                        realm = %realm_id,
                        "ak.mls.genesis submit failed; creator MLS bootstrap will retry",
                    );
                    return Err(format!("submitting ak.mls.genesis failed: {error}"));
                }
            }
        }
    }

    let accepted_event_id = accepted_event_id.ok_or_else(|| {
        "MLS genesis is marked emitted but its accepted Event is unavailable".to_owned()
    })?;
    // The accepted Genesis Event id is bound to the epoch-zero checkpoint by
    // `mark_mls_genesis_emitted_*`; that binding is the completion boundary.
    if !state_store.read(|store| {
        let Some(checkpoint) = store.mls_checkpoint_for(realm_id) else {
            return false;
        };
        checkpoint.group_state_event_id.as_ref() == Some(&accepted_event_id)
            && store
                .mls_group_state_ref_for_effective_scope(
                    realm_id,
                    None,
                    &checkpoint.group_id,
                    checkpoint.epoch,
                )
                .is_ok()
    }) {
        return Err("accepted MLS Genesis did not become durably ready".to_owned());
    }

    Ok(())
}

/// Confirm that this device's durable MLS epoch names the accepted transition
/// that materialized it, before exporting from it or encrypting under it.
///
/// A checkpoint without that reference cannot be the base of the next
/// transition and must not be used to author, so this fails closed rather than
/// guessing which accepted Event produced the local state.
pub(crate) fn ensure_local_mls_transition_ready(
    state_store: &StateStoreHandle,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<(), String> {
    if matches!(effective_scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
        return Ok(());
    }
    let snapshot = state_store
        .read(|store| store.mls_checkpoint_for_scope(effective_scope))
        .ok_or_else(|| "local MLS group state is pending".to_owned())?;
    state_store
        .read(|store| {
            store.mls_group_state_ref_for_scope(effective_scope, &snapshot.group_id, snapshot.epoch)
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn creator_bootstrap_serializes_same_group_without_blocking_other_groups() {
        let first = creator_bootstrap_lock("test-account/device/realm-one".into());
        let second = creator_bootstrap_lock("test-account/device/realm-one".into());
        let other = creator_bootstrap_lock("test-account/device/realm-two".into());
        let guard = first.try_lock().unwrap();
        assert!(second.try_lock().is_err());
        assert!(other.try_lock().is_ok());
        drop(guard);
        assert!(second.try_lock().is_ok());
    }

    fn temp_store(name: &str) -> LocalStateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        LocalStateStore::with_path(
            std::env::temp_dir().join(format!("inkson-creator-bootstrap-{name}-{stamp}.json")),
        )
    }

    /// A realm projection in its post-P1 shape: the creator fact is only
    /// available through the Station's current `ak.component.realm.authority_root.v1`
    /// value, whose controller comes from the accepted `ak.realm.create`
    /// envelope. The retired `owner` / `created_by` mirrors are deliberately
    /// absent — a fixture that carried them would test a fallback the client
    /// no longer has.
    fn realm_projection(creator: &str) -> serde_json::Value {
        let principal_id = crate::mls_api_helpers::principal_core_id(creator).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        json!({
            "__kind": "realm",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": creator, "membership": "join" }],
            "summary": { "title": "Realm" },
            "current": {
                "entries": [authority_root_entry(&creator)]
            }
        })
    }

    /// The single installed current authority-root result for [`REALM`].
    fn authority_root_entry(controller: &arkret_sdk::ActorId) -> serde_json::Value {
        json!({
            "selector": {
                "scope_ref": {"kind": "realm", "realm_id": REALM},
                "cell_id": "ak:cell:ak.component.realm.authority_root.v1:null"
            },
            "result": {"status": "value", "value": {
                "controller_actor_id": controller,
                "controller_epoch": 0,
                "authority_generation": 0
            }}
        })
    }

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn epoch_zero_snapshot(
        group_id: String,
    ) -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
        crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: REALM.to_owned(),
            group_id,
            epoch: 0,
            admission_epoch: 0,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        }
    }

    #[test]
    fn creator_of_an_encrypted_realm_without_local_mls_state_is_pending() {
        let mut store = temp_store("pending");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn plaintext_realm_without_staged_genesis_is_not_a_resume_intent() {
        let mut store = temp_store("no-implicit-start");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR));
        assert!(!has_staged_creator_genesis(&store, REALM));

        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        store
            .save_mls_checkpoint(
                REALM,
                epoch_zero_snapshot(scope.canonical_mls_group_id().unwrap().to_string()),
            )
            .unwrap();
        assert!(has_staged_creator_genesis(&store, REALM));
    }

    #[test]
    fn background_resume_requires_staged_or_exact_queued_genesis() {
        assert!(!creator_genesis_has_resume_evidence(false, false, false));
        assert!(creator_genesis_has_resume_evidence(false, true, false));
        assert!(creator_genesis_has_resume_evidence(false, false, true));
        assert!(!creator_genesis_has_resume_evidence(true, false, true));
        assert!(creator_genesis_has_resume_evidence(true, true, false));
    }

    #[test]
    fn optimistic_encrypted_realm_is_incomplete_before_authority_current_arrives() {
        let mut store = temp_store("optimistic-incomplete");
        store.save_realm_tree_projection(
            REALM,
            json!({
                "__kind": "realm",
                "summary": { "title": "Realm" }
            }),
        );
        // The gate is the local epoch-0 group material, so an optimistic
        // projection with no installed authority current is still incomplete
        // and the pending hint agrees with it exactly.
        assert!(creator_mls_bootstrap_incomplete(&store, REALM));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn checkpoint_event_ref_without_emitted_marker_remains_pending() {
        let mut store = temp_store("stale-checkpoint");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap().to_string();
        let accepted_genesis =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let mut snapshot = epoch_zero_snapshot(group_id);
        snapshot.group_state_event_id = Some(accepted_genesis.clone());
        store.save_mls_checkpoint(REALM, snapshot).unwrap();

        // An isolated local field is not an accepted Genesis or an emitted
        // marker. Only the authenticated Station result can drive convergence.
        assert_eq!(
            store
                .mls_checkpoint_for(REALM)
                .unwrap()
                .group_state_event_id,
            Some(accepted_genesis)
        );
        assert!(!store.mls_genesis_emitted_for(REALM));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[tokio::test]
    async fn accepted_genesis_publication_failure_never_completes_bootstrap() {
        let directory = std::env::temp_dir().join(format!(
            "inkson-genesis-publication-failure-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("state.json");
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        };
        let mut store = LocalStateStore::with_path(path.clone());
        store
            .save_mls_checkpoint(
                REALM,
                epoch_zero_snapshot(scope.canonical_mls_group_id().unwrap().to_string()),
            )
            .unwrap();
        let account_path = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        std::fs::remove_file(&account_path).unwrap();
        std::fs::create_dir(&account_path).unwrap();
        let accepted =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let result = store.mark_mls_genesis_emitted_for_scope_with_event(&scope, &accepted);
        std::fs::remove_dir(&account_path).unwrap();
        assert!(
            result.is_err(),
            "failed durable publication cannot acknowledge accepted Genesis locally"
        );
        assert!(
            creator_mls_bootstrap_incomplete(&store, REALM),
            "a failed publication remains pending even if its cache was updated"
        );
        assert!(
            store
                .durable_mls_checkpoint_for_scope(&scope)
                .unwrap()
                .is_none()
        );
        store
            .mark_mls_genesis_emitted_for_scope_with_event(&scope, &accepted)
            .unwrap()
            .wait()
            .await
            .unwrap();
        let reopened = LocalStateStore::with_path(path);
        assert!(!creator_mls_bootstrap_incomplete(&reopened, REALM));
        assert_eq!(
            reopened
                .durable_mls_checkpoint_for_scope(&scope)
                .unwrap()
                .unwrap()
                .group_state_event_id
                .as_ref(),
            Some(&accepted)
        );
    }

    #[tokio::test]
    async fn accepted_genesis_publication_preserves_an_installed_later_epoch() {
        let mut store = temp_store("genesis-preserves-later-epoch");
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        };
        let mut snapshot = epoch_zero_snapshot(scope.canonical_mls_group_id().unwrap().to_string());
        snapshot.epoch = 1;
        let current = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]);
        store
            .install_accepted_mls_transition(&scope, snapshot, &current)
            .unwrap()
            .wait()
            .await
            .unwrap();
        let canonical = store
            .durable_mls_checkpoint_for_scope(&scope)
            .unwrap()
            .unwrap();
        let genesis = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x50; 32]);
        store
            .mark_mls_genesis_emitted_for_scope_with_event(&scope, &genesis)
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(
            store.durable_mls_checkpoint_for_scope(&scope).unwrap(),
            Some(canonical)
        );
        assert_eq!(
            store
                .mls_group_state_ref_for_scope(
                    &scope,
                    &scope.canonical_mls_group_id().unwrap().to_string(),
                    1
                )
                .unwrap(),
            current
        );
    }

    #[test]
    fn accepted_genesis_resumes_at_convergence_without_reauthoring() {
        let accepted =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        assert_eq!(
            creator_genesis_resume_action(Some(&accepted), true).unwrap(),
            CreatorGenesisResumeAction::ConvergeAccepted
        );
        assert_eq!(
            creator_genesis_resume_action(Some(&accepted), false).unwrap(),
            CreatorGenesisResumeAction::ConvergeAccepted
        );
        assert_eq!(
            creator_genesis_resume_action(None, false).unwrap(),
            CreatorGenesisResumeAction::Author
        );
        assert!(creator_genesis_resume_action(None, true).is_err());
    }

    #[test]
    fn station_absence_can_repair_only_unaccepted_epoch_zero_marker() {
        let mut store = temp_store("repair-stale-marker");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap().to_string();
        store
            .save_mls_checkpoint(REALM, epoch_zero_snapshot(group_id.clone()))
            .unwrap();
        let stale =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        store
            .mark_mls_genesis_emitted_for_effective_scope_with_event(REALM, None, &stale)
            .unwrap();

        store.clear_unaccepted_creator_mls_genesis(REALM).unwrap();

        assert!(!store.mls_genesis_emitted_for(REALM));
        let snapshot = store.mls_checkpoint_for(REALM).unwrap();
        assert_eq!(snapshot.epoch, 0);
        assert!(snapshot.group_state_event_id.is_none());
        assert!(
            store
                .mls_group_state_ref_for_scope(&scope, &group_id, 0)
                .is_err()
        );
    }

    #[test]
    fn the_local_gate_is_group_material_only_and_never_classifies_the_actor() {
        // Creator identity is resolved against the accepted founding authority
        // by `authenticated_account_is_realm_creator`, never from a local
        // projection. The synchronous gate is therefore identical for every
        // actor: it answers only "does this device still owe epoch-0 work".
        let mut store = temp_store("actor-independent");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR));
        assert_eq!(
            creator_mls_bootstrap_pending(&store, REALM, ACTOR),
            creator_mls_bootstrap_pending(&store, REALM, "did:web:bob.example"),
        );
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn a_device_without_epoch_zero_material_still_owes_creator_bootstrap() {
        // A device that never staged epoch-0 material has nothing to converge
        // locally; the asynchronous entry point resolves whether it is the
        // creator at all, and a non-creator joins through a Welcome instead.
        let store = temp_store("unknown");
        assert!(creator_mls_bootstrap_incomplete(&store, REALM));
    }

    #[test]
    fn an_installed_later_epoch_is_owned_by_commit_convergence_not_bootstrap() {
        let mut store = temp_store("advanced-epoch");
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap().to_string();
        let mut advanced = epoch_zero_snapshot(group_id);
        advanced.epoch = 3;
        store.save_mls_checkpoint(REALM, advanced).unwrap();
        assert!(!creator_mls_bootstrap_incomplete(&store, REALM));
    }
}
