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

fn genesis_already_accepted(error: &anyhow::Error) -> bool {
    crate::api_error::api_error_status_and_envelope(error).is_some_and(|(_, problem)| {
        problem.code() == arkret_sdk::error_codes::ErrorCode::MLS_GENESIS_ALREADY_EXISTS
    })
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

/// Whether this client is the creator of an encrypted `realm_id` whose MLS
/// bootstrap is still incomplete.
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
    store
        .mls_group_state_ref_for_effective_scope(realm_id, None, &snapshot.group_id, 0)
        .is_err()
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
        .accepted_realm_creator_matches_account(realm_id, authority)
        .await
        .map_err(|error| format!("resolve accepted Realm creator: {error}"))
}

/// Refresh the accepted Seal view, acquire + verify + pin the governance
/// proof, create the epoch-0 creator group and submit `ak.mls.genesis`.
///
/// Idempotent and safe to re-enter: it returns early only after the accepted
/// Genesis is present in the locally verified checkpoint and its accepted MLS
/// artifact is durable. A server-side duplicate genesis is resolved to its
/// accepted Event id rather than treated as an error.
/// Select the unfinished Genesis transaction, not every device of its account.
/// Once Genesis exists, a device without that local group must join/recover.
pub(crate) async fn should_resume_creator_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
) -> Result<bool, String> {
    let accepted = api
        .event_submitter()
        .map_err(|e| e.to_string())?
        .find_mls_genesis_event_id(realm_id)
        .await
        .map_err(|e| e.to_string())?;
    if accepted.is_some() {
        return Ok(state_store.read(|store| store.mls_checkpoint_for(realm_id).is_some()));
    }
    authenticated_account_is_realm_creator(api, state_store, realm_id, authority).await
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
    state_store.write(|store| {
        store.mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            None,
            accepted_event_id,
        )
    })?;
    // Genesis carries no MLS message, so nothing has to be merged: the accepted
    // Event id recorded above is what makes the epoch-zero group usable.
    let _ = (api, authority, device_id);
    Ok(())
}

pub(crate) async fn ensure_creator_realm_mls_genesis(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
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
    if !submitter
        .accepted_realm_is_encrypted(realm_id)
        .await
        .map_err(|error| format!("resolve accepted Realm encryption profile: {error}"))?
    {
        return Ok(());
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
            state_store.write(|store| {
                store.mark_mls_genesis_emitted_for_effective_scope_with_event(
                    realm_id,
                    None,
                    accepted_event_id,
                )
            })?;
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
                // A duplicate is success only after resolving the exact
                // already-accepted Event id: encrypted writes bind their
                // `group_state_ref` to it, so merely setting the emitted flag would
                // strand them without a resolvable group state.
                Err(error) if genesis_already_accepted(&error) => submitter
                    .find_mls_genesis_event_id(realm_id)
                    .await
                    .and_then(|event_id| {
                        event_id.ok_or_else(|| {
                            anyhow::anyhow!(
                                "MLS genesis already exists server-side but its accepted Event id is unavailable"
                            )
                        })
                    }),
                Err(error) => Err(error),
            };
            match accepted {
                Ok(event_id) => {
                    state_store.write(|store| {
                        store.mark_mls_genesis_emitted_for_effective_scope_with_event(
                            realm_id, None, &event_id,
                        )
                    })?;
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
    if state_store.read(|store| {
        store
            .mls_group_state_ref_for_effective_scope(realm_id, None, &accepted_event_id.to_string(), 0)
            .is_err()
            && store.mls_checkpoint_for(realm_id).is_none()
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
            store.mls_group_state_ref_for_scope(
                effective_scope,
                &snapshot.group_id,
                snapshot.epoch,
            )
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

    #[test]
    fn creator_bootstrap_recognizes_typed_genesis_conflict_without_matching_diagnostic_text() {
        let conflict = |code: &str, detail: &str| {
            anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                status: 409,
                error: Box::new(arkret_sdk::Problem::from_code(code, detail)),
            })
        };
        assert!(genesis_already_accepted(&conflict(
            "mls_genesis_already_exists",
            "already accepted"
        )));
        assert!(!genesis_already_accepted(&conflict(
            "failed_precondition",
            "mls_genesis_already_exists"
        )));
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
    fn realm_projection(creator: &str, encryption_profile: &str) -> serde_json::Value {
        let principal_id = crate::mls_api_helpers::principal_core_id(creator).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        json!({
            "__kind": "realm",
            "content_scheme": encryption_profile,
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": creator, "membership": "join" }],
            "summary": {
                "title": "Realm",
                "encryption_profile": encryption_profile,
            },
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
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn optimistic_encrypted_realm_is_incomplete_before_authority_current_arrives() {
        let mut store = temp_store("optimistic-incomplete");
        store.save_realm_tree_projection(
            REALM,
            json!({
                "__kind": "realm",
                "content_scheme": "mls_rfc9420",
                "summary": { "encryption_profile": "mls_rfc9420" }
            }),
        );
        // The gate is the local epoch-0 group material, so an optimistic
        // projection with no installed authority current is still incomplete
        // and the pending hint agrees with it exactly.
        assert!(creator_mls_bootstrap_incomplete(&store, REALM));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn emitted_genesis_with_stale_checkpoint_remains_pending() {
        let mut store = temp_store("stale-checkpoint");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        store
            .save_mls_checkpoint(REALM, epoch_zero_snapshot(group_id.clone()))
            .unwrap();
        let accepted_genesis =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        store
            .mark_mls_genesis_emitted_for_effective_scope_with_event(REALM, None, &accepted_genesis)
            .unwrap();

        // The emitted marker plus its accepted Event id do not replace durable
        // MLS application: the epoch-zero checkpoint still has to name the
        // accepted transition before the group may be used.
        assert_eq!(
            store
                .mls_checkpoint_for(REALM)
                .unwrap()
                .group_state_event_id,
            Some(accepted_genesis)
        );
        assert!(
            store
                .accepted_current_realm_mls_transition_evidence(REALM)
                .is_err()
        );
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
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
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
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
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
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
        let group_id = scope.canonical_mls_group_id().unwrap();
        let mut advanced = epoch_zero_snapshot(group_id);
        advanced.epoch = 3;
        store.save_mls_checkpoint(REALM, advanced).unwrap();
        assert!(!creator_mls_bootstrap_incomplete(&store, REALM));
    }
}
