//! Creator-side MLS bootstrap for an encrypted Realm, made replayable.
//!
//! A Realm creator never receives a Welcome — the epoch-0 group is created
//! locally, its `ak.mls.genesis` is submitted by the creator, and a durable
//! replay checkpoint is pinned only after the accepted Seal closure passes the full
//! `encryption-and-audit.md` §2.5.1.1 verification order. Until this module
//! existed, that whole sequence lived inline in the Realm-create wizard's
//! `spawn`, so a component unmount (the user clicking straight into the new
//! Realm), a transient network failure or a closed tab left the Realm with no
//! pinned checkpoint, no local snapshot and no genesis — and nothing ever retried.
//! Every later encrypted write then failed forever with
//! `MLS governance proof requires a locally verified replay checkpoint`.
//!
//! Spec position: `encryption-and-audit.md` §2.5.4 T1 defines when a Seal cut may
//! become the local checkpoint — the candidate must include the genesis Seal of the
//! `ak.realm.create` Event that `realm_id` retypes to, signed by the notary that
//! create payload names. This module does not decide any of that; it calls
//! [`ensure_governance_checkpoint`](crate::mls::governance_proof::ensure_governance_checkpoint),
//! which runs the SDK admission test. Nothing here requires the sequence to
//! complete in one attempt, and replaying it is safe.

use crate::runtime::input::StateStoreHandle;
use crate::state::LocalStateStore;

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

/// Acquire, verify, and durably pin the accepted Seal checkpoint for a Realm
/// that the current principal has created or joined. This is required for
/// every Realm, not only encrypted ones: subsequent writes derive authority
/// and the digest suite from verified governance state covered by that
/// checkpoint.
pub(crate) async fn ensure_realm_governance_checkpoint<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &crate::transport::TransportClient,
    state_store: S,
    realm_id: &str,
) -> Result<(), String> {
    if state_store
        .with_read(|store| store.trusted_mls_governance_checkpoint(realm_id))
        .is_some()
    {
        return Ok(());
    }
    // Checkpoint acquisition also runs from the framework-independent Realm
    // events engine. Construct this read-only frontier client from the
    // authenticated HTTP client instead of consulting Dioxus SessionContext;
    // the durable state dependency is carried explicitly by `state_store`.
    let submitter = crate::event_submit::EventSubmitter::new(
        api.sdk_http_client()
            .map_err(|error| format!("Realm governance proof frontier client: {error}"))?,
    );
    let seal_view = wait_for_realm_seal_view(&submitter, realm_id)
        .await
        .map_err(|error| {
            format!("refreshing the accepted Seal view failed: {error}")
        })?;
    state_store.with_write(|store| {
        let mut view = store.seal_view_for_realm(realm_id);
        view.frontier = seal_view
            .seal_basis
            .leaves
            .iter()
            .map(ToString::to_string)
            .collect();
        view.state_root = None;
        store.set_realm_seal_view(realm_id.to_owned(), view);
    });
    crate::mls::governance_proof::ensure_governance_checkpoint(api, state_store, realm_id)
        .await
        .map_err(|error| format!("establishing the Realm governance checkpoint failed: {error}"))
}

/// Whether this client is the creator of an encrypted `realm_id` whose MLS
/// bootstrap is still incomplete.
///
/// Cheap and synchronous so UI effects can gate on it without spawning. The
/// creator check is what keeps the trust source inside §2.5.1.1's enumeration:
/// only the actor that created the Realm may establish the initial replay
/// checkpoint from its genesis. It mirrors the gate in
/// creator test is shared with group-event construction.
pub(crate) fn creator_mls_bootstrap_pending(
    store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
) -> bool {
    let state = store.load();
    let Some(projection) =
        garth::security_projection_for_scope_id(&state.realm_tree_projections, realm_id)
    else {
        return false;
    };
    if !garth::realm_projection_is_encrypted(projection)
        || !crate::mls::group_events::projected_realm_creator_matches_actor(
            &state.realm_tree_projections,
            realm_id,
            actor_id,
        )
    {
        return false;
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
    // `emitted` plus a local Event id is not a completion boundary. The
    // create wizard can be unmounted immediately after the submit succeeds,
    // leaving the accepted Genesis outside the still-pinned pre-Genesis
    // checkpoint. The exact transition must be in a valid verified checkpoint
    // and its accepted artifact must be durably published before bootstrap is
    // considered complete.
    let Ok(evidence) = store.accepted_current_realm_mls_transition_evidence(realm_id) else {
        return true;
    };
    !store
        .accepted_mls_artifact_snapshot()
        .snapshot
        .artifacts
        .contains_key(evidence.transition_ref.as_str())
}

/// Refresh the accepted Seal view, acquire + verify + pin the governance
/// proof, create the epoch-0 creator group and submit `ak.mls.genesis`.
///
/// Idempotent and safe to re-enter: it returns early only after the accepted
/// Genesis is present in the locally verified checkpoint and its accepted MLS
/// artifact is durable. A server-side duplicate genesis is resolved to its
/// accepted Event id rather than treated as an error.
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
    if state_store.read(|store| !creator_mls_bootstrap_pending(store, realm_id, actor_id)) {
        return Ok(());
    }
    if state_store.read(|store| {
        store.mls_genesis_emitted_for(realm_id) && store.mls_checkpoint_for(realm_id).is_none()
    }) {
        return Err(format!(
            "accepted MLS genesis exists for {realm_id}, but the local snapshot is missing; restore this device before retrying creator bootstrap"
        ));
    }

    // encryption-and-audit.md 2.5.4 T1. The creator's trust in the checkpoint
    // comes from the create Event it authored, recognised through realm_id.
    ensure_realm_governance_checkpoint(api, state_store.clone(), realm_id).await?;
    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS genesis Event submitter: {error}"))?;

    let leaves = crate::mls::governance_proof::singleton_security_frontier_leaf(
        &arkret_sdk::ActorId::account(authority.clone()),
        device_id.as_str(),
    )?;
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
    let genesis_emitted = state_store.read(|store| store.mls_genesis_emitted_for(realm_id));
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
            let request = state_store
                .read(|store| {
                    crate::mls::governance_proof::proof_request(
                        store,
                        realm_id,
                        None,
                        garth::mls::welcome_admission::mls_group_id_for_realm(realm_id)?,
                        0,
                        0,
                        leaves.clone(),
                    )
                })
                .map_err(|error| {
                    format!("preparing the MLS governance proof request failed: {error}")
                })?;
            crate::mls::governance_proof::fetch_verify_and_cache_proof(
                api,
                state_store.clone(),
                &request,
                &leaves,
            )
            .await
            .map_err(|error| {
                format!("verifying the accepted governance proof before MLS setup failed: {error}")
            })?;

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
            Ok(accepted) => arkret_sdk::EventId::new(accepted.event_id.clone()).map_err(|error| {
                anyhow::anyhow!("accepted ak.mls.genesis carries an invalid Event id: {error}")
            }),
            // A duplicate is success only after resolving the exact
            // already-accepted Event id: encrypted writes bind their
            // `group_state_ref` to it, so merely setting the emitted flag would
            // strand them without a resolvable group state.
            Err(error)
                if crate::ephemeral::events_submit_rejected_for_reason(
                    &error,
                    &arkret_sdk::ReasonCode::MlsGenesisAlreadyExists,
                ) => submitter
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
    let checkpoint_has_genesis = state_store
        .read(|store| store.trusted_mls_governance_checkpoint(realm_id))
        .is_some_and(|checkpoint| {
            checkpoint
                .accepted_events
                .iter()
                .any(|event| event.event_id == accepted_event_id)
        });
    if !checkpoint_has_genesis {
        let current_basis = state_store
            .read(|store| store.trusted_mls_governance_checkpoint(realm_id))
            .ok_or_else(|| "creator MLS genesis has no verified base checkpoint".to_owned())?
            .basis;
        let seal_view =
            wait_for_realm_seal_view_after_basis(&submitter, realm_id, &current_basis).await?;
        state_store.write(|store| {
            store.set_realm_seal_view(
                realm_id.to_owned(),
                crate::state::LocalSealView {
                    frontier: seal_view
                        .seal_basis
                        .leaves
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    state_root: None,
                    ..Default::default()
                },
            );
        });
        let request = state_store.read(|store| {
            crate::mls::governance_proof::proof_request(
                store,
                realm_id,
                None,
                garth::mls::welcome_admission::mls_group_id_for_realm(realm_id)?,
                0,
                0,
                leaves.clone(),
            )
        })?;
        crate::mls::governance_proof::fetch_verify_and_cache_proof(
            api,
            state_store.clone(),
            &request,
            &leaves,
        )
        .await?;
    }
    crate::mls::runtime::converge_accepted_mls_artifacts(state_store, authority, device_id).await?;
    let ready = state_store
        .read(|store| store.accepted_mls_artifact_snapshot())
        .snapshot
        .artifacts
        .contains_key(accepted_event_id.as_str());
    if !ready {
        return Err("accepted MLS Genesis did not become durably ready".to_owned());
    }

    Ok(())
}

async fn wait_for_realm_seal_view_after_basis(
    submitter: &crate::event_submit::EventSubmitter,
    realm_id: &str,
    previous: &arkret_sdk::SealBasis,
) -> Result<arkret_sdk::RealmSealFrontierView, String> {
    const ATTEMPTS: usize = 20;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(250);
    for attempt in 0..ATTEMPTS {
        match submitter.seals_frontier_realm_view(realm_id).await {
            Ok(view) if &view.seal_basis != previous => return Ok(view),
            Ok(_) if attempt + 1 < ATTEMPTS => {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Ok(_) => {
                return Err(
                    "accepted MLS Genesis was not covered by a new Realm Seal frontier".to_owned(),
                );
            }
            Err(error) if realm_seal_view_retry_is_allowed(&error, attempt, ATTEMPTS) => {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    unreachable!("Realm Seal retry loop returns on its final attempt")
}

/// Poll `ak.self.seals.read.frontier.v1` until the Realm has an accepted Seal.
///
/// A Realm accepted moments ago may not be sealed yet. During that window the
/// registered frontier surface can report either `not_found` before a Seal
/// exists or `frontier_unavailable` while accepted Control Events are still
/// being materialized. Both are transient for this creator-only post-create
/// poll; every other protocol or transport error still fails closed.
pub(crate) async fn wait_for_realm_seal_view(
    submitter: &crate::event_submit::EventSubmitter,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
    const ATTEMPTS: usize = 20;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(250);

    for attempt in 0..ATTEMPTS {
        match submitter.seals_frontier_realm_view(realm_id).await {
            Ok(view) => return Ok(view),
            Err(error) if realm_seal_view_retry_is_allowed(&error, attempt, ATTEMPTS) => {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("realm Seal retry loop returns on its final attempt")
}

fn realm_seal_view_retry_is_allowed(
    error: &anyhow::Error,
    attempt: usize,
    attempts: usize,
) -> bool {
    attempt + 1 < attempts && crate::api_error::is_realm_seal_frontier_pending_error(error)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
    /// available through the projected `ak.realm.create` Event, which is the
    /// single registered writer of the authority-root cell. The retired
    /// `owner` / `created_by` mirrors are deliberately absent — a fixture that
    /// carried them would test a fallback the client no longer has.
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
            "state": {
                "events": [{
                    "kind": "ak.realm.create",
                    "actor_id": creator,
                    "payload": {
                        "object": {
                            "encryption_profile": encryption_profile,
                        }
                    }
                }]
            }
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
    fn emitted_genesis_with_stale_checkpoint_remains_pending() {
        let mut store = temp_store("stale-checkpoint");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        let scope = arkret_sdk::HistoryEffectiveScope::Realm {
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

        // Reproduce the interrupted first-user transaction: a checkpoint is
        // pinned, the local snapshot carries the accepted Genesis id, and the
        // emitted flag is set, but the checkpoint still predates Genesis.
        crate::mls::governance_proof::seed_test_governance_proof(
            &mut store, REALM, None, group_id, 0, 0,
        );
        assert!(store.trusted_mls_governance_checkpoint(REALM).is_some());
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
    fn creator_is_recognized_from_the_projected_realm_create_when_no_owner_field_exists() {
        // Post-P1 realm projections carry no owner/created_by mirror; the
        // creator fact lives in the projected `ak.realm.create` event.
        let mut store = temp_store("create-event-source");
        let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(ACTOR).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        store.save_realm_tree_projection(
            REALM,
            json!({
                "__kind": "realm",
                "content_scheme": "mls_rfc9420",
                "summary": { "title": "Realm", "encryption_profile": "mls_rfc9420" },
                "state": {
                    "events": [{
                        "kind": "ak.realm.create",
                        "actor_id": actor_id,
                        "payload": { "object": { "encryption_profile": "mls_rfc9420" } }
                    }]
                }
            }),
        );
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
        assert!(!creator_mls_bootstrap_pending(
            &store,
            REALM,
            "did:web:bob.example"
        ));
    }

    #[test]
    fn a_non_creator_is_never_pending() {
        let mut store = temp_store("non-creator");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        // Members join through a Welcome; they must never treat the Realm's
        // genesis Seal as an already-trusted anchor.
        assert!(!creator_mls_bootstrap_pending(
            &store,
            REALM,
            "did:web:bob.example"
        ));
    }

    #[test]
    fn a_plaintext_realm_is_never_pending() {
        let mut store = temp_store("plaintext");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "none"));
        assert!(!creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn an_unprojected_realm_is_never_pending() {
        let store = temp_store("unknown");
        assert!(!creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    fn frontier_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_sdk::Problem::from_code(
                code,
                "frontier is not ready",
            )),
        })
    }

    #[test]
    fn creator_seal_poll_retries_normative_frontier_pending_responses() {
        for error in [
            frontier_error(404, "not_found"),
            frontier_error(503, "frontier_unavailable"),
        ] {
            assert!(realm_seal_view_retry_is_allowed(&error, 0, 20));
        }

        let wrapped = frontier_error(503, "frontier_unavailable")
            .context("refreshing the accepted Realm Seal view");
        assert!(realm_seal_view_retry_is_allowed(&wrapped, 0, 20));
    }

    #[test]
    fn creator_seal_poll_does_not_retry_permanent_or_exhausted_responses() {
        assert!(!realm_seal_view_retry_is_allowed(
            &frontier_error(409, "state_mismatch"),
            0,
            20,
        ));
        assert!(!realm_seal_view_retry_is_allowed(
            &frontier_error(409, "frontier_unavailable"),
            0,
            20,
        ));
        assert!(!realm_seal_view_retry_is_allowed(
            &frontier_error(412, "frontier_unavailable"),
            0,
            20,
        ));
        assert!(!realm_seal_view_retry_is_allowed(
            &frontier_error(503, "frontier_unavailable"),
            19,
            20,
        ));
    }
}
