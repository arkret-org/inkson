//! `encryption-and-audit.md` §2.4.1 / §2.5.2 — recover a scope from
//! `epoch_update_required` by advancing the MLS epoch.
//!
//! §2.5.2 gates every E2EE application ordinary Event on the accepted MLS Security
//! Frontier. Membership or key-access control changes require an accepted
//! `ak.mls.commit` whose governance binding projects the new control state and
//! active leaf set. §2.4.1 makes the sender MUST pause until that happens.
//!
//! Endpoint authorization and policy updates do not advance key-access revision.
//! A receiver's typed refusal or a verified durable MLS current result can
//! establish missing coverage; a moving stream head cannot. The receiver
//! reports it with `failed_precondition` / `epoch_update_required`. A
//! top-level `epoch_mismatch` is a different state (decision 0100): a covering
//! Commit already exists, so this module does nothing for it and the sender
//! refreshes its group and re-encrypts a new request instead.
//!
//! Genesis replay lives in [`crate::mls::creator_bootstrap`]; this is the same
//! shape (idempotent, re-enterable, driven from the per-Realm MLS effect) for
//! the state after genesis.

use crate::runtime::input::StateStoreHandle;
use crate::state::LocalStateStore;

/// Record a receiver's governance-binding coverage refusal for the effective
/// scope that produced it. Returns `true` when the error was that refusal.
///
/// Call this from every E2EE application ordinary Event send path: without it the
/// refusal is just another failed submit and the epoch never advances.
pub(crate) fn note_e2ee_submit_refusal(
    state_store: &StateStoreHandle,
    realm_id: &str,
    circle_id: Option<&str>,
    error: &anyhow::Error,
) -> bool {
    state_store.write(|store| note_e2ee_submit_refusal_in_store(store, realm_id, circle_id, error))
}

/// Record the same coverage refusal when it arrives already classified.
///
/// The typed message authoring path reports `epoch_update_required` as
/// [`garth::MessageAuthoringFailure::EpochCommitPending`] rather than as a raw
/// transport error, and the epoch still has to advance for that scope.
pub(crate) fn note_e2ee_epoch_update_required(
    state_store: &StateStoreHandle,
    realm_id: &str,
    circle_id: Option<&str>,
    detail: &str,
) -> bool {
    state_store.write(|store| {
        if let Err(error) = store.record_mls_coverage_stale(realm_id.to_owned(), circle_id, detail)
        {
            tracing::warn!(realm = %realm_id, %error, "refusing to persist an invalid MLS coverage scope");
            return false;
        }
        true
    })
}

/// The durable send gate can discover missing coverage before a submit is
/// allowed. Wake the same repair scheduler once, without inventing a refusal
/// from error text or repeatedly dirtying the store while the gate is blocked.
pub(crate) fn note_send_gate_blocked_in_store(
    store: &mut LocalStateStore,
    scope: &arkret_sdk::ScopeRef,
    blocked: &crate::mls::send_gate::MlsSendGateBlocked,
) -> bool {
    if blocked != &crate::mls::send_gate::MlsSendGateBlocked::EpochUpdateRequired {
        return false;
    }
    let (realm, circle) = match scope {
        arkret_sdk::ScopeRef::Realm { realm_id } => (realm_id, None),
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => (realm_id, Some(circle_id.as_str())),
        _ => return false,
    };
    if store
        .mls_coverage_stale_reason(realm.as_str(), circle)
        .is_some()
    {
        return false;
    }
    match store.record_mls_coverage_stale(realm.to_string(), circle, &blocked.to_string()) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, "could not schedule MLS send-gate coverage repair");
            false
        }
    }
}

/// Store-level form for callers that already hold the store borrow.
pub(crate) fn note_e2ee_submit_refusal_in_store(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    error: &anyhow::Error,
) -> bool {
    if crate::api_error::mls_send_refusal(error) != Some(garth::MlsSendRefusal::EpochUpdateRequired)
    {
        return false;
    }
    if let Err(error) =
        state_store.record_mls_coverage_stale(realm_id.to_owned(), circle_id, &error.to_string())
    {
        tracing::warn!(realm = %realm_id, %error, "refusing to persist an invalid MLS coverage scope");
        return false;
    }
    true
}

/// The effective scopes of `realm_id` waiting for an epoch advance to restore
/// sending, as the `circle_id` argument [`ensure_mls_governance_coverage`]
/// takes (`None` = the Realm-default group).
///
/// Cheap and synchronous so UI effects can gate on it without spawning, and
/// deliberately requires a local snapshot per scope: without group material
/// there is nothing to commit from, and the creator bootstrap / Welcome pass is
/// what fixes that.
pub(crate) fn pending_mls_coverage_repairs(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<Option<String>> {
    store
        .stale_mls_coverage_scopes(realm_id)
        .into_iter()
        .filter(|circle_id| {
            store
                .mls_checkpoint_for_effective_scope(realm_id, circle_id.as_deref())
                .is_some()
        })
        .collect()
}

/// Stable, non-secret fingerprint for the Realm bootstrap effect's dedup key.
///
/// Recording `epoch_update_required` mutates only the local state store;
/// it does not advance the sync cursor or any of the other inputs that used to
/// make up that effect's key.  Without this hint the effect woke up, compared
/// the same key, and returned before running the repair it had just been asked
/// to perform.  Include every stale effective scope (even one that is not yet
/// repairable because its snapshot is still arriving) so a later snapshot
/// write and the stale marker are both observable scheduler edges.
pub(crate) fn mls_coverage_repair_dedup_hint(store: &LocalStateStore, realm_id: &str) -> String {
    store
        .stale_mls_coverage_scopes(realm_id)
        .into_iter()
        .map(|circle_id| circle_id.unwrap_or_else(|| "realm".to_owned()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Advance the MLS epoch so the scope's new commit covers its current
/// key-access revision, restoring encrypted sending.
///
/// Returns `Ok(true)` when repair is settled: nothing remains scheduled, an
/// accepted transition already covers current, or this pass installed a Commit.
/// `Ok(false)` retains pending work without claiming a new accepted Commit.
/// A stale scheduling hint cannot require another rotation after a member-add
/// or another device's accepted Commit has restored coverage. This does not
/// make a lagging private group ready; the ordinary send gate still checks it.
pub(crate) async fn ensure_mls_governance_coverage(
    api: &crate::transport::TransportClient,
    state_store: &StateStoreHandle,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<bool, String> {
    let actor_id = authority.principal_id.as_str();
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err("realm_id is required for MLS coverage repair".to_owned());
    }
    let circle_id = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let authoring_lock = crate::mls::admission::mls_admission_authoring_lock(realm_id);
    let _authoring_guard = authoring_lock.lock().await;
    if state_store.read(|store| store.active_authority().as_ref() != Some(authority)) {
        return Err("MLS coverage repair belongs to a replaced account".to_owned());
    }
    let (pending, has_checkpoint) = state_store.read(|store| {
        (
            store
                .mls_coverage_stale_reason(realm_id, circle_id)
                .is_some(),
            store
                .mls_checkpoint_for_effective_scope(realm_id, circle_id)
                .is_some(),
        )
    });
    if !pending {
        return Ok(true);
    }
    if !has_checkpoint {
        return Ok(false);
    }

    // Resume the original frozen unit before attempting another transition.
    // Pending OpenMLS state is not permission to overwrite it or claim anew.
    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS coverage repair client: {error}"))?
        .with_authority(authority.clone())
        .with_state_store(state_store.clone());
    submitter
        .drain_mls_outbound()
        .await
        .map_err(|error| format!("resuming the original MLS submission failed: {error}"))?;
    if submitter
        .has_pending_mls_admission_for_realm(realm_id)
        .await
        .map_err(|error| format!("checking the original MLS submission failed: {error}"))?
    {
        return Ok(false);
    }

    let realm = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| error.to_string())?;
    let scope = match circle_id {
        Some(circle) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::new(circle.to_owned())
                .map_err(|error| error.to_string())?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
    };
    let Some(current) = current_needing_coverage_repair(state_store, &scope, authority).await?
    else {
        return Ok(true);
    };
    // Pin the same verified current used by the send gate for both the MLS
    // authenticated handshake and its outer Event. The product view can lag.
    let binding = crate::mls::governance_proof::binding_for_current_transition(&current)?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let local_state = state_store.read(Clone::clone);
    let staged = crate::mls::runtime::force_epoch_rotation_commit_with_binding(
        &local_state,
        secure_store.as_ref(),
        &binding,
        authority,
        device_id,
    )
    .map_err(|error| {
        format!(
            "building the MLS coverage repair commit failed: {}",
            error.user_message()
        )
    })?;
    let commit_event = crate::mls::group_events::mls_commit_event_with_binding(
        &local_state,
        actor_id,
        &staged.envelope,
        &binding,
    )
    .map_err(|error| format!("building ak.mls.commit event failed: {error}"))?;

    let authored = submitter
        .author_for_direct_submission(&commit_event)
        .await
        .map_err(|error| format!("authoring the MLS coverage repair commit failed: {error}"))?;
    // No Welcome travels with a self-update: membership is unchanged, so the
    // atomic submission carries the Commit alone. The accepted commit is
    // installed by the submission's own post-accept step.
    submitter
        .submit_mls_commit(
            authored,
            Vec::new(),
            device_id.clone(),
            Vec::new(),
            state_store,
            staged.staged_checkpoint,
        )
        .await
        .map_err(|error| format!("submitting the MLS coverage repair commit failed: {error}"))?;
    state_store.write(|store| store.clear_mls_coverage_stale(realm_id, circle_id))?;
    tracing::info!(
        realm = %realm_id,
        circle = circle_id.unwrap_or("-"),
        epoch = staged.envelope.epoch,
        "MLS coverage repair commit accepted; encrypted sending may resume",
    );
    Ok(true)
}

/// Recheck the scheduling hint against the complete durable public cut.
/// This decision does not imply that this device's private state can send.
async fn current_needing_coverage_repair(
    state_store: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
) -> Result<Option<arkret_wire::MlsGroupValue>, String> {
    let (realm, circle) = match scope {
        arkret_sdk::ScopeRef::Realm { realm_id } => (realm_id, None),
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => (realm_id, Some(circle_id.as_str())),
        _ => return Err("MLS coverage repair requires a Realm or Circle".to_owned()),
    };
    let realm_id = realm.as_str();
    let circle_id = circle;
    let read = state_store
        .read(LocalStateStore::capture_committed_account_read)
        .map_err(|error| format!("capturing MLS coverage repair cut failed: {error}"))?;
    let input = crate::mls::send_gate::MlsSendGateInput::capture(state_store, scope);
    let current = crate::mls::send_gate::read_durable_mls_current(&input, scope)
        .await
        .map_err(|error| format!("reading MLS coverage repair current failed: {error}"))?
        .ok_or_else(|| "MLS coverage repair requires verified durable current".to_owned())?;
    if current.covered_key_access_revision >= current.current_key_access_revision {
        state_store.write(|store| {
            if !read.matches(store)
                || store.current_reset_required()
                || store.active_authority().as_ref() != Some(authority)
            {
                return Err("MLS coverage repair cut changed before completion".to_owned());
            }
            store.clear_mls_coverage_stale(realm_id, circle_id)
        })?;
        return Ok(None);
    }
    if !state_store.read(|store| {
        read.matches(store)
            && !store.current_reset_required()
            && store.active_authority().as_ref() == Some(authority)
    }) {
        return Err("MLS coverage repair cut changed before authoring".to_owned());
    }
    Ok(Some(current))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> LocalStateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        LocalStateStore::with_path(
            std::env::temp_dir().join(format!("inkson-coverage-liveness-{name}-{stamp}.json")),
        )
    }

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    #[cfg(not(target_arch = "wasm32"))]
    async fn exercise_current_coverage(
        covered: bool,
        complete: bool,
        change_cut: bool,
        wrong_authority: bool,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use serde_json::json;
        let directory = tempfile::tempdir().unwrap();
        let mut local = LocalStateStore::with_path(directory.path().join("state.json"));
        local.promote_accepted_context_for_test(
            &arkret_sdk::Did::new(format!(
                "did:web:coverage-{}.example",
                crate::operation::uuid_v7()
            ))
            .unwrap(),
        );
        let authority = local.active_authority().unwrap();
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: REALM.parse().unwrap(),
        };
        let checkpoint = garth::mls::checkpoint::encrypt_state(
            REALM,
            scope.canonical_mls_group_id().unwrap().as_str(),
            1,
            b"old-private-state",
            "test-secret",
            b"coverage-salt",
        );
        local
            .save_mls_checkpoint_for_scope(&scope, checkpoint.clone())
            .unwrap();
        local
            .record_mls_coverage_stale(REALM, None, "epoch_update_required")
            .unwrap();
        let commit = arkret_sdk::RealmCommitId::from_digest([9; 32]);
        let head = json!([{"stream_ref":scope,"stream_position":1,"commit_id":commit}]);
        let frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(json!({
            "kind":"delta", "cursor":"ak:cursor:YQ", "realms":{REALM:{
                "current":{"realm_id":REALM,"governance_generation":"1","stream_heads":head,"entries":[{
                    "selector":{"kind":"mls_group","scope_ref":scope},
                    "source_stream_ref":scope,"revision":{"commit_id":commit,"stream_position":1},
                    "value":{
                        "effective_scope":scope,
                        "genesis_event_ref":arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[1;32]),
                        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                        "current_mls_commit_event_ref":arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[2;32]),
                        "epoch":"2","current_key_access_revision":"2",
                        "covered_key_access_revision":if covered {"2"} else {"1"},
                        "public_tree_ref":format!("ak:blob:sha256:{}","33".repeat(32))
                    }
                }]},
                "baseline":{"snapshot_cursor":"ak:cursor:cw","cut_revision":1,
                    "coverage":{"realm_id":REALM,"stream_heads":head,"complete_for_authorized_streams":complete},
                    "complete":complete}
            }}
        })).unwrap();
        let index = crate::state::CurrentIndex::open(&authority, 0, local.current_index_location())
            .await
            .unwrap();
        let mut staged = index.stage_frame(0, &frame).await.unwrap();
        staged.arm_account_commit();
        local
            .verified_projection_transaction(|store| {
                store.set_current_generation(staged.generation());
                Ok(())
            })
            .unwrap();
        local.begin_durable_flush().unwrap().wait().await.unwrap();
        staged.finish();
        let data = Arc::new(Mutex::new(local));
        let read = data.clone();
        let write = data.clone();
        let reads = AtomicUsize::new(0);
        let state = StateStoreHandle::new(
            move |callback| {
                let mut store = read.lock().unwrap();
                callback(&store);
                // Commit after the index captures its generation, before the
                // coverage decision can clear the old scheduling hint.
                if change_cut && reads.fetch_add(1, Ordering::SeqCst) == 2 {
                    store.append_raw_operation("concurrent-write", None, json!({"changed":true}));
                    store.flush().unwrap();
                }
            },
            move |callback| callback(&mut write.lock().unwrap()),
        );
        let caller = if wrong_authority {
            arkret_sdk::AccountId::new(
                crate::test_support::core_id("ak:did_core:web:replaced-coverage.example"),
                authority.station_id.clone(),
            )
        } else {
            authority.clone()
        };
        let result = current_needing_coverage_repair(&state, &scope, &caller).await;
        if wrong_authority {
            assert!(result.unwrap_err().contains("cut changed before"));
            assert!(state.read(|store| store.mls_coverage_stale_reason(REALM, None).is_some()));
        } else if change_cut {
            assert!(
                result
                    .unwrap_err()
                    .contains("cut changed before completion")
            );
            assert!(state.read(|store| store.mls_coverage_stale_reason(REALM, None).is_some()));
        } else if covered && complete {
            assert!(result.unwrap().is_none());
            assert!(state.read(|store| store.mls_coverage_stale_reason(REALM, None).is_none()));
            let input = crate::mls::send_gate::MlsSendGateInput::capture(&state, &scope);
            assert!(matches!(
                crate::mls::send_gate::resolve_mls_send_gate(&input, &scope).await,
                Err(
                    crate::mls::send_gate::MlsSendGateBlocked::LocalGroupBehind {
                        current_epoch: 2
                    }
                )
            ));
        } else {
            if complete {
                let current = result
                    .unwrap()
                    .expect("uncovered current still needs repair");
                assert_eq!(current.current_key_access_revision, 2);
                assert_eq!(current.covered_key_access_revision, 1);
                let input = crate::mls::send_gate::MlsSendGateInput::capture(&state, &scope);
                assert_eq!(
                    crate::mls::send_gate::resolve_mls_send_gate(&input, &scope).await,
                    Err(crate::mls::send_gate::MlsSendGateBlocked::EpochUpdateRequired)
                );
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.contains("complete authorized-stream coverage"),
                    "{error}"
                );
            }
            assert!(state.read(|store| store.mls_coverage_stale_reason(REALM, None).is_some()));
        }
        assert_eq!(
            state.read(|store| store.mls_checkpoint_for_scope(&scope)),
            Some(checkpoint)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn covered_member_commit_clears_hint_without_rotating_or_readying_old_private_group() {
        exercise_current_coverage(true, true, false, false).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn incomplete_current_cannot_settle_a_coverage_repair() {
        exercise_current_coverage(true, false, false, false).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn uncovered_current_keeps_repair_pending() {
        exercise_current_coverage(false, true, false, false).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_changed_checkpoint_cannot_clear_the_old_coverage_hint() {
        exercise_current_coverage(true, true, true, false).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_replaced_account_cannot_clear_covered_or_author_uncovered_current() {
        exercise_current_coverage(true, true, false, true).await;
        exercise_current_coverage(false, true, false, true).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn completion_distinguishes_settled_hints_from_missing_private_material() {
        use std::sync::{Arc, Mutex};
        let directory = tempfile::tempdir().unwrap();
        let mut local = LocalStateStore::with_path(directory.path().join("state.json"));
        local.promote_accepted_context_for_test(
            &arkret_sdk::Did::new("did:web:coverage-completion.example").unwrap(),
        );
        let authority = local.active_authority().unwrap();
        let shared = Arc::new(Mutex::new(local));
        let read = shared.clone();
        let write = shared.clone();
        let state = StateStoreHandle::new(
            move |callback| callback(&read.lock().unwrap()),
            move |callback| callback(&mut write.lock().unwrap()),
        );
        let api =
            crate::transport::TransportClient::unauthenticated("http://127.0.0.1:1/").unwrap();
        let device =
            crate::test_support::device_id("ak:device:01904100-0000-7000-8000-000000000001");
        assert!(
            ensure_mls_governance_coverage(&api, &state, REALM, None, &authority, &device)
                .await
                .unwrap(),
            "a cleared scheduling hint must let its owner clear the old error and stop retrying"
        );
        state
            .write(|store| store.record_mls_coverage_stale(REALM, None, "epoch_update_required"))
            .unwrap();
        assert!(
            !ensure_mls_governance_coverage(&api, &state, REALM, None, &authority, &device)
                .await
                .unwrap(),
            "missing private material remains pending, without transport or a new Commit"
        );
        assert!(state.read(|store| store.mls_coverage_stale_reason(REALM, None).is_some()));
    }

    #[test]
    fn a_verified_send_gate_block_wakes_coverage_repair_without_a_failed_submit() {
        use crate::mls::send_gate::MlsSendGateBlocked;
        let mut store = temp_store("send-gate");
        let realm_id = arkret_sdk::RealmId::new(REALM).unwrap();
        let realm = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        for blocked in [
            MlsSendGateBlocked::GenesisPending,
            MlsSendGateBlocked::EpochMismatch,
            MlsSendGateBlocked::LocalGroupBehind { current_epoch: 2 },
            MlsSendGateBlocked::NotReady("epoch_update_required".to_owned()),
        ] {
            assert!(!note_send_gate_blocked_in_store(
                &mut store, &realm, &blocked
            ));
        }
        assert!(store.stale_mls_coverage_scopes(REALM).is_empty());
        let blocked = MlsSendGateBlocked::EpochUpdateRequired;
        assert!(note_send_gate_blocked_in_store(
            &mut store, &realm, &blocked
        ));
        assert!(!note_send_gate_blocked_in_store(
            &mut store, &realm, &blocked
        ));
        let circle = arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(
                "ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            )
            .unwrap(),
        };
        assert!(note_send_gate_blocked_in_store(
            &mut store, &circle, &blocked
        ));
        assert_eq!(store.stale_mls_coverage_scopes(REALM).len(), 2);
        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert!(note_send_gate_blocked_in_store(
            &mut store, &realm, &blocked
        ));
    }

    #[test]
    fn coverage_repair_needs_both_a_refusal_and_local_group_material() {
        let mut store = temp_store("pending");
        assert!(pending_mls_coverage_repairs(&store, REALM).is_empty());
        store
            .record_mls_coverage_stale(REALM, None, "epoch_update_required: ...")
            .unwrap();
        // Still not repairable: without group material there is nothing to
        // commit from, and the creator bootstrap owns that step.
        assert!(pending_mls_coverage_repairs(&store, REALM).is_empty());
        assert_eq!(store.stale_mls_coverage_scopes(REALM), vec![None]);
    }

    fn station_problem(problem: arkret_sdk::Problem) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: problem.status,
            error: Box::new(problem),
        })
    }

    #[test]
    fn only_a_typed_epoch_update_required_arms_the_repair() {
        use arkret_sdk::error_codes::{ErrorCode, ReasonCode};
        let mut store = temp_store("typed-refusal");
        let pending = arkret_sdk::Problem::from_code(
            ErrorCode::FAILED_PRECONDITION,
            "key-access checkpoint awaits a Commit",
        )
        .with_extension(
            "reason_code",
            serde_json::Value::String(ReasonCode::EPOCH_UPDATE_REQUIRED.to_owned()),
        );
        let mismatch = arkret_sdk::Problem::from_code(ErrorCode::EPOCH_MISMATCH, "stale epoch");
        let binding_stale = arkret_sdk::Problem::from_code(
            ErrorCode::FAILED_PRECONDITION,
            "mls_governance_binding_stale epoch_update_required",
        )
        .with_extension(
            "reason_code",
            serde_json::Value::String(ReasonCode::MLS_GOVERNANCE_BINDING_STALE.to_owned()),
        );

        for refusal in [mismatch, binding_stale] {
            assert!(!note_e2ee_submit_refusal_in_store(
                &mut store,
                REALM,
                None,
                &station_problem(refusal),
            ));
        }
        assert!(store.stale_mls_coverage_scopes(REALM).is_empty());

        assert!(note_e2ee_submit_refusal_in_store(
            &mut store,
            REALM,
            None,
            &station_problem(pending),
        ));
        assert_eq!(store.stale_mls_coverage_scopes(REALM), vec![None]);
    }

    #[test]
    fn circle_scopes_are_tracked_as_their_own_repairs() {
        let mut store = temp_store("scopes");
        store
            .record_mls_coverage_stale(REALM, None, "realm-default")
            .unwrap();
        store
            .record_mls_coverage_stale(
                REALM,
                Some("ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
                "circle",
            )
            .unwrap();
        // Keyed by effective scope, but each record still names its Realm so
        // the Realm's MLS effect can find the Circle group it has to repair.
        let mut scopes = store.stale_mls_coverage_scopes(REALM);
        scopes.sort();
        assert_eq!(
            scopes,
            vec![
                None,
                Some("ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned())
            ]
        );
        assert!(
            store
                .stale_mls_coverage_scopes("ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo")
                .is_empty()
        );
    }

    #[test]
    fn clearing_is_scoped_and_idempotent() {
        let mut store = temp_store("clear");
        store
            .record_mls_coverage_stale(REALM, None, "first")
            .unwrap();
        assert_eq!(
            store.mls_coverage_stale_reason(REALM, None).as_deref(),
            Some("first")
        );
        // Last writer wins so the stored message always names the governance
        // Seals the receiver is currently missing.
        store
            .record_mls_coverage_stale(REALM, None, "second")
            .unwrap();
        assert_eq!(
            store.mls_coverage_stale_reason(REALM, None).as_deref(),
            Some("second")
        );
        store.clear_mls_coverage_stale(REALM, None).unwrap();
        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert!(store.mls_coverage_stale_reason(REALM, None).is_none());
        // A Circle-scoped group is a separate MLS group with its own
        // accumulator; clearing the Realm-default scope must not touch it.
        store
            .record_mls_coverage_stale(
                REALM,
                Some("ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
                "circle",
            )
            .unwrap();
        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert_eq!(
            store
                .mls_coverage_stale_reason(
                    REALM,
                    Some("ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
                )
                .as_deref(),
            Some("circle")
        );
    }

    #[test]
    fn stale_marker_changes_the_bootstrap_dedup_hint() {
        let mut store = temp_store("dedup-hint");
        assert_eq!(mls_coverage_repair_dedup_hint(&store, REALM), "");

        store
            .record_mls_coverage_stale(REALM, None, "realm-default")
            .unwrap();
        assert_eq!(mls_coverage_repair_dedup_hint(&store, REALM), "realm");

        store
            .record_mls_coverage_stale(
                REALM,
                Some("ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"),
                "circle",
            )
            .unwrap();
        assert_eq!(
            mls_coverage_repair_dedup_hint(&store, REALM),
            "ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1,realm"
        );

        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert_eq!(
            mls_coverage_repair_dedup_hint(&store, REALM),
            "ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
        );
    }
}
