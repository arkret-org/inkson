//! `encryption-and-audit.md` §2.4.1 / §2.5.2 — recover a scope from
//! `epoch_update_required` by advancing the MLS epoch.
//!
//! §2.5.2 gates every E2EE application ordinary Event on the accepted MLS Security
//! Frontier. Membership or key-access control changes require an accepted
//! `ak.mls.commit` whose governance binding projects the new control state and
//! active leaf set. §2.4.1 makes the sender MUST pause until that happens.
//!
//! Endpoint authorization and policy updates do not advance key-access revision.
//! The trigger is a receiver's typed refusal, rather than a moving stream head.
//! Only the receiver can decide that coverage is actually missing,
//! and it says so with `failed_precondition` / `epoch_update_required`. A
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

/// Whether the scope's accepted MLS epoch still covers its current key-access
/// revision.
///
/// The scope's own current MLS group state publishes both numbers: a
/// `covered_key_access_revision` behind `current_key_access_revision` means a
/// membership or key-access change has landed that no accepted `ak.mls.commit`
/// covers yet, which is exactly the condition a receiver reports as
/// `epoch_update_required`. An undelivered current view answers nothing and
/// never schedules a repair on its own.
pub(crate) fn mls_key_access_coverage_is_stale(
    store: &LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
) -> bool {
    store
        .current_mls_group_for_scope(effective_scope)
        .is_some_and(|current| {
            current.covered_key_access_revision < current.current_key_access_revision
        })
}

/// Advance the MLS epoch so the scope's new commit covers its current
/// key-access revision, restoring encrypted sending.
///
/// Returns `Ok(true)` when a commit was accepted and installed, `Ok(false)`
/// when nothing was pending. Idempotent: the stale marker is cleared only by an
/// accepted commit, and a still-insufficient epoch re-arms it from the next
/// refusal, so this never declares the repair finished on its own.
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
    if state_store.read(|store| {
        store
            .mls_coverage_stale_reason(realm_id, circle_id)
            .is_none()
            || store
                .mls_checkpoint_for_effective_scope(realm_id, circle_id)
                .is_none()
    }) {
        return Ok(false);
    }

    // Resume the original frozen unit before attempting another transition.
    // Pending OpenMLS state is not permission to overwrite it or claim anew.
    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS coverage repair client: {error}"))?
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

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let local_state = state_store.read(Clone::clone);
    let staged = crate::mls::runtime::force_epoch_rotation_commit_for_effective_scope(
        &local_state,
        secure_store.as_ref(),
        realm_id,
        circle_id,
        authority,
        device_id,
    )
    .map_err(|error| {
        format!(
            "building the MLS coverage repair commit failed: {}",
            error.user_message()
        )
    })?;
    let commit_event = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
        &local_state,
        realm_id,
        circle_id,
        actor_id,
        &staged.envelope,
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
