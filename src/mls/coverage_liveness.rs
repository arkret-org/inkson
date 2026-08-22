//! `encryption-and-audit.md` §2.4.1 / §2.5.2 — recover a scope from
//! `epoch_update_required` by advancing the MLS epoch.
//!
//! §2.5.2 gates every E2EE application DataEvent on the accepted MLS Security
//! Frontier. Membership or key-access control changes require an accepted
//! `ak.mls.commit` whose governance binding projects the new control state and
//! active leaf set. §2.4.1 makes the sender MUST pause until that happens.
//!
//! Every commit inkson emitted before this module was bound to a membership
//! frontier change (`sync_engine`'s Remove pass, `mls::admission`'s Add pass).
//! A capability grant, a policy update, or any other governance write outside
//! membership therefore left the scope paused with nothing to unpause it, and
//! a single-member creator group had no membership transition at all — the
//! Realm simply stopped accepting encrypted writes for the life of the
//! process.
//!
//! The trigger here is a receiver's own typed refusal, not a heuristic. That
//! matters: an accepted `ak.mls.commit` is itself a Control Move and lands in
//! a new Seal, so "the accepted Seal head moved since our last binding" is
//! true after every commit and would make the client emit one commit per Seal
//! forever. Only the receiver can decide that coverage is actually missing,
//! and it says so with `mls_governance_binding_stale`.
//!
//! Genesis replay lives in [`crate::mls::creator_bootstrap`]; this is the same
//! shape (idempotent, re-enterable, driven from the per-Realm MLS effect) for
//! the state after genesis.

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::state::LocalStateStore;

/// Record a receiver's governance-binding coverage refusal for the effective
/// scope that produced it. Returns `true` when the error was that refusal.
///
/// Call this from every E2EE application DataEvent send path: without it the
/// refusal is just another failed submit and the epoch never advances.
pub(crate) fn note_e2ee_submit_refusal(
    state_store: &mut SyncSignal<LocalStateStore>,
    realm_id: &str,
    circle_id: Option<&str>,
    error: &anyhow::Error,
) -> bool {
    if !crate::api_error::is_mls_governance_binding_stale_error(error) {
        return false;
    }
    if let Err(error) = state_store.write().record_mls_coverage_stale(
        realm_id.to_owned(),
        circle_id,
        &error.to_string(),
    ) {
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
                .mls_snapshot_for_effective_scope(realm_id, circle_id.as_deref())
                .is_some()
        })
        .collect()
}

/// Stable, non-secret fingerprint for the Realm bootstrap effect's dedup key.
///
/// Recording `mls_governance_binding_stale` mutates only the local state store;
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

/// Refresh the accepted Seal view, acquire + verify a governance proof for
/// `epoch → epoch + 1`, and submit the `ak.mls.commit` that attests the
/// governance Seals the scope is currently missing.
///
/// Returns `Ok(true)` when a commit was accepted, `Ok(false)` when nothing was
/// pending. Idempotent: the flag is cleared only by an accepted commit, and a
/// still-insufficient epoch re-arms it from the next refusal, so this can never
/// declare the repair finished on its own.
pub(crate) async fn ensure_mls_governance_coverage(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
) -> Result<bool, String> {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err("realm_id is required for MLS coverage repair".to_owned());
    }
    let circle_id = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    {
        let store = state_store.read();
        if store
            .mls_coverage_stale_reason(realm_id, circle_id)
            .is_none()
            || store
                .mls_snapshot_for_effective_scope(realm_id, circle_id)
                .is_none()
        {
            return Ok(false);
        }
    }

    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS coverage repair frontier client: {error}"))?;
    // The authoritative frontier source is `ak.self.events.read.frontier`
    // (`client-sync.md` §4/§5 publishes none on the Realm delta). Storing it
    // also evicts the cached governance proofs bound to the older head, which
    // is exactly what the next request must not reuse.
    let seal_view = crate::mls::creator_bootstrap::wait_for_realm_seal_view(&submitter, realm_id)
        .await
        .map_err(|error| {
            format!("refreshing the accepted Seal view before MLS coverage repair failed: {error}")
        })?;
    {
        let mut store = state_store.write();
        let mut view = store.seal_view_for_realm(realm_id);
        view.frontier = seal_view
            .seal_basis
            .leaves
            .iter()
            .map(ToString::to_string)
            .collect();
        // The frontier view carries no service-derived root hint; the local
        // post-state root is filled by verified Seal replay.
        view.state_root = None;
        store.set_realm_seal_view(realm_id.to_owned(), view);
    }

    let snapshot = state_store
        .read()
        .mls_snapshot_for_effective_scope(realm_id, circle_id)
        .ok_or_else(|| "MLS coverage repair requires a local group snapshot".to_owned())?;
    let leaves = crate::mls::governance_proof::current_security_frontier_leaves(
        &state_store.read(),
        realm_id,
        circle_id,
        actor_id,
        device_id,
    )?;
    let request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        circle_id,
        snapshot.group_id.clone(),
        snapshot.epoch,
        snapshot.epoch.saturating_add(1),
        leaves.clone(),
    )
    .map_err(|error| format!("preparing the MLS governance proof request failed: {error}"))?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof(api, state_store, &request, &leaves)
        .await
        .map_err(|error| {
            format!(
                "verifying the accepted governance proof before MLS coverage repair failed: {error}"
            )
        })?;

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (commit_envelope, next_snapshot, commit_event) = {
        let store = state_store.read();
        let (commit_envelope, next_snapshot, previous_governance_binding) =
            crate::mls::runtime::force_epoch_rotation_commit_for_effective_scope(
                &store,
                secure_store.as_ref(),
                realm_id,
                circle_id,
                actor_id,
                device_id,
            )
            .map_err(|error| {
                format!(
                    "building the MLS coverage repair commit failed: {}",
                    error.user_message()
                )
            })?;
        let commit_event =
            crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
                &store,
                realm_id,
                circle_id,
                actor_id,
                &commit_envelope,
                &previous_governance_binding,
            )
            .map_err(|error| format!("building ak.mls.commit event failed: {error}"))?;
        (commit_envelope, next_snapshot, commit_event)
    };

    // Persist-on-accept binds the group state to the Event the server admitted,
    // so its id is read from the receipt rather than from a pre-submit draft.
    let accepted = submitter
        .submit_sdk_event(&commit_event)
        .await
        .map_err(|error| format!("submitting the MLS coverage repair commit failed: {error}"))?;
    let commit_event_id = arkret_sdk::EventId::new(accepted.event_id.clone())
        .map_err(|error| format!("accepted MLS commit carries an invalid Event id: {error}"))?;

    // Persist-on-accept, identical to every other commit path: the local
    // snapshot only advances once the server admitted the epoch.
    {
        let mut store = state_store.write();
        store
            .record_mls_group_state_ref_for_effective_scope(
                realm_id.to_owned(),
                circle_id,
                next_snapshot.group_id.as_str(),
                next_snapshot.epoch,
                commit_event_id,
            )
            .map_err(|error| {
                format!("MLS coverage repair accepted but reference persistence failed: {error}")
            })?;
        store.save_mls_snapshot_for_effective_scope(
            realm_id.to_owned(),
            circle_id,
            next_snapshot,
        )?;
        store.clear_mls_coverage_stale(realm_id, circle_id)?;
    }
    tracing::info!(
        realm = %realm_id,
        circle = circle_id.unwrap_or("-"),
        epoch = commit_envelope.epoch,
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
            .record_mls_coverage_stale(REALM, None, "mls_governance_binding_stale: ...")
            .unwrap();
        // Still not repairable: without group material there is nothing to
        // commit from, and the creator bootstrap owns that step.
        assert!(pending_mls_coverage_repairs(&store, REALM).is_empty());
        assert_eq!(store.stale_mls_coverage_scopes(REALM), vec![None]);
    }

    #[test]
    fn circle_scopes_are_tracked_as_their_own_repairs() {
        let mut store = temp_store("scopes");
        store
            .record_mls_coverage_stale(REALM, None, "realm-default")
            .unwrap();
        store
            .record_mls_coverage_stale(REALM, Some("ak:circle:demo"), "circle")
            .unwrap();
        // Keyed by effective scope, but each record still names its Realm so
        // the Realm's MLS effect can find the Circle group it has to repair.
        let mut scopes = store.stale_mls_coverage_scopes(REALM);
        scopes.sort();
        assert_eq!(scopes, vec![None, Some("ak:circle:demo".to_owned())]);
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
            .record_mls_coverage_stale(REALM, Some("ak:circle:demo"), "circle")
            .unwrap();
        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert_eq!(
            store
                .mls_coverage_stale_reason(REALM, Some("ak:circle:demo"))
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
            .record_mls_coverage_stale(REALM, Some("ak:circle:demo"), "circle")
            .unwrap();
        assert_eq!(
            mls_coverage_repair_dedup_hint(&store, REALM),
            "ak:circle:demo,realm"
        );

        store.clear_mls_coverage_stale(REALM, None).unwrap();
        assert_eq!(
            mls_coverage_repair_dedup_hint(&store, REALM),
            "ak:circle:demo"
        );
    }
}
