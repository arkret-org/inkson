//! Creator-side MLS bootstrap for an encrypted Realm, made replayable.
//!
//! A Realm creator never receives a Welcome — the epoch-0 group is created
//! locally, its `ak.mls.genesis` is submitted by the creator, and the trusted
//! Seal anchor is pinned only after a governance proof bundle passes the full
//! `encryption-and-audit.md` §2.5.1.1 verification order. Until this module
//! existed, that whole sequence lived inline in the Realm-create wizard's
//! `spawn`, so a component unmount (the user clicking straight into the new
//! Realm), a transient network failure or a closed tab left the Realm with no
//! pinned anchor, no local snapshot and no genesis — and nothing ever retried.
//! Every later encrypted write then failed forever with
//! `MLS governance proof requires a locally trusted Seal anchor`.
//!
//! Spec position: §2.5.1.1 states that a bootstrapping client may use a
//! genesis/compaction Seal as its request anchor once trust is established by
//! "Realm create/join, a verified snapshot/compaction, or an equivalent
//! authenticated bootstrap package". Realm create is exactly the creator's
//! trust source here; nothing in the spec requires that step to complete inside
//! one attempt, and nothing forbids replaying it. This module therefore adds
//! liveness only: it introduces no new trust source, and the anchor is still
//! pinned exclusively by
//! [`fetch_verify_and_cache_proof`](crate::mls::governance_proof::fetch_verify_and_cache_proof)
//! after full verification.

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::state::LocalStateStore;

/// What a bootstrap attempt actually did. Empty when the Realm was already
/// fully bootstrapped (the common re-entry case).
#[derive(Default)]
pub(crate) struct CreatorMlsBootstrapOutcome {
    /// The epoch-0 snapshot, when this call created it. The Realm-create
    /// wizard uses it to seed the first `mls_history` backup series.
    pub(crate) fresh_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
}

/// Whether this client is the creator of an encrypted `realm_id` whose MLS
/// bootstrap is still incomplete.
///
/// Cheap and synchronous so UI effects can gate on it without spawning. The
/// creator check is what keeps the trust source inside §2.5.1.1's enumeration:
/// only the actor that created the Realm may treat its genesis Seal as an
/// already-trusted anchor. It mirrors the gate in
/// `group_events::ensure_creator_mls_snapshot_for_encrypted_scope`.
pub(crate) fn creator_mls_bootstrap_pending(
    store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
) -> bool {
    let state = store.load();
    let Some(projection) = crate::security_state::security_projection_for_scope_id(
        &state.realm_tree_projections,
        realm_id,
    ) else {
        return false;
    };
    if !crate::security_state::realm_projection_is_encrypted(projection)
        || !crate::mls::group_events::projected_realm_creator_matches_actor(
            &state.realm_tree_projections,
            projection,
            realm_id,
            actor_id,
        )
    {
        return false;
    }
    let Some(snapshot) = store.mls_snapshot_for(realm_id) else {
        return true;
    };
    !store.mls_genesis_emitted_for(realm_id)
        || store
            .mls_group_state_ref_for_effective_scope(
                realm_id,
                None,
                &snapshot.group_id,
                snapshot.epoch,
            )
            .is_err()
}

/// Refresh the accepted Seal view, acquire + verify + pin the governance
/// proof, create the epoch-0 creator group and submit `ak.mls.genesis`.
///
/// Idempotent and safe to re-enter: it returns early once a local snapshot and
/// an emitted genesis both exist, and a server-side duplicate genesis is
/// resolved to its accepted Event id rather than treated as an error.
pub(crate) async fn ensure_creator_realm_mls_genesis(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<CreatorMlsBootstrapOutcome, String> {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err("realm_id is required for creator MLS bootstrap".to_owned());
    }
    if !creator_mls_bootstrap_pending(&state_store.read(), realm_id, actor_id) {
        return Ok(CreatorMlsBootstrapOutcome::default());
    }

    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS governance proof frontier client: {error}"))?;
    // The authoritative frontier source is `ak.self.events.query.frontier`
    // (`client-sync.md` publishes none on the Realm delta). A freshly accepted
    // Realm may not be sealed yet, so poll briefly.
    let seal_view = wait_for_realm_seal_view(&submitter, realm_id)
        .await
        .map_err(|error| {
            format!("refreshing the accepted Seal view before MLS setup failed: {error}")
        })?;
    {
        let mut store = state_store.write();
        let mut view = store.seal_view_for_realm(realm_id);
        view.frontier = vec![seal_view.seal_id.to_string()];
        view.state_root = Some(seal_view.state_root.to_string());
        store.set_realm_seal_view(realm_id.to_owned(), view);
    }

    let request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        None,
        arkret_sdk::base64url_encode(realm_id.as_bytes()),
        0,
        0,
    )
    .map_err(|error| format!("preparing the MLS governance proof request failed: {error}"))?;
    let leaves =
        crate::mls::governance_proof::singleton_security_frontier_leaf(actor_id, device_id)?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof(api, state_store, &request, &leaves)
        .await
        .map_err(|error| {
            format!("verifying the accepted governance proof before MLS setup failed: {error}")
        })?;

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let fresh_summary = {
        let mut store = state_store.write();
        crate::mls::runtime::ensure_creator_mls_snapshot(
            &mut store,
            secure_store.as_ref(),
            realm_id,
            actor_id,
            device_id,
        )
        .map_err(|error| format!("MLS initial group setup failed: {}", error.user_message()))?
    };
    let fresh_snapshot = fresh_summary
        .as_ref()
        .and_then(|_| state_store.read().mls_snapshot_for(realm_id));
    // The interesting recovery case is "snapshot persisted, genesis never
    // accepted": `ensure_creator_mls_snapshot` short-circuits to `None` there,
    // and the genesis builder refuses to emit without epoch-0 material. Restore
    // that material from the stored epoch-0 snapshot — the same fallback the
    // direct-conversation and Agent PCR bootstraps use — so the submit is
    // actually retried instead of silently skipped.
    let summary = match fresh_summary {
        Some(summary) => Some(summary),
        None => crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
            &state_store.read(),
            secure_store.as_ref(),
            realm_id,
            actor_id,
            device_id,
        )
        .map_err(|error| {
            format!(
                "restoring the epoch-0 MLS summary failed: {}",
                error.user_message()
            )
        })?,
    };
    let genesis_event = {
        let mut store = state_store.write();
        if store.mls_genesis_emitted_for(realm_id) {
            None
        } else {
            crate::mls::group_events::build_creator_mls_genesis_event(
                &mut store,
                realm_id,
                actor_id,
                device_id,
                summary.as_ref(),
            )
            .map_err(|error| format!("building ak.mls.genesis event failed: {error}"))?
        }
    };

    if let Some(genesis_event) = genesis_event {
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
        let provisional_event_id = genesis_event.event_id.clone();
        let accepted = match submitter.submit_sdk_event(&genesis_event).await {
            Ok(_) => Ok(provisional_event_id),
            // A duplicate is success only after resolving the exact
            // already-accepted Event id: encrypted writes bind their
            // `group_state_ref` to it, so merely setting the emitted flag would
            // strand them without a resolvable group state.
            Err(error) if error.to_string().contains("mls_genesis_already_exists") => submitter
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
            Ok(accepted_event_id) => {
                state_store
                    .write()
                    .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &accepted_event_id);
            }
            Err(error) => {
                // The local snapshot and pinned anchor stay persisted, but the
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

    Ok(CreatorMlsBootstrapOutcome { fresh_snapshot })
}

/// Poll `ak.self.events.query.frontier` until the Realm has an accepted Seal.
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
        match submitter.events_frontier_realm_seal_view(realm_id).await {
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

    fn realm_projection(owner: &str, encryption_profile: &str) -> serde_json::Value {
        json!({
            "__kind": "realm",
            "owner": owner,
            "content_scheme": encryption_profile,
            "members_limited": false,
            "members": [{ "actor_id": owner, "membership": "join" }],
            "summary": {
                "title": "Realm",
                "encryption_profile": encryption_profile,
                "owner": owner,
            }
        })
    }

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000001";

    #[test]
    fn creator_of_an_encrypted_realm_without_local_mls_state_is_pending() {
        let mut store = temp_store("pending");
        store.save_realm_tree_projection(REALM, realm_projection(ACTOR, "mls_rfc9420"));
        assert!(creator_mls_bootstrap_pending(&store, REALM, ACTOR));
    }

    #[test]
    fn creator_is_recognized_from_the_projected_realm_create_when_no_owner_field_exists() {
        // Post-P1 realm projections carry no owner/created_by mirror; the
        // creator fact lives in the projected `ak.realm.create` event.
        let mut store = temp_store("create-event-source");
        store.save_realm_tree_projection(
            REALM,
            json!({
                "__kind": "realm",
                "content_scheme": "mls_rfc9420",
                "summary": { "title": "Realm", "encryption_profile": "mls_rfc9420" },
                "state": {
                    "events": [{
                        "kind": "ak.realm.create",
                        "payload": { "object": { "id": REALM, "created_by": ACTOR } }
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
            error: Box::new(arkret_sdk::ErrorEnvelope::new(
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
            &frontier_error(503, "frontier_unavailable"),
            19,
            20,
        ));
    }
}
