//! Controller-side Agent PCR bootstrap and managed recovery publication.

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::state::LocalStateStore;

pub(crate) fn controller_signer_device_id(
    controller_full_id: &arkret_sdk::DidFullId,
    controller_authority: &arkret_sdk::PrincipalAuthorityKey,
    signer: &crate::event_signer::InksonEventSigner,
    signer_account_scope: Option<&crate::secure_key_store::ActiveDeviceSeedScope>,
) -> anyhow::Result<arkret_sdk::DeviceId> {
    let signer_binding_matches = match signer_account_scope {
        Some(scope) => scope.authority == *controller_authority,
        None => signer.signer_did() == controller_full_id.as_str(),
    };
    if !signer_binding_matches {
        anyhow::bail!(
            "active signer is not bound to controller {} (signer DID: {}, account authority: {:?})",
            controller_full_id,
            signer.signer_did(),
            signer_account_scope.map(|scope| &scope.authority)
        );
    }
    let device_id = signer
        .device_id()
        .filter(|device| !device.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller device id is unavailable"))?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    if signer_account_scope.is_some_and(|scope| scope.device_id != device_id) {
        anyhow::bail!("active signer device does not match its account seed scope");
    }
    Ok(device_id)
}

fn managed_agent_initial_seal_required(error: &anyhow::Error) -> bool {
    crate::api_error::is_realm_seal_frontier_pending_error(error)
}

fn has_managed_agent_pcr_create(events: &[arkret_sdk::Event]) -> bool {
    events.iter().any(|event| {
        event.kind == arkret_sdk::EventKind::RealmCreate
            && event.executed_by.is_some()
            && event
                .payload
                .get("object")
                .and_then(|object| object.get("fields"))
                .and_then(|fields| fields.get("purpose"))
                .and_then(serde_json::Value::as_str)
                == Some(arkret_bootstrap::PRINCIPAL_CONTROL_PURPOSE)
    })
}

async fn submit_managed_agent_pcr_seal(
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_id: &arkret_sdk::DidFullId,
    device_id: &str,
    realm_id: &str,
    events: &[arkret_sdk::Event],
    predecessor: Option<&arkret_sdk::Seal>,
) -> anyhow::Result<arkret_sdk::Seal> {
    let hlc =
        crate::signing_stamp::issue_protocol_hlc(controller_id.as_str(), device_id, realm_id)?;
    let seal = signer
        .sign_managed_agent_pcr_event_seal(controller_id, events, predecessor, hlc)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    // `accepted_event_digests` is a set in `Seal.delta`'s normalization
    // (byte-wise ascending, unique), which is what makes this comparison
    // well-defined; reducer apply order is a different sequence.
    let expected_digests = seal.delta.clone();
    let outcome = http.events_submit_seal(&seal).await?;
    if outcome.seal_id != seal.id
        || outcome.accepted_event_digests != expected_digests
        || outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched managed Agent PCR Seal outcome");
    }
    Ok(seal)
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Close all currently accepted managed Agent PCR Events into a Seal signed by
/// the active controller device. The accepted head returned by frontier can
/// lag the Event log and is the predecessor for the successor authored here.
pub(crate) async fn ensure_managed_agent_pcr_seal_current<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    submitter: &crate::event_submit::EventSubmitter,
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_id: &arkret_sdk::DidFullId,
    device_id: &str,
    realm_id: &str,
    state_store: S,
) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
    let current = submitter
        .events_frontier_managed_agent_seal_head(realm_id, controller_id, state_store.clone())
        .await;
    if current
        .as_ref()
        .is_err_and(managed_agent_seal_head_receipt_unavailable)
    {
        return Err(current.expect_err("checked managed PCR signed-head receipt error"));
    }
    let accepted_events = submitter
        .backfill(realm_id)
        .await?
        .complete_events("managed Agent PCR Seal materialization")?;
    let material =
        arkret_bootstrap::materialize_managed_agent_pcr_control(&accepted_events, &|event| {
            crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
        })
        .map_err(|error| anyhow::anyhow!("managed Agent PCR materialization failed: {error}"))?;

    let submitted = match current {
        Ok((view, head)) => {
            if head.covered_event_digests == material.covered_event_digests {
                if head.state_root != material.state_root {
                    anyhow::bail!(
                        "accepted managed Agent PCR Seal state differs from accepted Events"
                    );
                }
                return Ok((view, head));
            }
            Some(
                submit_managed_agent_pcr_seal(
                    http,
                    signer,
                    controller_id,
                    device_id,
                    realm_id,
                    &accepted_events,
                    Some(&head),
                )
                .await?,
            )
        }
        Err(error) if managed_agent_initial_seal_required(&error) => Some({
            // Re-publish the exact genesis before the first Seal. New
            // servers return the stored duplicate receipt; servers
            // upgraded from the pre-receipt managed-PCR path use this
            // idempotent retry to attach the first valid Control Proposal Ack
            // and rebuild the durable pending index that the atomic Seal
            // commit consumes.
            let creates = accepted_events
                .iter()
                .filter(|event| {
                    event.kind == arkret_sdk::EventKind::RealmCreate
                        && event.realm_id.as_str() == realm_id
                })
                .collect::<Vec<_>>();
            let [create] = creates.as_slice() else {
                anyhow::bail!(
                    "managed Agent PCR initial Seal requires exactly one accepted create Event"
                );
            };
            let submission = crate::authorization_lease::standard_initial_submission(
                http,
                create,
                arkret_sdk::DigestSuite::Sha256,
            )
            .await?;
            http.events_submit(&submission).await?;
            submit_managed_agent_pcr_seal(
                http,
                signer,
                controller_id,
                device_id,
                realm_id,
                &accepted_events,
                None,
            )
            .await?
        }),
        Err(error) => return Err(error),
    };

    let expected = submitted.expect("managed PCR Seal submission branch always returns a Seal");
    let (view, head) = submitter
        .events_frontier_managed_agent_seal_head(realm_id, controller_id, state_store)
        .await?;
    if head.id != expected.id
        || head.state_root != expected.state_root
        || head.covered_event_digests != material.covered_event_digests
    {
        anyhow::bail!("accepted managed Agent PCR Seal differs from the submitted successor");
    }
    Ok((view, head))
}

pub(crate) fn managed_agent_seal_head_receipt_unavailable(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .contains("events/frontier omitted the accepted managed Agent PCR Seal head")
}

/// Seal one newly accepted controller self-PCR Event with the active
/// controller device.  The server may durably admit the Control Move, but it
/// cannot manufacture the principal's notary signature; publication is not
/// authoritative until this successor Seal is accepted.
pub(crate) async fn seal_self_principal_event_current(
    api: &crate::transport::TransportClient,
    controller_id: &arkret_sdk::DidFullId,
    realm_id: &arkret_sdk::RealmId,
    expected_event_id: &arkret_sdk::EventId,
) -> anyhow::Result<arkret_sdk::Seal> {
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let predecessor = submitter
        .events_frontier_realm_seal_head(realm_id.as_str())
        .await?;
    let controller_actor_id = arkret_sdk::project_full_id_to_core_id(controller_id)?;
    let mut accepted = submitter
        .backfill(realm_id.as_str())
        .await?
        .complete_events("controller self-PCR successor Seal construction")?
        .into_iter()
        .filter(|event| event.actor_id == controller_actor_id)
        .collect::<Vec<_>>();
    accepted.sort_by(|left, right| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    if accepted.last().map(|event| &event.event_id) != Some(expected_event_id) {
        anyhow::bail!("accepted controller self-PCR Event is not the actor frontier");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let device_id = signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("active controller signer has no bound device id"))?;
    let hlc = crate::signing_stamp::issue_protocol_hlc(
        controller_id.as_str(),
        device_id,
        realm_id.as_str(),
    )?;
    let seal = signer
        .sign_self_principal_linear_successor_seal(&accepted, &predecessor, hlc)
        .map_err(|error| anyhow::anyhow!("sign controller self-PCR successor Seal: {error}"))?;
    let expected_digests = seal.delta.clone();
    let outcome = http.events_submit_seal(&seal).await?;
    if outcome.seal_id != seal.id
        || outcome.accepted_event_digests != expected_digests
        || outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched controller self-PCR Seal outcome");
    }
    Ok(seal)
}

/// Publish the controller-authored successor Seal required to turn durable
/// managed Agent-PCR Events into accepted authorization state.
pub(crate) async fn seal_managed_agent_pcr_current(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::Seal> {
    let controller_id = state_store
        .read()
        .active_principal_id()
        .filter(|did| !did.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller DID is unavailable"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        account.full_id(),
        &account.authority,
        signer.as_ref(),
        signer_account_scope.as_ref(),
    )?;
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let (_, seal) = ensure_managed_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        account.full_id(),
        device_id.as_str(),
        realm_id.as_str(),
        state_store,
    )
    .await?;
    Ok(seal)
}

/// Complete the client-owned half of `agent_provision`: create the Agent PCR,
/// generate its epoch-0 MLS state locally, publish a controller-owned managed
/// recovery envelope, and select that envelope's series from the controller
/// PCR before returning pairing material to the UI.
pub(crate) async fn bootstrap_provisioned_agent(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    agent_id: &arkret_sdk::DidCoreId,
    realm_id: &arkret_sdk::RealmId,
    controller_authorization_ref: &str,
) -> anyhow::Result<()> {
    let controller_id = state_store
        .read()
        .active_principal_id()
        .filter(|did| !did.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller DID is unavailable"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        account.full_id(),
        &account.authority,
        signer.as_ref(),
        signer_account_scope.as_ref(),
    )?;
    let agent_id = agent_id.as_str();
    let realm_id = realm_id.as_str();
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;

    let accepted_events = submitter
        .backfill(realm_id)
        .await?
        .complete_events("managed Agent PCR bootstrap")?;
    if !has_managed_agent_pcr_create(&accepted_events) {
        anyhow::bail!(
            "managed Agent PCR genesis is not accepted; provisioning must submit the exact locally frozen create Event before recovery bootstrap"
        );
    }
    if !has_managed_agent_pcr_create(&accepted_events) {
        anyhow::bail!("Principal Server did not expose the accepted managed Agent PCR genesis");
    }

    let (_, initial_frontier_seal) = ensure_managed_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        account.full_id(),
        device_id.as_str(),
        realm_id,
        state_store,
    )
    .await?;
    state_store.write().set_realm_seal_view(
        realm_id.to_owned(),
        crate::state::LocalSealView {
            frontier: vec![initial_frontier_seal.id.to_string()],
            state_root: Some(initial_frontier_seal.state_root.to_string()),
            ..Default::default()
        },
    );

    let group_id = arkret_sdk::base64url_encode(realm_id.as_bytes());
    let leaves = crate::mls::governance_proof::singleton_security_frontier_leaf(
        agent_id,
        device_id.as_str(),
    )
    .map_err(anyhow::Error::msg)?;
    let proof_request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        None,
        group_id,
        0,
        0,
        leaves.clone(),
    )
    .map_err(anyhow::Error::msg)?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof_bundle(
        api,
        state_store,
        &proof_request,
        &leaves,
    )
    .await
    .map_err(anyhow::Error::msg)?;

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let existing_genesis = submitter.find_mls_genesis_event_id(realm_id).await?;
    let frontier = if let Some(event_id) = existing_genesis {
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
            .map_err(anyhow::Error::msg)?;
        if state_store.read().mls_snapshot_for(realm_id).is_none() {
            anyhow::bail!(
                "Agent PCR MLS genesis exists, but this controller device has no local private group state"
            );
        }
        ensure_managed_agent_pcr_seal_current(
            &submitter,
            &http,
            signer.as_ref(),
            account.full_id(),
            device_id.as_str(),
            realm_id,
            state_store,
        )
        .await?
        .1
    } else {
        let summary = {
            let mut store = state_store.write();
            match crate::mls::runtime::ensure_creator_mls_snapshot(
                &mut store,
                secure_store.as_ref(),
                realm_id,
                &account.authority,
                &device_id,
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?
            {
                Some(summary) => summary,
                None => crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
                    &store,
                    secure_store.as_ref(),
                    realm_id,
                    &account.authority,
                    &device_id,
                )
                .map_err(|error| anyhow::anyhow!(error.user_message()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Agent PCR has no recoverable epoch-0 MLS state for genesis retry"
                    )
                })?,
            }
        };
        let genesis = {
            let mut store = state_store.write();
            crate::mls::group_events::build_creator_mls_genesis_event(
                &mut store,
                realm_id,
                agent_id,
                Some(&summary),
            )
            .map_err(anyhow::Error::msg)?
        }
        .ok_or_else(|| anyhow::anyhow!("Agent PCR MLS genesis was not built"))?;
        let genesis = genesis
            .with_executed_by(account.authority.principal_id.clone())
            .with_authorization_ref(
                arkret_sdk::AuthorizationRef::new(controller_authorization_ref.to_owned())
                    .map_err(anyhow::Error::msg)?,
            );
        crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
            .await
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
        match submitter.submit_sdk_event(&genesis).await {
            // The accepted id is the only one the encrypted writes may bind to.
            Ok(accepted) => state_store
                .write()
                .mark_mls_genesis_emitted_with_event(
                    realm_id.to_owned(),
                    &arkret_sdk::EventId::new(accepted.event_id.clone())
                        .map_err(anyhow::Error::msg)?,
                )
                .map_err(anyhow::Error::msg)?,
            Err(error)
                if crate::ephemeral::events_submit_rejected_for_reason(
                    &error,
                    &arkret_sdk::ReasonCode::MlsGenesisAlreadyExists,
                ) =>
            {
                let event_id = submitter
                    .find_mls_genesis_event_id(realm_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Agent PCR reports duplicate MLS genesis but exposes no accepted genesis"
                        )
                    })?;
                state_store
                    .write()
                    .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
                    .map_err(anyhow::Error::msg)?;
            }
            Err(error) => return Err(error),
        }
        let (_, frontier) = ensure_managed_agent_pcr_seal_current(
            &submitter,
            &http,
            signer.as_ref(),
            account.full_id(),
            device_id.as_str(),
            realm_id,
            state_store,
        )
        .await?;
        frontier
    };
    state_store.write().set_realm_seal_view(
        realm_id.to_owned(),
        crate::state::LocalSealView {
            frontier: vec![frontier.id.to_string()],
            state_root: Some(frontier.state_root.to_string()),
            ..Default::default()
        },
    );
    if state_store.read().mls_snapshot_for(realm_id).is_none() {
        anyhow::bail!("Agent PCR MLS snapshot was not persisted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn controller(full_id: &str) -> (arkret_sdk::DidFullId, arkret_sdk::PrincipalAuthorityKey) {
        let full_id = arkret_sdk::DidFullId::new(full_id.to_owned()).unwrap();
        let principal_id = arkret_sdk::project_full_id_to_core_id(&full_id).unwrap();
        let server_id = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        (
            full_id,
            arkret_sdk::PrincipalAuthorityKey::new(principal_id, server_id),
        )
    }

    fn scope(
        authority: arkret_sdk::PrincipalAuthorityKey,
    ) -> crate::secure_key_store::ActiveDeviceSeedScope {
        crate::secure_key_store::ActiveDeviceSeedScope {
            authority,
            device_id: arkret_sdk::DeviceId::new(TEST_DEVICE_ID).unwrap(),
        }
    }

    fn api_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_wire::ErrorEnvelope::new(code, "test error")),
        })
    }

    #[test]
    fn managed_agent_initial_seal_accepts_missing_frontier_states() {
        assert!(managed_agent_initial_seal_required(&api_error(
            404,
            "not_found"
        )));
        assert!(managed_agent_initial_seal_required(&api_error(
            503,
            "frontier_unavailable"
        )));
    }

    #[test]
    fn managed_agent_initial_seal_does_not_hide_other_api_failures() {
        assert!(!managed_agent_initial_seal_required(&api_error(
            503,
            "service_unavailable"
        )));
        assert!(!managed_agent_initial_seal_required(&api_error(
            403,
            "capability_denied"
        )));
    }

    #[test]
    fn controller_signer_accepts_account_scoped_device_did_key() {
        let (controller_id, authority) = controller("did:web:alice.example");
        let account_scope = scope(authority.clone());
        let signer = crate::event_signer::build_ed25519_device_signer(
            [31_u8; 32],
            "did:key:z6MkhDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(&controller_id, &authority, &signer, Some(&account_scope),)
                .unwrap()
                .as_str(),
            TEST_DEVICE_ID,
        );
    }

    #[test]
    fn controller_signer_rejects_device_key_from_another_account_scope() {
        let signer = crate::event_signer::build_ed25519_device_signer(
            [32_u8; 32],
            "did:key:z6MkhOtherDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        let (controller_id, authority) = controller("did:web:alice.example");
        let (_, other_authority) = controller("did:web:bob.example");
        let account_scope = scope(other_authority);
        let error =
            controller_signer_device_id(&controller_id, &authority, &signer, Some(&account_scope))
                .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_rejects_controller_did_when_account_scope_differs() {
        let (controller_id, authority) = controller("did:web:alice.example");
        let (_, other_authority) = controller("did:web:bob.example");
        let account_scope = scope(other_authority);
        let signer = crate::event_signer::build_ed25519_device_signer(
            [34_u8; 32],
            controller_id.as_str(),
            TEST_DEVICE_ID,
        );

        let error =
            controller_signer_device_id(&controller_id, &authority, &signer, Some(&account_scope))
                .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_accepts_controller_identified_external_signer() {
        let (controller_id, authority) = controller("did:web:alice.example");
        let signer = crate::event_signer::build_ed25519_device_signer(
            [33_u8; 32],
            controller_id.as_str(),
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(&controller_id, &authority, &signer, None)
                .unwrap()
                .as_str(),
            TEST_DEVICE_ID,
        );
    }
}
