//! Controller-side Agent PCR acceptance and Seal finalization for pairing.

use dioxus::prelude::{SyncSignal, WritableExt};

use crate::state::LocalStateStore;

pub(crate) fn controller_signer_device_id(
    controller_did: &arkret_sdk::Did,
    controller_authority: &arkret_sdk::AccountId,
    signer: &crate::event_signer::InksonEventSigner,
    signer_account_scope: Option<&crate::secure_key_store::ActiveDeviceSeedScope>,
) -> anyhow::Result<arkret_sdk::DeviceId> {
    let signer_binding_matches = match signer_account_scope {
        Some(scope) => scope.authority == *controller_authority,
        None => signer.signer_did() == controller_did.as_str(),
    };
    if !signer_binding_matches {
        anyhow::bail!(
            "active signer is not bound to controller {} (signer DID: {}, account authority: {:?})",
            controller_did,
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

fn agent_initial_seal_required(error: &anyhow::Error) -> bool {
    crate::api_error::is_realm_seal_frontier_pending_error(error)
}

fn has_agent_pcr_create(events: &[arkret_sdk::Event]) -> bool {
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

async fn submit_agent_pcr_seal(
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_did: &arkret_sdk::Did,
    device_id: &str,
    realm_id: &str,
    events: &[arkret_sdk::Event],
    predecessor: Option<&arkret_sdk::Seal>,
) -> anyhow::Result<arkret_sdk::Seal> {
    let hlc =
        crate::signing_stamp::issue_protocol_hlc(controller_did.as_str(), device_id, realm_id)?;
    let availability = match predecessor {
        Some(predecessor) => {
            let delta = crate::event_signer::pcr_successor_delta_digests(events, predecessor)?;
            Some(
                crate::event_signer::issue_pcr_successor_availability(
                    http,
                    &arkret_sdk::RealmId::new(realm_id.to_owned())?,
                    predecessor,
                    delta,
                )
                .await?,
            )
        }
        None => None,
    };
    let seal = signer
        .sign_agent_pcr_event_seal(
            controller_did,
            events,
            predecessor,
            availability.as_ref(),
            hlc,
        )
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
        anyhow::bail!("Station returned a mismatched Agent PCR Seal outcome");
    }
    Ok(seal)
}

async fn verify_and_pin_agent_pcr_checkpoint<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    http: &arkret_sdk::http_client::Client,
    state_store: S,
    signer: &crate::event_signer::InksonEventSigner,
    accepted_events: &[arkret_sdk::Event],
    seal: &arkret_sdk::Seal,
) -> anyhow::Result<()> {
    let target_basis = arkret_sdk::SealBasis {
        leaves: vec![seal.id.clone()],
    };
    let resolved = crate::mls::governance_acquisition::resolve_mls_governance_checkpoint_with_http(
        http,
        &seal.realm_id,
        &target_basis,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        resolved.seals.iter().any(|accepted| accepted == seal),
        "resolved Agent PCR governance closure omitted the byte-exact submitted Seal"
    );
    let has_pinned_checkpoint = state_store.with_read(|store| {
        store
            .trusted_mls_governance_checkpoint(seal.realm_id.as_str())
            .is_some()
    });
    let checkpoint = if !has_pinned_checkpoint && seal.predecessor_refs.is_empty() {
        // The generic Realm verifier applies the frozen Agent-DID notary
        // quorum. Agent PCR genesis is the registered exception: its accepted
        // delegation authorizes the controller's current device to sign the
        // first Seal. This client authored that exact Event and Seal, so verify
        // the resolved bytes against the local authority and recompute every
        // signed root before installing the initial checkpoint.
        anyhow::ensure!(
            resolved.seals.as_slice() == std::slice::from_ref(seal),
            "Agent PCR genesis checkpoint contains an unexpected Seal"
        );
        anyhow::ensure!(
            resolved.events.len() == accepted_events.len()
                && accepted_events
                    .iter()
                    .all(|event| resolved.events.iter().any(|candidate| {
                        crate::event_submit::accepted_event_preserves_authored_envelope(
                            candidate,
                            event,
                            arkret_sdk::DigestSuite::Sha256,
                        )
                        .unwrap_or(false)
                    })),
            "Agent PCR genesis checkpoint Events differ from locally accepted history"
        );
        let material =
            arkret_bootstrap::materialize_agent_pcr_control(&resolved.events, &|event| {
                crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
            })?;
        let covered = material
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let control_root =
            arkret_state::control_event_set_root(&covered, arkret_sdk::DigestSuite::Sha256)?;
        let completeness_root = arkret_state::control_event_completeness_root(
            &resolved
                .events
                .iter()
                .cloned()
                .map(|event| (event, arkret_sdk::DigestSuite::Sha256))
                .collect::<Vec<_>>(),
            &covered,
            arkret_sdk::DigestSuite::Sha256,
        )?;
        anyhow::ensure!(
            seal.covered_event_digests == material.covered_event_digests
                && seal.state_root == material.state_root
                && seal.control_event_set_root == control_root
                && seal.completeness_root == completeness_root,
            "Agent PCR genesis Seal roots differ from local reducer replay"
        );
        seal.validate_id(arkret_sdk::DigestSuite::Sha256)?;
        let arkret_sdk::NotarySig::Single(signature) = &seal.notary_signature else {
            anyhow::bail!("Agent PCR genesis Seal requires one controller-device signature");
        };
        let public_key = signer
            .public_key_base64url()
            .ok_or_else(|| anyhow::anyhow!("active controller public key is unavailable"))?;
        let descriptor = arkret_sdk::NotarySignerDescriptor {
            actor_id: material.controller_actor_id,
            verification_method: signature.verification_method.clone(),
            key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
                arkret_sdk::base64url_decode(&public_key)?,
            ))?,
            frozen_public_key_b64u: public_key,
        };
        descriptor.validate()?;
        arkret_signatures::verify_frozen_notary_signature(
            signature,
            &descriptor,
            &seal.canonical_bytes_for_id()?,
            arkret_sdk::DigestSuite::Sha256,
        )?;
        arkret_sdk::MlsGovernanceVerificationCheckpoint {
            realm_id: seal.realm_id.clone(),
            basis: resolved.target_basis,
            live_digest_suite: arkret_sdk::DigestSuite::Sha256,
            accepted_seals: resolved.seals,
            accepted_events: resolved.events,
            governance_dependencies: resolved.dependencies,
        }
    } else {
        let verifier_store = state_store.clone();
        arkret_sdk::verify_mls_governance_closure(
            &seal.realm_id,
            &resolved.target_basis,
            &resolved.seals,
            &resolved.events,
            &resolved.dependencies,
            move |event, digest_suite, evidence, dependencies| {
                crate::mls::governance_proof::verify_agent_history_key(
                    &verifier_store,
                    event,
                    digest_suite,
                    evidence,
                    dependencies,
                )
            },
        )
        .await?
        .checkpoint
    };
    state_store
        .with_write(|store| {
            store.advance_verified_mls_governance_checkpoint(seal.realm_id.as_str(), checkpoint)
        })
        .map_err(anyhow::Error::msg)
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Close all currently accepted Agent PCR Events into a Seal signed by
/// the active controller device. The accepted head returned by frontier can
/// lag the Event log and is the predecessor for the successor authored here.
pub(crate) async fn ensure_agent_pcr_seal_current<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    submitter: &crate::event_submit::EventSubmitter,
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_did: &arkret_sdk::Did,
    device_id: &str,
    agent_id: &arkret_sdk::ActorId,
    realm_id: &str,
    state_store: S,
    pending_genesis: Option<&arkret_sdk::Event>,
) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
    let current = submitter
        .seals_frontier_agent_head(realm_id, controller_did, state_store.clone())
        .await;
    if current
        .as_ref()
        .is_err_and(agent_seal_head_receipt_unavailable)
    {
        return Err(current.expect_err("checked managed PCR signed-head receipt error"));
    }
    let realm_id_typed = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let accepted_events = if current.as_ref().is_err_and(agent_initial_seal_required) {
        match pending_genesis {
            Some(genesis) => {
                anyhow::ensure!(
                    genesis.kind == arkret_sdk::EventKind::RealmCreate
                        && genesis.realm_id == realm_id_typed
                        && &genesis.actor_id == agent_id,
                    "pending Agent PCR genesis does not match the requested control Realm"
                );
                vec![genesis.clone()]
            }
            None => crate::event_signer::PrincipalControlHistory::load(
                http,
                agent_id,
                &realm_id_typed,
                "Agent PCR Seal materialization",
            )
            .await?
            .into_events(),
        }
    } else {
        crate::event_signer::PrincipalControlHistory::load(
            http,
            agent_id,
            &realm_id_typed,
            "Agent PCR Seal materialization",
        )
        .await?
        .into_events()
    };
    let material = arkret_bootstrap::materialize_agent_pcr_control(&accepted_events, &|event| {
        crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
    })
    .map_err(|error| anyhow::anyhow!("Agent PCR materialization failed: {error}"))?;

    let submitted = match current {
        Ok((view, head)) => {
            if head.covered_event_digests == material.covered_event_digests {
                if head.state_root != material.state_root {
                    anyhow::bail!("accepted Agent PCR Seal state differs from accepted Events");
                }
                return Ok((view, head));
            }
            Some(
                submit_agent_pcr_seal(
                    http,
                    signer,
                    controller_did,
                    device_id,
                    realm_id,
                    &accepted_events,
                    Some(&head),
                )
                .await?,
            )
        }
        Err(error) if agent_initial_seal_required(&error) => Some({
            // Re-publish the exact genesis before the first Seal. New
            // servers return the stored duplicate receipt; servers
            // upgraded from the pre-receipt managed-PCR path use this
            // idempotent retry to attach the first valid Control Proposal Ack
            // and rebuild the durable pending index that the atomic Seal
            // commit consumes.
            if pending_genesis.is_none() {
                let creates = accepted_events
                    .iter()
                    .filter(|event| {
                        event.kind == arkret_sdk::EventKind::RealmCreate
                            && event.realm_id.as_str() == realm_id
                    })
                    .collect::<Vec<_>>();
                let [create] = creates.as_slice() else {
                    anyhow::bail!(
                        "Agent PCR initial Seal requires exactly one accepted create Event"
                    );
                };
                let submission = crate::authorization_lease::standard_initial_submission(
                    http,
                    create,
                    arkret_sdk::DigestSuite::Sha256,
                )
                .await?;
                http.events_submit(&submission).await?;
            }
            submit_agent_pcr_seal(
                http,
                signer,
                controller_did,
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
    verify_and_pin_agent_pcr_checkpoint(
        http,
        state_store.clone(),
        signer,
        &accepted_events,
        &expected,
    )
    .await?;
    let view = submitter.seals_frontier_realm_view(realm_id).await?;
    if view.sole_leaf().ok() != Some(&expected.id)
        || expected.covered_event_digests != material.covered_event_digests
    {
        anyhow::bail!("accepted Agent PCR Seal differs from the submitted successor");
    }
    Ok((view, expected))
}

pub(crate) fn agent_seal_head_receipt_unavailable(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .contains("seals/frontier omitted the accepted Agent PCR Seal head")
}

/// Seal one newly accepted controller self-PCR Event with the active
/// controller device.  The server may durably admit the Control Move, but it
/// cannot manufacture the principal's notary signature; publication is not
/// authoritative until this successor Seal is accepted.
pub(crate) async fn seal_self_principal_event_current(
    api: &crate::transport::TransportClient,
    controller_did: &arkret_sdk::Did,
    realm_id: &arkret_sdk::RealmId,
    expected_event_id: &arkret_sdk::EventId,
) -> anyhow::Result<arkret_sdk::Seal> {
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let predecessor = submitter
        .seals_frontier_realm_head(realm_id.as_str())
        .await?;
    let controller_actor_id =
        crate::mls_api_helpers::local_account_actor_id(controller_did.as_str())?;
    let history = crate::event_signer::PrincipalControlHistory::load(
        &http,
        &controller_actor_id,
        realm_id,
        "controller self-PCR successor Seal construction",
    )
    .await?;
    if history.last().map(|event| &event.event_id) != Some(expected_event_id) {
        anyhow::bail!("accepted controller self-PCR Event is not the actor frontier");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let device_id = signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("active controller signer has no bound device id"))?;
    let hlc = crate::signing_stamp::issue_protocol_hlc(
        controller_did.as_str(),
        device_id,
        realm_id.as_str(),
    )?;
    let delta = crate::event_signer::pcr_successor_delta_digests(history.events(), &predecessor)?;
    let availability =
        crate::event_signer::issue_pcr_successor_availability(&http, realm_id, &predecessor, delta)
            .await?;
    let seal = signer
        .sign_self_principal_linear_successor_seal(&history, &predecessor, &availability, hlc)
        .map_err(|error| anyhow::anyhow!("sign controller self-PCR successor Seal: {error}"))?;
    let expected_digests = seal.delta.clone();
    let outcome = http.events_submit_seal(&seal).await?;
    if outcome.seal_id != seal.id
        || outcome.accepted_event_digests != expected_digests
        || outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Station returned a mismatched controller self-PCR Seal outcome");
    }
    Ok(seal)
}

/// Publish the controller-authored successor Seal required to turn durable
/// Agent-PCR Events into accepted authorization state.
pub(crate) async fn seal_agent_pcr_current(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    account: &crate::config::ActiveAccountContext,
    agent_id: &arkret_sdk::DidCoreId,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::Seal> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        account.did(),
        &account.authority,
        signer.as_ref(),
        signer_account_scope.as_ref(),
    )?;
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let agent_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        agent_id.clone(),
        account.authority.station_id.clone(),
    ));
    let (_, seal) = ensure_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        account.did(),
        device_id.as_str(),
        &agent_actor_id,
        realm_id.as_str(),
        state_store,
        None,
    )
    .await?;
    Ok(seal)
}

/// Seal the accepted Agent PCR before returning pairing material.
/// Agent active MLS state belongs to its runtime endpoint, never the controller
/// device. Pairing depends on accepted control authority, not an MLS snapshot.
pub(crate) async fn bootstrap_provisioned_agent(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    account: &crate::config::ActiveAccountContext,
    agent_id: &arkret_sdk::DidCoreId,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<()> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        account.did(),
        &account.authority,
        signer.as_ref(),
        signer_account_scope.as_ref(),
    )?;
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let agent_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        agent_id.clone(),
        account.authority.station_id.clone(),
    ));
    let accepted_events = crate::event_signer::PrincipalControlHistory::load(
        &http,
        &agent_actor_id,
        realm_id,
        "Agent PCR bootstrap",
    )
    .await?
    .into_events();
    let realm_id = realm_id.as_str();

    if !has_agent_pcr_create(&accepted_events) {
        anyhow::bail!(
            "Agent PCR genesis is not accepted; provisioning must submit the exact locally frozen create Event before recovery bootstrap"
        );
    }

    let (_, initial_frontier_seal) = ensure_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        account.did(),
        device_id.as_str(),
        &agent_actor_id,
        realm_id,
        state_store,
        None,
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

    // A fresh Agent runtime must generate its own endpoint key and initialize
    // or join its MLS group through the normal authenticated lifecycle. The
    // controller cannot publish a Genesis that disguises its leaf as the Agent.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn controller(did: &str) -> (arkret_sdk::Did, arkret_sdk::AccountId) {
        let did = arkret_sdk::Did::new(did.to_owned()).unwrap();
        let principal_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let server_id = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        (did, arkret_sdk::AccountId::new(principal_id, server_id))
    }

    fn scope(authority: arkret_sdk::AccountId) -> crate::secure_key_store::ActiveDeviceSeedScope {
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
    fn agent_initial_seal_accepts_missing_frontier_states() {
        assert!(agent_initial_seal_required(&api_error(404, "not_found")));
        assert!(agent_initial_seal_required(&api_error(
            503,
            "frontier_unavailable"
        )));
    }

    #[test]
    fn agent_initial_seal_does_not_hide_other_api_failures() {
        assert!(!agent_initial_seal_required(&api_error(
            503,
            "service_unavailable"
        )));
        assert!(!agent_initial_seal_required(&api_error(
            403,
            "capability_denied"
        )));
    }

    #[test]
    fn controller_signer_accepts_account_scoped_device_did_key() {
        let (controller_did, authority) = controller("did:web:alice.example");
        let account_scope = scope(authority.clone());
        let signer = crate::event_signer::build_ed25519_device_signer(
            [31_u8; 32],
            "did:key:z6MkhDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(&controller_did, &authority, &signer, Some(&account_scope),)
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

        let (controller_did, authority) = controller("did:web:alice.example");
        let (_, other_authority) = controller("did:web:bob.example");
        let account_scope = scope(other_authority);
        let error =
            controller_signer_device_id(&controller_did, &authority, &signer, Some(&account_scope))
                .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_rejects_controller_did_when_account_scope_differs() {
        let (controller_did, authority) = controller("did:web:alice.example");
        let (_, other_authority) = controller("did:web:bob.example");
        let account_scope = scope(other_authority);
        let signer = crate::event_signer::build_ed25519_device_signer(
            [34_u8; 32],
            controller_did.as_str(),
            TEST_DEVICE_ID,
        );

        let error =
            controller_signer_device_id(&controller_did, &authority, &signer, Some(&account_scope))
                .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_accepts_controller_identified_external_signer() {
        let (controller_did, authority) = controller("did:web:alice.example");
        let signer = crate::event_signer::build_ed25519_device_signer(
            [33_u8; 32],
            controller_did.as_str(),
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(&controller_did, &authority, &signer, None)
                .unwrap()
                .as_str(),
            TEST_DEVICE_ID,
        );
    }
}
