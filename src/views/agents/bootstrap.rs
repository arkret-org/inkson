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

fn is_agent_pcr_genesis(event: &arkret_sdk::Event) -> bool {
    event.kind == arkret_sdk::EventKind::RealmCreate
        && event.executed_by.is_some()
        && event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("agent_control")
}

async fn read_agent_pcr_genesis(
    http: &arkret_sdk::http_client::Client,
    agent_id: &arkret_sdk::ActorId,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::Event> {
    let page = http
        .events_read(&arkret_sdk::EventsQueryPostRequestBody {
            realm_ids: vec![realm_id.clone()],
            actor_ids: vec![agent_id.clone()],
            order: Some("ascending".to_owned()),
            limit: Some(1),
            ..Default::default()
        })
        .await?;
    let mut events = crate::models::require_complete_event_rows(&page.events, "Agent PCR genesis")?;
    let event = events
        .pop()
        .ok_or_else(|| anyhow::anyhow!("Agent PCR genesis is unavailable"))?;
    anyhow::ensure!(
        is_agent_pcr_genesis(&event) && &event.realm_id == realm_id && &event.actor_id == agent_id,
        "Agent PCR genesis result has the wrong binding"
    );
    Ok(event)
}

/// Seal bounded pending batches using the Account Station's validated input.
/// A known Event's final acceptance is checked by its operation caller.
pub(crate) async fn ensure_agent_pcr_seal_current(
    submitter: &crate::event_submit::EventSubmitter,
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_did: &arkret_sdk::Did,
    device_id: &str,
    agent_id: &arkret_sdk::ActorId,
    realm_id: &str,
    pending_genesis: Option<&arkret_sdk::Event>,
) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let authority = submitter.authority()?;
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(controller_did)? == authority.principal_id,
        "controller DID differs from the authenticated account"
    );
    let controller_actor = arkret_sdk::ActorId::account(authority.clone());
    let current = submitter.seals_frontier_agent_head(realm_id).await;
    let (mut view, mut head) = match current {
        Ok(current) => current,
        Err(error) if agent_initial_seal_required(&error) => {
            let genesis = match pending_genesis {
                Some(event) => event.clone(),
                None => read_agent_pcr_genesis(http, agent_id, &realm).await?,
            };
            anyhow::ensure!(
                is_agent_pcr_genesis(&genesis)
                    && genesis.realm_id == realm
                    && &genesis.actor_id == agent_id,
                "Agent PCR bootstrap differs from the requested Realm/actor"
            );
            let hlc = crate::signing_stamp::issue_protocol_hlc(
                controller_did.as_str(),
                device_id,
                realm_id,
            )?;
            let seal = signer.sign_agent_pcr_bootstrap_seal(controller_did, &[genesis], hlc)?;
            let outcome = http.events_submit_seal(&seal).await?;
            anyhow::ensure!(
                outcome.seal_id == seal.id
                    && outcome.post_state_root == seal.state_root
                    && outcome.accepted_event_digests == seal.delta,
                "Station returned a mismatched Agent PCR genesis Seal outcome"
            );
            let current = submitter.seals_frontier_agent_head(realm_id).await?;
            anyhow::ensure!(
                current.1 == seal,
                "accepted Agent PCR genesis differs from the signed body"
            );
            current
        }
        Err(error) => return Err(error),
    };
    for _ in 0..64 {
        let pending = http
            .pcr_pending_control(&arkret_sdk::PcrPendingControlRequestBody {
                realm_id: realm.clone(),
                predecessor_refs: view.seal_basis.leaves.clone(),
                limit: 1,
            })
            .await?;
        if pending.event_digests.is_empty() {
            return Ok((view, head));
        }
        let seal = crate::event_signer::prepare_and_sign_pcr_successor(
            http,
            &controller_actor,
            &realm,
            view.seal_basis.leaves.clone(),
            pending.event_digests,
        )
        .await?;
        let outcome = http.events_submit_seal(&seal).await?;
        anyhow::ensure!(
            outcome.seal_id == seal.id
                && outcome.post_state_root == seal.state_root
                && outcome.accepted_event_digests == seal.delta,
            "Station returned a mismatched Agent PCR successor Seal outcome"
        );
        (view, head) = submitter.seals_frontier_agent_head(realm_id).await?;
        anyhow::ensure!(
            head == seal,
            "Agent PCR frontier differs from the signed successor"
        );
    }
    anyhow::bail!(
        "Agent PCR still has pending work after the bounded signing pass; retry to continue"
    )
}

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
    let controller_authority = submitter.authority()?;
    if arkret_sdk::project_did_to_core_id(controller_did)? != controller_authority.principal_id {
        anyhow::bail!("controller DID does not belong to the authenticated account");
    }
    let controller_actor_id = arkret_sdk::ActorId::account(controller_authority.clone());
    let expected_digest = expected_event_id.event_digest();
    let seal = crate::event_signer::prepare_and_sign_pcr_successor(
        &http,
        &controller_actor_id,
        realm_id,
        vec![predecessor.id.clone()],
        vec![expected_digest.clone()],
    )
    .await?;
    if !seal.delta.contains(&expected_digest) {
        anyhow::bail!("controller self-PCR successor Seal does not cover the requested Event");
    }
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
    mut state_store: SyncSignal<LocalStateStore>,
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
        None,
    )
    .await?;
    state_store.write().set_realm_seal_view(
        realm_id.to_string(),
        crate::state::LocalSealView {
            frontier: vec![seal.id.to_string()],
            state_root: Some(seal.state_root.to_string()),
            ..Default::default()
        },
    );
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
    let realm_id = realm_id.as_str();

    let (_, initial_frontier_seal) = ensure_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        account.did(),
        device_id.as_str(),
        &agent_actor_id,
        realm_id,
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
            error: Box::new(arkret_wire::Problem::from_code(code, "test error")),
        })
    }

    fn delegated_create(payload: serde_json::Value) -> arkret_sdk::Event {
        let mut event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::RealmCreate.as_str(),
            arkret_sdk::ScopeRef::Realm {
                realm_id: crate::test_support::realm_id(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                ),
            },
            crate::test_support::core_id("ak:did_core:web:agent.example"),
            crate::test_support::core_id("ak:did_core:web:principal.example"),
            1,
            arkret_sdk::Hlc::new("000000000000-0000-00000000").unwrap(),
            payload,
        )
        .unwrap();
        event.executed_by = Some(crate::test_support::account_actor("did:web:alice.example"));
        event
    }

    #[test]
    fn agent_pcr_create_recognizes_current_genesis_purpose() {
        let event = delegated_create(serde_json::json!({
            "object": {"purpose": arkret_sdk::RealmPurpose::AgentControl}
        }));
        assert!(is_agent_pcr_genesis(&event));

        let mut undelegated = event.clone();
        undelegated.executed_by = None;
        assert!(!is_agent_pcr_genesis(&undelegated));

        let mut other_kind = event;
        other_kind.kind = arkret_sdk::EventKind::MessageCreate;
        assert!(!is_agent_pcr_genesis(&other_kind));
    }

    #[test]
    fn agent_pcr_create_rejects_self_pcr_and_legacy_payloads() {
        for object in [
            serde_json::json!({"purpose": arkret_sdk::RealmPurpose::PrincipalControl}),
            serde_json::json!({"fields": {"purpose": "principal_control"}}),
            serde_json::json!({"fields": {"purpose": "agent_control"}}),
            serde_json::json!({}),
        ] {
            assert!(!is_agent_pcr_genesis(&delegated_create(
                serde_json::json!({"object": object}),
            )));
        }
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
