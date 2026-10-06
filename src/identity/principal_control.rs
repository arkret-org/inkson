//! Principal Control Realm authority boundary.

/// Authenticate the holder PCR's lifetime root reference before Event identity
/// is frozen. The principal-control closed allowlist excludes owner transfer
/// and authority reset (realm-and-space section 2.8.1), so its verified genesis
/// remains the root. This rule does not apply to ordinary collaboration Realms.
pub(crate) async fn current_root_authorization_ref(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    holder: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::EventId> {
    crate::transport::own_station_results::holder_pcr_root_ref(http, realm, holder).await
}

#[cfg(test)]
fn holder_root_from_verified_bundle(
    bundle: &arkret_sdk::RealmAuthorityBundle,
    realm: &arkret_sdk::RealmId,
    holder: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::EventId> {
    let genesis: arkret_sdk::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&bundle.genesis_event.payload)?)?;
    genesis.object.validate()?;
    anyhow::ensure!(
        &bundle.realm_id == realm
            && &bundle.genesis_event.realm_id == realm
            && genesis.object.purpose == arkret_sdk::RealmPurpose::PrincipalControl
            && bundle.genesis_event.actor_id == arkret_sdk::ActorId::account(holder.clone()),
        "verified authority does not bind the holder principal-control root"
    );
    Ok(bundle.genesis_event.event_id.clone())
}

pub(crate) async fn resolve_accepted<P: std::fmt::Display + ?Sized>(
    http: &arkret_sdk::http_client::Client,
    principal: &P,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let active = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("principal-control operation has no active account"))?;
    let principal = principal.to_string();
    let principal_id = if principal.starts_with("did:") {
        let did = arkret_sdk::Did::new(principal)?;
        arkret_sdk::project_did_to_core_id(&did)?
    } else {
        arkret_sdk::DidCoreId::new(principal)?
    };
    anyhow::ensure!(
        principal_id == active.authority.principal_id,
        "principal-control operation does not target the active account"
    );

    resolve_accepted_for_authority(http, &active.authority).await
}

/// Resolve an accepted PCR for an explicitly authenticated account authority.
///
/// Device-pairing completion uses this before the pending signer is promoted
/// into the process-wide active account scope. The authenticated Station
/// client and the exact handoff-bound AccountId are the authority at this
/// boundary; requiring an already-promoted local scope would invert the
/// device-lifecycle verification order.
pub(crate) async fn resolve_accepted_for_authority(
    http: &arkret_sdk::http_client::Client,
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let result =
        crate::transport::account::current_principal_for_authority(http, authority).await?;
    Ok(result.principal_control_realm_id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn holder_root_requires_principal_control_genesis_and_complete_account_binding() {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let holder = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let genesis = arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::PrincipalControl,
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_sdk::SecurityClass::HighAssurance,
            holder.station_id.clone(),
            arkret_sdk::JoinRule::Invite,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::Secret,
            Some(serde_json::from_value(json!({
                "descriptor_version": 1,
                "device_id": "ak:device:01904100-0000-7000-8000-000000000003",
                "device_public_key_did": "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
                "device_key_algorithm": arkret_sdk::FoundingDeviceKeyAlgorithm::Ed25519,
                "device_key_purpose": "event_signing_and_mls_identity",
                "hpke_key": "z6LSDeviceHpkeKey",
                "hpke_key_algorithm": arkret_sdk::FoundingDeviceHpkeKeyAlgorithm::X25519,
                "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                "founding_authorize_payload_digest": format!("sha256:{}", "b".repeat(64))
            })).unwrap()),
            Some(arkret_sdk::ResolutionCommitment {
                did: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
                method_history_head: format!("sha256:{}", "a".repeat(64)),
                version_id: "fixture-1".into(),
            }),
        )
        .unwrap();
        let (bundle, ..) = crate::test_support::committed_event::verified_realm_fixture_signed_by(
            &crate::test_support::committed_event::FixtureStation::did_web(),
            realm.clone(),
            json!({"object": genesis}),
            vec![],
            "alice.example",
            "ak:device:01904100-0000-7000-8000-000000000003",
        );
        assert_eq!(
            holder_root_from_verified_bundle(&bundle, &realm, &holder).unwrap(),
            bundle.genesis_event.event_id
        );
        let mut wrong_account = holder.clone();
        wrong_account.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(holder_root_from_verified_bundle(&bundle, &realm, &wrong_account).is_err());
        wrong_account = holder.clone();
        wrong_account.principal_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        assert!(holder_root_from_verified_bundle(&bundle, &realm, &wrong_account).is_err());
        let wrong_realm =
            arkret_sdk::RealmId::new("ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD")
                .unwrap();
        assert!(holder_root_from_verified_bundle(&bundle, &wrong_realm, &holder).is_err());
        let mut ordinary = bundle.clone();
        let mut payload = genesis;
        payload.purpose = arkret_sdk::RealmPurpose::Collaboration;
        payload.founding_device_descriptor = None;
        payload.initial_resolution = None;
        ordinary.genesis_event.payload =
            serde_json::from_value(json!({"object": payload})).unwrap();
        assert!(holder_root_from_verified_bundle(&ordinary, &realm, &holder).is_err());
    }
}
