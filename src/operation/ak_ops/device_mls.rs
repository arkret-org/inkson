//! Device revoke Control Move and MLS epoch builders.

use super::TypedOperationBuilder;

/// Durable `ak.device.revoke` Control Move on the principal control
/// Realm (`crypto-media/device-lifecycle.md` §2.2). `realm_id` MUST be the
/// principal control Realm (`arkret_sdk::auth::principal_control_realm_id`).
/// The payload binds the exact current device authorization; revocation
/// becomes effective at the accepted RealmCommit.
///
/// `reason` must match the schema slug form `^[a-z][a-z0-9_]{0,63}$`
/// (e.g. `user_request`, `device_lost`).
pub fn device_revoke(
    realm_id: &str,
    account: &arkret_sdk::AccountId,
    target_device_id: &str,
    revoked_by_device_id: &str,
    reason: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::DeviceRevokePayload {
        device_id: arkret_sdk::DeviceId::new(target_device_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid target device id: {err}"))?,
        revoked_by: arkret_sdk::DeviceOrPrincipalRef::DeviceId(
            arkret_sdk::DeviceId::new(revoked_by_device_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid revoking device id: {err}"))?,
        ),
        revoked_at: crate::clock::now_utc_canonical(),
        reason: arkret_sdk::DeviceRevocationReason::new(reason.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid device revocation reason: {err}"))?,
        proof: None,
    };
    Ok(
        TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::DeviceRevoke>(
            realm_id,
            account.principal_id.as_str(),
            account.station_id.clone(),
            payload,
        )
        .target_ref(target_device_id),
    )
}

/// `ak.mls.commit` event carrying the current wire-schema MLS
/// governance binding. The event carries the complete Commit bytes plus the
/// schema-closed epoch and governance binding fields; an optional
/// content-addressed `commit_message_ref` is the only independent wire digest
/// carrier.
pub fn mls_commit_with_governance(
    realm_id: &str,
    actor: &str,
    payload: &arkret_sdk::MlsCommitPayload,
) -> anyhow::Result<TypedOperationBuilder> {
    let group_id = payload.mls_group_id()?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MlsCommit>(
            realm_id,
            actor,
            payload.clone(),
        )
        .target_ref(group_id.as_str()),
    )
}

/// `ak.mls.genesis` event installing an MLS group at epoch 0. Emitted
/// once when a creator's local group is first observed by the server so
/// the canonical audit record and creator Security Frontier binding exist and
/// the server epoch starts in lockstep with the local snapshot before
/// the first `ak.mls.commit` bumps it to 1.
///
/// `payload` uses the SDK's canonical wire type, so protocol field changes are
/// compile-time failures in consumers rather than late schema/server errors.
pub fn mls_genesis_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &arkret_sdk::MlsGenesisPayload,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MlsGenesis>(
            realm_id,
            actor,
            payload.clone(),
        )
        .target_ref(group_id.to_owned()),
    )
}

#[cfg(test)]
mod revoke_tests {
    use super::*;

    #[test]
    fn revoke_builder_binds_the_supplied_complete_account_and_core_id() {
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:QmPjVhccBPngemwoNXgqsXeCevJMbT18QGxYikYaeRzPig",
            )
            .unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:explicit-revoke-station.example").unwrap(),
        );
        let realm = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
        let target = "ak:device:01964137-0000-7000-8000-000000000022";
        let current = "ak:device:01964137-0000-7000-8000-000000000011";
        let operation = device_revoke(realm, &account, target, current, "user_request")
            .unwrap()
            .build_sdk_event(current)
            .unwrap();
        assert_eq!(operation.actor_id(), &arkret_sdk::ActorId::account(account));
        assert_eq!(operation.realm_id_opt().unwrap().as_str(), realm);
        let payload: arkret_sdk::DeviceRevokePayload =
            serde_json::from_value(operation.payload_value()).unwrap();
        assert_eq!(payload.device_id.as_str(), target);
    }
}
