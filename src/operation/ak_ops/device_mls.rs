//! Device revoke Control Move and MLS epoch builders.

use super::TypedOperationBuilder;

/// Durable `ak.device.revoke` Control Move on the principal control
/// stream (`crypto-media/device-lifecycle.md` §2.2, SPEC-SOL-003
/// resolution). `realm_id` MUST be the principal's control realm
/// (`arkret_sdk::auth::principal_control_realm_id`); the caller MUST
/// attach a `seal_basis` minted from the registered frontier sourcing
/// before building. The payload carries no frontier field — the
/// authorization basis is the envelope `seal_basis` and the effective
/// cutoff is the accepted Seal covering this Move.
///
/// `reason` must match the schema slug form `^[a-z][a-z0-9_]{0,63}$`
/// (e.g. `user_request`, `device_lost`).
pub fn device_revoke(
    realm_id: &str,
    actor: &str,
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
        TypedOperationBuilder::new::<arkret_sdk::event_spec::DeviceRevoke>(
            realm_id, actor, payload,
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
    let group_id = payload.mls_group_id().to_owned();
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MlsCommit>(
            realm_id,
            actor,
            payload.clone(),
        )
        .target_ref(group_id),
    )
}

/// `ak.mls.proposal` event for a durable MLS membership-change intent.
pub fn mls_proposal_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &arkret_sdk::MlsProposalPayload,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MlsProposal>(
            realm_id,
            actor,
            payload.clone(),
        )
        .target_ref(group_id.to_owned()),
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

/// `ak.mls.welcome` event carrying the durable Welcome claim envelope and
/// opaque Welcome ciphertext. As with the other closed MLS payloads, this
/// boundary accepts only the SDK wire type so schema changes fail at compile
/// time in consumers.
pub fn mls_welcome_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &arkret_sdk::MlsWelcomePayload,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MlsWelcome>(
            realm_id,
            actor,
            payload.clone(),
        )
        .target_ref(group_id.to_owned()),
    )
}
