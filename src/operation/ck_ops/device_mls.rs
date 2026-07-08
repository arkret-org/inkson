//! Device revoke Control Move and MLS epoch builders.

use serde_json::Value;

use super::OperationBuilder;

/// Durable `ck.device.revoke` Control Move on the principal control
/// stream (`crypto-media/device-lifecycle.md` §2.2, SPEC-SOL-003
/// resolution). `realm_id` MUST be the principal's control realm
/// (`cokret_sdk::auth::principal_control_realm_id`); the caller MUST
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
) -> anyhow::Result<OperationBuilder> {
    let payload = cokret_sdk::DeviceRevokePayload {
        principal_id: cokret_sdk::Did::new(actor.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid principal DID {actor:?}: {err}"))?,
        device_id: target_device_id.to_owned(),
        revoked_by: cokret_sdk::DeviceOrPrincipalRef::DeviceId(
            cokret_sdk::DeviceId::new(revoked_by_device_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid revoking device id: {err}"))?,
        ),
        revoked_at: crate::clock::now_utc_secs(),
        reason: reason.to_owned(),
        proof: None,
    };
    let body = serde_json::to_value(payload)
        .map_err(|err| anyhow::anyhow!("device_revoke_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::DeviceRevoke,
    )
    .target_ref(target_device_id)
    .body(body))
}

/// `ck.mls.commit` event carrying the current wire-schema MLS
/// governance binding. The commit bytes themselves are stored out of
/// band; the event carries `commit_digest` plus the schema-closed
/// epoch and governance binding fields soland validates before
/// projection.
pub fn mls_commit_with_governance(
    realm_id: &str,
    actor: &str,
    payload: &cokret_sdk::MlsCommitPayload,
) -> anyhow::Result<OperationBuilder> {
    let group_id = payload.mls_group_id().to_owned();
    let body = serde_json::to_value(payload)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MlsCommit,
    )
    .target_ref(group_id)
    .body(body))
}

/// `ck.mls.proposal` event for a durable MLS membership-change intent.
pub fn mls_proposal_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &cokret_sdk::MlsProposalPayload,
) -> anyhow::Result<OperationBuilder> {
    let body = serde_json::to_value(payload)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MlsProposal,
    )
    .target_ref(group_id.to_owned())
    .body(body))
}

/// `ck.mls.genesis` event installing an MLS group at epoch 0. Emitted
/// once when a creator's local group is first observed by the server so
/// the canonical audit record + creator/covered_seals seed exist and
/// the server epoch starts in lockstep with the local snapshot before
/// the first `ck.mls.commit` bumps it to 1.
///
/// `payload` is the full canonical `mls_genesis_payload` Value (see
/// [`crate::mls::runtime::build_mls_genesis_payload`]); `group_id` is the
/// genesis target ref.
pub fn mls_genesis_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MlsGenesis,
    )
    .target_ref(group_id.to_owned())
    .body(payload.clone())
}

/// `ck.mls.welcome` event carrying the durable Welcome claim envelope and
/// opaque Welcome ciphertext. The payload is passed as `Value` so callers can
/// build from the actual MLS runtime output while still validating against the
/// registered payload schema before submit.
pub fn mls_welcome_with_governance(
    realm_id: &str,
    actor: &str,
    group_id: &str,
    payload: &Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MlsWelcome,
    )
    .target_ref(group_id.to_owned())
    .body(payload.clone())
}
