//! Invite create / accept / cancel builders.

use serde_json::json;

use super::OperationBuilder;

pub fn invite_create_structured(
    realm_id: &str,
    actor: &str,
    invitee: &str,
    role: Option<&str>,
    invite_delivery_target: arkret_sdk::InviteDeliveryTarget,
    introduction_evidence_digest: &str,
) -> anyhow::Result<OperationBuilder> {
    // Strong `invite_payload` (directed-create anyOf branch). The id /
    // digest strings are parsed into SDK newtypes so malformed wire is a
    // build-time error, and `x_role` is carried via the typed extension
    // map (re-prefixed on serialize).
    let invitee_did = arkret_sdk::Did::new(invitee.to_owned())
        .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
    let digest = arkret_sdk::Hash::new(introduction_evidence_digest.to_owned())
        .map_err(|err| anyhow::anyhow!("introduction_evidence_digest invalid: {err}"))?;
    let mut payload =
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            invitee_did,
            invite_delivery_target,
            digest,
            chrono::Utc::now() + chrono::Duration::days(7),
        );
    if let Some(role) = role {
        payload = payload
            .with_extension("role", json!(role))
            .map_err(|err| anyhow::anyhow!("invalid invite extension: {err}"))?;
    }
    let body = payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invite create payload: {err}"))?;
    Ok(OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::InviteCreate).body(body))
}

pub fn invite_accept(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
) -> anyhow::Result<OperationBuilder> {
    let invite_id_typed = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
    let payload = arkret_sdk::InviteAcceptPayload {
        invite_id: invite_id_typed,
        delivery_status: arkret_sdk::DeliveryStatus::Unroutable,
        delivery_binding: None,
        extensions: Default::default(),
    };
    payload.validate()?;
    let body = serde_json::to_value(payload)?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::InviteAccept)
            .target_ref(invite_id.to_string())
            .body(body),
    )
}

/// Build a `ak.invite.cancel` Control Move.
///
/// `target_state` is REQUIRED and restricted to `rejected` / `revoked` by
/// `event-envelope.schema.json`: the registered contract's
/// `transition_to` projection reads it as the signed target of the
/// `ak.component.invite.lifecycle.v1` FSM, so a cancel without it has no
/// derivable write. `rejected` is the invitee declining, `revoked` is the
/// inviter or an admin withdrawing.
pub fn invite_cancel(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee: &str,
    target_state: &str,
    reason: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    if !matches!(target_state, "rejected" | "revoked") {
        anyhow::bail!(
            "ak.invite.cancel target_state must be rejected or revoked, got {target_state:?}"
        );
    }
    let invite_id = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical: {err}"))?;
    let invite_id_ref = invite_id.to_string();
    let invitee = arkret_sdk::Did::new(invitee.to_owned())
        .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
    let target_state = match target_state {
        "rejected" => arkret_sdk::InviteCancelTargetState::Rejected,
        "revoked" => arkret_sdk::InviteCancelTargetState::Revoked,
        _ => unreachable!("validated invite cancel target state"),
    };
    let mut payload = arkret_sdk::InviteCancelPayload::new(invite_id, invitee, target_state);
    if let Some(reason) = reason {
        payload = payload.with_reason(reason);
    }
    let body = payload.to_value()?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::InviteCancel)
            .target_ref(invite_id_ref)
            .body(body),
    )
}

/// Build the high-risk `ak.invite.revoke` path used by token/3PID invites.
/// A directed invite may also use this path, but then its frozen invitee
/// binding must be supplied so the reducer can atomically close member.state.
pub fn invite_revoke(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee: Option<&str>,
    target_state: &str,
    reason_code: &str,
) -> anyhow::Result<OperationBuilder> {
    if !matches!(
        target_state,
        "revoked"
            | "expired"
            | "revoked_by_capability_loss"
            | "revoked_by_inviter_left"
            | "invalidated_by_rate_limit"
    ) {
        anyhow::bail!("ak.invite.revoke target_state is not terminal: {target_state:?}");
    }
    if reason_code.trim().is_empty() {
        anyhow::bail!("ak.invite.revoke reason_code is required");
    }
    let invite_id = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical: {err}"))?;
    let invite_id_ref = invite_id.to_string();
    let invitee = invitee
        .map(|value| arkret_sdk::Did::new(value.to_owned()))
        .transpose()
        .map_err(|err| anyhow::anyhow!("invitee is not a DID: {err}"))?;
    let target_state = match target_state {
        "revoked" => arkret_sdk::InviteRevokeTargetState::Revoked,
        "expired" => arkret_sdk::InviteRevokeTargetState::Expired,
        "revoked_by_capability_loss" => {
            arkret_sdk::InviteRevokeTargetState::RevokedByCapabilityLoss
        }
        "revoked_by_inviter_left" => arkret_sdk::InviteRevokeTargetState::RevokedByInviterLeft,
        "invalidated_by_rate_limit" => arkret_sdk::InviteRevokeTargetState::InvalidatedByRateLimit,
        _ => unreachable!("validated invite revoke target state"),
    };
    let payload = arkret_sdk::InviteRevokePayload {
        invite_id,
        invitee,
        target_state,
        reason: Some(reason_code.to_owned()),
    };
    let body = serde_json::to_value(payload)?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::InviteRevoke)
            .target_ref(invite_id_ref)
            .body(body),
    )
}
