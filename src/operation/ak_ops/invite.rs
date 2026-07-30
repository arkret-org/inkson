//! Invite create / accept / cancel builders.

use serde_json::{Value, json};

use super::{OperationBuilder, invite_ref_payload_value};

pub fn invite_create_structured(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee: &str,
    role: Option<&str>,
    invite_delivery_target: arkret_sdk::InviteDeliveryTarget,
    introduction_evidence_digest: &str,
) -> anyhow::Result<OperationBuilder> {
    // Strong `invite_payload` (directed-create anyOf branch). The id /
    // digest strings are parsed into SDK newtypes so malformed wire is a
    // build-time error, and `x_role` is carried via the typed extension
    // map (re-prefixed on serialize).
    let invite_id_typed = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
    let invitee_did = arkret_sdk::Did::new(invitee.to_owned())
        .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
    let digest = arkret_sdk::Hash::new(introduction_evidence_digest.to_owned())
        .map_err(|err| anyhow::anyhow!("introduction_evidence_digest invalid: {err}"))?;
    let mut payload =
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            invite_id_typed,
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
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteCreate,
    )
    .body(body))
}

pub fn invite_accept(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
) -> anyhow::Result<OperationBuilder> {
    let body = invite_ref_payload_value(invite_id, None)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteAccept,
    )
    .target_ref(invite_id)
    .body(body))
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
    let mut body = invite_ref_payload_value(invite_id, reason)?;
    let invitee = arkret_sdk::Did::new(invitee.to_owned())
        .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
    body.as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invite ref payload is not an object"))?
        .extend([
            (
                "invitee".to_owned(),
                serde_json::Value::String(invitee.to_string()),
            ),
            (
                "target_state".to_owned(),
                serde_json::Value::String(target_state.to_owned()),
            ),
        ]);
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteCancel,
    )
    .target_ref(invite_id)
    .body(body))
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
    let mut body = invite_ref_payload_value(invite_id, None)?;
    let body = body
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invite ref payload is not an object"))?;
    body.insert(
        "target_state".to_owned(),
        serde_json::Value::String(target_state.to_owned()),
    );
    body.insert(
        "reason_code".to_owned(),
        serde_json::Value::String(reason_code.to_owned()),
    );
    if let Some(invitee) = invitee {
        let invitee = arkret_sdk::Did::new(invitee.to_owned())
            .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
        body.insert(
            "invitee".to_owned(),
            serde_json::Value::String(invitee.to_string()),
        );
    }
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteRevoke,
    )
    .target_ref(invite_id)
    .body(Value::Object(body.clone())))
}
