//! Invite create / accept / cancel builders.

use serde_json::json;

use super::{OperationBuilder, invite_ref_payload_value};

fn fsm_transition_effect(
    cell: String,
    from: serde_json::Value,
    to: serde_json::Value,
) -> anyhow::Result<arkret_sdk::Effect> {
    Ok(arkret_sdk::Effect {
        cell: arkret_sdk::CellRef::new(cell)
            .map_err(|error| anyhow::anyhow!("invalid invite effect cell: {error}"))?,
        op: arkret_sdk::LatticeOp {
            op_type: arkret_sdk::LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(from),
            to: Some(to),
            reason: None,
            issuer_seq: None,
        },
    })
}

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
    let effects = vec![
        fsm_transition_effect(
            format!("ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"),
            serde_json::Value::Null,
            json!("pending"),
        )?,
        fsm_transition_effect(
            format!("ak:cell:ak.component.member.state.v1:{invitee}"),
            json!("leave"),
            json!("invite"),
        )?,
    ];
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteCreate,
    )
    .body(body)
    .effects(effects))
}

pub fn invite_accept(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
) -> anyhow::Result<OperationBuilder> {
    let body = invite_ref_payload_value(invite_id, None)?;
    let effects = vec![
        fsm_transition_effect(
            format!("ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"),
            json!("pending"),
            json!("accepted"),
        )?,
        fsm_transition_effect(
            format!("ak:cell:ak.component.member.state.v1:{actor}"),
            json!("invite"),
            json!("join"),
        )?,
    ];
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteAccept,
    )
    .target_ref(invite_id)
    .body(body)
    .effects(effects))
}

pub fn invite_cancel(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    let body = invite_ref_payload_value(invite_id, reason)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::InviteCancel,
    )
    .target_ref(invite_id)
    .body(body))
}
