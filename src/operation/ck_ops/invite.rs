//! Invite create / accept / cancel builders.

use serde_json::json;

use super::{OperationBuilder, invite_ref_payload_value};

pub fn invite_create_structured(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee: &str,
    role: Option<&str>,
    invite_delivery_target: cokret_sdk::InviteDeliveryTarget,
    introduction_evidence_digest: &str,
) -> anyhow::Result<OperationBuilder> {
    // Strong `invite_payload` (directed-create anyOf branch). The id /
    // digest strings are parsed into SDK newtypes so malformed wire is a
    // build-time error, and `x_role` is carried via the typed extension
    // map (re-prefixed on serialize).
    let invite_id_typed = cokret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
    let invitee_did = cokret_sdk::Did::new(invitee.to_owned())
        .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
    let digest = cokret_sdk::Hash::new(introduction_evidence_digest.to_owned())
        .map_err(|err| anyhow::anyhow!("introduction_evidence_digest invalid: {err}"))?;
    let mut payload = cokret_sdk::models::InviteCreatePayload::new(
        invite_id_typed,
        invitee_did,
        invite_delivery_target,
        digest,
        chrono::Utc::now() + chrono::Duration::days(7),
    );
    if let Some(role) = role {
        payload = payload.with_extension("role", json!(role));
    }
    let body = payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invite create payload: {err}"))?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.invite.create").body(body))
}

pub fn invite_accept(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
) -> anyhow::Result<OperationBuilder> {
    let body = invite_ref_payload_value(invite_id, None)?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.invite.accept")
        .target_ref(invite_id)
        .body(body))
}

pub fn invite_cancel(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    let body = invite_ref_payload_value(invite_id, reason)?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.invite.cancel")
        .target_ref(invite_id)
        .body(body))
}
