//! Invite create / accept / cancel builders.

use serde_json::json;

use super::TypedOperationBuilder;

pub fn invite_create_structured(
    realm_id: &str,
    actor: &str,
    invitee_account_id: arkret_sdk::AccountId,
    role: Option<&str>,
    introduction_evidence_digest: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    // Strong `invite_payload` (directed-create anyOf branch). The id /
    // digest strings are parsed into SDK newtypes so malformed wire is a
    // build-time error, and `x_role` is carried via the typed extension
    // map (re-prefixed on serialize).
    let digest = arkret_sdk::Hash::new(introduction_evidence_digest.to_owned())
        .map_err(|err| anyhow::anyhow!("introduction_evidence_digest invalid: {err}"))?;
    let mut payload =
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            invitee_account_id,
            digest,
            chrono::Utc::now() + chrono::Duration::days(7),
        );
    if let Some(role) = role {
        payload = payload
            .with_extension("role", json!(role))
            .map_err(|err| anyhow::anyhow!("invalid invite extension: {err}"))?;
    }
    // governance-objects.md section 5.3: an invitee holds at most one live
    // Realm invite. The current governance Station evaluates that against its
    // own committed current state and refuses the loser of two concurrent
    // invites with `invite_live_target_occupied`; a producer Event carries no
    // precondition of its own.
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::InviteCreate,
    >(realm_id, actor, payload))
}

/// Build `ak.invite.accept`.
///
/// `invitee_account_id` is present exactly for a directed invite, where it is
/// the only signed source the live-target release write can derive its subject
/// from — the projection grammar cannot turn the envelope ActorId into an
/// AccountId. It MUST equal the accepting actor's own account and never widens
/// who may accept; a third-party invite omits it.
pub fn invite_accept(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee_account_id: Option<arkret_sdk::AccountId>,
) -> anyhow::Result<TypedOperationBuilder> {
    let invite_id_typed = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
    let payload = arkret_sdk::InviteAcceptPayload {
        invite_id: invite_id_typed,
        invitee_account_id,
        extensions: Default::default(),
    };
    payload.validate()?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::InviteAccept>(
            realm_id, actor, payload,
        )
        .target_ref(invite_id.to_string()),
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
///
/// `invitee` is the complete account the Invite stores, read back from the
/// signed `ak.invite.create` payload: it names the live-target slot the cancel
/// releases, and an invitee hosted at another Station occupies a different
/// slot than `(principal, this Station)` would (account-lifecycle.md §156).
pub fn invite_cancel(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    invitee: &arkret_sdk::AccountId,
    target_state: &str,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let (payload, invite_id_ref) = invite_cancel_payload(invite_id, invitee, target_state, reason)?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::InviteCancel>(
            realm_id, actor, payload,
        )
        .target_ref(invite_id_ref),
    )
}

fn invite_cancel_payload(
    invite_id: &str,
    invitee: &arkret_sdk::AccountId,
    target_state: &str,
    reason: Option<&str>,
) -> anyhow::Result<(arkret_sdk::InviteCancelPayload, String)> {
    if !matches!(target_state, "rejected" | "revoked") {
        anyhow::bail!(
            "ak.invite.cancel target_state must be rejected or revoked, got {target_state:?}"
        );
    }
    let invite_id = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical: {err}"))?;
    let invite_id_ref = invite_id.to_string();
    invitee
        .validate()
        .map_err(|err| anyhow::anyhow!("invitee account is not closed: {err}"))?;
    let target_state = match target_state {
        "rejected" => arkret_sdk::InviteCancelTargetState::Rejected,
        "revoked" => arkret_sdk::InviteCancelTargetState::Revoked,
        _ => unreachable!("validated invite cancel target state"),
    };
    let mut payload =
        arkret_sdk::InviteCancelPayload::new(invite_id, invitee.clone(), target_state);
    if let Some(reason) = reason {
        payload = payload.with_reason(reason);
    }
    Ok((payload, invite_id_ref))
}

/// [`invite_cancel`] for an author whose Station is supplied explicitly rather
/// than read from the ambient authoring slot. Conformance harnesses drive
/// several Stations from one process, so the ambient slot cannot describe
/// them; the invitee is still the complete account the Invite stores, which is
/// hosted wherever it is hosted and never at the author's Station by default.
pub fn invite_cancel_for_station(
    realm_id: &str,
    actor: &str,
    station_id: arkret_sdk::DidCoreId,
    invite_id: &str,
    invitee: &arkret_sdk::AccountId,
    target_state: &str,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let (payload, invite_id_ref) = invite_cancel_payload(invite_id, invitee, target_state, reason)?;
    Ok(
        TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::InviteCancel>(
            realm_id, actor, station_id, payload,
        )
        .target_ref(invite_id_ref),
    )
}

/// Build the high-risk `ak.invite.revoke` path used by token/3PID invites.
/// A directed invite may also use this path, but then its frozen invitee
/// binding must be supplied so the reducer can atomically close member.state.
pub fn invite_revoke(
    realm_id: &str,
    actor: &str,
    invite_id: &str,
    // The complete account the Invite stores, for the directed branch that
    // releases the live-target slot; `None` for a token / 3PID Invite.
    invitee: Option<&arkret_sdk::AccountId>,
    target_state: &str,
    reason_code: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    if !matches!(
        target_state,
        "revoked"
            | "expired"
            | "send_failed"
            | "revoked_by_capability_loss"
            | "revoked_by_inviter_left"
            | "invalidated_by_rate_limit"
    ) {
        anyhow::bail!("ak.invite.revoke target_state is not registered: {target_state:?}");
    }
    // `send_failed` keeps the invite inside the live set, so it releases no
    // live-target slot and the payload schema forbids `invitee_account_id`
    // there (governance-objects.md section 5.3).
    if target_state == "send_failed" && invitee.is_some() {
        anyhow::bail!("ak.invite.revoke send_failed must not carry an invitee_account_id");
    }
    if reason_code.trim().is_empty() {
        anyhow::bail!("ak.invite.revoke reason_code is required");
    }
    let invite_id = arkret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical: {err}"))?;
    let invite_id_ref = invite_id.to_string();
    let invitee_account_id = invitee
        .map(|account| {
            account
                .validate()
                .map(|()| account.clone())
                .map_err(|err| anyhow::anyhow!("invitee account is not closed: {err}"))
        })
        .transpose()?;
    let target_state = match target_state {
        "revoked" => arkret_sdk::InviteRevokeTargetState::Revoked,
        "expired" => arkret_sdk::InviteRevokeTargetState::Expired,
        "send_failed" => arkret_sdk::InviteRevokeTargetState::SendFailed,
        "revoked_by_capability_loss" => {
            arkret_sdk::InviteRevokeTargetState::RevokedByCapabilityLoss
        }
        "revoked_by_inviter_left" => arkret_sdk::InviteRevokeTargetState::RevokedByInviterLeft,
        "invalidated_by_rate_limit" => arkret_sdk::InviteRevokeTargetState::InvalidatedByRateLimit,
        _ => unreachable!("validated invite revoke target state"),
    };
    let payload = arkret_sdk::InviteRevokePayload {
        invite_id,
        invitee_account_id,
        target_state,
        reason: Some(reason_code.to_owned()),
    };
    payload.validate()?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::InviteRevoke>(
            realm_id, actor, payload,
        )
        .target_ref(invite_id_ref),
    )
}
