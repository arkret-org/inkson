//! Explicit two-handoff abandonment of a never-accepted provisional identity.

use crate::state::{PendingAccountHandoff, PendingIdentityAbandonment};

struct IdentityAbandonmentTarget {
    lease_id: String,
    lease_fence: u64,
    principal_id: arkret_sdk::DidCoreId,
    did_version_id: String,
}

fn target_from_handoff(
    handoff: &PendingAccountHandoff,
) -> anyhow::Result<IdentityAbandonmentTarget> {
    let reserved = handoff
        .reserved_identity
        .clone()
        .ok_or_else(|| anyhow::anyhow!("account handoff has no provisional identity to abandon"))?;
    let validated = arkret_sdk::signatures::webvh::validate_principal_inception_operation(
        &reserved.did_operation,
    )
    .map_err(|error| anyhow::anyhow!("reserved DID inception operation is invalid: {error}"))?;
    if validated.principal_id != reserved.principal_id
        || validated.operation_digest != reserved.operation_digest
    {
        anyhow::bail!("reserved DID operation digest or principal does not match its checkpoint");
    }
    Ok(IdentityAbandonmentTarget {
        lease_id: handoff
            .lease_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("account handoff has no identity-creation lease"))?,
        lease_fence: handoff.lease_fence.ok_or_else(|| {
            anyhow::anyhow!("account handoff has no identity-creation lease fence")
        })?,
        principal_id: reserved.principal_id,
        did_version_id: validated.did_version_id,
    })
}

pub fn has_fresh_confirmation_handoff(
    _handoff: &PendingAccountHandoff,
    pending: &PendingIdentityAbandonment,
) -> bool {
    let ready = !pending.requires_fresh_authentication;
    tracing::debug!(
        challenge_request_id = %pending.challenge.request_id,
        server_requires_fresh_authentication = pending.requires_fresh_authentication,
        challenge_expired = pending.challenge.expires_at <= chrono::Utc::now(),
        "evaluated identity-abandonment confirmation readiness"
    );
    ready
}

fn account_client(
    handoff: &PendingAccountHandoff,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
    grant: String,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    if handoff.holder_jkt != dpop.jkt() {
        anyhow::bail!("account handoff holder key changed during identity abandonment");
    }
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &handoff.gate_account_base,
    )?;
    Ok(arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(grant),
        ))
        .build()?)
}

pub async fn issue_challenge(
    handoff: &PendingAccountHandoff,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<PendingIdentityAbandonment> {
    if handoff
        .identity_abandonment
        .as_ref()
        .is_some_and(|pending| pending.challenge.expires_at > chrono::Utc::now())
    {
        anyhow::bail!("identity abandonment challenge is already pending");
    }
    let grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let target = target_from_handoff(handoff)?;
    let request = arkret_sdk::IdentityAbandonmentChallengeRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        identity_creation_lease_id: target.lease_id,
        lease_fence: target.lease_fence,
        principal_id: target.principal_id,
        did_version_id: target.did_version_id,
    };
    let challenge = account_client(handoff, dpop, grant)?
        .auth_issue_identity_abandonment_challenge(&request)
        .await?;
    if challenge.request_id != request.request_id
        || challenge.identity_creation_lease_id != request.identity_creation_lease_id
        || challenge.lease_fence != request.lease_fence
        || challenge.principal_id != request.principal_id
        || challenge.did_version_id != request.did_version_id
        || challenge.consequence_disclosure
            != arkret_sdk::IDENTITY_ABANDONMENT_CONSEQUENCE_DISCLOSURE
    {
        anyhow::bail!("identity abandonment challenge changed the frozen provisional identity");
    }
    tracing::info!(
        handoff_request_id = %handoff.request_id,
        challenge_request_id = %challenge.request_id,
        challenge_expires_at = %challenge.expires_at,
        "persisting identity-abandonment challenge before fresh authentication"
    );
    Ok(PendingIdentityAbandonment {
        challenge,
        requires_fresh_authentication: true,
    })
}

pub async fn confirm(
    handoff: &PendingAccountHandoff,
    pending: &PendingIdentityAbandonment,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<arkret_sdk::IdentityAbandonmentOutcome> {
    let grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?;
    tracing::info!(
        handoff_request_id = %handoff.request_id,
        challenge_request_id = %pending.challenge.request_id,
        handoff_grant_present = grant.is_some(),
        challenge_expired = pending.challenge.expires_at <= chrono::Utc::now(),
        "validating identity-abandonment confirmation state"
    );
    let grant =
        grant.ok_or_else(|| anyhow::anyhow!("fresh account handoff credential is unavailable"))?;
    tracing::info!(
        handoff_request_id = %handoff.request_id,
        challenge_request_id = %pending.challenge.request_id,
        server_requires_fresh_authentication = pending.requires_fresh_authentication,
        "using Account Authority abandonment freshness decision"
    );
    if pending.requires_fresh_authentication {
        anyhow::bail!("identity abandonment confirmation requires a fresh account handoff");
    }
    if pending.challenge.expires_at <= chrono::Utc::now() {
        anyhow::bail!("identity abandonment challenge expired; issue a new challenge");
    }
    let request = arkret_sdk::IdentityAbandonmentRequestBody {
        request_id: pending.challenge.request_id.clone(),
        challenge_id: pending.challenge.challenge_id.clone(),
        challenge: pending.challenge.challenge.clone(),
        identity_creation_lease_id: pending.challenge.identity_creation_lease_id.clone(),
        lease_fence: pending.challenge.lease_fence,
        principal_id: pending.challenge.principal_id.clone(),
        did_version_id: pending.challenge.did_version_id.clone(),
    };
    let outcome = account_client(handoff, dpop, grant)?
        .auth_abandon_identity_creation(&request)
        .await?;
    if outcome.request_id != request.request_id
        || outcome.principal_id != request.principal_id
        || outcome.did_version_id != request.did_version_id
        || outcome.status != arkret_sdk::IdentityAbandonmentStatus::Abandoned
    {
        anyhow::bail!("identity abandonment terminal does not match the frozen challenge");
    }
    Ok(outcome)
}
