//! Explicit two-handoff abandonment of a never-accepted provisional identity.

use crate::state::{
    PendingAccountHandoff, PendingIdentityAbandonment, PendingPrincipalRegistration,
};

fn grant_digest(grant: &str) -> anyhow::Result<arkret_sdk::Hash> {
    arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(grant.as_bytes()))
        .map_err(anyhow::Error::from)
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
    checkpoint: &PendingPrincipalRegistration,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<PendingIdentityAbandonment> {
    if checkpoint
        .identity_abandonment
        .as_ref()
        .is_some_and(|pending| pending.challenge.expires_at > chrono::Utc::now())
    {
        anyhow::bail!("identity abandonment challenge is already pending");
    }
    let grant = crate::identity::account_auth::load_account_handoff_grant()?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let digest = grant_digest(&grant)?;
    let request = arkret_sdk::IdentityAbandonmentChallengeRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        identity_creation_lease_id: checkpoint.lease_id.clone(),
        lease_fence: checkpoint.lease_fence,
        principal_id: arkret_sdk::project_full_id_to_core_id(&arkret_sdk::DidFullId::new(
            checkpoint.did.clone(),
        )?)?,
        did_version_id: checkpoint.version_id.clone(),
    };
    let challenge = account_client(handoff, dpop, grant)?
        .auth_issue_identity_abandonment_challenge(&request)
        .await?;
    if challenge.request_id != request.request_id
        || challenge.identity_creation_lease_id != checkpoint.lease_id
        || challenge.lease_fence != checkpoint.lease_fence
        || challenge.principal_id.as_str() != checkpoint.did
        || challenge.did_version_id != checkpoint.version_id
        || challenge.consequence_disclosure
            != arkret_sdk::IDENTITY_ABANDONMENT_CONSEQUENCE_DISCLOSURE
    {
        anyhow::bail!("identity abandonment challenge changed the frozen provisional identity");
    }
    Ok(PendingIdentityAbandonment {
        challenge,
        challenge_handoff_grant_digest: digest,
    })
}

pub async fn confirm(
    handoff: &PendingAccountHandoff,
    checkpoint: &PendingPrincipalRegistration,
    pending: &PendingIdentityAbandonment,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<arkret_sdk::IdentityAbandonmentOutcome> {
    let grant = crate::identity::account_auth::load_account_handoff_grant()?
        .ok_or_else(|| anyhow::anyhow!("fresh account handoff credential is unavailable"))?;
    if grant_digest(&grant)? == pending.challenge_handoff_grant_digest {
        anyhow::bail!("identity abandonment confirmation requires a fresh account handoff");
    }
    if pending.challenge.expires_at <= chrono::Utc::now() {
        anyhow::bail!("identity abandonment challenge expired; issue a new challenge");
    }
    let request = arkret_sdk::IdentityAbandonmentRequestBody {
        request_id: pending.challenge.request_id.clone(),
        challenge_id: pending.challenge.challenge_id.clone(),
        challenge: pending.challenge.challenge.clone(),
        identity_creation_lease_id: checkpoint.lease_id.clone(),
        lease_fence: checkpoint.lease_fence,
        principal_id: arkret_sdk::project_full_id_to_core_id(&arkret_sdk::DidFullId::new(
            checkpoint.did.clone(),
        )?)?,
        did_version_id: checkpoint.version_id.clone(),
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
