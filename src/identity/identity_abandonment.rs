//! Explicit abandonment of a never-accepted provisional identity.

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
    let validated = arkret_sdk::identity::validate_principal_registration_anchor(
        &reserved.principal_registration_anchor,
    )
    .map_err(|error| anyhow::anyhow!("reserved registration anchor is invalid: {error}"))?;
    if validated.principal_id != reserved.principal_id
        || validated.registration_anchor_digest != reserved.registration_anchor_digest
    {
        anyhow::bail!(
            "reserved registration anchor digest or principal does not match its checkpoint"
        );
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

fn account_client(
    handoff: &PendingAccountHandoff,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
    grant: String,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    if handoff.holder_jkt != dpop.jkt() {
        anyhow::bail!("account handoff holder key changed during identity abandonment");
    }
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &handoff.gate_account_base_url,
    )?;
    Ok(arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(grant),
        ))
        .build()?)
}

/// Freeze the explicit local command before any network call. This is not
/// authorization evidence; the Account Authority checks fresh authentication.
pub fn prepare(handoff: &PendingAccountHandoff) -> anyhow::Result<PendingIdentityAbandonment> {
    let target = target_from_handoff(handoff)?;
    Ok(PendingIdentityAbandonment {
        request: arkret_sdk::IdentityAbandonmentRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            identity_creation_lease_id: target.lease_id,
            lease_fence: target.lease_fence,
            principal_id: target.principal_id,
            did_version_id: target.did_version_id,
        },
    })
}

pub async fn confirm(
    handoff: &PendingAccountHandoff,
    pending: &PendingIdentityAbandonment,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<arkret_sdk::IdentityAbandonmentOutcome> {
    let grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
        .ok_or_else(|| anyhow::anyhow!("fresh account handoff credential is unavailable"))?;
    let request = &pending.request;
    let target = target_from_handoff(handoff)?;
    if request.identity_creation_lease_id != target.lease_id
        || request.lease_fence != target.lease_fence
        || request.principal_id != target.principal_id
        || request.did_version_id != target.did_version_id
    {
        anyhow::bail!("abandonment target changed; review the current identity before confirming");
    }
    let outcome = account_client(handoff, dpop, grant)?
        .auth_abandon_identity_creation(request)
        .await?;
    if outcome.request_id != request.request_id
        || outcome.principal_id != request.principal_id
        || outcome.did_version_id != request.did_version_id
        || handoff.account_subject.as_ref() != Some(&outcome.account_subject)
    {
        anyhow::bail!("identity abandonment terminal does not match the frozen command");
    }
    Ok(outcome)
}
