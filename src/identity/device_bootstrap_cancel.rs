//! Recoverable cancellation of a founding device-bootstrap transaction.
//!
//! The transaction identity is read from the already-issued, DPoP-bound
//! bootstrap credential. The complete canonical cancel body is persisted in
//! the hardened store before the first request, then reused byte-for-byte for
//! every retry. Public onboarding checkpoints never contain this intent.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::identity::account_auth::grant_dpop::DpopHandle;
use crate::state::{
    PendingPrincipalRegistration, PendingPrincipalRegistrationStage, PersistedSessionGrant,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct FoundingCancelBinding {
    transaction_id: arkret_sdk::ProtocolOpaqueId,
    canonical_request_digest: arkret_sdk::Hash,
}

pub(crate) fn stage_can_cancel_device_bootstrap(stage: PendingPrincipalRegistrationStage) -> bool {
    matches!(
        stage,
        PendingPrincipalRegistrationStage::BootstrapGrantIssued
            | PendingPrincipalRegistrationStage::DeviceEnrolled
    )
}

pub(crate) fn cancel_outcome_is_terminal(
    outcome: &arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome,
) -> bool {
    cancel_terminal_outcome(outcome).is_some()
}

pub(crate) fn cancel_terminal_outcome(
    outcome: &arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome,
) -> Option<crate::state::PendingPrincipalBootstrapTerminal> {
    match outcome {
        arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome::Cancelled { .. } => {
            Some(crate::state::PendingPrincipalBootstrapTerminal::Cancelled)
        }
        arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome::Expired { .. } => {
            Some(crate::state::PendingPrincipalBootstrapTerminal::Expired)
        }
        arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome::Pending { .. } => None,
    }
}

fn signed_claims(grant_jwt: &str) -> anyhow::Result<arkret_sdk::SignedSessionGrantClaims> {
    let mut segments = grant_jwt.split('.');
    let _header = segments
        .next()
        .context("bootstrap grant JWT is missing its header")?;
    let payload = segments
        .next()
        .context("bootstrap grant JWT is missing its claims")?;
    let _signature = segments
        .next()
        .context("bootstrap grant JWT is missing its signature")?;
    if segments.next().is_some() {
        anyhow::bail!("bootstrap grant JWT must have exactly three segments");
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .context("bootstrap grant claims are not canonical base64url")?;
    let claims: arkret_sdk::SignedSessionGrantClaims =
        serde_json::from_slice(&payload).context("bootstrap grant claims are invalid")?;
    claims
        .validate()
        .context("bootstrap grant claims fail their closed contract")?;
    Ok(claims)
}

fn founding_cancel_binding(
    registration: &PendingPrincipalRegistration,
    grant: &PersistedSessionGrant,
    dpop: &DpopHandle,
) -> anyhow::Result<FoundingCancelBinding> {
    if !stage_can_cancel_device_bootstrap(registration.stage) {
        anyhow::bail!("the saved setup is not in a cancellable bootstrap stage");
    }
    let claims = signed_claims(&grant.grant_jwt)?;
    if claims.credential_class != arkret_sdk::SessionGrantCredentialClass::DeviceBootstrap
        || claims.grant_id.as_str() != grant.grant_id
        || claims.subject.as_str() != registration.did
        || claims.subject.as_str() != grant.principal_id
        || claims.audience.as_str() != grant.audience
        || grant.device_id != registration.device_id
        || claims.cnf.jkt != dpop.jkt()
    {
        anyhow::bail!("saved bootstrap grant does not match this setup and device");
    }

    let Some(arkret_sdk::SessionGrantBootstrapBinding::Founding {
        principal_id,
        device_id,
        transaction_id,
        holder_jkt,
        canonical_request_digest,
        founding_batch_digest,
        founding_event_ids,
        ..
    }) = claims.bootstrap_binding
    else {
        anyhow::bail!("only a founding bootstrap grant can cancel this setup");
    };

    let expected_founding_digest = registration
        .founding_batch_digest
        .as_deref()
        .context("saved setup has no founding batch digest")?;
    let expected_event_ids = registration
        .founding_event_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let claimed_event_ids = founding_event_ids
        .iter()
        .map(arkret_sdk::EventId::as_str)
        .collect::<Vec<_>>();
    if principal_id.as_str() != registration.did
        || device_id.as_str() != registration.device_id
        || holder_jkt != dpop.jkt()
        || founding_batch_digest.as_str() != expected_founding_digest
        || claimed_event_ids != expected_event_ids
    {
        anyhow::bail!("founding bootstrap binding does not match the durable setup checkpoint");
    }

    let bootstrap =
        crate::identity::principal_registration::device_bootstrap_request_from_checkpoint(
            registration,
        )?;
    let enroll_request = arkret_sdk::AccountDeviceEnrollRequestBody {
        device_id: arkret_sdk::DeviceId::new(registration.device_id.clone())?,
        authorize_event_preimage: bootstrap.authorize_event_preimage,
    };
    let expected_request_digest = enroll_request.canonical_request_digest()?;
    if canonical_request_digest != expected_request_digest {
        anyhow::bail!("bootstrap grant is bound to a different device-enroll request");
    }

    Ok(FoundingCancelBinding {
        transaction_id: arkret_sdk::ProtocolOpaqueId::new(transaction_id)
            .map_err(anyhow::Error::msg)?,
        canonical_request_digest,
    })
}

async fn prepare_or_restore_cancel(
    binding: &FoundingCancelBinding,
) -> anyhow::Result<garth::PreparedDeviceBootstrapCancel> {
    if let Some(prepared) = crate::identity::account_auth::load_prepared_bootstrap_cancel_request()?
    {
        if prepared.request().transaction_id != binding.transaction_id
            || prepared.request().canonical_request_digest != binding.canonical_request_digest
            || prepared.request().mode != arkret_sdk::contact_operations::BootstrapMode::Founding
        {
            anyhow::bail!("saved bootstrap cancel intent belongs to a different transaction");
        }
        return Ok(prepared);
    }

    let prepared = garth::PreparedDeviceBootstrapCancel::prepare(
        binding.transaction_id.clone(),
        binding.canonical_request_digest.clone(),
        arkret_sdk::IdempotencyKey::new(format!(
            "bootstrap-cancel-{}",
            crate::operation::uuid_v7()
        ))
        .map_err(anyhow::Error::msg)?,
    )?;
    crate::identity::account_auth::persist_prepared_bootstrap_cancel_request(&prepared).await?;
    Ok(prepared)
}

/// Cancel the transaction associated with the persisted founding grant.
///
/// This function deliberately performs no local cleanup. The caller may clear
/// transaction-bound material only after a validated `cancelled` or `expired`
/// outcome. A `pending` outcome, transport error, or accepted-race 409 keeps
/// both the prepared body and the onboarding checkpoint intact for recovery.
pub(crate) async fn cancel_pending_device_bootstrap(
    registration: &PendingPrincipalRegistration,
    grant: &PersistedSessionGrant,
    dpop: &DpopHandle,
) -> anyhow::Result<arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome> {
    let binding = founding_cancel_binding(registration, grant, dpop)?;
    let prepared = prepare_or_restore_cancel(&binding).await?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &registration.gate_account_base,
    )?;
    let client = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_dpop_auth_for_access_token(grant.grant_jwt.clone()),
        ))
        .build()?;
    garth::send_prepared_device_bootstrap_cancel(&client, &prepared)
        .await
        .map_err(Into::into)
}

use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pre_acceptance_network_stages_are_cancellable() {
        use PendingPrincipalRegistrationStage as Stage;
        assert!(!stage_can_cancel_device_bootstrap(Stage::CustodyConfirmed));
        assert!(!stage_can_cancel_device_bootstrap(Stage::BootstrapPrepared));
        assert!(stage_can_cancel_device_bootstrap(
            Stage::BootstrapGrantIssued
        ));
        assert!(stage_can_cancel_device_bootstrap(Stage::DeviceEnrolled));
        assert!(!stage_can_cancel_device_bootstrap(Stage::BatchAccepted));
        assert!(!stage_can_cancel_device_bootstrap(Stage::StandardPromoted));
    }

    #[test]
    fn pending_is_never_treated_as_terminal_cleanup_authority() {
        let transaction_id = arkret_sdk::ProtocolOpaqueId::new("bootstrap-fixture").unwrap();
        let placeholder = arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let pending = arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome::Pending {
            transaction_id: transaction_id.clone(),
            retryable_error:
                arkret_sdk::contact_operations::BootstrapRetryableError::DependencyPending,
            retry_after_ms: Some(10),
            outcome_digest: placeholder.clone(),
        };
        let cancelled = arkret_sdk::contact_operations::CancelDeviceBootstrapOutcome::Cancelled {
            transaction_id,
            outcome_digest: placeholder,
        };
        assert!(!cancel_outcome_is_terminal(&pending));
        assert!(cancel_outcome_is_terminal(&cancelled));
    }
}
