//! Caller-signed self-service moderation report transport.

use crate::event_submit::EventSubmitter;

pub async fn report(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &str,
    effective_scope: arkret_sdk::ScopeRef,
    target_ref: &str,
    report_reason_code: &str,
    description: Option<&str>,
) -> anyhow::Result<arkret_sdk::ModerationReportOutcome> {
    let event = crate::operation::ak_ops::moderation_report(
        realm_id,
        actor,
        effective_scope.clone(),
        target_ref,
        report_reason_code,
        description,
    )?;
    let principal_id = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|error| anyhow::anyhow!("invalid moderation reporter DID: {error}"))?;
    let authority = submitter.authority()?;
    if principal_id != authority.principal_id {
        anyhow::bail!("moderation reporter does not belong to the authenticated account");
    }
    // The Station forwards this exact producer-signed Event through ordinary
    // Event admission, so the wire carrier is the single-Event commit
    // submission DTO rather than a report-specific envelope.
    let signed = submitter.author_for_direct_submission(&event).await?;
    let body = arkret_sdk::ModerationReportRequestBody {
        report_event: arkret_wire::EventAdmissionSubmission {
            event: signed.into_event(),
            approval_signatures: None,
        },
    };
    body.validate_authoring_context(
        authority,
        &arkret_sdk::ModerationReportAcceptedTargetBasis {
            target_ref: target_ref.to_owned(),
            effective_scope,
        },
    )?;
    submitter
        .http()
        .moderation_report(&body)
        .await
        .map_err(anyhow::Error::from)
}
