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
    let (signed, _) = submitter.prepare_sdk_event_for_submit(&event).await?;
    let report_event =
        crate::authorization_lease::standard_initial_submission(submitter.http(), &signed).await?;
    let body = arkret_sdk::ModerationReportRequestBody { report_event };
    body.validate_authoring_context(
        &principal_id,
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
