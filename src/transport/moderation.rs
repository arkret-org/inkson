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
    let signed = submitter.author_for_direct_submission(&event).await?;
    let report_event = crate::authorization_lease::standard_initial_submission(
        submitter.http(),
        &signed,
        signed.digest_suite(),
    )
    .await?;
    let body = arkret_sdk::ModerationReportRequestBody { report_event };
    body.validate_authoring_context(
        &principal_id,
        &arkret_sdk::ModerationReportAcceptedTargetBasis {
            target_ref: target_ref.to_owned(),
            effective_scope,
        },
        signed.digest_suite(),
    )?;
    submitter
        .http()
        .moderation_report(&body, signed.digest_suite())
        .await
        .map_err(anyhow::Error::from)
}
