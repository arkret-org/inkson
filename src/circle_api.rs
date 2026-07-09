//! Free-function circle transport (E2 CokretApi strangler).
//!
//! The circle scope-list read and the scope-rotate event submission used to
//! live as inherent methods on [`crate::api::CokretApi`]. `list_circles` is a
//! pure passthrough over the shared SDK `http-client::Client`;
//! `submit_circle_scope_rotate_events` signs each rotate event through the
//! [`crate::event_submit::EventSubmitter`] proof/CBA path and posts the batch
//! through `submitter.http()`.

use crate::event_submit::EventSubmitter;
use crate::operation::uuid_v7;

pub async fn list_circles(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::CircleList> {
    http.circle_list(realm_id)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn submit_circle_scope_rotate_events(
    submitter: &EventSubmitter,
    circle_id: &str,
    events: &[arkret_sdk::Event],
    idempotency_key: Option<String>,
) -> anyhow::Result<arkret_sdk::CircleScopeRotateOutcome> {
    let circle_id = circle_id.trim();
    if circle_id.is_empty() {
        anyhow::bail!("circle_id is required for scope rotate");
    }
    let mut signed_events = Vec::with_capacity(events.len());
    let proof_context = submitter.event_proof_context().await?;
    for event in events {
        let mut signed = event.clone();
        submitter.stamp_cba_basis_for_sdk_event(&mut signed).await?;
        if signed.proofs.is_empty() {
            crate::event_signer::sign_sdk_event_with_active_context(
                &mut signed,
                proof_context.clone(),
            )
            .map_err(|err| {
                anyhow::anyhow!(
                    "no active signer configured \u{2014} cannot submit Circle scope rotate event: {err}"
                )
            })?;
        }
        signed_events.push(signed);
    }
    let idem = idempotency_key.unwrap_or_else(uuid_v7);
    let body = arkret_sdk::CircleScopeRotateRequestBody {
        events: signed_events,
        idempotency_key: Some(idem.clone()),
    };
    submitter
        .http()
        .circle_scope_rotate(circle_id, &idem, &body)
        .await
        .map_err(anyhow::Error::from)
}
