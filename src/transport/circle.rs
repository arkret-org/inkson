//! Typed Circle transport.
//!
//! The circle scope-list read and the scope-rotate event submission used to
//! live as inherent methods on [`crate::transport::TransportClient`]. `list_circles` is a
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
    let signed_events = submitter.prepare_sdk_events_batch(events.to_vec()).await?;
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
