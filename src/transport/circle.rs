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

/// Add or move a Circle member by submitting the caller-signed
/// `ak.circle.member.state`. Spec OpenAPI `ak.self.circle.member.command.add`.
pub async fn add_circle_member(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    target_actor: &str,
    membership: arkret_sdk::CircleMembership,
) -> anyhow::Result<arkret_sdk::CircleMembershipOutcome> {
    let event = crate::operation::ak_ops::circle_member_state(
        realm_id,
        actor,
        circle_id,
        target_actor,
        membership,
    )?
    .build_sdk_event("inkson")?;
    let body = arkret_sdk::CircleMemberRequestBody {
        member_event: arkret_wire::EventInitialSubmission::online(event),
    };
    http.circle_member_add(circle_id, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Archive a Circle by submitting the caller-signed `ak.circle.archive`.
pub async fn archive_circle(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<arkret_sdk::CircleView> {
    let body = arkret_sdk::CircleArchiveRequestBody {
        lifecycle_event: circle_lifecycle_submission(
            realm_id,
            actor,
            circle_id,
            arkret_sdk::EventKind::CircleArchive,
            reason,
        )?,
    };
    http.circle_archive(circle_id, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Restore an archived Circle by submitting the caller-signed `ak.circle.restore`.
pub async fn restore_circle(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<arkret_sdk::CircleView> {
    let body = arkret_sdk::CircleRestoreRequestBody {
        lifecycle_event: circle_lifecycle_submission(
            realm_id,
            actor,
            circle_id,
            arkret_sdk::EventKind::CircleRestore,
            reason,
        )?,
    };
    http.circle_restore(circle_id, &body)
        .await
        .map_err(anyhow::Error::from)
}

fn circle_lifecycle_submission(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    kind: arkret_sdk::EventKind,
    reason: Option<&str>,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let event =
        crate::operation::ak_ops::circle_lifecycle(realm_id, actor, circle_id, kind, reason)?
            .build_sdk_event("inkson")?;
    Ok(arkret_wire::EventInitialSubmission::online(event))
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
