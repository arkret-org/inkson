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
/// `ak.circle.member.state`. Spec OpenAPI `ak.self.circle.member.command.add.v1`.
pub async fn add_circle_member(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    target_actor: &arkret_sdk::ActorId,
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
        member_event: arkret_wire::EventInitialSubmission::online(
            submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
        ),
    };
    submitter
        .http()
        .circle_member_add(circle_id, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Remove an active Circle member with a caller-signed, CAS-guarded leave Event.
pub async fn remove_circle_member(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    target_actor: &arkret_sdk::ActorId,
) -> anyhow::Result<arkret_sdk::CircleMembershipOutcome> {
    let event = crate::operation::ak_ops::circle_member_state_with_expected(
        realm_id,
        actor,
        circle_id,
        target_actor,
        arkret_sdk::CircleMembership::Leave,
        arkret_wire::WirePresence::Value(arkret_sdk::CircleMembership::Join),
    )?
    .build_sdk_event("inkson")?;
    let body = arkret_sdk::CircleMemberDeleteRequestBody {
        member_event: arkret_wire::EventInitialSubmission::online(
            submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
        ),
    };
    submitter
        .http()
        .circle_member_remove(circle_id, target_actor, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Archive a Circle through the canonical Event submission surface.
pub async fn archive_circle(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<crate::models::SubmitEventResult> {
    let event = crate::operation::ak_ops::circle_lifecycle(
        realm_id,
        actor,
        circle_id,
        arkret_sdk::EventKind::CircleArchive,
        reason,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Restore an archived Circle through the canonical Event submission surface.
pub async fn restore_circle(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<crate::models::SubmitEventResult> {
    let event = crate::operation::ak_ops::circle_lifecycle(
        realm_id,
        actor,
        circle_id,
        arkret_sdk::EventKind::CircleRestore,
        reason,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

pub async fn submit_circle_scope_rotate_unit(
    submitter: &EventSubmitter,
    circle_id: &str,
    steps: Vec<crate::event_submit::EventUnitStep>,
    idempotency_key: Option<String>,
) -> anyhow::Result<(
    arkret_sdk::CircleScopeRotateOutcome,
    Vec<arkret_sdk::AuthoredEvent>,
)> {
    let circle_id = circle_id.trim();
    if circle_id.is_empty() {
        anyhow::bail!("circle_id is required for scope rotate");
    }
    let signed_events = submitter.author_event_unit(steps).await?;
    let idem = idempotency_key.unwrap_or_else(uuid_v7);
    let body = arkret_sdk::CircleScopeRotateRequestBody {
        events: signed_events
            .iter()
            .map(|event| event.event().clone())
            .collect(),
        idempotency_key: Some(idem.clone()),
    };
    // The authored Events travel back with the outcome: the caller needs the
    // Commit's FINAL id to record the group-state reference, and that id only
    // exists once the unit has been authored here.
    let outcome = submitter
        .http()
        .circle_scope_rotate(circle_id, &idem, &body)
        .await?;
    Ok((outcome, signed_events))
}
