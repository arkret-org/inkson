//! Typed Circle transport.
//!
//! Circle discovery and member/lifecycle commands share the typed SDK transport.
//! Exact-leaf scope rotation is authored by the reconciliation worker so its
//! frozen snapshot and session fences surround authoring and submission.

use crate::event_submit::EventSubmitter;

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
        member_event: arkret_wire::EventAdmissionSubmission {
            event: submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
            approval_signatures: None,
        },
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
        member_event: arkret_wire::EventAdmissionSubmission {
            event: submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
            approval_signatures: None,
        },
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
