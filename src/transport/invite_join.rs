use crate::config::validate_server_url;
use crate::models::{RealmJoinCandidate, SubmitEventResult};
use crate::realm_helpers::select_join_candidate;

impl crate::transport::TransportClient {
    /// Accept an invite via `ak.invite.accept` event (spec-canonical).
    pub async fn accept_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        invite_token: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let mut event = crate::operation::ak_ops::invite_accept(realm_id, actor_id, invite_id)?
            .build_sdk_event("inkson")?;
        let resolved = crate::transport::directory::resolve_realm_with_invite_token(
            &self.sdk_http_client()?,
            realm_id,
            invite_token,
        )
        .await?;
        let candidate = select_join_candidate(
            &resolved,
            arkret_models_discovery::RealmJoinMethod::InviteAccept,
        )?;
        stamp_invite_join_seal_basis(&mut event, candidate)?;
        self.submit_built_event_via_join_candidate(candidate, &event)
            .await
    }

    async fn submit_built_event_via_join_candidate(
        &self,
        candidate: &RealmJoinCandidate,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        let Some(endpoint) = candidate
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return self.event_submitter()?.submit_sdk_event(event).await;
        };
        let endpoint_url = validate_server_url(endpoint)?;
        if endpoint_url == *self.base_url() {
            return self.event_submitter()?.submit_sdk_event(event).await;
        }
        reject_unauthenticated_remote_candidate()?;
        unreachable!("remote candidate rejection always fails closed")
    }
}

fn reject_unauthenticated_remote_candidate() -> anyhow::Result<()> {
    anyhow::bail!(
        "remote invite join requires authenticated Garth service-route evidence; bare candidate endpoints are not transport authority"
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn bare_remote_candidate_fails_closed() {
        let error = super::reject_unauthenticated_remote_candidate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authenticated Garth service-route")
        );
    }
}

/// Stamp an invite-to-join Control Move's `seal_basis` from the resolve-realm
/// join candidate.
///
/// The invitee is not yet a member, so it cannot read the membership-gated
/// Realm Seal view. The current basis is disclosed by resolve-realm and bound
/// to the invite instead.
fn stamp_invite_join_seal_basis(
    event: &mut arkret_sdk::Event,
    candidate: &RealmJoinCandidate,
) -> anyhow::Result<()> {
    // Only a reducer-input Event needs a CBA basis at all.
    if event.seal_basis.is_some()
        || event
            .kind
            .descriptor()
            .is_none_or(|descriptor| !descriptor.reducer_input)
    {
        return Ok(());
    }
    if event.seal_ref.is_some() {
        anyhow::bail!("invite join Control Move must use seal_basis, not seal_ref");
    }
    if candidate.seal_basis.leaves.is_empty() {
        anyhow::bail!("resolve_realm join candidate seal_basis has no leaves");
    }
    event.seal_basis = Some(candidate.seal_basis.clone());
    Ok(())
}
