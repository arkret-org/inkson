use crate::config::validate_server_url;
use crate::models::{RealmJoinCandidate, SubmitEventResult};
use crate::realm_helpers::select_join_candidate;

impl crate::transport::TransportClient {
    /// Accept an invite via `ak.invite.accept` event (spec-canonical).
    ///
    /// Returns the submit result together with the Realm title the directory
    /// resolve disclosed, so the caller can seed local title hints without a
    /// second lookup.
    pub async fn accept_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        invite_token: Option<&str>,
    ) -> anyhow::Result<(SubmitEventResult, Option<String>)> {
        let event = crate::operation::ak_ops::invite_accept(realm_id, actor_id, invite_id)?
            .build_sdk_event("inkson")?;
        let resolved = crate::transport::directory::resolve_realm_with_invite_token(
            &self.sdk_http_client()?,
            realm_id,
            invite_token,
        )
        .await
        .map_err(|error| invite_accept_resolve_error(error, invite_token.is_none()))?;
        let realm_title = resolved.realm_preview.title.clone();
        let candidate = select_join_candidate(
            &resolved,
            arkret_models_discovery::RealmJoinMethod::InviteAccept,
        )?;
        let event = stamp_invite_join_seal_basis(event, candidate)?;
        let submit = self
            .submit_built_event_via_join_candidate(candidate, &event)
            .await?;
        Ok((submit, realm_title))
    }

    async fn submit_built_event_via_join_candidate(
        &self,
        candidate: &RealmJoinCandidate,
        event: &crate::operation::LocalOperation,
    ) -> anyhow::Result<SubmitEventResult> {
        let Some(endpoint) = candidate
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return self
                .event_submitter()?
                .submit_sdk_event_via_join_candidate(
                    event,
                    &candidate.encryption_profile,
                    candidate.digest_algorithm,
                )
                .await;
        };
        let endpoint_url = validate_server_url(endpoint)?;
        if endpoint_url == *self.base_url() {
            return self
                .event_submitter()?
                .submit_sdk_event_via_join_candidate(
                    event,
                    &candidate.encryption_profile,
                    candidate.digest_algorithm,
                )
                .await;
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

/// A resolve-realm 404 with no credential to present means the Realm is not
/// publicly discoverable and the private delivery token never reached this
/// device: report the missing credential instead of a bare not-found so the
/// user can tell "invite token absent" apart from "realm gone". Any other
/// failure passes through unchanged.
fn invite_accept_resolve_error(error: anyhow::Error, invite_token_missing: bool) -> anyhow::Error {
    if invite_token_missing
        && crate::api_error::api_error_status_and_envelope(&error)
            .is_some_and(|(status, _)| status.as_u16() == 404)
    {
        return anyhow::anyhow!(
            "missing invite credential: the Realm is not publicly resolvable and no delivered invite token is available on this device ({error})"
        );
    }
    error
}

/// Stamp an invite-to-join Control Move's `seal_basis` from the resolve-realm
/// join candidate.
///
/// The invitee is not yet a member, so it cannot read the membership-gated
/// Realm Seal view. The current basis is disclosed by resolve-realm and bound
/// to the invite instead.
/// Pin the join candidate's Seal basis on the intent.
///
/// A pre-join invitee cannot read the membership-gated Realm Seal view, so this
/// is the one basis it will ever have — a producer decision, pinned before
/// authoring, that the authoring boundary then leaves alone.
fn stamp_invite_join_seal_basis(
    event: crate::operation::LocalOperation,
    candidate: &RealmJoinCandidate,
) -> anyhow::Result<crate::operation::LocalOperation> {
    // Only a reducer-input Event needs a CBA basis at all.
    if event.seal_basis().is_some()
        || event
            .kind()
            .descriptor()
            .is_none_or(|descriptor| !descriptor.reducer_input)
    {
        return Ok(event);
    }
    if event.seal_ref().is_some() {
        anyhow::bail!("invite join Control Move must use seal_basis, not seal_ref");
    }
    candidate.seal_basis.validate_protocol_bounds()?;
    Ok(event.with_seal_basis(candidate.seal_basis.clone()))
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

    fn resolve_api_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(code, code)),
        })
    }

    #[test]
    fn not_found_without_token_reports_missing_credential() {
        let error = super::invite_accept_resolve_error(resolve_api_error(404, "not_found"), true);
        assert!(error.to_string().contains("missing invite credential"));
    }

    #[test]
    fn not_found_with_token_passes_through() {
        let error = super::invite_accept_resolve_error(resolve_api_error(404, "not_found"), false);
        assert!(!error.to_string().contains("missing invite credential"));
    }

    #[test]
    fn other_failures_without_token_pass_through() {
        let error = super::invite_accept_resolve_error(resolve_api_error(403, "forbidden"), true);
        assert_eq!(
            error.to_string(),
            resolve_api_error(403, "forbidden").to_string()
        );
        let transport =
            super::invite_accept_resolve_error(anyhow::anyhow!("connection refused"), true);
        assert_eq!(transport.to_string(), "connection refused");
    }
}
