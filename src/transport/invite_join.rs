use crate::models::SubmitEventResult;

impl crate::transport::TransportClient {
    /// Accept an invite via `ak.invite.accept` event (spec-canonical).
    ///
    /// Returns the submit result. The optional title remains empty because
    /// join authority no longer comes from a client-side Directory result.
    ///
    /// The join preparation (`ak.self.realm_join.command.prepare.v1`) no longer
    /// hands back a Station-authored unsigned Event: it returns the nonce-bound
    /// [`arkret_wire::RealmAuthorityBundle`] plus the Realm stream head. The
    /// bundle is the only admissible source of the current governance Station,
    /// so it is validated here and the acceptance fails closed when the chain
    /// or its freshness window does not hold. The Event itself is then authored
    /// locally and submitted through `ak.self.events.command.submit.v1` like any
    /// other Control Move.
    ///
    /// `invitee_account_id` is required for a directed invite, whose
    /// acceptance also releases the inviter Realm's live-target slot for that
    /// account and therefore needs the account the slot subject is derived
    /// from. A third-party invite stores no account and MUST omit it.
    pub async fn accept_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        invite_token: Option<&str>,
        invitee_account_id: Option<arkret_sdk::AccountId>,
    ) -> anyhow::Result<(SubmitEventResult, Option<String>)> {
        let account_id = invitee_account_id.ok_or_else(|| {
            anyhow::anyhow!("directed invite acceptance requires the current complete account")
        })?;
        let invite_token = invite_token
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| anyhow::anyhow!("missing invite credential"))?;
        if account_id.principal_id.as_str() != actor_id {
            anyhow::bail!("invite acceptance actor differs from the accepting account");
        }
        let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
        // The locator hint set is untrusted routing input. This account's own
        // Station is the one endpoint the client already authenticated, so it
        // is the single hint offered; the returned bundle decides who the
        // current governance Station actually is.
        let hint = arkret_sdk::RealmJoinCandidate {
            service_kind: arkret_sdk::RealmJoinCandidateServiceKind::Station,
            service_id: self.describe_cached().await?.service_id.clone(),
            endpoint_url: Some(self.base_url().to_string()),
            source: arkret_sdk::AuthorityLocatorSource::Invite,
        };
        let target = arkret_sdk::RealmJoinTarget {
            realm_id: realm.clone(),
            invite_id: Some(arkret_sdk::InviteId::new(invite_id.to_owned())?),
            invite_token: Some(invite_token.to_owned()),
            authority_locator_hints: vec![hint],
        };
        target.validate()?;
        let request = arkret_sdk::SelfRealmJoinPrepareRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms() as u64),
            target,
            intent: arkret_sdk::RealmJoinIntent::InviteAccept {
                invite_id: arkret_sdk::InviteId::new(invite_id.to_owned())?,
                invite_token: invite_token.to_owned(),
            },
        };
        let prepared = self
            .sdk_http_client()?
            .self_realm_join_prepare(&request)
            .await?;
        if prepared.request_id != request.request_id {
            anyhow::bail!("join preparation answered a different request");
        }
        prepared.authority_bundle.validate_shape()?;
        let now = crate::clock::now_utc();
        if prepared.authority_bundle.realm_id != realm
            || prepared.authority_bundle.bundle_issued_at > now
            || prepared.authority_bundle.current_assertion.expires_at <= now
        {
            anyhow::bail!("join preparation returned a stale or mismatched authority bundle");
        }
        if prepared.realm_stream_head != prepared.authority_bundle.realm_stream_head {
            anyhow::bail!("join preparation stream head contradicts the authority bundle");
        }
        let operation = crate::operation::ak_ops::invite_accept(
            realm_id,
            actor_id,
            invite_id,
            Some(account_id),
            arkret_sdk::InvitePreviousState::Pending,
        )?
        .build_sdk_event("inkson")?;
        let submit = self.event_submitter()?.submit_sdk_event(&operation).await?;
        Ok((submit, None))
    }
}
