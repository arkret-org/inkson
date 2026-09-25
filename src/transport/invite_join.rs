use crate::models::SubmitEventResult;

/// What this account may see of one invited Realm before it accepts.
///
/// The preview is answered only by the Realm's verified current governance
/// Station, relayed by this account's own Station. It is never membership or
/// a join commitment: accepting stays a separate, explicit action.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum InvitePreviewOutcome {
    /// The governance Station disclosed these policy-permitted fields,
    /// verified under a nonce-bound assertion that is fresh until
    /// `fresh_until`.
    Disclosed {
        preview: arkret_sdk::RealmPublicPreview,
        fresh_until: chrono::DateTime<chrono::Utc>,
    },
    /// The governance Station discloses nothing to this account. Unknown,
    /// hidden and undisclosed targets share this one answer.
    Restricted,
}

/// The join target a directed invite names: its Realm, the invite and
/// exactly the untrusted locator hints its private delivery carried.
fn invite_join_target(
    realm_id: &str,
    invite_id: &str,
    credential: &crate::state::StoredInviteCredential,
) -> anyhow::Result<arkret_sdk::RealmJoinTarget> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    if credential.realm_id != realm {
        anyhow::bail!("invite credential belongs to another Realm");
    }
    Ok(arkret_sdk::RealmJoinTarget {
        realm_id: realm,
        invite_id: Some(arkret_sdk::InviteId::new(invite_id.to_owned())?),
        authority_locator_hints: credential.authority_locator_hints.clone(),
    })
}

/// Key of one cached preview answer: the exact account and the digest of the
/// exact join target it was asked for. A different account, invite or hint
/// set never reuses another answer.
pub(crate) fn invite_preview_cache_key(
    account_id: &arkret_sdk::AccountId,
    target: &arkret_sdk::RealmJoinTarget,
) -> anyhow::Result<String> {
    let account = arkret_sdk::canonical::canonical_json_bytes(account_id)?;
    let target = arkret_sdk::canonical::canonical_json_bytes(target)?;
    Ok(format!(
        "{}:{}",
        arkret_sdk::canonical::sha256_hex(&account),
        arkret_sdk::canonical::sha256_hex(&target)
    ))
}

impl crate::transport::TransportClient {
    /// Load the pre-accept preview of a directed invite through this
    /// account's own Station. The SDK binds the answer to the request (echoed
    /// request id, requested Realm on both the bundle and the preview, and the
    /// governance tenure); the client additionally requires the nonce-bound
    /// current assertion to be unexpired, the only freshness rule.
    pub(crate) async fn preview_realm_invite(
        &self,
        realm_id: &str,
        invite_id: &str,
        credential: &crate::state::StoredInviteCredential,
    ) -> anyhow::Result<InvitePreviewOutcome> {
        let request = arkret_sdk::SelfRealmJoinPreviewRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms() as u64),
            target: invite_join_target(realm_id, invite_id, credential)?,
        };
        match self
            .sdk_http_client()?
            .self_realm_join_preview(&request)
            .await
        {
            Ok(outcome) => {
                if outcome.authority_bundle.current_assertion.expires_at <= crate::clock::now_utc()
                {
                    anyhow::bail!("Realm preview returned an expired authority assertion");
                }
                Ok(InvitePreviewOutcome::Disclosed {
                    preview: outcome.preview,
                    fresh_until: outcome.authority_bundle.current_assertion.expires_at,
                })
            }
            Err(arkret_sdk::http_client::Error::Api { status: 404, .. }) => {
                Ok(InvitePreviewOutcome::Restricted)
            }
            Err(error) => Err(error.into()),
        }
    }

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
        credential: Option<&crate::state::StoredInviteCredential>,
        invitee_account_id: Option<arkret_sdk::AccountId>,
    ) -> anyhow::Result<(SubmitEventResult, Option<String>)> {
        let account_id = invitee_account_id.ok_or_else(|| {
            anyhow::anyhow!("directed invite acceptance requires the current complete account")
        })?;
        let credential = credential.ok_or_else(|| anyhow::anyhow!("missing invite credential"))?;
        if account_id.principal_id.as_str() != actor_id {
            anyhow::bail!("invite acceptance actor differs from the accepting account");
        }
        let invite = arkret_sdk::InviteId::new(invite_id.to_owned())?;
        // The locator hints are the untrusted set the delivery carried; this
        // account's own Station resolves them to a verified nonce-bound
        // authority bundle. The client offers exactly those hints and never
        // substitutes an endpoint of its own choosing.
        let target = invite_join_target(realm_id, invite_id, credential)?;
        let request = arkret_sdk::SelfRealmJoinPrepareRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms() as u64),
            target,
            intent: arkret_sdk::RealmJoinIntent::InviteAccept { invite_id: invite },
        };
        // The SDK checks the request and binds the outcome to it: echoed
        // request id, requested Realm and its Realm stream head.
        let prepared = self
            .sdk_http_client()?
            .self_realm_join_prepare(&request)
            .await?;
        // The unexpired nonce-bound current assertion is the only freshness
        // rule; the client adds no bundle age or clock-skew window.
        if prepared.authority_bundle.current_assertion.expires_at <= crate::clock::now_utc() {
            anyhow::bail!("join preparation returned an expired authority assertion");
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
