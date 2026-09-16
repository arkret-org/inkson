use crate::models::SubmitEventResult;

impl crate::transport::TransportClient {
    /// Accept an invite via `ak.invite.accept` event (spec-canonical).
    ///
    /// Returns the submit result. The optional title remains empty because
    /// join authority no longer comes from a client-side Directory result.
    ///
    /// `invitee_account_id` is required for a directed invite, whose
    /// acceptance also releases the inviter Realm's live-target slot for that
    /// account and therefore needs the account the slot subject is derived
    /// from. A third-party invite stores no account and MUST omit it, or the
    /// registered `stored_field_matches_payload` pre-state requirement rejects
    /// the Move (`governance-objects.md` section 5.3).
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
        let request = arkret_sdk::RealmJoinPrepareRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms() as u64),
            account_id,
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
            created_at: arkret_sdk::canonical::normalize_timestamp_canonical(
                crate::clock::now_utc(),
            ),
            hlc: None,
            intent: arkret_sdk::RealmJoinIntent::InviteAccept {
                invite_id: arkret_sdk::InviteId::new(invite_id.to_owned())?,
                invite_token: invite_token.to_owned(),
            },
        };
        let prepared = self
            .sdk_http_client()?
            .self_realm_join_prepare(&request)
            .await?;
        if prepared.expires_at <= crate::clock::now_utc() {
            anyhow::bail!("Realm join preparation expired before authoring")
        }
        if prepared
            .unsigned_event
            .actor_id
            .signing_principal_id()
            .as_str()
            != actor_id
        {
            anyhow::bail!("prepared join actor differs from current signer");
        }
        let submit = self
            .event_submitter()?
            .submit_prepared_join_event(&prepared)
            .await?;
        Ok((submit, None))
    }
}
