use arkret_sdk::contact_operations::{
    ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedEventDraft, ContactPreparedOutcome, ContactScope,
};
use arkret_sdk::{IdempotencyKey, ProtocolOperationId, ReservationHandle};

fn contact_scope(scope: &str) -> anyhow::Result<ContactScope> {
    match scope.trim() {
        "invite" => Ok(ContactScope::Invite),
        "direct_message" => Ok(ContactScope::DirectMessage),
        "voice_call" => Ok(ContactScope::VoiceCall),
        "video_call" => Ok(ContactScope::VideoCall),
        "presence" => Ok(ContactScope::Presence),
        other => anyhow::bail!("unsupported Contact scope `{other}`"),
    }
}

fn prepared_contact_request(
    outcome: ContactOperationOutcome,
) -> anyhow::Result<(
    ProtocolOperationId,
    ReservationHandle,
    ContactPreparedEventDraft,
)> {
    match outcome {
        ContactOperationOutcome::Prepared {
            outcome:
                ContactPreparedOutcome::Request {
                    operation_id,
                    reservation_handle,
                    event_draft,
                    ..
                },
        } => Ok((operation_id, reservation_handle, event_draft)),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact request prepare was rejected: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact request prepare returned an invalid result kind"),
    }
}

fn sign_prepared_contact_event(
    draft: &ContactPreparedEventDraft,
) -> anyhow::Result<arkret_sdk::Event> {
    let mut event = draft.unsigned_event()?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for Contact commit"))?;
    signer.sign_sdk_event_with_context(
        &mut event,
        crate::event_signer::EventProofContext::default(),
    )?;
    let signed_digest = arkret_sdk::Hash::new(event.event_digest()?)?;
    if signed_digest != draft.event_digest {
        anyhow::bail!("signing changed the prepared Contact Event digest");
    }
    Ok(event)
}

impl crate::transport::TransportClient {
    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactOperationOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<ContactOperationOutcome> {
        self.request_contact_with_message(target, &[scope.to_owned()], None, None)
            .await
    }

    /// Execute the future-only Contact prepare -> local signature -> commit
    /// ceremony. The UI's contact-request surface is explicitly human-only;
    /// Agent contacts require their controller binding and therefore need a
    /// separate typed UX instead of guessing from a DID string.
    pub async fn request_contact_with_message(
        &self,
        target: &str,
        scopes: &[String],
        message: Option<&str>,
        recipient_service_id: Option<&str>,
    ) -> anyhow::Result<ContactOperationOutcome> {
        if recipient_service_id.is_some_and(|value| !value.trim().is_empty()) {
            anyhow::bail!(
                "the Contact request protocol no longer accepts an unverified recipient service override"
            );
        }
        let mut granted_to_peer_scopes = scopes
            .iter()
            .map(|scope| contact_scope(scope))
            .collect::<anyhow::Result<Vec<_>>>()?;
        granted_to_peer_scopes.sort();
        granted_to_peer_scopes.dedup();
        if granted_to_peer_scopes.is_empty() {
            anyhow::bail!("at least one Contact scope is required");
        }
        let addressing = self.contact_request_addressing(target, None).await?;
        let nonce = crate::operation::uuid_v7();
        let operation_id =
            ProtocolOperationId::new(format!("ak:operation:contact.request.{nonce}"))
                .map_err(anyhow::Error::msg)?;
        let idempotency_key = IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?;
        let prepare = ContactOperationRequestBody::Prepare(ContactPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            peer: ContactPeer::Human {
                principal_id: addressing.target,
            },
            granted_to_peer_scopes,
            introduction_evidence: addressing.introduction_evidence,
            message: message
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(ToOwned::to_owned),
        });
        let (prepared_operation_id, reservation_handle, event_draft) =
            prepared_contact_request(self.sdk_http_client()?.contacts_request(&prepare).await?)?;
        if prepared_operation_id != operation_id {
            anyhow::bail!("Contact prepare changed operation_id");
        }
        let signed_event = sign_prepared_contact_event(&event_draft)?;
        let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event,
        });
        self.sdk_http_client()?
            .contacts_request(&commit)
            .await
            .map_err(anyhow::Error::from)
    }
}
