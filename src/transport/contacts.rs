use arkret_sdk::contact_operations::{
    ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedEventDraft, ContactPreparedOutcome, ContactScope,
};
use arkret_sdk::{IdempotencyKey, ProtocolOperationId, ReservationHandle};

pub(crate) struct PrincipalSuccessorSealContext {
    actor_id: arkret_sdk::DidCoreId,
    control_realm: arkret_sdk::RealmId,
    predecessor: arkret_sdk::Seal,
}

pub(crate) async fn prepare_principal_successor_seal(
    http: &arkret_sdk::http_client::Client,
    contact_event: &arkret_sdk::Event,
) -> anyhow::Result<PrincipalSuccessorSealContext> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for principal commit"))?;
    let principal = arkret_sdk::DidFullId::new(signer.signer_did().to_owned())?;
    let actor_id = arkret_sdk::project_full_id_to_core_id(&principal)?;
    if contact_event.actor_id != actor_id {
        anyhow::bail!("prepared principal Event actor does not match the active signer");
    }
    let control_realm = contact_event.realm_id.clone();
    let selector = arkret_sdk::EventsFrontierSelector::RealmSeal {
        realm_id: control_realm.clone(),
    };
    let state = http.events_frontier(&selector).await?;
    let arkret_sdk::EventsFrontierView::RealmSeal(view) = state.frontier else {
        anyhow::bail!("principal control frontier did not return a Realm Seal view");
    };
    if view.realm_id != control_realm {
        anyhow::bail!("principal control frontier returned a different Realm");
    }
    // The successor Seal binds the predecessor's own signed roots, so the
    // frontier leaf is resolved instead of trusting a service root hint.
    let leaf = view.sole_leaf()?.clone();
    let predecessor = http
        .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
            realm_id: control_realm.clone(),
            seal_refs: vec![leaf.clone()],
            history_traversal_access: None,
        })
        .await?
        .seals
        .into_iter()
        .find(|seal| seal.id == leaf)
        .ok_or_else(|| anyhow::anyhow!("accepted principal control Seal leaf did not resolve"))?;
    Ok(PrincipalSuccessorSealContext {
        actor_id,
        control_realm,
        predecessor,
    })
}

pub(crate) async fn submit_principal_successor_seal(
    http: &arkret_sdk::http_client::Client,
    context: PrincipalSuccessorSealContext,
    principal_event: &arkret_sdk::Event,
) -> anyhow::Result<()> {
    let accepted_rows = http
        .events_read_all_pages(context.control_realm.as_str())
        .await?
        .events;
    let mut accepted = crate::models::require_complete_event_rows(
        &accepted_rows,
        "principal successor Seal construction",
    )?
    .into_iter()
    .filter(|event| event.actor_id == context.actor_id)
    .collect::<Vec<_>>();
    accepted.sort_by_key(|event| event.actor_seq);
    if accepted.last().map(|event| &event.event_id) != Some(&principal_event.event_id) {
        anyhow::bail!("accepted principal Event is not the actor frontier");
    }

    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for principal Seal"))?;
    let device_id = signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("principal Seal signer requires a bound device_id"))?;
    let hlc = crate::signing_stamp::issue_protocol_hlc(
        context.actor_id.as_str(),
        device_id,
        context.control_realm.as_str(),
    )?;
    let seal = signer
        .sign_self_principal_linear_successor_seal(&accepted, &context.predecessor, hlc)
        .map_err(|error| anyhow::anyhow!("sign principal successor Seal: {error}"))?;
    let principal_digest = arkret_sdk::Hash::new(
        principal_event.event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
    )?;
    let outcome = http.events_submit_seal(&seal).await?;
    if !outcome
        .accepted_event_digests
        .iter()
        .any(|digest| digest == &principal_digest)
    {
        anyhow::bail!("Principal Server did not seal the accepted principal Event");
    }
    Ok(())
}

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

pub(crate) fn sign_prepared_contact_event(
    draft: &ContactPreparedEventDraft,
) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
    let mut event = draft.unsigned_event()?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for Contact commit"))?;
    signer.sign_sdk_event_with_context(
        &mut event,
        crate::event_signer::EventProofContext::default(),
    )?;
    let signed_digest =
        arkret_sdk::Hash::new(event.event_digest_with_digest_suite(event.digest_suite())?)?;
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
        self.request_contact_with_message(target, &[scope.to_owned()], None)
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
    ) -> anyhow::Result<ContactOperationOutcome> {
        let mut granted_to_peer_scopes = scopes
            .iter()
            .map(|scope| contact_scope(scope))
            .collect::<anyhow::Result<Vec<_>>>()?;
        granted_to_peer_scopes.sort();
        granted_to_peer_scopes.dedup();
        if granted_to_peer_scopes.is_empty() {
            anyhow::bail!("at least one Contact scope is required");
        }
        let addressing = self.contact_request_addressing(target).await?;
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
            previous_terminal_contact_round_id: None,
            continuity_evidence: None,
            message: message
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(ToOwned::to_owned),
        });
        let http = self.sdk_http_client()?;
        let (prepared_operation_id, reservation_handle, event_draft) =
            prepared_contact_request(http.contacts_request(&prepare).await?)?;
        if prepared_operation_id != operation_id {
            anyhow::bail!("Contact prepare changed operation_id");
        }
        let signed_event = sign_prepared_contact_event(&event_draft)?;
        let seal_context = prepare_principal_successor_seal(&http, &signed_event).await?;
        let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        let outcome = http
            .contacts_request(&commit)
            .await
            .map_err(anyhow::Error::from)?;
        if matches!(outcome, ContactOperationOutcome::Accepted { .. }) {
            submit_principal_successor_seal(&http, seal_context, &signed_event).await?;
        }
        Ok(outcome)
    }
}
