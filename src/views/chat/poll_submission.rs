use super::*;

/// Polls use the same content protection and accepted identity as any Message.
#[derive(Clone)]
pub(super) struct PollSubmissionContext {
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub encrypted: bool,
    pub circle_id: Option<String>,
}

/// Until the verified response projection retains accepted response Event ids,
/// this producer can only author a first vote. A known re-vote needs the exact
/// pairwise declaration required by content-types §4.9.1.
pub(super) fn ensure_first_poll_vote(
    card: &crate::messaging::polls::PollCard,
    poll_ref: &arkret_sdk::MessageId,
    actor: &arkret_sdk::ActorId,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        card.poll_ref.as_ref() == Some(poll_ref),
        "poll is not an accepted message"
    );
    anyhow::ensure!(
        !card.actor_has_voted(actor),
        "cannot change a poll vote until the accepted response Event reference is available"
    );
    Ok(())
}

pub(super) async fn submit_poll_operation(
    api: &TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    context: &PollSubmissionContext,
    operation: &crate::operation::LocalOperation,
    realm_id: &str,
    strand_id: &str,
) -> anyhow::Result<String> {
    let content = operation
        .payload()
        .get("content")
        .ok_or_else(|| anyhow::anyhow!("poll operation is missing its canonical Content Block"))?;
    let content_bytes = serde_json::to_vec(content)?;
    let event_id = if context.encrypted {
        let mut build = crate::views::secure_send::build_secure_send(
            api,
            state_store,
            realm_id,
            &context.authority,
            context.authority.principal_id.as_str(),
            &context.device_id,
            strand_id,
            &operation.local_operation_id().to_string(),
            None,
            &content_bytes,
            None,
            context.circle_id.as_deref(),
            None,
        )
        .await
        .map_err(anyhow::Error::msg)?;
        // The closed prepared-message intent does not carry the typed
        // poll_response_heads declaration. Poll responses therefore use a
        // directly authored MessageCreate Event; initial votes have no head.
        let crate::views::secure_send::SecureWritePlan::Message(authoring) = build.message_plan
        else {
            anyhow::bail!("a poll response requires the encrypted message build");
        };
        let plan_realm_id = realm_id.to_owned();
        let plan_actor = context.authority.principal_id.as_str().to_owned();
        let plan_scope = build.effective_scope.clone();
        let plan_local_operation_id = build.message_local_operation_id.clone();
        build.message_plan =
            crate::views::secure_send::SecureWritePlan::Control(Box::new(move |commit_ref| {
                let content = (authoring.plan)(commit_ref)?;
                let intent = crate::views::chat::model::chat_message_authoring_intent(
                    &authoring.strand_id,
                    content,
                    authoring.reply_to.as_deref(),
                )
                .map_err(|error| format!("poll response intent build failed: {error:#}"))?;
                crate::operation::TypedOperationBuilder::new::<
                    arkret_sdk::event_spec::MessageCreate,
                >(&plan_realm_id, &plan_actor, intent.payload())
                .effective_scope(plan_scope)
                .build_sdk_event("inkson")
                .map(|operation| operation.with_local_operation_id(plan_local_operation_id))
                .map_err(|error| format!("poll response Event conversion failed: {error}"))
            }));
        match crate::views::secure_send::submit_secure_send(
            api,
            state_store,
            build,
            realm_id,
            context.circle_id.clone(),
        )
        .await
        {
            crate::views::secure_send::SecureSendOutcome::Sent { event_id, .. } => event_id,
            crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                anyhow::bail!(message);
            }
            crate::views::secure_send::SecureSendOutcome::MessageAuthoringFailed { failure } => {
                anyhow::bail!(crate::i18n::tr(
                    crate::views::chat::model::chat_authoring_failure_message(&failure)
                ));
            }
        }
    } else {
        api.event_submitter()?
            .submit_sdk_event(operation)
            .await?
            .event_id
    };
    let accepted = arkret_sdk::EventId::new(event_id.clone())?;
    let message_id = arkret_sdk::MessageId::from_event_id(&accepted);
    state_store.write().save_private_plaintext(
        realm_id,
        strand_id,
        &format!("message-content:{message_id}"),
        std::str::from_utf8(&content_bytes)?,
    );
    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_vote_allowed_but_known_revote_requires_accepted_head() {
        let poll_ref = arkret_sdk::MessageId::new(
            "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu".to_owned(),
        )
        .unwrap();
        let actor = crate::views::chat::tests::local_fixture_actor("did:web:alice.example");
        let mut draft = crate::messaging::polls::PollDraft::new();
        draft.question = "ship?".to_owned();
        draft.set_option(0, "yes".to_owned());
        draft.set_option(1, "no".to_owned());
        let mut card = crate::messaging::polls::PollCard::from_draft("accepted".to_owned(), &draft);
        card.poll_ref = Some(poll_ref.clone());
        assert!(ensure_first_poll_vote(&card, &poll_ref, &actor).is_ok());
        card.votes[0].push(actor.clone());
        assert!(ensure_first_poll_vote(&card, &poll_ref, &actor).is_err());
        card.votes[0].clear();
        card.poll_ref = None;
        assert!(ensure_first_poll_vote(&card, &poll_ref, &actor).is_err());
    }
}
