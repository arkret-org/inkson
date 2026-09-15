use super::*;

/// Polls use the same content protection and accepted identity as any Message.
#[derive(Clone)]
pub(super) struct PollSubmissionContext {
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub encrypted: bool,
    pub circle_id: Option<String>,
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
        // A poll response is an `ak.message.create` that has to name the poll
        // it answers in `causal_refs`. The closed message authoring intent has
        // no member for that, and a prepared message with non-empty
        // `causal_refs` is refused, so this one write is authored locally
        // instead of prepared. Ordinary discussion messages do not take this
        // path; when the contract carries the reference, neither will this one.
        let crate::views::secure_send::SecureWritePlan::Message(authoring) = build.message_plan
        else {
            anyhow::bail!("a poll response requires the encrypted message build");
        };
        let response_refs = operation.intent().causal_refs().to_vec();
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
                let mut refs = response_refs;
                refs.sort();
                refs.dedup();
                crate::operation::TypedOperationBuilder::new::<
                    arkret_sdk::event_spec::MessageCreate,
                >(&plan_realm_id, &plan_actor, intent.payload())
                .effective_scope(plan_scope)
                .causal_refs(refs)
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
            crate::views::secure_send::SecureSendOutcome::CommitFailed { message }
            | crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
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
