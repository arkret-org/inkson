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
        let plan = build.message_plan;
        let response_refs = operation.intent().causal_refs().to_vec();
        build.message_plan = Box::new(move |commit_ref| {
            let message = plan(commit_ref)?;
            let mut refs = message.intent().causal_refs().to_vec();
            refs.extend(response_refs);
            refs.sort();
            refs.dedup();
            Ok(message.with_causal_refs(refs))
        });
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
