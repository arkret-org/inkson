use super::*;

/// Polls use the same content protection and accepted identity as any Message.
#[derive(Clone)]
pub(super) struct PollSubmissionContext {
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub circle_id: Option<String>,
}

/// Replacement declarations are derived only from the verified SDK projection.
pub(super) fn verified_poll_response_heads(
    card: &crate::messaging::polls::PollCard,
    poll_ref: &arkret_sdk::MessageId,
    actor: &arkret_sdk::ActorId,
) -> anyhow::Result<Vec<arkret_sdk::PollResponseHead>> {
    anyhow::ensure!(
        card.poll_ref.as_ref() == Some(poll_ref),
        "poll is not an accepted message"
    );
    anyhow::ensure!(
        !card.provisional,
        "poll stream prefix or decrypted inputs are incomplete"
    );
    if let Some(head) = card.response_heads.get(actor) {
        anyhow::ensure!(
            arkret_sdk::MessageId::from_event_id(&head.poll_event_ref) == *poll_ref,
            "poll response head belongs to another poll"
        );
        Ok(vec![head.clone()])
    } else {
        anyhow::ensure!(
            !card.actor_has_voted(actor),
            "verified response Event identity is unavailable"
        );
        Ok(Vec::new())
    }
}

fn ensure_response_heads_match_operation(
    operation: &crate::operation::LocalOperation,
    response_heads: &[arkret_sdk::PollResponseHead],
) -> anyhow::Result<()> {
    let operation_heads = operation.payload().get("poll_response_heads");
    let expected_heads = if response_heads.is_empty() {
        None
    } else {
        Some(serde_json::to_value(response_heads)?)
    };
    anyhow::ensure!(
        operation_heads == expected_heads.as_ref(),
        "poll response heads differ from the typed operation"
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
    response_heads: Vec<arkret_sdk::PollResponseHead>,
) -> anyhow::Result<String> {
    let scope = operation.intent().scope_ref().clone();
    let store = crate::app::runtime_adapter::state_store_handle(state_store);
    anyhow::ensure!(
        store.read(|state| state.active_authority().as_ref() == Some(&context.authority)),
        "poll authoring account changed"
    );
    let input = crate::mls::send_gate::MlsSendGateInput::capture(&store, &scope);
    let gate =
        crate::mls::send_gate::resolve_restorable_mls_send_gate(&input, &scope, &context.device_id)
            .await?;
    anyhow::ensure!(
        matches!(gate, crate::mls::send_gate::MlsSendGate::Plaintext),
        "encrypted polls are unavailable in v1"
    );
    ensure_response_heads_match_operation(operation, &response_heads)?;
    let content = operation
        .payload()
        .get("content")
        .ok_or_else(|| anyhow::anyhow!("poll operation is missing its canonical Content Block"))?;
    let content_bytes = serde_json::to_vec(content)?;
    let event_id = api
        .event_submitter()?
        .submit_sdk_event(operation)
        .await?
        .event_id;
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
    fn votes_and_revotes_require_a_complete_verified_head_projection() {
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
        assert!(verified_poll_response_heads(&card, &poll_ref, &actor).is_err());
        card.provisional = false;
        assert!(verified_poll_response_heads(&card, &poll_ref, &actor).is_ok());
        card.votes[0].push(actor.clone());
        assert!(verified_poll_response_heads(&card, &poll_ref, &actor).is_err());
        let head = arkret_sdk::PollResponseHead {
            poll_event_ref: arkret_sdk::EventId::new(poll_ref.as_str().replacen(
                "ak:message:",
                "ak:event:",
                1,
            ))
            .unwrap(),
            response_event_ref: arkret_sdk::EventId::new(
                "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            )
            .unwrap(),
        };
        card.response_heads.insert(actor.clone(), head.clone());
        assert_eq!(
            verified_poll_response_heads(&card, &poll_ref, &actor).unwrap(),
            vec![head]
        );
        card.votes[0].clear();
        card.poll_ref = None;
        assert!(verified_poll_response_heads(&card, &poll_ref, &actor).is_err());
    }

    #[test]
    fn response_head_parameter_must_match_signed_operation_payload() {
        let poll = arkret_sdk::EventId::new(
            "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu".to_owned(),
        )
        .unwrap();
        let head = arkret_sdk::PollResponseHead {
            poll_event_ref: poll.clone(),
            response_event_ref: arkret_sdk::EventId::new(
                "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z".to_owned(),
            )
            .unwrap(),
        };
        let operation = crate::messaging::polls::build_poll_vote_op_with_heads(
            "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
            "ak:did_core:web:alice.example",
            "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
            arkret_sdk::MessageId::from_event_id(&poll).as_str(),
            &["opt-0".to_owned()],
            vec![head.clone()],
        )
        .unwrap();
        assert!(ensure_response_heads_match_operation(&operation, &[head]).is_ok());
        assert!(ensure_response_heads_match_operation(&operation, &[]).is_err());
    }
}
