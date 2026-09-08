//! Endorse the existing Direct Conversation after its exact-pair MLS admission.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MessageAuthority {
    Participant(arkret_sdk::EventId),
    ProvisionalFounder(arkret_sdk::EventId),
}

/// Select evidence from a verified Seal closure, never a service's display
/// representative. Equivalent OR-Set endorsements are interchangeable evidence;
/// distinct semantic bindings are a conflict, not candidates to rank.
pub(crate) fn message_authority(
    checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
    actor: &arkret_sdk::ActorId,
    binding_observed: bool,
) -> Option<MessageAuthority> {
    let events = &checkpoint.accepted_events;
    let create = events.iter().find(|event| {
        event.realm_id == checkpoint.realm_id && event.kind == arkret_sdk::EventKind::RealmCreate
    })?;
    if create.payload.get("object")?.get("purpose")?.as_str()? != "direct_conversation" {
        return None;
    }
    let mut endorsement = None;
    let mut digest = None;
    for event in events.iter().filter(|event| {
        event.realm_id == checkpoint.realm_id
            && event.kind == arkret_sdk::EventKind::DirectConversationBound
    }) {
        let payload: arkret_sdk::DirectConversationBoundPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).ok()?).ok()?;
        if payload.realm_id != checkpoint.realm_id
            || !payload.unordered_participant_ids.contains(actor)
        {
            return None;
        }
        let next = payload.binding_digest().ok()?;
        if digest.as_ref().is_some_and(|prior| prior != &next) {
            return None;
        }
        digest = Some(next);
        endorsement.get_or_insert_with(|| event.event_id.clone());
    }
    if let Some(reference) = endorsement {
        return Some(MessageAuthority::Participant(reference));
    }
    // An observed binding can only close bootstrap; it cannot grant authority
    // until an endorsement is covered by the verified checkpoint above.
    (!binding_observed
        && create.actor_id == *actor
        && events.iter().any(|event| {
            event.realm_id == checkpoint.realm_id && event.kind == arkret_sdk::EventKind::MlsGenesis
        }))
    .then(|| MessageAuthority::ProvisionalFounder(create.event_id.clone()))
}

pub(crate) fn accepted_pair_commit<'a>(
    events: &'a [arkret_sdk::Event],
    realm_id: &str,
    group_id: &str,
    epoch: u64,
) -> anyhow::Result<&'a arkret_sdk::Event> {
    let matches = events.iter().filter(|event| {
        event.realm_id.as_str() == realm_id
            && event.kind == arkret_sdk::EventKind::MlsCommit
            && serde_json::from_value::<arkret_sdk::MlsCommitPayload>(
                serde_json::to_value(&event.payload).unwrap_or_default(),
            ).is_ok_and(|payload| {
                payload.next_epoch() == epoch
                    && payload.mls_group_id() == group_id
                    && matches!(payload.governance_binding().effective_scope(),
                        arkret_sdk::ScopeRef::Realm { realm_id: scope_realm } if scope_realm.as_str() == realm_id)
            })
    }).collect::<Vec<_>>();
    anyhow::ensure!(
        matches.len() == 1,
        "waiting for one accepted MLS Commit matching the local Direct Conversation group and epoch; found {}",
        matches.len()
    );
    Ok(matches[0])
}

pub(crate) async fn ensure_binding(
    api: &crate::transport::TransportClient,
    store: &crate::state::LocalStateStore,
    realm_id: &str,
    events: &[arkret_sdk::Event],
) -> anyhow::Result<()> {
    use arkret_sdk::{ActorId, EventKind};
    if store.realm_collaboration_role(realm_id)
        != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        || events
            .iter()
            .any(|event| event.kind == EventKind::DirectConversationBound)
    {
        return Ok(());
    }
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account is unavailable"))?;
    let create = events
        .iter()
        .find(|event| event.kind == EventKind::RealmCreate)
        .ok_or_else(|| anyhow::anyhow!("accepted Direct Conversation genesis is unavailable"))?;
    let mut founding = events
        .iter()
        .filter(|event| event.actor_id == create.actor_id && event.actor_seq <= 3)
        .collect::<Vec<_>>();
    founding.sort_by_key(|event| event.actor_seq);
    let exact: [&arkret_sdk::Event; 4] = founding
        .try_into()
        .map_err(|_| anyhow::anyhow!("accepted Direct Conversation founding unit is incomplete"))?;
    let plan =
        arkret_sdk::direct_conversation_ops::DirectConversationFoundingPlan::from_events(exact)?;
    let peer_membership: arkret_sdk::MembershipPayload =
        serde_json::from_value(serde_json::to_value(&exact[2].payload)?)?;
    let participants = vec![create.actor_id.clone(), peer_membership.member_id];
    let self_actor = ActorId::account(account.authority.clone());
    anyhow::ensure!(
        participants.contains(&self_actor),
        "binding endorser is not a founding participant"
    );
    let peer = participants
        .iter()
        .find(|actor| **actor != self_actor)
        .unwrap();
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let members = crate::mls::runtime::mls_group_member_actor_ids_for_effective_scope(
        store,
        secure.as_ref(),
        realm_id,
        None,
        &account.authority,
        &account.device_id,
    )
    .ok_or_else(|| anyhow::anyhow!("waiting for the local exact-pair MLS state"))?;
    anyhow::ensure!(
        members
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            == participants.iter().cloned().collect(),
        "waiting for exact-pair MLS admission"
    );
    let snapshot = store
        .mls_checkpoint_for(realm_id)
        .ok_or_else(|| anyhow::anyhow!("MLS checkpoint is unavailable"))?;
    anyhow::ensure!(snapshot.epoch > 0, "waiting for the peer MLS Add");
    let initial_state = accepted_pair_commit(events, realm_id, &snapshot.group_id, snapshot.epoch)?;
    let live_handoff = events
        .iter()
        .filter(|event| event.kind == EventKind::MlsWelcome)
        .filter_map(|event| {
            serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(
                serde_json::to_value(&event.payload).ok()?,
            )
            .ok()
        })
        .any(|welcome| {
            welcome.commit_ref == initial_state.event_id
                && welcome.expires_at > crate::clock::now_utc()
        });
    if !live_handoff {
        // The founder's ordinary endpoint repair must finish before either
        // participant can endorse a previously abandoned handoff.
        return Ok(());
    }
    let peer_account = peer
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("human Contact binding requires an account peer"))?;
    let http = api.sdk_http_client()?;
    let peer_selector = arkret_sdk::contact_operations::ContactPeer::Human {
        account_id: peer_account.clone(),
    };
    let resolved = http
        .direct_conversation_resolve(
            &arkret_sdk::direct_conversation_ops::DirectConversationResolveRequestBody {
                peer: peer_selector,
            },
        )
        .await?;
    use arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome;
    let coordinates = match resolved {
        DirectConversationResolveOutcome::Found { .. } => return Ok(()),
        DirectConversationResolveOutcome::Provisional { coordinates, .. } => coordinates,
        _ => anyhow::bail!("Direct Conversation current authority is not ready for binding"),
    };
    anyhow::ensure!(
        coordinates.realm_id == plan.realm_id && coordinates.main_strand_id == plan.main_strand_id,
        "resolver and accepted founding coordinates differ"
    );
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .iter()
        .find(|row| row.peer.contact_actor_id() == *peer)
        .ok_or_else(|| anyhow::anyhow!("accepted Contact is unavailable"))?;
    let refs = [
        row.request_event_ref.clone(),
        row.response_event_ref.clone(),
    ]
    .into_iter()
    .collect::<Option<Vec<_>>>()
    .ok_or_else(|| {
        anyhow::anyhow!("accepted Contact request/response references are unavailable")
    })?;
    let payload = arkret_sdk::DirectConversationBoundPayload {
        pair_key: coordinates.pair_key,
        unordered_participant_ids: participants,
        realm_id: plan.realm_id,
        main_strand_id: plan.main_strand_id,
        founding_unit_digest: plan.founding_unit_digest,
        authorization_basis: arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::accepted_contact(refs),
        initial_exact_pair_group_state_ref: initial_state.event_id.clone(),
        created_at: crate::clock::now_utc_millis(),
    };
    let operation = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::DirectConversationBound,
    >(realm_id, account.principal_id().as_str(), payload)
    .build_sdk_event("inkson")?;
    let operation = crate::operation::LocalOperation::new(
        operation
            .into_intent()
            .with_authorization_ref(
                arkret_sdk::AuthorizationRef::new(
                    arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1,
                )
                .map_err(anyhow::Error::msg)?,
            )
            .with_ref(arkret_sdk::EventRef::new(
                create.event_id.to_string(),
                "direct_conversation_founding_unit",
            )),
    );
    api.event_submitter()?.submit_sdk_event(&operation).await?;
    Ok(())
}
