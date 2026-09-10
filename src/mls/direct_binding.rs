//! Endorse the existing Direct Conversation after its exact-pair MLS admission.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MessageAuthority {
    Participant(arkret_sdk::EventId),
    ProvisionalFounder(arkret_sdk::EventId),
}

/// Read the last exact own-Station result for display/encryption. Every new
/// Message submit refreshes this context before freezing its authoring intent.
pub(crate) fn message_authority(
    store: &crate::state::LocalStateStore,
    realm: &str,
    actor: &arkret_sdk::ActorId,
) -> Option<MessageAuthority> {
    store
        .direct_message_context(realm, actor)
        .map(|context| context.authority)
}

static QUERY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static QUERIES: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeMap<String, u64>>> =
    std::sync::OnceLock::new();
fn query_key(
    account: &arkret_sdk::AccountId,
    peer: &arkret_sdk::contact_operations::ContactPeer,
) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&(account, peer))?)
}
pub(crate) fn begin_query(
    account: &arkret_sdk::AccountId,
    peer: &arkret_sdk::contact_operations::ContactPeer,
) -> anyhow::Result<u64> {
    let sequence = QUERY_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut queries = QUERIES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("Direct Conversation query lock poisoned"))?;
    queries.insert(query_key(account, peer)?, sequence);
    while queries.len() > 64 {
        let key = queries
            .iter()
            .min_by_key(|(_, value)| *value)
            .unwrap()
            .0
            .clone();
        queries.remove(&key);
    }
    Ok(sequence)
}
pub(crate) fn query_is_current(
    account: &arkret_sdk::AccountId,
    peer: &arkret_sdk::contact_operations::ContactPeer,
    sequence: u64,
) -> bool {
    query_key(account, peer).ok().is_some_and(|key| {
        QUERIES
            .get_or_init(Default::default)
            .lock()
            .is_ok_and(|queries| queries.get(&key) == Some(&sequence))
    })
}

pub(crate) async fn install_resolved_message_context(
    http: &arkret_sdk::http_client::Client,
    store: &crate::runtime::input::StateStoreHandle,
    account: &arkret_sdk::AccountId,
    epoch: u64,
    query_sequence: u64,
    peer: arkret_sdk::contact_operations::ContactPeer,
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) -> anyhow::Result<()> {
    use arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome;
    outcome.validate_shape()?;
    let Some(coordinates) = outcome.coordinates() else {
        return Ok(());
    };
    let realm = coordinates.realm_id.clone();
    anyhow::ensure!(
        query_is_current(account, &peer, query_sequence),
        "Direct Conversation query was superseded"
    );
    store.write(|state| -> anyhow::Result<()> {
        anyhow::ensure!(
            state.active_authority().as_ref() == Some(account)
                && epoch == crate::identity::device_directory::cache_epoch(),
            "Direct Conversation account changed"
        );
        state.set_direct_message_context(realm.to_string(), None);
        state.save_direct_conversation_peer(realm.to_string(), peer.clone())
    })?;
    let (authority, group_state_ref) = match outcome {
        DirectConversationResolveOutcome::Found {
            coordinates,
            group_state_ref,
            send_blockers,
        } if send_blockers.is_empty() => {
            let reference = coordinates.binding_event_ref.clone().ok_or_else(|| {
                anyhow::anyhow!("Found Direct Conversation omits binding reference")
            })?;
            let decision = http
                .read_control_proposal_decision(
                    &arkret_sdk::ControlProposalDecisionReadRequestBody {
                        realm_id: realm.clone(),
                        proposal_digest: reference.event_digest(),
                    },
                )
                .await?;
            anyhow::ensure!(
                decision.proposal_event_kind
                    == arkret_sdk::EventKind::DirectConversationBound.as_str()
                    && decision.proposal_state == arkret_sdk::ControlProposalState::Sealed
                    && decision.accepted_seal_id.is_some(),
                "Direct Conversation endorsement is not sealed"
            );
            (
                MessageAuthority::Participant(reference),
                group_state_ref.clone(),
            )
        }
        DirectConversationResolveOutcome::Provisional {
            group_state_ref: Some(group_state_ref),
            ..
        } => {
            let reference = arkret_sdk::EventId::new(format!(
                "ak:event:{}",
                realm.as_str().trim_start_matches("ak:realm:")
            ))?;
            let resolved = http
                .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                    event_ids: vec![reference.clone()],
                    event_digests: vec![],
                    include_payload: Some(true),
                    history_traversal_access: None,
                    max_response_bytes: Some(8 * 1024 * 1024),
                })
                .await?;
            anyhow::ensure!(
                resolved.missing.is_empty()
                    && resolved.unauthorized.is_empty()
                    && resolved.events.len() == 1,
                "Direct Conversation founding Event unavailable"
            );
            let create = &resolved.events[0];
            anyhow::ensure!(
                create.event_id == reference
                    && create.realm_id == realm
                    && create.kind == arkret_sdk::EventKind::RealmCreate
                    && create
                        .payload
                        .get("object")
                        .and_then(|object| object.get("purpose"))
                        .and_then(serde_json::Value::as_str)
                        == Some("direct_conversation"),
                "Direct Conversation founding result differs"
            );
            if create.actor_id.as_account_id() != Some(account) {
                return Ok(());
            }
            (
                MessageAuthority::ProvisionalFounder(reference),
                group_state_ref.clone(),
            )
        }
        _ => return Ok(()),
    };
    let frontier = http.seals_frontier(realm.clone()).await?.frontier;
    anyhow::ensure!(
        frontier.realm_id == realm,
        "Direct Conversation frontier differs"
    );
    let seal_ref = frontier.sole_leaf()?.clone();
    store.write(|state| -> anyhow::Result<()> {
        anyhow::ensure!(
            state.active_authority().as_ref() == Some(account)
                && epoch == crate::identity::device_directory::cache_epoch()
                && query_is_current(account, &peer, query_sequence),
            "Direct Conversation result arrived after session or query changed"
        );
        state
            .cache_realm_governance_frontier(frontier)
            .map_err(anyhow::Error::msg)?;
        state.set_direct_message_context(
            realm.to_string(),
            Some(crate::state::DirectMessageContext {
                account: account.clone(),
                session_epoch: epoch,
                query_sequence,
                authority,
                group_state_ref,
                seal_ref,
            }),
        );
        Ok(())
    })
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
