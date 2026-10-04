//! Endorse the existing Direct Conversation after its exact-pair MLS admission.

/// Read the last verified exact-pair binding for display and encryption.
pub(crate) fn message_authority(
    store: &crate::state::LocalStateStore,
    realm: &str,
    actor: &arkret_sdk::ActorId,
) -> Option<arkret_sdk::EventId> {
    store
        .direct_message_context(realm, actor)
        .map(|context| context.authority_event_ref)
}

static QUERY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Complete producer-signed Direct authority before the Commit is addressed.
/// The caller supplies a nonce-verified genesis and its own Station's resolver.
pub(crate) fn mls_authoring_intent(
    intent: &crate::operation::EventIntent,
    genesis: &arkret_sdk::Event,
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
) -> anyhow::Result<crate::operation::EventIntent> {
    use arkret_sdk::direct_conversation::DirectConversationResolveOutcome;
    outcome.validate_shape()?;
    let realm = intent
        .realm_id_opt()
        .ok_or_else(|| anyhow::anyhow!("Direct MLS requires a Realm"))?;
    anyhow::ensure!(
        intent.kind() == &arkret_sdk::EventKind::MlsCommit
            && matches!(intent.scope_ref(), arkret_sdk::ScopeRef::Realm { realm_id } if realm_id == realm)
            && intent.executed_by().is_none()
            && genesis.kind == arkret_sdk::EventKind::RealmCreate
            && genesis.scope_ref == arkret_sdk::ScopeRef::RealmGenesis
            && genesis.realm_id == *realm
            && arkret_sdk::RealmId::from_event_id(&genesis.event_id) == *realm,
        "Direct MLS authoring and verified genesis differ"
    );
    let payload: arkret_sdk::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.payload)?)?;
    anyhow::ensure!(
        payload.object.purpose == arkret_sdk::RealmPurpose::DirectConversation,
        "Direct MLS requires Direct genesis"
    );
    let coordinates = outcome
        .coordinates()
        .ok_or_else(|| anyhow::anyhow!("Direct MLS coordinates are unavailable"))?;
    anyhow::ensure!(
        coordinates.realm_id == *realm,
        "Direct MLS resolver names another Realm"
    );
    let (source, reference) = match outcome {
        DirectConversationResolveOutcome::Provisional { .. } => {
            anyhow::ensure!(
                intent.actor_id() == &genesis.actor_id,
                "only the Direct founder may author provisional MLS"
            );
            (
                arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1,
                genesis.event_id.clone(),
            )
        }
        DirectConversationResolveOutcome::Found { .. } => (
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1,
            coordinates
                .binding_event_ref
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Direct binding is unavailable"))?,
        ),
        _ => anyhow::bail!("Direct MLS current authority is not ready"),
    };
    participant_authoring_intent(
        intent,
        arkret_wire::AuthoritySourceId::from_wire(source)
            .ok_or_else(|| anyhow::anyhow!("unknown Direct participant source"))?,
        &reference,
    )
}

pub(crate) fn participant_authoring_intent(
    intent: &crate::operation::EventIntent,
    source: arkret_wire::AuthoritySourceId,
    reference: &arkret_sdk::EventId,
) -> anyhow::Result<crate::operation::EventIntent> {
    let role = match source {
        arkret_wire::AuthoritySourceId::DirectConversationParticipantV1 => {
            "direct_conversation_binding"
        }
        arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1 => {
            "direct_conversation_founding_unit"
        }
        _ => anyhow::bail!("invalid Direct message or MLS source"),
    };
    anyhow::ensure!(
        matches!(
            intent.kind(),
            arkret_sdk::EventKind::MessageCreate
                | arkret_sdk::EventKind::MlsCommit
                | arkret_sdk::EventKind::StrandWatchSet
        ) || arkret_sdk::direct_conversation::direct_conversation_structure_action(intent.kind()),
        "Direct intent is not a participant action"
    );
    if intent.kind() == &arkret_sdk::EventKind::StrandWatchSet {
        let payload = intent.typed_payload::<arkret_sdk::event_spec::StrandWatchSet>()?;
        anyhow::ensure!(
            source == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
                && &payload.watcher_actor_id == intent.actor_id(),
            "Direct watch requires a stable participant writing its own cell"
        );
    }
    anyhow::ensure!(
        intent.executed_by().is_none()
            && intent.authorization_ref().is_none()
            && !intent
                .semantic_refs()
                .iter()
                .any(|reference| reference.role == "direct_conversation_binding"
                    || reference.role == "direct_conversation_founding_unit"),
        "Direct intent already carries an authority"
    );
    Ok(intent
        .clone()
        .with_authorization_ref(
            arkret_sdk::AuthorizationRef::new(source.as_str()).map_err(anyhow::Error::msg)?,
        )
        .with_semantic_ref(arkret_sdk::SemanticRef::new(reference.to_string(), role)))
}
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
pub(crate) fn invalidate_query(
    account: &arkret_sdk::AccountId,
    peer: &arkret_sdk::contact_operations::ContactPeer,
) {
    if let Ok(key) = query_key(account, peer)
        && let Ok(mut queries) = QUERIES.get_or_init(Default::default).lock()
    {
        queries.remove(&key);
    }
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
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
) -> anyhow::Result<()> {
    use arkret_sdk::direct_conversation::DirectConversationResolveOutcome;
    outcome.validate_shape()?;
    // A refresh in flight is not a revocation. Only a current authenticated
    // result may replace or invalidate an installed authoring context.
    store.write(|state| -> anyhow::Result<()> {
        anyhow::ensure!(
            state.active_authority().as_ref() == Some(account)
                && epoch == crate::identity::device_directory::session_cache_epoch()
                && query_is_current(account, &peer, query_sequence),
            "Direct Conversation account or query changed"
        );
        if matches!(
            outcome,
            DirectConversationResolveOutcome::TemporarilyUnavailable { .. }
        ) {
            return Ok(());
        }
        let Some(coordinates) = outcome.coordinates() else {
            state.invalidate_direct_message_peer(account, &peer);
            return Ok(());
        };
        let realm = coordinates.realm_id.to_string();
        let retain = match outcome {
            DirectConversationResolveOutcome::Found { send_blockers, .. } => {
                send_blockers.is_empty()
            }
            DirectConversationResolveOutcome::Provisional {
                group_state_ref: Some(_),
                ..
            } => state
                .direct_message_context(&realm, &arkret_sdk::ActorId::account(account.clone()))
                .is_some_and(|context| {
                    context.authority_source
                        == arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1
                }),
            _ => false,
        };
        if !retain {
            state.set_direct_message_context(realm.clone(), None);
        }
        state.save_direct_conversation_peer(realm, peer.clone())
    })?;
    let Some(coordinates) = outcome.coordinates() else {
        return Ok(());
    };
    let realm = coordinates.realm_id.clone();
    let (authority_source, authority_event_ref, group_state_ref) = match outcome {
        DirectConversationResolveOutcome::Found {
            coordinates,
            group_state_ref,
            send_blockers,
        } if send_blockers.is_empty() => {
            let reference = coordinates.binding_event_ref.clone().ok_or_else(|| {
                anyhow::anyhow!("Found Direct Conversation omits binding reference")
            })?;
            // A `Found` resolution is the current authority's own answer that
            // the binding Event is committed on the Realm stream, so there is
            // no separate endorsement state to read: finality is the commit.
            (
                arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
                reference,
                group_state_ref.clone(),
            )
        }
        DirectConversationResolveOutcome::Provisional {
            group_state_ref: Some(group_state_ref),
            ..
        } => {
            let (bundle, ..) = crate::realm_events_engine::fresh_verified_realm(
                &garth::AuthorityClient::new(http.clone()),
                http,
                &realm,
            )
            .await?;
            let genesis = &bundle.genesis_event;
            let payload: arkret_sdk::RealmCreatePayload =
                serde_json::from_value(serde_json::to_value(&genesis.payload)?)?;
            anyhow::ensure!(
                payload.object.purpose == arkret_sdk::RealmPurpose::DirectConversation
                    && genesis.scope_ref == arkret_sdk::ScopeRef::RealmGenesis
                    && arkret_sdk::RealmId::from_event_id(&genesis.event_id) == realm,
                "provisional Direct result and verified genesis differ"
            );
            if genesis.actor_id != arkret_sdk::ActorId::account(account.clone()) {
                return Ok(());
            }
            (
                arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1,
                genesis.event_id.clone(),
                group_state_ref.clone(),
            )
        }
        _ => return Ok(()),
    };
    store.write(|state| -> anyhow::Result<()> {
        anyhow::ensure!(
            state.active_authority().as_ref() == Some(account)
                && epoch == crate::identity::device_directory::session_cache_epoch()
                && query_is_current(account, &peer, query_sequence)
                && state.direct_conversation_peer(realm.as_str()).as_ref() == Some(&peer),
            "Direct Conversation result arrived after session, query or peer changed"
        );
        state.set_direct_message_context(
            realm.to_string(),
            Some(crate::state::DirectMessageContext {
                account: account.clone(),
                session_epoch: epoch,
                query_sequence,
                authority_source,
                authority_event_ref,
                group_state_ref,
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
                    && payload
                        .mls_group_id()
                        .is_ok_and(|payload_group_id| payload_group_id.as_str() == group_id)
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

/// Only the genesis-prefix commits of this Realm stream may define the
/// founding digest. A time sort or a filtered founder-authored subset can
/// silently select later Events, especially when authored timestamps tie.
fn founding_genesis_prefix(
    backfill: &crate::models::BackfillView,
    realm_id: &str,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    keys: &arkret_identity::RealmAuthorityKeyMap,
) -> anyhow::Result<[arkret_sdk::Event; 4]> {
    let verified = arkret_identity::verify_realm_authority_bundle(bundle, freshness, keys)?;
    let expected_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
    };
    anyhow::ensure!(
        bundle.realm_id.as_str() == realm_id
            && bundle.genesis_commit.stream_ref == expected_stream
            && bundle.genesis_commit.stream_position == 0
            && bundle.genesis_commit.previous_commit_ref.is_none(),
        "Direct founding genesis is not this Realm's stream origin"
    );
    let mut exact = vec![bundle.genesis_event.clone()];
    let mut previous = bundle.genesis_commit.commit_id.clone();
    let mut founding = backfill.0.committed_events.iter();
    if founding
        .clone()
        .next()
        .is_some_and(|item| item.commit().stream_position == 0)
    {
        let item = founding.next().unwrap();
        anyhow::ensure!(
            item.commit() == &bundle.genesis_commit
                && item.reducer_input() == Some(&bundle.genesis_event),
            "readable genesis differs from verified authority"
        );
    }
    for position in 1..4 {
        let committed = founding.next().ok_or_else(|| {
            anyhow::anyhow!("accepted Direct Conversation founding unit is incomplete")
        })?;
        anyhow::ensure!(
            committed.commit().stream_ref == expected_stream
                && committed.commit().stream_position == position
                && committed.commit().previous_commit_ref.as_ref() == Some(&previous),
            "Direct Conversation founding unit is not the Realm stream genesis prefix"
        );
        let arkret_wire::CommittedEventView::Full(item) = committed else {
            anyhow::bail!("Direct Conversation founding Event is withheld");
        };
        verified.verify_committed_item(item, keys)?;
        previous = item.commit.commit_id.clone();
        exact.push(item.event.clone());
    }
    exact
        .try_into()
        .map_err(|_| anyhow::anyhow!("accepted Direct Conversation founding unit is incomplete"))
}

pub(crate) async fn ensure_binding(
    api: &crate::transport::TransportClient,
    store: &crate::state::LocalStateStore,
    realm_id: &str,
    backfill: &crate::models::BackfillView,
) -> anyhow::Result<()> {
    use arkret_sdk::{ActorId, EventKind};
    let events = backfill.events();
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
    let http = api.sdk_http_client()?;
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let (bundle, freshness, _) = crate::realm_events_engine::fresh_verified_realm(
        &garth::AuthorityClient::new(http.clone()),
        &http,
        &realm,
    )
    .await?;
    let keys = garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
    let exact = founding_genesis_prefix(backfill, realm_id, &bundle, &freshness, &keys)?;
    let create = &exact[0];
    // The four committed genesis-prefix Events, never timestamps or an
    // arbitrary founder-authored subset, bind the exact Realm/Strand unit.
    let plan = arkret_sdk::direct_conversation::DirectConversationFoundingPlan::from_events(
        exact.each_ref(),
    )?;
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
    // The current accepted Commit must match our installed state. Its epoch
    // does not select the immutable initial exact-pair binding reference.
    accepted_pair_commit(&events, realm_id, &snapshot.group_id, snapshot.epoch)?;
    let peer_selector = store
        .direct_conversation_peer(realm_id)
        .ok_or_else(|| anyhow::anyhow!("waiting for the exact Direct Conversation peer"))?;
    anyhow::ensure!(
        peer_selector.contact_actor_id() == *peer,
        "cached Direct peer differs from accepted founding membership"
    );
    let resolved = http
        .direct_conversation_resolve(
            &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
                peer: peer_selector.clone(),
            },
        )
        .await?;
    use arkret_sdk::direct_conversation::DirectConversationResolveOutcome;
    resolved.validate_shape()?;
    let (coordinates, authorization_basis, initial_state_ref) = match resolved {
        DirectConversationResolveOutcome::Found { .. } => return Ok(()),
        DirectConversationResolveOutcome::Provisional {
            coordinates,
            authorization_basis,
            initial_exact_pair_group_state_ref: Some(initial),
            peer_mls_admission:
                arkret_sdk::direct_conversation::DirectConversationPeerMlsAdmission::Durable,
            ..
        } => (coordinates, authorization_basis, initial),
        DirectConversationResolveOutcome::Provisional { .. } => return Ok(()),
        _ => anyhow::bail!("Direct Conversation current authority is not ready for binding"),
    };
    anyhow::ensure!(
        coordinates.realm_id == plan.realm_id && coordinates.main_strand_id == plan.main_strand_id,
        "resolver and accepted founding coordinates differ"
    );
    authorization_basis.validate_shape()?;
    anyhow::ensure!(
        events
            .iter()
            .any(|event| event.event_id == initial_state_ref
                && event.realm_id == realm
                && event.kind == EventKind::MlsCommit),
        "initial exact-pair reference is absent from accepted Realm history"
    );
    let payload = arkret_sdk::DirectConversationBoundPayload {
        pair_key: coordinates.pair_key,
        unordered_participant_ids: participants,
        realm_id: plan.realm_id,
        main_strand_id: plan.main_strand_id,
        founding_unit_digest: plan.founding_unit_digest,
        authorization_basis,
        initial_exact_pair_group_state_ref: initial_state_ref,
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
            .with_semantic_ref(arkret_sdk::SemanticRef::new(
                create.event_id.to_string(),
                "direct_conversation_founding_unit",
            )),
    );
    api.event_submitter()?.submit_sdk_event(&operation).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn founding_fixture() -> (
        arkret_sdk::RealmAuthorityBundle,
        arkret_identity::RealmAuthorityKeyMap,
        arkret_identity::RealmAuthorityFreshness,
        crate::models::BackfillView,
    ) {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3")
                .unwrap();
        let (bundle, keys, items) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm,
            vec![
                ("ak.member.state".into(), json!({"membership":"join"})),
                ("ak.member.state".into(), json!({"membership":"join"})),
                ("ak.strand.create".into(), json!({})),
            ],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            crate::test_support::committed_event::fixture_time(100),
            bundle.current_assertion.nonce.clone(),
        );
        let backfill = crate::models::BackfillView(arkret_wire::StreamScanOutcome {
            committed_events: items
                .into_iter()
                .map(arkret_wire::CommittedEventView::Full)
                .collect(),
            readable_floor: None,
            truncated: false,
        });
        (bundle, keys, freshness, backfill)
    }

    #[test]
    fn direct_founding_combines_verified_genesis_with_the_readable_signed_chain() {
        let (bundle, keys, freshness, backfill) = founding_fixture();
        assert_eq!(backfill.0.committed_events[0].commit().stream_position, 1);
        let exact = founding_genesis_prefix(
            &backfill,
            bundle.realm_id.as_str(),
            &bundle,
            &freshness,
            &keys,
        )
        .unwrap();
        assert_eq!(exact[0], bundle.genesis_event);
        for (event, committed) in exact[1..].iter().zip(&backfill.0.committed_events) {
            assert_eq!(Some(event), committed.reducer_input());
        }
        let mut with_genesis = backfill.clone();
        with_genesis.0.committed_events.insert(
            0,
            arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
                commit: bundle.genesis_commit.clone(),
                event: bundle.genesis_event.clone(),
            }),
        );
        assert_eq!(
            founding_genesis_prefix(
                &with_genesis,
                bundle.realm_id.as_str(),
                &bundle,
                &freshness,
                &keys
            )
            .unwrap(),
            exact
        );
    }

    #[test]
    fn direct_founding_rejects_missing_reordered_tampered_and_signed_forked_history() {
        let (bundle, keys, freshness, backfill) = founding_fixture();
        let mut candidates = Vec::new();
        let mut missing = backfill.clone();
        missing.0.committed_events.remove(0);
        candidates.push(missing);
        let mut reversed = backfill.clone();
        reversed.0.committed_events.swap(0, 1);
        candidates.push(reversed);
        let mut tampered = backfill.clone();
        if let arkret_wire::CommittedEventView::Full(item) = &mut tampered.0.committed_events[1] {
            item.event
                .payload
                .insert("membership".into(), json!("leave"));
        }
        candidates.push(tampered);
        let mut invalid_commit = backfill.clone();
        if let arkret_wire::CommittedEventView::Full(item) =
            &mut invalid_commit.0.committed_events[2]
        {
            item.commit.commit_id = arkret_sdk::RealmCommitId::from_digest([99; 32]);
        }
        candidates.push(invalid_commit);
        let mut fork = backfill.clone();
        if let arkret_wire::CommittedEventView::Full(item) = &mut fork.0.committed_events[1] {
            item.commit.previous_commit_ref =
                Some(arkret_sdk::RealmCommitId::from_digest([98; 32]));
            item.commit = crate::test_support::committed_event::FixtureStation::did_web()
                .seal_commit(item.commit.clone());
        }
        candidates.push(fork);
        for candidate in candidates {
            assert!(
                founding_genesis_prefix(
                    &candidate,
                    bundle.realm_id.as_str(),
                    &bundle,
                    &freshness,
                    &keys
                )
                .is_err()
            );
        }
        let mut replay = freshness.clone();
        replay.expected_nonce =
            arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode([9; 32])).unwrap();
        assert!(
            founding_genesis_prefix(&backfill, bundle.realm_id.as_str(), &bundle, &replay, &keys)
                .is_err()
        );
        assert!(
            founding_genesis_prefix(
                &backfill,
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                &bundle,
                &freshness,
                &keys
            )
            .is_err()
        );
    }

    #[test]
    fn direct_mls_authority_tracks_founder_and_committed_binding_before_addressing() {
        let station = crate::test_support::committed_event::FixtureStation::did_web();
        let genesis = arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::DirectConversation,
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
            arkret_sdk::SecurityClass::Standard,
            station.service_id().clone(),
            arkret_sdk::JoinRule::Closed,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::InviteOnly,
            None,
            None,
        )
        .unwrap();
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
        );
        let founder = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station.service_id().clone(),
        ));
        let create = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            "ak.realm.create",
            arkret_sdk::ScopeRef::RealmGenesis,
            founder.clone(),
            json!({"object":genesis}),
        )
        .with_created_at(crate::test_support::committed_event::fixture_time(0))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let intent: crate::operation::EventIntent = serde_json::from_value(json!({
            "kind":"ak.mls.commit", "scope_ref":{"kind":"realm","realm_id":create.realm_id},
            "actor_id":founder, "created_at":"2026-05-19T00:00:00.000Z", "payload":{}
        }))
        .unwrap();
        let coordinates: arkret_sdk::direct_conversation::DirectConversationCoordinates =
            serde_json::from_value(json!({
                "pair_key": format!("sha256:{}", "ab".repeat(32)), "realm_id":create.realm_id,
                "main_strand_id":"ak:strand:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3"
            }))
            .unwrap();
        let provisional =
            arkret_sdk::direct_conversation::DirectConversationResolveOutcome::Provisional {
                coordinates: coordinates.clone(),
                authorization_basis:
                    arkret_sdk::DirectConversationAuthorizationBasis::accepted_contact(vec![
                        create.event_id.clone(),
                        arkret_sdk::EventId::new(
                            "ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3",
                        )
                        .unwrap(),
                    ]),
                group_state_ref: None,
                initial_exact_pair_group_state_ref: None,
                peer_mls_admission:
                    arkret_sdk::direct_conversation::DirectConversationPeerMlsAdmission::Missing,
            };
        let authorized = mls_authoring_intent(&intent, &create, &provisional).unwrap();
        assert_eq!(
            authorized.authorization_ref().unwrap().as_str(),
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1
        );
        assert_eq!(
            authorized.semantic_refs()[0],
            arkret_sdk::SemanticRef::new(
                create.event_id.to_string(),
                "direct_conversation_founding_unit"
            )
        );
        assert_ne!(
            authorized
                .clone()
                .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap()
                .event_id,
            intent
                .clone()
                .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap()
                .event_id
        );
        assert!(mls_authoring_intent(&authorized, &create, &provisional).is_err());
        let mut other = create.clone();
        other.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            station.service_id().clone(),
        ));
        assert!(mls_authoring_intent(&intent, &other, &provisional).is_err());
        let binding = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [3; 32]);
        let mut bound_coordinates = coordinates;
        bound_coordinates.binding_event_ref = Some(binding.clone());
        let found = arkret_sdk::direct_conversation::DirectConversationResolveOutcome::Found {
            coordinates: bound_coordinates,
            group_state_ref: binding.clone(),
            send_blockers: vec![],
        };
        let authorized = mls_authoring_intent(&intent, &create, &found).unwrap();
        assert_eq!(
            authorized.authorization_ref().unwrap().as_str(),
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1
        );
        assert_eq!(
            authorized.semantic_refs()[0],
            arkret_sdk::SemanticRef::new(binding.to_string(), "direct_conversation_binding")
        );
        let mut message = serde_json::to_value(&intent).unwrap();
        message["kind"] = json!("ak.message.create");
        let message: crate::operation::EventIntent = serde_json::from_value(message).unwrap();
        for (source, reference, role) in [
            (
                arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
                binding.clone(),
                "direct_conversation_binding",
            ),
            (
                arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1,
                create.event_id.clone(),
                "direct_conversation_founding_unit",
            ),
        ] {
            let signed_content = participant_authoring_intent(&message, source, &reference)
                .unwrap()
                .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap();
            assert_eq!(
                signed_content.authorization_ref.as_ref().unwrap().as_str(),
                source.as_str()
            );
            assert_eq!(
                signed_content.semantic_refs,
                vec![arkret_sdk::SemanticRef::new(reference.to_string(), role)]
            );
            assert!(
                participant_authoring_intent(
                    &message.clone().with_executed_by(create.actor_id.clone()),
                    source,
                    &reference
                )
                .is_err()
            );
        }
        assert!(
            participant_authoring_intent(
                &message,
                arkret_wire::AuthoritySourceId::DirectConversationRepairV1,
                &binding
            )
            .is_err()
        );
        let unavailable = arkret_sdk::direct_conversation::DirectConversationResolveOutcome::TemporarilyUnavailable { retry_after_ms:None };
        assert!(mls_authoring_intent(&intent, &create, &unavailable).is_err());
        let mut wrong = found;
        if let arkret_sdk::direct_conversation::DirectConversationResolveOutcome::Found {
            coordinates,
            ..
        } = &mut wrong
        {
            coordinates.realm_id =
                arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap();
        }
        assert!(mls_authoring_intent(&intent, &create, &wrong).is_err());
    }

    #[test]
    fn direct_binding_never_invents_a_missing_founding_prefix() {
        let (bundle, keys, freshness, _) = founding_fixture();
        let empty = crate::models::BackfillView(arkret_wire::StreamScanOutcome {
            committed_events: Vec::new(),
            readable_floor: None,
            truncated: false,
        });
        assert!(
            super::founding_genesis_prefix(
                &empty,
                "ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3",
                &bundle,
                &freshness,
                &keys,
            )
            .is_err()
        );
    }
}
