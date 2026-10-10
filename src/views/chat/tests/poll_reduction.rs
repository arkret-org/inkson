use arkret_identity::RealmAuthorityFreshness;
use arkret_sdk::{
    CommittedEventView, ReadableFloor, ReadableFloorReason, StreamScanDirection, StreamScanOutcome,
    StreamScanRequest,
};

use super::*;
use crate::test_support::committed_event::{
    FixtureStation, fixture_time, verified_realm_fixture_as,
};

const REALM: &str = "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
const STRAND: &str = "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

fn definition_payload() -> Value {
    json!({"strand_id":STRAND,"track_name":"discussion","content":{
        "kind":"ak.content.poll","body":"Ship?","poll":{
            "kind":"disclosed","max_selections":1,"answers":[
                {"id":"yes","text":{"kind":"ak.content.text","body":"Yes"}},
                {"id":"no","text":{"kind":"ak.content.text","body":"No"}}
            ]
        }
    }})
}

fn response_payload(
    poll: &arkret_sdk::EventId,
    choice: &str,
    prior: Option<&arkret_sdk::EventId>,
) -> Value {
    let mut payload = json!({"strand_id":STRAND,"track_name":"discussion","content":{
        "kind":"ak.content.poll.response","body":"Vote","poll_response":{
            "poll_ref":arkret_sdk::MessageId::from_event_id(poll),"selections":[choice]
        }
    }});
    if let Some(prior) = prior {
        payload["poll_response_heads"] =
            json!([{"poll_event_ref":poll,"response_event_ref":prior}]);
    }
    payload
}

fn verified_page(
    foreign_last_station: bool,
    start_at_poll: bool,
) -> (garth::VerifiedScanPage, Vec<Value>) {
    verified_page_variant(foreign_last_station, start_at_poll, false, false)
}

fn verified_page_variant(
    foreign_last_station: bool,
    start_at_poll: bool,
    invalid_last_head: bool,
    withhold_first_response: bool,
) -> (garth::VerifiedScanPage, Vec<Value>) {
    let realm = arkret_sdk::RealmId::new(REALM).unwrap();
    let make = |entries| verified_realm_fixture_as(realm.clone(), entries, "alice.example", DEVICE);
    let kind = "ak.message.create".to_owned();
    let (_, _, first) = make(vec![(kind.clone(), definition_payload())]);
    let poll = first[0].event.event_id.clone();
    let response = response_payload(&poll, "yes", None);
    let (_, _, second) = make(vec![
        (kind.clone(), definition_payload()),
        (kind.clone(), response.clone()),
    ]);
    let prior = second[1].event.event_id.clone();
    let mut last_response =
        response_payload(&poll, "no", (!foreign_last_station).then_some(&prior));
    if invalid_last_head {
        last_response["poll_response_heads"] = json!([{
            "poll_event_ref": arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9;32]),
            "response_event_ref": prior,
        }]);
    }
    let (mut bundle, keys, mut rows) = make(vec![
        (kind.clone(), definition_payload()),
        (kind.clone(), response),
        (kind, last_response),
    ]);
    if foreign_last_station {
        let mut actor = rows[2].event.actor_id.as_account_id().unwrap().clone();
        actor.station_id = arkret_sdk::DidCoreId::new(REMOTE_STATION_ID).unwrap();
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            arkret_sdk::DidUrl::new(format!("did:web:alice.example#{DEVICE}")).unwrap(),
        );
        rows[2].event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            "ak.message.create",
            rows[2].event.scope_ref.clone(),
            arkret_sdk::ActorId::account(actor),
            serde_json::to_value(&rows[2].event.payload).unwrap(),
        )
        .with_created_at(rows[2].event.created_at)
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        rows[2].commit.event_ref = rows[2].event.event_id.clone();
        rows[2].commit = FixtureStation::did_web().seal_commit(rows[2].commit.clone());
        FixtureStation::did_web().reassert_for_nonce(
            &mut bundle,
            arkret_sdk::Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            fixture_time(50),
        );
    }
    let visible = rows
        .iter()
        .map(|row| serde_json::to_value(&row.event).unwrap())
        .collect();
    let mut committed = if start_at_poll {
        Vec::new()
    } else {
        vec![CommittedEventView::Full(
            arkret_sdk::CommittedEventFullView {
                event: bundle.genesis_event.clone(),
                commit: bundle.genesis_commit.clone(),
            },
        )]
    };
    committed.extend(rows.into_iter().map(CommittedEventView::Full));
    if withhold_first_response {
        let row = committed
            .iter_mut()
            .find(|row| row.commit().stream_position == 2)
            .unwrap();
        *row = CommittedEventView::Withheld(arkret_sdk::CommittedEventWithheldView {
            commit: row.commit().clone(),
            event_disclosure: arkret_sdk::EventDisclosure {
                status: arkret_sdk::EventDisclosureStatus::Withheld,
            },
        });
    }
    let stream = bundle.realm_stream_head.stream_ref.clone();
    let nonce = bundle.current_assertion.nonce.clone();
    let freshness = RealmAuthorityFreshness::new(fixture_time(100), nonce.clone());
    let mut replica = garth::RealmReplica::new(realm.clone());
    replica
        .install_verified_authority(
            &arkret_sdk::AuthorityBundleRequest {
                realm_id: realm.clone(),
                nonce,
            },
            bundle,
            &freshness,
            &keys,
        )
        .unwrap();
    let first = committed[0].commit();
    let floor = ReadableFloor {
        oldest_position: first.stream_position,
        floor_commit_id: first.commit_id.clone(),
        floor_reason: if start_at_poll {
            ReadableFloorReason::MembershipJoin
        } else {
            ReadableFloorReason::StreamStart
        },
    };
    let request = StreamScanRequest {
        realm_id: realm,
        stream_ref: stream,
        direction: StreamScanDirection::After(None),
        limit: 100,
    };
    let page = replica
        .apply_verified_scan(
            &request,
            StreamScanOutcome {
                committed_events: committed,
                readable_floor: Some(floor),
                truncated: false,
            },
            &freshness,
            &keys,
        )
        .unwrap();
    (page, visible)
}

fn verified_circle_page() -> (garth::VerifiedScanPage, Value) {
    use arkret_sdk::{
        ActorId, CircleId, CommitStreamRef, CommittedEventFullView, Did, DidCoreId, DidUrl,
        RealmCommit, RealmCommitId, ScopeRef,
    };

    let realm = arkret_sdk::RealmId::new(REALM).unwrap();
    let (bundle, keys, created) = verified_realm_fixture_as(
        realm.clone(),
        vec![(
            "ak.circle.create".to_owned(),
            json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
                "title":"Poll circle","display":{"short_name":"Polls","color_token":"blue",
                    "symbol":{"glyph":"vote"}},"directory_visibility":"members",
                "join_rule":"public","history_access":"all_history_for_current_members",
                "state":"active","created_by":{"kind":"account","principal_id":
                    "ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"},
                "created_at":arkret_sdk::canonical::format_timestamp_canonical(fixture_time(2))}}),
        )],
        "alice.example",
        DEVICE,
    );
    let circle_id = CircleId::from_event_id(&created[0].event.event_id);
    let scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle_id.clone(),
    };
    let stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle_id.clone(),
    };
    let actor = ActorId::account(arkret_sdk::AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let signer = arkret_test_kit::keys::seeded_signer(
        Did::new("did:web:alice.example").unwrap(),
        DidUrl::new(format!("did:web:alice.example#{DEVICE}")).unwrap(),
    );
    let signed = |kind: &str, payload, seconds| {
        arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            kind,
            scope.clone(),
            actor.clone(),
            payload,
        )
        .with_created_at(fixture_time(seconds))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable()
    };
    let membership = signed(
        "ak.circle.member.state",
        json!({"circle_id":circle_id,"member_id":actor,"membership":"join",
            "expected_membership":null}),
        9,
    );
    let poll = signed("ak.message.create", definition_payload(), 10);
    let first = signed(
        "ak.message.create",
        response_payload(&poll.event_id, "yes", None),
        11,
    );
    let changed = signed(
        "ak.message.create",
        response_payload(&poll.event_id, "no", Some(&first.event_id)),
        12,
    );
    let visible_poll = serde_json::to_value(&poll).unwrap();
    let mut previous = None;
    let rows = [membership, poll, first, changed]
        .into_iter()
        .enumerate()
        .map(|(position, event)| {
            let commit = FixtureStation::did_web().seal_commit(RealmCommit {
                commit_id: RealmCommitId::from_digest([0x80 + position as u8; 32]),
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                stream_position: position as u64,
                previous_commit_ref: previous.clone(),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: bundle.genesis_commit.authority_ref.clone(),
                committed_at: fixture_time(60 + position as i64),
                producer_signer_fact_digest: None,
                signature: bundle.genesis_commit.signature.clone(),
            });
            previous = Some(commit.commit_id.clone());
            CommittedEventView::Full(CommittedEventFullView { commit, event })
        })
        .collect::<Vec<_>>();
    let floor_commit_id = rows[0].commit().commit_id.clone();
    let freshness =
        RealmAuthorityFreshness::new(fixture_time(100), bundle.current_assertion.nonce.clone());
    let mut replica = garth::RealmReplica::new(realm.clone());
    replica
        .install_verified_authority(
            &arkret_sdk::AuthorityBundleRequest {
                realm_id: realm.clone(),
                nonce: bundle.current_assertion.nonce.clone(),
            },
            bundle,
            &freshness,
            &keys,
        )
        .unwrap();
    let page = replica
        .apply_verified_scan(
            &StreamScanRequest {
                realm_id: realm,
                stream_ref: stream,
                direction: StreamScanDirection::After(None),
                limit: 100,
            },
            StreamScanOutcome {
                committed_events: rows,
                readable_floor: Some(ReadableFloor {
                    oldest_position: 0,
                    floor_commit_id,
                    floor_reason: ReadableFloorReason::StreamStart,
                }),
                truncated: false,
            },
            &freshness,
            &keys,
        )
        .unwrap();
    (page, visible_poll)
}

#[test]
fn verified_circle_poll_revote_survives_durable_reopen_and_retains_circle_heads() {
    let (page, visible_poll) = verified_circle_page();
    let path = std::env::temp_dir().join(format!("inkson-circle-poll-replay-{}.json", uuid_v7()));
    let mut store = LocalStateStore::with_path(&path);
    store.ingest_verified_message_commits(&page).unwrap();
    store.ingest_verified_message_commits(&page).unwrap();
    let cards = poll_cards_from_events_with_sidecar(
        REALM,
        std::slice::from_ref(&visible_poll),
        Some(&store),
        None,
    );
    assert_eq!(cards.len(), 1);
    assert!(!cards[0].provisional);
    assert_eq!(
        (
            cards[0].votes_for(0),
            cards[0].votes_for(1),
            cards[0].total_votes()
        ),
        (0, 1, 1)
    );
    assert!(matches!(
        cards[0].verified_scope,
        Some(arkret_sdk::ScopeRef::Circle { .. })
    ));
    let winner = page.rows().last().unwrap();
    let actor = winner.reducer_input().unwrap().actor_id.clone();
    assert_eq!(
        cards[0].response_heads[&actor].response_event_ref,
        winner.commit().event_ref
    );
    let heads = super::super::poll_submission::verified_poll_response_heads(
        &cards[0],
        cards[0].poll_ref.as_ref().unwrap(),
        &actor,
    )
    .unwrap();
    assert_eq!(heads[0].response_event_ref, winner.commit().event_ref);
    let arkret_sdk::ScopeRef::Circle { circle_id, .. } = cards[0].verified_scope.as_ref().unwrap()
    else {
        unreachable!("the verified poll came from the Circle stream")
    };
    let next_vote = crate::messaging::polls::build_poll_vote_op_with_heads_scoped(
        REALM,
        actor.signing_principal_id().as_str(),
        STRAND,
        Some(circle_id.as_str()),
        cards[0].poll_ref.as_ref().unwrap().as_str(),
        &["yes".to_owned()],
        heads.clone(),
    )
    .unwrap();
    assert_eq!(
        next_vote.intent().scope_ref(),
        cards[0].verified_scope.as_ref().unwrap()
    );
    assert_eq!(next_vote.payload()["poll_response_heads"], json!(heads));
    let mut state = store.load();
    assert_eq!(state.verified_poll_inputs.len(), 3);
    state.verified_poll_inputs.reverse();
    store.save(state);
    drop(store);
    let reopened = LocalStateStore::with_path(&path);
    assert_eq!(
        poll_cards_from_events_with_sidecar(REALM, &[visible_poll], Some(&reopened), None),
        cards
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn verified_poll_revote_survives_reverse_replay_and_durable_reopen() {
    let (page, visible) = verified_page(false, false);
    let path = std::env::temp_dir().join(format!("inkson-verified-poll-replay-{}.json", uuid_v7()));
    let mut store = LocalStateStore::with_path(&path);
    store.ingest_verified_message_commits(&page).unwrap();
    store.ingest_verified_message_commits(&page).unwrap();
    let cards = poll_cards_from_events_with_sidecar(REALM, &visible[..1], Some(&store), None);
    assert_eq!(cards.len(), 1);
    assert!(!cards[0].provisional);
    assert_eq!(
        (
            cards[0].votes_for(0),
            cards[0].votes_for(1),
            cards[0].total_votes()
        ),
        (0, 1, 1)
    );
    let actor = page
        .rows()
        .last()
        .unwrap()
        .reducer_input()
        .unwrap()
        .actor_id
        .clone();
    let winner = &cards[0].response_heads[&actor];
    assert_eq!(
        winner.response_event_ref,
        page.rows().last().unwrap().commit().event_ref
    );
    let heads = super::super::poll_submission::verified_poll_response_heads(
        &cards[0],
        cards[0].poll_ref.as_ref().unwrap(),
        &actor,
    )
    .unwrap();
    let operation = crate::messaging::polls::build_poll_vote_op_with_heads(
        REALM,
        actor.signing_principal_id().as_str(),
        STRAND,
        cards[0].poll_ref.as_ref().unwrap().as_str(),
        &["yes".to_owned()],
        heads.clone(),
    )
    .unwrap();
    assert_eq!(operation.payload()["poll_response_heads"], json!(heads));
    let mut state = store.load();
    assert_eq!(state.verified_poll_inputs.len(), 3);
    state.verified_poll_inputs.reverse();
    store.save(state);
    drop(store);
    let reopened = LocalStateStore::with_path(&path);
    assert_eq!(
        poll_cards_from_events_with_sidecar(REALM, &visible[..1], Some(&reopened), None),
        cards
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn poll_created_at_authorized_join_floor_is_complete_and_full_account_partitions_stay_distinct() {
    let (page, visible) = verified_page(true, true);
    let mut store = crate::state::isolated_store_for_tests("verified-poll-membership-floor");
    store.ingest_verified_message_commits(&page).unwrap();
    let cards = poll_cards_from_events_with_sidecar(REALM, &visible[..1], Some(&store), None);
    assert_eq!(cards.len(), 1);
    assert!(!cards[0].provisional);
    assert_eq!(
        (
            cards[0].votes_for(0),
            cards[0].votes_for(1),
            cards[0].total_votes()
        ),
        (1, 1, 2)
    );
    assert_eq!(cards[0].response_heads.len(), 2);
}

#[test]
fn shape_only_rows_never_supply_poll_tally_or_revote_heads() {
    let (_page, visible) = verified_page(false, false);
    let store = crate::state::isolated_store_for_tests("unverified-poll-timeline");
    let cards = poll_cards_from_events_with_sidecar(REALM, &visible, Some(&store), None);
    assert_eq!(cards.len(), 1);
    assert!(cards[0].provisional);
    assert_eq!(cards[0].total_votes(), 0);
    assert!(cards[0].response_heads.is_empty());
    let actor =
        serde_json::from_value::<arkret_sdk::ActorId>(visible[0]["actor_id"].clone()).unwrap();
    assert!(
        super::super::poll_submission::verified_poll_response_heads(
            &cards[0],
            cards[0].poll_ref.as_ref().unwrap(),
            &actor
        )
        .is_err()
    );
}

#[test]
fn invalid_signed_replacement_head_is_quarantined_and_withheld_history_retracts_the_vote() {
    let (invalid, visible) = verified_page_variant(false, false, true, false);
    let mut store = crate::state::isolated_store_for_tests("verified-poll-invalid-head");
    store.ingest_verified_message_commits(&invalid).unwrap();
    let cards = poll_cards_from_events_with_sidecar(REALM, &visible[..1], Some(&store), None);
    assert_eq!((cards[0].votes_for(0), cards[0].votes_for(1)), (1, 0));
    assert_eq!(
        cards[0]
            .response_heads
            .values()
            .next()
            .unwrap()
            .response_event_ref,
        invalid
            .rows()
            .iter()
            .find(|row| row.commit().stream_position == 2)
            .unwrap()
            .commit()
            .event_ref
    );
    let (withheld, visible) = verified_page_variant(false, false, true, true);
    store.ingest_verified_message_commits(&withheld).unwrap();
    let cards = poll_cards_from_events_with_sidecar(REALM, &visible[..1], Some(&store), None);
    assert!(cards[0].provisional);
    assert_eq!(cards[0].total_votes(), 0);
    assert!(cards[0].response_heads.is_empty());
    assert_eq!(store.verified_poll_inputs().len(), 2);
}
