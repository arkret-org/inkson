use arkret_sdk::{CurrentRevision, RealmCommitId};
use serde_json::{Value, json};

use super::*;

fn realm() -> RealmId {
    RealmId::from_event_id(&event_id(1))
}

fn event_id(byte: u8) -> arkret_sdk::EventId {
    arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32])
}

fn call() -> CallId {
    CallId::from_event_id(&event_id(2))
}

fn account_actor(station: &str) -> ActorId {
    ActorId::account(arkret_sdk::AccountId::new(
        "ak:did_core:web:alice.example".parse().unwrap(),
        station.parse().unwrap(),
    ))
}

fn revision(position: u8) -> CurrentRevision {
    CurrentRevision {
        commit_id: RealmCommitId::from_digest([position; 32]),
        stream_position: u64::from(position),
    }
}

fn entry(selector: CurrentSelector, position: u8, value: Value) -> CurrentState {
    CurrentState::Value {
        selector,
        source_stream_ref: arkret_sdk::CommitStreamRef::Realm { realm_id: realm() },
        revision: revision(position),
        value,
    }
}

// These rows exercise selection from an already accepted disclosure. They do
// not stand in for the transport's independent bound-snapshot verification.
fn current() -> Vec<CurrentState> {
    vec![
        entry(
            CurrentSelector::CallState { call_id: call() },
            3,
            json!({
                "from": "connecting", "to": "active"
            }),
        ),
        entry(
            CurrentSelector::CallFocus { call_id: call() },
            4,
            json!({
                "mode": "sfu", "session_focus": "focus-a"
            }),
        ),
        entry(
            CurrentSelector::RealmMediaService,
            5,
            json!({
                "service_id": "ak:did_core:web:media.example",
                "foci": [{
                    "focus_id": "focus-a", "focus_kind": "arkret_native",
                    "token_endpoint": "https://media.example/token",
                    "connect_url": "wss://media.example/rtc"
                }],
                "recording_supported": true
            }),
        ),
        entry(
            CurrentSelector::MlsGroup {
                scope_ref: ScopeRef::Realm { realm_id: realm() },
            },
            6,
            json!({"effective_scope":{"kind":"realm","realm_id":realm()},
                "genesis_event_ref":event_id(11),
                "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "current_mls_commit_event_ref":event_id(12),"epoch":"3",
                "current_key_access_revision":"2","covered_key_access_revision":"2",
                "public_tree_ref":format!("ak:blob:sha256:{}", "11".repeat(32))}),
        ),
    ]
}

fn replace_value(rows: &mut [CurrentState], index: usize, value: Value) {
    let CurrentState::Value {
        value: original, ..
    } = &mut rows[index];
    *original = value;
}

fn grant_snapshot(
    subject: ActorId,
    action: arkret_sdk::CapabilityActionId,
) -> arkret_sdk::EffectiveGrantSnapshot {
    let root_event = event_id(7);
    let grant = arkret_sdk::CapabilityGrant {
        id: GrantId::from_event_id(&event_id(8)),
        schema: "ak.schema.capability.v1".to_owned(),
        realm_id: Some(realm()),
        issuer_id: account_actor("ak:did_core:web:station.example"),
        subject: arkret_sdk::CapabilitySubject::Actor(subject),
        actions: vec![action.as_str().to_owned()],
        resources: vec![arkret_sdk::WireResourceSelector::realm(realm())],
        constraints: vec![],
        issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmRoot {
            realm_id: realm(),
            authority_event_ref: root_event.clone(),
            authority_generation: 1,
        }],
        authority_depth: 1,
        authority_root_ref: arkret_sdk::AuthorityRootRef::RealmRoot {
            realm_id: realm(),
            authority_event_ref: root_event,
            authority_generation: 1,
        },
        issued_at: "2026-11-15T00:00:00Z".parse().unwrap(),
        status: arkret_sdk::CapabilityGrantStatus::Active,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: None,
    };
    arkret_sdk::EffectiveGrantSnapshot {
        grants: vec![arkret_sdk::EffectiveCapabilityGrantView {
            grant,
            revision: revision(8),
        }],
        state_digest: arkret_sdk::Hash::new(
            arkret_sdk::canonical::canonical_sha256(&"grants").unwrap(),
        )
        .unwrap(),
        evaluated_at: "2026-11-15T00:00:01Z".parse().unwrap(),
    }
}

fn signed(operation: crate::operation::LocalOperation) -> arkret_sdk::AuthoredEvent {
    let mut event = crate::operation::author_for_test(&operation);
    crate::event_signer::build_ed25519_device_signer(
        [43; 32],
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
    )
    .sign_sdk_event_with_context(
        &mut event,
        crate::event_signer::ProducerProofContext::new()
            .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
    )
    .unwrap();
    event.verify_identity().unwrap();
    event
        .validate_proof_bindings_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .unwrap();
    arkret_event_draft::validate_event_for_submit(&event).unwrap();
    event
}

#[test]
fn start_uses_exact_actor_grant_media_and_signed_ingress() {
    let actor = account_actor("ak:did_core:web:station.example");
    for kind in [
        RecordingCaptureKind::Recording,
        RecordingCaptureKind::Transcript,
    ] {
        let source = call_capture_source(&realm(), &call(), &current(), kind).unwrap();
        let rows = grant_snapshot(actor.clone(), capture_action(kind));
        let grant = select_capture_grant(&rows, &actor, &source.scope, kind).unwrap();
        assert_eq!(grant, rows.grants[0].grant.id);
        assert!(
            crate::webrtc::build_call_recording_start(
                &source.scope,
                &actor,
                &call(),
                &CallRecordingId::new("segment-1").unwrap(),
                &grant,
                &source.recorder,
                source.key_ref.as_ref(),
                kind,
                arkret_sdk::RecordingMode::AudioOnly,
                false,
            )
            .is_err()
        );
        let operation = crate::webrtc::build_call_recording_start(
            &source.scope,
            &actor,
            &call(),
            &CallRecordingId::new("segment-1").unwrap(),
            &grant,
            &source.recorder,
            source.key_ref.as_ref(),
            kind,
            arkret_sdk::RecordingMode::AudioOnly,
            true,
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        let event = signed(operation);
        assert_eq!(event.actor_id, actor);
        assert_eq!(
            event.authorization_ref.as_ref().unwrap().as_str(),
            grant.as_str()
        );
        assert_eq!(
            event.payload["recording_agent_id"],
            "ak:did_core:web:media.example"
        );
        assert_eq!(event.payload["visible_notice"], true);
        if kind == RecordingCaptureKind::Recording {
            assert_eq!(
                event.payload["capture_metadata"]["key_ref"],
                serde_json::to_value(source.key_ref.as_ref().unwrap()).unwrap()
            );
            let mut changed = event.clone().into_event();
            changed.payload.get_mut("capture_metadata").unwrap()["key_ref"]["group_state_ref"] =
                json!(event_id(13));
            assert!(
                changed
                    .verify_event_id_matches_content_with_digest_suite(
                        arkret_sdk::DigestSuite::Sha256
                    )
                    .is_err()
            );
        } else {
            assert!(source.key_ref.is_none());
            assert!(event.payload["capture_metadata"].get("key_ref").is_none());
        }
        let mut missing = event.clone().into_event();
        missing.authorization_ref = None;
        assert!(arkret_event_draft::validate_event_for_submit(&missing).is_err());
        let mut swapped = event.into_event();
        swapped.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new(GrantId::from_event_id(&event_id(9)).as_str())
                .unwrap(),
        );
        assert!(
            swapped
                .verify_event_id_matches_content_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .is_err()
        );
    }
}

#[test]
fn start_requires_active_focus_and_real_current_media_source() {
    for index in 0..4 {
        let mut rows = current();
        rows.remove(index);
        assert!(
            call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
        );
    }
    let mut rows = current();
    replace_value(&mut rows, 0, json!({"from": "ringing", "to": "connecting"}));
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
    replace_value(&mut rows, 0, json!({"from": "connecting", "to": "active"}));
    replace_value(
        &mut rows,
        1,
        json!({"mode": "sfu", "session_focus": "different-focus"}),
    );
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
    let mut rows = current();
    let CurrentState::Value {
        source_stream_ref, ..
    } = &mut rows[2];
    *source_stream_ref = arkret_sdk::CommitStreamRef::Realm {
        realm_id: RealmId::from_event_id(&event_id(99)),
    };
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
    let mut rows = current();
    rows.push(rows[1].clone());
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
}

#[test]
fn transcript_has_its_own_action_and_does_not_borrow_recording_support() {
    let mut rows = current();
    let CurrentState::Value { value, .. } = &mut rows[2];
    value["recording_supported"] = json!(false);
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Transcript).is_ok()
    );
    let actor = account_actor("ak:did_core:web:station.example");
    let source =
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Transcript).unwrap();
    let recording = grant_snapshot(actor.clone(), arkret_sdk::CapabilityActionId::CallRecord);
    assert!(
        select_capture_grant(
            &recording,
            &actor,
            &source.scope,
            RecordingCaptureKind::Transcript
        )
        .is_err()
    );
}

#[test]
fn recording_q_requires_one_current_source_in_the_exact_call_scope() {
    let selected = call_capture_source(
        &realm(),
        &call(),
        &current(),
        RecordingCaptureKind::Recording,
    )
    .unwrap();
    assert_eq!(
        selected
            .key_ref
            .unwrap()
            .group_state_ref
            .event_id()
            .unwrap(),
        event_id(12)
    );
    let mut missing = current();
    missing.remove(3);
    assert!(
        call_capture_source(&realm(), &call(), &missing, RecordingCaptureKind::Recording).is_err()
    );
    // Transcript has no registered recording Q and does not borrow one.
    let transcript = call_capture_source(
        &realm(),
        &call(),
        &missing,
        RecordingCaptureKind::Transcript,
    )
    .unwrap();
    assert!(transcript.key_ref.is_none());
    let mut duplicate = current();
    duplicate.push(duplicate[3].clone());
    assert!(
        call_capture_source(
            &realm(),
            &call(),
            &duplicate,
            RecordingCaptureKind::Recording
        )
        .is_err()
    );
    for axis in 0..5 {
        let mut wrong = current();
        let CurrentState::Value {
            source_stream_ref,
            value,
            ..
        } = &mut wrong[3];
        match axis {
            0 => {
                *source_stream_ref = arkret_sdk::CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&event_id(90)),
                }
            }
            1 => {
                value["effective_scope"]["realm_id"] = json!(RealmId::from_event_id(&event_id(90)))
            }
            2 => value["covered_key_access_revision"] = json!("1"),
            3 => {
                value["cipher_suite"] = json!("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519")
            }
            4 => value["epoch"] = json!("0"),
            _ => unreachable!(),
        }
        assert!(
            call_capture_source(&realm(), &call(), &wrong, RecordingCaptureKind::Recording)
                .is_err(),
            "axis {axis}"
        );
    }
}

#[test]
fn recording_current_winner_and_revision_are_fenced_between_real_snapshot_reads() {
    let before = call_capture_source(
        &realm(),
        &call(),
        &current(),
        RecordingCaptureKind::Recording,
    )
    .unwrap();
    before
        .require_unchanged(
            &call_capture_source(
                &realm(),
                &call(),
                &current(),
                RecordingCaptureKind::Recording,
            )
            .unwrap(),
        )
        .unwrap();
    for axis in 0..5 {
        let mut after = current();
        let CurrentState::Value {
            revision: source_revision,
            value,
            ..
        } = &mut after[3];
        match axis {
            0 => value["current_mls_commit_event_ref"] = json!(event_id(13)),
            1 => value["epoch"] = json!("4"),
            2 => value["genesis_event_ref"] = json!(event_id(14)),
            3 => value["public_tree_ref"] = json!(format!("ak:blob:sha256:{}", "22".repeat(32))),
            4 => *source_revision = revision(9),
            _ => unreachable!(),
        }
        let next = call_capture_source(&realm(), &call(), &after, RecordingCaptureKind::Recording)
            .unwrap();
        assert!(before.require_unchanged(&next).is_err(), "axis {axis}");
    }
    let before_transcript = call_capture_source(
        &realm(),
        &call(),
        &current(),
        RecordingCaptureKind::Transcript,
    )
    .unwrap();
    let mut after = current();
    after.remove(3);
    before_transcript
        .require_unchanged(
            &call_capture_source(&realm(), &call(), &after, RecordingCaptureKind::Transcript)
                .unwrap(),
        )
        .unwrap();
}

#[test]
fn circle_recording_uses_circle_winner_without_falling_back_to_realm_mls() {
    let circle = arkret_sdk::CircleId::from_event_id(&event_id(91));
    let stream = arkret_sdk::CommitStreamRef::Circle {
        realm_id: realm(),
        circle_id: circle,
    };
    let mut rows = current();
    let realm_mls = rows[3].clone();
    for index in [0, 1, 3] {
        let CurrentState::Value {
            source_stream_ref, ..
        } = &mut rows[index];
        *source_stream_ref = stream.clone();
    }
    let CurrentState::Value { selector, .. } = &mut rows[3];
    *selector = CurrentSelector::MlsGroup {
        scope_ref: stream.scope_ref(),
    };
    // An exact selector with a foreign value is not a qualified source.
    assert!(
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).is_err()
    );
    let CurrentState::Value { value, .. } = &mut rows[3];
    value["effective_scope"] = serde_json::to_value(stream.scope_ref()).unwrap();
    rows.push(realm_mls);
    let selected =
        call_capture_source(&realm(), &call(), &rows, RecordingCaptureKind::Recording).unwrap();
    assert_eq!(selected.scope, stream.scope_ref());
    assert_eq!(
        selected
            .key_ref
            .unwrap()
            .group_state_ref
            .event_id()
            .unwrap(),
        event_id(12)
    );
}

#[test]
fn grant_selection_rejects_wrong_account_action_resource_or_missing_source() {
    let actor = account_actor("ak:did_core:web:station.example");
    let scope = ScopeRef::Realm { realm_id: realm() };
    let rows = grant_snapshot(actor.clone(), arkret_sdk::CapabilityActionId::CallRecord);
    let foreign = account_actor("ak:did_core:web:other-station.example");
    assert!(
        select_capture_grant(&rows, &foreign, &scope, RecordingCaptureKind::Recording).is_err()
    );
    assert!(select_capture_grant(&rows, &actor, &scope, RecordingCaptureKind::Transcript).is_err());
    let mut missing = rows.clone();
    missing.grants.clear();
    assert!(
        select_capture_grant(&missing, &actor, &scope, RecordingCaptureKind::Recording).is_err()
    );
    let mut wrong = rows.clone();
    wrong.grants[0].grant.resources = vec![arkret_sdk::WireResourceSelector::realm(
        RealmId::from_event_id(&event_id(99)),
    )];
    assert!(select_capture_grant(&wrong, &actor, &scope, RecordingCaptureKind::Recording).is_err());
    let mut repeated = rows;
    repeated.grants.push(repeated.grants[0].clone());
    assert!(
        select_capture_grant(&repeated, &actor, &scope, RecordingCaptureKind::Recording).is_err()
    );
}

#[test]
fn stop_submits_only_its_native_axis_without_retired_guard_or_start_grant() {
    let actor = account_actor("ak:did_core:web:station.example");
    let id = CallRecordingId::new("segment-1").unwrap();
    let scope = ScopeRef::Realm { realm_id: realm() };
    for (kind, axis, other, from) in [
        (
            RecordingCaptureKind::Recording,
            "recording_transition",
            "transcript_transition",
            "recording",
        ),
        (
            RecordingCaptureKind::Transcript,
            "transcript_transition",
            "recording_transition",
            "transcribing",
        ),
    ] {
        let operation = crate::webrtc::build_call_capture_stop(&scope, &actor, &call(), &id, kind)
            .unwrap()
            .build_sdk_event("inkson")
            .unwrap();
        let event = signed(operation);
        assert!(event.authorization_ref.is_none());
        assert_eq!(event.payload[axis]["recording_id"], id.as_str());
        assert_eq!(event.payload[axis]["from"], from);
        assert_eq!(event.payload[axis]["to"], "stopped");
        assert!(event.payload[axis].get("expected_commit_id").is_none());
        assert!(!event.payload.contains_key(other));
        let mut rows = current();
        let selector = if kind == RecordingCaptureKind::Recording {
            CurrentSelector::CallRecordingState {
                call_id: call(),
                recording_id: id.clone(),
            }
        } else {
            CurrentSelector::CallTranscriptState {
                call_id: call(),
                recording_id: id.clone(),
            }
        };
        assert!(capture_segment_is_stopped(&realm(), &call(), &rows, &id, kind).is_err());
        let capture_index = rows.len();
        rows.push(entry(selector, 7, json!(from)));
        assert!(!capture_segment_is_stopped(&realm(), &call(), &rows, &id, kind).unwrap());
        assert_eq!(
            active_capture_segments(&realm(), &call(), &rows, kind)
                .unwrap()
                .as_slice(),
            std::slice::from_ref(&id)
        );
        replace_value(&mut rows, capture_index, json!("stopped"));
        assert!(capture_segment_is_stopped(&realm(), &call(), &rows, &id, kind).unwrap());
        for artifact_status in ["ready", "failed"] {
            replace_value(&mut rows, capture_index, json!(artifact_status));
            assert!(capture_segment_is_stopped(&realm(), &call(), &rows, &id, kind).is_err());
            assert!(active_capture_segments(&realm(), &call(), &rows, kind).is_err());
        }
    }
}

#[test]
fn queued_or_rejected_stop_never_reports_native_stopped() {
    let id = event_id(10).to_string();
    assert!(
        !CallCaptureStopOutcome::Submitted(Box::new(EventSubmissionProgress::queued(id.clone())))
            .is_stopped()
    );
    assert!(
        !CallCaptureStopOutcome::Submitted(Box::new(EventSubmissionProgress::rejected(
            id,
            "forbidden".to_owned()
        )))
        .is_stopped()
    );
    assert!(CallCaptureStopOutcome::ObservedStopped.is_stopped());
    let missing_commit = EventSubmissionProgress {
        event_id: event_id(10).to_string(),
        status: garth::SendQueueStatus::Committed,
        commit: None,
        rejection_reason_code: None,
    };
    assert!(!CallCaptureStopOutcome::Submitted(Box::new(missing_commit)).is_stopped());
    let operation = crate::webrtc::build_call_capture_stop(
        &ScopeRef::Realm { realm_id: realm() },
        &account_actor("ak:did_core:web:station.example"),
        &call(),
        &CallRecordingId::new("segment-1").unwrap(),
        RecordingCaptureKind::Recording,
    )
    .unwrap()
    .build_sdk_event("inkson")
    .unwrap();
    let event = signed(operation);
    // The submitter verifies actual authority signatures. This structural
    // receipt only tests its local progress-to-visible-state binding.
    let commit = arkret_wire::test_support::structural_realm_commit_at(
        &event,
        realm(),
        11,
        arkret_sdk::DidUrl::new("did:web:station.example#key-1").unwrap(),
        "2026-11-15T00:00:02Z".parse().unwrap(),
    );
    assert!(
        !CallCaptureStopOutcome::Submitted(Box::new(EventSubmissionProgress::committed(
            event_id(99).to_string(),
            commit.clone(),
        )))
        .is_stopped()
    );
    assert!(
        CallCaptureStopOutcome::Submitted(Box::new(EventSubmissionProgress::committed(
            event.event_id().to_string(),
            commit,
        )))
        .is_stopped()
    );
}
