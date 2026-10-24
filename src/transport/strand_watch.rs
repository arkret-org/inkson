//! Self watch writes use the Station's exact current value as their CAS preimage.

use arkret_sdk::{
    StrandWatchCurrentRequestBody, StrandWatchCurrentResponseBody, StrandWatchLevel,
    StrandWatchSetPayload, StrandWatchValue,
};

pub(crate) fn payload_from_current(
    request: &StrandWatchCurrentRequestBody,
    current: &StrandWatchCurrentResponseBody,
    level: Option<StrandWatchLevel>,
) -> anyhow::Result<StrandWatchSetPayload> {
    anyhow::ensure!(
        request.watcher_actor_id.as_account_id().is_some(),
        "self watch requires a complete Account Actor"
    );
    current
        .validate_for_request(request)
        .map_err(anyhow::Error::msg)?;
    let head = match current {
        StrandWatchCurrentResponseBody::NeverWritten { stream_head, .. }
        | StrandWatchCurrentResponseBody::Current { stream_head, .. } => stream_head,
    };
    anyhow::ensure!(
        matches!(&head.stream_ref,
        arkret_sdk::CommitStreamRef::Realm { realm_id } if realm_id == &request.realm_id),
        "self watch requires a current Realm-stream cut"
    );
    let publication = match current {
        StrandWatchCurrentResponseBody::Current {
            current_state: result,
            ..
        } => match result.value {
            StrandWatchValue::Set(value) => value.level_public,
            StrandWatchValue::Cleared(()) => None,
        },
        StrandWatchCurrentResponseBody::NeverWritten { .. } => None,
    };
    let mut payload = match level {
        Some(level) => StrandWatchSetPayload::set(
            request.strand_id.clone(),
            request.watcher_actor_id.clone(),
            level,
            publication,
        ),
        None => StrandWatchSetPayload::clear(
            request.strand_id.clone(),
            request.watcher_actor_id.clone(),
        ),
    };
    // A written null is a CAS value; it must never become an omitted guard.
    if let StrandWatchCurrentResponseBody::Current {
        current_state: result,
        ..
    } = current
    {
        payload = payload.with_expected_value(result.value);
    }
    Ok(payload)
}

pub(crate) fn current_level(current: &StrandWatchCurrentResponseBody) -> StrandWatchLevel {
    match current {
        StrandWatchCurrentResponseBody::Current {
            current_state: result,
            ..
        } => match result.value {
            StrandWatchValue::Set(value) => value.level,
            StrandWatchValue::Cleared(()) => StrandWatchLevel::MentionsOnly,
        },
        StrandWatchCurrentResponseBody::NeverWritten { .. } => StrandWatchLevel::MentionsOnly,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("watch current observation crossed its exact own Station cut")]
struct WatchCutChanging;

fn validate_own_observation(
    current: &StrandWatchCurrentResponseBody,
    before: &arkret_sdk::RealmStateSnapshot,
    after: &arkret_sdk::RealmStateSnapshot,
) -> anyhow::Result<()> {
    let (realm, generation, head) = match current {
        StrandWatchCurrentResponseBody::NeverWritten {
            realm_id,
            governance_generation,
            stream_head,
            ..
        }
        | StrandWatchCurrentResponseBody::Current {
            realm_id,
            governance_generation,
            stream_head,
            ..
        } => (realm_id, *governance_generation, stream_head),
    };
    let before_head = before
        .visible_stream_heads
        .iter()
        .find(|candidate| candidate.stream_ref == head.stream_ref)
        .ok_or_else(|| anyhow::anyhow!("watch current has no original Realm head"))?;
    let after_head = after
        .visible_stream_heads
        .iter()
        .find(|candidate| candidate.stream_ref == head.stream_ref)
        .ok_or_else(|| anyhow::anyhow!("watch current has no original Realm head"))?;
    anyhow::ensure!(
        before.realm_id == *realm
            && after.realm_id == *realm
            && before.governance_generation == after.governance_generation
            && generation == after.governance_generation,
        "watch current observation crossed a Realm or governance generation"
    );
    if before_head != after_head || head != after_head {
        return Err(WatchCutChanging.into());
    }
    if let StrandWatchCurrentResponseBody::Current {
        current_state: result,
        ..
    } = current
    {
        let original = serde_json::to_value(result)?;
        anyhow::ensure!(
            after
                .current_state_entries
                .iter()
                .any(|row| serde_json::to_value(row).ok().as_ref() == Some(&original)),
            "watch current differs from the original same-cut row"
        );
    }
    Ok(())
}

pub(crate) async fn read(
    http: &arkret_sdk::http_client::Client,
    request: &StrandWatchCurrentRequestBody,
) -> anyhow::Result<StrandWatchCurrentResponseBody> {
    // Only reobserve a changing read cut. No Event has been authored here;
    // submission refusal, unknown outcome and whole-value CAS are never retried.
    for attempt in 0..3 {
        match read_once(http, request).await {
            Err(error) if error.is::<WatchCutChanging>() && attempt < 2 => {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                    100 * (attempt + 1),
                ))
                .await;
            }
            result => return result,
        }
    }
    unreachable!("the final read attempt always returns")
}

async fn read_once(
    http: &arkret_sdk::http_client::Client,
    request: &StrandWatchCurrentRequestBody,
) -> anyhow::Result<StrandWatchCurrentResponseBody> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    anyhow::ensure!(
        request.watcher_actor_id.as_account_id() == Some(client.session()?.account_id()),
        "watch cell is not the current complete account"
    );
    crate::event_submit::ensure_strand_watch_settled(client.session()?.account_id(), request)
        .await?;
    client.check_session()?;
    let before = client.snapshot_head(&request.realm_id).await?;
    garth::own_station_results::consume_bound_snapshot(&before, &request.realm_id)?;
    client.check_session()?;
    let current = http.strand_watch_current(request).await?;
    client.check_session()?;
    payload_from_current(request, &current, None)?;
    let after = client.snapshot_head(&request.realm_id).await?;
    garth::own_station_results::consume_bound_snapshot(&after, &request.realm_id)?;
    let before = before.value()?;
    let after = after.value()?;
    validate_own_observation(&current, before, after)?;
    client.check_session()?;
    Ok(current)
}

pub(crate) async fn write(
    http: &arkret_sdk::http_client::Client,
    request: &StrandWatchCurrentRequestBody,
    level: Option<StrandWatchLevel>,
) -> anyhow::Result<StrandWatchCurrentResponseBody> {
    let before = read(http, request).await?;
    let payload = payload_from_current(request, &before, level)?;
    let operation =
        crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandWatchSet>(
            request.realm_id.as_str(),
            request.watcher_actor_id.signing_principal_id().as_str(),
            payload,
        )
        .target_ref(request.strand_id.as_str())
        .build_sdk_event("inkson")?;
    anyhow::ensure!(
        operation.actor_id() == &request.watcher_actor_id
            && operation.intent().scope_ref()
                == &arkret_sdk::ScopeRef::Realm {
                    realm_id: request.realm_id.clone()
                },
        "watch producer Actor or effective scope differs from the observed self cell"
    );
    let accepted = crate::app::runtime_adapter::event_submitter(http.clone())
        .submit_sdk_event(&operation)
        .await?;
    anyhow::ensure!(accepted.is_committed(), "watch submission is not committed");
    let commit = accepted
        .commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("watch submission omits Commit"))?;
    let after = read(http, request).await?;
    let StrandWatchCurrentResponseBody::Current {
        governance_generation,
        stream_head,
        current_state: result,
        ..
    } = &after
    else {
        anyhow::bail!("accepted watch write has no durable current result");
    };
    let before_generation = match before {
        StrandWatchCurrentResponseBody::NeverWritten {
            governance_generation,
            ..
        }
        | StrandWatchCurrentResponseBody::Current {
            governance_generation,
            ..
        } => governance_generation,
    };
    anyhow::ensure!(
        *governance_generation == before_generation
            && commit.governance_generation == before_generation,
        "watch write crossed a governance generation"
    );
    anyhow::ensure!(
        result.source_stream_ref == stream_head.stream_ref,
        "watch readback source differs from stream head"
    );
    anyhow::ensure!(
        result.source_stream_ref == commit.stream_ref
            && result.revision.stream_position >= commit.stream_position
            && (result.revision.stream_position != commit.stream_position
                || result.revision.commit_id == commit.commit_id),
        "watch readback does not cover the accepted Commit"
    );
    Ok(after)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn observation(
        value: Option<serde_json::Value>,
    ) -> (
        StrandWatchCurrentRequestBody,
        StrandWatchCurrentResponseBody,
        arkret_sdk::RealmAuthorityBundle,
    ) {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q")
                .unwrap();
        let strand =
            arkret_sdk::StrandId::new("ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c")
                .unwrap();
        let (bundle, _, rows) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm.clone(),
            vec![(
                "ak.message.create".to_owned(),
                json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","body":"fixture"}}),
            )],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let realm = bundle.realm_id.clone();
        let request = StrandWatchCurrentRequestBody {
            realm_id: realm.clone(),
            strand_id: strand.clone(),
            watcher_actor_id: rows[0].event.actor_id.clone(),
        };
        let selector = json!({"kind":"strand_watch","strand_id":strand,"watcher_actor_id":request.watcher_actor_id});
        let current = match value {
            None => {
                json!({"status":"never_written","realm_id":realm,"governance_generation":bundle.current_generation.to_string(),"stream_head":bundle.realm_stream_head,"selector":selector})
            }
            Some(value) => {
                json!({"status":"current","realm_id":realm,"governance_generation":bundle.current_generation.to_string(),"stream_head":bundle.realm_stream_head,"current_state":{
                "selector":selector,"source_stream_ref":rows[0].commit.stream_ref,
                "revision":{"commit_id":rows[0].commit.commit_id,"stream_position":rows[0].commit.stream_position},"value":value}})
            }
        };
        (request, serde_json::from_value(current).unwrap(), bundle)
    }

    #[test]
    fn exact_current_preimages_keep_never_written_cleared_and_public_flag_distinct() {
        let (request, never, _) = observation(None);
        let first = payload_from_current(&request, &never, Some(StrandWatchLevel::All)).unwrap();
        assert!(
            !serde_json::to_value(first)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("expected_value")
        );
        let (request, cleared, _) = observation(Some(serde_json::Value::Null));
        let reset = serde_json::to_value(
            payload_from_current(&request, &cleared, Some(StrandWatchLevel::All)).unwrap(),
        )
        .unwrap();
        assert_eq!(reset.get("expected_value"), Some(&serde_json::Value::Null));
        let (request, set, _) = observation(Some(json!({"level":"all","level_public":true})));
        let update = payload_from_current(&request, &set, Some(StrandWatchLevel::Muted)).unwrap();
        assert_eq!(update.level_public, Some(true));
        let (request_private, private, _) =
            observation(Some(json!({"level":"all","level_public":false})));
        assert_eq!(
            payload_from_current(&request_private, &private, Some(StrandWatchLevel::All))
                .unwrap()
                .level_public,
            Some(false)
        );
        assert!(
            payload_from_current(&request, &cleared, Some(StrandWatchLevel::All))
                .unwrap()
                .level_public
                .is_none()
        );
        let clear =
            serde_json::to_value(payload_from_current(&request, &set, None).unwrap()).unwrap();
        assert_eq!(
            clear["expected_value"],
            json!({"level":"all","level_public":true})
        );
        assert_eq!(clear["level"], serde_json::Value::Null);
        assert!(clear.get("level_public").is_none());
        assert_eq!(current_level(&never), StrandWatchLevel::MentionsOnly);
        assert_eq!(current_level(&cleared), StrandWatchLevel::MentionsOnly);
    }

    #[test]
    fn self_watch_rejects_other_station_actor_and_circle_cut() {
        let (mut request, current, _) = observation(None);
        let mut account = request.watcher_actor_id.as_account_id().unwrap().clone();
        account.station_id = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        request.watcher_actor_id = arkret_sdk::ActorId::account(account);
        assert!(payload_from_current(&request, &current, None).is_err());
        let (request, current, _) = observation(None);
        let mut wire = serde_json::to_value(current).unwrap();
        wire["stream_head"]["stream_ref"] = json!({"kind":"circle","realm_id":request.realm_id,
            "circle_id":arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[7;32]))});
        let circle: StrandWatchCurrentResponseBody = serde_json::from_value(wire).unwrap();
        assert!(payload_from_current(&request, &circle, None).is_err());
    }

    fn cut(bundle: &arkret_sdk::RealmAuthorityBundle) -> arkret_sdk::RealmStateSnapshot {
        let mut signature = bundle.current_assertion.signature.clone();
        signature.context = arkret_sdk::DetachedSignatureContext::RealmSnapshot;
        // Shape fixture for observation checks, not authenticated origin proof.
        arkret_sdk::RealmStateSnapshot {
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([3; 32]),
            realm_id: bundle.realm_id.clone(),
            governance_generation: bundle.current_generation,
            visible_stream_heads: vec![bundle.realm_stream_head.clone()],
            current_state_entries: vec![],
            retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
                history_access: arkret_sdk::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_sdk::StreamHistoryFloor {
                    stream_ref: bundle.realm_stream_head.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: bundle.bundle_issued_at,
            signature,
        }
    }

    #[test]
    fn current_observation_keeps_original_generation_and_head_without_governing_endpoint_discovery()
    {
        let (_, current, bundle) = observation(None);
        let original = cut(&bundle);
        assert!(validate_own_observation(&current, &original, &original).is_ok());
        let mut changed = original.clone();
        changed.governance_generation += 1;
        let error = validate_own_observation(&current, &original, &changed).unwrap_err();
        assert!(!error.is::<WatchCutChanging>());
        changed = original.clone();
        changed.visible_stream_heads[0].commit_id = arkret_sdk::RealmCommitId::from_digest([4; 32]);
        assert!(
            validate_own_observation(&current, &original, &changed)
                .unwrap_err()
                .is::<WatchCutChanging>()
        );
        changed = original.clone();
        changed.visible_stream_heads[0].stream_position = 0;
        assert!(validate_own_observation(&current, &original, &changed).is_err());
    }

    #[test]
    fn same_cut_watch_value_requires_the_original_signed_row() {
        let (_, current, bundle) = observation(Some(json!({"level":"all","level_public":false})));
        let mut original = cut(&bundle);
        let StrandWatchCurrentResponseBody::Current {
            current_state: result,
            ..
        } = &current
        else {
            unreachable!();
        };
        original
            .current_state_entries
            .push(serde_json::from_value(serde_json::to_value(result).unwrap()).unwrap());
        assert!(validate_own_observation(&current, &original, &original).is_ok());
        let mut missing = original.clone();
        missing.current_state_entries.clear();
        let error = validate_own_observation(&current, &original, &missing).unwrap_err();
        assert!(!error.is::<WatchCutChanging>());
        let mut wrong = original.clone();
        let arkret_sdk::CurrentState::Value { value, .. } = &mut wrong.current_state_entries[0];
        *value = json!({"level":"muted","level_public":false});
        assert!(validate_own_observation(&current, &original, &wrong).is_err());
    }
}
