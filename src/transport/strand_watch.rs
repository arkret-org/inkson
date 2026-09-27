//! Self watch writes use the Station's exact current value as their CAS preimage.

use arkret_sdk::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentValue,
    StrandWatchLevel, StrandWatchSetPayload,
};

pub(crate) fn payload_from_current(
    request: &StrandWatchCurrentRequestBody,
    current: &StrandWatchCurrentOutcome,
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
        StrandWatchCurrentOutcome::NeverWritten { stream_head, .. }
        | StrandWatchCurrentOutcome::Current { stream_head, .. } => stream_head,
    };
    anyhow::ensure!(
        matches!(&head.stream_ref,
        arkret_sdk::CommitStreamRef::Realm { realm_id } if realm_id == &request.realm_id),
        "self watch requires a current Realm-stream cut"
    );
    let publication = match current {
        StrandWatchCurrentOutcome::Current { result, .. } => match result.value {
            StrandWatchCurrentValue::Set(value) => value.level_public,
            StrandWatchCurrentValue::Cleared(()) => None,
        },
        StrandWatchCurrentOutcome::NeverWritten { .. } => None,
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
    if let StrandWatchCurrentOutcome::Current { result, .. } = current {
        payload = payload.with_expected_value(result.value);
    }
    Ok(payload)
}

pub(crate) fn current_level(current: &StrandWatchCurrentOutcome) -> StrandWatchLevel {
    match current {
        StrandWatchCurrentOutcome::Current { result, .. } => match result.value {
            StrandWatchCurrentValue::Set(value) => value.level,
            StrandWatchCurrentValue::Cleared(()) => StrandWatchLevel::MentionsOnly,
        },
        StrandWatchCurrentOutcome::NeverWritten { .. } => StrandWatchLevel::MentionsOnly,
    }
}

fn validate_authority_observation(
    current: &StrandWatchCurrentOutcome,
    before: &arkret_sdk::RealmAuthorityBundle,
    after: &arkret_sdk::RealmAuthorityBundle,
    endpoint_station: &arkret_sdk::DidCoreId,
) -> anyhow::Result<()> {
    let (realm, generation, head) = match current {
        StrandWatchCurrentOutcome::NeverWritten {
            realm_id,
            governance_generation,
            stream_head,
            ..
        }
        | StrandWatchCurrentOutcome::Current {
            realm_id,
            governance_generation,
            stream_head,
            ..
        } => (realm_id, *governance_generation, stream_head),
    };
    anyhow::ensure!(
        before.realm_id == *realm
            && after.realm_id == *realm
            && endpoint_station == &before.current_service_id
            && before.current_generation == after.current_generation
            && before.current_service_id == after.current_service_id
            && generation == after.current_generation
            && head.stream_position <= after.realm_stream_head.stream_position
            && (head.stream_position != after.realm_stream_head.stream_position
                || head.commit_id == after.realm_stream_head.commit_id),
        "watch current observation crossed an authority generation, Station or unconfirmed head"
    );
    Ok(())
}

pub(crate) async fn read(
    http: &arkret_sdk::http_client::Client,
    request: &StrandWatchCurrentRequestBody,
) -> anyhow::Result<StrandWatchCurrentOutcome> {
    let authority = garth::AuthorityClient::new(http.clone());
    let (before, ..) =
        crate::realm_events_engine::fresh_verified_realm(&authority, http, &request.realm_id)
            .await?;
    let describe = http.describe().await?;
    anyhow::ensure!(
        describe.service_id == before.current_service_id,
        "watch current endpoint is not the verified governing Station"
    );
    let current = http.strand_watch_current(request).await?;
    payload_from_current(request, &current, None)?;
    let (after, ..) =
        crate::realm_events_engine::fresh_verified_realm(&authority, http, &request.realm_id)
            .await?;
    validate_authority_observation(&current, &before, &after, &describe.service_id)?;
    Ok(current)
}

pub(crate) async fn write(
    http: &arkret_sdk::http_client::Client,
    request: &StrandWatchCurrentRequestBody,
    level: Option<StrandWatchLevel>,
) -> anyhow::Result<StrandWatchCurrentOutcome> {
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
    let accepted = crate::event_submit::EventSubmitter::from_current_session(http.clone())
        .submit_sdk_event(&operation)
        .await?;
    anyhow::ensure!(accepted.is_committed(), "watch submission is not committed");
    let commit = accepted
        .commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("watch submission omits Commit"))?;
    let after = read(http, request).await?;
    let StrandWatchCurrentOutcome::Current {
        governance_generation,
        stream_head,
        result,
        ..
    } = &after
    else {
        anyhow::bail!("accepted watch write has no durable current result");
    };
    let before_generation = match before {
        StrandWatchCurrentOutcome::NeverWritten {
            governance_generation,
            ..
        }
        | StrandWatchCurrentOutcome::Current {
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
        StrandWatchCurrentOutcome,
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
        let request = StrandWatchCurrentRequestBody {
            realm_id: realm.clone(),
            strand_id: strand.clone(),
            watcher_actor_id: rows[0].event.actor_id.clone(),
        };
        let selector = json!({"kind":"strand_watch","strand_id":strand,"watcher_actor_id":request.watcher_actor_id});
        let current = match value {
            None => {
                json!({"status":"never_written","realm_id":realm,"governance_generation":bundle.current_generation,"stream_head":bundle.realm_stream_head,"selector":selector})
            }
            Some(value) => {
                json!({"status":"current","realm_id":realm,"governance_generation":bundle.current_generation,"stream_head":bundle.realm_stream_head,"result":{
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
        let circle: StrandWatchCurrentOutcome = serde_json::from_value(wire).unwrap();
        assert!(payload_from_current(&request, &circle, None).is_err());
    }

    #[test]
    fn current_observation_requires_verified_generation_station_and_confirmed_head() {
        let (_, current, bundle) = observation(None);
        assert_eq!(bundle.current_generation, 0);
        assert!(
            validate_authority_observation(&current, &bundle, &bundle, &bundle.current_service_id)
                .is_ok()
        );
        let mut handoff = bundle.clone();
        handoff.current_generation += 1;
        assert!(
            validate_authority_observation(&current, &bundle, &handoff, &bundle.current_service_id)
                .is_err()
        );
        let other = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(validate_authority_observation(&current, &bundle, &bundle, &other).is_err());
        let mut behind = bundle.clone();
        behind.realm_stream_head.stream_position = 0;
        assert!(
            validate_authority_observation(&current, &behind, &behind, &bundle.current_service_id)
                .is_err()
        );
    }
}
