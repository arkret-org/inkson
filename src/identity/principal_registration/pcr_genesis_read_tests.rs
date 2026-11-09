//! Original-consumption fixture: genuine producer and Commit signatures over
//! real HTTP, without claiming native Station admission or a complete archive.

use arkret_sdk::{
    ActorId, CommittedEventFullView, CurrentPrincipalRequestBody, PcrGenesisUnit,
    PrincipalRegistrationAnchor, RealmCommit, RealmCommitId,
};
use serde_json::json;

fn committed(unit: &PcrGenesisUnit) -> Vec<CommittedEventFullView> {
    let method = arkret_sdk::DidUrl::new(format!(
        "did:{}#pcr-read-fixture",
        unit.create()
            .actor_id
            .as_account_id()
            .unwrap()
            .station_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap()
    ))
    .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[57; 32]);
    let mut previous: Option<RealmCommitId> = None;
    unit.events
        .iter()
        .enumerate()
        .map(|(position, event)| {
            let mut body = json!({
                "realm_id":event.realm_id,
                "stream_ref":arkret_sdk::CommitStreamRef::Realm { realm_id:event.realm_id.clone() },
                "stream_position":position, "previous_commit_ref":previous,
                "event_ref":event.event_id, "governance_generation":"0",
                "authority_ref":unit.create().event_id,
                "committed_at":arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
            });
            let bytes = arkret_sdk::canonical::canonical_json_bytes(&body).unwrap();
            let id = RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(&bytes));
            body["commit_id"] = serde_json::to_value(&id).unwrap();
            let signature = arkret_sdk::sign_detached_object(
                &body,
                arkret_sdk::DetachedSignatureContext::RealmCommit,
                method.clone(),
                event.created_at,
                &signing,
            )
            .unwrap();
            body["signature"] = serde_json::to_value(signature).unwrap();
            let commit: RealmCommit = serde_json::from_value(body).unwrap();
            commit.validate_content_address().unwrap();
            previous = Some(id);
            CommittedEventFullView {
                event: event.clone(),
                commit,
            }
        })
        .collect()
}

pub(super) async fn assert_original_read(
    unit: &PcrGenesisUnit,
    anchor: &PrincipalRegistrationAnchor,
) {
    let account = unit.create().actor_id.as_account_id().unwrap();
    let payload: arkret_sdk::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&unit.create().payload).unwrap()).unwrap();
    let resolution = payload.object.initial_resolution.unwrap();
    let request = CurrentPrincipalRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(1_790_000_000_001),
        account_id: account.clone(),
    };
    let rows = committed(unit);
    let current = json!({
        "request_id":request.request_id,"account_id":account,"principal_control_realm_id":unit.create().realm_id,
        "resolution_projection": {
            "did":resolution.did,"method_history_head":resolution.method_history_head,"version_id":resolution.version_id,
            "resolution_event_ref":unit.create().event_id,"updated_at":arkret_sdk::canonical::format_timestamp_canonical(unit.create().created_at),
        },
    });
    let first = serde_json::to_value(&rows[0]).unwrap();
    let founding = json!({
        "committed_events":rows,
        "readable_floor":{"oldest_position":0,"floor_commit_id":rows[0].commit.commit_id,"floor_reason":"stream_start"},
        "truncated":true,
    });
    let PrincipalRegistrationAnchor::WebvhRegistration {
        normalized_did_document,
        log_entries,
        ..
    } = anchor;
    let document = json!({"did_document":normalized_did_document});
    let logs = json!({"did":anchor.did(),"method":arkret_sdk::DidMethodUri::Webvh,"native_history":true,"entries":log_entries,"has_more":false});
    for case in [
        "valid",
        "other_pcr",
        "missing_founder",
        "wrong_floor",
        "altered_native_log",
    ] {
        let mut reply_current = current.clone();
        let mut reply_founding = founding.clone();
        let mut reply_logs = logs.clone();
        match case {
            "other_pcr" => {
                reply_current["principal_control_realm_id"] = serde_json::to_value(
                    arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
                        arkret_sdk::DigestSuite::Sha256,
                        [99; 32],
                    )),
                )
                .unwrap()
            }
            "missing_founder" => reply_founding["committed_events"] = json!([rows[0]]),
            "wrong_floor" => reply_founding["readable_floor"]["oldest_position"] = json!(1),
            "altered_native_log" => {
                reply_logs["entries"][0]["proof"][0]["proofValue"] = json!("zForged")
            }
            _ => {}
        }
        let mut bodies = vec![reply_current, first.clone()];
        if case != "other_pcr" {
            bodies.push(reply_founding);
        }
        if matches!(case, "valid" | "altered_native_log") {
            bodies.extend([document.clone(), reply_logs]);
        }
        let (client, server, active) =
            crate::transport::own_station_results::test_http::revocable_client(
                account,
                bodies.into_iter().map(|body| (200, body)).collect(),
                false,
            );
        let principal = client.current_principal(&request).await.unwrap();
        let read =
            garth::own_station_results::read_own_station_human_pcr_genesis(&client, principal)
                .await;
        if case == "valid" {
            let read = read.unwrap_or_else(|error| panic!("valid private PCR read: {error}"));
            assert_eq!(read.account().unwrap(), account);
            assert_eq!(read.realm().unwrap(), &unit.create().realm_id);
            assert_eq!(read.unit().unwrap(), unit);
            assert_eq!(read.genesis().unwrap(), &rows[0]);
            let verified = arkret_sdk::verify_pcr_genesis_events(
                read.unit().unwrap(),
                read.registration_verification_anchor().unwrap(),
                &ActorId::account(account.clone()),
            )
            .unwrap();
            assert_eq!(
                verified[0].canonical_bytes(),
                arkret_sdk::canonical::canonical_json_bytes(unit.create()).unwrap()
            );
            active.store(false, std::sync::atomic::Ordering::SeqCst);
            assert!(read.genesis().is_err());
        } else {
            assert!(read.is_err(), "private PCR read must reject {case}");
        }
        server.join().unwrap();
    }
}
