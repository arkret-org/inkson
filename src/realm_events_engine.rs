//! Per-stream `ak.self.committed_event.read.scan.v1` tail-follow engine.
//!
//! This is the Realm-scoped counterpart to [`crate::sync_engine`]. The account
//! engine drives `/_arkret/self/account/subscribe` (the account-aggregate
//! stream); this engine drives `POST /_arkret/self/streams/scan` for every
//! independent commit stream of the currently-selected Realm.
//!
//! Why a SECOND engine instead of reusing the account stream's cursor: the
//! account aggregate need not carry every Realm Event visible to the account,
//! while an authority commit stream is the durable Realm history itself. The
//! two are also cursor-incompatible: the account cursor is an opaque
//! subscription cursor, and a commit-stream cursor is that stream's own
//! `stream_position`.
//!
//! Why per-stream and not per-Realm: a Realm, each of its Circles and each of
//! its Sidecars own an **independent** commit stream
//! ([`arkret_wire::CommitStreamRef`]). There is no Realm-global order, no
//! Realm-global position and no Realm-global cursor to hold; this engine keeps
//! one durable position per stream ref ([`garth::CursorScope::CommitStream`])
//! and advances each of them on its own. A stream is drained by repeating the
//! scan while the Station reports `truncated`.
//!
//! The Station answers a scan with [`arkret_wire::CommittedEventView`] values,
//! preserving withheld disclosure without inventing a replacement Event.

use std::collections::BTreeSet;
use std::time::Duration;

use garth::{
    AuthorityClient, ClientEvent, ClientProjector, CommitStreamRef, CommittedDelta,
    CommittedEventView, CursorScope, CursorStore, DecodedInbound, InboundDecoder, RealmReplica,
    RetrySchedule, StreamScanRequest,
};

use crate::config::MultiProfileConfig;

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence. The doubling ladder is [`garth::RetrySchedule`];
/// these are just its bounds, kept as `Duration` so the account and realm
/// engines share one unit (F-10).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Pause between drained passes over the Realm's streams.
const BEAT: Duration = Duration::from_millis(250);

/// Rows requested per scan. The Station may return fewer and flag `truncated`,
/// which this engine drains before moving to the next stream.
const SCAN_LIMIT: u16 = 200;

/// Runtime inputs consumed by the realm events engine. UI frameworks are
/// confined to the app adapter that constructs these handles.
#[derive(Clone)]
pub struct RealmEventsEngineContext {
    pub base_url: crate::runtime::input::ValueReader<String>,
    pub token: crate::runtime::input::ValueCell<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    /// The realm the kanban view is currently showing. The engine exits when
    /// this no longer matches the realm it was spawned for, so a realm switch
    /// retires the old loop while `app` spawns a fresh one for the new realm.
    pub selected_realm_id: crate::runtime::input::ValueReader<String>,
    /// Whether the current route actually consumes a Realm stream. This lets a
    /// stream spawned on Board/Chat exit when navigation returns to Home.
    pub route_enabled: crate::runtime::input::ValueReader<bool>,
    /// Bumped once per pass that folded >= 1 new operation into the local
    /// store, so the kanban panel can re-project off a signal that is NOT the
    /// (cross-member-lossy) account `sync_cursor`.
    pub realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    /// Removes transient message previews only after the matching final Event
    /// has been durably folded by this projector.
    pub message_stream_hub: crate::views::message_streams::MessageStreamHub,
    /// Active multi-profile config — the engine exits when the active profile
    /// rotates (mirrors the account engine's profile guard).
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub client_runtime: crate::client_core::InksonClientRuntime,
    pub effect: crate::runtime::effects::EffectHandle,
}

/// [`ClientProjector`] that folds each scanned batch into the shared local
/// store (kanban / message / membership), bumping `realm_live_epoch`
/// immediately after each batch that changes the projection. The fold is
/// durable BEFORE the stream position is checkpointed, so a failed fold is
/// redelivered by the next scan rather than skipped.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    digest_suite: arkret_sdk::DigestSuite,
    realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    message_stream_hub: crate::views::message_streams::MessageStreamHub,
}

impl ClientProjector for RealmIngestProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let digest_suite = self.digest_suite;
        let finals = self.state_store.read(|store| {
            batch
                .iter()
                .filter_map(|event| accepted_direct_message_final(event, digest_suite, store))
                .collect::<Vec<_>>()
        });
        // This batch came from shape-only `apply_scan`; it has no verified
        // authority proof. Never turn it into historical Agent signer evidence.
        let changed = self
            .state_store
            .write(|store| ingest_shape_only_realm_batch(store, &self.realm_id, &batch));
        // The local fold above is the durable gate. A preview is never
        // removed merely because a frame with the same message id was
        // observed on the wire.
        let mut message_stream_hub = self.message_stream_hub;
        for (event, sender_endpoint) in finals {
            if let Err(error) = message_stream_hub.bind_verified_final(event, &sender_endpoint) {
                tracing::warn!(%error, event_id = %event.event_id, "message stream final binding failed closed");
            }
        }
        if changed > 0 {
            self.realm_live_epoch
                .update(|epoch| *epoch = epoch.wrapping_add(1));
        }
        Ok(())
    }
}

fn ingest_shape_only_realm_batch(
    store: &mut crate::state::LocalStateStore,
    realm_id: &str,
    batch: &[ClientEvent],
) -> usize {
    crate::sync_engine::ingest_kanban_events(store, realm_id, batch)
        + crate::sync_engine::ingest_message_events(store, realm_id, batch)
        + crate::sync_engine::ingest_membership_events(store, realm_id, batch)
        + crate::sync_engine::ingest_moderation_events(store, batch)
}

/// Fan one stream's scanned commits into the ordered [`ClientEvent`] batch the
/// product projections consume.
///
/// Every row carries its own [`arkret_wire::CommitStreamRef`] and
/// `stream_position` inside [`CommittedDelta`], so nothing here has to invent a
/// cross-stream ordering to represent them.
fn committed_views_to_client_events(
    realm_id: &arkret_sdk::RealmId,
    committed_events: Vec<CommittedEventView>,
) -> garth::Result<Vec<ClientEvent>> {
    let decoder = InboundDecoder::new();
    let mut batch = Vec::with_capacity(committed_events.len());
    for item in committed_events {
        let delta = CommittedDelta::from_committed_event_view(realm_id.clone(), item)?;
        if let Some(event) = delta.event()
            && let DecodedInbound::Message(message) = decoder.decode_event(event.clone())
        {
            batch.push(ClientEvent::Message(message));
        }
        batch.push(ClientEvent::Committed(delta));
    }
    Ok(batch)
}

/// Extract the verified sender endpoint from a service-accepted direct Message Event.
///
/// The Realm stream contains the canonical Event only after the Station's
/// normal schema, proof, authorization and admission gates. This function does
/// not invent a second ordinary proof verifier. Agent finals additionally
/// require locally verified historical signer evidence so a new runtime key
/// cannot terminate a preview authored by an older key.
fn accepted_direct_message_final<'a>(
    client_event: &'a ClientEvent,
    digest_suite: arkret_sdk::DigestSuite,
    store: &crate::state::LocalStateStore,
) -> Option<(&'a arkret_sdk::Event, arkret_sdk::SignalSequenceEndpoint)> {
    let ClientEvent::Message(message) = client_event else {
        return None;
    };
    let event = &message.event;
    if event.kind != arkret_sdk::EventKind::MessageCreate
        || event
            .validate_proof_bindings_with_digest_suite(digest_suite)
            .is_err()
    {
        return None;
    }
    if event.executed_by.is_some() || event.payload.get("agent_context").is_some() {
        let endpoint =
            crate::identity::agent_signer_evidence::verified_cached_agent_event_endpoint(
                event, store,
            )?;
        return Some((event, endpoint));
    }
    let method = event.producer_proof.as_ref()?.verification_method.as_str();
    let (controller, device) = method.rsplit_once('#')?;
    let controller = crate::mls_api_helpers::principal_core_id(controller).ok()?;
    if &controller != event.actor_id.signing_principal_id() {
        return None;
    }
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    Some((
        event,
        arkret_sdk::SignalSequenceEndpoint::AccountDevice { device_id: device },
    ))
}

/// The Realm's live digest suite.
///
/// A Realm id is the suite-tagged digest of its own `ak.realm.create`, so the
/// suite every later Event in that Realm is bound under is readable from the
/// id itself. The former Seal-frontier `live_digest_suite` read is gone with
/// the Seal family.
fn realm_live_digest_suite(realm_id: &arkret_sdk::RealmId) -> arkret_sdk::DigestSuite {
    realm_id.digest_suite_code().digest_suite()
}

/// Run the Realm commit-stream follow loop for `realm_id` until the generation
/// is bumped, the active profile rotates, or the selected realm changes.
pub async fn run_realm_events_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    realm_id: String,
    ctx: RealmEventsEngineContext,
) {
    if realm_id.trim().is_empty() {
        return;
    }
    let start_profile_id = ctx.profiles.get().active_profile_id;
    let realm_id_typed = match arkret_sdk::RealmId::new(realm_id.clone()) {
        Ok(realm_id) => realm_id,
        Err(error) => {
            tracing::warn!(error = %error, realm_id, "invalid realm id for stream follow");
            return;
        }
    };
    let is_active = || {
        generation.get() == start_generation
            && ctx.profiles.get().active_profile_id == start_profile_id
            && ctx.selected_realm_id.get() == realm_id
            && ctx.route_enabled.get()
            && !ctx.effect.is_cancelled()
            && !ctx.base_url.get().trim().is_empty()
            && !ctx.token.get().trim().is_empty()
    };
    let projector = RealmIngestProjector {
        state_store: ctx.state_store.clone(),
        realm_id: realm_id.clone(),
        digest_suite: realm_live_digest_suite(&realm_id_typed),
        realm_live_epoch: ctx.realm_live_epoch.clone(),
        message_stream_hub: ctx.message_stream_hub,
    };
    let cursors = ctx.client_runtime.inbox_store();
    let mut replica = RealmReplica::new(realm_id_typed.clone());
    let mut backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING);

    while is_active() {
        let http = match crate::identity::session_refresh::provide_authenticated_sdk_client(
            &ctx.base_url.get(),
        )
        .await
        {
            Ok(http) => http,
            Err(error) => {
                if !retry_after(&mut backoff, is_active(), &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        let authority = AuthorityClient::new(http);
        match follow_once(
            &authority,
            &cursors,
            &mut replica,
            &realm_id_typed,
            &projector,
            &ctx,
            &is_active,
        )
        .await
        {
            Ok(()) => {
                backoff.reset();
                crate::runtime_helpers::sleep_for(BEAT).await;
            }
            Err(error) => {
                if garth::classify_error(&error) == garth::RunErrorClass::Unauthorized {
                    match crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
                        &ctx.base_url.get(),
                    )
                    .await
                    {
                        Ok(_) => continue,
                        Err(refresh_error)
                            if crate::api_error::is_terminal_session_grant_error(&refresh_error) =>
                        {
                            break;
                        }
                        Err(refresh_error) => {
                            if !retry_after(&mut backoff, is_active(), &refresh_error.to_string())
                                .await
                            {
                                break;
                            }
                            continue;
                        }
                    }
                }
                if !retry_after(&mut backoff, is_active(), &error.to_string()).await {
                    break;
                }
            }
        }
    }
}

async fn retry_after(backoff: &mut RetrySchedule, active: bool, reason: &str) -> bool {
    let Some(delay) = crate::runtime_helpers::next_reconnect_delay(active, backoff) else {
        return false;
    };
    tracing::warn!(
        reason,
        retry_delay_ms = delay.as_millis(),
        "Realm stream follow interrupted; retrying"
    );
    crate::runtime_helpers::sleep_for(delay).await;
    true
}

/// Drain every stream this client follows for the Realm, once.
async fn follow_once<T, F>(
    authority: &AuthorityClient<T>,
    cursors: &crate::client_core::InksonLocalStateStoreAdapter,
    replica: &mut RealmReplica,
    realm_id: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    ctx: &RealmEventsEngineContext,
    is_active: &F,
) -> garth::Result<()>
where
    T: garth::AuthorityTransport,
    F: Fn() -> bool,
{
    for stream_ref in followed_streams(realm_id, ctx) {
        if !is_active() {
            return Ok(());
        }
        drain_stream(
            authority,
            cursors,
            replica,
            realm_id,
            &stream_ref,
            projector,
        )
        .await?;
    }
    Ok(())
}

/// The independent streams this client follows for one Realm.
///
/// The Realm stream is always followed. Circle and Sidecar streams are added
/// for the scopes this client already holds local state for; a scope the client
/// cannot read is never scanned, and no combined ordering is derived across the
/// set — each entry is drained against its own durable position.
fn followed_streams(
    realm_id: &arkret_sdk::RealmId,
    ctx: &RealmEventsEngineContext,
) -> Vec<CommitStreamRef> {
    let mut refs: BTreeSet<CommitStreamRef> = BTreeSet::from([CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    }]);
    let scopes = ctx
        .state_store
        .read(|store| store.local_mls_scopes_in_realm(realm_id.as_str()));
    for scope in scopes {
        if let Ok(stream_ref) = CommitStreamRef::from_scope(&scope, Some(realm_id.clone()))
            && stream_ref.realm_id() == realm_id
        {
            refs.insert(stream_ref);
        }
    }
    refs.into_iter().collect()
}

/// Pull one stream forward from its durable position until the Station stops
/// reporting a truncated window.
async fn drain_stream<T>(
    authority: &AuthorityClient<T>,
    cursors: &crate::client_core::InksonLocalStateStoreAdapter,
    replica: &mut RealmReplica,
    realm_id: &arkret_sdk::RealmId,
    stream_ref: &CommitStreamRef,
    projector: &RealmIngestProjector,
) -> garth::Result<()>
where
    T: garth::AuthorityTransport,
{
    let scope = CursorScope::CommitStream {
        service_id: None,
        stream_ref: stream_ref.clone(),
    };
    let mut after_position = cursors
        .load(scope.clone())
        .await?
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|error| garth::Error::Protocol(format!("stored stream position: {error}")))?;
    loop {
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(after_position),
            limit: SCAN_LIMIT,
        };
        let outcome = authority.scan(&request).await?;
        let truncated = outcome.truncated;
        let batch = committed_views_to_client_events(realm_id, outcome.committed_events.clone())?;
        // `apply_scan` validates the page shape and local tail continuity only.
        // It does not establish a fresh authority chain or verify Commit
        // signatures. Its rows must never feed the verified poll coordinate
        // index; that requires `apply_verified_scan` and its page carrier.
        replica.apply_scan(&request, outcome)?;
        let Some(head) = replica
            .streams
            .get(stream_ref)
            .and_then(|stream| stream.head.as_ref())
        else {
            return Ok(());
        };
        let next_position = head.stream_position;
        if batch.is_empty() {
            return Ok(());
        }
        // Durable fold first: the position is only advanced once the product
        // projection that consumes these rows has committed them.
        projector.project(batch).await?;
        cursors
            .save(scope.clone(), next_position.to_string())
            .await?;
        after_position = Some(next_position);
        if !truncated {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const STRAND_ID: &str = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    const ACTOR_ID: &str = "ak:did_core:web:alice.example";
    const ACTOR_CONTROLLER: &str = "did:web:alice.example";
    const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000003";

    fn direct_message_event() -> ClientEvent {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Realm { realm_id },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            json!({
                "strand_id": STRAND_ID,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "final"}
            }),
        )
        .unwrap();
        let event_digest = arkret_sdk::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.producer_proof = Some(arkret_sdk::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_sdk::DidUrl::new(format!("{ACTOR_CONTROLLER}#{DEVICE_ID}"))
                .unwrap(),
            event_digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        });
        match garth::InboundDecoder::new()
            .try_decode_event(event)
            .unwrap()
        {
            garth::DecodedInbound::Message(message) => ClientEvent::Message(message),
            garth::DecodedInbound::Event(_) => panic!("message.create must decode as a message"),
        }
    }

    #[test]
    fn the_realm_live_suite_comes_from_the_realm_identity_itself() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap();
        assert_eq!(
            realm_live_digest_suite(&realm_id),
            arkret_sdk::DigestSuite::Sha256
        );
    }

    #[test]
    fn the_realm_stream_is_always_followed_and_is_never_a_realm_global_cursor() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap();
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let scope = CursorScope::CommitStream {
            service_id: None,
            stream_ref: realm_stream.clone(),
        };
        let circle_scope = CursorScope::CommitStream {
            service_id: None,
            stream_ref: CommitStreamRef::Circle {
                realm_id,
                circle_id: arkret_sdk::CircleId::new(
                    "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                )
                .unwrap(),
            },
        };
        // Two streams of one Realm never share a cursor slot, which is what
        // stops a Realm-global position from being representable at all.
        assert_ne!(scope, circle_scope);
    }

    #[test]
    fn final_binding_extracts_only_the_exact_accepted_actor_device_proof() {
        let event = direct_message_event();
        let store = crate::state::LocalStateStore::default();
        let (final_event, endpoint) =
            accepted_direct_message_final(&event, arkret_sdk::DigestSuite::Sha256, &store)
                .expect("direct final is bindable");
        assert_eq!(
            final_event.actor_id.signing_principal_id().as_str(),
            ACTOR_ID
        );
        assert_eq!(
            endpoint,
            arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
            }
        );
    }

    #[test]
    fn final_binding_rejects_delegated_sender_identity() {
        let mut delegated = direct_message_event();
        let ClientEvent::Message(message) = &mut delegated else {
            unreachable!();
        };
        message.event.executed_by = Some(arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        ));
        let store = crate::state::LocalStateStore::default();
        assert!(
            accepted_direct_message_final(&delegated, arkret_sdk::DigestSuite::Sha256, &store,)
                .is_none()
        );
    }

    #[test]
    fn shape_only_scan_events_never_enter_verified_authority_indexes() {
        let realm = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let committed = crate::test_support::committed_event::verified_realm_item_as(
            realm.clone(),
            arkret_sdk::EventKind::MessageCreate.as_str(),
            json!({
                "strand_id": STRAND_ID,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "not a poll"}
            }),
            "agent.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let event_id = committed.event.event_id.clone();
        let batch = committed_views_to_client_events(
            &realm,
            vec![arkret_sdk::CommittedEventView::Full(committed)],
        )
        .unwrap();
        let mut store = crate::state::isolated_store_for_tests("shape-only-agent-commit");
        store.switch_test_account("did:web:reader.example");
        ingest_shape_only_realm_batch(&mut store, realm.as_str(), &batch);
        assert!(store.verified_message_commit(&event_id).is_none());
        assert!(store.historical_agent_event_candidates().is_empty());
    }
}
