//! Per-realm `ak.self.events.stream.subscribe.v1` long-poll engine.
//!
//! This is the realm-scoped counterpart to [`crate::sync_engine`]. The account
//! engine drives `/_arkret/self/account/subscribe` (the account-aggregate
//! stream); this engine drives `/_arkret/self/events/subscribe?realms=<R>` for
//! the currently-selected realm.
//!
//! Why a SECOND engine instead of reusing the account stream's cursor:
//! `service-surface.md` forbids merging the account-aggregate stream and the
//! bare realm events read into one "stream" — their selectors / auth / frame
//! schema / freshness all differ. Concretely, each cursor is bound to a
//! `filter_digest` (`encoding.md` §8.3.1): the account stream and a realm
//! stream have different selectors, so their cursors are NOT interchangeable
//! (cross-use is `cursor_integrity_invalid`). The realm cursor therefore lives
//! in its own store slot ([`LocalStateStore::realm_events_cursor`]).
//!
//! Why this fixes cross-member sync: a realm's `events/subscribe` history +
//! live frames are served from the projection layer + per-realm broadcast
//! fan-out. The account-aggregate stream need not contain every Realm Event
//! visible to the account, while the Realm stream follows the durable Realm
//! history independently of which member Account actor authored an Event or
//! which Station its `AccountId` routes through.
//!
//! Transport reality (wasm): the shared SDK http-client opens the canonical
//! `events/subscribe` stream, and inkson wraps it as a client-core typed frame
//! source. The all-target adapter buffers the response and parses typed NDJSON
//! frames at stream close. The server holds the stream open for
//! `max_duration_ms`, so that window doubles as this engine's liveness latency.
//! Native can later switch this adapter to the SDK streaming frame source
//! without changing the ingest / cursor contract here.

use std::time::Duration;

use garth::{
    ClientEvent, ClientProjector, DurableInboxStore, RetrySchedule, RunOptions, ScanCatchupOptions,
    SyncLoopControl, TransportProvider,
};

use crate::config::MultiProfileConfig;

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence. The doubling ladder is [`garth::RetrySchedule`];
/// these are just its bounds, kept as `Duration` so the account and realm
/// engines share one unit (F-10).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

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
    /// The session's optional WebSocket. A live rail supplies the events
    /// channel; a scan always stays on HTTPS.
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
    /// Bumped once per iteration that folded ≥1 new operation into the local
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

/// [`ClientProjector`] that folds each driver-emitted batch into the shared
/// local store (kanban / message / membership), bumping `realm_live_epoch`
/// immediately after each batch that changes the projection. The runner owns a
/// long-lived reconnect loop, so deferring the signal until that loop returns
/// would leave the UI stale even though the event was already durable locally.
/// The ingest is durable BEFORE
/// the driver checkpoints the cursor (the projector gates cursor advance), and
/// the cursor stays coherent because the garth adapter writes the same root
/// state backend used by the projector.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    digest_suite: arkret_sdk::DigestSuite,
    realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    message_stream_hub: crate::views::message_streams::MessageStreamHub,
}

impl ClientProjector for RealmIngestProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        let (batch, digest_suite) =
            expand_delivery_events(batch, &self.realm_id, self.digest_suite)?;
        if !batch.is_empty() {
            let finals = self.state_store.read(|store| {
                batch
                    .iter()
                    .filter_map(|event| accepted_direct_message_final(event, digest_suite, store))
                    .collect::<Vec<_>>()
            });
            let changed = self.state_store.write(|store| {
                crate::sync_engine::ingest_kanban_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_message_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_membership_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_default_strand_events(
                        store,
                        &self.realm_id,
                        &batch,
                    )
                    + crate::sync_engine::ingest_moderation_events(store, &batch)
            });
            // The local fold above is the durable gate. A preview is never
            // removed merely because a frame with the same message id was
            // observed on the wire.
            let mut message_stream_hub = self.message_stream_hub;
            for (event, sender_endpoint) in finals {
                if let Err(error) = message_stream_hub.bind_verified_final(event, &sender_endpoint)
                {
                    tracing::warn!(%error, event_id = %event.event_id, "message stream final binding failed closed");
                }
            }
            if changed > 0 {
                self.realm_live_epoch
                    .update(|epoch| *epoch = epoch.wrapping_add(1));
            }
        }
        Ok(())
    }
}

fn expand_delivery_events(
    events: Vec<ClientEvent>,
    expected_realm_id: &str,
    fallback_digest_suite: arkret_sdk::DigestSuite,
) -> garth::Result<(Vec<ClientEvent>, arkret_sdk::DigestSuite)> {
    let decoder = garth::InboundDecoder::new();
    let mut expanded = Vec::new();
    let mut carried_digest_suite = None;
    for event in events {
        match event {
            ClientEvent::Backfill {
                realm_id,
                digest_suite,
                outcome,
            } => {
                validate_carried_realm_suite(
                    expected_realm_id,
                    &realm_id,
                    digest_suite,
                    &mut carried_digest_suite,
                )?;
                for (index, row) in outcome.events.into_iter().enumerate() {
                    let event = row.into_event().ok_or_else(|| {
                        garth::Error::Protocol(format!(
                            "Realm inbox backfill requires complete Events; row {index} is redacted or reference-locked"
                        ))
                    })?;
                    expanded.push(match decoder.decode_event(event) {
                        garth::DecodedInbound::Message(message) => ClientEvent::Message(*message),
                        garth::DecodedInbound::Event(event) => ClientEvent::Event(*event),
                    });
                }
            }
            ClientEvent::RealmAccepted {
                realm_id,
                digest_suite,
                event,
            } => {
                validate_carried_realm_suite(
                    expected_realm_id,
                    &realm_id,
                    digest_suite,
                    &mut carried_digest_suite,
                )?;
                expanded.push(match decoder.decode_event(event) {
                    garth::DecodedInbound::Message(message) => ClientEvent::Message(*message),
                    garth::DecodedInbound::Event(event) => ClientEvent::Event(*event),
                });
            }
            event => expanded.push(event),
        }
    }
    Ok((
        expanded,
        carried_digest_suite.unwrap_or(fallback_digest_suite),
    ))
}

fn validate_carried_realm_suite(
    expected_realm_id: &str,
    realm_id: &arkret_sdk::RealmId,
    digest_suite: arkret_sdk::DigestSuite,
    carried_digest_suite: &mut Option<arkret_sdk::DigestSuite>,
) -> garth::Result<()> {
    if realm_id.as_str() != expected_realm_id {
        return Err(garth::Error::Protocol(
            "durable Realm delivery crossed Realm scope".to_owned(),
        ));
    }
    if carried_digest_suite.is_some_and(|existing| existing != digest_suite) {
        return Err(garth::Error::Protocol(
            "durable Realm delivery mixed digest suites".to_owned(),
        ));
    }
    *carried_digest_suite = Some(digest_suite);
    Ok(())
}

async fn deliver_realm_inbox(
    provider: &RealmTransportProvider,
    inbox: crate::client_core::InksonLocalStateStoreAdapter,
    projector: &RealmIngestProjector,
) {
    while provider.is_active() {
        let pending = match inbox.pending(64).await {
            Ok(pending) => pending,
            Err(error) => {
                tracing::error!(%error, "durable Realm inbox read failed closed");
                crate::runtime_helpers::sleep_for(BACKOFF_FLOOR).await;
                continue;
            }
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut handled = false;
        for delivery in pending {
            let delivery_realm = match &delivery.scope {
                garth::CursorScope::RealmEvents { realm_id, .. } => realm_id,
                _ => continue,
            };
            if delivery_realm.as_str() != provider.realm_id {
                continue;
            }
            if delivery
                .next_attempt_at_ms
                .is_some_and(|retry_at| retry_at > now_ms)
            {
                continue;
            }
            handled = true;
            let result = projector.project(delivery.events).await;
            match result {
                Ok(()) => match inbox.ack(delivery.id).await {
                    Ok(true) => {}
                    Ok(false) => tracing::warn!(
                        delivery_id = delivery.id.get(),
                        "Realm inbox delivery disappeared before acknowledgement"
                    ),
                    Err(error) => tracing::error!(
                        %error,
                        delivery_id = delivery.id.get(),
                        "Realm inbox acknowledgement failed; delivery remains pending"
                    ),
                },
                Err(error) => {
                    let exponent = delivery.attempts.min(6);
                    let delay_ms = 1_000_i64.saturating_mul(1_i64 << exponent);
                    if let Err(store_error) = inbox
                        .retry(
                            delivery.id,
                            Some(now_ms.saturating_add(delay_ms)),
                            garth::DeliveryErrorClass::Processing,
                            error.to_string(),
                        )
                        .await
                    {
                        tracing::error!(
                            error = %store_error,
                            delivery_id = delivery.id.get(),
                            "Realm inbox retry state failed closed"
                        );
                    }
                }
            }
        }
        if !handled {
            crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
        }
    }
}

/// Extract the verified sender endpoint from a service-accepted direct Message Event.
///
/// The Realm stream contains the canonical Event only after Soland's normal
/// schema, proof, authorization and reducer gates. This function does not
/// invent a second ordinary proof verifier. Agent finals additionally require
/// locally verified historical signer evidence so a new runtime key cannot
/// terminate a preview authored by an older key.
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
        || event.executed_by.is_some()
        || event
            .validate_station_admission_binding(digest_suite)
            .is_err()
    {
        return None;
    }
    if event.actor_kind == Some(arkret_sdk::EnvelopeActorKind::Agent) {
        let endpoint =
            crate::identity::agent_signer_evidence::verified_cached_agent_event_endpoint(
                event, store,
            )?;
        return Some((event, endpoint));
    }
    let method = event
        .proofs
        .iter()
        .find_map(arkret_sdk::EventProof::as_producer)?
        .verification_method
        .as_str();
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

/// Run the realm events subscribe loop for `realm_id` until the generation is
/// bumped, the active profile rotates, or the selected realm changes.
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
            tracing::warn!(error = %error, realm_id, "invalid realm id for events subscribe");
            return;
        }
    };
    let provider = RealmTransportProvider {
        ctx: ctx.clone(),
        generation,
        start_generation,
        start_profile_id,
        realm_id: realm_id.clone(),
    };
    let mut restart_backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING);
    while provider.is_active() {
        let checkpoint = ctx
            .state_store
            .read(|store| store.trusted_mls_governance_checkpoint(realm_id_typed.as_str()));
        let checkpoint = match checkpoint {
            Some(checkpoint) => checkpoint,
            None => {
                // A server restart, browser storage loss, a second device, or
                // navigation into a Realm created through another surface can
                // all leave the accepted Realm Seal available server-side but
                // no locally pinned governance checkpoint. Merely waiting here
                // is circular: history bootstrap itself is gated by the
                // checkpoint. Re-enter the shared acquisition path, which
                // fetches the complete Seal closure and verifies it with the
                // SDK before pinning anything locally.
                let result = acquire_realm_governance_checkpoint(&ctx, &realm_id_typed).await;
                match result {
                    Ok(()) => {
                        restart_backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING);
                        tracing::info!(
                            realm_id = %realm_id_typed,
                            "Realm Event subscription acquired a verified governance checkpoint"
                        );
                        continue;
                    }
                    Err(error) => {
                        let Some(retry_delay) = crate::runtime_helpers::next_reconnect_delay(
                            provider.is_active(),
                            &mut restart_backoff,
                        ) else {
                            break;
                        };
                        tracing::warn!(
                            %error,
                            realm_id = %realm_id_typed,
                            retry_delay_ms = retry_delay.as_millis(),
                            "Realm governance checkpoint acquisition failed; reconnecting"
                        );
                        crate::runtime_helpers::sleep_for(retry_delay).await;
                        continue;
                    }
                }
            }
        };
        let digest_suite = checkpoint.live_digest_suite;
        let projector = RealmIngestProjector {
            state_store: ctx.state_store.clone(),
            realm_id: realm_id.clone(),
            digest_suite,
            realm_live_epoch: ctx.realm_live_epoch.clone(),
            message_stream_hub: ctx.message_stream_hub,
        };
        // `events/subscribe` without `after` is a live tail, not a history
        // endpoint. Bootstrap durable history through events.query.scan and let
        // the shared client core checkpoint only after the projector commits it.
        let has_stream_cursor = ctx
            .state_store
            .read(|store| store.realm_events_cursor(realm_id_typed.as_str()).is_some());
        if !has_stream_cursor {
            let bootstrap_transport = match provider.provide().await {
                Ok(transport) => transport,
                Err(error) => {
                    let Some(retry_delay) = crate::runtime_helpers::next_reconnect_delay(
                        provider.is_active(),
                        &mut restart_backoff,
                    ) else {
                        break;
                    };
                    tracing::warn!(
                        error = %error,
                        retry_delay_ms = retry_delay.as_millis(),
                        "realm history transport is not ready; reconnecting"
                    );
                    crate::runtime_helpers::sleep_for(retry_delay).await;
                    continue;
                }
            };
            if let Err(error) = ctx
                .client_runtime
                .subscription_engine()
                .bootstrap_realm_history_to_inbox(
                    &bootstrap_transport,
                    realm_id_typed.clone(),
                    digest_suite,
                    ScanCatchupOptions::default(),
                )
                .await
            {
                let Some(retry_delay) = crate::runtime_helpers::next_reconnect_delay(
                    provider.is_active(),
                    &mut restart_backoff,
                ) else {
                    break;
                };
                tracing::warn!(
                    error = %error,
                    retry_delay_ms = retry_delay.as_millis(),
                    "realm history bootstrap failed; reconnecting"
                );
                crate::runtime_helpers::sleep_for(retry_delay).await;
                continue;
            }
        }
        let client = ctx.client_runtime.client();
        let inbox = ctx.client_runtime.inbox_store();
        let control = SyncLoopControl::new();
        let runner = client.run_realm_to_inbox(
            &provider,
            realm_id_typed.clone(),
            digest_suite,
            &control,
            RunOptions {
                beat: Duration::from_millis(250),
                min_backoff: BACKOFF_FLOOR,
                max_backoff: BACKOFF_CEILING,
                jitter_ratio: 0.2,
            },
        );
        let worker = deliver_realm_inbox(&provider, inbox, &projector);
        futures_util::pin_mut!(runner, worker);
        let result = match futures_util::future::select(runner, worker).await {
            futures_util::future::Either::Left((result, _)) => result,
            futures_util::future::Either::Right(((), _)) => break,
        };
        let Some(retry_delay) = crate::runtime_helpers::next_reconnect_delay(
            provider.is_active(),
            &mut restart_backoff,
        ) else {
            break;
        };
        match result {
            Ok(reason) => tracing::warn!(
                reason = ?reason,
                retry_delay_ms = retry_delay.as_millis(),
                "realm events runner stopped while still active; reconnecting"
            ),
            Err(error) => tracing::warn!(
                error = %error,
                retry_delay_ms = retry_delay.as_millis(),
                "realm events runner stopped with error; reconnecting"
            ),
        }
        crate::runtime_helpers::sleep_for(retry_delay).await;
    }
}

async fn acquire_realm_governance_checkpoint(
    ctx: &RealmEventsEngineContext,
    realm_id: &arkret_sdk::RealmId,
) -> Result<(), String> {
    let base_url = ctx.base_url.get();
    let http = crate::identity::session_refresh::provide_authenticated_sdk_client(&base_url)
        .await
        .map_err(|error| format!("authenticated Realm checkpoint transport: {error}"))?;
    let api = crate::transport::TransportClient::from_http(
        http,
        crate::transport::RequestContext::new(ctx.token.get()),
    );
    crate::mls::creator_bootstrap::ensure_realm_governance_checkpoint(
        &api,
        ctx.state_store.clone(),
        realm_id.as_str(),
    )
    .await
}

struct RealmTransportProvider {
    ctx: RealmEventsEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<String>,
    realm_id: String,
}

impl TransportProvider for RealmTransportProvider {
    type Transport = crate::transport::websocket_rail::StreamRail<
        crate::client_core::InksonRealmEventsTransport,
    >;

    /// A scan is not a covered operation (§1), so it stays on HTTPS even while
    /// the rail is live; only the subscribe half moves.
    async fn provide(&self) -> garth::Result<Self::Transport> {
        let base = self.ctx.base_url.get();
        let http = crate::identity::session_refresh::provide_authenticated_sdk_client(&base)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(crate::transport::websocket_rail::StreamRail::select(
            &self.ctx.websocket_rail,
            crate::client_core::InksonRealmEventsTransport::new(http),
        ))
    }

    async fn recover_unauthorized(&self) -> garth::Result<bool> {
        match crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
            &self.ctx.base_url.get(),
        )
        .await
        {
            Ok(_) => Ok(true),
            Err(error) if crate::api_error::is_terminal_session_grant_error(&error) => Ok(false),
            Err(error) => Err(garth::Error::Http(error.to_string())),
        }
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && self.ctx.profiles.get().active_profile_id == self.start_profile_id
            && self.ctx.selected_realm_id.get() == self.realm_id
            && self.ctx.route_enabled.get()
            && !self.ctx.effect.is_cancelled()
            && !self.ctx.base_url.get().trim().is_empty()
            && !self.ctx.token.get().trim().is_empty()
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
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
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
        event.proofs.push(
            arkret_sdk::ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!(
                    "{ACTOR_CONTROLLER}#{DEVICE_ID}"
                ))
                .unwrap(),
                event_digest,
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }
            .into(),
        );
        let producer = event.proofs[0].as_producer().unwrap().clone();
        event.proofs.push(
            arkret_sdk::StationAdmissionProof {
                kind: arkret_sdk::StationAdmissionProofKind::StationAdmission,
                verification_method: arkret_sdk::DidUrl::new(
                    "did:web:principal.example#admission-1",
                )
                .unwrap(),
                event_digest: producer.event_digest.clone(),
                producer_proof_digest: arkret_sdk::StationAdmissionProof::producer_proof_digest(
                    &producer,
                )
                .unwrap(),
                producer_verification_method: producer.verification_method.clone(),
                producer_signing_key_did: arkret_sdk::DidKey::new("did:key:z6MkhFixtureDeviceKey")
                    .unwrap(),
                producer_signer_resolution_evidence_ref: None,
                producer_signer_resolution_evidence_digest: None,
                signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
                signer_resolution_evidence_digest: arkret_sdk::Hash::new(format!(
                    "sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
                accepted_at: event.created_at,
                jws: "header..admission".to_owned(),
            }
            .into(),
        );
        match garth::InboundDecoder::new()
            .try_decode_event(event)
            .unwrap()
        {
            garth::DecodedInbound::Message(message) => ClientEvent::Message(*message),
            garth::DecodedInbound::Event(_) => panic!("message.create must decode as a message"),
        }
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
    fn final_binding_rejects_delegated_or_ambiguous_sender_identity() {
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

        let mut ambiguous = direct_message_event();
        let ClientEvent::Message(message) = &mut ambiguous else {
            unreachable!();
        };
        message.event.proofs.push(message.event.proofs[0].clone());
        assert!(
            accepted_direct_message_final(&ambiguous, arkret_sdk::DigestSuite::Sha256, &store,)
                .is_none()
        );
    }
}
