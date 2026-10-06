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

mod own_live;
mod own_station;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use arkret_sdk::EventPayloadExt;
use garth::{
    AuthorityClient, ClientEvent, CommitStreamRef, CommittedDelta, CommittedEventView,
    DecodedInbound, InboundDecoder, RealmReplica, RetrySchedule, StreamScanRequest,
};
pub(crate) use own_station::refresh_accepted_sidecar;

use crate::config::MultiProfileConfig;
// Native hosts share the app's verifier and durable projector through these
// narrow adapters, without exposing UI or the rest of the transport internals.
pub use crate::runtime::effects::{EffectKey, EffectOwner, EffectRegistry};
pub use crate::runtime::input::{StateStoreHandle, ValueCell, ValueReader};
pub use crate::state::LocalStateStore;
pub use crate::transport::websocket::WebSocketTransportSelector;
pub use crate::transport::websocket_rail::{SharedConnection, WebSocketRail};

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence. The doubling ladder is [`garth::RetrySchedule`];
/// these are just its bounds, kept as `Duration` so the account and realm
/// engines share one unit (F-10).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Cancellation checks while the bounded subscription waits for a live hint.
const SUBSCRIBE_CANCEL_POLL: Duration = Duration::from_millis(250);

/// Rows requested per scan. The Station may return fewer and flag `truncated`,
/// which this engine drains before moving to the next stream.
const SCAN_LIMIT: u16 = 200;

/// Runtime inputs consumed by the realm events engine. UI frameworks are
/// confined to the app adapter that constructs these handles.
#[derive(Clone)]
pub struct RealmEventsEngineContext {
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
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
    pub message_stream_hub: Option<crate::views::message_streams::MessageStreamHub>,
    /// Active multi-profile config — the engine exits when the active profile
    /// rotates (mirrors the account engine's profile guard).
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub effect: crate::runtime::effects::EffectHandle,
}

/// Shared product projection handles for a fully verified Realm replay.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    digest_suite: arkret_sdk::DigestSuite,
    realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    message_stream_hub: Option<crate::views::message_streams::MessageStreamHub>,
}

fn ingest_realm_batch(
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
        // Every verified reducer input reaches the product ingests: message
        // families decoded, all other kinds (Space, Strand, membership,
        // moderation, RSVP) as the Event itself.
        if let Some(event) = delta.event() {
            match decoder.decode_event(event.clone()) {
                DecodedInbound::Message(message) => batch.push(ClientEvent::Message(message)),
                DecodedInbound::Event(event) => batch.push(ClientEvent::Event(event)),
            }
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
pub(crate) fn accepted_direct_message_final<'a>(
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
    if event.human_device_producer().ok().flatten().is_none() {
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

#[cfg(test)]
fn stage_verified_page(
    replica: &mut RealmReplica,
    request: &StreamScanRequest,
    outcome: arkret_sdk::StreamScanOutcome,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    keys: &arkret_identity::RealmAuthorityKeyMap,
    pages: &mut Vec<garth::VerifiedScanPage>,
) -> garth::Result<(Option<u64>, bool)> {
    let page = replica.apply_verified_scan(request, outcome, freshness, keys)?;
    let empty = page.rows().is_empty();
    let position = replica
        .verified_head(&request.stream_ref)
        .map(|head| head.stream_position);
    pages.push(page);
    Ok((position, empty))
}

/// Run the Realm commit-stream follow loop for `realm_id` until the generation
/// is bumped, the active profile rotates, or the selected realm changes.
pub async fn run_realm_events_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    realm_id: String,
    ctx: RealmEventsEngineContext,
) {
    run_realm_events_engine_with_transport(
        start_generation,
        generation,
        realm_id,
        ctx,
        |station: String| async move {
            crate::identity::session_refresh::provide_authenticated_sdk_client(&station).await
        },
    )
    .await;
}

/// Run the same verifier, follower and durable projector with a host-provided
/// authenticated SDK transport. Native hosts can supply their trust store;
/// the default app entry point retains the shared session provider.
pub async fn run_realm_events_engine_with_transport<P, F>(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    realm_id: String,
    ctx: RealmEventsEngineContext,
    provide: P,
) where
    P: Fn(String) -> F,
    F: std::future::Future<Output = anyhow::Result<arkret_sdk::http_client::Client>>,
{
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
    let mut backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING);
    let mut replica = garth::own_station_results::OwnStationReplica::new(realm_id_typed.clone());
    let mut replica_session = None;
    let mut subscription_cursor = None;

    while is_active() {
        let http = match provide(ctx.base_url.get()).await {
            Ok(http) => http,
            Err(error) => {
                if !retry_after(&mut backoff, is_active(), &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        let own = match crate::transport::own_station_results::client_for_http(&http).await {
            Ok(own) => own,
            Err(error) => {
                if !retry_after(&mut backoff, is_active(), &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        let session = match own.session() {
            Ok(session) => session.clone(),
            Err(error) => {
                if !retry_after(&mut backoff, is_active(), &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        if replica_session.as_ref() != Some(&session) {
            replica = garth::own_station_results::OwnStationReplica::new(realm_id_typed.clone());
            replica_session = Some(session);
            subscription_cursor = None;
        }
        match own_live::subscription(
            &own,
            &http,
            &realm_id_typed,
            &projector,
            &ctx,
            &is_active,
            &mut replica,
            &mut subscription_cursor,
        )
        .await
        {
            Ok(()) => {
                backoff.reset();
            }
            Err(error) => {
                if error.is_invalid_cursor() {
                    // Only this subscription handle is invalid. Independent
                    // verified stream heads and private MLS state survive.
                    subscription_cursor = None;
                }
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

/// Read the private scope's MLS current from a complete authority-signed cut.
/// Parent Realm state and a shape-only Sidecar GET cannot supply this binding.
pub(crate) async fn verified_sidecar_mls_current(
    api: &crate::transport::TransportClient,
    scope: &arkret_sdk::ScopeRef,
) -> garth::Result<(
    arkret_wire::MlsGroupCurrent,
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
)> {
    if !matches!(scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
        return Err(protocol(
            "Sidecar current read requires its native effective scope",
        ));
    }
    let realm = scope.realm_id();
    let http = api.http();
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let response = client.snapshot_head(realm).await?;
    let mut replica = garth::own_station_results::OwnStationReplica::new(realm.clone());
    replica.install_bound_snapshot(&response)?;
    let snapshot = response.value()?;
    let stream = CommitStreamRef::from_scope(scope, Some(realm.clone()))?;
    if !snapshot
        .visible_stream_heads
        .iter()
        .any(|head| head.stream_ref == stream)
    {
        return Err(protocol(
            "authorized current Snapshot does not cover this Sidecar stream",
        ));
    }
    let current =
        crate::current_projection::current_mls_group(&snapshot.current_state_entries, scope)
            .ok_or_else(|| protocol("verified Sidecar Snapshot has no current MLS group"))?;
    client.check_session()?;
    Ok((current, client))
}

/// The human PCR's root is its accepted genesis: the closed PCR allowlist
/// has no owner-transfer or authority-reset writer. A fresh verified authority
/// bundle proves that exact lifetime lineage without disclosing a private PCR
/// through the ordinary Collaboration Realm snapshot surface.
pub(crate) async fn verified_root_authorization(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    actor: &arkret_sdk::ActorId,
) -> garth::Result<arkret_sdk::AuthorizationRef> {
    let holder = actor
        .as_account_id()
        .ok_or_else(|| protocol("PCR lifetime root requires a complete holder Account"))?;
    let root = crate::transport::own_station_results::holder_pcr_root_ref(http, realm, holder)
        .await
        .map_err(protocol)?;
    arkret_sdk::AuthorizationRef::new(root.to_string()).map_err(protocol)
}

#[cfg(test)]
fn holder_pcr_root_authorization(
    bundle: &arkret_sdk::RealmAuthorityBundle,
    realm: &arkret_sdk::RealmId,
    actor: &arkret_sdk::ActorId,
) -> garth::Result<arkret_sdk::AuthorizationRef> {
    let event = &bundle.genesis_event;
    let commit = &bundle.genesis_commit;
    let payload = event
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(protocol)?;
    if bundle.realm_id != *realm
        || event.realm_id != *realm
        || event.kind != arkret_sdk::EventKind::RealmCreate
        || event.scope_ref != arkret_sdk::ScopeRef::RealmGenesis
        || event.actor_id != *actor
        || actor.as_account_id().is_none()
        || payload.object.purpose != arkret_sdk::RealmPurpose::PrincipalControl
        || arkret_sdk::RealmId::from_event_id(&event.event_id) != *realm
        || commit.event_ref != event.event_id
        || commit.realm_id != *realm
        || commit.stream_position != 0
        || commit.previous_commit_ref.is_some()
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: realm.clone(),
            })
    {
        return Err(protocol(
            "root authorization does not bind this holder's exact human PCR genesis",
        ));
    }
    payload.object.validate().map_err(protocol)?;
    arkret_sdk::AuthorizationRef::new(event.event_id.to_string()).map_err(protocol)
}

/// Verify the original scope create under the current Realm authority and a
/// continuous parent stream ending at the signed current snapshot cut.
/// A Circle create is a parent Realm Event, not the Realm's root create.
pub(crate) async fn verified_creator_create(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
) -> garth::Result<(
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
    arkret_sdk::RealmStateSnapshot,
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
)> {
    for attempt in 0..3 {
        let result = verified_creator_create_at_cut(http, intent).await;
        if !creator_cut_changed(&result) || attempt == 2 {
            return result;
        }
        crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
    }
    unreachable!("the bounded creator-cut loop always returns")
}

fn creator_cut_changed<T>(result: &garth::Result<T>) -> bool {
    matches!(result, Err(garth::Error::AuthorityCutBehind))
        || matches!(result, Err(garth::Error::Api { status: 503, error })
            if error.error_code() == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable))
}

async fn verified_creator_create_at_cut(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
) -> garth::Result<(
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
    arkret_sdk::RealmStateSnapshot,
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
)> {
    let (client, response, cut) = creator_own_station_cut(http, intent).await?;
    let full_response = client
        .committed_event_get(intent.scope_create_event_id())
        .await?;
    let full = match full_response.value()? {
        CommittedEventView::Full(full) => full.clone(),
        _ => return Err(protocol("creator original Create is withheld")),
    };
    let reference = arkret_wire::CommittedEventRef {
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
        event_id: full.event.event_id.clone(),
    };
    let original =
        garth::own_station_results::consume_bound_event(&client, &reference, full_response).await?;
    original.value()?;
    let accepted =
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate::new(
            intent,
            full.event,
            full.commit,
            intent
                .effective_scope()
                .realm_id()
                .digest_suite_code()
                .digest_suite(),
            cut,
        )?;
    creator_own_station_unchanged(&client, &response).await?;
    Ok((accepted, response.into_value()?, client))
}

type CreatorOwnSnapshot = arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
    arkret_sdk::RealmId,
    arkret_sdk::RealmStateSnapshot,
>;

async fn creator_own_station_cut(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
) -> garth::Result<(
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    CreatorOwnSnapshot,
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority,
)> {
    use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority;
    static NEXT_QUERY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let response = client
        .snapshot_head(intent.effective_scope().realm_id())
        .await?;
    garth::own_station_results::consume_bound_snapshot(
        &response,
        intent.effective_scope().realm_id(),
    )?;
    let snapshot = response.value()?;
    own_station::validate_current_product(snapshot, intent.effective_scope().realm_id())?;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: snapshot.realm_id.clone(),
    };
    let genesis = snapshot
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                source_stream_ref: stream_ref,
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                value,
                ..
            } if stream_ref == &realm_stream => Some(value),
            _ => None,
        })
        .ok_or_else(|| protocol("creator current original omits Realm Genesis"))?;
    let genesis: arkret_sdk::RealmGenesis =
        serde_json::from_value(genesis.clone()).map_err(protocol)?;
    let session = response.session();
    let sequence = NEXT_QUERY
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |v| v.checked_add(1),
        )
        .map_err(|_| protocol("creator read sequence exhausted"))?
        + 1;
    let cut = MlsCreatorBootstrapAuthority::own_station(
        snapshot.clone(),
        genesis,
        session.account_id().clone(),
        session.grant_id().clone(),
        session.epoch(),
        sequence,
    )?;
    client.check_session()?;
    Ok((client, response, cut))
}

async fn creator_own_station_unchanged(
    client: &arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    before: &CreatorOwnSnapshot,
) -> garth::Result<()> {
    let after = client.snapshot_head(&before.value()?.realm_id).await?;
    garth::own_station_results::consume_bound_snapshot(&after, &before.value()?.realm_id)?;
    if before.value()?.governance_generation != after.value()?.governance_generation
        || before.value()?.visible_stream_heads != after.value()?.visible_stream_heads
    {
        return Err(garth::Error::AuthorityCutBehind);
    }
    client.check_session()?;
    Ok(())
}

/// Exact creator query at a complete independently verified current cut.
/// Missing disclosure, an incomplete chain or a changed cut is unavailable,
/// never evidence that a queued Genesis can be replaced.
pub(crate) async fn verified_creator_genesis(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
    pinned_create: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
) -> garth::Result<(
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority,
    arkret_sdk::RealmStateSnapshot,
    Option<arkret_sdk::CommittedEventFullView>,
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
)> {
    for attempt in 0..3 {
        let result = verified_creator_genesis_at_cut(http, intent, pinned_create).await;
        if !creator_cut_changed(&result) || attempt == 2 {
            return result;
        }
        // This is only a read retry. No absence or winner is published until
        // new own-Station originals and their complete chain agree.
        crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
    }
    unreachable!("the bounded creator-cut loop always returns")
}

async fn verified_creator_genesis_at_cut(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
    pinned_create: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
) -> garth::Result<(
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority,
    arkret_sdk::RealmStateSnapshot,
    Option<arkret_sdk::CommittedEventFullView>,
    arkret_sdk::http_client::own_station_results::OwnStationResultClient,
)> {
    let realm = intent.effective_scope().realm_id();
    let stream = CommitStreamRef::from_scope(intent.effective_scope(), Some(realm.clone()))?;
    let (client, snapshot_response, cut) = creator_own_station_cut(http, intent).await?;
    let snapshot = snapshot_response.value()?;
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|h| h.stream_ref == stream)
        .ok_or_else(|| protocol("creator scope has no current head"))?;
    let end = head
        .stream_position
        .checked_add(1)
        .ok_or_else(|| protocol("creator head overflow"))?;
    let mut replica = garth::own_station_results::OwnStationReplica::new(realm.clone());
    replica.install_bound_snapshot(&snapshot_response)?;
    let pages = own_station::genesis_pages(&client, realm, &stream, end, &mut replica)
        .await?
        .ok_or_else(|| protocol("creator exact history is unavailable below the readable floor"))?;
    if replica.head(&stream) != Some(head) {
        return Err(protocol("creator history does not reach exact current cut"));
    }
    let mut accepted = None;
    for page in &pages {
        for row in page.rows()? {
            let CommittedEventView::Full(full) = row else {
                return Err(protocol("creator history is withheld"));
            };
            if full.event.kind == arkret_sdk::EventKind::MlsGenesis
                && full.event.scope_ref == *intent.effective_scope()
            {
                if accepted.replace(full.clone()).is_some() {
                    return Err(protocol("creator scope has multiple accepted Genesis"));
                }
            }
        }
    }
    if accepted.is_none() {
        let current_create = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate::new(
            intent, pinned_create.accepted_event().clone(), pinned_create.covering_commit().clone(), pinned_create.digest_suite(), cut.clone())?;
        arkret_models_collaboration::mls_creator_bootstrap::validate_creator_genesis_absence_snapshot(intent, &current_create, snapshot)?;
    }
    creator_own_station_unchanged(&client, &snapshot_response).await?;
    Ok((cut, snapshot_response.into_value()?, accepted, client))
}

#[cfg(test)]
pub(crate) async fn fresh_verified_realm<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
) -> garth::Result<(
    arkret_sdk::RealmAuthorityBundle,
    arkret_identity::RealmAuthorityFreshness,
    RealmReplica,
)> {
    let mut replica = RealmReplica::new(realm_id.clone());
    let (bundle, freshness) =
        refresh_verified_realm(authority, http, realm_id, &mut replica).await?;
    Ok((bundle, freshness, replica))
}

#[cfg(test)]
async fn refresh_verified_realm<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    replica: &mut RealmReplica,
) -> garth::Result<(
    arkret_sdk::RealmAuthorityBundle,
    arkret_identity::RealmAuthorityFreshness,
)> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| garth::Error::Protocol(format!("authority nonce: {error}")))?;
    let request = arkret_sdk::AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(nonce))
            .map_err(|error| garth::Error::Protocol(error.to_string()))?,
    };
    let bundle = authority.resolve_authority(&request).await?;
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce.clone());
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    replica.refresh_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
    Ok((bundle, freshness))
}

/// The independent streams this client follows for one Realm.
///
/// The Realm stream is always followed. The authenticated Circle directory
/// supplies readable Circle streams even before any local MLS state exists;
/// previously held MLS scopes remain followed during directory refresh.
/// A directory preview never adds a stream. Every row is still checked
/// against the signed authority and Commit chain.
/// No combined ordering is derived across streams.
fn followed_streams(
    realm_id: &arkret_sdk::RealmId,
    ctx: &RealmEventsEngineContext,
    circles: &arkret_sdk::CircleList,
) -> Vec<CommitStreamRef> {
    let scopes = ctx
        .state_store
        .read(|store| store.local_mls_scopes_in_realm(realm_id.as_str()));
    merge_followed_streams(realm_id, circles, scopes)
}

fn merge_followed_streams(
    realm_id: &arkret_sdk::RealmId,
    circles: &arkret_sdk::CircleList,
    local_scopes: impl IntoIterator<Item = arkret_sdk::ScopeRef>,
) -> Vec<CommitStreamRef> {
    let mut refs: BTreeSet<CommitStreamRef> = BTreeSet::from([CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    }]);
    refs.extend(directory_circle_streams(realm_id, circles));
    for scope in local_scopes {
        if let Ok(stream_ref) = CommitStreamRef::from_scope(&scope, Some(realm_id.clone()))
            && stream_ref.realm_id() == realm_id
        {
            refs.insert(stream_ref);
        }
    }
    refs.into_iter().collect()
}

fn directory_circle_streams(
    realm_id: &arkret_sdk::RealmId,
    circles: &arkret_sdk::CircleList,
) -> BTreeSet<CommitStreamRef> {
    let mut refs = BTreeSet::new();
    if circles.realm_id == *realm_id {
        for circle in &circles.circles {
            if let arkret_sdk::CircleReadView::Full(circle) = circle
                && circle.realm_id == *realm_id
                && circle.viewer_membership == Some(arkret_sdk::CircleMembership::Join)
            {
                refs.insert(CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle.circle_id.clone(),
                });
            }
        }
    }
    refs
}

/// Pull one stream forward from its durable position until the Station stops
/// reporting a truncated window.
pub(crate) async fn resolve_stream_agent_keys(
    http: &arkret_sdk::http_client::Client,
    state_store: &crate::runtime::input::StateStoreHandle,
    projection_changed: bool,
) -> garth::Result<bool> {
    let changed = crate::identity::agent_signer_evidence::prefetch_durable_historical_agent_keys(
        http,
        state_store,
    )
    .await;
    state_store
        .read(|store| store.begin_durable_flush())
        .map_err(|error| garth::Error::Protocol(error.to_string()))?
        .wait()
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    Ok(changed || projection_changed)
}

/// The exact signed predecessor a limited Account window names, and the own
/// Station description whose operation bundles decide whether the by-ref read
/// exists at all.
#[derive(Clone, Copy)]
struct FloorAnchor<'a> {
    basis: &'a arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
    describe: &'a arkret_models_discovery::ServiceDescribe,
}

/// Where one verified per-stream replay may begin.
#[derive(Clone, Copy)]
enum ReplayStart<'a> {
    /// Continue only from a predecessor installed by this live verifier.
    VerifiedTail,
    /// Position 0 only. A readable history that begins above genesis cannot
    /// settle an Account window without a signed basis: such a window stays
    /// `preview_only` (`sync/client-sync.md` 5.2).
    Genesis,
    /// The caller's readable floor. The floor Commit the scan's
    /// `readable_floor` names is the one readable row whose predecessor the
    /// caller cannot resolve, so a `since_join` member verifies its readable
    /// prefix without position 0 (`governance/history-visibility.md` 3.1).
    /// Only the live stream follow uses it; it never settles a window cut.
    ReadableFloor,
    /// The exact signed committed-prefix basis of a limited Account window.
    Basis(FloorAnchor<'a>),
}

#[cfg(test)]
async fn verified_stream_pages<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    replica: &mut RealmReplica,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    realm_id: &arkret_sdk::RealmId,
    stream_ref: &CommitStreamRef,
    start: ReplayStart<'_>,
    window_end: Option<u64>,
) -> garth::Result<StreamPages> {
    // A full-history stream starts at genesis, or at the caller's verified
    // readable floor for the live follow. A limited Account window may start
    // only from the exact signed head named by its basis, read by reference
    // from a Station that advertises the exact-read bundle; the first
    // readable page must extend that signed head.
    let floor_anchor = match start {
        ReplayStart::Basis(anchor) => Some(anchor),
        ReplayStart::Genesis | ReplayStart::ReadableFloor | ReplayStart::VerifiedTail => None,
    };
    let floor_basis = floor_anchor.map(|anchor| anchor.basis);
    let snapshot = if let Some(anchor) = floor_anchor {
        let snapshot = authority
            .exact_snapshot(anchor.describe, realm_id, &anchor.basis.snapshot_ref)
            .await?;
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream_ref)
            .ok_or_else(|| {
                garth::Error::Protocol("exact floor snapshot omits requested stream".to_owned())
            })?;
        let position = head.stream_position;
        Some((snapshot, position))
    } else {
        None
    };
    let mut after_position = if matches!(start, ReplayStart::VerifiedTail) {
        Some(
            replica
                .verified_head(stream_ref)
                .ok_or_else(|| protocol("tail continuation has no verified predecessor"))?
                .stream_position,
        )
    } else {
        snapshot.as_ref().map(|(_, position)| *position)
    };
    let mut pages = Vec::new();
    let mut verified_floor_snapshot = None;
    let mut dependency_pages = BTreeMap::new();
    if let (Some(basis), Some((signed_snapshot, _))) = (floor_basis, snapshot.as_ref()) {
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependency.stream_ref == *stream_ref || dependency.stream_ref.realm_id() != realm_id
            {
                return Err(garth::Error::Protocol(
                    "floor dependency names the wrong stream or Realm".to_owned(),
                ));
            }
            if dependency_pages.contains_key(&dependency.stream_ref) {
                continue;
            }
            let head = signed_snapshot
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == dependency.stream_ref)
                .ok_or_else(|| {
                    garth::Error::Protocol("floor dependency has no signed stream head".to_owned())
                })?;
            let end = head.stream_position.checked_add(1).ok_or_else(|| {
                garth::Error::Protocol("floor dependency head overflows".to_owned())
            })?;
            let mut dependency_replica = replica.fork_verified_authority()?;
            let (proof, predecessor) = Box::pin(verified_stream_pages(
                authority,
                http,
                &mut dependency_replica,
                bundle,
                freshness,
                realm_id,
                &dependency.stream_ref,
                ReplayStart::Genesis,
                Some(end),
            ))
            .await?
            .into_verified()?;
            if predecessor.is_some()
                || dependency_replica.verified_head(&dependency.stream_ref) != Some(head)
            {
                return Err(garth::Error::Protocol(
                    "floor dependency scan does not reach signed head".to_owned(),
                ));
            }
            dependency_pages.insert(dependency.stream_ref.clone(), proof);
        }
    }
    loop {
        let next_position = match after_position {
            Some(position) => position.checked_add(1).ok_or_else(|| {
                garth::Error::Protocol("verified stream position overflow".to_owned())
            })?,
            None => 0,
        };
        let remaining = window_end
            .map(|end| {
                end.checked_sub(next_position).ok_or_else(|| {
                    garth::Error::Protocol(
                        "signed floor lies beyond Account window head".to_owned(),
                    )
                })
            })
            .transpose()?;
        // Scan only the frame's prefix. A later committed suffix belongs to
        // a subsequent frame and cannot change this frame's exact cut.
        let limit = remaining.map_or(SCAN_LIMIT, |count| {
            count.min(u64::from(SCAN_LIMIT)).max(1) as u16
        });
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(after_position),
            limit,
        };
        let outcome = authority.scan(&request).await?;
        if matches!(start, ReplayStart::VerifiedTail)
            && outcome
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > next_position)
        {
            outcome.validate_for_request(&request)?;
            return Ok(StreamPages::FloorAdvanced);
        }
        if let Some(basis) = floor_basis {
            if pages.is_empty() {
                let floor = outcome.readable_floor.as_ref().ok_or_else(|| {
                    garth::Error::Protocol("limited scan omits readable floor".to_owned())
                })?;
                let (snapshot, _) = snapshot.as_ref().ok_or_else(|| {
                    garth::Error::Protocol("floor basis has no exact snapshot".to_owned())
                })?;
                // The Snapshot's own signing method is resolved from the
                // signer Station's complete history at its signing time.
                let snapshot_keys = garth::fetch_historical_station_key_directory(
                    http,
                    bundle,
                    Some(&outcome),
                    Some(snapshot),
                )
                .await?;
                let snapshot_freshness = arkret_identity::RealmAuthorityFreshness::new(
                    chrono::Utc::now(),
                    freshness.expected_nonce.clone(),
                );
                // Every declared dependency has an exact verified scan.
                verified_floor_snapshot = Some(replica.install_verified_floor_predecessor(
                    stream_ref,
                    basis,
                    floor,
                    snapshot,
                    &snapshot_freshness,
                    &snapshot_keys,
                    &dependency_pages,
                )?);
            }
        } else if matches!(start, ReplayStart::Genesis)
            && let Err(error) = require_genesis_readable_floor(&outcome)
        {
            // Only the first page decides whether a genesis replay can start;
            // a floor that moves above genesis mid-replay is a broken scan.
            // A readable-floor replay needs no such gate: the scan contract
            // binds its first row to the named floor Commit, and Garth binds
            // every later page to the verified predecessor head.
            if pages.is_empty() {
                return Ok(StreamPages::AboveGenesis);
            }
            return Err(error);
        }
        // An empty tail is proved by the exact signed floor itself. The
        // read supplies its visibility floor, but no later row is installed.
        if remaining == Some(0) {
            break;
        }
        let truncated = outcome.truncated;
        let keys =
            garth::fetch_historical_station_key_directory(http, bundle, Some(&outcome), None)
                .await?;
        let page_freshness = arkret_identity::RealmAuthorityFreshness::new(
            chrono::Utc::now(),
            freshness.expected_nonce.clone(),
        );
        let (next_position, empty) = stage_verified_page(
            replica,
            &request,
            outcome,
            &page_freshness,
            &keys,
            &mut pages,
        )?;
        if empty
            || !truncated
            || window_end.is_some_and(|end| {
                next_position.and_then(|position| position.checked_add(1)) == Some(end)
            })
        {
            break;
        }
        after_position = next_position;
    }
    Ok(StreamPages::Verified(pages, verified_floor_snapshot))
}

/// One stream's verified scan, or the fact that a replay from genesis cannot
/// start because the caller's readable history begins above position 0 and
/// no signed basis was named.
enum StreamPages {
    Verified(
        Vec<garth::VerifiedScanPage>,
        Option<garth::VerifiedFloorSnapshot>,
    ),
    AboveGenesis,
    FloorAdvanced,
}

impl StreamPages {
    fn into_verified(
        self,
    ) -> garth::Result<(
        Vec<garth::VerifiedScanPage>,
        Option<garth::VerifiedFloorSnapshot>,
    )> {
        match self {
            Self::Verified(pages, snapshot) => Ok((pages, snapshot)),
            Self::AboveGenesis => Err(above_genesis_without_basis()),
            Self::FloorAdvanced => Err(protocol("stream readable floor moved during continuation")),
        }
    }
}

fn above_genesis_without_basis() -> garth::Error {
    garth::Error::Protocol(
        "verified stream requires a signed readable-floor snapshot anchor".to_owned(),
    )
}

fn require_genesis_readable_floor(outcome: &arkret_sdk::StreamScanOutcome) -> garth::Result<()> {
    if outcome
        .readable_floor
        .as_ref()
        .is_some_and(|floor| floor.oldest_position != 0)
    {
        return Err(garth::Error::Protocol(
            "verified stream requires a signed readable-floor snapshot anchor".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Default)]
pub struct VerifiedAccountFrame {
    pages: Vec<garth::VerifiedScanPage>,
    own_pages: Vec<garth::own_station_results::OwnStationScanPage>,
    own_replicas: BTreeMap<CommitStreamRef, garth::own_station_results::OwnStationReplica>,
    own_client: Option<arkret_sdk::http_client::own_station_results::OwnStationResultClient>,
    current_snapshots: BTreeMap<String, VerifiedCurrentSnapshot>,
    authority_bases: Vec<crate::state::PersistedRealmAuthorityBasis>,
    genesis_roles: BTreeMap<String, Option<arkret_sdk::CollaborationRealmRole>>,
    /// `preview_only` windows whose whole readable prefix this client
    /// replayed from genesis through a verified scan: exact from here on.
    resolved_preview_streams: BTreeSet<CommitStreamRef>,
    /// `preview_only` windows that stay display-only in this frame.
    preview_streams: BTreeSet<CommitStreamRef>,
}

/// Complete current material at a signature-verified head. Only the fetch
/// below constructs this capability; an Account current subset cannot.
pub(crate) struct VerifiedCurrentSnapshot {
    snapshot: arkret_wire::RealmStateSnapshot,
}

impl VerifiedCurrentSnapshot {
    pub(crate) fn snapshot(&self) -> &arkret_wire::RealmStateSnapshot {
        &self.snapshot
    }
}

pub(crate) fn snapshot_covers_account_cut(
    snapshot: &arkret_wire::RealmStateSnapshot,
    current: &arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult,
) -> bool {
    snapshot.realm_id == current.realm_id
        && snapshot.governance_generation >= current.governance_generation
        && current.stream_heads.iter().all(|old| {
            snapshot.visible_stream_heads.iter().any(|new| {
                new.stream_ref == old.stream_ref
                    && (new.stream_position > old.stream_position
                        || (new.stream_position == old.stream_position
                            && new.commit_id == old.commit_id))
            })
        })
}

impl VerifiedAccountFrame {
    #[cfg(test)]
    pub(crate) fn test_own_context(
        client: arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    ) -> Self {
        Self {
            own_client: Some(client),
            ..Self::default()
        }
    }

    pub(crate) fn stage_own_checkpoints(
        &self,
        store: &mut crate::state::LocalStateStore,
    ) -> Result<(), String> {
        if let Some(client) = &self.own_client {
            self.check_session().map_err(|error| error.to_string())?;
            for (stream, replica) in &self.own_replicas {
                store.stage_own_station_commit_stream_checkpoint(
                    client,
                    replica,
                    stream,
                    &self.own_pages,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn own_pages(&self) -> &[garth::own_station_results::OwnStationScanPage] {
        &self.own_pages
    }
    pub(crate) fn check_session(&self) -> garth::Result<()> {
        if let Some(client) = &self.own_client {
            client.check_session()?;
        }
        Ok(())
    }

    pub(crate) fn project_transaction<R>(
        &self,
        store: &mut crate::state::LocalStateStore,
        body: impl FnOnce(&mut crate::state::LocalStateStore) -> Result<R, String>,
    ) -> Result<R, String> {
        store.verified_projection_transaction(|store| {
            self.check_session().map_err(|error| error.to_string())?;
            if let Some(client) = &self.own_client {
                if store.active_authority().as_ref()
                    != Some(
                        client
                            .session()
                            .map_err(|error| error.to_string())?
                            .account_id(),
                    )
                {
                    return Err("ordinary frame belongs to another account store".into());
                }
            }
            body(store)
        })
    }

    pub(crate) fn current_snapshots(&self) -> &BTreeMap<String, VerifiedCurrentSnapshot> {
        &self.current_snapshots
    }

    pub(crate) fn authority_bases(&self) -> &[crate::state::PersistedRealmAuthorityBasis] {
        &self.authority_bases
    }

    pub(crate) fn genesis_roles(
        &self,
    ) -> &BTreeMap<String, Option<arkret_sdk::CollaborationRealmRole>> {
        &self.genesis_roles
    }

    fn retain_verified_authority(
        &mut self,
        bundle: &arkret_sdk::RealmAuthorityBundle,
        freshness: &arkret_identity::RealmAuthorityFreshness,
        keys: &dyn arkret_identity::RealmAuthorityKeyDirectory,
    ) -> garth::Result<()> {
        let verified = arkret_identity::verify_realm_authority_bundle(bundle, freshness, keys)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        // The readable history can start after genesis under `since_join`.
        // Classify only the closed genesis carried by this verified authority
        // chain, never an editable projection or a readable-window first row.
        let event = &bundle.genesis_event;
        let commit = &bundle.genesis_commit;
        if event.kind == arkret_sdk::EventKind::RealmCreate
            && event.scope_ref == arkret_sdk::ScopeRef::RealmGenesis
            && arkret_sdk::RealmId::from_event_id(&event.event_id) == bundle.realm_id
            && commit.stream_position == 0
            && commit.previous_commit_ref.is_none()
            && commit.stream_ref
                == (CommitStreamRef::Realm {
                    realm_id: bundle.realm_id.clone(),
                })
            && let Ok(payload) = serde_json::to_value(&event.payload)
                .and_then(serde_json::from_value::<arkret_sdk::RealmCreatePayload>)
            && payload.object.validate().is_ok()
        {
            self.genesis_roles.insert(
                bundle.realm_id.to_string(),
                (payload.object.purpose == arkret_sdk::RealmPurpose::DirectConversation)
                    .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation),
            );
        }
        let committed_ref = |commit: &arkret_wire::RealmCommit| arkret_wire::CommittedEventRef {
            event_id: commit.event_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        };
        self.authority_bases
            .push(crate::state::PersistedRealmAuthorityBasis {
                realm_id: verified.realm_id().clone(),
                current_service_id: verified.current_service_id().clone(),
                current_generation: verified.current_generation(),
                genesis_ref: committed_ref(&bundle.genesis_commit),
                last_authority_change_ref: bundle
                    .authority_transitions
                    .last()
                    .map(|transition| committed_ref(&transition.change_commit)),
                validated_at: freshness.now,
            });
        Ok(())
    }

    pub fn pages(&self) -> &[garth::VerifiedScanPage] {
        &self.pages
    }

    /// Preview windows the verified genesis replay settled as exact.
    pub fn resolved_preview_streams(&self) -> &BTreeSet<CommitStreamRef> {
        &self.resolved_preview_streams
    }

    /// Preview windows that remain display-only.
    pub fn preview_streams(&self) -> &BTreeSet<CommitStreamRef> {
        &self.preview_streams
    }

    /// The frame the product layer may consume. An entry whose current cut,
    /// rows or baseline coverage read a still-preview stream loses its
    /// current and baseline unless a separately verified signed Snapshot
    /// covers that cut. Preview committed rows remain display-only.
    pub fn product_frame(
        &self,
        frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    ) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        let mut product = frame.clone();
        if let Some(realms) = product.realms.as_mut() {
            for (realm, entry) in &mut realms.entries {
                if !self.current_snapshots.contains_key(realm)
                    && crate::state::current_index::current_reads_preview_stream(
                        entry,
                        &self.resolved_preview_streams,
                    )
                {
                    entry.current = None;
                    entry.baseline = None;
                }
            }
        }
        product
    }
}

fn row_source(row: &arkret_wire::TypedCurrentResult) -> &CommitStreamRef {
    match row {
        arkret_wire::TypedCurrentResult::Value {
            source_stream_ref, ..
        } => source_stream_ref,
    }
}

fn closed_discovery_value(payload: serde_json::Value) -> garth::Result<serde_json::Value> {
    let discovery: arkret_sdk::RealmDiscoveryPayload = serde_json::from_value(payload.clone())
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    if discovery
        .to_value()
        .map_err(|error| garth::Error::Protocol(error.to_string()))?
        != payload
    {
        return Err(garth::Error::Protocol(
            "floor discovery is not the closed payload".to_owned(),
        ));
    }
    payload
        .get("value")
        .cloned()
        .ok_or_else(|| garth::Error::Protocol("floor discovery omits its value".to_owned()))
}

fn closed_join_rule_value(
    policy: Option<&serde_json::Value>,
    payload: serde_json::Value,
) -> garth::Result<serde_json::Value> {
    let Some(policy) = policy else {
        return Err(garth::Error::Protocol(
            "floor join rule has no verified policy bundle predecessor".to_owned(),
        ));
    };
    let rule: arkret_sdk::RealmJoinRulePayload = serde_json::from_value(payload.clone())
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    if rule
        .to_value()
        .map_err(|error| garth::Error::Protocol(error.to_string()))?
        != payload
    {
        return Err(garth::Error::Protocol(
            "floor join rule is not the closed payload".to_owned(),
        ));
    }
    let value = payload
        .get("value")
        .cloned()
        .ok_or_else(|| garth::Error::Protocol("floor join rule omits its value".to_owned()))?;
    // join-policy.md §2: a restricted entry mode needs at least one automatic
    // gate in the same signed cut's policy bundle. The Station evaluated the
    // gates at admission; the client only checks the signed rows agree.
    if value == "restricted" || value == "knock_restricted" {
        let bundle: arkret_sdk::RealmPolicyBundlePayload =
            serde_json::from_value(policy.clone()).map_err(protocol)?;
        let automatic = bundle.join_policy.is_some_and(|join_policy| {
            join_policy.gates.iter().any(|gate| {
                matches!(
                    gate,
                    arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ClaimRequired { .. }
                        | arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ChallengeResponse { .. }
                        | arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ParentMembership { .. }
                )
            })
        });
        if !automatic {
            return Err(garth::Error::Protocol(
                "floor restricted join rule has no automatic join gate in the signed cut"
                    .to_owned(),
            ));
        }
    }
    Ok(value)
}

fn protocol(error: impl std::fmt::Display) -> garth::Error {
    garth::Error::Protocol(error.to_string())
}

/// Parse `value` as the closed type `T` and require the canonical
/// re-serialization to be the same JSON: unknown members, defaulted members
/// and non-canonical encodings all fail closed.
fn closed_value<T>(value: &serde_json::Value, family: &str) -> garth::Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let parsed: T = serde_json::from_value(value.clone())
        .map_err(|error| protocol(format!("signed {family} row: {error}")))?;
    if serde_json::to_value(&parsed).map_err(protocol)? != *value {
        return Err(protocol(format!(
            "signed {family} row is not its closed value"
        )));
    }
    Ok(parsed)
}

/// Strictly parse every current row of an exact signed single-stream
/// snapshot as its registered typed family. The rows are committed by the
/// Station signature Garth verified with the historical key of the snapshot's
/// governing tenure; their covering Commits lie at or before the signed head.
///
/// - Every row names this Realm stream as its `source_stream_ref` (decision 0103) at a position no
///   later than the signed head.
/// - `realm_genesis` and `realm_authority_root` are the genesis projections: their covering Commit
///   is the verified bundle's exact genesis Commit, the genesis value is the genesis Event's
///   `object`, and the root is the generation-zero creator controller.
/// - Other admitted families are the ordinary bootstrap closure a single governing Station issues:
///   profile, policy bundle (including a join policy the Station evaluated at admission), join rule
///   (a restricted mode needs an automatic gate in that bundle), history access (equal to the
///   signed floor's `history_access`), discovery, the alias and plaintext-visible-services facets,
///   member state, Realm-scoped Strand and the default-Strand pointer, which must name a Strand in
///   the same signed cut, the `message_revision` of each message (a create carrier's Strand must
///   have been created earlier in the same signed cut; a revise carrier names its own Message), and
///   the `object_redaction` of a redacted Message, whose every assertion redacts that Message.
///
/// MLS, Space structural siblings, placement, Invite registers and grants
/// use their existing SDK value types and retain their exact Realm subjects.
/// Missing structural siblings, unknown families and cross-row mismatches
/// reject the whole snapshot.
fn validate_signed_floor_rows(
    realm_id: &arkret_sdk::RealmId,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    signed_head: &arkret_wire::CommitStreamHead,
    history_access: arkret_sdk::HistoryAccess,
    rows: &[arkret_wire::TypedCurrentResult],
) -> garth::Result<()> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let genesis_commit = &bundle.genesis_commit;
    if bundle.realm_id != *realm_id
        || signed_head.stream_ref != realm_stream
        || genesis_commit.stream_ref != realm_stream
        || genesis_commit.stream_position != 0
        || genesis_commit.event_ref != bundle.genesis_event.event_id
    {
        return Err(protocol(
            "signed floor snapshot is not this Realm stream's verified genesis chain",
        ));
    }
    let genesis_revision = arkret_wire::CurrentRevision {
        commit_id: genesis_commit.commit_id.clone(),
        stream_position: 0,
    };
    let payload = serde_json::to_value(&bundle.genesis_event.payload).map_err(protocol)?;
    let object = payload
        .get("object")
        .ok_or_else(|| protocol("Genesis has no object"))?;
    validate_floor_product_rows(
        realm_id,
        signed_head,
        history_access,
        rows,
        &genesis_revision,
        object,
        &bundle.genesis_event.actor_id,
    )
}

fn validate_floor_product_rows(
    realm_id: &arkret_sdk::RealmId,
    signed_head: &arkret_wire::CommitStreamHead,
    history_access: arkret_sdk::HistoryAccess,
    rows: &[arkret_wire::TypedCurrentResult],
    genesis_revision: &arkret_wire::CurrentRevision,
    genesis_object: &serde_json::Value,
    genesis_actor: &arkret_sdk::ActorId,
) -> garth::Result<()> {
    use arkret_wire::CurrentSelector;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let policy = rows.iter().find_map(|row| match row {
        arkret_wire::TypedCurrentResult::Value {
            selector: CurrentSelector::RealmPolicyBundle,
            value,
            ..
        } => Some(value),
        _ => None,
    });
    let mut genesis = false;
    let mut direct_conversation = false;
    let mut history_at_genesis = false;
    let mut bindings = Vec::new();
    let mut root = false;
    let mut strands = BTreeMap::new();
    let mut default_strand = None;
    let mut messages = Vec::new();
    let mut spaces = BTreeMap::new();
    let mut space_parents = BTreeMap::new();
    let mut space_policies = BTreeSet::new();
    let mut positions = Vec::new();
    let mut selectors = BTreeSet::new();
    for row in rows {
        let arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        if !selectors
            .insert(arkret_sdk::canonical::canonical_json_bytes(selector).map_err(protocol)?)
        {
            return Err(protocol("signed floor repeats a current selector"));
        }
        if source_stream_ref != &realm_stream
            || revision.stream_position > signed_head.stream_position
            || (revision.stream_position == signed_head.stream_position
                && revision.commit_id != signed_head.commit_id)
        {
            return Err(protocol(
                "signed floor row source is not the signed Realm stream prefix",
            ));
        }
        let genesis_projection = matches!(selector, CurrentSelector::RealmGenesis);
        let authority_root = matches!(selector, CurrentSelector::RealmAuthorityRoot);
        // A Direct Conversation genesis also writes `realm_history_access`
        // `null -> since_join` in its own covering Commit
        // (`models/realm-and-space.md` 2.5.1 step 5).
        let genesis_history =
            matches!(selector, CurrentSelector::RealmHistoryAccess) && revision == genesis_revision;
        if !genesis_history
            && !authority_root
            && genesis_projection != (revision == genesis_revision)
        {
            return Err(protocol(
                "signed floor row revision differs from its genesis covering Commit",
            ));
        }
        match selector {
            CurrentSelector::RealmGenesis => {
                let parsed: arkret_sdk::RealmGenesis = closed_value(value, "realm_genesis")?;
                parsed.validate().map_err(protocol)?;
                // A Collaboration Realm is founded with genesis purpose
                // `collaboration` or `direct_conversation`
                // (`models/realm-and-space.md` 2.8.2).
                if !matches!(
                    parsed.purpose,
                    arkret_sdk::RealmPurpose::Collaboration
                        | arkret_sdk::RealmPurpose::DirectConversation
                ) || genesis_object != value
                {
                    return Err(protocol(
                        "signed genesis row is not the verified collaboration genesis object",
                    ));
                }
                direct_conversation =
                    parsed.purpose == arkret_sdk::RealmPurpose::DirectConversation;
                genesis = true;
            }
            CurrentSelector::RealmAuthorityRoot => {
                let parsed: arkret_wire::RealmAuthorityRootValue =
                    closed_value(value, "realm_authority_root")?;
                parsed.validate().map_err(protocol)?;
                if revision.stream_position == 0 && revision != genesis_revision {
                    return Err(protocol(
                        "signed authority root has a different genesis covering Commit",
                    ));
                }
                // Owner transfers and authority resets update this current value;
                // only its genesis revision fixes the initial creator and counters.
                if revision == genesis_revision
                    && *value
                        != serde_json::json!({
                            "controller_actor_id": genesis_actor,
                            "controller_epoch": 0,
                            "authority_generation": 0,
                        })
                {
                    return Err(protocol(
                        "signed authority root is not the generation-zero creator controller",
                    ));
                }
                root = true;
            }
            CurrentSelector::RealmReadReceiptPolicy => {
                closed_value::<
                    arkret_models_collaboration::events_payloads::ReadReceiptPolicyPayload,
                >(value, "realm_read_receipt_policy")?
                .validate()
                .map_err(protocol)?;
            }
            CurrentSelector::RealmProfile => {
                let parsed: arkret_sdk::RealmProfile = closed_value(value, "realm_profile")?;
                if parsed.to_value().map_err(protocol)? != *value {
                    return Err(protocol("signed Realm profile is not its closed value"));
                }
            }
            CurrentSelector::RealmPolicyBundle => {
                let parsed: arkret_sdk::RealmPolicyBundlePayload =
                    closed_value(value, "realm_policy_bundle")?;
                if parsed.policy_revision == 0 {
                    return Err(protocol("signed policy bundle has no policy revision"));
                }
            }
            CurrentSelector::RealmJoinRule => {
                closed_join_rule_value(policy, serde_json::json!({ "value": value }))?;
            }
            CurrentSelector::RealmHistoryAccess => {
                let parsed: arkret_sdk::HistoryAccess =
                    closed_value(value, "realm_history_access")?;
                if parsed != history_access {
                    return Err(protocol(
                        "signed history access differs from the signed history floor",
                    ));
                }
                if genesis_history {
                    if parsed != arkret_sdk::HistoryAccess::SinceJoin {
                        return Err(protocol(
                            "genesis history access is not the Direct Conversation since_join",
                        ));
                    }
                    history_at_genesis = true;
                }
            }
            CurrentSelector::RealmDiscovery => {
                closed_discovery_value(serde_json::json!({ "value": value }))?;
            }
            CurrentSelector::RealmAlias => {
                closed_value::<
                    arkret_models_collaboration::governance::realm_governance::RealmAliasPayload,
                >(value, "realm_alias")?
                .validate()
                .map_err(protocol)?;
            }
            CurrentSelector::RealmPlaintextVisibleServices => {
                closed_value::<
                    arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
                >(value, "realm_plaintext_visible_services")?;
            }
            CurrentSelector::MessageRevision { message_id } => {
                // The chain's current carrier: its create, or the revise that
                // replaced it, which must name this same Message.
                if value.get("message_id").is_some() {
                    let parsed: arkret_models_collaboration::events_payloads::message::MessageRevisePayload =
                        closed_value(value, "message_revision")?;
                    if &parsed.message_id != message_id {
                        return Err(protocol("signed message revision names another Message"));
                    }
                } else {
                    let parsed: arkret_sdk::MessageCreatePayload =
                        closed_value(value, "message_revision")?;
                    messages.push((parsed.strand_id, revision.stream_position));
                }
            }
            CurrentSelector::ObjectRedaction { target_ref } => {
                // Only a Message redaction has a product installer; its
                // assertions all redact exactly the selected Message.
                if arkret_sdk::MessageId::new(target_ref.as_str()).is_err() {
                    return Err(protocol(
                        "signed object redaction subject has no product installer",
                    ));
                }
                closed_value::<
                    arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue,
                >(value, "object_redaction")?
                .validate_for_subject(target_ref)
                .map_err(protocol)?;
            }
            CurrentSelector::MemberIdentityUpdates { member_id, segment } => {
                // This family is Realm-local; the enclosing stream gate rejects
                // a Circle source. Preserve every exact signed update payload.
                closed_value::<arkret_models_identity::MemberIdentityUpdatesCurrentValue>(
                    value,
                    "member_identity_updates",
                )?
                .validate_for_tuple(realm_id, member_id, *segment)
                .map_err(protocol)?;
            }
            CurrentSelector::AppletRegistration { applet_id } => {
                let registration = closed_value::<
                    arkret_models_integration::AppletRegistrationPayload,
                >(value, "applet_registration")?;
                if &registration.applet_id != applet_id {
                    return Err(protocol(
                        "signed Applet registration differs from its selector",
                    ));
                }
            }
            CurrentSelector::MemberState { .. } => {
                closed_value::<arkret_wire::MemberStateCurrent>(value, "member_state")?;
            }
            CurrentSelector::Sidecar { sidecar_id } => {
                // The Sidecar object is created in the parent Realm stream;
                // its private context, exchanges and MLS retain their own stream.
                let sidecar: arkret_sdk::AgentSidecar = closed_value(value, "sidecar")?;
                sidecar.validate_shape().map_err(protocol)?;
                if sidecar.id != *sidecar_id || sidecar.realm_id != *realm_id {
                    return Err(protocol(
                        "signed Sidecar differs from its parent Realm subject",
                    ));
                }
            }
            CurrentSelector::Circle { circle_id } => {
                // Circle configuration is created in the parent Realm stream.
                // Membership and MLS state retain their own Circle stream.
                let circle: arkret_sdk::Circle = closed_value(value, "circle")?;
                if circle.id.as_ref() != Some(circle_id)
                    || circle.realm_id != *realm_id
                    || circle.schema != arkret_wire::SchemaId::CIRCLE_V1
                {
                    return Err(protocol(
                        "signed Circle differs from its parent Realm subject",
                    ));
                }
            }
            CurrentSelector::Strand { strand_id } => {
                let parsed: arkret_models_collaboration::objects::strand::Strand =
                    closed_value(value, "strand")?;
                if parsed.id.as_ref() != Some(strand_id)
                    || parsed.schema != arkret_wire::SchemaId::STRAND_V1
                    || parsed.realm_id != *realm_id
                    || parsed.scope_circle_id.is_some()
                {
                    return Err(protocol(
                        "signed Strand row is not a Realm-scoped Strand of this Realm",
                    ));
                }
                strands.insert(strand_id.clone(), revision.stream_position);
            }
            CurrentSelector::Relation {
                primary_conflict_domain,
            } => {
                let relation: arkret_wire::relation::Relation = closed_value(value, "relation")?;
                relation
                    .validate_current_for_domain(realm_id, primary_conflict_domain)
                    .map_err(protocol)?;
                if relation.scope_circle_id.is_some() {
                    return Err(protocol("signed Realm floor contains a Circle Relation"));
                }
            }
            CurrentSelector::MlsGroup { scope_ref } => {
                let group: arkret_wire::MlsGroupCurrent = closed_value(value, "mls_group")?;
                if scope_ref
                    != &(arkret_sdk::ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                    || group.effective_scope != *scope_ref
                    || group.covered_key_access_revision > group.current_key_access_revision
                {
                    return Err(protocol(
                        "signed MLS group differs from its Realm selector or key-access cut",
                    ));
                }
            }
            CurrentSelector::Space { space_id } => {
                let space: arkret_models_collaboration::objects::space::Space =
                    closed_value(value, "space")?;
                space.validate().map_err(protocol)?;
                if space.id.as_ref() != Some(space_id)
                    || space.schema != arkret_wire::SchemaId::SPACE_V1
                    || space.realm_id != *realm_id
                    || space.scope_circle_id.is_some()
                    || space.parent_space_id.is_some()
                    || space.child_scope_policy.is_some()
                {
                    return Err(protocol(
                        "signed Space metadata differs from its registered Realm subject",
                    ));
                }
                spaces.insert(space_id.clone(), space);
            }
            CurrentSelector::SpaceParent { space_id } => {
                let parent = value
                    .as_object()
                    .filter(|object| object.len() == 1)
                    .and_then(|object| object.get("parent_space_id"))
                    .ok_or_else(|| {
                        protocol("signed Space parent is not its one-member closed value")
                    })?;
                let parent: Option<arkret_sdk::SpaceId> =
                    serde_json::from_value(parent.clone()).map_err(protocol)?;
                space_parents.insert(space_id.clone(), parent);
            }
            CurrentSelector::SpaceChildScopePolicy { space_id } => {
                closed_value::<
                    Option<arkret_models_collaboration::objects::space::ChildScopePolicy>,
                >(value, "space_child_scope_policy")?;
                space_policies.insert(space_id.clone());
            }
            CurrentSelector::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                let position: Option<
                    arkret_models_collaboration::objects::strand::StrandPositionCurrent,
                > = closed_value(value, "strand_position")?;
                if position.as_ref().is_some_and(|position| {
                    !(1..=128).contains(&position.rank.len())
                        || !position
                            .rank
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric())
                }) {
                    return Err(protocol(
                        "signed Strand position has an invalid canonical rank",
                    ));
                }
                positions.push((board_space_id.clone(), strand_id.clone(), position));
            }
            CurrentSelector::InviteLifecycle { .. } => {
                closed_value::<arkret_wire::InviteState>(value, "invite_lifecycle")?;
            }
            CurrentSelector::InviteDirectedInvitee { .. } => {
                closed_value::<arkret_models_collaboration::governance::membership_invite::InviteDirectedInviteeValue>(
                    value, "invite_directed_invitee",
                )?;
            }
            CurrentSelector::InviteLiveTarget { .. } => {
                closed_value::<arkret_models_collaboration::governance::membership_invite::InviteLiveTargetValue>(
                    value, "invite_live_target",
                )?;
            }
            CurrentSelector::CapabilityGrant { grant_id } => {
                let grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
                    closed_value(value, "capability_grant")?;
                if &grant.id != grant_id
                    || grant.realm_id.as_ref() != Some(realm_id)
                    || grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
                {
                    return Err(protocol(
                        "signed Capability Grant differs from its registered Realm subject",
                    ));
                }
            }
            CurrentSelector::RealmSetDefaultStrand => {
                let member = value
                    .as_object()
                    .filter(|object| object.len() == 1)
                    .and_then(|object| object.get("default_strand_id"))
                    .ok_or_else(|| {
                        protocol("signed default Strand is not its one-member closed value")
                    })?;
                let pointer: Option<arkret_sdk::StrandId> =
                    serde_json::from_value(member.clone()).map_err(protocol)?;
                default_strand = Some((pointer, revision.stream_position));
            }
            CurrentSelector::StrandWatch { .. } => {
                // This authenticated snapshot row remains typed current state.
                // Only the separate exact read can supply a self-watch CAS preimage.
                closed_value::<arkret_sdk::StrandWatchCurrentValue>(value, "strand_watch")?;
            }
            CurrentSelector::AgentInteraction { .. } => {
                // The signed Realm cut authenticates this registered mode row.
                // Ownership and mode authorization remain exact-read decisions.
                closed_value::<arkret_sdk::AgentInteractionCurrentValue>(
                    value,
                    "agent_interaction",
                )?;
            }
            CurrentSelector::ModerationFrankingProof { event_id } => {
                // This is authenticated current state of the receipt, not an
                // independently verified moderation evidence package. Garth
                // has already verified the Station's signed snapshot cut.
                let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                    closed_value(value, "moderation_franking_proof")?;
                if proof.realm_id != *realm_id
                    || proof.event_id != *event_id
                    || !(16..=256).contains(&proof.replay_nonce.len())
                    || !proof
                        .replay_nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
                    || proof.signature.is_empty()
                {
                    return Err(protocol(
                        "signed franking receipt differs from its Realm, target Event or closed proof shape",
                    ));
                }
            }
            CurrentSelector::DirectConversationBinding { pair_key } => {
                // The pair's endorsement set: one binding digest, and every
                // endorsement binds this pair inside this Realm
                // (`identity/contact-and-direct-conversation.md` 8.3).
                let binding: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue =
                    closed_value(value, "direct_conversation_binding")?;
                binding.binding_digest().map_err(protocol)?;
                if binding.endorsements.iter().any(|entry| {
                    &entry.value.pair_key != pair_key || entry.value.realm_id != *realm_id
                }) {
                    return Err(protocol(
                        "signed Direct Conversation binding names another pair or Realm",
                    ));
                }
                bindings.push(pair_key.clone());
            }
            _ => {
                return Err(protocol(format!(
                    "signed floor current family {selector:?} has no product installer"
                )));
            }
        }
    }
    if spaces.keys().collect::<BTreeSet<_>>() != space_parents.keys().collect::<BTreeSet<_>>()
        || spaces.keys().collect::<BTreeSet<_>>() != space_policies.iter().collect::<BTreeSet<_>>()
    {
        return Err(protocol(
            "signed Space cut omits a registered structural sibling",
        ));
    }
    for space_id in spaces.keys() {
        let mut parent = space_parents.get(space_id).and_then(Option::as_ref);
        let mut visited = BTreeSet::from([space_id]);
        while let Some(id) = parent {
            if !visited.insert(id) || !spaces.contains_key(id) {
                return Err(protocol("signed Space parent chain is missing or cyclic"));
            }
            parent = space_parents.get(id).and_then(Option::as_ref);
        }
    }
    for (board_id, strand_id, position) in positions {
        if !strands.contains_key(&strand_id)
            || spaces
                .get(&board_id)
                .is_none_or(|space| space.kind != "board")
            || position.as_ref().is_some_and(|position| {
                spaces
                    .get(&position.list_space_id)
                    .is_none_or(|space| space.kind != "list")
            })
        {
            return Err(protocol(
                "signed Strand position has no matching Board, List or Strand in its Realm cut",
            ));
        }
    }
    if let Some((Some(strand_id), position)) = &default_strand
        && strands
            .get(strand_id)
            .is_none_or(|created| created > position)
    {
        return Err(protocol(
            "signed default Strand names no Strand in the signed cut",
        ));
    }
    if messages.iter().any(|(strand_id, position)| {
        strands
            .get(strand_id)
            .is_none_or(|created| created >= position)
    }) {
        return Err(protocol(
            "signed message names no earlier Strand in the signed cut",
        ));
    }
    if history_at_genesis && !direct_conversation {
        return Err(protocol(
            "signed history access at genesis belongs only to a Direct Conversation genesis",
        ));
    }
    if !bindings.is_empty() && (!direct_conversation || bindings.len() > 1) {
        return Err(protocol(
            "signed Direct Conversation binding is not the one binding of a Direct Conversation Realm",
        ));
    }
    if genesis && root {
        Ok(())
    } else {
        Err(protocol(
            "signed floor snapshot omits collaboration genesis current",
        ))
    }
}

/// The account aggregate's committed rows are claims until an independent
/// nonce-bound stream scan returns the same exact rows. Full history can be
/// projected. A non-preview Realm-stream window anchored after a committed
/// prefix verifies its exact signed snapshot and continuous tail; typed
/// current remains the Station result carried by the Account frame.
///
/// Every window is decided per stream (client-sync §5.2), and a Realm may
/// carry a snapshot-anchored window beside other stream windows:
///
/// - A `preview_only` window never fails its siblings: the client backfills it with the same
///   verified scan from genesis. When that replay verifies the whole readable prefix, the window
///   start is no longer unknown and the stream is exact; when the caller's readable history starts
///   above genesis, the stream stays preview: its rows remain display rows only, and neither its
///   current nor any verified index or checkpoint advances.
/// - A snapshot slice of any stream uses that stream's signed predecessor and verified tail.
///   Sibling heads in the same snapshot do not become replay predecessors for the stream being
///   checked.
///
/// A verified row that contradicts the frame or a snapshot that fails
/// verification still fails the whole frame closed.
pub async fn verify_account_frame_commits(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    own_station::account_frame(http, frame).await
}

#[cfg(test)]
async fn verify_account_frame_with<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    verify_account_frame_described(authority, http, None, frame).await
}

/// `describe` is the own Station description whose operation bundles gate
/// the by-ref snapshot read; `None` reads it from the Station when a Realm
/// names a snapshot basis.
#[cfg(test)]
async fn verify_account_frame_described<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    describe: Option<&arkret_models_discovery::ServiceDescribe>,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    let mut verified = VerifiedAccountFrame::default();
    let Some(realms) = frame.realms.as_ref() else {
        return Ok(verified);
    };
    for (realm, entry) in &realms.entries {
        let realm_id = arkret_sdk::RealmId::new(realm.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if entry
            .streams
            .iter()
            .flatten()
            .any(|window| snapshot_window_basis(window).is_some())
        {
            verify_snapshot_realm(authority, http, describe, &realm_id, entry, &mut verified)
                .await?;
            continue;
        }
        require_genesis_window_basis(entry)?;
        verify_full_history_realm(authority, http, &realm_id, entry, &mut verified).await?;
    }
    Ok(verified)
}

/// Committed rows of one Realm entry grouped by their exact stream, each
/// stream named by exactly one window of the entry.
fn claimed_rows_by_stream<'a>(
    realm_id: &arkret_sdk::RealmId,
    entry: &'a arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
) -> garth::Result<BTreeMap<CommitStreamRef, Vec<&'a CommittedEventView>>> {
    let mut windows = BTreeSet::new();
    for window in entry.streams.iter().flatten() {
        if window.stream_ref.realm_id() != realm_id {
            return Err(garth::Error::Protocol(
                "account frame stream window belongs to another Realm".to_owned(),
            ));
        }
        if !windows.insert(&window.stream_ref) {
            return Err(garth::Error::Protocol(
                "account frame repeats a stream window".to_owned(),
            ));
        }
    }
    let mut by_stream: BTreeMap<CommitStreamRef, Vec<&CommittedEventView>> = BTreeMap::new();
    let mut seen_rows = BTreeSet::new();
    for row in entry.committed_events.iter().flatten() {
        if row.commit().realm_id != *realm_id {
            return Err(garth::Error::Protocol(
                "account frame Commit belongs to another Realm".to_owned(),
            ));
        }
        if !seen_rows.insert((
            row.commit().stream_ref.clone(),
            row.commit().stream_position,
        )) {
            return Err(garth::Error::Protocol(
                "account frame repeats a committed stream position".to_owned(),
            ));
        }
        if !windows.contains(&row.commit().stream_ref) {
            return Err(garth::Error::Protocol(
                "account frame Commit has no exact stream window head".to_owned(),
            ));
        }
        by_stream
            .entry(row.commit().stream_ref.clone())
            .or_default()
            .push(row);
    }
    Ok(by_stream)
}

/// Verify one Realm entry that names a signed snapshot basis on at least one
/// stream window. Each basis names its own exact signed predecessor and
/// verified tail; other windows use a verified replay from genesis (or stay
/// preview). The Account current is installed only when every stream read by
/// its cut has settled independently.
#[cfg(test)]
async fn verify_snapshot_realm<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    describe: Option<&arkret_models_discovery::ServiceDescribe>,
    realm_id: &arkret_sdk::RealmId,
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    verified: &mut VerifiedAccountFrame,
) -> garth::Result<()> {
    let mut claimed = claimed_rows_by_stream(realm_id, entry)?;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let (bundle, freshness, mut replica) = fresh_verified_realm(authority, http, realm_id).await?;
    let mut exact_pages = Vec::new();
    let mut exact_streams = BTreeSet::new();
    let mut unsettled = BTreeSet::new();
    let mut floors = Vec::new();
    for window in entry.streams.iter().flatten() {
        let rows = claimed.remove(&window.stream_ref).unwrap_or_default();
        if let Some(basis) = snapshot_window_basis(window) {
            let fetched;
            let describe = match describe {
                Some(describe) => describe,
                None => {
                    fetched = http
                        .describe_for_role(arkret_sdk::ServiceKind::Station)
                        .await?;
                    &fetched
                }
            };
            let (pages, floor_snapshot) = verified_stream_pages(
                authority,
                http,
                &mut replica,
                &bundle,
                &freshness,
                realm_id,
                &window.stream_ref,
                ReplayStart::Basis(FloorAnchor { basis, describe }),
                Some(window.next_position),
            )
            .await?
            .into_verified()?;
            let scanned = pages
                .iter()
                .flat_map(|page| page.rows())
                .collect::<Vec<_>>();
            require_window_start_row(basis, &scanned)?;
            require_exact_claimed_rows(&rows, &scanned)?;
            if rows.len() != scanned.len() {
                return Err(garth::Error::Protocol(
                    "Account window rows differ from the verified floor stream".to_owned(),
                ));
            }
            require_verified_window_head(window, &replica)?;
            let floor_snapshot = floor_snapshot.ok_or_else(|| {
                garth::Error::Protocol("floor snapshot did not pass Garth".to_owned())
            })?;
            floors.push((floor_snapshot, pages));
            continue;
        }
        let scan = verified_stream_pages(
            authority,
            http,
            &mut replica,
            &bundle,
            &freshness,
            realm_id,
            &window.stream_ref,
            ReplayStart::Genesis,
            Some(window.next_position),
        )
        .await?;
        match resolve_full_history_window(Some(window), &rows, scan)? {
            WindowResolution::Exact(pages) => {
                if window.preview_only == Some(true) {
                    verified
                        .resolved_preview_streams
                        .insert(window.stream_ref.clone());
                }
                exact_streams.insert(window.stream_ref.clone());
                exact_pages.extend(pages);
            }
            WindowResolution::Preview => {
                verified.preview_streams.insert(window.stream_ref.clone());
                unsettled.insert(window.stream_ref.clone());
            }
        }
    }
    if !floors.is_empty() {
        let current = entry.current.as_ref().ok_or_else(|| {
            garth::Error::Protocol("floor snapshot has no Account current cut".to_owned())
        })?;
        require_floor_current_cut(
            current,
            &floors.iter().map(|(floor, _)| floor).collect::<Vec<_>>(),
            bundle.current_generation,
            &replica,
            entry,
            &exact_streams,
            &unsettled,
        )?;
        for (floor_snapshot, floor_pages) in floors {
            if floor_snapshot.head().stream_ref == realm_stream {
                validate_signed_floor_rows(
                    realm_id,
                    &bundle,
                    floor_snapshot.head(),
                    floor_snapshot.history_access(),
                    floor_snapshot.rows(),
                )?;
            }
            verified.pages.extend(floor_pages);
        }
    }
    verified.pages.extend(exact_pages);
    let final_freshness = arkret_identity::RealmAuthorityFreshness::new(
        chrono::Utc::now(),
        freshness.expected_nonce.clone(),
    );
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    verified.retain_verified_authority(&bundle, &final_freshness, &keys)?;
    Ok(())
}

fn require_verified_window_head(
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    replica: &RealmReplica,
) -> garth::Result<()> {
    let expected_position = window.next_position.checked_sub(1).ok_or_else(|| {
        garth::Error::Protocol("account frame stream head has no position".to_owned())
    })?;
    if replica
        .verified_head(&window.stream_ref)
        .is_none_or(|head| {
            head.stream_position != expected_position || head.commit_id != window.head_commit_ref
        })
    {
        return Err(garth::Error::Protocol(
            "account frame stream head differs from verified scan".to_owned(),
        ));
    }
    Ok(())
}

/// The Account current cut of a snapshot-anchored Realm: the signed floor's
/// governance generation no older than any signed floor, one head per stream
/// window, each signed floor stream at its own verified head, every exactly
/// replayed stream at its verified head, and
/// every row sourced from a stream the frame settles (exact, or explicitly
/// preview so the cut stays out of the product current).
fn require_floor_current_cut(
    current: &arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult,
    floor_snapshots: &[&garth::VerifiedFloorSnapshot],
    current_generation: u64,
    replica: &RealmReplica,
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    exact_streams: &BTreeSet<CommitStreamRef>,
    unsettled: &BTreeSet<CommitStreamRef>,
) -> garth::Result<()> {
    let floor_streams = floor_snapshots
        .iter()
        .map(|floor| &floor.head().stream_ref)
        .collect::<BTreeSet<_>>();
    let windows = entry
        .streams
        .iter()
        .flatten()
        .map(|window| &window.stream_ref)
        .collect::<BTreeSet<_>>();
    let mut heads = BTreeSet::new();
    let mismatch = current.governance_generation != current_generation
        || floor_snapshots
            .iter()
            .any(|floor| current.governance_generation < floor.governance_generation())
        || current.stream_heads.iter().any(|head| {
            !heads.insert(&head.stream_ref)
                || !windows.contains(&head.stream_ref)
                || ((floor_streams.contains(&head.stream_ref)
                    || exact_streams.contains(&head.stream_ref))
                    && replica.verified_head(&head.stream_ref) != Some(head))
        })
        || floor_streams.iter().any(|stream| !heads.contains(*stream))
        || current.entries.iter().any(|row| {
            let source = row_source(row);
            !floor_streams.contains(source)
                && !exact_streams.contains(source)
                && !unsettled.contains(source)
        });
    if mismatch {
        return Err(garth::Error::Protocol(
            "Account current cut differs from signed floor snapshot".to_owned(),
        ));
    }
    Ok(())
}

/// Verify one Realm entry without a signed snapshot basis: every stream window
/// is replayed from genesis through a fresh nonce-bound verified scan. A
/// non-preview window without basis is valid only after this complete replay.
#[cfg(test)]
async fn verify_full_history_realm<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    verified: &mut VerifiedAccountFrame,
) -> garth::Result<()> {
    let mut by_stream: BTreeMap<CommitStreamRef, Vec<&CommittedEventView>> = BTreeMap::new();
    let mut seen_rows = BTreeSet::new();
    for row in entry.committed_events.iter().flatten() {
        if row.commit().realm_id != *realm_id {
            return Err(garth::Error::Protocol(
                "account frame Commit belongs to another Realm".to_owned(),
            ));
        }
        if !seen_rows.insert((
            row.commit().stream_ref.clone(),
            row.commit().stream_position,
        )) {
            return Err(garth::Error::Protocol(
                "account frame repeats a committed stream position".to_owned(),
            ));
        }
        by_stream
            .entry(row.commit().stream_ref.clone())
            .or_default()
            .push(row);
    }
    for window in entry.streams.iter().flatten() {
        if window.stream_ref.realm_id() != realm_id {
            return Err(garth::Error::Protocol(
                "account frame stream window belongs to another Realm".to_owned(),
            ));
        }
        by_stream.entry(window.stream_ref.clone()).or_default();
    }
    if by_stream.is_empty() {
        return Ok(());
    }
    let (bundle, freshness, mut replica) = fresh_verified_realm(authority, http, realm_id).await?;
    if entry
        .current
        .as_ref()
        .is_some_and(|current| current.governance_generation != bundle.current_generation)
    {
        return Err(garth::Error::Protocol(
            "Account current generation differs from fresh verified authority".to_owned(),
        ));
    }
    for (stream_ref, claimed_rows) in by_stream {
        let window = entry.streams.as_ref().and_then(|windows| {
            windows
                .iter()
                .find(|window| window.stream_ref == stream_ref)
        });
        let scan = verified_stream_pages(
            authority,
            http,
            &mut replica,
            &bundle,
            &freshness,
            realm_id,
            &stream_ref,
            ReplayStart::Genesis,
            window.map(|window| window.next_position),
        )
        .await?;
        let preview = window.is_some_and(|window| window.preview_only == Some(true));
        match resolve_full_history_window(window, &claimed_rows, scan)? {
            WindowResolution::Exact(pages) => {
                if preview {
                    verified.resolved_preview_streams.insert(stream_ref);
                }
                verified.pages.extend(pages);
            }
            WindowResolution::Preview => {
                verified.preview_streams.insert(stream_ref);
            }
        }
    }
    let final_freshness = arkret_identity::RealmAuthorityFreshness::new(
        chrono::Utc::now(),
        freshness.expected_nonce.clone(),
    );
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    verified.retain_verified_authority(&bundle, &final_freshness, &keys)?;
    Ok(())
}

/// How one stream window of a snapshot-less Realm entry was settled.
#[derive(Debug)]
enum WindowResolution {
    /// The verified replay from genesis covers the window and its head.
    Exact(Vec<garth::VerifiedScanPage>),
    /// A `preview_only` window whose prefix the caller cannot replay: its
    /// rows are display rows only.
    Preview,
}

fn resolve_full_history_window(
    window: Option<&arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow>,
    claimed_rows: &[&CommittedEventView],
    scan: StreamPages,
) -> garth::Result<WindowResolution> {
    let window = window.ok_or_else(|| {
        garth::Error::Protocol("account frame Commit has no exact stream window head".to_owned())
    })?;
    let pages = match scan {
        StreamPages::Verified(pages, None) => pages,
        StreamPages::Verified(_, Some(_)) => {
            return Err(garth::Error::Protocol(
                "genesis replay cannot carry a floor snapshot".to_owned(),
            ));
        }
        StreamPages::AboveGenesis if window.preview_only == Some(true) => {
            return Ok(WindowResolution::Preview);
        }
        StreamPages::AboveGenesis => return Err(above_genesis_without_basis()),
        StreamPages::FloorAdvanced => {
            return Err(protocol(
                "stream readable floor moved during window verification",
            ));
        }
    };
    let scanned = pages
        .iter()
        .flat_map(|page| page.rows())
        .collect::<Vec<_>>();
    require_exact_claimed_rows(claimed_rows, &scanned)?;
    require_exact_window_head(window, &scanned)?;
    Ok(WindowResolution::Exact(pages))
}

/// The exact signed-snapshot basis of one stream window. A preview window
/// never reaches the by-ref read or the product installer. A position-0 window
/// has no basis and is verified by a complete genesis scan.
fn snapshot_window_basis(
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
) -> Option<&arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis> {
    if window.preview_only == Some(true) {
        return None;
    }
    window.window_start_basis.as_ref()
}

/// The first verified row of a snapshot-anchored window starts right after
/// the committed-prefix anchor the basis names (Garth has already bound the
/// first row's predecessor to that signed head); the tail may be empty.
fn require_window_start_row(
    basis: &arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
    scanned: &[&CommittedEventView],
) -> garth::Result<()> {
    let anchored = scanned.first().is_none_or(|row| {
        basis.anchor_position.checked_add(1) == Some(row.commit().stream_position)
    });
    if anchored {
        Ok(())
    } else {
        Err(garth::Error::Protocol(
            "window start Commit differs from its signed snapshot anchor".to_owned(),
        ))
    }
}

fn require_genesis_window_basis(
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
) -> garth::Result<()> {
    if entry.streams.as_ref().is_some_and(|windows| {
        windows
            .iter()
            .any(|window| window.window_start_basis.is_some())
    }) {
        return Err(garth::Error::Protocol(
            "non-genesis Account window requires an exact verified snapshot slice".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn require_exact_claimed_rows(
    claimed_rows: &[&CommittedEventView],
    scanned: &[&CommittedEventView],
) -> garth::Result<()> {
    for claimed in claimed_rows {
        let exact = scanned
            .iter()
            .find(|item| item.commit().stream_position == claimed.commit().stream_position);
        if exact.is_none_or(|item| *item != *claimed) {
            return Err(garth::Error::Protocol(format!(
                "account frame Commit differs from verified stream row: stream={:?}, position={}, scanned={}, commit_matches={}, claimed_disclosed={}, scanned_disclosed={}",
                claimed.commit().stream_ref,
                claimed.commit().stream_position,
                exact.is_some(),
                exact.is_some_and(|item| item.commit() == claimed.commit()),
                claimed.reducer_input().is_some(),
                exact.is_some_and(|item| item.reducer_input().is_some()),
            )));
        }
    }
    Ok(())
}

fn require_exact_window_head(
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    scanned: &[&CommittedEventView],
) -> garth::Result<()> {
    let head_position = window.next_position.checked_sub(1).ok_or_else(|| {
        garth::Error::Protocol("account frame stream head has no position".to_owned())
    })?;
    let head = scanned
        .iter()
        .find(|item| item.commit().stream_position == head_position);
    if head.is_none_or(|item| item.commit().commit_id != window.head_commit_ref) {
        return Err(garth::Error::Protocol(
            "account frame stream head differs from verified scan".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_wire::TypedCurrentResult;
    use garth::CursorScope;
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const STRAND_ID: &str = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    const ACTOR_ID: &str = "ak:did_core:web:alice.example";
    const ACTOR_CONTROLLER: &str = "did:web:alice.example";
    const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000003";

    fn collaboration_genesis(salt: &str) -> arkret_sdk::RealmGenesis {
        arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::Collaboration,
            arkret_sdk::GenesisSalt::new(salt).unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_sdk::SecurityClass::Standard,
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            arkret_sdk::JoinRule::Invite,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::Listed,
            None,
            None,
        )
        .unwrap()
    }

    const GENESIS_SALT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn holder_pcr_root_is_exact_immutable_genesis_and_never_collaboration_owner() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../arkret-spec/spec/v1/artifacts/fixtures/pcr-genesis-fixture.json"
        ))
        .unwrap();
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let genesis = arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::PrincipalControl,
            arkret_sdk::GenesisSalt::new(GENESIS_SALT).unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_sdk::SecurityClass::HighAssurance,
            actor.as_account_id().unwrap().station_id.clone(),
            arkret_sdk::JoinRule::Invite,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::InviteOnly,
            Some(serde_json::from_value(fixture["founding_device_descriptor"].clone()).unwrap()),
            Some(arkret_sdk::ResolutionCommitment {
                did: arkret_sdk::Did::new(ACTOR_CONTROLLER).unwrap(),
                method_history_head: format!("sha256:{}", "a".repeat(64)),
                version_id: "1-fixture".to_owned(),
            }),
        )
        .unwrap();
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new(ACTOR_CONTROLLER).unwrap(),
            arkret_sdk::DidUrl::new(format!("{ACTOR_CONTROLLER}#{DEVICE_ID}")).unwrap(),
        );
        let event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            arkret_sdk::EventKind::RealmCreate.as_str(),
            arkret_sdk::ScopeRef::RealmGenesis,
            actor.clone(),
            json!({"object":genesis}),
        )
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let realm = event.realm_id.clone();
        let (mut bundle, ..) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm.clone(),
            Vec::new(),
            "alice.example",
            DEVICE_ID,
        );
        bundle.genesis_event = event.clone();
        bundle.genesis_commit.event_ref = event.event_id.clone();
        assert_eq!(
            holder_pcr_root_authorization(&bundle, &realm, &actor)
                .unwrap()
                .as_str(),
            event.event_id.as_str()
        );

        let other_account = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            actor.as_account_id().unwrap().principal_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(holder_pcr_root_authorization(&bundle, &realm, &other_account).is_err());
        let other_realm = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        assert!(holder_pcr_root_authorization(&bundle, &other_realm, &actor).is_err());
        let mut wrong_commit = bundle.clone();
        wrong_commit.genesis_commit.stream_position = 1;
        assert!(holder_pcr_root_authorization(&wrong_commit, &realm, &actor).is_err());
        wrong_commit = bundle.clone();
        wrong_commit.genesis_commit.event_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [7; 32]);
        assert!(holder_pcr_root_authorization(&wrong_commit, &realm, &actor).is_err());
        let mut collaboration = bundle;
        collaboration.genesis_event.payload.insert(
            "object".to_owned(),
            json!(collaboration_genesis(GENESIS_SALT)),
        );
        assert!(holder_pcr_root_authorization(&collaboration, &realm, &actor).is_err());
    }

    #[test]
    fn plaintext_circle_directory_membership_selects_scannable_streams() {
        let circle_id =
            arkret_sdk::CircleId::new("ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0")
                .unwrap();
        let preview_id = "ak:circle:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu";
        let directory_value = json!({
            "realm_id": REALM_ID,
            "circles": [
                {
                    "circle_id": circle_id,
                    "realm_id": REALM_ID,
                    "title": "Polls",
                    "summary": null,
                    "display": {"short_name": "Polls", "color_token": "blue", "symbol": {"glyph": "bolt"}},
                    "directory_visibility": "members",
                    "join_rule": "public",
                    "history_access": "all_history_for_current_members",
                    "mls_group_id": null,
                    "state": "active",
                    "viewer_membership": "join",
                    "member_ids": [{"kind": "account", "account_id": {
                        "principal_id": ACTOR_ID,
                        "station_id": "ak:did_core:web:station.example"}}],
                    "created_by": {"kind": "account", "account_id": {
                        "principal_id": ACTOR_ID,
                        "station_id": "ak:did_core:web:station.example"}},
                    "created_at": "2026-01-01T00:00:00.000Z",
                    "updated_by": null,
                    "updated_at": null
                },
                {
                    "circle_id": preview_id,
                    "realm_id": REALM_ID,
                    "visibility": "realm_members",
                    "display": {"color_token": "blue", "symbol": {"glyph": "bolt"}},
                    "member_count_bucket": "2-3",
                    "join_rule": "public",
                    "opaque_commitment": "a".repeat(64)
                }
            ]
        });
        let full: arkret_sdk::CircleView =
            serde_json::from_value(directory_value["circles"][0].clone()).unwrap();
        let mut nonmember_full = full.clone();
        nonmember_full.circle_id = arkret_sdk::CircleId::from_event_id(
            &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x62; 32]),
        );
        nonmember_full.viewer_membership = Some(arkret_sdk::CircleMembership::Leave);
        let preview: arkret_sdk::CirclePreview =
            serde_json::from_value(directory_value["circles"][1].clone()).unwrap();
        let directory = arkret_sdk::CircleList {
            realm_id: arkret_sdk::RealmId::new(REALM_ID).unwrap(),
            circles: vec![
                arkret_sdk::CircleReadView::Full(full),
                arkret_sdk::CircleReadView::Full(nonmember_full),
                arkret_sdk::CircleReadView::Preview(preview),
            ],
        };
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let sidecar_id = arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let local_sidecar = arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        };
        assert_eq!(
            merge_followed_streams(&realm_id, &directory, [local_sidecar]),
            vec![
                CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id,
                },
                CommitStreamRef::Sidecar {
                    realm_id,
                    sidecar_id,
                },
            ]
        );
    }

    fn set_row_value(row: &mut TypedCurrentResult, next: serde_json::Value) {
        let TypedCurrentResult::Value { value, .. } = row;
        *value = next;
    }

    #[test]
    fn signed_floor_watch_rows_admit_written_null_and_closed_object_but_reject_open_value() {
        use crate::test_support::committed_event::FixtureStation;
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let station = FixtureStation::did_web();
        let chain = |tail: Vec<(String, serde_json::Value)>| {
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &station,
                realm_id.clone(),
                json!({"object":collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator)
                    .into_iter()
                    .chain(tail)
                    .collect(),
                "alice.example",
                DEVICE_ID,
            )
        };
        let strand = strand_create_entry(
            &realm_id,
            &creator,
            crate::test_support::committed_event::fixture_time(8),
        );
        let (_, _, probe) = chain(vec![strand.clone()]);
        let strand_id = arkret_sdk::StrandId::from_event_id(&probe[6].event.event_id);
        for level in [None, Some(arkret_sdk::StrandWatchLevel::All)] {
            let watch = match level {
                Some(level) => arkret_sdk::StrandWatchSetPayload::set(
                    strand_id.clone(),
                    creator.clone(),
                    level,
                    Some(true),
                ),
                None => {
                    arkret_sdk::StrandWatchSetPayload::clear(strand_id.clone(), creator.clone())
                }
            };
            let (bundle, keys, items) = chain(vec![
                strand.clone(),
                ("ak.strand.watch.set".to_owned(), json!(watch)),
            ]);
            let mut snapshot = snapshot_at(&bundle, &items, bundle.bundle_issued_at);
            station.sign_snapshot(&mut snapshot);
            let request = arkret_sdk::AuthorityBundleRequest {
                realm_id: realm_id.clone(),
                nonce: bundle.current_assertion.nonce.clone(),
            };
            let freshness = arkret_identity::RealmAuthorityFreshness::new(
                bundle.bundle_issued_at + chrono::Duration::seconds(50),
                request.nonce.clone(),
            );
            let mut replica = RealmReplica::new(realm_id.clone());
            replica
                .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
                .unwrap();
            replica
                .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
                .unwrap();
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &snapshot.visible_stream_heads[0],
                arkret_sdk::HistoryAccess::SinceJoin,
                &snapshot.current_state_entries,
            )
            .unwrap();
            let watch_row = snapshot
                .current_state_entries
                .iter()
                .find(|row| {
                    matches!(
                        row,
                        TypedCurrentResult::Value {
                            selector: arkret_sdk::CurrentSelector::StrandWatch { .. },
                            ..
                        }
                    )
                })
                .unwrap();
            let TypedCurrentResult::Value { value, .. } = watch_row;
            assert_eq!(
                *value,
                if level.is_some() {
                    json!({"level":"all","level_public":true})
                } else {
                    json!(null)
                }
            );
            let mut open_snapshot = snapshot.clone();
            let row = open_snapshot
                .current_state_entries
                .iter_mut()
                .find(|row| {
                    matches!(
                        row,
                        TypedCurrentResult::Value {
                            selector: arkret_sdk::CurrentSelector::StrandWatch { .. },
                            ..
                        }
                    )
                })
                .unwrap();
            set_row_value(
                row,
                json!({"level":"all","level_public":true,"unknown":true}),
            );
            station.sign_snapshot(&mut open_snapshot);
            let mut open_replica = RealmReplica::new(realm_id.clone());
            open_replica
                .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
                .unwrap();
            open_replica
                .install_verified_current_snapshot_heads(&open_snapshot, &freshness, &keys)
                .unwrap();
            assert!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &open_snapshot.visible_stream_heads[0],
                    arkret_sdk::HistoryAccess::SinceJoin,
                    &open_snapshot.current_state_entries
                )
                .is_err()
            );
        }
    }

    #[test]
    fn signed_floor_space_cut_requires_closed_structural_siblings_and_acyclic_parents() {
        use arkret_wire::CurrentSelector;
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                vec![(
                    "ak.realm.profile".to_owned(),
                    json!({"schema": "ak.schema.realm_profile.v1", "title": "Tail"}),
                )],
                "alice.example",
                DEVICE_ID,
            );
        let snapshot = snapshot_at(&bundle, &items, bundle.bundle_issued_at);
        let head = &snapshot.visible_stream_heads[0];
        let space_id = arkret_sdk::SpaceId::from_event_id(&items[0].event.event_id);
        let space = arkret_models_collaboration::objects::space::Space::new(
            space_id.clone(),
            realm_id.clone(),
            "board",
            "Board",
            bundle.genesis_event.actor_id.clone(),
        );
        let row = |selector, value| TypedCurrentResult::Value {
            selector,
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value,
        };
        let mut rows = snapshot.current_state_entries.clone();
        rows.extend([
            row(
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                json!(space),
            ),
            row(
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                json!({"parent_space_id": null}),
            ),
            row(
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                json!(null),
            ),
        ]);
        let validate = |rows: &[TypedCurrentResult]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        // These checks exercise the current-value boundary after snapshot authentication.
        validate(&rows).unwrap();
        let mut incomplete = rows.clone();
        incomplete.pop();
        assert!(validate(&incomplete).is_err());
        let mut cyclic = rows.clone();
        let parent_index = cyclic.len() - 2;
        set_row_value(
            &mut cyclic[parent_index],
            json!({"parent_space_id": space_id}),
        );
        assert!(validate(&cyclic).is_err());
        let mut extra = rows.clone();
        set_row_value(
            &mut extra[parent_index],
            json!({"parent_space_id": null, "unexpected": true}),
        );
        assert!(validate(&extra).is_err());
        let mut duplicate = rows.clone();
        duplicate.push(rows.last().unwrap().clone());
        assert!(validate(&duplicate).is_err());
        let mut foreign = rows.clone();
        let metadata_index = foreign.len() - 3;
        let mut foreign_space = space;
        foreign_space.realm_id = arkret_sdk::RealmId::from_event_id(&items[0].event.event_id);
        assert_ne!(foreign_space.realm_id, realm_id);
        set_row_value(&mut foreign[metadata_index], json!(foreign_space));
        assert!(validate(&foreign).is_err());
    }

    #[test]
    fn signed_parent_floor_installs_sidecar_and_rejects_foreign_or_open_values() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator)
                    .into_iter()
                    .chain([("ak.sidecar.create".to_owned(), json!({}))])
                    .collect(),
                "alice.example",
                DEVICE_ID,
            );
        let created = items.last().unwrap();
        let head = arkret_wire::CommitStreamHead {
            stream_ref: created.commit.stream_ref.clone(),
            stream_position: created.commit.stream_position,
            commit_id: created.commit.commit_id.clone(),
        };
        let rows = soland_bootstrap_rows(&bundle, &items);
        let validate = |rows: &[TypedCurrentResult]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        validate(&rows).unwrap();
        for (field, invalid) in [
            (
                "id",
                json!(arkret_sdk::SidecarId::from_event_id(
                    &bundle.genesis_event.event_id
                )),
            ),
            (
                "realm_id",
                json!(arkret_sdk::RealmId::from_event_id(&created.event.event_id)),
            ),
            ("schema", json!(arkret_sdk::SchemaId::CIRCLE_V1)),
            ("controller_account_id", json!({"principal_id": ACTOR_ID})),
            ("state", json!("suspended")),
            ("extra", json!(true)),
        ] {
            let mut forged = rows.clone();
            let TypedCurrentResult::Value { value, .. } = forged.last_mut().unwrap();
            value[field] = invalid;
            assert!(validate(&forged).is_err(), "accepted invalid {field}");
        }
        let mut private_source = rows.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = private_source.last_mut().unwrap();
        *source_stream_ref = CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&created.event.event_id),
        };
        assert!(validate(&private_source).is_err());
    }

    #[test]
    fn signed_parent_floor_installs_exact_circle_configuration_without_child_state() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let circle = arkret_sdk::Circle::create_object(
            realm_id.clone(),
            "Circle",
            crate::operation::ak_ops::circle_display_from_title("Circle"),
            creator.clone(),
        );
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator)
                    .into_iter()
                    .chain([("ak.circle.create".to_owned(), json!({"object": circle}))])
                    .collect(),
                "alice.example",
                DEVICE_ID,
            );
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let rows = soland_bootstrap_rows(&bundle, &items);
        let validate = |rows: &[TypedCurrentResult]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        validate(&rows).unwrap();
        let index = rows.len() - 1;
        let mut substituted = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut substituted[index];
        value["id"] = json!(arkret_sdk::CircleId::from_event_id(
            &items[0].event.event_id
        ));
        assert!(validate(&substituted).is_err());
        let mut foreign = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut foreign[index];
        value["realm_id"] = json!(arkret_sdk::RealmId::from_event_id(&items[0].event.event_id));
        assert!(validate(&foreign).is_err());
        let mut open = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut open[index];
        value["unregistered"] = json!(true);
        assert!(validate(&open).is_err());
        let mut child_source = rows.clone();
        let TypedCurrentResult::Value {
            source_stream_ref,
            selector,
            ..
        } = &mut child_source[index];
        let arkret_wire::CurrentSelector::Circle { circle_id } = selector else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        assert!(validate(&child_source).is_err());
    }

    #[test]
    fn signed_floor_genesis_rows_require_the_verified_genesis_commit_and_closed_value() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let genesis = collaboration_genesis(GENESIS_SALT);
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": genesis}),
                vec![(
                    "ak.realm.profile".to_owned(),
                    json!({"schema": "ak.schema.realm_profile.v1", "title": "Tail"}),
                )],
                "alice.example",
                DEVICE_ID,
            );
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            commit_id: bundle.genesis_commit.commit_id.clone(),
        };
        let genesis_revision = arkret_wire::CurrentRevision {
            commit_id: bundle.genesis_commit.commit_id.clone(),
            stream_position: 0,
        };
        let row = TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmGenesis,
            source_stream_ref: stream_ref.clone(),
            revision: genesis_revision.clone(),
            value: serde_json::to_value(&genesis).unwrap(),
        };
        let root = TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
            source_stream_ref: stream_ref.clone(),
            revision: genesis_revision,
            value: json!({
                "controller_actor_id": bundle.genesis_event.actor_id,
                "controller_epoch": 0,
                "authority_generation": 0,
            }),
        };
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        let installed_rows = vec![row.clone(), root.clone()];
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &installed_rows).unwrap();

        let mut forged_rows = Vec::new();
        let mut bad_value = row.clone();
        let TypedCurrentResult::Value { value, .. } = &mut bad_value;
        value.as_object_mut().unwrap().remove("schema");
        forged_rows.push(vec![bad_value, root.clone()]);
        let mut extra_member = row.clone();
        let TypedCurrentResult::Value { value, .. } = &mut extra_member;
        value["unknown"] = json!(true);
        forged_rows.push(vec![extra_member, root.clone()]);
        let mut other_genesis = row.clone();
        set_row_value(
            &mut other_genesis,
            serde_json::to_value(collaboration_genesis(
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            ))
            .unwrap(),
        );
        forged_rows.push(vec![other_genesis, root.clone()]);
        let mut unsupported = row.clone();
        let TypedCurrentResult::Value { selector, .. } = &mut unsupported;
        *selector = arkret_wire::CurrentSelector::DeviceGeneration;
        forged_rows.push(vec![unsupported, root.clone()]);
        let mut wrong_source = row.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut wrong_source;
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        forged_rows.push(vec![wrong_source, root.clone()]);
        let mut readable_revision = row.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut readable_revision;
        revision.stream_position = 1;
        revision.commit_id = items[0].commit.commit_id.clone();
        forged_rows.push(vec![readable_revision, root.clone()]);
        let mut other_controller = root.clone();
        set_row_value(
            &mut other_controller,
            json!({
                "controller_actor_id": {"kind":"service", "service_id":"ak:did_core:web:wrong.example"},
                "controller_epoch": 0,
                "authority_generation": 0,
            }),
        );
        forged_rows.push(vec![row.clone(), other_controller]);
        let mut rotated = root.clone();
        set_row_value(
            &mut rotated,
            json!({
                "controller_actor_id": bundle.genesis_event.actor_id,
                "controller_epoch": 1,
                "authority_generation": 0,
            }),
        );
        forged_rows.push(vec![row.clone(), rotated]);
        forged_rows.push(vec![row.clone()]);
        for rows in forged_rows {
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).is_err(),
                "{rows:?}"
            );
        }

        // A later registered owner transfer/reset changes this mutable current
        // root. Its immutable Realm genesis projection remains at position 0.
        let later_head = arkret_wire::CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: items[0].commit.stream_position,
            commit_id: items[0].commit.commit_id.clone(),
        };
        for (epoch, generation) in [(1, 0), (0, 1)] {
            let mut advanced = root.clone();
            let TypedCurrentResult::Value {
                revision, value, ..
            } = &mut advanced;
            *revision = arkret_wire::CurrentRevision {
                commit_id: later_head.commit_id.clone(),
                stream_position: later_head.stream_position,
            };
            value["controller_epoch"] = json!(epoch);
            value["authority_generation"] = json!(generation);
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &later_head,
                since_join,
                &[row.clone(), advanced.clone()],
            )
            .unwrap();
            let TypedCurrentResult::Value { value, .. } = &mut advanced;
            value["controller_epoch"] = json!(9_007_199_254_740_992_u64);
            assert!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &later_head,
                    since_join,
                    &[row.clone(), advanced]
                )
                .is_err()
            );
        }
    }

    /// A Direct Conversation is a Collaboration Realm founded with genesis
    /// purpose `direct_conversation` (`models/realm-and-space.md` 2.8.2); a
    /// control-plane genesis never installs as a collaboration floor.
    #[test]
    fn verified_authority_genesis_persists_role_without_readable_position_zero() {
        use crate::test_support::committed_event::{FixtureStation, fixture_time};
        for purpose in [
            arkret_sdk::RealmPurpose::DirectConversation,
            arkret_sdk::RealmPurpose::Collaboration,
        ] {
            let station = FixtureStation::did_web();
            let direct = purpose == arkret_sdk::RealmPurpose::DirectConversation;
            let genesis = arkret_sdk::RealmGenesis::new(
                purpose,
                arkret_sdk::GenesisSalt::new(GENESIS_SALT).unwrap(),
                arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
                arkret_sdk::SecurityClass::Standard,
                station.service_id().clone(),
                if direct {
                    arkret_sdk::JoinRule::Closed
                } else {
                    arkret_sdk::JoinRule::Invite
                },
                arkret_sdk::HistoryAccess::SinceJoin,
                if direct {
                    arkret_sdk::Discoverability::InviteOnly
                } else {
                    arkret_sdk::Discoverability::Listed
                },
                None,
                None,
            )
            .unwrap();
            let signer = arkret_test_kit::keys::seeded_signer(
                arkret_sdk::Did::new("did:web:alice.example").unwrap(),
                arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
            );
            let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                station.service_id().clone(),
            ));
            let event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
                arkret_sdk::EventKind::RealmCreate.as_str(),
                arkret_sdk::ScopeRef::RealmGenesis,
                actor,
                json!({"object": genesis}),
            )
            .with_created_at(fixture_time(0))
            .sign_verifiable(&signer)
            .unwrap()
            .expect_verifiable();
            let realm = event.realm_id.clone();
            let (mut bundle, keys, _) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &station,
                    realm.clone(),
                    json!({}),
                    Vec::new(),
                    "alice.example",
                    DEVICE_ID,
                );
            bundle.genesis_event = event.clone();
            bundle.genesis_commit.event_ref = event.event_id.clone();
            bundle.genesis_commit.authority_ref =
                arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
            bundle.genesis_commit = station.seal_commit(bundle.genesis_commit);
            bundle.realm_stream_head.commit_id = bundle.genesis_commit.commit_id.clone();
            bundle.current_assertion.realm_stream_head = bundle.realm_stream_head.clone();
            let nonce = bundle.current_assertion.nonce.clone();
            station.reassert_for_nonce(&mut bundle, nonce.clone(), fixture_time(50));
            let freshness = arkret_identity::RealmAuthorityFreshness::new(fixture_time(100), nonce);
            let mut verified = VerifiedAccountFrame::default();
            verified
                .retain_verified_authority(&bundle, &freshness, &keys)
                .unwrap();
            assert!(verified.pages().is_empty(), "no readable genesis replay");
            let expected = (purpose == arkret_sdk::RealmPurpose::DirectConversation)
                .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation);
            let path = std::env::temp_dir().join(format!(
                "inkson-authority-genesis-{}.json",
                crate::operation::uuid_v7()
            ));
            let mut store = crate::state::LocalStateStore::with_path(&path);
            store.save_realm_collaboration_role(
                realm.to_string(),
                Some(arkret_sdk::CollaborationRealmRole::DirectConversation),
            );
            store
                .verified_projection_transaction(|store| {
                    for (realm, role) in verified.genesis_roles() {
                        store.save_realm_collaboration_role(realm.clone(), *role);
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                crate::state::LocalStateStore::with_path(&path)
                    .load()
                    .realm_collaboration_roles
                    .get(realm.as_str())
                    .copied(),
                expected
            );
            let mut tampered = bundle.clone();
            tampered.genesis_event.payload.insert(
                "object".to_owned(),
                json!({"purpose": "direct_conversation"}),
            );
            let mut refused = VerifiedAccountFrame::default();
            assert!(
                refused
                    .retain_verified_authority(&tampered, &freshness, &keys)
                    .is_err()
            );
            assert!(refused.genesis_roles().is_empty());
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn signed_floor_genesis_admits_both_collaboration_purposes_only() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        for (purpose, admitted) in [
            (arkret_sdk::RealmPurpose::Collaboration, true),
            (arkret_sdk::RealmPurpose::DirectConversation, true),
            (arkret_sdk::RealmPurpose::PrincipalControl, false),
        ] {
            let genesis = arkret_sdk::RealmGenesis::new(
                purpose,
                arkret_sdk::GenesisSalt::new(GENESIS_SALT).unwrap(),
                arkret_sdk::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
                arkret_sdk::SecurityClass::Standard,
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                arkret_sdk::JoinRule::Invite,
                arkret_sdk::HistoryAccess::SinceJoin,
                arkret_sdk::Discoverability::Listed,
                None,
                None,
            );
            let Ok(genesis) = genesis else {
                assert!(!admitted, "{purpose:?} genesis must be constructible");
                continue;
            };
            let (bundle, ..) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &crate::test_support::committed_event::FixtureStation::did_web(),
                    realm_id.clone(),
                    json!({"object": genesis}),
                    Vec::new(),
                    "alice.example",
                    DEVICE_ID,
                );
            let stream_ref = CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            };
            let head = arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: bundle.genesis_commit.commit_id.clone(),
            };
            let revision = arkret_wire::CurrentRevision {
                commit_id: bundle.genesis_commit.commit_id.clone(),
                stream_position: 0,
            };
            let rows = vec![
                TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmGenesis,
                    source_stream_ref: stream_ref.clone(),
                    revision: revision.clone(),
                    value: serde_json::to_value(&genesis).unwrap(),
                },
                TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                    source_stream_ref: stream_ref,
                    revision,
                    value: json!({
                        "controller_actor_id": bundle.genesis_event.actor_id,
                        "controller_epoch": 0,
                        "authority_generation": 0,
                    }),
                },
            ];
            assert_eq!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &head,
                    arkret_sdk::HistoryAccess::SinceJoin,
                    &rows,
                )
                .is_ok(),
                admitted,
                "{purpose:?}"
            );
            // Only a Direct Conversation genesis writes history access in
            // its own covering Commit.
            let mut with_history = rows.clone();
            let TypedCurrentResult::Value {
                source_stream_ref,
                revision,
                ..
            } = rows[0].clone();
            with_history.push(TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                source_stream_ref,
                revision,
                value: json!("since_join"),
            });
            assert_eq!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &head,
                    arkret_sdk::HistoryAccess::SinceJoin,
                    &with_history,
                )
                .is_ok(),
                purpose == arkret_sdk::RealmPurpose::DirectConversation,
                "{purpose:?} genesis history access"
            );
        }
    }

    /// Soland discloses the founder's cut after messages and bootstrap facets:
    /// alias, plaintext-visible services and each created message's
    /// `message_revision` are installable closed rows, and a message must name
    /// a Strand created earlier in the same signed cut.
    #[test]
    fn signed_floor_rows_admit_bootstrap_facets_and_messages_of_earlier_strands() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let chain = |tail: Vec<(String, serde_json::Value)>| {
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator)
                    .into_iter()
                    .chain(tail)
                    .collect(),
                "alice.example",
                DEVICE_ID,
            )
        };
        let strand = strand_create_entry(
            &realm_id,
            &creator,
            crate::test_support::committed_event::fixture_time(8),
        );
        let (_, _, probe) = chain(vec![strand.clone()]);
        let strand_id = arkret_sdk::StrandId::from_event_id(&probe[6].event.event_id);
        let (bundle, _, items) = chain(vec![
            strand,
            default_strand_entry(&strand_id, None),
            message_create_entry(&strand_id, "discussion"),
        ]);
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let facet = |selector, value| TypedCurrentResult::Value {
            selector,
            source_stream_ref: items[0].commit.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: items[0].commit.commit_id.clone(),
                stream_position: items[0].commit.stream_position,
            },
            value,
        };
        let mut rows = soland_bootstrap_rows(&bundle, &items);
        rows.push(facet(
            arkret_wire::CurrentSelector::RealmPlaintextVisibleServices,
            json!({"services": [{
                "service_id": "ak:did_core:web:station.example",
                "service_kind": "station",
                "purposes": ["search"],
                "data_classes": ["message_content"],
                "visibility": "private_plaintext"
            }]}),
        ));
        rows.push(facet(
            arkret_wire::CurrentSelector::RealmAlias,
            json!({"tombstone": true}),
        ));
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).unwrap();

        let message_index = rows
            .iter()
            .position(|row| {
                matches!(
                    row,
                    TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        ..
                    }
                )
            })
            .unwrap();
        let mut forged = Vec::new();
        let mut unknown_strand = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut unknown_strand[message_index];
        value["strand_id"] = json!(arkret_sdk::StrandId::from_event_id(
            &bundle.genesis_event.event_id
        ));
        forged.push(unknown_strand);
        let mut open_message = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut open_message[message_index];
        value["unknown"] = json!(true);
        forged.push(open_message);
        let mut early_message = rows.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut early_message[message_index];
        revision.stream_position = items[5].commit.stream_position;
        revision.commit_id = items[5].commit.commit_id.clone();
        forged.push(early_message);
        let mut open_alias = rows.clone();
        let last = open_alias.len() - 1;
        set_row_value(&mut open_alias[last], json!({"tombstone": false}));
        forged.push(open_alias);
        let mut open_services = rows.clone();
        let services = open_services.len() - 2;
        set_row_value(
            &mut open_services[services],
            json!({"services": [], "extra": true}),
        );
        forged.push(open_services);
        for rows in forged {
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).is_err()
            );
        }
    }

    #[test]
    fn signed_floor_agent_interaction_keeps_closed_modes_and_stream_binding() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let controller = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let creator = arkret_sdk::ActorId::account(controller.clone());
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let agent = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            controller.station_id.clone(),
        );
        let mut rows = soland_bootstrap_rows(&bundle, &items);
        rows.push(TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::AgentInteraction {
                agent_account_id: agent,
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: json!({
                "controller_account_id": controller,
                "interaction_mode": "public",
            }),
        });
        let access = arkret_sdk::HistoryAccess::SinceJoin;
        for mode in ["public", "private"] {
            let TypedCurrentResult::Value { value, .. } = rows.last_mut().unwrap();
            value["interaction_mode"] = json!(mode);
            validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows).unwrap();
        }
        for (key, invalid) in [
            ("interaction_mode", json!("unknown")),
            ("interaction_mode", serde_json::Value::Null),
            ("controller_account_id", json!({"principal_id": ACTOR_ID})),
            ("scope_ref", json!({"realm_id": realm_id})),
        ] {
            let mut forged = rows.clone();
            let TypedCurrentResult::Value { value, .. } = forged.last_mut().unwrap();
            value[key] = invalid;
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, access, &forged).is_err()
            );
        }
        let mut foreign = rows.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = foreign.last_mut().unwrap();
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&items[2].event.event_id),
        };
        assert!(validate_signed_floor_rows(&realm_id, &bundle, &head, access, &foreign).is_err());
    }

    #[test]
    fn signed_floor_franking_receipt_binds_the_proven_event_and_closed_value() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let proven_event = items[2].event.event_id.clone();
        let value = json!({
            "realm_id": realm_id,
            "event_id": proven_event,
            "received_by": "ak:did_core:web:station.example",
            "verification_method": "did:web:station.example#receipt",
            "received_at": "2026-10-05T03:03:49.000Z",
            "replay_nonce": "opaque_receipt_nonce",
            "signature": "signed-receipt"
        });
        let mut rows = soland_bootstrap_rows(&bundle, &items);
        rows.push(TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::ModerationFrankingProof {
                event_id: proven_event,
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: value.clone(),
        });
        let access = arkret_sdk::HistoryAccess::SinceJoin;
        validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows).unwrap();
        for (key, invalid) in [
            ("event_id", json!(items[3].event.event_id)),
            (
                "realm_id",
                json!(arkret_sdk::RealmId::from_event_id(&items[3].event.event_id)),
            ),
            ("replay_nonce", json!("too-short")),
            ("replay_nonce", json!("invalid nonce with spaces")),
            ("signature", json!("")),
            ("plaintext", json!("must not appear in receipts")),
        ] {
            let mut bad = value.clone();
            bad[key] = invalid;
            let mut forged = rows.clone();
            set_row_value(forged.last_mut().unwrap(), bad);
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, access, &forged).is_err(),
                "{key}"
            );
        }
    }

    /// Soland's founder cut after an edit and a retraction: the edited
    /// Message's `message_revision` is the revise carrier naming that Message,
    /// and a retracted Message is disclosed as its `object_redaction` row, each
    /// assertion redacting exactly that Message. A revise naming another
    /// Message, an open or foreign redaction and a non-Message redaction
    /// subject reject the whole snapshot.
    #[test]
    fn signed_floor_snapshot_installs_message_revise_and_redaction() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let chain = |tail: Vec<(String, serde_json::Value)>| {
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator)
                    .into_iter()
                    .chain(tail)
                    .collect(),
                "alice.example",
                DEVICE_ID,
            )
        };
        let strand = strand_create_entry(
            &realm_id,
            &creator,
            crate::test_support::committed_event::fixture_time(8),
        );
        let (_, _, probe) = chain(vec![strand.clone()]);
        let strand_id = arkret_sdk::StrandId::from_event_id(&probe[6].event.event_id);
        let (bundle, _, items) = chain(vec![
            strand,
            default_strand_entry(&strand_id, None),
            message_create_entry(&strand_id, "discussion"),
        ]);
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let mut rows = soland_bootstrap_rows(&bundle, &items);
        let message_index = rows
            .iter()
            .position(|row| {
                matches!(
                    row,
                    TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        ..
                    }
                )
            })
            .unwrap();
        let TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MessageRevision { message_id },
            ..
        } = rows[message_index].clone()
        else {
            unreachable!()
        };
        set_row_value(
            &mut rows[message_index],
            json!({
                "message_id": message_id,
                "content": {"kind": "ak.content.text", "body": "edited", "format": "plain"}
            }),
        );
        let retracted = arkret_sdk::MessageId::from_event_id(&items[5].event.event_id);
        let redaction_tag = format!("{}:0", items.last().unwrap().event.event_id);
        let redaction = |target: &str, value: serde_json::Value| TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::ObjectRedaction {
                target_ref: target.to_owned(),
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value,
        };
        rows.push(redaction(
            retracted.as_str(),
            json!({"assertions": [{
                "tag_id": redaction_tag,
                "value": {"message_id": retracted, "reason": "retracted"}
            }]}),
        ));
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).unwrap();

        let redaction_index = rows.len() - 1;
        let mut forged = Vec::new();
        let mut foreign_revision = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut foreign_revision[message_index];
        value["message_id"] = json!(retracted);
        forged.push(foreign_revision);
        let mut open_revision = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut open_revision[message_index];
        value["unknown"] = json!(true);
        forged.push(open_revision);
        let mut foreign_redaction = rows.clone();
        set_row_value(
            &mut foreign_redaction[redaction_index],
            json!({"assertions": [{
                "tag_id": redaction_tag,
                "value": {"message_id": message_id}
            }]}),
        );
        forged.push(foreign_redaction);
        let mut open_redaction = rows.clone();
        set_row_value(
            &mut open_redaction[redaction_index],
            json!({"assertions": [{
                "tag_id": redaction_tag,
                "value": {"message_id": retracted}
            }], "redaction_ref": redaction_tag}),
        );
        forged.push(open_redaction);
        let mut empty_redaction = rows.clone();
        set_row_value(
            &mut empty_redaction[redaction_index],
            json!({"assertions": []}),
        );
        forged.push(empty_redaction);
        let mut event_subject = rows.clone();
        let event_target = items[5].event.event_id.to_string();
        event_subject[redaction_index] = redaction(
            &event_target,
            json!({"assertions": [{
                "tag_id": redaction_tag,
                "value": {"target_ref": event_target}
            }]}),
        );
        forged.push(event_subject);
        for rows in forged {
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).is_err(),
                "{rows:?}"
            );
        }
    }

    /// A restricted founder Realm: the Station evaluated the join policy at
    /// admission, so its signed bundle and restricted join rule install; a
    /// restricted rule without an automatic gate in that bundle does not.
    #[test]
    fn signed_floor_rows_admit_a_join_policy_and_its_restricted_join_rule() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        let rows_with = |join_policy: Option<serde_json::Value>, rule: &str| {
            let mut rows = soland_bootstrap_rows(&bundle, &items);
            for row in &mut rows {
                let TypedCurrentResult::Value {
                    selector, value, ..
                } = row;
                match selector {
                    arkret_wire::CurrentSelector::RealmPolicyBundle => {
                        if let Some(join_policy) = &join_policy {
                            value["join_policy"] = join_policy.clone();
                        }
                    }
                    arkret_wire::CurrentSelector::RealmJoinRule => *value = json!(rule),
                    _ => {}
                }
            }
            rows
        };
        let claim_gate = json!({"gates": [{
            "gate_id": "employee",
            "kind": "claim_required",
            "required_claims": ["employee"],
            "trusted_issuer_ids": ["ak:did_core:web:issuer.example"]
        }], "combinator": "all"});
        let hard_only = json!({"gates": [{
            "gate_id": "cooldown",
            "kind": "cooldown",
            "min_interval_since_leave": "P1D"
        }], "combinator": "all"});
        for (join_policy, rule) in [
            (Some(claim_gate.clone()), "restricted"),
            (Some(claim_gate.clone()), "knock_restricted"),
            (Some(hard_only.clone()), "invite"),
            (None, "invite"),
        ] {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                since_join,
                &rows_with(join_policy, rule),
            )
            .unwrap();
        }
        for (join_policy, rule) in [
            (None, "restricted"),
            (Some(hard_only), "knock_restricted"),
            (
                Some(json!({"gates": [], "combinator": "all", "extra": 1})),
                "invite",
            ),
        ] {
            assert!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &head,
                    since_join,
                    &rows_with(join_policy, rule),
                )
                .is_err(),
                "{rule}"
            );
        }
    }

    fn station_describe(bundles: &[&str]) -> arkret_models_discovery::ServiceDescribe {
        arkret_models_discovery::ServiceDescribe::development(
            arkret_sdk::Did::new("did:web:station.example".to_owned()).unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            arkret_sdk::ServiceKind::Station,
            bundles.iter().map(|id| (*id).to_owned()).collect(),
            vec![arkret_models_discovery::TransportBinding::HttpJson {
                base_url: "https://station.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    fn soland_bootstrap_rows(
        bundle: &arkret_sdk::RealmAuthorityBundle,
        items: &[arkret_sdk::CommittedEventFullView],
    ) -> Vec<TypedCurrentResult> {
        use arkret_wire::CurrentSelector;
        let row = |selector, commit: &arkret_sdk::RealmCommit, value| TypedCurrentResult::Value {
            selector,
            source_stream_ref: commit.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        };
        let genesis = serde_json::to_value(&bundle.genesis_event.payload).unwrap();
        let mut rows = vec![
            row(
                CurrentSelector::RealmGenesis,
                &bundle.genesis_commit,
                genesis["object"].clone(),
            ),
            row(
                CurrentSelector::RealmAuthorityRoot,
                &bundle.genesis_commit,
                json!({
                    "controller_actor_id": bundle.genesis_event.actor_id,
                    "controller_epoch": 0,
                    "authority_generation": 0,
                }),
            ),
        ];
        for item in items {
            let payload = serde_json::to_value(&item.event.payload).unwrap();
            let commit = &item.commit;
            rows.push(match item.event.kind.as_str() {
                "ak.realm.profile" => row(CurrentSelector::RealmProfile, commit, payload),
                "ak.realm.read_receipt_policy" => {
                    row(CurrentSelector::RealmReadReceiptPolicy, commit, payload)
                }
                "ak.realm.policy_bundle" => {
                    row(CurrentSelector::RealmPolicyBundle, commit, payload)
                }
                "ak.realm.join_rule" => row(
                    CurrentSelector::RealmJoinRule,
                    commit,
                    payload["value"].clone(),
                ),
                "ak.realm.history_access" => row(
                    CurrentSelector::RealmHistoryAccess,
                    commit,
                    payload["to"].clone(),
                ),
                "ak.realm.discovery" => row(
                    CurrentSelector::RealmDiscovery,
                    commit,
                    payload["value"].clone(),
                ),
                "ak.member.state" => row(
                    CurrentSelector::MemberState {
                        actor_id: serde_json::from_value(payload["member_id"].clone()).unwrap(),
                    },
                    commit,
                    json!({"membership": "join"}),
                ),
                "ak.circle.create" => {
                    let circle_id = arkret_sdk::CircleId::from_event_id(&item.event.event_id);
                    let mut value = payload["object"].clone();
                    value["id"] = json!(circle_id);
                    row(CurrentSelector::Circle { circle_id }, commit, value)
                }
                "ak.sidecar.create" => {
                    let sidecar_id = arkret_sdk::SidecarId::from_event_id(&item.event.event_id);
                    let sidecar = arkret_sdk::AgentSidecar {
                        id: sidecar_id.clone(),
                        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_V1.to_owned(),
                        realm_id: item.event.realm_id.clone(),
                        controller_account_id: item.event.actor_id.as_account_id().unwrap().clone(),
                        state: arkret_sdk::AgentSidecarState::Active,
                        state_changed_at: None,
                        created_at: item.event.created_at,
                        updated_at: None,
                    };
                    row(
                        CurrentSelector::Sidecar { sidecar_id },
                        commit,
                        json!(sidecar),
                    )
                }
                "ak.strand.create" => {
                    let strand_id = arkret_sdk::StrandId::from_event_id(&item.event.event_id);
                    let mut value = payload["object"].clone();
                    value["id"] = json!(strand_id);
                    value["state"] = json!("active");
                    row(CurrentSelector::Strand { strand_id }, commit, value)
                }
                "ak.realm.set_default_strand" => row(
                    CurrentSelector::RealmSetDefaultStrand,
                    commit,
                    json!({"default_strand_id": payload["strand_id"]}),
                ),
                "ak.strand.watch.set" => {
                    let watch: arkret_sdk::StrandWatchSetPayload =
                        serde_json::from_value(payload).unwrap();
                    let value = match watch.level {
                        Some(level) => arkret_sdk::StrandWatchCurrentValue::Set(
                            arkret_sdk::StrandWatchExpectedValue {
                                level,
                                level_public: watch.level_public,
                            },
                        ),
                        None => arkret_sdk::StrandWatchCurrentValue::Cleared(()),
                    };
                    row(
                        CurrentSelector::StrandWatch {
                            strand_id: watch.strand_id,
                            watcher_actor_id: watch.watcher_actor_id,
                        },
                        commit,
                        json!(value),
                    )
                }
                // Soland's `message_revision` writer: the create payload at
                // the Event-derived MessageId.
                "ak.message.create" => row(
                    CurrentSelector::MessageRevision {
                        message_id: arkret_sdk::MessageId::from_event_id(&item.event.event_id),
                    },
                    commit,
                    payload,
                ),
                other => panic!("{other} is outside the Soland bootstrap cut"),
            });
        }
        rows
    }

    fn ordinary_bootstrap_entries(
        creator: &arkret_sdk::ActorId,
    ) -> Vec<(String, serde_json::Value)> {
        vec![
            (
                "ak.realm.profile".to_owned(),
                json!({"schema": "ak.schema.realm_profile.v1", "title": "Bootstrap"}),
            ),
            (
                "ak.realm.policy_bundle".to_owned(),
                json!({"policy_revision": 1}),
            ),
            ("ak.realm.join_rule".to_owned(), json!({"value": "invite"})),
            (
                "ak.realm.history_access".to_owned(),
                json!({"from": null, "to": "since_join"}),
            ),
            (
                "ak.realm.discovery".to_owned(),
                json!({"value": {"discoverability": "listed"}}),
            ),
            (
                "ak.member.state".to_owned(),
                json!({
                    "realm_id": REALM_ID,
                    "member_id": creator,
                    "membership": "join",
                    "reason": "creator_membership"
                }),
            ),
        ]
    }

    fn account_scope() -> garth::CursorScope {
        garth::CursorScope::Account {
            service_id: None,
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
        }
    }

    #[test]
    fn creator_current_cut_replay_forks_authority_before_genesis_scan() {
        use crate::test_support::committed_event::FixtureStation;
        let realm = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let owner = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let station = FixtureStation::did_web();
        let (bundle, keys, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &station,
                realm.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&owner),
                "alice.example",
                DEVICE_ID,
            );
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(50),
            request.nonce.clone(),
        );
        let mut snapshot = snapshot_at(&bundle, &items, bundle.bundle_issued_at);
        station.sign_snapshot(&mut snapshot);
        let mut replica = RealmReplica::new(realm.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        replica
            .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
            .unwrap();
        let stream = arkret_sdk::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let scan = StreamScanRequest {
            realm_id: realm,
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 200,
        };
        let outcome = arkret_sdk::StreamScanOutcome {
            committed_events: std::iter::once(arkret_sdk::CommittedEventFullView {
                event: bundle.genesis_event.clone(),
                commit: bundle.genesis_commit.clone(),
            })
            .chain(items)
            .map(CommittedEventView::Full)
            .collect(),
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            }),
            truncated: false,
        };
        assert!(
            replica
                .apply_verified_scan(&scan, outcome.clone(), &freshness, &keys)
                .is_err()
        );
        let mut replay = replica.fork_verified_authority().unwrap();
        let mut forged = outcome.clone();
        let CommittedEventView::Full(last) = forged.committed_events.last_mut().unwrap() else {
            unreachable!()
        };
        last.commit.signature.sig = arkret_sdk::Base64UrlString::new("AA").unwrap();
        assert!(
            replay
                .apply_verified_scan(&scan, forged, &freshness, &keys)
                .is_err()
        );
        let page = replay
            .apply_verified_scan(&scan, outcome, &freshness, &keys)
            .unwrap();
        assert!(!page.rows().is_empty());
        assert_eq!(
            replay.verified_head(&stream),
            snapshot
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == stream)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn verified_native_sidecar_prefix_survives_restart_and_requires_the_signed_head() {
        use crate::state::LocalStateStore;
        use crate::test_support::committed_event::{FixtureStation, fixture_time};
        let realm = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let station = FixtureStation::did_web();
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            station.service_id().clone(),
        ));
        let (bundle, keys, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &station,
                realm.clone(),
                json!({"object":collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&actor),
                "alice.example",
                DEVICE_ID,
            );
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness =
            arkret_identity::RealmAuthorityFreshness::new(fixture_time(100), request.nonce.clone());
        let mut replica = RealmReplica::new(realm.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        let sidecar = arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [118; 32],
        ));
        let scope = arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        };
        let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
        );
        // This regression proves signature-gated replay persistence, not the
        // governing Station's separate context or MLS admission policy.
        let mut native = Vec::<arkret_sdk::CommittedEventFullView>::new();
        for position in 0..2_u64 {
            let mut payload = json!({"sidecar_id":sidecar,
                "source_context_ref":{"kind":"strand","strand_id":arkret_sdk::StrandId::from_event_id(&bundle.genesis_event.event_id)},
                "version":position+1});
            if let Some(previous) = native.last() {
                payload["predecessor_event_ref"] = json!(previous.event.event_id);
            }
            let event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
                arkret_sdk::EventKind::SidecarContextAttach.as_str(),
                scope.clone(),
                actor.clone(),
                payload,
            )
            .with_created_at(fixture_time(2 + position as i64))
            .sign_verifiable(&signer)
            .unwrap()
            .expect_verifiable();
            let mut commit = bundle.genesis_commit.clone();
            commit.commit_id = arkret_sdk::RealmCommitId::from_digest([120 + position as u8; 32]);
            commit.stream_ref = stream.clone();
            commit.stream_position = position;
            commit.previous_commit_ref = native.last().map(|full| full.commit.commit_id.clone());
            commit.event_ref = event.event_id.clone();
            // The ordinary checkpoint consumer checks the actual Commit
            // content address before admitting its original HTTP carrier.
            let mut identity = serde_json::to_value(&commit).unwrap();
            identity.as_object_mut().unwrap().remove("commit_id");
            identity.as_object_mut().unwrap().remove("signature");
            commit.commit_id =
                arkret_sdk::RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(
                    &arkret_sdk::canonical::canonical_json_bytes(&identity).unwrap(),
                ));
            native.push(arkret_sdk::CommittedEventFullView {
                commit: station.seal_commit(commit),
                event,
            });
        }
        let directory = std::env::temp_dir().join(format!(
            "inkson-sidecar-replay-{}",
            crate::operation::uuid_v7()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.json");
        let mut store = LocalStateStore::with_path(&path);
        let mut snapshot = snapshot_at(&bundle, &items, bundle.bundle_issued_at);
        let source_strand = arkret_sdk::StrandId::from_event_id(&bundle.genesis_event.event_id);
        let controller = actor.as_account_id().unwrap().clone();
        let revision = arkret_sdk::CurrentRevision {
            commit_id: native[0].commit.commit_id.clone(),
            stream_position: 0,
        };
        let mls_current = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: native[0].event.event_id.clone(),
            cipher_suite: arkret_sdk::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_mls_commit_event_ref: native[0].event.event_id.clone(),
            epoch: 1,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        };
        snapshot.current_state_entries.extend([
            TypedCurrentResult::Value {
                selector: arkret_sdk::CurrentSelector::MlsGroup {
                    scope_ref: scope.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: serde_json::to_value(&mls_current).unwrap(),
            },
            TypedCurrentResult::Value {
                selector: arkret_sdk::CurrentSelector::Sidecar {
                    sidecar_id: sidecar.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: json!({"id":sidecar,"schema":"ak.schema.agent_sidecar.v1",
                    "realm_id":realm,"controller_account_id":controller,"state":"active",
                    "created_at":"2026-01-01T00:00:00.000Z"}),
            },
            TypedCurrentResult::Value {
                selector: arkret_sdk::CurrentSelector::SidecarContext {
                    sidecar_id: sidecar.clone(),
                    source_context_ref: arkret_sdk::SidecarContextRef::Strand {
                        strand_id: source_strand.clone(),
                    },
                },
                source_stream_ref: stream.clone(),
                revision,
                value: serde_json::to_value(&native[0].event.payload).unwrap(),
            },
        ]);
        snapshot
            .visible_stream_heads
            .push(arkret_sdk::CommitStreamHead {
                stream_ref: stream.clone(),
                commit_id: native[0].commit.commit_id.clone(),
                stream_position: 0,
            });
        snapshot
            .retention_and_history_floor
            .stream_floors
            .push(arkret_sdk::StreamHistoryFloor {
                stream_ref: stream.clone(),
                oldest_position: 0,
            });
        station.sign_snapshot(&mut snapshot);
        replica
            .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
            .unwrap();
        store
            .install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })
            .unwrap();
        assert!(store.verified_sidecar_inputs(REALM_ID).is_err());
        assert!(store.current_mls_group_for_scope(&scope).is_none());
        let mut replay = replica.fork_verified_authority().unwrap();
        let scan = arkret_sdk::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 1,
        };
        let page = replay
            .apply_verified_scan(
                &scan,
                arkret_sdk::StreamScanOutcome {
                    committed_events: vec![CommittedEventView::Full(native[0].clone())],
                    readable_floor: Some(arkret_sdk::ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: native[0].commit.commit_id.clone(),
                        floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
                    }),
                    truncated: false,
                },
                &freshness,
                &keys,
            )
            .unwrap();
        store.ingest_verified_message_history(&page).unwrap();
        store.flush().unwrap();
        assert!(std::fs::read_dir(&directory).unwrap().next().is_some());
        drop(store);
        let mut reopened = LocalStateStore::with_path(&path);
        assert_eq!(
            reopened.current_mls_group_for_scope(&scope),
            Some(mls_current.clone())
        );
        let group_id = scope.canonical_mls_group_id().unwrap();
        let checkpoint = crate::mls::persistence::encrypt_state(
            REALM_ID,
            group_id.as_str(),
            0,
            b"provider state",
            "test-secret",
            &[7; 16],
        );
        reopened
            .install_accepted_mls_transition(&scope, checkpoint, &native[0].event.event_id)
            .unwrap();
        assert_eq!(
            reopened.mls_scopes_needing_tail_recovery(),
            vec![scope.clone()]
        );
        assert_eq!(
            reopened
                .verified_sidecar_for_source(&controller, REALM_ID, &source_strand)
                .unwrap()
                .unwrap()
                .id,
            sidecar
        );
        let other_strand = arkret_sdk::StrandId::from_event_id(&native[0].event.event_id);
        assert!(
            reopened
                .verified_sidecar_for_source(&controller, REALM_ID, &other_strand)
                .unwrap()
                .is_none()
        );
        let mut other_station = controller.clone();
        other_station.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            reopened
                .verified_sidecar_for_source(&other_station, REALM_ID, &source_strand)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            vec![native[0].clone()]
        );
        let old = snapshot.clone();
        let head = snapshot
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == stream)
            .unwrap();
        head.stream_position = 1;
        head.commit_id = native[1].commit.commit_id.clone();
        station.sign_snapshot(&mut snapshot);
        let mut current_verifier = replica.fork_verified_authority().unwrap();
        current_verifier
            .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
            .unwrap();
        let before_new_cut = reopened.load();
        assert!(!reopened.has_pending_sidecar_history(REALM_ID));
        let incomplete_cut = reopened.verified_projection_transaction(|store| {
            store.install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })?;
            store
                .sidecar_history_at_snapshot(&snapshot)
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        assert!(incomplete_cut.is_err());
        assert_eq!(
            reopened.load().verified_sidecar_current,
            before_new_cut.verified_sidecar_current
        );
        reopened
            .install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })
            .unwrap();
        assert!(reopened.verified_sidecar_inputs(REALM_ID).is_err());
        assert!(reopened.has_pending_sidecar_history(REALM_ID));
        assert!(
            reopened
                .install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                    snapshot: old.clone(),
                })
                .is_err()
        );
        assert!(reopened.current_mls_group_for_scope(&scope).is_none());
        assert!(reopened.mls_scopes_needing_tail_recovery().is_empty());
        assert!(
            reopened
                .verified_sidecar_for_source(&controller, REALM_ID, &source_strand)
                .is_err()
        );
        let scan = arkret_sdk::StreamScanRequest {
            direction: arkret_sdk::StreamScanDirection::After(Some(0)),
            ..scan
        };
        let page = replay
            .apply_verified_scan(
                &scan,
                arkret_sdk::StreamScanOutcome {
                    committed_events: vec![CommittedEventView::Full(native[1].clone())],
                    readable_floor: Some(arkret_sdk::ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: native[0].commit.commit_id.clone(),
                        floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
                    }),
                    truncated: false,
                },
                &freshness,
                &keys,
            )
            .unwrap();
        let mut live_follow = LocalStateStore::with_path(directory.join("live-follow.json"));
        live_follow.save(before_new_cut.clone());
        let previous_current = live_follow.load().verified_sidecar_current;
        live_follow.ingest_verified_message_history(&page).unwrap();
        assert_eq!(
            live_follow.load().verified_sidecar_current,
            previous_current,
            "history alone must not replace the accepted current original"
        );
        assert_eq!(
            live_follow.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            vec![native[0].clone()],
            "the old complete cut still exposes only its exact prefix"
        );
        let live_follow = own_live::tests::refresh_fixture_accepted_sidecar_current(
            live_follow,
            &snapshot,
            &controller,
            &native[1].commit,
        )
        .await;
        assert_eq!(
            live_follow.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            native
        );
        reopened.ingest_verified_message_history(&page).unwrap();
        assert!(!reopened.has_pending_sidecar_history(REALM_ID));
        let mut ahead = LocalStateStore::with_path(directory.join("ahead.json"));
        ahead.save(before_new_cut);
        ahead.ingest_verified_message_history(&page).unwrap();
        assert_eq!(
            ahead.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            vec![native[0].clone()]
        );
        let stream_key = serde_json::to_string(&stream).unwrap();
        assert_eq!(ahead.load().verified_sidecar_history[&stream_key].len(), 2);
        ahead
            .verified_projection_transaction(|store| {
                store
                    .sidecar_history_at_snapshot(&snapshot)
                    .map_err(|error| error.to_string())?;
                store.install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                    snapshot: snapshot.clone(),
                })
            })
            .unwrap();
        assert_eq!(
            ahead.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            native
        );
        let complete = ahead.load();
        let mut missing = complete.clone();
        missing
            .verified_sidecar_history
            .get_mut(&stream_key)
            .unwrap()
            .pop();
        ahead.save(missing);
        assert!(ahead.verified_sidecar_inputs(REALM_ID).is_err());
        let mut gap = complete.clone();
        gap.verified_sidecar_history
            .get_mut(&stream_key)
            .unwrap()
            .remove(0);
        ahead.save(gap);
        assert!(ahead.verified_sidecar_inputs(REALM_ID).is_err());
        let mut withheld = complete.clone();
        withheld
            .verified_sidecar_history
            .get_mut(&stream_key)
            .unwrap()[0] = CommittedEventView::Withheld(arkret_sdk::CommittedEventWithheldView {
            commit: native[0].commit.clone(),
            event_disclosure: arkret_sdk::EventDisclosure {
                status: arkret_sdk::EventDisclosureStatus::Withheld,
            },
        });
        ahead.save(withheld);
        assert!(ahead.verified_sidecar_inputs(REALM_ID).is_err());
        let mut wrong_head = snapshot.clone();
        wrong_head
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == stream)
            .unwrap()
            .commit_id = native[0].commit.commit_id.clone();
        ahead.save(complete);
        assert!(ahead.sidecar_history_at_snapshot(&wrong_head).is_err());
        drop(ahead);
        assert_eq!(
            reopened.current_mls_group_for_scope(&scope),
            Some(mls_current)
        );
        assert_eq!(
            reopened.mls_scopes_needing_tail_recovery(),
            vec![scope.clone()]
        );
        assert_eq!(
            reopened.verified_sidecar_inputs(REALM_ID).unwrap().1[sidecar.as_str()],
            native
        );
        assert!(
            reopened
                .install_verified_sidecar_current(&VerifiedCurrentSnapshot { snapshot: old })
                .is_err()
        );
        reopened.invalidate_sidecar_current(Some(REALM_ID));
        assert!(!reopened.has_pending_sidecar_history(REALM_ID));
        assert!(reopened.verified_sidecar_inputs(REALM_ID).is_err());
        assert!(reopened.mls_scopes_needing_tail_recovery().is_empty());
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn signed_snapshot_current_staging_is_atomic_and_cut_bound() {
        use crate::test_support::committed_event::FixtureStation;
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let creator = arkret_sdk::ActorId::account(account.clone());
        let station = FixtureStation::did_web();
        let (bundle, keys, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &station,
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(50),
            request.nonce.clone(),
        );
        let mut snapshot = snapshot_at(&bundle, &items, bundle.bundle_issued_at);
        station.sign_snapshot(&mut snapshot);
        let mut replica = RealmReplica::new(realm_id.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        replica
            .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
            .unwrap();
        let selector = match &snapshot.current_state_entries[0] {
            arkret_wire::TypedCurrentResult::Value { selector, .. } => selector.clone(),
        };
        let mut frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(json!({
            "kind":"delta", "cursor":"ak:cursor:YQ",
            "realms":{REALM_ID:{"current":{
                "realm_id":realm_id, "governance_generation":snapshot.governance_generation,
                "stream_heads":snapshot.visible_stream_heads, "entries":[]
            }}}
        }))
        .unwrap();
        let head = &snapshot.visible_stream_heads[0];
        frame
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .streams = Some(vec![
            serde_json::from_value(json!({
                "stream_ref": head.stream_ref,
                "head_commit_ref": head.commit_id,
                "next_position": head.stream_position + 1,
                "limited": true,
                "window_limit": 1,
                "complete": true,
                "preview_only": true
            }))
            .unwrap(),
        ]);
        let proofs = BTreeMap::from([(REALM_ID.to_owned(), VerifiedCurrentSnapshot { snapshot })]);
        let unresolved = VerifiedAccountFrame::default();
        assert!(
            unresolved.product_frame(&frame).realms.unwrap().entries[REALM_ID]
                .current
                .is_none()
        );
        let proven = VerifiedAccountFrame {
            current_snapshots: BTreeMap::from([(
                REALM_ID.to_owned(),
                VerifiedCurrentSnapshot {
                    snapshot: proofs[REALM_ID].snapshot().clone(),
                },
            )]),
            ..Default::default()
        };
        assert!(
            proven.product_frame(&frame).realms.unwrap().entries[REALM_ID]
                .current
                .is_some()
        );
        let store = crate::state::isolated_store_for_tests("signed-snapshot-atomic-cut");
        let index = crate::state::current_index::CurrentIndex::open(
            &account,
            0,
            store.current_index_location(),
        )
        .await
        .unwrap();
        let stage = index
            .stage_verified_frame_with_snapshots(0, &frame, &BTreeSet::new(), &proofs)
            .await
            .unwrap();
        drop(stage);
        assert_eq!(
            index.read_selector(REALM_ID, &selector).await.unwrap(),
            None
        );
        assert_eq!(index.read_complete_cut(REALM_ID).await.unwrap(), None);
        let mut wrong_cut = frame.clone();
        wrong_cut
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .current
            .as_mut()
            .unwrap()
            .stream_heads[0]
            .stream_position += 1;
        assert!(
            index
                .stage_verified_frame_with_snapshots(0, &wrong_cut, &BTreeSet::new(), &proofs,)
                .await
                .is_err()
        );
        assert_eq!(index.read_complete_cut(REALM_ID).await.unwrap(), None);
        let mut lagging = frame.clone();
        let earlier = &items[items.len() - 2].commit;
        let lagging_head = &mut lagging
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .current
            .as_mut()
            .unwrap()
            .stream_heads[0];
        lagging_head.stream_position = earlier.stream_position;
        lagging_head.commit_id = earlier.commit_id.clone();
        index
            .stage_verified_frame_with_snapshots(0, &lagging, &BTreeSet::new(), &proofs)
            .await
            .unwrap()
            .finish();
        assert!(index.read_complete_cut(REALM_ID).await.unwrap().is_some());
        assert!(
            index
                .read_selector(REALM_ID, &selector)
                .await
                .unwrap()
                .is_some()
        );
        let invalidation = serde_json::from_value(json!({
            "kind":"delta", "cursor":"ak:cursor:YQ",
            "realm_invalidations":[{"realm_id":REALM_ID,"revision":1}]
        }))
        .unwrap();
        index
            .stage_verified_frame(1, &invalidation, &BTreeSet::new())
            .await
            .unwrap()
            .finish();
        assert_eq!(index.read_complete_cut(REALM_ID).await.unwrap(), None);
        index
            .stage_verified_frame_with_snapshots(2, &lagging, &BTreeSet::new(), &proofs)
            .await
            .unwrap()
            .finish();
        assert!(index.read_complete_cut(REALM_ID).await.unwrap().is_some());
        assert!(
            index
                .read_selector_ready(REALM_ID, &selector)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn signed_floor_policy_values_preserve_omissions_and_reject_invalid_current() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        for policy in [
            json!({"disclosure":"disabled"}),
            json!({"disclosure":"required","visibility":"private","scope_overrides_allowed":false}),
        ] {
            let mut entries = ordinary_bootstrap_entries(&creator);
            entries.push(("ak.realm.read_receipt_policy".to_owned(), policy.clone()));
            let (bundle, _, items) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &crate::test_support::committed_event::FixtureStation::did_web(),
                    realm_id.clone(),
                    json!({"object": collaboration_genesis(GENESIS_SALT)}),
                    entries,
                    "alice.example",
                    DEVICE_ID,
                );
            let rows = soland_bootstrap_rows(&bundle, &items);
            let head = bundle.current_assertion.realm_stream_head.clone();
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                &rows,
            )
            .unwrap();
            let index = rows
                .iter()
                .position(|row| {
                    matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmReadReceiptPolicy,
                            ..
                        }
                    )
                })
                .unwrap();
            let arkret_wire::TypedCurrentResult::Value { value, .. } = &rows[index];
            assert_eq!(*value, policy);
            for invalid in [
                json!({}),
                json!({"disclosure":"sometimes"}),
                json!({"visibility":"anonymous"}),
                json!({"disclosure":"optional","visibility":null}),
                json!({"disclosure":"optional","unknown":true}),
            ] {
                let mut rejected = rows.clone();
                set_row_value(&mut rejected[index], invalid);
                assert!(
                    validate_signed_floor_rows(
                        &realm_id,
                        &bundle,
                        &head,
                        arkret_sdk::HistoryAccess::SinceJoin,
                        &rejected
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn signed_realm_floor_accepts_complete_relation_and_rejects_domain_or_scope_drift() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let domain = json!({"domain_kind":"tuple","relation_kind":"references",
            "from_ref":realm_id,"to_ref":realm_id});
        let mut entries = ordinary_bootstrap_entries(&creator);
        entries.push((
            "ak.relation.create".to_owned(),
            json!({
                "primary_conflict_domain":domain,"expected_revision":null,
                "relation":{"relation_kind":"references","from_ref":realm_id,"to_ref":realm_id}
            }),
        ));
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                entries,
                "alice.example",
                DEVICE_ID,
            );
        let accepted = items.last().unwrap();
        let head = bundle.current_assertion.realm_stream_head.clone();
        let mut rows = soland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        rows.push(arkret_wire::TypedCurrentResult::Value {
            selector: serde_json::from_value(json!({"kind":"relation",
                "primary_conflict_domain":domain}))
            .unwrap(),
            source_stream_ref: accepted.commit.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: accepted.commit.commit_id.clone(),
                stream_position: accepted.commit.stream_position,
            },
            value: json!({
                "schema":arkret_wire::SchemaId::RELATION_V1,
                "id":arkret_wire::RelationId::from_event_id(&accepted.event.event_id),
                "realm_id":realm_id,"effective_scope":accepted.event.scope_ref,
                "relation_kind":"references","from_ref":realm_id,"to_ref":realm_id,
                "state":"active","created_by":creator,
                "created_at":accepted.event.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }),
        });
        let validate = |rows: &[arkret_wire::TypedCurrentResult]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        validate(&rows).unwrap();
        let arkret_wire::TypedCurrentResult::Value { value, .. } = rows.last().unwrap();
        let valid = value.clone();
        for invalid in [
            {
                let mut value = valid.clone();
                value["locked"] = json!(true);
                value
            },
            {
                let mut value = valid.clone();
                value["id"] = serde_json::Value::Null;
                value
            },
            {
                let mut value = valid.clone();
                value["state"] = json!("tombstoned");
                value
            },
            {
                let mut value = valid.clone();
                value["scope_circle_id"] = json!(arkret_wire::CircleId::from_event_id(
                    &accepted.event.event_id
                ));
                value["effective_scope"] = json!(arkret_wire::ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: arkret_wire::CircleId::from_event_id(&accepted.event.event_id),
                });
                value
            },
        ] {
            let mut rejected = rows.clone();
            set_row_value(rejected.last_mut().unwrap(), invalid);
            assert!(validate(&rejected).is_err());
        }
        let mut rejected = rows.clone();
        let arkret_wire::TypedCurrentResult::Value { selector, .. } = rejected.last_mut().unwrap();
        let foreign = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x73; 32],
        ));
        *selector = serde_json::from_value(json!({"kind":"relation",
            "primary_conflict_domain":{"domain_kind":"tuple","relation_kind":"references",
                "from_ref":foreign,"to_ref":realm_id}}))
        .unwrap();
        assert!(validate(&rejected).is_err());
    }

    fn snapshot_at(
        bundle: &arkret_sdk::RealmAuthorityBundle,
        prefix: &[arkret_sdk::CommittedEventFullView],
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_sdk::RealmStateSnapshot {
        let stream_ref = CommitStreamRef::Realm {
            realm_id: bundle.realm_id.clone(),
        };
        let head = prefix.last().unwrap();
        arkret_sdk::RealmStateSnapshot {
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: bundle.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: head.commit.stream_position,
                commit_id: head.commit.commit_id.clone(),
            }],
            current_state_entries: soland_bootstrap_rows(bundle, prefix),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at,
            signature: bundle.genesis_commit.signature.clone(),
        }
    }

    /// A Realm-scoped Strand create of `creator` at the fixture Event time
    /// of tail index `index`, carrying the discussion track.
    fn strand_create_entry(
        realm_id: &arkret_sdk::RealmId,
        creator: &arkret_sdk::ActorId,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> (String, serde_json::Value) {
        let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
            realm_id.clone(),
            "General",
            creator.clone(),
        );
        object.created_at = created_at;
        object.tracks.clear();
        object.tracks.insert(
            "discussion".to_owned(),
            arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
        );
        ("ak.strand.create".to_owned(), json!({ "object": object }))
    }

    fn default_strand_entry(
        target: &arkret_sdk::StrandId,
        expected: Option<&arkret_sdk::StrandId>,
    ) -> (String, serde_json::Value) {
        let mut payload = json!({"realm_id": REALM_ID, "strand_id": target});
        if let Some(expected) = expected {
            payload["expected_default_strand_id"] = json!(expected);
        }
        ("ak.realm.set_default_strand".to_owned(), payload)
    }

    fn message_create_entry(
        strand_id: &arkret_sdk::StrandId,
        track_name: &str,
    ) -> (String, serde_json::Value) {
        (
            "ak.message.create".to_owned(),
            json!({
                "strand_id": strand_id,
                "track_name": track_name,
                "content": {"kind": "ak.content.text", "format": "plain", "body": "hello"}
            }),
        )
    }

    #[test]
    fn preview_and_position_zero_windows_never_reach_the_snapshot_installer() {
        use arkret_models_collaboration::sync_frames::account_sync::{
            RealmStreamWindow, StreamWindowStartBasis,
        };
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let basis = StreamWindowStartBasis {
            anchor_position: 8,
            anchor_commit_ref: arkret_wire::RealmCommitId::from_digest([8; 32]),
            snapshot_ref: arkret_sdk::RealmSnapshotId::from_digest([1; 32]),
            governance_generation: 0,
            accepted_dependency_refs: None,
        };
        let window = RealmStreamWindow {
            stream_ref: CommitStreamRef::Realm { realm_id },
            head_commit_ref: arkret_wire::RealmCommitId::from_digest([9; 32]),
            next_position: 10,
            limited: true,
            window_limit: 1,
            complete: true,
            preview_only: None,
            window_start_basis: Some(basis.clone()),
            e2ee_epoch: None,
        };
        assert_eq!(snapshot_window_basis(&window), Some(&basis));
        let mut preview = window.clone();
        preview.preview_only = Some(true);
        assert_eq!(snapshot_window_basis(&preview), None);
        let mut genesis = window.clone();
        genesis.window_start_basis = None;
        assert_eq!(snapshot_window_basis(&genesis), None);
        // An empty tail after the committed-prefix anchor is legal.
        assert!(require_window_start_row(&basis, &[]).is_ok());
    }

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
        ingest_realm_batch(&mut store, realm.as_str(), &batch);
        assert!(store.verified_message_commit(&event_id).is_none());
        assert!(store.historical_agent_event_candidates().is_empty());
    }

    #[test]
    fn forged_second_page_cannot_project_a_verified_first_page() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let (bundle, keys, items) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm_id.clone(),
            vec![
                (
                    arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                    json!({
                        "strand_id": STRAND_ID, "track_name": "discussion",
                        "content": {"kind": "ak.content.text", "body": "first"}
                    }),
                ),
                (
                    arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                    json!({
                        "strand_id": STRAND_ID, "track_name": "discussion",
                        "content": {"kind": "ak.content.text", "body": "second"}
                    }),
                ),
            ],
            "agent.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let stream_ref = arkret_sdk::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(50),
            request.nonce.clone(),
        );
        let mut replica = RealmReplica::new(realm_id.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        let first_event_id = items[0].event.event_id.clone();
        let first = arkret_sdk::StreamScanOutcome {
            committed_events: vec![
                arkret_sdk::CommittedEventView::Full(arkret_sdk::CommittedEventFullView {
                    commit: bundle.genesis_commit.clone(),
                    event: bundle.genesis_event.clone(),
                }),
                arkret_sdk::CommittedEventView::Full(items[0].clone()),
            ],
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            }),
            truncated: true,
        };
        let first_request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 2,
        };
        let mut pages = Vec::new();
        let wrong_nonce = arkret_identity::RealmAuthorityFreshness::new(
            freshness.now,
            arkret_sdk::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap(),
        );
        assert!(
            stage_verified_page(
                &mut replica,
                &first_request,
                first.clone(),
                &wrong_nonce,
                &keys,
                &mut pages
            )
            .is_err()
        );
        assert!(
            stage_verified_page(
                &mut replica,
                &first_request,
                first.clone(),
                &freshness,
                &arkret_identity::RealmAuthorityKeyMap::new(),
                &mut pages
            )
            .is_err()
        );
        let mut bad_generation = first.clone();
        let arkret_sdk::CommittedEventView::Full(row) = &mut bad_generation.committed_events[1]
        else {
            unreachable!()
        };
        row.commit.governance_generation += 1;
        assert!(
            stage_verified_page(
                &mut replica,
                &first_request,
                bad_generation,
                &freshness,
                &keys,
                &mut pages
            )
            .is_err()
        );
        assert!(pages.is_empty());
        let restricted_floor = arkret_sdk::StreamScanOutcome {
            committed_events: Vec::new(),
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 4,
                floor_commit_id: arkret_sdk::RealmCommitId::from_digest([0x44; 32]),
                floor_reason: arkret_sdk::ReadableFloorReason::MembershipJoin,
            }),
            truncated: false,
        };
        assert!(require_genesis_readable_floor(&restricted_floor).is_err());
        stage_verified_page(
            &mut replica,
            &first_request,
            first,
            &freshness,
            &keys,
            &mut pages,
        )
        .unwrap();
        // The scan verifies the genesis Commit independently of Account current.
        let scanned = pages[0].rows().iter().collect::<Vec<_>>();
        let claimed = vec![scanned[1]];
        require_exact_claimed_rows(&claimed, &scanned).unwrap();
        let window = arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow {
            stream_ref: stream_ref.clone(),
            head_commit_ref: items[0].commit.commit_id.clone(),
            next_position: 2,
            limited: false,
            window_limit: 2,
            complete: true,
            preview_only: None,
            window_start_basis: None,
            e2ee_epoch: None,
        };
        require_exact_window_head(&window, &scanned).unwrap();
        let mut forged_window = window;
        forged_window.head_commit_ref = arkret_sdk::RealmCommitId::from_digest([0x77; 32]);
        assert!(require_exact_window_head(&forged_window, &scanned).is_err());
        let prefix_basis =
            arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis {
                anchor_position: 0,
                anchor_commit_ref: bundle.genesis_commit.commit_id.clone(),
                snapshot_ref: arkret_sdk::RealmSnapshotId::from_digest([0x55; 32]),
                governance_generation: 0,
                accepted_dependency_refs: None,
            };
        // The tail starts right after the committed-prefix anchor.
        require_window_start_row(&prefix_basis, &scanned[1..]).unwrap();
        // A basis never names the first row of its own window: a window
        // starting exactly at a nonzero readable floor carries no basis.
        let floor_start_basis =
            arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis {
                anchor_position: 1,
                anchor_commit_ref: items[0].commit.commit_id.clone(),
                ..prefix_basis.clone()
            };
        assert!(require_window_start_row(&floor_start_basis, &scanned[1..]).is_err());
        forged_window.window_start_basis = Some(prefix_basis);
        let limited_entry =
            arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
                streams: Some(vec![forged_window]),
                ..Default::default()
            };
        assert!(require_genesis_window_basis(&limited_entry).is_err());
        let mut forged = items[1].clone();
        forged.commit.signature.signed_digest =
            arkret_sdk::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let second = arkret_sdk::StreamScanOutcome {
            committed_events: vec![arkret_sdk::CommittedEventView::Full(forged)],
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id,
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            }),
            truncated: false,
        };
        let second_request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(Some(1)),
            limit: 2,
        };
        assert!(
            stage_verified_page(
                &mut replica,
                &second_request,
                second,
                &freshness,
                &keys,
                &mut pages
            )
            .is_err()
        );
        assert_eq!(pages.len(), 1);
        let mut store = crate::state::isolated_store_for_tests("forged-second-realm-page");
        store.switch_test_account("did:web:reader.example");
        assert!(store.verified_message_commit(&first_event_id).is_none());
        assert!(
            store
                .verified_commit_stream_cursor(&stream_ref)
                .unwrap()
                .is_none()
        );
    }

    const OTHER_REALM_ID: &str = "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";

    /// One fixture Realm the frame Station serves: its bundle, every row
    /// from genesis, and the caller's readable floor on that stream.
    struct StationRealm {
        bundle: arkret_sdk::RealmAuthorityBundle,
        rows: Vec<CommittedEventView>,
        readable_floor: u64,
    }

    /// The own Station behind an Account frame: a fresh nonce-bound bundle
    /// per request and forward verified scans. Nothing else is reachable.
    struct FrameStation {
        station: crate::test_support::committed_event::FixtureStation,
        realms: BTreeMap<arkret_sdk::RealmId, StationRealm>,
        scans: std::sync::Mutex<Vec<CommitStreamRef>>,
        /// Issued exact snapshots the by-ref read returns.
        snapshots: BTreeMap<arkret_sdk::RealmSnapshotId, arkret_sdk::RealmStateSnapshot>,
    }

    impl garth::AuthorityTransport for FrameStation {
        async fn submit(
            &self,
            _request: &arkret_wire::AuthoritySubmitRequest,
            _options: &arkret_sdk::http_client::ClientRequestOptions,
        ) -> garth::Result<arkret_wire::AuthoritySubmitOutcome> {
            unreachable!("frame verification never submits")
        }

        async fn scan(
            &self,
            request: &StreamScanRequest,
        ) -> garth::Result<arkret_sdk::StreamScanOutcome> {
            self.scans.lock().unwrap().push(request.stream_ref.clone());
            let realm = &self.realms[&request.realm_id];
            if request.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: request.realm_id.clone(),
                })
            {
                // The caller joined every other stream above its genesis.
                return Ok(arkret_sdk::StreamScanOutcome {
                    committed_events: Vec::new(),
                    readable_floor: Some(arkret_sdk::ReadableFloor {
                        oldest_position: 1,
                        floor_commit_id: arkret_sdk::RealmCommitId::from_digest([0x6c; 32]),
                        floor_reason: arkret_sdk::ReadableFloorReason::MembershipJoin,
                    }),
                    truncated: false,
                });
            }
            let arkret_sdk::StreamScanDirection::After(after) = request.direction else {
                unreachable!("frame verification replays forward")
            };
            let floor = &realm.rows[realm.readable_floor as usize];
            Ok(arkret_sdk::StreamScanOutcome {
                committed_events: realm
                    .rows
                    .iter()
                    .filter(|row| {
                        let position = row.commit().stream_position;
                        position >= realm.readable_floor
                            && after.is_none_or(|after| position > after)
                    })
                    .take(usize::from(request.limit))
                    .cloned()
                    .collect(),
                readable_floor: Some(arkret_sdk::ReadableFloor {
                    oldest_position: realm.readable_floor,
                    floor_commit_id: floor.commit().commit_id.clone(),
                    floor_reason: if realm.readable_floor == 0 {
                        arkret_sdk::ReadableFloorReason::StreamStart
                    } else {
                        arkret_sdk::ReadableFloorReason::MembershipJoin
                    },
                }),
                truncated: realm
                    .rows
                    .iter()
                    .filter(|row| {
                        row.commit().stream_position >= realm.readable_floor
                            && after.is_none_or(|after| row.commit().stream_position > after)
                    })
                    .count()
                    > usize::from(request.limit),
            })
        }

        async fn authority_bundle(
            &self,
            request: &arkret_sdk::AuthorityBundleRequest,
        ) -> garth::Result<arkret_sdk::RealmAuthorityBundle> {
            let mut bundle = self.realms[&request.realm_id].bundle.clone();
            self.station
                .reassert_for_nonce(&mut bundle, request.nonce.clone(), chrono::Utc::now());
            Ok(bundle)
        }

        async fn install_handoff(
            &self,
            _request: &arkret_sdk::AuthorityHandoffRequest,
            _options: &arkret_sdk::http_client::ClientRequestOptions,
        ) -> garth::Result<arkret_wire::RealmAuthorityHandoff> {
            unreachable!("frame verification never installs a handoff")
        }

        async fn exact_snapshot(
            &self,
            _realm_id: &arkret_sdk::RealmId,
            snapshot_id: &arkret_sdk::RealmSnapshotId,
        ) -> garth::Result<arkret_sdk::RealmStateSnapshot> {
            self.snapshots
                .get(snapshot_id)
                .cloned()
                .ok_or_else(|| garth::Error::Api {
                    status: 503,
                    error: Box::new(arkret_wire::Problem::new(
                        "realm_state_snapshot_unavailable",
                        503,
                        "never issued",
                    )),
                })
        }
    }

    fn message_entries(bodies: &[&str]) -> Vec<(String, serde_json::Value)> {
        bodies
            .iter()
            .map(|body| {
                (
                    arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                    json!({
                        "strand_id": STRAND_ID, "track_name": "discussion",
                        "content": {"kind": "ak.content.text", "body": body}
                    }),
                )
            })
            .collect()
    }

    /// A Realm entry whose window carries `window_rows` of the stream and a
    /// profile current sourced from its first Commit.
    fn frame_entry(
        realm: &StationRealm,
        window_rows: usize,
        preview: bool,
    ) -> arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
        let head = realm.rows.last().unwrap().commit();
        let first = realm.rows[1].commit();
        arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
            streams: Some(vec![
                arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow {
                    stream_ref: head.stream_ref.clone(),
                    head_commit_ref: head.commit_id.clone(),
                    next_position: head.stream_position + 1,
                    limited: preview,
                    window_limit: window_rows as u32,
                    complete: true,
                    preview_only: preview.then_some(true),
                    window_start_basis: None,
                    e2ee_epoch: None,
                },
            ]),
            committed_events: Some(realm.rows[realm.rows.len() - window_rows..].to_vec()),
            current: Some(
                arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult {
                    realm_id: head.realm_id.clone(),
                    governance_generation: 0,
                    stream_heads: vec![arkret_wire::CommitStreamHead {
                        stream_ref: head.stream_ref.clone(),
                        stream_position: head.stream_position,
                        commit_id: head.commit_id.clone(),
                    }],
                    entries: vec![TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::RealmProfile,
                        source_stream_ref: first.stream_ref.clone(),
                        revision: arkret_wire::CurrentRevision {
                            commit_id: first.commit_id.clone(),
                            stream_position: first.stream_position,
                        },
                        value: json!({"schema": "ak.schema.realm_profile.v1", "title": "Realm"}),
                    }],
                },
            ),
            ..Default::default()
        }
    }

    fn account_frame(
        entries: Vec<(
            &str,
            arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
        )>,
    ) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        let mut frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
            serde_json::from_value(json!({"kind": "delta", "cursor": "ak:cursor:YQ"})).unwrap();
        frame.realms = Some(
            arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeRealms {
                entries: entries
                    .into_iter()
                    .map(|(realm, entry)| (realm.to_owned(), entry))
                    .collect(),
            },
        );
        frame
    }

    fn event_ids(realm: &StationRealm) -> Vec<arkret_sdk::EventId> {
        realm
            .rows
            .iter()
            .skip(1)
            .map(|row| row.commit().event_ref.clone())
            .collect()
    }

    #[tokio::test]
    async fn preview_realm_stays_display_only_beside_a_verified_realm_until_backfilled() {
        use crate::test_support::committed_event::FixtureStation;
        // The Station answers every request at the caller's wall clock, so
        // its did:webvh history starts before it.
        let inception_at = chrono::Utc::now() - chrono::Duration::seconds(1000);
        let fixture_realm = |realm_id: &str, bodies: &[&str], readable_floor| {
            let (bundle, _, items) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &FixtureStation::webvh(0x46, inception_at),
                    arkret_sdk::RealmId::new(realm_id).unwrap(),
                    json!({}),
                    message_entries(bodies),
                    "alice.example",
                    DEVICE_ID,
                );
            let rows = std::iter::once(CommittedEventView::Full(
                arkret_sdk::CommittedEventFullView {
                    commit: bundle.genesis_commit.clone(),
                    event: bundle.genesis_event.clone(),
                },
            ))
            .chain(items.into_iter().map(CommittedEventView::Full))
            .collect();
            StationRealm {
                bundle,
                rows,
                readable_floor,
            }
        };
        let preview_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let verified_id = arkret_sdk::RealmId::new(OTHER_REALM_ID).unwrap();
        let preview_stream = CommitStreamRef::Realm {
            realm_id: preview_id.clone(),
        };
        let verified_stream = CommitStreamRef::Realm {
            realm_id: verified_id.clone(),
        };
        // The preview Realm has more Commits than its window and the caller
        // joined above genesis, so no verified replay can reach its start.
        let station = |preview_floor| FrameStation {
            station: FixtureStation::webvh(0x46, inception_at),
            realms: BTreeMap::from([
                (
                    preview_id.clone(),
                    fixture_realm(REALM_ID, &["p1", "p2", "p3"], preview_floor),
                ),
                (
                    verified_id.clone(),
                    fixture_realm(OTHER_REALM_ID, &["v1", "v2"], 0),
                ),
            ]),
            scans: std::sync::Mutex::new(Vec::new()),
            snapshots: BTreeMap::new(),
        };
        let batch = |station: &FrameStation| {
            account_frame(vec![
                (REALM_ID, frame_entry(&station.realms[&preview_id], 1, true)),
                (
                    OTHER_REALM_ID,
                    frame_entry(&station.realms[&verified_id], 2, false),
                ),
            ])
        };
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let forged_station = station(0);
        let mut forged_generation = batch(&forged_station);
        forged_generation
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(OTHER_REALM_ID)
            .unwrap()
            .current
            .as_mut()
            .unwrap()
            .governance_generation = 99;
        assert!(
            verify_account_frame_with(
                &AuthorityClient::new(forged_station),
                &http,
                &forged_generation,
            )
            .await
            .is_err()
        );
        let mut store = crate::state::isolated_store_for_tests("account-frame-preview-sibling");
        store.switch_test_account("did:web:reader.example");
        let scope = account_scope();
        let project = |store: &mut crate::state::LocalStateStore,
                       verified: &VerifiedAccountFrame,
                       cursor: &str| {
            store
                .verified_projection_transaction(|store| {
                    for page in verified.pages() {
                        store.ingest_verified_message_commits(page)?;
                    }
                    store
                        .save_account_checkpoint(
                            &scope,
                            garth::AccountCursorCheckpoint {
                                cursor: cursor.to_owned(),
                                station_cas: garth::StationCasProjection::default(),
                            },
                        )
                        .map_err(|error| error.to_string())
                })
                .unwrap();
        };

        // 1. Unresolved preview: the sibling Realm verifies and installs; the preview Realm's rows
        //    stay display rows, with no current, no verified index and no verified stream
        //    checkpoint.
        let unresolved = station(2);
        let frame = batch(&unresolved);
        let verified = verify_account_frame_with(&AuthorityClient::new(unresolved), &http, &frame)
            .await
            .unwrap();
        assert_eq!(
            verified.preview_streams(),
            &BTreeSet::from([preview_stream.clone()])
        );
        assert!(verified.resolved_preview_streams().is_empty());
        assert!(
            verified
                .pages()
                .iter()
                .flat_map(|page| page.rows())
                .all(|row| row.commit().stream_ref == verified_stream)
        );
        let product = verified.product_frame(&frame);
        let entries = &product.realms.as_ref().unwrap().entries;
        assert!(entries[REALM_ID].current.is_none() && entries[REALM_ID].baseline.is_none());
        assert_eq!(
            entries[REALM_ID].committed_events.as_ref().unwrap().len(),
            1
        );
        assert_eq!(
            entries[OTHER_REALM_ID].current,
            frame.realms.as_ref().unwrap().entries[OTHER_REALM_ID].current
        );
        project(&mut store, &verified, "ak:cursor:preview-1");
        let unresolved = station(2);
        for event_id in event_ids(&unresolved.realms[&verified_id]) {
            assert!(store.verified_message_commit(&event_id).is_some());
        }
        for event_id in event_ids(&unresolved.realms[&preview_id]) {
            assert!(store.verified_message_commit(&event_id).is_none());
        }
        assert!(
            store
                .verified_commit_stream_cursor(&preview_stream)
                .unwrap()
                .is_none()
        );

        // 2. A contradicting row in a preview window still fails closed once the replay can reach
        //    genesis.
        let readable = station(0);
        let mut forged = batch(&readable);
        let entry = forged
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap();
        let CommittedEventView::Full(row) = &mut entry.committed_events.as_mut().unwrap()[0] else {
            unreachable!()
        };
        row.commit.commit_id = arkret_sdk::RealmCommitId::from_digest([0x7e; 32]);
        let Err(error) =
            verify_account_frame_with(&AuthorityClient::new(readable), &http, &forged).await
        else {
            panic!("a forged preview row must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("differs from verified stream row")
        );

        // 3. Backfill: the verified replay from genesis covers the preview window and its head, so
        //    the stream becomes exact.
        let readable = station(0);
        let frame = batch(&readable);
        let verified = verify_account_frame_with(&AuthorityClient::new(readable), &http, &frame)
            .await
            .unwrap();
        assert!(verified.preview_streams().is_empty());
        assert_eq!(
            verified.resolved_preview_streams(),
            &BTreeSet::from([preview_stream.clone()])
        );
        let product = verified.product_frame(&frame);
        assert_eq!(
            serde_json::to_value(&product).unwrap(),
            serde_json::to_value(&frame).unwrap()
        );
        project(&mut store, &verified, "ak:cursor:preview-2");
        for event_id in event_ids(&station(0).realms[&preview_id]) {
            assert!(store.verified_message_commit(&event_id).is_some());
        }

        // 4. A non-preview window whose readable history starts above genesis and names no signed
        //    basis still fails closed.
        let mut restricted = station(0);
        restricted
            .realms
            .get_mut(&verified_id)
            .unwrap()
            .readable_floor = 1;
        let frame = batch(&restricted);
        let Err(error) =
            verify_account_frame_with(&AuthorityClient::new(restricted), &http, &frame).await
        else {
            panic!("a non-preview window above genesis must fail closed");
        };
        assert!(error.to_string().contains("readable-floor snapshot anchor"));
    }

    /// A `since_join` member's readable history starts at its join Commit.
    /// A genesis replay (the Account-window settle path) still refuses it,
    /// while the live stream follow verifies from the named floor Commit
    /// through the signed head without position 0.
    #[tokio::test]
    async fn live_follow_replays_from_the_verified_readable_floor() {
        use crate::test_support::committed_event::FixtureStation;
        let inception_at = chrono::Utc::now() - chrono::Duration::seconds(1000);
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &FixtureStation::webvh(0x48, inception_at),
                realm_id.clone(),
                json!({}),
                message_entries(&["m1", "m2", "m3"]),
                "alice.example",
                DEVICE_ID,
            );
        let rows = std::iter::once(CommittedEventView::Full(
            arkret_sdk::CommittedEventFullView {
                commit: bundle.genesis_commit.clone(),
                event: bundle.genesis_event.clone(),
            },
        ))
        .chain(items.into_iter().map(CommittedEventView::Full))
        .collect::<Vec<_>>();
        let head = rows.last().unwrap().commit().clone();
        let station = || FrameStation {
            station: FixtureStation::webvh(0x48, inception_at),
            realms: BTreeMap::from([(
                realm_id.clone(),
                StationRealm {
                    bundle: bundle.clone(),
                    rows: rows.clone(),
                    readable_floor: 2,
                },
            )]),
            scans: std::sync::Mutex::new(Vec::new()),
            snapshots: BTreeMap::new(),
        };
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();

        let authority = AuthorityClient::new(station());
        let (verified_bundle, freshness, mut replica) =
            fresh_verified_realm(&authority, &http, &realm_id)
                .await
                .unwrap();
        let genesis_only = verified_stream_pages(
            &authority,
            &http,
            &mut replica,
            &verified_bundle,
            &freshness,
            &realm_id,
            &stream_ref,
            ReplayStart::Genesis,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(genesis_only, StreamPages::AboveGenesis));
        assert!(replica.verified_head(&stream_ref).is_none());

        let authority = AuthorityClient::new(station());
        let (verified_bundle, freshness, mut replica) =
            fresh_verified_realm(&authority, &http, &realm_id)
                .await
                .unwrap();
        let (pages, floor_snapshot) = verified_stream_pages(
            &authority,
            &http,
            &mut replica,
            &verified_bundle,
            &freshness,
            &realm_id,
            &stream_ref,
            ReplayStart::ReadableFloor,
            None,
        )
        .await
        .unwrap()
        .into_verified()
        .unwrap();
        assert!(floor_snapshot.is_none());
        let positions = pages
            .iter()
            .flat_map(|page| page.rows())
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>();
        assert_eq!(positions, (2..=head.stream_position).collect::<Vec<_>>());
        assert_eq!(
            replica.verified_head(&stream_ref),
            Some(&arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: head.stream_position,
                commit_id: head.commit_id.clone(),
            })
        );
    }

    /// A Realm whose issued `/head` anchors a limited Realm-stream window,
    /// beside a full-history sibling Realm: the snapshot window's tail runs
    /// the signed predecessor and verified tail; an unregistered tail kind
    /// does not become a local typed-current reducer; another stream window
    /// of the same Realm is settled on its own
    /// stream; a contradicting Account current still fails the frame.
    #[tokio::test]
    async fn snapshot_window_tail_and_sibling_windows_settle_per_stream() {
        use arkret_models_collaboration::sync_frames::account_sync::{
            RealmStreamWindow, StreamWindowStartBasis,
        };

        use crate::test_support::committed_event::FixtureStation;
        let inception_at = chrono::Utc::now() - chrono::Duration::seconds(1000);
        let fixture_station = || FixtureStation::webvh(0x47, inception_at);
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let sibling_id = arkret_sdk::RealmId::new(OTHER_REALM_ID).unwrap();
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let sibling_stream = CommitStreamRef::Realm {
            realm_id: sibling_id.clone(),
        };
        let circle_stream = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [0x6e; 32],
            )),
        };
        let sidecar_stream = CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [0x6f; 32],
            )),
        };
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let with_genesis =
            |bundle: &arkret_sdk::RealmAuthorityBundle,
             items: Vec<arkret_sdk::CommittedEventFullView>| {
                std::iter::once(CommittedEventView::Full(
                    arkret_sdk::CommittedEventFullView {
                        commit: bundle.genesis_commit.clone(),
                        event: bundle.genesis_event.clone(),
                    },
                ))
                .chain(items.into_iter().map(CommittedEventView::Full))
                .collect::<Vec<_>>()
            };
        let (sibling_bundle, _, sibling_items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &fixture_station(),
                sibling_id.clone(),
                json!({}),
                message_entries(&["s1", "s2"]),
                "alice.example",
                DEVICE_ID,
            );
        let sibling = StationRealm {
            rows: with_genesis(&sibling_bundle, sibling_items),
            bundle: sibling_bundle,
            readable_floor: 0,
        };
        // The anchored Realm: bootstrap signed at position 6, then `tail`.
        let anchored = |tail: Vec<(String, serde_json::Value)>| {
            let (bundle, _, items) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &fixture_station(),
                    realm_id.clone(),
                    json!({"object": collaboration_genesis(GENESIS_SALT)}),
                    ordinary_bootstrap_entries(&creator)
                        .into_iter()
                        .chain(tail)
                        .collect(),
                    "alice.example",
                    DEVICE_ID,
                );
            let mut snapshot = snapshot_at(
                &bundle,
                &items[..6],
                chrono::Utc::now() - chrono::Duration::seconds(60),
            );
            fixture_station().sign_snapshot(&mut snapshot);
            (bundle, items, snapshot)
        };
        let strand = strand_create_entry(
            &realm_id,
            &creator,
            crate::test_support::committed_event::fixture_time(8),
        );
        let (_, probe, _) = anchored(vec![strand.clone()]);
        let strand_id = arkret_sdk::StrandId::from_event_id(&probe[6].event.event_id);
        let exact_tail = vec![strand.clone(), default_strand_entry(&strand_id, None)];
        let unsupported_tail = vec![
            strand.clone(),
            ("ak.realm.alias".to_owned(), json!({"alias": "general"})),
        ];
        let station_for = |tail: &[(String, serde_json::Value)]| {
            let (bundle, items, snapshot) = anchored(tail.to_vec());
            let rows = with_genesis(&bundle, items.clone());
            let station = FrameStation {
                station: fixture_station(),
                realms: BTreeMap::from([
                    (
                        realm_id.clone(),
                        StationRealm {
                            bundle: bundle.clone(),
                            rows,
                            readable_floor: 0,
                        },
                    ),
                    (
                        sibling_id.clone(),
                        StationRealm {
                            bundle: sibling.bundle.clone(),
                            rows: sibling.rows.clone(),
                            readable_floor: 0,
                        },
                    ),
                ]),
                scans: std::sync::Mutex::new(Vec::new()),
                snapshots: BTreeMap::from([(snapshot.snapshot_id.clone(), snapshot.clone())]),
            };
            (station, bundle, items, snapshot)
        };
        let circle_window = RealmStreamWindow {
            stream_ref: circle_stream.clone(),
            head_commit_ref: arkret_sdk::RealmCommitId::from_digest([0x6d; 32]),
            next_position: 3,
            limited: true,
            window_limit: 1,
            complete: true,
            preview_only: Some(true),
            window_start_basis: None,
            e2ee_epoch: None,
        };
        // The Account entry the own Station serves for the anchored Realm:
        // its window after the issued head, and the same-cut current.
        let anchored_entry = |bundle: &arkret_sdk::RealmAuthorityBundle,
                              items: &[arkret_sdk::CommittedEventFullView],
                              snapshot: &arkret_sdk::RealmStateSnapshot,
                              current_rows: Vec<TypedCurrentResult>,
                              circle: bool| {
            let head = &items.last().unwrap().commit;
            let mut streams = vec![RealmStreamWindow {
                stream_ref: realm_stream.clone(),
                head_commit_ref: head.commit_id.clone(),
                next_position: head.stream_position + 1,
                limited: true,
                window_limit: (items.len() - 6) as u32,
                complete: true,
                preview_only: None,
                window_start_basis: Some(StreamWindowStartBasis {
                    anchor_position: 6,
                    anchor_commit_ref: items[5].commit.commit_id.clone(),
                    snapshot_ref: snapshot.snapshot_id.clone(),
                    governance_generation: 0,
                    accepted_dependency_refs: None,
                }),
                e2ee_epoch: None,
            }];
            let mut stream_heads = vec![arkret_wire::CommitStreamHead {
                stream_ref: realm_stream.clone(),
                stream_position: head.stream_position,
                commit_id: head.commit_id.clone(),
            }];
            if circle {
                streams.push(circle_window.clone());
                stream_heads.push(arkret_wire::CommitStreamHead {
                    stream_ref: circle_stream.clone(),
                    stream_position: 2,
                    commit_id: circle_window.head_commit_ref.clone(),
                });
            }
            let _ = bundle;
            arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
                streams: Some(streams),
                committed_events: Some(
                    items[6..]
                        .iter()
                        .cloned()
                        .map(CommittedEventView::Full)
                        .collect(),
                ),
                current: Some(
                    arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult {
                        realm_id: realm_id.clone(),
                        governance_generation: 0,
                        stream_heads,
                        entries: current_rows,
                    },
                ),
                ..Default::default()
            }
        };
        let describe = station_describe(&[
            "ak.operation_bundle.station.http_core_current.v1",
            "ak.operation_bundle.station.snapshot_exact_read.v1",
        ]);
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let positions = |verified: &VerifiedAccountFrame, stream: &CommitStreamRef| {
            verified
                .pages()
                .iter()
                .flat_map(|page| page.rows())
                .filter(|row| &row.commit().stream_ref == stream)
                .map(|row| row.commit().stream_position)
                .collect::<Vec<_>>()
        };

        // 1. The exact signed floor and tail leave Station current untouched.
        let (station, bundle, items, snapshot) = station_for(&exact_tail);
        let exact_rows = soland_bootstrap_rows(&bundle, &items);
        let frame = account_frame(vec![
            (
                REALM_ID,
                anchored_entry(&bundle, &items, &snapshot, exact_rows.clone(), false),
            ),
            (OTHER_REALM_ID, frame_entry(&sibling, 2, false)),
        ]);
        let verified = verify_account_frame_described(
            &AuthorityClient::new(station),
            &http,
            Some(&describe),
            &frame,
        )
        .await
        .unwrap();
        let basis = verified
            .authority_bases()
            .iter()
            .find(|basis| basis.realm_id == bundle.realm_id)
            .expect("verified floor retains its nonce-bound authority lineage");
        assert_eq!(basis.current_service_id, bundle.current_service_id);
        assert_eq!(basis.current_generation, bundle.current_generation);
        assert_eq!(basis.genesis_ref.event_id, bundle.genesis_commit.event_ref);
        assert_eq!(basis.genesis_ref.commit_id, bundle.genesis_commit.commit_id);
        assert_eq!(positions(&verified, &realm_stream), vec![7, 8]);
        assert_eq!(positions(&verified, &sibling_stream), vec![0, 1, 2]);
        assert_eq!(
            serde_json::to_value(verified.product_frame(&frame)).unwrap(),
            serde_json::to_value(&frame).unwrap()
        );
        // A single signed snapshot can bind three independent predecessors.
        // Empty Circle and Sidecar tails still need their own signed heads;
        // the Realm head cannot stand in for either stream.
        let (mut station, bundle, items, mut multi_snapshot) = station_for(&exact_tail);
        let scoped_head = arkret_sdk::RealmCommitId::from_digest([0x6c; 32]);
        for stream_ref in [&circle_stream, &sidecar_stream] {
            multi_snapshot
                .visible_stream_heads
                .push(arkret_wire::CommitStreamHead {
                    stream_ref: stream_ref.clone(),
                    stream_position: 1,
                    commit_id: scoped_head.clone(),
                });
            multi_snapshot
                .retention_and_history_floor
                .stream_floors
                .push(arkret_wire::StreamHistoryFloor {
                    stream_ref: stream_ref.clone(),
                    oldest_position: 1,
                });
        }
        fixture_station().sign_snapshot(&mut multi_snapshot);
        station.snapshots =
            BTreeMap::from([(multi_snapshot.snapshot_id.clone(), multi_snapshot.clone())]);
        let mut multi_entry =
            anchored_entry(&bundle, &items, &multi_snapshot, exact_rows.clone(), false);
        for stream_ref in [&circle_stream, &sidecar_stream] {
            multi_entry
                .streams
                .as_mut()
                .unwrap()
                .push(RealmStreamWindow {
                    stream_ref: stream_ref.clone(),
                    head_commit_ref: scoped_head.clone(),
                    next_position: 2,
                    limited: true,
                    window_limit: 0,
                    complete: true,
                    preview_only: None,
                    window_start_basis: Some(StreamWindowStartBasis {
                        anchor_position: 1,
                        anchor_commit_ref: scoped_head.clone(),
                        snapshot_ref: multi_snapshot.snapshot_id.clone(),
                        governance_generation: 0,
                        accepted_dependency_refs: None,
                    }),
                    e2ee_epoch: None,
                });
            multi_entry.current.as_mut().unwrap().stream_heads.push(
                arkret_wire::CommitStreamHead {
                    stream_ref: stream_ref.clone(),
                    stream_position: 1,
                    commit_id: scoped_head.clone(),
                },
            );
        }
        let multi_frame = account_frame(vec![(REALM_ID, multi_entry)]);
        let multi_authority = AuthorityClient::new(station);
        let multi_verified =
            verify_account_frame_described(&multi_authority, &http, Some(&describe), &multi_frame)
                .await
                .unwrap();
        assert!(multi_verified.preview_streams().is_empty());
        assert_eq!(positions(&multi_verified, &realm_stream), vec![7, 8]);
        assert_eq!(
            positions(&multi_verified, &circle_stream),
            Vec::<u64>::new()
        );
        assert_eq!(
            positions(&multi_verified, &sidecar_stream),
            Vec::<u64>::new()
        );
        assert!(
            multi_verified
                .product_frame(&multi_frame)
                .realms
                .unwrap()
                .entries[REALM_ID]
                .current
                .is_some()
        );
        let mut accepted_dependency = multi_frame.clone();
        accepted_dependency
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .streams
            .as_mut()
            .unwrap()[1]
            .window_start_basis
            .as_mut()
            .unwrap()
            .accepted_dependency_refs = Some(vec![arkret_wire::CommittedEventRef {
            event_id: items[5].event.event_id.clone(),
            commit_id: items[5].commit.commit_id.clone(),
            stream_ref: realm_stream.clone(),
            stream_position: 6,
        }]);
        let accepted_verified = verify_account_frame_described(
            &multi_authority,
            &http,
            Some(&describe),
            &accepted_dependency,
        )
        .await
        .unwrap();
        assert!(accepted_verified.preview_streams().is_empty());
        assert_eq!(positions(&accepted_verified, &realm_stream), vec![7, 8]);
        let mut invented_dependency = multi_frame.clone();
        invented_dependency
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .streams
            .as_mut()
            .unwrap()[1]
            .window_start_basis
            .as_mut()
            .unwrap()
            .accepted_dependency_refs = Some(vec![arkret_wire::CommittedEventRef {
            event_id: bundle.genesis_event.event_id.clone(),
            commit_id: arkret_sdk::RealmCommitId::from_digest([0xee; 32]),
            stream_ref: realm_stream.clone(),
            stream_position: 999,
        }]);
        assert!(
            verify_account_frame_described(
                &multi_authority,
                &http,
                Some(&describe),
                &invented_dependency,
            )
            .await
            .is_err()
        );
        let (station, ..) = station_for(&exact_tail);
        let mut forged_generation = frame.clone();
        forged_generation
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .current
            .as_mut()
            .unwrap()
            .governance_generation = 99;
        assert!(
            verify_account_frame_described(
                &AuthorityClient::new(station),
                &http,
                Some(&describe),
                &forged_generation,
            )
            .await
            .is_err()
        );

        // The Station has a later signed Commit than this Account window.
        // Verify only the older exact prefix, without adopting the suffix.
        let (station, bundle, items, snapshot) = station_for(&exact_tail);
        let prefix = &items[..7];
        let older_frame = account_frame(vec![(
            REALM_ID,
            anchored_entry(
                &bundle,
                prefix,
                &snapshot,
                soland_bootstrap_rows(&bundle, prefix),
                false,
            ),
        )]);
        let older_verified = verify_account_frame_described(
            &AuthorityClient::new(station),
            &http,
            Some(&describe),
            &older_frame,
        )
        .await
        .unwrap();
        assert_eq!(positions(&older_verified, &realm_stream), vec![7]);
        assert_eq!(
            serde_json::to_value(older_verified.product_frame(&older_frame)).unwrap(),
            serde_json::to_value(&older_frame).unwrap()
        );

        // The signed anchor itself also proves an empty older window, even
        // when the Station has already appended a valid suffix.
        let (station, bundle, items, snapshot) = station_for(&exact_tail);
        let prefix = &items[..6];
        let empty_frame = account_frame(vec![(
            REALM_ID,
            anchored_entry(
                &bundle,
                prefix,
                &snapshot,
                soland_bootstrap_rows(&bundle, prefix),
                false,
            ),
        )]);
        let empty_verified = verify_account_frame_described(
            &AuthorityClient::new(station),
            &http,
            Some(&describe),
            &empty_frame,
        )
        .await
        .unwrap();
        assert!(positions(&empty_verified, &realm_stream).is_empty());

        // Bounding the scan never permits a different Commit at that head.
        let (station, ..) = station_for(&exact_tail);
        let mut forged_prefix = older_frame.clone();
        forged_prefix
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(REALM_ID)
            .unwrap()
            .streams
            .as_mut()
            .unwrap()[0]
            .head_commit_ref = arkret_sdk::RealmCommitId::from_digest([0x91; 32]);
        assert!(
            verify_account_frame_described(
                &AuthorityClient::new(station),
                &http,
                Some(&describe),
                &forged_prefix,
            )
            .await
            .is_err()
        );

        // 2. A different Station current value is not reconstructed from the scan; the client
        //    verifies its source cut and uses that value.
        let (station, bundle, items, snapshot) = station_for(&exact_tail);
        let mut forged_rows = exact_rows.clone();
        forged_rows.pop();
        let forged = account_frame(vec![
            (
                REALM_ID,
                anchored_entry(&bundle, &items, &snapshot, forged_rows.clone(), false),
            ),
            (OTHER_REALM_ID, frame_entry(&sibling, 2, false)),
        ]);
        let verified = verify_account_frame_described(
            &AuthorityClient::new(station),
            &http,
            Some(&describe),
            &forged,
        )
        .await
        .unwrap();
        assert_eq!(
            verified.product_frame(&forged).realms.unwrap().entries[REALM_ID]
                .current
                .as_ref()
                .unwrap()
                .entries,
            forged_rows
        );

        // 3. An unrecognized tail kind still has a verifiable Commit chain; current comes from the
        //    Station result, not a local reducer.
        let (station, bundle, items, snapshot) = station_for(&unsupported_tail);
        let frame = account_frame(vec![
            (
                REALM_ID,
                anchored_entry(
                    &bundle,
                    &items,
                    &snapshot,
                    soland_bootstrap_rows(&bundle, &items[..7]),
                    false,
                ),
            ),
            (OTHER_REALM_ID, frame_entry(&sibling, 2, false)),
        ]);
        let verified = verify_account_frame_described(
            &AuthorityClient::new(station),
            &http,
            Some(&describe),
            &frame,
        )
        .await
        .unwrap();
        assert_eq!(positions(&verified, &realm_stream), vec![7, 8]);
        assert_eq!(positions(&verified, &sibling_stream), vec![0, 1, 2]);
        let product = verified.product_frame(&frame);
        let entries = &product.realms.as_ref().unwrap().entries;
        assert!(entries[REALM_ID].current.is_some());
        assert_eq!(
            entries[REALM_ID].committed_events.as_ref().unwrap().len(),
            2
        );
        assert_eq!(
            entries[OTHER_REALM_ID].current,
            frame.realms.as_ref().unwrap().entries[OTHER_REALM_ID].current
        );
        let mut store = crate::state::isolated_store_for_tests("account-frame-unresolved-tail");
        store.switch_test_account("did:web:reader.example");
        let scope = account_scope();
        store
            .verified_projection_transaction(|store| {
                for page in verified.pages() {
                    store.ingest_verified_message_commits(page)?;
                }
                store
                    .save_account_checkpoint(
                        &scope,
                        garth::AccountCursorCheckpoint {
                            cursor: "ak:cursor:unresolved".to_owned(),
                            station_cas: garth::StationCasProjection::default(),
                        },
                    )
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        assert!(store.realm_tree_projection(REALM_ID).is_none());
        assert!(
            store
                .verified_commit_stream_cursor(&realm_stream)
                .unwrap()
                .is_none()
        );
        for event_id in event_ids(&sibling) {
            assert!(store.verified_message_commit(&event_id).is_some());
        }

        // 4. A preview Circle window beside the snapshot window is settled on its own stream. With
        //    a cut that does not read the Circle the Realm-stream current installs; a cut that
        //    reads it stays out of the product current without failing the frame.
        for reads_circle in [false, true] {
            let (station, bundle, items, snapshot) = station_for(&exact_tail);
            let frame = account_frame(vec![(
                REALM_ID,
                anchored_entry(&bundle, &items, &snapshot, exact_rows.clone(), reads_circle),
            )]);
            let mut entry = frame.realms.as_ref().unwrap().entries[REALM_ID].clone();
            if !reads_circle {
                entry.current.as_mut().unwrap().stream_heads.truncate(1);
                entry.streams.as_mut().unwrap().push(circle_window.clone());
            }
            let frame = account_frame(vec![(REALM_ID, entry)]);
            let verified = verify_account_frame_described(
                &AuthorityClient::new(station),
                &http,
                Some(&describe),
                &frame,
            )
            .await
            .unwrap();
            assert_eq!(
                verified.preview_streams(),
                &BTreeSet::from([circle_stream.clone()])
            );
            assert_eq!(positions(&verified, &realm_stream), vec![7, 8]);
            let product = verified.product_frame(&frame);
            let installed = product.realms.as_ref().unwrap().entries[REALM_ID]
                .current
                .is_some();
            assert_eq!(installed, !reads_circle, "reads Circle: {reads_circle}");
        }
    }
}
