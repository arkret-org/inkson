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

#[cfg(test)]
use arkret_sdk::EventPayloadExt;
#[cfg(test)]
use garth::RealmReplica;
#[cfg(test)]
use garth::StreamScanRequestBody;
use garth::current_ingest::committed_views_to_client_events;
#[cfg(test)]
use garth::current_ingest::validate_floor_product_rows;
use garth::history_recovery::require_exact_claimed_rows;
use garth::{ClientEvent, CommitStreamRef, CommittedEventView, RetrySchedule};
pub(crate) use own_station::{
    refresh_accepted_sidecar, refresh_joined_realm, refresh_sidecar_history,
};

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
    if event.account_device_producer().ok().flatten().is_none() {
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
        !ctx.effect.is_cancelled()
            && generation.get() == start_generation
            && ctx.profiles.get().active_profile_id == start_profile_id
            && ctx.selected_realm_id.get() == realm_id
            && ctx.route_enabled.get()
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
    let mut subscription_state = own_live::SubscriptionState::default();

    while is_active() {
        let http = match provide(ctx.base_url.get()).await {
            Ok(http) => http,
            Err(error) => {
                if !retry_after(&mut backoff, &is_active, &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        let own = match crate::transport::own_station_results::client_for_http(&http).await {
            Ok(own) => own,
            Err(error) => {
                if !retry_after(&mut backoff, &is_active, &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        let session = match own.session() {
            Ok(session) => session.clone(),
            Err(error) => {
                if !retry_after(&mut backoff, &is_active, &error.to_string()).await {
                    break;
                }
                continue;
            }
        };
        if replica_session.as_ref() != Some(&session) {
            replica = garth::own_station_results::OwnStationReplica::new(realm_id_typed.clone());
            replica_session = Some(session);
            subscription_state.reset();
        }
        match own_live::subscription(
            &own,
            &http,
            &realm_id_typed,
            &projector,
            &ctx,
            &is_active,
            &mut replica,
            &mut subscription_state,
            &mut backoff,
        )
        .await
        {
            Ok(()) => {
                backoff.reset();
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
                            if crate::api_error::is_terminal_session_grant_refresh_error(&refresh_error) =>
                        {
                            break;
                        }
                        Err(refresh_error) => {
                            if !retry_after(&mut backoff, &is_active, &refresh_error.to_string())
                                .await
                            {
                                break;
                            }
                            continue;
                        }
                    }
                }
                if !retry_after(&mut backoff, &is_active, &error.to_string()).await {
                    break;
                }
            }
        }
    }
}

async fn retry_after<F: Fn() -> bool>(
    backoff: &mut RetrySchedule,
    is_active: &F,
    reason: &str,
) -> bool {
    let Some(delay) = crate::runtime_helpers::next_reconnect_delay(is_active(), backoff) else {
        return false;
    };
    tracing::warn!(
        reason,
        retry_delay_ms = delay.as_millis(),
        "Realm stream follow interrupted; retrying"
    );
    let mut waiting = Box::pin(crate::runtime_helpers::sleep_for(delay));
    while is_active() {
        match futures_util::future::select(
            &mut waiting,
            Box::pin(crate::runtime_helpers::sleep_for(SUBSCRIBE_CANCEL_POLL)),
        )
        .await
        {
            futures_util::future::Either::Left(_) => return is_active(),
            futures_util::future::Either::Right(_) => {}
        }
    }
    false
}

/// Read the private scope's MLS current from a complete authority-signed cut.
/// Parent Realm state and a shape-only Sidecar GET cannot supply this binding.
pub(crate) async fn verified_sidecar_mls_current(
    api: &crate::transport::TransportClient,
    scope: &arkret_sdk::ScopeRef,
) -> garth::Result<(
    arkret_wire::MlsGroupValue,
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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

pub(crate) type CreatorOwnSnapshot =
    arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::RealmId,
        arkret_sdk::RealmStateSnapshot,
    >;

async fn creator_own_station_cut(
    http: &arkret_sdk::http_client::Client,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
) -> garth::Result<(
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
    CreatorOwnSnapshot,
    arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority,
)> {
    use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAuthority;
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
            arkret_wire::CurrentState::Value {
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
    let sequence = garth::mls::creator::next_creator_read_sequence()?;
    let cut = MlsCreatorBootstrapAuthority::own_station(
        snapshot.clone(),
        genesis,
        session.account_id().clone(),
        session.grant_ref().clone(),
        session.epoch(),
        sequence,
    )?;
    client.check_session()?;
    Ok((client, response, cut))
}

async fn creator_own_station_unchanged(
    client: &arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
    arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
                && accepted.replace(full.clone()).is_some()
            {
                return Err(protocol("creator scope has multiple accepted Genesis"));
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

#[derive(Default)]
pub struct VerifiedAccountFrame {
    /// Recoverable stream-local interruption; no complete Account cut exists.
    stream_interruption: Option<garth::Error>,
    own_pages: Vec<garth::own_station_results::OwnStationScanPage>,
    own_replicas: BTreeMap<CommitStreamRef, garth::own_station_results::OwnStationReplica>,
    own_client: Option<arkret_sdk::http_client::own_station_results::OwnStationStateClient>,
    own_windows: Vec<(
        arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
        usize,
    )>,
    current_snapshots: BTreeMap<String, VerifiedCurrentSnapshot>,
    genesis_roles: BTreeMap<String, Option<arkret_sdk::CollaborationRealmRole>>,
    /// `preview_only` windows whose whole readable prefix this client
    /// replayed from genesis through a verified scan: exact from here on.
    resolved_preview_streams: BTreeSet<CommitStreamRef>,
    /// `preview_only` windows that stay display-only in this frame.
    preview_streams: BTreeSet<CommitStreamRef>,
}

/// In-memory capabilities retained only after an interrupted batch durably
/// projected its independent public history. Never serialized as wire evidence.
#[derive(Default)]
pub(crate) struct AccountRecoveryHistory {
    windows: BTreeMap<CommitStreamRef, RecoveredAccountWindow>,
}

struct RecoveredAccountWindow {
    session: arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot,
    window: arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    replica: garth::own_station_results::OwnStationReplica,
    pages: Vec<garth::own_station_results::OwnStationScanPage>,
}

impl AccountRecoveryHistory {
    pub(crate) fn retain(&mut self, proof: &mut VerifiedAccountFrame) -> garth::Result<()> {
        proof.check_session()?;
        let Some(client) = &proof.own_client else {
            return Ok(());
        };
        let session = client.session()?.clone();
        let mut pages = std::mem::take(&mut proof.own_pages).into_iter();
        for (window, count) in std::mem::take(&mut proof.own_windows) {
            let pages: Vec<_> = pages.by_ref().take(count).collect();
            if matches!(window.stream_ref, CommitStreamRef::Sidecar { .. }) {
                continue;
            }
            if let Some(replica) = proof.own_replicas.remove(&window.stream_ref) {
                self.windows.insert(
                    window.stream_ref.clone(),
                    RecoveredAccountWindow {
                        session: session.clone(),
                        window,
                        replica,
                        pages,
                    },
                );
            }
        }
        // Retention is bounded across the entire batch, not per Realm/window.
        let mut bytes = 0usize;
        for window in self.windows.values() {
            if let Some(snapshot) = window.replica.snapshot() {
                bytes = bytes.saturating_add(
                    serde_json::to_vec(snapshot)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?
                        .len(),
                );
            }
            for page in &window.pages {
                bytes = bytes.saturating_add(
                    serde_json::to_vec(page.rows()?)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?
                        .len(),
                );
            }
        }
        if bytes > 64 * 1024 * 1024 || self.windows.len() > 128 {
            self.windows.clear();
        }
        Ok(())
    }
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
    current: &arkret_models_collaboration::sync_frames::current_states::AccountStateView,
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
        client: arkret_sdk::http_client::own_station_results::OwnStationStateClient,
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
        self.stage_own_checkpoints_for(store, false)
    }

    pub(crate) fn require_current_own_checkpoints(
        &self,
        store: &mut crate::state::LocalStateStore,
        public_only: bool,
    ) -> anyhow::Result<()> {
        if let Some(client) = &self.own_client {
            self.check_session()?;
            for (stream, replica) in &self.own_replicas {
                if public_only && matches!(stream, CommitStreamRef::Sidecar { .. }) {
                    continue;
                }
                store.require_own_station_checkpoint_current(client, replica, stream)?;
            }
        }
        Ok(())
    }

    fn stage_own_checkpoints_for(
        &self,
        store: &mut crate::state::LocalStateStore,
        public_only: bool,
    ) -> Result<(), String> {
        if let Some(client) = &self.own_client {
            self.check_session().map_err(|error| error.to_string())?;
            for (stream, replica) in &self.own_replicas {
                if public_only && matches!(stream, CommitStreamRef::Sidecar { .. }) {
                    continue;
                }
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

    /// The caller holds the batch's verified projection transaction.
    pub(crate) fn stage_independent_public_history(
        &self,
        store: &mut crate::state::LocalStateStore,
    ) -> Result<(), String> {
        self.check_session().map_err(|error| error.to_string())?;
        for page in &self.own_pages {
            let rows = page.rows().map_err(|error| error.to_string())?;
            // Private Sidecar history/current always crosses one same-cut
            // barrier. Public history alone does not assert typed current.
            if rows.is_empty()
                || rows
                    .iter()
                    .any(|row| matches!(row.commit().stream_ref, CommitStreamRef::Sidecar { .. }))
            {
                continue;
            }
            store.ingest_verified_message_history(page)?;
            crate::identity::agent_signer_evidence::index_verified_committed_page(store, page)?;
        }
        self.stage_own_checkpoints_for(store, true)
    }

    pub(crate) fn take_stream_interruption(&mut self) -> Option<garth::Error> {
        self.stream_interruption.take()
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
            if let Some(client) = &self.own_client
                && store.active_authority().as_ref()
                    != Some(
                        client
                            .session()
                            .map_err(|error| error.to_string())?
                            .account_id(),
                    )
            {
                return Err("ordinary frame belongs to another account store".into());
            }
            body(store)
        })
    }

    pub(crate) fn current_snapshots(&self) -> &BTreeMap<String, VerifiedCurrentSnapshot> {
        &self.current_snapshots
    }

    pub(crate) fn genesis_roles(
        &self,
    ) -> &BTreeMap<String, Option<arkret_sdk::CollaborationRealmRole>> {
        &self.genesis_roles
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

fn protocol(error: impl std::fmt::Display) -> garth::Error {
    garth::Error::Protocol(error.to_string())
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
///   the same signed cut, the `message_revision` of each message (a create carrier's Strand must be
///   present in the cut; its mutable current revision is not its creation Commit), and the
///   `object_redaction` of a Message or Event, whose every assertion names that exact subject.
///
/// MLS, Space structural siblings, placement, Invite registers and grants
/// use their existing SDK value types and retain their exact Realm subjects.
/// Missing structural siblings, unknown families and cross-row mismatches
/// reject the whole snapshot.
#[cfg(test)]
fn validate_signed_floor_rows(
    realm_id: &arkret_sdk::RealmId,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    signed_head: &arkret_wire::CommitStreamHead,
    history_access: arkret_sdk::HistoryAccess,
    rows: &[arkret_wire::CurrentState],
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

/// Bind one aggregate frame to the current authenticated own-Station session.
/// Current rows must match a covering own-Station snapshot, and each exact
/// history window must match its independent accepted stream scan. Limited
/// preview history stays display-only until its window is independently admitted.
pub async fn verify_account_frame_commits(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    verify_account_frame_recovering(http, frame, &mut AccountRecoveryHistory::default()).await
}

pub(crate) async fn verify_account_frame_recovering(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    recovery: &mut AccountRecoveryHistory,
) -> garth::Result<VerifiedAccountFrame> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    own_station::account_frame(client, frame, recovery).await
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

#[cfg(test)]
mod tests {
    use arkret_wire::CurrentState;
    use garth::CursorScope;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn retry_backoff_stops_after_route_cancellation() {
        let active = std::cell::Cell::new(true);
        let mut backoff = RetrySchedule::new(Duration::from_secs(10), Duration::from_secs(10));
        let waiting =
            async { retry_after(&mut backoff, &|| active.get(), "cancelled route").await };
        let cancel = async {
            crate::runtime_helpers::sleep_for(Duration::from_millis(25)).await;
            active.set(false);
        };
        let (continued, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            futures_util::future::join(waiting, cancel).await
        })
        .await
        .expect("route cancellation must not wait for a ten-second reconnect backoff");
        assert!(!continued);
    }

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

    fn collaboration_fixture_realm_id() -> arkret_sdk::RealmId {
        crate::test_support::committed_event::verified_realm_fixture_signed_by(
            &crate::test_support::committed_event::FixtureStation::did_web(),
            arkret_sdk::RealmId::new(REALM_ID).unwrap(),
            json!({"object": collaboration_genesis(GENESIS_SALT)}),
            Vec::new(),
            "alice.example",
            DEVICE_ID,
        )
        .0
        .realm_id
    }

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
        let (mut bundle, ..) =
            crate::test_support::committed_event::verified_realm_fixture_from_genesis(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                event.clone(),
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

    fn set_row_value(row: &mut CurrentState, next: serde_json::Value) {
        let CurrentState::Value { value, .. } = row;
        *value = next;
    }

    #[test]
    fn signed_floor_watch_rows_admit_written_null_and_closed_object_but_reject_open_value() {
        use crate::test_support::committed_event::FixtureStation;
        let realm_id = collaboration_fixture_realm_id();
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
            let request = arkret_sdk::RealmAuthorityBundleRequestBody {
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
                        CurrentState::Value {
                            selector: arkret_sdk::CurrentSelector::StrandWatch { .. },
                            ..
                        }
                    )
                })
                .unwrap();
            let CurrentState::Value { value, .. } = watch_row;
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
                        CurrentState::Value {
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
        let realm_id = bundle.realm_id.clone();
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
        let row = |selector, value| CurrentState::Value {
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
        let validate = |rows: &[CurrentState]| {
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
        let realm_id = bundle.realm_id.clone();
        let created = items.last().unwrap();
        let head = arkret_wire::CommitStreamHead {
            stream_ref: created.commit.stream_ref.clone(),
            stream_position: created.commit.stream_position,
            commit_id: created.commit.commit_id.clone(),
        };
        let rows = coland_bootstrap_rows(&bundle, &items);
        let validate = |rows: &[CurrentState]| {
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
            let CurrentState::Value { value, .. } = forged.last_mut().unwrap();
            value[field] = invalid;
            assert!(validate(&forged).is_err(), "accepted invalid {field}");
        }
        let mut private_source = rows.clone();
        let CurrentState::Value {
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
        let realm_id = collaboration_fixture_realm_id();
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
        let realm_id = bundle.realm_id.clone();
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let rows = coland_bootstrap_rows(&bundle, &items);
        let validate = |rows: &[CurrentState]| {
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
        let CurrentState::Value { value, .. } = &mut substituted[index];
        value["id"] = json!(arkret_sdk::CircleId::from_event_id(
            &items[0].event.event_id
        ));
        assert!(validate(&substituted).is_err());
        let mut foreign = rows.clone();
        let CurrentState::Value { value, .. } = &mut foreign[index];
        value["realm_id"] = json!(arkret_sdk::RealmId::from_event_id(&items[0].event.event_id));
        assert!(validate(&foreign).is_err());
        let mut open = rows.clone();
        let CurrentState::Value { value, .. } = &mut open[index];
        value["unregistered"] = json!(true);
        assert!(validate(&open).is_err());
        let mut child_source = rows.clone();
        let CurrentState::Value {
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
        let realm_id = bundle.realm_id.clone();
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
        let row = CurrentState::Value {
            selector: arkret_wire::CurrentSelector::RealmGenesis,
            source_stream_ref: stream_ref.clone(),
            revision: genesis_revision.clone(),
            value: serde_json::to_value(&genesis).unwrap(),
        };
        let root = CurrentState::Value {
            selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
            source_stream_ref: stream_ref.clone(),
            revision: genesis_revision,
            value: json!({
                "controller_actor_id": bundle.genesis_event.actor_id,
                "controller_epoch": 0,
                "authority_generation": "0",
                "authority_event_ref": realm_id.event_id(),
            }),
        };
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        let installed_rows = vec![row.clone(), root.clone()];
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &installed_rows).unwrap();

        let mut forged_rows = Vec::new();
        let mut bad_value = row.clone();
        let CurrentState::Value { value, .. } = &mut bad_value;
        value.as_object_mut().unwrap().remove("schema");
        forged_rows.push(vec![bad_value, root.clone()]);
        let mut extra_member = row.clone();
        let CurrentState::Value { value, .. } = &mut extra_member;
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
        let CurrentState::Value { selector, .. } = &mut unsupported;
        *selector = arkret_wire::CurrentSelector::DeviceGeneration;
        forged_rows.push(vec![unsupported, root.clone()]);
        let mut wrong_source = row.clone();
        let CurrentState::Value {
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
        let CurrentState::Value { revision, .. } = &mut readable_revision;
        revision.stream_position = 1;
        revision.commit_id = items[0].commit.commit_id.clone();
        forged_rows.push(vec![readable_revision, root.clone()]);
        let mut other_controller = root.clone();
        set_row_value(
            &mut other_controller,
            json!({
                "controller_actor_id": {"kind":"service", "service_id":"ak:did_core:web:wrong.example"},
                "controller_epoch": 0,
                "authority_generation": "0",
                "authority_event_ref": realm_id.event_id(),
            }),
        );
        forged_rows.push(vec![row.clone(), other_controller]);
        let mut rotated = root.clone();
        set_row_value(
            &mut rotated,
            json!({
                "controller_actor_id": bundle.genesis_event.actor_id,
                "controller_epoch": 1,
                "authority_generation": "0",
                "authority_event_ref": realm_id.event_id(),
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
            let CurrentState::Value {
                revision, value, ..
            } = &mut advanced;
            *revision = arkret_wire::CurrentRevision {
                commit_id: later_head.commit_id.clone(),
                stream_position: later_head.stream_position,
            };
            value["controller_epoch"] = json!(epoch);
            value["authority_generation"] = json!(generation.to_string());
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &later_head,
                since_join,
                &[row.clone(), advanced.clone()],
            )
            .unwrap();
            let CurrentState::Value { value, .. } = &mut advanced;
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
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn own_station_genesis_persists_role_without_readable_position_zero() {
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
                arkret_sdk::DidUrl::new(format!("did:web:alice.example#{DEVICE_ID}")).unwrap(),
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
            let (mut bundle, _keys, _) =
                crate::test_support::committed_event::verified_realm_fixture_from_genesis(
                    &station,
                    event.clone(),
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
            let stream = CommitStreamRef::Realm {
                realm_id: realm.clone(),
            };
            let mut snapshot = arkret_sdk::RealmStateSnapshot {
                purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
                history_basis: None,
                snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
                realm_id: realm.clone(),
                governance_generation: 0,
                visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                    stream_ref: stream.clone(),
                    stream_position: 5,
                    commit_id: arkret_sdk::RealmCommitId::from_digest([42; 32]),
                }],
                current_state_entries: coland_bootstrap_rows(&bundle, &[]),
                retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                    history_access: arkret_wire::HistoryAccess::SinceJoin,
                    stream_floors: vec![arkret_wire::StreamHistoryFloor {
                        stream_ref: stream,
                        oldest_position: 3,
                    }],
                },
                created_at: fixture_time(50),
                signature: bundle.genesis_commit.signature.clone(),
            };
            station.sign_snapshot(&mut snapshot);
            let account = event.actor_id.as_account_id().unwrap().clone();
            let (client, server) = crate::transport::own_station_results::test_http::client(
                &account,
                vec![serde_json::to_value(&snapshot).unwrap()],
            );
            let frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(json!({
                "kind": "delta", "cursor": "ak:cursor:YQ",
                "realms": {realm.as_str(): {"current": {
                    "realm_id": realm, "governance_generation": "0",
                    "stream_heads": snapshot.visible_stream_heads,
                    "entries": snapshot.current_state_entries,
                }}}
            }))
            .unwrap();
            let verified = own_station::account_frame(client, &frame, &mut Default::default())
                .await
                .unwrap();
            server.join().unwrap();
            assert!(
                verified.own_pages().is_empty(),
                "current role needs no readable genesis replay"
            );
            let expected = (purpose == arkret_sdk::RealmPurpose::DirectConversation)
                .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("current-role.json");
            let mut store = crate::state::LocalStateStore::with_path(&path);
            let active = crate::test_support::AccountFixture::new("did:web:alice.example")
                .station(account.station_id.as_str())
                .build();
            store.switch_active_account(&active).unwrap();
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
            let mut tampered = snapshot.clone();
            let row = tampered
                .current_state_entries
                .iter_mut()
                .find(|row| {
                    matches!(
                        row,
                        arkret_wire::CurrentState::Value {
                            selector: arkret_wire::CurrentSelector::RealmGenesis,
                            ..
                        }
                    )
                })
                .unwrap();
            set_row_value(row, json!({"purpose": "direct_conversation"}));
            station.sign_snapshot(&mut tampered);
            let (client, server) = crate::transport::own_station_results::test_http::client(
                &account,
                vec![serde_json::to_value(tampered).unwrap()],
            );
            assert!(
                own_station::account_frame(client, &frame, &mut Default::default())
                    .await
                    .is_err()
            );
            server.join().unwrap();
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
            let realm_id = bundle.realm_id.clone();
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
                CurrentState::Value {
                    selector: arkret_wire::CurrentSelector::RealmGenesis,
                    source_stream_ref: stream_ref.clone(),
                    revision: revision.clone(),
                    value: serde_json::to_value(&genesis).unwrap(),
                },
                CurrentState::Value {
                    selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                    source_stream_ref: stream_ref,
                    revision,
                    value: json!({
                            "controller_actor_id": bundle.genesis_event.actor_id,
                            "controller_epoch": 0,
                            "authority_generation": "0",
                    "authority_event_ref": realm_id.event_id(),
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
            let CurrentState::Value {
                source_stream_ref,
                revision,
                ..
            } = rows[0].clone();
            with_history.push(CurrentState::Value {
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

    /// Coland discloses the founder's cut after messages and bootstrap facets:
    /// alias, plaintext-visible services and each created message's
    /// `message_revision` are installable closed rows, and a message must name
    /// a Strand present in the same signed cut, including after later updates.
    #[test]
    fn signed_floor_rows_admit_bootstrap_facets_and_messages_of_earlier_strands() {
        let realm_id = collaboration_fixture_realm_id();
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
            (
                "ak.strand.update".to_owned(),
                json!({
                    "strand_id": strand_id,
                    "patch": {"metadata": {"op": "set", "value": {"title": "Renamed"}}}
                }),
            ),
        ]);
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let facet = |selector, value| CurrentState::Value {
            selector,
            source_stream_ref: items[0].commit.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: items[0].commit.commit_id.clone(),
                stream_position: items[0].commit.stream_position,
            },
            value,
        };
        let mut rows = coland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        let media_index = rows.len();
        rows.push(facet(
            arkret_wire::CurrentSelector::RealmMediaService,
            json!({
                "service_id": "ak:did_core:web:station.example",
                "foci": [{
                    "focus_id": "call-focus",
                    "focus_kind": "livekit",
                    "token_endpoint": "https://station.example/token",
                    "connect_url": "wss://station.example/rtc"
                }]
            }),
        ));
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

        let mut updated = rows.clone();
        let row = updated.iter_mut().find(|row| matches!(row,
            CurrentState::Value { selector: arkret_wire::CurrentSelector::Strand { strand_id: id }, .. } if id == &strand_id
        )).unwrap();
        let CurrentState::Value {
            revision, value, ..
        } = row;
        *revision = arkret_wire::CurrentRevision {
            commit_id: head_commit.commit_id.clone(),
            stream_position: head_commit.stream_position,
        };
        value["metadata"]["title"] = json!("Renamed");
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &updated).unwrap();

        let message_index = rows
            .iter()
            .position(|row| {
                matches!(
                    row,
                    CurrentState::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        ..
                    }
                )
            })
            .unwrap();
        let mut forged = Vec::new();
        for invalid in [
            json!({"service_id": "ak:did_core:web:station.example", "foci": []}),
            json!({"service_id": "ak:did_core:web:station.example", "foci": [], "unknown": true}),
        ] {
            let mut invalid_media = rows.clone();
            set_row_value(&mut invalid_media[media_index], invalid);
            forged.push(invalid_media);
        }
        let mut insecure_media = rows.clone();
        let CurrentState::Value { value, .. } = &mut insecure_media[media_index];
        value["foci"][0]["token_endpoint"] = json!("http://station.example/token");
        forged.push(insecure_media);
        let mut unknown_strand = rows.clone();
        let CurrentState::Value { value, .. } = &mut unknown_strand[message_index];
        value["strand_id"] = json!(arkret_sdk::StrandId::from_event_id(
            &bundle.genesis_event.event_id
        ));
        forged.push(unknown_strand);
        let mut open_message = rows.clone();
        let CurrentState::Value { value, .. } = &mut open_message[message_index];
        value["unknown"] = json!(true);
        forged.push(open_message);
        let mut future_message = rows.clone();
        let CurrentState::Value { revision, .. } = &mut future_message[message_index];
        revision.stream_position = head.stream_position + 1;
        forged.push(future_message);
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
    fn signed_floor_call_state_preserves_creation_and_rejects_invalid_current_or_stream() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = crate::test_support::account_actor(ACTOR_ID);
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let realm_id = bundle.realm_id.clone();
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let rows_with = |value| {
            let mut rows = coland_bootstrap_rows(&bundle, &items);
            rows.push(CurrentState::Value {
                selector: arkret_wire::CurrentSelector::CallState {
                    call_id: arkret_sdk::CallId::from_event_id(&items[1].event.event_id),
                },
                source_stream_ref: head.stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: head.commit_id.clone(),
                    stream_position: head.stream_position,
                },
                value,
            });
            rows
        };
        let access = arkret_sdk::HistoryAccess::SinceJoin;
        for value in [
            json!({"from":null,"to":"scheduled"}),
            json!({"from":null,"to":"ringing"}),
            json!({"from":null,"to":"connecting"}),
            json!({"from":"connecting","to":"active"}),
        ] {
            validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows_with(value))
                .unwrap();
        }
        for value in [
            json!({"to":"ringing"}),
            json!({"from":null,"to":"active"}),
            json!({"from":"active","to":"failed"}),
            json!({"from":null,"to":"ringing","extra":true}),
            json!({"from":"unknown","to":"active"}),
        ] {
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows_with(value))
                    .is_err()
            );
        }
        let mut foreign = rows_with(json!({"from":null,"to":"ringing"}));
        let CurrentState::Value {
            source_stream_ref, ..
        } = foreign.last_mut().unwrap();
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&items[2].event.event_id),
        };
        assert!(validate_signed_floor_rows(&realm_id, &bundle, &head, access, &foreign).is_err());
    }

    #[test]
    fn signed_floor_rsvp_keeps_closed_entry_and_stream_binding() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = crate::test_support::account_actor(ACTOR_ID);
        let (bundle, _, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": collaboration_genesis(GENESIS_SALT)}),
                ordinary_bootstrap_entries(&creator),
                "alice.example",
                DEVICE_ID,
            );
        let realm_id = bundle.realm_id.clone();
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let mut rows = coland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        rows.push(CurrentState::Value {
            selector: arkret_wire::CurrentSelector::Rsvp {
                event_ref: arkret_sdk::StrandId::from_event_id(&items[1].event.event_id),
                occurrence: None,
                responder_actor_id: creator,
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: json!({
                "schedule_basis_refs": [bundle.genesis_event.event_id],
                "response": {"status":"accepted"},
            }),
        });
        let access = arkret_sdk::HistoryAccess::SinceJoin;
        validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows).unwrap();
        for (key, invalid) in [
            ("schedule_basis_refs", json!([])),
            ("response", json!({"status":"unknown"})),
            ("encrypted_response", json!({})),
            ("scope_ref", json!({"realm_id": realm_id})),
        ] {
            let mut forged = rows.clone();
            let CurrentState::Value { value, .. } = forged.last_mut().unwrap();
            value[key] = invalid;
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, access, &forged).is_err()
            );
        }
        let mut foreign = rows.clone();
        let CurrentState::Value {
            source_stream_ref, ..
        } = foreign.last_mut().unwrap();
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&items[2].event.event_id),
        };
        assert!(validate_signed_floor_rows(&realm_id, &bundle, &head, access, &foreign).is_err());
        let CurrentState::Value { selector, .. } = rows.last_mut().unwrap();
        let arkret_wire::CurrentSelector::Rsvp { occurrence, .. } = selector else {
            unreachable!()
        };
        *occurrence = Some("2026-10-07T09:00:00Z".to_owned());
        assert!(validate_signed_floor_rows(&realm_id, &bundle, &head, access, &rows).is_err());
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
        let realm_id = bundle.realm_id.clone();
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
        let mut rows = coland_bootstrap_rows(&bundle, &items);
        rows.push(CurrentState::Value {
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
            let CurrentState::Value { value, .. } = rows.last_mut().unwrap();
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
            let CurrentState::Value { value, .. } = forged.last_mut().unwrap();
            value[key] = invalid;
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, access, &forged).is_err()
            );
        }
        let mut foreign = rows.clone();
        let CurrentState::Value {
            source_stream_ref, ..
        } = foreign.last_mut().unwrap();
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&items[2].event.event_id),
        };
        assert!(validate_signed_floor_rows(&realm_id, &bundle, &head, access, &foreign).is_err());
    }

    #[test]
    fn signed_floor_reactions_admit_active_metadata_without_old_add_bytes() {
        let realm_id = collaboration_fixture_realm_id();
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
        let prefix = vec![
            strand,
            default_strand_entry(&strand_id, None),
            message_create_entry(&strand_id, "discussion"),
        ];
        let (_, _, probe) = chain(prefix.clone());
        let message = arkret_sdk::MessageId::from_event_id(&probe.last().unwrap().event.event_id);
        let mut tail = prefix;
        tail.push((
            "ak.reaction.add".to_owned(),
            json!({"target_ref":message,"key":"thumbsup"}),
        ));
        let (bundle, _, items) = chain(tail);
        let accepted = items.last().unwrap();
        let head = arkret_wire::CommitStreamHead {
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
            commit_id: accepted.commit.commit_id.clone(),
        };
        let mut rows = coland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        rows.push(CurrentState::Value {
            selector: arkret_wire::CurrentSelector::MessageReactions {
                target_ref: message.to_string(),
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: json!({"entries":[{
                "actor_id":accepted.event.actor_id,"key":"thumbsup",
                "source":{"event_id":accepted.event.event_id,"commit_id":accepted.commit.commit_id,
                    "stream_ref":accepted.commit.stream_ref,"stream_position":accepted.commit.stream_position}
            }]}),
        });
        validate_signed_floor_rows(
            &realm_id,
            &bundle,
            &head,
            arkret_sdk::HistoryAccess::SinceJoin,
            &rows,
        )
        .unwrap();
        let active = json!({"actor_id":accepted.event.actor_id,"key":"thumbsup",
            "source":{"event_id":accepted.event.event_id,"commit_id":accepted.commit.commit_id,
                "stream_ref":accepted.commit.stream_ref,"stream_position":accepted.commit.stream_position}});
        let mut future = active.clone();
        future["source"]["stream_position"] = json!(accepted.commit.stream_position + 1);
        for invalid in [
            json!({"assertions":[]}),
            json!({"entries":[active],"count":1}),
            json!({"entries":[active,active]}),
            json!({"entries":[future]}),
            json!({"entries":[{"actor_id":{"principal_id":ACTOR_ID},"key":"thumbsup","source":active["source"]}]}),
        ] {
            let mut forged = rows.clone();
            let CurrentState::Value { value, .. } = forged.last_mut().unwrap();
            *value = invalid;
            assert!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &head,
                    arkret_sdk::HistoryAccess::SinceJoin,
                    &forged
                )
                .is_err()
            );
        }
    }

    #[test]
    fn signed_floor_pins_admit_the_closed_set_and_reject_scope_or_dot_drift() {
        let realm_id = collaboration_fixture_realm_id();
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
        let prefix = vec![
            strand,
            default_strand_entry(&strand_id, None),
            message_create_entry(&strand_id, "discussion"),
        ];
        let (_, _, probe) = chain(prefix.clone());
        let message = arkret_sdk::MessageId::from_event_id(&probe.last().unwrap().event.event_id);
        let mut tail = prefix;
        tail.push((
            "ak.pin.add".to_owned(),
            json!({"pin_scope":{"kind":"realm","id":realm_id},"target_ref":message,"rank":"m"}),
        ));
        let (bundle, _, items) = chain(tail);
        let accepted = items.last().unwrap();
        let head = arkret_wire::CommitStreamHead {
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
            commit_id: accepted.commit.commit_id.clone(),
        };
        let mut rows = coland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        rows.push(CurrentState::Value {
            selector: arkret_wire::CurrentSelector::Pin {
                pin_scope: arkret_sdk::PinScope::Realm {
                    id: realm_id.clone(),
                },
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: json!({"assertions":[{
                "tag_id":format!("{}:0", accepted.event.event_id),
                "value":{"pin_scope":{"kind":"realm","id":realm_id},"target_ref":message,"rank":"m"}
            }]}),
        });
        validate_signed_floor_rows(
            &realm_id,
            &bundle,
            &head,
            arkret_sdk::HistoryAccess::SinceJoin,
            &rows,
        )
        .unwrap();
        for invalid in [
            json!({"assertions":[{"tag_id":format!("{}:1", accepted.event.event_id),
                "value":{"pin_scope":{"kind":"realm","id":realm_id},"target_ref":message,"rank":"m"}}]}),
            json!({"assertions":[{"tag_id":format!("{}:0", accepted.event.event_id),
                "value":{"pin_scope":{"kind":"strand","id":strand_id},"target_ref":message,"rank":"m"}}]}),
            json!({"assertions":[],"count":1}),
        ] {
            let mut forged = rows.clone();
            let CurrentState::Value { value, .. } = forged.last_mut().unwrap();
            *value = invalid;
            assert!(
                validate_signed_floor_rows(
                    &realm_id,
                    &bundle,
                    &head,
                    arkret_sdk::HistoryAccess::SinceJoin,
                    &forged
                )
                .is_err()
            );
        }
    }

    /// Coland's founder cut after an edit and a retraction: the edited
    /// Message's `message_revision` is the revise carrier naming that Message,
    /// and a retracted Message is disclosed as its `object_redaction` row, each
    /// assertion redacting exactly that Message. A revise naming another
    /// Message, an open or foreign redaction and an unsupported object
    /// subject reject the whole snapshot. Event crops remain independent of
    /// the Message lifecycle and preserve their exact assertion.
    #[test]
    fn signed_floor_snapshot_installs_message_revise_and_redaction() {
        let realm_id = collaboration_fixture_realm_id();
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
        let mut rows = coland_bootstrap_rows(&bundle, &items);
        let message_index = rows
            .iter()
            .position(|row| {
                matches!(
                    row,
                    CurrentState::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        ..
                    }
                )
            })
            .unwrap();
        let CurrentState::Value {
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
        let redaction = |target: &str, value: serde_json::Value| CurrentState::Value {
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
        let CurrentState::Value { value, .. } = &mut foreign_revision[message_index];
        value["message_id"] = json!(retracted);
        forged.push(foreign_revision);
        let mut open_revision = rows.clone();
        let CurrentState::Value { value, .. } = &mut open_revision[message_index];
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
        validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &event_subject).unwrap();
        let mut wrong_event_target = event_subject.clone();
        set_row_value(
            &mut wrong_event_target[redaction_index],
            json!({"assertions":[{
                "tag_id":redaction_tag,"value":{"target_ref":items[4].event.event_id}
            }]}),
        );
        forged.push(wrong_event_target);
        let mut event_with_message_payload = event_subject.clone();
        set_row_value(
            &mut event_with_message_payload[redaction_index],
            json!({"assertions":[{
                "tag_id":redaction_tag,"value":{"message_id":retracted}
            }]}),
        );
        forged.push(event_with_message_payload);
        let mut unsupported_subject = event_subject;
        let target = arkret_wire::MorphId::from_event_id(&items[5].event.event_id).to_string();
        unsupported_subject[redaction_index] = redaction(
            &target,
            json!({"assertions":[{
                "tag_id":redaction_tag,"value":{"target_ref":target}
            }]}),
        );
        forged.push(unsupported_subject);
        for rows in forged {
            assert!(
                validate_signed_floor_rows(&realm_id, &bundle, &head, since_join, &rows).is_err(),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn signed_floor_reactions_require_a_visible_typed_target_even_when_empty() {
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
        let realm_id = bundle.realm_id.clone();
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let target = arkret_sdk::MessageId::from_event_id(&items[1].event.event_id);
        let value = json!({"entries":[]});
        let mut rows = coland_bootstrap_rows(&bundle, &items);
        rows.push(CurrentState::Value {
            selector: arkret_wire::CurrentSelector::MessageReactions {
                target_ref: target.to_string(),
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: head.stream_position,
            },
            value: value.clone(),
        });
        let validate = |rows: &[CurrentState]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        // The target retypes a bootstrap policy Event, not a disclosed
        // Message current. A trusted empty set cannot reveal or create it.
        assert!(validate(&rows).is_err());
        let mut unsupported = rows.clone();
        let CurrentState::Value { selector, .. } = unsupported.last_mut().unwrap();
        *selector = arkret_wire::CurrentSelector::MessageReactions {
            target_ref: items[1].event.event_id.to_string(),
        };
        assert!(validate(&unsupported).is_err());
    }

    #[test]
    fn signed_floor_pin_assertions_are_closed_and_scope_bound() {
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
        let realm_id = bundle.realm_id.clone();
        let commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        let event_id = &items[2].event.event_id;
        let target = arkret_sdk::MessageId::from_event_id(&items[1].event.event_id);
        let tag = format!("{event_id}:0");
        let validate = |rows: &[CurrentState]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        for scope in [
            arkret_wire::PinScope::Realm {
                id: realm_id.clone(),
            },
            arkret_wire::PinScope::Strand {
                id: arkret_sdk::StrandId::from_event_id(event_id),
            },
            arkret_wire::PinScope::Circle {
                id: arkret_sdk::CircleId::from_event_id(event_id),
            },
            arkret_wire::PinScope::Space {
                id: arkret_sdk::SpaceId::from_event_id(event_id),
            },
        ] {
            let assertion = json!({"tag_id": tag, "value": {
                "pin_scope": scope, "target_ref": target, "rank": "a0"
            }});
            let mut rows = coland_bootstrap_rows(&bundle, &items);
            rows.push(CurrentState::Value {
                selector: arkret_wire::CurrentSelector::Pin {
                    pin_scope: scope.clone(),
                },
                source_stream_ref: head.stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: head.commit_id.clone(),
                    stream_position: head.stream_position,
                },
                value: json!({"assertions": [assertion]}),
            });
            validate(&rows).unwrap();
            for payload in [
                json!({"pin_scope": scope, "target_ref": target}),
                json!({"pin_scope": scope, "target_ref": target, "rank": "b0", "expected_rank": "a0"}),
            ] {
                let mut accepted = rows.clone();
                set_row_value(
                    accepted.last_mut().unwrap(),
                    json!({"assertions": [{"tag_id": tag, "value": payload}]}),
                );
                validate(&accepted).unwrap();
            }
            for bad in [
                json!({"assertions": [assertion], "roster": [target]}),
                json!({"assertions": [assertion, assertion]}),
                json!({"assertions": [{"tag_id": format!("{event_id}:1"), "value": assertion["value"]}]}),
                json!({"assertions": [{"tag_id": tag, "actor_id": creator, "value": assertion["value"]}]}),
                json!({"assertions": [{"tag_id": tag, "kind": "ak.pin.add", "value": assertion["value"]}]}),
                json!({"assertions": [{"tag_id": tag, "value": {"pin_scope": scope, "target_ref": target, "rank": "!"}}]}),
                json!({"assertions": [{"tag_id": tag, "value": {"pin_scope": scope, "target_ref": "hidden", "rank": "a0"}}]}),
                json!({"assertions": [{"tag_id": tag, "value": {"pin_scope": scope, "target_ref": target, "rank": "a0", "note": "plaintext"}}]}),
            ] {
                let mut forged = rows.clone();
                set_row_value(forged.last_mut().unwrap(), bad);
                assert!(validate(&forged).is_err());
            }
            let mut foreign = rows.clone();
            let CurrentState::Value { selector, .. } = foreign.last_mut().unwrap();
            *selector = arkret_wire::CurrentSelector::Pin {
                pin_scope: arkret_wire::PinScope::Realm {
                    id: arkret_sdk::RealmId::from_event_id(&items[3].event.event_id),
                },
            };
            assert!(validate(&foreign).is_err());
            let mut empty = rows.clone();
            set_row_value(empty.last_mut().unwrap(), json!({"assertions": []}));
            validate(&empty).unwrap();
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
        let realm_id = bundle.realm_id.clone();
        let head_commit = &items.last().unwrap().commit;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: head_commit.stream_ref.clone(),
            stream_position: head_commit.stream_position,
            commit_id: head_commit.commit_id.clone(),
        };
        let since_join = arkret_sdk::HistoryAccess::SinceJoin;
        let rows_with = |join_policy: Option<serde_json::Value>, rule: &str| {
            let mut rows = coland_bootstrap_rows(&bundle, &items);
            for row in &mut rows {
                let CurrentState::Value {
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

    pub(in crate::realm_events_engine) fn coland_bootstrap_rows(
        bundle: &arkret_sdk::RealmAuthorityBundle,
        items: &[arkret_sdk::CommittedEventFullView],
    ) -> Vec<CurrentState> {
        use arkret_wire::CurrentSelector;
        let row = |selector, commit: &arkret_sdk::RealmCommit, value| CurrentState::Value {
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
                    "authority_generation": "0",
                "authority_event_ref": bundle.realm_id.event_id(),
                }),
            ),
        ];
        for item in items {
            let payload = serde_json::to_value(&item.event.payload).unwrap();
            let commit = &item.commit;
            rows.push(match item.event.kind.as_str() {
                "ak.realm.profile" => row(CurrentSelector::RealmProfile, commit, payload),
                "ak.scope.read_receipt_policy" => row(
                    CurrentSelector::ScopeReadReceiptPolicy {
                        scope_ref: commit.stream_ref.scope_ref(),
                    },
                    commit,
                    payload,
                ),
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
                        Some(level) => arkret_sdk::StrandWatchValue::Set(
                            arkret_sdk::StrandWatchExpectedValue {
                                level,
                                level_public: watch.level_public,
                            },
                        ),
                        None => arkret_sdk::StrandWatchValue::Cleared(()),
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
                // Coland's `message_revision` writer: the create payload at
                // the Event-derived MessageId.
                "ak.message.create" => row(
                    CurrentSelector::MessageRevision {
                        message_id: arkret_sdk::MessageId::from_event_id(&item.event.event_id),
                    },
                    commit,
                    payload,
                ),
                other => panic!("{other} is outside the Coland bootstrap cut"),
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
        let realm = bundle.realm_id.clone();
        let request = arkret_sdk::RealmAuthorityBundleRequestBody {
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
        let scan = StreamScanRequestBody {
            realm_id: realm,
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 200,
        };
        let outcome = arkret_sdk::StreamScanResponseBody {
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
        last.commit.signature.signature = arkret_sdk::Base64UrlString::new("AA").unwrap();
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
        let realm = collaboration_fixture_realm_id();
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
        let realm = bundle.realm_id.clone();
        let request = arkret_sdk::RealmAuthorityBundleRequestBody {
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
                    arkret_sdk::canonical::canonical_json_bytes(&identity).unwrap(),
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
        let mls_current = arkret_wire::MlsGroupValue {
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
            CurrentState::Value {
                selector: arkret_sdk::CurrentSelector::MlsGroup {
                    scope_ref: scope.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: serde_json::to_value(&mls_current).unwrap(),
            },
            CurrentState::Value {
                selector: arkret_sdk::CurrentSelector::Sidecar {
                    sidecar_id: sidecar.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: json!({"id":sidecar,"schema":"ak.schema.agent_sidecar.v1",
                    "realm_id":realm,"controller_account_id":controller,"state":"active",
                    "created_at":"2026-01-01T00:00:00.000Z"}),
            },
            CurrentState::Value {
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
        assert!(store.verified_sidecar_inputs(realm.as_str()).is_err());
        assert!(store.current_mls_group_for_scope(&scope).is_none());
        let mut replay = replica.fork_verified_authority().unwrap();
        let scan = arkret_sdk::StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 1,
        };
        let page = replay
            .apply_verified_scan(
                &scan,
                arkret_sdk::StreamScanResponseBody {
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
        let checkpoint_scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: actor.clone(),
            device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
        };
        let old_checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:verified-sidecar-old-cut".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        store
            .verified_projection_transaction(|store| {
                store.ingest_verified_message_history(&page)?;
                store
                    .save_account_checkpoint(&checkpoint_scope, old_checkpoint.clone())
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        store.flush().unwrap();
        assert!(std::fs::read_dir(&directory).unwrap().next().is_some());
        drop(store);
        let mut reopened = LocalStateStore::with_path(&path);
        assert_eq!(
            reopened.current_mls_group_for_scope(&scope),
            Some(mls_current.clone())
        );
        let group_id = scope.canonical_mls_group_id().unwrap();
        let checkpoint = garth::mls::checkpoint::encrypt_state(
            realm.as_str(),
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
                .verified_sidecar_for_source(&controller, realm.as_str(), &source_strand)
                .unwrap()
                .unwrap()
                .id,
            sidecar
        );
        let other_strand = arkret_sdk::StrandId::from_event_id(&native[0].event.event_id);
        assert!(
            reopened
                .verified_sidecar_for_source(&controller, realm.as_str(), &other_strand)
                .unwrap()
                .is_none()
        );
        let mut other_station = controller.clone();
        other_station.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            reopened
                .verified_sidecar_for_source(&other_station, realm.as_str(), &source_strand)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened.verified_sidecar_inputs(realm.as_str()).unwrap().1[sidecar.as_str()],
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
        let prior_position = reopened.verified_sidecar_inputs(realm.as_str()).unwrap().1
            [sidecar.as_str()]
        .last()
        .unwrap()
        .commit
        .stream_position;
        assert!(!reopened.has_pending_sidecar_history(realm.as_str()));
        let mut missing_tail = snapshot.clone();
        let missing_head = missing_tail
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == stream)
            .unwrap();
        missing_head.stream_position = 2;
        missing_head.commit_id = arkret_sdk::RealmCommitId::from_digest([122; 32]);
        station.sign_snapshot(&mut missing_tail);
        let mut missing_verifier = replica.fork_verified_authority().unwrap();
        missing_verifier
            .install_verified_current_snapshot_heads(&missing_tail, &freshness, &keys)
            .unwrap();
        let missing_before = serde_json::to_value(reopened.load()).unwrap();
        let mut missing_staged = false;
        let missing_result = reopened.verified_projection_transaction(|store| {
            store.install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: missing_tail.clone(),
            })?;
            store
                .save_account_checkpoint(
                    &account_scope(),
                    garth::AccountCursorCheckpoint {
                        cursor: "ak:cursor:sidecar-position-2".into(),
                        station_cas: garth::StationCasProjection::default(),
                    },
                )
                .map_err(|error| error.to_string())?;
            missing_staged = true;
            store
                .sidecar_history_at_snapshot(&missing_tail)
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        assert!(missing_result.is_err());
        assert!(
            missing_staged,
            "the refusal must come from missing authenticated history"
        );
        assert_eq!(
            serde_json::to_value(reopened.load()).unwrap(),
            missing_before
        );
        let missing_reload = LocalStateStore::with_path(&path);
        assert_eq!(
            serde_json::to_value(missing_reload.load()).unwrap(),
            missing_before
        );
        println!(
            "SYNC_CHECKPOINT_CASE {}",
            json!({
                "case_id":"sidecar_missing_tail_does_not_install_newer_current_or_checkpoint", "assertions":5,
                "stream_kind":"sidecar", "candidate_position":missing_tail.visible_stream_heads.iter().find(|head| head.stream_ref == stream).unwrap().stream_position,
                "prior_position":prior_position, "durable":missing_result.is_ok(),
                "checkpoint_advanced":missing_reload.load().sync_cursor != before_new_cut.sync_cursor
            })
        );
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
            serde_json::to_value(reopened.load()).unwrap(),
            serde_json::to_value(&before_new_cut).unwrap()
        );
        assert_eq!(
            reopened.load_account_checkpoint(&checkpoint_scope).unwrap(),
            Some(old_checkpoint.clone())
        );
        reopened
            .install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })
            .unwrap();
        assert!(reopened.verified_sidecar_inputs(realm.as_str()).is_err());
        assert!(reopened.has_pending_sidecar_history(realm.as_str()));
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
                .verified_sidecar_for_source(&controller, realm.as_str(), &source_strand)
                .is_err()
        );
        let scan = arkret_sdk::StreamScanRequestBody {
            direction: arkret_sdk::StreamScanDirection::After(Some(0)),
            ..scan
        };
        let page = replay
            .apply_verified_scan(
                &scan,
                arkret_sdk::StreamScanResponseBody {
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
            live_follow
                .verified_sidecar_inputs(realm.as_str())
                .unwrap()
                .1[sidecar.as_str()],
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
            live_follow
                .verified_sidecar_inputs(realm.as_str())
                .unwrap()
                .1[sidecar.as_str()],
            native
        );
        reopened.ingest_verified_message_history(&page).unwrap();
        assert!(!reopened.has_pending_sidecar_history(realm.as_str()));
        let mut ahead = LocalStateStore::with_path(directory.join("ahead.json"));
        ahead.save(before_new_cut.clone());
        ahead.ingest_verified_message_history(&page).unwrap();
        assert_eq!(
            ahead.verified_sidecar_inputs(realm.as_str()).unwrap().1[sidecar.as_str()],
            vec![native[0].clone()]
        );
        let stream_key = serde_json::to_string(&stream).unwrap();
        assert_eq!(ahead.load().verified_sidecar_history[&stream_key].len(), 2);
        let mut failed = LocalStateStore::with_path(directory.join("failed-cut.json"));
        failed.save(before_new_cut.clone());
        failed
            .save_account_checkpoint(
                &account_scope(),
                garth::AccountCursorCheckpoint {
                    cursor: "ak:cursor:sidecar-retained".into(),
                    station_cas: garth::StationCasProjection::default(),
                },
            )
            .unwrap();
        failed.flush().unwrap();
        let failed_before = serde_json::to_value(failed.load()).unwrap();
        let prior_bytes = failed.conformance_account_checkpoint_token().unwrap();
        failed.conformance_fail_account_commit(true).unwrap();
        let mut candidate_validated = false;
        let failed_cut = failed.verified_projection_transaction(|store| {
            store.ingest_verified_message_history(&page)?;
            store
                .sidecar_history_at_snapshot(&snapshot)
                .map_err(|error| error.to_string())?;
            store.install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })?;
            store
                .save_account_checkpoint(
                    &account_scope(),
                    garth::AccountCursorCheckpoint {
                        cursor: "ak:cursor:sidecar-position-1".into(),
                        station_cas: garth::StationCasProjection::default(),
                    },
                )
                .map_err(|error| error.to_string())?;
            candidate_validated = true;
            Ok(())
        });
        assert!(failed_cut.is_err());
        assert!(
            candidate_validated,
            "the candidate must reach the real durable write"
        );
        assert_eq!(serde_json::to_value(failed.load()).unwrap(), failed_before);
        failed.conformance_fail_account_commit(false).unwrap();
        assert_eq!(
            failed.conformance_account_checkpoint_token().unwrap(),
            prior_bytes
        );
        let failed_reload = LocalStateStore::with_path(directory.join("failed-cut.json"));
        assert_eq!(
            serde_json::to_value(failed_reload.load()).unwrap(),
            failed_before
        );
        assert_eq!(
            failed_reload
                .verified_sidecar_inputs(realm.as_str())
                .unwrap()
                .1[sidecar.as_str()],
            vec![native[0].clone()]
        );
        println!(
            "SYNC_CHECKPOINT_CASE {}",
            json!({
                "case_id":"sidecar_projection_transaction_failure_preserves_prior_cut", "assertions":6,
                "stream_kind":"sidecar", "candidate_position":snapshot.visible_stream_heads.iter().find(|head| head.stream_ref == stream).unwrap().stream_position,
                "prior_position":prior_position, "durable":failed_cut.is_ok(),
                "checkpoint_advanced":serde_json::to_value(failed_reload.load()).unwrap()["sync_cursor"] != failed_before["sync_cursor"]
            })
        );
        let mut atomic = LocalStateStore::with_path(directory.join("atomic-cut.json"));
        atomic.save(before_new_cut);
        let atomic_before = atomic.load();
        let installed = atomic.verified_projection_transaction(|store| {
            store.ingest_verified_message_history(&page)?;
            store
                .sidecar_history_at_snapshot(&snapshot)
                .map_err(|error| error.to_string())?;
            store.install_verified_sidecar_current(&VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            })?;
            store
                .save_account_checkpoint(
                    &account_scope(),
                    garth::AccountCursorCheckpoint {
                        cursor: "ak:cursor:sidecar-position-1".into(),
                        station_cas: garth::StationCasProjection::default(),
                    },
                )
                .map_err(|error| error.to_string())
        });
        assert!(installed.is_ok());
        let atomic_reload = LocalStateStore::with_path(directory.join("atomic-cut.json"));
        assert_eq!(
            serde_json::to_value(atomic_reload.load()).unwrap(),
            serde_json::to_value(atomic.load()).unwrap()
        );
        assert_eq!(
            atomic_reload
                .verified_sidecar_inputs(realm.as_str())
                .unwrap()
                .1[sidecar.as_str()],
            native
        );
        assert_eq!(
            atomic_reload.load().sync_cursor.as_deref(),
            Some("ak:cursor:sidecar-position-1")
        );
        println!(
            "SYNC_CHECKPOINT_CASE {}",
            json!({
                "case_id":"sidecar_history_current_projection_same_cut_before_checkpoint", "assertions":4,
                "stream_kind":"sidecar", "candidate_position":snapshot.visible_stream_heads.iter().find(|head| head.stream_ref == stream).unwrap().stream_position,
                "prior_position":prior_position, "durable":installed.is_ok(),
                "checkpoint_advanced":atomic_reload.load().sync_cursor != atomic_before.sync_cursor
            })
        );
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
            ahead.verified_sidecar_inputs(realm.as_str()).unwrap().1[sidecar.as_str()],
            native
        );
        ahead.flush().unwrap();
        let complete_reload = LocalStateStore::with_path(directory.join("ahead.json"));
        assert_eq!(
            serde_json::to_value(complete_reload.load()).unwrap(),
            serde_json::to_value(ahead.load()).unwrap()
        );
        assert_eq!(
            complete_reload
                .verified_sidecar_inputs(realm.as_str())
                .unwrap()
                .1[sidecar.as_str()],
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
        assert!(ahead.verified_sidecar_inputs(realm.as_str()).is_err());
        let mut gap = complete.clone();
        gap.verified_sidecar_history
            .get_mut(&stream_key)
            .unwrap()
            .remove(0);
        ahead.save(gap);
        assert!(ahead.verified_sidecar_inputs(realm.as_str()).is_err());
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
        assert!(ahead.verified_sidecar_inputs(realm.as_str()).is_err());
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
            reopened.verified_sidecar_inputs(realm.as_str()).unwrap().1[sidecar.as_str()],
            native
        );
        assert!(
            reopened
                .install_verified_sidecar_current(&VerifiedCurrentSnapshot { snapshot: old })
                .is_err()
        );
        reopened.invalidate_sidecar_current(Some(realm.as_str()));
        assert!(!reopened.has_pending_sidecar_history(realm.as_str()));
        assert!(reopened.verified_sidecar_inputs(realm.as_str()).is_err());
        assert!(reopened.mls_scopes_needing_tail_recovery().is_empty());
        drop((
            reopened,
            live_follow,
            failed,
            atomic,
            missing_reload,
            failed_reload,
            atomic_reload,
            complete_reload,
        ));
        // Independent GC can finish its last SQLite transaction after a host drops.
        let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match std::fs::remove_dir_all(&directory) {
                Ok(()) => break,
                Err(error)
                    if error.raw_os_error() == Some(32)
                        && std::time::Instant::now() < cleanup_deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("fixture cleanup failed: {error}"),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn signed_snapshot_current_staging_is_atomic_and_cut_bound() {
        use crate::test_support::committed_event::FixtureStation;
        let realm_id = collaboration_fixture_realm_id();
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
        let realm_id = bundle.realm_id.clone();
        let request = arkret_sdk::RealmAuthorityBundleRequestBody {
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
            arkret_wire::CurrentState::Value { selector, .. } => selector.clone(),
        };
        let mut frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(json!({
            "kind":"delta", "cursor":"ak:cursor:YQ",
            "realms":{realm_id.as_str():{"current":{
                "realm_id":realm_id, "governance_generation":(snapshot.governance_generation).to_string(),
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
            .get_mut(realm_id.as_str())
            .unwrap()
            .streams = Some(vec![
            serde_json::from_value(json!({
                "stream_ref": head.stream_ref,
                "head_commit_ref": head.commit_id,
                "next_position": head.stream_position + 1,
                "limited": true,
                "max_window_event_count": 1,
                "complete": true,
                "preview_only": true
            }))
            .unwrap(),
        ]);
        let proofs = BTreeMap::from([(
            realm_id.as_str().to_owned(),
            VerifiedCurrentSnapshot { snapshot },
        )]);
        let unresolved = VerifiedAccountFrame::default();
        assert!(
            unresolved.product_frame(&frame).realms.unwrap().entries[realm_id.as_str()]
                .current
                .is_none()
        );
        let proven = VerifiedAccountFrame {
            current_snapshots: BTreeMap::from([(
                realm_id.as_str().to_owned(),
                VerifiedCurrentSnapshot {
                    snapshot: proofs[realm_id.as_str()].snapshot().clone(),
                },
            )]),
            ..Default::default()
        };
        assert!(
            proven.product_frame(&frame).realms.unwrap().entries[realm_id.as_str()]
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
            index
                .read_selector(realm_id.as_str(), &selector)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            index.read_complete_cut(realm_id.as_str()).await.unwrap(),
            None
        );
        let mut wrong_cut = frame.clone();
        wrong_cut
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(realm_id.as_str())
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
        assert_eq!(
            index.read_complete_cut(realm_id.as_str()).await.unwrap(),
            None
        );
        let mut lagging = frame.clone();
        let earlier = &items[items.len() - 2].commit;
        let lagging_head = &mut lagging
            .realms
            .as_mut()
            .unwrap()
            .entries
            .get_mut(realm_id.as_str())
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
        assert!(
            index
                .read_complete_cut(realm_id.as_str())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            index
                .read_selector(realm_id.as_str(), &selector)
                .await
                .unwrap()
                .is_some()
        );
        let invalidation = serde_json::from_value(json!({
            "kind":"delta", "cursor":"ak:cursor:YQ",
            "realm_invalidations":[{"realm_id":realm_id.as_str(),"revision":1}]
        }))
        .unwrap();
        index
            .stage_verified_frame(1, &invalidation, &BTreeSet::new())
            .await
            .unwrap()
            .finish();
        assert_eq!(
            index.read_complete_cut(realm_id.as_str()).await.unwrap(),
            None
        );
        index
            .stage_verified_frame_with_snapshots(2, &lagging, &BTreeSet::new(), &proofs)
            .await
            .unwrap()
            .finish();
        assert!(
            index
                .read_complete_cut(realm_id.as_str())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            index
                .read_selector_ready(realm_id.as_str(), &selector)
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
            json!({"disclosure":"required","visibility":"private"}),
        ] {
            let mut entries = ordinary_bootstrap_entries(&creator);
            entries.push(("ak.scope.read_receipt_policy".to_owned(), policy.clone()));
            let (bundle, _, items) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &crate::test_support::committed_event::FixtureStation::did_web(),
                    realm_id.clone(),
                    json!({"object": collaboration_genesis(GENESIS_SALT)}),
                    entries,
                    "alice.example",
                    DEVICE_ID,
                );
            let realm_id = bundle.realm_id.clone();
            let rows = coland_bootstrap_rows(&bundle, &items);
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
                        arkret_wire::CurrentState::Value {
                            selector: arkret_wire::CurrentSelector::ScopeReadReceiptPolicy { .. },
                            ..
                        }
                    )
                })
                .unwrap();
            let arkret_wire::CurrentState::Value { value, .. } = &rows[index];
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
        let realm_id = collaboration_fixture_realm_id();
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
                "primary_conflict_domain":domain,"expected_commit_id":null,
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
        let realm_id = bundle.realm_id.clone();
        let accepted = items.last().unwrap();
        let head = bundle.current_assertion.realm_stream_head.clone();
        let mut rows = coland_bootstrap_rows(&bundle, &items[..items.len() - 1]);
        rows.push(arkret_wire::CurrentState::Value {
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
        let validate = |rows: &[arkret_wire::CurrentState]| {
            validate_signed_floor_rows(
                &realm_id,
                &bundle,
                &head,
                arkret_sdk::HistoryAccess::SinceJoin,
                rows,
            )
        };
        validate(&rows).unwrap();
        let arkret_wire::CurrentState::Value { value, .. } = rows.last().unwrap();
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
        let arkret_wire::CurrentState::Value { selector, .. } = rejected.last_mut().unwrap();
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
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: bundle.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: head.commit.stream_position,
                commit_id: head.commit.commit_id.clone(),
            }],
            current_state_entries: coland_bootstrap_rows(bundle, prefix),
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
        let mut payload =
            json!({"realm_id": collaboration_fixture_realm_id(), "strand_id": target});
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
        let realm = committed.event.realm_id.clone();
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
}
