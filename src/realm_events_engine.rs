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

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use garth::{
    AuthorityClient, ClientEvent, CommitStreamRef, CommittedDelta, CommittedEventView,
    DecodedInbound, InboundDecoder, RealmReplica, RetrySchedule, StreamScanRequest,
};

use crate::config::MultiProfileConfig;

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence. The doubling ladder is [`garth::RetrySchedule`];
/// these are just its bounds, kept as `Duration` so the account and realm
/// engines share one unit (F-10).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Pause between drained passes over the Realm's streams.
// A fresh bundle resets the verified predecessor, so each pass replays from
// genesis. Do not spin that O(history) work at the old shape-only 250 ms beat.
const BEAT: Duration = Duration::from_secs(5);

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

/// Shared product projection handles for a fully verified Realm replay.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    digest_suite: arkret_sdk::DigestSuite,
    realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    message_stream_hub: crate::views::message_streams::MessageStreamHub,
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
        let authority = AuthorityClient::new(http.clone());
        match follow_once(
            &authority,
            &http,
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
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    ctx: &RealmEventsEngineContext,
    is_active: &F,
) -> garth::Result<()>
where
    T: garth::AuthorityTransport,
    F: Fn() -> bool,
{
    let (bundle, freshness, mut replica) = fresh_verified_realm(authority, http, realm_id).await?;
    for stream_ref in followed_streams(realm_id, ctx) {
        if !is_active() {
            return Ok(());
        }
        drain_stream(
            authority,
            http,
            &mut replica,
            &bundle,
            &freshness,
            realm_id,
            &stream_ref,
            projector,
        )
        .await?;
    }
    Ok(())
}

async fn fresh_verified_realm<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
) -> garth::Result<(
    arkret_sdk::RealmAuthorityBundle,
    arkret_identity::RealmAuthorityFreshness,
    RealmReplica,
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
    let freshness = arkret_identity::RealmAuthorityFreshness::new(
        chrono::Utc::now(),
        request.nonce.clone(),
        chrono::Duration::minutes(5),
    )
    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    let mut replica = RealmReplica::new(realm_id.clone());
    replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
    Ok((bundle, freshness, replica))
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
    http: &arkret_sdk::http_client::Client,
    replica: &mut RealmReplica,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    realm_id: &arkret_sdk::RealmId,
    stream_ref: &CommitStreamRef,
    projector: &RealmIngestProjector,
) -> garth::Result<()>
where
    T: garth::AuthorityTransport,
{
    let projected_through = projector
        .state_store
        .read(|store| store.verified_commit_stream_cursor(stream_ref))
        .map_err(garth::Error::Protocol)?;
    let (pages, _) = verified_stream_pages(
        authority, http, replica, bundle, freshness, realm_id, stream_ref, None,
    )
    .await?
    .into_verified()?;
    let tail = replica.verified_head(stream_ref).cloned();
    // A stored cursor is a commit identity, not merely a number. Locate that
    // exact commit in the newly verified genesis replay before deduplicating.
    if let Some(saved) = projected_through.as_ref() {
        let found = pages
            .iter()
            .flat_map(|page| page.rows())
            .find(|row| row.commit().stream_position == saved.stream_position);
        if found.is_none_or(|row| row.commit().commit_id != saved.commit_id)
            || tail
                .as_ref()
                .is_none_or(|head| head.stream_position < saved.stream_position)
        {
            return Err(garth::Error::Protocol(
                "verified replay does not contain stored Commit cursor".to_owned(),
            ));
        }
    }
    let fresh_rows = pages
        .iter()
        .flat_map(|page| page.rows())
        .filter(|row| {
            projected_through
                .as_ref()
                .is_none_or(|saved| row.commit().stream_position > saved.stream_position)
        })
        .cloned()
        .collect();
    let batch = committed_views_to_client_events(realm_id, fresh_rows)?;
    if batch.is_empty() {
        return Ok(());
    }
    let final_freshness = arkret_identity::RealmAuthorityFreshness::new(
        chrono::Utc::now(),
        freshness.expected_nonce.clone(),
        freshness.max_bundle_age,
    )
    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let bundle_keys =
        garth::fetch_historical_station_key_directory(http, bundle, None, None).await?;
    arkret_identity::verify_realm_authority_bundle(bundle, &final_freshness, &bundle_keys)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    // Nothing is projected until the complete stream has passed the verifier.
    // Index, product fold, and cursor form one account-state write. Any
    // validation conflict restores the previous state before persistence.
    let (changed, finals) = projector
        .state_store
        .write(|store| {
            store.verified_projection_transaction(|store| {
                for page in &pages {
                    store.ingest_verified_message_commits(page)?;
                    crate::identity::agent_signer_evidence::index_verified_committed_page(
                        store, page,
                    )?;
                }
                let finals = batch
                    .iter()
                    .filter_map(|event| {
                        accepted_direct_message_final(event, projector.digest_suite, store)
                    })
                    .collect::<Vec<_>>();
                let changed = ingest_realm_batch(store, &projector.realm_id, &batch);
                if let Some(tail) = tail.clone() {
                    store.save_verified_commit_stream_cursor(stream_ref, tail)?;
                }
                Ok((changed, finals))
            })
        })
        .map_err(garth::Error::Protocol)?;
    let barrier = projector
        .state_store
        .read(|store| store.begin_durable_flush())
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    barrier
        .wait()
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let mut message_stream_hub = projector.message_stream_hub;
    for (event, sender_endpoint) in finals {
        if let Err(error) = message_stream_hub.bind_verified_final(event, &sender_endpoint) {
            tracing::warn!(%error, event_id = %event.event_id, "message stream final binding failed closed");
        }
    }
    if changed > 0 {
        projector
            .realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
    Ok(())
}

/// The exact signed predecessor a limited Account window names, and the own
/// Station description whose operation bundles decide whether the by-ref read
/// exists at all.
#[derive(Clone, Copy)]
struct FloorAnchor<'a> {
    basis: &'a arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
    describe: &'a arkret_models_discovery::ServiceDescribe,
}

async fn verified_stream_pages<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    replica: &mut RealmReplica,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    realm_id: &arkret_sdk::RealmId,
    stream_ref: &CommitStreamRef,
    floor_anchor: Option<FloorAnchor<'_>>,
) -> garth::Result<StreamPages> {
    // A full-history stream starts at genesis. A limited Account window may
    // start only from the exact signed head named by its basis, read by
    // reference from a Station that advertises the exact-read bundle; the
    // first readable page must extend that signed head (and, for a
    // `before_readable_floor` basis, be the named floor Commit).
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
    let mut after_position = snapshot.as_ref().map(|(_, position)| *position);
    let mut pages = Vec::new();
    let mut verified_floor_snapshot = None;
    loop {
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(after_position),
            limit: SCAN_LIMIT,
        };
        let outcome = authority.scan(&request).await?;
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
                    freshness.max_bundle_age,
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                verified_floor_snapshot = Some(replica.install_verified_floor_predecessor(
                    stream_ref,
                    basis,
                    floor,
                    snapshot,
                    &snapshot_freshness,
                    &snapshot_keys,
                )?);
            }
        } else if let Err(error) = require_genesis_readable_floor(&outcome) {
            // Only the first page decides whether a genesis replay can start;
            // a floor that moves above genesis mid-replay is a broken scan.
            if pages.is_empty() {
                return Ok(StreamPages::AboveGenesis);
            }
            return Err(error);
        }
        let truncated = outcome.truncated;
        let keys =
            garth::fetch_historical_station_key_directory(http, bundle, Some(&outcome), None)
                .await?;
        let page_freshness = arkret_identity::RealmAuthorityFreshness::new(
            chrono::Utc::now(),
            freshness.expected_nonce.clone(),
            freshness.max_bundle_age,
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let (next_position, empty) = stage_verified_page(
            replica,
            &request,
            outcome,
            &page_freshness,
            &keys,
            &mut pages,
        )?;
        if empty || !truncated {
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
    floor_current_rows: Vec<(arkret_sdk::RealmId, Vec<arkret_wire::TypedCurrentResult>)>,
    /// `preview_only` windows whose whole readable prefix this client
    /// replayed from genesis through a verified scan: exact from here on.
    resolved_preview_streams: BTreeSet<CommitStreamRef>,
    /// `preview_only` windows that stay display-only in this frame.
    preview_streams: BTreeSet<CommitStreamRef>,
}

impl VerifiedAccountFrame {
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
    /// current and baseline, so nothing downstream (durable current index,
    /// Realm projection, product view) can take them as exact; the preview
    /// stream's committed rows stay as display rows.
    pub fn product_frame(
        &self,
        frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    ) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        let mut product = frame.clone();
        if let Some(realms) = product.realms.as_mut() {
            for entry in realms.entries.values_mut() {
                if crate::state::current_index::current_reads_preview_stream(
                    entry,
                    &self.resolved_preview_streams,
                ) {
                    entry.current = None;
                    entry.baseline = None;
                }
            }
        }
        product
    }

    /// Called inside the Account frame's durable projection transaction.
    /// Only `verify_account_frame_commits` can populate the private signed
    /// current carrier; a shape-only frame never reaches this installer.
    pub fn install_floor_current(
        &self,
        store: &mut crate::state::LocalStateStore,
    ) -> Result<(), String> {
        for (realm_id, rows) in &self.floor_current_rows {
            store
                .install_current_product_view(
                    realm_id.as_str(),
                    rows.clone(),
                    crate::current_projection::required_realm_values_ready(rows),
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

/// Install the current rows of one exact signed single-stream snapshot and
/// the verified readable tail after it. Every signed row is strictly parsed
/// as its registered typed family (see [`validate_signed_floor_rows`]); the
/// tail may contain audit facts, closed Realm facet writes, or the registered
/// history-access state transition. Gate-bearing policy remains fail closed.
fn admit_single_stream_floor_current(
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    realm_id: &arkret_sdk::RealmId,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    snapshot: garth::VerifiedFloorSnapshot,
    pages: &[garth::VerifiedScanPage],
) -> garth::Result<Vec<arkret_wire::TypedCurrentResult>> {
    let current = entry.current.as_ref().ok_or_else(|| {
        garth::Error::Protocol("floor snapshot has no exact Account current cut".to_owned())
    })?;
    if current.realm_id != *realm_id {
        return Err(garth::Error::Protocol(
            "Account current rows belong to another Realm".to_owned(),
        ));
    }
    validate_signed_floor_rows(
        realm_id,
        bundle,
        snapshot.head(),
        snapshot.history_access(),
        snapshot.rows(),
    )?;
    let expected = fold_floor_current_tail(snapshot.into_rows(), pages)?;
    require_exact_floor_tail_current(&current.entries, &expected)?;
    Ok(current.entries.clone())
}

fn require_exact_floor_tail_current(
    claimed: &[arkret_wire::TypedCurrentResult],
    expected: &[arkret_wire::TypedCurrentResult],
) -> garth::Result<()> {
    if claimed.len() != expected.len() || expected.iter().any(|row| !claimed.contains(row)) {
        return Err(garth::Error::Protocol(
            "Account current rows differ from verified floor and readable tail".to_owned(),
        ));
    }
    Ok(())
}

fn fold_floor_current_tail(
    mut rows: Vec<arkret_wire::TypedCurrentResult>,
    pages: &[garth::VerifiedScanPage],
) -> garth::Result<Vec<arkret_wire::TypedCurrentResult>> {
    for page in pages {
        for committed in page.rows() {
            let arkret_wire::CommittedEventView::Full(full) = committed else {
                return Err(garth::Error::Protocol(
                    "floor current tail requires a disclosed Event".to_owned(),
                ));
            };
            if full.event.kind == arkret_wire::EventKind::AuditAccessed {
                let audit: arkret_models_collaboration::events_payloads::audit::AuditAccessedPayload =
                    serde_json::from_value(serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                if audit.writer_actor_id != full.event.actor_id {
                    return Err(garth::Error::Protocol(
                        "audit tail writer differs from signed Event actor".to_owned(),
                    ));
                }
            } else if full.event.kind.as_str() == "ak.realm.profile" {
                let profile: arkret_sdk::RealmProfile = serde_json::from_value(
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                let value = profile
                    .to_value()
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                if value
                    != serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?
                {
                    return Err(garth::Error::Protocol(
                        "Realm profile tail payload is not the closed current value".to_owned(),
                    ));
                }
                rows.retain(|row| {
                    !matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmProfile,
                            ..
                        }
                    )
                });
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmProfile,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value,
                });
            } else if full.event.kind.as_str() == "ak.realm.policy_bundle" {
                let previous = rows.iter().find_map(|row| match row {
                    arkret_wire::TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                        value,
                        ..
                    } => Some(value),
                    _ => None,
                });
                let value = closed_policy_bundle_value(
                    previous,
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )?;
                rows.retain(|row| {
                    !matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                            ..
                        }
                    )
                });
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value,
                });
            } else if full.event.kind.as_str() == "ak.realm.join_rule" {
                let policy = rows.iter().find_map(|row| match row {
                    arkret_wire::TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                        value,
                        ..
                    } => Some(value),
                    _ => None,
                });
                let value = closed_join_rule_value(
                    policy,
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )?;
                rows.retain(|row| {
                    !matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmJoinRule,
                            ..
                        }
                    )
                });
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmJoinRule,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value,
                });
            } else if full.event.kind.as_str() == "ak.realm.discovery" {
                let value = closed_discovery_value(
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )?;
                rows.retain(|row| {
                    !matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmDiscovery,
                            ..
                        }
                    )
                });
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmDiscovery,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value,
                });
            } else if full.event.kind.as_str() == "ak.member.state" {
                let selector = closed_creator_join_selector(
                    &rows,
                    &full.event,
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )?;
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value: serde_json::json!({"membership": "join"}),
                });
            } else if full.event.kind.as_str() == "ak.realm.history_access" {
                let previous = rows.iter().find_map(|row| match row {
                    arkret_wire::TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                        value,
                        ..
                    } => Some(value),
                    _ => None,
                });
                let previous = previous
                    .map(|value| {
                        serde_json::from_value::<arkret_sdk::HistoryAccess>(value.clone())
                            .map_err(|error| garth::Error::Protocol(error.to_string()))
                    })
                    .transpose()?;
                let next = closed_history_transition(
                    previous,
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )?;
                rows.retain(|row| {
                    !matches!(
                        row,
                        arkret_wire::TypedCurrentResult::Value {
                            selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                            ..
                        }
                    )
                });
                rows.push(arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                    source_stream_ref: full.commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: full.commit.commit_id.clone(),
                        stream_position: full.commit.stream_position,
                    },
                    value: serde_json::to_value(next)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                });
            } else {
                return Err(garth::Error::Protocol(
                    "floor current tail has an unsupported typed reducer".to_owned(),
                ));
            }
        }
    }
    Ok(rows)
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

fn closed_creator_join_selector(
    rows: &[arkret_wire::TypedCurrentResult],
    event: &arkret_sdk::Event,
    payload: serde_json::Value,
) -> garth::Result<arkret_wire::CurrentSelector> {
    let member: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    if serde_json::to_value(&member).map_err(|error| garth::Error::Protocol(error.to_string()))?
        != payload
        || member.membership
            != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
        || member.member_id != event.actor_id
        || member.realm_id.as_ref() != Some(&event.realm_id)
        || member.strand_id.is_some()
        || !member.gate_proofs.is_empty()
        || member.membership_cause.is_some()
        || member.agent_controller_binding.is_some()
        || member.invite_ref.is_some()
    {
        return Err(garth::Error::Protocol(
            "floor member state is not the closed creator join".to_owned(),
        ));
    }
    for required in [
        arkret_wire::CurrentSelector::RealmProfile,
        arkret_wire::CurrentSelector::RealmPolicyBundle,
        arkret_wire::CurrentSelector::RealmJoinRule,
        arkret_wire::CurrentSelector::RealmHistoryAccess,
        arkret_wire::CurrentSelector::RealmDiscovery,
    ] {
        if !rows.iter().any(|row| {
            matches!(row,
                arkret_wire::TypedCurrentResult::Value { selector, .. } if selector == &required
            )
        }) {
            return Err(garth::Error::Protocol(
                "creator join lacks verified bootstrap facets".to_owned(),
            ));
        }
    }
    let selector = arkret_wire::CurrentSelector::MemberState {
        actor_id: member.member_id,
    };
    if rows.iter().any(|row| matches!(row,
        arkret_wire::TypedCurrentResult::Value { selector: existing, .. } if existing == &selector
    )) {
        return Err(garth::Error::Protocol(
            "creator member state already exists at signed cut".to_owned(),
        ));
    }
    Ok(selector)
}

fn closed_policy_bundle_value(
    previous: Option<&serde_json::Value>,
    payload: serde_json::Value,
) -> garth::Result<serde_json::Value> {
    let bundle: arkret_sdk::RealmPolicyBundlePayload = serde_json::from_value(payload.clone())
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let canonical =
        serde_json::to_value(&bundle).map_err(|error| garth::Error::Protocol(error.to_string()))?;
    if canonical != payload || bundle.join_policy.is_some() {
        return Err(garth::Error::Protocol(
            "floor policy bundle has unsupported or non-closed components".to_owned(),
        ));
    }
    let expected_revision = match previous {
        Some(value) => value
            .get("policy_revision")
            .and_then(serde_json::Value::as_u64)
            .and_then(|revision| revision.checked_add(1))
            .ok_or_else(|| garth::Error::Protocol("invalid prior policy revision".to_owned()))?,
        None => 1,
    };
    if bundle.policy_revision != expected_revision {
        return Err(garth::Error::Protocol(
            "floor policy revision is not the next accepted revision".to_owned(),
        ));
    }
    Ok(payload)
}

fn closed_join_rule_value(
    policy: Option<&serde_json::Value>,
    payload: serde_json::Value,
) -> garth::Result<serde_json::Value> {
    if policy.is_none() {
        return Err(garth::Error::Protocol(
            "floor join rule has no verified policy bundle predecessor".to_owned(),
        ));
    }
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
    if value == "restricted" || value == "knock_restricted" {
        return Err(garth::Error::Protocol(
            "floor join rule requires an unverified automatic gate".to_owned(),
        ));
    }
    Ok(value)
}

fn closed_history_transition(
    previous: Option<arkret_sdk::HistoryAccess>,
    payload: serde_json::Value,
) -> garth::Result<arkret_sdk::HistoryAccess> {
    if payload.get("from").is_none() {
        return Err(garth::Error::Protocol(
            "Realm history access tail omits required from".to_owned(),
        ));
    }
    if payload
        .get("reason")
        .is_some_and(|reason| !reason.is_string())
    {
        return Err(garth::Error::Protocol(
            "Realm history access tail has a non-string reason".to_owned(),
        ));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HistoryTransition {
        from: Option<arkret_sdk::HistoryAccess>,
        to: arkret_sdk::HistoryAccess,
        #[allow(dead_code)]
        reason: Option<String>,
    }
    let transition: HistoryTransition = serde_json::from_value(payload)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let allowed = match (&previous, &transition.from, &transition.to) {
        (None, None, _) => true,
        (
            Some(arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers),
            Some(arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers),
            arkret_sdk::HistoryAccess::SinceJoin,
        ) => true,
        _ => false,
    };
    if !allowed {
        return Err(garth::Error::Protocol(
            "Realm history access tail violates its closed transition".to_owned(),
        ));
    }
    Ok(transition.to)
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
/// - Every row names this Realm stream as its `source_stream_ref` (decision
///   0103) at a position no later than the signed head.
/// - `realm_genesis` and `realm_authority_root` are the genesis projections:
///   their covering Commit is the verified bundle's exact genesis Commit, the
///   genesis value is the genesis Event's `object`, and the root is the
///   generation-zero creator controller.
/// - Other admitted families are the ordinary bootstrap closure a single
///   governing Station issues: profile, policy bundle, join rule, history
///   access (equal to the signed floor's `history_access`), discovery,
///   member state, Realm-scoped Strand and the default-Strand pointer, which
///   must name a Strand in the same signed cut.
///
/// Any other family, extra member, gate-bearing policy or cross-row mismatch
/// rejects the whole snapshot.
fn validate_signed_floor_rows(
    realm_id: &arkret_sdk::RealmId,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    signed_head: &arkret_wire::CommitStreamHead,
    history_access: arkret_sdk::HistoryAccess,
    rows: &[arkret_wire::TypedCurrentResult],
) -> garth::Result<()> {
    use arkret_wire::CurrentSelector;

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
    let policy = rows.iter().find_map(|row| match row {
        arkret_wire::TypedCurrentResult::Value {
            selector: CurrentSelector::RealmPolicyBundle,
            value,
            ..
        } => Some(value),
        _ => None,
    });
    let mut genesis = false;
    let mut root = false;
    let mut strands = BTreeMap::new();
    let mut default_strand = None;
    for row in rows {
        let arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            return Err(protocol(
                "signed floor current family has no product installer",
            ));
        };
        if source_stream_ref != &realm_stream
            || revision.stream_position > signed_head.stream_position
            || (revision.stream_position == signed_head.stream_position
                && revision.commit_id != signed_head.commit_id)
        {
            return Err(protocol(
                "signed floor row source is not the signed Realm stream prefix",
            ));
        }
        let genesis_projection = matches!(
            selector,
            CurrentSelector::RealmGenesis | CurrentSelector::RealmAuthorityRoot
        );
        if genesis_projection != (revision == &genesis_revision) {
            return Err(protocol(
                "signed floor row revision differs from its genesis covering Commit",
            ));
        }
        match selector {
            CurrentSelector::RealmGenesis => {
                let parsed: arkret_sdk::RealmGenesis = closed_value(value, "realm_genesis")?;
                parsed.validate().map_err(protocol)?;
                let payload =
                    serde_json::to_value(&bundle.genesis_event.payload).map_err(protocol)?;
                if parsed.purpose != arkret_sdk::RealmPurpose::Collaboration
                    || payload.get("object") != Some(value)
                {
                    return Err(protocol(
                        "signed genesis row is not the verified collaboration genesis object",
                    ));
                }
                genesis = true;
            }
            CurrentSelector::RealmAuthorityRoot => {
                #[derive(serde::Deserialize, serde::Serialize)]
                #[serde(deny_unknown_fields)]
                struct AuthorityRoot {
                    controller_actor_id: arkret_sdk::ActorId,
                    controller_epoch: u64,
                    authority_generation: u64,
                }
                let parsed: AuthorityRoot = closed_value(value, "realm_authority_root")?;
                if parsed.controller_actor_id != bundle.genesis_event.actor_id
                    || parsed.controller_epoch != 0
                    || parsed.authority_generation != 0
                {
                    return Err(protocol(
                        "signed authority root is not the generation-zero creator controller",
                    ));
                }
                root = true;
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
                if parsed.join_policy.is_some() || parsed.policy_revision == 0 {
                    return Err(protocol(
                        "signed policy bundle carries an unverified gate or revision",
                    ));
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
            }
            CurrentSelector::RealmDiscovery => {
                closed_discovery_value(serde_json::json!({ "value": value }))?;
            }
            CurrentSelector::MemberState { .. } => {
                closed_value::<arkret_wire::MemberStateCurrent>(value, "member_state")?;
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
            _ => {
                return Err(protocol(
                    "signed floor current family has no product installer",
                ));
            }
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
/// projected. One non-preview single-stream window anchored
/// `before_readable_floor` or `after_committed_prefix` installs its exact
/// signed snapshot rows plus the verified tail; any other limited shape stays
/// out of the product current.
///
/// A `preview_only` window (client-sync §5.2) is decided per stream and never
/// fails its siblings: the client backfills it with the same verified scan
/// from genesis. When that replay verifies the whole readable prefix, the
/// window start is no longer unknown and the stream is exact; when the
/// caller's readable history starts above genesis, the stream stays preview:
/// its rows remain display rows only, and neither its current nor any
/// verified index or checkpoint advances. A verified row that contradicts the
/// frame still fails closed.
pub async fn verify_account_frame_commits(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    verify_account_frame_with(&AuthorityClient::new(http.clone()), http, frame).await
}

async fn verify_account_frame_with<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    let mut verified = VerifiedAccountFrame::default();
    let Some(realms) = frame.realms.as_ref() else {
        return Ok(verified);
    };
    'realms: for (realm, entry) in &realms.entries {
        let realm_id = arkret_sdk::RealmId::new(realm.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if let Some(windows) = entry.streams.as_ref() {
            for window in windows {
                let Some(basis) = snapshot_window_basis(window) else {
                    continue;
                };
                if windows.len() != 1 {
                    return Err(garth::Error::Protocol(
                        "floor current projection requires one exact Realm stream".to_owned(),
                    ));
                }
                let describe = http
                    .describe_for_role(arkret_sdk::ServiceKind::Station)
                    .await?;
                let (bundle, freshness, mut replica) =
                    fresh_verified_realm(authority, http, &realm_id).await?;
                let (pages, floor_snapshot) = verified_stream_pages(
                    authority,
                    http,
                    &mut replica,
                    &bundle,
                    &freshness,
                    &realm_id,
                    &window.stream_ref,
                    Some(FloorAnchor {
                        basis,
                        describe: &describe,
                    }),
                )
                .await?
                .into_verified()?;
                let scanned = pages
                    .iter()
                    .flat_map(|page| page.rows())
                    .collect::<Vec<_>>();
                require_window_start_row(basis, &scanned)?;
                if let Some(all_claimed) = entry.committed_events.as_ref() {
                    let claimed = all_claimed
                        .iter()
                        .filter(|row| row.commit().stream_ref == window.stream_ref)
                        .collect::<Vec<_>>();
                    require_exact_claimed_rows(&claimed, &scanned)?;
                    if claimed.len() != scanned.len() || claimed.len() != all_claimed.len() {
                        return Err(garth::Error::Protocol(
                            "Account window rows differ from the verified floor stream".to_owned(),
                        ));
                    }
                } else if !scanned.is_empty() {
                    return Err(garth::Error::Protocol(
                        "Account window omits its verified floor tail".to_owned(),
                    ));
                }
                let expected_position = window.next_position.checked_sub(1).ok_or_else(|| {
                    garth::Error::Protocol("account frame stream head has no position".to_owned())
                })?;
                if replica
                    .verified_head(&window.stream_ref)
                    .is_none_or(|head| {
                        head.stream_position != expected_position
                            || head.commit_id != window.head_commit_ref
                    })
                {
                    return Err(garth::Error::Protocol(
                        "account frame stream head differs from verified scan".to_owned(),
                    ));
                }
                let floor_snapshot = floor_snapshot.ok_or_else(|| {
                    garth::Error::Protocol("floor snapshot did not pass Garth".to_owned())
                })?;
                let current = entry.current.as_ref().ok_or_else(|| {
                    garth::Error::Protocol("floor snapshot has no Account current cut".to_owned())
                })?;
                if window.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                    || current.governance_generation != floor_snapshot.governance_generation()
                    || current.stream_heads.len() != 1
                    || current.stream_heads.first() != replica.verified_head(&window.stream_ref)
                {
                    return Err(garth::Error::Protocol(
                        "Account current cut differs from signed floor snapshot".to_owned(),
                    ));
                }
                let rows = admit_single_stream_floor_current(
                    entry,
                    &realm_id,
                    &bundle,
                    floor_snapshot,
                    &pages,
                )?;
                verified.pages.extend(pages);
                verified.floor_current_rows.push((realm_id, rows));
                continue 'realms;
            }
        }
        require_genesis_window_basis(entry)?;
        verify_full_history_realm(authority, http, &realm_id, entry, &mut verified).await?;
    }
    Ok(verified)
}

/// Verify one Realm entry without a signed snapshot basis: every stream that
/// carries rows, and every `preview_only` window, is replayed from genesis
/// through a fresh nonce-bound verified scan.
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
        if window.preview_only != Some(true) {
            continue;
        }
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
            None,
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
        freshness.max_bundle_age,
    )
    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    arkret_identity::verify_realm_authority_bundle(&bundle, &final_freshness, &keys)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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
/// never reaches the by-ref read or the product installer, whatever basis it
/// carries, and a genesis basis needs no snapshot.
fn snapshot_window_basis(
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
) -> Option<&arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;
    if window.preview_only == Some(true) {
        return None;
    }
    window
        .window_start_basis
        .as_ref()
        .filter(|basis| basis.anchor_kind != StreamWindowAnchorKind::StreamGenesis)
}

/// The first verified row of a snapshot-anchored window. `before_readable_floor`
/// must start with the floor Commit the basis names; `after_committed_prefix`
/// starts right after the signed head the basis names (Garth has already
/// bound the first row's predecessor to that head) and may be empty.
fn require_window_start_row(
    basis: &arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
    scanned: &[&CommittedEventView],
) -> garth::Result<()> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;
    let anchored = match basis.anchor_kind {
        StreamWindowAnchorKind::BeforeReadableFloor => scanned.first().is_some_and(|row| {
            Some(row.commit().stream_position) == basis.anchor_position
                && Some(&row.commit().commit_id) == basis.anchor_commit_ref.as_ref()
        }),
        StreamWindowAnchorKind::AfterCommittedPrefix => scanned.first().is_none_or(|row| {
            basis
                .anchor_position
                .and_then(|position| position.checked_add(1))
                == Some(row.commit().stream_position)
        }),
        StreamWindowAnchorKind::StreamGenesis => false,
    };
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
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;
    if entry.streams.as_ref().is_some_and(|windows| {
        windows.iter().any(|window| {
            window.preview_only != Some(true)
                && window
                    .window_start_basis
                    .as_ref()
                    .is_some_and(|basis| basis.anchor_kind != StreamWindowAnchorKind::StreamGenesis)
        })
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
            return Err(garth::Error::Protocol(
                "account frame Commit differs from verified stream row".to_owned(),
            ));
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

    #[test]
    fn verified_bootstrap_facets_require_exact_commits_and_atomic_install() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let profile = json!({"schema": "ak.schema.realm_profile.v1", "title": "After floor"});
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let (bundle, keys, items) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm_id.clone(),
            vec![
                ("ak.realm.profile".to_owned(), profile.clone()),
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
            ],
            "alice.example",
            DEVICE_ID,
        );
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(10),
            request.nonce.clone(),
            chrono::Duration::minutes(5),
        )
        .unwrap();
        let mut replica = RealmReplica::new(realm_id.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        let genesis_request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 1,
        };
        let genesis_scan = arkret_sdk::StreamScanOutcome {
            committed_events: vec![CommittedEventView::Full(
                arkret_sdk::CommittedEventFullView {
                    commit: bundle.genesis_commit.clone(),
                    event: bundle.genesis_event.clone(),
                },
            )],
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            }),
            truncated: true,
        };
        stage_verified_page(
            &mut replica,
            &genesis_request,
            genesis_scan,
            &freshness,
            &keys,
            &mut Vec::new(),
        )
        .unwrap();
        let scan_request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(Some(0)),
            limit: 10,
        };
        let scan = arkret_sdk::StreamScanOutcome {
            committed_events: items
                .iter()
                .cloned()
                .map(CommittedEventView::Full)
                .collect(),
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 1,
                floor_commit_id: items[0].commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::RetentionPruned,
            }),
            truncated: false,
        };
        let mut pages = Vec::new();
        stage_verified_page(
            &mut replica,
            &scan_request,
            scan,
            &freshness,
            &keys,
            &mut pages,
        )
        .unwrap();
        let expected = fold_floor_current_tail(Vec::new(), &pages).unwrap();
        assert_eq!(expected.len(), 6);
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &expected[1]
        else {
            panic!("policy bundle must be a closed value");
        };
        assert_eq!(selector, &arkret_wire::CurrentSelector::RealmPolicyBundle);
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[1].commit.commit_id);
        assert_eq!(revision.stream_position, items[1].commit.stream_position);
        assert_eq!(value, &json!({"policy_revision": 1}));
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &expected[2]
        else {
            panic!("join rule must be a closed value");
        };
        assert_eq!(selector, &arkret_wire::CurrentSelector::RealmJoinRule);
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[2].commit.commit_id);
        assert_eq!(revision.stream_position, items[2].commit.stream_position);
        assert_eq!(value, "invite");
        let TypedCurrentResult::Value {
            source_stream_ref,
            revision,
            value,
            ..
        } = &expected[0]
        else {
            panic!("profile must be a closed value");
        };
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[0].commit.commit_id);
        assert_eq!(revision.stream_position, items[0].commit.stream_position);
        assert_eq!(value, &profile);
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &expected[3]
        else {
            panic!("history access must be a closed value");
        };
        assert_eq!(selector, &arkret_wire::CurrentSelector::RealmHistoryAccess);
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[3].commit.commit_id);
        assert_eq!(revision.stream_position, items[3].commit.stream_position);
        assert_eq!(value, "since_join");
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &expected[4]
        else {
            panic!("discovery must be a closed value");
        };
        assert_eq!(selector, &arkret_wire::CurrentSelector::RealmDiscovery);
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[4].commit.commit_id);
        assert_eq!(revision.stream_position, items[4].commit.stream_position);
        assert_eq!(value, &json!({"discoverability": "listed"}));
        let TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &expected[5]
        else {
            panic!("creator membership must be a closed value");
        };
        assert_eq!(
            selector,
            &arkret_wire::CurrentSelector::MemberState { actor_id: creator }
        );
        assert_eq!(source_stream_ref, &stream_ref);
        assert_eq!(revision.commit_id, items[5].commit.commit_id);
        assert_eq!(revision.stream_position, items[5].commit.stream_position);
        assert_eq!(value, &json!({"membership": "join"}));
        let creator_payload = serde_json::to_value(&items[5].event.payload).unwrap();
        assert!(
            closed_creator_join_selector(&expected[..4], &items[5].event, creator_payload.clone())
                .is_err()
        );
        assert!(
            closed_creator_join_selector(&expected, &items[5].event, creator_payload.clone())
                .is_err()
        );
        let mut forged_join = creator_payload.clone();
        forged_join["membership"] = json!("leave");
        assert!(
            closed_creator_join_selector(&expected[..5], &items[5].event, forged_join).is_err()
        );
        let mut forged_join = creator_payload;
        forged_join["member_id"] =
            json!({"kind":"service", "service_id":"ak:did_core:web:wrong.example"});
        assert!(
            closed_creator_join_selector(&expected[..5], &items[5].event, forged_join).is_err()
        );
        require_exact_floor_tail_current(&expected, &expected).unwrap();

        let mut forged = expected.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut forged[0] else {
            unreachable!()
        };
        revision.stream_position += 1;
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut forged[0]
        else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { value, .. } = &mut forged[0] else {
            unreachable!()
        };
        *value = json!({"schema": "ak.schema.realm_profile.v1", "title": "Forged"});
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut forged[3] else {
            unreachable!()
        };
        revision.commit_id = items[0].commit.commit_id.clone();
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut forged[3]
        else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { value, .. } = &mut forged[3] else {
            unreachable!()
        };
        *value = json!("all_history_for_current_members");
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut forged[1]
        else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut forged[2] else {
            unreachable!()
        };
        revision.commit_id = items[1].commit.commit_id.clone();
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { value, .. } = &mut forged[2] else {
            unreachable!()
        };
        *value = json!("public");
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value { value, .. } = &mut forged[4] else {
            unreachable!()
        };
        *value = json!({"discoverability":"secret"});
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());
        let mut forged = expected.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut forged[5]
        else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        assert!(require_exact_floor_tail_current(&forged, &expected).is_err());

        let path = std::env::temp_dir().join(format!(
            "inkson-profile-tail-atomic-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(&path);
        let verified = VerifiedAccountFrame {
            pages: Vec::new(),
            floor_current_rows: vec![(realm_id.clone(), expected.clone())],
            ..Default::default()
        };
        let scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
        };
        let checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:profile-tail".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        let failed: Result<(), String> = store.verified_projection_transaction(|store| {
            verified.install_floor_current(store)?;
            store
                .save_account_checkpoint(&scope, checkpoint.clone())
                .map_err(|error| error.to_string())?;
            Err("late frame rejection".to_owned())
        });
        assert!(failed.is_err());
        assert!(store.realm_tree_projection(realm_id.as_str()).is_none());
        assert_eq!(store.load_account_checkpoint(&scope).unwrap(), None);
        store
            .verified_projection_transaction(|store| {
                verified.install_floor_current(store)?;
                store
                    .save_account_checkpoint(&scope, checkpoint.clone())
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        assert_eq!(
            store.load_account_checkpoint(&scope).unwrap(),
            Some(checkpoint)
        );
        assert_eq!(
            store.realm_tree_projection(realm_id.as_str()).unwrap()["summary"]["title"],
            "After floor"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn history_access_tail_obeys_registered_one_way_transition() {
        use arkret_sdk::HistoryAccess::{AllHistoryForCurrentMembers, SinceJoin};

        assert_eq!(
            closed_history_transition(None, json!({"from": null, "to": "since_join"})).unwrap(),
            SinceJoin
        );
        assert_eq!(
            closed_history_transition(
                None,
                json!({"from": null, "to": "all_history_for_current_members"})
            )
            .unwrap(),
            AllHistoryForCurrentMembers
        );
        assert_eq!(
            closed_history_transition(
                Some(AllHistoryForCurrentMembers),
                json!({"from": "all_history_for_current_members", "to": "since_join"})
            )
            .unwrap(),
            SinceJoin
        );
        for (prior, payload) in [
            (None, json!({"to": "since_join"})),
            (None, json!({"from": "since_join", "to": "since_join"})),
            (
                Some(SinceJoin),
                json!({"from": "since_join", "to": "all_history_for_current_members"}),
            ),
            (
                Some(SinceJoin),
                json!({"from": "since_join", "to": "since_join"}),
            ),
            (
                Some(AllHistoryForCurrentMembers),
                json!({"from": null, "to": "since_join"}),
            ),
            (
                Some(AllHistoryForCurrentMembers),
                json!({"from": "since_join", "to": "since_join"}),
            ),
            (
                None,
                json!({"from": null, "to": "since_join", "other": true}),
            ),
            (
                None,
                json!({"from": null, "to": "since_join", "reason": null}),
            ),
        ] {
            assert!(closed_history_transition(prior, payload).is_err());
        }
    }

    #[test]
    fn policy_and_join_tail_reject_gaps_and_unverified_gates() {
        let first = closed_policy_bundle_value(None, json!({"policy_revision": 1})).unwrap();
        assert_eq!(first, json!({"policy_revision": 1}));
        assert_eq!(
            closed_policy_bundle_value(Some(&first), json!({"policy_revision": 2})).unwrap(),
            json!({"policy_revision": 2})
        );
        for (previous, payload) in [
            (None, json!({"policy_revision": 0})),
            (None, json!({"policy_revision": 2})),
            (Some(&first), json!({"policy_revision": 1})),
            (Some(&first), json!({"policy_revision": 3})),
            (None, json!({"policy_revision": 1, "join_policy": null})),
            (None, json!({"policy_revision": 1, "unknown": true})),
        ] {
            assert!(closed_policy_bundle_value(previous, payload).is_err());
        }
        assert_eq!(
            closed_join_rule_value(Some(&first), json!({"value": "invite"})).unwrap(),
            json!("invite")
        );
        for (policy, payload) in [
            (None, json!({"value": "invite"})),
            (Some(&first), json!({"value": "restricted"})),
            (Some(&first), json!({"value": "knock_restricted"})),
            (Some(&first), json!({"value": "invite", "reason": "extra"})),
            (Some(&first), json!({"value": "unknown"})),
        ] {
            assert!(closed_join_rule_value(policy, payload).is_err());
        }
    }

    #[test]
    fn discovery_tail_requires_closed_whole_value() {
        assert_eq!(
            closed_discovery_value(json!({"value":{"discoverability":"listed"}})).unwrap(),
            json!({"discoverability":"listed"})
        );
        for payload in [
            json!({"value":{"discoverability":"unknown"}}),
            json!({"value":{"discoverability":"listed","unknown":true}}),
            json!({"value":{"discoverability":"listed"},"reason":"extra"}),
        ] {
            assert!(closed_discovery_value(payload).is_err());
        }
    }

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

    fn set_row_value(row: &mut TypedCurrentResult, next: serde_json::Value) {
        let TypedCurrentResult::Value { value, .. } = row else {
            unreachable!()
        };
        *value = next;
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
        let TypedCurrentResult::Value { value, .. } = &mut bad_value else {
            unreachable!()
        };
        value.as_object_mut().unwrap().remove("schema");
        forged_rows.push(vec![bad_value, root.clone()]);
        let mut extra_member = row.clone();
        let TypedCurrentResult::Value { value, .. } = &mut extra_member else {
            unreachable!()
        };
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
        let TypedCurrentResult::Value { selector, .. } = &mut unsupported else {
            unreachable!()
        };
        *selector = arkret_wire::CurrentSelector::RealmPolicy;
        forged_rows.push(vec![unsupported, root.clone()]);
        let mut wrong_source = row.clone();
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut wrong_source
        else {
            unreachable!()
        };
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )
            .unwrap(),
        };
        forged_rows.push(vec![wrong_source, root.clone()]);
        let mut readable_revision = row.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut readable_revision else {
            unreachable!()
        };
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

        let path = std::env::temp_dir().join(format!(
            "inkson-signed-floor-product-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(&path);
        let verified = VerifiedAccountFrame {
            pages: Vec::new(),
            floor_current_rows: vec![(realm_id.clone(), installed_rows.clone())],
            ..Default::default()
        };
        let scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
        };
        let checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:signed-floor-baseline".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        let failed: Result<(), String> = store.verified_projection_transaction(|store| {
            verified.install_floor_current(store)?;
            store
                .save_account_checkpoint(&scope, checkpoint.clone())
                .map_err(|error| error.to_string())?;
            Err("bad later frame work".to_owned())
        });
        assert!(failed.is_err());
        assert!(store.realm_tree_projection(realm_id.as_str()).is_none());
        assert_eq!(store.load_account_checkpoint(&scope).unwrap(), None);
        store
            .verified_projection_transaction(|store| {
                verified.install_floor_current(store)?;
                store
                    .save_account_checkpoint(&scope, checkpoint.clone())
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        let projection = store.realm_tree_projection(realm_id.as_str()).unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<arkret_wire::TypedCurrentResult>>(
                projection["current"].clone()
            )
            .unwrap(),
            installed_rows
        );
        assert_eq!(
            store.load_account_checkpoint(&scope).unwrap(),
            Some(checkpoint)
        );
        let _ = std::fs::remove_file(path);
    }

    enum ByRefScript {
        Snapshot(Box<arkret_sdk::RealmStateSnapshot>),
        Problem(&'static str, u16),
    }

    /// The own Station's by-ref surface. Every other authority operation is
    /// outside this path and must not be reached.
    struct ByRefAuthority {
        script: ByRefScript,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl garth::AuthorityTransport for ByRefAuthority {
        async fn submit(
            &self,
            _request: &arkret_wire::AuthoritySubmitRequest,
            _options: &arkret_sdk::http_client::ClientRequestOptions,
        ) -> garth::Result<arkret_wire::AuthoritySubmitOutcome> {
            unreachable!("floor predecessor reads never submit")
        }

        async fn scan(
            &self,
            _request: &StreamScanRequest,
        ) -> garth::Result<arkret_sdk::StreamScanOutcome> {
            unreachable!("the fixture stages its verified scan directly")
        }

        async fn authority_bundle(
            &self,
            _request: &arkret_sdk::AuthorityBundleRequest,
        ) -> garth::Result<arkret_sdk::RealmAuthorityBundle> {
            unreachable!("the fixture installs its verified bundle directly")
        }

        async fn install_handoff(
            &self,
            _request: &arkret_wire::AuthorityHandoffRequest,
            _options: &arkret_sdk::http_client::ClientRequestOptions,
        ) -> garth::Result<arkret_wire::RealmAuthorityHandoff> {
            unreachable!("floor predecessor reads never install a handoff")
        }

        async fn exact_snapshot(
            &self,
            _realm_id: &arkret_sdk::RealmId,
            _snapshot_id: &arkret_sdk::RealmSnapshotId,
        ) -> garth::Result<arkret_sdk::RealmStateSnapshot> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match &self.script {
                ByRefScript::Snapshot(snapshot) => Ok((**snapshot).clone()),
                ByRefScript::Problem(code, status) => Err(garth::Error::Api {
                    status: *status,
                    error: Box::new(arkret_wire::Problem::new(*code, *status, "refused")),
                }),
            }
        }
    }

    fn by_ref_authority(script: ByRefScript) -> AuthorityClient<ByRefAuthority> {
        AuthorityClient::new(ByRefAuthority {
            script,
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
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

    #[tokio::test]
    async fn exact_by_ref_floor_snapshot_installs_with_account_checkpoint_or_fails_closed() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let genesis_value = collaboration_genesis(GENESIS_SALT);
        let (bundle, keys, items) =
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &crate::test_support::committed_event::FixtureStation::did_web(),
                realm_id.clone(),
                json!({"object": genesis_value}),
                vec![
                    (
                        "ak.realm.profile".to_owned(),
                        json!({"schema": "ak.schema.realm_profile.v1", "title": "By ref"}),
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
                ],
                "alice.example",
                DEVICE_ID,
            );
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let genesis_head = arkret_wire::CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            commit_id: bundle.genesis_commit.commit_id.clone(),
        };
        let genesis_revision = arkret_wire::CurrentRevision {
            commit_id: bundle.genesis_commit.commit_id.clone(),
            stream_position: 0,
        };
        let signed_rows = vec![
            TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                source_stream_ref: stream_ref.clone(),
                revision: genesis_revision.clone(),
                value: serde_json::to_value(genesis_value).unwrap(),
            },
            TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                source_stream_ref: stream_ref.clone(),
                revision: genesis_revision,
                value: json!({
                    "controller_actor_id": creator,
                    "controller_epoch": 0,
                    "authority_generation": 0,
                }),
            },
        ];
        let mut snapshot = arkret_sdk::RealmStateSnapshot {
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![genesis_head.clone()],
            current_state_entries: signed_rows.clone(),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: bundle.bundle_issued_at + chrono::Duration::seconds(5),
            signature: bundle.genesis_commit.signature.clone(),
        };
        crate::test_support::committed_event::sign_fixture_snapshot(&mut snapshot);
        let basis = arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis {
            anchor_kind: arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind::BeforeReadableFloor,
            anchor_position: Some(1),
            anchor_commit_ref: Some(items[0].commit.commit_id.clone()),
            snapshot_ref: snapshot.snapshot_id.clone(),
            governance_generation: 0,
            accepted_dependency_refs: None,
        };
        let floor = arkret_sdk::ReadableFloor {
            oldest_position: 1,
            floor_commit_id: items[0].commit.commit_id.clone(),
            floor_reason: arkret_sdk::ReadableFloorReason::RetentionPruned,
        };
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(10),
            request.nonce.clone(),
            chrono::Duration::minutes(5),
        )
        .unwrap();
        let mut replica = RealmReplica::new(realm_id.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        let advertised = station_describe(&[
            "ak.operation_bundle.station.http_core.v1",
            "ak.operation_bundle.station.snapshot_exact_read.v1",
        ]);

        // Availability is decided by the advertised bundle before any read.
        let unadvertised = by_ref_authority(ByRefScript::Snapshot(Box::new(snapshot.clone())));
        let refused = unadvertised
            .exact_snapshot(
                &station_describe(&["ak.operation_bundle.station.http_core.v1"]),
                &realm_id,
                &basis.snapshot_ref,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::NotAdvertised)
        ));
        assert_eq!(
            unadvertised
                .transport()
                .calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let unavailable = by_ref_authority(ByRefScript::Problem(
            "realm_state_snapshot_unavailable",
            503,
        ))
        .exact_snapshot(&advertised, &realm_id, &basis.snapshot_ref)
        .await
        .unwrap_err();
        assert!(matches!(
            unavailable,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::Unavailable)
        ));

        // A tampered by-ref object never becomes a verified predecessor.
        let mut tampered = snapshot.clone();
        tampered.signature.signed_digest =
            arkret_sdk::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let fetched_tampered = by_ref_authority(ByRefScript::Snapshot(Box::new(tampered)))
            .exact_snapshot(&advertised, &realm_id, &basis.snapshot_ref)
            .await
            .unwrap();
        let before = replica.clone();
        assert!(
            replica
                .install_verified_floor_predecessor(
                    &stream_ref,
                    &basis,
                    &floor,
                    &fetched_tampered,
                    &freshness,
                    &keys,
                )
                .is_err()
        );
        assert_eq!(replica, before);

        let fetched = by_ref_authority(ByRefScript::Snapshot(Box::new(snapshot.clone())))
            .exact_snapshot(&advertised, &realm_id, &basis.snapshot_ref)
            .await
            .unwrap();
        let floor_snapshot = replica
            .install_verified_floor_predecessor(
                &stream_ref,
                &basis,
                &floor,
                &fetched,
                &freshness,
                &keys,
            )
            .unwrap();
        assert_eq!(replica.verified_head(&stream_ref), Some(&genesis_head));
        let tail_request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(Some(0)),
            limit: 10,
        };
        let tail = arkret_sdk::StreamScanOutcome {
            committed_events: items
                .iter()
                .cloned()
                .map(CommittedEventView::Full)
                .collect(),
            readable_floor: Some(floor.clone()),
            truncated: false,
        };
        let mut pages = Vec::new();
        stage_verified_page(
            &mut replica,
            &tail_request,
            tail,
            &freshness,
            &keys,
            &mut pages,
        )
        .unwrap();
        let expected = fold_floor_current_tail(signed_rows.clone(), &pages).unwrap();
        assert_eq!(expected.len(), 8);
        let head = replica.verified_head(&stream_ref).cloned().unwrap();
        assert_eq!(head.stream_position, 6);
        let entry = arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
            current: Some(
                arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult {
                    realm_id: realm_id.clone(),
                    governance_generation: 0,
                    stream_heads: vec![head],
                    entries: expected.clone(),
                },
            ),
            ..Default::default()
        };
        let mut forged_entry = entry.clone();
        forged_entry.current.as_mut().unwrap().entries.pop();
        assert!(
            admit_single_stream_floor_current(
                &forged_entry,
                &realm_id,
                &bundle,
                floor_snapshot.clone(),
                &pages
            )
            .is_err()
        );
        let rows =
            admit_single_stream_floor_current(&entry, &realm_id, &bundle, floor_snapshot, &pages)
                .unwrap();
        assert_eq!(rows, expected);

        let path = std::env::temp_dir().join(format!(
            "inkson-by-ref-floor-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(&path);
        let verified = VerifiedAccountFrame {
            pages,
            floor_current_rows: vec![(realm_id.clone(), rows.clone())],
            ..Default::default()
        };
        let scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: creator.clone(),
            device_id: arkret_sdk::DeviceId::new(DEVICE_ID).unwrap(),
        };
        let checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:by-ref-floor".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        let failed: Result<(), String> = store.verified_projection_transaction(|store| {
            verified.install_floor_current(store)?;
            store
                .save_account_checkpoint(&scope, checkpoint.clone())
                .map_err(|error| error.to_string())?;
            Err("late frame rejection".to_owned())
        });
        assert!(failed.is_err());
        assert!(store.realm_tree_projection(realm_id.as_str()).is_none());
        assert_eq!(store.load_account_checkpoint(&scope).unwrap(), None);
        store
            .verified_projection_transaction(|store| {
                verified.install_floor_current(store)?;
                store
                    .save_account_checkpoint(&scope, checkpoint.clone())
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        let projection = store.realm_tree_projection(realm_id.as_str()).unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<TypedCurrentResult>>(projection["current"].clone())
                .unwrap(),
            rows
        );
        assert_eq!(projection["summary"]["title"], "By ref");
        assert_eq!(
            store.load_account_checkpoint(&scope).unwrap(),
            Some(checkpoint)
        );
        let _ = std::fs::remove_file(path);
    }

    /// The typed rows Soland's `/head` single-member bootstrap disclosure
    /// gate signs for this accepted prefix (`snapshot_disclosure_gate`): each
    /// row's source stream and revision are its covering Commit's.
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

    fn readable_tail_entries() -> Vec<(String, serde_json::Value)> {
        vec![
            (
                "ak.realm.profile".to_owned(),
                json!({"schema": "ak.schema.realm_profile.v1", "title": "After snapshot"}),
            ),
            (
                "ak.realm.policy_bundle".to_owned(),
                json!({"policy_revision": 2}),
            ),
        ]
    }

    /// One exact signed cut plus the verified readable tail after it.
    #[derive(Clone)]
    struct SignedCut {
        bundle: arkret_sdk::RealmAuthorityBundle,
        snapshot: arkret_sdk::RealmStateSnapshot,
        basis: arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
        floor: arkret_sdk::ReadableFloor,
        tail: Vec<arkret_sdk::CommittedEventFullView>,
    }

    impl SignedCut {
        /// Replace the signed body, re-sign it as `station` and re-address
        /// the window basis to the new exact snapshot.
        fn resigned(
            &self,
            station: &crate::test_support::committed_event::FixtureStation,
            edit: impl FnOnce(&mut arkret_sdk::RealmStateSnapshot),
        ) -> Self {
            let mut cut = self.clone();
            edit(&mut cut.snapshot);
            station.sign_snapshot(&mut cut.snapshot);
            cut.basis.snapshot_ref = cut.snapshot.snapshot_id.clone();
            cut
        }
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

    /// Verify the cut with Garth's historical Station keys, fold the tail,
    /// admit the Account current and commit product current plus Account
    /// checkpoint in one transaction. Any failure leaves the replica, the
    /// product current and the checkpoint unchanged.
    fn attempt_signed_cut(
        cut: &SignedCut,
        resolutions: &BTreeMap<
            arkret_sdk::DidCoreId,
            arkret_models_identity::AuthenticatedServiceResolution,
        >,
        title: &str,
    ) -> Result<Vec<TypedCurrentResult>, String> {
        let realm_id = cut.bundle.realm_id.clone();
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let tail = arkret_sdk::StreamScanOutcome {
            committed_events: cut
                .tail
                .iter()
                .cloned()
                .map(CommittedEventView::Full)
                .collect(),
            readable_floor: Some(cut.floor.clone()),
            truncated: false,
        };
        let path = std::env::temp_dir().join(format!(
            "inkson-signed-cut-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(&path);
        let scope = account_scope();
        let checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:signed-cut".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        let text = |error: garth::Error| error.to_string();
        let result = (|| -> Result<Vec<TypedCurrentResult>, String> {
            let keys = garth::historical_station_key_directory(
                &cut.bundle,
                Some(&tail),
                Some(&cut.snapshot),
                resolutions,
            )
            .map_err(text)?;
            let request = arkret_sdk::AuthorityBundleRequest {
                realm_id: realm_id.clone(),
                nonce: cut.bundle.current_assertion.nonce.clone(),
            };
            let freshness = arkret_identity::RealmAuthorityFreshness::new(
                crate::test_support::committed_event::fixture_time(60),
                request.nonce.clone(),
                chrono::Duration::minutes(5),
            )
            .unwrap();
            let mut replica = RealmReplica::new(realm_id.clone());
            replica
                .install_verified_authority(&request, cut.bundle.clone(), &freshness, &keys)
                .map_err(text)?;
            let before = replica.clone();
            let carrier = match replica.install_verified_floor_predecessor(
                &stream_ref,
                &cut.basis,
                &cut.floor,
                &cut.snapshot,
                &freshness,
                &keys,
            ) {
                Ok(carrier) => carrier,
                Err(error) => {
                    assert_eq!(replica, before);
                    return Err(error.to_string());
                }
            };
            let tail_request = StreamScanRequest {
                realm_id: realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction: arkret_sdk::StreamScanDirection::After(Some(
                    carrier.head().stream_position,
                )),
                limit: 10,
            };
            let mut pages = Vec::new();
            stage_verified_page(
                &mut replica,
                &tail_request,
                tail,
                &freshness,
                &keys,
                &mut pages,
            )
            .map_err(text)?;
            let scanned = pages
                .iter()
                .flat_map(|page| page.rows())
                .collect::<Vec<_>>();
            require_window_start_row(&cut.basis, &scanned).map_err(text)?;
            let expected =
                fold_floor_current_tail(carrier.rows().to_vec(), &pages).map_err(text)?;
            let entry =
                arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
                    current: Some(
                        arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult {
                            realm_id: realm_id.clone(),
                            governance_generation: 0,
                            stream_heads: vec![replica.verified_head(&stream_ref).cloned().unwrap()],
                            entries: expected,
                        },
                    ),
                    ..Default::default()
                };
            let rows =
                admit_single_stream_floor_current(&entry, &realm_id, &cut.bundle, carrier, &pages)
                    .map_err(text)?;
            let verified = VerifiedAccountFrame {
                pages,
                floor_current_rows: vec![(realm_id.clone(), rows.clone())],
                ..Default::default()
            };
            store.verified_projection_transaction(|store| {
                verified.install_floor_current(store)?;
                store
                    .save_account_checkpoint(&scope, checkpoint.clone())
                    .map_err(|error| error.to_string())
            })?;
            Ok(rows)
        })();
        match &result {
            Ok(rows) => {
                let projection = store.realm_tree_projection(realm_id.as_str()).unwrap();
                assert_eq!(
                    &serde_json::from_value::<Vec<TypedCurrentResult>>(
                        projection["current"].clone()
                    )
                    .unwrap(),
                    rows
                );
                assert_eq!(projection["summary"]["title"], title);
                assert_eq!(
                    store.load_account_checkpoint(&scope).unwrap(),
                    Some(checkpoint)
                );
            }
            Err(_) => {
                assert!(store.realm_tree_projection(realm_id.as_str()).is_none());
                assert_eq!(store.load_account_checkpoint(&scope).unwrap(), None);
            }
        }
        let _ = std::fs::remove_file(path);
        result
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

    #[test]
    fn soland_issued_bootstrap_snapshots_install_with_historical_keys_or_fail_closed() {
        use crate::test_support::committed_event::{FixtureStation, fixture_time};
        use arkret_models_collaboration::sync_frames::account_sync::{
            StreamWindowAnchorKind, StreamWindowStartBasis,
        };

        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let creator = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let inception_at = fixture_time(-1000);
        let station = FixtureStation::webvh(0x44, inception_at);
        let resolutions = BTreeMap::from([(
            station.service_id().clone(),
            station.resolution().unwrap().clone(),
        )]);
        let genesis_payload = json!({"object": collaboration_genesis(GENESIS_SALT)});
        let fixture = |entries| {
            crate::test_support::committed_event::verified_realm_fixture_signed_by(
                &station,
                realm_id.clone(),
                genesis_payload.clone(),
                entries,
                "alice.example",
                DEVICE_ID,
            )
        };

        // Seven-Commit bootstrap (8 rows) signed before a pruned readable
        // floor; the readable tail rewrites profile and policy.
        let (bundle, _, items) = fixture(
            ordinary_bootstrap_entries(&creator)
                .into_iter()
                .chain(readable_tail_entries())
                .collect(),
        );
        let mut floor_cut = SignedCut {
            snapshot: snapshot_at(&bundle, &items[..6], fixture_time(58)),
            basis: StreamWindowStartBasis {
                anchor_kind: StreamWindowAnchorKind::BeforeReadableFloor,
                anchor_position: Some(7),
                anchor_commit_ref: Some(items[6].commit.commit_id.clone()),
                snapshot_ref: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
                governance_generation: 0,
                accepted_dependency_refs: None,
            },
            floor: arkret_sdk::ReadableFloor {
                oldest_position: 7,
                floor_commit_id: items[6].commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::RetentionPruned,
            },
            tail: items[6..].to_vec(),
            bundle,
        };
        assert_eq!(floor_cut.snapshot.current_state_entries.len(), 8);
        floor_cut = floor_cut.resigned(&station, |_| {});
        let rows = attempt_signed_cut(&floor_cut, &resolutions, "After snapshot").unwrap();
        assert_eq!(rows.len(), 8);

        // Nine-Commit bootstrap + StrandCreate/default (10 rows) named by an
        // `after_committed_prefix` window of the creator, who may read from
        // position 0.
        let strand_prefix = ordinary_bootstrap_entries(&creator)
            .into_iter()
            .chain([("ak.strand.create".to_owned(), {
                let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
                    realm_id.clone(),
                    "General",
                    creator.clone(),
                );
                object.created_at = fixture_time(8);
                json!({"object": object})
            })])
            .collect::<Vec<_>>();
        let (_, _, strand_items) = fixture(strand_prefix.clone());
        let strand_id = arkret_sdk::StrandId::from_event_id(&strand_items[6].event.event_id);
        let (bundle, _, items) = fixture(
            strand_prefix
                .into_iter()
                .chain([(
                    "ak.realm.set_default_strand".to_owned(),
                    json!({"realm_id": REALM_ID, "strand_id": strand_id}),
                )])
                .chain(readable_tail_entries())
                .collect(),
        );
        assert_eq!(items[6].event.event_id, strand_items[6].event.event_id);
        let prefix_cut = SignedCut {
            snapshot: snapshot_at(&bundle, &items[..8], fixture_time(58)),
            basis: StreamWindowStartBasis {
                anchor_kind: StreamWindowAnchorKind::AfterCommittedPrefix,
                anchor_position: Some(8),
                anchor_commit_ref: Some(items[7].commit.commit_id.clone()),
                snapshot_ref: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
                governance_generation: 0,
                accepted_dependency_refs: None,
            },
            floor: arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            },
            tail: items[8..].to_vec(),
            bundle,
        }
        .resigned(&station, |_| {});
        assert_eq!(prefix_cut.snapshot.current_state_entries.len(), 10);
        let rows = attempt_signed_cut(&prefix_cut, &resolutions, "After snapshot").unwrap();
        assert_eq!(rows.len(), 10);
        assert!(rows.iter().any(|row| matches!(
            row,
            TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
                value,
                ..
            } if value == &json!({"default_strand_id": strand_id})
        )));
        // A prefix window whose head is already the stream head has an empty
        // tail and installs exactly the signed rows.
        let mut empty_tail = prefix_cut.clone();
        empty_tail.tail.clear();
        assert_eq!(
            attempt_signed_cut(&empty_tail, &resolutions, "Bootstrap").unwrap(),
            prefix_cut.snapshot.current_state_entries
        );

        let row_index = |cut: &SignedCut, wanted: arkret_wire::CurrentSelector| {
            cut.snapshot
                .current_state_entries
                .iter()
                .position(|row| matches!(row, TypedCurrentResult::Value { selector, .. } if *selector == wanted))
                .unwrap()
        };
        let profile = row_index(&prefix_cut, arkret_wire::CurrentSelector::RealmProfile);
        let strand = row_index(
            &prefix_cut,
            arkret_wire::CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
        );
        let member = row_index(
            &prefix_cut,
            arkret_wire::CurrentSelector::MemberState {
                actor_id: creator.clone(),
            },
        );
        let other = FixtureStation::webvh(0x45, inception_at);
        let both = BTreeMap::from([
            (
                station.service_id().clone(),
                station.resolution().unwrap().clone(),
            ),
            (
                other.service_id().clone(),
                other.resolution().unwrap().clone(),
            ),
        ]);
        let mut rejected: Vec<(&str, SignedCut, &BTreeMap<_, _>)> = Vec::new();
        // A row changed after signing no longer matches the signed body.
        let mut tampered = prefix_cut.clone();
        set_row_value(
            &mut tampered.snapshot.current_state_entries[profile],
            json!({"schema": "ak.schema.realm_profile.v1", "title": "Tampered"}),
        );
        rejected.push(("tampered row", tampered.clone(), &resolutions));
        // Re-addressing the tampered body does not make the old signature
        // cover it.
        let signature = tampered.snapshot.signature.clone();
        let mut readdressed = tampered.resigned(&station, |_| {});
        readdressed.snapshot.signature = signature;
        rejected.push(("tampered row with its own ID", readdressed, &resolutions));
        // A row whose source is another stream of the Realm.
        rejected.push((
            "wrong source stream",
            prefix_cut.resigned(&station, |snapshot| {
                let TypedCurrentResult::Value {
                    source_stream_ref, ..
                } = &mut snapshot.current_state_entries[profile]
                else {
                    unreachable!()
                };
                *source_stream_ref = CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: arkret_sdk::CircleId::from_event_id(&items[0].event.event_id),
                };
            }),
            &resolutions,
        ));
        // Another Station's key: absent from the historical directory, and
        // not the generation's governing Station even when resolvable.
        let wrong_key = prefix_cut.resigned(&other, |_| {});
        rejected.push(("unresolved wrong key", wrong_key.clone(), &resolutions));
        rejected.push(("wrong governing key", wrong_key, &both));
        // Signed before the Station's did:webvh inception.
        rejected.push((
            "signature before inception",
            prefix_cut.resigned(&station, |snapshot| {
                snapshot.created_at = inception_at - chrono::Duration::seconds(1);
            }),
            &resolutions,
        ));
        // Validly signed but outside the closed typed families.
        rejected.push((
            "extra profile member",
            prefix_cut.resigned(&station, |snapshot| {
                let TypedCurrentResult::Value { value, .. } =
                    &mut snapshot.current_state_entries[profile]
                else {
                    unreachable!()
                };
                value["extra"] = json!(true);
            }),
            &resolutions,
        ));
        rejected.push((
            "extra member state member",
            prefix_cut.resigned(&station, |snapshot| {
                set_row_value(
                    &mut snapshot.current_state_entries[member],
                    json!({"membership": "join", "role": "owner"}),
                );
            }),
            &resolutions,
        ));
        rejected.push((
            "unknown family",
            prefix_cut.resigned(&station, |snapshot| {
                let mut alias = snapshot.current_state_entries[profile].clone();
                let TypedCurrentResult::Value { selector, .. } = &mut alias else {
                    unreachable!()
                };
                *selector = arkret_wire::CurrentSelector::RealmAlias;
                snapshot.current_state_entries.push(alias);
            }),
            &resolutions,
        ));
        rejected.push((
            "history floor mismatch",
            prefix_cut.resigned(&station, |snapshot| {
                snapshot.retention_and_history_floor.history_access =
                    arkret_wire::HistoryAccess::AllHistoryForCurrentMembers;
            }),
            &resolutions,
        ));
        rejected.push((
            "dangling default Strand",
            prefix_cut.resigned(&station, |snapshot| {
                snapshot.current_state_entries.remove(strand);
            }),
            &resolutions,
        ));
        rejected.push((
            "genesis differs from verified genesis Event",
            prefix_cut.resigned(&station, |snapshot| {
                let genesis = row_index(&prefix_cut, arkret_wire::CurrentSelector::RealmGenesis);
                set_row_value(
                    &mut snapshot.current_state_entries[genesis],
                    serde_json::to_value(collaboration_genesis(
                        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
                    ))
                    .unwrap(),
                );
            }),
            &resolutions,
        ));
        // Window bases that do not name the signed head exactly.
        let mut early_anchor = prefix_cut.clone();
        early_anchor.basis.anchor_position = Some(7);
        early_anchor.basis.anchor_commit_ref = Some(items[6].commit.commit_id.clone());
        rejected.push(("prefix anchor before head", early_anchor, &resolutions));
        let mut unreadable_prefix = prefix_cut.clone();
        unreadable_prefix.floor = arkret_sdk::ReadableFloor {
            oldest_position: 9,
            floor_commit_id: items[8].commit.commit_id.clone(),
            floor_reason: arkret_sdk::ReadableFloorReason::RetentionPruned,
        };
        rejected.push(("prefix above floor", unreadable_prefix, &resolutions));
        let mut floor_as_prefix = floor_cut.clone();
        floor_as_prefix.basis.anchor_kind = StreamWindowAnchorKind::AfterCommittedPrefix;
        rejected.push(("floor basis as prefix", floor_as_prefix, &resolutions));
        for (case, cut, keys) in rejected {
            assert!(
                attempt_signed_cut(&cut, keys, "After snapshot").is_err(),
                "{case} must fail closed"
            );
        }
    }

    #[test]
    fn preview_and_genesis_windows_never_reach_the_snapshot_installer() {
        use arkret_models_collaboration::sync_frames::account_sync::{
            RealmStreamWindow, StreamWindowAnchorKind, StreamWindowStartBasis,
        };
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let basis = StreamWindowStartBasis {
            anchor_kind: StreamWindowAnchorKind::AfterCommittedPrefix,
            anchor_position: Some(8),
            anchor_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([8; 32])),
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
        genesis.window_start_basis = Some(StreamWindowStartBasis {
            anchor_kind: StreamWindowAnchorKind::StreamGenesis,
            anchor_position: None,
            anchor_commit_ref: None,
            ..basis.clone()
        });
        assert_eq!(snapshot_window_basis(&genesis), None);
        let mut floor_basis = basis.clone();
        floor_basis.anchor_kind = StreamWindowAnchorKind::BeforeReadableFloor;
        let mut floor_window = window;
        floor_window.window_start_basis = Some(floor_basis.clone());
        assert_eq!(snapshot_window_basis(&floor_window), Some(&floor_basis));
        // An empty prefix tail is legal only for `after_committed_prefix`.
        assert!(require_window_start_row(&basis, &[]).is_ok());
        assert!(require_window_start_row(&floor_basis, &[]).is_err());
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
            chrono::Duration::minutes(5),
        )
        .unwrap();
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
            freshness.max_bundle_age,
        )
        .unwrap();
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
        assert!(fold_floor_current_tail(Vec::new(), &pages).is_err());
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
        forged_window.window_start_basis = Some(
            arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis {
                anchor_kind: arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind::BeforeReadableFloor,
                anchor_position: Some(1),
                anchor_commit_ref: Some(items[0].commit.commit_id.clone()),
                snapshot_ref: arkret_sdk::RealmSnapshotId::from_digest([0x55; 32]),
                governance_generation: 0,
                accepted_dependency_refs: None,
            },
        );
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
                truncated: false,
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
            _request: &arkret_wire::AuthorityHandoffRequest,
            _options: &arkret_sdk::http_client::ClientRequestOptions,
        ) -> garth::Result<arkret_wire::RealmAuthorityHandoff> {
            unreachable!("frame verification never installs a handoff")
        }

        async fn exact_snapshot(
            &self,
            _realm_id: &arkret_sdk::RealmId,
            _snapshot_id: &arkret_sdk::RealmSnapshotId,
        ) -> garth::Result<arkret_sdk::RealmStateSnapshot> {
            unreachable!("a preview or full-history window names no snapshot")
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

        // 1. Unresolved preview: the sibling Realm verifies and installs; the
        //    preview Realm's rows stay display rows, with no current, no
        //    verified index and no verified stream checkpoint.
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

        // 2. A contradicting row in a preview window still fails closed once
        //    the replay can reach genesis.
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

        // 3. Backfill: the verified replay from genesis covers the preview
        //    window and its head, so the stream becomes exact.
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

        // 4. A non-preview window whose readable history starts above genesis
        //    and names no signed basis still fails closed.
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
}
