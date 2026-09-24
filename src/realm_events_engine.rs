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
    let keys =
        crate::identity::realm_authority_keys::fetch_verified_key_directory(http, &bundle, None)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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
    .await?;
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
        crate::identity::realm_authority_keys::fetch_verified_key_directory(http, bundle, None)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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

async fn verified_stream_pages<T: garth::AuthorityTransport>(
    authority: &AuthorityClient<T>,
    http: &arkret_sdk::http_client::Client,
    replica: &mut RealmReplica,
    bundle: &arkret_sdk::RealmAuthorityBundle,
    freshness: &arkret_identity::RealmAuthorityFreshness,
    realm_id: &arkret_sdk::RealmId,
    stream_ref: &CommitStreamRef,
    floor_basis: Option<
        &arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
    >,
) -> garth::Result<(
    Vec<garth::VerifiedScanPage>,
    Option<garth::VerifiedFloorSnapshot>,
)> {
    // A full-history stream starts at genesis. A limited Account window may
    // start only from the exact signed head named by its basis; the first
    // readable page must prove the matching floor Commit and predecessor.
    let snapshot = if let Some(basis) = floor_basis {
        let snapshot = http
            .realm_state_snapshot_by_ref(realm_id, &basis.snapshot_ref)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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
                let snapshot_keys =
                    crate::identity::realm_authority_keys::fetch_verified_key_directory(
                        http,
                        bundle,
                        Some(&outcome),
                    )
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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
        } else {
            require_genesis_readable_floor(&outcome)?;
        }
        let truncated = outcome.truncated;
        let keys = crate::identity::realm_authority_keys::fetch_verified_key_directory(
            http,
            bundle,
            Some(&outcome),
        )
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
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
    Ok((pages, verified_floor_snapshot))
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

pub(crate) struct VerifiedAccountFrame {
    pages: Vec<garth::VerifiedScanPage>,
    floor_current_rows: Option<(arkret_sdk::RealmId, Vec<arkret_wire::TypedCurrentResult>)>,
}

impl VerifiedAccountFrame {
    pub fn pages(&self) -> &[garth::VerifiedScanPage] {
        &self.pages
    }

    /// Called inside the Account frame's durable projection transaction.
    /// Only `verify_account_frame_commits` can populate the private signed
    /// current carrier; a shape-only frame never reaches this installer.
    pub fn install_floor_current(
        &self,
        store: &mut crate::state::LocalStateStore,
    ) -> Result<(), String> {
        if let Some((realm_id, rows)) = &self.floor_current_rows {
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

/// The first product installer is intentionally narrow: the two complete
/// collaboration-genesis rows from a signed one-stream cut. The only readable tail
/// is an audit fact whose registered reducer writes no typed current result.
fn admit_single_stream_floor_current(
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    realm_id: &arkret_sdk::RealmId,
    snapshot: garth::VerifiedFloorSnapshot,
    pages: &[garth::VerifiedScanPage],
) -> garth::Result<Vec<arkret_wire::TypedCurrentResult>> {
    validate_floor_no_current_tail(pages)?;
    let current = entry.current.as_ref().ok_or_else(|| {
        garth::Error::Protocol("floor snapshot has no exact Account current cut".to_owned())
    })?;
    let signed_head = snapshot.head().clone();
    let rows = snapshot.into_rows();
    validate_floor_current_rows(realm_id, current, &rows, &signed_head)?;
    Ok(rows)
}

fn validate_floor_no_current_tail(pages: &[garth::VerifiedScanPage]) -> garth::Result<()> {
    for page in pages {
        for committed in page.rows() {
            let arkret_wire::CommittedEventView::Full(full) = committed else {
                return Err(garth::Error::Protocol(
                    "floor current tail requires a disclosed audit Event".to_owned(),
                ));
            };
            if full.event.kind != arkret_wire::EventKind::AuditAccessed {
                return Err(garth::Error::Protocol(
                    "floor current tail has an unsupported typed reducer".to_owned(),
                ));
            }
            let audit: arkret_models_collaboration::events_payloads::audit::AuditAccessedPayload =
                serde_json::from_value(
                    serde_json::to_value(&full.event.payload)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            if audit.writer_actor_id != full.event.actor_id {
                return Err(garth::Error::Protocol(
                    "audit tail writer differs from signed Event actor".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_floor_current_rows(
    realm_id: &arkret_sdk::RealmId,
    current: &arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult,
    rows: &[arkret_wire::TypedCurrentResult],
    signed_head: &arkret_wire::CommitStreamHead,
) -> garth::Result<()> {
    if current.realm_id != *realm_id || current.entries != rows {
        return Err(garth::Error::Protocol(
            "Account current rows differ from signed floor snapshot".to_owned(),
        ));
    }
    if rows.len() != 2 || signed_head.stream_position != 0 {
        return Err(garth::Error::Protocol(
            "floor snapshot current families have no complete product installer".to_owned(),
        ));
    }
    let mut genesis = false;
    let mut root = false;
    for row in rows {
        let arkret_wire::TypedCurrentResult::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            return Err(garth::Error::Protocol(
                "unsupported signed current row".to_owned(),
            ));
        };
        if source_stream_ref != &signed_head.stream_ref
            || revision.stream_position != signed_head.stream_position
            || revision.commit_id != signed_head.commit_id
        {
            return Err(garth::Error::Protocol(
                "genesis current revision differs from signed predecessor".to_owned(),
            ));
        }
        match selector {
            arkret_wire::CurrentSelector::RealmGenesis if !genesis => {
                let value: arkret_sdk::RealmGenesis = serde_json::from_value(value.clone())
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                value
                    .validate()
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                if value.purpose != arkret_sdk::RealmPurpose::Collaboration {
                    return Err(garth::Error::Protocol(
                        "floor genesis installer requires collaboration Realm".to_owned(),
                    ));
                }
                genesis = true;
            }
            arkret_wire::CurrentSelector::RealmAuthorityRoot if !root => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct AuthorityRoot {
                    controller_actor_id: arkret_sdk::ActorId,
                    controller_epoch: u64,
                    authority_generation: u64,
                }
                let value: AuthorityRoot = serde_json::from_value(value.clone())
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                if value.controller_epoch != 0 || value.authority_generation != 0 {
                    return Err(garth::Error::Protocol(
                        "genesis authority root is not generation zero".to_owned(),
                    ));
                }
                let _ = value.controller_actor_id;
                root = true;
            }
            _ => {
                return Err(garth::Error::Protocol(
                    "floor snapshot current family has no complete product installer".to_owned(),
                ));
            }
        }
    }
    if genesis && root {
        Ok(())
    } else {
        Err(garth::Error::Protocol(
            "floor snapshot omits collaboration genesis current".to_owned(),
        ))
    }
}

/// The account aggregate's committed rows are claims until an independent
/// nonce-bound stream scan returns the same exact rows. Full history can be
/// projected; limited windows pass the exact signed predecessor and tail gate
/// but remain fail closed until snapshot current rows can be installed.
pub(crate) async fn verify_account_frame_commits(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    let mut verified = VerifiedAccountFrame {
        pages: Vec::new(),
        floor_current_rows: None,
    };
    let Some(realms) = frame.realms.as_ref() else {
        return Ok(verified);
    };
    let authority = AuthorityClient::new(http.clone());
    for (realm, entry) in &realms.entries {
        if let Some(windows) = entry.streams.as_ref() {
            for window in windows {
                if window.preview_only == Some(true) {
                    continue;
                }
                let Some(basis) = window.window_start_basis.as_ref() else {
                    continue;
                };
                if basis.anchor_kind
                    != arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind::BeforeReadableFloor
                {
                    continue;
                }
                if realms.entries.len() != 1 || windows.len() != 1 {
                    return Err(garth::Error::Protocol(
                        "floor current projection requires one exact Realm stream".to_owned(),
                    ));
                }
                let realm_id = arkret_sdk::RealmId::new(realm.clone())
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                let (bundle, freshness, mut replica) =
                    fresh_verified_realm(&authority, http, &realm_id).await?;
                let (pages, floor_snapshot) = verified_stream_pages(
                    &authority,
                    http,
                    &mut replica,
                    &bundle,
                    &freshness,
                    &realm_id,
                    &window.stream_ref,
                    Some(basis),
                )
                .await?;
                let scanned = pages
                    .iter()
                    .flat_map(|page| page.rows())
                    .collect::<Vec<_>>();
                if scanned.first().is_none_or(|row| {
                    Some(row.commit().stream_position) != basis.anchor_position
                        || Some(&row.commit().commit_id) != basis.anchor_commit_ref.as_ref()
                }) {
                    return Err(garth::Error::Protocol(
                        "readable floor Commit lacks a verified full Event".to_owned(),
                    ));
                }
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
                let rows =
                    admit_single_stream_floor_current(entry, &realm_id, floor_snapshot, &pages)?;
                verified.pages = pages;
                verified.floor_current_rows = Some((realm_id, rows));
                return Ok(verified);
            }
        }
        require_genesis_window_basis(entry)?;
        let Some(rows) = entry
            .committed_events
            .as_ref()
            .filter(|rows| !rows.is_empty())
        else {
            continue;
        };
        let realm_id = arkret_sdk::RealmId::new(realm.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let (bundle, freshness, mut replica) =
            fresh_verified_realm(&authority, http, &realm_id).await?;
        let mut by_stream: BTreeMap<CommitStreamRef, Vec<&CommittedEventView>> = BTreeMap::new();
        let mut seen_rows = BTreeSet::new();
        for row in rows {
            if row.commit().realm_id != realm_id {
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
        for (stream_ref, claimed_rows) in by_stream {
            let (pages, _) = verified_stream_pages(
                &authority,
                http,
                &mut replica,
                &bundle,
                &freshness,
                &realm_id,
                &stream_ref,
                None,
            )
            .await?;
            let scanned = pages
                .iter()
                .flat_map(|page| page.rows())
                .collect::<Vec<_>>();
            require_exact_claimed_rows(&claimed_rows, &scanned)?;
            let window = entry
                .streams
                .as_ref()
                .and_then(|windows| {
                    windows
                        .iter()
                        .find(|window| window.stream_ref == stream_ref)
                })
                .ok_or_else(|| {
                    garth::Error::Protocol(
                        "account frame Commit has no exact stream window head".to_owned(),
                    )
                })?;
            if window.preview_only == Some(true) {
                return Err(garth::Error::Protocol(
                    "account frame stream window is preview only".to_owned(),
                ));
            }
            require_exact_window_head(window, &scanned)?;
            verified.pages.extend(pages);
        }
        let final_freshness = arkret_identity::RealmAuthorityFreshness::new(
            chrono::Utc::now(),
            freshness.expected_nonce.clone(),
            freshness.max_bundle_age,
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let keys = crate::identity::realm_authority_keys::fetch_verified_key_directory(
            http, &bundle, None,
        )
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        arkret_identity::verify_realm_authority_bundle(&bundle, &final_freshness, &keys)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    }
    Ok(verified)
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
    use garth::CursorScope;
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const STRAND_ID: &str = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    const ACTOR_ID: &str = "ak:did_core:web:alice.example";
    const ACTOR_CONTROLLER: &str = "did:web:alice.example";
    const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000003";

    #[test]
    fn signed_floor_genesis_rows_require_exact_account_cut_and_closed_value() {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let genesis = arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::Collaboration,
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_sdk::SecurityClass::Standard,
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            arkret_sdk::JoinRule::Invite,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::Listed,
            None,
            None,
        )
        .unwrap();
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let commit_id = arkret_wire::RealmCommitId::from_digest([0x31; 32]);
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            commit_id: commit_id.clone(),
        };
        let row = arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmGenesis,
            source_stream_ref: stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: commit_id.clone(),
                stream_position: 0,
            },
            value: serde_json::to_value(genesis).unwrap(),
        };
        let root = arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
            source_stream_ref: stream_ref,
            revision: arkret_wire::CurrentRevision {
                commit_id,
                stream_position: 0,
            },
            value: json!({
                "controller_actor_id": arkret_sdk::ActorId::account(
                    arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new(ACTOR_ID).unwrap(),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    )
                ),
                "controller_epoch": 0,
                "authority_generation": 0,
            }),
        };
        let current =
            arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult {
                realm_id: realm_id.clone(),
                governance_generation: 0,
                stream_heads: vec![head.clone()],
                entries: vec![row.clone(), root.clone()],
            };
        let installed_rows = current.entries.clone();
        assert!(
            validate_floor_current_rows(&realm_id, &current, &[row.clone(), root.clone()], &head)
                .is_ok()
        );

        let mut wrong_cut = current.clone();
        wrong_cut.entries.clear();
        assert!(
            validate_floor_current_rows(&realm_id, &wrong_cut, &[row.clone(), root.clone()], &head)
                .is_err()
        );
        let mut bad_value = row.clone();
        let arkret_wire::TypedCurrentResult::Value { value, .. } = &mut bad_value else {
            unreachable!()
        };
        value.as_object_mut().unwrap().remove("schema");
        let mut matching_bad_cut = current.clone();
        matching_bad_cut.entries = vec![bad_value.clone(), root.clone()];
        assert!(
            validate_floor_current_rows(
                &realm_id,
                &matching_bad_cut,
                &[bad_value, root.clone()],
                &head
            )
            .is_err()
        );
        let mut unsupported = row.clone();
        let arkret_wire::TypedCurrentResult::Value { selector, .. } = &mut unsupported else {
            unreachable!()
        };
        *selector = arkret_wire::CurrentSelector::RealmPolicy;
        let mut matching_unsupported_cut = current.clone();
        matching_unsupported_cut.entries = vec![unsupported.clone(), root.clone()];
        assert!(
            validate_floor_current_rows(
                &realm_id,
                &matching_unsupported_cut,
                &[unsupported, root.clone()],
                &head
            )
            .is_err()
        );
        let mut wrong_source = row.clone();
        let arkret_wire::TypedCurrentResult::Value {
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
        let mut matching_wrong_source = current;
        matching_wrong_source.entries = vec![wrong_source.clone(), root.clone()];
        assert!(
            validate_floor_current_rows(
                &realm_id,
                &matching_wrong_source,
                &[wrong_source, root.clone()],
                &head
            )
            .is_err()
        );
        let mut readable_revision = row;
        let arkret_wire::TypedCurrentResult::Value { revision, .. } = &mut readable_revision else {
            unreachable!()
        };
        revision.stream_position = 1;
        let mut matching_readable_revision = matching_wrong_source;
        matching_readable_revision.entries = vec![readable_revision.clone(), root.clone()];
        assert!(
            validate_floor_current_rows(
                &realm_id,
                &matching_readable_revision,
                &[readable_revision, root],
                &head,
            )
            .is_err()
        );

        let path = std::env::temp_dir().join(format!(
            "inkson-signed-floor-product-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(&path);
        let verified = VerifiedAccountFrame {
            pages: Vec::new(),
            floor_current_rows: Some((realm_id.clone(), installed_rows.clone())),
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
        assert!(validate_floor_no_current_tail(&pages).is_err());
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
}
