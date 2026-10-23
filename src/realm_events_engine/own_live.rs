//! Ordinary live projection consumes bound own-Station originals. Subscription
//! frames are hints; only the independent admitted stream scan moves a cursor.
use arkret_sdk::http_client::own_station_results::OwnStationResultClient;
use garth::history_recovery::replay_with_admitted_replica;
use garth::own_station_results::{OwnStationReplica, OwnStationScanPage};

use super::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "own_live/sidecar_tests.rs"]
mod sidecar_tests;

const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_HINT_BATCH: usize = 64;
const MAX_COVERED_HINTS: usize = 2048;

type HintOriginals = BTreeMap<(CommitStreamRef, u64), [u8; 32]>;

#[derive(Default)]
struct HintAdmission {
    originals: HintOriginals,
    generation: Option<u64>,
}

struct InstalledLiveCut {
    changed: usize,
    current_changed: bool,
    generation: u64,
}

fn content_hint_digest(view: &CommittedEventView) -> garth::Result<Option<[u8; 32]>> {
    if !matches!(view, CommittedEventView::Full(full) if matches!(full.event.kind,
        arkret_sdk::EventKind::MessageCreate | arkret_sdk::EventKind::MessageRevise))
    {
        return Ok(None);
    }
    Ok(Some(arkret_sdk::canonical::sha256_bytes(
        arkret_sdk::canonical::canonical_json_bytes(view).map_err(protocol)?,
    )))
}

fn admitted_hint_originals(pages: &[OwnStationScanPage]) -> garth::Result<HintOriginals> {
    let mut originals = HintOriginals::new();
    for page in pages {
        for row in page.rows()? {
            if let Some(digest) = content_hint_digest(row)? {
                originals.insert(
                    (
                        row.commit().stream_ref.clone(),
                        row.commit().stream_position,
                    ),
                    digest,
                );
                if originals.len() > MAX_COVERED_HINTS {
                    originals.pop_first();
                }
            }
        }
    }
    Ok(originals)
}

/// An optimization proof for exact content wakeups, not a reusable allow ticket.
/// Its bound response keeps the original provider and authority lease alive.
struct HintCoverage {
    snapshot: CreatorOwnSnapshot,
    generation: u64,
    list_fence: crate::state::RealmListReadFence,
    originals: HintOriginals,
}

impl HintCoverage {
    fn covers(
        &self,
        client: &OwnStationResultClient,
        hints: &HintBatch,
        projector: &RealmIngestProjector,
        current: &OwnStationReplica,
    ) -> garth::Result<bool> {
        client.check_session()?;
        let snapshot = self.snapshot.value()?;
        if client.session()? != self.snapshot.session()
            || hints.revalidate
            || hints.originals.is_empty()
            || hints
                .originals
                .iter()
                .any(|(key, digest)| self.originals.get(key) != Some(digest))
            || current.snapshot() != Some(snapshot)
        {
            return Ok(false);
        }
        projector
            .state_store
            .read(|store| -> Result<bool, String> {
                if store.active_authority().as_ref() != Some(self.snapshot.session().account_id())
                    || store.current_generation() != self.generation
                    || store.realm_list_read_fence(snapshot.realm_id.as_str()) != self.list_fence
                    || store.current_product_cut_generation(snapshot.realm_id.as_str())
                        != Some(self.generation)
                {
                    return Ok(false);
                }
                for stream in &hints.streams {
                    let Some(head) = snapshot
                        .visible_stream_heads
                        .iter()
                        .find(|head| &head.stream_ref == stream)
                    else {
                        return Ok(false);
                    };
                    if current.head(stream) != Some(head)
                        || store.verified_commit_stream_cursor(stream)?.as_ref() != Some(head)
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .map_err(protocol)
    }
}

type HintFrame = arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrame;

/// Disposable wakeups, never historical or authorization evidence. Keep only
/// bounded coordinates so a burst cannot retain dozens of large Event bodies.
#[derive(Default)]
struct HintBatch {
    positions: BTreeMap<(CommitStreamRef, u64), arkret_sdk::RealmCommitId>,
    streams: BTreeSet<CommitStreamRef>,
    discover: bool,
    cursor: Option<String>,
    originals: HintOriginals,
    revalidate: bool,
}

impl HintBatch {
    fn push(&mut self, realm: &arkret_sdk::RealmId, frame: &HintFrame) -> garth::Result<bool> {
        let Some(view) = frame.committed_event() else {
            return Ok(false);
        };
        let commit = view.commit();
        if commit.stream_ref.realm_id() != realm {
            return Err(protocol("subscription names another Realm"));
        }
        let key = (commit.stream_ref.clone(), commit.stream_position);
        if self
            .positions
            .insert(key, commit.commit_id.clone())
            .is_some_and(|prior| prior != commit.commit_id)
        {
            return Err(protocol(
                "subscription hints conflict at one stream position",
            ));
        }
        self.streams.insert(commit.stream_ref.clone());
        if let Some(digest) = content_hint_digest(view)? {
            if self
                .originals
                .insert((commit.stream_ref.clone(), commit.stream_position), digest)
                .is_some_and(|prior| prior != digest)
            {
                self.revalidate = true;
            }
        } else {
            self.revalidate = true;
        }
        self.discover |= matches!(view, CommittedEventView::Full(full) if matches!(full.event.kind,
            arkret_sdk::EventKind::CircleCreate | arkret_sdk::EventKind::CircleMemberState | arkret_sdk::EventKind::MemberState | arkret_sdk::EventKind::InviteAccept | arkret_sdk::EventKind::SidecarCreate | arkret_sdk::EventKind::SidecarContextAttach));
        if let Some(cursor) = &frame.cursor {
            self.cursor = Some(cursor.clone());
        }
        Ok(true)
    }
}

fn collect_ready_hints<F: Fn() -> bool>(
    realm: &arkret_sdk::RealmId,
    mut frame: HintFrame,
    stream: &mut crate::transport::websocket_rail::CommittedRailSource,
    resume: &mut SubscriptionState,
    is_active: &F,
) -> garth::Result<(HintBatch, Option<HintFrame>, bool)> {
    use futures_util::FutureExt;
    let mut hints = HintBatch::default();
    for index in 0..MAX_HINT_BATCH {
        if !hints.push(realm, &frame)? {
            return Ok((hints, Some(frame), false));
        }
        // Do not wait for another hint or consume beyond the batch budget.
        // The outer loop checks cancellation and the independent discovery timer.
        if index + 1 == MAX_HINT_BATCH || !is_active() {
            break;
        }
        match stream.next_frame().now_or_never() {
            Some(result) => match resume.hint_read(result)? {
                Some(next) => frame = next,
                None => return Ok((hints, None, true)),
            },
            None => break,
        }
    }
    Ok((hints, None, false))
}

#[derive(Default)]
pub(super) struct SubscriptionState {
    cursor: Option<String>,
}

impl SubscriptionState {
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    fn hint_read<T>(&mut self, result: garth::Result<T>) -> garth::Result<T> {
        if result
            .as_ref()
            .is_err_and(|error| error.is_invalid_cursor())
        {
            // Discovery has its own disposable enumeration cursor. Only a
            // failure on the hint surface may reset this subscription handle.
            self.reset();
        }
        result
    }
}

pub(super) async fn subscription<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    ctx: &RealmEventsEngineContext,
    is_active: &F,
    current: &mut OwnStationReplica,
    resume: &mut SubscriptionState,
) -> garth::Result<()> {
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind as Kind;
    client.check_session()?;
    let opened = crate::transport::websocket_rail::CommittedRailSource::open(
        http,
        &ctx.websocket_rail,
        realm.clone(),
        resume.cursor.clone(),
    )
    .await;
    let mut stream = resume.hint_read(opened)?;
    client.check_session()?;
    // The bounded hint subscription cannot notify every discovered stream.
    // Re-enumerate at rollover and while idle or busy so the first 64 cannot
    // permanently starve another stream. Only verified scans move checkpoints.
    follow_once(client, http, realm, projector, ctx, is_active, current).await?;
    let mut coverage = None;
    let mut rediscovery = Box::pin(crate::runtime_helpers::sleep_for(DISCOVERY_INTERVAL));
    while is_active() {
        client.check_session()?;
        let frame = loop {
            use futures_util::future::{Either, select};
            match select(
                &mut rediscovery,
                Box::pin(select(
                    Box::pin(stream.next_frame()),
                    Box::pin(crate::runtime_helpers::sleep_for(SUBSCRIBE_CANCEL_POLL)),
                )),
            )
            .await
            {
                Either::Left(_) => {
                    coverage = None;
                    follow_once(client, http, realm, projector, ctx, is_active, current).await?;
                    rediscovery = Box::pin(crate::runtime_helpers::sleep_for(DISCOVERY_INTERVAL));
                }
                Either::Right((Either::Left((frame, _)), _)) => break resume.hint_read(frame)?,
                Either::Right(_) if !is_active() => return Ok(()),
                Either::Right(_) => {
                    client.check_session()?;
                    if projector
                        .state_store
                        .read(|s| s.has_pending_sidecar_history(realm.as_str()))
                    {
                        coverage = None;
                        refresh_sidecars(client, http, realm, projector, is_active, current)
                            .await?;
                    }
                }
            }
        };
        client.check_session()?;
        let Some(mut frame) = frame else {
            return Ok(());
        };
        if frame.committed_event().is_some() {
            let (hints, control, ended) =
                collect_ready_hints(realm, frame, &mut stream, resume, is_active)?;
            drain_hints(
                client,
                http,
                realm,
                &hints,
                projector,
                is_active,
                current,
                &mut coverage,
            )
            .await?;
            if !is_active() {
                return Ok(());
            }
            if hints.discover {
                coverage = None;
                follow_once(client, http, realm, projector, ctx, is_active, current).await?;
            }
            client.check_session()?;
            if let Some(cursor) = hints.cursor {
                resume.cursor = Some(cursor);
            }
            if ended {
                return Ok(());
            }
            let Some(next) = control else {
                continue;
            };
            frame = next;
        }
        // A control frame is always an invalidation barrier, even when it
        // carries no cursor. It is never absorbed by content deduplication.
        coverage = None;
        match frame.kind {
            Kind::ResyncRequired => {
                resume.reset();
                return Ok(());
            }
            Kind::Unauthorized => {
                return Err(garth::Error::Api {
                    status: 401,
                    error: Box::new(arkret_wire::Problem::new(
                        "unauthenticated",
                        401,
                        "subscription authorization ended",
                    )),
                });
            }
            Kind::Quarantined => return Err(protocol("subscription stream is quarantined")),
            _ => {}
        }
        if !is_active() {
            return Ok(());
        }
        client.check_session()?;
        let terminal = frame.is_terminal();
        if let Some(cursor) = frame.cursor {
            resume.cursor = Some(cursor);
        }
        if let Some(delay) = frame.reconnect_after_ms {
            crate::runtime_helpers::sleep_for(Duration::from_millis(delay)).await;
        }
        if terminal {
            return Ok(());
        }
    }
    Ok(())
}

async fn follow_once<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    _ctx: &RealmEventsEngineContext,
    is_active: &F,
    current: &mut OwnStationReplica,
) -> garth::Result<()> {
    client.check_session()?;
    let mut streams = garth::discover_realm_streams(client, realm).await?;
    let list_fence = projector
        .state_store
        .read(|store| store.realm_list_read_fence(realm.as_str()));
    let snapshot = client.snapshot_head(realm).await?;
    let heads = snapshot
        .value()?
        .visible_stream_heads
        .iter()
        .map(|head| (&head.stream_ref, head))
        .collect::<BTreeMap<_, _>>();
    // Prioritize the selected Realm's live tail; this is scheduling only,
    // never an ordering or position comparison between independent streams.
    // New/changed streams precede rechecking already admitted heads so an
    // outside-page update need not wait behind a full unchanged prefix.
    // Bound-cut and admitted-original requirements remain independent per stream.
    streams.sort_by_key(|row| {
        (
            !matches!(row.stream_ref, CommitStreamRef::Realm { .. }),
            heads
                .get(&row.stream_ref)
                .is_some_and(|head| current.head(&row.stream_ref) == Some(*head)),
        )
    });
    let private = streams
        .iter()
        .any(|s| matches!(s.stream_ref, CommitStreamRef::Sidecar { .. }));
    let mut installed_generation = None;
    for row in streams {
        if !is_active() {
            return Ok(());
        }
        if matches!(row.stream_ref, CommitStreamRef::Sidecar { .. }) {
            continue;
        }
        if let Some(generation) = installed_generation
            && let Some(expected) = heads.get(&row.stream_ref).copied()
            && current.head(&row.stream_ref) == Some(expected)
        {
            // The complete current cut has already committed in this pass.
            // Reuse only an original admitted in this live session AND its
            // exact durable checkpoint. Bare coordinates after a restart,
            // a changed head or a concurrent current transaction still drain.
            let retained = projector
                .state_store
                .read(|store| -> Result<bool, String> {
                    if store.active_authority().as_ref() != Some(snapshot.session().account_id()) {
                        return Err(
                            "live current account changed before retained-head reuse".into()
                        );
                    }
                    Ok(store.current_generation() == generation
                        && store
                            .verified_commit_stream_cursor(&row.stream_ref)?
                            .as_ref()
                            == Some(expected))
                })
                .map_err(protocol)?;
            if retained {
                client.check_session()?;
                snapshot.value()?;
                continue;
            }
        }
        let admitted = drain_from_snapshot(
            client,
            http,
            realm,
            &row.stream_ref,
            &snapshot,
            projector,
            is_active,
            current,
            Some(&list_fence),
        )
        .await?;
        installed_generation = admitted.generation;
    }
    if private && is_active() {
        refresh_sidecars_from_snapshot(
            client,
            http,
            realm,
            projector,
            is_active,
            current,
            &snapshot,
            &list_fence,
        )
        .await?;
    }
    Ok(())
}

async fn drain_hints<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    hints: &HintBatch,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
    coverage: &mut Option<HintCoverage>,
) -> garth::Result<()> {
    client.check_session()?;
    if !is_active() || hints.streams.is_empty() {
        return Ok(());
    }
    if let Some(proof) = coverage.as_ref()
        && proof.covers(client, hints, projector, current)?
    {
        return Ok(());
    }
    *coverage = None;
    let list_fence = projector
        .state_store
        .read(|store| store.realm_list_read_fence(realm.as_str()));
    let snapshot = client.snapshot_head(realm).await?;
    for ((stream, position), commit_id) in &hints.positions {
        let head = snapshot
            .value()?
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream)
            .ok_or_else(|| protocol("current cut omits a hinted stream"))?;
        if head.stream_position < *position
            || (head.stream_position == *position && &head.commit_id != commit_id)
        {
            return Err(protocol(
                "current cut does not cover the hinted stream head",
            ));
        }
    }
    let mut originals = HintOriginals::new();
    let mut installed_generation = None;
    for stream in &hints.streams {
        if !is_active() {
            return Ok(());
        }
        if matches!(stream, CommitStreamRef::Sidecar { .. }) {
            continue;
        }
        let admitted = drain_from_snapshot(
            client,
            http,
            realm,
            stream,
            &snapshot,
            projector,
            is_active,
            current,
            Some(&list_fence),
        )
        .await?;
        installed_generation = admitted.generation;
        for (key, digest) in admitted.originals {
            originals.insert(key, digest);
            if originals.len() > MAX_COVERED_HINTS {
                originals.pop_first();
            }
        }
    }
    if hints
        .streams
        .iter()
        .any(|stream| matches!(stream, CommitStreamRef::Sidecar { .. }))
        && is_active()
    {
        let private_originals = refresh_sidecars_from_snapshot(
            client,
            http,
            realm,
            projector,
            is_active,
            current,
            &snapshot,
            &list_fence,
        )
        .await?;
        installed_generation = private_originals.generation;
        originals.extend(private_originals.originals);
    }
    if let Some(generation) = installed_generation
        && is_active()
        && projector
            .state_store
            .read(|store| store.current_generation())
            == generation
    {
        client.check_session()?;
        snapshot.value()?;
        while originals.len() > MAX_COVERED_HINTS {
            originals.pop_first();
        }
        *coverage = Some(HintCoverage {
            snapshot,
            generation,
            list_fence,
            originals,
        });
    }
    Ok(())
}

#[cfg(test)]
async fn replay(
    client: &OwnStationResultClient,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    snapshot: &CreatorOwnSnapshot,
    saved: Option<&arkret_sdk::CommitStreamHead>,
) -> garth::Result<(OwnStationReplica, Vec<OwnStationScanPage>)> {
    replay_with_admitted_replica(
        client,
        realm,
        stream,
        snapshot,
        saved,
        OwnStationReplica::new(realm.clone()),
    )
    .await
}

pub(super) async fn drain<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
) -> garth::Result<()> {
    let list_fence = projector
        .state_store
        .read(|store| store.realm_list_read_fence(realm.as_str()));
    let snapshot = client.snapshot_head(realm).await?;
    drain_from_snapshot(
        client,
        http,
        realm,
        stream,
        &snapshot,
        projector,
        is_active,
        current,
        Some(&list_fence),
    )
    .await
    .map(|_| ())
}

async fn drain_from_snapshot<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    snapshot: &CreatorOwnSnapshot,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
    list_fence: Option<&crate::state::RealmListReadFence>,
) -> garth::Result<HintAdmission> {
    current.install_bound_snapshot(snapshot)?;
    own_station::validate_current_product(snapshot.value()?, realm)?;
    let saved = projector
        .state_store
        .read(|s| s.verified_commit_stream_cursor(stream))
        .map_err(protocol)?;
    let (replica, pages) = replay_with_admitted_replica(
        client,
        realm,
        stream,
        snapshot,
        saved.as_ref(),
        current.clone(),
    )
    .await?;
    let mut rows = Vec::new();
    let originals = admitted_hint_originals(&pages)?;
    for page in &pages {
        rows.extend(page.rows()?.iter().cloned());
    }
    let batch = committed_views_to_client_events(realm, rows)?;
    if !is_active() {
        return Ok(HintAdmission::default());
    }
    client.check_session()?;
    let installed = install_live_cut(
        client,
        snapshot,
        realm,
        std::slice::from_ref(stream),
        projector,
        &replica,
        &pages,
        &batch,
        is_active,
        list_fence,
        false,
    )
    .await?;
    let changed = installed.changed;
    let evidence = resolve_stream_agent_keys(http, &projector.state_store, changed > 0).await?;
    client.check_session()?;
    if !is_active() {
        return Ok(HintAdmission::default());
    }
    let finals = projector.state_store.read(|store| {
        batch
            .iter()
            .filter_map(|e| accepted_direct_message_final(e, projector.digest_suite, store))
            .collect::<Vec<_>>()
    });
    if let Some(mut hub) = projector.message_stream_hub {
        for (event, sender) in finals {
            hub.bind_verified_final(event, &sender)
                .map_err(|e| protocol(e.to_string()))?;
        }
    }
    if changed > 0 || installed.current_changed || evidence || batch.iter().any(|e| matches!(e, ClientEvent::Event(e) if e.kind == arkret_sdk::EventKind::AgentInteractionSet)) {
        projector.realm_live_epoch.update(|v| *v = v.wrapping_add(1));
    }
    // Adopt only the candidate whose history and current pointer committed.
    // Cloning preserves independently admitted heads for every other stream.
    client.check_session()?;
    if is_active() {
        *current = replica;
    }
    Ok(HintAdmission {
        originals,
        generation: Some(installed.generation),
    })
}

/// Install real live history and its current original at one durable pointer;
/// the Account cursor is deliberately outside this independent transaction.
#[cfg(test)]
async fn install_live_current_snapshot<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    snapshot: &arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::RealmId,
        arkret_sdk::RealmStateSnapshot,
    >,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    projector: &RealmIngestProjector,
    replica: &OwnStationReplica,
    pages: &[OwnStationScanPage],
    batch: &[ClientEvent],
    is_active: &F,
    list_fence: Option<&crate::state::RealmListReadFence>,
) -> garth::Result<(usize, bool)> {
    let installed = install_live_cut(
        client,
        snapshot,
        realm,
        std::slice::from_ref(stream),
        projector,
        replica,
        pages,
        batch,
        is_active,
        list_fence,
        false,
    )
    .await?;
    if installed.current_changed {
        projector
            .realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
    Ok((installed.changed, installed.current_changed))
}

async fn install_live_cut<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    snapshot: &CreatorOwnSnapshot,
    realm: &arkret_sdk::RealmId,
    streams: &[CommitStreamRef],
    projector: &RealmIngestProjector,
    replica: &OwnStationReplica,
    pages: &[OwnStationScanPage],
    batch: &[ClientEvent],
    is_active: &F,
    list_fence: Option<&crate::state::RealmListReadFence>,
    complete_sidecars: bool,
) -> garth::Result<InstalledLiveCut> {
    let account = snapshot.session().account_id().clone();
    let source_guard = || -> anyhow::Result<()> {
        anyhow::ensure!(is_active(), "live current route ended");
        snapshot.value()?;
        Ok(())
    };
    let guard = || -> anyhow::Result<()> {
        source_guard()?;
        projector
            .state_store
            .read(|store| store.require_realm_list_read_fence(realm.as_str(), list_fence))?;
        anyhow::ensure!(
            projector.state_store.read(|store| store.active_authority()) == Some(account.clone()),
            "live current account changed"
        );
        Ok(())
    };
    guard().map_err(crate::state::current_index::current_stage_error)?;
    let location = projector
        .state_store
        .read(|store| store.current_index_location());
    let index = crate::state::CurrentIndex::open_committed(&account, location, || {
        guard()?;
        Ok(projector
            .state_store
            .read(|store| store.current_generation()))
    })
    .await
    .map_err(crate::state::current_index::current_stage_error)?;
    guard().map_err(crate::state::current_index::current_stage_error)?;
    let generation = projector
        .state_store
        .read(|store| store.current_generation());
    if index.is_poisoned() {
        confirm_live_current_pointer(&index, &projector.state_store, &account, generation)
            .await
            .map_err(crate::state::current_index::current_stage_error)?;
        guard().map_err(crate::state::current_index::current_stage_error)?;
    }
    let mut stage = index
        .stage_committed_own_station_snapshot_with_history(
            || {
                guard()?;
                Ok(projector
                    .state_store
                    .read(|store| store.current_generation()))
            },
            snapshot,
            pages,
            &guard,
        )
        .await
        .map_err(crate::state::current_index::current_stage_error)?;
    let generation = stage.previous_generation();
    let published_generation = stage.generation();
    guard().map_err(crate::state::current_index::current_stage_error)?;
    let current_changed = stage.changed();
    projector
        .state_store
        .write(|store| store.require_sidecar_current_not_superseded(snapshot.value()?))
        .map_err(crate::state::current_index::current_stage_error)?;
    let transaction = projector.state_store.write(|store| {
        store.verified_projection_transaction(|store| {
            source_guard().map_err(|error| error.to_string())?;
            store
                .require_realm_list_read_fence(realm.as_str(), list_fence)
                .map_err(|error| error.to_string())?;
            if store.active_authority() != Some(account.clone()) {
                return Err("live current account changed before transaction".into());
            }
            let mut changed = 0;
            for page in pages {
                changed += store.ingest_verified_message_history(page)?;
                crate::identity::agent_signer_evidence::index_verified_committed_page(store, page)?;
            }
            changed += ingest_realm_batch(store, &projector.realm_id, batch);
            if complete_sidecars {
                store
                    .sidecar_history_at_snapshot(
                        snapshot.value().map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
            }
            for stream in streams {
                store.stage_own_station_commit_stream_checkpoint(client, replica, stream, pages)?;
            }
            store.install_own_station_sidecar_current(snapshot)?;
            snapshot.value().map_err(|error| error.to_string())?;
            if !is_active() || store.active_authority() != Some(account.clone()) {
                return Err("live current account or route changed before commit".into());
            }
            stage.arm_account_commit();
            store.set_current_generation(stage.generation());
            Ok(changed)
        })
    });
    let changed = match transaction {
        Ok(changed) => changed,
        Err(error) => {
            rollback_live_current_pointer(&index, &projector.state_store, &account, generation)
                .await
                .map_err(crate::state::current_index::current_stage_error)?;
            return Err(protocol(error));
        }
    };
    let durable = match projector
        .state_store
        .read(|store| store.begin_durable_flush())
    {
        Ok(barrier) => barrier.wait().await,
        Err(error) => Err(error),
    };
    if let Err(error) = durable {
        rollback_live_current_pointer(&index, &projector.state_store, &account, generation)
            .await
            .map_err(crate::state::current_index::current_stage_error)?;
        return Err(protocol(error));
    }
    // A late response from an ended provider may not publish a shared pointer.
    // A mere navigation change can retain the already durable original while
    // its view publication is suppressed by the route guard below.
    if let Err(error) = snapshot.value() {
        rollback_live_current_pointer(&index, &projector.state_store, &account, generation)
            .await
            .map_err(crate::state::current_index::current_stage_error)?;
        return Err(protocol(error));
    }
    if projector.state_store.read(|store| store.active_authority()) != Some(account.clone()) {
        index.poison();
        return Err(protocol("live current account ended before publication"));
    }
    stage.finish();
    guard().map_err(crate::state::current_index::current_stage_error)?;
    crate::sync_engine::publish_current_product_view(
        &index,
        &projector.state_store,
        &account,
        realm.as_str(),
        &source_guard,
    )
    .await
    .map_err(crate::state::current_index::current_stage_error)?;
    guard().map_err(crate::state::current_index::current_stage_error)?;
    Ok(InstalledLiveCut {
        changed,
        current_changed,
        generation: published_generation,
    })
}

/// Confirm only the pointer belonging to this store. A poisoned independent
/// live transaction can recover without waiting for an Account frame.
async fn confirm_live_current_pointer(
    index: &crate::state::CurrentIndex,
    store: &crate::runtime::input::StateStoreHandle,
    account: &arkret_sdk::AccountId,
    generation: u64,
) -> anyhow::Result<()> {
    let barrier = store.read(|store| -> anyhow::Result<_> {
        anyhow::ensure!(
            store.active_authority() == Some(account.clone())
                && store.current_generation() == generation,
            "live current store changed before durability confirmation"
        );
        store.begin_durable_flush()
    })?;
    barrier.wait().await?;
    store.read(|store| -> anyhow::Result<()> {
        anyhow::ensure!(
            store.active_authority() == Some(account.clone())
                && store.current_generation() == generation,
            "live current store changed during durability confirmation"
        );
        index.confirm_durable_pointer(generation)
    })
}

async fn rollback_live_current_pointer(
    index: &crate::state::CurrentIndex,
    store: &crate::runtime::input::StateStoreHandle,
    account: &arkret_sdk::AccountId,
    generation: u64,
) -> anyhow::Result<()> {
    index.poison();
    store.write(|store| -> anyhow::Result<()> {
        anyhow::ensure!(
            store.active_authority() == Some(account.clone()),
            "live current store changed during rollback"
        );
        // Accepted history remains an independently authenticated prefix. Only
        // the failed current pointer and its derived view are withdrawn; no
        // Account cursor or demand baseline is fabricated or advanced.
        store.batch(|store| {
            store.set_current_generation(generation);
            store.clear_current_product_view();
        });
        Ok(())
    })?;
    confirm_live_current_pointer(index, store, account, generation).await
}

pub(super) async fn refresh_sidecars<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
) -> garth::Result<()> {
    let list_fence = projector
        .state_store
        .read(|store| store.realm_list_read_fence(realm.as_str()));
    let snapshot = client.snapshot_head(realm).await?;
    refresh_sidecars_from_snapshot(
        client,
        http,
        realm,
        projector,
        is_active,
        current,
        &snapshot,
        &list_fence,
    )
    .await
    .map(|_| ())
}

async fn refresh_sidecars_from_snapshot<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
    snapshot: &CreatorOwnSnapshot,
    list_fence: &crate::state::RealmListReadFence,
) -> garth::Result<HintAdmission> {
    let mut candidate = current.clone();
    candidate.install_bound_snapshot(snapshot)?;
    own_station::validate_current_product(snapshot.value()?, realm)?;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    let frozen = snapshot.value()?;
    if frozen
        .retention_and_history_floor
        .stream_floors
        .iter()
        .any(|floor| {
            matches!(floor.stream_ref, CommitStreamRef::Sidecar { .. }) && floor.oldest_position > 0
        })
    {
        projector
            .state_store
            .write(|store| -> anyhow::Result<()> {
                anyhow::ensure!(is_active(), "private route ended before floor invalidation");
                client.check_session()?;
                snapshot.value()?;
                store.require_realm_list_read_fence(realm.as_str(), Some(list_fence))?;
                anyhow::ensure!(
                    store.active_authority().as_ref() == Some(snapshot.session().account_id()),
                    "private account changed before floor invalidation"
                );
                store.require_sidecar_current_not_superseded(snapshot.value()?)?;
                // Withdrawal is fail-closed even when the subsequent flush fails.
                // It never publishes a partial new cut or advances a checkpoint.
                store.invalidate_sidecar_current(Some(realm.as_str()));
                Ok(())
            })
            .map_err(protocol)?;
        projector
            .realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
        let barrier = projector
            .state_store
            .read(|store| store.begin_durable_flush())
            .map_err(protocol)?;
        barrier.wait().await.map_err(protocol)?;
        return Err(protocol(
            "complete Sidecar history is below its readable floor",
        ));
    }
    let mut streams = Vec::new();
    for head in &frozen.visible_stream_heads {
        if !matches!(head.stream_ref, CommitStreamRef::Sidecar { .. }) {
            continue;
        }
        if !is_active() {
            return Ok(HintAdmission::default());
        }
        streams.push(head.stream_ref.clone());
        let admitted = candidate
            .complete_sidecar_head(client, &head.stream_ref)?
            .cloned();
        let retained = admitted.as_ref().is_some_and(|prefix| {
            projector
                .state_store
                .read(|store| store.has_complete_sidecar_prefix(frozen, prefix))
        });
        if retained && admitted.as_ref() == Some(head) {
            continue;
        }
        let (next, recovered) = candidate
            .replay_sidecar_history(client, snapshot, &head.stream_ref, retained)
            .await?;
        candidate = next;
        for page in recovered {
            retained_bytes = retained_bytes
                .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
                .ok_or_else(|| protocol("Sidecar current capacity overflow"))?;
            if retained_bytes > MAX_REPLAY_BYTES {
                return Err(protocol(
                    "Sidecar current exceeds bounded candidate capacity",
                ));
            }
            pages.push(page);
        }
    }
    if !is_active() {
        return Ok(HintAdmission::default());
    }
    client.check_session()?;
    let installed = install_live_cut(
        client,
        snapshot,
        realm,
        &streams,
        projector,
        &candidate,
        &pages,
        &[],
        is_active,
        Some(list_fence),
        true,
    )
    .await?;
    let changed = installed.changed;
    client.check_session()?;
    if !is_active() {
        return Ok(HintAdmission::default());
    }
    *current = candidate;
    let evidence = resolve_stream_agent_keys(http, &projector.state_store, changed > 0).await?;
    client.check_session()?;
    if !is_active() {
        return Ok(HintAdmission::default());
    }
    if changed > 0 || installed.current_changed || evidence {
        projector
            .realm_live_epoch
            .update(|v| *v = v.wrapping_add(1));
    }
    Ok(HintAdmission {
        originals: admitted_hint_originals(&pages)?,
        generation: Some(installed.generation),
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use arkret_sdk::http_client::own_station_results::{
        OwnStationSessionSnapshot, OwnStationSessionSource,
    };
    use garth::history_recovery::replay_with_admitted_replica;

    use super::*;

    fn hint(row: CommittedEventView, cursor: usize) -> HintFrame {
        serde_json::from_value(serde_json::json!({
            "kind": "committed_event", "realm_id": row.commit().realm_id,
            "cursor": format!("ak:cursor:batch{cursor}"), "payload": row
        }))
        .unwrap()
    }

    fn queued_hints(
        realm: &arkret_sdk::RealmId,
        frames: Vec<HintFrame>,
    ) -> crate::transport::websocket_rail::CommittedRailSource {
        use arkret_models_collaboration::sync_frames::websocket::*;
        use arkret_wire::websocket_binding::WebSocketOperationId;
        let connection = SharedConnection::new();
        connection.set_ready(true);
        let channel = connection
            .open(WebSocketOpenParameters::Events(
                WebSocketEventsOpenParameters {
                    realm_ids: Some(vec![realm.clone()]),
                    actor_ids: None,
                    after: None,
                    catchup: None,
                },
            ))
            .unwrap()
            .unwrap();
        let Some(WebSocketClientFrame::Open { channel_id, .. }) = connection.next_command() else {
            panic!("expected the real channel open");
        };
        connection
            .publish(WebSocketServerFrame::Opened {
                channel_id: channel_id.clone(),
                operation_id: WebSocketOperationId::CommittedEventStreamSubscribe,
            })
            .unwrap();
        for frame in frames {
            let frame = if frame.committed_event().is_some() {
                WebSocketServerFrame::Data {
                    channel_id: channel_id.clone(),
                    payload: WebSocketDataPayload::Events(Box::new(frame)),
                }
            } else {
                WebSocketServerFrame::ChannelControl {
                    frame_scope: WebSocketChannelScope::Channel,
                    channel_id: channel_id.clone(),
                    payload: WebSocketChannelControlPayload::Events(Box::new(frame)),
                }
            };
            connection.publish(frame).unwrap();
        }
        crate::transport::websocket_rail::CommittedRailSource::Socket {
            channel,
            trace: arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventStreamTrace::new(false, None),
        }
    }

    #[tokio::test]
    async fn twenty_queued_hints_use_one_snapshot_and_one_real_scan() {
        let (rows, snapshot) = burst_fixture();
        let realm = snapshot.realm_id.clone();
        let frames = rows
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, row)| hint(row, i))
            .collect();
        let mut stream = queued_hints(&realm, frames);
        let first = stream.next_frame().await.unwrap().unwrap();
        let mut resume = SubscriptionState::default();
        let (hints, control, ended) =
            collect_ready_hints(&realm, first, &mut stream, &mut resume, &|| true).unwrap();
        assert_eq!(hints.positions.len(), 20);
        assert_eq!(hints.streams.len(), 1);
        assert_eq!(hints.cursor.as_deref(), Some("ak:cursor:batch19"));
        assert!(control.is_none() && !ended);
        assert!(
            resume.cursor.is_none(),
            "collecting hints must not acknowledge them"
        );

        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("burst.json"));
        local.switch_active_account(&account).unwrap();
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &realm);
        // This real HTTP server accepts exactly one snapshot and one scan.
        // A third request fails instead of silently supplying a cached result.
        let (client, _, server) = http(vec![
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!({"committed_events": rows, "readable_floor": {
                "oldest_position": 0, "floor_commit_id": rows[0].commit().commit_id,
                "floor_reason": "stream_start"}, "truncated": false}),
        ]);
        let mut current = OwnStationReplica::new(realm.clone());
        drain_hints(
            &client,
            &client.http_client().unwrap(),
            &realm,
            &hints,
            &projector,
            &|| true,
            &mut current,
            &mut None,
        )
        .await
        .unwrap();
        server.join().unwrap();
        let head = &snapshot.visible_stream_heads[0];
        assert_eq!(current.head(&head.stream_ref), Some(head));
        assert_eq!(
            store
                .lock()
                .unwrap()
                .verified_commit_stream_cursor(&head.stream_ref)
                .unwrap()
                .as_ref(),
            Some(head)
        );
    }

    fn burst_fixture() -> (Vec<CommittedEventView>, arkret_sdk::RealmStateSnapshot) {
        let (bundle, _, items) = crate::test_support::committed_event::verified_realm_fixture_as(
            withheld(0, None).commit().realm_id.clone(),
            (1..20).map(|number| (
                arkret_sdk::EventKind::RealmProfile.as_str().to_owned(),
                serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":format!("Profile {number}")}),
            )).collect(),
            "alice.example", "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let rows = std::iter::once(bundle.genesis_commit.clone())
            .chain(items.iter().map(|item| item.commit.clone()))
            .map(|commit| {
                serde_json::from_value(serde_json::json!({
                    "commit":commit,"event_disclosure":{"status":"withheld"}
                }))
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut snapshot = frozen(&rows);
        let origin = &bundle.genesis_commit;
        let latest = items.last().unwrap();
        for (selector, commit, value) in [
            (
                arkret_sdk::CurrentSelector::RealmGenesis,
                origin,
                serde_json::to_value(&bundle.genesis_event.payload).unwrap()["object"].clone(),
            ),
            (
                arkret_sdk::CurrentSelector::RealmAuthorityRoot,
                origin,
                serde_json::json!({
                    "controller_actor_id":bundle.genesis_event.actor_id,"controller_epoch":0,
                    "authority_generation":0,"authority_event_ref":bundle.realm_id.event_id()
                }),
            ),
            (
                arkret_sdk::CurrentSelector::RealmProfile,
                &latest.commit,
                serde_json::to_value(&latest.event.payload).unwrap(),
            ),
        ] {
            snapshot
                .current_state_entries
                .push(arkret_sdk::TypedCurrentRow::Value {
                    selector,
                    source_stream_ref: commit.stream_ref.clone(),
                    revision: arkret_sdk::CurrentRevision {
                        commit_id: commit.commit_id.clone(),
                        stream_position: commit.stream_position,
                    },
                    value,
                });
        }
        seal_current_snapshot(&mut snapshot);
        (rows, snapshot)
    }

    pub(super) fn content_burst_fixture() -> (
        Vec<CommittedEventView>,
        arkret_sdk::RealmStateSnapshot,
        serde_json::Value,
    ) {
        use crate::test_support::committed_event::{
            FixtureStation, fixture_time, verified_realm_fixture_as,
            verified_realm_fixture_from_genesis,
        };
        let station = FixtureStation::did_web();
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let (origin, ..) = verified_realm_fixture_as(
            withheld(0, None).commit().realm_id.clone(),
            vec![],
            "alice.example",
            device,
        );
        let mut strand = arkret_models_collaboration::objects::strand::Strand::new_create(
            origin.realm_id.clone(),
            "Content fixture",
            origin.genesis_event.actor_id.clone(),
        );
        strand.created_at = fixture_time(2);
        strand.tracks.clear();
        strand.tracks.insert(
            "discussion".into(),
            arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
        );
        let entry = (
            "ak.strand.create".to_owned(),
            serde_json::json!({"object":strand}),
        );
        let (_, _, first) = verified_realm_fixture_from_genesis(
            &station,
            origin.genesis_event.clone(),
            vec![entry.clone()],
            "alice.example",
            device,
        );
        let strand_id = arkret_sdk::StrandId::from_event_id(&first[0].event.event_id);
        let mut entries = vec![entry];
        for number in 0..20 {
            entries.push((
                "ak.message.create".to_owned(),
                serde_json::json!({
                    "strand_id":strand_id,"track_name":"discussion",
                    "content":{"kind":"ak.content.text","body":format!("Content {number}")}
                }),
            ));
        }
        let (bundle, _, mut items) = verified_realm_fixture_from_genesis(
            &station,
            origin.genesis_event,
            entries,
            "alice.example",
            device,
        );
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            arkret_sdk::DidUrl::new(format!("did:web:alice.example#{device}")).unwrap(),
        );
        let key = arkret_models_identity::ResolvedSignerKey {
            public_key_b64u: arkret_sdk::Base64UrlString::new(
                arkret_sdk::canonical::base64url_encode(signer.verifying_key().as_bytes()),
            )
            .unwrap(),
            authorization_ref: arkret_sdk::CommittedEventRef {
                event_id: bundle.genesis_event.event_id.clone(),
                commit_id: bundle.genesis_commit.commit_id.clone(),
                stream_ref: bundle.genesis_commit.stream_ref.clone(),
                stream_position: 0,
            },
            revision: arkret_sdk::CurrentRevision {
                commit_id: bundle.genesis_commit.commit_id.clone(),
                stream_position: 0,
            },
            governance_generation: 0,
        };
        let mut previous = bundle.genesis_commit.commit_id.clone();
        let mut rows = vec![serde_json::from_value(serde_json::json!({"commit":bundle.genesis_commit,"event_disclosure":{"status":"withheld"}})).unwrap()];
        for item in &mut items {
            item.commit.previous_commit_ref = Some(previous);
            if item.event.kind == arkret_sdk::EventKind::MessageCreate {
                let fact = arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact {
                    event_id: item.event.event_id.clone(), actor: item.event.actual_signer().clone(),
                    device_id: item.event.account_device_producer().unwrap().unwrap().device_id,
                    verification_method: item.event.producer_proof.as_ref().unwrap().verification_method.clone(),
                    key: key.clone(), accepted_at: fixture_time(1),
                };
                item.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
            }
            item.commit = station.seal_commit(item.commit.clone());
            previous = item.commit.commit_id.clone();
            rows.push(if item.event.kind == arkret_sdk::EventKind::MessageCreate {
                CommittedEventView::Full(item.clone())
            } else {
                serde_json::from_value(serde_json::json!({"commit":item.commit,"event_disclosure":{"status":"withheld"}})).unwrap()
            });
        }
        let mut snapshot = frozen(&rows);
        snapshot.current_state_entries =
            super::super::tests::coland_bootstrap_rows(&bundle, &items);
        seal_current_snapshot(&mut snapshot);
        (rows, snapshot, serde_json::to_value(key).unwrap())
    }

    #[tokio::test]
    async fn twenty_separate_batches_reuse_only_durably_admitted_content_at_the_same_cut() {
        let (rows, snapshot, key) = content_burst_fixture();
        let realm = snapshot.realm_id.clone();
        let mut bodies = vec![
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!({
                "committed_events":rows,"readable_floor":{"oldest_position":0,
                "floor_commit_id":rows[0].commit().commit_id,"floor_reason":"stream_start"},"truncated":false
            }),
        ];
        bodies.extend((0..20).map(|_| serde_json::json!({"__signer_key":key})));
        let (client, source, server) = http(bodies);
        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local = crate::state::LocalStateStore::with_path(
            directory.path().join("separate-batches.json"),
        );
        local.switch_active_account(&account).unwrap();
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &realm);
        let mut current = OwnStationReplica::new(realm.clone());
        let mut coverage = None;
        for (number, row) in rows.iter().skip(2).enumerate() {
            let mut hints = HintBatch::default();
            hints.push(&realm, &hint(row.clone(), number)).unwrap();
            drain_hints(
                &client,
                &client.http_client().unwrap(),
                &realm,
                &hints,
                &projector,
                &|| true,
                &mut current,
                &mut coverage,
            )
            .await
            .unwrap();
        }
        server.join().unwrap();
        let proof = coverage.as_ref().unwrap();
        assert_eq!(proof.originals.len(), 20);
        let mut repeated = HintBatch::default();
        repeated.push(&realm, &hint(rows[2].clone(), 20)).unwrap();
        assert!(
            proof
                .covers(&client, &repeated, &projector, &current)
                .unwrap()
        );
        let mut undisclosed = HintBatch::default();
        undisclosed.push(&realm, &hint(serde_json::from_value(serde_json::json!({"commit":rows[2].commit(),"event_disclosure":{"status":"withheld"}})).unwrap(), 20)).unwrap();
        assert!(
            !proof
                .covers(&client, &undisclosed, &projector, &current)
                .unwrap()
        );
        let generation = store.lock().unwrap().current_generation();
        store.lock().unwrap().set_current_generation(generation + 1);
        assert!(
            !proof
                .covers(&client, &repeated, &projector, &current)
                .unwrap()
        );
        store.lock().unwrap().set_current_generation(generation);
        let old = source.0.lock().unwrap().clone();
        *source.0.lock().unwrap() = OwnStationSessionSnapshot::new(
            old.binding().clone(),
            old.account_id().clone(),
            old.account_id().station_id.clone(),
            old.grant_id().clone(),
            old.epoch() + 1,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        assert!(
            proof
                .covers(&client, &repeated, &projector, &current)
                .is_err()
        );
    }

    #[tokio::test]
    async fn hint_coverage_never_adopts_a_concurrent_generation_after_publication() {
        let (rows, snapshot, key) = content_burst_fixture();
        let realm = snapshot.realm_id.clone();
        let mut bodies = vec![
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!({
                "committed_events":rows,"readable_floor":{"oldest_position":0,
                "floor_commit_id":rows[0].commit().commit_id,"floor_reason":"stream_start"},"truncated":false
            }),
        ];
        bodies.extend((0..20).map(|_| serde_json::json!({"__signer_key":key})));
        let (client, _, server) = http(bodies);
        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("concurrent-cut.json"));
        local.switch_active_account(&account).unwrap();
        let store = Arc::new(Mutex::new(local));
        let mut projector = test_projector(store.clone(), &realm);
        let writer = store.clone();
        projector.realm_live_epoch = crate::runtime::input::ValueCell::new(
            || 0,
            |_| {},
            move |update| {
                let mut epoch = 0;
                update(&mut epoch);
                let mut store = writer.lock().unwrap();
                let next = store.current_generation() + 1;
                store.set_current_generation(next);
            },
        );
        let mut hints = HintBatch::default();
        hints.push(&realm, &hint(rows[2].clone(), 0)).unwrap();
        let mut replica = OwnStationReplica::new(realm.clone());
        let mut coverage = None;
        drain_hints(
            &client,
            &client.http_client().unwrap(),
            &realm,
            &hints,
            &projector,
            &|| true,
            &mut replica,
            &mut coverage,
        )
        .await
        .unwrap();
        server.join().unwrap();
        assert!(store.lock().unwrap().current_generation() > 1);
        assert!(
            coverage.is_none(),
            "a later store generation is not this install's publication proof"
        );
    }

    #[tokio::test]
    async fn hint_batch_does_not_scan_or_advance_when_snapshot_does_not_cover_hint() {
        let first = withheld(0, None);
        let second = withheld(1, Some(first.commit().commit_id.clone()));
        let realm = first.commit().realm_id.clone();
        for candidate in [
            second.clone(),
            withheld(0, Some(second.commit().commit_id.clone())),
        ] {
            let mut hints = HintBatch::default();
            hints.push(&realm, &hint(candidate, 0)).unwrap();
            let snapshot = frozen(std::slice::from_ref(&first));
            let (client, _, server) = http(vec![serde_json::to_value(&snapshot).unwrap()]);
            let directory = tempfile::tempdir().unwrap();
            let mut local =
                crate::state::LocalStateStore::with_path(directory.path().join("stale.json"));
            let account = crate::test_support::AccountFixture::new("did:web:alice.example")
                .station("ak:did_core:web:station.example")
                .build();
            local.switch_active_account(&account).unwrap();
            let store = Arc::new(Mutex::new(local));
            let projector = test_projector(store.clone(), &realm);
            let mut current = OwnStationReplica::new(realm.clone());
            assert!(
                drain_hints(
                    &client,
                    &client.http_client().unwrap(),
                    &realm,
                    &hints,
                    &projector,
                    &|| true,
                    &mut current,
                    &mut None
                )
                .await
                .is_err()
            );
            server.join().unwrap();
            assert!(current.snapshot().is_none());
            assert!(
                store
                    .lock()
                    .unwrap()
                    .verified_commit_stream_cursor(&first.commit().stream_ref)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn hint_batch_preserves_control_barriers_and_conflicts() {
        let row = withheld(0, None);
        let realm = row.commit().realm_id.clone();
        for kind in [
            "resync_required",
            "unauthorized",
            "quarantined",
            "epoch_rotation",
        ] {
            let control = match kind {
                "quarantined" => serde_json::json!({"kind":kind,"payload":{
                    "realm_id":realm,"error_code":"witness_disagreement",
                    "affected_stream_refs":[row.commit().stream_ref]}}),
                "epoch_rotation" => {
                    serde_json::json!({"kind":kind,"realm_id":realm,"payload":{"new_epoch":1}})
                }
                _ => serde_json::json!({"kind":kind}),
            };
            let control: HintFrame = serde_json::from_value(control).unwrap();
            control.validate().unwrap();
            let mut stream = queued_hints(&realm, vec![hint(row.clone(), 0), control.clone()]);
            let first = stream.next_frame().await.unwrap().unwrap();
            let mut resume = SubscriptionState::default();
            let (hints, barrier, ended) =
                collect_ready_hints(&realm, first, &mut stream, &mut resume, &|| true).unwrap();
            assert_eq!(hints.positions.len(), 1);
            assert_eq!(barrier, Some(control));
            assert!(!ended);
            assert!(resume.cursor.is_none());
        }
        let mut hints = HintBatch::default();
        hints.push(&realm, &hint(row.clone(), 0)).unwrap();
        let mut conflict = row;
        if let CommittedEventView::Withheld(withheld) = &mut conflict {
            withheld.commit.commit_id = arkret_sdk::RealmCommitId::from_digest([77; 32]);
        }
        assert!(hints.push(&realm, &hint(conflict, 1)).is_err());
    }

    pub(super) struct Source(pub(super) Mutex<OwnStationSessionSnapshot>);
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    fn withheld(position: u64, previous: Option<arkret_sdk::RealmCommitId>) -> CommittedEventView {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let genesis = arkret_sdk::EventId::from_digest(
            realm.digest_suite_code().digest_suite(),
            realm.digest_bytes(),
        );
        let event = if position == 0 {
            genesis.clone()
        } else {
            arkret_sdk::EventId::from_digest(
                realm.digest_suite_code().digest_suite(),
                [position as u8; 32],
            )
        };
        let mut commit = arkret_sdk::RealmCommit {
            commit_id: arkret_sdk::RealmCommitId::from_digest([0; 32]),
            realm_id: realm.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id: realm },
            stream_position: position,
            previous_commit_ref: previous,
            event_ref: event.clone(),
            governance_generation: 0,
            authority_ref: arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
            committed_at: "2026-10-05T00:00:01.000Z".parse().unwrap(),
            producer_signer_fact_digest: None,
            signature: arkret_sdk::DetachedObjectSignature {
                context: arkret_sdk::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_sdk::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_sdk::DidUrl::new("did:web:station.example#key-1")
                    .unwrap(),
                signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                created_at: "2026-10-05T00:00:01.000Z".parse().unwrap(),
                sig: arkret_sdk::Base64UrlString::new("AA").unwrap(),
            },
        };
        let mut body = serde_json::to_value(&commit).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        commit.commit_id =
            arkret_sdk::RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(
                arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        commit =
            crate::test_support::committed_event::FixtureStation::did_web().seal_commit(commit);
        serde_json::from_value(
            serde_json::json!({"commit":commit,"event_disclosure":{"status":"withheld"}}),
        )
        .unwrap()
    }

    pub(super) fn frozen(rows: &[CommittedEventView]) -> arkret_sdk::RealmStateSnapshot {
        let last = rows.last().unwrap().commit();
        let mut snapshot = arkret_sdk::RealmStateSnapshot {
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: last.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![arkret_sdk::CommitStreamHead {
                stream_ref: last.stream_ref.clone(),
                stream_position: last.stream_position,
                commit_id: last.commit_id.clone(),
            }],
            current_state_entries: vec![],
            retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
                history_access: arkret_sdk::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_sdk::StreamHistoryFloor {
                    stream_ref: last.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: last.committed_at,
            signature: last.signature.clone(),
        };
        let mut body = serde_json::to_value(&snapshot).unwrap();
        body.as_object_mut().unwrap().remove("snapshot_id");
        body.as_object_mut().unwrap().remove("signature");
        snapshot.snapshot_id =
            arkret_sdk::RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
                arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        crate::test_support::committed_event::FixtureStation::did_web()
            .sign_snapshot(&mut snapshot);
        snapshot
    }

    fn http(
        bodies: Vec<serde_json::Value>,
    ) -> (
        OwnStationResultClient,
        Arc<Source>,
        std::thread::JoinHandle<()>,
    ) {
        http_for_account(
            bodies,
            arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            None,
        )
    }

    fn http_for_account(
        bodies: Vec<serde_json::Value>,
        account: arkret_sdk::AccountId,
        exact_checkpoint: Option<arkret_sdk::CommitStreamHead>,
    ) -> (
        OwnStationResultClient,
        Arc<Source>,
        std::thread::JoinHandle<()>,
    ) {
        http_for_account_observed(bodies, account, exact_checkpoint, None)
    }

    pub(super) fn http_for_account_observed(
        bodies: Vec<serde_json::Value>,
        account: arkret_sdk::AccountId,
        exact_checkpoint: Option<arkret_sdk::CommitStreamHead>,
        observed: Option<Arc<Mutex<Vec<String>>>>,
    ) -> (
        OwnStationResultClient,
        Arc<Source>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let station = account.station_id.clone();
        let binding = arkret_sdk::StationConnectionBinding {
            service_id: station.clone(),
            base_url: base.clone(),
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_sdk::AuthMetadata::minimal(),
        };
        let session = OwnStationSessionSnapshot::new(
            binding.clone(),
            account,
            station,
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            0,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let source = Arc::new(Source(Mutex::new(session)));
        let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer("test-grant".into()))
            .build()
            .unwrap();
        let expected_limit = bodies[0]["visible_stream_heads"][0]["stream_position"]
            .as_u64()
            .unwrap()
            + 1;
        let server = std::thread::spawn(move || {
            for (index, mut body) in bodies.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 8192];
                let end = loop {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                assert!(headers.contains("authorization: bearer test-grant"));
                if let Some(observed) = &observed {
                    observed
                        .lock()
                        .unwrap()
                        .push(headers.lines().next().unwrap().to_owned());
                }
                let len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < end + len {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                if let Some(expected) = body.get("__scan_request") {
                    assert!(headers.starts_with("post /_arkret/self/streams/scan "));
                    let request: StreamScanRequest =
                        serde_json::from_slice(&bytes[end..end + len]).unwrap();
                    assert_eq!(serde_json::to_value(request).unwrap(), *expected);
                    body = body["response"].clone();
                } else if let Some(key) = body.get("__signer_key") {
                    use arkret_models_identity::signer_key_operations::{
                        SignerKeyQueryOutcome, SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
                    };
                    assert!(headers.starts_with("post /_arkret/self/signer-keys/query "));
                    let request: SignerKeysQueryRequestBody =
                        serde_json::from_slice(&bytes[end..end + len]).unwrap();
                    body = serde_json::to_value(SignerKeysQueryOutcome {
                        request_id: request.request_id,
                        realm_id: request.realm_id,
                        recipient_account_id: request.recipient_account_id,
                        recipient_actor_id: request.recipient_actor_id,
                        results: vec![SignerKeyQueryOutcome::HistoricalResolved {
                            selector: request.queries[0].clone(),
                            key: serde_json::from_value(key.clone()).unwrap(),
                            accepted_at: crate::test_support::committed_event::fixture_time(1),
                        }],
                    })
                    .unwrap();
                } else if body.get("visible_stream_heads").is_some() {
                    assert!(headers.starts_with("get "));
                } else if index > 0 {
                    assert!(headers.starts_with("post /_arkret/self/streams/scan "));
                    let request: StreamScanRequest =
                        serde_json::from_slice(&bytes[end..end + len]).unwrap();
                    if let Some(head) = &exact_checkpoint {
                        assert_eq!(request.realm_id, request.stream_ref.realm_id().clone());
                        assert_eq!(request.stream_ref, head.stream_ref);
                        if index == 1 {
                            assert_eq!(request.limit, 1);
                            assert_eq!(
                                request.direction,
                                arkret_sdk::StreamScanDirection::Before(Some(
                                    head.stream_position + 1
                                ))
                            );
                        } else {
                            assert_eq!(
                                u64::from(request.limit),
                                expected_limit - head.stream_position - 1
                            );
                            assert_eq!(
                                request.direction,
                                arkret_sdk::StreamScanDirection::After(Some(head.stream_position))
                            );
                        }
                    } else {
                        assert_eq!(u64::from(request.limit), expected_limit);
                        assert_eq!(
                            request.direction,
                            arkret_sdk::StreamScanDirection::After(None)
                        );
                    }
                }
                let body = serde_json::to_vec(&body).unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        (
            OwnStationResultClient::new(raw, binding, source.clone()).unwrap(),
            source,
            server,
        )
    }

    fn current_snapshot(
        rows: &[CommittedEventView],
        chats: usize,
    ) -> arkret_sdk::RealmStateSnapshot {
        let mut snapshot = frozen(rows);
        let account = arkret_sdk::AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        );
        for number in 0..chats {
            let event = arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [number as u8 + 20; 32],
            );
            let strand_id = arkret_sdk::StrandId::from_event_id(&event);
            let mut strand = arkret_models_collaboration::objects::strand::Strand::new_create(
                snapshot.realm_id.clone(),
                "fixture Chat",
                arkret_sdk::ActorId::account(account.clone()),
            );
            strand.id = Some(strand_id.clone());
            strand.created_at = snapshot.created_at;
            strand.tracks.clear();
            strand.tracks.insert(
                "discussion".into(),
                arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
            );
            let revision = rows[number.min(rows.len() - 1)].commit();
            snapshot
                .current_state_entries
                .push(arkret_sdk::TypedCurrentRow::Value {
                    selector: arkret_sdk::CurrentSelector::Strand { strand_id },
                    source_stream_ref: revision.stream_ref.clone(),
                    revision: arkret_sdk::CurrentRevision {
                        commit_id: revision.commit_id.clone(),
                        stream_position: revision.stream_position,
                    },
                    value: serde_json::to_value(strand).unwrap(),
                });
        }
        seal_current_snapshot(&mut snapshot);
        snapshot
    }

    pub(super) fn seal_current_snapshot(snapshot: &mut arkret_sdk::RealmStateSnapshot) {
        let mut body = serde_json::to_value(&*snapshot).unwrap();
        body.as_object_mut().unwrap().remove("snapshot_id");
        body.as_object_mut().unwrap().remove("signature");
        snapshot.snapshot_id =
            arkret_sdk::RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
                arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        crate::test_support::committed_event::FixtureStation::did_web().sign_snapshot(snapshot);
    }

    pub(super) fn test_projector(
        store: Arc<Mutex<crate::state::LocalStateStore>>,
        realm: &arkret_sdk::RealmId,
    ) -> RealmIngestProjector {
        let reader = store.clone();
        let writer = store;
        let epoch = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let epoch_read = epoch.clone();
        let epoch_write = epoch.clone();
        RealmIngestProjector {
            state_store: crate::runtime::input::StateStoreHandle::new(
                move |read| read(&reader.lock().unwrap()),
                move |write| write(&mut writer.lock().unwrap()),
            ),
            realm_id: realm.to_string(),
            digest_suite: arkret_sdk::DigestSuite::Sha256,
            realm_live_epoch: crate::runtime::input::ValueCell::new(
                move || epoch_read.get(),
                move |value| epoch_write.set(value),
                move |update| {
                    let mut value = epoch.get();
                    update(&mut value);
                    epoch.set(value);
                },
            ),
            message_stream_hub: None,
        }
    }

    async fn bound_snapshot(
        snapshot: &arkret_sdk::RealmStateSnapshot,
    ) -> (
        arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
            arkret_sdk::RealmId,
            arkret_sdk::RealmStateSnapshot,
        >,
        Arc<Source>,
    ) {
        let (client, source, server) = http(vec![serde_json::to_value(snapshot).unwrap()]);
        let bound = client.snapshot_head(&snapshot.realm_id).await.unwrap();
        server.join().unwrap();
        (bound, source)
    }

    /// Keep this audit-prefix fixture's accepted history separate from the
    /// ordinary current carrier: only a real bound HTTP response may publish it.
    pub(in crate::realm_events_engine) async fn refresh_fixture_accepted_sidecar_current(
        mut local: crate::state::LocalStateStore,
        snapshot: &arkret_sdk::RealmStateSnapshot,
        account: &arkret_sdk::AccountId,
        head: &arkret_sdk::RealmCommit,
    ) -> crate::state::LocalStateStore {
        let fixture_account = crate::test_support::AccountFixture::new(&format!(
            "did:web:{}",
            account
                .principal_id
                .as_str()
                .strip_prefix("ak:did_core:web:")
                .unwrap()
        ))
        .station(account.station_id.as_str())
        .build();
        let accepted_state = local.load();
        let accepted_history = accepted_state.verified_sidecar_history.clone();
        local.switch_active_account(&fixture_account).unwrap();
        local.save(accepted_state);
        let expected = arkret_sdk::CommitStreamHead {
            stream_ref: head.stream_ref.clone(),
            commit_id: head.commit_id.clone(),
            stream_position: head.stream_position,
        };
        // A checkpoint read may withhold the Event; it never manufactures
        // producer evidence or replaces the already admitted complete history.
        let original: CommittedEventView = serde_json::from_value(serde_json::json!({
            "commit": head, "event_disclosure":{"status":"withheld"}
        }))
        .unwrap();
        let (client, _, server) = http_for_account(
            vec![
                serde_json::to_value(snapshot).unwrap(),
                serde_json::json!({"committed_events":[original],"readable_floor":null,"truncated":true}),
            ],
            account.clone(),
            Some(expected.clone()),
        );
        let bound = client.snapshot_head(&snapshot.realm_id).await.unwrap();
        let mut replica = OwnStationReplica::new(snapshot.realm_id.clone());
        replica.install_bound_snapshot(&bound).unwrap();
        replica
            .restore_checkpoint_head(&client, &expected)
            .await
            .unwrap();
        server.join().unwrap();
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &snapshot.realm_id);
        let (_, current_changed) = install_live_current_snapshot(
            &client,
            &bound,
            &snapshot.realm_id,
            &expected.stream_ref,
            &projector,
            &replica,
            &[],
            &[],
            &|| true,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            store.lock().unwrap().load().verified_sidecar_history,
            accepted_history,
            "the current read must not fabricate or replace history rows"
        );
        assert!(current_changed);
        drop(projector);
        match Arc::try_unwrap(store) {
            Ok(store) => store.into_inner().unwrap(),
            Err(_) => panic!("fixture projector must release its store"),
        }
    }

    #[tokio::test]
    async fn own_live_since_join_bootstrap_persists_current_head_without_historical_rows() {
        let row = withheld(5, Some(arkret_sdk::RealmCommitId::from_digest([43; 32])));
        let mut snapshot = current_snapshot(std::slice::from_ref(&row), 1);
        snapshot.retention_and_history_floor.stream_floors[0].oldest_position = 3;
        seal_current_snapshot(&mut snapshot);
        let head = snapshot.visible_stream_heads[0].clone();
        let account = arkret_sdk::AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        );
        let (client, _, server) = http_for_account(
            vec![
                serde_json::to_value(&snapshot).unwrap(),
                serde_json::json!({"committed_events":[row.clone()],"readable_floor":null,"truncated":true}),
            ],
            account,
            Some(head.clone()),
        );
        let bound = client.snapshot_head(&snapshot.realm_id).await.unwrap();
        let (replica, pages) = replay(&client, &snapshot.realm_id, &head.stream_ref, &bound, None)
            .await
            .unwrap();
        server.join().unwrap();
        assert!(
            pages.is_empty(),
            "current bootstrap must not admit preview history"
        );
        assert_eq!(replica.head(&head.stream_ref), Some(&head));
        let directory = tempfile::tempdir().unwrap();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("live-floor.json"));
        let fixture = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        local.switch_active_account(&fixture).unwrap();
        local.save_sync_cursor("ak:cursor:unchanged-account");
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &snapshot.realm_id);
        install_live_current_snapshot(
            &client,
            &bound,
            &snapshot.realm_id,
            &head.stream_ref,
            &projector,
            &replica,
            &pages,
            &[],
            &|| true,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .verified_commit_stream_cursor(&head.stream_ref)
                .unwrap(),
            Some(head.clone())
        );
        assert_eq!(
            store.lock().unwrap().sync_cursor().as_deref(),
            Some("ak:cursor:unchanged-account")
        );
        // A later route starts from the join-time durable head, even if a new
        // Commit was accepted before the user first opened that route.
        let next = withheld(6, Some(head.commit_id.clone()));
        let mut later = current_snapshot(std::slice::from_ref(&next), 1);
        later.retention_and_history_floor.stream_floors[0].oldest_position = 3;
        seal_current_snapshot(&mut later);
        let account = store.lock().unwrap().active_authority().unwrap();
        let (client, _, server) = http_for_account(
            vec![
                serde_json::to_value(&later).unwrap(),
                serde_json::json!({"committed_events":[row],"readable_floor":null,"truncated":true}),
                serde_json::json!({"committed_events":[next.clone()],"readable_floor":{
                    "oldest_position":3,"floor_commit_id":arkret_sdk::RealmCommitId::from_digest([43;32]),
                    "floor_reason":"membership_join"},"truncated":false}),
            ],
            account,
            Some(head.clone()),
        );
        let bound = client.snapshot_head(&later.realm_id).await.unwrap();
        let (replica, pages) = replay(
            &client,
            &later.realm_id,
            &head.stream_ref,
            &bound,
            Some(&head),
        )
        .await
        .unwrap();
        assert_eq!(replica.head(&head.stream_ref).unwrap().stream_position, 6);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].rows().unwrap(), &[next]);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn late_live_cut_retries_before_arming_without_poisoning_or_cursor_advance() {
        let first = withheld(0, None);
        let second = withheld(1, Some(first.commit().commit_id.clone()));
        let realm = first.commit().realm_id.clone();
        let stream = first.commit().stream_ref.clone();
        let newer = current_snapshot(&[first.clone(), second], 2);
        let older = current_snapshot(&[first], 1);
        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("late.json"));
        local.switch_active_account(&account).unwrap();
        local.save_sync_cursor("ak:cursor:unchanged-account");
        let (client, _, server) = http(vec![serde_json::to_value(&older).unwrap()]);
        let inflight = client.snapshot_head(&realm).await.unwrap();
        server.join().unwrap();
        let (published, _) = bound_snapshot(&newer).await;
        local
            .install_own_station_sidecar_current(&published)
            .unwrap();
        let location = local.current_index_location();
        let before = serde_json::to_value(local.load()).unwrap();
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &realm);
        let mut replica = OwnStationReplica::new(realm.clone());
        replica.install_bound_snapshot(&inflight).unwrap();
        let refused = install_live_current_snapshot(
            &client,
            &inflight,
            &realm,
            &stream,
            &projector,
            &replica,
            &[],
            &[],
            &|| true,
            None,
        )
        .await;
        assert!(matches!(refused, Err(garth::Error::AuthorityCutBehind)));
        assert_eq!(
            serde_json::to_value(store.lock().unwrap().load()).unwrap(),
            before
        );
        let index =
            crate::state::CurrentIndex::open_committed(&account.authority, location, || Ok(0))
                .await
                .unwrap();
        assert!(!index.is_poisoned());
    }

    #[tokio::test]
    async fn account_list_change_refuses_inflight_live_snapshot_without_poisoning_or_cursor_advance()
     {
        let first = withheld(0, None);
        let realm = first.commit().realm_id.clone();
        let stream = first.commit().stream_ref.clone();
        let older = current_snapshot(&[first], 1);
        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("late.json"));
        local.switch_active_account(&account).unwrap();
        local.save_sync_cursor("ak:cursor:unchanged-account");
        let (client, _, server) = http(vec![serde_json::to_value(&older).unwrap()]);
        let inflight = client.snapshot_head(&realm).await.unwrap();
        server.join().unwrap();
        let list_fence = local.realm_list_read_fence(realm.as_str());
        let removal = serde_json::from_value(serde_json::json!({
            "kind":"delta", "cursor":"ak:cursor:YQ",
            "realm_list_changes":{"upserts":[],"removals":[{"realm_id":realm,"revision":100_000}]}
        }))
        .unwrap();
        let prepared = local.prepare_account_demand_frame(&removal).unwrap();
        local.finish_account_demand_frame(&prepared).unwrap();
        let location = local.current_index_location();
        let before = serde_json::to_value(local.load()).unwrap();
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &realm);
        let mut replica = OwnStationReplica::new(realm.clone());
        replica.install_bound_snapshot(&inflight).unwrap();
        let refused = install_live_current_snapshot(
            &client,
            &inflight,
            &realm,
            &stream,
            &projector,
            &replica,
            &[],
            &[],
            &|| true,
            Some(&list_fence),
        )
        .await;
        assert!(matches!(refused, Err(garth::Error::AuthorityCutBehind)));
        assert_eq!(
            serde_json::to_value(store.lock().unwrap().load()).unwrap(),
            before
        );
        let index =
            crate::state::CurrentIndex::open_committed(&account.authority, location, || Ok(0))
                .await
                .unwrap();
        assert!(!index.is_poisoned());
    }

    #[tokio::test]
    async fn initial_join_and_activity_do_not_refuse_an_inflight_live_snapshot() {
        let first = withheld(0, None);
        let realm = first.commit().realm_id.clone();
        let stream = first.commit().stream_ref.clone();
        let snapshot = current_snapshot(std::slice::from_ref(&first), 1);
        let directory = tempfile::tempdir().unwrap();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local =
            crate::state::LocalStateStore::with_path(directory.path().join("join.json"));
        local.switch_active_account(&account).unwrap();
        local.save_sync_cursor("ak:cursor:unchanged-account");
        let fence = local.realm_list_read_fence(realm.as_str());
        let (client, _, server) = http(vec![
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!({"committed_events":[first.clone()],"readable_floor":{
                "oldest_position":0,"floor_commit_id":first.commit().commit_id,
                "floor_reason":"stream_start"},"truncated":false}),
        ]);
        let bound = client.snapshot_head(&realm).await.unwrap();
        let (replica, pages) = replay(&client, &realm, &stream, &bound, None)
            .await
            .unwrap();
        server.join().unwrap();
        for revision in [10, 11] {
            let frame = serde_json::from_value(serde_json::json!({
                "kind":"delta", "cursor":"ak:cursor:YQ", "realm_list_changes":{
                    "upserts":[{"realm_id":realm,"revision":revision,"activity_position":1,"membership":"join"}],
                    "removals":[]}
            })).unwrap();
            crate::state::current_index::search::tests::install_account_scope_frame(
                &mut local, &frame,
            )
            .await;
            assert_eq!(local.realm_list_read_fence(realm.as_str()), fence);
            assert!(!local.account_scope_read_denied(realm.as_str()));
        }
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &realm);
        let (_, changed) = install_live_current_snapshot(
            &client,
            &bound,
            &realm,
            &stream,
            &projector,
            &replica,
            &pages,
            &[],
            &|| true,
            Some(&fence),
        )
        .await
        .unwrap();
        assert!(changed);
        let local = store.lock().unwrap();
        assert_eq!(local.current_generation(), 3);
        assert_eq!(
            local.sync_cursor().as_deref(),
            Some("ak:cursor:unchanged-account")
        );
        assert_eq!(
            local
                .verified_commit_stream_cursor(&stream)
                .unwrap()
                .as_ref(),
            replica.head(&stream)
        );
        let view = local.current_product_view().unwrap();
        assert!(view.complete_cut);
        let visible = garth::direct_structure::DirectStructureView::from_current(
            &realm,
            view.entries_for(realm.as_str()).unwrap(),
        )
        .unwrap();
        assert_eq!(visible.chats.len(), 1);
    }

    #[tokio::test]
    async fn own_live_current_installs_new_chat_reopens_and_keeps_account_cursor() {
        let first = withheld(0, None);
        let second = withheld(1, Some(first.commit().commit_id.clone()));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("live.json");
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local = crate::state::LocalStateStore::with_path(&path);
        local.switch_active_account(&account).unwrap();
        local.save_sync_cursor("ak:cursor:unchanged-account");
        let store = Arc::new(Mutex::new(local));
        let realm = first.commit().realm_id.clone();
        let stream = first.commit().stream_ref.clone();
        let projector = test_projector(store.clone(), &realm);
        for (rows, chat_count) in [
            (vec![first.clone()], 1),
            (vec![first.clone(), second.clone()], 2),
        ] {
            let snapshot = current_snapshot(&rows, chat_count);
            let (client, _, server) = http(vec![
                serde_json::to_value(&snapshot).unwrap(),
                serde_json::json!({"committed_events":rows,"readable_floor":{
                    "oldest_position":0,"floor_commit_id":first.commit().commit_id,
                    "floor_reason":"stream_start"},"truncated":false}),
            ]);
            let bound = client.snapshot_head(&realm).await.unwrap();
            let (replica, pages) = replay(&client, &realm, &stream, &bound, None)
                .await
                .unwrap();
            let previous = store.lock().unwrap().current_generation();
            assert!(
                install_live_current_snapshot(
                    &client,
                    &bound,
                    &realm,
                    &stream,
                    &projector,
                    &replica,
                    &pages,
                    &[],
                    &|| false,
                    None,
                )
                .await
                .is_err()
            );
            assert_eq!(store.lock().unwrap().current_generation(), previous);
            let (changed, current_changed) = install_live_current_snapshot(
                &client,
                &bound,
                &realm,
                &stream,
                &projector,
                &replica,
                &pages,
                &[],
                &|| true,
                None,
            )
            .await
            .unwrap();
            assert!(current_changed);
            assert_eq!(projector.realm_live_epoch.get(), chat_count as u64);
            let _ = changed;
            {
                let local = store.lock().unwrap();
                assert_eq!(
                    local.sync_cursor().as_deref(),
                    Some("ak:cursor:unchanged-account")
                );
                assert_eq!(
                    local
                        .verified_commit_stream_cursor(&stream)
                        .unwrap()
                        .as_ref(),
                    replica.head(&stream)
                );
                let view = local.current_product_view().unwrap();
                assert!(view.complete_cut);
                let visible = garth::direct_structure::DirectStructureView::from_current(
                    &realm,
                    view.entries_for(realm.as_str()).unwrap(),
                )
                .unwrap();
                assert_eq!(visible.chats.len(), chat_count);
            }
            server.join().unwrap();
            // A repeated identical authenticated original shares the durable
            // generation. No Account frame/cursor is manufactured.
            let prior = store.lock().unwrap().current_generation();
            let (bound, _) = bound_snapshot(&snapshot).await;
            let location = store.lock().unwrap().current_index_location();
            let index =
                crate::state::CurrentIndex::open_committed(&account.authority, location, || {
                    Ok(store.lock().unwrap().current_generation())
                })
                .await
                .unwrap();
            let stage = index
                .stage_own_station_snapshot(prior, &bound, &|| Ok(()))
                .await
                .unwrap();
            assert!(!stage.changed());
            assert_eq!(stage.generation(), prior);
            stage.finish();
        }
        let mut reopened = crate::state::LocalStateStore::with_path(&path);
        reopened.switch_active_account(&account).unwrap();
        assert_eq!(
            reopened.current_generation(),
            store.lock().unwrap().current_generation()
        );
        assert_eq!(
            reopened.sync_cursor().as_deref(),
            Some("ak:cursor:unchanged-account")
        );
        let index = crate::state::CurrentIndex::open_committed(
            &account.authority,
            reopened.current_index_location(),
            || Ok(reopened.current_generation()),
        )
        .await
        .unwrap();
        assert!(reopened.current_product_view().is_none());
        let reopened_projector = test_projector(Arc::new(Mutex::new(reopened)), &realm);
        crate::sync_engine::publish_current_product_view(
            &index,
            &reopened_projector.state_store,
            &account.authority,
            realm.as_str(),
            &|| Ok(()),
        )
        .await
        .unwrap();
        let visible = reopened_projector
            .state_store
            .read(|local| local.current_product_view().unwrap());
        assert_eq!(
            garth::direct_structure::DirectStructureView::from_current(&realm, &visible.entries)
                .unwrap()
                .chats
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn own_live_current_rejects_late_source_fork_and_account_generation_conflict() {
        let first = withheld(0, None);
        let second = withheld(1, Some(first.commit().commit_id.clone()));
        let snapshot = current_snapshot(&[first.clone(), second.clone()], 2);
        let (bound, source) = bound_snapshot(&snapshot).await;
        let directory = tempfile::tempdir().unwrap();
        let store = crate::state::LocalStateStore::with_path(directory.path().join("source.json"));
        let account = source.0.lock().unwrap().account_id().clone();
        let index = crate::state::CurrentIndex::open_committed(
            &account,
            store.current_index_location(),
            || Ok(0),
        )
        .await
        .unwrap();
        let stage = index
            .stage_own_station_snapshot(0, &bound, &|| Ok(()))
            .await
            .unwrap();
        stage.finish();
        let before = index
            .read_complete_cut(snapshot.realm_id.as_str())
            .await
            .unwrap();
        // An Account stage that captured the old generation cannot overwrite
        // this independently committed original.
        let frame: arkret_sdk::sync::AccountSubscribeFrame =
            serde_json::from_value(serde_json::json!({"kind":"delta","cursor":"ak:cursor:YQ"}))
                .unwrap();
        assert!(index.stage_frame(0, &frame).await.is_err());
        for mut candidate in [current_snapshot(&[first], 1), snapshot.clone()] {
            if candidate.visible_stream_heads[0].stream_position == 1 {
                candidate.visible_stream_heads[0].commit_id =
                    arkret_sdk::RealmCommitId::from_digest([91; 32]);
                candidate.current_state_entries.clear();
                seal_current_snapshot(&mut candidate);
            }
            let (candidate, _) = bound_snapshot(&candidate).await;
            assert!(
                index
                    .stage_own_station_snapshot(1, &candidate, &|| Ok(()))
                    .await
                    .is_err()
            );
            assert_eq!(
                index
                    .read_complete_cut(snapshot.realm_id.as_str())
                    .await
                    .unwrap(),
                before
            );
        }
        let (inflight, inflight_source) = bound_snapshot(&snapshot).await;
        let checks = std::cell::Cell::new(0);
        let live = inflight_source.0.lock().unwrap().clone();
        let changed_during_stage = || -> anyhow::Result<()> {
            let next = checks.get() + 1;
            checks.set(next);
            if next == 2 {
                *inflight_source.0.lock().unwrap() = OwnStationSessionSnapshot::new(
                    live.binding().clone(),
                    live.account_id().clone(),
                    live.binding().service_id.clone(),
                    live.grant_id().clone(),
                    live.epoch() + 1,
                    "test-grant".into(),
                )
                .unwrap()
                .with_provider_identity(Default::default());
            }
            Ok(())
        };
        assert!(
            index
                .stage_own_station_snapshot(1, &inflight, &changed_during_stage)
                .await
                .is_err()
        );
        assert!(checks.get() >= 2);
        assert_eq!(
            index
                .read_complete_cut(snapshot.realm_id.as_str())
                .await
                .unwrap(),
            before
        );
        let original = source.0.lock().unwrap().clone();
        for epoch in [original.epoch() + 1, original.epoch()] {
            *source.0.lock().unwrap() = OwnStationSessionSnapshot::new(
                original.binding().clone(),
                original.account_id().clone(),
                original.binding().service_id.clone(),
                original.grant_id().clone(),
                epoch,
                "test-grant".into(),
            )
            .unwrap()
            .with_provider_identity(Default::default());
            assert!(
                index
                    .stage_own_station_snapshot(1, &bound, &|| Ok(()))
                    .await
                    .is_err()
            );
            assert_eq!(
                index
                    .read_complete_cut(snapshot.realm_id.as_str())
                    .await
                    .unwrap(),
                before
            );
        }
    }

    #[tokio::test]
    async fn own_live_current_hidden_heads_and_governance_watermarks_survive_scope_omission() {
        let first = withheld(0, None);
        let mut initial = current_snapshot(std::slice::from_ref(&first), 1);
        let sidecar_stream = CommitStreamRef::Sidecar {
            realm_id: initial.realm_id.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [41; 32],
            )),
        };
        initial
            .visible_stream_heads
            .push(arkret_sdk::CommitStreamHead {
                stream_ref: sidecar_stream.clone(),
                stream_position: 5,
                commit_id: arkret_sdk::RealmCommitId::from_digest([42; 32]),
            });
        initial
            .retention_and_history_floor
            .stream_floors
            .push(arkret_sdk::StreamHistoryFloor {
                stream_ref: sidecar_stream,
                oldest_position: 2,
            });
        initial.governance_generation = 3;
        seal_current_snapshot(&mut initial);
        let (bound, _) = bound_snapshot(&initial).await;
        let directory = tempfile::tempdir().unwrap();
        let local = crate::state::LocalStateStore::with_path(directory.path().join("hidden.json"));
        let account = bound.session().account_id().clone();
        let index = crate::state::CurrentIndex::open_committed(
            &account,
            local.current_index_location(),
            || Ok(0),
        )
        .await
        .unwrap();
        index
            .stage_own_station_snapshot(0, &bound, &|| Ok(()))
            .await
            .unwrap()
            .finish();
        let mut omitted = current_snapshot(&[first], 1);
        omitted.governance_generation = 4;
        seal_current_snapshot(&mut omitted);
        let (bound, _) = bound_snapshot(&omitted).await;
        index
            .stage_own_station_snapshot(1, &bound, &|| Ok(()))
            .await
            .unwrap()
            .finish();
        for (position, generation, fork) in [(4, 4, false), (5, 4, true), (5, 2, false)] {
            let mut reappeared = initial.clone();
            reappeared.governance_generation = generation;
            reappeared.visible_stream_heads[1].stream_position = position;
            if fork {
                reappeared.visible_stream_heads[1].commit_id =
                    arkret_sdk::RealmCommitId::from_digest([43; 32]);
            }
            seal_current_snapshot(&mut reappeared);
            let (bound, _) = bound_snapshot(&reappeared).await;
            assert!(
                index
                    .stage_own_station_snapshot(2, &bound, &|| Ok(()))
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            index
                .read_complete_cut(initial.realm_id.as_str())
                .await
                .unwrap()
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn own_live_current_failed_flush_recovers_independently_without_cursor_or_checkpoint_advance()
     {
        let first = withheld(0, None);
        let second = withheld(1, Some(first.commit().commit_id.clone()));
        let rows = vec![first.clone(), second];
        let snapshot = current_snapshot(&rows, 2);
        let (client, _, server) = http(vec![
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!({"committed_events":rows,"readable_floor":{
                "oldest_position":0,"floor_commit_id":first.commit().commit_id,
                "floor_reason":"stream_start"},"truncated":false}),
        ]);
        let bound = client.snapshot_head(&snapshot.realm_id).await.unwrap();
        let stream = first.commit().stream_ref.clone();
        let (replica, pages) = replay(&client, &snapshot.realm_id, &stream, &bound, None)
            .await
            .unwrap();
        server.join().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("failure.json");
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let mut local = crate::state::LocalStateStore::with_path(&path);
        local.switch_active_account(&account).unwrap();
        local.save_sync_cursor("ak:cursor:retained");
        let store = Arc::new(Mutex::new(local));
        let projector = test_projector(store.clone(), &snapshot.realm_id);
        let durable_before = store
            .lock()
            .unwrap()
            .conformance_account_checkpoint_token()
            .unwrap();
        // Fail the actual account-root write inside the shared current transaction.
        store
            .lock()
            .unwrap()
            .conformance_fail_account_commit(true)
            .unwrap();
        assert!(
            install_live_current_snapshot(
                &client,
                &bound,
                &snapshot.realm_id,
                &stream,
                &projector,
                &replica,
                &pages,
                &[],
                &|| true,
                None,
            )
            .await
            .is_err()
        );
        {
            let local = store.lock().unwrap();
            assert_eq!(local.current_generation(), 0);
            assert!(local.current_product_view().is_none());
            assert!(
                local
                    .verified_commit_stream_cursor(&stream)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(local.sync_cursor().as_deref(), Some("ak:cursor:retained"));
        }
        let index_location = store.lock().unwrap().current_index_location();
        let index =
            crate::state::CurrentIndex::open_committed(&account.authority, index_location, || {
                Ok(0)
            })
            .await
            .unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .conformance_account_checkpoint_token()
                .unwrap(),
            durable_before
        );
        assert!(
            !index.is_poisoned(),
            "the old root was independently confirmed after atomic rollback"
        );
        assert!(
            index
                .read_selector_ready(
                    snapshot.realm_id.as_str(),
                    &arkret_sdk::CurrentSelector::RealmProfile
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            index
                .read_mls_group_ready(
                    &arkret_sdk::ScopeRef::Realm {
                        realm_id: snapshot.realm_id.clone()
                    },
                    &arkret_sdk::ActorId::account(account.authority.clone())
                )
                .await
                .is_err()
        );
        assert!(
            index
                .read_complete_cut(snapshot.realm_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
        store
            .lock()
            .unwrap()
            .conformance_fail_account_commit(false)
            .unwrap();
        // The same real live entry recovers its own durable pointer, then
        // retries its real accepted prefix/current transaction.
        install_live_current_snapshot(
            &client,
            &bound,
            &snapshot.realm_id,
            &stream,
            &projector,
            &replica,
            &pages,
            &[],
            &|| true,
            None,
        )
        .await
        .unwrap();
        assert!(!index.is_poisoned());
        let local = store.lock().unwrap();
        assert_eq!(local.current_generation(), 1);
        assert_eq!(
            local
                .verified_commit_stream_cursor(&stream)
                .unwrap()
                .as_ref(),
            replica.head(&stream)
        );
        assert_eq!(local.sync_cursor().as_deref(), Some("ak:cursor:retained"));
        assert_eq!(
            garth::direct_structure::DirectStructureView::from_current(
                &snapshot.realm_id,
                &local.current_product_view().unwrap().entries
            )
            .unwrap()
            .chats
            .len(),
            2
        );
    }

    #[tokio::test]
    async fn actual_live_prefix_keeps_withheld_commit_chain_and_rejects_fork_or_late_session() {
        for fork in [false, true] {
            let first = withheld(0, None);
            let second = withheld(
                1,
                Some(if fork {
                    arkret_sdk::RealmCommitId::from_digest([7; 32])
                } else {
                    first.commit().commit_id.clone()
                }),
            );
            let snapshot = frozen(&[first.clone(), second.clone()]);
            let (client, source, server) = http(vec![
                serde_json::to_value(&snapshot).unwrap(),
                serde_json::json!({
                "committed_events":[first,second],"readable_floor":{"oldest_position":0,
                "floor_commit_id":first.commit().commit_id,"floor_reason":"stream_start"},"truncated":false}),
            ]);
            let bound = client.snapshot_head(&snapshot.realm_id).await.unwrap();
            let stream = snapshot.visible_stream_heads[0].stream_ref.clone();
            let result = replay(&client, &snapshot.realm_id, &stream, &bound, None).await;
            assert_eq!(result.is_ok(), !fork);
            if let Ok((replica, pages)) = result {
                assert_eq!(replica.head(&stream), snapshot.visible_stream_heads.first());
                assert_eq!(
                    pages
                        .iter()
                        .map(|page| page.rows().unwrap().len())
                        .sum::<usize>(),
                    2
                );
                let mut store = crate::state::isolated_store_for_tests("own-live-prefix-source");
                store
                    .switch_active_account(
                        &crate::test_support::AccountFixture::new("did:web:alice.example")
                            .station("ak:did_core:web:station.example")
                            .build(),
                    )
                    .unwrap();
                store
                    .stage_own_station_commit_stream_checkpoint(&client, &replica, &stream, &pages)
                    .unwrap();
                let saved = store.verified_commit_stream_cursor(&stream).unwrap();
                assert_eq!(saved.as_ref(), replica.head(&stream));
                // The HTTP fixture served its only snapshot and original page.
                // Reusing an admitted same-session head must require no new read.
                let (idle_replica, idle_pages) = replay_with_admitted_replica(
                    &client,
                    &snapshot.realm_id,
                    &stream,
                    &bound,
                    saved.as_ref(),
                    replica.clone(),
                )
                .await
                .unwrap();
                assert!(idle_pages.is_empty());
                assert_eq!(idle_replica.head(&stream), saved.as_ref());
                let old = source.0.lock().unwrap().clone();
                for replace_provider in [false, true] {
                    *source.0.lock().unwrap() = OwnStationSessionSnapshot::new(
                        old.binding().clone(),
                        old.account_id().clone(),
                        old.binding().service_id.clone(),
                        old.grant_id().clone(),
                        if replace_provider {
                            old.epoch()
                        } else {
                            old.epoch() + 2
                        },
                        "test-grant".into(),
                    )
                    .unwrap()
                    .with_provider_identity(Default::default());
                    assert!(pages[0].rows().is_err());
                    assert!(
                        replay_with_admitted_replica(
                            &client,
                            &snapshot.realm_id,
                            &stream,
                            &bound,
                            saved.as_ref(),
                            idle_replica.clone(),
                        )
                        .await
                        .is_err()
                    );
                    assert!(
                        store
                            .stage_own_station_commit_stream_checkpoint(
                                &client, &replica, &stream, &pages
                            )
                            .is_err()
                    );
                    assert_eq!(store.verified_commit_stream_cursor(&stream).unwrap(), saved);
                }
            }
            server.join().unwrap();
        }
    }
}
