//! Ordinary live projection consumes bound own-Station originals. Subscription
//! frames are hints; only the independent admitted stream scan moves a cursor.
use arkret_sdk::http_client::own_station_results::OwnStationResultClient;
use garth::own_station_results::{OwnStationReplica, OwnStationScanPage};

use super::*;

const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;

pub(super) async fn subscription<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    ctx: &RealmEventsEngineContext,
    is_active: &F,
    current: &mut OwnStationReplica,
    resume: &mut Option<String>,
) -> garth::Result<()> {
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind as Kind;
    client.check_session()?;
    let mut stream = crate::transport::websocket_rail::CommittedRailSource::open(
        http,
        &ctx.websocket_rail,
        realm.clone(),
        resume.clone(),
    )
    .await?;
    client.check_session()?;
    if resume.is_none() {
        follow_once(client, http, realm, projector, ctx, is_active, current).await?;
    }
    while is_active() {
        client.check_session()?;
        let frame = loop {
            use futures_util::future::{Either, select};
            match select(
                Box::pin(stream.next_frame()),
                Box::pin(crate::runtime_helpers::sleep_for(SUBSCRIBE_CANCEL_POLL)),
            )
            .await
            {
                Either::Left((frame, _)) => break frame?,
                Either::Right(_) if !is_active() => return Ok(()),
                Either::Right(_) => {
                    client.check_session()?;
                    if projector
                        .state_store
                        .read(|s| s.has_pending_sidecar_history(realm.as_str()))
                    {
                        refresh_sidecars(client, http, realm, projector, is_active, current)
                            .await?;
                    }
                }
            }
        };
        client.check_session()?;
        let Some(frame) = frame else {
            return Ok(());
        };
        if let Some(view) = frame.committed_event() {
            if view.commit().stream_ref.realm_id() != realm {
                return Err(protocol("subscription names another Realm"));
            }
            drain(
                client,
                http,
                realm,
                &view.commit().stream_ref,
                projector,
                is_active,
                current,
            )
            .await?;
            if matches!(view.commit().stream_ref, CommitStreamRef::Sidecar { .. }) {
                refresh_sidecars(client, http, realm, projector, is_active, current).await?;
            }
            if matches!(view, CommittedEventView::Full(full) if matches!(full.event.kind,
                arkret_sdk::EventKind::CircleCreate | arkret_sdk::EventKind::CircleMemberState | arkret_sdk::EventKind::MemberState | arkret_sdk::EventKind::InviteAccept | arkret_sdk::EventKind::SidecarCreate | arkret_sdk::EventKind::SidecarContextAttach))
            {
                follow_once(client, http, realm, projector, ctx, is_active, current).await?;
            }
        }
        match frame.kind {
            Kind::ResyncRequired => {
                *resume = None;
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
            *resume = Some(cursor);
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
    ctx: &RealmEventsEngineContext,
    is_active: &F,
    current: &mut OwnStationReplica,
) -> garth::Result<()> {
    client.check_session()?;
    let circles = http.circle_list(realm.as_str()).await?;
    client.check_session()?;
    let mut streams = followed_streams(realm, ctx, &circles)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        let page = http
            .agent_sidecar_list(Some(realm), cursor.as_deref())
            .await?;
        client.check_session()?;
        for view in page.sidecars {
            view.validate()?;
            if view.sidecar.realm_id != *realm {
                return Err(protocol("Sidecar directory crosses Realm"));
            }
            if view.sidecar.state != arkret_sdk::AgentSidecarState::Tombstoned {
                streams.insert(CommitStreamRef::Sidecar {
                    realm_id: realm.clone(),
                    sidecar_id: view.sidecar.id,
                });
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        if !seen.insert(next.to_string()) || seen.len() > 128 {
            return Err(protocol("Sidecar pagination did not terminate"));
        }
        cursor = Some(next.to_string());
    }
    let private = streams
        .iter()
        .any(|s| matches!(s, CommitStreamRef::Sidecar { .. }));
    for stream in streams {
        if !is_active() {
            return Ok(());
        }
        drain(client, http, realm, &stream, projector, is_active, current).await?;
    }
    if private && is_active() {
        refresh_sidecars(client, http, realm, projector, is_active, current).await?;
    }
    Ok(())
}

async fn replay(
    client: &OwnStationResultClient,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    snapshot: &CreatorOwnSnapshot,
    saved: Option<&arkret_sdk::CommitStreamHead>,
) -> garth::Result<(OwnStationReplica, Vec<OwnStationScanPage>)> {
    let mut replica = OwnStationReplica::new(realm.clone());
    replica.install_bound_snapshot(snapshot)?;
    let cap = snapshot
        .value()?
        .visible_stream_heads
        .iter()
        .find(|h| &h.stream_ref == stream)
        .ok_or_else(|| protocol("own-Station current omits the followed stream"))?;
    if let Some(saved) = saved {
        if saved.stream_position > cap.stream_position
            || (saved.stream_position == cap.stream_position && saved.commit_id != cap.commit_id)
        {
            return Err(protocol(
                "current cut regresses or forks the durable stream",
            ));
        }
        replica.restore_checkpoint_head(client, saved).await?;
    }
    let mut after = saved.map(|h| h.stream_position);
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    while after != Some(cap.stream_position) {
        let next = after.map_or(Ok(0), |p| {
            p.checked_add(1).ok_or_else(|| protocol("stream overflow"))
        })?;
        let remaining = cap
            .stream_position
            .checked_add(1)
            .and_then(|end| end.checked_sub(next))
            .ok_or_else(|| protocol("stream exceeded frozen cut"))?;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        if after.is_none()
            && response
                .value()?
                .readable_floor
                .as_ref()
                .is_some_and(|f| f.oldest_position > 0)
        {
            // A preview floor is not a replay anchor. Account-window ingestion
            // must first persist the genuine exact snapshot-basis prefix.
            return Err(protocol(
                "live stream awaits an admitted Account window basis",
            ));
        }
        let page = replica.apply_bound_scan(client, response).await?;
        if page.rows()?.is_empty() {
            return Err(protocol("own-Station scan ended before its frozen head"));
        }
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("live replay capacity overflow"))?;
        if retained_bytes > MAX_REPLAY_BYTES {
            return Err(protocol("live replay exceeds bounded candidate capacity"));
        }
        after = replica.head(stream).map(|h| h.stream_position);
        pages.push(page);
    }
    if replica.head(stream) != Some(cap) {
        return Err(protocol(
            "own-Station replay does not reach the frozen head",
        ));
    }
    Ok((replica, pages))
}

async fn drain<F: Fn() -> bool>(
    client: &OwnStationResultClient,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    projector: &RealmIngestProjector,
    is_active: &F,
    current: &mut OwnStationReplica,
) -> garth::Result<()> {
    let snapshot = client.snapshot_head(realm).await?;
    current.install_bound_snapshot(&snapshot)?;
    own_station::validate_current_product(snapshot.value()?, realm)?;
    let saved = projector
        .state_store
        .read(|s| s.verified_commit_stream_cursor(stream))
        .map_err(protocol)?;
    let (replica, pages) = replay(client, realm, stream, &snapshot, saved.as_ref()).await?;
    let mut rows = Vec::new();
    for page in &pages {
        rows.extend(page.rows()?.iter().cloned());
    }
    let batch = committed_views_to_client_events(realm, rows)?;
    if !is_active() {
        return Ok(());
    }
    client.check_session()?;
    let (changed, _) = install_live_current_snapshot(
        client, &snapshot, realm, stream, projector, &replica, &pages, &batch, is_active,
    )
    .await?;
    let evidence = resolve_stream_agent_keys(http, &projector.state_store, changed > 0).await?;
    client.check_session()?;
    if !is_active() {
        return Ok(());
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
    if changed > 0 || evidence || batch.iter().any(|e| matches!(e, ClientEvent::Event(e) if e.kind == arkret_sdk::EventKind::AgentInteractionSet)) {
        projector.realm_live_epoch.update(|v| *v = v.wrapping_add(1));
    }
    Ok(())
}

/// Install real live history and its current original at one durable pointer;
/// the Account cursor is deliberately outside this independent transaction.
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
) -> garth::Result<(usize, bool)> {
    let account = snapshot.session().account_id().clone();
    let source_guard = || -> anyhow::Result<()> {
        anyhow::ensure!(is_active(), "live current route ended");
        snapshot.value()?;
        Ok(())
    };
    let guard = || -> anyhow::Result<()> {
        source_guard()?;
        anyhow::ensure!(
            projector.state_store.read(|store| store.active_authority()) == Some(account.clone()),
            "live current account changed"
        );
        Ok(())
    };
    guard().map_err(protocol)?;
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
    .map_err(protocol)?;
    guard().map_err(protocol)?;
    let generation = projector
        .state_store
        .read(|store| store.current_generation());
    if index.is_poisoned() {
        confirm_live_current_pointer(&index, &projector.state_store, &account, generation)
            .await
            .map_err(protocol)?;
        guard().map_err(protocol)?;
    }
    let mut stage = index
        .stage_own_station_snapshot(generation, &snapshot, &guard)
        .await
        .map_err(crate::state::current_index::current_stage_error)?;
    guard().map_err(protocol)?;
    let current_changed = stage.changed();
    let transaction = projector.state_store.write(|store| {
        store.verified_projection_transaction(|store| {
            source_guard().map_err(|error| error.to_string())?;
            if store.active_authority() != Some(account.clone()) {
                return Err("live current account changed before transaction".into());
            }
            let mut changed = 0;
            for page in pages {
                changed += store.ingest_verified_message_history(page)?;
                crate::identity::agent_signer_evidence::index_verified_committed_page(store, page)?;
            }
            changed += ingest_realm_batch(store, &projector.realm_id, &batch);
            store.stage_own_station_commit_stream_checkpoint(client, &replica, stream, &pages)?;
            store.install_own_station_sidecar_current(&snapshot)?;
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
                .map_err(protocol)?;
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
            .map_err(protocol)?;
        return Err(protocol(error));
    }
    // A late response from an ended provider may not publish a shared pointer.
    // A mere navigation change can retain the already durable original while
    // its view publication is suppressed by the route guard below.
    if let Err(error) = snapshot.value() {
        rollback_live_current_pointer(&index, &projector.state_store, &account, generation)
            .await
            .map_err(protocol)?;
        return Err(protocol(error));
    }
    if projector.state_store.read(|store| store.active_authority()) != Some(account.clone()) {
        index.poison();
        return Err(protocol("live current account ended before publication"));
    }
    stage.finish();
    guard().map_err(protocol)?;
    crate::sync_engine::publish_current_product_view(
        &index,
        &projector.state_store,
        &account,
        realm.as_str(),
        &source_guard,
    )
    .await
    .map_err(protocol)?;
    guard().map_err(protocol)?;
    if current_changed {
        projector
            .realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
    Ok((changed, current_changed))
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
    let snapshot = client.snapshot_head(realm).await?;
    current.install_bound_snapshot(&snapshot)?;
    own_station::validate_current_product(snapshot.value()?, realm)?;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    let frozen = snapshot.value()?;
    if projector
        .state_store
        .read(|s| s.sidecar_history_at_snapshot(frozen).is_err())
    {
        for head in &snapshot.value()?.visible_stream_heads {
            if !matches!(head.stream_ref, CommitStreamRef::Sidecar { .. }) {
                continue;
            }
            let mut replica = OwnStationReplica::new(realm.clone());
            replica.install_bound_snapshot(&snapshot)?;
            let end = head
                .stream_position
                .checked_add(1)
                .ok_or_else(|| protocol("Sidecar head overflow"))?;
            let recovered =
                own_station::genesis_pages(client, realm, &head.stream_ref, end, &mut replica)
                    .await?
                    .ok_or_else(|| protocol("Sidecar native history is below readable floor"))?;
            if replica.head(&head.stream_ref) != Some(head) {
                return Err(protocol("Sidecar history has not reached exact current"));
            }
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
    }
    if !is_active() {
        return Ok(());
    }
    client.check_session()?;
    let changed = projector
        .state_store
        .write(|store| {
            store.verified_projection_transaction(|store| {
                if !is_active() {
                    return Err("private route ended before projection".into());
                }
                client.check_session().map_err(|e| e.to_string())?;
                let mut changed = 0;
                for page in &pages {
                    changed += store.ingest_verified_message_history(page)?;
                    crate::identity::agent_signer_evidence::index_verified_committed_page(
                        store, page,
                    )?;
                }
                store
                    .sidecar_history_at_snapshot(snapshot.value().map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                changed += store.install_own_station_sidecar_current(&snapshot)?;
                Ok(changed)
            })
        })
        .map_err(protocol)?;
    projector
        .state_store
        .read(|s| s.begin_durable_flush())
        .map_err(protocol)?
        .wait()
        .await
        .map_err(protocol)?;
    client.check_session()?;
    if !is_active() {
        return Ok(());
    }
    let evidence = resolve_stream_agent_keys(http, &projector.state_store, changed > 0).await?;
    client.check_session()?;
    if !is_active() {
        return Ok(());
    }
    if changed > 0 || evidence {
        projector
            .realm_live_epoch
            .update(|v| *v = v.wrapping_add(1));
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use arkret_sdk::http_client::own_station_results::{
        OwnStationSessionSnapshot, OwnStationSessionSource,
    };

    use super::*;

    struct Source(Mutex<OwnStationSessionSnapshot>);
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
                &arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        commit =
            crate::test_support::committed_event::FixtureStation::did_web().seal_commit(commit);
        serde_json::from_value(
            serde_json::json!({"commit":commit,"event_disclosure":{"status":"withheld"}}),
        )
        .unwrap()
    }

    fn frozen(rows: &[CommittedEventView]) -> arkret_sdk::RealmStateSnapshot {
        let last = rows.last().unwrap().commit();
        let mut snapshot = arkret_sdk::RealmStateSnapshot {
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
                &arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
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
            for (index, body) in bodies.into_iter().enumerate() {
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
                if index > 0 {
                    assert!(headers.starts_with("post /_arkret/self/streams/scan "));
                    let request: StreamScanRequest =
                        serde_json::from_slice(&bytes[end..end + len]).unwrap();
                    if let Some(head) = &exact_checkpoint {
                        assert_eq!(request.realm_id, request.stream_ref.realm_id().clone());
                        assert_eq!(request.stream_ref, head.stream_ref);
                        assert_eq!(request.limit, 1);
                        assert_eq!(
                            request.direction,
                            arkret_sdk::StreamScanDirection::Before(Some(head.stream_position + 1))
                        );
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
                .push(arkret_sdk::TypedCurrentResult::Value {
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

    fn seal_current_snapshot(snapshot: &mut arkret_sdk::RealmStateSnapshot) {
        let mut body = serde_json::to_value(&*snapshot).unwrap();
        body.as_object_mut().unwrap().remove("snapshot_id");
        body.as_object_mut().unwrap().remove("signature");
        snapshot.snapshot_id =
            arkret_sdk::RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
                &arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        crate::test_support::committed_event::FixtureStation::did_web().sign_snapshot(snapshot);
    }

    fn test_projector(
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
                    &|| false
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
            )
            .await
            .unwrap();
            assert!(current_changed);
            assert_eq!(projector.realm_live_epoch.get(), chat_count as u64);
            let _ = changed;
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
            drop(local);
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
        let mut initial = current_snapshot(&[first.clone()], 1);
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
        // switch_active_account also persists the previous anonymous namespace.
        // Select the actual durable account blob by the public marker written
        // above, rather than whichever matching filename read_dir returns first.
        let account_files = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("failure.account.")
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
            })
            .filter(|path| {
                let state: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                state.get("sync_cursor").and_then(serde_json::Value::as_str)
                    == Some("ak:cursor:retained")
            })
            .collect::<Vec<_>>();
        assert_eq!(account_files.len(), 1);
        let account_file = account_files.into_iter().next().unwrap();
        let backup = account_file.with_extension("saved");
        std::fs::rename(&account_file, &backup).unwrap();
        std::fs::create_dir(&account_file).unwrap();
        let io_failure = match projector
            .state_store
            .read(|store| store.begin_durable_flush())
        {
            Err(error) => error,
            Ok(_) => panic!("the active account file must fail its real durable write"),
        };
        assert!(io_failure.downcast_ref::<std::io::Error>().is_some());
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
                &|| true
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
        let index = crate::state::CurrentIndex::open_committed(
            &account.authority,
            store.lock().unwrap().current_index_location(),
            || Ok(0),
        )
        .await
        .unwrap();
        assert!(index.is_poisoned());
        assert!(
            index
                .read_selector_ready(
                    snapshot.realm_id.as_str(),
                    &arkret_sdk::CurrentSelector::RealmProfile
                )
                .await
                .is_err()
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
                .is_err()
        );
        std::fs::remove_dir(&account_file).unwrap();
        std::fs::rename(&backup, &account_file).unwrap();
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
