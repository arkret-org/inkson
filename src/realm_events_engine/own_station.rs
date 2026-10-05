//! Ordinary Account result consumption. Governance signatures and native
//! authority history remain the Station's admission responsibility.

use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
use garth::own_station::{OwnStationConsumer, OwnStationSnapshot};

use super::*;

pub(super) async fn authenticate(
    http: &arkret_sdk::http_client::Client,
    account: arkret_sdk::AccountId,
    epoch: u64,
) -> garth::Result<OwnStationConsumer> {
    let binding = crate::station_connection::enrolled(http.base_url().as_str())
        .await
        .map_err(protocol)?;
    OwnStationConsumer::authenticate(http.clone(), &binding, account, epoch).await
}

/// Authorized history from its actual readable floor. It cannot settle a
/// preview window or provide reconstructed current for an unreadable prefix.
pub(super) async fn readable_pages(
    consumer: &OwnStationConsumer,
    cut: &OwnStationSnapshot,
    stream: &CommitStreamRef,
) -> garth::Result<Vec<garth::VerifiedScanPage>> {
    let head = cut
        .snapshot()
        .visible_stream_heads
        .iter()
        .find(|head| &head.stream_ref == stream)
        .ok_or_else(|| protocol("readable history has no current stream cut"))?;
    let floor = consumer.readable_floor(stream.realm_id(), stream).await?;
    let mut replica = RealmReplica::new(stream.realm_id().clone());
    let mut pages = Vec::new();
    loop {
        let after = replica
            .verified_head(stream)
            .map(|head| head.stream_position);
        if after == Some(head.stream_position) {
            break;
        }
        let next = after.map_or(Ok(floor.oldest_position), |position| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("readable position overflow"))
        })?;
        let remaining = head
            .stream_position
            .checked_sub(next)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| protocol("readable floor advanced beyond the original cut"))?;
        let request = StreamScanRequest {
            realm_id: stream.realm_id().clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let page = consumer.scan(&mut replica, &request, cut).await?;
        if page.rows().is_empty() {
            return Err(protocol("readable tail does not reach original cut"));
        }
        pages.push(page);
    }
    if replica.verified_head(stream) != Some(head) {
        return Err(protocol("readable tail forks original head"));
    }
    Ok(pages)
}

pub(super) async fn follow_once<F: Fn() -> bool>(
    consumer: &OwnStationConsumer,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    projector: &RealmIngestProjector,
    ctx: &RealmEventsEngineContext,
    active: &F,
    replica: &mut RealmReplica,
) -> garth::Result<()> {
    let circles = http.circle_list(realm.as_str()).await?;
    let mut streams = followed_streams(realm, ctx, &circles)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        let page = http
            .agent_sidecar_list(Some(realm), cursor.as_deref())
            .await?;
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
    for stream in streams {
        if !active() {
            return Ok(());
        }
        drain_stream(consumer, http, realm, &stream, projector, active, replica).await?;
    }
    Ok(())
}

pub(super) async fn drain_stream<F: Fn() -> bool>(
    consumer: &OwnStationConsumer,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    projector: &RealmIngestProjector,
    active: &F,
    replica: &mut RealmReplica,
) -> garth::Result<()> {
    let cut = consumer.snapshot_head(realm).await?;
    let private_cut = matches!(stream, CommitStreamRef::Sidecar { .. });
    if !cut
        .snapshot()
        .visible_stream_heads
        .iter()
        .any(|head| &head.stream_ref == stream)
    {
        return Err(protocol("own Station cut omits followed stream"));
    }
    // A complete private current cut covers all visible Sidecar streams. Read
    // those exact heads before publishing it; a separately fetched newer cut
    // or a history-only live update cannot settle the exchange fold.
    let streams = if private_cut {
        cut.snapshot()
            .visible_stream_heads
            .iter()
            .filter(|head| matches!(head.stream_ref, CommitStreamRef::Sidecar { .. }))
            .map(|head| head.stream_ref.clone())
            .collect::<Vec<_>>()
    } else {
        vec![stream.clone()]
    };
    let mut candidate = replica.clone();
    let mut pages = Vec::new();
    let mut rows = Vec::new();
    for stream in &streams {
        if !active() {
            return Ok(());
        }
        let head = cut
            .snapshot()
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream)
            .ok_or_else(|| protocol("own Station cut omits followed stream"))?;
        let saved = projector
            .state_store
            .read(|store| store.verified_commit_stream_cursor(stream))
            .map_err(protocol)?;
        let anchor = projector
            .state_store
            .read(|store| store.verified_commit_stream_anchor(stream))
            .map_err(protocol)?;
        if candidate.verified_head(stream).is_none()
            && let (Some(saved), Some(anchor)) = (&saved, &anchor)
        {
            if anchor.stream_ref != saved.stream_ref
                || anchor.stream_position != saved.stream_position
                || anchor.commit_id != saved.commit_id
            {
                return Err(protocol(
                    "durable anchor differs from its Account stream head",
                ));
            }
            consumer.restore_anchor(&mut candidate, anchor, &cut)?;
        }
        let predecessor = candidate.verified_head(stream).cloned();
        if predecessor.is_none()
            && consumer
                .readable_floor(realm, stream)
                .await?
                .oldest_position
                > 0
        {
            // Current/head is the existing live bootstrap surface. This never
            // clears an Account historical preview or claims unavailable rows.
            consumer.bootstrap_stream(&mut candidate, stream, &cut)?;
        }
        let end = head
            .stream_position
            .checked_add(1)
            .ok_or_else(|| protocol("stream head overflow"))?;
        let (stream_pages, _) =
            scan_window(consumer, &mut candidate, &cut, stream, None, end).await?;
        let stream_pages = stream_pages.ok_or_else(above_genesis_without_basis)?;
        if candidate.verified_head(stream) != Some(head) {
            return Err(protocol("follow does not reach exact original head"));
        }
        if let Some(saved) = &saved {
            let found = stream_pages
                .iter()
                .flat_map(|page| page.rows())
                .find(|row| row.commit().stream_position == saved.stream_position);
            if predecessor.as_ref() != Some(saved)
                && found.is_none_or(|row| row.commit().commit_id != saved.commit_id)
            {
                return Err(protocol(
                    "own Station replay substitutes the durable cursor",
                ));
            }
        }
        let new_rows = stream_pages
            .iter()
            .flat_map(|page| page.rows())
            .filter(|row| {
                saved
                    .as_ref()
                    .is_none_or(|saved| row.commit().stream_position > saved.stream_position)
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.extend(new_rows);
        pages.extend(stream_pages);
    }
    let batch = committed_views_to_client_events(realm, rows)?;
    if !active() {
        return Ok(());
    }
    let changed = projector
        .state_store
        .write(|store| {
            store.verified_projection_transaction(|store| {
                let mut changed = 0;
                for page in &pages {
                    changed += store.ingest_verified_message_history(page)?;
                    crate::identity::agent_signer_evidence::index_verified_committed_page(
                        store, page,
                    )?;
                }
                changed += ingest_realm_batch(store, &projector.realm_id, &batch);
                if private_cut {
                    changed += install_followed_sidecar_current(
                        store,
                        &VerifiedCurrentSnapshot {
                            snapshot: cut.snapshot().clone(),
                        },
                    )?;
                }
                for stream in &streams {
                    if candidate.verified_anchor(stream).is_some() {
                        store.stage_verified_commit_stream_checkpoint(&candidate, stream)?;
                    }
                }
                Ok(changed)
            })
        })
        .map_err(protocol)?;
    projector
        .state_store
        .read(|store| store.begin_durable_flush())
        .map_err(protocol)?
        .wait()
        .await
        .map_err(protocol)?;
    if !active() {
        return Ok(());
    }
    candidate.release_verified_rows();
    *replica = candidate;
    // New message rows may introduce Agent candidates. Resolve their evidence
    // even when the product fold already requires a timeline invalidation.
    if resolve_stream_projection_dependencies(http, &projector.state_store, changed > 0).await? {
        projector
            .realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
    Ok(())
}

/// Called inside the history/checkpoint transaction so readers never observe
/// a live Sidecar suffix paired with a different signed current cut.
pub(super) fn install_followed_sidecar_current(
    store: &mut crate::state::LocalStateStore,
    proof: &VerifiedCurrentSnapshot,
) -> Result<usize, String> {
    let changed = store.install_verified_sidecar_current(proof)?;
    store
        .verified_sidecar_inputs(proof.snapshot().realm_id.as_str())
        .map_err(|error| format!("followed Sidecar cut is incomplete: {error:#}"))?;
    Ok(changed)
}

/// The host fences the full Account and request epoch before durable projection.
pub(crate) async fn consume_account_frame(
    consumer: &OwnStationConsumer,
    frame: &AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    let mut accepted = VerifiedAccountFrame::default();
    for (name, entry) in frame.realms.iter().flat_map(|realms| &realms.entries) {
        let realm = arkret_sdk::RealmId::new(name.clone()).map_err(protocol)?;
        let mut claimed = claimed_rows_by_stream(&realm, entry)?;
        if entry.current.is_none()
            && entry.streams.as_ref().is_none_or(Vec::is_empty)
            && claimed.is_empty()
        {
            // An identity-only Account container conveys no collaboration
            // current or historical window to install. In particular a PCR
            // holder is not a joined Collaboration Realm member. This grants
            // no baseline, history, writable current or preview resolution.
            continue;
        }
        let cut = consumer.snapshot_head(&realm).await.map_err(|error| {
            tracing::warn!(realm = %realm, has_current = entry.current.is_some(), windows = entry.streams.as_ref().map_or(0, Vec::len), claimed_streams = claimed.len(), reason = %error, "own Station Account snapshot read failed");
            error
        })?;
        let snapshot = cut.snapshot();
        let mut replica = RealmReplica::new(realm.clone());
        let mut exact = BTreeSet::new();
        let mut unsettled = BTreeSet::new();
        let mut floors = Vec::new();
        for window in entry.streams.iter().flatten() {
            let rows = claimed.remove(&window.stream_ref).unwrap_or_default();
            let (pages, floor) = scan_window(
                consumer,
                &mut replica,
                &cut,
                &window.stream_ref,
                snapshot_window_basis(window),
                window.next_position,
            )
            .await?;
            let Some(pages) = pages else {
                if window.preview_only != Some(true) {
                    return Err(above_genesis_without_basis());
                }
                accepted.preview_streams.insert(window.stream_ref.clone());
                unsettled.insert(window.stream_ref.clone());
                continue;
            };
            let scanned = pages
                .iter()
                .flat_map(|page| page.rows())
                .collect::<Vec<_>>();
            require_exact_claimed_rows(&rows, &scanned)?;
            if let Some(basis) = snapshot_window_basis(window) {
                require_window_start_row(basis, &scanned)?;
                if rows.len() != scanned.len() {
                    return Err(protocol("Account window differs from its exact floor tail"));
                }
                require_verified_window_head(window, &replica)?;
            } else {
                require_exact_window_head(window, &scanned)?;
            }
            if window.preview_only == Some(true) {
                accepted
                    .resolved_preview_streams
                    .insert(window.stream_ref.clone());
            }
            exact.insert(window.stream_ref.clone());
            accepted.pages.extend(pages);
            if let Some(floor) = floor {
                floors.push(floor);
            }
        }
        if !floors.is_empty() {
            let current = entry
                .current
                .as_ref()
                .ok_or_else(|| protocol("floor has no Account cut"))?;
            // A newer independently fetched head may cover an older frame;
            // the frame's generation is checked against its exact floor/tail.
            require_floor_current_cut(
                current,
                &floors.iter().collect::<Vec<_>>(),
                current.governance_generation,
                &replica,
                entry,
                &exact,
                &unsettled,
            )?;
        }
        for floor in &floors {
            if matches!(floor.head().stream_ref, CommitStreamRef::Realm { .. }) {
                validate_current_rows(&realm, floor.head(), floor.history_access(), floor.rows())?;
            }
        }
        retain_genesis(&mut accepted, snapshot)?;
        let Some(current) = &entry.current else {
            continue;
        };
        if !snapshot_covers_account_cut(snapshot, current) {
            tracing::warn!("own Station snapshot does not yet cover Account window");
            continue;
        }
        let same_cut = current.governance_generation == snapshot.governance_generation
            && current.stream_heads.len() == snapshot.visible_stream_heads.len()
            && current
                .stream_heads
                .iter()
                .all(|head| snapshot.visible_stream_heads.contains(head));
        if same_cut
            && !current
                .entries
                .iter()
                .all(|row| snapshot.current_state_entries.contains(row))
        {
            return Err(protocol(
                "Account current differs from the original same-cut snapshot",
            ));
        }
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == realm_stream)
            .ok_or_else(|| protocol("current snapshot omits Realm head"))?;
        let realm_rows = snapshot
            .current_state_entries
            .iter()
            .filter(|row| row_source(row) == &realm_stream)
            .cloned()
            .collect::<Vec<_>>();
        validate_current_rows(
            &realm,
            head,
            snapshot.retention_and_history_floor.history_access,
            &realm_rows,
        )?;
        for row in &snapshot.current_state_entries {
            if let arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } = row
            {
                let group: arkret_wire::MlsGroupCurrent = closed_value(value, "mls_group")?;
                if &group.effective_scope != scope_ref {
                    return Err(protocol("MLS current scope differs from selector"));
                }
            }
        }
        accepted.current_snapshots.insert(
            name.clone(),
            VerifiedCurrentSnapshot {
                snapshot: snapshot.clone(),
            },
        );
    }
    Ok(accepted)
}

fn genesis_rows(
    rows: &[arkret_wire::TypedCurrentResult],
) -> garth::Result<(
    &arkret_wire::CurrentRevision,
    &serde_json::Value,
    arkret_sdk::ActorId,
)> {
    let genesis = rows
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                revision,
                value,
                ..
            } => Some((revision, value)),
            _ => None,
        })
        .ok_or_else(|| protocol("original current omits immutable Realm genesis"))?;
    let root = rows
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .ok_or_else(|| protocol("original current omits matching authority root"))?;
    let root: arkret_wire::RealmAuthorityRootValue = closed_value(root, "realm_authority_root")?;
    root.validate().map_err(protocol)?;
    Ok((genesis.0, genesis.1, root.controller_actor_id))
}

fn validate_current_rows(
    realm: &arkret_sdk::RealmId,
    head: &arkret_wire::CommitStreamHead,
    history: arkret_sdk::HistoryAccess,
    rows: &[arkret_wire::TypedCurrentResult],
) -> garth::Result<()> {
    let (revision, value, founder) = genesis_rows(rows)?;
    validate_floor_rows_at_genesis(realm, head, history, rows, revision, value, &founder)
}

fn retain_genesis(
    accepted: &mut VerifiedAccountFrame,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> garth::Result<()> {
    let (revision, value, _) = genesis_rows(&snapshot.current_state_entries)?;
    let genesis: arkret_sdk::RealmGenesis = closed_value(value, "realm_genesis")?;
    genesis.validate().map_err(protocol)?;
    accepted.genesis_roles.insert(
        snapshot.realm_id.to_string(),
        (genesis.purpose == arkret_sdk::RealmPurpose::DirectConversation)
            .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation),
    );
    // Higher-generation admin bases require the original accepted change,
    // never a retained signature kid or a fabricated history chain.
    if snapshot.governance_generation == 0 {
        accepted
            .authority_bases
            .push(crate::state::PersistedRealmAuthorityBasis {
                realm_id: snapshot.realm_id.clone(),
                current_service_id: genesis.governance_station_id,
                current_generation: 0,
                genesis_ref: arkret_wire::CommittedEventRef {
                    event_id: snapshot.realm_id.event_id(),
                    commit_id: revision.commit_id.clone(),
                    stream_ref: CommitStreamRef::Realm {
                        realm_id: snapshot.realm_id.clone(),
                    },
                    stream_position: 0,
                },
                last_authority_change_ref: None,
                validated_at: chrono::Utc::now(),
            });
    }
    Ok(())
}

async fn scan_window(
    consumer: &OwnStationConsumer,
    replica: &mut RealmReplica,
    cut: &OwnStationSnapshot,
    stream: &CommitStreamRef,
    basis: Option<&StreamWindowStartBasis>,
    end: u64,
) -> garth::Result<(
    Option<Vec<garth::VerifiedScanPage>>,
    Option<garth::VerifiedFloorSnapshot>,
)> {
    let realm = stream.realm_id();
    let floor = consumer.readable_floor(realm, stream).await?;
    let mut predecessor = None;
    if let Some(basis) = basis {
        let anchor = consumer.exact_snapshot(realm, &basis.snapshot_ref).await?;
        let mut dependencies = BTreeMap::new();
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependencies.contains_key(&dependency.stream_ref) {
                continue;
            }
            let head = anchor
                .snapshot()
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == dependency.stream_ref)
                .ok_or_else(|| protocol("floor dependency has no original head"))?;
            let mut replay = RealmReplica::new(realm.clone());
            let (pages, _) = Box::pin(scan_window(
                consumer,
                &mut replay,
                &anchor,
                &dependency.stream_ref,
                None,
                head.stream_position
                    .checked_add(1)
                    .ok_or_else(|| protocol("dependency head overflow"))?,
            ))
            .await?;
            let pages = pages.ok_or_else(above_genesis_without_basis)?;
            if replay.verified_head(&dependency.stream_ref) != Some(head) {
                return Err(protocol("dependency does not reach exact original head"));
            }
            dependencies.insert(dependency.stream_ref.clone(), pages);
        }
        predecessor = Some(consumer.install_window_floor(
            replica,
            stream,
            basis,
            &floor,
            &anchor,
            &dependencies,
        )?);
    } else if replica.verified_head(stream).is_none() && floor.oldest_position > 0 {
        return Ok((None, None));
    }
    let mut pages = Vec::new();
    loop {
        let after = replica
            .verified_head(stream)
            .map(|head| head.stream_position);
        let next = after.map_or(Ok(0), |position| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))
        })?;
        if next == end {
            break;
        }
        let remaining = end
            .checked_sub(next)
            .ok_or_else(|| protocol("floor lies beyond Account window head"))?;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let page = consumer.scan(replica, &request, cut).await?;
        if page.rows().is_empty() {
            return Err(protocol("original scan ended before Account window head"));
        }
        pages.push(page);
    }
    Ok((Some(pages), predecessor))
}
