//! Ordinary Account projection through the accepted authenticated Station.
use arkret_sdk::http_client::own_station_results::{
    BoundOwnStationResponse, OwnStationResultClient,
};
use garth::own_station_results::{OwnStationReplica, OwnStationScanPage};

use super::*;

const MAX_PREFIX_BYTES: usize = 64 * 1024 * 1024;

type SnapshotResponse =
    BoundOwnStationResponse<arkret_sdk::RealmId, arkret_sdk::RealmStateSnapshot>;

/// Read back an accepted private write without depending on a live hint rail.
/// The existing follower owns original-cut admission, complete native tails,
/// transactional current/history installation and its durable barrier.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn refresh_accepted_sidecar<F: Fn() -> bool>(
    http: &arkret_sdk::http_client::Client,
    account: &arkret_sdk::AccountId,
    request_epoch: u64,
    realm: &arkret_sdk::RealmId,
    sidecar: &arkret_sdk::SidecarId,
    event: &arkret_sdk::EventId,
    state_store: crate::runtime::input::StateStoreHandle,
    active: F,
) -> garth::Result<()> {
    if !active() {
        return Err(protocol(
            "accepted Sidecar readback belongs to a replaced session",
        ));
    }
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    require_readback_session(&client, account, request_epoch)?;
    if !active() {
        return Err(protocol(
            "accepted Sidecar readback belongs to a replaced session",
        ));
    }
    // Store writes directly invalidate the UI's exact timeline basis. This
    // local notification value lets the same follower resolve dependencies
    // without creating another app-wide epoch or persistent checkpoint.
    let revision = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    let read_revision = revision.clone();
    let write_revision = revision.clone();
    let projector = RealmIngestProjector {
        state_store,
        realm_id: realm.to_string(),
        digest_suite: realm_live_digest_suite(realm),
        realm_live_epoch: crate::runtime::input::ValueCell::new(
            move || read_revision.get(),
            move |value| write_revision.set(value),
            move |update| {
                let mut value = revision.get();
                update(&mut value);
                revision.set(value);
            },
        ),
        message_stream_hub: None,
    };
    let mut replica = OwnStationReplica::new(realm.clone());
    // The follower also checks its callback while holding the store write
    // guard. Its bound host session covers Account, Device and ABA generation
    // without re-borrowing the caller's store signal; current installation
    // additionally checks the actual account namespace in that transaction.
    let session_active = || require_readback_session(&client, account, request_epoch).is_ok();
    super::own_live::refresh_sidecars(
        &client,
        http,
        realm,
        &projector,
        &session_active,
        &mut replica,
    )
    .await?;
    require_readback_session(&client, account, request_epoch)?;
    if !active() {
        return Err(protocol(
            "accepted Sidecar readback belongs to a replaced session",
        ));
    }
    projector
        .state_store
        .read(|store| require_accepted_sidecar_event(store, account, realm, sidecar, event))
}

fn require_readback_session(
    client: &OwnStationResultClient,
    account: &arkret_sdk::AccountId,
    request_epoch: u64,
) -> garth::Result<()> {
    client.check_session()?;
    if client.session()?.account_id() != account
        || crate::identity::device_directory::session_cache_epoch() != request_epoch
    {
        return Err(protocol(
            "accepted Sidecar readback belongs to a replaced session",
        ));
    }
    Ok(())
}

fn require_accepted_sidecar_event(
    store: &crate::state::LocalStateStore,
    account: &arkret_sdk::AccountId,
    realm: &arkret_sdk::RealmId,
    sidecar: &arkret_sdk::SidecarId,
    event: &arkret_sdk::EventId,
) -> garth::Result<()> {
    let projections =
        crate::sidecar::cached_sidecar_exchange_projections(store, account, realm.as_str())
            .map_err(protocol)?;
    if !projections.iter().any(|projection| {
        projection.sidecar_id == *sidecar && projection.private_request_event_id == *event
    }) {
        return Err(protocol(
            "accepted private request is awaiting its verified native history",
        ));
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "own_station_readback_tests.rs"]
mod accepted_readback_tests;

pub(super) async fn account_frame(
    http: &arkret_sdk::http_client::Client,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> garth::Result<VerifiedAccountFrame> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let mut accepted = VerifiedAccountFrame::default();
    for (realm, entry) in frame.realms.iter().flat_map(|realms| &realms.entries) {
        let realm_id = arkret_sdk::RealmId::new(realm.clone()).map_err(protocol)?;
        let response = client.snapshot_head(&realm_id).await?;
        let mut current_replica = OwnStationReplica::new(realm_id.clone());
        current_replica.install_bound_snapshot(&response)?;
        let snapshot = response.value()?;
        validate_current_product(snapshot, &realm_id)?;
        let mut claimed = claimed_rows_by_stream(&realm_id, entry)?;
        for window in entry.streams.iter().flatten() {
            let rows = claimed.remove(&window.stream_ref).unwrap_or_default();
            let mut replica = OwnStationReplica::new(realm_id.clone());
            replica.install_bound_snapshot(&response)?;
            let pages = window_pages(&client, &realm_id, &response, &mut replica, window).await?;
            let Some(pages) = pages else {
                accepted.preview_streams.insert(window.stream_ref.clone());
                continue;
            };
            let mut scanned = Vec::new();
            for page in &pages {
                scanned.extend(page.rows()?);
            }
            require_exact_claimed_rows(&rows, &scanned)?;
            let expected = window
                .next_position
                .checked_sub(1)
                .ok_or_else(|| protocol("Account independent window has no head"))?;
            if replica.head(&window.stream_ref).is_none_or(|head| {
                head.stream_position != expected || head.commit_id != window.head_commit_ref
            }) {
                return Err(protocol(
                    "Account window differs from own Station continuous stream",
                ));
            }
            if snapshot_window_basis(window).is_some() && rows.len() != scanned.len() {
                return Err(protocol(
                    "Account snapshot tail differs from its original disclosed rows",
                ));
            }
            if window.preview_only == Some(true) {
                accepted
                    .resolved_preview_streams
                    .insert(window.stream_ref.clone());
            }
            accepted
                .own_replicas
                .insert(window.stream_ref.clone(), replica);
            accepted.own_pages.extend(pages);
        }
        if !claimed.is_empty() {
            return Err(protocol("Account originals have no independent window"));
        }
        if let Some(current) = &entry.current {
            if !snapshot_covers_account_cut(snapshot, current) {
                return Err(protocol(
                    "own Station current snapshot does not cover the Account cut",
                ));
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
                    "Account current row differs from its exact own Station snapshot",
                ));
            }
            for row in &snapshot.current_state_entries {
                if let arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::RealmGenesis,
                    value,
                    ..
                } = row
                {
                    let genesis: arkret_sdk::RealmGenesis = closed_value(value, "realm_genesis")?;
                    genesis.validate().map_err(protocol)?;
                    accepted.genesis_roles.insert(
                        realm.clone(),
                        (genesis.purpose == arkret_sdk::RealmPurpose::DirectConversation)
                            .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation),
                    );
                }
                if let arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                    value,
                    ..
                } = row
                {
                    let group: arkret_wire::MlsGroupCurrent =
                        serde_json::from_value(value.clone()).map_err(protocol)?;
                    if &group.effective_scope != scope_ref {
                        return Err(protocol("own Station MLS selector has another scope"));
                    }
                }
            }
            accepted.current_snapshots.insert(
                realm.clone(),
                VerifiedCurrentSnapshot {
                    snapshot: snapshot.clone(),
                },
            );
        }
    }
    client.check_session()?;
    accepted.own_client = Some(client);
    Ok(accepted)
}

pub(super) fn validate_current_product(
    snapshot: &arkret_sdk::RealmStateSnapshot,
    realm: &arkret_sdk::RealmId,
) -> garth::Result<()> {
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| protocol("own Station snapshot omits Realm coverage"))?;
    let rows = snapshot
        .current_state_entries
        .iter()
        .filter(|row| row_source(row) == &stream)
        .cloned()
        .collect::<Vec<_>>();
    let (object, revision) = rows
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                value,
                revision,
                ..
            } => Some((value, revision)),
            _ => None,
        })
        .ok_or_else(|| protocol("own Station complete cut omits typed Realm Genesis"))?;
    if revision.stream_position != 0 {
        return Err(protocol("typed Genesis is not at the Realm origin"));
    }
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
        .ok_or_else(|| protocol("own Station cut omits typed authority root"))?;
    let actor: arkret_sdk::ActorId = serde_json::from_value(
        root.get("controller_actor_id")
            .cloned()
            .ok_or_else(|| protocol("typed root lacks its full controller"))?,
    )
    .map_err(protocol)?;
    validate_floor_product_rows(
        realm,
        head,
        snapshot.retention_and_history_floor.history_access,
        &rows,
        revision,
        object,
        &actor,
    )
}

async fn window_pages(
    client: &OwnStationResultClient,
    realm: &arkret_sdk::RealmId,
    current: &SnapshotResponse,
    replica: &mut OwnStationReplica,
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
) -> garth::Result<Option<Vec<OwnStationScanPage>>> {
    let mut after = None;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    let basis = snapshot_window_basis(window);
    let mut floor_response = None;
    let mut dependencies = BTreeMap::new();
    if let Some(basis) = basis {
        let response = client.snapshot_by_ref(realm, &basis.snapshot_ref).await?;
        garth::own_station_results::consume_bound_snapshot(&response, realm)?;
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependencies.contains_key(&dependency.stream_ref) {
                continue;
            }
            let cap = response
                .value()?
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == dependency.stream_ref)
                .ok_or_else(|| protocol("own Station floor dependency has no covering head"))?;
            let mut dependency_replica = OwnStationReplica::new(realm.clone());
            dependency_replica.install_bound_snapshot(current)?;
            let dependency_pages = genesis_pages(
                client,
                realm,
                &dependency.stream_ref,
                cap.stream_position
                    .checked_add(1)
                    .ok_or_else(|| protocol("dependency position overflow"))?,
                &mut dependency_replica,
            )
            .await?
            .ok_or_else(|| protocol("floor dependency lacks its original readable prefix"))?;
            dependencies.insert(dependency.stream_ref.clone(), dependency_pages);
        }
        after = Some(basis.anchor_position);
        floor_response = Some(response);
    }
    loop {
        let next = after.map_or(Ok(0), |position: u64| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))
        })?;
        let remaining = window
            .next_position
            .checked_sub(next)
            .ok_or_else(|| protocol("Account window lies behind its exact basis"))?;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: window.stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)).max(1) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        let outcome = response.value()?;
        if let Some(basis) = basis {
            if let Some(snapshot) = floor_response.take() {
                let floor = outcome
                    .readable_floor
                    .as_ref()
                    .ok_or_else(|| protocol("own Station floor scan omits its floor"))?;
                replica.install_bound_floor_predecessor(
                    &window.stream_ref,
                    basis,
                    floor,
                    snapshot,
                    &dependencies,
                )?;
            }
        } else if pages.is_empty()
            && outcome
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > 0)
        {
            if window.preview_only == Some(true) {
                return Ok(None);
            }
            return Err(above_genesis_without_basis());
        }
        if remaining == 0 {
            response.value()?;
            break;
        }
        let truncated = outcome.truncated;
        let page = replica.apply_bound_scan(client, response).await?;
        let empty = page.rows()?.is_empty();
        after = replica
            .head(&window.stream_ref)
            .map(|head| head.stream_position);
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("own-Station prefix capacity overflow"))?;
        if retained_bytes > MAX_PREFIX_BYTES {
            return Err(protocol(
                "own-Station prefix exceeds bounded candidate capacity",
            ));
        }
        pages.push(page);
        if empty
            || !truncated
            || after.and_then(|position| position.checked_add(1)) == Some(window.next_position)
        {
            break;
        }
    }
    Ok(Some(pages))
}

pub(super) async fn genesis_pages(
    client: &OwnStationResultClient,
    realm: &arkret_sdk::RealmId,
    stream: &CommitStreamRef,
    end: u64,
    replica: &mut OwnStationReplica,
) -> garth::Result<Option<Vec<OwnStationScanPage>>> {
    let mut after = None;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    loop {
        let next = after.map_or(Ok(0), |position: u64| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))
        })?;
        let remaining = end
            .checked_sub(next)
            .ok_or_else(|| protocol("own stream crossed its requested prefix"))?;
        if remaining == 0 {
            break;
        }
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_sdk::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        if pages.is_empty()
            && response
                .value()?
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > 0)
        {
            return Ok(None);
        }
        let truncated = response.value()?.truncated;
        let page = replica.apply_bound_scan(client, response).await?;
        let empty = page.rows()?.is_empty();
        after = replica.head(stream).map(|head| head.stream_position);
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("own-Station prefix capacity overflow"))?;
        if retained_bytes > MAX_PREFIX_BYTES {
            return Err(protocol(
                "own-Station prefix exceeds bounded candidate capacity",
            ));
        }
        pages.push(page);
        if empty || !truncated {
            break;
        }
    }
    Ok(Some(pages))
}
