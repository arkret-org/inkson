use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct TimelineProjectionBasis {
    state: ClientLocalState,
    current: Option<crate::current_projection::RealmCurrentView>,
}

#[cfg(test)]
thread_local! {
    pub(super) static WEAVE_HEAD_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static ORDINARY_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn use_ordinary_timeline_projection(
    state_store: SyncSignal<LocalStateStore>,
    basis: Memo<TimelineProjectionBasis>,
    messages: Signal<Vec<ChatMessage>>,
    principal: String,
    authority: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    evidence_epoch: u64,
) -> Memo<Vec<ChatMessage>> {
    use_memo(use_reactive(
        (&principal, &authority, &device, &evidence_epoch),
        move |(principal, authority, device, _)| {
            #[cfg(test)]
            ORDINARY_BUILDS.with(|count| count.set(count.get() + 1));
            let local_rows = messages.read();
            let store = state_store.peek();
            let snapshot = basis.read();
            let identity = Some((&authority, principal.as_str(), &device));
            let mut folded = fold_local_state_into_chat_messages_with_sidecar(
                verified_scope_timeline_seed(local_rows.as_slice()),
                &snapshot.state,
                Some(&store),
                identity,
            );
            merge_chat_messages(
                &mut folded,
                chat_messages_from_sync_realms_with_sidecar(
                    &snapshot.state.realm_tree_projections,
                    Some(&store),
                    identity,
                ),
            );
            position_local_timeline_rows(folded)
        },
    ))
}

/// Keep all security and content inputs, including receive overlays. Opaque
/// resume tokens and delivery bookkeeping do not change a displayed message.
/// Comparing this disposable snapshot prevents unrelated writes from repeating
/// the cryptographic history fold while observing local accepted Events directly.
pub(super) fn use_timeline_projection_basis(
    state_store: SyncSignal<LocalStateStore>,
    realm_live_epoch: Signal<u64>,
) -> Memo<TimelineProjectionBasis> {
    use_memo(move || {
        let _ = realm_live_epoch();
        let store = state_store.read();
        let mut state = store.load();
        state.sync_cursor = None;
        state.commit_stream_cursors.clear();
        state.device_message_cursors.clear();
        state.client_core_pending_deliveries.clear();
        state.client_core_next_delivery_id = 0;
        state.client_core_seen_event_ids.clear();
        state.presence_projection.clear();
        state.notification_projection.clear();
        state.notification_client_state.clear();
        state.read_cursors.clear();
        TimelineProjectionBasis {
            state,
            current: store.current_product_view(),
        }
    })
}

/// Merge display heads only: neither wall clocks nor Event IDs may reverse the
/// accepted order within an ordinary or native Sidecar stream. Explicit source
/// anchors remain lower bounds, rather than pinning every private row forever
/// behind future ordinary messages.
pub(super) fn interleave_private_timeline_rows(
    rows: Vec<ChatMessage>,
    projections: &std::collections::BTreeMap<String, &arkret_sdk::AgentSidecarExchangeProjection>,
) -> Vec<ChatMessage> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    let mut ordinary = VecDeque::new();
    let mut private = BTreeMap::<String, VecDeque<ChatMessage>>::new();
    for row in rows {
        if let Some(projection) = projections.get(&row.id) {
            private
                .entry(projection.sidecar_id.to_string())
                .or_default()
                .push_back(row);
        } else {
            ordinary.push_back(row);
        }
    }
    let mut shown_source_ids = BTreeSet::new();
    let mut available = BTreeSet::new();
    let mut blocked = BTreeMap::<String, Vec<String>>::new();
    let mut pending_heads = private.keys().cloned().collect::<VecDeque<_>>();
    let mut merged = Vec::new();
    while !ordinary.is_empty() || !available.is_empty() || !pending_heads.is_empty() {
        while let Some(stream_id) = pending_heads.pop_front() {
            #[cfg(test)]
            WEAVE_HEAD_VISITS.with(|count| count.set(count.get() + 1));
            let Some(row) = private.get(&stream_id).and_then(|stream| stream.front()) else {
                continue;
            };
            let Some(projection) = projections.get(&row.id) else {
                continue;
            };
            if let Some(anchor) = projection
                .source_event_id
                .as_ref()
                .filter(|anchor| !shown_source_ids.contains(anchor.as_str()))
            {
                blocked
                    .entry(anchor.to_string())
                    .or_default()
                    .push(stream_id);
                continue;
            }
            let time = row
                .created_at
                .map(|at| at.timestamp_millis())
                .unwrap_or_else(|| projection.source_hlc.components().physical_ms as i64);
            available.insert((
                time,
                projection.source_hlc.clone(),
                projection.client_order_key.clone(),
                projection.exchange_id.to_string(),
                row.id.clone(),
                stream_id,
            ));
        }
        let private_precedes = available.first().is_some_and(|head| {
            ordinary.front().is_none_or(|row| {
                row.created_at
                    .is_some_and(|at| head.0 <= at.timestamp_millis())
            })
        });
        if private_precedes {
            let Some(head) = available.pop_first() else {
                continue;
            };
            let stream_id = head.5;
            if let Some(row) = private.get_mut(&stream_id).and_then(VecDeque::pop_front) {
                merged.push(row);
                pending_heads.push_back(stream_id);
            }
        } else if let Some(row) = ordinary.pop_front() {
            if let Some(streams) = blocked.remove(&row.id) {
                pending_heads.extend(streams);
            }
            shown_source_ids.insert(row.id.clone());
            merged.push(row);
        } else {
            // Missing anchors cannot authorize an otherwise hidden private row.
            break;
        }
    }
    merged
}
