use arkret_sdk::{
    AccountBaselineChannel as Channel, AccountSubscribeFrame, Event, RealmListItem,
    RealmListMembership, SyncFilter,
};
use arkret_wire::Cursor;

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct DemandSyncState {
    filter: Option<SyncFilter>,
    list_after: Option<Cursor>,
    requested_list_after: Option<Cursor>,
    list_snapshot: Option<Cursor>,
    list_revision: u64,
    list_complete: bool,
    list_seen: BTreeSet<String>,
    summaries: BTreeMap<String, RealmListItem>,
    summary_removals: BTreeMap<String, u64>,
    global_snapshot: Option<Cursor>,
    channels: BTreeMap<Channel, BaselineChannelState>,
    account_events: BTreeMap<String, Event>,
    device_ids: BTreeSet<String>,
    cas_removals: BTreeMap<String, u64>,
    details: BTreeMap<String, DetailState>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct BaselineChannelState {
    seen: BTreeSet<String>,
    mutated: BTreeSet<String>,
    complete: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct DetailState {
    snapshot: Option<Cursor>,
    invalidated_snapshot: Option<Cursor>,
    invalidation_revision: u64,
    invalidated: bool,
    complete: bool,
}

impl DemandSyncState {
    fn accepts(&mut self, channel: Channel, key: &str, baseline: bool) -> bool {
        let Some(state) = self.channels.get_mut(&channel) else {
            return true;
        };
        if baseline {
            state.seen.insert(key.to_owned());
            !state.complete && !state.mutated.contains(key)
        } else {
            if !state.complete {
                state.mutated.insert(key.to_owned());
            }
            true
        }
    }
    fn retained(&self, channel: Channel, key: &str) -> bool {
        self.channels
            .get(&channel)
            .is_some_and(|state| state.seen.contains(key) || state.mutated.contains(key))
    }
}

impl LocalStateStore {
    pub(crate) fn local_device_refresh_pending(&self) -> bool {
        self.cached.local_device_refresh_pending
    }

    pub(crate) fn set_local_device_refresh_pending(&mut self, pending: bool) {
        self.ensure_cached_loaded();
        if self.cached.local_device_refresh_pending != pending {
            self.cached.local_device_refresh_pending = pending;
            let _ = self.flush();
        }
    }

    /// Invalidate a partially applied frame before a coalesced batch can persist it.
    /// A fresh baseline repairs derived caches without copying the account history.
    pub(crate) fn abort_account_demand_frame(&mut self, generation: u64) {
        self.reset_account_demand_progress();
        self.cached.current_reset_required = true;
        self.clear_sync_cursor();
        self.set_current_generation(generation);
    }

    pub(crate) fn reset_account_demand_progress(&mut self) {
        self.ensure_cached_loaded();
        let state = &mut self.cached.demand_sync;
        state.filter = None;
        state.list_after = None;
        state.requested_list_after = None;
        state.list_snapshot = None;
        state.list_complete = false;
        state.list_seen.clear();
        state.global_snapshot = None;
        state.channels.clear();
        for detail in state.details.values_mut() {
            detail.invalidated = true;
            detail.complete = false;
            detail.invalidated_snapshot = detail.snapshot.clone();
        }
        for projection in self.cached.realm_tree_projections.values_mut() {
            if let Some(object) = projection.as_object_mut() {
                object.remove("__current_required_ready");
            }
        }
    }
    /// Already delivered holder-private Events; this clones no Realm/history cache.
    pub(crate) fn current_account_data_events(&mut self) -> Vec<Event> {
        self.ensure_cached_loaded();
        self.cached
            .demand_sync
            .account_events
            .values()
            .cloned()
            .collect()
    }
    pub(crate) fn account_data_baseline_complete(&self) -> bool {
        self.cached
            .demand_sync
            .channels
            .get(&Channel::AccountDataEvents)
            .is_some_and(|state| state.complete)
    }
    pub(crate) fn current_account_projection_step(&mut self) -> crate::models::AccountSyncStep {
        let account_data = self.current_account_data_events();
        crate::models::AccountSyncStep {
            cursor: self.cached.sync_cursor.clone().unwrap_or_default(),
            realm_entries: BTreeMap::new(),
            realm_projections: BTreeMap::new(),
            updates: arkret_sdk::SyncUpdates {
                realm_updates: Vec::new(),
                malformed_realm_ids: Vec::new(),
                to_device: Vec::new(),
                to_device_ack_token: None,
                to_device_limited: false,
                to_device_next_cursor: None,
                to_device_lost: false,
                device_lists: arkret_sdk::AccountSubscribeDeviceListChanges {
                    changed_ids: Vec::new(),
                    left_ids: Vec::new(),
                },
                account_data,
                station_cas_account_data: Vec::new(),
                notifications: Vec::new(),
                partial: true,
            },
        }
    }
    pub(crate) fn sync_demand_filter(&self) -> Option<SyncFilter> {
        self.cached.demand_sync.filter.clone()
    }
    pub(crate) fn save_sync_demand_filter(
        &mut self,
        filter: Option<SyncFilter>,
    ) -> anyhow::Result<()> {
        if let Some(filter) = &filter {
            filter.validate()?;
        }
        self.ensure_cached_loaded();
        self.cached.demand_sync.filter = filter;
        self.flush()
    }
    pub(crate) fn request_next_sync_realm_list_page(&mut self) {
        self.ensure_cached_loaded();
        self.cached.demand_sync.requested_list_after = self.cached.demand_sync.list_after.clone();
        let _ = self.flush();
    }
    pub(crate) fn sync_requested_realm_list_after(&self) -> Option<Cursor> {
        self.cached.demand_sync.requested_list_after.clone()
    }
    pub(crate) fn sync_realm_list_after(&self) -> Option<Cursor> {
        self.cached.demand_sync.list_after.clone()
    }
    pub(crate) fn realm_detail_invalidated(&self, realm_id: &str) -> bool {
        if self
            .cached
            .realm_tree_projections
            .get(realm_id)
            .and_then(|projection| projection.get("__current_required_ready"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return false;
        }
        self.cached.demand_sync.details.contains_key(realm_id)
    }

    /// Runs inside the caller's cursor transaction before derived projection reducers.
    /// It never installs a cursor and never flushes independently.
    pub(crate) fn prepare_account_demand_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<AccountSubscribeFrame> {
        frame.validate()?;
        self.ensure_cached_loaded();
        // Validate every conflict before mutating the cache: LocalStateStore::batch coalesces
        // writes but does not roll back a returned error.
        if let Some(page) = &frame.realm_list {
            if self.cached.demand_sync.list_snapshot.as_ref() == Some(&page.snapshot_cursor) {
                anyhow::ensure!(
                    self.cached.demand_sync.list_revision == page.snapshot_revision,
                    "Realm list snapshot changed revision"
                );
            }
        }
        for row in frame.realm_list.iter().flat_map(|page| &page.items).chain(
            frame
                .realm_list_changes
                .iter()
                .flat_map(|changes| &changes.upserts),
        ) {
            if let Some(previous) = self.cached.demand_sync.summaries.get(row.realm_id.as_str()) {
                anyhow::ensure!(
                    previous.revision != row.revision || previous == row,
                    "Realm summary changed at same revision"
                );
            }
        }
        if let Some(cas) = frame
            .account_data
            .as_ref()
            .and_then(|data| data.station_cas.as_ref())
        {
            let baseline = frame
                .baseline
                .as_ref()
                .is_some_and(|segment| segment.channels.contains(&Channel::StationCas));
            for row in &cas.upserts {
                let previous = self
                    .cached
                    .station_cas_account_data
                    .get(&row.account_data_key);
                let revision = previous.map(|row| row.revision).unwrap_or(0).max(
                    self.cached
                        .demand_sync
                        .cas_removals
                        .get(&row.account_data_key)
                        .copied()
                        .unwrap_or(0),
                );
                anyhow::ensure!(
                    baseline || row.revision >= revision,
                    "Station-CAS revision regressed"
                );
                anyhow::ensure!(
                    row.revision != revision
                        || previous.is_some_and(|old| old.content == row.content),
                    "Station-CAS same revision changed value"
                );
            }
            for removal in &cas.removals {
                let previous = self
                    .cached
                    .station_cas_account_data
                    .get(&removal.account_data_key);
                let revision = previous.map(|row| row.revision).unwrap_or(0).max(
                    self.cached
                        .demand_sync
                        .cas_removals
                        .get(&removal.account_data_key)
                        .copied()
                        .unwrap_or(0),
                );
                anyhow::ensure!(
                    removal.revision >= revision
                        && (removal.revision != revision || previous.is_none()),
                    "Station-CAS removal revision conflict"
                );
            }
        }
        let mut accepted = frame.clone();
        if let Some(baseline) = &frame.baseline {
            if self.cached.demand_sync.global_snapshot.as_ref() != Some(&baseline.snapshot_cursor) {
                self.cached.demand_sync.global_snapshot = Some(baseline.snapshot_cursor.clone());
                self.cached.demand_sync.channels = [
                    Channel::AccountDataEvents,
                    Channel::StationCas,
                    Channel::DeviceLists,
                    Channel::Notifications,
                ]
                .into_iter()
                .map(|channel| (channel, BaselineChannelState::default()))
                .collect();
            }
        }
        let baseline = |channel| {
            frame
                .baseline
                .as_ref()
                .is_some_and(|segment| segment.channels.contains(&channel))
        };
        if let Some(page) = &frame.realm_list {
            let state = &mut self.cached.demand_sync;
            if state.list_snapshot.as_ref() != Some(&page.snapshot_cursor) {
                state.list_snapshot = Some(page.snapshot_cursor.clone());
                state.list_revision = page.snapshot_revision;
                state.list_seen.clear();
                state.list_complete = false;
            }
            anyhow::ensure!(
                state.list_revision == page.snapshot_revision,
                "Realm list snapshot changed revision"
            );
            for row in &page.items {
                state.list_seen.insert(row.realm_id.to_string());
            }
            for row in &page.items {
                self.apply_demand_summary(row)?;
            }
            self.cached.demand_sync.list_after = page.next_cursor.clone();
            self.cached.demand_sync.requested_list_after = None;
            self.cached.demand_sync.list_complete = page.complete;
            if page.complete {
                let stale = self
                    .cached
                    .demand_sync
                    .summaries
                    .iter()
                    .filter(|(id, row)| {
                        row.revision <= page.snapshot_revision
                            && !self.cached.demand_sync.list_seen.contains(*id)
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for id in stale {
                    self.remove_demand_summary(&id, page.snapshot_revision);
                }
            }
        }
        if let Some(changes) = &frame.realm_list_changes {
            for row in &changes.upserts {
                self.apply_demand_summary(row)?;
            }
            for row in &changes.removals {
                self.remove_demand_summary(row.realm_id.as_str(), row.revision);
            }
        }
        if let Some(invalidations) = &frame.realm_invalidations {
            for invalidation in invalidations {
                let state = self
                    .cached
                    .demand_sync
                    .details
                    .entry(invalidation.realm_id.to_string())
                    .or_default();
                if invalidation.revision >= state.invalidation_revision {
                    state.invalidation_revision = invalidation.revision;
                    state.invalidated = true;
                    state.complete = false;
                    state.invalidated_snapshot = state.snapshot.clone();
                    if let Some(projection) = self
                        .cached
                        .realm_tree_projections
                        .get_mut(invalidation.realm_id.as_str())
                    {
                        projection["__current_required_ready"] = Value::Bool(false);
                    }
                }
            }
        }
        if let Some(realms) = &mut accepted.realms {
            realms.entries.retain(|id, entry| {
                let state = self
                    .cached
                    .demand_sync
                    .details
                    .entry(id.clone())
                    .or_default();
                if entry.unavailable.is_some() {
                    state.invalidated = true;
                    state.complete = false;
                    state.invalidated_snapshot = state.snapshot.clone();
                    if let Some(projection) = self.cached.realm_tree_projections.get_mut(id) {
                        projection["__current_required_ready"] = Value::Bool(false);
                    }
                    return true;
                }
                if let Some(segment) = &entry.baseline {
                    if state.invalidated_snapshot.as_ref() == Some(&segment.snapshot_cursor) {
                        return false;
                    }
                    if state.snapshot.as_ref() != Some(&segment.snapshot_cursor) {
                        state.snapshot = Some(segment.snapshot_cursor.clone());
                        state.complete = false;
                    }
                    if segment.complete {
                        state.complete = true;
                        state.invalidated = false;
                    }
                }
                true
            });
        }
        if let Some(data) = &mut accepted.account_data {
            data.events.retain(|event| {
                let notification_key = serde_json::from_value::<arkret_sdk::Notification>(
                    Value::Object(event.payload.clone().into_iter().collect()),
                )
                .ok()
                .map(|notification| format!("notification:{}", notification.id));
                let key = notification_key.as_deref().unwrap_or_else(|| {
                    event
                        .payload
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or(event.event_id.as_str())
                });
                if !self.cached.demand_sync.accepts(
                    Channel::AccountDataEvents,
                    key,
                    baseline(Channel::AccountDataEvents),
                ) {
                    return false;
                }
                self.cached
                    .demand_sync
                    .account_events
                    .insert(key.to_owned(), event.clone());
                true
            });
            if let Some(cas) = &mut data.station_cas {
                let is_baseline = baseline(Channel::StationCas);
                let mut error = None;
                cas.upserts.retain(|row| {
                    let key = row.account_data_key.as_str();
                    if !self
                        .cached
                        .demand_sync
                        .accepts(Channel::StationCas, key, is_baseline)
                    {
                        return false;
                    }
                    let previous = self.cached.station_cas_account_data.get(key);
                    let revision = previous.map(|row| row.revision).unwrap_or(0).max(
                        self.cached
                            .demand_sync
                            .cas_removals
                            .get(key)
                            .copied()
                            .unwrap_or(0),
                    );
                    if row.revision < revision {
                        if !is_baseline {
                            error = Some("Station-CAS revision regressed");
                        }
                        return false;
                    }
                    if row.revision == revision {
                        if previous.is_none_or(|old| old.content != row.content) {
                            error = Some("Station-CAS same revision changed value");
                        }
                        return false;
                    }
                    self.cached.demand_sync.cas_removals.remove(key);
                    true
                });
                for removal in &cas.removals {
                    self.cached.demand_sync.accepts(
                        Channel::StationCas,
                        &removal.account_data_key,
                        false,
                    );
                    let previous = self
                        .cached
                        .station_cas_account_data
                        .get(&removal.account_data_key)
                        .map(|row| row.revision)
                        .unwrap_or(0)
                        .max(
                            self.cached
                                .demand_sync
                                .cas_removals
                                .get(&removal.account_data_key)
                                .copied()
                                .unwrap_or(0),
                        );
                    anyhow::ensure!(
                        removal.revision >= previous,
                        "Station-CAS removal revision regressed"
                    );
                    anyhow::ensure!(
                        removal.revision != previous
                            || !self
                                .cached
                                .station_cas_account_data
                                .contains_key(&removal.account_data_key),
                        "Station-CAS same revision changed to removal"
                    );
                    self.cached
                        .demand_sync
                        .cas_removals
                        .insert(removal.account_data_key.clone(), removal.revision);
                }
                if let Some(error) = error {
                    anyhow::bail!(error);
                }
            }
        }
        if let Some(notifications) = &mut accepted.notifications {
            notifications.items.retain(|item| {
                self.cached.demand_sync.accepts(
                    Channel::Notifications,
                    item.id.as_str(),
                    baseline(Channel::Notifications),
                )
            });
        }
        if let Some(devices) = &mut accepted.device_lists {
            let mut changed = Vec::new();
            for id in std::mem::take(&mut devices.changed_ids) {
                let key = id.canonical_key()?;
                if self.cached.demand_sync.accepts(
                    Channel::DeviceLists,
                    &key,
                    baseline(Channel::DeviceLists),
                ) {
                    self.cached.demand_sync.device_ids.insert(key);
                    changed.push(id);
                }
            }
            devices.changed_ids = changed;
            let mut left = Vec::new();
            for id in std::mem::take(&mut devices.left_ids) {
                let key = id.canonical_key()?;
                if self.cached.demand_sync.accepts(
                    Channel::DeviceLists,
                    &key,
                    baseline(Channel::DeviceLists),
                ) {
                    self.cached.demand_sync.device_ids.remove(&key);
                    left.push(id);
                }
            }
            devices.left_ids = left;
        }
        Ok(accepted)
    }

    pub(crate) fn finish_account_demand_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<()> {
        let Some(segment) = &frame.baseline else {
            return Ok(());
        };
        anyhow::ensure!(
            self.cached.demand_sync.global_snapshot.as_ref() == Some(&segment.snapshot_cursor),
            "Baseline completion belongs to another snapshot"
        );
        for channel in &segment.completed_channels {
            if self
                .cached
                .demand_sync
                .channels
                .get(channel)
                .is_some_and(|state| state.complete)
            {
                continue;
            }
            match channel {
                Channel::StationCas => {
                    self.cached
                        .station_cas_account_data
                        .retain(|key, _| self.cached.demand_sync.retained(*channel, key));
                    let delivery = self
                        .cached
                        .station_cas_account_data
                        .get(arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY)
                        .map(|row| row.content.clone());
                    self.replace_invite_delivery_cell(delivery.as_ref());
                }
                Channel::AccountDataEvents => {
                    let stale = self
                        .cached
                        .demand_sync
                        .account_events
                        .keys()
                        .filter(|key| !self.cached.demand_sync.retained(*channel, key))
                        .cloned()
                        .collect::<Vec<_>>();
                    for key in stale {
                        if let Some(event) = self.cached.demand_sync.account_events.remove(&key) {
                            if let Ok(notification) =
                                serde_json::from_value::<arkret_sdk::Notification>(Value::Object(
                                    event.payload.into_iter().collect(),
                                ))
                            {
                                self.cached.notification_projection.retain(|item| {
                                    item.notification_id() != notification.id.as_str()
                                });
                            }
                        }
                        self.cached.saved_account_data.remove(&key);
                        self.remove_scheduled_send_account_data_entry(&key);
                        if let Some(realm) =
                            crate::account_data::realm_id_from_realm_remark_key(&key)
                        {
                            self.cached.realm_remarks.remove(realm);
                        }
                    }
                }
                Channel::Notifications => {
                    self.cached.notification_projection.retain(|item| {
                        !matches!(item, StoredNotification::AgentRuntimeApproval { .. })
                            || self
                                .cached
                                .demand_sync
                                .retained(*channel, &item.notification_id())
                    });
                }
                Channel::DeviceLists => {
                    let retained = self
                        .cached
                        .demand_sync
                        .device_ids
                        .iter()
                        .filter(|id| self.cached.demand_sync.retained(*channel, id))
                        .cloned()
                        .collect();
                    self.cached.demand_sync.device_ids = retained;
                }
            }
            if let Some(state) = self.cached.demand_sync.channels.get_mut(channel) {
                state.complete = true;
                state.seen.clear();
                state.mutated.clear();
            }
        }
        Ok(())
    }

    fn apply_demand_summary(&mut self, row: &RealmListItem) -> anyhow::Result<()> {
        let id = row.realm_id.to_string();
        let state = &mut self.cached.demand_sync;
        if state
            .summary_removals
            .get(&id)
            .is_some_and(|revision| *revision >= row.revision)
        {
            return Ok(());
        }
        if let Some(previous) = state.summaries.get(&id) {
            if previous.revision > row.revision {
                return Ok(());
            }
            anyhow::ensure!(
                previous.revision != row.revision || previous == row,
                "Realm summary changed at same revision"
            );
        }
        state.summary_removals.remove(&id);
        state.summaries.insert(id.clone(), row.clone());
        if row.membership == RealmListMembership::Knock {
            self.cached.realm_tree_projections.remove(&id);
            self.cached.realm_collaboration_roles.remove(&id);
        }
        let projection = self
            .cached
            .realm_tree_projections
            .entry(id)
            .or_insert_with(|| serde_json::json!({}));
        if let Some(object) = projection.as_object_mut() {
            object.insert("realm_id".into(), Value::String(row.realm_id.to_string()));
            object.insert(
                "membership".into(),
                Value::String(
                    match row.membership {
                        RealmListMembership::Join => "join",
                        RealmListMembership::Knock => "knock",
                    }
                    .into(),
                ),
            );
            object.remove("title");
            object.remove("default_strand_id");
            if let Some(title) = &row.title {
                object.insert("title".into(), Value::String(title.clone()));
            }
            if let Some(strand) = &row.default_strand_id {
                object.insert(
                    "default_strand_id".into(),
                    Value::String(strand.to_string()),
                );
            }
        }
        Ok(())
    }
    fn remove_demand_summary(&mut self, id: &str, revision: u64) {
        if self
            .cached
            .demand_sync
            .summaries
            .get(id)
            .is_some_and(|row| row.revision > revision)
            || self
                .cached
                .demand_sync
                .summary_removals
                .get(id)
                .is_some_and(|previous| *previous > revision)
        {
            return;
        }
        self.cached.demand_sync.summaries.remove(id);
        self.cached
            .demand_sync
            .summary_removals
            .insert(id.to_owned(), revision);
        self.cached.realm_tree_projections.remove(id);
        self.cached.realm_collaboration_roles.remove(id);
        let detail = self
            .cached
            .demand_sync
            .details
            .entry(id.to_owned())
            .or_default();
        detail.invalidated = true;
        detail.complete = false;
        detail.invalidated_snapshot = detail.snapshot.clone();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    const REALM: &str = "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
    fn frame(value: Value) -> AccountSubscribeFrame {
        serde_json::from_value(value).unwrap()
    }
    fn store() -> LocalStateStore {
        LocalStateStore::with_path(std::env::temp_dir().join(format!(
                "inkson-demand-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )))
    }
    fn apply(store: &mut LocalStateStore, frame: &AccountSubscribeFrame) -> AccountSubscribeFrame {
        let accepted = store.prepare_account_demand_frame(frame).unwrap();
        if let Some(cas) = accepted
            .account_data
            .as_ref()
            .and_then(|data| data.station_cas.as_ref())
        {
            store.apply_station_cas_account_data(std::slice::from_ref(cas));
        }
        store.finish_account_demand_frame(&accepted).unwrap();
        accepted
    }
    #[test]
    fn older_list_page_cannot_resurrect_live_removal() {
        let mut store = store();
        let first = frame(
            json!({"kind":"delta","cursor":"ak:cursor:YQ","realm_list":{"snapshot_cursor":"ak:cursor:cw","snapshot_revision":10,"items":[],"next_cursor":"ak:cursor:cA","complete":false}}),
        );
        apply(&mut store, &first);
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yg","realm_list_changes":{"upserts":[],"removals":[{"realm_id":REALM,"revision":11}]}}),
            ),
        );
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yw","realm_list":{"snapshot_cursor":"ak:cursor:cw","snapshot_revision":10,"items":[{"realm_id":REALM,"revision":10,"activity_position":1,"membership":"join","title":"old"}],"complete":true}}),
            ),
        );
        assert!(!store.cached.realm_tree_projections.contains_key(REALM));
        assert_eq!(
            store.cached.demand_sync.summary_removals.get(REALM),
            Some(&11)
        );
    }
    #[test]
    fn baseline_station_cas_preserves_interleaved_newer_row_and_prunes_only_at_completion() {
        let mut store = store();
        let row = |revision, content| json!({"account_data_key":"test.key","revision":revision,"content":{"value":content},"updated_at":"2026-09-10T00:00:00.000Z"});
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:YQ","baseline":{"snapshot_cursor":"ak:cursor:cw","channels":["station_cas"],"completed_channels":[]},"account_data":{"station_cas":{"upserts":[],"removals":[]}}}),
            ),
        );
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yg","account_data":{"station_cas":{"upserts":[row(8,"new")],"removals":[]}}}),
            ),
        );
        let accepted = apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yw","baseline":{"snapshot_cursor":"ak:cursor:cw","channels":["station_cas"],"completed_channels":["station_cas"]},"account_data":{"station_cas":{"upserts":[row(7,"old")],"removals":[]}}}),
            ),
        );
        assert!(
            accepted
                .account_data
                .unwrap()
                .station_cas
                .unwrap()
                .upserts
                .is_empty()
        );
        assert_eq!(
            store.cached.station_cas_account_data["test.key"].revision,
            8
        );
    }
    #[test]
    fn invalidation_rejects_old_detail_completion() {
        let mut store = store();
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{REALM:{"baseline":{"snapshot_cursor":"ak:cursor:cw","cut_revision":2,"coverage":{"realm":true,"strand_ids":[],"members":{"mode":"selected","actor_ids":[]},"event_ids":[]},"complete":false}}}}),
            ),
        );
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yg","realm_invalidations":[{"realm_id":REALM,"revision":3}]}),
            ),
        );
        let accepted = apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yw","realms":{REALM:{"baseline":{"snapshot_cursor":"ak:cursor:cw","cut_revision":2,"coverage":{"realm":true,"strand_ids":[],"members":{"mode":"selected","actor_ids":[]},"event_ids":[]},"complete":true}}}}),
            ),
        );
        assert!(accepted.realms.unwrap().entries.is_empty());
        assert!(store.realm_detail_invalidated(REALM));
    }

    #[test]
    fn failed_frame_invalidates_partial_progress_before_batch_flush() {
        let mut store = store();
        store.ensure_cached_loaded();
        store.cached.current_generation = 4;
        store.cached.demand_sync.details.insert(
            REALM.into(),
            DetailState {
                complete: true,
                ..Default::default()
            },
        );
        store.cached.realm_tree_projections.insert(
            REALM.into(),
            json!({
                "__current_required_ready":true, "title":"cached"
            }),
        );
        let result = store.batch(|store| -> anyhow::Result<()> {
            store.set_current_generation(5);
            store.save_sync_cursor("ak:cursor:YQ");
            let result = Err(anyhow::anyhow!("frame reduction failed"));
            store.abort_account_demand_frame(4);
            result
        });
        assert!(result.is_err());
        assert_eq!(store.current_generation(), 4);
        assert!(store.sync_cursor().is_none());
        assert!(store.sync_demand_filter().is_none());
        assert!(store.realm_detail_invalidated(REALM));
        assert!(!store.cached.demand_sync.details[REALM].complete);
    }
}
