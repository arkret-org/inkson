use arkret_models_collaboration::sync_frames::account_subscribe::{
    AgentDraftPendingIntentChange, AgentDraftPendingIntentContainer,
};
use arkret_sdk::Event;
use arkret_sdk::sync::{AccountSubscribeFrame, SyncFilter};
use arkret_wire::Cursor;

use super::*;

/// Baseline delivery channels of the account stream.
///
/// The wire baseline segment is an opaque JSON value; this is the host's typed
/// view of the channel names it carries, used only to track which account-scoped
/// caches a snapshot has finished replacing. It is not a protocol identifier
/// set and never reaches the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountBaselineChannel {
    AccountDataEvents,
    StationCas,
    DeviceLists,
    Notifications,
    AgentDraftPendingIntents,
}

use AccountBaselineChannel as Channel;

/// Host view of one account baseline segment.
#[derive(Clone, Debug)]
struct BaselineSegmentView {
    snapshot_cursor: String,
    channels: BTreeSet<Channel>,
    completed_channels: Vec<Channel>,
}

/// Host view of one Realm-list row.
///
/// `revision` is the account Station's own list revision for this row. It is a
/// per-row monotone counter on the account list projection, never a Realm
/// commit position: Realm, Circle and Sidecar streams each have their own
/// position and none of them is exposed here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct RealmRow {
    pub realm_id: arkret_sdk::RealmId,
    pub revision: u64,
    pub membership: arkret_wire::MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_strand_id: Option<arkret_sdk::StrandId>,
}

#[derive(Clone, Debug)]
struct RealmRemovalView {
    realm_id: arkret_sdk::RealmId,
    revision: u64,
}

#[derive(Clone, Debug)]
struct RealmListPageView {
    snapshot_cursor: String,
    snapshot_revision: u64,
    items: Vec<RealmRow>,
    next_cursor: Option<Cursor>,
    complete: bool,
}

#[derive(Clone, Debug, Default)]
struct RealmListChangesView {
    upserts: Vec<RealmRow>,
    removals: Vec<RealmRemovalView>,
}

/// Typed host view of the opaque list/baseline members of one frame.
///
/// Parsing fails closed: a member that does not decode is treated as absent
/// rather than silently half-applied, and the frame is rejected.
struct FrameViews {
    realm_list: Option<RealmListPageView>,
    realm_list_changes: Option<RealmListChangesView>,
    baseline: Option<BaselineSegmentView>,
}

impl FrameViews {
    fn decode(frame: &AccountSubscribeFrame) -> anyhow::Result<Self> {
        let realm_list = if let Some(page) = frame.realm_list.as_ref() {
            Some(RealmListPageView {
                snapshot_cursor: page.snapshot_cursor.clone(),
                snapshot_revision: page.snapshot_revision,
                items: page.items.iter().map(realm_row).collect(),
                next_cursor: page
                    .next_cursor
                    .as_ref()
                    .map(|cursor| Cursor::new(cursor.clone()))
                    .transpose()?,
                complete: page.is_terminal(),
            })
        } else {
            None
        };
        let realm_list_changes =
            frame
                .realm_list_changes
                .as_ref()
                .map(|changes| RealmListChangesView {
                    upserts: changes.upserts.iter().map(realm_row).collect(),
                    removals: changes
                        .removals
                        .iter()
                        .map(|row| RealmRemovalView {
                            realm_id: row.realm_id.clone(),
                            revision: row.revision,
                        })
                        .collect(),
                });
        let baseline = frame.baseline.as_ref().map(|segment| BaselineSegmentView {
            snapshot_cursor: segment.snapshot_cursor.clone(),
            channels: segment
                .channels
                .iter()
                .copied()
                .map(baseline_channel)
                .collect(),
            completed_channels: segment
                .completed_channels
                .iter()
                .copied()
                .map(baseline_channel)
                .collect(),
        });
        Ok(Self {
            realm_list,
            realm_list_changes,
            baseline,
        })
    }
}

fn realm_row(
    row: &arkret_models_collaboration::sync_frames::demand_sync::RealmListRow,
) -> RealmRow {
    RealmRow {
        realm_id: row.realm_id.clone(),
        revision: row.revision,
        membership: match row.membership {
            arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership::Join => {
                arkret_wire::MembershipState::Join
            }
            arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership::Knock => {
                arkret_wire::MembershipState::Knock
            }
        },
        title: row.title.clone(),
        default_strand_id: row.default_strand_id.clone(),
    }
}

fn baseline_channel(
    channel: arkret_models_collaboration::sync_frames::demand_sync::AccountBaselineChannel,
) -> Channel {
    use arkret_models_collaboration::sync_frames::demand_sync::AccountBaselineChannel as Wire;
    match channel {
        Wire::AccountDataEvents => Channel::AccountDataEvents,
        Wire::StationCas => Channel::StationCas,
        Wire::DeviceLists => Channel::DeviceLists,
        Wire::Notifications => Channel::Notifications,
        Wire::AgentDraftPendingIntents => Channel::AgentDraftPendingIntents,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct DemandSyncState {
    filter: Option<SyncFilter>,
    list_after: Option<Cursor>,
    requested_list_after: Option<Cursor>,
    list_snapshot: Option<String>,
    list_revision: u64,
    list_complete: bool,
    list_seen: BTreeSet<String>,
    summaries: BTreeMap<String, RealmRow>,
    summary_removals: BTreeMap<String, u64>,
    global_snapshot: Option<String>,
    channels: BTreeMap<Channel, BaselineChannelState>,
    account_events: BTreeMap<String, Event>,
    device_ids: BTreeSet<String>,
    #[serde(default)]
    agent_draft_pending_intents: BTreeMap<String, StoredAgentDraftPendingIntent>,
    #[serde(default)]
    agent_draft_pending_projection_position: Option<u64>,
    #[serde(default)]
    agent_draft_pending_delta_fingerprint: Option<String>,
    #[serde(default)]
    agent_draft_pending_baseline: Option<AgentDraftPendingBaselineState>,
    details: BTreeMap<String, DetailState>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAgentDraftPendingIntent {
    value: Value,
    removed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDraftPendingBaselineState {
    snapshot_cursor: String,
    snapshot_cut_position: u64,
    next_page_offset: Option<u64>,
    terminal_page_seen: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct BaselineChannelState {
    seen: BTreeSet<String>,
    mutated: BTreeSet<String>,
    complete: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct DetailState {
    snapshot: Option<String>,
    invalidated_snapshot: Option<String>,
    invalidation_revision: u64,
    invalidated: bool,
    complete: bool,
}

fn pending_required(value: &Value, field: &str) -> anyhow::Result<Value> {
    value
        .get(field)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("pending-intent value lacks {field}"))
}

fn pending_intent_key(value: &Value, removed: bool) -> anyhow::Result<String> {
    let identity = if removed {
        value
            .get("key")
            .ok_or_else(|| anyhow::anyhow!("pending-intent removal lacks key"))?
    } else {
        value
    };
    serde_json::to_string(&serde_json::json!([
        pending_required(identity, "controller_account_id")?,
        pending_required(identity, "agent_id")?,
        pending_required(identity, "draft_id")?,
    ]))
    .map_err(Into::into)
}

fn pending_core_identity(value: &Value, removed: bool) -> anyhow::Result<Value> {
    let identity = if removed {
        value
            .get("key")
            .ok_or_else(|| anyhow::anyhow!("pending-intent removal lacks key"))?
    } else {
        value
    };
    Ok(serde_json::json!([
        pending_required(identity, "controller_account_id")?,
        pending_required(identity, "agent_id")?,
        pending_required(identity, "draft_id")?,
        pending_required(value, "accepted_event_id")?,
        pending_required(value, "canonical_event_digest")?,
        pending_required(value, "content_digest")?,
        pending_required(value, "expires_at")?,
    ]))
}

fn pending_full_create_identity(value: &Value) -> anyhow::Result<Value> {
    Ok(serde_json::json!([
        pending_core_identity(value, false)?,
        pending_required(value, "proposed_action")?,
        pending_required(value, "target")?,
        pending_required(value, "created_at")?,
    ]))
}

fn pending_terminal_metadata(value: &Value) -> anyhow::Result<Value> {
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("pending-intent value lacks state"))?;
    match state {
        "consumed" => Ok(serde_json::json!([
            state,
            pending_required(value, "consumption")?
        ])),
        "expired" => Ok(serde_json::json!([
            state,
            pending_required(value, "expired_at")?
        ])),
        _ => anyhow::bail!("pending-intent terminal metadata has a non-terminal state"),
    }
}

fn pending_intent_change_parts(
    item: &AgentDraftPendingIntentChange,
) -> anyhow::Result<(String, Value, bool)> {
    let (value, removed) = match item {
        AgentDraftPendingIntentChange::Upsert(value) => (serde_json::to_value(value)?, false),
        AgentDraftPendingIntentChange::Remove(value) => (serde_json::to_value(value)?, true),
    };
    let key = pending_intent_key(&value, removed)?;
    Ok((key, value, removed))
}

fn install_pending_intent_change(
    records: &mut BTreeMap<String, StoredAgentDraftPendingIntent>,
    key: String,
    value: Value,
    removed: bool,
) -> anyhow::Result<()> {
    let Some(previous) = records.get(&key) else {
        records.insert(key, StoredAgentDraftPendingIntent { value, removed });
        return Ok(());
    };
    anyhow::ensure!(
        pending_core_identity(&previous.value, previous.removed)?
            == pending_core_identity(&value, removed)?,
        "Agent draft pending-intent create-once identity changed"
    );
    if previous.removed {
        anyhow::ensure!(
            removed && previous.value == value,
            "Agent draft pending-intent removal cannot be resurrected or changed"
        );
        return Ok(());
    }

    let previous_state = previous
        .value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("stored pending-intent lacks state"))?;
    let next_state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("pending-intent change lacks state"))?;
    if removed {
        if previous_state != "available" {
            anyhow::ensure!(
                pending_terminal_metadata(&previous.value)? == pending_terminal_metadata(&value)?,
                "Agent draft pending-intent removal changed terminal outcome"
            );
        }
    } else if next_state == "available" {
        anyhow::ensure!(
            previous_state == "available" && previous.value == value,
            "Agent draft pending-intent terminal state cannot return to available"
        );
    } else if previous_state == "available" {
        anyhow::ensure!(
            pending_full_create_identity(&previous.value)? == pending_full_create_identity(&value)?,
            "Agent draft pending-intent terminal update changed create-once metadata"
        );
    } else {
        anyhow::ensure!(
            previous.value == value,
            "Agent draft pending-intent terminal outcome changed"
        );
    }
    records.insert(key, StoredAgentDraftPendingIntent { value, removed });
    Ok(())
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
        state.agent_draft_pending_projection_position = None;
        state.agent_draft_pending_delta_fingerprint = None;
        state.agent_draft_pending_baseline = None;
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
    /// Dedicated controller-private Agent draft projection. Values have already
    /// passed the SDK's closed live | terminal-redacted decoder; removal
    /// tombstones stay internal so callers cannot mistake them for live rows.
    pub(crate) fn agent_draft_pending_intents(&self) -> Vec<Value> {
        self.cached
            .demand_sync
            .agent_draft_pending_intents
            .values()
            .filter(|record| !record.removed)
            .map(|record| record.value.clone())
            .collect()
    }
    /// Snapshot of what this device has already accepted, with no new frame
    /// applied. It carries the account subscription's own resume cursor — never
    /// a commit-stream position — and the Realm projections already folded.
    pub(crate) fn current_account_projection_step(&mut self) -> crate::models::AccountSyncStep {
        self.ensure_cached_loaded();
        crate::models::AccountSyncStep {
            cursor: self.cached.sync_cursor.clone().unwrap_or_default(),
            realm_entries: BTreeMap::new(),
            realm_projections: self.cached.realm_tree_projections.clone(),
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
        self.cached
            .demand_sync
            .details
            .get(realm_id)
            .is_some_and(|state| state.invalidated || !state.complete)
    }

    pub(crate) fn realm_detail_requires_replacement(&self, realm_id: &str) -> bool {
        self.cached
            .demand_sync
            .details
            .get(realm_id)
            .is_some_and(|state| state.invalidated)
    }

    /// Runs inside the caller's cursor transaction before derived projection reducers.
    /// It never installs a cursor and never flushes independently.
    pub(crate) fn prepare_account_demand_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<AccountSubscribeFrame> {
        frame.validate()?;
        self.ensure_cached_loaded();
        let views = FrameViews::decode(frame)?;
        // Validate every conflict before mutating the cache: LocalStateStore::batch coalesces
        // writes but does not roll back a returned error.
        if let Some(page) = &views.realm_list {
            if self.cached.demand_sync.list_snapshot.as_ref() == Some(&page.snapshot_cursor) {
                anyhow::ensure!(
                    self.cached.demand_sync.list_revision == page.snapshot_revision,
                    "Realm list snapshot changed revision"
                );
            }
        }
        for row in views.realm_list.iter().flat_map(|page| &page.items).chain(
            views
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
        let mut accepted = frame.clone();
        if let Some(baseline) = &views.baseline {
            if self.cached.demand_sync.global_snapshot.as_deref()
                != Some(baseline.snapshot_cursor.as_str())
            {
                self.cached.demand_sync.global_snapshot = Some(baseline.snapshot_cursor.clone());
                self.cached.demand_sync.channels = [
                    Channel::AccountDataEvents,
                    Channel::StationCas,
                    Channel::DeviceLists,
                    Channel::Notifications,
                    Channel::AgentDraftPendingIntents,
                ]
                .into_iter()
                .map(|channel| (channel, BaselineChannelState::default()))
                .collect();
                self.cached.demand_sync.agent_draft_pending_baseline = None;
            }
        }
        let baseline = |channel| {
            views
                .baseline
                .as_ref()
                .is_some_and(|segment| segment.channels.contains(&channel))
        };
        if let Some(page) = &views.realm_list {
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
        if let Some(changes) = &views.realm_list_changes {
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
                cas.upserts.retain(|row| {
                    self.cached.demand_sync.accepts(
                        Channel::StationCas,
                        row.account_data_key.as_str(),
                        is_baseline,
                    )
                });
                cas.removals.retain(|removal| {
                    self.cached.demand_sync.accepts(
                        Channel::StationCas,
                        &removal.account_data_key,
                        is_baseline,
                    )
                });
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
        self.apply_agent_draft_pending_intent_channel(&mut accepted, &views)?;
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

    fn apply_agent_draft_pending_intent_channel(
        &mut self,
        frame: &mut AccountSubscribeFrame,
        views: &FrameViews,
    ) -> anyhow::Result<()> {
        let Some(container) = frame.agent_draft_pending_intents.as_mut() else {
            return Ok(());
        };
        let fingerprint = serde_json::to_string(container)?;
        let mut records = self.cached.demand_sync.agent_draft_pending_intents.clone();
        let mut channel_state = self
            .cached
            .demand_sync
            .channels
            .get(&Channel::AgentDraftPendingIntents)
            .cloned();
        let mut baseline_progress = self.cached.demand_sync.agent_draft_pending_baseline.clone();

        let (is_baseline, items) = match container {
            AgentDraftPendingIntentContainer::Delta {
                projection_position,
                items,
            } => {
                if let Some(previous) = self
                    .cached
                    .demand_sync
                    .agent_draft_pending_projection_position
                {
                    anyhow::ensure!(
                        *projection_position >= previous,
                        "Agent draft pending-intent projection position regressed"
                    );
                    if *projection_position == previous {
                        anyhow::ensure!(
                            self.cached
                                .demand_sync
                                .agent_draft_pending_delta_fingerprint
                                .as_deref()
                                == Some(fingerprint.as_str()),
                            "Agent draft pending-intent position changed content"
                        );
                        items.clear();
                        return Ok(());
                    }
                }
                (false, items)
            }
            AgentDraftPendingIntentContainer::Baseline {
                snapshot_cut_position,
                page_offset,
                next_page_offset,
                items,
            } => {
                let snapshot_cursor = views
                    .baseline
                    .as_ref()
                    .map(|segment| segment.snapshot_cursor.as_str())
                    .ok_or_else(|| anyhow::anyhow!("pending-intent baseline lacks snapshot"))?;
                if let Some(progress) = &baseline_progress {
                    anyhow::ensure!(
                        progress.snapshot_cursor == snapshot_cursor,
                        "Agent draft pending-intent page belongs to another snapshot"
                    );
                    anyhow::ensure!(
                        progress.snapshot_cut_position == *snapshot_cut_position,
                        "Agent draft pending-intent snapshot changed cut position"
                    );
                    anyhow::ensure!(
                        !progress.terminal_page_seen,
                        "Agent draft pending-intent baseline continued after its terminal page"
                    );
                    anyhow::ensure!(
                        progress.next_page_offset == Some(*page_offset),
                        "Agent draft pending-intent baseline page offset is not contiguous"
                    );
                } else {
                    anyhow::ensure!(
                        *page_offset == 0,
                        "Agent draft pending-intent baseline must begin at offset zero"
                    );
                }
                baseline_progress = Some(AgentDraftPendingBaselineState {
                    snapshot_cursor: snapshot_cursor.to_owned(),
                    snapshot_cut_position: *snapshot_cut_position,
                    next_page_offset: *next_page_offset,
                    terminal_page_seen: next_page_offset.is_none(),
                });
                (true, items)
            }
        };

        let mut retained_items = Vec::with_capacity(items.len());
        for item in std::mem::take(items) {
            let (key, value, removed) = pending_intent_change_parts(&item)?;
            let accepted = if let Some(state) = &mut channel_state {
                if is_baseline {
                    state.seen.insert(key.clone());
                    !state.complete && !state.mutated.contains(&key)
                } else {
                    if !state.complete {
                        state.mutated.insert(key.clone());
                    }
                    true
                }
            } else {
                true
            };
            if !accepted {
                continue;
            }
            install_pending_intent_change(&mut records, key, value, removed)?;
            retained_items.push(item);
        }
        *items = retained_items;

        self.cached.demand_sync.agent_draft_pending_intents = records;
        if let Some(state) = channel_state {
            self.cached
                .demand_sync
                .channels
                .insert(Channel::AgentDraftPendingIntents, state);
        }
        self.cached.demand_sync.agent_draft_pending_baseline = baseline_progress;
        if let AgentDraftPendingIntentContainer::Delta {
            projection_position,
            ..
        } = container
        {
            self.cached
                .demand_sync
                .agent_draft_pending_projection_position = Some(*projection_position);
            self.cached
                .demand_sync
                .agent_draft_pending_delta_fingerprint = Some(fingerprint);
        }
        Ok(())
    }

    pub(crate) fn finish_account_demand_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<()> {
        let Some(segment) = FrameViews::decode(frame)?.baseline else {
            return Ok(());
        };
        anyhow::ensure!(
            self.cached.demand_sync.global_snapshot.as_deref()
                == Some(segment.snapshot_cursor.as_str()),
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
                        item.agent_runtime_approval().is_none()
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
                Channel::AgentDraftPendingIntents => {
                    let progress = self
                        .cached
                        .demand_sync
                        .agent_draft_pending_baseline
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::anyhow!("pending-intent completion lacks baseline progress")
                        })?;
                    anyhow::ensure!(
                        progress.terminal_page_seen && progress.next_page_offset.is_none(),
                        "pending-intent completion requires its terminal page"
                    );
                    let retained = self
                        .cached
                        .demand_sync
                        .channels
                        .get(channel)
                        .map(|state| {
                            state
                                .seen
                                .union(&state.mutated)
                                .cloned()
                                .collect::<BTreeSet<_>>()
                        })
                        .unwrap_or_default();
                    self.cached
                        .demand_sync
                        .agent_draft_pending_intents
                        .retain(|key, record| record.removed || retained.contains(key));
                    let cut = progress.snapshot_cut_position;
                    self.cached
                        .demand_sync
                        .agent_draft_pending_projection_position = Some(
                        self.cached
                            .demand_sync
                            .agent_draft_pending_projection_position
                            .unwrap_or(0)
                            .max(cut),
                    );
                    self.cached
                        .demand_sync
                        .agent_draft_pending_delta_fingerprint = None;
                    self.cached.demand_sync.agent_draft_pending_baseline = None;
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

    fn apply_demand_summary(&mut self, row: &RealmRow) -> anyhow::Result<()> {
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
        if row.membership != arkret_wire::MembershipState::Join {
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
            object.insert("membership".into(), serde_json::to_value(row.membership)?);
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
    const EVENT: &str = "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    const KEY: &str = "ak.agent.draft.v1:29zs6Yu_GblluGkdTEDf8gWy8fRlKv2Am4Ms91DB-U8:HpcHzfESu5dFt2Is2QQ2Tp_c7hfh4SZtz4pKrbxp0_s";
    fn frame(value: Value) -> AccountSubscribeFrame {
        serde_json::from_value(value).unwrap()
    }
    fn detail_baseline(snapshot: &str, cut: u64, complete: bool) -> Value {
        json!({
            "snapshot_cursor": snapshot,
            "cut_revision": cut,
            "coverage": {
                "realm_id": REALM,
                "stream_heads": [{
                    "stream_ref": {"kind": "realm", "realm_id": REALM},
                    "stream_position": cut,
                    "commit_id": arkret_wire::RealmCommitId::from_digest([0x31; 32])
                }],
                "complete_for_authorized_streams": complete
            },
            "complete": complete
        })
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
    fn pending_live(draft_id: &str) -> Value {
        json!({
            "schema":"ak.schema.agent_draft_pending_intent.v1",
            "controller_account_id":{
                "principal_id":"ak:did_core:web:controller.example",
                "station_id":"ak:did_core:web:station.example"
            },
            "agent_id":"ak:did_core:web:agent.example",
            "draft_id":draft_id,
            "proposed_action":"ak.message.create",
            "target":{"kind":"realm","realm_id":REALM},
            "content_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "content_handoff":{
                "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
                "recipients":[{
                    "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000000",
                    "recipient_hpke_key_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                    "ciphertext_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }]
            },
            "canonical_event_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "accepted_event_id":EVENT,
            "expires_at":"2026-09-20T03:00:00.000Z",
            "created_at":"2026-09-20T01:00:00.000Z",
            "state":"available"
        })
    }
    fn pending_consumed(draft_id: &str) -> Value {
        let mut value = pending_live(draft_id);
        let object = value.as_object_mut().unwrap();
        object.remove("content_handoff");
        object.insert("state".into(), json!("consumed"));
        object.insert(
            "consumption".into(),
            json!({
                "account_data_set_event_id":EVENT,
                "account_data_key":KEY,
                "accepted_revision":1,
                "consumed_at":"2026-09-20T01:30:00.000Z"
            }),
        );
        value
    }
    fn pending_removal(draft_id: &str) -> Value {
        json!({
            "key":{
                "controller_account_id":{
                    "principal_id":"ak:did_core:web:controller.example",
                    "station_id":"ak:did_core:web:station.example"
                },
                "agent_id":"ak:did_core:web:agent.example",
                "draft_id":draft_id
            },
            "accepted_event_id":EVENT,
            "canonical_event_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "content_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expires_at":"2026-09-20T03:00:00.000Z",
            "state":"consumed",
            "consumption":{
                "account_data_set_event_id":EVENT,
                "account_data_key":KEY,
                "accepted_revision":1,
                "consumed_at":"2026-09-20T01:30:00.000Z"
            },
            "removed_at":"2026-09-20T04:00:00.000Z"
        })
    }
    fn pending_delta(position: u64, action: &str, value: Value) -> AccountSubscribeFrame {
        frame(json!({
            "kind":"delta",
            "cursor":format!("ak:cursor:pending-{position}"),
            "agent_draft_pending_intents":{
                "mode":"delta",
                "projection_position":position,
                "items":[{"action":action,"value":value}]
            }
        }))
    }
    fn pending_baseline(
        snapshot: &str,
        cut: u64,
        offset: u64,
        next: Option<u64>,
        complete: bool,
        items: Vec<Value>,
    ) -> AccountSubscribeFrame {
        frame(json!({
            "kind":"delta",
            "cursor":format!("ak:cursor:{snapshot}-{offset}"),
            "baseline":{
                "snapshot_cursor":format!("ak:cursor:{snapshot}"),
                "channels":["agent_draft_pending_intents"],
                "completed_channels":if complete { json!(["agent_draft_pending_intents"]) } else { json!([]) }
            },
            "agent_draft_pending_intents":{
                "mode":"baseline",
                "snapshot_cut_position":cut,
                "page_offset":offset,
                "next_page_offset":next,
                "items":items
            }
        }))
    }

    #[test]
    fn pending_intent_baseline_delta_terminal_and_removal_are_monotone() {
        let mut store = store();
        apply(
            &mut store,
            &pending_delta(6, "upsert", pending_live("draft-stale")),
        );
        apply(
            &mut store,
            &pending_baseline(
                "pending-snapshot",
                7,
                0,
                Some(1),
                false,
                vec![json!({"action":"upsert","value":pending_live("draft-001")})],
            ),
        );
        assert!(
            store
                .agent_draft_pending_intents()
                .into_iter()
                .find(|value| value["draft_id"] == "draft-001")
                .unwrap()["content_handoff"]
                .is_object()
        );

        apply(
            &mut store,
            &pending_delta(8, "upsert", pending_consumed("draft-001")),
        );
        let terminal = store
            .agent_draft_pending_intents()
            .into_iter()
            .find(|value| value["draft_id"] == "draft-001")
            .unwrap();
        assert_eq!(terminal["state"], "consumed");
        assert!(terminal.get("content_handoff").is_none());
        assert_eq!(terminal["accepted_event_id"], EVENT);
        assert!(terminal["consumption"].is_object());

        let accepted = apply(
            &mut store,
            &pending_baseline(
                "pending-snapshot",
                7,
                1,
                None,
                true,
                vec![json!({"action":"upsert","value":pending_live("draft-001")})],
            ),
        );
        let AgentDraftPendingIntentContainer::Baseline { items, .. } =
            accepted.agent_draft_pending_intents.unwrap()
        else {
            panic!("baseline expected")
        };
        assert!(
            items.is_empty(),
            "older baseline cannot restore live ciphertext"
        );
        assert_eq!(store.agent_draft_pending_intents().len(), 1);
        assert_eq!(store.agent_draft_pending_intents()[0]["state"], "consumed");

        apply(
            &mut store,
            &pending_delta(9, "remove", pending_removal("draft-001")),
        );
        assert!(store.agent_draft_pending_intents().is_empty());
        let tombstone = store
            .cached
            .demand_sync
            .agent_draft_pending_intents
            .values()
            .next()
            .unwrap();
        assert!(tombstone.removed);
        assert_eq!(tombstone.value["state"], "consumed");
        assert!(tombstone.value.get("content_handoff").is_none());

        assert!(
            store
                .prepare_account_demand_frame(&pending_delta(
                    10,
                    "upsert",
                    pending_live("draft-001")
                ))
                .is_err(),
            "a retained removal tombstone forbids resurrection"
        );
    }

    #[test]
    fn pending_intent_offsets_reset_on_resync_and_prune_only_at_completion() {
        let mut store = store();
        assert!(
            store
                .prepare_account_demand_frame(&pending_baseline(
                    "bad-offset",
                    3,
                    2,
                    None,
                    true,
                    vec![]
                ))
                .is_err()
        );
        apply(
            &mut store,
            &pending_baseline(
                "first-cut",
                3,
                0,
                Some(1),
                false,
                vec![json!({"action":"upsert","value":pending_live("draft-001")})],
            ),
        );
        assert!(
            store
                .cached
                .demand_sync
                .agent_draft_pending_baseline
                .is_some()
        );
        assert_eq!(store.agent_draft_pending_intents().len(), 1);

        store.reset_account_demand_progress();
        assert!(
            store
                .cached
                .demand_sync
                .agent_draft_pending_baseline
                .is_none()
        );
        assert_eq!(store.agent_draft_pending_intents().len(), 1);
        apply(
            &mut store,
            &pending_baseline("fresh-cut", 4, 0, None, true, vec![]),
        );
        assert!(store.agent_draft_pending_intents().is_empty());
        assert!(store.cached.demand_sync.channels[&Channel::AgentDraftPendingIntents].complete);
    }

    #[test]
    fn notification_and_to_device_carriers_never_create_pending_intents() {
        let mut store = store();
        apply(
            &mut store,
            &frame(json!({
                "kind":"delta",
                "cursor":"ak:cursor:other-carriers",
                "notifications":{"items":[]},
                "to_device":{"messages":[]}
            })),
        );
        assert!(store.agent_draft_pending_intents().is_empty());
        assert!(
            store
                .cached
                .demand_sync
                .agent_draft_pending_intents
                .is_empty()
        );
    }
    #[test]
    fn older_list_page_cannot_resurrect_live_removal() {
        let mut store = store();
        let first = frame(
            json!({"kind":"delta","cursor":"ak:cursor:YQ","realm_list":{"snapshot_cursor":"ak:cursor:cw","snapshot_revision":10,"items":[{"realm_id":REALM,"revision":9,"activity_position":1,"membership":"join"}],"next_cursor":"ak:cursor:cA"}}),
        );
        apply(&mut store, &first);
        assert_eq!(
            store.sync_realm_list_after(),
            Some(Cursor::new("ak:cursor:cA").unwrap())
        );
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yg","realm_list_changes":{"upserts":[],"removals":[{"realm_id":REALM,"revision":11}]}}),
            ),
        );
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:Yw","realm_list":{"snapshot_cursor":"ak:cursor:cw","snapshot_revision":10,"items":[{"realm_id":REALM,"revision":10,"activity_position":1,"membership":"join","title":"old"}]}}),
            ),
        );
        assert!(!store.cached.realm_tree_projections.contains_key(REALM));
        assert_eq!(
            store.cached.demand_sync.summary_removals.get(REALM),
            Some(&11)
        );
        assert!(store.sync_realm_list_after().is_none());
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
        store.save_realm_tree_projection(REALM, json!({"__current_required_ready": true}));
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{REALM:{"baseline":detail_baseline("ak:cursor:cw", 2, false)}}}),
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
                json!({"kind":"delta","cursor":"ak:cursor:Yw","realms":{REALM:{"baseline":detail_baseline("ak:cursor:cw", 2, true)}}}),
            ),
        );
        assert!(accepted.realms.unwrap().entries.is_empty());
        assert!(store.realm_detail_invalidated(REALM));
        assert_eq!(
            store.load().realm_tree_projections[REALM]["__current_required_ready"],
            false
        );
    }

    #[test]
    fn completed_detail_is_current_before_optional_product_cells_exist() {
        let mut store = store();
        apply(
            &mut store,
            &frame(
                json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{REALM:{"baseline":detail_baseline("ak:cursor:cw", 2, true)}}}),
            ),
        );

        assert!(!store.realm_detail_invalidated(REALM));
        // Baseline completion is delivery progress, not a verified current
        // value or an authoring decision by the governing Station.
        assert!(store.cached_current_entries(REALM).is_empty());
        assert!(
            store
                .load()
                .realm_tree_projections
                .get(REALM)
                .is_none_or(|projection| {
                    projection.get("__current_required_ready") != Some(&Value::Bool(true))
                })
        );
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
