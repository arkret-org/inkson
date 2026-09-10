//! Background account subscribe sync loop.
//!
//! Background engine that keeps the local store + UI signals continuously
//! aligned with `/_arkret/self/account/subscribe` instead of refreshing only on
//! app boot, the Refresh button, or a server switch.
//!
//! Each validated frame commits its payload, baseline progress, demand filter,
//! and cursor atomically before product work or transport checkpointing.
//! Realm summaries arrive in explicit pages; detail is requested only for the
//! selected Realm. Partial pages never imply removal of unseen Realms.
//! Session and request coordinates fence late responses across navigation.
//! //! When an iteration hits `is_auth_expired_error`, the engine calls the
//! app-wide single-flight refresher and either continues with the refreshed
//! token, backs off on retryable restore failures, or exits after terminal
//! invalidation. This keeps refresh policy in one place without turning
//! auth failures into a spawn/exit/render loop.
//!
//! The protocol loop runs through `garth::ArkretClient::run_account_steps`.
//! `InksonAccountCommitter` atomically persists the typed raw step and cursor;
//! `InksonAccountPostCommit` retains product-only invite, MLS, call and
//! to-device work after that durability boundary.

#[cfg(test)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Context as _;
use arkret_sdk::EventPayloadExt as _;
use arkret_wire::{AccountDataKey, event_kind_str};
use garth::sync_client::{
    accepted_human_event_signing_device, account_updates_are_empty,
    collect_member_identity_proof_devices_from_value, collect_persistent_proof_sender_devices,
    collect_proof_sender_devices_from_value, realm_update_has_durable_projection,
    sync_realm_timeline_events, to_device_backfill_cursor, to_device_batch_safe_for_ingest_ack,
};
use garth::{
    AccountCommitOutcome, AccountPostCommitHook, AccountPostCommitOutcome, AccountStepCommitter,
    AccountStepHandlers, AccountStreamStep, RealmProjectionFrame, RunOptions, SyncLoopControl,
    TransportProvider, reconcile_realm_projection,
};
#[cfg(test)]
use garth::{ClientEvent, ClientProjector};
#[cfg(test)]
use garth::{DecodedInbound, InboundDecoder};
use serde::Serialize;
use serde_json::Value;

use crate::api_error::{is_auth_expired_error, is_terminal_session_grant_error};
use crate::models::AccountSyncStep;
use crate::runtime::projection::{ClientProjectionEvent, ProjectionSink, SyncStatusEvent};
use crate::state::{LocalStateStore, RawOperationRecord};
use crate::transport::TransportClient;

/// Connection-status label surfaced to the app shell's status signal.
/// A pure sync-layer concept (no Dioxus state, no rendering); the app views
/// consume it via the `crate::views::ConnectionState` re-export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Offline,
    Loading,
    Online,
    Reconnecting,
    Empty,
    Error,
}

impl ConnectionState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline",
            Self::Loading => "Loading",
            Self::Online => "Online",
            Self::Reconnecting => "Reconnecting",
            Self::Empty => "Empty",
            Self::Error => "Error",
        }
    }
}

/// Failure-backoff bounds for the account subscribe loop. The doubling ladder
/// itself is [`garth::RetrySchedule`]; these are just its floor/ceiling. A 1s floor
/// keeps recovery noticeable to the user; a 60s ceiling stops a wedged server
/// from being hammered by retries. Kept as `Duration` so there is a single unit
/// (F-10: the old seconds-vs-milliseconds split across engines is gone).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

const TO_DEVICE_PAGE_LIMIT: u32 = 1000;
const MAX_TO_DEVICE_BACKFILL_PAGES: usize = 32;

/// Session snapshot plus the remaining app adapters needed while response
/// application migrates fully behind runtime traits. UI outputs are emitted
/// exclusively through `projection_sink`.
#[derive(Clone)]
pub struct SyncEngineContext {
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account: crate::config::ActiveAccountContext,
    pub principal_id: arkret_sdk::DidCoreId,
    /// `encryption-and-audit.md` §5.6 — the local device id, needed by the idle
    /// self-update driver to load the device snapshot secret and build the
    /// background `self_update_commit`. Sourced from the active profile config
    /// (same value the chat / realm-admin send paths use).
    pub device_id: String,
    /// Writable app-level device id. A sync response that revokes this local
    /// device rotates the live value before session invalidation persists the
    /// login form state, so the revoked id cannot be resurrected on re-login.
    pub live_device_id: crate::runtime::input::ValueCell<String>,
    pub selected_realm_id: crate::runtime::input::ValueReader<String>,
    /// The session's optional WebSocket. A live rail supplies the account
    /// channel; otherwise this engine stays on the canonical NDJSON binding.
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
    /// Monotonic UI projection revision for Realm-backed views. Account-sync
    /// ingestion bumps this even when cursor checkpointing is deliberately
    /// deferred by unacknowledged to-device key material.
    pub realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    /// Session-scoped DID resolution cache handle, provided by `app.rs` via
    /// `use_context_provider`. Exact DID proof prefetches use this cache;
    /// lifecycle reset remains responsible for clearing it. Realm projections
    /// carrying only a principal core never select or invalidate an authority
    /// instance through this handle.
    pub session: crate::runtime::session::SessionCoordinator,
    pub client_runtime: crate::client_core::InksonClientRuntime,
    pub effect: crate::runtime::effects::EffectHandle,
    pub projection_sink: crate::runtime::projection::ProjectionRouter,
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AccountClientEventReport {
    account_updates: usize,
    realm_deltas: usize,
    decoded_messages: usize,
    decoded_events: usize,
    to_device: usize,
    notifications: usize,
    malformed_realm_ids: Vec<String>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct AccountClientEventProjector {
    report: RefCell<AccountClientEventReport>,
}

#[cfg(test)]
impl AccountClientEventProjector {
    fn report(&self) -> AccountClientEventReport {
        self.report.borrow().clone()
    }

    fn record(&self, event: ClientEvent) {
        let mut report = self.report.borrow_mut();
        match event {
            ClientEvent::AccountUpdates(updates) => {
                report.account_updates += 1;
                report.malformed_realm_ids.extend(updates.malformed_realms);
            }
            ClientEvent::RealmDelta { .. } => {
                report.realm_deltas += 1;
            }
            ClientEvent::Message(_) => {
                report.decoded_messages += 1;
            }
            ClientEvent::Event(_) => {
                report.decoded_events += 1;
            }
            ClientEvent::RealmAccepted { .. } => {
                report.decoded_events += 1;
            }
            ClientEvent::Notification(_) => {
                report.notifications += 1;
            }
            ClientEvent::ToDevice(_) => {
                report.to_device += 1;
            }
            ClientEvent::Backfill { .. } => {}
        }
    }
}

#[cfg(test)]
impl ClientProjector for AccountClientEventProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        {
            for event in batch {
                self.record(event);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
fn push_decoded_account_event(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    event: arkret_sdk::Event,
) {
    match decoder.decode_event(event) {
        DecodedInbound::Message(message) => batch.push(ClientEvent::Message(*message)),
        DecodedInbound::Event(event) => batch.push(ClientEvent::Event(*event)),
    }
}

#[cfg(test)]
fn push_account_event_payload(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    event: &arkret_sdk::Event,
) {
    push_decoded_account_event(decoder, batch, event.clone());
}

#[cfg(test)]
fn push_account_realm_update_events(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    update: &arkret_sdk::RealmUpdate,
) {
    if let Some(timeline) = &update.entry.timeline {
        for payload in &timeline.events {
            push_account_event_payload(decoder, batch, payload);
        }
    }
}

#[cfg(test)]
async fn project_account_response_client_events<P>(
    response: &AccountSyncStep,
    decoder: &InboundDecoder,
    projector: &P,
) -> anyhow::Result<()>
where
    P: ClientProjector + ?Sized,
{
    let updates = response.updates.clone();
    let realm_updates = updates.realm_updates.clone();
    let mut batch = garth::account_updates_to_events(updates);

    for update in &realm_updates {
        push_account_realm_update_events(decoder, &mut batch, update);
    }
    projector.project(batch).await?;

    Ok(())
}

/// Main entry point. Spawn this once per "session generation" — see the
/// module-level doc for what bumps the generation.
///
/// The engine returns when the generation moves past `start_generation`
/// (signal that a new engine should be spawned with the next number) or
/// when an unrecoverable error fires (auth-expired, missing config).
struct AccountTransportProvider {
    ctx: SyncEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
}

impl TransportProvider for AccountTransportProvider {
    type Transport =
        crate::transport::websocket_rail::StreamRail<crate::client_core::InksonAccountTransport>;

    fn account_request(&self, after: Option<String>) -> garth::Result<arkret_sdk::SyncRequestBody> {
        let filter = Some(selected_account_filter(&self.ctx));
        let previous = self
            .ctx
            .state_store
            .read(|store| store.sync_demand_filter());
        let replace_filter = (after.is_some() && previous != filter).then_some(true);
        Ok(arkret_sdk::SyncRequestBody {
            after,
            catchup: Some(true),
            filter,
            realm_list: self
                .ctx
                .state_store
                .read(|store| store.sync_requested_realm_list_after())
                .map(|after| arkret_sdk::RealmListRequest {
                    after: Some(after),
                    limit: Some(20),
                }),
            replace_filter,
        })
    }

    fn account_request_is_current(&self, request: &arkret_sdk::SyncRequestBody) -> bool {
        self.is_active()
            && request.filter == Some(selected_account_filter(&self.ctx))
            && request
                .realm_list
                .as_ref()
                .and_then(|page| page.after.clone())
                == self
                    .ctx
                    .state_store
                    .read(|store| store.sync_requested_realm_list_after())
    }

    fn account_session_generation(&self) -> u64 {
        self.ctx.session.generation()
    }

    /// §6.1 — the account channel keeps canonical cursor semantics on either
    /// transport, so the resume point survives a switch and the choice is made
    /// per connection attempt rather than per session.
    async fn provide(&self) -> garth::Result<Self::Transport> {
        let session_generation = self.ctx.session.generation();
        let transport = crate::identity::session_refresh::provide_authenticated_sdk_client(
            self.ctx.account.server_url.as_str(),
        )
        .await
        .map(crate::client_core::InksonAccountTransport::new)
        .map(|http| {
            crate::transport::websocket_rail::StreamRail::select(&self.ctx.websocket_rail, http)
        })
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if self.ctx.session.generation() != session_generation || !self.is_active() {
            return Err(garth::Error::Protocol(
                "session changed while preparing account transport".to_owned(),
            ));
        }
        Ok(transport)
    }

    async fn recover_unauthorized(&self) -> garth::Result<bool> {
        let session_generation = self.ctx.session.generation();
        let result =
            crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
                self.ctx.account.server_url.as_str(),
            )
            .await;
        if self.ctx.session.generation() != session_generation || !self.is_active() {
            return Ok(false);
        }
        match result {
            Ok(_) => Ok(true),
            Err(error) if is_terminal_session_grant_error(&error) => {
                self.ctx
                    .session
                    .invalidate_if_generation(session_generation, error.to_string());
                Ok(false)
            }
            Err(error) => Err(garth::Error::Http(error.to_string())),
        }
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && !self.ctx.effect.is_cancelled()
            && !self.ctx.token.get().trim().is_empty()
    }
}

struct InksonAccountCommitter {
    ctx: SyncEngineContext,
    current_index: tokio::sync::Mutex<Option<crate::state::CurrentIndex>>,
}

impl InksonAccountCommitter {
    async fn current_index(&self) -> garth::Result<crate::state::CurrentIndex> {
        let mut cached = self.current_index.lock().await;
        let (generation, location) = self
            .ctx
            .state_store
            .read(|store| (store.current_generation(), store.current_index_location()));
        let index = match cached.as_ref() {
            Some(index) => index.clone(),
            None => {
                crate::state::CurrentIndex::open(&self.ctx.account.authority, generation, location)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?
            }
        };
        if index.is_poisoned() {
            self.confirm_current_pointer_durable(&index, generation)
                .await?;
        }
        if self
            .ctx
            .state_store
            .read(LocalStateStore::current_reset_required)
        {
            let reset_frame = serde_json::from_value(serde_json::json!({"kind":"resync_required"}))
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            let mut stage = index
                .stage_frame(generation, &reset_frame)
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            stage.arm_account_commit();
            self.ctx.state_store.write(|store| -> garth::Result<()> {
                if store.active_authority() != Some(self.ctx.account.authority.clone()) {
                    return Err(garth::Error::Protocol(
                        "account changed during current reset".into(),
                    ));
                }
                store.batch(|store| {
                    store.reset_account_demand_progress();
                    store.set_current_generation(stage.generation());
                    store.set_current_reset_required(false);
                    store.clear_sync_cursor();
                });
                Ok(())
            })?;
            if let Err(error) =
                await_account_state_durable(&self.ctx, "failed frame current reset").await
            {
                self.rollback_current_pointer(&index, generation).await?;
                return Err(garth::Error::Protocol(error.to_string()));
            }
            stage.finish();
        }
        *cached = Some(index.clone());
        Ok(index)
    }

    async fn confirm_current_pointer_durable(
        &self,
        index: &crate::state::CurrentIndex,
        generation: u64,
    ) -> garth::Result<()> {
        let barrier = self
            .ctx
            .state_store
            .read(|store| -> anyhow::Result<_> {
                anyhow::ensure!(
                    store.active_authority() == Some(self.ctx.account.authority.clone())
                        && store.current_generation() == generation,
                    "account changed before confirming current pointer"
                );
                store.begin_durable_flush()
            })
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        barrier
            .wait()
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        index
            .confirm_durable_pointer(generation)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn rollback_current_pointer(
        &self,
        index: &crate::state::CurrentIndex,
        generation: u64,
    ) -> garth::Result<()> {
        index.poison();
        let restored = self.ctx.state_store.write(|store| {
            if store.active_authority() != Some(self.ctx.account.authority.clone()) {
                return false;
            }
            store.batch(|store| store.abort_account_demand_frame(generation));
            true
        });
        if !restored {
            return Err(garth::Error::Protocol(
                "account changed during current rollback".into(),
            ));
        }
        self.confirm_current_pointer_durable(index, generation)
            .await
    }
}

impl AccountStepCommitter for InksonAccountCommitter {
    async fn reset_account_context(&self, session_generation: u64) -> garth::Result<bool> {
        if session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(false);
        }
        let index = self.current_index().await?;
        let previous_generation = self
            .ctx
            .state_store
            .read(LocalStateStore::current_generation);
        let reset_frame = serde_json::from_value(serde_json::json!({"kind":"resync_required"}))
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let mut stage = index
            .stage_frame(previous_generation, &reset_frame)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(false);
        }
        stage.arm_account_commit();
        self.ctx
            .state_store
            .write(|store| {
                store.batch(|store| {
                    store.reset_account_demand_progress();
                    store.clear_sync_cursor();
                    store.set_current_generation(stage.generation());
                    store.set_current_reset_required(false);
                    let result = store.save_sync_demand_filter(None);
                    if result.is_err() {
                        store.abort_account_demand_frame(previous_generation);
                    }
                    result
                })
            })
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if let Err(error) =
            await_account_state_durable(&self.ctx, "account cursor and baseline reset").await
        {
            self.rollback_current_pointer(&index, previous_generation)
                .await?;
            return Err(garth::Error::Protocol(error.to_string()));
        }
        stage.finish();
        Ok(true)
    }

    async fn commit(&self, step: &AccountStreamStep) -> garth::Result<AccountCommitOutcome> {
        if step.frame.kind == arkret_sdk::AccountSubscribeFrameKind::ResyncRequired {
            return if self.reset_account_context(step.session_generation).await? {
                Ok(AccountCommitOutcome::Committed {
                    updates: step.updates.clone(),
                })
            } else {
                Ok(AccountCommitOutcome::Replay)
            };
        }
        let selected = selected_account_filter(&self.ctx);
        if step.request.filter != Some(selected)
            || step.session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(AccountCommitOutcome::Replay);
        }
        let current_index = self.current_index().await?;
        let previous_generation = self
            .ctx
            .state_store
            .read(LocalStateStore::current_generation);
        let mut current_stage = current_index
            .stage_frame(previous_generation, &step.frame)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if step.request.filter != Some(selected_account_filter(&self.ctx))
            || step.session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(AccountCommitOutcome::Replay);
        }
        current_stage.arm_account_commit();
        let (theme, changed, committed_updates) = self
            .ctx
            .state_store
            .write(|store| {
                store.batch(|store| {
                    let result = (|| -> anyhow::Result<_> {
                        let frame =
                            store.prepare_account_demand_frame(current_stage.filtered_frame())?;
                        let updates = garth::SyncResponseProcessor::process_frame(frame.clone())?;
                        let response = AccountSyncStep::from_updates(
                            step.cursor.clone().unwrap_or_default(),
                            updates,
                        )?;
                        let effects = apply_account_frame_payload(store, &response, &self.ctx);
                        if changed_device_accounts(&response.updates.device_lists)
                            .contains(&self.ctx.account.authority)
                        {
                            store.set_local_device_refresh_pending(true);
                        }
                        store.finish_account_demand_frame(&frame)?;
                        let cursor = step
                            .cursor
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("account frame lacks cursor"))?;
                        store.save_sync_cursor(cursor.clone());
                        store.set_current_generation(current_stage.generation());
                        store.save_sync_demand_filter(step.request.filter.clone())?;
                        Ok((effects.0, effects.1, response.updates))
                    })();
                    if result.is_err() {
                        store.abort_account_demand_frame(previous_generation);
                    }
                    result
                })
            })
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if let Err(error) = await_account_state_durable(&self.ctx, "account frame and cursor").await
        {
            self.rollback_current_pointer(&current_index, previous_generation)
                .await?;
            return Err(garth::Error::Protocol(error.to_string()));
        }
        current_stage.finish();
        if step.session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(AccountCommitOutcome::Committed {
                updates: committed_updates,
            });
        }
        if let Err(error) = refresh_current_product_view(&current_index, &self.ctx).await {
            // The authoritative cursor/current transaction is already durable.
            // Product cache failure must not turn it into an uncommitted frame.
            tracing::warn!(%error, "current product view remains pending");
        }
        if step.session_generation != self.ctx.session.generation()
            || self.ctx.effect.is_cancelled()
            || !self
                .ctx
                .state_store
                .read(|store| store.active_authority() == Some(self.ctx.account.authority.clone()))
        {
            return Ok(AccountCommitOutcome::Committed {
                updates: committed_updates,
            });
        }
        if changed || step.frame.realm_list.is_some() || step.frame.realm_list_changes.is_some() {
            self.ctx
                .realm_live_epoch
                .update(|epoch| *epoch = epoch.wrapping_add(1));
        }
        if let Some(value) = theme {
            self.ctx
                .projection_sink
                .projection(ClientProjectionEvent::Theme { value });
        }
        self.ctx
            .projection_sink
            .sync_status(SyncStatusEvent::Online);
        if let Ok(response) = AccountSyncStep::from_updates(
            step.cursor.clone().unwrap_or_default(),
            committed_updates.clone(),
        ) {
            refresh_projection_events_from_sync_response(&response, &self.ctx);
            for account in changed_device_accounts(&response.updates.device_lists) {
                crate::identity::device_directory::invalidate_actor(&account.to_string());
            }
        }
        if let Some(cursor) = &step.cursor {
            self.ctx
                .projection_sink
                .projection(ClientProjectionEvent::CursorCheckpoint {
                    scope: "account".into(),
                    cursor: cursor.clone(),
                });
        }
        Ok(AccountCommitOutcome::Committed {
            updates: committed_updates,
        })
    }
}

fn selected_account_filter(ctx: &SyncEngineContext) -> arkret_sdk::SyncFilter {
    let realms = arkret_sdk::RealmId::new(ctx.selected_realm_id.get().trim().to_owned())
        .ok()
        .into_iter()
        .collect();
    arkret_sdk::SyncFilter {
        realm_ids: Some(realms),
        timeline_limit: Some(20),
        lazy_load_members: Some(true),
        ..Default::default()
    }
}

async fn refresh_current_product_view(
    index: &crate::state::CurrentIndex,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let realm_id = ctx.selected_realm_id.get();
    let Ok(realm) = arkret_sdk::RealmId::new(realm_id.clone()) else {
        return Ok(());
    };
    let session_generation = ctx.session.generation();
    let mut entries = std::collections::BTreeMap::new();
    let mut remaining_bytes = 8 * 1024 * 1024usize - 4096;
    let selector = |cell: &str| -> anyhow::Result<arkret_sdk::CurrentSelector> {
        Ok(arkret_sdk::CurrentSelector {
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            cell_id: arkret_sdk::CellRef::new(cell.to_owned())?,
        })
    };
    for cell in crate::current_projection::REQUIRED_REALM_CELLS
        .into_iter()
        .chain([
            "ak:cell:ak.component.realm.profile.v1:null",
            "ak:cell:ak.component.realm.authority_root.v1:null",
            "ak:cell:ak.component.realm.digest_suite.v1:null",
            "ak:cell:ak.component.realm.reducer_profile.v1:null",
        ])
    {
        if let Some(entry) = index.read_selector_ready(&selector(cell)?).await? {
            let bytes = arkret_sdk::canonical::canonical_json_bytes(&entry)?.len();
            if bytes > remaining_bytes {
                break;
            }
            remaining_bytes -= bytes;
            entries.insert(entry.selector().canonical_key()?, entry);
        }
    }
    let default_strand = entries.values().find_map(|entry| {
        if entry.selector().cell_id.as_str() != crate::current_projection::REQUIRED_REALM_CELLS[3] {
            return None;
        }
        let arkret_sdk::CurrentResult::Value { value } = entry.result() else {
            return None;
        };
        arkret_sdk::StrandId::new(value.as_json().as_str()?.to_owned()).ok()
    });
    let requested = selected_account_filter(ctx)
        .strand_ids
        .unwrap_or_else(|| default_strand.into_iter().collect());
    'strands: for strand_id in requested {
        let budget = (512usize.saturating_sub(entries.len())).min(100);
        if budget == 0 {
            break;
        }
        let page = index
            .read_target_page(
                &realm_id,
                &arkret_sdk::CurrentTarget::Strand { strand_id },
                None,
                budget,
            )
            .await?;
        for entry in page.entries {
            let bytes = arkret_sdk::canonical::canonical_json_bytes(&entry)?.len();
            if bytes > remaining_bytes {
                break 'strands;
            }
            remaining_bytes -= bytes;
            entries.insert(entry.selector().canonical_key()?, entry);
        }
    }
    if ctx.effect.is_cancelled()
        || ctx.session.generation() != session_generation
        || ctx.selected_realm_id.get() != realm_id
        || !ctx
            .state_store
            .read(|store| store.active_authority() == Some(ctx.account.authority.clone()))
    {
        return Ok(());
    }
    let entries = entries.into_values().collect::<Vec<_>>();
    let ready = crate::current_projection::required_realm_values_ready(&entries, &realm_id);
    ctx.state_store
        .write(|store| store.install_current_product_view(&realm_id, entries, ready))?;
    ctx.realm_live_epoch
        .update(|epoch| *epoch = epoch.wrapping_add(1));
    Ok(())
}
struct InksonAccountPostCommit {
    ctx: SyncEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    removal_schedule: std::sync::Mutex<RemovalSchedule>,
}

fn scope_rotate_realm_ids(
    response: &AccountSyncStep,
    state_store: &LocalStateStore,
) -> Vec<String> {
    let mut realm_ids = response
        .updates
        .realm_updates
        .iter()
        .filter(|update| realm_update_has_durable_projection(update))
        .map(|update| update.realm_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    realm_ids.extend(
        state_store
            .all_move_submissions()
            .into_iter()
            .filter(|record| {
                record.kind == "mls_member_remove"
                    && record.state == crate::state::MoveSubmissionState::PendingMlsBinding
            })
            .map(|record| record.realm_id),
    );
    realm_ids.into_iter().collect()
}

impl InksonAccountPostCommit {
    fn active(&self) -> bool {
        self.generation.get() == self.start_generation && !self.ctx.effect.is_cancelled()
    }

    fn classify_error(&self, error: anyhow::Error) -> AccountPostCommitOutcome {
        if is_auth_expired_error(&error) || is_terminal_session_grant_error(&error) {
            AccountPostCommitOutcome::Unauthorized {
                reason: Some(error.to_string()),
            }
        } else {
            tracing::debug!(error = %error, "account post-commit work deferred");
            AccountPostCommitOutcome::Retry
        }
    }
}

/// The hook runs against whichever transport carried the step, but its own work
/// — invite-delivery recovery, MLS, calls, to-device acknowledgement — is not a covered
/// operation (§1), so it always uses the canonical HTTPS client the rail keeps.
impl
    AccountPostCommitHook<
        crate::transport::websocket_rail::StreamRail<crate::client_core::InksonAccountTransport>,
    > for InksonAccountPostCommit
{
    async fn post_commit(
        &self,
        transport: &crate::transport::websocket_rail::StreamRail<
            crate::client_core::InksonAccountTransport,
        >,
        step: &AccountStreamStep,
    ) -> garth::Result<AccountPostCommitOutcome> {
        let http = transport.http().http();
        if !self.active()
            || step.session_generation != self.ctx.session.generation()
            || step.request.filter != Some(selected_account_filter(&self.ctx))
        {
            return Ok(AccountPostCommitOutcome::Continue);
        }
        if self
            .ctx
            .state_store
            .read(LocalStateStore::local_device_refresh_pending)
            || changed_device_accounts(&step.updates.device_lists)
                .contains(&self.ctx.account.authority)
        {
            let viewer = match http.account_viewer().await {
                Ok(viewer) => viewer,
                Err(error) => return Ok(self.classify_error(error.into())),
            };
            if !self.active()
                || step.session_generation != self.ctx.session.generation()
                || !self.ctx.state_store.read(|store| {
                    store.active_authority() == Some(self.ctx.account.authority.clone())
                })
            {
                return Ok(AccountPostCommitOutcome::Continue);
            }
            if viewer.principal_id != self.ctx.principal_id {
                return Ok(
                    self.classify_error(anyhow::anyhow!("account viewer principal mismatch"))
                );
            }
            for device in &viewer.devices {
                if let Err(error) = device.validate() {
                    return Ok(self.classify_error(error.into()));
                }
            }
            if device_summary_revokes_local_device(
                &viewer,
                &self.ctx.principal_id,
                &self.ctx.device_id,
            ) {
                self.ctx
                    .state_store
                    .write(LocalStateStore::clear_device_scoped);
                rotate_live_device_id_after_revocation(&self.ctx.live_device_id);
                self.ctx
                    .session
                    .invalidate("this device was revoked by its Station");
                return Ok(AccountPostCommitOutcome::Unauthorized {
                    reason: Some("this device was revoked by its Station".into()),
                });
            }
            self.ctx
                .state_store
                .write(|store| store.set_local_device_refresh_pending(false));
        }
        let submitter = crate::event_submit::EventSubmitter::new(http.clone())
            .with_state_store(self.ctx.state_store.clone());
        if let Err(error) = submitter.drain_outbound().await {
            tracing::debug!(
                ?error,
                "account post-commit deferred durable outbound drain"
            );
        }
        if let Err(error) = submitter.drain_mls_outbound().await {
            tracing::debug!(?error, "account post-commit deferred MLS outbound drain");
        }

        // A bounded account-sync poll is also the retry clock for durable
        // outbound work. Its empty business delta must not suppress a due
        // RetryAt item; projection work below still remains delta-driven.
        if account_updates_are_empty(&step.updates) {
            return Ok(AccountPostCommitOutcome::Continue);
        }
        let cursor = step.cursor.clone().ok_or_else(|| {
            garth::Error::Protocol("account post-commit step has no cursor".to_owned())
        })?;
        let response = AccountSyncStep::from_updates(cursor, step.updates.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let api = TransportClient::from_http(
            http.clone(),
            crate::transport::RequestContext::new(self.ctx.token.get()),
        );

        let agent_evidence_changed =
            crate::identity::agent_signer_evidence::prefetch_from_realm_projections(
                http,
                &response.realm_projections,
                &self.ctx.state_store,
            )
            .await;
        let state_store_for_profiles = self.ctx.state_store.clone();
        let device_keys_changed = prefetch_persistent_event_sender_keys(
            &api,
            &response,
            self.ctx.state_store.clone(),
            |realm_id| {
                state_store_for_profiles
                    .read(|store| store.realm_projection_is_minimal_metadata(realm_id))
            },
        )
        .await;
        if agent_evidence_changed || device_keys_changed {
            refresh_projection_events_from_sync_response(&response, &self.ctx);
        }
        prefetch_member_identity_proof_keys(&api, &response, self.ctx.state_store.clone()).await;
        if let Err(error) = process_to_device_delivery(&api, &response, &self.ctx).await {
            return Ok(self.classify_error(error));
        }

        // Typing/presence/call-signal deltas cannot create MLS removal
        // obligations. A previously discovered PendingMlsBinding does need a
        // retry on a later bounded poll, however, even when that poll carries
        // no new durable Realm delta (for example after a transient proof
        // fetch failure).
        let realm_ids = self
            .ctx
            .state_store
            .read(|store| scope_rotate_realm_ids(&response, store));
        if !realm_ids.is_empty() || self.removal_schedule.lock().unwrap().has_pending() {
            run_circle_scope_rotate_pass(
                self.start_generation,
                self.generation.clone(),
                &self.ctx,
                &realm_ids,
                &self.removal_schedule,
            )
            .await;
            // This remains an opportunistic durability pass, driven by new
            // durable Realm work or an explicit pending reconciliation.
            run_idle_self_update_pass(self.start_generation, self.generation.clone(), &self.ctx)
                .await;
        }
        Ok(AccountPostCommitOutcome::Continue)
    }
}

pub async fn run_sync_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: SyncEngineContext,
) {
    ctx.projection_sink.sync_status(SyncStatusEvent::Connecting);
    let actor_id = ctx.principal_id.clone();
    let device_id = match arkret_sdk::DeviceId::new(ctx.device_id.trim().to_owned()) {
        Ok(device_id) => device_id,
        Err(error) => {
            ctx.projection_sink.sync_status(SyncStatusEvent::Terminal {
                reason: format!("invalid device id: {error}"),
            });
            return;
        }
    };
    let provider = AccountTransportProvider {
        ctx: ctx.clone(),
        generation: generation.clone(),
        start_generation,
    };
    let committer = InksonAccountCommitter {
        ctx: ctx.clone(),
        current_index: tokio::sync::Mutex::new(None),
    };
    let hook = InksonAccountPostCommit {
        removal_schedule: std::sync::Mutex::new(RemovalSchedule::default()),
        ctx: ctx.clone(),
        generation,
        start_generation,
    };
    let control = SyncLoopControl::new();
    let client = ctx.client_runtime.client();
    let runner = client.run_account_steps(
        actor_id,
        device_id,
        &provider,
        AccountStepHandlers::new(&committer, &hook),
        &control,
        RunOptions {
            // Successful bounded polls reconnect immediately. The server
            // owns the 30-second idle wait window.
            beat: Duration::ZERO,
            min_backoff: BACKOFF_FLOOR,
            max_backoff: BACKOFF_CEILING,
            jitter_ratio: 0.2,
        },
    );
    let maintenance = async {
        let mut delay = Duration::from_secs(1);
        loop {
            crate::runtime_helpers::sleep_for(delay).await;
            if !provider.is_active() {
                break;
            }
            let index = committer.current_index.lock().await.clone();
            let Some(index) = index else { continue };
            delay = match index.maintain().await {
                Ok(true) => Duration::from_millis(250),
                Ok(false) => Duration::from_secs(1),
                Err(error) => {
                    tracing::debug!(%error, "current index maintenance deferred");
                    Duration::from_secs(5)
                }
            };
        }
    };
    let result = tokio::select! {
        result = runner => result,
        _ = maintenance => Ok(garth::RunStopReason::LifecycleEnded),
    };
    match result {
        Ok(garth::RunStopReason::Unauthorized { reason }) => {
            ctx.projection_sink
                .sync_status(SyncStatusEvent::NeedsSignIn {
                    reason: reason
                        .unwrap_or_else(|| "session grant is no longer active".to_owned()),
                });
        }
        Ok(garth::RunStopReason::Cancelled | garth::RunStopReason::LifecycleEnded) => {
            ctx.projection_sink.sync_status(SyncStatusEvent::Offline);
        }
        Ok(garth::RunStopReason::Failed { class }) => {
            ctx.projection_sink.sync_status(SyncStatusEvent::Terminal {
                reason: format!("account runner failed: {class:?}"),
            });
        }
        Err(error) => ctx.projection_sink.sync_status(SyncStatusEvent::Terminal {
            reason: error.to_string(),
        }),
    }
}

const REMOVAL_SCOPES_PER_PASS: usize = 4;

/// Session-local scheduling coordinates, never reusable authorization.
#[derive(Default)]
struct RemovalSchedule {
    pending: BTreeSet<arkret_sdk::RealmId>,
    last_realm: Option<arkret_sdk::RealmId>,
    scopes: std::collections::BTreeMap<arkret_sdk::RealmId, RemovalScopeRound>,
}
#[derive(Default)]
struct RemovalScopeRound {
    next: usize,
    empty: std::collections::BTreeMap<String, String>,
}
impl RemovalSchedule {
    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
    fn next_realm(&mut self, ids: &[String]) -> Option<arkret_sdk::RealmId> {
        self.pending.extend(
            ids.iter()
                .filter_map(|id| arkret_sdk::RealmId::new(id.clone()).ok()),
        );
        let next = self
            .pending
            .iter()
            .find(|id| self.last_realm.as_ref().is_none_or(|last| *id > last))
            .or_else(|| self.pending.first())
            .cloned()?;
        self.last_realm = Some(next.clone());
        Some(next)
    }
}

fn removal_scope_stamp(store: &LocalStateStore, scope: &arkret_sdk::ScopeRef) -> Option<String> {
    let checkpoint = store.mls_checkpoint_for_scope(scope)?;
    let base = store
        .mls_group_state_ref_for_scope(scope, &checkpoint.group_id, checkpoint.epoch)
        .ok()?;
    let mut basis = store
        .seal_view_for_realm(scope.realm_id_opt()?.as_str())
        .frontier;
    basis.sort();
    basis.dedup();
    arkret_sdk::canonical::canonical_sha256(&(checkpoint, base, basis)).ok()
}

#[cfg(test)]
mod removal_schedule_tests {
    use super::*;

    #[test]
    fn pending_realm_round_robin_does_not_starve_later_realms() {
        let first = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned();
        let second = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned();
        let mut schedule = RemovalSchedule::default();
        let a = schedule.next_realm(&[first, second]).unwrap();
        let b = schedule.next_realm(&[]).unwrap();
        assert_ne!(a, b);
        assert_eq!(schedule.next_realm(&[]), Some(a.clone()));
        schedule.pending.remove(&a);
        assert_eq!(schedule.next_realm(&[]), Some(b));
    }
}

/// Fence every asynchronous reconciliation boundary, including local installation.
fn removal_session_current(
    start_generation: u64,
    generation: &crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
) -> bool {
    generation.get() == start_generation
        && ctx
            .state_store
            .read(|store| store.active_authority())
            .as_ref()
            == Some(&ctx.account.authority)
        && crate::secure_key_store::active_device_seed_scope().is_some_and(|scope| {
            scope.authority == ctx.account.authority && scope.device_id == ctx.account.device_id
        })
}

/// Reconcile occupied RFC MLS leaves with the authenticated Station. Local
/// membership projections are never negative authority for an MLS Remove.
async fn run_circle_scope_rotate_pass(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
    realm_ids: &[String],
    schedule: &std::sync::Mutex<RemovalSchedule>,
) {
    if !removal_session_current(start_generation, &generation, ctx) {
        return;
    }
    let base = ctx.account.server_url.as_str().to_owned();
    let token = ctx.token.get();
    let authority = &ctx.account.authority;
    let device = &ctx.account.device_id;
    let actor = ctx.account.principal_id().to_string();
    let Some(realm) = schedule.lock().unwrap().next_realm(realm_ids) else {
        return;
    };
    {
        if !removal_session_current(start_generation, &generation, ctx) {
            return;
        }
        let mut scopes = vec![arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        }];
        // This read discovers scopes only; member_ids never decide removals.
        let circles =
            crate::transport::auth::with_authed_sdk_client(&base, token.clone(), |http| {
                let realm = realm.clone();
                async move { crate::transport::circle::list_circles(&http, realm.as_str()).await }
            })
            .await;
        let mut all_reconciled = circles.is_ok();

        if let Ok(circles) = circles {
            for circle in circles.circle_views {
                if circle.state == arkret_sdk::CircleState::Active
                    && circle.encryption_profile == arkret_sdk::EncryptionProfile::MlsRfc9420
                {
                    scopes.push(arkret_sdk::ScopeRef::Circle {
                        realm_id: realm.clone(),
                        circle_id: circle.circle_id,
                    });
                }
            }
        }
        let relevant_scopes = scopes
            .into_iter()
            .filter(|scope| {
                ctx.state_store
                    .read(|store| store.mls_checkpoint_for_scope(scope).is_some())
            })
            .collect::<Vec<_>>();
        let selected_scopes = {
            let mut scheduling = schedule.lock().unwrap();
            let round = scheduling.scopes.entry(realm.clone()).or_default();
            let count = relevant_scopes.len();
            if count == 0 {
                Vec::new()
            } else {
                let start = round.next % count;
                let selected = (0..count.min(REMOVAL_SCOPES_PER_PASS))
                    .map(|offset| relevant_scopes[(start + offset) % count].clone())
                    .collect::<Vec<_>>();
                round.next = (start + selected.len()) % count;
                selected
            }
        };
        for scope in selected_scopes {
            if !removal_session_current(start_generation, &generation, ctx) {
                return;
            }
            if ctx
                .state_store
                .read(|store| store.mls_checkpoint_for_scope(&scope).is_none())
            {
                continue;
            }
            let frozen = match ctx.state_store.read(|store| {
                crate::circle_mls::MembershipRemovalSnapshot::capture(
                    store,
                    scope.clone(),
                    authority,
                    device,
                )
            }) {
                Ok(value) => value,
                Err(error) => {
                    all_reconciled = false;
                    tracing::debug!(%realm, %error, "MLS removal snapshot is not ready");
                    continue;
                }
            };
            let submitted = crate::transport::auth::with_authed_api(&base, token.clone(), |api| {
                let frozen = &frozen;
                let scope = &scope;
                let generation = &generation;
                let actor = &actor;
                async move {
                    let fence = || -> anyhow::Result<()> {
                        anyhow::ensure!(
                            removal_session_current(start_generation, generation, ctx),
                            "MLS removal account session changed"
                        );
                        ctx.state_store
                            .read(|store| frozen.ensure_current(store))
                            .map_err(anyhow::Error::msg)
                    };
                    fence()?;
                    let outcome = api
                        .sdk_http_client()?
                        .mls_membership_removal(&frozen.request, authority)
                        .await?;
                    fence()?;
                    outcome.validate_for_request(&frozen.request, authority)?;
                    if outcome.remove_leaf_indices.is_empty() {
                        return Ok(None);
                    }
                    let leaves = crate::mls::governance_proof::security_frontier_without_leaves(
                        frozen.request.local_mls_leaves.clone(),
                        &outcome.remove_leaf_indices,
                    );
                    let proof_request = arkret_sdk::MlsGovernanceFrontierRequestBody {
                        effective_scope: scope.clone(),
                        mls_group_id: frozen.request.mls_group_id.clone(),
                        local_mls_leaves: leaves.clone(),
                        seal_basis: frozen.request.seal_basis.clone(),
                        base_group_state_ref: Some(frozen.request.base_group_state_ref.clone()),
                        proposed_group_genesis_binding: None,
                        previous_epoch: frozen.request.epoch,
                        next_epoch: frozen
                            .request
                            .epoch
                            .checked_add(1)
                            .context("MLS epoch overflow")?,
                    };
                    crate::mls::governance_proof::fetch_and_cache_frontier(
                        &api,
                        ctx.state_store.clone(),
                        &proof_request,
                        &leaves,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
                    fence()?;
                    let local = ctx.state_store.read(Clone::clone);
                    let secure = crate::secure_key_store::default_secure_key_store("inkson");
                    let draft = crate::circle_mls::build_remove_scope_rotate_draft(
                        &local,
                        secure.as_ref(),
                        authority,
                        actor,
                        device,
                        frozen,
                        &outcome,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
                    fence()?;
                    let submitter = api.event_submitter()?;
                    let authored = submitter.author_event_unit(draft.steps).await?;
                    fence()?;
                    let commit_id = authored
                        .iter()
                        .find(|e| e.kind.as_str() == event_kind_str::MLS_COMMIT)
                        .map(|e| e.event_id().clone())
                        .context("MLS Remove unit has no Commit")?;
                    if let arkret_sdk::ScopeRef::Circle { circle_id, .. } = scope {
                        let idempotency = crate::operation::uuid_v7();
                        let body = arkret_sdk::CircleScopeRotateRequestBody {
                            events: authored.iter().map(|e| e.event().clone()).collect(),
                            idempotency_key: Some(idempotency.clone()),
                        };
                        submitter
                            .http()
                            .circle_scope_rotate(circle_id.as_str(), &idempotency, &body)
                            .await?;
                    } else {
                        submitter
                            .submit_signed_sdk_events_batch(&authored, None)
                            .await?;
                    }
                    fence()?;
                    Ok(Some((draft.post_commit_checkpoint, commit_id)))
                }
            })
            .await;
            match submitted {
                Ok(None) => {
                    let stamp = ctx.state_store.read(|store| {
                        frozen.ensure_current(store).ok()?;
                        removal_scope_stamp(store, &scope)
                    });
                    if let Some(stamp) = stamp {
                        schedule
                            .lock()
                            .unwrap()
                            .scopes
                            .entry(realm.clone())
                            .or_default()
                            .empty
                            .insert(frozen.request.mls_group_id.to_string(), stamp);
                    } else {
                        all_reconciled = false;
                    }
                }
                Ok(Some((checkpoint, commit))) => {
                    if !removal_session_current(start_generation, &generation, ctx) {
                        return;
                    }
                    let installed = ctx.state_store.write(|store| {
                        // Compare-and-install under the same host state write guard.
                        frozen.ensure_current(store)?;
                        let circle = match &scope {
                            arkret_sdk::ScopeRef::Circle { circle_id, .. } => {
                                Some(circle_id.as_str())
                            }
                            _ => None,
                        };
                        store.record_mls_group_state_ref_for_effective_scope(
                            realm.to_string(),
                            circle,
                            checkpoint.group_id.as_str(),
                            checkpoint.epoch,
                            commit,
                        )?;
                        store.save_mls_checkpoint_for_scope(&scope, checkpoint)?;
                        Ok::<_, String>(())
                    });
                    if let Err(error) = installed {
                        tracing::warn!(%realm, %error, "accepted MLS Remove awaits current-state reconciliation");
                    }
                    // Preserve the existing one-Commit-per-pass write bound.
                    return;
                }
                Err(error) => {
                    all_reconciled = false;
                    if !removal_session_current(start_generation, &generation, ctx) {
                        return;
                    }
                    ctx.state_store.write(|store| {
                        store.record_move_submission(
                            format!("mls-removal:{}:{}", realm, frozen.request.mls_group_id),
                            realm.to_string(),
                            "mls_member_remove",
                            crate::state::MoveSubmissionState::PendingMlsBinding,
                            Some(
                                "MLS membership reconciliation is unavailable; retry required"
                                    .to_owned(),
                            ),
                            None,
                        );
                    });
                    tracing::debug!(%realm, error = %error.display_diagnostic(), "MLS removal remains pending");
                }
            }
        }
        if removal_session_current(start_generation, &generation, ctx) {
            let mut scheduling = schedule.lock().unwrap();
            let round = scheduling.scopes.entry(realm.clone()).or_default();
            let complete = all_reconciled
                && ctx.state_store.write(|store| {
                    let exact = relevant_scopes.iter().all(|scope| {
                        let Ok(group) = scope.canonical_mls_group_id() else {
                            return false;
                        };
                        removal_scope_stamp(store, scope)
                            .is_some_and(|stamp| round.empty.get(&group) == Some(&stamp))
                    });
                    if exact {
                        store.resolve_member_remove_mls_bindings(realm.as_str());
                    }
                    exact
                });
            if complete {
                scheduling.pending.remove(&realm);
                scheduling.scopes.remove(&realm);
            } else {
                // A partial round or failed discovery must wake the next bounded poll.
                ctx.state_store.write(|store| {
                    store.record_move_submission(
                        format!("mls-removal-round:{realm}"),
                        realm.to_string(),
                        "mls_member_remove",
                        crate::state::MoveSubmissionState::PendingMlsBinding,
                        Some("MLS scope reconciliation is pending".to_owned()),
                        None,
                    );
                });
            }
        }
    }
}

/// Background idle self-preservation commit driver.
///
/// Walks persisted MLS Realm snapshots and submits at most one due
/// self-update commit per pass. The snapshot is persisted only after
/// server acceptance, matching the send path and epoch-rotation button.
async fn run_idle_self_update_pass(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
) {
    if generation.get() != start_generation {
        return;
    }
    let base = ctx.account.server_url.as_str().to_owned();
    let token = ctx.token.get();
    let actor_id = ctx.account.principal_id().to_string();
    let authority = ctx.account.authority.clone();
    let device_id = ctx.account.device_id.clone();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.as_str().is_empty()
    {
        return;
    }
    let now = crate::clock::now_utc();
    let realm_ids: Vec<String> = ctx
        .state_store
        .read(|store| store.mls_local_checkpoints().into_keys().collect());
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    for realm_id in realm_ids {
        // Re-check cancellation between Realms: a logout / profile rotation
        // mid-pass must not keep minting commits under the dead generation.
        if generation.get() != start_generation {
            return;
        }
        // Build the gated idle commit under a read borrow. `Ok(None)` is the
        // overwhelmingly common case (Realm not yet due / before this member's
        // jitter slot / a pending commit already suppresses it).
        let built = ctx.state_store.read(|store| {
            crate::mls::runtime::build_idle_self_update_commit(
                store,
                secure_store.as_ref(),
                &realm_id,
                &authority,
                &actor_id,
                &device_id,
                now,
            )
            .map_err(|err| err.user_message())
        });
        let built = match built {
            Ok(None) => Ok(None),
            Ok(Some((commit_envelope, snapshot, previous_governance_binding))) => {
                let schedule_hash = commit_envelope.commit_digest.clone();
                let local_state = ctx.state_store.read(Clone::clone);
                crate::mls::group_events::mls_commit_event_from_store(
                    &local_state,
                    &realm_id,
                    &actor_id,
                    &schedule_hash,
                    &commit_envelope,
                    &previous_governance_binding,
                )
                .await
                .map(|event| Some((event, commit_envelope.epoch, snapshot)))
            }
            Err(error) => Err(error),
        };
        let (commit_event, next_epoch, snapshot) = match built {
            Ok(Some(parts)) => parts,
            Ok(None) => continue,
            Err(err) => {
                // Soft failure (missing secret, build error): log once and move
                // on. Local state is untouched; the next pass retries.
                tracing::debug!(
                    %realm_id,
                    error = %err,
                    "sync_engine: idle §5.6 self-update build skipped",
                );
                continue;
            }
        };
        // Submit the canonical ak.mls.commit. The server's expected-prev-epoch
        // CAS (§5.4) rejects the loser of any concurrent commit race; either
        // way the epoch advances, so a rejection is fine — we simply do NOT
        // persist the local snapshot (persist-on-accept).
        let submit_token = token.clone();
        match crate::transport::auth::with_authed_api(&base, submit_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&commit_event).await
        })
        .await
        {
            Ok(accepted) => {
                let commit_event_id =
                    arkret_sdk::EventId::new(accepted.event_id.clone()).map_err(anyhow::Error::msg);
                let Ok(commit_event_id) = commit_event_id else {
                    tracing::debug!(
                        %realm_id,
                        "sync_engine: accepted self-update commit carries an invalid Event id",
                    );
                    return;
                };
                if generation.get() != start_generation {
                    // A late accept under a stale generation must not write the
                    // snapshot into the new generation's store.
                    return;
                }
                let persisted = ctx.state_store.write(|store| {
                    store.record_mls_group_state_ref_for_effective_scope(
                        realm_id.clone(),
                        None,
                        snapshot.group_id.as_str(),
                        snapshot.epoch,
                        commit_event_id,
                    )?;
                    store.save_mls_checkpoint(realm_id.clone(), snapshot)?;
                    Ok::<_, String>(())
                });
                if let Err(error) = persisted {
                    tracing::error!(
                        %realm_id,
                        %error,
                        "sync_engine: idle MLS commit group-state reference conflicted",
                    );
                    return;
                }
                tracing::info!(
                    %realm_id,
                    epoch = next_epoch,
                    "sync_engine: §5.6 idle self-update commit accepted",
                );
                // One commit per pass: a multi-Realm client staggers the rest
                // across subsequent sync iterations rather than bursting.
                return;
            }
            Err(err) => {
                tracing::debug!(
                    %realm_id,
                    error = %err.display_diagnostic(),
                    "sync_engine: idle §5.6 self-update commit not accepted (race or transient)",
                );
                // Lost the §5.4 CAS or a transient error — discard the local
                // change (never persisted) and let the next pass re-evaluate.
                continue;
            }
        }
    }
}

/// Prime the same device-directory cache used by the synchronous chat proof
/// verifier for proof-bearing persistent events in the current sync response.
/// Chat projection cannot await `keys/query` inline, so `apply_response` first
/// renders unresolved proofs conservatively; this pass resolves missing sender
/// device keys and the caller then recomputes the projection.
///
/// SPI-INK-001 (encryption-and-audit.md §2.10.3): Realms for which
/// `is_minimal_metadata_realm(realm_id)` returns true are excluded — content
/// authorship there is anchored to the active MLS LeafNode and MUST NOT form
/// a principal-scoped `(actor, device)` `keys/query` pair.
pub(crate) async fn prefetch_persistent_event_sender_keys<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    response: &AccountSyncStep,
    state_store: S,
    is_minimal_metadata_realm: impl Fn(&str) -> bool,
) -> bool {
    let pairs = collect_persistent_proof_sender_devices(
        &response.realm_projections,
        &is_minimal_metadata_realm,
    );
    prefetch_persistent_event_sender_key_pairs(api, pairs, state_store).await
}

/// MID-5: resolve the authoritative device signing key for every
/// `ak.member.identity.update` asserter referenced by this sync response, so the
/// synchronous [`crate::identity::member_identity_store::MemberIdentityStore`] proof
/// verifier (which is cache-only and fail-closed) can validate the proofs. The
/// `(actor, device)` pair is derived from each proof's `verification_method`
/// (`did:method:identifier#device`); the controller MUST be the asserting actor.
async fn prefetch_member_identity_proof_keys<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    response: &AccountSyncStep,
    state_store: S,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for body in response.realm_projections.values() {
        collect_member_identity_proof_devices_from_value(body, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(api, pairs.into_iter().collect(), state_store).await
}

pub(crate) async fn prefetch_persistent_event_sender_keys_from_values<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    values: &[Value],
    state_store: S,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for value in values {
        collect_proof_sender_devices_from_value(value, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(api, pairs.into_iter().collect(), state_store).await
}

/// Fetch only missing device facts from the authenticated account Station.
async fn prefetch_persistent_event_sender_key_pairs<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    pairs: Vec<(String, String)>,
    state_store: S,
) -> bool {
    if pairs.is_empty() {
        return false;
    }
    let missing: Vec<(String, String)> = pairs
        .into_iter()
        .filter(|(actor, device)| {
            !matches!(
                crate::identity::device_directory::cached_device_signing_key(actor, device),
                crate::identity::device_directory::CacheLookup::Hit(_)
            )
        })
        .collect();
    if missing.is_empty() {
        return false;
    }

    let Some(authority) = state_store.with_read(|store| store.active_authority()) else {
        return false;
    };
    for (actor, device) in missing {
        if state_store
            .with_read(|store| store.active_authority())
            .as_ref()
            != Some(&authority)
        {
            return false;
        }
        let _ = crate::identity::device_directory::resolve_device_signing_key(api, &actor, &device)
            .await;
    }
    true
}

fn refresh_projection_events_from_sync_response(
    response: &AccountSyncStep,
    ctx: &SyncEngineContext,
) {
    let state_store = ctx.state_store.clone();
    let synced_projection_events = state_store.read(|store| {
        crate::state::projection::projection_events_from_sync_realms(
            &response.realm_projections,
            Some(store),
            Some((&ctx.account.authority, &ctx.account.device_id)),
        )
    });
    for event in synced_projection_events {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Account(event));
    }
}

fn rotate_live_device_id_after_revocation(
    live_device_id: &crate::runtime::input::ValueCell<String>,
) {
    live_device_id.set(crate::config::new_device_id());
}

/// Freeze the current account state and wait until IndexedDB confirms the
/// corresponding queue sequence before performing a destructive remote ACK.
async fn await_account_state_durable(
    ctx: &SyncEngineContext,
    operation: &str,
) -> anyhow::Result<()> {
    let barrier = ctx
        .state_store
        .read(|store| store.begin_durable_flush())
        .map_err(|error| anyhow::anyhow!("begin durable {operation}: {error}"))?;
    barrier
        .wait()
        .await
        .map_err(|error| anyhow::anyhow!("persist {operation}: {error}"))
}

async fn process_to_device_delivery(
    api: &TransportClient,
    response: &AccountSyncStep,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let key_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let keys = key_clients.keys();
    let mut durable_prefix = ctx
        .state_store
        .read(|store| store.persist_error().is_none());
    if durable_prefix
        && !response.updates.to_device.is_empty()
        && to_device_batch_safe_for_ingest_ack(&response.updates.to_device)
        && let Some(ack_token) = response.updates.to_device_ack_token.as_deref()
    {
        await_account_state_durable(ctx, "account to-device batch before ACK").await?;
        keys.ack_device_messages(ack_token).await?;
    }

    let mut next_cursor = to_device_backfill_cursor(&response.updates);
    let mut page_count = 0usize;
    while let Some(cursor) = next_cursor {
        page_count += 1;
        if page_count > MAX_TO_DEVICE_BACKFILL_PAGES {
            anyhow::bail!(
                "to-device backfill exceeded {MAX_TO_DEVICE_BACKFILL_PAGES} pages without finishing"
            );
        }
        let page = keys
            .receive_device_messages_page(Some(&cursor), Some(TO_DEVICE_PAGE_LIMIT))
            .await?;
        let messages = page.messages.clone();
        let persisted = ctx.state_store.write(|store| {
            store.ingest_to_device_messages(&messages);
            store.persist_error().is_none()
        });
        if !persisted {
            durable_prefix = false;
        }
        if durable_prefix
            && !messages.is_empty()
            && to_device_batch_safe_for_ingest_ack(&messages)
            && let Some(ack_token) = page.ack_token.as_deref()
        {
            await_account_state_durable(ctx, "paginated to-device batch before ACK").await?;
            keys.ack_device_messages(ack_token).await?;
        }
        if !(page.has_more || page.limited) {
            break;
        }
        next_cursor = page.next_cursor.clone();
        if next_cursor.is_none() {
            anyhow::bail!("to-device page reported more data without next_cursor");
        }
    }
    ctx.projection_sink
        .projection(ClientProjectionEvent::DeviceQueue {
            pending: ctx
                .state_store
                .read(|store| store.load().to_device_inbox.len()),
        });
    Ok(())
}

/// Fold the realm's discussion timeline into the shared `raw_operations` log so
/// the Discussion tab projects local-first — no per-open realm backfill /
/// redecrypt — mirroring [`ingest_kanban_projection_events`].
/// Returns the number of newly inserted / changed records. Stores only
/// ciphertext envelopes / tombstones (never decrypted plaintext); dedup is by
/// the message event id via `upsert_raw_operation`.
fn ingest_message_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    ingest_message_projection_events(store, realm_id, &sync_realm_timeline_events(body))
}

pub(crate) fn ingest_moderation_events(
    store: &mut LocalStateStore,
    events: &[garth::ClientEvent],
) -> usize {
    let records =
        crate::state::projection::moderation_ops::moderation_operations_from_client_events(events);
    let mut changed = 0;
    for record in records {
        if store.upsert_raw_operation(record.operation_id, record.realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

/// Fold a batch of discussion message events into `raw_operations`. Shared by
/// the account-aggregate sync path (above) and the per-realm `events/subscribe`
/// engine ([`crate::realm_events_engine`]). A cross-member message omitted from
/// the account aggregate still lands locally through the Realm's durable event
/// stream; both paths dedupe by message Event id.
pub(crate) fn ingest_message_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    let records =
        crate::state::projection::message_ops::message_operations_from_events(realm_id, events);
    let mut changed = 0;
    for record in records {
        if store.upsert_raw_operation(record.operation_id, record.realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

pub(crate) fn ingest_message_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let records = crate::state::projection::message_ops::message_operations_from_client_events(
        realm_id, events,
    );
    let mut changed = 0;
    for record in records {
        if store.upsert_raw_operation(record.operation_id, record.realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

/// Fold a batch of realm events into the local kanban `raw_operations` overlay,
/// returning the number of records that were newly inserted / changed. Shared
/// by the account-aggregate sync path (above) and the per-realm
/// `events/subscribe` engine ([`crate::realm_events_engine`]) so both sources
/// dedupe through the same `operation_id` upsert. Events are the projection
/// event JSON shape (`event_kind` / `payload` / `operation_id`), matching both
/// `account.subscribe` `state.events[]` and `events/subscribe` Event frames.
pub(crate) fn ingest_kanban_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[arkret_sdk::Event],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    // Single ingest funnel: fold EVERY kanban-relevant kind (space.create,
    // strand.create, strand.update, strand.move/reorder, strand.archive/restore,
    // relation.*) into `raw_operations` so the event-sourced `project_board`
    // sees the full log. The prior code ingested only strand.update +
    // space.create, which silently dropped remote `ak.strand.create` — the
    // root cause of cross-member cards never appearing.
    let records = crate::state::projection::kanban_ops::kanban_operations_from_events(events);
    let mut changed = 0;
    for record in records {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

pub(crate) fn ingest_kanban_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let records =
        crate::state::projection::kanban_ops::kanban_operations_from_client_events(events);
    let mut changed = 0;
    for record in records {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

// Internal ingest-dispatch enum: each value is constructed from one Event and
// consumed immediately, so boxing the larger variant would only add an
// allocation per membership Event without changing layout anywhere durable.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum LocalMembershipEvent {
    MemberState(arkret_sdk::MembershipPayload),
    InviteCreate(arkret_sdk::InviteCreatePayload),
    InviteAccept(arkret_sdk::InviteAcceptPayload),
}

impl LocalMembershipEvent {
    fn from_sdk_event(event: &arkret_sdk::Event) -> Option<Self> {
        Some(match &event.kind {
            arkret_sdk::EventKind::MemberState => Self::MemberState(
                event
                    .typed_payload::<arkret_wire::event_spec::MemberState>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::InviteAccept => Self::InviteAccept(
                event
                    .typed_payload::<arkret_wire::event_spec::InviteAccept>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::InviteCreate => Self::InviteCreate(
                event
                    .typed_payload::<arkret_wire::event_spec::InviteCreate>()
                    .ok()?,
            ),
            _ => return None,
        })
    }

    fn record_value(&self, metadata: &LocalMembershipMetadata) -> Option<Value> {
        macro_rules! serialize_record {
            ($kind:ident, $payload:expr) => {
                serde_json::to_value(LocalMembershipRecord {
                    kind: arkret_sdk::EventKind::$kind,
                    operation_id: &metadata.operation_id,
                    event_id: &metadata.event_id,
                    invite_id: match self {
                        Self::InviteCreate(_) => Some(arkret_sdk::InviteId::from_event_id(
                            &arkret_sdk::EventId::new(metadata.event_id.clone()).ok()?,
                        )),
                        _ => None,
                    },
                    actor_id: &metadata.actor_id,
                    signing_device_id: metadata.signing_device_id.as_ref(),
                    created_at: &metadata.created_at,
                    write_state: "synced",
                    body: $payload,
                })
                .ok()
            };
        }
        match self {
            Self::MemberState(payload) => serialize_record!(MemberState, payload),
            Self::InviteCreate(payload) => serialize_record!(InviteCreate, payload),
            Self::InviteAccept(payload) => serialize_record!(InviteAccept, payload),
        }
    }
}

#[derive(Serialize)]
struct LocalMembershipRecord<'a, T> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    event_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite_id: Option<arkret_sdk::InviteId>,
    actor_id: &'a arkret_sdk::ActorId,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_device_id: Option<&'a arkret_sdk::DeviceId>,
    created_at: &'a str,
    write_state: &'static str,
    body: &'a T,
}

struct LocalMembershipMetadata {
    operation_id: String,
    event_id: String,
    actor_id: arkret_sdk::ActorId,
    signing_device_id: Option<arkret_sdk::DeviceId>,
    created_at: String,
}

fn membership_operation_from_event(event: &arkret_sdk::Event) -> Option<RawOperationRecord> {
    let local_event = LocalMembershipEvent::from_sdk_event(event)?;
    let operation_id = event.event_id.as_str().to_owned();
    let metadata = LocalMembershipMetadata {
        operation_id: operation_id.clone(),
        event_id: operation_id.clone(),
        // Keep the complete Account/Service actor. Reducing it to a principal
        // string loses the Station and cannot match the accepted invite route.
        actor_id: event.actor_id.clone(),
        signing_device_id: accepted_human_event_signing_device(event),
        created_at: arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
    };
    let payload = local_event.record_value(&metadata)?;

    Some(RawOperationRecord {
        operation_id,
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload,
    })
}

pub(crate) fn ingest_membership_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[arkret_sdk::Event],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    let mut changed = 0;
    for record in events.iter().filter_map(membership_operation_from_event) {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

fn membership_operation_from_client_event(
    client_event: &garth::ClientEvent,
) -> Option<RawOperationRecord> {
    let event = match client_event {
        garth::ClientEvent::Message(message) => &message.event,
        garth::ClientEvent::Event(event) => event,
        _ => return None,
    };
    membership_operation_from_event(event)
}

pub(crate) fn ingest_membership_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let mut changed = 0;
    for record in events
        .iter()
        .filter_map(membership_operation_from_client_event)
    {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

fn ingest_member_identity_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) {
    for source in [body.get("member_roster_entries")].into_iter().flatten() {
        let Some(items) = source.as_array() else {
            continue;
        };
        for entry in items {
            let Some(map) = entry.as_object() else {
                continue;
            };
            let Some(actor_id) = map.get("actor_id").and_then(|value| {
                serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok()
            }) else {
                continue;
            };
            // Inline events have priority — they're complete envelopes.
            if let Some(events) = map.get("identity_events").and_then(Value::as_array) {
                store.ingest_member_identity_events(realm_id, &actor_id, events);
            }
        }
    }
}

/// Device authority invalidation preserves each account's Station binding.
fn changed_device_accounts(
    changes: &arkret_sdk::AccountSubscribeDeviceListChanges,
) -> BTreeSet<arkret_sdk::AccountId> {
    changes
        .changed_ids
        .iter()
        .chain(&changes.left_ids)
        .filter_map(|actor| actor.as_account_id().cloned())
        .collect()
}

fn device_summary_revokes_local_device(
    viewer: &arkret_sdk::AccountView,
    principal: &arkret_sdk::DidCoreId,
    device_id: &str,
) -> bool {
    if &viewer.principal_id != principal {
        return false;
    }
    let mut matches = viewer
        .devices
        .iter()
        .filter(|device| device.device_id.as_str() == device_id);
    let Some(device) = matches.next() else {
        return false;
    };
    matches.next().is_none()
        && device.validate().is_ok()
        && device.status == arkret_sdk::DeviceSummaryStatus::Revoked
}

fn apply_notification_projection(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    account_actor: &arkret_sdk::ActorId,
) {
    let should_save_notification_projection = !response.updates.notifications.is_empty()
        || !response.updates.account_data.is_empty()
        // Realm membership is itself a notification transition: a live
        // `join` delta must retire the pending invite even when this frame
        // carries neither wire notifications nor notification account-data.
        || !response.realm_entries.is_empty();
    let mut notification_projection = store.notification_projection();
    let joined_realms = crate::state::projection::notifications::JoinedRealmIds::from_realm_entries(
        &response.realm_entries,
        account_actor,
    );
    crate::state::projection::notifications::apply_notification_projection(
        &mut notification_projection,
        &response.updates.notifications,
        &response.updates.account_data,
        &joined_realms,
    );
    if should_save_notification_projection {
        store.save_notification_projection(notification_projection);
    }
}

fn apply_account_data(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    authority: &arkret_sdk::AccountId,
) -> Option<String> {
    apply_account_data_entries(store, &response.updates.account_data, authority)
}

pub(crate) fn apply_account_data_entries(
    store: &mut LocalStateStore,
    entries: &[arkret_sdk::Event],
    authority: &arkret_sdk::AccountId,
) -> Option<String> {
    let mut synced_theme = None;
    for entry in entries {
        let Some(account_data_key) = entry.payload.get("key").and_then(Value::as_str) else {
            continue;
        };
        match crate::sidecar::ingest_sidecar_view_state_account_data(
            store,
            authority,
            account_data_key,
            &entry.payload,
        ) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    "sync engine: ignoring malformed Sidecar view-state account_data: {error}"
                );
                continue;
            }
        }
        // Ak.client.ui_state — theme + avatar pointer.
        if account_data_key == AccountDataKey::CLIENT_UI_STATE {
            match crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            ) {
                Ok(content) => {
                    let local_theme = store
                        .load_plain_local_data("theme")
                        .unwrap_or_else(|| "night".to_owned());
                    if let Some(remote_theme) =
                        crate::account_data::merge_client_ui_theme(&local_theme, &content)
                    {
                        store.save_plain_local_data("theme", remote_theme.clone());
                        synced_theme = Some(remote_theme);
                    }
                    if let Some(avatar_blob_ref) =
                        crate::account_data::avatar_blob_ref_from_client_ui(&content)
                    {
                        store.save_plain_local_data("avatar_blob_ref", avatar_blob_ref);
                    } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(
                        &content,
                    ) {
                        store.save_plain_local_data("avatar_blob_ref", "");
                    }
                }
                Err(error) => tracing::warn!(
                    "sync engine: ignoring undecryptable ak.client.ui_state: {error}"
                ),
            }
            continue;
        }
        // Ak.account.blocklist — personal block list.
        if account_data_key == AccountDataKey::PRESENCE_VISIBILITY {
            let Some(visibility) = crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            )
            .ok()
            .as_ref()
            .and_then(|content| content.get("presence_visibility"))
            .and_then(Value::as_str)
            .and_then(crate::state::PresenceVisibility::parse_wire) else {
                tracing::warn!(
                    "sync engine: ignoring malformed ak.presence.visibility account_data"
                );
                continue;
            };
            store.set_presence_visibility(visibility);
            continue;
        }
        // Ak.presence.preference — manual presence preference
        // (profiles-presence.md §3.6). The server stores only the standard
        // account-data AEAD envelope; decrypt before applying it locally.
        if account_data_key == AccountDataKey::PRESENCE_PREFERENCE {
            match crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            )
            .and_then(|content| serde_json::from_value(content).map_err(Into::into))
            {
                Ok(preference) => store.set_presence_preference(preference),
                Err(error) => tracing::warn!(
                    "sync engine: ignoring undecryptable ak.presence.preference: {error}"
                ),
            }
            continue;
        }
        if account_data_key == AccountDataKey::DND_SCHEDULE {
            match crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            ) {
                Ok(content) => match crate::notification_rules::parse_dnd_settings(&content) {
                    Ok(settings) => store.set_notification_dnd_settings(Some(settings)),
                    Err(rejection) => tracing::warn!(
                        code = rejection.wire_code(),
                        reason = %rejection.reason,
                        "sync engine: ignoring invalid ak.dnd_schedule; retaining the last valid setting"
                    ),
                },
                Err(error) => {
                    tracing::warn!("sync engine: ignoring undecryptable ak.dnd_schedule: {error}")
                }
            }
            continue;
        }
        if account_data_key == AccountDataKey::ACCOUNT_BLOCKLIST {
            match crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            )
            .and_then(|content| {
                let payload = crate::account_data::blocklist_payload_from_account_data(&content)
                .map_err(anyhow::Error::msg)?;
                let revision = entry
                    .payload
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("ak.account.blocklist is missing revision"))?;
                if payload.version != revision {
                    anyhow::bail!(
                        "ak.account.blocklist payload version {} differs from Account Data revision {revision}",
                        payload.version
                    );
                }
                Ok((revision, payload.entries))
            }) {
                Ok((revision, entries)) => {
                    store.set_client_blocklist(revision, entries);
                }
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed ak.account.blocklist account_data: {error}",
                    );
                }
            }
            continue;
        }
        // Ak.contacts.actor.<principal_key> — holder-private global petnames.
        if crate::account_data::principal_key_from_contact_remark_key(account_data_key).is_some() {
            if entry.payload.get("tombstone").and_then(Value::as_bool) == Some(true) {
                match crate::account_data::account_data_namespace_key(authority) {
                    Ok(namespace_key) => {
                        store
                            .remove_contact_remark_by_storage_key(&namespace_key, account_data_key);
                    }
                    Err(error) => tracing::warn!(
                        key = %account_data_key,
                        "sync engine: Contact petname tombstone cannot be applied: {error}",
                    ),
                }
                continue;
            }
            match crate::account_data::decrypt_account_data_entry(
                authority,
                account_data_key,
                &entry.payload,
            )
            .and_then(|content| {
                let remark: crate::account_data::ContactRemark = serde_json::from_value(content)?;
                let namespace_key = crate::account_data::account_data_namespace_key(authority)?;
                remark
                    .validate_for_account_data_key(&namespace_key, account_data_key)
                    .map_err(anyhow::Error::msg)?;
                Ok(remark)
            }) {
                Ok(remark) => {
                    let principal_id = remark.subject.principal_id.to_string();
                    store.set_contact_remark(principal_id, remark);
                }
                Err(error) => {
                    tracing::warn!(
                        key = %account_data_key,
                        "sync engine: ignoring malformed Contact petname: {error}",
                    );
                }
            }
            continue;
        }
        // Ak.contacts.realm.<realm_id> — actor-private Realm remarks.
        let Some(realm_id) = crate::account_data::realm_id_from_realm_remark_key(account_data_key)
        else {
            continue;
        };
        match crate::account_data::decrypt_account_data_entry(
            authority,
            account_data_key,
            &entry.payload,
        )
        .and_then(|content| serde_json::from_value(content).map_err(Into::into))
        {
            Ok(remark) => store.set_realm_remark(realm_id.to_owned(), remark),
            Err(error) => {
                tracing::warn!(
                    "sync engine: ignoring malformed Realm remark for {realm_id}: {error}",
                );
            }
        }
    }
    synced_theme
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn local_device_revocation_rotates_the_live_device_id() {
        let revoked = "ak:device:0196419b-0000-7000-8000-000000000001".to_owned();
        let value = Rc::new(RefCell::new(revoked.clone()));
        let read_value = value.clone();
        let write_value = value.clone();
        let update_value = value.clone();
        let live_device_id = crate::runtime::input::ValueCell::new(
            move || read_value.borrow().clone(),
            move |replacement| *write_value.borrow_mut() = replacement,
            move |update| update(&mut update_value.borrow_mut()),
        );

        rotate_live_device_id_after_revocation(&live_device_id);

        let replacement = live_device_id.get();
        assert_ne!(replacement, revoked);
        assert!(crate::config::is_valid_device_id(&replacement));
    }

    #[test]
    fn pending_mls_binding_retries_on_empty_account_poll_until_resolved() {
        let realm_id = "ak:realm:AfbvDP-Jqz3hzfK3cKfuiVdW52Ok5br5hib19xfECd7t";
        let response = empty_response("ak:cursor:mls-retry");
        let mut store = temp_store("mls-remove-empty-poll-retry");

        assert!(scope_rotate_realm_ids(&response, &store).is_empty());
        store.record_move_submission(
            "ak:event:AeoKZ3s6w5QgkoSbU4vsBE4Rqrgcl-BmQy4Nb6pqIjVf",
            realm_id,
            "mls_member_remove",
            crate::state::MoveSubmissionState::PendingMlsBinding,
            Some("epoch_update_required".to_owned()),
            None,
        );

        assert_eq!(
            scope_rotate_realm_ids(&response, &store),
            vec![realm_id.to_owned()]
        );
        assert_eq!(store.resolve_member_remove_mls_bindings(realm_id), 1);
        assert!(scope_rotate_realm_ids(&response, &store).is_empty());
    }

    fn empty_response(cursor: &str) -> AccountSyncStep {
        AccountSyncStep {
            cursor: cursor.to_owned(),
            realm_entries: Default::default(),
            realm_projections: Default::default(),
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
                account_data: Vec::new(),
                station_cas_account_data: Vec::new(),
                notifications: Vec::new(),
                partial: false,
            },
        }
    }

    fn temp_store(tag: &str) -> LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "inkson-engine-{tag}-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        LocalStateStore::with_path(path)
    }

    fn sdk_realm_id() -> arkret_sdk::RealmId {
        crate::test_support::realm_id("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk")
    }

    fn sdk_actor_id() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn sdk_event(kind: &str, payload: Value) -> arkret_sdk::Event {
        arkret_wire::test_support::raw_event(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: sdk_realm_id(),
            },
            sdk_actor_id(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn account_response_projects_client_events_and_decodes_realm_payloads() {
        let message_event = sdk_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            json!({
                "strand_id": "ak:strand:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        );
        let space_event = sdk_event(
            "ak.space.create",
            json!({
                "object": {
                    "id": "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "schema": "ak.schema.space.v1",
                    "realm_id": sdk_realm_id().as_str(),
                    "kind": "board",
                    "title": "Adapter Board"
                }
            }),
        );
        let mut response = empty_response("ak:cursor:account-adapter");
        let realm_id = sdk_realm_id();
        let projection = json!({
            "timeline": {
                "events": [serde_json::to_value(message_event).unwrap(), serde_json::to_value(space_event).unwrap()],
                "limited": false
            },
            "summary": {}
        });
        let entry: arkret_sdk::RealmSyncEntry =
            serde_json::from_value(projection.clone()).expect("typed Realm sync entry");
        response
            .realm_projections
            .insert(realm_id.as_str().to_owned(), projection);
        response
            .updates
            .realm_updates
            .push(arkret_sdk::RealmUpdate { realm_id, entry });

        let projector = AccountClientEventProjector::default();
        project_account_response_client_events(&response, &InboundDecoder::new(), &projector)
            .await
            .expect("account response projects through client-core adapter");

        let report = projector.report();
        assert_eq!(report.account_updates, 1);
        assert_eq!(report.realm_deltas, 1);
        assert_eq!(report.decoded_messages, 1);
        assert_eq!(report.decoded_events, 1);
        assert!(report.malformed_realm_ids.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn account_subscription_engine_accepts_inkson_local_state_adapter() {
        let store = temp_store("subscription-engine-adapter");
        let adapter = crate::client_core::InksonLocalStateStoreAdapter::new(store);
        let engine =
            garth::SubscriptionEngine::new(garth::NativeExecutor, adapter.clone(), adapter);

        let _control = engine.control();
    }

    /// The per-realm `events/subscribe` engine ingest contract: a realistic
    /// NDJSON stream (history Event frames + `catchup_complete` + `heartbeat`)
    /// parses into typed frames, whose Event payloads fold through the SHARED
    /// [`ingest_kanban_events`] into `raw_operations` — and re-folding the same
    /// frames is idempotent (operation_id dedupe), so a buffered long-poll that
    /// re-delivers history never double-inserts.
    #[test]
    fn realm_subscribe_frames_ingest_into_raw_operations_and_dedupe() {
        let realm_id = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
        let object = arkret_sdk::Space::create_object(
            arkret_sdk::RealmId::new(realm_id).unwrap(),
            "board",
            "Cross-member board",
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                sdk_actor_id(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
        );
        let space_create = sdk_event(
            arkret_sdk::EventKind::SpaceCreate.as_str(),
            serde_json::to_value(arkret_sdk::SpaceCreatePayload::new(object)).unwrap(),
        );
        // Mirrors the server's `events/subscribe` framing: one `event` frame
        // carrying the projection-event JSON, a `catchup_complete`, a heartbeat.
        let ndjson = format!(
            "{}\n{}\n{}\n",
            json!({
                "kind": "event",
                "realm_id": realm_id,
                "cursor": "ak:cursor:realmframe1",
                "payload": space_create
            }),
            json!({ "kind": "catchup_complete", "cursor": "ak:cursor:realmframe1" }),
            json!({ "kind": "heartbeat" }),
        );

        let frames = ndjson
            .lines()
            .map(|line| {
                arkret_sdk::EventsSubscribeFrame::from_ndjson_line(line)
                    .expect("events/subscribe NDJSON parses")
                    .expect("fixture lines are non-empty")
            })
            .collect::<Vec<_>>();
        // event + catchup_complete + heartbeat.
        assert_eq!(frames.len(), 3);

        let event_payloads: Vec<arkret_sdk::Event> = frames
            .iter()
            .filter_map(|frame| {
                if let arkret_sdk::EventsSubscribeFrame::Event { payload, .. } = frame {
                    Some(payload.as_ref().clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(event_payloads.len(), 1);

        let mut store = temp_store("realm-subscribe-ingest");
        let changed = ingest_kanban_projection_events(&mut store, realm_id, &event_payloads);
        assert_eq!(changed, 1, "the remote space-create folds in once");
        assert_eq!(store.load().raw_operations.len(), 1);

        // Re-folding the same frames (buffered long-poll re-delivers history) is
        // idempotent: operation_id dedupe means zero new inserts.
        let changed_again = ingest_kanban_projection_events(&mut store, realm_id, &event_payloads);
        assert_eq!(changed_again, 0, "re-ingest is deduped by operation_id");
        assert_eq!(store.load().raw_operations.len(), 1);
    }

    #[test]
    fn membership_events_ingest_into_raw_operations() {
        let realm_id = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
        let mut store = temp_store("membership-events");
        let events = [
            sdk_event(
                arkret_sdk::EventKind::MemberState.as_str(),
                json!({
                    "member_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "join"
                }),
            ),
            sdk_event(
                arkret_sdk::EventKind::InviteAccept.as_str(),
                json!({
                    "invite_id": "ak:invite:AT75JCcnHexLP4y-Juac4pnRIpfUaiaat4XhL9W7g610"
                }),
            ),
            sdk_event(arkret_sdk::EventKind::MlsCommit.as_str(), json!({})),
        ];
        let changed = ingest_membership_projection_events(&mut store, realm_id, &events);

        assert_eq!(changed, 2);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 2);
        assert_eq!(state.raw_operations[0].payload["kind"], "ak.member.state");
        assert_eq!(
            state.raw_operations[0].payload["body"]["membership"],
            "join"
        );
        assert_eq!(state.raw_operations[1].payload["kind"], "ak.invite.accept");
        assert_eq!(
            state.raw_operations[1].payload["body"]["invite_id"],
            "ak:invite:AT75JCcnHexLP4y-Juac4pnRIpfUaiaat4XhL9W7g610"
        );
    }

    #[test]
    fn accepted_membership_event_retains_exact_human_signing_device() {
        let device_id = "ak:device:0196419b-0000-7000-8000-000000000002";
        let mut event = sdk_event(
            arkret_sdk::EventKind::InviteAccept.as_str(),
            json!({
                "invite_id": "ak:invite:AT75JCcnHexLP4y-Juac4pnRIpfUaiaat4XhL9W7g610"
            }),
        );
        event.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let event_digest = arkret_sdk::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs.push(
            arkret_sdk::ProducerEventProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!(
                    "did:web:alice.example#{device_id}"
                ))
                .unwrap(),
                event_digest,
                signer_resolution_evidence_ref: None,
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "header..producer".to_owned(),
            }
            .into(),
        );

        let record = membership_operation_from_event(&event).unwrap();
        assert_eq!(record.payload["signing_device_id"], device_id);

        event.proofs[0]
            .as_producer_mut()
            .unwrap()
            .verification_method =
            arkret_sdk::DidUrl::new(format!("did:web:mallory.example#{device_id}")).unwrap();
        let record = membership_operation_from_event(&event).unwrap();
        assert!(record.payload.get("signing_device_id").is_none());
    }

    #[test]
    fn sync_state_events_ingest_kanban_strand_updates_as_synced_raw_operations() {
        let temp = std::env::temp_dir().join(format!(
            "inkson-sync-state-events-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(temp);
        let mut event = sdk_event(
            arkret_sdk::EventKind::StrandUpdate.as_str(),
            json!({
                "target_ref": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "patch": {
                    "synthesis": {"$op": "set", "value": "bob synthesis"}
                }
            }),
        );
        event.actor_id =
            crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:bob.example").unwrap();

        let changed =
            ingest_kanban_projection_events(&mut store, sdk_realm_id().as_str(), &[event]);

        assert_eq!(changed, 1);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 1);
        let actor_id: arkret_sdk::ActorId =
            serde_json::from_value(state.raw_operations[0].payload["actor_id"].clone()).unwrap();
        assert_eq!(
            actor_id.signing_principal_id().as_str(),
            "ak:did_core:web:bob.example"
        );
        assert_eq!(state.raw_operations[0].payload["write_state"], "synced");
        assert_eq!(
            state.raw_operations[0].payload["body"]["patch"]["synthesis"]["value"],
            "bob synthesis"
        );
    }

    #[test]
    fn notification_projection_filters_invites_by_typed_membership() {
        let mut store = temp_store("invite-membership-projection");
        let actor_id = "ak:did_core:web:bob.example";
        let realm_id = "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
        let invite = crate::state::projection::notifications::test_invite(0x10, realm_id);
        store.save_notification_projection(vec![crate::state::StoredNotification::Invite {
            invite: crate::state::StoredInviteNotification {
                invite_id: invite.id,
                realm_id: invite.realm_id,
                created_at: invite.created_at,
            },
        }]);
        let response = |membership: &str| {
            let mut response = empty_response("sx:invite-membership");
            let realm_id = arkret_sdk::RealmId::new(realm_id).unwrap();
            let entry = serde_json::from_value::<arkret_sdk::RealmSyncEntry>(json!({
                "member_roster": {
                    "entries": [{
                        "actor_id": {"kind":"account","account_id":{
                            "principal_id":actor_id,
                            "station_id":"ak:did_core:web:principal.example"
                        }},
                        "membership": membership
                    }],
                    "limited": false
                }
            }))
            .unwrap();
            response
                .realm_entries
                .insert(realm_id.clone(), entry.clone());
            response.realm_projections.insert(
                realm_id.as_str().to_owned(),
                serde_json::to_value(entry).unwrap(),
            );
            response
        };

        // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`
        // closes `membership` to `join | knock` and states that invite
        // lifecycle records are not membership and MUST NOT appear on the
        // roster. `knock` is therefore the roster's real "present but not
        // joined" row, and it is what must leave a pending invite standing.
        let account_actor = crate::test_support::account_actor(actor_id);
        apply_notification_projection(&mut store, &response("knock"), &account_actor);
        assert!(
            store
                .notification_projection()
                .iter()
                .any(|entry| entry.invite().is_some()),
            "a non-join roster membership must preserve the pending invite"
        );

        apply_notification_projection(&mut store, &response("join"), &account_actor);
        assert!(
            store
                .notification_projection()
                .iter()
                .all(|entry| entry.invite().is_none()),
            "a live joined membership delta must drop the stale invite without polling authz invites"
        );
    }

    #[test]
    fn device_changes_preserve_complete_station_scoped_accounts() {
        let first = crate::test_support::account_actor("ak:did_core:web:subject.example");
        let mut second = first.as_account_id().unwrap().clone();
        second.station_id = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        let changes = arkret_sdk::AccountSubscribeDeviceListChanges {
            changed_ids: vec![first.clone()],
            left_ids: vec![first.clone(), arkret_sdk::ActorId::account(second.clone())],
        };
        assert_eq!(
            changed_device_accounts(&changes),
            BTreeSet::from([first.as_account_id().unwrap().clone(), second])
        );
    }

    #[test]
    fn local_device_wipe_requires_an_explicit_current_revoked_summary() {
        let principal = sdk_actor_id();
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let proposal = sdk_event("ak.device.revoke", json!({}));
        let signer = arkret_test_kit::proof::StructuralOnlyPayloadSigner::new(
            arkret_sdk::Did::new("did:web:station.example").unwrap(),
            arkret_sdk::DidUrl::new("did:web:station.example#key-1").unwrap(),
        );
        let accepted_at = chrono::Utc::now();
        let ack = arkret_sdk::ControlProposalAuthorityAck::issue_with_signer(
            sdk_realm_id(),
            proposal.event_id.event_digest(),
            arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            accepted_at,
            arkret_sdk::ControlProposalDecisionPolicy::default(),
            &signer,
        )
        .unwrap();
        let ack =
            arkret_sdk::ControlProposalAck::from_authority_acks_protocol_bounds(vec![ack]).unwrap();
        let mut viewer: arkret_sdk::AccountView = serde_json::from_value(json!({
            "principal_id":principal,"state":"active","devices":[{
                "device_id":device,"status":"revoked","verification_state":"verified",
                "revocation_states":[{
                    "schema":"ak.schema.device_revocation_state.v1",
                    "account_id":{"principal_id":principal,"station_id":"ak:did_core:web:station.example"},
                    "device_id":device,"target_device_authorize_event_id":proposal.event_id,
                    "target_device_generation_ref":1,"proposal_event_id":proposal.event_id,
                    "accepted_at":arkret_sdk::canonical::format_timestamp_canonical(accepted_at),
                    "acceptance_seq":1,"control_proposal_ack":ack,"status":"revoked",
                    "covering_seal_id":format!("ak:seal:sha256:{}", "2".repeat(64)),
                    "sealed_at":arkret_sdk::canonical::format_timestamp_canonical(accepted_at)
                }]
            }]
        })).unwrap();
        assert!(device_summary_revokes_local_device(
            &viewer, &principal, device
        ));
        assert!(!device_summary_revokes_local_device(
            &viewer,
            &principal,
            "other-device"
        ));
        let other = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(!device_summary_revokes_local_device(
            &viewer, &other, device
        ));
        viewer.devices[0].status = arkret_sdk::DeviceSummaryStatus::RevocationPending;
        assert!(!device_summary_revokes_local_device(
            &viewer, &principal, device
        ));
        viewer.devices.clear();
        assert!(!device_summary_revokes_local_device(
            &viewer, &principal, device
        ));
    }
}

fn apply_account_frame_payload(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    ctx: &SyncEngineContext,
) -> (Option<String>, bool) {
    let mut realm_projection_changed = false;
    // Apply explicit Realm deltas; baseline completion is reconciled separately
    // by the demand-sync reducer.
    for update in &response.updates.realm_updates {
        let id = update.realm_id.as_str();
        let Some(body) = response.realm_projections.get(id) else {
            continue;
        };
        if !realm_update_has_durable_projection(update) {
            continue;
        }
        // The live epoch represents the durable Realm projection as a
        // whole, not only events understood by one product surface.
        // Summary/member/state-only deltas must invalidate durable
        // consumers just as timeline events do.
        realm_projection_changed = true;
        let existing = store.realm_tree_projection(id);
        let frame = RealmProjectionFrame::Incremental(body);
        let projection = reconcile_realm_projection(existing.as_ref(), frame);
        store.save_realm_tree_projection(id.to_owned(), projection.clone());
        if response.has_window_start_realm_metadata(id) {
            store.save_realm_collaboration_role(id.to_owned(), response.collaboration_role(id));
        }
        store.merge_realm_seal_view_from_sync_body(id, &projection);
        store.ingest_move_event_states(id, &projection);
        let _ = ingest_message_events_from_projection(store, id, &projection);
        // Fold the discussion timeline into `raw_operations` too so the
        // card-detail Discussion tab renders local-first instead of
        // refetching + redecrypting the realm on every open.
        // MID-2 — harvest inlined `ak.member.identity.update`
        // event envelopes off the `members[]` roster entries. The
        // SDK's effective-set filter is applied lazily when a UI
        // surface needs to resolve a display identity.
        ingest_member_identity_events_from_projection(store, id, &projection);
    }
    let synced_theme = apply_account_data(store, response, &ctx.account.authority);
    store.apply_station_cas_account_data(&response.updates.station_cas_account_data);
    // Fold holder-private delivery cells before Realm membership
    // adjudicates the inbox. If a frame carries both an older full
    // invite-delivery cell and membership=`join`, the joined roster
    // is authoritative for the final notification projection and
    // must not let the stale delivery re-add the invite afterward.
    store.ingest_to_device_messages(&response.updates.to_device);
    apply_notification_projection(
        store,
        response,
        &arkret_sdk::ActorId::account(ctx.account.authority.clone()),
    );

    (synced_theme, realm_projection_changed)
}
