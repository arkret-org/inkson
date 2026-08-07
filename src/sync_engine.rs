//! Background account subscribe sync loop.
//!
//! Background engine that keeps the local store + UI signals continuously
//! aligned with `/_arkret/self/account/subscribe` instead of refreshing only on
//! app boot, the Refresh button, or a server switch.
//!
//! Design contract (matches the intended approach laid out in the design
//! discussion):
//!
//! * **Cursor lives in `LocalStateStore.sync_cursor`** — the engine reads it on every iteration and
//!   writes back the new `cursor` after each successful response. Reload of the tab resumes from
//!   the persisted cursor without losing position.
//! * **First iteration is initial account sync** when no cursor is stored. Subsequent iterations
//!   resume with `after=<cursor>&catchup=true`.
//! * **Server-authoritative reconcile**: on a full sync the response is the truth for top-level
//!   Realm membership. Nested container Spaces may not appear as top-level realm projections
//!   entries, so locally projected Spaces are retained while their home Realm remains in the
//!   full-sync response. On incremental, soland's `left_realms` field is the prune signal.
//! * **Lifecycle via generation counter**: callers (login / logout / server-switch) bump the
//!   engine's `generation` Signal; the loop notices on the next iteration and exits cleanly. A
//!   fresh engine spawn picks up the next generation.
//! * **Backoff**: transient network errors double the sleep via [`garth::Backoff`] (capped at
//!   `BACKOFF_CEILING`); a successful response resets it. Auth-expired errors stop the engine and
//!   let the refresh poller
//!   + login strand take over. Cursor-invalid errors clear the cursor and immediately retry as a
//!     full sync.
//!
//! When an iteration hits `is_auth_expired_error`, the engine calls the
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

use garth::{
    AccountCommitOutcome, AccountPostCommitHook, AccountPostCommitOutcome, AccountStepCommitter,
    AccountStepHandlers, AccountStreamStep, RunOptions, SyncLoopControl, TransportProvider,
};
#[cfg(test)]
use garth::{ClientEvent, ClientProjector};
#[cfg(test)]
use garth::{DecodedInbound, InboundDecoder};
use serde_json::{Value, json};

use crate::api_error::{is_auth_expired_error, is_terminal_session_grant_error};
use crate::models::{AccountSyncStep, RealmTreeNodeKind};
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
/// itself is [`garth::Backoff`]; these are just its floor/ceiling. A 1s floor
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
    pub base_url: String,
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account_did: String,
    /// YOU-02-004R (§5.6) — the local device id, needed by the idle
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
    /// Y1/Y2 - session-scoped DID resolution cache handle, provided by
    /// `app.rs` via `use_context_provider` as documented there. While ingesting
    /// projections, the Y2 invalidation hook uses it to call `invalidate` for
    /// related actor DIDs when `ak.cross_signing.reset` / `ak.device.revoke`
    /// arrive, and `clear` on logout / trust-bundle reset.
    pub did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
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
    malformed_realms: Vec<String>,
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
                report.malformed_realms.extend(updates.malformed_realms);
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
    if let Some(state) = &update.entry.state {
        for payload in &state.events {
            push_account_event_payload(decoder, batch, payload);
        }
    }
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

    /// §6.1 — the account channel keeps canonical cursor semantics on either
    /// transport, so the resume point survives a switch and the choice is made
    /// per connection attempt rather than per session.
    async fn provide(&self) -> garth::Result<Self::Transport> {
        let session_generation = self.ctx.session.generation();
        let transport =
            crate::identity::session_refresh::provide_authenticated_sdk_client(&self.ctx.base_url)
                .await
                .map(crate::client_core::InksonAccountTransport::new)
                .map(|http| {
                    crate::transport::websocket_rail::StreamRail::select(
                        &self.ctx.websocket_rail,
                        http,
                    )
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
        match crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
            &self.ctx.base_url,
        )
        .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_terminal_session_grant_error(&error) => {
                self.ctx.session.invalidate(error.to_string());
                Ok(false)
            }
            Err(error) => Err(garth::Error::Http(error.to_string())),
        }
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && !self.ctx.effect.is_cancelled()
            && !self.ctx.base_url.trim().is_empty()
            && !self.ctx.token.get().trim().is_empty()
    }
}

struct InksonAccountCommitter {
    ctx: SyncEngineContext,
}

impl AccountStepCommitter for InksonAccountCommitter {
    async fn commit(&self, step: &AccountStreamStep) -> garth::Result<AccountCommitOutcome> {
        let cursor = step.cursor.clone().ok_or_else(|| {
            garth::Error::Protocol("account stream update has no validated cursor".to_owned())
        })?;
        if !step.initial && account_updates_are_empty(&step.updates) {
            // A bounded long-poll timeout carries only
            // frontier+catchup_complete. Persist the resume cursor, but do
            // not publish a fake business update that remounts resources
            // and fans out viewer/backups/invites requests.
            self.ctx
                .state_store
                .write(|store| store.save_sync_cursor(cursor));
            if let Some(error) = self.ctx.state_store.read(LocalStateStore::persist_error) {
                return Err(garth::Error::Protocol(format!(
                    "persist idle account stream cursor: {error}"
                )));
            }
            return Ok(AccountCommitOutcome::Committed);
        }
        let response = AccountSyncStep::from_updates(cursor, step.updates.clone())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        apply_response(&response, step.initial, &self.ctx, None);
        if let Some(error) = self.ctx.state_store.read(LocalStateStore::persist_error) {
            return Err(garth::Error::Protocol(format!(
                "persist account stream step: {error}"
            )));
        }
        // client-sync.md §10.1: account stream cursor advancement is
        // independent of to-device ACK. The raw envelopes are now durable
        // in the local inbox, so the account checkpoint may advance even
        // when queue pagination or kind-specific handling follows.
        Ok(AccountCommitOutcome::Committed)
    }
}

struct InksonAccountPostCommit {
    ctx: SyncEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
}

fn account_updates_are_empty(updates: &arkret_sdk::SyncUpdates) -> bool {
    updates.realm_updates.is_empty()
        && updates.malformed_realms.is_empty()
        && updates.to_device.is_empty()
        && updates.to_device_ack_token.is_none()
        && !updates.to_device_limited
        && updates.to_device_next_cursor.is_none()
        && !updates.to_device_lost
        && updates.device_lists.changed.is_empty()
        && updates.device_lists.left.is_empty()
        && updates.account_data.is_empty()
        && updates.notifications.is_empty()
        && updates.agent_signer_evidence.is_empty()
        && !updates.partial
}

fn should_bootstrap_invites(initial: bool) -> bool {
    // Invites are part of the initial account projection. Live changes arrive
    // through the account/events subscribe planes; a steady-state GET loop
    // would create a third, protocol-divergent source of truth.
    initial
}

fn realm_update_has_durable_projection(update: &arkret_sdk::RealmUpdate) -> bool {
    let entry = &update.entry;
    entry.timeline.is_some()
        || entry.state_at_window_start.is_some()
        || entry.state.is_some()
        || entry.state_after.is_some()
        || entry.account_data.is_some()
        || entry.summary.is_some()
        || entry.members.is_some()
        || entry.members_limited.is_some()
        || entry.members_next_cursor.is_some()
        || entry.unread_notifications.is_some()
        || entry.event_states.is_some()
        || entry.bottoms.is_some()
}

fn overlay_json_object(base: &mut Value, incoming: &Value) {
    let (Some(base), Some(incoming)) = (base.as_object_mut(), incoming.as_object()) else {
        *base = incoming.clone();
        return;
    };
    for (key, value) in incoming {
        match base.get_mut(key) {
            Some(current) if current.is_object() && value.is_object() => {
                overlay_json_object(current, value);
            }
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

fn event_id(event: &Value) -> Option<&str> {
    event.get("event_id").and_then(Value::as_str)
}

fn state_event_cells(event: &Value) -> BTreeSet<&str> {
    event
        .get("effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|effect| effect.get("cell").and_then(Value::as_str))
        .collect()
}

fn merged_event_container(
    cached: Option<&Value>,
    incoming: &Value,
    replace_same_state_cell: bool,
) -> Value {
    let mut merged = incoming.clone();
    let Some(incoming_events) = incoming.get("events").and_then(Value::as_array) else {
        return merged;
    };
    let mut events = cached
        .and_then(|container| container.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for incoming_event in incoming_events {
        let incoming_id = event_id(incoming_event);
        let incoming_cells = replace_same_state_cell.then(|| state_event_cells(incoming_event));
        events.retain(|cached_event| {
            if incoming_id.is_some() && event_id(cached_event) == incoming_id {
                return false;
            }
            let Some(incoming_cells) = incoming_cells.as_ref() else {
                return true;
            };
            if incoming_cells.is_empty() {
                return true;
            }
            state_event_cells(cached_event).is_disjoint(incoming_cells)
        });
        events.push(incoming_event.clone());
    }
    if let Some(object) = merged.as_object_mut() {
        object.insert("events".to_owned(), Value::Array(events));
    }
    merged
}

fn without_state_cells(container: Option<&Value>, cells: &BTreeSet<&str>) -> Option<Value> {
    let mut container = container?.clone();
    let Some(events) = container.get_mut("events").and_then(Value::as_array_mut) else {
        return Some(container);
    };
    events.retain(|event| state_event_cells(event).is_disjoint(cells));
    Some(container)
}

fn state_container_cells(container: Option<&Value>) -> BTreeSet<&str> {
    container
        .and_then(|container| container.get("events"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(state_event_cells)
        .collect()
}

/// Apply an account-subscribe Realm delta without treating omitted fields or
/// current-state cells as deletions. `client-sync.md` defines `state` and
/// `state_after` as deltas; timeline events are likewise incremental. Full
/// sync frames bypass this helper and replace the cached projection.
fn merge_incremental_realm_projection(cached: Option<&Value>, incoming: &Value) -> Value {
    let Some(cached) = cached else {
        return incoming.clone();
    };
    let mut merged = cached.clone();
    overlay_json_object(&mut merged, incoming);
    let Some(object) = merged.as_object_mut() else {
        return incoming.clone();
    };
    let incoming_state_cells = state_container_cells(incoming.get("state"));
    let incoming_state_after_cells = state_container_cells(incoming.get("state_after"));
    let mut state = incoming
        .get("state")
        .map(|container| merged_event_container(cached.get("state"), container, true));
    if state.is_none() && !incoming_state_after_cells.is_empty() {
        state = without_state_cells(cached.get("state"), &incoming_state_after_cells);
    } else if !incoming_state_after_cells.is_empty() {
        state = without_state_cells(state.as_ref(), &incoming_state_after_cells);
    }
    if let Some(state) = state {
        object.insert("state".to_owned(), state);
    }

    let state_after_base = without_state_cells(cached.get("state_after"), &incoming_state_cells);
    let state_after = incoming
        .get("state_after")
        .map(|container| merged_event_container(state_after_base.as_ref(), container, true));
    if let Some(state_after) = state_after.or(state_after_base) {
        object.insert("state_after".to_owned(), state_after);
    }
    if let Some(container) = incoming.get("timeline") {
        object.insert(
            "timeline".to_owned(),
            merged_event_container(cached.get("timeline"), container, false),
        );
    }
    merged
}

fn preserve_realm_security_projection(existing: Option<&Value>, incoming: &Value) -> Value {
    let security_state = crate::security_state::realm_projection_security_state(incoming)
        .or_else(|| existing.and_then(crate::security_state::realm_projection_security_state));
    let mut merged = incoming.clone();
    if let (Some(encrypted), Some(object)) = (security_state, merged.as_object_mut()) {
        // `encryption_profile` is create-locked. Incremental account frames
        // can omit the original `ak.realm.create` event, so retain the last
        // authoritative classification in the local projection instead of
        // letting a partial delta silently downgrade the UI to plaintext.
        object.insert(
            "__realm_security_encrypted".to_owned(),
            Value::Bool(encrypted),
        );
    }
    merged
}

fn to_device_backfill_cursor(updates: &arkret_sdk::SyncUpdates) -> Option<String> {
    // client-sync.md §10.0: account subscribe is the primary receive path.
    // The standalone queue endpoint is only a continuation path when the
    // account frame explicitly reports a limited batch.
    updates
        .to_device_limited
        .then(|| updates.to_device_next_cursor.clone())
        .flatten()
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
/// — invite refresh, MLS, calls, to-device acknowledgement — is not a covered
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
        if !self.active() {
            return Ok(AccountPostCommitOutcome::Continue);
        }
        if !step.initial && account_updates_are_empty(&step.updates) {
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

        if !self.ctx.account_did.trim().is_empty() {
            let submitter = crate::event_submit::EventSubmitter::new(http.clone());
            if let Err(error) = submitter.drain_outbound(self.ctx.account_did.trim()).await {
                tracing::debug!(
                    ?error,
                    "account post-commit deferred durable outbound drain"
                );
            }
            if let Err(error) = submitter
                .drain_mls_outbound(self.ctx.account_did.trim(), self.ctx.state_store.clone())
                .await
            {
                tracing::debug!(?error, "account post-commit deferred MLS outbound drain");
            }
        }

        // `/authz/invites` is an initial/bootstrap projection only. Live
        // membership and invite changes arrive on the account/events
        // subscribe planes; maintaining a third periodic poll loop here
        // violates the sync protocol and amplifies every account delta.
        if should_bootstrap_invites(step.initial) {
            match crate::transport::account::invites(http).await {
                Ok(invites) => {
                    let invite_notifications = invites.invites;
                    self.ctx.state_store.write(|store| {
                        store.batch(|store| {
                            apply_notification_projection(
                                store,
                                &response,
                                &self.ctx.account_did,
                                step.initial,
                                Some(invite_notifications),
                            );
                        });
                    });
                }
                Err(error) if is_auth_expired_error(&error) => {
                    return Ok(AccountPostCommitOutcome::Unauthorized {
                        reason: Some(error.to_string()),
                    });
                }
                Err(error) => tracing::debug!(?error, "invite refresh deferred"),
            }
        }

        let agent_evidence_changed =
            crate::identity::agent_signer_evidence::prefetch_from_realm_projections(
                http,
                &response.realm_projections,
                &response.updates.agent_signer_evidence,
                &self.ctx.state_store,
                self.ctx.did_cache.clone(),
            )
            .await;
        let state_store_for_profiles = self.ctx.state_store.clone();
        let device_keys_changed = prefetch_persistent_event_sender_keys(
            &api,
            &response,
            self.ctx.did_cache.clone(),
            self.ctx.state_store.clone(),
            |realm_id| {
                state_store_for_profiles
                    .read(|store| store.realm_projection_is_minimal_metadata(realm_id))
            },
        )
        .await;
        if agent_evidence_changed || device_keys_changed {
            refresh_projection_events_from_sync_response(&response, step.initial, &self.ctx);
        }
        prefetch_member_identity_proof_keys(
            &api,
            &response,
            self.ctx.did_cache.clone(),
            self.ctx.state_store.clone(),
        )
        .await;
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
        if !realm_ids.is_empty() {
            run_circle_scope_rotate_pass(
                self.start_generation,
                self.generation.clone(),
                &self.ctx,
                &realm_ids,
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
    let actor_id = match arkret_sdk::Did::new(ctx.account_did.trim().to_owned()) {
        Ok(actor_id) => actor_id,
        Err(error) => {
            ctx.projection_sink.sync_status(SyncStatusEvent::Terminal {
                reason: format!("invalid account DID: {error}"),
            });
            return;
        }
    };
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
    let committer = InksonAccountCommitter { ctx: ctx.clone() };
    let hook = InksonAccountPostCommit {
        ctx: ctx.clone(),
        generation,
        start_generation,
    };
    let result = ctx
        .client_runtime
        .client()
        .run_account_steps(
            actor_id,
            device_id,
            &provider,
            AccountStepHandlers::new(&committer, &hook),
            &SyncLoopControl::new(),
            RunOptions {
                // Successful bounded polls reconnect immediately. The server
                // owns the 30-second idle wait window.
                beat: Duration::ZERO,
                min_backoff: BACKOFF_FLOOR,
                max_backoff: BACKOFF_CEILING,
                jitter_ratio: 0.2,
            },
        )
        .await;
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
        Err(error) => ctx.projection_sink.sync_status(SyncStatusEvent::Retryable {
            reason: error.to_string(),
        }),
    }
}

fn realm_membership_removal_basis(
    projection: &Value,
) -> Option<(BTreeSet<String>, Vec<arkret_sdk::EventId>)> {
    // A truncated roster is not negative membership evidence.  Waiting for a
    // complete projection is required before comparing it with the MLS tree.
    if projection.get("members_limited").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    let active_members = projection
        .get("members")?
        .as_array()?
        .iter()
        .filter(|member| member.get("membership").and_then(Value::as_str) == Some("join"))
        .filter_map(|member| member.get("actor_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut membership_frontier = sync_realm_state_events(projection)
        .into_iter()
        .filter(|event| {
            event
                .get("kind")
                .or_else(|| event.get("event_kind"))
                .and_then(Value::as_str)
                == Some("ak.member.state")
        })
        .filter(|event| {
            let payload = event
                .get("payload")
                .or_else(|| event.get("content"))
                .unwrap_or(&Value::Null);
            matches!(
                payload
                    .get("membership")
                    .or_else(|| payload.get("target_state"))
                    .or_else(|| payload.get("state"))
                    .and_then(Value::as_str),
                Some("leave" | "ban")
            )
        })
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|event_id| arkret_sdk::EventId::new(event_id.to_owned()).ok())
        })
        .collect::<Vec<_>>();
    membership_frontier.sort();
    membership_frontier.dedup();
    (!membership_frontier.is_empty()).then_some((active_members, membership_frontier))
}

fn realm_default_mls_removal_candidates(
    state_store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<Vec<(String, Vec<arkret_sdk::EventId>)>> {
    let state = state_store.load();
    let projection = state.realm_tree_projections.get(realm_id)?;
    let (active_members, membership_frontier) = realm_membership_removal_basis(projection)?;
    let mut mls_members = crate::mls::runtime::mls_group_member_principal_ids_for_realm(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )?;
    mls_members.sort();
    mls_members.dedup();
    Some(
        mls_members
            .into_iter()
            .filter(|member| !active_members.contains(member))
            .map(|member| (member, membership_frontier.clone()))
            .collect(),
    )
}

/// Background Realm-default + Circle MLS scope-rotate worker.
///
/// Scans the Realm ids that changed in the just-applied sync response. Realm
/// removals are derived from the canonical account-sync membership projection;
/// Circle obligations come from the registered typed Circle list response. It
/// builds real OpenMLS Remove commits and persists each post-commit snapshot
/// only after the canonical Events are accepted.
/// One commit is submitted per pass so competing clients and multi-Realm
/// accounts do not burst writes after a sync wakeup.
async fn run_circle_scope_rotate_pass(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
    realm_ids: &[String],
) {
    if generation.get() != start_generation {
        return;
    }
    let base = ctx.base_url.clone();
    let token = ctx.token.get();
    let actor_id = ctx.account_did.trim().to_owned();
    let device_id = ctx.device_id.trim().to_owned();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.is_empty()
    {
        return;
    }
    let realm_ids: BTreeSet<String> = realm_ids
        .iter()
        .map(|realm_id| realm_id.trim())
        .filter(|realm_id| realm_id.starts_with("ak:realm:"))
        .map(str::to_owned)
        .collect();
    if realm_ids.is_empty() {
        return;
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    for realm_id in realm_ids {
        if generation.get() != start_generation {
            return;
        }
        let circles = match crate::transport::auth::with_authed_sdk_client(&base, token.clone(), {
            let realm_id = realm_id.clone();
            move |http| async move { crate::transport::circle::list_circles(&http, &realm_id).await }
        })
        .await
        {
            Ok(circles) => circles,
            Err(err) => {
                if err.is_auth_expired() {
                    return;
                }
                tracing::debug!(
                    %realm_id,
                    error = %err.display(),
                    "sync_engine: Circle scope-rotate scan skipped",
                );
                continue;
            }
        };

        // circle.md §10.2/§10.3: a Realm membership removal rotates the
        // Realm-default MLS group in addition to every MLS-backed Circle.
        // Derive the Realm obligation exclusively from canonical sync state:
        // a complete active-member roster, accepted ak.member.state
        // leave/ban frontier Events, and the local RFC 9420 group roster.
        // No private server flag or unregistered HTTP field participates.
        let realm_removals = ctx.state_store.read(|store| {
            realm_default_mls_removal_candidates(
                store,
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
            )
        });
        if let Some(removals) = realm_removals
            .as_ref()
            .filter(|removals| !removals.is_empty())
        {
            let target_principal_ids: Vec<String> = removals
                .iter()
                .map(|(principal_id, _)| principal_id.clone())
                .collect();
            let mut revocation_membership_frontier: Vec<arkret_sdk::EventId> = removals
                .iter()
                .flat_map(|(_, frontier)| frontier.iter().cloned())
                .collect();
            revocation_membership_frontier.sort();
            revocation_membership_frontier.dedup();
            if !ctx
                .state_store
                .read(|store| store.realm_has_pending_mls_binding(&realm_id))
            {
                let tracking_id = format!(
                    "mls-binding:{}:{}",
                    realm_id,
                    revocation_membership_frontier
                        .first()
                        .map(arkret_sdk::EventId::as_str)
                        .unwrap_or("membership-frontier")
                );
                ctx.state_store.write(|store| {
                    store.record_move_submission(
                        tracking_id,
                        realm_id.clone(),
                        "mls_member_remove",
                        crate::state::MoveSubmissionState::PendingMlsBinding,
                        Some(
                            "epoch_update_required: membership frontier changed; MLS Remove commit required"
                                .to_owned(),
                        ),
                        None,
                    );
                });
            }
            let Some(snapshot) = ctx
                .state_store
                .read(|store| store.mls_snapshot_for(&realm_id))
            else {
                tracing::debug!(
                    %realm_id,
                    ?target_principal_ids,
                    "sync_engine: Realm MLS remove skipped without local snapshot",
                );
                continue;
            };
            let proof_request = ctx.state_store.read(|store| {
                crate::mls::governance_proof::proof_request(
                    store,
                    &realm_id,
                    None,
                    snapshot.group_id.clone(),
                    snapshot.epoch,
                    snapshot.epoch.saturating_add(1),
                )
            });
            let proof_request = match proof_request {
                Ok(request) => request,
                Err(error) => {
                    tracing::debug!(
                        %realm_id,
                        ?target_principal_ids,
                        %error,
                        "sync_engine: Realm MLS remove proof request deferred",
                    );
                    continue;
                }
            };
            let proof_leaves = ctx.state_store.read(|store| {
                crate::mls::governance_proof::current_security_frontier_leaves(
                    store, &realm_id, None, &actor_id, &device_id,
                )
            });
            let proof_leaves = match proof_leaves {
                Ok(leaves) => crate::mls::governance_proof::security_frontier_without_principals(
                    leaves,
                    &target_principal_ids,
                ),
                Err(error) => {
                    tracing::debug!(
                        %realm_id,
                        ?target_principal_ids,
                        %error,
                        "sync_engine: Realm MLS remove security frontier deferred",
                    );
                    continue;
                }
            };
            let realm_for_submit = realm_id.clone();
            let actor_for_submit = actor_id.clone();
            let device_for_submit = device_id.clone();
            let targets_for_submit = target_principal_ids.clone();
            let frontier_for_submit = revocation_membership_frontier.clone();
            let state_store = ctx.state_store.clone();
            let submitted = crate::transport::auth::with_authed_api(
                &base,
                token.clone(),
                move |api| async move {
                    crate::mls::governance_proof::fetch_verify_and_cache_proof(
                        &api,
                        state_store.clone(),
                        &proof_request,
                        &proof_leaves,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    let draft = state_store
                        .read(|store| {
                            let target_refs: Vec<&str> =
                                targets_for_submit.iter().map(String::as_str).collect();
                            crate::circle_mls::build_realm_remove_members_scope_rotate_draft(
                                store,
                                secure_store.as_ref(),
                                &realm_for_submit,
                                &actor_for_submit,
                                &device_for_submit,
                                &target_refs,
                                &frontier_for_submit,
                            )
                        })
                        .map_err(anyhow::Error::msg)?;
                    let post_commit_snapshot = draft.post_commit_snapshot;
                    let removed_principals = draft.removed_principals;
                    let commit_event_id = draft
                        .events
                        .iter()
                        .find(|event| event.kind.as_str() == "ak.mls.commit")
                        .map(|event| event.event_id.clone())
                        .ok_or_else(|| {
                            anyhow::anyhow!("Realm scope rotate has no MLS commit Event")
                        })?;
                    let submitter = api.event_submitter()?;
                    for event in draft.events {
                        submitter.submit_sdk_event(&event).await?;
                    }
                    Ok::<_, anyhow::Error>((
                        post_commit_snapshot,
                        removed_principals,
                        commit_event_id,
                    ))
                },
            )
            .await;
            match submitted {
                Ok((post_commit_snapshot, removed_principals, commit_event_id)) => {
                    if generation.get() != start_generation {
                        return;
                    }
                    let persisted = ctx.state_store.write(|store| {
                        store.record_mls_group_state_ref_for_effective_scope(
                            realm_id.clone(),
                            None,
                            post_commit_snapshot.group_id.as_str(),
                            post_commit_snapshot.epoch,
                            commit_event_id,
                        )?;
                        store.save_mls_snapshot(realm_id.clone(), post_commit_snapshot);
                        Ok::<_, String>(())
                    });
                    if let Err(error) = persisted {
                        tracing::error!(
                            %realm_id,
                            %error,
                            "sync_engine: accepted Realm MLS commit group-state reference conflicted",
                        );
                        return;
                    }
                    tracing::info!(
                        %realm_id,
                        ?target_principal_ids,
                        ?removed_principals,
                        "sync_engine: Realm-default MLS remove commit accepted",
                    );
                    // One canonical MLS group rotation per pass. Every Realm
                    // removal obligation is included in this single Commit;
                    // the accepted Event wakes sync for Circle obligations.
                    return;
                }
                Err(error) => {
                    if error.is_auth_expired() {
                        return;
                    }
                    tracing::debug!(
                        %realm_id,
                        ?target_principal_ids,
                        error = %error.display(),
                        "sync_engine: Realm-default MLS remove commit deferred",
                    );
                    continue;
                }
            }
        }

        let has_pending_circle_removals = circles
            .circles
            .iter()
            .any(|circle| !circle.pending_mls_removals.is_empty());
        if has_pending_circle_removals
            && !ctx
                .state_store
                .read(|store| store.realm_has_pending_mls_binding(&realm_id))
        {
            let tracking_suffix = circles
                .circles
                .iter()
                .find_map(|circle| {
                    circle
                        .pending_mls_removals
                        .first()
                        .map(|removal| format!("{}:{}", circle.circle_id, removal.principal_id()))
                })
                .unwrap_or_else(|| "circle-membership-frontier".to_owned());
            ctx.state_store.write(|store| {
                store.record_move_submission(
                    format!("mls-binding:{realm_id}:{tracking_suffix}"),
                    realm_id.clone(),
                    "mls_member_remove",
                    crate::state::MoveSubmissionState::PendingMlsBinding,
                    Some(
                        "epoch_update_required: membership frontier changed; MLS Remove commit required"
                            .to_owned(),
                    ),
                    None,
                );
            });
        }
        if realm_removals.as_ref().is_some_and(Vec::is_empty) && !has_pending_circle_removals {
            ctx.state_store.write(|store| {
                store.resolve_member_remove_mls_bindings(&realm_id);
            });
        }
        for circle in circles.circles {
            if generation.get() != start_generation {
                return;
            }
            let circle_id = circle.circle_id.to_string();
            if circle.state != arkret_sdk::CircleState::Active
                || circle.encryption_profile != arkret_sdk::EncryptionProfile::MlsRfc9420
                || circle.pending_mls_removals.is_empty()
            {
                continue;
            }
            if !circle
                .members
                .iter()
                .any(|member| member.to_string() == actor_id)
            {
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    "sync_engine: Circle scope-rotate skipped for non-member actor",
                );
                continue;
            }
            if ctx.state_store.read(|store| {
                store
                    .mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id))
                    .is_none()
            }) {
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    "sync_engine: Circle scope-rotate skipped without local MLS snapshot",
                );
                continue;
            }
            let mut target_principal_ids = Vec::new();
            let mut revocation_membership_frontier = Vec::new();
            let mut missing_frontier = false;
            for target in circle.pending_mls_removals {
                let target_principal_id = target.principal_id().to_string();
                if target.membership_frontier().is_empty() {
                    missing_frontier = true;
                    tracing::debug!(
                        %realm_id,
                        %circle_id,
                        %target_principal_id,
                        "sync_engine: Circle scope-rotate skipped without revoke/import membership frontier",
                    );
                    continue;
                }
                target_principal_ids.push(target_principal_id);
                revocation_membership_frontier.extend(target.membership_frontier().iter().cloned());
            }
            // Server validation is all-or-nothing for the pending obligations
            // in one effective scope; a partial Remove commit must not be sent.
            if missing_frontier || target_principal_ids.is_empty() {
                continue;
            }
            revocation_membership_frontier.sort();
            revocation_membership_frontier.dedup();
            let draft = ctx.state_store.read(|store| {
                let target_refs: Vec<&str> =
                    target_principal_ids.iter().map(String::as_str).collect();
                crate::circle_mls::build_circle_remove_members_scope_rotate_draft(
                    store,
                    secure_store.as_ref(),
                    &realm_id,
                    &circle_id,
                    &actor_id,
                    &device_id,
                    &target_refs,
                    &revocation_membership_frontier,
                )
            });
            let draft = match draft {
                Ok(draft) => draft,
                Err(err) => {
                    tracing::debug!(
                        %realm_id,
                        %circle_id,
                        ?target_principal_ids,
                        error = %err,
                        "sync_engine: Circle scope-rotate draft build skipped",
                    );
                    continue;
                }
            };
            let events = draft.events;
            let commit_event_id = match events
                .iter()
                .find(|event| event.kind.as_str() == "ak.mls.commit")
                .map(|event| event.event_id.clone())
            {
                Some(event_id) => event_id,
                None => {
                    tracing::error!(
                        %realm_id,
                        %circle_id,
                        "sync_engine: Circle scope-rotate has no MLS commit Event",
                    );
                    continue;
                }
            };
            let post_commit_snapshot = draft.post_commit_snapshot;
            let removed_leaves = draft.removed_leaves;
            let removed_principals = draft.removed_principals;
            let outcome =
                match crate::transport::auth::with_event_submitter(&base, token.clone(), {
                    let circle_id = circle_id.clone();
                    move |sub| async move {
                        crate::transport::circle::submit_circle_scope_rotate_events(
                            &sub, &circle_id, &events, None,
                        )
                        .await
                    }
                })
                .await
                {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        if err.is_auth_expired() {
                            return;
                        }
                        tracing::debug!(
                            %realm_id,
                            %circle_id,
                            ?target_principal_ids,
                            error = %err.display(),
                            "sync_engine: Circle scope-rotate submit failed",
                        );
                        continue;
                    }
                };
            if generation.get() != start_generation {
                return;
            }
            let persisted = ctx.state_store.write(|store| {
                store.record_mls_group_state_ref_for_effective_scope(
                    realm_id.clone(),
                    Some(&circle_id),
                    post_commit_snapshot.group_id.as_str(),
                    post_commit_snapshot.epoch,
                    commit_event_id,
                )?;
                store.save_mls_snapshot_for_effective_scope(
                    realm_id.clone(),
                    Some(&circle_id),
                    post_commit_snapshot,
                );
                Ok::<_, String>(())
            });
            if let Err(error) = persisted {
                tracing::error!(
                    %realm_id,
                    %circle_id,
                    %error,
                    "sync_engine: accepted Circle MLS commit group-state reference conflicted",
                );
                return;
            }
            tracing::info!(
                %realm_id,
                %circle_id,
                ?target_principal_ids,
                ?removed_leaves,
                ?removed_principals,
                mls_group_ref = ?outcome.mls_group_ref,
                note = ?outcome.note,
                "sync_engine: Circle scope-rotate commit accepted",
            );
            return;
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
    let base = ctx.base_url.clone();
    let token = ctx.token.get();
    let actor_id = ctx.account_did.trim().to_owned();
    let device_id = ctx.device_id.trim().to_owned();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.is_empty()
    {
        return;
    }
    let now = crate::clock::now_utc();
    let realm_ids: Vec<String> = ctx
        .state_store
        .read(|store| store.mls_snapshots().into_keys().collect());
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
                &actor_id,
                &device_id,
                now,
            )
            .map_err(|err| err.user_message())
            .and_then(|maybe| match maybe {
                None => Ok(None),
                Some((commit_envelope, snapshot, previous_governance_binding)) => {
                    let schedule_hash = commit_envelope.commit_digest.clone();
                    crate::mls::group_events::mls_commit_event_from_store(
                        store,
                        &realm_id,
                        &actor_id,
                        &schedule_hash,
                        &commit_envelope,
                        &previous_governance_binding,
                    )
                    .map(|event| Some((event, commit_envelope.epoch, snapshot)))
                }
            })
        });
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
        let commit_event_id = commit_event.event_id.clone();
        match crate::transport::auth::with_authed_api(&base, submit_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&commit_event).await
        })
        .await
        {
            Ok(_) => {
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
                    store.save_mls_snapshot(realm_id.clone(), snapshot);
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
                    error = %err.display(),
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
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
    state_store: S,
    is_minimal_metadata_realm: impl Fn(&str) -> bool,
) -> bool {
    let pairs = collect_persistent_proof_sender_devices(response, &is_minimal_metadata_realm);
    prefetch_persistent_event_sender_key_pairs(api, pairs, did_cache, state_store).await
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
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
    state_store: S,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for body in response.realm_projections.values() {
        collect_member_identity_proof_devices_from_value(body, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(
        api,
        pairs.into_iter().collect(),
        did_cache,
        state_store,
    )
    .await
}

/// Recursively scan a projection `Value` for `ak.member.identity.update`
/// proofs, extracting `(controller_id, device_id)` from each
/// `member_identity.proof.verification_method`. Depth-bounded to mirror the
/// persistent-event scanner.
fn collect_member_identity_proof_devices_from_value(
    value: &Value,
    depth: usize,
    out: &mut BTreeSet<(String, String)>,
) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            // A `member_identity` object carries `actor_id` + `proof`.
            if let Some(proof) = map.get("proof").and_then(Value::as_object)
                && let Some(vm) = proof.get("verification_method").and_then(Value::as_str)
                && let Some((controller, device)) = split_verification_method(vm)
            {
                // Bind to the object's own actor_id when present (defence in
                // depth: the controller already equals the asserter at verify
                // time, but we prefetch whatever the proof names so resolution
                // can run).
                out.insert((controller, device));
            }
            for nested in map.values() {
                collect_member_identity_proof_devices_from_value(nested, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_identity_proof_devices_from_value(item, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Split a `did:method:identifier#device` verification-method URL into its
/// controller DID and device fragment. Returns `None` when there is no
/// fragment (no device selector).
fn split_verification_method(verification_method: &str) -> Option<(String, String)> {
    let (controller, fragment) = verification_method.split_once('#')?;
    let controller = controller
        .split_once('?')
        .map_or(controller, |(head, _)| head)
        .trim();
    let device = fragment.trim();
    if controller.is_empty() || device.is_empty() {
        return None;
    }
    Some((controller.to_owned(), device.to_owned()))
}

pub(crate) async fn prefetch_persistent_event_sender_keys_from_values<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    values: &[Value],
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
    state_store: S,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for value in values {
        collect_proof_sender_devices_from_value(value, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(
        api,
        pairs.into_iter().collect(),
        did_cache,
        state_store,
    )
    .await
}

/// Public alias of [`prefetch_persistent_event_sender_key_pairs`] for callers
/// outside the persistent-event projection path (e.g. the history-share install
/// loop priming `ak.realm_key.share` sender device keys before SEC-02
/// fail-closed verification).
pub(crate) async fn prefetch_device_key_pairs<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    pairs: Vec<(String, String)>,
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
    state_store: S,
) -> bool {
    prefetch_persistent_event_sender_key_pairs(api, pairs, did_cache, state_store).await
}

/// DID-P2-B: `state_store` is the durable accepted-binding handle.
///
/// This is the ordinary sync/render device-key path, so it is exactly the path
/// the "restart ⇒ resolver network delta 0" criterion is about. The anchor is
/// hydrated from the persisted bindings before it resolves anything and its
/// acceptances are written back afterwards; a DID that was accepted before the
/// restart is served from local state and never reaches the network.
async fn prefetch_persistent_event_sender_key_pairs<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    api: &TransportClient,
    pairs: Vec<(String, String)>,
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
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

    let did_cache = did_cache;
    // Fail closed: without a canonical policy digest there is no store key to
    // scope acceptances to, and inventing one would collide two policies onto
    // one key. Skipping the prefetch only costs a later authority resolution.
    let binding_scope = match crate::identity::did_binding::DidBindingScope::for_server(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        api.base_url().as_str(),
    ) {
        Ok(scope) => scope,
        Err(error) => {
            tracing::warn!(%error, "skipping device-key prefetch: resolver policy digest failed");
            return false;
        }
    };
    let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_persisted_bindings(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.get(),
        binding_scope,
        arkret_sdk::identity::DidBindingPurpose::DeviceSigner,
        state_store.with_read(crate::state::LocalStateStore::accepted_did_bindings),
    );
    crate::identity::device_directory::refresh_device_keys(api, &anchor, &missing).await;
    let (cache, records) = anchor.into_cache_and_bindings();
    did_cache.set(cache);
    if let Some(records) = records {
        state_store.with_write(|store| store.store_accepted_did_bindings(records));
    }
    true
}

fn refresh_projection_events_from_sync_response(
    response: &AccountSyncStep,
    is_full_sync: bool,
    ctx: &SyncEngineContext,
) {
    let state_store = ctx.state_store.clone();
    let account_did = ctx.account_did.clone();
    let device_id = ctx.device_id.clone();
    let synced_projection_events = state_store.read(|store| {
        crate::state::projection::projection_events_from_sync_realms(
            &response.realm_projections,
            Some(store),
            Some((&account_did, &device_id)),
        )
    });
    if is_full_sync {
        ctx.projection_sink.projection(ClientProjectionEvent::Reset);
    }
    for event in synced_projection_events {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Account(event));
    }
}

fn collect_persistent_proof_sender_devices(
    response: &AccountSyncStep,
    is_minimal_metadata_realm: &impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for (realm_id, body) in &response.realm_projections {
        // §2.10.3 — a minimal-metadata Realm's content authorship never forms
        // a directory pair; its authors verify against the MLS LeafNode.
        if is_minimal_metadata_realm(realm_id) {
            continue;
        }
        collect_proof_sender_devices_from_value(body, 0, &mut pairs);
    }
    pairs.into_iter().collect()
}

fn collect_proof_sender_devices_from_value(
    value: &Value,
    depth: usize,
    pairs: &mut BTreeSet<(String, String)>,
) {
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some((actor, device)) = proof_bearing_sender_device(object) {
                pairs.insert((actor, device));
            }
            for child in object.values() {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        _ => {}
    }
}

fn proof_bearing_sender_device(
    object: &serde_json::Map<String, Value>,
) -> Option<(String, String)> {
    let proofs = object
        .get("proofs")
        .and_then(Value::as_array)
        .filter(|proofs| !proofs.is_empty())?;
    let actor = object
        .get("actor_id")
        .or_else(|| object.get("sender_actor_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|actor| !actor.is_empty())?;
    // AKP-0008 / AKP-0009: delegated Events keep the accountable principal
    // in `actor_id`, while `executed_by` identifies the runtime that actually
    // signed the envelope. Keep this selector byte-aligned with the chat proof
    // verifier when that signer is a real directory-backed device. Independent
    // Native Agent MLS endpoints use their authenticated LeafNode key instead
    // and deliberately do not form a device-directory lookup here.
    let proof_controller = object
        .get("executed_by")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|controller| !controller.is_empty())
        .unwrap_or(actor);
    let controller_matches = proofs
        .iter()
        .filter_map(|proof| proof.get("verification_method").and_then(Value::as_str))
        .any(|method| {
            let no_query = method.split_once('?').map_or(method, |(head, _)| head);
            no_query.split_once('#').map_or(no_query, |(head, _)| head) == proof_controller
        });
    if !controller_matches {
        return None;
    }
    let device = object
        .get("device_id")
        .or_else(|| object.get("sender_device_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .map(str::to_owned)
        .or_else(|| proof_sender_device_from_verification_method(object, proof_controller))?;
    Some((proof_controller.to_owned(), device))
}

fn proof_sender_device_from_verification_method(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> Option<String> {
    object
        .get("proofs")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|proof| proof.get("verification_method").and_then(Value::as_str))
        .find_map(|method| {
            let no_query = method
                .split_once('?')
                .map(|(head, _)| head)
                .unwrap_or(method);
            let (controller, fragment) = no_query.split_once('#')?;
            (controller == actor && fragment.starts_with("ak:device:")).then(|| fragment.to_owned())
        })
}

fn rotate_live_device_id_after_revocation(
    live_device_id: &crate::runtime::input::ValueCell<String>,
) {
    live_device_id.set(crate::config::new_device_id());
}

/// Apply an account subscribe response: persist projections (server-authoritatively
/// reconciled when full-sync), hydrate Seal views + account-data, and
/// publish derived UI signals (realm tree nodes / event projections / device queue /
/// status / cursor).
///
/// Exposed at module scope so tests can drive it without spinning up
/// the loop. `connect()` in `app.rs` shares the same code path — once
/// the engine fully owns sync, `connect()` is just a "force one
/// iteration now" entry that calls this.
pub fn apply_response(
    response: &AccountSyncStep,
    is_full_sync: bool,
    ctx: &SyncEngineContext,
    invite_notifications: Option<
        Vec<arkret_models_collaboration::governance::operation_wire::Invite>,
    >,
) {
    // Clone runtime adapter handles before applying this response.
    let state_store = ctx.state_store.clone();
    let did_cache = ctx.did_cache.clone();
    let account_did = ctx.account_did.clone();
    let mut synced_theme = None;
    let mut realm_projection_changed = false;

    // Y2 invalidation hook: scan identity events in this response before writing
    // projections. On `ak.cross_signing.reset` / `ak.device.revoke`, invalidate
    // the related actor DID so the next authority resolution (`resolve_with_cache`)
    // walks the resolver chain instead of trusting a stale cache entry (old key
    // set). Keep this separate from the state-store write callback.
    //
    // DID-P2-B extends this from two coarse event kinds to the five classes
    // §4 lists (rotation / deactivation / device-agent epoch / service-
    // controller delegation / policy change), and routes them at two
    // granularities: the DID-keyed session cache gets the DID, the durable
    // binding store gets the precise six-dimension selectors.
    let mut binding_selectors: Vec<arkret_sdk::identity::BindingInvalidation> = Vec::new();
    did_cache.update(|cache| {
        for body in response.realm_projections.values() {
            for (did, selectors) in collect_binding_invalidations(body) {
                cache.invalidate(&did);
                binding_selectors.extend(selectors);
            }
        }
    });
    if !binding_selectors.is_empty() {
        state_store.write(|store| {
            store.invalidate_accepted_did_bindings_batch(&binding_selectors);
        });
    }

    // The device-signing-key cache is a *separate* cache from the DID bindings
    // above, and its 5-minute positive TTL is not sufficient on its own:
    // `signal.md` §1 forbids reusing an older positive entry once a device-list
    // or generation frontier change has been observed. Dropping the actor's
    // entries here only forces a re-query; the synchronous receive path fails
    // closed on the resulting miss.
    for body in response.realm_projections.values() {
        for actor in collect_device_frontier_actors(body) {
            let dropped = crate::identity::device_directory::invalidate_actor(&actor);
            if dropped > 0 {
                tracing::debug!(
                    %actor,
                    dropped,
                    "dropped cached device signing keys after a device frontier change"
                );
            }
        }
    }

    if response_revokes_local_device(response, &account_did, &ctx.device_id) {
        state_store.write(|store| store.clear_device_scoped());
        rotate_live_device_id_after_revocation(&ctx.live_device_id);
        ctx.session
            .invalidate("this device was revoked by an accepted control event");
        return;
    }

    state_store.write(|store| {
        // Perf (P0): a single sync response can touch the cursor, dozens of
        // realm-tree projections, seal views, member identity events and account
        // data — each setter used to flush the *entire* `ClientLocalState` to
        // disk/localStorage. Wrap the whole apply in one batch so it persists
        // exactly once.
        let cursor_can_advance = to_device_batch_allows_cursor_advance(
            &response.updates.to_device,
            response.updates.to_device_limited,
        );
        store.batch(|store| {
            if is_full_sync {
                // Server-authoritative for top-level Realm membership:
                // drop projections the server didn't include, except an
                // acknowledged optimistic Realm awaiting its first account
                // projection and local Space containers whose home Realm is
                // still present.
                let server_set: BTreeSet<String> =
                    response.realm_projections.keys().cloned().collect();
                let keep_set = crate::app::full_sync_projection_keep_set(
                    &server_set,
                    &store.load().realm_tree_projections,
                );
                let pruned = store.retain_realm_tree_projections(|id| keep_set.contains(id));
                if !pruned.is_empty() {
                    tracing::info!(
                        pruned_count = pruned.len(),
                        "sync engine: full-sync pruned stale realm-tree projections",
                    );
                }
            }
            // Explicit `left_realms` deltas — meaningful primarily on
            // incremental sync, but cheap to apply on full sync too.
            for update in &response.updates.realm_updates {
                let id = update.realm_id.as_str();
                let Some(body) = response.realm_projections.get(id) else {
                    continue;
                };
                if !is_full_sync && !realm_update_has_durable_projection(update) {
                    continue;
                }
                // The live epoch represents the durable Realm projection as a
                // whole, not only events understood by one product surface.
                // Summary/member/state-only deltas must invalidate durable
                // consumers just as timeline events do.
                realm_projection_changed = true;
                let existing = store.load().realm_tree_projections.get(id).cloned();
                let projection = if is_full_sync {
                    body.clone()
                } else {
                    merge_incremental_realm_projection(existing.as_ref(), body)
                };
                let projection = preserve_realm_security_projection(existing.as_ref(), &projection);
                store.save_realm_tree_projection(id.to_owned(), projection.clone());
                if let Err(error) =
                    store.reconcile_mls_genesis_group_state_ref_from_projection(id, None)
                {
                    tracing::error!(
                        realm_id = %id,
                        %error,
                        "sync engine: accepted MLS genesis projection conflicts with local group state",
                    );
                }
                if is_full_sync || response.has_window_start_realm_metadata(id) {
                    store.save_realm_collaboration_role(
                        id.to_owned(),
                        response.collaboration_role(id),
                    );
                }
                store.merge_realm_seal_view_from_sync_body(id, &projection);
                store.ingest_move_event_states(id, &projection);
                let _ = ingest_kanban_state_events_from_projection(store, id, &projection)
                    + ingest_discussion_state_events_from_projection(store, id, &projection)
                    + ingest_message_events_from_projection(store, id, &projection)
                    + ingest_moderation_events_from_projection(store, id, &projection);
                ingest_membership_events_from_projection(store, id, &projection);
                // Fold the discussion timeline into `raw_operations` too so the
                // card-detail Discussion tab renders local-first instead of
                // refetching + redecrypting the realm on every open.
                // R3.1 MID-2 — harvest inlined `ak.member.identity.update`
                // event envelopes off the `members[]` roster entries. The
                // SDK's effective-set filter is applied lazily when a UI
                // surface needs to resolve a display identity.
                ingest_member_identity_events_from_projection(store, id, &projection);
            }
            crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                store,
                &response.realm_projections,
            );

            synced_theme = apply_account_data(store, response, &account_did);
            apply_notification_projection(
                store,
                response,
                &account_did,
                is_full_sync,
                invite_notifications,
            );
            store.ingest_to_device_messages(&response.updates.to_device);
            if cursor_can_advance {
                store.save_sync_cursor(response.cursor.clone());
            }
        }); // store.batch — single coalesced flush happens here
    });
    if realm_projection_changed {
        ctx.realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
    if let Some(value) = synced_theme {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Theme { value });
    }

    // Receive side of `ak.call.signal`: route inbound call-signal envelopes
    // from each realm body into the hub (dedup → incoming ring / per-call
    // Realm tree nodes are derived in the app projection adapter from the
    // canonical local-state projection; the engine only computes a snapshot
    // for status and selected-Realm bookkeeping.
    let reconciled = state_store.read(|store| {
        let state = store.load();
        crate::app::realm_tree_nodes_from_sync_realms_with_roles(
            &state.realm_tree_projections,
            &state.realm_collaboration_roles,
        )
    });
    ctx.projection_sink.sync_status(SyncStatusEvent::Online);
    let first_realm = reconciled
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone());
    {
        let current = ctx.selected_realm_id.get();
        let trimmed = current.trim();
        let needs_reset = trimmed.is_empty() || !reconciled.iter().any(|node| node.id == trimmed);
        if needs_reset {
            ctx.projection_sink
                .projection(ClientProjectionEvent::SelectedRealm {
                    realm_id: first_realm.unwrap_or_default(),
                });
        }
    }

    // Merge encrypted bodies on read (author sidecar → remote decrypt-on-read).
    // The `store` write guard above is out of scope; take a fresh read guard.
    let device_id = ctx.device_id.clone();
    let synced_projection_events = state_store.read(|store| {
        crate::state::projection::projection_events_from_sync_realms(
            &response.realm_projections,
            Some(store),
            Some((&account_did, &device_id)),
        )
    });
    if is_full_sync {
        ctx.projection_sink.projection(ClientProjectionEvent::Reset);
    }
    for event in synced_projection_events {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Account(event));
    }

    ctx.projection_sink
        .projection(ClientProjectionEvent::DeviceQueue {
            pending: state_store.read(|store| store.load().to_device_inbox.len()),
        });
    if to_device_batch_allows_cursor_advance(
        &response.updates.to_device,
        response.updates.to_device_limited,
    ) {
        ctx.projection_sink
            .projection(ClientProjectionEvent::CursorCheckpoint {
                scope: "account".to_owned(),
                cursor: response.cursor.clone(),
            });
    } else {
        tracing::debug!(
            cursor = %response.cursor,
            to_device_count = response.updates.to_device.len(),
            "sync engine: deferred cursor advancement until to-device key material is durable"
        );
    }
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

/// Raw inbox durability is enough for ordinary device messages, but an MLS
/// Welcome is destructive-consumer state: acknowledging it before the MLS
/// runtime imports and durably snapshots the group makes the only join secret
/// disappear from the server queue. The Welcome bootstrap owns that ACK after
/// successful apply (or an explicitly verified stale replay).
fn to_device_batch_safe_for_ingest_ack(messages: &[arkret_sdk::DeviceMessageEnvelope]) -> bool {
    !messages.iter().any(|message| {
        serde_json::to_value(message)
            .ok()
            .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
            .as_deref()
            == Some("ak.mls.welcome")
    })
}

fn to_device_batch_allows_cursor_advance(
    _messages: &[arkret_sdk::DeviceMessageEnvelope],
    _limited: bool,
) -> bool {
    // Cursor position and to-device deletion are deliberately independent.
    // This predicate is retained at projection call sites to document that
    // all durably-ingested batches, including limited pages, may checkpoint.
    true
}

fn sync_realm_state_events(body: &Value) -> Vec<Value> {
    body.get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn response_revokes_local_device(
    response: &AccountSyncStep,
    account_did: &str,
    device_id: &str,
) -> bool {
    let account_did = account_did.trim();
    let device_id = device_id.trim();
    if account_did.is_empty() || device_id.is_empty() {
        return false;
    }
    response.realm_projections.values().any(|body| {
        sync_realm_state_events(body).iter().any(|event| {
            let kind = event
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(payload) = event.get("payload") else {
                return false;
            };
            kind == "ak.device.revoke"
                && payload.get("principal_id").and_then(Value::as_str) == Some(account_did)
                && payload.get("device_id").and_then(Value::as_str) == Some(device_id)
        })
    })
}

fn ingest_kanban_state_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    let events = sync_realm_state_events(body);
    ingest_kanban_projection_events(store, realm_id, &events)
}

/// Discussion message events ride a SEPARATE projection array from the kanban
/// state log: `timeline.events[]` (see `chat_messages_from_sync_realms_*`).
fn sync_realm_timeline_events(body: &Value) -> Vec<Value> {
    body.get("timeline")
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Fold the realm's discussion timeline into the shared `raw_operations` log so
/// the Discussion tab projects local-first — no per-open realm backfill /
/// redecrypt — mirroring [`ingest_kanban_state_events_from_projection`].
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

fn ingest_moderation_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    ingest_moderation_projection_events(store, realm_id, &sync_realm_state_events(body))
}

pub(crate) fn ingest_moderation_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
) -> usize {
    let records = crate::state::projection::moderation_ops::moderation_operations_from_events(
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

fn discussion_state_control_event_kind(event: &Value) -> Option<&str> {
    event
        .get("kind")
        .or_else(|| event.get("event_kind"))
        .or_else(|| event.get("type"))
        .or_else(|| event.get("op_type"))
        .or_else(|| event.get("event_type"))
        .and_then(Value::as_str)
}

fn discussion_state_event_is_ingestable(event: &Value) -> bool {
    matches!(
        discussion_state_control_event_kind(event),
        Some(
            "ak.message.create"
                | "ak.message.revise"
                | "ak.message.redact"
                | "ak.reaction.add"
                | "ak.reaction.remove"
                | "ak.pin.add"
                | "ak.pin.remove"
                | "ak.pin.reorder"
        )
    )
}

fn ingest_discussion_state_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    let events = sync_realm_state_events(body)
        .into_iter()
        .filter(discussion_state_event_is_ingestable)
        .collect::<Vec<_>>();
    ingest_message_projection_events(store, realm_id, &events)
}

/// Fold a batch of discussion message events into `raw_operations`. Shared by
/// the account-aggregate sync path (above) and the per-realm `events/subscribe`
/// engine ([`crate::realm_events_engine`]) — a cross-member message that the
/// account stream never routed (unroutable delivery binding) still lands
/// locally through the realm stream — both deduping via the message event id.
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
    events: &[Value],
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

fn sync_event_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn membership_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    let kind = sync_event_string(Some(event), &["event_kind"])
        .or_else(|| sync_event_string(Some(event), &["kind"]))?;
    if !matches!(kind.as_str(), "ak.member.state" | "ak.invite.accept") {
        return None;
    }
    let body = event
        .get("payload")
        .or_else(|| event.get("content"))
        .cloned()
        .unwrap_or(Value::Null);
    let event_id = sync_event_string(Some(event), &["event_id"])?;
    let operation_id =
        sync_event_string(Some(event), &["operation_id"]).unwrap_or_else(|| event_id.clone());
    let actor_id = sync_event_string(Some(event), &["actor_id"])
        .or_else(|| sync_event_string(Some(event), &["sender_actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["sender_actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["sender"]))
        .unwrap_or_default();
    let created_at = sync_event_string(Some(event), &["created_at"])
        .or_else(|| sync_event_string(Some(&body), &["created_at"]))
        .unwrap_or_default();
    let received_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let mut payload = json!({
        "kind": kind,
        "operation_id": operation_id,
        "actor_id": actor_id,
        "created_at": created_at,
        "write_state": "synced",
        "body": body,
    });
    if let Some(object) = payload.as_object_mut() {
        object.insert("event_id".to_owned(), Value::String(event_id));
    }

    Some(RawOperationRecord {
        operation_id: payload
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("remote-membership")
            .to_owned(),
        realm_id: sync_event_string(Some(event), &["realm_id"])
            .or_else(|| sync_event_string(payload.get("body"), &["realm_id"]))
            .or_else(|| sync_event_string(payload.get("body"), &["object", "realm_id"])),
        received_at,
        payload,
    })
}

pub(crate) fn ingest_membership_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
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
    let kind = event.kind.as_str();
    if !matches!(kind, "ak.member.state" | "ak.invite.accept") {
        return None;
    }
    let operation_id = event.event_id.as_str().to_owned();
    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "event_id": event.event_id.as_str(),
            "actor_id": event.actor_id.as_str(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
            "write_state": "synced",
            "body": event.payload,
        }),
    })
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

fn ingest_membership_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    ingest_membership_projection_events(store, realm_id, &sync_realm_state_events(body))
}

fn ingest_member_identity_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) {
    // Build a quick lookup over the canonical `state.events[]` array on the
    // projection so that referenced identity_event_ids can be resolved
    // without a separate query.
    let state_log_events = sync_realm_state_events(body);
    let state_events: BTreeSet<String> = state_log_events
        .iter()
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let state_event_by_id: std::collections::BTreeMap<String, Value> = state_log_events
        .iter()
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), event.clone()))
        })
        .collect();

    for source in [
        body.get("members"),
        body.get("summary").and_then(|s| s.get("members")),
    ]
    .into_iter()
    .flatten()
    {
        let Some(items) = source.as_array() else {
            continue;
        };
        for entry in items {
            let Some(map) = entry.as_object() else {
                continue;
            };
            let Some(actor_id) = map
                .get("actor_id")
                .or_else(|| map.get("did"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            // Inline events have priority — they're complete envelopes.
            if let Some(events) = map.get("identity_events").and_then(Value::as_array) {
                store.ingest_member_identity_events(realm_id, actor_id, events);
            }
            // Otherwise hydrate envelopes from `state.events[]` keyed
            // by id. Missing references are dropped silently — the
            // server will resend them on the next subscribe frame, or
            // a `ak.self.events.read.scan` backfill will catch up.
            if let Some(refs) = map.get("identity_event_ids").and_then(Value::as_array) {
                let mut resolved: Vec<Value> = Vec::new();
                for r in refs {
                    if let Some(id) = r.as_str()
                        && state_events.contains(id)
                        && let Some(envelope) = state_event_by_id.get(id)
                    {
                        resolved.push(envelope.clone());
                    }
                }
                if !resolved.is_empty() {
                    store.ingest_member_identity_events(realm_id, actor_id, &resolved);
                }
            }
        }
    }
}

/// Core scanner for the Y2 invalidation hook.
///
/// Finds `ak.cross_signing.reset` / `ak.device.revoke` events in one Realm
/// projection `body`, then calls
/// [`arkret_sdk::identity::DidResolutionCache::invalidate`] for the related actor
/// DID. Events may appear in:
/// - inline `identity_events[]` on each member roster entry;
/// - projection event logs at `state.events[]`.
///
/// Actor DID is read from the event `actor_id` / `did`, falling back to the
/// roster entry `actor_id` / `did`. Forbidden `actor` / `sender` fields are
/// ignored. The value is validated via `Did::new`; invalid DID syntax is
/// skipped because this best-effort invalidation hook must not panic.
///
/// TRUST-CACHE boundary: this only clears cache entries so the next resolution
/// walks the authority chain again; it does not replace authority validation.
#[cfg(test)]
fn invalidate_cache_for_revocation_events(
    cache: &mut arkret_sdk::identity::DidResolutionCache,
    body: &Value,
) {
    for (did, _) in collect_binding_invalidations(body) {
        cache.invalidate(&did);
    }
}

/// DID-P2-B step 4: derive the precise binding invalidations implied by one
/// Realm projection `body`.
///
/// Returns `(actor DID, selectors)` pairs. The DID drives the coarse
/// session-cache eviction (`DidResolutionCache` is keyed by DID and can express
/// nothing finer); the selectors drive the persisted binding store, where the
/// SDK's six-dimension conjunctive [`arkret_sdk::identity::BindingInvalidation`]
/// keeps a device revoke from evicting a `Principal` acceptance and keeps one
/// trust domain's rotation from touching another's.
///
/// The event-kind → selector mapping lives in
/// [`crate::state::binding_invalidations_for_event`] so the table and its tests
/// sit next to the store they act on. This function only handles *finding* the
/// events in the two projection shapes inkson receives.
fn collect_binding_invalidations(
    body: &Value,
) -> Vec<(
    arkret_sdk::Did,
    Vec<arkret_sdk::identity::BindingInvalidation>,
)> {
    /// The concrete rotated key, when the event names one. Absent → the whole
    /// DID is invalidated rather than one key, which is the conservative side.
    fn verification_method(event: &Value) -> Option<arkret_sdk::DidUrl> {
        let raw = event
            .get("verification_method")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .pointer("/content/verification_method")
                    .and_then(Value::as_str)
            })?;
        arkret_sdk::DidUrl::new(raw.to_owned()).ok()
    }

    let mut out = Vec::new();
    for_each_projection_identity_event(body, |event, fallback| {
        let kind = projection_event_kind(event);
        if !crate::state::is_binding_invalidating_kind(kind) {
            return;
        }
        // Invalid DID syntax is skipped: this hook must not panic, and a
        // malformed identity event is not authority to evict anything.
        let Some(did) = projection_event_actor_id(event, fallback)
            .and_then(|value| arkret_sdk::Did::new(value.to_owned()).ok())
        else {
            return;
        };
        let selectors = crate::state::binding_invalidations_for_event(
            kind,
            &did,
            verification_method(event).as_ref(),
        );
        out.push((did, selectors));
    });
    out
}

fn projection_event_kind(event: &Value) -> &str {
    event
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| event.get("type").and_then(Value::as_str))
        .unwrap_or("")
}

/// Read the actor DID string from the event, falling back to the roster entry.
fn projection_event_actor_id<'a>(event: &'a Value, fallback: Option<&'a Value>) -> Option<&'a str> {
    let from = |value: &'a Value| {
        value
            .get("actor_id")
            .or_else(|| value.get("did"))
            .and_then(Value::as_str)
    };
    from(event).or_else(|| fallback.and_then(from))
}

/// Visit every identity-carrying event in one Realm projection `body`, in the
/// two shapes inkson receives them:
///
/// - the canonical top-level `state[]` event log;
/// - inline `identity_events[]` on each member roster entry, where the entry is passed as the actor
///   fallback.
fn for_each_projection_identity_event(body: &Value, mut visit: impl FnMut(&Value, Option<&Value>)) {
    for event in &sync_realm_state_events(body) {
        visit(event, None);
    }
    for source in [
        body.get("members"),
        body.get("summary").and_then(|s| s.get("members")),
    ]
    .into_iter()
    .flatten()
    {
        let Some(items) = source.as_array() else {
            continue;
        };
        for entry in items {
            if let Some(events) = entry.get("identity_events").and_then(Value::as_array) {
                for event in events {
                    visit(event, Some(entry));
                }
            }
        }
    }
}

/// Principals whose device-list / generation frontier moved in this projection.
///
/// The subject of a device event is the principal named by the payload, not
/// necessarily the authoring actor, so `principal_id` wins when present.
fn collect_device_frontier_actors(body: &Value) -> BTreeSet<String> {
    let mut actors = BTreeSet::new();
    for_each_projection_identity_event(body, |event, fallback| {
        if !crate::identity::device_directory::is_device_frontier_event_kind(projection_event_kind(
            event,
        )) {
            return;
        }
        let subject = event
            .pointer("/payload/principal_id")
            .and_then(Value::as_str)
            .or_else(|| projection_event_actor_id(event, fallback));
        if let Some(subject) = subject.map(str::trim).filter(|value| !value.is_empty()) {
            actors.insert(subject.to_owned());
        }
    });
    actors
}

fn apply_notification_projection(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    account_did: &str,
    is_full_sync: bool,
    invite_notifications: Option<
        Vec<arkret_models_collaboration::governance::operation_wire::Invite>,
    >,
) {
    let should_save_notification_projection = !response.updates.notifications.is_empty()
        || is_full_sync
        || !response.updates.account_data.is_empty()
        || invite_notifications.is_some();
    let mut notification_projection = store.notification_projection();
    let joined_realms = crate::state::projection::notifications::JoinedRealmIds::from_realm_entries(
        &response.realm_entries,
        account_did,
    );
    crate::state::projection::notifications::apply_notification_projection(
        &mut notification_projection,
        &response.updates.notifications,
        &response.updates.account_data,
        is_full_sync,
        invite_notifications,
        &joined_realms,
    );
    if should_save_notification_projection {
        store.save_notification_projection(notification_projection);
    }
}

fn apply_account_data(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    account_did: &str,
) -> Option<String> {
    apply_account_data_entries(store, &response.updates.account_data, account_did)
}

pub(crate) fn apply_account_data_entries(
    store: &mut LocalStateStore,
    entries: &[arkret_sdk::Event],
    account_did: &str,
) -> Option<String> {
    let mut synced_theme = None;
    for entry in entries {
        let Some(account_data_key) = entry.payload.get("key").and_then(Value::as_str) else {
            continue;
        };
        match crate::sidecar::ingest_sidecar_view_state_account_data(
            store,
            account_did,
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
        // ak.client.ui_state — theme + avatar pointer.
        if account_data_key == "ak.client.ui_state" {
            match crate::account_data::decrypt_account_data_entry(
                account_did,
                account_data_key,
                &entry.payload,
            ) {
                Ok(content) => {
                    let local_theme = store
                        .load_private_data(account_did, "theme")
                        .unwrap_or_else(|| "night".to_owned());
                    if let Some(remote_theme) =
                        crate::account_data::merge_client_ui_theme(&local_theme, &content)
                    {
                        store.save_private_data(account_did, "theme", remote_theme.clone());
                        synced_theme = Some(remote_theme);
                    }
                    if let Some(avatar_blob_ref) =
                        crate::account_data::avatar_blob_ref_from_client_ui(&content)
                    {
                        store.save_private_data(account_did, "avatar_blob_ref", avatar_blob_ref);
                    } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(
                        &content,
                    ) {
                        store.save_private_data(account_did, "avatar_blob_ref", "");
                    }
                }
                Err(error) => tracing::warn!(
                    "sync engine: ignoring undecryptable ak.client.ui_state: {error}"
                ),
            }
            continue;
        }
        // ak.account.blocklist — personal block list.
        if account_data_key == "ak.presence.visibility" {
            let Some(visibility) = crate::account_data::decrypt_account_data_entry(
                account_did,
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
        // ak.presence.preference — manual presence preference
        // (profiles-presence.md §3.6). The server stores only the standard
        // account-data AEAD envelope; decrypt before applying it locally.
        if account_data_key == "ak.presence.preference" {
            match crate::account_data::decrypt_account_data_entry(
                account_did,
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
        if account_data_key == "ak.dnd_schedule" {
            match crate::account_data::decrypt_account_data_entry(
                account_did,
                account_data_key,
                &entry.payload,
            ) {
                Ok(content) => store.set_notification_dnd_settings(
                    crate::notification_rules::parse_dnd_settings(&content),
                ),
                Err(error) => {
                    tracing::warn!("sync engine: ignoring undecryptable ak.dnd_schedule: {error}")
                }
            }
            continue;
        }
        if account_data_key == "ak.account.blocklist" {
            match crate::account_data::decrypt_account_data_entry(
                account_did,
                account_data_key,
                &entry.payload,
            )
            .and_then(|content| {
                let entries =
                    crate::account_data::blocklist_entries_from_account_data(&content, account_did)
                        .map_err(anyhow::Error::msg)?;
                let revision = entry
                    .payload
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("ak.account.blocklist is missing revision"))?;
                Ok((revision, entries))
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
        // ak.contacts.actor.<did> — actor-private contact remarks.
        if let Some(actor_id) =
            crate::account_data::actor_id_from_contact_remark_key(account_data_key)
        {
            match crate::account_data::decrypt_account_data_entry(
                account_did,
                account_data_key,
                &entry.payload,
            )
            .and_then(|content| serde_json::from_value(content).map_err(Into::into))
            {
                Ok(remark) => store.set_contact_remark(actor_id.to_owned(), remark),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed Contact remark for {actor_id}: {error}",
                    );
                }
            }
            continue;
        }
        // ak.contacts.realm.<realm_id> — actor-private Realm remarks.
        let Some(realm_id) = crate::account_data::realm_id_from_realm_remark_key(account_data_key)
        else {
            continue;
        };
        match crate::account_data::decrypt_account_data_entry(
            account_did,
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
    fn realm_mls_removal_basis_requires_complete_roster_and_accepted_frontier() {
        let removal_event = "ak:event:AXYOPItXAzTTu_rqIAINR7C7AvNSR5bjjBslclmJ9ZVt";
        let projection = json!({
            "members_limited": false,
            "members": [{
                "actor_id": "did:webvh:z6mkfixture:alice.example",
                "membership": "join"
            }],
            "state": {"events": [{
                "event_id": removal_event,
                "kind": "ak.member.state",
                "payload": {
                    "actor_id": "did:webvh:z6mkfixture:bob.example",
                    "membership": "ban"
                }
            }]}
        });

        let (active, frontier) = realm_membership_removal_basis(&projection).unwrap();
        assert_eq!(
            active,
            BTreeSet::from(["did:webvh:z6mkfixture:alice.example".to_owned()])
        );
        assert_eq!(
            frontier,
            vec![arkret_sdk::EventId::new(removal_event.to_owned()).unwrap()]
        );

        let mut truncated = projection;
        truncated["members_limited"] = json!(true);
        assert!(realm_membership_removal_basis(&truncated).is_none());
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
                malformed_realms: Vec::new(),
                to_device: Vec::new(),
                to_device_ack_token: None,
                to_device_limited: false,
                to_device_next_cursor: None,
                to_device_lost: false,
                device_lists: arkret_sdk::AccountSubscribeDeviceListChanges {
                    changed: Vec::new(),
                    left: Vec::new(),
                },
                account_data: Vec::new(),
                notifications: Vec::new(),
                agent_signer_evidence: Vec::new(),
                partial: false,
            },
        }
    }

    #[test]
    fn frontier_only_account_step_is_projection_empty() {
        let mut response = empty_response("ak:cursor:idle");
        assert!(account_updates_are_empty(&response.updates));

        response.updates.partial = true;
        assert!(!account_updates_are_empty(&response.updates));
    }

    #[test]
    fn steady_state_sync_does_not_poll_invites() {
        assert!(should_bootstrap_invites(true));
        assert!(!should_bootstrap_invites(false));
    }

    /// Restates `circle_scan_ignores_ephemeral_only_realm_updates`.
    ///
    /// Its premise died with the plaintext rail: a Realm sync entry can no
    /// longer carry an `ephemeral` bucket at all — the SDK type rejects the
    /// member outright. What survives is the rule the test was protecting: a
    /// sync entry with no durable projection must not trigger a Circle scan.
    #[test]
    fn circle_scan_ignores_realm_updates_without_a_durable_projection() {
        let realm_id = sdk_realm_id();
        assert!(
            serde_json::from_value::<arkret_sdk::RealmSyncEntry>(json!({
                "ephemeral": {"events": []}
            }))
            .is_err(),
            "the deleted plaintext ephemeral bucket must not decode on a Realm sync entry"
        );
        let projection_empty = arkret_sdk::RealmUpdate {
            realm_id: realm_id.clone(),
            entry: serde_json::from_value(json!({})).expect("empty Realm update"),
        };
        assert!(!realm_update_has_durable_projection(&projection_empty));

        let durable = arkret_sdk::RealmUpdate {
            realm_id,
            entry: serde_json::from_value(json!({
                "state": {"events": [serde_json::to_value(sdk_event(
                    "ak.circle.member.remove",
                    json!({"circle_id": "ak:circle:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"})
                )).unwrap()]}
            }))
            .expect("durable Realm update"),
        };
        assert!(realm_update_has_durable_projection(&durable));
    }

    #[test]
    fn incremental_realm_delta_preserves_omitted_policy_state() {
        let cached = json!({
            "__kind": "realm",
            "content_scheme": "mls_exporter_aead_v1",
            "history_visibility": "shared",
            "summary": {"title": "Shared history"},
            "state": {"events": [
                {
                    "event_id": "ak:event:create",
                    "kind": "ak.realm.create",
                    "effects": [{"cell": "ak:cell:realm.create"}]
                },
                {
                    "event_id": "ak:event:policy",
                    "kind": "ak.realm.policy_bundle",
                    "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                    "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
                }
            ]},
            "timeline": {"events": [{"event_id": "ak:event:one"}]}
        });
        let incoming = json!({
            "summary": {"joined_member_count": 1},
            "state": {"events": [{
                "event_id": "ak:event:genesis",
                "kind": "ak.mls.genesis"
            }]},
            "timeline": {"events": [{"event_id": "ak:event:two"}]}
        });

        let merged = merge_incremental_realm_projection(Some(&cached), &incoming);

        assert_eq!(merged["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(merged["summary"]["title"], "Shared history");
        assert_eq!(merged["summary"]["joined_member_count"], 1);
        assert_eq!(merged["state"]["events"].as_array().unwrap().len(), 3);
        assert_eq!(merged["timeline"]["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn incremental_state_delta_replaces_the_same_reducer_cell() {
        let cached = json!({
            "state": {"events": [{
                "event_id": "ak:event:old-policy",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]},
            "state_after": {"events": [{
                "event_id": "ak:event:old-policy-after",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]}
        });
        let incoming = json!({
            "state": {"events": [{
                "event_id": "ak:event:new-policy",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
            }]}
        });

        let merged = merge_incremental_realm_projection(Some(&cached), &incoming);
        let events = merged["state"]["events"].as_array().unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_id"], "ak:event:new-policy");
        assert!(
            merged["state_after"]["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn incremental_state_after_delta_shadows_the_same_current_state_cell() {
        let cached = json!({
            "state": {"events": [{
                "event_id": "ak:event:old-policy",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]}
        });
        let incoming = json!({
            "state_after": {"events": [{
                "event_id": "ak:event:new-policy",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
            }]}
        });

        let merged = merge_incremental_realm_projection(Some(&cached), &incoming);

        assert!(merged["state"]["events"].as_array().unwrap().is_empty());
        assert_eq!(
            merged["state_after"]["events"][0]["event_id"],
            "ak:event:new-policy"
        );
    }

    #[test]
    fn incremental_realm_projection_preserves_create_locked_security_state() {
        let encrypted_create = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });
        let initial = preserve_realm_security_projection(None, &encrypted_create);
        assert_eq!(initial["__realm_security_encrypted"], true);

        let partial_delta = json!({
            "state_at_window_start": {
                "realm_metadata": {"title": "Renamed Realm"},
                "e2ee_epoch": null
            },
            "state": {"events": []}
        });
        let merged = preserve_realm_security_projection(Some(&initial), &partial_delta);

        assert_eq!(merged["__realm_security_encrypted"], true);
        assert!(crate::security_state::realm_projection_is_encrypted(
            &merged
        ));
    }

    #[test]
    fn incremental_realm_projection_keeps_explicit_plaintext_state() {
        let plaintext_create = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "none"}}
            }]}
        });
        let merged = preserve_realm_security_projection(None, &plaintext_create);

        assert_eq!(merged["__realm_security_encrypted"], false);
        assert!(!crate::security_state::realm_projection_is_encrypted(
            &merged
        ));
    }

    #[test]
    fn standalone_to_device_pull_requires_limited_account_batch() {
        let mut response = empty_response("ak:cursor:to-device");
        response.updates.to_device_next_cursor = Some("ak:cursor:page-2".to_owned());
        assert_eq!(to_device_backfill_cursor(&response.updates), None);

        response.updates.to_device_limited = true;
        assert_eq!(
            to_device_backfill_cursor(&response.updates).as_deref(),
            Some("ak:cursor:page-2")
        );
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
        arkret_sdk::RealmId::new("ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j").unwrap()
    }

    fn sdk_actor_id() -> arkret_sdk::Did {
        arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn sdk_event(kind: &str, payload: Value) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: sdk_realm_id(),
            },
            sdk_actor_id(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn minimal_metadata_realms_never_form_directory_prefetch_pairs() {
        // §2.10.3 / SPI-INK-001: a proof-bearing persistent event inside a
        // minimal-metadata Realm must not contribute an `(actor, device)`
        // `keys/query` prefetch pair; the same shape in an ordinary Realm
        // does. This is the receiver-side "principal_directory_queries = 0"
        // guarantee — no pair, no query.
        let pairwise_envelope = json!({
            "actor_id": "did:key:z6MkpairwiseAlice",
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000aa",
            "proofs": [{
                "verification_method": "did:key:z6MkpairwiseAlice#z6MkpairwiseAuthorKey"
            }],
        });
        let directory_envelope = json!({
            "actor_id": "did:webvh:z6mkfixture:bob.example",
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000bb",
            "proofs": [{
                "verification_method": "did:webvh:z6mkfixture:bob.example#key-1"
            }],
        });
        let minimal_realm = "ak:realm:AR6sSnzYzneKDHwNTaEOztzBtLnt8geLs44CLQ9Bw2WW";
        let ordinary_realm = "ak:realm:Af9zSmEjGsepWRH4BZAZH6au69G5_e_iQ6s383Z9--fe";
        let mut response = empty_response("ak:cursor:minimal-metadata");
        response.realm_projections.insert(
            minimal_realm.to_owned(),
            json!({ "events": [pairwise_envelope] }),
        );
        response.realm_projections.insert(
            ordinary_realm.to_owned(),
            json!({ "events": [directory_envelope] }),
        );

        let pairs = collect_persistent_proof_sender_devices(&response, &|realm_id: &str| {
            realm_id == minimal_realm
        });
        assert_eq!(
            pairs,
            vec![(
                "did:webvh:z6mkfixture:bob.example".to_owned(),
                "ak:device:0196419b-0000-7000-8000-0000000000bb".to_owned()
            )]
        );

        // Control: without the minimal-metadata classification both realms
        // would have contributed pairs.
        let all = collect_persistent_proof_sender_devices(&response, &|_: &str| false);
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn account_response_projects_client_events_and_decodes_realm_payloads() {
        let message_event = sdk_event(
            arkret_sdk::EventKind::MESSAGE_CREATE,
            json!({
                "strand_id": "ak:strand:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        );
        let state_event = sdk_event(
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
                "events": [serde_json::to_value(message_event).unwrap()],
                "limited": false
            },
            "state": {"events": [serde_json::to_value(state_event).unwrap()]},
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
        assert!(report.malformed_realms.is_empty());
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
        use arkret_sdk::EventsSubscribeFrameKind;

        let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
        let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        // Mirrors the server's `events/subscribe` framing: one `event` frame
        // carrying the projection-event JSON, a `catchup_complete`, a heartbeat.
        let ndjson = format!(
            "{}\n{}\n{}\n",
            json!({
                "kind": "event",
                "seq": 1,
                "cursor": "ak:cursor:realmframe1",
                "payload": {
                    "event_id": "ak:event:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz",
                    "event_kind": "ak.space.create",
                    "realm_id": realm_id,
                    "actor_id": "did:web:bob.example",
                    "created_at": "2026-06-29T00:00:00.000Z",
                    "operation_id": "sha256:remote-board-create",
                    "payload": {
                        "object": {
                            "id": board_id,
                            "schema": "ak.schema.space.v1",
                            "realm_id": realm_id,
                            "kind": "board",
                            "title": "Cross-member board"
                        }
                    }
                }
            }),
            json!({ "kind": "catchup_complete", "cursor": "ak:cursor:realmframe1" }),
            json!({ "kind": "heartbeat", "ts": "2026-06-29T00:00:01.000Z" }),
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

        let event_payloads: Vec<Value> = frames
            .iter()
            .filter(|frame| frame.kind == EventsSubscribeFrameKind::Event)
            .filter_map(|frame| frame.payload.as_ref())
            .map(|payload| serde_json::to_value(payload).expect("frame payload serializes"))
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
        let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
        let mut store = temp_store("membership-events");
        let changed = ingest_membership_projection_events(
            &mut store,
            realm_id,
            &[
                json!({
                    "event_id": "ak:event:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg",
                    "event_kind": "ak.member.state",
                    "realm_id": realm_id,
                    "actor_id": "did:web:alice.example",
                    "created_at": "2026-06-29T00:00:00.000Z",
                    "payload": {
                        "actor_id": "did:web:bob.example",
                        "membership": "join"
                    }
                }),
                json!({
                    "event_id": "ak:event:AUiTFJVo328Rc7lc2Le2mjzL_ELZ-uQUn1Fq-C1QNAbh",
                    "kind": "ak.invite.accept",
                    "realm_id": realm_id,
                    "actor_id": "did:web:carol.example",
                    "created_at": "2026-06-29T00:00:01.000Z",
                    "payload": {
                        "invite_ref": "ak:invite:0196419b-0000-7000-8000-000000000301"
                    }
                }),
                json!({
                    "event_id": "ak:event:AVKDZWS92w01isZDuPKuX-DiJymAf0Qcvf0A6qz8Gy-0",
                    "kind": "ak.mls.commit",
                    "realm_id": realm_id,
                    "payload": {}
                }),
                json!({
                    "kind": "ak.member.state",
                    "realm_id": realm_id,
                    "actor_id": "did:web:dave.example",
                    "created_at": "2026-06-29T00:00:02.000Z",
                    "payload": {
                        "actor_id": "did:web:dave.example",
                        "membership": "join"
                    }
                }),
            ],
        );

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
            state.raw_operations[1].payload["body"]["invite_ref"],
            "ak:invite:0196419b-0000-7000-8000-000000000301"
        );
    }

    fn to_device_message(kind: &str) -> arkret_sdk::DeviceMessageEnvelope {
        serde_json::from_value(json!({
            "message_id": "ak:device_message:0196419b-0000-7000-8000-000000000003",
            "kind": kind,
            "sender_principal_id": "did:webvh:z6mkfixture:alice.example",
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_principal_id": "did:webvh:z6mkfixture:bob.example",
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-16T00:00:00.000Z",
            "content": {
                "transaction_id": "txn-1",
                "request_id": "request-1"
            }
        }))
        .unwrap()
    }

    #[test]
    fn durable_to_device_batches_do_not_block_account_cursor() {
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.key.verification.request")],
            false,
        ));
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.key.verification.request")],
            true,
        ));
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.mls.welcome")],
            false,
        ));
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.future.secret.material")],
            false,
        ));
    }

    #[test]
    fn mls_welcome_requires_consumer_ack_after_group_state_is_durable() {
        assert!(!to_device_batch_safe_for_ingest_ack(&[to_device_message(
            "ak.mls.welcome"
        )]));
        assert!(!to_device_batch_safe_for_ingest_ack(&[
            to_device_message("ak.key.verification.request"),
            to_device_message("ak.mls.welcome"),
        ]));
        assert!(to_device_batch_safe_for_ingest_ack(&[to_device_message(
            "ak.key.verification.request"
        )]));
    }

    #[test]
    fn sync_state_events_ingest_kanban_strand_updates_as_synced_raw_operations() {
        let temp = std::env::temp_dir().join(format!(
            "inkson-sync-state-events-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(temp);
        let body = json!({
            "state": { "events": [{
                    "event_id": "ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t",
                    "operation_id": "ak:operation:01904100-0000-7000-8000-0000000000a1",
                    "event_kind": "ak.strand.update",
                    "actor_id": "did:web:bob.example",
                    "created_at": "2026-06-24T10:00:00.000Z",
                    "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "payload": {
                        "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                        "patch": {
                            "synthesis": {"$op": "set", "value": "bob synthesis"}
                        }
                    }
                }] }
        });

        let changed = ingest_kanban_state_events_from_projection(
            &mut store,
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            &body,
        );

        assert_eq!(changed, 1);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 1);
        assert_eq!(
            state.raw_operations[0].payload["actor_id"],
            "did:web:bob.example"
        );
        assert_eq!(state.raw_operations[0].payload["write_state"], "synced");
        assert_eq!(
            state.raw_operations[0].payload["body"]["patch"]["synthesis"]["value"],
            "bob synthesis"
        );
    }

    #[test]
    fn sync_state_events_ingest_discussion_pin_controls_as_raw_operations() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let strand_id = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let mut store = temp_store("discussion-pin-state-events");
        let body = json!({
            "state": { "events": [{
                    "event_id": "ak:event:AZaaHAEvC1DejakImwHCcJHb0F1pgE-Jd-3_9BGirbuW",
                    "event_kind": "ak.pin.add",
                    "actor_id": "did:web:mei.example",
                    "created_at": "2026-06-24T10:00:00.000Z",
                    "realm_id": realm_id,
                    "payload": {
                        "pin_scope": {"kind": "strand", "id": strand_id},
                        "target_ref": "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                        "rank": "r001"
                    }
                }] }
        });

        let changed = ingest_discussion_state_events_from_projection(&mut store, realm_id, &body);

        assert_eq!(changed, 1);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 1);
        assert_eq!(
            state.raw_operations[0].operation_id,
            "ak:event:AZaaHAEvC1DejakImwHCcJHb0F1pgE-Jd-3_9BGirbuW"
        );
        assert_eq!(state.raw_operations[0].payload["event_kind"], "ak.pin.add");
        assert_eq!(
            state.raw_operations[0].payload["payload"]["pin_scope"]["id"],
            strand_id
        );
    }

    #[test]
    fn sync_state_events_ingest_message_lifecycle_rows_for_discussion_raw_operations() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let strand_id = "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let mut store = temp_store("discussion-message-state-events");
        let body = json!({
            "state": { "events": [
                    {
                        "event_id": "ak:event:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN",
                        "event_kind": "ak.message.revise",
                        "actor_id": "did:web:bob.example",
                        "created_at": "2026-06-24T10:00:00.000Z",
                        "realm_id": realm_id,
                        "payload": {
                            "event_id": "ak:event:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN",
                            "target_ref": "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                            "strand_id": strand_id,
                            "content": {
                                "kind": "ak.content.text",
                                "body": "edited state projection"
                            }
                        }
                    },
                    {
                        "event_id": "ak:event:Adpb76fsaup_4Y_cV39of-L1_k6Nv1kSoCzXa9TM4szu",
                        "event_kind": "ak.message.redact",
                        "actor_id": "did:web:bob.example",
                        "created_at": "2026-06-24T10:01:00.000Z",
                        "realm_id": realm_id,
                        "payload": {
                            "event_id": "ak:event:Adpb76fsaup_4Y_cV39of-L1_k6Nv1kSoCzXa9TM4szu",
                            "message_id": "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                            "reason": "user requested tombstone"
                        }
                    },
                    {
                        "event_id": "ak:event:AR9d8WoyQJCOjt6n46diPUzg9zsrG9OZ9TAgE1rz6tJa",
                        "event_kind": "ak.reaction.add",
                        "actor_id": "did:web:carol.example",
                        "created_at": "2026-06-24T10:02:00.000Z",
                        "realm_id": realm_id,
                        "payload": {
                            "target_ref": "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                            "key": "👍"
                        }
                    }
                ] }
        });

        let changed = ingest_discussion_state_events_from_projection(&mut store, realm_id, &body);

        assert_eq!(changed, 3);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 3);
        assert_eq!(
            state.raw_operations[0].payload["event_kind"],
            "ak.message.revise"
        );
        assert_eq!(
            state.raw_operations[1].payload["event_kind"],
            "ak.message.redact"
        );
        assert_eq!(
            state.raw_operations[2].payload["event_kind"],
            "ak.reaction.add"
        );
    }

    #[test]
    fn persistent_proof_sender_device_collection_dedupes_nested_events() {
        let mut response = empty_response("cursor-1");
        response.realm_projections.insert(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            json!({
                "timeline": {
                    "events": [
                        {
                            "event": {
                                "actor_id": "did:web:alice.example",
                                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                                "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                            }
                        },
                        {
                            "actor_id": "did:web:alice.example",
                            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                            "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                        },
                        {
                            "actor_id": "did:web:bob.example",
                            "proofs": [{"verification_method": "did:web:bob.example#device"}]
                        },
                        {
                            "actor_id": "did:web:carol.example",
                            "proofs": [{"verification_method": "did:web:carol.example#ak:device:01904100-0000-7000-8000-000000000002"}]
                        }
                    ]
                }
            }),
        );
        assert_eq!(
            collect_persistent_proof_sender_devices(&response, &|_: &str| false),
            vec![
                (
                    "did:web:alice.example".to_owned(),
                    "ak:device:01904100-0000-7000-8000-000000000001".to_owned()
                ),
                (
                    "did:web:carol.example".to_owned(),
                    "ak:device:01904100-0000-7000-8000-000000000002".to_owned()
                )
            ]
        );
    }

    #[test]
    fn delegated_event_prefetches_executing_principals_device_key() {
        let controller = "did:web:bob.example";
        let agent = "did:web:bob.example:agent:assistant";
        let device = "ak:device:01904100-0000-7000-8000-0000000000aa";
        let mut response = empty_response("cursor-agent");
        response.realm_projections.insert(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            json!({
                "timeline": {
                    "events": [{
                        "actor_id": controller,
                        "executed_by": agent,
                        "device_id": device,
                        "proofs": [{
                            "verification_method": format!("{agent}#{device}")
                        }]
                    }]
                }
            }),
        );

        assert_eq!(
            collect_persistent_proof_sender_devices(&response, &|_: &str| false),
            vec![(agent.to_owned(), device.to_owned())]
        );
    }

    #[test]
    fn notification_projection_merges_pending_invites_from_authz() {
        let mut store = temp_store("invite-notifications");
        let existing = crate::state::projection::notifications::test_event_notification(
            1,
            arkret_sdk::NotificationKind::Message,
            "ak:realm:AZiQUXWgexBvj0pdmSuNERtMTAFCjqds5-eP8K9OsgEo",
            None,
            json!({}),
        );
        let existing_id = existing.notification_id();
        store.save_notification_projection(vec![existing]);
        let response = empty_response("sx:invite");

        apply_notification_projection(
            &mut store,
            &response,
            "",
            false,
            Some(vec![crate::state::projection::notifications::test_invite(
                0x10,
                "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
                None,
                None,
            )]),
        );

        let projection = store.notification_projection();
        assert!(
            projection
                .iter()
                .any(|entry| entry.notification_id() == existing_id)
        );
        // The invite notification is keyed on the unique invite id, not the
        // realm id, so a re-invite to the same realm cannot inherit stale
        // archive/read client-state from an earlier invite.
        assert!(projection.iter().any(|entry| {
            entry.notification_id() == "invite:ak:invite:0196419b-0000-7000-8000-000000000010"
        }));
    }

    #[test]
    fn notification_projection_filters_invites_by_typed_membership() {
        let mut store = temp_store("invite-membership-projection");
        let actor_id = "did:webvh:z6mkfixture:bob.example";
        let realm_id = "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
        let invite =
            || crate::state::projection::notifications::test_invite(0x10, realm_id, None, None);
        let response = |membership: &str| {
            let mut response = empty_response("sx:invite-membership");
            let realm_id = arkret_sdk::RealmId::new(realm_id).unwrap();
            let entry = serde_json::from_value::<arkret_sdk::RealmSyncEntry>(json!({
                "members": [{
                    "actor_id": actor_id,
                    "membership": membership
                }]
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

        apply_notification_projection(
            &mut store,
            &response("invite"),
            actor_id,
            false,
            Some(vec![invite()]),
        );
        assert!(
            store
                .notification_projection()
                .iter()
                .any(|entry| entry.invite().is_some()),
            "an invite membership projection must preserve the pending invite"
        );

        apply_notification_projection(
            &mut store,
            &response("join"),
            actor_id,
            false,
            Some(vec![invite()]),
        );
        assert!(
            store
                .notification_projection()
                .iter()
                .all(|entry| entry.invite().is_none()),
            "a joined membership projection must drop the stale invite"
        );
    }

    #[test]
    fn full_sync_response_prunes_cached_projection() {
        // Bench against the store directly — we don't need the dioxus
        // signals to verify the reconcile semantics. The signal-side
        // wiring is exercised by the lib's integration tests; the unit
        // contract here is "after a full sync, server-reported ids
        // remain, plus nested Space containers under still-joined
        // Realms".
        let mut store = temp_store("prune");
        store.save_realm_tree_projection("ak:realm:a", json!({"summary": {"title": "A"}}));
        store.save_realm_tree_projection(
            "ak:space:child",
            json!({
                "__kind": "space",
                "realm_id": "ak:realm:a",
                "summary": {"title": "Child"}
            }),
        );
        store.save_realm_tree_projection("ak:space:b", json!({"summary": {"title": "B"}}));

        let mut response = empty_response("sx:42");
        response
            .realm_projections
            .insert("ak:realm:a".to_owned(), json!({"summary": {"title": "A"}}));

        // Mirror the engine's full-sync prune step.
        let server_set: BTreeSet<String> = response.realm_projections.keys().cloned().collect();
        let keep_set = crate::app::full_sync_projection_keep_set(
            &server_set,
            &store.load().realm_tree_projections,
        );
        let pruned = store.retain_realm_tree_projections(|id| keep_set.contains(id));
        assert_eq!(pruned, vec!["ak:space:b".to_owned()]);

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ak:realm:a"));
        assert!(state.realm_tree_projections.contains_key("ak:space:child"));
        assert!(!state.realm_tree_projections.contains_key("ak:space:b"));
    }

    // ── Y2 invalidation hook ──────────────────────────────────────────

    use arkret_sdk::identity::DidResolutionCache;
    use arkret_sdk::{Did, DidDocument};

    fn seed_cache(did_str: &str) -> (DidResolutionCache, Did) {
        let cache = DidResolutionCache::new(8);
        let did = Did::new(did_str.to_owned()).expect("valid did");
        let doc = DidDocument::new(did.clone(), "key-1", "z6Mksample");
        cache
            .insert(
                did.clone(),
                // `did:web` publishes no method proof.
                arkret_sdk::identity::ResolvedDid::proofless(doc),
                chrono::Utc::now(),
                chrono::Duration::seconds(600),
            )
            .unwrap();
        (cache, did)
    }

    #[test]
    fn cross_signing_reset_event_invalidates_actor_in_inline_member_events() {
        let (mut cache, did) = seed_cache("did:web:alice.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:alice.example",
                "identity_events": [
                    { "event_id": "e1", "kind": "ak.cross_signing.reset" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_none(),
            "reset event must drop the cached actor entry"
        );
    }

    #[test]
    fn device_revoke_event_in_state_events_invalidates_actor() {
        // state.events[] use canonical `actor_id`; forbidden
        // `actor` / `sender` fields are ignored by the scanner.
        let (mut cache, did) = seed_cache("did:web:bob.example");
        let body = json!({
            "state": { "events": [
                { "event_id": "e9", "kind": "ak.device.revoke", "actor_id": "did:web:bob.example" }
            ] }
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(cache.get(&did, chrono::Utc::now()).is_none());
    }

    /// `signal.md` §1: the device-signing-key cache must not outlive an
    /// observed frontier change, so the subject is taken from the payload's
    /// `principal_id` — the authoring actor may be another device of the same
    /// principal, or the server-side reducer.
    #[test]
    fn device_frontier_actors_prefer_the_payload_principal() {
        let body = json!({
            "state": { "events": [
                {
                    "event_id": "e1",
                    "kind": "ak.device.revoke",
                    "actor_id": "did:web:author.example",
                    "payload": { "principal_id": "did:web:subject.example" }
                },
                { "event_id": "e2", "kind": "ak.device.list_update", "actor_id": "did:web:bob.example" },
                { "event_id": "e3", "kind": "ak.message.create", "actor_id": "did:web:carol.example" }
            ] },
            "members": [{
                "actor_id": "did:web:dave.example",
                "identity_events": [{ "event_id": "e4", "kind": "ak.cross_signing.publish" }]
            }]
        });

        let actors = collect_device_frontier_actors(&body);
        assert_eq!(
            actors.into_iter().collect::<Vec<_>>(),
            vec![
                "did:web:bob.example".to_owned(),
                "did:web:dave.example".to_owned(),
                "did:web:subject.example".to_owned(),
            ]
        );
    }

    #[test]
    fn accepted_device_revoke_targets_current_local_device() {
        let actor = "did:web:alice.example";
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let mut response = empty_response("ak:cursor:device-revoke");
        response.realm_projections.insert(
            "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            json!({
                "state": { "events": [{
                    "event_id": "ak:event:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
                    "kind": "ak.device.revoke",
                    "payload": {
                        "principal_id": actor,
                        "device_id": device,
                        "revoked_by": "ak:device:0196419b-0000-7000-8000-000000000004",
                        "revoked_at": "2026-07-14T02:00:00.000Z",
                        "reason": "device_loss"
                    }
                }]}
            }),
        );

        assert!(response_revokes_local_device(&response, actor, device));
        assert!(!response_revokes_local_device(
            &response,
            actor,
            "ak:device:0196419b-0000-7000-8000-0000000000ff"
        ));
        assert!(!response_revokes_local_device(
            &response,
            "did:web:mallory.example",
            device
        ));
    }

    #[test]
    fn malformed_or_non_state_device_revoke_does_not_trigger_local_wipe() {
        let actor = "did:web:alice.example";
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let mut response = empty_response("ak:cursor:malformed-device-revoke");
        response.realm_projections.insert(
            "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            json!({
                "state": { "events": [{
                    "kind": "ak.device.revoke",
                    "principal_id": actor,
                    "device_id": device
                }]},
                "timeline": { "events": [{
                    "kind": "ak.device.revoke",
                    "payload": { "principal_id": actor, "device_id": device }
                }]}
            }),
        );

        assert!(!response_revokes_local_device(&response, actor, device));
    }

    #[test]
    fn device_revoke_event_with_removed_actor_key_is_ignored() {
        // Negative case: revoke events carrying only forbidden `actor` /
        // `sender` keys must not drive cache invalidation.
        let (mut cache, did) = seed_cache("did:web:dave.example");
        let body = json!({
            "state": { "events": [
                { "event_id": "e10", "kind": "ak.device.revoke", "actor": "did:web:dave.example" },
                { "event_id": "e11", "kind": "ak.device.revoke", "sender": "did:web:dave.example" }
            ] }
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_some(),
            "forbidden actor/sender keys must not drive cache invalidation"
        );
    }

    #[test]
    fn non_revocation_events_do_not_invalidate() {
        // Ordinary identity update events must not clear the cache.
        let (mut cache, did) = seed_cache("did:web:carol.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:carol.example",
                "identity_events": [
                    { "event_id": "e2", "kind": "ak.member.identity.update" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_some(),
            "unrelated event must leave the cache intact"
        );
    }

    #[test]
    fn revocation_for_other_actor_leaves_unrelated_entry() {
        // Alice is cached, but the revocation targets Mallory, so Alice should
        // not be affected.
        let (mut cache, alice) = seed_cache("did:web:alice.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:mallory.example",
                "identity_events": [
                    { "event_id": "e3", "kind": "ak.device.revoke" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(cache.get(&alice, chrono::Utc::now()).is_some());
    }
}
