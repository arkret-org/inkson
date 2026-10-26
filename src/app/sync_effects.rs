//! Account-owned real synchronization loops.
use std::rc::Rc;

use glory::Scope;

use crate::presentation::InksonContext;

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
#[derive(Clone, PartialEq)]
struct RealmEngineDiagnostic {
    generation: u64,
    realm: String,
    base: bool,
    token: bool,
    enabled: bool,
    bootstrapped: bool,
    already_started: bool,
}

pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    let runtime_services = context.services.clone();
    let message_stream_hub = context.message_stream_hub;
    let sync_generation = context.sync_generation;
    let sync_bootstrap_complete = context.sync_bootstrap_complete;
    let token = context.token;
    let principal_id = context.principal_id;
    let device_id = context.device_id;
    let selected_realm_id = context.selected_realm_id;
    let realm_events_route_enabled = context.realm_events_route_enabled;
    let realm_live_epoch = context.realm_live_epoch;
    let profiles = context.profiles;
    let base_url = context.base_url;
    let active_account = context.active_account;
    let sync_engine_active_generation = scope.cage(None::<String>);
    let realm_events_engine_active_key = scope.cage(None::<String>);
    let signal_receive_engine_active_generation = scope.cage(None::<u64>);
    let websocket_rail_active_generation = scope.cage(None::<u64>);
    let sync_effects = runtime_services.effects.clone();
    let sync_session = runtime_services.session.clone();
    let sync_projection_sink = runtime_services.projection_sink.clone();
    let sync_client_runtime = runtime_services.client.clone();
    let sync_websocket_rail = runtime_services.websocket_rail.clone();
    let state_store = context.state_store.clone();
    let owner = scope.downgrade();
    scope.effect(move || {
        let Some(scope) = owner.upgrade() else { return };
        let current_gen = sync_generation.get();
        let selected_realm = selected_realm_id.get();
        let Some(account) = active_account.get() else {
            return;
        };
        let base = account.server_url.to_string();
        let session = token.get();
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete.get() {
            return;
        }
        let active_key = format!("{current_gen}|{selected_realm}");
        if sync_engine_active_generation.get_untracked().as_deref() == Some(active_key.as_str()) {
            return;
        }
        sync_engine_active_generation.revise(|current| *current = Some(active_key.clone()));
        let effect = sync_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(
                account.principal_id().to_string(),
            ),
            name: "account-sync".to_owned(),
            generation: current_gen,
        });
        let completion_effects = sync_effects.clone();
        let ctx = crate::sync_engine::SyncEngineContext {
            token: InksonContext::value_reader(token),
            state_store: state_store.handle(),
            account: account.clone(),
            principal_id: account.principal_id().clone(),
            device_id: device_id.get(),
            live_device_id: InksonContext::value_cell(device_id),
            selected_realm_id: InksonContext::value_reader(selected_realm_id),
            websocket_rail: sync_websocket_rail.clone(),
            realm_live_epoch: InksonContext::value_cell(realm_live_epoch),
            session: sync_session.clone(),
            client_runtime: sync_client_runtime.clone(),
            effect: effect.clone(),
            projection_sink: sync_projection_sink.clone(),
        };
        let active_generation = sync_engine_active_generation;
        if let Err(error) = scope.spawn(async move {
            crate::sync_engine::run_sync_engine(
                current_gen,
                InksonContext::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if active_generation.get_untracked().as_deref() == Some(active_key.as_str()) {
                active_generation.revise(|current| *current = None);
            }
        }) {
            scope.report_error(error);
        }
    });

    // The encrypted Signal receive rail. It is account-scoped like the account
    // engine (the operation takes no selector at all), so it shares the same
    // generation axis and is spawned exactly once per generation. Only the
    // single-leader tab mounts this component, which is also what keeps one
    // browser session from holding two Signal consumers.
    let signal_effects = runtime_services.effects.clone();
    let signal_product_sink = runtime_services.signal_product_sink.clone();
    let signal_websocket_rail = runtime_services.websocket_rail.clone();
    let state_store = context.state_store.clone();
    let owner = scope.downgrade();
    scope.effect(move || {
        let Some(scope) = owner.upgrade() else { return };
        let current_gen = sync_generation.get();
        let Some(account) = active_account.get() else {
            return;
        };
        let base = account.server_url.to_string();
        let session = token.get();
        let actor = account.principal_id().clone();
        let device = device_id.get();
        if base.trim().is_empty()
            || session.trim().is_empty()
            || actor.as_str().trim().is_empty()
            || device.trim().is_empty()
            || !sync_bootstrap_complete.get()
        {
            return;
        }
        if signal_receive_engine_active_generation.get_untracked() == Some(current_gen) {
            return;
        }
        signal_receive_engine_active_generation.revise(|current| *current = Some(current_gen));
        let effect = signal_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(
                account.principal_id().to_string(),
            ),
            name: "signal-receive".to_owned(),
            generation: current_gen,
        });
        let completion_effects = signal_effects.clone();
        let ctx = crate::signal_receive_engine::SignalReceiveEngineContext {
            websocket_rail: signal_websocket_rail.clone(),
            token: InksonContext::value_reader(token),
            state_store: state_store.handle(),
            account,
            profiles: InksonContext::value_reader(profiles),
            effect: effect.clone(),
            products: signal_product_sink.clone(),
        };
        let active_generation = signal_receive_engine_active_generation;
        if let Err(error) = scope.spawn(async move {
            crate::signal_receive_engine::run_signal_receive_engine(
                current_gen,
                InksonContext::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if active_generation.get_untracked() == Some(current_gen) {
                active_generation.revise(|current| *current = None);
            }
        }) {
            scope.report_error(error);
        }
    });

    // The optional WebSocket rail. It is generation-scoped like the three
    // stream engines and, unlike them, may simply end: a service that does not
    // advertise `ak.profile.binding.websocket.v1` leaves every stream on the
    // mandatory HTTP binding, which is §2's default rather than a failure.
    let rail_effects = runtime_services.effects.clone();
    let rail_service = runtime_services.websocket_rail.clone();
    let state_store = context.state_store.clone();
    let owner = scope.downgrade();
    scope.effect(move || {
        let Some(scope) = owner.upgrade() else { return };
        let current_gen = sync_generation.get();
        let base = base_url.get();
        let session = token.get();
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete.get() {
            return;
        }
        if websocket_rail_active_generation.get_untracked() == Some(current_gen) {
            return;
        }
        websocket_rail_active_generation.revise(|current| *current = Some(current_gen));
        let effect = rail_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(crate::app::principal_id_owned(
                principal_id.get(),
            )),
            name: "websocket-rail".to_owned(),
            generation: current_gen,
        });
        let completion_effects = rail_effects.clone();
        let ctx = crate::websocket_rail_engine::WebSocketRailContext {
            base_url: InksonContext::value_reader(base_url),
            token: InksonContext::value_reader(token),
            profiles: InksonContext::value_reader(profiles),
            state_store: state_store.handle(),
            effect: effect.clone(),
            rail: rail_service.clone(),
        };
        let active_generation = websocket_rail_active_generation;
        if let Err(error) = scope.spawn(async move {
            crate::websocket_rail_engine::run_websocket_rail_engine(
                current_gen,
                InksonContext::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if active_generation.get_untracked() == Some(current_gen) {
                active_generation.revise(|current| *current = None);
            }
        }) {
            scope.report_error(error);
        }
    });

    let realm_effects = runtime_services.effects.clone();
    let realm_websocket_rail = runtime_services.websocket_rail.clone();
    let state_store = context.state_store.clone();
    let owner = scope.downgrade();
    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
    let diagnostic = scope.cage(None::<RealmEngineDiagnostic>);
    scope.effect(move || {
        let Some(scope) = owner.upgrade() else { return };
        let current_gen = sync_generation.get();
        let base = base_url.get();
        let session = token.get();
        let realm_id = selected_realm_id.get();
        let route_enabled = realm_events_route_enabled.get();
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        {
            let next = RealmEngineDiagnostic {
                generation: current_gen,
                realm: realm_id.clone(),
                base: !base.trim().is_empty(),
                token: !session.trim().is_empty(),
                enabled: route_enabled,
                bootstrapped: sync_bootstrap_complete.get_untracked(),
                already_started: realm_events_engine_active_key.get_untracked().as_deref()
                    == Some(format!("{current_gen}|{realm_id}").as_str()),
            };
            if diagnostic.get_untracked().as_ref() != Some(&next) {
                tracing::warn!(
                    generation = current_gen,
                    selected_empty = realm_id.is_empty(),
                    selected_typed_valid = arkret_sdk::RealmId::new(realm_id.clone()).is_ok(),
                    base_present = next.base,
                    token_present = next.token,
                    route_enabled,
                    bootstrap_complete = next.bootstrapped,
                    already_started = next.already_started,
                    "Realm event engine startup dependencies changed"
                );
                diagnostic.revise(|value| *value = Some(next));
            }
        }
        if base.trim().is_empty()
            || session.trim().is_empty()
            || realm_id.trim().is_empty()
            || !route_enabled
            || !sync_bootstrap_complete.get()
        {
            return;
        }
        let active_key = format!("{current_gen}|{realm_id}");
        if realm_events_engine_active_key.get_untracked().as_deref() == Some(active_key.as_str()) {
            return;
        }
        realm_events_engine_active_key.revise(|current| *current = Some(active_key.clone()));
        let effect = realm_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Realm {
                account: crate::app::principal_id_owned(principal_id.get()),
                realm: realm_id.clone(),
            },
            name: "realm-events".to_owned(),
            generation: current_gen,
        });
        let completion_effects = realm_effects.clone();
        let ctx = crate::realm_events_engine::RealmEventsEngineContext {
            websocket_rail: realm_websocket_rail.clone(),
            base_url: InksonContext::value_reader(base_url),
            token: InksonContext::value_cell(token),
            state_store: state_store.handle(),
            selected_realm_id: InksonContext::value_reader(selected_realm_id),
            route_enabled: InksonContext::value_reader(realm_events_route_enabled),
            realm_live_epoch: InksonContext::value_cell(realm_live_epoch),
            message_stream_hub: Some(message_stream_hub),
            profiles: InksonContext::value_reader(profiles),
            effect: effect.clone(),
        };
        let active_key_signal = realm_events_engine_active_key;
        if let Err(error) = scope.spawn(async move {
            crate::realm_events_engine::run_realm_events_engine(
                current_gen,
                InksonContext::value_reader(sync_generation),
                realm_id,
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if active_key_signal.get_untracked().as_deref() == Some(active_key.as_str()) {
                active_key_signal.revise(|current| *current = None);
            }
        }) {
            scope.report_error(error);
        }
    });
}
