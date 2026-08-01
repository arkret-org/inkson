use super::*;

/// Owns the account and selected-Realm synchronization loops for the mounted
/// session shell. Each loop is generation-scoped and self-terminates when its
/// account or route inputs become stale.
#[component]
pub(super) fn SyncEffects(
    sync_generation: Signal<u64>,
    mut sync_engine_active_generation: Signal<Option<u64>>,
    mut realm_events_engine_active_key: Signal<Option<String>>,
    mut signal_receive_engine_active_generation: Signal<Option<u64>>,
    mut websocket_rail_active_generation: Signal<Option<u64>>,
    sync_bootstrap_complete: Signal<bool>,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    selected_realm_id: Signal<String>,
    realm_events_route_enabled: Signal<bool>,
    realm_live_epoch: Signal<u64>,
    profiles: Signal<crate::config::MultiProfileConfig>,
) -> Element {
    let SessionContext {
        state_store,
        base_url,
        ..
    } = SessionContext::get();
    let runtime_services = use_context::<crate::runtime::services::RuntimeServices>();
    let did_cache = use_context::<Signal<arkret_sdk::identity::DidResolutionCache>>();

    let sync_effects = runtime_services.effects.clone();
    let sync_session = runtime_services.session.clone();
    let sync_projection_sink = runtime_services.projection_sink.clone();
    let sync_client_runtime = runtime_services.client.clone();
    let sync_websocket_rail = runtime_services.websocket_rail.clone();
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete() {
            return;
        }
        if *sync_engine_active_generation.peek() == Some(current_gen) {
            return;
        }
        sync_engine_active_generation.set(Some(current_gen));
        let effect = sync_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(account_did()),
            name: "account-sync".to_owned(),
            generation: current_gen,
        });
        let completion_effects = sync_effects.clone();
        let ctx = crate::sync_engine::SyncEngineContext {
            base_url: base,
            token: runtime_adapter::value_reader(token),
            state_store: runtime_adapter::state_store_handle(state_store),
            account_did: account_did(),
            device_id: device_id(),
            live_device_id: runtime_adapter::value_cell(device_id),
            selected_realm_id: runtime_adapter::value_reader(selected_realm_id),
            websocket_rail: sync_websocket_rail.clone(),
            realm_live_epoch: runtime_adapter::value_cell(realm_live_epoch),
            did_cache: runtime_adapter::value_cell(did_cache),
            session: sync_session.clone(),
            client_runtime: sync_client_runtime.clone(),
            effect: effect.clone(),
            projection_sink: sync_projection_sink.clone(),
        };
        let mut active_generation = sync_engine_active_generation;
        spawn(async move {
            crate::sync_engine::run_sync_engine(
                current_gen,
                runtime_adapter::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if *active_generation.peek() == Some(current_gen) {
                active_generation.set(None);
            }
        });
    });

    // The encrypted Signal receive rail. It is account-scoped like the account
    // engine (the operation takes no selector at all), so it shares the same
    // generation axis and is spawned exactly once per generation. Only the
    // single-leader tab mounts this component, which is also what keeps one
    // browser session from holding two Signal consumers.
    let signal_effects = runtime_services.effects.clone();
    let signal_client_runtime = runtime_services.client.clone();
    let signal_product_sink = runtime_services.signal_product_sink.clone();
    let signal_websocket_rail = runtime_services.websocket_rail.clone();
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        let actor = account_did();
        let device = device_id();
        if base.trim().is_empty()
            || session.trim().is_empty()
            || actor.trim().is_empty()
            || device.trim().is_empty()
            || !sync_bootstrap_complete()
        {
            return;
        }
        if *signal_receive_engine_active_generation.peek() == Some(current_gen) {
            return;
        }
        signal_receive_engine_active_generation.set(Some(current_gen));
        let effect = signal_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(actor.clone()),
            name: "signal-receive".to_owned(),
            generation: current_gen,
        });
        let completion_effects = signal_effects.clone();
        let ctx = crate::signal_receive_engine::SignalReceiveEngineContext {
            base_url: runtime_adapter::value_reader(base_url),
            token: runtime_adapter::value_reader(token),
            state_store: runtime_adapter::state_store_handle(state_store),
            account_did: actor,
            device_id: device,
            profiles: runtime_adapter::value_reader(profiles),
            client_runtime: signal_client_runtime.clone(),
            effect: effect.clone(),
            products: signal_product_sink.clone(),
            websocket_rail: signal_websocket_rail.clone(),
        };
        let mut active_generation = signal_receive_engine_active_generation;
        spawn(async move {
            crate::signal_receive_engine::run_signal_receive_engine(
                current_gen,
                runtime_adapter::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if *active_generation.peek() == Some(current_gen) {
                active_generation.set(None);
            }
        });
    });

    // The optional WebSocket rail. It is generation-scoped like the three
    // stream engines and, unlike them, may simply end: a service that does not
    // advertise `ak.profile.binding.websocket.v1` leaves every stream on the
    // mandatory HTTP binding, which is §2's default rather than a failure.
    let rail_effects = runtime_services.effects.clone();
    let rail_service = runtime_services.websocket_rail.clone();
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete() {
            return;
        }
        if *websocket_rail_active_generation.peek() == Some(current_gen) {
            return;
        }
        websocket_rail_active_generation.set(Some(current_gen));
        let effect = rail_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(account_did()),
            name: "websocket-rail".to_owned(),
            generation: current_gen,
        });
        let completion_effects = rail_effects.clone();
        let ctx = crate::websocket_rail_engine::WebSocketRailContext {
            base_url: runtime_adapter::value_reader(base_url),
            token: runtime_adapter::value_reader(token),
            profiles: runtime_adapter::value_reader(profiles),
            state_store: runtime_adapter::state_store_handle(state_store),
            effect: effect.clone(),
            rail: rail_service.clone(),
        };
        let mut active_generation = websocket_rail_active_generation;
        spawn(async move {
            crate::websocket_rail_engine::run_websocket_rail_engine(
                current_gen,
                runtime_adapter::value_reader(sync_generation),
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if *active_generation.peek() == Some(current_gen) {
                active_generation.set(None);
            }
        });
    });

    let realm_effects = runtime_services.effects.clone();
    let client_runtime = runtime_services.client.clone();
    let realm_websocket_rail = runtime_services.websocket_rail.clone();
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        let realm_id = selected_realm_id();
        let route_enabled = realm_events_route_enabled();
        if base.trim().is_empty()
            || session.trim().is_empty()
            || realm_id.trim().is_empty()
            || !route_enabled
            || !sync_bootstrap_complete()
        {
            return;
        }
        let active_key = format!("{current_gen}|{realm_id}");
        if realm_events_engine_active_key.peek().as_deref() == Some(active_key.as_str()) {
            return;
        }
        realm_events_engine_active_key.set(Some(active_key.clone()));
        let effect = realm_effects.register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Realm {
                account: account_did(),
                realm: realm_id.clone(),
            },
            name: "realm-events".to_owned(),
            generation: current_gen,
        });
        let completion_effects = realm_effects.clone();
        let ctx = crate::realm_events_engine::RealmEventsEngineContext {
            base_url: runtime_adapter::value_reader(base_url),
            token: runtime_adapter::value_cell(token),
            state_store: runtime_adapter::state_store_handle(state_store),
            selected_realm_id: runtime_adapter::value_reader(selected_realm_id),
            route_enabled: runtime_adapter::value_reader(realm_events_route_enabled),
            websocket_rail: realm_websocket_rail.clone(),
            realm_live_epoch: runtime_adapter::value_cell(realm_live_epoch),
            profiles: runtime_adapter::value_reader(profiles),
            client_runtime: client_runtime.clone(),
            effect: effect.clone(),
        };
        let mut active_key_signal = realm_events_engine_active_key;
        spawn(async move {
            crate::realm_events_engine::run_realm_events_engine(
                current_gen,
                runtime_adapter::value_reader(sync_generation),
                realm_id,
                ctx,
            )
            .await;
            completion_effects.complete(&effect);
            if active_key_signal.peek().as_deref() == Some(active_key.as_str()) {
                active_key_signal.set(None);
            }
        });
    });

    rsx! {}
}
