use super::*;

pub(super) fn use_circle_welcome(
    base_url: String,
    realm_id: String,
    circle_id: Option<String>,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    token: Signal<String>,
    sync_cursor: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
) {
    let backup = use_context::<crate::components::MlsBackupSignal>().0;
    let mut seen = use_signal(String::new);
    let mut generation = use_signal(|| 0_u64);
    use_effect(use_reactive!(|(
        base_url,
        realm_id,
        circle_id,
        authority,
        device_id,
    )| {
        let credential = token();
        let cursor = sync_cursor();
        let _active = state_store.read().active_authority();
        let keys =
            crate::app::local_mls_key_material_hint(&authority, &device_id).unwrap_or_default();
        let key = format!(
            "{realm_id}|{circle_id:?}|{authority:?}|{device_id}|{credential}|{cursor}|{keys}"
        );
        if *seen.peek() == key {
            return;
        }
        seen.set(key);
        let next_generation = generation.peek().wrapping_add(1);
        generation.set(next_generation);
        let Some(circle_id) = circle_id else {
            return;
        };
        if credential.is_empty()
            || state_store
                .peek()
                .mls_checkpoint_for_effective_scope(&realm_id, Some(&circle_id))
                .is_some()
        {
            return;
        }
        let (Ok(realm_id), Ok(circle_id)) = (
            arkret_sdk::RealmId::new(realm_id),
            arkret_sdk::CircleId::new(circle_id),
        ) else {
            return;
        };
        let scope = arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        };
        spawn(async move {
            let state = crate::app::runtime_adapter::state_store_handle(state_store);
            let work = crate::app::bootstrap_mls_welcome_for_scope(
                base_url,
                credential,
                authority.principal_id.to_string(),
                authority,
                device_id,
                scope,
                &state,
                Some(backup),
            );
            tokio::pin!(work);
            loop {
                tokio::select! {
                    result = &mut work => {
                        if let Err(error) = result {
                            tracing::debug!(%error, "selected Circle MLS Welcome remains pending");
                        }
                        break;
                    }
                    _ = crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(500)) => {
                        if *generation.peek() != next_generation { break; }
                    }
                }
            }
        });
    }));
}
