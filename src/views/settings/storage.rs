//! Protected E2EE cache occupancy, browser quota, and explicit cleanup controls.

use dioxus::prelude::*;

use crate::state::{BrowserStorageEstimate, E2eePlaintextCacheClearScope, E2eePlaintextCacheUsage};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::helpers::short_protocol_id;

async fn retain_current_history_secrets_before_clear(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    scope: &E2eePlaintextCacheClearScope,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<usize> {
    let realms: Vec<String> = {
        let store = state_store.read();
        let usage = store.e2ee_plaintext_cache_usage();
        match scope {
            E2eePlaintextCacheClearScope::All => usage.realms.into_keys().collect(),
            E2eePlaintextCacheClearScope::Realm(realm_id) => usage
                .realms
                .contains_key(realm_id)
                .then(|| realm_id.clone())
                .into_iter()
                .collect(),
        }
    };

    let mut retained = 0;
    for realm_id in realms {
        let derived = {
            let store = state_store.read();
            if !crate::mls::runtime::realm_content_scheme_is_exporter_aead(&store, &realm_id) {
                continue;
            }
            crate::mls::runtime::derive_and_retain_realm_history_secret(
                &store,
                secure_store,
                &realm_id,
                authority,
                actor_id,
                device_id,
            )
        }
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
        let Some((_epoch, _secret, pending)) = derived else {
            continue;
        };
        pending.persist(secure_store).await?;
        state_store.write().publish_history_secrets(pending);
        retained += 1;
    }
    Ok(retained)
}

fn format_storage_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn browser_storage_summary(estimate: BrowserStorageEstimate) -> String {
    let percent = estimate
        .usage_ratio()
        .map(|ratio| format!(" ({:.0}%)", ratio * 100.0))
        .unwrap_or_default();
    format!(
        "{} of {}{}",
        format_storage_bytes(estimate.usage_bytes),
        format_storage_bytes(estimate.quota_bytes),
        percent
    )
}

async fn refresh_browser_storage_quota(
    mut quota: Signal<Option<BrowserStorageEstimate>>,
    mut status: Signal<String>,
) {
    quota.set(None);
    status.set("Checking browser quota…".to_owned());
    match crate::state::browser_storage_estimate().await {
        Ok(Some(estimate)) => {
            quota.set(Some(estimate));
            status.set(String::new());
        }
        Ok(None) => status.set("Origin quota is reported by browsers only.".to_owned()),
        Err(error) => status.set(format!("Browser quota unavailable: {error}")),
    }
}

#[component]
pub(super) fn E2eeStorageManagement(principal_id: String, device_id: String) -> Element {
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut cache_usage = use_signal(|| state_store.read().e2ee_plaintext_cache_usage());
    let mut pending_clear = use_signal(|| None::<E2eePlaintextCacheClearScope>);
    let mut cache_status = use_signal(String::new);
    let browser_quota = use_signal(|| None::<BrowserStorageEstimate>);
    let browser_quota_status = use_signal(String::new);
    use_future(move || refresh_browser_storage_quota(browser_quota, browser_quota_status));

    let usage: E2eePlaintextCacheUsage = cache_usage();
    let quota = browser_quota();

    rsx! {
        div { class: "event", "data-testid": "browser-storage-quota",
            div { class: "event-head",
                span { "Browser origin quota" }
                if quota.is_some_and(|estimate| estimate.is_near_quota()) {
                    span {
                        class: "badge badge-warning",
                        "data-testid": "browser-storage-quota-warning",
                        "Low space"
                    }
                } else {
                    span { class: "badge badge-info", "Origin total" }
                }
            }
            if let Some(estimate) = quota {
                div { class: "metric",
                    strong { "Used / available" }
                    span { "{browser_storage_summary(estimate)}" }
                }
                if estimate.is_near_quota() {
                    div { class: "callout warn",
                        div { class: "body",
                            strong { "Browser storage is above 80% of its reported quota." }
                            div { "Review local data before the browser starts rejecting writes." }
                        }
                    }
                }
            } else {
                div { class: "muted", "{browser_quota_status}" }
            }
        }

        div { class: "event", "data-testid": "e2ee-plaintext-cache",
            div { class: "event-head",
                span { "Protected E2EE plaintext cache" }
                span { "Manual cleanup only" }
            }
            div { class: "metric-grid",
                div { class: "metric",
                    strong { "Protected plaintext" }
                    span { "{format_storage_bytes(usage.plaintext_bytes as u64)}" }
                }
                div { class: "metric",
                    strong { "Protected entries" }
                    span { "{usage.entry_count()} across {usage.realms.len()} Realms" }
                }
            }
            div { class: "callout warn",
                div { class: "body",
                    strong { "Automatic eviction is disabled." }
                    div {
                        "A cached plaintext may be the only locally renderable copy after the MLS ratchet advances. Clear it only if you accept that affected content may no longer open on this device. MLS receive state is retained."
                    }
                }
            }
            if usage.realms.is_empty() {
                div { class: "muted", "No protected plaintext is cached for this account." }
            } else {
                div { class: "metric-grid", "data-testid": "e2ee-cache-realm-usage",
                    for (realm_id, realm_usage) in &usage.realms {
                        {
                            let realm_id_for_clear = realm_id.clone();
                            let realm_label = short_protocol_id(realm_id);
                            rsx! {
                                div { class: "metric", key: "{realm_id}",
                                    strong { title: "{realm_id}", "{realm_label}" }
                                    span {
                                        "{format_storage_bytes(realm_usage.plaintext_bytes as u64)} · {realm_usage.entry_count()} entries ({realm_usage.authored_entries} authored, {realm_usage.received_entries} received)"
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            size: ButtonSize::Sm,
                                            "data-testid": "e2ee-cache-clear-realm",
                                            onclick: move |_| pending_clear.set(Some(
                                                E2eePlaintextCacheClearScope::Realm(
                                                    realm_id_for_clear.clone(),
                                                ),
                                            )),
                                            "Clear Realm cache"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    size: ButtonSize::Sm,
                    "data-testid": "e2ee-cache-refresh",
                    onclick: move |_| {
                        cache_usage.set(state_store.read().e2ee_plaintext_cache_usage());
                        spawn(refresh_browser_storage_quota(browser_quota, browser_quota_status));
                    },
                    "Refresh"
                }
                Button {
                    variant: ButtonVariant::Destructive,
                    size: ButtonSize::Sm,
                    "data-testid": "e2ee-cache-clear-all",
                    disabled: usage.entry_count() == 0,
                    onclick: move |_| pending_clear.set(Some(E2eePlaintextCacheClearScope::All)),
                    "Clear all protected plaintext"
                }
            }
            if !cache_status().is_empty() {
                div { class: "muted", role: "status", "{cache_status}" }
            }
        }

        if let Some(clear_scope) = pending_clear() {
            {
                let clear_scope_for_action = clear_scope.clone();
                let clear_target = match &clear_scope {
                    E2eePlaintextCacheClearScope::All => "all Realms".to_owned(),
                    E2eePlaintextCacheClearScope::Realm(realm_id) => {
                        format!("Realm {}", short_protocol_id(realm_id))
                    }
                };
                rsx! {
                    Dialog {
                        open: true,
                        on_open_change: move |open: bool| {
                            if !open {
                                pending_clear.set(None);
                            }
                        },
                        "data-testid": "e2ee-cache-clear-modal",
                        "aria-labelledby": "e2ee-cache-clear-title",
                        div { class: "modal event",
                            div { class: "modal-head event-head",
                                h3 {
                                    id: "e2ee-cache-clear-title",
                                    "Clear protected plaintext for {clear_target}?"
                                }
                                span { class: "badge red", "May be irreversible" }
                            }
                            div { class: "modal-body",
                                p {
                                    "Before cleanup, Inkson durably retains every current-epoch history key that this device can export. This then removes locally cached authored and received plaintext for {clear_target}. Older ratcheted content without a verifiable recovery source may still not open again on this device. MLS receive state and encrypted checkpoints are kept."
                                }
                            }
                            div { class: "modal-foot actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "e2ee-cache-clear-cancel",
                                    onclick: move |_| pending_clear.set(None),
                                    "Cancel"
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "e2ee-cache-clear-confirm",
                                    onclick: move |_| {
                                        let clear_scope = clear_scope_for_action.clone();
                                        let actor_id = principal_id.clone();
                                        let active_device_id = device_id.clone();
                                        spawn(async move {
                                            let secure_store =
                                                crate::secure_key_store::default_secure_key_store("inkson");
                                            let retained = retain_current_history_secrets_before_clear(
                                                state_store,
                                                secure_store.as_ref(),
                                                &clear_scope,
                                                &authority,
                                                &actor_id,
                                                &active_device_id,
                                            )
                                            .await;
                                            let result = match retained {
                                                Ok(retained) => {
                                                    let pending = state_store
                                                        .write()
                                                        .prepare_e2ee_plaintext_cache_clear(&clear_scope);
                                                    match pending {
                                                        Ok(Some(pending)) => {
                                                            if let Err(error) =
                                                                pending.persist(secure_store.as_ref()).await
                                                            {
                                                                state_store
                                                                    .write()
                                                                    .rollback_e2ee_plaintext_cache_clear(
                                                                        pending,
                                                                    );
                                                                Err(error)
                                                            } else {
                                                                Ok(Some(retained))
                                                            }
                                                        }
                                                        Ok(None) => Ok(None),
                                                        Err(error) => Err(error),
                                                    }
                                                }
                                                Err(error) => Err(error),
                                            };
                                            match result {
                                                Ok(Some(retained)) => cache_status.set(format!(
                                                    "Protected plaintext cleared. MLS receive state was retained; {retained} current-epoch history key(s) were durably retained first."
                                                )),
                                                Ok(None) => cache_status
                                                    .set("Nothing matched that cleanup scope.".to_owned()),
                                                Err(error) => cache_status.set(format!(
                                                    "Protected plaintext cleanup failed: {error}"
                                                )),
                                            }
                                            cache_usage.set(
                                                state_store.read().e2ee_plaintext_cache_usage(),
                                            );
                                            pending_clear.set(None);
                                        });
                                    },
                                    "Clear protected plaintext"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_bytes_use_binary_units() {
        assert_eq!(format_storage_bytes(999), "999 B");
        assert_eq!(format_storage_bytes(1536), "1.5 KiB");
        assert_eq!(format_storage_bytes(2 * 1024 * 1024), "2.0 MiB");
    }
}
