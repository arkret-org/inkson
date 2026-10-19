//! Local account selection over the existing, single root session authority.
use dioxus::core::{Task, spawn_forever};

use super::*;
use crate::config::{ActiveAccountContext, MultiProfileConfig};
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub use crate::state::{LocalStateStore, PersistedSessionGrant};

/// Stable handles survive account-view teardown. The revision is only a UI
/// mount key; authorization continues to use the existing session generation.
#[derive(Clone)]
pub struct AccountSessionRoot {
    pub(crate) config: Signal<LocalConfigStore>,
    pub(crate) base_url: Signal<String>,
    pub(crate) account: Signal<Option<ActiveAccountContext>>,
    pub(crate) principal: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(crate) device: Signal<String>,
    pub(crate) token: Signal<String>,
    pub(crate) generation: Signal<u64>,
    pub(crate) profiles: Signal<MultiProfileConfig>,
    revision: Signal<u64>,
    busy: Signal<bool>,
    view_retired: Signal<bool>,
    blocked: Signal<bool>,
    error: Signal<Option<String>>,
    store: SyncSignal<LocalStateStore>,
    services: crate::runtime::services::RuntimeServices,
}

fn root_signal<T: 'static>(value: T) -> Signal<T> {
    Signal::new_in_scope(value, ScopeId::ROOT)
}

/// Dioxus reconciles keys in fragments/lists. A key on a lone static
/// component is insufficient to retire its hook state. Replacing this keyed
/// parent destroys every account-local descendant while preserving the root.
#[component]
pub fn AccountViewBoundary(revision: u64, children: Element) -> Element {
    rsx! {
        for key in [revision] {
            div { key: "{key}", style: "display: contents", {children.clone()} }
        }
    }
}

/// The leader mounts this once, outside the account-specific bootstrap.
#[component]
pub fn SessionRoot(
    state_store: SyncSignal<LocalStateStore>,
    #[props(default)] config_store: Option<Signal<LocalConfigStore>>,
    children: Element,
) -> Element {
    let root = use_hook(|| {
        let config = config_store.unwrap_or_else(|| root_signal(LocalConfigStore::default()));
        let (initial, _, state) =
            read_bootstrap_snapshot(config.peek().clone(), state_store.peek().clone());
        let account = root_signal(initial.active_account.clone());
        let base_url = root_signal(
            initial
                .server_url()
                .or_else(|| initial.stations.first())
                .map(ToString::to_string)
                .unwrap_or_else(|| "https://local.host".into()),
        );
        let principal = root_signal(initial.principal_id().cloned());
        let device = root_signal(
            initial
                .device_id()
                .map(ToString::to_string)
                .unwrap_or_else(crate::config::new_device_id),
        );
        let token = root_signal(initial_session_credential_from_state(
            &state,
            &initial,
            chrono::Utc::now().timestamp(),
        ));
        let generation = root_signal(0_u64);
        let session = crate::runtime::session::SessionCoordinator::new(move || {
            Box::pin(refresh_session_credential_for_active_context(
                base_url,
                state_store,
                token,
                config,
                generation,
                account,
            ))
        });
        let adapter = crate::client_core::InksonLocalStateStoreAdapter::from_backend(
            runtime_adapter::SignalLocalStateBackend::new(state_store),
        );
        AccountSessionRoot {
            config,
            base_url,
            account,
            principal,
            device,
            token,
            generation,
            profiles: root_signal(MultiProfileConfig::default()),
            revision: root_signal(0_u64),
            busy: root_signal(false),
            view_retired: root_signal(false),
            blocked: root_signal(false),
            error: root_signal(None),
            store: state_store,
            services: crate::runtime::services::RuntimeServices::new(adapter, session),
        }
    });
    // Keep handles only: the initial decrypted account snapshot must be
    // released instead of living for the lifetime of all subsequent accounts.
    use_context_provider(|| root.services.clone());
    use_context_provider(|| root);
    rsx! { {children} }
}

impl AccountSessionRoot {
    pub fn get() -> Self {
        consume_context()
    }
    pub fn revision(&self) -> u64 {
        (self.revision)()
    }
    pub(crate) fn blocked(&self) -> bool {
        (self.blocked)()
    }
    pub fn active_account(&self) -> Option<ActiveAccountContext> {
        (self.account)()
    }

    pub fn is_switching(&self) -> bool {
        (self.busy)()
    }

    pub(crate) fn account_view_retired(&self) -> bool {
        (self.view_retired)()
    }

    /// The initiating menu can unmount while persistence is pending. Only
    /// root-owned handles may be captured by the completion callback.
    pub fn start_select_profile(
        self,
        id: String,
        done: impl FnOnce(anyhow::Result<()>) + 'static,
    ) -> Task {
        spawn_forever(async move { done(self.select_profile(id).await) })
    }

    pub fn start_add_account(self, done: impl FnOnce(anyhow::Result<()>) + 'static) -> Task {
        spawn_forever(async move { done(self.add_account().await) })
    }

    fn retire(&mut self) {
        self.services.session.suspend();
        self.services.session.clear_invalidator();
        self.services.effects.retire_all();
        self.services.websocket_rail.reset_for_account_switch();
        crate::identity::device_directory::reset_session_cache();
        crate::identity::contact_profile::reset_session_cache();
        self.services.projection_sink.install(std::rc::Rc::new(
            crate::runtime::projection::NoopProjectionSink,
        ));
        self.services.signal_product_sink.install(std::rc::Rc::new(
            crate::runtime::projection::NoopSignalProductSink,
        ));
        let next = (*self.generation.peek()).wrapping_add(1);
        self.generation.set(next);
        self.token.set(String::new());
        self.view_retired.set(true);
    }

    fn check_selection_coherence(&mut self) {
        let expected = self
            .account
            .peek()
            .as_ref()
            .map(|account| account.authority.clone());
        let actual = self.store.read().active_authority();
        let configured = self.config.read().selected_authority();
        self.blocked
            .set(actual != expected || configured != expected);
    }

    fn remount(&mut self) {
        crate::event_signer::clear_active_device_signer();
        match self.account.peek().as_ref() {
            Some(account) => match crate::secure_key_store::UserLocalStore::new(
                account.authority.clone(),
                account.device_id.clone(),
            ) {
                Ok(store) => store.activate(),
                Err(error) => {
                    tracing::error!(%error, "selected account key scope is invalid");
                    crate::secure_key_store::set_active_device_seed_scope(None);
                    self.blocked.set(true);
                }
            },
            None => crate::secure_key_store::set_active_device_seed_scope(None),
        }
        let next = (*self.revision.peek()).wrapping_add(1);
        self.revision.set(next);
        self.view_retired.set(false);
    }

    /// Select a saved, pinned account. No logout, grant issuance or revocation.
    pub async fn select_profile(mut self, profile_id: String) -> anyhow::Result<()> {
        anyhow::ensure!(
            !*self.busy.peek(),
            "an account switch is already in progress"
        );
        let mut profiles = self.config.read().load_profile_metadata()?;
        let selected = profiles
            .profiles
            .iter()
            .find(|profile| profile.account.profile_id == profile_id)
            .ok_or_else(|| anyhow::anyhow!("selected account is no longer saved"))?
            .account
            .clone();
        if self.account.peek().as_ref().is_some_and(|current| {
            current.authority == selected.authority
                && current.device_id == selected.device_id
                && current.server_url == selected.server_url
                && current.profile_id == selected.profile_id
        }) && !*self.blocked.peek()
            && self.store.read().active_authority() == Some(selected.authority.clone())
            && self.config.read().selected_authority() == Some(selected.authority.clone())
            && self.store.read().pending_login().is_none()
        {
            return Ok(());
        }
        self.busy.set(true);
        let expected = *self.generation.peek();
        let probe = self.store.read().clone();
        let prepared = probe.prepare_saved_account(&selected).await;
        if let Err(error) = prepared {
            self.busy.set(false);
            return Err(error);
        }
        if *self.generation.peek() != expected {
            self.busy.set(false);
            anyhow::bail!("session changed while preparing the selected account");
        }
        self.retire();
        let switching_generation = *self.generation.peek();
        let result = async {
            let barrier = self.store.read().begin_durable_flush()?;
            barrier.wait().await?;
            anyhow::ensure!(
                *self.generation.peek() == switching_generation,
                "session changed during account persistence"
            );
            crate::identity::account_auth::clear_all_persisted_oidc_scaffolds()?;
            profiles.activate(&profile_id);
            // Persist selection first. If activating the target store fails,
            // restore metadata before the old account can resume.
            let old_account = self.account.peek().clone();
            let old_profiles = self.config.read().load_profile_metadata()?;
            self.config
                .write()
                .save_account_selection(Some(selected.clone()), &profiles)?;
            if let Err(error) = self.store.write().switch_saved_account(&selected) {
                self.config
                    .write()
                    .save_account_selection(old_account, &old_profiles)?;
                return Err(error);
            }
            self.base_url.set(selected.server_url.to_string());
            self.principal.set(Some(selected.principal_id().clone()));
            self.device.set(selected.device_id.to_string());
            self.account.set(Some(selected));
            self.profiles.set(profiles);
            self.blocked.set(false);
            Ok(())
        }
        .await;
        self.busy.set(false);
        if *self.generation.peek() != switching_generation {
            self.retire();
            self.check_selection_coherence();
            self.remount();
            return result;
        }
        self.check_selection_coherence();
        // Both success and refusal rebuild account-local views; the root
        // identity and coordinator are retained and restore only their owner.
        self.remount();
        result
    }

    pub async fn add_account(mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !*self.busy.peek(),
            "an account switch is already in progress"
        );
        self.busy.set(true);
        self.retire();
        let switching_generation = *self.generation.peek();
        let result = async {
            let barrier = self.store.read().begin_durable_flush()?;
            barrier.wait().await?;
            anyhow::ensure!(
                *self.generation.peek() == switching_generation,
                "session changed during account persistence"
            );
            crate::identity::account_auth::clear_all_persisted_oidc_scaffolds()?;
            let profiles = self.config.read().load_profile_metadata()?;
            self.config
                .write()
                .save_account_selection(None, &profiles)?;
            let device = arkret_sdk::DeviceId::new(crate::config::new_device_id())?;
            if let Err(error) = self.store.write().begin_account_switch_login(&device) {
                let old_account = self.account.peek().clone();
                self.config
                    .write()
                    .save_account_selection(old_account, &profiles)?;
                return Err(error);
            }
            self.account.set(None);
            self.principal.set(None);
            self.device.set(device.to_string());
            Ok(())
        }
        .await;
        self.busy.set(false);
        if *self.generation.peek() != switching_generation {
            self.retire();
            self.check_selection_coherence();
            self.remount();
            return result;
        }
        self.check_selection_coherence();
        self.remount();
        result
    }
}

/// The real picker is also used on the login surface, so an unfinished new
/// sign-in never traps the user away from a previously saved account.
#[component]
pub fn SavedAccountPicker(
    options: Vec<(String, String)>,
    selected: String,
    busy: bool,
    on_select: EventHandler<String>,
    on_add: EventHandler<()>,
) -> Element {
    rsx! {
        div { class: "account-menu__actions", "data-testid": "account-switcher",
            label {
                {crate::i18n::tr("app.account.switch")}
                select {
                    "data-testid": "account-switch-select",
                    disabled: busy,
                    value: selected,
                    onchange: move |event| on_select.call(event.value()),
                    option { value: "", disabled: true, {crate::i18n::tr("app.account.choose")} }
                    for (id, label) in options {
                        option { key: "{id}", value: id,
                            "{label}"
                        }
                    }
                }
            }
            Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm,
                disabled: busy, "data-testid": "account-add", onclick: move |_| on_add.call(()),
                {crate::i18n::tr("app.account.add")}
            }
        }
    }
}

pub fn account_picker_options(profiles: &MultiProfileConfig) -> Vec<(String, String)> {
    profiles
        .profiles
        .iter()
        .map(|profile| {
            (
                profile.account.profile_id.clone(),
                format!(
                    "{} · {}",
                    profile.display_label(),
                    profile.account.server_url
                ),
            )
        })
        .collect()
}

#[component]
pub(super) fn AccountSwitcher() -> Element {
    let root = AccountSessionRoot::get();
    let mut error = root.error;
    let account = (root.account)();
    let _token = (root.token)();
    let profiles = root.config.read().load_profile_metadata();
    let navigator = use_navigator();
    match profiles {
        Err(_) => rsx! { p { role: "alert", {crate::i18n::tr("app.account.saved_unavailable")} } },
        Ok(profiles) => {
            let selecting = root.clone();
            let adding = root.clone();
            rsx! {
                SavedAccountPicker {
                    options: account_picker_options(&profiles),
                    selected: if root.blocked() { String::new() } else { account.map(|account| account.profile_id).unwrap_or_default() },
                    busy: (root.busy)(),
                    on_select: move |id| {
                        let selecting = selecting.clone();
                        selecting.start_select_profile(id, move |outcome| {
                            match outcome {
                                Ok(()) => { error.set(None); navigator.replace(Route::Dashboard); }
                                Err(failure) => { tracing::warn!(%failure, "account selection failed"); error.set(Some(crate::i18n::tr("app.account.switch_failed"))); }
                            }
                        });
                    },
                    on_add: move |_| {
                        let adding = adding.clone();
                        adding.start_add_account(move |outcome| {
                            match outcome {
                                Ok(()) => { error.set(None); navigator.push(Route::Login); }
                                Err(failure) => { tracing::warn!(%failure, "add-account preparation failed"); error.set(Some(crate::i18n::tr("app.account.switch_failed"))); }
                            }
                        });
                    },
                }
                if let Some(message) = (root.error)() { p { role: "alert", "{message}" } }
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Existing browser conformance hosts use the real encrypted account writer.
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub async fn prepare_browser_switch_storage(
    accounts: &[ActiveAccountContext],
) -> anyhow::Result<LocalStateStore> {
    let store = LocalStateStore::default();
    LocalStateStore::prepare_account_records(store.account_record_scopes_for_boot()).await?;
    for account in accounts {
        store.prepare_saved_account(account).await?;
    }
    Ok(store)
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub async fn commit_browser_switch_storage(store: &LocalStateStore) -> anyhow::Result<()> {
    store.begin_durable_flush()?.wait().await
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
impl AccountSessionRoot {
    pub fn conformance_session_generation(&self) -> u64 {
        self.services.session.generation()
    }
    pub fn conformance_invalidate_session(&self, generation: u64) -> bool {
        self.services
            .session
            .invalidate_if_generation(generation, "late conformance denial")
    }
}

/// Conformance fixtures commit/read the same scoped secret as accepted login.
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub async fn browser_switch_grant(
    account: &ActiveAccountContext,
    save: Option<&PersistedSessionGrant>,
) -> anyhow::Result<PersistedSessionGrant> {
    let keys = crate::secure_key_store::initialize_wasm_secure_key_store_async("inkson")
        .await?
        .ok_or_else(|| anyhow::anyhow!("secure store unavailable"))?;
    let user = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )?;
    if let Some(grant) = save {
        crate::state::store_session_grant_in_user_secure_store_durable(&user, keys.as_ref(), grant)
            .await?;
    }
    crate::identity::session_refresh::load_account_session_grant_with_secure_store(
        account,
        keys.as_ref(),
    )
}
