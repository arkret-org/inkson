//! Account selection retains its root authority while page owners retire.
use std::rc::Rc;

use glory::{Cage, Lotus, Scope};

use crate::config::{ActiveAccountContext, LocalConfigStore, MultiProfileConfig};
use crate::presentation::widgets::{empty, reactive, stack};
use crate::presentation::{InksonContext, SharedStateStore, View};
use crate::routes::Route;
#[cfg(any(test, all(target_arch = "wasm32", feature = "spec-conformance")))]
use crate::state::LocalStateStore;
#[cfg(all(test, not(feature = "spec-conformance")))]
use crate::state::PersistedSessionGrant;
// Name the grant type used by the public browser conformance storage helpers.
#[cfg(feature = "spec-conformance")]
#[doc(hidden)]
pub use crate::state::PersistedSessionGrant;

#[derive(Clone)]
pub struct AccountSessionRoot {
    context: Rc<InksonContext>,
    pub(crate) config: Cage<LocalConfigStore>,
    pub(crate) base_url: Cage<String>,
    pub(crate) account: Cage<Option<ActiveAccountContext>>,
    pub(crate) principal: Cage<Option<arkret_sdk::DidCoreId>>,
    pub(crate) device: Cage<String>,
    pub(crate) token: Cage<String>,
    pub(crate) generation: Cage<u64>,
    pub(crate) profiles: Cage<MultiProfileConfig>,
    revision: Cage<u64>,
    busy: Cage<bool>,
    view_retired: Cage<bool>,
    blocked: Cage<bool>,
    error: Cage<Option<String>>,
    store: SharedStateStore,
    services: crate::runtime::services::RuntimeServices,
}

impl AccountSessionRoot {
    pub fn from_context(context: Rc<InksonContext>) -> Self {
        Self {
            config: context.config_store,
            base_url: context.base_url,
            account: context.active_account,
            principal: context.principal_id,
            device: context.device_id,
            token: context.token,
            generation: context.session_generation,
            profiles: context.profiles,
            revision: context.account_revision,
            busy: context.account_busy,
            view_retired: context.account_view_retired,
            blocked: context.account_blocked,
            error: context.account_error,
            store: context.state_store.clone(),
            services: context.services.clone(),
            context,
        }
    }
}
impl AccountSessionRoot {
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    #[cfg(test)]
    pub(crate) fn blocked(&self) -> bool {
        self.blocked.get()
    }
    pub fn active_account(&self) -> Option<ActiveAccountContext> {
        self.account.get()
    }

    pub fn is_switching(&self) -> bool {
        self.busy.get()
    }

    #[cfg(test)]
    pub(crate) fn account_view_retired(&self) -> bool {
        self.view_retired.get()
    }

    /// The initiating menu can unmount while persistence is pending. Only
    /// root-owned handles may be captured by the completion callback.
    pub fn start_select_profile(
        self,
        id: String,
        done: impl FnOnce(anyhow::Result<()>) + 'static,
    ) -> Result<(), glory::core::AccessError> {
        let context = self.context.clone();
        context.spawn(async move { done(self.select_profile(id).await) })
    }

    pub fn start_add_account(
        self,
        done: impl FnOnce(anyhow::Result<()>) + 'static,
    ) -> Result<(), glory::core::AccessError> {
        let context = self.context.clone();
        context.spawn(async move { done(self.add_account().await) })
    }

    fn retire(&mut self) {
        self.services.session.suspend();
        self.services.session.clear_invalidator();
        self.services.effects.retire_all();
        self.services.websocket_rail.reset_for_account_switch();
        self.context.clear_account_projections();
        #[cfg(target_arch = "wasm32")]
        self.context
            .secure_store_bootstrap_ready
            .revise(|value| *value = false);
        crate::identity::device_directory::reset_session_cache();
        crate::identity::contact_profile::reset_session_cache();
        self.services.projection_sink.install(std::rc::Rc::new(
            crate::runtime::projection::NoopProjectionSink,
        ));
        self.services.signal_product_sink.install(std::rc::Rc::new(
            crate::runtime::projection::NoopSignalProductSink,
        ));
        let next = (self.generation.get_untracked()).wrapping_add(1);
        self.generation.revise(|current| *current = next);
        self.token.revise(|current| *current = String::new());
        self.view_retired.revise(|current| *current = true);
    }

    fn check_selection_coherence(&mut self) {
        let expected = self
            .account
            .get_untracked()
            .as_ref()
            .map(|account| account.authority.clone());
        let actual = self.store.read(|store| store.active_authority());
        let configured = self.config.with(|store| store.selected_authority());
        self.blocked
            .revise(|value| *value = actual != expected || configured != expected);
    }

    fn remount(&mut self) {
        crate::event_signer::clear_active_device_signer();
        match self.account.get_untracked().as_ref() {
            Some(account) => match crate::secure_key_store::UserLocalStore::new(
                account.authority.clone(),
                account.device_id.clone(),
            ) {
                Ok(store) => store.activate(),
                Err(error) => {
                    tracing::error!(%error, "selected account key scope is invalid");
                    crate::secure_key_store::set_active_device_seed_scope(None);
                    self.blocked.revise(|current| *current = true);
                }
            },
            None => crate::secure_key_store::set_active_device_seed_scope(None),
        }
        let next = (self.revision.get_untracked()).wrapping_add(1);
        self.revision.revise(|current| *current = next);
        self.view_retired.revise(|current| *current = false);
    }

    /// Select a saved, pinned account. No logout, grant issuance or revocation.
    pub async fn select_profile(mut self, profile_id: String) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.busy.get_untracked(),
            "an account switch is already in progress"
        );
        let mut profiles = self.config.with(|store| store.load_profile_metadata())?;
        let selected = profiles
            .profiles
            .iter()
            .find(|profile| profile.account.profile_id == profile_id)
            .ok_or_else(|| anyhow::anyhow!("selected account is no longer saved"))?
            .account
            .clone();
        if self
            .account
            .get_untracked()
            .as_ref()
            .is_some_and(|current| {
                current.authority == selected.authority
                    && current.device_id == selected.device_id
                    && current.server_url == selected.server_url
                    && current.profile_id == selected.profile_id
            })
            && !self.blocked.get_untracked()
            && self.store.read(|store| store.active_authority()) == Some(selected.authority.clone())
            && self.config.with(|store| store.selected_authority())
                == Some(selected.authority.clone())
            && self.store.read(|store| store.pending_login()).is_none()
        {
            return Ok(());
        }
        self.busy.revise(|current| *current = true);
        let expected = self.generation.get_untracked();
        let probe = self.store.read(|store| store.clone());
        let prepared = probe.prepare_saved_account(&selected).await;
        if let Err(error) = prepared {
            self.busy.revise(|current| *current = false);
            return Err(error);
        }
        if self.generation.get_untracked() != expected {
            self.busy.revise(|current| *current = false);
            anyhow::bail!("session changed while preparing the selected account");
        }
        self.retire();
        let switching_generation = self.generation.get_untracked();
        let result = async {
            let barrier = self.store.read(|store| store.begin_durable_flush())?;
            barrier.wait().await?;
            anyhow::ensure!(
                self.generation.get_untracked() == switching_generation,
                "session changed during account persistence"
            );
            crate::identity::account_auth::clear_all_persisted_oidc_scaffolds()?;
            profiles.activate(&profile_id);
            // Persist selection first. If activating the target store fails,
            // restore metadata before the old account can resume.
            let old_account = self.account.get_untracked().clone();
            let old_profiles = self.config.with(|store| store.load_profile_metadata())?;
            self.config
                .revise(|store| store.save_account_selection(Some(selected.clone()), &profiles))?;
            if let Err(error) = self
                .store
                .write(|store| store.switch_saved_account(&selected))
            {
                self.config
                    .revise(|store| store.save_account_selection(old_account, &old_profiles))?;
                return Err(error);
            }
            self.base_url
                .revise(|current| *current = selected.server_url.to_string());
            self.principal
                .revise(|current| *current = Some(selected.principal_id().clone()));
            self.device
                .revise(|current| *current = selected.device_id.to_string());
            self.account.revise(|current| *current = Some(selected));
            self.profiles.revise(|current| *current = profiles);
            self.blocked.revise(|current| *current = false);
            Ok(())
        }
        .await;
        self.busy.revise(|current| *current = false);
        if self.generation.get_untracked() != switching_generation {
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
            !self.busy.get_untracked(),
            "an account switch is already in progress"
        );
        self.busy.revise(|current| *current = true);
        self.retire();
        let switching_generation = self.generation.get_untracked();
        let result = async {
            let barrier = self.store.read(|store| store.begin_durable_flush())?;
            barrier.wait().await?;
            anyhow::ensure!(
                self.generation.get_untracked() == switching_generation,
                "session changed during account persistence"
            );
            crate::identity::account_auth::clear_all_persisted_oidc_scaffolds()?;
            let profiles = self.config.with(|store| store.load_profile_metadata())?;
            self.config
                .revise(|store| store.save_account_selection(None, &profiles))?;
            let device = arkret_sdk::DeviceId::new(crate::config::new_device_id())?;
            if let Err(error) = self
                .store
                .write(|store| store.begin_account_switch_login(&device))
            {
                let old_account = self.account.get_untracked().clone();
                self.config
                    .revise(|store| store.save_account_selection(old_account, &profiles))?;
                return Err(error);
            }
            self.account.revise(|current| *current = None);
            self.principal.revise(|current| *current = None);
            self.device.revise(|current| *current = device.to_string());
            Ok(())
        }
        .await;
        self.busy.revise(|current| *current = false);
        if self.generation.get_untracked() != switching_generation {
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

pub fn account_picker_options(profiles: &MultiProfileConfig) -> Vec<(String, String)> {
    profiles
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| {
            let label = if profile.label.trim().is_empty() {
                format!("{} {}", crate::i18n::tr("app.account.unnamed"), index + 1)
            } else {
                profile.label.clone()
            };
            let server = profile.account.server_url.as_str().trim_end_matches('/');
            let server = server
                .strip_prefix("https://")
                .or_else(|| server.strip_prefix("http://"))
                .unwrap_or(server);
            (
                profile.account.profile_id.clone(),
                format!("{label} · {server}"),
            )
        })
        .collect()
}

pub fn account_switcher(scope: &Scope, context: Rc<InksonContext>, enabled: Lotus<bool>) -> View {
    let root = AccountSessionRoot::from_context(context.clone());
    let source = scope.bond({
        let context = context.clone();
        move || {
            (
                context.account_revision.get(),
                context.account_view_retired.get(),
                context.token.get(),
            )
        }
    });
    reactive(source, move |scope, _| {
        let context = context.clone();
        let profiles = match root.config.with(LocalConfigStore::load_profile_metadata) {
            Ok(profiles) => profiles,
            Err(_) => {
                return crate::presentation::widgets::paragraph(
                    "error",
                    context.translated(scope, "app.account.saved_unavailable"),
                );
            }
        };
        let options = account_picker_options(&profiles);
        if options.is_empty() {
            return empty();
        }
        let selecting = root.clone();
        let adding = root.clone();
        let busy = root.busy;
        let ready = scope.bond({
            let enabled = enabled.clone();
            move || enabled.get() && !busy.get()
        });
        let selection = scope.bond({
            let context = context.clone();
            move || {
                if context.account_blocked.get() {
                    None
                } else {
                    context
                        .active_account
                        .get()
                        .map(|account| account.profile_id)
                }
            }
        });
        let selected_context = context.clone();
        let add_context = context.clone();
        let errors = reactive(root.error, |_, error| match error {
            Some(error) => crate::presentation::widgets::paragraph("error", error),
            None => empty(),
        });
        let on_select = move |id: Option<String>| {
            if let Some(id) = id {
                let context = selected_context.clone();
                let failure = context.clone();
                if let Err(error) = selecting.clone().start_select_profile(id, move |result| {
                    finish_switch(context, result, Route::Dashboard)
                }) {
                    failure
                        .account_error
                        .revise(|value| *value = Some(error.to_string()));
                }
            }
        };
        #[cfg(target_arch = "wasm32")]
        let picker = Box::new(
            sapid::native_select("account-switcher")
                .unstyled()
                .class("select account-picker__select")
                .label(context.translated(scope, "app.account.switch"))
                .enabled(ready)
                .value(selection)
                .options(
                    options
                        .into_iter()
                        .map(|(id, label)| sapid::select_option(id.clone(), label).value(id)),
                )
                .on_value_change(on_select),
        ) as View;
        #[cfg(not(target_arch = "wasm32"))]
        let picker = {
            use crate::presentation::native_choice::{
                NativeChoiceOption, NativeChoiceProps, native_choice,
            };
            native_choice(
                scope,
                NativeChoiceProps::new(
                    "account-switcher",
                    context.translated(scope, "app.account.switch"),
                    selection,
                    options
                        .into_iter()
                        .map(|(value, label)| NativeChoiceOption::new(value, label))
                        .collect(),
                    on_select,
                )
                .enabled(ready)
                .class("select account-picker__select")
                .close_label(context.translated(scope, "common.close")),
            )
        };
        stack(
            "account-picker",
            vec![
                picker,
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn btn-ghost account-picker__add")
                        .enabled(ready)
                        .label(context.translated(scope, "app.account.add"))
                        .on_press(move || {
                            let context = add_context.clone();
                            let failure = context.clone();
                            if let Err(error) = adding.clone().start_add_account(move |result| {
                                finish_switch(context, result, Route::Login)
                            }) {
                                failure
                                    .account_error
                                    .revise(|value| *value = Some(error.to_string()));
                            }
                        }),
                ),
                errors,
            ],
        )
    })
}

pub(crate) fn return_to_previous_account(
    scope: &Scope,
    context: Rc<InksonContext>,
    enabled: Lotus<bool>,
) -> View {
    if context.active_account.get_untracked().is_some() {
        return empty();
    }
    let Ok(profiles) = context
        .config_store
        .with(LocalConfigStore::load_profile_metadata)
    else {
        return empty();
    };
    let Some(previous) = profiles
        .active()
        .map(|profile| profile.account.profile_id.clone())
    else {
        return empty();
    };
    let root = AccountSessionRoot::from_context(context.clone());
    let busy = context.account_busy;
    let ready = scope.bond(move || enabled.get() && !busy.get());
    Box::new(
        sapid::button()
            .unstyled()
            .class("btn btn-ghost")
            .enabled(ready)
            .label(context.translated(scope, "app.account.return_previous"))
            .on_press(move || {
                let context = context.clone();
                let failure = context.clone();
                if let Err(error) = root
                    .clone()
                    .start_select_profile(previous.clone(), move |result| {
                        finish_switch(context, result, Route::Dashboard)
                    })
                {
                    failure
                        .account_error
                        .revise(|value| *value = Some(error.to_string()));
                }
            }),
    )
}

fn finish_switch(context: Rc<InksonContext>, result: anyhow::Result<()>, route: Route) {
    match result {
        Ok(()) => {
            context.account_error.revise(|value| *value = None);
            context.navigate(route);
        }
        Err(error) => {
            tracing::warn!(%error, "account selection failed");
            context
                .account_error
                .revise(|value| *value = Some(context.tr("app.account.switch_failed")));
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
