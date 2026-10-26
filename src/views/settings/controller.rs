use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::{InksonContext, SharedStateStore};

/// Signals the settings writes fold their outcome back into.
#[derive(Clone)]
pub(super) struct SettingsController {
    pub context: Rc<InksonContext>,
    pub owner: glory::ui::WeakScope,
    pub invite_locator: Cage<InviteLocatorState>,
    pub profile_avatar_blob_ref: Cage<String>,
    pub avatar_upload_status: Cage<String>,
    pub avatar_uploading: Cage<bool>,
    pub avatar_cache_status: Cage<String>,
    pub avatar_removing: Cage<bool>,
    pub avatar_reading: Cage<bool>,
    pub avatar_file_read: crate::components::avatar_uploader::ImageReadState,
    pub settings_session: SettingsSessionSignals,
    pub avatar_selection_epoch: Cage<AvatarSelectionEpoch>,
    pub pending_avatar_crop: Cage<Option<PendingAvatarCrop>>,
    pub avatar_crop_zoom: Cage<i32>,
    pub avatar_crop_x: Cage<i32>,
    pub avatar_crop_y: Cage<i32>,
    /// Bumped so every rendered `<img>` for the account avatar re-fetches
    /// after an upload or a removal, instead of showing the cached bytes.
    pub avatar_refresh_nonce: Cage<u64>,
    pub profile_display_name: Cage<String>,
    pub profile_bio: Cage<String>,
    pub profile_text_status: Cage<String>,
    pub profile_text_saving: Cage<bool>,
    pub mimi_directory: Cage<String>,
    pub mimi_receipt: Cage<String>,
    pub mimi_directory_loading: Cage<bool>,
    pub mimi_query_loading: Cage<bool>,
    pub mimi_submit_loading: Cage<bool>,
    pub mimi_proxy_loading: Cage<bool>,
    pub mimi_submit_receipt: Cage<String>,
    pub mimi_proxy_receipt: Cage<String>,

    pub push_state: Cage<String>,
    /// The UI theme preference, republished alongside every avatar change so
    /// the merged `ak.client.ui_state` patch never drops it.
    pub theme: Cage<String>,
    pub state_store: SharedStateStore,
}

/// Root-owned session coordinates; each completion checks these synchronously,
/// so an account switch is effective before the UI cleanup effect is polled.
#[derive(Clone, Copy)]
pub(super) struct SettingsSessionSignals {
    pub active_account: Cage<Option<crate::config::ActiveAccountContext>>,
    pub base_url: Cage<String>,
    pub token: Cage<String>,
    pub generation: Cage<u64>,
}

#[derive(Clone, PartialEq)]
pub(super) struct SettingsSessionStamp {
    account: Option<(arkret_sdk::AccountId, arkret_sdk::DeviceId, String)>,
    base_url: String,
    token: String,
    generation: u64,
}

impl SettingsSessionSignals {
    pub(super) fn capture(self) -> SettingsSessionStamp {
        SettingsSessionStamp {
            account: self.active_account.get().map(|account| {
                (
                    account.authority,
                    account.device_id,
                    account.server_url.to_string(),
                )
            }),
            base_url: self.base_url.get(),
            token: self.token.get(),
            generation: self.generation.get(),
        }
    }

    pub(super) fn is_current(self, started: &SettingsSessionStamp) -> bool {
        self.capture() == *started
    }
}

/// UI cleanup subscribes to the same live roots as the synchronous completion
/// fence; it does not create a second session authority or decide acceptance.
pub(super) fn avatar_selection_boundary(scope: &Scope, controller: SettingsController) {
    let previous = scope.cage(None::<SettingsSessionStamp>);
    scope.effect(move || {
        let subject = controller.settings_session.capture();
        if previous.get_untracked().as_ref() != Some(&subject) {
            controller.clone().cancel_avatar_crop();
            controller.avatar_uploading.revise(|value| {
                *value = false;
            });
            controller.avatar_removing.revise(|value| {
                *value = false;
            });
            controller.avatar_cache_status.revise(|value| value.clear());
            controller.mimi_directory_loading.revise(|value| {
                *value = false;
            });
            controller.mimi_query_loading.revise(|value| {
                *value = false;
            });
            controller.mimi_submit_loading.revise(|value| {
                *value = false;
            });
            controller.mimi_proxy_loading.revise(|value| {
                *value = false;
            });
            previous.revise(|value| {
                *value = Some(subject);
            });
        }
    });
}

impl SettingsController {
    pub(super) fn new(scope: &Scope, context: Rc<InksonContext>) -> Self {
        let avatar_reading = scope.cage(false);
        Self {
            invite_locator: scope.cage(InviteLocatorState::default()),
            profile_avatar_blob_ref: scope.cage(
                context
                    .state_store
                    .read(|store| store.load_plain_local_data("avatar_blob_ref"))
                    .unwrap_or_default(),
            ),
            avatar_upload_status: scope.cage(String::new()),
            avatar_uploading: scope.cage(false),
            avatar_cache_status: scope.cage(String::new()),
            avatar_removing: scope.cage(false),
            avatar_reading,
            avatar_file_read: crate::components::avatar_uploader::ImageReadState::new(
                scope,
                avatar_reading,
            ),
            settings_session: SettingsSessionSignals {
                active_account: context.active_account,
                base_url: context.base_url,
                token: context.token,
                generation: context.session_generation,
            },
            avatar_selection_epoch: scope.cage(AvatarSelectionEpoch::default()),
            pending_avatar_crop: scope.cage(None),
            avatar_crop_zoom: scope.cage(125),
            avatar_crop_x: scope.cage(0),
            avatar_crop_y: scope.cage(0),
            avatar_refresh_nonce: scope.cage(0),
            profile_display_name: scope.cage(context.account_primary_handle.get()),
            profile_bio: scope.cage(String::new()),
            profile_text_status: scope.cage(String::new()),
            profile_text_saving: scope.cage(false),
            mimi_directory: scope.cage(String::new()),
            mimi_receipt: scope.cage(String::new()),
            mimi_directory_loading: scope.cage(false),
            mimi_query_loading: scope.cage(false),
            mimi_submit_loading: scope.cage(false),
            mimi_proxy_loading: scope.cage(false),
            mimi_submit_receipt: scope.cage(String::new()),
            mimi_proxy_receipt: scope.cage(String::new()),
            push_state: context.push_state,
            theme: context.theme,
            state_store: context.state_store.clone(),
            owner: scope.downgrade(),
            context,
        }
    }

    /// Publish display name and biography through the same create/update authoring
    /// path as avatar changes. Local mirrors advance only after acceptance.
    pub(super) fn save_profile_text(
        self,
        base: String,
        api_token: String,
        first_profile_display_name: String,
    ) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            profile_display_name,
            profile_bio,
            profile_text_status,
            profile_text_saving,
            state_store,
            ..
        } = self;
        let display_name = profile_display_name.get().trim().to_owned();
        let biography = profile_bio.get().trim().to_owned();
        if display_name.is_empty() {
            profile_text_status.revise(|value| {
                *value = crate::i18n::tr("settings.profile.display_name_required");
            });
            return;
        }
        if let Err(error) = arkret_sdk::validate_single_line_display_text(&display_name, 128) {
            profile_text_status.revise(|value| {
                *value = format!(
                    "{}: {error}",
                    crate::i18n::tr("settings.profile.invalid_display_name")
                )
            });
            return;
        }
        profile_text_saving.revise(|value| {
            *value = true;
        });
        profile_text_status.revise(|value| {
            *value = crate::i18n::tr("settings.profile.saving");
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let authority_evidence =
                        state_store.read(|store| store.recovery_material_evidence());
                    let result = async {
                        let authority_evidence = authority_evidence.ok_or_else(|| {
                            anyhow::anyhow!(
                                "profile update requires durable accepted PCR authority evidence"
                            )
                        })?;
                        crate::transport::auth::with_event_submitter(
                            &base,
                            api_token,
                            move |submitter| async move {
                                crate::transport::account::update_profile(
                                    &submitter,
                                    &authority_evidence,
                                    &first_profile_display_name,
                                    Some(&display_name),
                                    Some(&biography),
                                    None,
                                )
                                .await
                            },
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.display()))
                    }
                    .await;
                    profile_text_saving.revise(|value| {
                        *value = false;
                    });
                    match result {
                        Ok(_) => {
                            profile_text_status.revise(|value| {
                                *value = crate::i18n::tr("settings.profile.saved");
                            });
                        }
                        Err(error) => {
                            profile_text_status.revise(|value| {
                                *value = format!(
                                    "{}: {error}",
                                    crate::i18n::tr("settings.profile.save_failed")
                                )
                            });
                        }
                    }
                });
            }
        };
    }

    /// Invalidate in-flight reads before clearing the staged editor.
    pub(super) fn cancel_avatar_crop(self) {
        self.avatar_file_read.cancel();
        let reading = self.avatar_reading;
        reading.revise(|value| {
            *value = false;
        });
        let epoch = self.avatar_selection_epoch;
        epoch.revise(|value| value.advance());
        let pending = self.pending_avatar_crop;
        pending.revise(|value| {
            *value = None;
        });
        let status = self.avatar_upload_status;
        status.revise(|value| {
            *value = String::new();
        });
    }

    /// Read the picked image and stage it for cropping.
    ///
    /// Every rejection path clears the staged selection as well as the
    /// reading flag: a half-staged crop would offer a Save button with
    /// nothing behind it.
    pub(super) fn stage_avatar_crop(self, bytes: Vec<u8>, content_type: String) {
        #[cfg(feature = "spec-conformance")]
        tracing::warn!(
            bytes = bytes.len(),
            owner_alive = self.owner.upgrade().is_some(),
            "Avatar crop staging started"
        );
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            avatar_upload_status,
            avatar_selection_epoch,
            avatar_reading,
            pending_avatar_crop,
            avatar_crop_zoom,
            avatar_crop_x,
            avatar_crop_y,
            ..
        } = self;
        if self.avatar_uploading.get() || self.avatar_removing.get() {
            return;
        }
        avatar_reading.revise(|value| {
            *value = true;
        });
        let started_session = settings_session.capture();
        let mut selection_epoch = avatar_selection_epoch.get();
        selection_epoch.advance();
        avatar_selection_epoch.revise(|value| {
            *value = selection_epoch;
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let result = Ok::<_, String>(bytes);
                    if avatar_selection_epoch.get() != selection_epoch
                        || !settings_session.is_current(&started_session)
                    {
                        #[cfg(feature = "spec-conformance")]
                        tracing::warn!(
                            session_current = settings_session.is_current(&started_session),
                            "Avatar crop staging retired before publication"
                        );
                        return;
                    }
                    avatar_reading.revise(|value| {
                        *value = false;
                    });
                    let bytes = match result {
                        Ok(b) => b.to_vec(),
                        Err(err) => {
                            pending_avatar_crop.revise(|value| {
                                *value = None;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                            return;
                        }
                    };
                    if !content_type.starts_with("image/") {
                        pending_avatar_crop.revise(|value| {
                            *value = None;
                        });
                        avatar_upload_status.revise(|value| {
                            *value = format!(
                                "{}: {}",
                                crate::i18n::tr("settings.avatar.error"),
                                crate::i18n::tr("settings.avatar.invalid_image"),
                            )
                        });
                        return;
                    }
                    let dimensions = match crate::avatar_crop::image_dimensions(&bytes) {
                        Ok(dimensions) => dimensions,
                        Err(err) => {
                            pending_avatar_crop.revise(|value| {
                                *value = None;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                            return;
                        }
                    };
                    let preview_data_url = avatar_preview_data_url(&bytes, &content_type);
                    pending_avatar_crop.revise(|value| {
                        *value = Some(PendingAvatarCrop {
                            bytes,
                            media_type: content_type,
                            preview_data_url,
                            dimensions,
                        })
                    });
                    #[cfg(feature = "spec-conformance")]
                    tracing::warn!("Avatar crop staging published");
                    avatar_crop_zoom.revise(|value| {
                        *value = 125;
                    });
                    avatar_crop_x.revise(|value| {
                        *value = 0;
                    });
                    avatar_crop_y.revise(|value| {
                        *value = 0;
                    });
                    avatar_upload_status.revise(|value| {
                        *value = crate::i18n::tr("settings.avatar.crop_ready");
                    });
                });
            }
        };
    }

    /// Crop, upload and publish the staged avatar.
    pub(super) fn upload_cropped_avatar(
        self,
        base: String,
        api_token: String,
        first_profile_display_name: String,
        selection: PendingAvatarCrop,
        crop: crate::avatar_crop::AvatarCrop,
    ) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            theme,
            profile_avatar_blob_ref,
            avatar_upload_status,
            avatar_uploading,
            pending_avatar_crop,
            avatar_refresh_nonce,
            state_store,
            ..
        } = self;
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let bytes = match crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            avatar_uploading.revise(|value| {
                                *value = false;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                            return;
                        }
                    };
                    let api = match crate::transport::auth::authed_api(&base, api_token.clone()) {
                        Ok(api) => api,
                        Err(err) => {
                            avatar_uploading.revise(|value| {
                                *value = false;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                            return;
                        }
                    };
                    let clients = match api.sdk_http_client() {
                        Ok(http) => crate::transport::EndpointClients::from_http(http),
                        Err(err) => {
                            avatar_uploading.revise(|value| {
                                *value = false;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                            return;
                        }
                    };
                    let upload_result = clients.blob().upload_bytes(bytes, "image/jpeg").await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match upload_result {
                        Ok(resp) => {
                            let blob_ref = resp.blob_ref.to_string();
                            let authority_evidence =
                                state_store.read(|store| store.recovery_material_evidence());
                            // Publish publicly first; only then refresh the
                            // local mirror so a failed profile update does not
                            // display an avatar that never became active.
                            let profile_result = async {
                                let authority_evidence = authority_evidence.ok_or_else(|| {
                            anyhow::anyhow!(
                                "profile update requires durable accepted PCR authority evidence"
                            )
                        })?;
                                let profile_blob_ref = blob_ref.clone();
                                crate::transport::auth::with_event_submitter(
                                    &base,
                                    api_token.clone(),
                                    move |submitter| async move {
                                        crate::transport::account::update_profile(
                                            &submitter,
                                            &authority_evidence,
                                            &first_profile_display_name,
                                            None,
                                            None,
                                            Some(&profile_blob_ref),
                                        )
                                        .await
                                    },
                                )
                                .await
                                .map_err(|error| anyhow::anyhow!(error.display()))
                            }
                            .await;
                            if !settings_session.is_current(&started_session) {
                                return;
                            }
                            match profile_result {
                                Ok(_) => {
                                    state_store.write(|store| {
                                        store.save_plain_local_data(
                                            "avatar_blob_ref",
                                            blob_ref.clone(),
                                        )
                                    });
                                    push_client_ui_account_data_with_avatar(
                                        context.clone(),
                                        base.clone(),
                                        api_token.clone(),
                                        theme.get(),
                                        Some(blob_ref.clone()),
                                    );
                                    let refreshed = state_store
                                        .read(|store| {
                                            store.load_plain_local_data("avatar_blob_ref")
                                        })
                                        .filter(|value| !value.trim().is_empty())
                                        .unwrap_or_else(|| blob_ref.clone());
                                    profile_avatar_blob_ref.revise(|value| {
                                        *value = refreshed;
                                    });
                                    avatar_refresh_nonce.revise(|value| {
                                        *value = avatar_refresh_nonce.get() + 1;
                                    });
                                    avatar_uploading.revise(|value| {
                                        *value = false;
                                    });
                                    pending_avatar_crop.revise(|value| {
                                        *value = None;
                                    });
                                    avatar_upload_status.revise(|value| {
                                        *value = String::new();
                                    });
                                    crate::components::feedback::toast_success(
                                        "feedback.avatar_updated",
                                        vec![],
                                    );
                                }
                                Err(err) => {
                                    avatar_uploading.revise(|value| {
                                        *value = false;
                                    });
                                    avatar_upload_status.revise(|value| {
                                        *value = format!(
                                            "{}: {}",
                                            crate::i18n::tr("settings.avatar.error"),
                                            err,
                                        )
                                    });
                                }
                            }
                        }
                        Err(err) => {
                            avatar_uploading.revise(|value| {
                                *value = false;
                            });
                            avatar_upload_status.revise(|value| {
                                *value =
                                    format!("{}: {err}", crate::i18n::tr("settings.avatar.error"),)
                            });
                        }
                    }
                });
            }
        };
    }

    /// Remove the account avatar.
    ///
    /// Publishes the public tombstone before the actor-private mirror. Both
    /// Events share one stream head; authoring them in the opposite order
    /// lets the mirror advance the frontier after the profile Event was built.
    pub(super) fn remove_avatar(
        self,
        base: String,
        api_token: String,
        first_profile_display_name: String,
    ) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            theme,
            profile_avatar_blob_ref,
            avatar_removing,
            avatar_cache_status,
            pending_avatar_crop,
            avatar_refresh_nonce,
            state_store,
            ..
        } = self;
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let authority_evidence =
                        state_store.read(|store| store.recovery_material_evidence());
                    let result = async {
                        let authority_evidence = authority_evidence.ok_or_else(|| {
                            anyhow::anyhow!(
                                "profile update requires durable accepted PCR authority evidence"
                            )
                        })?;
                        crate::transport::auth::with_event_submitter(
                            &base,
                            api_token.clone(),
                            move |submitter| async move {
                                crate::transport::account::update_profile(
                                    &submitter,
                                    &authority_evidence,
                                    &first_profile_display_name,
                                    None,
                                    None,
                                    Some(""),
                                )
                                .await
                            },
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.display()))
                    }
                    .await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match result {
                        Ok(_) => {
                            state_store
                                .write(|store| store.save_plain_local_data("avatar_blob_ref", ""));
                            push_client_ui_account_data_with_avatar(
                                context.clone(),
                                base,
                                api_token,
                                theme.get(),
                                Some(String::new()),
                            );
                            profile_avatar_blob_ref.revise(|value| {
                                *value = String::new();
                            });
                            avatar_refresh_nonce.revise(|value| {
                                *value = avatar_refresh_nonce.get() + 1;
                            });
                            pending_avatar_crop.revise(|value| {
                                *value = None;
                            });
                            avatar_removing.revise(|value| {
                                *value = false;
                            });
                            avatar_cache_status.revise(|value| {
                                *value = crate::i18n::tr("settings.avatar.removed")
                            });
                        }
                        Err(err) => {
                            avatar_removing.revise(|value| {
                                *value = false;
                            });
                            avatar_cache_status.revise(|value| {
                                *value = format!("Avatar removal failed: {err}");
                            });
                            tracing::warn!("avatar profile clear failed: {err}");
                        }
                    }
                });
            }
        };
    }

    /// Serialize writes and fence their completion against the live session roots.
    pub(super) fn change_invite_locator(self, revoke: bool) {
        let started = self.settings_session.capture();
        let base = started.base_url.clone();
        let token = started.token.clone();
        if token.trim().is_empty() || started.account.is_none() {
            return;
        }
        let session = self.settings_session;
        self.run_invite_locator(revoke, move |old| async move {
            with_authed_sdk_client(&base, token, |client| async move {
                // Authentication preparation may await a different active account.
                if !session.is_current(&started) {
                    anyhow::bail!("invite locator session changed before dispatch");
                }
                if revoke {
                    client
                        .revoke_invite_locator(&arkret_sdk::InviteLocatorRevokeRequestBody {
                            locator_id: arkret_sdk::InviteLocatorId::new(old)?,
                        })
                        .await?;
                    Ok(None)
                } else if old.is_empty() {
                    issue_invite_locator(client).await.map(Some)
                } else {
                    rotate_invite_locator(client, old).await.map(Some)
                }
            })
            .await
            .map_err(|e| e.display())
        });
    }

    pub(super) fn run_invite_locator<F, Fut>(self, revoke: bool, operation: F)
    where
        F: FnOnce(String) -> Fut + 'static,
        Fut: std::future::Future<
                Output = std::result::Result<
                    Option<arkret_sdk::InviteLocatorIssueResponseBody>,
                    String,
                >,
            > + 'static,
    {
        let started = self.settings_session.capture();
        let mut state = self.invite_locator.get_untracked();
        if state.session.as_ref() != Some(&started) {
            state = InviteLocatorState {
                session: Some(started.clone()),
                ..Default::default()
            };
        }
        if state.busy || (revoke && state.id.is_empty()) {
            return;
        }
        state.busy = true;
        state.token.clear();
        state.status = crate::i18n::tr(if revoke {
            "settings.invite_locator.revoking"
        } else if state.id.is_empty() {
            "settings.invite_locator.issuing"
        } else {
            "settings.invite_locator.rotating"
        });
        let old = state.id.clone();
        self.invite_locator.revise(|value| {
            *value = state;
        });
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        super::widgets::spawn(&scope, async move {
            if !self.settings_session.is_current(&started) {
                return;
            }
            let result = operation(old).await;
            if !self.settings_session.is_current(&started) {
                return;
            }
            self.invite_locator.revise(|state| {
                state.busy = false;
                match result {
                    Ok(Some(outcome)) => {
                        state.id = outcome.locator_id.to_string();
                        state.token = outcome.locator_token;
                        state.status.clear();
                    }
                    Ok(None) => {
                        state.id.clear();
                        state.token.clear();
                        state.status = crate::i18n::tr("settings.invite_locator.revoked");
                    }
                    Err(error) => {
                        state.status = format!(
                            "{}: {error}",
                            crate::i18n::tr(if revoke {
                                "settings.invite_locator.revoke_failed"
                            } else {
                                "settings.invite_locator.refresh_failed"
                            })
                        );
                    }
                }
            });
        });
    }

    /// MIMI interop probe: read the provider directory.
    pub(super) fn refresh_mimi_directory(self, base: String, api_token: String) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            mimi_directory_loading,
            mimi_directory,
            ..
        } = self;
        if mimi_directory_loading.get() {
            return;
        }
        mimi_directory_loading.revise(|value| {
            *value = true;
        });
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let result = with_authed_sdk_client(&base, api_token, |http| async move {
                        let binding =
                            crate::station_connection::load_accepted(http.base_url().as_str())
                                .await?;
                        // The user-selected own Station is an explicit target scope.
                        // No remote directory can choose a transport or trust anchor.
                        // This only reads the accepted own Station; no remote provider
                        // target is fetched. HTTPS and metadata/link-local refusal remain.
                        let policy =
                            arkret_sdk::network_policy::OutboundPolicy::controlled_network(false);
                        Ok(http
                            .mimi_provider_directory_from_own_station(
                                &binding,
                                None,
                                &[],
                                chrono::Duration::minutes(5),
                                policy,
                            )
                            .await?)
                    })
                    .await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match result {
                        Ok(directory) => {
                            let directory = directory.directory();
                            let features = serde_json::to_string_pretty(&directory.mimi.features)
                                .unwrap_or_else(|_| "[]".to_owned());
                            mimi_directory.revise(|value| {
                                *value = format!(
                                    "provider {}\nfeatures {}",
                                    directory.mimi.provider_id, features,
                                )
                            });
                        }
                        Err(err) => {
                            let message = format!("MIMI directory: {}", err.display());
                            mimi_directory.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.mimi_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                    mimi_directory_loading.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    /// MIMI interop probe: resolve a fixed identifier commitment.
    pub(super) fn query_mimi_identifiers(self, base: String, api_token: String) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            mimi_query_loading,
            mimi_receipt,
            ..
        } = self;
        if mimi_query_loading.get() {
            return;
        }
        mimi_query_loading.revise(|value| {
            *value = true;
        });
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let result = with_authed_sdk_client(&base, api_token, |http| async move {
                        let request = arkret_sdk::MimiIdentifierQueryRequestBody {
                            identifiers: vec![arkret_sdk::MimiIdentifier {
                                kind: arkret_sdk::MimiIdentifierKind::MimiUri,
                                identifier_commitment: arkret_sdk::Hash::new(
                                    arkret_sdk::canonical::sha256_digest(
                                        b"mimi://remote.example/alice",
                                    ),
                                )?,
                            }],
                            requester_id: None,
                            privacy_profile: Some(
                                arkret_sdk::NonEmptyString::new("private_identifier_query")
                                    .map_err(anyhow::Error::msg)?,
                            ),
                            proofs: Vec::new(),
                        };
                        http.mimi_identifier_query(&request)
                            .await
                            .map_err(anyhow::Error::from)
                    })
                    .await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match result {
                        Ok(response) => {
                            let first = response
                                .matches
                                .first()
                                .map(|value| {
                                    serde_json::to_string(value)
                                        .unwrap_or_else(|_| "invalid-result".to_owned())
                                })
                                .unwrap_or_else(|| "none".to_owned());
                            mimi_receipt.revise(|value| {
                                *value = format!(
                                    "identifier results {} first {}",
                                    response.matches.len(),
                                    first
                                )
                            });
                        }
                        Err(err) => {
                            let message =
                                format!("MIMI identifier query failed: {}", err.display());
                            mimi_receipt.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.mimi_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                    mimi_query_loading.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    /// MIMI interop probe: submit a fixed test message.
    pub(super) fn submit_mimi_message(
        self,
        base: String,
        api_token: String,
        actor: arkret_sdk::ActorId,
        device: String,
    ) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            mimi_submit_loading,
            mimi_submit_receipt,
            ..
        } = self;
        if mimi_submit_loading.get() {
            return;
        }
        mimi_submit_loading.revise(|value| {
            *value = true;
        });
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let result = with_authed_sdk_client(&base, api_token, |http| async move {
                let plaintext = br#"{"source_format":"text/markdown;variant=GFM-MIMI","body":"MIMI interop test from inkson","mimi_room_uri":"mimi://mimi.example.com/rooms/01JSMIMI"}"#;
                let request = arkret_sdk::MimiSubmitMessageRequestBody {
                    sender_actor_id: actor,
                    device_id: arkret_sdk::DeviceId::new(device.trim().to_owned())?,
                    ciphertext: arkret_sdk::MimiCiphertext {
                        content_type: arkret_sdk::NonEmptyString::new("application/json")
                            .map_err(anyhow::Error::msg)?,
                        ciphertext_digest: arkret_sdk::Hash::new(
                            arkret_sdk::canonical::sha256_digest(plaintext),
                        )?,
                        payload: arkret_sdk::Base64UrlString::new(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext),
                        )
                        .map_err(anyhow::Error::msg)?,
                    },
                    mls_group_id: None,
                    epoch: None,
                    associated_data: None,
                };
                http.mimi_submit_message("01JSMIMI", &request)
                .await
                .map_err(anyhow::Error::from)
            })
            .await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match result {
                        Ok(response) => {
                            mimi_submit_receipt.revise(|value| {
                                *value = format!(
                                    "submit-message event {} rejected {}",
                                    response
                                        .event_ref
                                        .as_ref()
                                        .map(ToString::to_string)
                                        .unwrap_or_else(|| "no-event".to_owned()),
                                    response.rejections.len()
                                )
                            });
                        }
                        Err(err) => {
                            let message = format!("MIMI submit failed: {}", err.display());
                            mimi_submit_receipt.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.mimi_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                    mimi_submit_loading.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    /// MIMI interop probe: proxy-download a fixed asset reference.
    pub(super) fn proxy_download_mimi_asset(self, base: String, api_token: String, actor: String) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            settings_session,
            mimi_proxy_loading,
            mimi_proxy_receipt,
            ..
        } = self;
        if mimi_proxy_loading.get() {
            return;
        }
        mimi_proxy_loading.revise(|value| {
            *value = true;
        });
        let started_session = settings_session.capture();
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    let result = with_authed_sdk_client(&base, api_token, |http| async move {
                let request = arkret_sdk::MimiProxyDownloadRequestBody {
                    asset_ref: arkret_sdk::NonEmptyString::new(
                        "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
                    )
                    .map_err(anyhow::Error::msg)?,
                    requester_id: crate::mls_api_helpers::principal_core_id(&actor)?,
                    strand_id: None,
                    ohttp_context: None,
                    range: None,
                };
                http.mimi_proxy_download(&request)
                .await
                .map_err(anyhow::Error::from)
            })
            .await;
                    if !settings_session.is_current(&started_session) {
                        return;
                    }
                    match result {
                        Ok(response) => {
                            mimi_proxy_receipt.revise(|value| {
                                *value = format!(
                                    "proxy-download {} headers {}",
                                    response.download_ref,
                                    response.download_request_headers.len()
                                )
                            });
                        }
                        Err(err) => {
                            let message = format!("MIMI proxy download failed: {}", err.display());
                            mimi_proxy_receipt.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.mimi_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                    mimi_proxy_loading.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    /// Register this device with the push gateway through chime.
    pub(super) fn register_push(
        self,
        base: String,
        api_token: String,
        dev: String,
        push_account_id: arkret_sdk::AccountId,
        persisted_grant: Option<crate::state::PersistedSessionGrant>,
    ) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            push_state,
            state_store,
            ..
        } = self;
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let context = crate::push::registration::RegisterContext {
                        station_url: base,
                        floria_gateway_url: crate::push::floria_gateway_url(),
                        device_id: dev,
                        account_id: Some(push_account_id),
                        authorization_credential: Some(api_token),
                        session_grant: None,
                        active_circle_id: None,
                    };
                    match crate::push::registration::register_via_chime(context, persisted_grant)
                        .await
                    {
                        Ok(outcome) => {
                            state_store
                                .write(|store| store.save_push_registration(outcome.state.clone()));
                            let label = outcome.response.registration_id.map_or_else(
                                || "registered".to_owned(),
                                arkret_sdk::OpaqueLocalId::into_string,
                            );
                            push_state.revise(|value| {
                                *value = label.clone();
                            });
                            crate::components::feedback::toast_success(
                                "feedback.push_registered",
                                vec![("label", label)],
                            );
                        }
                        Err(err) => {
                            let message = format!("push register failed: {err}");
                            push_state.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.push_register_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                });
            }
        };
    }

    /// Unregister this device from the push gateway.
    pub(super) fn unregister_push(
        self,
        base: String,
        api_token: String,
        dev: String,
        persisted_grant: Option<crate::state::PersistedSessionGrant>,
        registration: Option<chime::PushRegistrationState>,
    ) {
        let _context = self.context.clone();
        let page_owner = self.owner.clone();

        let SettingsController {
            push_state,
            state_store,
            ..
        } = self;
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let context = crate::push::registration::UnregisterContext {
                        station_url: base,
                        device_id: dev,
                        authorization_credential: Some(api_token),
                        session_grant: None,
                    };
                    match crate::push::registration::unregister_via_chime(
                        context,
                        persisted_grant,
                        registration,
                    )
                    .await
                    {
                        Ok(_) => {
                            state_store.write(|store| store.clear_push_registration());
                            push_state.revise(|value| {
                                *value = crate::i18n::tr("settings.push.not_registered")
                            });
                            crate::components::feedback::toast_success(
                                "feedback.push_unregistered",
                                vec![],
                            );
                        }
                        Err(err) => {
                            let message = format!("push unregister failed: {err}");
                            push_state.revise(|value| {
                                *value = message.clone();
                            });
                            crate::components::feedback::toast_error(
                                "feedback.push_unregister_failed",
                                vec![],
                                Some(message),
                            );
                        }
                    }
                });
            }
        };
    }
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
