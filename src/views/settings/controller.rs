//! Settings writes, out of the `rsx!` and named.
//!
//! Eleven `spawn(async move { … })` blocks used to sit inside `onclick`
//! attributes and one `use_effect`, some over a hundred lines deep in the
//! nesting. They read and wrote the panel's Signals directly, so the only way
//! to reach any of them was to mount `SettingsPanel`.
//!
//! [`SettingsController`] is the bundle of Signals those writes land in — the
//! same shape `KanbanController` uses — and each write below is one method on
//! it. The panel keeps the synchronous half of every click: read the form,
//! validate it, set the in-progress status.

use super::*;

/// Signals the settings writes fold their outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct SettingsController {
    pub invite_locator_id: Signal<String>,
    pub invite_locator_token: Signal<String>,
    pub invite_locator_status: Signal<String>,
    pub profile_avatar_blob_ref: Signal<String>,
    pub avatar_upload_status: Signal<String>,
    pub avatar_uploading: Signal<bool>,
    pub avatar_cache_status: Signal<String>,
    pub pending_avatar_crop: Signal<Option<PendingAvatarCrop>>,
    pub avatar_crop_zoom: Signal<i32>,
    pub avatar_crop_x: Signal<i32>,
    pub avatar_crop_y: Signal<i32>,
    /// Bumped so every rendered `<img>` for the account avatar re-fetches
    /// after an upload or a removal, instead of showing the cached bytes.
    pub avatar_refresh_nonce: Signal<u64>,
    pub profile_display_name: Signal<String>,
    pub profile_bio: Signal<String>,
    pub profile_text_status: Signal<String>,
    pub profile_text_saving: Signal<bool>,
    pub mimi_directory: Signal<String>,
    pub mimi_receipt: Signal<String>,
    pub push_state: Signal<String>,
    /// The UI theme preference, republished alongside every avatar change so
    /// the merged `ak.client.ui_state` patch never drops it.
    pub theme: Signal<String>,
    pub state_store: SyncSignal<crate::state::LocalStateStore>,
}

impl SettingsController {
    /// Publish display name and bio through the same create/update authoring
    /// path as avatar changes. Local mirrors advance only after acceptance.
    pub(super) fn save_profile_text(
        self,
        base: String,
        api_token: String,
        first_profile_display_name: String,
    ) {
        let SettingsController {
            profile_display_name,
            profile_bio,
            mut profile_text_status,
            mut profile_text_saving,
            state_store,
            ..
        } = self;
        let display_name = profile_display_name().trim().to_owned();
        let bio = profile_bio().trim().to_owned();
        if display_name.is_empty() {
            profile_text_status.set(crate::i18n::tr("settings.profile.display_name_required"));
            return;
        }
        if let Err(error) = arkret_sdk::validate_single_line_display_text(&display_name, 128) {
            profile_text_status.set(format!(
                "{}: {error}",
                crate::i18n::tr("settings.profile.invalid_display_name")
            ));
            return;
        }
        profile_text_saving.set(true);
        profile_text_status.set(crate::i18n::tr("settings.profile.saving"));
        spawn(async move {
            let authority_evidence = state_store.read().recovery_material_evidence();
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
                            Some(&bio),
                            None,
                        )
                        .await
                    },
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.display()))
            }
            .await;
            profile_text_saving.set(false);
            match result {
                Ok(_) => {
                    profile_text_status.set(crate::i18n::tr("settings.profile.saved"));
                }
                Err(error) => {
                    profile_text_status.set(format!(
                        "{}: {error}",
                        crate::i18n::tr("settings.profile.save_failed")
                    ));
                }
            }
        });
    }

    /// Issue the account's first invite locator when the panel opens for a
    /// signed-in account that has none.
    pub(super) fn issue_first_invite_locator(self, base: String, api_token: String) {
        let SettingsController {
            mut invite_locator_id,
            mut invite_locator_token,
            mut invite_locator_status,
            ..
        } = self;
        spawn(async move {
            match with_authed_sdk_client(&base, api_token, |client| async move {
                issue_invite_locator(client).await
            })
            .await
            {
                Ok(outcome) => {
                    invite_locator_id.set(outcome.locator_id.as_str().to_owned());
                    invite_locator_token.set(outcome.locator_token);
                    invite_locator_status.set(String::new());
                }
                Err(error) => {
                    invite_locator_status.set(format!(
                        "{}: {}",
                        crate::i18n::tr("settings.invite_locator.unavailable"),
                        error.display()
                    ));
                }
            }
        });
    }

    /// Read the picked image and stage it for cropping.
    ///
    /// Every rejection path clears the staged selection as well as the
    /// uploading flag: a half-staged crop would offer a Save button with
    /// nothing behind it.
    pub(super) fn stage_avatar_crop(self, file: dioxus::html::FileData, content_type: String) {
        let SettingsController {
            mut avatar_upload_status,
            mut avatar_uploading,
            mut pending_avatar_crop,
            mut avatar_crop_zoom,
            mut avatar_crop_x,
            mut avatar_crop_y,
            ..
        } = self;
        spawn(async move {
            let bytes = match file.read_bytes().await {
                Ok(b) => b.to_vec(),
                Err(err) => {
                    pending_avatar_crop.set(None);
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                    return;
                }
            };
            if !content_type.starts_with("image/") {
                pending_avatar_crop.set(None);
                avatar_uploading.set(false);
                avatar_upload_status.set(format!(
                    "{}: {}",
                    crate::i18n::tr("settings.avatar.error"),
                    crate::i18n::tr("settings.avatar.invalid_image"),
                ));
                return;
            }
            let dimensions = match crate::avatar_crop::image_dimensions(&bytes) {
                Ok(dimensions) => dimensions,
                Err(err) => {
                    pending_avatar_crop.set(None);
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                    return;
                }
            };
            let preview_data_url = avatar_preview_data_url(&bytes, &content_type);
            pending_avatar_crop.set(Some(PendingAvatarCrop {
                bytes,
                media_type: content_type,
                preview_data_url,
                dimensions,
            }));
            avatar_crop_zoom.set(125);
            avatar_crop_x.set(0);
            avatar_crop_y.set(0);
            avatar_upload_status.set(crate::i18n::tr("settings.avatar.crop_ready"));
        });
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
        let SettingsController {
            theme,
            mut profile_avatar_blob_ref,
            mut avatar_upload_status,
            mut avatar_uploading,
            mut pending_avatar_crop,
            mut avatar_refresh_nonce,
            mut state_store,
            ..
        } = self;
        spawn(async move {
            let bytes = match crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop) {
                Ok(bytes) => bytes,
                Err(err) => {
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                    return;
                }
            };
            let api = match crate::transport::auth::authed_api(&base, api_token.clone()) {
                Ok(api) => api,
                Err(err) => {
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                    return;
                }
            };
            let clients = match api.sdk_http_client() {
                Ok(http) => crate::transport::EndpointClients::from_http(http),
                Err(err) => {
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                    return;
                }
            };
            match clients.blob().upload_bytes(bytes, "image/jpeg").await {
                Ok(resp) => {
                    let blob_ref = resp.blob_ref.to_string();
                    let authority_evidence = state_store.read().recovery_material_evidence();
                    // Publish publicly first; only then refresh the
                    // local mirror so a failed profile update does not
                    // display an avatar that never became active.
                    match async {
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
                    .await
                    {
                        Ok(_) => {
                            state_store
                                .write()
                                .save_plain_local_data("avatar_blob_ref", blob_ref.clone());
                            push_client_ui_account_data_with_avatar(
                                base.clone(),
                                api_token.clone(),
                                theme(),
                                Some(blob_ref.clone()),
                            );
                            let refreshed = state_store
                                .read()
                                .load_plain_local_data("avatar_blob_ref")
                                .filter(|value| !value.trim().is_empty())
                                .unwrap_or_else(|| blob_ref.clone());
                            profile_avatar_blob_ref.set(refreshed);
                            avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                            avatar_uploading.set(false);
                            pending_avatar_crop.set(None);
                            avatar_upload_status.set(String::new());
                            crate::components::feedback::toast_success(
                                "feedback.avatar_updated",
                                vec![],
                            );
                        }
                        Err(err) => {
                            avatar_uploading.set(false);
                            avatar_upload_status.set(format!(
                                "{}: {}",
                                crate::i18n::tr("settings.avatar.error"),
                                err,
                            ));
                        }
                    }
                }
                Err(err) => {
                    avatar_uploading.set(false);
                    avatar_upload_status.set(format!(
                        "{}: {err}",
                        crate::i18n::tr("settings.avatar.error"),
                    ));
                }
            }
        });
    }

    /// Remove the account avatar.
    ///
    /// Publishes the public tombstone before the actor-private mirror. Both
    /// Events share one actor frontier; authoring them in the opposite order
    /// lets the mirror advance the frontier after the profile Event was built.
    pub(super) fn remove_avatar(
        self,
        base: String,
        api_token: String,
        first_profile_display_name: String,
    ) {
        let SettingsController {
            theme,
            mut profile_avatar_blob_ref,
            mut avatar_uploading,
            mut avatar_cache_status,
            mut pending_avatar_crop,
            mut avatar_refresh_nonce,
            mut state_store,
            ..
        } = self;
        spawn(async move {
            let authority_evidence = state_store.read().recovery_material_evidence();
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
            match result {
                Ok(_) => {
                    state_store
                        .write()
                        .save_plain_local_data("avatar_blob_ref", "");
                    push_client_ui_account_data_with_avatar(
                        base,
                        api_token,
                        theme(),
                        Some(String::new()),
                    );
                    profile_avatar_blob_ref.set(String::new());
                    avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                    pending_avatar_crop.set(None);
                    avatar_uploading.set(false);
                    avatar_cache_status.set(crate::i18n::tr("settings.avatar.removed"));
                }
                Err(err) => {
                    avatar_uploading.set(false);
                    avatar_cache_status.set(format!("Avatar removal failed: {err}"));
                    tracing::warn!("avatar profile clear failed: {err}");
                }
            }
        });
    }

    /// Rotate the invite locator, or issue the first one when none exists.
    pub(super) fn rotate_invite_locator(
        self,
        base: String,
        api_token: String,
        old_locator_id: String,
    ) {
        let SettingsController {
            mut invite_locator_id,
            mut invite_locator_token,
            mut invite_locator_status,
            ..
        } = self;
        spawn(async move {
            let result = with_authed_sdk_client(&base, api_token, |client| async move {
                if old_locator_id.is_empty() {
                    issue_invite_locator(client).await
                } else {
                    rotate_invite_locator(client, old_locator_id).await
                }
            })
            .await;
            match result {
                Ok(outcome) => {
                    invite_locator_id.set(outcome.locator_id.as_str().to_owned());
                    invite_locator_token.set(outcome.locator_token);
                    invite_locator_status.set(String::new());
                    crate::components::feedback::toast_success(
                        "feedback.invite_locator_refreshed",
                        vec![],
                    );
                }
                Err(error) => invite_locator_status.set(format!(
                    "{}: {}",
                    crate::i18n::tr("settings.invite_locator.refresh_failed"),
                    error.display()
                )),
            }
        });
    }

    /// MIMI interop probe: read the provider directory.
    pub(super) fn refresh_mimi_directory(self, base: String, api_token: String) {
        let SettingsController {
            mut mimi_directory, ..
        } = self;
        spawn(async move {
            match with_authed_sdk_client(&base, api_token, |http| async move {
                http.mimi_provider_directory(None, &[])
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(directory) => {
                    let features = serde_json::to_string_pretty(&directory.mimi.features)
                        .unwrap_or_else(|_| "[]".to_owned());
                    mimi_directory.set(format!(
                        "provider {}\nfeatures {}",
                        directory.mimi.provider_id, features,
                    ));
                }
                Err(err) => {
                    let message = format!("MIMI directory: {}", err.display());
                    mimi_directory.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.mimi_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
    }

    /// MIMI interop probe: resolve a fixed identifier commitment.
    pub(super) fn query_mimi_identifiers(self, base: String, api_token: String) {
        let SettingsController {
            mut mimi_receipt, ..
        } = self;
        spawn(async move {
            match with_authed_sdk_client(&base, api_token, |http| async move {
                let request = arkret_sdk::MimiIdentifierQueryRequestBody {
                    identifiers: vec![arkret_sdk::MimiIdentifier {
                        kind: arkret_sdk::MimiIdentifierKind::MimiUri,
                        identifier_commitment: arkret_sdk::Hash::new(
                            arkret_sdk::canonical::sha256_digest(b"mimi://remote.example/alice"),
                        )?,
                    }],
                    requester_id: None,
                    privacy_profile: Some(
                        arkret_sdk::NonEmptyString::new("private_identifier_query")
                            .map_err(anyhow::Error::msg)?,
                    ),
                    proofs: Vec::new(),
                };
                http.post::<_, arkret_sdk::MimiIdentifierQueryOutcome>(
                    "/_arkret/open/mimi/identifiers/query",
                    &request,
                )
                .await
                .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(response) => {
                    let first = response
                        .matches
                        .first()
                        .map(|value| {
                            serde_json::to_string(value)
                                .unwrap_or_else(|_| "invalid-result".to_owned())
                        })
                        .unwrap_or_else(|| "none".to_owned());
                    mimi_receipt.set(format!(
                        "identifier results {} first {}",
                        response.matches.len(),
                        first
                    ));
                }
                Err(err) => {
                    let message = format!("MIMI identifier query failed: {}", err.display());
                    mimi_receipt.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.mimi_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
    }

    /// MIMI interop probe: submit a fixed test message.
    pub(super) fn submit_mimi_message(
        self,
        base: String,
        api_token: String,
        actor: arkret_sdk::ActorId,
        device: String,
    ) {
        let SettingsController {
            mut mimi_receipt, ..
        } = self;
        spawn(async move {
            match with_authed_sdk_client(&base, api_token, |http| async move {
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
                http.post::<_, arkret_sdk::MimiSubmitMessageOutcome>(
                    "/_arkret/open/mimi/strands/01JSMIMI/messages",
                    &request,
                )
                .await
                .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(response) => {
                    mimi_receipt.set(format!(
                        "submit-message event {} rejected {}",
                        response
                            .event_ref
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "no-event".to_owned()),
                                response.rejections.len()
                    ));
                }
                Err(err) => {
                    let message = format!("MIMI submit failed: {}", err.display());
                    mimi_receipt.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.mimi_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
    }

    /// MIMI interop probe: proxy-download a fixed asset reference.
    pub(super) fn proxy_download_mimi_asset(self, base: String, api_token: String, actor: String) {
        let SettingsController {
            mut mimi_receipt, ..
        } = self;
        spawn(async move {
            match with_authed_sdk_client(&base, api_token, |http| async move {
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
                http.post::<_, arkret_sdk::MimiProxyDownloadOutcome>(
                    "/_arkret/open/mimi/proxy-download",
                    &request,
                )
                .await
                .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(response) => {
                    mimi_receipt.set(format!(
                        "proxy-download {} headers {}",
                        response.download_ref,
                        response.headers.len()
                    ));
                }
                Err(err) => {
                    let message = format!("MIMI proxy download failed: {}", err.display());
                    mimi_receipt.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.mimi_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
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
        let SettingsController {
            mut push_state,
            mut state_store,
            ..
        } = self;
        spawn(async move {
            let context = crate::push::registration::RegisterContext {
                station_url: base,
                floria_gateway_url: crate::push::floria_gateway_url(),
                device_id: dev,
                account_id: Some(push_account_id),
                authorization_credential: Some(api_token),
                session_grant: None,
                active_circle_id: None,
            };
            match crate::push::registration::register_via_chime(context, persisted_grant).await {
                Ok(outcome) => {
                    state_store
                        .write()
                        .save_push_registration(outcome.state.clone());
                    let label = outcome.response.registration_id.map_or_else(
                        || "registered".to_owned(),
                        arkret_sdk::OpaqueLocalId::into_string,
                    );
                    push_state.set(label.clone());
                    crate::components::feedback::toast_success(
                        "feedback.push_registered",
                        vec![("label", label)],
                    );
                }
                Err(err) => {
                    let message = format!("push register failed: {err}");
                    push_state.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.push_register_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
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
        let SettingsController {
            mut push_state,
            mut state_store,
            ..
        } = self;
        spawn(async move {
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
                    state_store.write().clear_push_registration();
                    push_state.set(crate::i18n::tr("settings.push.not_registered"));
                    crate::components::feedback::toast_success(
                        "feedback.push_unregistered",
                        vec![],
                    );
                }
                Err(err) => {
                    let message = format!("push unregister failed: {err}");
                    push_state.set(message.clone());
                    crate::components::feedback::toast_error(
                        "feedback.push_unregister_failed",
                        vec![],
                        Some(message),
                    );
                }
            }
        });
    }
}
