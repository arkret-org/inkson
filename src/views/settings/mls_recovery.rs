//! X11.1 — persistent "MLS Recovery Key" settings section.
//!
//! The one-time [`crate::components::MlsBackupPrompt`] only surfaces when the
//! boot-time detection effect flips `needs_mls_backup`, whose `detection_key`
//! rarely changes — so users frequently never see it. This section is the
//! RELIABLE entry: it is always reachable under
//! `/settings/encryption`, is NOT gated on
//! `needs_mls_backup`, shows the live backup status, and lets the user
//! generate/replace the MLS recovery key regardless of effect timing.
//!
//! On mount it fetches `list_key_backups` to compute status; the submit path
//! mirrors `MlsBackupPrompt` exactly (account-secret upload + best-effort
//! sidecar upload).

use std::rc::Rc;

use glory::prelude::*;

use super::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::{
    generate_recovery_key, normalize_recovery_key_input, recovery_key_confirmation_matches,
};
use crate::transport::auth::with_authed_api;

/// Resolved backup status for the section header / status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlsRecoveryStatus {
    /// Still loading the server backup list.
    Loading,
    /// No local account secret — encryption hasn't been used yet, so there's
    /// nothing to back up.
    NoLocalSecret,
    /// Server already holds an `mls_account_secret` backup.
    BackedUp,
    /// Local account secret exists but the server has no backup → the user
    /// should generate a recovery key backup.
    NotBackedUp,
}

impl MlsRecoveryStatus {
    fn badge_label_key(self) -> &'static str {
        match self {
            Self::Loading => "settings.mls_recovery.badge.loading",
            Self::NoLocalSecret => "settings.mls_recovery.badge.no_local_secret",
            Self::BackedUp => "settings.mls_recovery.badge.backed_up",
            Self::NotBackedUp => "settings.mls_recovery.badge.not_backed_up",
        }
    }

    /// i18n key for the human-readable status line.
    fn i18n_key(self) -> &'static str {
        match self {
            Self::Loading => "settings.mls_recovery.status.loading",
            Self::NoLocalSecret => "settings.mls_recovery.status.no_local_secret",
            Self::BackedUp => "settings.mls_recovery.status.backed_up",
            Self::NotBackedUp => "settings.mls_recovery.status.not_backed_up",
        }
    }

    /// `data-testid` status badge value (stable across locales for e2e).
    fn badge(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::NoLocalSecret => "no-local-secret",
            Self::BackedUp => "backed-up",
            Self::NotBackedUp => "not-backed-up",
        }
    }
}

fn recovery_form(scope: &Scope, status: Cage<MlsRecoveryStatus>, children: Vec<View>) -> View {
    Box::new(
        view()
            .class("settings-mls-recovery-form")
            .semantics(scope.bond(move || {
                let hidden = status.get() == MlsRecoveryStatus::NoLocalSecret;
                Some(Box::new(glory::render::Semantics {
                    hidden,
                    inert: hidden,
                    ..Default::default()
                }))
            }))
            .fill(children),
    )
}

/// Local feedback keeps its translation key until render. Server-provided
/// error details stay verbatim and are never interpreted as dictionary keys.
#[derive(Clone, Debug, Default, PartialEq)]
enum RecoveryFeedback {
    #[default]
    Empty,
    Localized {
        key: &'static str,
        detail: Option<String>,
    },
    External(String),
}

impl RecoveryFeedback {
    fn message(key: &'static str) -> Self {
        Self::Localized { key, detail: None }
    }

    fn with_detail(key: &'static str, detail: String) -> Self {
        Self::Localized {
            key,
            detail: Some(detail),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Localized { key, detail: None } => crate::i18n::tr(key),
            Self::Localized {
                key,
                detail: Some(detail),
            } => format!("{} {detail}", crate::i18n::tr(key)),
            Self::External(detail) => detail.clone(),
        }
    }
}

/// Compute the backup status from a fetched `list_key_backups` payload + the
/// local account-secret presence. Pure so it can be unit-tested without a
/// live session.
fn resolve_status(server_backup: bool, local_secret: bool) -> MlsRecoveryStatus {
    if server_backup {
        MlsRecoveryStatus::BackedUp
    } else if local_secret {
        MlsRecoveryStatus::NotBackedUp
    } else {
        MlsRecoveryStatus::NoLocalSecret
    }
}

fn start_recovery_key_generation(
    scope: &Scope,
    context: Rc<InksonContext>,
    account: crate::config::ActiveAccountContext,
    generated_recovery_key: Cage<String>,
    generated_recovery_key_confirm: Cage<String>,
    action_status: Cage<RecoveryFeedback>,
    busy: Cage<bool>,
    copied: Cage<bool>,
    status: Cage<MlsRecoveryStatus>,
) {
    let token = context.token;
    let state_store = context.state_store.clone();
    if busy.get() {
        return;
    }
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            action_status.revise(|value| {
                *value = RecoveryFeedback::with_detail(
                    "mls_backup.status.generate_failed",
                    err.to_string(),
                )
            });
            return;
        }
    };
    let Some(recovery_secret) = normalize_recovery_key_input(&recovery_key) else {
        action_status.revise(|value| {
            *value = RecoveryFeedback::message("mls_backup.status.generate_failed")
        });
        return;
    };
    let base = account.server_url.to_string();
    let authority = account.authority.clone();
    let session = token.get();
    let actor = account.principal_id().to_string();
    let device = account.device_id.to_string();
    let Some(recovery_material_evidence) =
        state_store.read(|store| store.recovery_material_evidence())
    else {
        action_status.revise(|value| {
            *value = RecoveryFeedback::message("settings.mls_recovery.authority_missing")
        });
        return;
    };
    if recovery_material_evidence.account_id != account.authority
        || recovery_material_evidence.principal_did != *account.did()
        || recovery_material_evidence.device_id != account.device_id
    {
        action_status.revise(|value| {
            *value = RecoveryFeedback::message("settings.mls_recovery.authority_mismatch")
        });
        return;
    }
    let principal_control_realm_id = recovery_material_evidence
        .principal_control_realm_id
        .clone();
    let sidecar_json = if state_store.read(|store| store.private_plaintext_is_empty()) {
        None
    } else {
        Some(state_store.read(|store| store.private_plaintext_snapshot_json()))
    };
    busy.revise(|value| {
        *value = true;
    });
    copied.revise(|value| {
        *value = false;
    });
    generated_recovery_key_confirm.revise(|value| {
        *value = String::new();
    });
    action_status.revise(|value| {
        *value = RecoveryFeedback::message("mls_backup.status.uploading");
    });
    super::widgets::spawn(scope, async move {
        let recovery_key_for_display = recovery_key.clone();
        let actor_for_sidecar = actor.clone();
        let authority_for_sidecar = authority.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let principal_control_realm_id_for_sidecar = principal_control_realm_id.clone();
        let result = with_authed_api(&base, session, |api| async move {
            crate::recovery_flow::verify_recovery_authority_evidence(
                &api,
                &recovery_material_evidence,
            )
            .await?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure_store.as_ref(),
                &authority,
                &principal_control_realm_id,
                &actor,
                &device,
                &recovery_secret,
            )
            .await
        })
        .await;
        busy.revise(|value| {
            *value = false;
        });
        match result {
            Ok(backup_id) => {
                state_store.write(|store| {
                    crate::components::mark_mls_recovery_backup_configured(store, &backup_id)
                });
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let outcome =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
                            let secure_store =
                                crate::secure_key_store::default_secure_key_store("inkson");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure_store.as_ref(),
                                &authority_for_sidecar,
                                &principal_control_realm_id_for_sidecar,
                                &actor,
                                &device,
                                &sidecar_json,
                            )
                            .await
                        })
                        .await;
                    let _ = outcome;
                }
                generated_recovery_key.revise(|value| {
                    *value = recovery_key_for_display;
                });
                generated_recovery_key_confirm.revise(|value| {
                    *value = String::new();
                });
                action_status.revise(|value| {
                    *value = RecoveryFeedback::message("mls_backup.status.created")
                });
                status.revise(|value| {
                    *value = MlsRecoveryStatus::BackedUp;
                });
            }
            Err(err) => {
                action_status.revise(|value| {
                    *value = RecoveryFeedback::External(err.display());
                });
            }
        }
    });
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let Some(account) = context.active_account.get() else {
        return empty();
    };
    let backup_status = scope.cage(MlsRecoveryStatus::Loading);
    let generated = scope.cage(String::new());
    let confirmed = scope.cage(String::new());
    let feedback = scope.cage(RecoveryFeedback::default());
    let busy = scope.cage(false);
    let copied = scope.cage(false);
    let refill_busy = scope.cage(false);
    let refill_status = scope.cage(RecoveryFeedback::default());
    let status_context = context.clone();
    let status_account = account.clone();
    let status_store = context.state_store.clone();
    let token = context.token;
    let generation = context.session_generation.get();
    let session = Some(account.clone());
    spawn(scope, async move {
        let account = status_account;
        let state_store = status_store;
        let status = backup_status;
        let action_status = feedback;
        let context = status_context;
        let base = account.server_url.to_string();
        let api_token = token.get();
        let actor = account.principal_id().to_string();
        let authority = account.authority.clone();
        let local_secret = {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &authority)
                .ok()
                .flatten()
                .is_some()
        };
        let device = account.device_id.to_string();
        let result = with_authed_api(&base, api_token, |api| async move {
            crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                &api, &actor, &device,
            )
            .await
        })
        .await;
        if !context.session_matches(generation, &session) {
            return;
        }
        match result {
            Ok(payload) => {
                let body = crate::mls::account_recovery::select_preferred_mls_account_secret_backup(
                    &payload,
                );
                if let Some(id) = body
                    .as_ref()
                    .and_then(|body| body.get("backup_id"))
                    .and_then(serde_json::Value::as_str)
                {
                    state_store.write(|store| {
                        crate::components::mark_mls_recovery_backup_configured(store, id)
                    });
                }
                status.revise(|value| {
                    *value = resolve_status(body.is_some(), local_secret);
                });
            }
            Err(error) => {
                action_status.revise(|value| {
                    *value = RecoveryFeedback::External(error.display());
                });
                status.revise(|value| {
                    *value = resolve_status(false, local_secret);
                });
            }
        }
    });
    let enabled = scope.bond(move || !busy.get());
    let generate_context = context.clone();
    let generate_owner = scope.downgrade();
    let generate_account = account.clone();
    let generate_button = action(
        scope,
        context.clone(),
        "settings-mls-recovery-submit",
        "settings.mls_recovery.submit",
        "primary",
        scope.bond(move || {
            !busy.get()
                && generated.get().trim().is_empty()
                && backup_status.get() != MlsRecoveryStatus::NoLocalSecret
        }),
        move || {
            if let Some(scope) = generate_owner.upgrade() {
                start_recovery_key_generation(
                    &scope,
                    generate_context.clone(),
                    generate_account.clone(),
                    generated,
                    confirmed,
                    feedback,
                    busy,
                    copied,
                    backup_status,
                );
            }
        },
    );
    let key_context = context.clone();
    let key_editor = reactive(generated, move |scope, key| {
        if key.trim().is_empty() {
            return empty();
        }
        let context = key_context.clone();
        let copy_key = key.clone();
        let download_key = key.clone();
        let download_context = context.clone();
        let regenerate_context = context.clone();
        let regenerate_owner = scope.downgrade();
        let regenerate_account = regenerate_context.active_account.get();
        stack(
            "workflow-form",
            vec![
                Box::new(
                    sapid::field("settings-mls-recovery-generated-key")
                        .unstyled()
                        .class("field")
                        .label(context.translated(scope, "mls_backup.generated_key_label"))
                        .control(move |field| {
                            sapid::text_field()
                                .unstyled()
                                .field(field)
                                .multiline(true)
                                .readonly(true)
                                .value(key.clone())
                        }),
                ),
                line(
                    "mls-backup-key-actions",
                    vec![
                        action(
                            scope,
                            context.clone(),
                            "settings-mls-recovery-copy-key",
                            "mls_backup.copy_key",
                            "secondary",
                            true,
                            move || {
                                crate::components::mls_backup_prompt::copy_text_to_clipboard(
                                    &copy_key,
                                );
                                copied.revise(|value| {
                                    *value = true;
                                });
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "settings-mls-recovery-download-key",
                            "mls_backup.download_key",
                            "secondary",
                            true,
                            move || {
                                let filename=crate::components::mls_backup_prompt::recovery_key_filename_from_handles(&[download_context.account_primary_handle.get()]);
                                crate::components::mls_backup_prompt::download_text_as_file(
                                    &filename,
                                    &download_key,
                                );
                            },
                        ),
                    ],
                ),
                paragraph(
                    "form-hint-warn",
                    context.translated(scope, "mls_backup.generated_key_warning"),
                ),
                field(
                    scope,
                    context.clone(),
                    "settings-mls-recovery-confirm-key",
                    "mls_backup.confirm_key_label",
                    confirmed,
                    enabled,
                    true,
                    move |next| {
                        confirmed.revise(|value| {
                            *value = next;
                        })
                    },
                ),
                paragraph(
                    "muted",
                    context.translated(scope, "mls_backup.confirm_key_hint"),
                ),
                line(
                    "actions",
                    vec![
                        action(
                            scope,
                            context.clone(),
                            "settings-mls-recovery-regenerate",
                            "mls_backup.button_regenerate",
                            "secondary",
                            enabled,
                            move || {
                                if let (Some(scope), Some(account)) =
                                    (regenerate_owner.upgrade(), regenerate_account.clone())
                                {
                                    start_recovery_key_generation(
                                        &scope,
                                        regenerate_context.clone(),
                                        account,
                                        generated,
                                        confirmed,
                                        feedback,
                                        busy,
                                        copied,
                                        backup_status,
                                    );
                                }
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "settings-mls-recovery-saved",
                            "mls_backup.button_confirm_saved",
                            "primary",
                            scope.bond(move || !confirmed.get().trim().is_empty()),
                            move || {
                                if !recovery_key_confirmation_matches(
                                    &generated.get(),
                                    &confirmed.get(),
                                ) {
                                    feedback.revise(|value| {
                                        *value = RecoveryFeedback::message(
                                            "mls_backup.status.confirm_mismatch",
                                        )
                                    });
                                    return;
                                }
                                generated.revise(|value| value.clear());
                                confirmed.revise(|value| value.clear());
                                feedback.revise(|value| {
                                    *value = RecoveryFeedback::Empty;
                                });
                                copied.revise(|value| {
                                    *value = false;
                                });
                            },
                        ),
                    ],
                ),
            ],
        )
    });
    let refill_context = context.clone();
    let refill_owner = scope.downgrade();
    let refill = action(
        scope,
        context.clone(),
        "settings-mls-keypackages-refill-button",
        "settings.mls_keypackages.refill_button",
        "secondary",
        scope.bond(move || !refill_busy.get()),
        move || {
            if refill_busy.get_untracked() {
                return;
            }
            let context = refill_context.clone();
            let Some(account) = context.active_account.get() else {
                return;
            };
            let base = account.server_url.to_string();
            let token = context.token.get();
            let has_session = context
                .state_store
                .read(|store| store.session_grant().is_some());
            let generation = context.session_generation.get();
            let session = Some(account.clone());
            refill_busy.revise(|value| {
                *value = true;
            });
            refill_status.revise(|value| {
                *value = RecoveryFeedback::message("settings.mls_keypackages.refill_busy")
            });
            let Some(scope) = refill_owner.upgrade() else {
                return;
            };
            spawn(&scope, async move {
                let result = if has_session {
                    crate::app::manual_refill_local_mls_key_packages(
                        base,
                        token,
                        account.authority,
                        account.device_id,
                    )
                    .await
                } else {
                    Err("active session is missing".to_owned())
                };
                if !context.session_matches(generation, &session) {
                    return;
                }
                refill_status.revise(|value| {
                    *value = match result {
                        Ok(count) => RecoveryFeedback::with_detail(
                            "settings.mls_keypackages.refill_done",
                            count.to_string(),
                        ),
                        Err(error) => {
                            if has_session {
                                RecoveryFeedback::with_detail(
                                    "settings.mls_keypackages.refill_failed",
                                    error,
                                )
                            } else {
                                RecoveryFeedback::message("settings.mls_recovery.session_missing")
                            }
                        }
                    }
                });
                refill_busy.revise(|value| {
                    *value = false;
                });
            });
        },
    );
    let status_context = context.clone();
    let guidance_context = context.clone();
    stack(
        "event settings-mls-recovery",
        vec![
            line(
                "event-head",
                vec![
                    plain(context.translated(scope, "settings.mls_recovery.title")),
                    reactive(backup_status, move |scope, status| {
                        Box::new(text().class(format!(
                                "badge settings-mls-recovery-status-badge settings-mls-recovery-status--{}",
                                status.badge()
                            )).content(status_context.translated(scope, status.badge_label_key())))
                    }),
                ],
            ),
            reactive(backup_status, move |scope, status| {
                paragraph(
                    "muted settings-mls-recovery-status",
                    guidance_context.translated(scope, status.i18n_key()),
                )
            }),
            paragraph(
                "muted settings-mls-recovery-warning",
                context.translated(scope, "mls_backup.warning.passphrase_loss"),
            ),
            recovery_form(scope, backup_status, vec![key_editor, generate_button]),
            status(scope.bond(move || feedback.get().text())),
            stack(
                "workflow-form",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "settings.mls_keypackages.refill_description"),
                    ),
                    refill,
                    status(scope.bond(move || refill_status.get().text())),
                ],
            ),
        ],
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_feedback_retranslates_existing_message_and_preserves_external_details() {
        use crate::i18n::{UiLocale, with_test_locale};
        let feedback = RecoveryFeedback::message("settings.mls_recovery.authority_missing");
        let detailed =
            RecoveryFeedback::with_detail("settings.mls_keypackages.refill_done", "3".into());
        with_test_locale(UiLocale::En, || {
            assert!(
                feedback
                    .text()
                    .starts_with("Account recovery details are unavailable.")
            );
            assert!(detailed.text().ends_with("3"));
        });
        with_test_locale(UiLocale::Zh, || {
            assert_eq!(feedback.text(), "账号恢复信息暂不可用。请刷新账号后重试。");
            assert!(detailed.text().contains("3"));
            assert!(!detailed.text().contains("KeyPackage maintenance complete"));
            assert_eq!(
                RecoveryFeedback::External("server detail".into()).text(),
                "server detail"
            );
            assert!(RecoveryFeedback::Empty.text().is_empty());
        });
        with_test_locale(UiLocale::En, || {
            assert!(
                feedback
                    .text()
                    .starts_with("Account recovery details are unavailable.")
            )
        });
    }

    #[test]
    fn status_backed_up_when_server_has_backup() {
        assert_eq!(resolve_status(true, true), MlsRecoveryStatus::BackedUp);
        // Server backup wins even if the local secret read failed.
        assert_eq!(resolve_status(true, false), MlsRecoveryStatus::BackedUp);
    }

    #[test]
    fn status_not_backed_up_when_local_secret_but_no_server() {
        assert_eq!(resolve_status(false, true), MlsRecoveryStatus::NotBackedUp);
    }

    #[test]
    fn status_no_local_secret_when_nothing_local() {
        assert_eq!(
            resolve_status(false, false),
            MlsRecoveryStatus::NoLocalSecret
        );
    }

    #[test]
    fn badge_values_are_stable() {
        assert_eq!(MlsRecoveryStatus::Loading.badge(), "loading");
        assert_eq!(MlsRecoveryStatus::BackedUp.badge(), "backed-up");
        assert_eq!(MlsRecoveryStatus::NotBackedUp.badge(), "not-backed-up");
        assert_eq!(MlsRecoveryStatus::NoLocalSecret.badge(), "no-local-secret");
    }
}
