use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use glory::prelude::*;

use super::mls_backup_prompt::try_set_state;
use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::normalize_recovery_key_input;
use crate::transport::auth::{ApiCallError, with_authed_api};

const MLS_UNLOCK_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

async fn mls_unlock_fetch_with_timeout<T, F>(future: F) -> std::result::Result<T, ApiCallError>
where
    F: Future<Output = std::result::Result<T, ApiCallError>>,
{
    tokio::select! {
        result = future => result,
        _ = crate::runtime_helpers::sleep_for(MLS_UNLOCK_FETCH_TIMEOUT) => Err(ApiCallError::Failed(anyhow::anyhow!(
            "MLS unlock timed out while fetching recovery material"
        ))),
    }
}

/// Each fetch has its own network deadline. Rate-limit waits occur between
/// attempts, while exact unlock requests and successful ciphertext receipts
/// remain owned by the key-backup layer.
async fn mls_unlock_fetch_with_retry<T, F, R, W, S>(
    mut fetch: F,
    mut wait: W,
) -> std::result::Result<T, ApiCallError>
where
    F: FnMut() -> R,
    R: Future<Output = std::result::Result<T, ApiCallError>>,
    W: FnMut(Duration) -> S,
    S: Future<Output = ()>,
{
    loop {
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        tracing::warn!(target: "mls_unlock", "MLS unlock: recovery fetch attempt");
        let error = match mls_unlock_fetch_with_timeout(fetch()).await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let Some(delay) = crate::key_backup::key_backup_unlock_retry_delay(error.inner()) else {
            return Err(error);
        };
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        tracing::warn!(target: "mls_unlock", delay_ms = delay.as_millis() as u64, "MLS unlock: retry wait started");
        wait(delay).await;
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        tracing::warn!(target: "mls_unlock", "MLS unlock: retry wait completed");
    }
}

#[derive(Clone)]
struct UnlockController {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    passphrase: Cage<String>,
    status: Cage<String>,
    busy: Cage<bool>,
    dismissed: Cage<bool>,
    recovery_key_open: Cage<bool>,
    task: Rc<RefCell<Option<glory::core::TaskToken>>>,
}
impl UnlockController {
    fn dismiss(&self) {
        if let Some(task) = self.task.borrow_mut().take() {
            task.cancel();
        }
        try_set_state(self.busy, false);
        try_set_state(self.dismissed, true);
    }
    fn unlock(&self) {
        if self.busy.get() {
            return;
        }
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        let Some(active_account) = self.context.active_account.get() else {
            return;
        };
        let raw = self.passphrase.get();
        if raw.trim().is_empty() {
            try_set_state(
                self.status,
                self.context.tr("mls_unlock.status.enter_passphrase"),
            );
            return;
        }
        let Some(pass) = normalize_recovery_key_input(&raw) else {
            try_set_state(
                self.status,
                self.context.tr("mls_unlock.status.invalid_recovery_key"),
            );
            return;
        };
        let context = self.context.clone();
        let generation = context.session_generation.get();
        let active = context.active_account.get();
        let owner = self.owner.clone();
        let base = context.base_url.get();
        let session = context.token.get();
        let actor = active_account.principal_id().to_string();
        let device = context.device_id.get();
        let authority = active_account.authority.clone();
        let state_store = context.state_store.handle();
        let status = self.status;
        let busy = self.busy;
        let restore_payload_cache = context.restore_payload_cache;
        let passphrase = self.passphrase;
        let needs_mls_unlock = context.needs_mls_unlock;
        try_set_state(busy, true);
        try_set_state(status, context.tr("mls_unlock.status.fetching"));
        match scope.owner().spawn(async move {
            tracing::warn!(
                target: "mls_unlock",
                %actor,
                %device,
                "MLS unlock: starting recovery-material fetch"
            );
            let fetch_actor = actor.clone();
            let fetch_device = device.clone();
            // SEC-05: fetch the restore payload AND the actor's currently-accepted
            // recovery policy in the same authed session, so the HPKE account-secret
            // backup's `recovery_policy_ref` can be verified before import.
            let payload_result = mls_unlock_fetch_with_retry(
                || {
                    let fetch_actor = fetch_actor.clone();
                    let fetch_device = fetch_device.clone();
                    with_authed_api(&base, session.clone(), |api| async move {
                        let payload = crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                            &api, &fetch_actor, &fetch_device,
                        ).await?;
                        let active_policy = crate::recovery_flow::fetch_active_recovery_policy(&api).await?;
                        Ok::<_, anyhow::Error>((payload, active_policy))
                    })
                },
                |delay| {
                    try_set_state(status, crate::i18n::tr("error.rate_limited"));
                    crate::runtime_helpers::sleep_for(delay)
                },
            ).await;
            if owner.upgrade().is_none()||!context.session_matches(generation,&active){return}
            let result = match payload_result {
                Ok((payload, active_policy)) => {
                    // The restorable set is the account's own key-backup
                    // envelopes: the account MLS secret and the private
                    // plaintext sidecar. The RHRK history-secret family was
                    // removed with the protocol, so there is no separate
                    // history-backup count to report any more.
                    let history_count =
                        crate::mls::runtime::all_secret_storage_backups(&payload).len();
                    try_set_state(restore_payload_cache, Some(payload.clone()));
                    tracing::warn!(
                        target: "mls_unlock",
                        history_count,
                        has_active_policy = active_policy.is_some(),
                        "MLS unlock: recovery material fetched"
                    );
                    try_set_state(
                        status,
                        format!(
                            "{} {} {}",
                            crate::i18n::tr("mls_unlock.status.restoring_prefix"),
                            history_count,
                            crate::i18n::tr("mls_unlock.status.restoring_suffix")
                        ),
                    );
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(16)).await;
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    // The restore now runs through the host-neutral store
                    // handle, so the store guard is taken and released around
                    // each durable step instead of being held across the whole
                    // async restore. Probe it once first: a dropped signal
                    // still means the prompt is gone.
                    if owner.upgrade().is_none()||!context.session_matches(generation,&active) {
                        Err(ApiCallError::Failed(anyhow::anyhow!(
                            "recovery prompt closed before restore completed"
                        )))
                    } else {
                        let store_handle =
                            state_store.clone();
                        tracing::warn!(
                            target: "mls_unlock",
                            history_count,
                            "MLS unlock: starting local restore"
                        );
                        let mut restore_result = match crate::hpke_backup::derive_recovery_keypair_from_recovery_key(&pass)
                            .map_err(|err| anyhow::anyhow!("derive recovery key: {err}"))
                        {
                            Ok((recovery_private_key, _)) => match active_policy.as_ref() {
                                Some(policy) => crate::mls::account_recovery::restore_mls_history_with_recovery_key_from_payload(
                                    &payload,
                                    &store_handle,
                                    secure_store.as_ref(),
                                    &authority,
                                    &actor,
                                    &device,
                                    &recovery_private_key,
                                    (policy.policy_id.as_str(), policy.version),
                                )
                                .await
                                .map_err(ApiCallError::Failed),
                                None => Err(ApiCallError::Failed(anyhow::anyhow!(
                                    "active recovery policy is required"
                                ))),
                            },
                            Err(error) => Err(ApiCallError::Failed(error)),
                        };
                        if owner.upgrade().is_none()||!context.session_matches(generation,&active){return}
                        if restore_result.is_ok() {
                            store_handle.write(|store| {
                                let account_data = store.current_account_data_events();
                                if let Err(error) = crate::sync_engine::apply_account_data_entries(
                                    store,
                                    &account_data,
                                    &authority,
                                ) {
                                    tracing::warn!(%error, "account data remains unavailable after MLS unlock");
                                }
                            });
                            if store_handle
                                .write(|store| {
                                    crate::views::recovery::save_generated_recovery_key_metadata_in_store(
                                        store, &pass,
                                    )
                                })
                                .is_none()
                            {
                                restore_result = Err(ApiCallError::Failed(anyhow::anyhow!(
                                    "recovery key public metadata could not be persisted"
                                )));
                            } else if let Some(backup_id) = crate::mls::account_recovery::select_preferred_mls_account_secret_backup(
                                &payload,
                            )
                            .and_then(|backup| {
                                backup
                                    .get("backup_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            }) {
                                store_handle.write(|store| {
                                    crate::components::mark_mls_recovery_backup_configured(
                                        store, &backup_id,
                                    );
                                });
                            }
                        }
                        tracing::warn!(
                            target: "mls_unlock",
                            success = restore_result.is_ok(),
                            "MLS unlock: local restore finished"
                        );
                        restore_result
                    }
                }
                Err(err) => Err(err),
            };
            if owner.upgrade().is_none()||!context.session_matches(generation,&active){return}
            try_set_state(busy, false);
            match result {
                Ok(report) => {
                    if let Some(err) = report.first_error {
                        // Some backups failed even though the call returned Ok —
                        // keep the prompt open so the user can retry.
                        try_set_state(
                            status,
                            format!(
                                "{} {} {}; {} {}: {err}",
                                crate::i18n::tr("mls_unlock.status.restored_prefix"),
                                report.restored,
                                crate::i18n::tr("mls_unlock.status.restored_suffix"),
                                report.failed,
                                crate::i18n::tr("mls_unlock.status.failed_suffix")
                            ),
                        );
                    } else {
                        let restored_status = format!(
                            "{} {} {}",
                            crate::i18n::tr("mls_unlock.status.restored_prefix"),
                            report.restored,
                            crate::i18n::tr("mls_unlock.status.restored_suffix")
                        );
                        try_set_state(passphrase, String::new());
                        try_set_state(status, restored_status);
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(750))
                            .await;
                        if owner.upgrade().is_some()&&context.session_matches(generation,&active){try_set_state(needs_mls_unlock, false);}
                    }
                }
                Err(err) => {
                    // Wrong passphrase / network: keep prompt open, surface reason.
                    try_set_state(status, err.display());
                }
            }

        }) {Ok(task)=>*self.task.borrow_mut()=Some(task),Err(error)=>{try_set_state(busy,false);try_set_state(status,error.to_string());}}
    }
}
pub fn mls_unlock_prompt(scope: &Scope, context: Rc<InksonContext>) -> View {
    let controller = UnlockController {
        context: context.clone(),
        owner: scope.downgrade(),
        passphrase: scope.cage(String::new()),
        status: scope.cage(String::new()),
        busy: scope.cage(false),
        dismissed: scope.cage(false),
        recovery_key_open: scope.cage(false),
        task: Rc::new(RefCell::new(None)),
    };
    let reset = controller.clone();
    let needed = context.needs_mls_unlock;
    scope.effect(move || {
        if !needed.get() {
            reset.dismiss();
            try_set_state(reset.dismissed, false);
            try_set_state(reset.recovery_key_open, false);
            try_set_state(reset.passphrase, String::new());
        }
    });
    let source = scope.bond({
        let state = controller.clone();
        let context = context.clone();
        move || {
            (
                needed.get(),
                state.dismissed.get(),
                state.recovery_key_open.get(),
                context.locale.get(),
            )
        }
    });
    reactive(
        source,
        move |scope, (needed, dismissed, recovery_open, _)| {
            if !needed || context.active_account.get().is_none() {
                return Box::new(widget(|_| Ok(())));
            }
            if dismissed {
                let state = controller.clone();
                return Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn mls-unlock-reopen-button primary")
                        .label(context.translated(scope, "mls_unlock.reopen"))
                        .on_press(move || try_set_state(state.dismissed, false)),
                );
            }
            let close = controller.clone();
            let close_button = Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn close")
                    .label(context.translated(scope, "mls_unlock.dismiss"))
                    .on_press(move || close.dismiss()),
            ) as View;
            let steps = [
                (
                    "mls_unlock.approve_step_existing_title",
                    "mls_unlock.approve_step_existing_body",
                ),
                (
                    "mls_unlock.approve_step_new_title",
                    "mls_unlock.approve_step_new_body",
                ),
            ]
            .into_iter()
            .map(|(title, body)| {
                stack(
                    "mls-device-authorization-step",
                    vec![
                        paragraph("", context.translated(scope, title)),
                        paragraph("", context.translated(scope, body)),
                    ],
                )
            })
            .collect();
            let mut body = vec![
                paragraph("muted", context.translated(scope, "mls_unlock.description")),
                stack(
                    "mls-device-authorization-details",
                    vec![stack("mls-device-authorization-path", steps)],
                ),
                line(
                    "mls-device-authorization-limitation",
                    vec![
                        super::ui_icon("alert"),
                        paragraph("", context.translated(scope, "mls_unlock.limitation")),
                    ],
                ),
            ];
            let busy = controller.busy;
            let ctx = context.clone();
            body.push(paragraph(
                "muted mls-unlock-loading",
                scope.bond(move || {
                    if busy.get() {
                        ctx.tr("mls_unlock.loading_hint")
                    } else {
                        String::new()
                    }
                }),
            ));
            body.push(paragraph("muted", controller.status));
            if recovery_open {
                let state = controller.clone();
                let enabled = scope.bond(move || !busy.get());
                let pass = controller.passphrase;
                let input = Box::new(
                    sapid::field("mls-unlock-passphrase")
                        .unstyled()
                        .label(context.translated(scope, "mls_unlock.placeholder"))
                        .control(move |field| {
                            sapid::text_field()
                                .unstyled()
                                .class("input")
                                .field(field)
                                .purpose(Purpose::Password)
                                .value(pass)
                                .enabled(enabled)
                                .on_value_change(move |value| try_set_state(pass, value))
                        }),
                ) as View;
                let ctx = context.clone();
                let label = scope.bond(move || {
                    ctx.tr(if busy.get() {
                        "mls_unlock.button_busy"
                    } else {
                        "mls_unlock.button_idle"
                    })
                });
                body.push(line(
                    "actions mls-unlock-row mls-unlock-recovery-row",
                    vec![
                        paragraph(
                            "muted mls-unlock-fallback-note",
                            context.translated(scope, "mls_unlock.recovery_fallback_hint"),
                        ),
                        input,
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class("primary")
                                .label(label)
                                .enabled(enabled)
                                .on_press(move || state.unlock()),
                        ),
                    ],
                ));
            }
            let open = controller.recovery_key_open;
            let toggle = Box::new(
                sapid::button()
                    .unstyled()
                    .class("secondary")
                    .label(context.translated(
                        scope,
                        if recovery_open {
                            "mls_unlock.hide_recovery_key"
                        } else {
                            "mls_unlock.show_recovery_key"
                        },
                    ))
                    .enabled(scope.bond(move || !busy.get()))
                    .on_press(move || open.revise(|value| *value = !*value)),
            ) as View;
            let content = stack(
                "modal mls-recovery-modal mls-unlock-dialog",
                vec![
                    line(
                        "modal-head event-head",
                        vec![
                            stack(
                                "",
                                vec![
                                    heading(3, "", context.translated(scope, "mls_unlock.title")),
                                    paragraph(
                                        "muted",
                                        context.translated(scope, "mls_unlock.subtitle"),
                                    ),
                                ],
                            ),
                            close_button,
                        ],
                    ),
                    stack("modal-body mls-recovery-modal-body", body),
                    line("modal-foot actions mls-unlock-row", vec![toggle]),
                ],
            );
            let close = controller.clone();
            let mut content = Some(content);
            Box::new(
                sapid::dialog("mls-unlock")
                    .unstyled()
                    .name(context.translated(scope, "mls_unlock.title"))
                    .open(true)
                    .show_trigger(false)
                    .show_close(false)
                    .on_dismiss(move |_| close.dismiss())
                    .content(move || {
                        content
                            .take()
                            .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                    }),
            )
        },
    )
}
pub fn mls_recovery_setup_missing_banner(_scope: &Scope, context: Rc<InksonContext>) -> View {
    let needed = context.needs_mls_recovery_setup;
    reactive(needed, move |scope, needed_now| {
        if !needed_now {
            return Box::new(widget(|_| Ok(())));
        }
        let Some(account) = context.active_account.get() else {
            return Box::new(widget(|_| Ok(())));
        };
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        if matches!(
            crate::mls::runtime::load_account_mls_secret(secure.as_ref(), &account.authority),
            Ok(Some(_))
        ) {
            return Box::new(widget(|_| Ok(())));
        }
        let close = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary")
                .label(context.translated(scope, "mls_recovery_missing.button_dismiss"))
                .on_press(move || try_set_state(needed, false)),
        ) as View;
        let content = stack(
            "modal event mls-recovery-modal mls-recovery-missing-banner",
            vec![
                stack(
                    "modal-head event-head",
                    vec![
                        heading(
                            3,
                            "",
                            context.translated(scope, "mls_recovery_missing.title"),
                        ),
                        paragraph(
                            "muted",
                            context.translated(scope, "mls_recovery_missing.subtitle"),
                        ),
                    ],
                ),
                stack(
                    "modal-body mls-recovery-modal-body",
                    vec![paragraph(
                        "muted",
                        context.translated(scope, "mls_recovery_missing.description"),
                    )],
                ),
                line("modal-foot mls-unlock-row", vec![close]),
            ],
        );
        let mut content = Some(content);
        Box::new(
            sapid::dialog("mls-recovery-missing")
                .unstyled()
                .name(context.translated(scope, "mls_recovery_missing.aria_label"))
                .open(true)
                .show_trigger(false)
                .show_close(false)
                .on_dismiss(move |_| try_set_state(needed, false))
                .content(move || {
                    content
                        .take()
                        .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                }),
        )
    })
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    fn rate_limit(retry_after_ms: Option<u64>) -> ApiCallError {
        let mut problem = arkret_sdk::Problem::new("rate_limited", 429, "slow down");
        if let Some(delay) = retry_after_ms {
            problem = problem.with_extension("retry_after_ms", serde_json::json!(delay));
        }
        let error = anyhow::Error::from(arkret_sdk::Error::Api {
            status: 429,
            error: Box::new(problem),
        })
        .context("fetch key backup with unlock proof");
        ApiCallError::Failed(error)
    }

    #[tokio::test]
    async fn rate_limit_waits_then_resumes_but_terminal_errors_stop() {
        for (hint, expected) in [(Some(250), 250), (None, 60_000)] {
            let mut results = std::collections::VecDeque::from([Err(rate_limit(hint)), Ok(7_u32)]);
            let mut delays = Vec::new();
            let restored = mls_unlock_fetch_with_retry(
                || std::future::ready(results.pop_front().unwrap()),
                |delay| {
                    delays.push(delay);
                    std::future::ready(())
                },
            )
            .await
            .unwrap();
            assert_eq!(restored, 7);
            assert_eq!(delays, vec![Duration::from_millis(expected)]);
            assert!(results.is_empty());
        }
        let mut waited = false;
        let rejected = mls_unlock_fetch_with_retry::<(), _, _, _, _>(
            || {
                std::future::ready(Err(ApiCallError::Failed(
                    anyhow::anyhow!("signature invalid")
                        .context("fetch key backup with unlock proof"),
                )))
            },
            |_| {
                waited = true;
                std::future::ready(())
            },
        )
        .await;
        assert!(rejected.is_err());
        assert!(!waited);
    }
}
